// Quantum-Lattice (QL) mining pool server — standalone project, same
// pattern as ql-miner: no RocksDB, since the pool doesn't need a full
// chain database, just its own small encrypted identity and in-memory
// share tracking for the current round.
//
// HOW THIS ACTUALLY WORKS, worth understanding before touching this file:
//
// The pool is, from the real node's point of view, indistinguishable from
// any solo miner — it has its own wallet, fetches templates, and submits
// solved blocks the exact same way. The difference is entirely on the
// OTHER side: instead of one machine grinding nonces, the pool hands the
// SAME candidate (built using the POOL's own address, not each individual
// contributor's) out to everyone connected, at a much easier, pool-set
// difficulty. Whoever finds a nonce meeting that easier target submits it
// back for credit — and the pool separately checks whether that same
// nonce, on that same pool-owned header, ALSO happens to satisfy the real
// network difficulty. When it does, the pool submits it as a genuine
// block under its own address, earns the real reward, and pays everyone
// out proportional to their share of the work since the pool's last win.
//
// IMPORTANT: calculate_pow_hash and meets_difficulty below are copied
// verbatim from ql-miner/src/main.rs, which is itself required to stay
// byte-for-byte identical to src/ledger.rs and src/consensus.rs on the
// main node. If any of the three drift apart, this silently stops working
// correctly — no crash, just nothing ever validating.
//
// TESTED: share tracking, correct hashing against the pool's own address,
// and proportional payout splitting have all been verified with a real,
// deliberate test — two independent miners contributing different share
// counts, a manually-funded real balance, and confirmed correct, real,
// on-chain payouts landing in both wallets in the right proportions.
//
// NOT YET TESTED: a genuine real-network block win through normal mining
// (as opposed to the manual test trigger), and behavior under many
// simultaneous connected miners rather than just two. Also worth knowing:
// difficulty is currently one fixed value for every connected miner —
// per-miner variable difficulty (so a very high-end machine and a modest
// one both get a similarly steady share rate) is a real, valuable
// improvement worth building later, not present in this version.

use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls::pki_types::ServerName;
use ml_dsa::{MlDsa65, Keypair, SigningKey, Signer, SignatureEncoding, Seed};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

fn now() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

// ---------------------------------------------------------------------
// Outbound connection to the real node — identical to ql-miner's own
// connect()/http_get/http_post, so the pool can reach a real public
// domain (TLS) or a local address (plain) exactly the same way a normal
// miner does.
// ---------------------------------------------------------------------

enum Conn {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

fn is_local_address(host: &str) -> bool {
    host == "localhost" || host.parse::<std::net::IpAddr>().is_ok()
}

fn connect(node_address: &str) -> Option<(Conn, String)> {
    let host = node_address.split(':').next().unwrap_or(node_address).to_string();
    const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);

    if is_local_address(&host) {
        let stream = TcpStream::connect(node_address).ok()?;
        stream.set_read_timeout(Some(NETWORK_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(NETWORK_TIMEOUT)).ok()?;
        Some((Conn::Plain(stream), node_address.to_string()))
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = ServerName::try_from(host.clone()).ok()?;
        let conn = ClientConnection::new(Arc::new(config), server_name).ok()?;
        let sock = TcpStream::connect((host.as_str(), 443)).ok()?;
        sock.set_read_timeout(Some(NETWORK_TIMEOUT)).ok()?;
        sock.set_write_timeout(Some(NETWORK_TIMEOUT)).ok()?;
        let tls_stream = StreamOwned::new(conn, sock);
        Some((Conn::Tls(Box::new(tls_stream)), host))
    }
}

fn http_get(host_port: &str, path: &str) -> Option<String> {
    let (mut conn, host_header) = connect(host_port)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_header
    );
    conn.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    conn.read_to_string(&mut response).ok()?;
    Some(response)
}

fn http_post(host_port: &str, path: &str, body: &str) -> Option<String> {
    let (mut conn, host_header) = connect(host_port)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host_header, body.len(), body
    );
    conn.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    conn.read_to_string(&mut response).ok()?;
    Some(response)
}

// ---------------------------------------------------------------------
// JSON helpers — same hand-rolled approach used throughout this whole
// project, avoiding a heavier dependency for simple field extraction.
// ---------------------------------------------------------------------

fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let key_pos = body.find(&pattern)?;
    let after_key = &body[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    let value_start = after_colon.strip_prefix('"')?;
    let mut result = String::new();
    let mut chars = value_start.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some(other) => { result.push('\\'); result.push(other); }
                None => break,
            }
        } else if c == '"' {
            return Some(result);
        } else {
            result.push(c);
        }
    }
    None
}

fn extract_json_number(body: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", key);
    let key_pos = body.find(&pattern)?;
    let after_key = &body[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    let end = after_colon.find(|c: char| c == ',' || c == '}').unwrap_or(after_colon.len());
    after_colon[..end].trim().parse::<u64>().ok()
}

/// Same as extract_json_number, but for genuine decimal values — the
/// node's /api/balance now correctly returns full-precision QL amounts
/// (e.g. "48.00000000") rather than a truncated whole number, so anything
/// reading a real balance needs this, not the integer-only parser above.
fn extract_json_float(body: &str, key: &str) -> Option<f64> {
    let pattern = format!("\"{}\"", key);
    let key_pos = body.find(&pattern)?;
    let after_key = &body[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    let end = after_colon.find(|c: char| c == ',' || c == '}').unwrap_or(after_colon.len());
    after_colon[..end].trim().parse::<f64>().ok()
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

// ---------------------------------------------------------------------
// Proof-of-work — copied verbatim from ql-miner. MUST stay identical to
// the main node's ledger.rs / consensus.rs.
// ---------------------------------------------------------------------

fn calculate_pow_hash(
    version: u32,
    previous_block_hash: &[u8],
    merkle_root: &[u8],
    block_height: u64,
    miner: &[u8],
    nonce: u64,
) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(&version.to_le_bytes());
    hasher.update(previous_block_hash);
    hasher.update(merkle_root);
    hasher.update(&block_height.to_le_bytes());
    hasher.update(miner);
    hasher.update(&nonce.to_le_bytes());
    hasher.finalize().to_vec()
}

fn meets_difficulty(hash: &[u8], required_bits: u32) -> bool {
    let mut bits_checked: u32 = 0;
    for byte in hash {
        if bits_checked + 8 <= required_bits {
            if *byte != 0 {
                return false;
            }
            bits_checked += 8;
        } else {
            let remaining_bits = required_bits - bits_checked;
            if remaining_bits == 0 {
                return true;
            }
            let mask: u8 = 0xFFu8 << (8 - remaining_bits);
            return byte & mask == 0;
        }
    }
    true
}

// ---------------------------------------------------------------------
// Fine-grained difficulty (fork 2). Copied from consensus.rs in the node:
// target_from_fine / hash_below_target MUST stay identical to the node's.
// A fixed-point difficulty of 65536 = 1.0 bit; whole-bit values give exactly
// the same result as the old "leading zero bits" test.
// ---------------------------------------------------------------------
fn exp2_factor(frac: u32) -> u64 {
    let f = frac as u128;
    ((195766423245049u128 * f + 971821376u128 * f * f + 5127u128 * f * f * f + (1u128 << 47)) >> 48) as u64
}

fn target_from_fine(fine: u32) -> [u8; 32] {
    let fine = fine.clamp(1 << 16, 255 << 16);
    let e = (256u64 << 16) - fine as u64;
    let int_part = (e >> 16) as u32;
    let frac = (e & 0xFFFF) as u32;
    let mant = 65536u64 + exp2_factor(frac);
    let shift = int_part - 16;
    let mut t = [0u8; 32];
    for k in 0..17u32 {
        if (mant >> k) & 1 == 1 {
            let pos = shift + k;
            if pos >= 256 {
                return [0xFFu8; 32];
            }
            t[31 - (pos / 8) as usize] |= 1u8 << (pos % 8);
        }
    }
    t
}

fn hash_below_target(hash: &[u8], target: &[u8; 32]) -> bool {
    if hash.len() != 32 {
        return false;
    }
    for i in 0..32 {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod fine_difficulty_tests {
    use super::*;
    #[test]
    fn matches_node_vectors() {
        let mut expect = [0u8; 32];
        expect[31 - 221 / 8] = 1 << (221 % 8);
        assert_eq!(target_from_fine(35 << 16), expect);
        let t = target_from_fine((35 << 16) + 32768);
        let mut m: u64 = 0;
        for k in 0..17u32 {
            let pos = 204 + k;
            if t[31 - (pos / 8) as usize] & (1u8 << (pos % 8)) != 0 {
                m |= 1 << k;
            }
        }
        assert_eq!(m, 92674);
    }
}

// ---------------------------------------------------------------------
// The pool's own encrypted identity — same AES-256-GCM + PBKDF2 scheme
// already used for the node's treasury vaults, duplicated here since this
// is a standalone project with no access to the main crate's wallet.rs.
// ---------------------------------------------------------------------

struct EncryptedVaultFile {
    kdf_iterations: u32,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn load_vault_file(path: &str) -> Option<EncryptedVaultFile> {
    let raw = std::fs::read_to_string(path).ok()?;
    Some(EncryptedVaultFile {
        kdf_iterations: extract_json_number(&raw, "kdf_iterations")? as u32,
        salt: hex::decode(extract_json_string(&raw, "salt")?).ok()?,
        nonce: hex::decode(extract_json_string(&raw, "nonce")?).ok()?,
        ciphertext: hex::decode(extract_json_string(&raw, "ciphertext")?).ok()?,
    })
}

fn save_vault_file(path: &str, kdf_iterations: u32, salt: &[u8], nonce: &[u8], ciphertext: &[u8]) {
    let json = format!(
        "{{\"version\":1,\"kdf\":\"pbkdf2-sha256\",\"kdf_iterations\":{},\"salt\":\"{}\",\"nonce\":\"{}\",\"ciphertext\":\"{}\"}}",
        kdf_iterations, hex::encode(salt), hex::encode(nonce), hex::encode(ciphertext)
    );
    std::fs::write(path, json).expect("Failed to write pool vault file");
}

fn decrypt_seed(file: &EncryptedVaultFile, password: &str) -> Option<[u8; 32]> {
    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &file.salt, file.kdf_iterations, &mut key_bytes);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&file.nonce);
    let plaintext = cipher.decrypt(nonce, file.ciphertext.as_ref()).ok()?;
    plaintext.try_into().ok()
}

fn create_and_save_vault(path: &str, password: &str) -> [u8; 32] {
    let mut seed_bytes = [0u8; 32];
    getrandom::fill(&mut seed_bytes).expect("OS randomness unavailable");

    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).expect("OS randomness unavailable");
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).expect("OS randomness unavailable");

    const ITERATIONS: u32 = 200_000;
    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, ITERATIONS, &mut key_bytes);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, seed_bytes.as_ref()).expect("Encryption failed");

    save_vault_file(path, ITERATIONS, &salt, &nonce_bytes, &ciphertext);
    seed_bytes
}

/// Unlocks the pool's identity, creating it fresh on first run. Returns
/// the raw seed (kept in memory for signing payouts) and the derived
/// public key bytes (the pool's real, on-chain address).
fn unlock_or_create_pool_identity() -> ([u8; 32], Vec<u8>) {
    let vault_path = "pool_identity.key";
    let seed_bytes = if let Some(file) = load_vault_file(vault_path) {
        loop {
            let password = rpassword::prompt_password("Enter password to unlock the pool's identity: ")
                .expect("failed to read password");
            match decrypt_seed(&file, &password) {
                Some(seed) => break seed,
                None => println!("[POOL] Incorrect password, try again."),
            }
        }
    } else {
        println!("[POOL] No existing pool identity found — creating a new one.");
        let password = rpassword::prompt_password("Set a password to encrypt the pool's identity: ")
            .expect("failed to read password");
        let confirm = rpassword::prompt_password("Confirm password: ")
            .expect("failed to read password");
        if password != confirm {
            eprintln!("[POOL] Passwords did not match. Exiting.");
            std::process::exit(1);
        }
        create_and_save_vault(vault_path, &password)
    };

    let seed = Seed::from(seed_bytes);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let pk_bytes = sk.verifying_key().encode().as_slice().to_vec();
    (seed_bytes, pk_bytes)
}

fn sign_with_seed(seed_bytes: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let seed = Seed::from(*seed_bytes);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    sk.sign(message).to_bytes().as_slice().to_vec()
}

// ---------------------------------------------------------------------
// Shared round state
// ---------------------------------------------------------------------

#[derive(Clone)]
struct RoundTemplate {
    block_height: u64,
    previous_block_hash: Vec<u8>,
    merkle_root: Vec<u8>,
    real_difficulty_bits: u32,
    real_difficulty_fp: u32,
    pool_difficulty_bits: u32,
}

/// A real record of a completed payout — kept purely so a dashboard can
/// show genuine history, not just the current live round.
#[derive(Clone)]
struct PayoutRecord {
    timestamp: i64,
    total_paid_ql: f64,
    contributor_count: usize,
    is_manual: bool,
}

struct SharedState {
    template: Mutex<Option<RoundTemplate>>,
    shares: Mutex<HashMap<String, u64>>,
    payout_history: Mutex<Vec<PayoutRecord>>,
    round_start_time: Mutex<i64>,
    all_time_blocks_found: Mutex<u64>,
    all_time_ql_distributed: Mutex<f64>,
    all_time_manual_rewards: Mutex<u64>,
    payments: Mutex<Vec<Payment>>,
    payments_updated: Mutex<i64>,
    /// (template id, nonces already credited for it) - stops one valid share being credited repeatedly.
    seen_shares: Mutex<(Vec<u8>, HashSet<u64>)>,
}

// ---------------------------------------------------------------------
// Serving connected miners
// ---------------------------------------------------------------------

fn read_http_request(stream: &mut TcpStream) -> String {
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut data: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&chunk[..n]);
                if let Some(header_end) = find_header_end(&data) {
                    let headers = String::from_utf8_lossy(&data[..header_end]);
                    let content_length = headers
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if data.len() - header_end >= content_length {
                        break;
                    }
                } else if data.len() > 65536 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&data).to_string()
}

fn handle_miner_connection(
    mut stream: TcpStream,
    state: Arc<SharedState>,
    node_address: String,
    pool_seed: [u8; 32],
    pool_pk: Vec<u8>,
    pool_pk_hex: String,
) {
    let request = read_http_request(&mut stream);
    if request.is_empty() {
        return;
    }
    let first_line = request.lines().next().unwrap_or("");

    if first_line.starts_with("GET /pool/template") {
        let template = state.template.lock().unwrap().clone();
        let response = match template {
            Some(t) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{{\"block_height\":{},\"previous_block_hash\":\"{}\",\"merkle_root\":\"{}\",\"pool_difficulty_bits\":{},\"pool_address\":\"{}\"}}\r\n",
                t.block_height,
                hex::encode(&t.previous_block_hash),
                hex::encode(&t.merkle_root),
                t.pool_difficulty_bits,
                pool_pk_hex
            ),
            None => "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n{\"error\":\"Pool is still starting up, try again shortly.\"}\r\n".to_string(),
        };
        let _ = stream.write_all(response.as_bytes());

    } else if first_line.starts_with("POST /pool/submit") {
        let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
        // Only well-formed addresses may earn shares (a bad string would otherwise dilute everyone's payout).
        let contributor_hex = extract_json_string(body, "miner")
            .filter(|m| m.len() == 3904 && m.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|m| m.to_lowercase());
        let nonce = extract_json_number(body, "nonce");

        let response = match (contributor_hex.clone(), nonce) {
            (Some(contributor_hex), Some(nonce)) => {
                let template = state.template.lock().unwrap().clone();
                match template {
                    Some(t) => {
                        let hash = calculate_pow_hash(
                            1,
                            &t.previous_block_hash,
                            &t.merkle_root,
                            t.block_height,
                            &pool_pk,
                            nonce,
                        );

                        if !meets_difficulty(&hash, t.pool_difficulty_bits) {
                            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n{\"status\":\"rejected\",\"reason\":\"does not meet pool difficulty\"}\r\n".to_string()
                        } else if {
                            let mut template_id = t.block_height.to_le_bytes().to_vec();
                            template_id.extend_from_slice(&t.previous_block_hash);
                            !claim_share(&state.seen_shares, &template_id, nonce)
                        } {
                            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n{\"status\":\"rejected\",\"reason\":\"duplicate share\"}\r\n".to_string()
                        } else {
                            {
                                let mut shares = state.shares.lock().unwrap();
                                *shares.entry(contributor_hex.clone()).or_insert(0) += 1;
                            }

                            let is_real_win = hash_below_target(&hash, &target_from_fine(t.real_difficulty_fp));
                            if is_real_win {
                                println!("[POOL] Real block found via a share from {}! Submitting...", contributor_hex);
                            }

                            // Reply first, THEN handle the (potentially slow)
                            // win submission and payout — no reason to make
                            // the contributing miner's connection wait on that.
                            let reply = if is_real_win {
                                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"status\":\"accepted\",\"note\":\"share credited — also a real block, submitting and processing payouts\"}\r\n".to_string()
                            } else {
                                "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"status\":\"accepted\",\"note\":\"share credited\"}\r\n".to_string()
                            };

                            if is_real_win {
                                let state = state.clone();
                                let node_address = node_address.clone();
                                let pool_pk = pool_pk.clone();
                                let pool_pk_hex = pool_pk_hex.clone();
                                thread::spawn(move || {
                                    submit_win_and_pay_out(&node_address, &state, pool_seed, pool_pk, pool_pk_hex, nonce);
                                });
                            }

                            reply
                        }
                    }
                    None => "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n{\"error\":\"No active template yet.\"}\r\n".to_string(),
                }
            }
            _ => "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n{\"error\":\"Expected JSON: miner, nonce\"}\r\n".to_string(),
        };
        let _ = stream.write_all(response.as_bytes());

    } else if first_line.starts_with("POST /pool/test-trigger-payout") {
        // TEST-ONLY: manually processes whatever shares have genuinely
        // accumulated so far, using the pool's ALREADY-FUNDED real
        // balance — deliberately skips the "submit a winning block" step
        // entirely, since this isn't triggered by an actual qualifying
        // nonce. Exists purely to verify the payout math, signing, and
        // real balance changes work correctly without waiting on genuine
        // 38-bit network odds. Restricted to loopback only — never meant
        // to be reachable by anyone actually connecting as a miner.
        let is_loopback = stream.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false) && !request.to_lowercase().contains("cf-connecting-ip") && !request.to_lowercase().contains("x-forwarded-for");
        if !is_loopback {
            let resp = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nThis endpoint is only reachable from the pool's own machine.\r\n";
            let _ = stream.write_all(resp.as_bytes());
        } else {
            println!("[POOL] TEST TRIGGER — manually processing current accumulated shares.");
            process_payouts(&node_address, &state, pool_seed, pool_pk, pool_pk_hex, true);
            let resp = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"status\":\"triggered\"}\r\n";
            let _ = stream.write_all(resp.as_bytes());
        }

    } else if first_line.starts_with("POST /pool/repay") {
        // ONE-SHOT, local only: replays a lost payout from repay.txt (lines of
        // "address,shares"), using the pool's real current balance and the same
        // proportional formula as process_payouts. repay.txt is renamed to
        // repay_done.txt before anything is sent, so it cannot run twice.
        let req_lower = request.to_lowercase();
        let local_only = stream.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false)
            && !req_lower.contains("cf-connecting-ip") && !req_lower.contains("x-forwarded-for");
        let resp = if !local_only {
            "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nLocal machine only.\r\n".to_string()
        } else {
            repay_from_file(&node_address, pool_seed, &pool_pk, &pool_pk_hex)
        };
        let _ = stream.write_all(resp.as_bytes());

    } else if first_line.starts_with("GET /pool/payments/recent") {
        // Latest payout rounds + top earners, read from the chain (see refresh_payments).
        let body = {
            let rows = state.payments.lock().unwrap();
            let updated = *state.payments_updated.lock().unwrap();
            build_recent_payments_json(&rows, updated)
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}\r\n",
            body
        );
        let _ = stream.write_all(resp.as_bytes());

    } else if first_line.starts_with("GET /pool/payments/round") || first_line.starts_with("GET /pool/payments/older") {
        // Round lookup by block number (?block=N) or paging backwards (?before=N).
        let is_lookup = first_line.starts_with("GET /pool/payments/round");
        let key = if is_lookup { "block" } else { "before" };
        let resp = match query_param(first_line, key).and_then(|v| v.parse::<u64>().ok()) {
            Some(n) => {
                let rows = state.payments.lock().unwrap();
                let body = if is_lookup {
                    build_rounds_json(&rows, Some(n), None, 1)
                } else {
                    build_rounds_json(&rows, None, Some(n), 10)
                };
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}\r\n",
                    body
                )
            }
            None => format!(
                "HTTP/1.1 400 Bad Request\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"error\":\"Expected ?{}= with a block number.\"}}\r\n",
                key
            ),
        };
        let _ = stream.write_all(resp.as_bytes());

    } else if first_line.starts_with("GET /pool/payments") {
        // Everything one address has been paid by the pool.
        let resp = match payments_query_address(first_line) {
            Some(addr) if addr.len() == 3904 => {
                let rows = state.payments.lock().unwrap();
                match build_address_payments_json(&rows, &addr) {
                    Some(b) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}\r\n",
                        b
                    ),
                    None => "HTTP/1.1 400 Bad Request\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Address must be hex.\"}\r\n".to_string(),
                }
            }
            _ => "HTTP/1.1 400 Bad Request\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{\"error\":\"Expected ?address= with a full 3904-character hex address.\"}\r\n".to_string(),
        };
        let _ = stream.write_all(resp.as_bytes());

    } else if first_line.starts_with("GET /pool/stats") {
        // Real, live data for a dashboard — current round info, a live
        // leaderboard with genuine hashrate estimates, and permanent
        // all-time totals plus recent payout history.
        let template = state.template.lock().unwrap().clone();
        let shares = state.shares.lock().unwrap().clone();
        let history = state.payout_history.lock().unwrap().clone();
        let round_start = *state.round_start_time.lock().unwrap();
        let all_time_blocks = *state.all_time_blocks_found.lock().unwrap();
        let all_time_ql = *state.all_time_ql_distributed.lock().unwrap();

        // Real, current balance the pool is actually holding right now —
        // whatever's sitting here is genuinely awaiting the next
        // distribution, whether triggered by a real win or a manual round.
        let pending_balance_ql: f64 = match http_get(&node_address, &format!("/api/balance?address={}", pool_pk_hex)) {
            Some(resp) => {
                let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
                extract_json_float(body, "balance_ql").unwrap_or(0.0)
            }
            None => 0.0,
        };
        let all_time_manual = *state.all_time_manual_rewards.lock().unwrap();

        let elapsed_secs = (chrono::Utc::now().timestamp() - round_start).max(1) as f64;
        let pool_difficulty_bits = template.as_ref().map(|t| t.pool_difficulty_bits).unwrap_or(20);
        // A share found at difficulty D took, on average, 2^D hash
        // attempts — real, standard math used by every real mining pool
        // to estimate contributor hashrate from observed share rate,
        // not a guess dressed up as data.
        let hashes_per_share = 2f64.powi(pool_difficulty_bits as i32);

        let mut standings: Vec<(String, u64)> = shares.into_iter().collect();
        standings.sort_by(|a, b| b.1.cmp(&a.1));
        let total_shares_this_round: u64 = standings.iter().map(|(_, c)| c).sum();
        let pool_hashrate = (total_shares_this_round as f64 * hashes_per_share) / elapsed_secs;

        let standings_json: Vec<String> = standings.iter().map(|(addr, count)| {
            let hashrate = (*count as f64 * hashes_per_share) / elapsed_secs;
            format!(
                "{{\"address\":\"{}\",\"shares\":{},\"estimated_hashrate\":{:.0}}}",
                addr, count, hashrate
            )
        }).collect();

        let history_json: Vec<String> = history.iter().rev().map(|r| {
            format!(
                "{{\"timestamp\":{},\"total_paid_ql\":{:.4},\"contributor_count\":{},\"is_manual\":{}}}",
                r.timestamp, r.total_paid_ql, r.contributor_count, r.is_manual
            )
        }).collect();

        let round_json = match template {
            Some(t) => format!(
                "{{\"block_height\":{},\"real_difficulty_bits\":{},\"pool_difficulty_bits\":{}}}",
                t.block_height, t.real_difficulty_bits, t.pool_difficulty_bits
            ),
            None => "null".to_string(),
        };

        let json_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"pool_address\":\"{}\",\"round\":{},\"pool_hashrate\":{:.0},\"all_time_blocks_found\":{},\"all_time_manual_rewards\":{},\"all_time_ql_distributed\":{:.4},\"pending_balance_ql\":{:.4},\"standings\":[{}],\"recent_payouts\":[{}]}}\r\n",
            pool_pk_hex,
            round_json,
            pool_hashrate,
            all_time_blocks,
            all_time_manual,
            all_time_ql,
            pending_balance_ql,
            standings_json.join(","),
            history_json.join(",")
        );
        let _ = stream.write_all(json_response.as_bytes());

    } else {
        let html_content = fs::read_to_string("pool_dashboard.html")
            .unwrap_or_else(|_| "<h1>pool_dashboard.html missing</h1>".to_string());
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
            html_content.len(),
            html_content
        );
        let _ = stream.write_all(http_response.as_bytes());
    }
}

// ---------------------------------------------------------------------
// Refreshing the real template, detecting genuine wins, and paying out
// ---------------------------------------------------------------------

/// How much easier the pool's own difficulty is than the real network
/// target — fewer required leading zero bits means shares come in far
/// more often, giving contributors frequent, meaningful feedback instead
/// of waiting as long as a real solo block would take. 16 bits aims for
/// roughly a 20-30 second average wait for a typical modern CPU — a
/// reasonable one-size-fits-most starting point. A genuinely better long
/// term fix is PER-MINER variable difficulty (adjusting each connected
/// miner's own target based on their individual submission rate), so a
/// high-end machine and a modest laptop both get a similarly steady
/// rhythm — a real, valuable upgrade worth building later, not attempted
/// in this first version.
const POOL_DIFFICULTY_REDUCTION_BITS: u32 = 16;

fn refresh_template(node_address: &str, state: &Arc<SharedState>) {
    let response = match http_get(node_address, "/api/mining/template") {
        Some(r) => r,
        None => {
            println!("[POOL] Could not reach node at {} to refresh template.", node_address);
            return;
        }
    };
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    let block_height = match extract_json_number(body, "block_height") { Some(v) => v, None => return };
    let prev_hash_hex = match extract_json_string(body, "previous_block_hash") { Some(v) => v, None => return };
    let merkle_root_hex = match extract_json_string(body, "merkle_root") { Some(v) => v, None => return };
    let real_difficulty_bits_ceil = extract_json_number(body, "difficulty_bits").unwrap_or(20) as u32;
    // Fine-grained difficulty (65536 = 1 bit). Nodes from before fork 2 don't send it.
    let real_difficulty_fp = extract_json_number(body, "difficulty_fp")
        .map(|v| v as u32)
        .unwrap_or(real_difficulty_bits_ceil << 16);
    let real_difficulty = real_difficulty_fp >> 16;
    let pool_difficulty = real_difficulty.saturating_sub(POOL_DIFFICULTY_REDUCTION_BITS).max(8);

    let previous_block_hash = hex::decode(&prev_hash_hex).unwrap_or_default();
    let merkle_root = hex::decode(&merkle_root_hex).unwrap_or_default();

    let is_new_round = {
        let current = state.template.lock().unwrap();
        current.as_ref().map(|t| t.block_height != block_height).unwrap_or(true)
    };

    *state.template.lock().unwrap() = Some(RoundTemplate {
        block_height,
        previous_block_hash,
        merkle_root,
        real_difficulty_bits: real_difficulty_bits_ceil,
        real_difficulty_fp,
        pool_difficulty_bits: pool_difficulty,
    });

    if is_new_round {
        println!(
            "[{}] [POOL] New round — block {} at real difficulty {:.3} bits (pool difficulty {} bits).",
            now(), block_height, real_difficulty_fp as f64 / 65536.0, pool_difficulty
        );
    }
}

fn submit_win_and_pay_out(node_address: &str, state: &Arc<SharedState>, pool_seed: [u8; 32], pool_pk: Vec<u8>, pool_pk_hex: String, nonce: u64) {
    let submit_body = format!("{{\"miner\":\"{}\",\"nonce\":{}}}", pool_pk_hex, nonce);
    let resp = match http_post(node_address, "/api/mining/submit", &submit_body) {
        Some(r) => r,
        None => { println!("[POOL] Failed to submit the winning block — node unreachable."); return; }
    };
    if !resp.starts_with("HTTP/1.1 200") {
        println!("[POOL] Node rejected our winning submission: {}", resp);
        return;
    }
    println!("[POOL] Real block submitted and accepted! Processing payouts...");
    process_payouts(node_address, state, pool_seed, pool_pk, pool_pk_hex, false);
}

/// Distributes whatever's currently sitting in the pool's real balance,
/// proportional to shares accumulated since the last payout — used both
/// after a genuine real-network win, and by the test-only trigger
/// endpoint (which skips the block-submission step entirely, since
/// there's no real winning nonce to submit in that case).
fn process_payouts(node_address: &str, state: &Arc<SharedState>, pool_seed: [u8; 32], pool_pk: Vec<u8>, pool_pk_hex: String, is_manual: bool) {
    // Snapshot and reset the round's shares atomically, so new shares
    // arriving during payout processing count toward the NEXT round, not
    // this one. Also mark a fresh start time here — this is genuinely
    // when share accumulation restarts, which is what hashrate estimates
    // need to be measured against, not simply when the chain's block
    // height last changed (shares span multiple heights until the pool
    // itself wins).
    let round_shares: HashMap<String, u64> = {
        let mut shares = state.shares.lock().unwrap();
        std::mem::take(&mut *shares)
    };
    *state.round_start_time.lock().unwrap() = chrono::Utc::now().timestamp();
    save_shares_to("pool_shares.txt", state);

    let total_shares: u64 = round_shares.values().sum();
    if total_shares > 0 {
        save_last_round(&round_shares);
    }
    if total_shares == 0 {
        println!("[POOL] No tracked shares this round — nothing to pay out.");
        return;
    }

    // Query the pool's ACTUAL current real balance rather than assuming a
    // fixed block reward — a real bug in an earlier version of this
    // function did exactly that assumption, which could sign a payout
    // for more than the pool genuinely holds. Real block wins credit
    // exactly 48 QL, but this function is also used by the manual test
    // trigger (any real amount) and should work correctly regardless of
    // how the pool's actual balance got there.
    let balance_response = match http_get(node_address, &format!("/api/balance?address={}", pool_pk_hex)) {
        Some(r) => r,
        None => { println!("[POOL] Could not check the pool's own balance — aborting payout."); return; }
    };
    let balance_body = balance_response.split("\r\n\r\n").nth(1).unwrap_or("");
    let available_ql = match extract_json_float(balance_body, "balance_ql") {
        Some(b) => b,
        None => { println!("[POOL] Could not parse the pool's balance — aborting payout."); return; }
    };

    if available_ql <= 0.0 {
        println!("[POOL] Pool balance is 0 — nothing available to pay out yet.");
        return;
    }

    println!("[POOL] Distributing {:.4} QL (the pool's current real balance) across {} contributor(s)...", available_ql, round_shares.len());

    const COIN: f64 = 100_000_000.0; // matches the node's smallest-unit scale
    let contributor_count = round_shares.len();

    for (contributor_hex, share_count) in round_shares {
        let proportion = share_count as f64 / total_shares as f64;
        let payout_ql = available_ql * proportion;
        let payout_smallest = (payout_ql * COIN).round() as u64;
        if payout_smallest == 0 {
            continue;
        }

        let receiver = match hex::decode(&contributor_hex) {
            Ok(bytes) => bytes,
            Err(_) => { println!("[POOL] Skipping payout to invalid address: {}", contributor_hex); continue; }
        };

        let mut message = Vec::with_capacity(pool_pk.len() + receiver.len() + 8);
        message.extend_from_slice(&pool_pk);
        message.extend_from_slice(&receiver);
        message.extend_from_slice(&payout_smallest.to_le_bytes());
        let signature = sign_with_seed(&pool_seed, &message);

        let tx_body = format!(
            "{{\"sender\":\"{}\",\"receiver\":\"{}\",\"amount\":{},\"signature\":\"{}\"}}",
            pool_pk_hex, contributor_hex, payout_smallest, hex::encode(&signature)
        );
        match http_post(node_address, "/api/submit_tx", &tx_body) {
            Some(r) if r.starts_with("HTTP/1.1 200") => {
                println!("[POOL] Paid {:.4} QL to {} ({} shares, {:.1}%)", payout_ql, contributor_hex, share_count, proportion * 100.0);
            }
            _ => {
                println!("[POOL] Failed to queue payout to {} — will need manual follow-up.", contributor_hex);
            }
        }
    }

    // Record real history for the dashboard — bounded so this never grows
    // without limit over a long-running pool.
    {
        let mut history = state.payout_history.lock().unwrap();
        history.push(PayoutRecord {
            timestamp: chrono::Utc::now().timestamp(),
            total_paid_ql: available_ql,
            contributor_count,
            is_manual,
        });
        if history.len() > 15 {
            let excess = history.len() - 15;
            history.drain(0..excess);
        }
    }

    // Permanent, unbounded totals — distinct from the bounded history
    // above, since these should never lose data over the pool's lifetime.
    // Genuine network wins and manually-initiated reward rounds are
    // tracked as two separate, honestly-labeled counters, rather than
    // blended into one number that would overstate real wins.
    if is_manual {
        *state.all_time_manual_rewards.lock().unwrap() += 1;
    } else {
        *state.all_time_blocks_found.lock().unwrap() += 1;
    }
    *state.all_time_ql_distributed.lock().unwrap() += available_ql;

    save_persistent_state(state);
}

fn repay_from_file(node_address: &str, pool_seed: [u8; 32], pool_pk: &[u8], pool_pk_hex: &str) -> String {
    fn http(status: &str, body: &str) -> String {
        format!("HTTP/1.1 {}\r\nConnection: close\r\n\r\n{}\r\n", status, body)
    }
    let content = match fs::read_to_string("repay.txt") {
        Ok(c) => c,
        Err(_) => return http("404 Not Found", "{\"error\":\"no repay.txt\"}"),
    };
    let mut rows: Vec<(String, u64)> = Vec::new();
    for line in content.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') { continue; }
        let mut parts = l.split(',');
        let addr = parts.next().unwrap_or("").trim().to_string();
        let shares = parts.next().unwrap_or("").trim().parse::<u64>();
        if addr.len() != 3904 || hex::decode(&addr).is_err() || shares.is_err() {
            return http("400 Bad Request", "{\"error\":\"bad line in repay.txt\"}");
        }
        rows.push((addr, shares.unwrap()));
    }
    let total: u64 = rows.iter().map(|(_, s)| *s).sum();
    if rows.is_empty() || total == 0 {
        return http("400 Bad Request", "{\"error\":\"repay.txt is empty\"}");
    }
    let balance_response = match http_get(node_address, &format!("/api/balance?address={}", pool_pk_hex)) {
        Some(r) => r,
        None => return http("502 Bad Gateway", "{\"error\":\"node unreachable\"}"),
    };
    let balance_body = balance_response.split("\r\n\r\n").nth(1).unwrap_or("");
    let available_ql = match extract_json_float(balance_body, "balance_ql") {
        Some(b) if b > 0.0 => b,
        _ => return http("400 Bad Request", "{\"error\":\"pool balance is zero or unreadable\"}"),
    };
    // Rename FIRST so a second call can never repeat the payout.
    if fs::rename("repay.txt", "repay_done.txt").is_err() {
        return http("500 Internal Server Error", "{\"error\":\"could not rename repay.txt\"}");
    }
    println!("[POOL] REPAY — distributing {:.4} QL across {} address(es).", available_ql, rows.len());
    const COIN: f64 = 100_000_000.0;
    let mut sent = 0;
    for (addr, shares) in rows.iter() {
        let payout_ql = available_ql * (*shares as f64 / total as f64);
        let payout_smallest = (payout_ql * COIN).round() as u64;
        if payout_smallest == 0 { continue; }
        let receiver = hex::decode(addr).unwrap();
        let mut message = Vec::with_capacity(pool_pk.len() + receiver.len() + 8);
        message.extend_from_slice(pool_pk);
        message.extend_from_slice(&receiver);
        message.extend_from_slice(&payout_smallest.to_le_bytes());
        let signature = sign_with_seed(&pool_seed, &message);
        let tx_body = format!(
            "{{\"sender\":\"{}\",\"receiver\":\"{}\",\"amount\":{},\"signature\":\"{}\"}}",
            pool_pk_hex, addr, payout_smallest, hex::encode(&signature)
        );
        match http_post(node_address, "/api/submit_tx", &tx_body) {
            Some(r) if r.starts_with("HTTP/1.1 200") => {
                sent += 1;
                println!("[POOL] REPAY — queued {:.4} QL to {}", payout_ql, addr);
            }
            _ => println!("[POOL] REPAY — FAILED to queue {:.4} QL to {}", payout_ql, addr),
        }
    }
    http("200 OK", &format!("{{\"status\":\"done\",\"queued\":{}}}", sent))
}

// ---------------------------------------------------------------------
// On-chain payout history. The pool's payouts are ordinary transactions
// SENT by the pool address, so the node already has the complete record.
// The pool re-reads it every couple of minutes and serves two views:
//   GET /pool/payments/recent          latest payout rounds, who got what, top earners
//   GET /pool/payments?address=HEX     everything one address has been paid
//   GET /pool/payments/round?block=N   the payout round recorded in block N
//   GET /pool/payments/older?before=N  the 10 payout rounds before block N
// Nothing here is stored on disk: it is rebuilt from the chain, so it
// includes every past payout (manual rounds and repayments too) and cannot
// drift from the real ledger. Addresses are kept as a short label plus a
// SHA3 hash (for lookups), so memory stays small however long the history.
// ---------------------------------------------------------------------

#[derive(Clone)]
struct Payment {
    block_height: u64,
    timestamp: i64,
    receiver_hash: [u8; 32],
    receiver_short: String,
    amount_ql: f64,
}

fn short_hex(h: &str) -> String {
    if h.len() <= 28 {
        h.to_string()
    } else {
        format!("{}...{}", &h[..16], &h[h.len() - 8..])
    }
}

fn address_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

/// Parses the node's /api/transactions response body, keeping only payments
/// the pool SENT. Newest first, as the node returns them.
fn parse_payments(body: &str) -> Vec<Payment> {
    let starts: Vec<usize> = body.match_indices("{\"direction\":").map(|(i, _)| i).collect();
    let mut rows: Vec<Payment> = Vec::new();
    for (n, &s) in starts.iter().enumerate() {
        let e = if n + 1 < starts.len() { starts[n + 1] } else { body.len() };
        let seg = &body[s..e];
        if extract_json_string(seg, "direction").as_deref() != Some("sent") {
            continue;
        }
        let counterparty = match extract_json_string(seg, "counterparty") {
            Some(c) => c,
            None => continue,
        };
        let bytes = match hex::decode(&counterparty) {
            Ok(b) => b,
            Err(_) => continue,
        };
        rows.push(Payment {
            block_height: extract_json_number(seg, "block_height").unwrap_or(0),
            timestamp: extract_json_number(seg, "timestamp").unwrap_or(0) as i64,
            receiver_hash: address_hash(&bytes),
            receiver_short: short_hex(&counterparty),
            amount_ql: extract_json_float(seg, "amount_ql").unwrap_or(0.0),
        });
    }
    // stable sort: newest block first, rows of one block stay together
    rows.sort_by(|a, b| b.block_height.cmp(&a.block_height));
    rows
}

fn refresh_payments(node_address: &str, pool_pk_hex: &str, state: &Arc<SharedState>) {
    let resp = match http_get(node_address, &format!("/api/transactions?address={}", pool_pk_hex)) {
        Some(r) => r,
        None => {
            println!("[POOL] Could not reach node to refresh payout history.");
            return;
        }
    };
    if !resp.starts_with("HTTP/1.1 200") {
        println!("[POOL] Node did not return payout history (non-200) — keeping the previous copy.");
        return;
    }
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    let rows = parse_payments(body);
    let count = rows.len();
    *state.payments.lock().unwrap() = rows;
    *state.payments_updated.lock().unwrap() = chrono::Utc::now().timestamp();
    println!("[{}] [POOL] Payout history refreshed from chain: {} payment(s).", now(), count);
}

/// Latest payout rounds (one round = all payments in one block), with who got
/// what, plus all-time totals and the top earners.
fn build_recent_payments_json(rows: &[Payment], updated: i64) -> String {
    let mut rounds: Vec<(u64, i64, f64, Vec<(&str, f64)>)> = Vec::new();
    for r in rows {
        let new_round = match rounds.last() {
            Some(l) => l.0 != r.block_height,
            None => true,
        };
        if new_round {
            if rounds.len() >= 10 {
                break;
            }
            rounds.push((r.block_height, r.timestamp, r.amount_ql, vec![(r.receiver_short.as_str(), r.amount_ql)]));
        } else {
            let l = rounds.last_mut().unwrap();
            l.2 += r.amount_ql;
            l.3.push((r.receiver_short.as_str(), r.amount_ql));
        }
    }

    let mut total_paid = 0.0f64;
    let mut total_rounds = 0u64;
    let mut last_block: Option<u64> = None;
    let mut by_addr: HashMap<[u8; 32], (String, f64, u64)> = HashMap::new();
    for r in rows {
        total_paid += r.amount_ql;
        if last_block != Some(r.block_height) {
            total_rounds += 1;
            last_block = Some(r.block_height);
        }
        let e = by_addr.entry(r.receiver_hash).or_insert((r.receiver_short.clone(), 0.0, 0));
        e.1 += r.amount_ql;
        e.2 += 1;
    }
    let mut top: Vec<(String, f64, u64)> = by_addr.into_values().collect();
    top.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    top.truncate(10);

    let rounds_json: Vec<String> = rounds
        .iter()
        .map(|(bh, ts, total, pays)| {
            let p: Vec<String> = pays
                .iter()
                .map(|(a, amt)| format!("{{\"address\":\"{}\",\"amount_ql\":{:.4}}}", a, amt))
                .collect();
            format!(
                "{{\"block_height\":{},\"timestamp\":{},\"total_ql\":{:.4},\"payments\":[{}]}}",
                bh, ts, total, p.join(",")
            )
        })
        .collect();
    let top_json: Vec<String> = top
        .iter()
        .map(|(a, t, n)| format!("{{\"address\":\"{}\",\"total_ql\":{:.4},\"payments\":{}}}", a, t, n))
        .collect();

    format!(
        "{{\"updated\":{},\"total_payments\":{},\"total_rounds\":{},\"total_paid_ql\":{:.4},\"rounds\":[{}],\"top\":[{}]}}",
        updated, rows.len(), total_rounds, total_paid, rounds_json.join(","), top_json.join(",")
    )
}

/// Everything one address has been paid (newest 200 shown, totals cover all).
fn build_address_payments_json(rows: &[Payment], address_hex: &str) -> Option<String> {
    let bytes = hex::decode(address_hex).ok()?;
    let target = address_hash(&bytes);
    let mut total = 0.0f64;
    let mut count = 0u64;
    let mut items: Vec<String> = Vec::new();
    for r in rows.iter().filter(|r| r.receiver_hash == target) {
        total += r.amount_ql;
        count += 1;
        if items.len() < 200 {
            items.push(format!(
                "{{\"block_height\":{},\"timestamp\":{},\"amount_ql\":{:.4}}}",
                r.block_height, r.timestamp, r.amount_ql
            ));
        }
    }
    Some(format!(
        "{{\"count\":{},\"total_ql\":{:.4},\"payments\":[{}]}}",
        count, total, items.join(",")
    ))
}

fn query_param(first_line: &str, key: &str) -> Option<String> {
    let path = first_line.split_whitespace().nth(1)?;
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        if kv.next()? == key {
            return Some(kv.next().unwrap_or("").trim().to_string());
        }
    }
    None
}

/// Payout rounds, newest first. `block` keeps only that block; `before` keeps only
/// blocks older than it; at most `limit` rounds. "more" says whether older ones exist.
fn build_rounds_json(rows: &[Payment], block: Option<u64>, before: Option<u64>, limit: usize) -> String {
    let mut rounds: Vec<(u64, i64, f64, Vec<(&str, f64)>)> = Vec::new();
    let mut more = false;
    for r in rows {
        if let Some(b) = block {
            if r.block_height != b {
                continue;
            }
        }
        if let Some(b) = before {
            if r.block_height >= b {
                continue;
            }
        }
        let new_round = match rounds.last() {
            Some(l) => l.0 != r.block_height,
            None => true,
        };
        if new_round {
            if rounds.len() >= limit {
                more = true;
                break;
            }
            rounds.push((r.block_height, r.timestamp, r.amount_ql, vec![(r.receiver_short.as_str(), r.amount_ql)]));
        } else {
            let l = rounds.last_mut().unwrap();
            l.2 += r.amount_ql;
            l.3.push((r.receiver_short.as_str(), r.amount_ql));
        }
    }
    let items: Vec<String> = rounds
        .iter()
        .map(|(bh, ts, total, pays)| {
            let p: Vec<String> = pays
                .iter()
                .map(|(a, amt)| format!("{{\"address\":\"{}\",\"amount_ql\":{:.4}}}", a, amt))
                .collect();
            format!(
                "{{\"block_height\":{},\"timestamp\":{},\"total_ql\":{:.4},\"payments\":[{}]}}",
                bh, ts, total, p.join(",")
            )
        })
        .collect();
    format!("{{\"rounds\":[{}],\"more\":{}}}", items.join(","), more)
}

fn payments_query_address(first_line: &str) -> Option<String> {
    let path = first_line.split_whitespace().nth(1)?;
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        if kv.next()? == "address" {
            return Some(kv.next().unwrap_or("").trim().to_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod payments_tests {
    use super::*;

    fn addr(c: char) -> String {
        std::iter::repeat(c).take(3904).collect()
    }

    // Same shape the node's /api/transactions returns (newest first).
    fn sample_body() -> String {
        let a = addr('a');
        let b = addr('b');
        let pool = addr('c');
        format!(
            "{{\"address\":\"{p}\",\"transactions\":[\
{{\"direction\":\"sent\",\"counterparty\":\"{b}\",\"amount_ql\":16.00000000,\"block_height\":300,\"timestamp\":3000}},\
{{\"direction\":\"sent\",\"counterparty\":\"{a}\",\"amount_ql\":32.00000000,\"block_height\":300,\"timestamp\":3000}},\
{{\"direction\":\"received\",\"counterparty\":\"{b}\",\"amount_ql\":5.00000000,\"block_height\":250,\"timestamp\":2500}},\
{{\"direction\":\"sent\",\"counterparty\":\"{a}\",\"amount_ql\":8.50000000,\"block_height\":200,\"timestamp\":2000}}\
]}}",
            p = pool, a = a, b = b
        )
    }

    #[test]
    fn parses_only_sent_payments() {
        let rows = parse_payments(&sample_body());
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].block_height, 300);
        assert_eq!(rows[2].block_height, 200);
        assert!((rows[1].amount_ql - 32.0).abs() < 1e-9);
        assert_eq!(rows[1].receiver_short, short_hex(&addr('a')));
    }

    #[test]
    fn recent_groups_rounds_and_totals() {
        let rows = parse_payments(&sample_body());
        let j = build_recent_payments_json(&rows, 12345);
        assert!(j.contains("\"total_payments\":3"));
        assert!(j.contains("\"total_rounds\":2"));
        assert!(j.contains("\"total_paid_ql\":56.5000"));
        // first round = block 300 = 48 QL across two payments
        assert!(j.contains("\"block_height\":300,\"timestamp\":3000,\"total_ql\":48.0000"));
        // top earner is address 'a' (32 + 8.5)
        assert!(j.contains(&format!("\"address\":\"{}\",\"total_ql\":40.5000,\"payments\":2", short_hex(&addr('a')))));
    }

    #[test]
    fn address_lookup() {
        let rows = parse_payments(&sample_body());
        let j = build_address_payments_json(&rows, &addr('a')).unwrap();
        assert!(j.contains("\"count\":2"));
        assert!(j.contains("\"total_ql\":40.5000"));
        let none = build_address_payments_json(&rows, &addr('d')).unwrap();
        assert!(none.contains("\"count\":0"));
        assert!(build_address_payments_json(&rows, "zz").is_none());
    }

    #[test]
    fn query_parsing() {
        let l = "GET /pool/payments?address=ABCD1234 HTTP/1.1";
        assert_eq!(query_param("GET /pool/payments/round?block=77 HTTP/1.1", "block"), Some("77".to_string()));
        assert_eq!(query_param("GET /pool/payments/round HTTP/1.1", "block"), None);
        assert_eq!(payments_query_address(l).unwrap(), "abcd1234");
        assert!(payments_query_address("GET /pool/payments HTTP/1.1").is_none());
    }
}

// ---------------------------------------------------------------------
// Round-share protection. The shares of the current round used to live only
// in memory, so restarting the pool wiped everyone's progress since the last
// win. Now:
//   pool_shares.txt         live snapshot, rewritten every 20 seconds and
//                           reloaded on start (a restart loses at most 20s)
//   last_round_shares.txt   written just before each payout, in the exact
//                           "address,shares" format repay.txt uses, so a lost
//                           payout can be replayed with no hand-building
// ---------------------------------------------------------------------

fn shares_file_contents(shares: &HashMap<String, u64>, round_start: i64) -> String {
    let mut content = format!("round_start={}\n", round_start);
    for (addr, count) in shares.iter() {
        // only well-formed addresses are ever written (keeps the file unambiguous)
        if addr.bytes().all(|b| b.is_ascii_hexdigit()) {
            content.push_str(&format!("{},{}\n", addr, count));
        }
    }
    content
}

fn parse_shares_file(content: &str) -> (HashMap<String, u64>, Option<i64>) {
    let mut map: HashMap<String, u64> = HashMap::new();
    let mut round_start: Option<i64> = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("round_start=") {
            round_start = rest.trim().parse::<i64>().ok();
        } else if let Some((addr, n)) = line.split_once(',') {
            let addr = addr.trim();
            if let Ok(c) = n.trim().parse::<u64>() {
                if !addr.is_empty() && addr.bytes().all(|b| b.is_ascii_hexdigit()) {
                    map.insert(addr.to_lowercase(), c);
                }
            }
        }
    }
    (map, round_start)
}

fn write_atomic(path: &str, content: &str) -> bool {
    let tmp = format!("{}.tmp", path);
    if std::fs::write(&tmp, content).is_err() {
        return false;
    }
    std::fs::rename(&tmp, path).is_ok()
}

static SAVE_LOCK: Mutex<()> = Mutex::new(());

fn save_shares_to(path: &str, state: &Arc<SharedState>) {
    // Held across the read AND the write, so the 20-second saver and the
    // payout saver can never interleave and leave an out-of-date file behind.
    let _guard = SAVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let shares = state.shares.lock().unwrap().clone();
    let round_start = *state.round_start_time.lock().unwrap();
    if !write_atomic(path, &shares_file_contents(&shares, round_start)) {
        println!("[POOL] Warning: could not save round shares to {}.", path);
    }
}

fn load_shares_from(path: &str, state: &Arc<SharedState>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            println!("[POOL] No saved round shares found — starting this round empty.");
            return;
        }
    };
    let (map, round_start) = parse_shares_file(&content);
    let total: u64 = map.values().sum();
    println!(
        "[POOL] Restored this round's shares from {}: {} contributor(s), {} share(s).",
        path, map.len(), total
    );
    *state.shares.lock().unwrap() = map;
    if let Some(rs) = round_start {
        *state.round_start_time.lock().unwrap() = rs;
    }
}

/// Written just before a payout is processed — same format as repay.txt.
fn save_last_round(round_shares: &HashMap<String, u64>) {
    let mut content = String::new();
    for (addr, count) in round_shares.iter() {
        content.push_str(&format!("{},{}\n", addr, count));
    }
    if !write_atomic("last_round_shares.txt", &content) {
        println!("[POOL] Warning: could not write last_round_shares.txt.");
    }
}

#[cfg(test)]
impl SharedState {
    fn for_tests() -> Self {
        SharedState {
            template: Mutex::new(None),
            shares: Mutex::new(HashMap::new()),
            payout_history: Mutex::new(Vec::new()),
            round_start_time: Mutex::new(0),
            all_time_blocks_found: Mutex::new(0),
            all_time_ql_distributed: Mutex::new(0.0),
            all_time_manual_rewards: Mutex::new(0),
            payments: Mutex::new(Vec::new()),
            payments_updated: Mutex::new(0),
            seen_shares: Mutex::new((Vec::new(), HashSet::new())),
        }
    }
}

#[cfg(test)]
mod duplicate_share_tests {
    use super::*;

    #[test]
    fn a_share_counts_once_per_template() {
        let seen = Mutex::new((Vec::new(), HashSet::new()));
        assert!(claim_share(&seen, b"tpl-1", 42));
        assert!(!claim_share(&seen, b"tpl-1", 42), "replay must be refused");
        assert!(claim_share(&seen, b"tpl-1", 43), "a different nonce is fine");
        // new template: the same nonce is a different share again
        assert!(claim_share(&seen, b"tpl-2", 42));
        assert!(!claim_share(&seen, b"tpl-2", 42));
    }
}

#[cfg(test)]
mod shares_tests {
    use super::*;

    fn addr(c: char) -> String {
        std::iter::repeat(c).take(3904).collect()
    }

    #[test]
    fn round_trip_in_memory() {
        let mut m = HashMap::new();
        m.insert(addr('a'), 80157u64);
        m.insert(addr('b'), 33698u64);
        let text = shares_file_contents(&m, 1_700_000_000);
        let (back, rs) = parse_shares_file(&text);
        assert_eq!(back, m);
        assert_eq!(rs, Some(1_700_000_000));
    }

    #[test]
    fn junk_and_injection_are_ignored() {
        let mut m = HashMap::new();
        m.insert("zz\nround_start=0".to_string(), 5u64); // not hex -> never written
        m.insert(addr('c'), 7u64);
        let text = shares_file_contents(&m, 42);
        let (back, rs) = parse_shares_file(&text);
        assert_eq!(back.len(), 1);
        assert_eq!(rs, Some(42));
        // garbage lines in a hand-edited file are skipped, not fatal
        let (b2, _) = parse_shares_file("round_start=9\nnot a line\nabc,notanumber\nAB12,3\n,4\n");
        assert_eq!(b2.get("ab12"), Some(&3u64));
        assert_eq!(b2.len(), 1);
    }

    #[test]
    fn file_round_trip() {
        let path = std::env::temp_dir().join(format!("ql_pool_shares_test_{}.txt", std::process::id()));
        let path = path.to_string_lossy().to_string();
        let state = Arc::new(SharedState::for_tests());
        state.shares.lock().unwrap().insert(addr('d'), 11);
        *state.round_start_time.lock().unwrap() = 777;
        save_shares_to(&path, &state);
        state.shares.lock().unwrap().clear();
        *state.round_start_time.lock().unwrap() = 1;
        load_shares_from(&path, &state);
        assert_eq!(state.shares.lock().unwrap().get(&addr('d')), Some(&11u64));
        assert_eq!(*state.round_start_time.lock().unwrap(), 777);
        let _ = std::fs::remove_file(&path);
    }
}

/// True the first time a nonce is seen for a given template, false for any repeat.
/// The set is cleared whenever the template (block height + previous hash) changes.
fn claim_share(seen: &Mutex<(Vec<u8>, HashSet<u64>)>, template_id: &[u8], nonce: u64) -> bool {
    let mut guard = seen.lock().unwrap_or_else(|e| e.into_inner());
    if guard.0 != template_id {
        guard.0 = template_id.to_vec();
        guard.1.clear();
    }
    guard.1.insert(nonce)
}

fn print_usage_and_exit() -> ! {
    eprintln!("=== QUANTUM-LATTICE (QL) MINING POOL ===");
    eprintln!();
    eprintln!("Usage: pool NODE_ADDRESS:PORT POOL_LISTEN_PORT");
    eprintln!();
    eprintln!("  NODE_ADDRESS:PORT   The real QL node this pool mines against.");
    eprintln!("  POOL_LISTEN_PORT    The local port miners connect to, e.g. 7999");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  pool quantum-lattice.futuristicai.co.za:8034 7999");
    std::process::exit(1);
}

/// Loads the pool's permanent stats from disk, if a save file exists —
/// without this, "all-time" data would only ever live in memory and
/// silently reset to zero on every restart, which would be misleading
/// given the dashboard explicitly labels these numbers as permanent.
fn load_persistent_state(state: &Arc<SharedState>) {
    let content = match std::fs::read_to_string("pool_state.txt") {
        Ok(c) => c,
        Err(_) => { println!("[POOL] No saved state file found — starting fresh all-time stats."); return; }
    };

    let mut history: Vec<PayoutRecord> = Vec::new();
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("all_time_blocks_found=") {
            if let Ok(v) = rest.trim().parse::<u64>() {
                *state.all_time_blocks_found.lock().unwrap() = v;
            }
        } else if let Some(rest) = line.strip_prefix("all_time_manual_rewards=") {
            if let Ok(v) = rest.trim().parse::<u64>() {
                *state.all_time_manual_rewards.lock().unwrap() = v;
            }
        } else if let Some(rest) = line.strip_prefix("all_time_ql_distributed=") {
            if let Ok(v) = rest.trim().parse::<f64>() {
                *state.all_time_ql_distributed.lock().unwrap() = v;
            }
        } else if let Some(rest) = line.strip_prefix("payout|") {
            let parts: Vec<&str> = rest.split('|').collect();
            if parts.len() == 4 {
                if let (Ok(timestamp), Ok(total_paid_ql), Ok(contributor_count), Ok(is_manual)) = (
                    parts[0].parse::<i64>(),
                    parts[1].parse::<f64>(),
                    parts[2].parse::<usize>(),
                    parts[3].parse::<bool>(),
                ) {
                    history.push(PayoutRecord { timestamp, total_paid_ql, contributor_count, is_manual });
                }
            }
        }
    }

    if !history.is_empty() {
        *state.payout_history.lock().unwrap() = history;
    }
    println!("[POOL] Restored saved all-time stats from pool_state.txt.");
}

/// Saves the pool's permanent stats to disk — called after every real
/// distribution, so this data genuinely survives a restart rather than
/// only existing in memory.
fn save_persistent_state(state: &Arc<SharedState>) {
    let blocks = *state.all_time_blocks_found.lock().unwrap();
    let manual = *state.all_time_manual_rewards.lock().unwrap();
    let distributed = *state.all_time_ql_distributed.lock().unwrap();
    let history = state.payout_history.lock().unwrap().clone();

    let mut content = format!(
        "all_time_blocks_found={}\nall_time_manual_rewards={}\nall_time_ql_distributed={:.4}\n",
        blocks, manual, distributed
    );
    for record in history.iter() {
        content.push_str(&format!(
            "payout|{}|{:.4}|{}|{}\n",
            record.timestamp, record.total_paid_ql, record.contributor_count, record.is_manual
        ));
    }

    if let Err(e) = std::fs::write("pool_state.txt", content) {
        println!("[POOL] Warning: could not save persistent state to disk: {}", e);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        print_usage_and_exit();
    }
    let node_address = args[1].clone();
    let listen_port: u16 = args[2].parse().unwrap_or_else(|_| print_usage_and_exit());

    println!("=== QUANTUM-LATTICE (QL) MINING POOL ===");
    let (pool_seed, pool_pk) = unlock_or_create_pool_identity();
    let pool_pk_hex = hex::encode(&pool_pk);
    println!("[POOL] Pool identity ready. Address: {}", pool_pk_hex);
    println!("[POOL] Mining against node: {}", node_address);

    let state = Arc::new(SharedState {
        template: Mutex::new(None),
        shares: Mutex::new(HashMap::new()),
        payout_history: Mutex::new(Vec::new()),
        round_start_time: Mutex::new(chrono::Utc::now().timestamp()),
        all_time_blocks_found: Mutex::new(0),
        all_time_ql_distributed: Mutex::new(0.0),
        all_time_manual_rewards: Mutex::new(0),
        payments: Mutex::new(Vec::new()),
        payments_updated: Mutex::new(0),
        seen_shares: Mutex::new((Vec::new(), HashSet::new())),
    });
    load_persistent_state(&state);
    load_shares_from("pool_shares.txt", &state);

    // Background thread: keeps the shared template current by periodically
    // re-fetching from the real node. The pool itself never grinds nonces —
    // same as real-world pools generally work, all the actual hashing comes
    // from connected miners; the pool's job is purely coordinating and
    // validating their submitted shares.
    {
        let state = state.clone();
        let node_address = node_address.clone();
        thread::spawn(move || {
            loop {
                refresh_template(&node_address, &state);
                thread::sleep(Duration::from_secs(5));
            }
        });
    }

    // Background thread: snapshots this round's shares every 20 seconds.
    {
        let state = state.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(20));
                save_shares_to("pool_shares.txt", &state);
            }
        });
    }

    // Background thread: re-reads the pool's own payout history from the chain.
    {
        let state = state.clone();
        let node_address = node_address.clone();
        let pool_pk_hex = pool_pk_hex.clone();
        thread::spawn(move || {
            loop {
                refresh_payments(&node_address, &pool_pk_hex, &state);
                thread::sleep(Duration::from_secs(120));
            }
        });
    }

    let listener = TcpListener::bind(format!("0.0.0.0:{}", listen_port))
        .unwrap_or_else(|e| { eprintln!("[POOL] Could not bind to port {}: {}", listen_port, e); std::process::exit(1); });
    println!("[POOL] Listening for connected miners on port {}.", listen_port);
    println!("[POOL] Miners should point at this address using pool mode.");

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let state = state.clone();
            let node_address = node_address.clone();
            let pool_seed_clone = pool_seed;
            let pool_pk_clone = pool_pk.clone();
            let pool_pk_hex_clone = pool_pk_hex.clone();
            thread::spawn(move || {
                handle_miner_connection(stream, state, node_address, pool_seed_clone, pool_pk_clone, pool_pk_hex_clone);
            });
        }
    }
}
