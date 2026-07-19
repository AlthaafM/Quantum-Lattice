// Quantum-Lattice (QL) mining client — standalone project.
//
// Deliberately kept as its own separate, minimal Cargo project rather than
// living inside the main node's codebase. The node depends on RocksDB (a
// full C++ database), which needs real build tooling (CMake, a C++
// compiler, and on Windows specifically, Visual Studio Build Tools) to
// compile from source. This miner never touches the database at all, so
// keeping it separate means anyone building it — especially on Windows —
// only needs a plain Rust toolchain, nothing else.
//
// Connects over plain HTTP to a raw IP address or "localhost" (for local
// testing, matching how this has always worked) — and over real HTTPS,
// via a pure-Rust TLS stack (rustls, not native-tls/OpenSSL — keeping the
// whole point of this being a lightweight, no-C-toolchain build), to any
// real domain name. Cloudflare Tunnel (and most reverse proxies) only
// accept genuine TLS traffic on port 443, not the internal port a domain
// happens to map to — so a real hostname always connects on 443
// regardless of what port was typed alongside it.
//
// IMPORTANT: calculate_pow_hash below MUST stay byte-for-byte identical to
// BlockHeader::calculate_pow_hash in src/ledger.rs. If one changes without
// the other, mining will silently never succeed — the hashes just won't
// match. This duplication is a real maintenance risk; unifying both under a
// shared library crate is worth doing later, but out of scope for this pass.
//
// This miner does NOT generate its own reward identity. Instead, you give it
// an address you already own — from your QL Wallet — and rewards land there
// directly. No separate mining account, no separate secret key to protect
// or lose, no import step needed afterward: whatever this mines is already
// sitting in a wallet you control.
//
// Usage: cargo run --bin miner -- quantum-lattice.futuristicai.co.za:8034 YOUR_WALLET_ADDRESS_HEX
// Pool:  cargo run --bin miner -- --pool ql-pool.futuristicai.co.za:7999 YOUR_WALLET_ADDRESS_HEX

use sha3::{Digest, Sha3_256};
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::thread;
use std::sync::Arc;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls::pki_types::ServerName;

fn now() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// Wraps either a plain TCP connection (local testing) or a real TLS
/// connection (public domains) behind one type, so the rest of the code
/// (the actual HTTP request/response logic below) never needs to know or
/// care which one it's using.
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

/// Opens a connection to node_address ("host:port" or a bare "host"),
/// choosing plain TCP or real TLS based on whether the host looks like a
/// local address or a real domain name. Returns the connection plus the
/// exact host string to use in the HTTP request's Host header.
fn connect(node_address: &str) -> Option<(Conn, String)> {
    let host = node_address.split(':').next().unwrap_or(node_address).to_string();

    // Without this, a connection that stalls mid-request (a dropped packet
    // on a flaky WiFi connection, for instance) hangs the whole program
    // indefinitely — no crash, no error, just silence — since std's
    // TcpStream has no timeout at all by default.
    const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);

    if is_local_address(&host) {
        // Local/dev testing — unchanged from how this always worked.
        let stream = TcpStream::connect(node_address).ok()?;
        stream.set_read_timeout(Some(NETWORK_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(NETWORK_TIMEOUT)).ok()?;
        Some((Conn::Plain(stream), node_address.to_string()))
    } else {
        // A real domain name — connect on 443 regardless of whatever port
        // was typed alongside it, since that's the only port a public
        // HTTPS-fronted domain actually accepts connections on.
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

fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let key_pos = body.find(&pattern)?;
    let after_key = &body[key_pos + pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    let value_start = after_colon.strip_prefix('"')?;
    let end_quote = value_start.find('"')?;
    Some(value_start[..end_quote].to_string())
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

/// Must exactly match BlockHeader::calculate_pow_hash in src/ledger.rs.
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

/// Must exactly match consensus::meets_difficulty in src/consensus.rs — a
/// bit-based check (not whole bytes), since Phase 6 added real difficulty
/// retargeting which needs finer granularity than 256x jumps.
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

fn print_usage_and_exit() -> ! {
    eprintln!("=== QUANTUM-LATTICE (QL) MINING CLIENT ===");
    eprintln!();
    eprintln!("Usage: miner NODE_ADDRESS:PORT YOUR_WALLET_ADDRESS_HEX [THREAD_COUNT]");
    eprintln!("       miner --pool POOL_ADDRESS:PORT YOUR_WALLET_ADDRESS_HEX [THREAD_COUNT]");
    eprintln!();
    eprintln!("  NODE_ADDRESS:PORT       The QL node to mine against directly, e.g. 127.0.0.1:8034");
    eprintln!("  POOL_ADDRESS:PORT       A mining pool to contribute to instead of mining solo.");
    eprintln!("  YOUR_WALLET_ADDRESS_HEX Your own QL Wallet address (get this from the wallet's");
    eprintln!("                          dashboard) — where solo rewards are paid, or where pool");
    eprintln!("                          payouts are credited.");
    eprintln!("  THREAD_COUNT            Optional. Number of CPU threads to use for mining.");
    eprintln!("                          Defaults to every core available on this machine.");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  miner quantum-lattice.futuristicai.co.za:8034 b8bd5b6d7983d328...5673");
    eprintln!("  miner --pool 127.0.0.1:7999 b8bd5b6d7983d328...5673");
    std::process::exit(1);
}

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        print_usage_and_exit();
    }

    let pool_mode = args[1] == "--pool";
    let (address_index, pk_index, thread_index) = if pool_mode { (2, 3, 4) } else { (1, 2, 3) };
    if args.len() <= pk_index {
        print_usage_and_exit();
    }

    let node_address = args[address_index].clone();
    let miner_pk_hex = args[pk_index].trim();

    let miner_pk = match hex::decode(miner_pk_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("[MINER] That doesn't look like a valid address — it should be hex characters only (0-9, a-f), no spaces.");
            print_usage_and_exit();
        }
    };
    if miner_pk.len() != 1952 {
        eprintln!(
            "[MINER] That address is {} bytes — a QL Wallet address should be exactly 1952 bytes (3904 hex characters). Double-check you copied the whole thing.",
            miner_pk.len()
        );
        print_usage_and_exit();
    }

    // Optional trailing argument to override the thread count — otherwise
    // uses every logical CPU core available.
    let num_threads: usize = args
        .get(thread_index)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));

    println!("=== QUANTUM-LATTICE (QL) MINING CLIENT ===");
    if pool_mode {
        println!("[CONFIG] Contributing to pool: {}", node_address);
        println!("[MINER] Pool payouts will be credited to: {}", hex::encode(&miner_pk));
    } else {
        println!("[CONFIG] Connecting to node: {}", node_address);
        println!("[MINER] Mining rewards will be paid to: {}", hex::encode(&miner_pk));
    }
    println!("[MINER] Using {} CPU thread(s) for mining.", num_threads);

    let miner_pk = Arc::new(miner_pk);
    let template_path = if pool_mode { "/pool/template" } else { "/api/mining/template" };
    let submit_path = if pool_mode { "/pool/submit" } else { "/api/mining/submit" };

    loop {
        let fetch_start = now();
        let response = match http_get(&node_address, template_path) {
            Some(r) => r,
            None => {
                println!("[MINER] Could not reach {} — retrying in 5s...", node_address);
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        let body = response.split("\r\n\r\n").nth(1).unwrap_or("");

        let block_height = match extract_json_number(body, "block_height") {
            Some(h) => h,
            None => { thread::sleep(Duration::from_secs(5)); continue; }
        };
        let prev_hash_hex = match extract_json_string(body, "previous_block_hash") {
            Some(h) => h,
            None => { thread::sleep(Duration::from_secs(5)); continue; }
        };
        let merkle_root_hex = match extract_json_string(body, "merkle_root") {
            Some(h) => h,
            None => { thread::sleep(Duration::from_secs(5)); continue; }
        };

        // In pool mode, the hash MUST be computed using the POOL's own
        // address, not this miner's — the pool is the one whose identity
        // actually goes on-chain if a share also happens to be a real
        // block. This miner's own address is only ever used separately,
        // purely so the pool knows who to credit for the share.
        let (hash_address, difficulty) = if pool_mode {
            let pool_address_hex = match extract_json_string(body, "pool_address") {
                Some(a) => a,
                None => { thread::sleep(Duration::from_secs(5)); continue; }
            };
            let pool_address = match hex::decode(&pool_address_hex) {
                Ok(a) => a,
                Err(_) => { thread::sleep(Duration::from_secs(5)); continue; }
            };
            let pool_difficulty = extract_json_number(body, "pool_difficulty_bits").unwrap_or(16) as u32;
            (Arc::new(pool_address), pool_difficulty)
        } else {
            let real_difficulty = extract_json_number(body, "difficulty_bits").unwrap_or(20) as u32;
            (miner_pk.clone(), real_difficulty)
        };

        let prev_hash = Arc::new(hex::decode(&prev_hash_hex).unwrap_or_default());
        let merkle_root = Arc::new(hex::decode(&merkle_root_hex).unwrap_or_default());

        println!(
            "[{}] [MINER] Got template for block {} (fetch started {}) — mining at {} leading zero bit(s)...",
            now(), block_height, fetch_start, difficulty
        );

        let hash_start = now();
        let timing_start = std::time::Instant::now();
        let found_flag = Arc::new(AtomicBool::new(false));
        let winning_nonce = Arc::new(AtomicU64::new(0));
        let total_tried = Arc::new(AtomicU64::new(0));

        // Each thread mines independently from its own random starting
        // point. With a 64-bit nonce space, the chance of two threads ever
        // meaningfully overlapping is negligible — no need to explicitly
        // partition the range.
        let mut handles = Vec::with_capacity(num_threads);
        for _ in 0..num_threads {
            let found_flag = found_flag.clone();
            let winning_nonce = winning_nonce.clone();
            let total_tried = total_tried.clone();
            let prev_hash = prev_hash.clone();
            let merkle_root = merkle_root.clone();
            let hash_address = hash_address.clone();

            let handle = thread::spawn(move || {
                let mut start_nonce_bytes = [0u8; 8];
                if getrandom::fill(&mut start_nonce_bytes).is_err() {
                    return;
                }
                let mut nonce: u64 = u64::from_le_bytes(start_nonce_bytes);
                let mut local_tried: u64 = 0;

                loop {
                    // Checked once per iteration — cheap relative to the hash
                    // itself, and lets every thread stop promptly once any
                    // one of them finds a valid nonce, instead of each
                    // grinding through its own full batch regardless.
                    if found_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    let hash = calculate_pow_hash(1, &prev_hash, &merkle_root, block_height, &hash_address, nonce);
                    if meets_difficulty(&hash, difficulty) {
                        winning_nonce.store(nonce, Ordering::SeqCst);
                        found_flag.store(true, Ordering::SeqCst);
                        break;
                    }
                    nonce = nonce.wrapping_add(1);
                    local_tried += 1;
                    // Same per-thread batch limit as before, per-thread — so
                    // total work per round scales naturally with core count
                    // rather than staying fixed regardless of hardware.
                    if local_tried % 2_000_000 == 0 {
                        break;
                    }
                }
                total_tried.fetch_add(local_tried, Ordering::Relaxed);
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.join();
        }

        let tried = total_tried.load(Ordering::Relaxed);
        let found = found_flag.load(Ordering::Relaxed);
        let nonce = winning_nonce.load(Ordering::SeqCst);

        let elapsed_secs = timing_start.elapsed().as_secs_f64().max(0.001);
        let hashes_per_sec = tried as f64 / elapsed_secs;
        let hashrate_display = if hashes_per_sec >= 1_000_000.0 {
            format!("{:.2} MH/s", hashes_per_sec / 1_000_000.0)
        } else if hashes_per_sec >= 1_000.0 {
            format!("{:.2} KH/s", hashes_per_sec / 1_000.0)
        } else {
            format!("{:.0} H/s", hashes_per_sec)
        };

        println!(
            "[{}] [MINER] Batch of {} nonces finished across {} thread(s) (started {}) — {} — {}",
            now(), tried, num_threads, hash_start, hashrate_display, if found { "FOUND" } else { "no match, refetching" }
        );

        if !found {
            continue;
        }

        let submit_body = format!(
            "{{\"miner\":\"{}\",\"nonce\":{}}}",
            hex::encode(miner_pk.as_ref()),
            nonce
        );
        match http_post(&node_address, submit_path, &submit_body) {
            Some(resp) => {
                let resp_body = resp.split("\r\n\r\n").nth(1).unwrap_or("").trim();
                if resp.starts_with("HTTP/1.1 200") {
                    if pool_mode {
                        println!("[MINER] Share accepted! {}", resp_body);
                    } else {
                        println!("[MINER] Block accepted! {}", resp_body);
                    }
                } else {
                    let wait_secs = extract_json_number(resp_body, "retry_after_secs").unwrap_or(2);
                    println!(
                        "[MINER] Submission rejected — {} — waiting {}s before retrying.",
                        resp_body, wait_secs
                    );
                    thread::sleep(Duration::from_secs(wait_secs));
                }
            }
            None => println!("[MINER] Failed to submit — unreachable."),
        }
    }
}
