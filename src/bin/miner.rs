// Real Quantum-Lattice mining client.
//
// This is a SEPARATE binary from the node (Cargo automatically builds any
// .rs file under src/bin/ as its own executable). It does NOT link against
// the node's internal modules — it's fully standalone, so it duplicates the
// small pieces of logic it needs rather than sharing code with src/ledger.rs
// and src/consensus.rs.
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
// Usage: cargo run --bin miner -- 127.0.0.1:8034 YOUR_WALLET_ADDRESS_HEX

use sha3::{Digest, Sha3_256};
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::thread;
use chrono::Local;

fn now() -> String {
    Local::now().format("%H:%M:%S").to_string()
}

fn http_get(host_port: &str, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(host_port).ok()?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_port
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

fn http_post(host_port: &str, path: &str, body: &str) -> Option<String> {
    let mut stream = TcpStream::connect(host_port).ok()?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host_port, body.len(), body
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
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
    eprintln!("Usage: miner NODE_ADDRESS:PORT YOUR_WALLET_ADDRESS_HEX");
    eprintln!();
    eprintln!("  NODE_ADDRESS:PORT       The QL node to mine against, e.g. 127.0.0.1:8034");
    eprintln!("  YOUR_WALLET_ADDRESS_HEX Your own QL Wallet address (get this from the wallet's");
    eprintln!("                          dashboard) — this is where mining rewards are paid.");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  miner quantum-lattice.futuristicai.co.za:8034 b8bd5b6d7983d328...5673");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        print_usage_and_exit();
    }
    let node_address = args[1].clone();
    let miner_pk_hex = args[2].trim();

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

    println!("=== QUANTUM-LATTICE (QL) MINING CLIENT ===");
    println!("[CONFIG] Connecting to node: {}", node_address);
    println!("[MINER] Mining rewards will be paid to: {}", hex::encode(&miner_pk));

    loop {
        let fetch_start = now();
        let response = match http_get(&node_address, "/api/mining/template") {
            Some(r) => r,
            None => {
                println!("[MINER] Could not reach node at {} — retrying in 5s...", node_address);
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
        let difficulty = extract_json_number(body, "difficulty_bits").unwrap_or(20) as u32;

        let prev_hash = hex::decode(&prev_hash_hex).unwrap_or_default();
        let merkle_root = hex::decode(&merkle_root_hex).unwrap_or_default();

        println!(
            "[{}] [MINER] Got template for block {} (fetch started {}) — mining at {} leading zero bit(s)...",
            now(), block_height, fetch_start, difficulty
        );

        let hash_start = now();
        let mut start_nonce_bytes = [0u8; 8];
        getrandom::fill(&mut start_nonce_bytes).expect("OS randomness unavailable");
        let mut nonce: u64 = u64::from_le_bytes(start_nonce_bytes);
        let batch_start_nonce = nonce;
        let mut tried: u64 = 0;
        let mut found = false;
        loop {
            let hash = calculate_pow_hash(1, &prev_hash, &merkle_root, block_height, &miner_pk, nonce);
            if meets_difficulty(&hash, difficulty) {
                found = true;
                break;
            }
            nonce = nonce.wrapping_add(1);
            tried += 1;
            // Periodically bail out and refetch the template in case someone
            // else (or our own test tx cycle) already produced this block —
            // otherwise we could grind forever on a stale target. Each batch
            // starts from a fresh random nonce (see above) so a refetch
            // actually explores new search space instead of re-checking the
            // exact same doomed range every time.
            if tried % 2_000_000 == 0 {
                break;
            }
        }
        println!(
            "[{}] [MINER] Batch of {} nonces finished (started {}, from nonce {}) — {}",
            now(), tried, hash_start, batch_start_nonce, if found { "FOUND" } else { "no match, refetching" }
        );

        if !found {
            continue;
        }

        let submit_body = format!(
            "{{\"miner\":\"{}\",\"nonce\":{}}}",
            hex::encode(&miner_pk),
            nonce
        );
        match http_post(&node_address, "/api/mining/submit", &submit_body) {
            Some(resp) => {
                let resp_body = resp.split("\r\n\r\n").nth(1).unwrap_or("").trim();
                if resp.starts_with("HTTP/1.1 200") {
                    println!("[MINER] Block accepted! {}", resp_body);
                } else {
                    let wait_secs = extract_json_number(resp_body, "retry_after_secs").unwrap_or(2);
                    println!(
                        "[MINER] Submission rejected — {} — waiting {}s before retrying.",
                        resp_body, wait_secs
                    );
                    thread::sleep(Duration::from_secs(wait_secs));
                }
            }
            None => println!("[MINER] Failed to submit — node unreachable."),
        }
    }
}
