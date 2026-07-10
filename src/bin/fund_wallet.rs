// Manual funding tool for testing — signs a real transaction from
// Vault A (master_vault_a_secret.key) to any recipient address you give it,
// and submits it straight to a running node.
//
// This is NOT part of the production system — it's a small, standalone
// helper so we can fund test wallets without needing the admin dashboard's
// transfer UI to exist yet.
//
// This binary does NOT link against the main crate's modules (same
// standalone pattern as src/bin/miner.rs) — it duplicates the small piece
// of AES-GCM/PBKDF2 decryption logic it needs, since master_vault_a's
// secret key file is now an encrypted JSON blob, not a raw 32-byte seed.
//
// Usage:
//   cargo run --bin fund_wallet -- 127.0.0.1:8034 <recipient_hex_address> <amount_ql>
//
// Example:
//   cargo run --bin fund_wallet -- 127.0.0.1:8034 3b6663c3...123e 100

use ml_dsa::{MlDsa65, Keypair, SigningKey, Signer, SignatureEncoding};
use serde::{Serialize, Deserialize};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Serialize, Deserialize)]
struct EncryptedVaultFile {
    version: u8,
    kdf: String,
    kdf_iterations: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn decrypt_seed(file: &EncryptedVaultFile, password: &str) -> Result<[u8; 32], String> {
    let salt = hex::decode(&file.salt).map_err(|e| e.to_string())?;
    let nonce_bytes = hex::decode(&file.nonce).map_err(|e| e.to_string())?;
    let ciphertext = hex::decode(&file.ciphertext).map_err(|e| e.to_string())?;

    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, file.kdf_iterations, &mut key_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Incorrect password, or this file is corrupted.".to_string())?;

    plaintext.try_into().map_err(|_| "Decrypted data is not a valid 32-byte seed.".to_string())
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

fn u64_to_le_bytes(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: cargo run --bin fund_wallet -- <node_host:port> <recipient_hex_address> <amount_ql>");
        std::process::exit(1);
    }
    let node_address = &args[1];
    let recipient_hex = &args[2];
    let amount_ql: f64 = args[3].parse().expect("amount_ql must be a number, e.g. 100 or 12.5");

    let amount_smallest: u64 = (amount_ql * 100_000_000.0).round() as u64;

    let sender_pk = fs::read("master_vault_a_public.key").expect(
        "Could not read master_vault_a_public.key — run this from the Quantum-Lattice project folder.",
    );

    let raw = fs::read("master_vault_a_secret.key").expect(
        "Could not read master_vault_a_secret.key — run this from the Quantum-Lattice project folder.",
    );
    let encrypted: EncryptedVaultFile = serde_json::from_slice(&raw).expect(
        "master_vault_a_secret.key doesn't look like an encrypted vault file — is the node's vault encryption feature in place?",
    );

    let password = rpassword::prompt_password("Enter password to unlock Master Vault A: ")
        .expect("failed to read password from terminal");
    let seed_arr = decrypt_seed(&encrypted, &password).unwrap_or_else(|e| {
        eprintln!("[ERROR] {}", e);
        std::process::exit(1);
    });

    let seed = ml_dsa::Seed::from(seed_arr);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);

    // Sanity check: does the seed's derived public key match what's on disk?
    let derived_pk: Vec<u8> = sk.verifying_key().encode().as_slice().to_vec();
    if derived_pk != sender_pk {
        eprintln!("[WARNING] master_vault_a_secret.key does not match master_vault_a_public.key — proceeding anyway, but this is unexpected.");
    }

    let receiver_bytes = hex::decode(recipient_hex).expect("Recipient address is not valid hex.");
    if receiver_bytes.len() != sender_pk.len() {
        eprintln!(
            "[WARNING] Recipient address is {} bytes, expected {} — double check you copied the full address.",
            receiver_bytes.len(),
            sender_pk.len()
        );
    }

    // Message format must match exactly what the node expects:
    // sender_bytes || receiver_bytes || amount_le_bytes(8)
    let mut message = Vec::with_capacity(sender_pk.len() + receiver_bytes.len() + 8);
    message.extend_from_slice(&sender_pk);
    message.extend_from_slice(&receiver_bytes);
    message.extend_from_slice(&u64_to_le_bytes(amount_smallest));

    let signature = sk.sign(&message);
    let signature_bytes = signature.to_bytes();

    let body = format!(
        "{{\"sender\":\"{}\",\"receiver\":\"{}\",\"amount\":{},\"signature\":\"{}\"}}",
        hex::encode(&sender_pk),
        hex::encode(&receiver_bytes),
        amount_smallest,
        hex::encode(signature_bytes.as_slice())
    );

    println!("[FUND] Sending {} QL from Vault A to {}...", amount_ql, recipient_hex);

    match http_post(node_address, "/api/submit_tx", &body) {
        Some(resp) => {
            let resp_body = resp.split("\r\n\r\n").nth(1).unwrap_or("").trim();
            if resp.starts_with("HTTP/1.1 200") {
                println!("[FUND] Accepted into mempool: {}", resp_body);
                println!("[FUND] It will be confirmed once a miner produces the next block.");
            } else {
                println!("[FUND] Node rejected the transaction: {}", resp_body);
            }
        }
        None => println!("[FUND] Could not reach node at {}.", node_address),
    }
}
