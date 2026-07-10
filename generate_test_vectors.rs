// One-time test vector generator for the "Security & Transparency" page.
//
// Uses a fixed, published seed — meaning anyone can run this exact program
// and get the exact same output, which is the entire point of a test
// vector: independent reproducibility, not just "trust us."
//
// This is NOT part of the running node — just run it once, copy the
// output, and it can be deleted afterward.
//
// Usage: cargo run --bin generate_test_vectors

use ml_dsa::{MlDsa65, Keypair, SigningKey, Signer, Seed, SignatureEncoding};
use sha3::{Digest, Sha3_256};

fn main() {
    println!("=== QUANTUM-LATTICE CRYPTOGRAPHIC TEST VECTORS ===\n");

    // ---- ML-DSA-65 signing ----
    // Fixed, published seed (all zero bytes except a marker) — deterministic
    // and reproducible by anyone, on purpose.
    let seed_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let seed = Seed::from(seed_bytes);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let vk = sk.verifying_key();
    let pub_key_bytes = vk.encode().as_slice().to_vec();

    let message = b"Quantum-Lattice test vector message";
    let signature = sk.sign(message);
    let sig_bytes = signature.to_bytes().as_slice().to_vec();

    println!("--- ML-DSA-65 (FIPS 204) ---");
    println!("Seed (hex): {}", hex::encode(seed_bytes));
    println!("Public key length: {} bytes", pub_key_bytes.len());
    println!("Public key (hex): {}", hex::encode(&pub_key_bytes));
    println!("Message (utf8): {}", String::from_utf8_lossy(message));
    println!("Message (hex): {}", hex::encode(message));
    println!("Signature length: {} bytes", sig_bytes.len());
    println!("Signature (hex): {}", hex::encode(&sig_bytes));

    // ---- SHA3-256 ----
    let mut hasher = Sha3_256::new();
    hasher.update(b"Quantum-Lattice");
    let hash = hasher.finalize();

    println!("\n--- SHA3-256 ---");
    println!("Input (utf8): Quantum-Lattice");
    println!("SHA3-256 (hex): {}", hex::encode(hash));

    // ---- Proof-of-work style hash (matches BlockHeader::calculate_pow_hash) ----
    let version: u32 = 1;
    let previous_block_hash = vec![0u8; 32];
    let merkle_root = vec![0u8; 32];
    let block_height: u64 = 1;
    let nonce: u64 = 12345;

    let mut pow_hasher = Sha3_256::new();
    pow_hasher.update(&version.to_le_bytes());
    pow_hasher.update(&previous_block_hash);
    pow_hasher.update(&merkle_root);
    pow_hasher.update(&block_height.to_le_bytes());
    pow_hasher.update(&pub_key_bytes); // used as the "miner" field here
    pow_hasher.update(&nonce.to_le_bytes());
    let pow_hash = pow_hasher.finalize();

    println!("\n--- Proof-of-Work Hash (same construction as real block mining) ---");
    println!("version: {}", version);
    println!("previous_block_hash (hex): {}", hex::encode(&previous_block_hash));
    println!("merkle_root (hex): {}", hex::encode(&merkle_root));
    println!("block_height: {}", block_height);
    println!("miner (hex): {}", hex::encode(&pub_key_bytes));
    println!("nonce: {}", nonce);
    println!("Resulting hash (hex): {}", hex::encode(pow_hash));
}
