// Migrated from pqcrypto-dilithium (pre-standardization Dilithium3, C-based)
// to ml-dsa (pure-Rust, final FIPS 204 ML-DSA-65). This is what makes real
// in-browser WASM signing possible for the wallet — pure Rust compiles to
// wasm32-unknown-unknown cleanly, unlike the old C-based crate.
//
// IMPORTANT: this crate's SigningKey has no "encode/decode" byte blob —
// it's always deterministically derived from a 32-byte Seed via
// SigningKey::from_seed(). That's actually better for us: the real secret
// we persist/encrypt is just 32 bytes, not a multi-kilobyte key blob.
use ml_dsa::{MlDsa65, Keypair, SigningKey, VerifyingKey, Signer, Seed, EncodedVerifyingKey, SignatureEncoding};
use std::fs::File;
use std::io::{Write, Read};
use serde::{Serialize, Deserialize};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

const VAULT_PBKDF2_ITERATIONS: u32 = 300_000;

fn array_to_vec(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    bytes.as_ref().to_vec()
}

fn random_seed() -> Seed {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness unavailable");
    Seed::from(bytes)
}

/// On-disk format for a password-encrypted vault seed. Deliberately mirrors
/// the browser wallet's keystore format (same KDF, same AES-GCM scheme) —
/// same security property, just the server-side equivalent.
#[derive(Serialize, Deserialize)]
pub struct EncryptedVaultFile {
    pub version: u8,
    pub kdf: String,
    pub kdf_iterations: u32,
    pub salt: String,       // hex
    pub nonce: String,      // hex
    pub ciphertext: String, // hex
}

pub fn encrypt_seed(seed_bytes: &[u8; 32], password: &str) -> EncryptedVaultFile {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).expect("OS randomness unavailable");
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).expect("OS randomness unavailable");

    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, VAULT_PBKDF2_ITERATIONS, &mut key_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, seed_bytes.as_ref())
        .expect("vault encryption failed");

    EncryptedVaultFile {
        version: 1,
        kdf: "PBKDF2-SHA256".to_string(),
        kdf_iterations: VAULT_PBKDF2_ITERATIONS,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    }
}

pub fn decrypt_seed(file: &EncryptedVaultFile, password: &str) -> Result<[u8; 32], String> {
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

    plaintext
        .try_into()
        .map_err(|_| "Decrypted data is not a valid 32-byte seed.".to_string())
}

/// Signs a message using an already-decrypted seed held in memory —
/// used for vaults, whose seeds are unlocked once at startup and never
/// re-read from disk afterward.
pub fn sign_with_seed_bytes(seed_bytes: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let seed = Seed::from(*seed_bytes);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let signature = sk.sign(message);
    array_to_vec(signature.to_bytes())
}

fn prompt_new_vault_password(prefix: &str) -> String {
    loop {
        let pw = rpassword::prompt_password(format!("[VAULT] Set a password to encrypt '{}': ", prefix))
            .expect("failed to read password from terminal");
        if pw.len() < 10 {
            println!("[VAULT] Password must be at least 10 characters — try again.");
            continue;
        }
        let pw2 = rpassword::prompt_password(format!("[VAULT] Confirm password for '{}': ", prefix))
            .expect("failed to read password from terminal");
        if pw != pw2 {
            println!("[VAULT] Passwords did not match — try again.");
            continue;
        }
        return pw;
    }
}

fn prompt_existing_vault_password(prefix: &str) -> String {
    rpassword::prompt_password(format!("[VAULT] Enter password to unlock '{}': ", prefix))
        .expect("failed to read password from terminal")
}

/// Unlocks a vault's seed at startup, prompting for a password on the
/// terminal. Handles three cases:
///  1. No key file exists yet -> create a brand-new encrypted vault.
///  2. Key file exists and is already encrypted -> ask for its password.
///  3. Key file exists but is an OLD unencrypted raw seed (from before this
///     feature existed) -> migrate it in place: same seed, same address,
///     same balance, now password-protected. This never changes the
///     vault's identity, so no genesis reset is needed for this upgrade.
pub fn unlock_or_create_vault(prefix: &str) -> [u8; 32] {
    let sk_path = format!("{}_secret.key", prefix);
    let pk_path = format!("{}_public.key", prefix);

    if !std::path::Path::new(&sk_path).exists() {
        println!("[VAULT] No existing key found for '{}' — creating a new encrypted vault.", prefix);
        let mut seed_bytes = [0u8; 32];
        getrandom::fill(&mut seed_bytes).expect("OS randomness unavailable");

        let password = prompt_new_vault_password(prefix);
        let seed = Seed::from(seed_bytes);
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let vk = sk.verifying_key();

        std::fs::write(&pk_path, array_to_vec(vk.encode())).expect("failed to write vault public key");
        let enc = encrypt_seed(&seed_bytes, &password);
        std::fs::write(&sk_path, serde_json::to_string_pretty(&enc).unwrap())
            .expect("failed to write vault secret key");
        println!("[VAULT] '{}' created and encrypted.", prefix);
        return seed_bytes;
    }

    let raw = std::fs::read(&sk_path).expect("failed to read vault secret key file");

    if let Ok(enc) = serde_json::from_slice::<EncryptedVaultFile>(&raw) {
        loop {
            let password = prompt_existing_vault_password(prefix);
            match decrypt_seed(&enc, &password) {
                Ok(seed_bytes) => {
                    println!("[VAULT] '{}' unlocked.", prefix);
                    return seed_bytes;
                }
                Err(_) => println!("[VAULT] Incorrect password for '{}' — try again.", prefix),
            }
        }
    } else {
        println!(
            "[VAULT] '{}' is using an older unencrypted key file. Let's add password protection now — this will NOT change its address or balance.",
            prefix
        );
        let seed_bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .expect("legacy vault key file is not a valid 32-byte seed — it may be corrupted");
        let password = prompt_new_vault_password(prefix);
        let enc = encrypt_seed(&seed_bytes, &password);
        std::fs::write(&sk_path, serde_json::to_string_pretty(&enc).unwrap())
            .expect("failed to write migrated vault secret key");
        println!("[VAULT] '{}' migrated to an encrypted key file — same address as before.", prefix);
        seed_bytes
    }
}

pub struct QLWallet;

impl QLWallet {
    // Generates a brand new post-quantum identity and locks it to disk files.
    // What's actually stored as the "secret key" is the 32-byte seed —
    // everything else is deterministically regenerated from it on demand.
    pub fn create_new_wallet(wallet_name: &str) {
        let seed = random_seed();
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let vk = sk.verifying_key();

        let pk_path = format!("{}_public.key", wallet_name);
        let sk_path = format!("{}_secret.key", wallet_name);

        let mut pk_file = File::create(&pk_path).unwrap();
        pk_file.write_all(&array_to_vec(vk.encode())).unwrap();

        let mut sk_file = File::create(&sk_path).unwrap();
        sk_file.write_all(seed.as_slice()).unwrap();

        println!("[WALLET CREATED] New Post-Quantum Identity generated successfully!");
        println!(" -> Public Address saved to: {}", pk_path);
        println!(" -> Secret Seed saved to: {}", sk_path);
    }

    // Loads a secret seed from disk to cryptographically sign a transaction payload.
    pub fn sign_transaction_payload(sk_path: &str, message: &[u8]) -> Vec<u8> {
        let mut file = File::open(sk_path).expect("[ERROR] Wallet key file not found");
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        let seed_bytes: [u8; 32] = buffer.as_slice().try_into()
            .expect("[CRITICAL] Corrupted wallet file — expected a 32-byte seed.");
        let seed = Seed::from(seed_bytes);
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);

        let signature = sk.sign(message);
        array_to_vec(signature.to_bytes())
    }
}

/// Used by consensus.rs to verify a signature came from the claimed sender,
/// without trusting anything the sender says — reconstructs the verifying
/// key purely from the raw public key bytes already on the transaction.
pub fn verify_signature(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let Ok(encoded_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(public_key_bytes) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

    let Ok(sig) = ml_dsa::Signature::<MlDsa65>::try_from(signature_bytes) else {
        return false;
    };

    use ml_dsa::Verifier;
    vk.verify(message, &sig).is_ok()
}
