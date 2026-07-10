// Thin WebAssembly wrapper around the exact same ml-dsa crate the node uses
// natively. Pure Rust — no C code, no toolchain wall like the earlier
// pqcrypto-dilithium attempt. This file does not implement any cryptography
// itself, only exposes keygen/sign to JavaScript.

use wasm_bindgen::prelude::*;
use ml_dsa::{MlDsa65, Keypair, SigningKey, Signer, Seed, EncodedVerifyingKey, SignatureEncoding};

fn array_to_vec(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    bytes.as_ref().to_vec()
}

fn random_seed() -> Result<Seed, JsValue> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| JsValue::from_str("Browser randomness unavailable"))?;
    Ok(Seed::from(bytes))
}

#[wasm_bindgen]
pub struct QLKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl QLKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }
}

/// Generates a brand-new ML-DSA-65 keypair entirely in the browser. The
/// "secret_key" returned here is the 32-byte seed — everything else is
/// deterministically regenerated from it whenever signing is needed.
#[wasm_bindgen]
pub fn generate_keypair() -> Result<QLKeyPair, JsValue> {
    let seed = random_seed()?;
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let vk = sk.verifying_key();
    Ok(QLKeyPair {
        public_key: array_to_vec(vk.encode()),
        secret_key: seed.as_slice().to_vec(),
    })
}

/// Reconstructs a keypair from an existing 32-byte seed — used when
/// restoring a wallet from its recovery seed phrase, rather than
/// generating a brand-new random one.
#[wasm_bindgen]
pub fn keypair_from_seed(seed_bytes: &[u8]) -> Result<QLKeyPair, JsValue> {
    let seed_arr: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("Seed must be exactly 32 bytes"))?;
    let seed = Seed::from(seed_arr);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let vk = sk.verifying_key();
    Ok(QLKeyPair {
        public_key: array_to_vec(vk.encode()),
        secret_key: seed.as_slice().to_vec(),
    })
}

/// Signs a message using a 32-byte seed (not a full key blob). message
/// must be built exactly as the node expects: sender_bytes || receiver_bytes
/// || amount.to_le_bytes() (8 bytes, little-endian u64).
#[wasm_bindgen]
pub fn sign_message(seed_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    let seed_arr: [u8; 32] = seed_bytes.try_into()
        .map_err(|_| JsValue::from_str("Secret key must be exactly 32 bytes (a seed)"))?;
    let seed = Seed::from(seed_arr);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let sig = sk.sign(message);
    Ok(array_to_vec(sig.to_bytes()))
}

/// Basic shape check on a public key — full cryptographic validity is
/// ultimately enforced by the node when a transaction is submitted.
#[wasm_bindgen]
pub fn validate_public_key(public_key_bytes: &[u8]) -> bool {
    EncodedVerifyingKey::<MlDsa65>::try_from(public_key_bytes).is_ok()
}
