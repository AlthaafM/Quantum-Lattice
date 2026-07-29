import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

// Lower than web/desktop's 300,000 — mobile JS is meaningfully slower, and
// since each keystore file stores its own iteration count, this stays
// fully cross-compatible regardless of which platform created the file.
const KDF_ITERATIONS = 25000;

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

export interface Keystore {
  version: number;
  algorithm: string;
  address: string;
  kdf: string;
  kdf_iterations: number;
  salt: string;
  iv: string;
  ciphertext: string;
}

export function buildKeystore(publicKey: Uint8Array, secretKey: Uint8Array, password: string): Keystore {
  const salt = randomBytes(16);
  const iv = randomBytes(12);

  const startTime = Date.now();
  const key = pbkdf2(sha256, password, salt, { c: KDF_ITERATIONS, dkLen: 32 });
  console.log('[TIMING] PBKDF2 (encrypt) took', Date.now() - startTime, 'ms for', KDF_ITERATIONS, 'iterations');

  const cipher = gcm(key, iv);
  const ciphertext = cipher.encrypt(secretKey);

  return {
    version: 1,
    algorithm: 'dilithium3',
    address: bytesToHex(publicKey),
    kdf: 'PBKDF2-SHA256',
    kdf_iterations: KDF_ITERATIONS,
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(ciphertext),
  };
}

export function decryptKeystore(keystore: Keystore, password: string): Uint8Array {
  const salt = hexToBytes(keystore.salt);
  const iv = hexToBytes(keystore.iv);
  const ciphertext = hexToBytes(keystore.ciphertext);

  const startTime = Date.now();
  const key = pbkdf2(sha256, password, salt, { c: keystore.kdf_iterations || KDF_ITERATIONS, dkLen: 32 });
  console.log('[TIMING] PBKDF2 (decrypt) took', Date.now() - startTime, 'ms for', keystore.kdf_iterations, 'iterations');

  const cipher = gcm(key, iv);
  return cipher.decrypt(ciphertext);
}
