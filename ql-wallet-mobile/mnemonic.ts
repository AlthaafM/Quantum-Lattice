import { sha256 } from '@noble/hashes/sha2.js';
import wordlist from './node_modules/bip39/src/wordlists/english.json';

// Our own, direct BIP39 mnemonic conversion — avoids the separate bip39
// npm package entirely, since its own internal, bundled copy of
// noble-hashes caused real, confirmed issues in React Native. Uses only
// the already-proven @noble/hashes directly, plus the real, standard
// wordlist as pure data (safe — no executable logic from that package
// is used at all).

function bytesToBinary(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(2).padStart(8, '0')).join('');
}

export function entropyToMnemonic(entropy: Uint8Array): string {
  if (entropy.length !== 32) {
    throw new Error('This wallet only supports 32-byte (256-bit) seeds.');
  }

  const hash = sha256(entropy);
  const checksumByte = hash[0]; // 8 bits, exactly what 256-bit entropy needs

  const combined = new Uint8Array(33);
  combined.set(entropy);
  combined[32] = checksumByte;

  const bits = bytesToBinary(combined); // 264 bits total
  const words: string[] = [];
  for (let i = 0; i < 24; i++) {
    const chunk = bits.slice(i * 11, i * 11 + 11);
    const index = parseInt(chunk, 2);
    words.push(wordlist[index]);
  }

  return words.join(' ');
}

export function mnemonicToEntropy(mnemonic: string): Uint8Array {
  const words = mnemonic.trim().split(/\s+/);
  if (words.length !== 24) {
    throw new Error('Enter all 24 words, separated by spaces.');
  }

  let bits = '';
  for (const word of words) {
    const index = wordlist.indexOf(word);
    if (index === -1) {
      throw new Error('Unknown word: "' + word + '" — check spelling.');
    }
    bits += index.toString(2).padStart(11, '0');
  }

  const entropyBits = bits.slice(0, 256);
  const checksumBits = bits.slice(256, 264);

  const entropy = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    entropy[i] = parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  }

  const hash = sha256(entropy);
  const expectedChecksum = hash[0].toString(2).padStart(8, '0');
  if (checksumBits !== expectedChecksum) {
    throw new Error('This seed phrase does not look valid — check the words and their order.');
  }

  return entropy;
}
