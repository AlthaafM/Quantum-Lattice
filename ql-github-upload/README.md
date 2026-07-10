# Quantum-Lattice (QL)

A Layer 1 blockchain signed entirely with *ML-DSA-65* — the finalized NIST post-quantum standard (FIPS 204) — built to resist both classical and quantum attacks, including "harvest now, decrypt later" threats that already apply to ECDSA-based chains like Bitcoin and Ethereum today.

Built by [Futuristic AI](https://futuristicai.co.za), Durban, South Africa.

- 🌐 *Live Explorer:* https://quantum-lattice.futuristicai.co.za
- 👛 *Wallet:* https://qlwallet.futuristicai.co.za

## What's Here

- src/ — the node itself: consensus, P2P gossip and catch-up sync, proof-of-work mining endpoint, difficulty retargeting, RocksDB-backed ledger
- src/bin/miner.rs — a standalone mining client bundled with the node
- ql-wallet-wasm/ — the WebAssembly signing core used by the browser wallet (pure Rust — no C toolchain required to build)
- wallet.html, public_explorer.html, admin_dashboard.html — the front-end pages served directly by the node

## Key Design Points

- *Post-quantum from genesis* — every signature, including mining rewards and vault transfers, uses ML-DSA-65. No legacy ECDSA anywhere in the signing path.
- *Non-custodial wallet* — keys are generated and signed entirely client-side (WASM in the browser); the node never sees a private key. Recovery via an encrypted keystore file or a 24-word BIP39 seed phrase.
- *Encrypted vaults at rest* — treasury keys are password-protected (AES-256-GCM + PBKDF2), unlocked once into memory at node startup, never re-read from disk in plaintext.
- *Real difficulty retargeting* — a 5-minute block time target, adjusted every 10 blocks based on actual observed timing.
- *Miners are paid directly to any wallet address you already control* — no separate mining account to manage or migrate funds out of later.
- *Optional email verification* (OTP) for the wallet directory layer, with rate limiting on every endpoint that sends email or accepts public input.
- *A public "Security & Transparency" page*, with real, independently reproducible cryptographic test vectors — see the live explorer.

## Building

Requires a standard Rust toolchain (rustup.rs).

bash
cargo build --release


RocksDB is compiled from source as part of the build — on Linux this typically works with no extra setup; on Windows, MSVC Build Tools (Desktop development with C++) are required.

The standalone miner has no RocksDB dependency and can be built as its own lightweight project — see src/bin/miner.rs.

## Running

bash
cargo run --release --bin quantum-lattice_core -- node1


On first run, you'll be prompted to set passwords for the two vault keys (Master Vault A and Operational Vault B), which are generated and encrypted automatically.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).

## Security

This codebase has gone through careful, methodical internal review — consensus and transaction validation, cryptographic signing, vault encryption, network input handling, and abuse protection — with issues found and fixed before release. See the live explorer's Security & Transparency tab for details and reproducible test vectors. This has not yet undergone independent third-party audit.
