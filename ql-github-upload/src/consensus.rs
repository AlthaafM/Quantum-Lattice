use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::wallet::verify_signature;

// Quantum-Lattice (QL) Core Supply Parameters
// Updated tokenomics: vaults reduced from 51.2% to ~20.4% of supply
// (3M + 2.2M = 5.2M of 25.5M) — founder allocation is now a minority stake,
// with the bulk of supply (20.3M) reserved purely for mining emissions.
pub const COIN: u64 = 100_000_000;
pub const GLOBAL_MAX_SUPPLY: u64 = 25_500_000 * COIN;
pub const MINING_REWARD_POOL: u64 = 20_300_000 * COIN;
pub const VAULT_A_ALLOCATION: u64 = 3_000_000 * COIN;
pub const VAULT_B_ALLOCATION: u64 = 2_200_000 * COIN;
pub const HALVING_INTERVAL: u64 = 210_000;
// 48 QL chosen (up from the original 25) so the full 20.3M mining pool is
// reachable through the halving schedule: reward * halving_interval * 2 =
// 48 * 210,000 * 2 = ~20.16M QL — nearly the entire pool, using the same
// halving cadence as Bitcoin (210,000 blocks) rather than an arbitrary interval.
pub const INITIAL_REWARD: u64 = 48 * COIN;

// Shared RocksDB key for persisted chain state — used by both main.rs and
// network.rs, so it lives here once instead of being duplicated.
pub const STATE_KEY: &[u8] = b"consensus_state";

// Phase 6: real difficulty retargeting, replacing the fixed Phase 5 target.
pub const TARGET_BLOCK_TIME_SECS: i64 = 300; // 5 minutes
pub const RETARGET_INTERVAL: u64 = 10; // recompute difficulty every 10 blocks
pub const MIN_DIFFICULTY_BITS: u32 = 0;
pub const MAX_DIFFICULTY_BITS: u32 = 256; // full SHA3-256 width

// STOPGAP safety floor from Phase 5, kept as a backstop only — NOT the
// primary pacing mechanism anymore now that real retargeting exists below.
// This just prevents pathological instant-mining if difficulty ever computes
// to something degenerate (e.g. a bug drives it to 0 bits).
pub const MIN_BLOCK_INTERVAL_SECS: i64 = 30;

/// Checks a hash against a required number of LEADING ZERO BITS (not whole
/// bytes — bytes only allow 256x jumps between difficulty levels, which is
/// far too coarse for real retargeting).
pub fn meets_difficulty(hash: &[u8], required_bits: u32) -> bool {
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

/// This is the ONLY thing that gets persisted to RocksDB between restarts.
/// If this struct isn't saved and reloaded, the chain has no memory — which
/// was the bug before: both nodes just re-ran genesis every boot.
#[derive(Serialize, Deserialize, Clone)]
pub struct ConsensusState {
    pub total_minted_supply: u64,
    pub balances: HashMap<Vec<u8>, u64>,
    pub chain_height: u64,
    // Phase 6: must be persisted and identical across all nodes, since it's
    // consensus-critical — every node must agree on what difficulty the next
    // block needs, or they'll accept different blocks and fork.
    pub difficulty_bits: u32,
}

pub struct ConsensusEngine {
    pub state: ConsensusState,
}

#[derive(Debug)]
pub enum TxError {
    InvalidSignature,
    InsufficientBalance,
    ZeroAmount,
}

impl ConsensusEngine {
    /// Runs exactly once, ever, for a given database. main.rs only calls this
    /// when no saved state exists yet.
    pub fn genesis(vault_a_pk: Vec<u8>, vault_b_pk: Vec<u8>) -> Self {
        let mut balances = HashMap::new();
        balances.insert(vault_a_pk, VAULT_A_ALLOCATION);
        balances.insert(vault_b_pk, VAULT_B_ALLOCATION);
        let genesis_supply = VAULT_A_ALLOCATION + VAULT_B_ALLOCATION;

        println!("[CONSENSUS] Genesis Token Economy initialized successfully.");
        println!("[CONSENSUS] Total Starting Supply: {} QL", genesis_supply / COIN);

        // Starting difficulty is a rough guess (not calibrated to any
        // specific hardware) — real retargeting corrects it toward the
        // 5-minute target within the first RETARGET_INTERVAL blocks
        // regardless of how far off this initial guess is.
        const GENESIS_DIFFICULTY_BITS: u32 = 20;

        Self {
            state: ConsensusState {
                total_minted_supply: genesis_supply,
                balances,
                chain_height: 0,
                difficulty_bits: GENESIS_DIFFICULTY_BITS,
            },
        }
    }

    /// Restores a chain that already exists — this is what makes restarts safe.
    pub fn from_state(state: ConsensusState) -> Self {
        println!("[CONSENSUS] Restored existing chain state at height {}", state.chain_height);
        Self { state }
    }

    pub fn balance_of(&self, pk: &[u8]) -> u64 {
        *self.state.balances.get(pk).unwrap_or(&0)
    }

    pub fn get_block_reward(&self) -> u64 {
        if self.state.total_minted_supply >= GLOBAL_MAX_SUPPLY {
            return 0;
        }
        let halvings = self.state.chain_height / HALVING_INTERVAL;
        if halvings >= 64 {
            return 0;
        }
        let reward = INITIAL_REWARD >> halvings;
        // Clamp to whatever room is actually left under the cap — without
        // this, the very last reward(s) before exhaustion could mint a few
        // QL past GLOBAL_MAX_SUPPLY, quietly violating the stated hard cap.
        reward.min(GLOBAL_MAX_SUPPLY - self.state.total_minted_supply)
    }

    /// THE FIX for "signatures generated but never checked". This rebuilds the
    /// exact message that should have been signed (sender || receiver || amount)
    /// and rejects the transaction outright if the signature doesn't match, or
    /// if the sender doesn't have the balance. Nothing moves without both checks
    /// passing.
    pub fn apply_transaction(
        &mut self,
        sender: &[u8],
        receiver: &[u8],
        amount: u64,
        signature: &[u8],
    ) -> Result<(), TxError> {
        if amount == 0 {
            return Err(TxError::ZeroAmount);
        }

        let mut message = Vec::new();
        message.extend_from_slice(sender);
        message.extend_from_slice(receiver);
        message.extend_from_slice(&amount.to_le_bytes());

        if !verify_signature(sender, &message, signature) {
            return Err(TxError::InvalidSignature);
        }

        let sender_balance = *self.state.balances.get(sender).unwrap_or(&0);
        if sender_balance < amount {
            return Err(TxError::InsufficientBalance);
        }

        *self.state.balances.get_mut(sender).unwrap() -= amount;
        *self.state.balances.entry(receiver.to_vec()).or_insert(0) += amount;

        Ok(())
    }

    /// Pays the miner for the block just produced and advances chain height.
    /// This is what makes GLOBAL_MAX_SUPPLY and the halving schedule real
    /// instead of dead code.
    pub fn process_block_reward(&mut self, miner_pk: Vec<u8>) {
        let reward = self.get_block_reward();
        if reward > 0 {
            *self.state.balances.entry(miner_pk).or_insert(0) += reward;
            self.state.total_minted_supply += reward;
            println!(
                "[MINT] Block {} rewarded {} QL to miner.",
                self.state.chain_height + 1,
                reward / COIN
            );
        }
        self.state.chain_height += 1;
    }

    /// Recomputes difficulty toward TARGET_BLOCK_TIME_SECS. Deterministic —
    /// depends only on the two given timestamps — so it MUST be called
    /// identically on every path that advances the chain (locally mined,
    /// gossiped from a peer, or pulled via catch-up), or nodes will disagree
    /// on what difficulty the next block needs and fork.
    ///
    /// first_timestamp = timestamp of the block RETARGET_INTERVAL blocks
    /// before the one just added. last_timestamp = timestamp of the block
    /// just added. Only call this when chain_height is an exact multiple of
    /// RETARGET_INTERVAL (checked by the caller).
    pub fn retarget_difficulty(&mut self, first_timestamp: i64, last_timestamp: i64) {
        let actual_secs = (last_timestamp - first_timestamp).max(1) as f64;
        let target_secs = (TARGET_BLOCK_TIME_SECS * RETARGET_INTERVAL as i64) as f64;
        let ratio = target_secs / actual_secs; // >1 => blocks came too fast => raise difficulty

        // log2(ratio) converts a speed ratio into a bit-count adjustment.
        // Clamped to ±2 bits per retarget (a 4x max swing) so one noisy
        // interval can't send difficulty wildly off course — the same
        // philosophy as Bitcoin's per-epoch adjustment cap.
        let bit_change = ratio.log2().clamp(-2.0, 2.0).round() as i32;

        let new_bits = (self.state.difficulty_bits as i32 + bit_change)
            .clamp(MIN_DIFFICULTY_BITS as i32, MAX_DIFFICULTY_BITS as i32) as u32;

        if new_bits != self.state.difficulty_bits {
            println!(
                "[RETARGET] Last {} blocks took {:.0}s (target {:.0}s) — difficulty {} -> {} leading zero bits.",
                RETARGET_INTERVAL, actual_secs, target_secs, self.state.difficulty_bits, new_bits
            );
        }
        self.state.difficulty_bits = new_bits;
    }
}
