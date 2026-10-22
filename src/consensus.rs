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


// ---------------------------------------------------------------------
// Emergency difficulty easing (hard fork, active from EMERGENCY_ACTIVATION_HEIGHT).
// If the previous block is more than EMERGENCY_GRACE_SECS old, the next block
// needs 1 fewer leading zero bit, plus 1 more per EMERGENCY_STEP_SECS beyond
// that. The eased value becomes the new baseline when a block is accepted, and
// normal retargeting then climbs back as hashrate returns. Deterministic:
// depends only on the stored baseline, the height and the timestamp gap.
// ---------------------------------------------------------------------
pub const EMERGENCY_ACTIVATION_HEIGHT: u64 = 34256;
pub const EMERGENCY_GRACE_SECS: i64 = 3600;
pub const EMERGENCY_STEP_SECS: i64 = 600;
pub const EMERGENCY_MAX_DROP_BITS: u32 = 20;
pub const EMERGENCY_FLOOR_BITS: u32 = 20;

pub fn effective_difficulty_bits(base_bits: u32, block_height: u64, gap_secs: i64) -> u32 {
    if block_height < EMERGENCY_ACTIVATION_HEIGHT || gap_secs <= EMERGENCY_GRACE_SECS {
        return base_bits;
    }
    let steps = ((gap_secs - EMERGENCY_GRACE_SECS) / EMERGENCY_STEP_SECS + 1) as u32;
    let drop = steps.min(EMERGENCY_MAX_DROP_BITS);
    let floor = EMERGENCY_FLOOR_BITS.min(base_bits);
    base_bits.saturating_sub(drop).max(floor)
}

#[cfg(test)]
mod emergency_tests {
    use super::*;
    #[test]
    fn eases_only_after_grace_and_from_activation() {
        assert_eq!(effective_difficulty_bits(37, 34256, 300), 37);
        assert_eq!(effective_difficulty_bits(37, 34256, 3600), 37);
        assert_eq!(effective_difficulty_bits(37, 34256, 3601), 36);
        assert_eq!(effective_difficulty_bits(37, 34256, 9000), 27);
        assert_eq!(effective_difficulty_bits(37, 34256, 10_000_000), 20);
        assert_eq!(effective_difficulty_bits(37, 34255, 10_000_000), 37);
        assert_eq!(effective_difficulty_bits(18, 34256, 10_000_000), 18);
    }
}


// ---------------------------------------------------------------------
// FORK 2 (hard fork, active from FORK2_ACTIVATION_HEIGHT): fine-grained,
// per-block difficulty.
//
// Why: the old rule only retargeted every 10th block and rounded to a whole
// bit, so any block-producer who controlled the timing of every 10th block
// could keep a window just above the rounding threshold forever and freeze
// difficulty. This rule fixes that three ways:
//   1. Difficulty is a fixed-point number (16 fractional bits), compared as
//      `pow_hash < target`, so it can move in tiny steps instead of x2 jumps.
//   2. It adjusts after EVERY block: L_next = L_parent + (T - gap) / TAU.
//      There is no special boundary block and no dead zone. Summed over many
//      blocks this depends only on total elapsed time, so pacing blocks
//      faster than the target makes difficulty rise continuously.
//   3. Timestamps must be above the median of the previous 11 blocks and no
//      more than FORK2_FUTURE_LIMIT_SECS ahead of a node's clock.
// Integer math only (no floating point) so every platform agrees exactly.
//
// state.difficulty_bits meaning:
//   * while the chain is below FORK2_ACTIVATION_HEIGHT: whole bits (as before)
//   * from block FORK2_ACTIVATION_HEIGHT onward: fixed-point, 1.0 bit = 65536.
// parent_fine() hides that switch.
// The emergency easing (stall protection) still applies on top, for the
// single block it eases, and is NOT written into the stored baseline.
// ---------------------------------------------------------------------
pub const FORK2_ACTIVATION_HEIGHT: u64 = 35600;
pub const FP_SHIFT: u32 = 16;
pub const FP_ONE: u32 = 1 << FP_SHIFT;
pub const FORK2_TAU_SECS: i64 = 3600;
pub const FORK2_MIN_FP: u32 = 20 << FP_SHIFT;
pub const FORK2_MAX_FP: u32 = 200 << FP_SHIFT;
pub const FORK2_FUTURE_LIMIT_SECS: i64 = 900;
pub const MTP_WINDOW: u64 = 11;

pub fn fork2_active(block_height: u64) -> bool {
    block_height >= FORK2_ACTIVATION_HEIGHT
}

/// Fixed-point difficulty in force BEFORE block `block_height` is applied,
/// given the stored state value.
pub fn parent_fine(state_bits: u32, block_height: u64) -> u32 {
    if block_height <= FORK2_ACTIVATION_HEIGHT {
        state_bits.saturating_mul(FP_ONE)
    } else {
        state_bits
    }
}

/// Difficulty a block must meet (fixed-point), including emergency easing for
/// a long gap since its parent. Only valid when fork2_active(block_height).
pub fn required_fine(state_bits: u32, block_height: u64, gap_secs: i64) -> u32 {
    let base = parent_fine(state_bits, block_height);
    if gap_secs <= EMERGENCY_GRACE_SECS {
        return base;
    }
    let steps = ((gap_secs - EMERGENCY_GRACE_SECS) / EMERGENCY_STEP_SECS + 1) as u64;
    let drop = steps.min(EMERGENCY_MAX_DROP_BITS as u64) as u32;
    let floor = FORK2_MIN_FP.min(base);
    base.saturating_sub(drop.saturating_mul(FP_ONE)).max(floor)
}

/// Stored baseline after a block: parent's baseline (NOT the eased value)
/// adjusted by how far this block's gap was from the target.
pub fn next_fine(parent_baseline: u32, gap_secs: i64) -> u32 {
    let delta = ((TARGET_BLOCK_TIME_SECS - gap_secs) as i128 * FP_ONE as i128)
        / FORK2_TAU_SECS as i128;
    let v = parent_baseline as i128 + delta;
    v.clamp(FORK2_MIN_FP as i128, FORK2_MAX_FP as i128) as u32
}

/// Whole-bit value old miners should use: rounded UP, so a hash that passes
/// it always also passes the exact fixed-point target.
pub fn ceil_bits(fine: u32) -> u32 {
    ((fine as u64 + (FP_ONE as u64 - 1)) >> FP_SHIFT) as u32
}

/// 2^x * 65536 for x in [0,1) given as a 16-bit fraction (cubic approximation,
/// integer only; the factor returned is 2^x*65536 - 65536).
fn exp2_factor(frac: u32) -> u64 {
    let f = frac as u128;
    ((195766423245049u128 * f + 971821376u128 * f * f + 5127u128 * f * f * f + (1u128 << 47)) >> 48) as u64
}

/// 256-bit big-endian target for a fixed-point difficulty: 2^(256 - fine/65536).
/// For whole-bit difficulties this is exactly 2^(256-bits), i.e. identical to
/// the old "leading zero bits" test.
pub fn target_from_fine(fine: u32) -> [u8; 32] {
    let fine = fine.clamp(FP_ONE, 255 << FP_SHIFT);
    let e = (256u64 << FP_SHIFT) - fine as u64;
    let int_part = (e >> FP_SHIFT) as u32;
    let frac = (e & (FP_ONE as u64 - 1)) as u32;
    let mant = 65536u64 + exp2_factor(frac); // 2^frac * 65536, 17 bits
    let shift = int_part - 16;
    let mut t = [0u8; 32];
    for k in 0..17u32 {
        if (mant >> k) & 1 == 1 {
            let pos = shift + k;
            if pos >= 256 {
                return [0xFFu8; 32];
            }
            t[31 - (pos / 8) as usize] |= 1u8 << (pos % 8);
        }
    }
    t
}

/// True if the 32-byte big-endian hash is strictly below the target.
pub fn hash_below_target(hash: &[u8], target: &[u8; 32]) -> bool {
    if hash.len() != 32 {
        return false;
    }
    for i in 0..32 {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    false
}

pub fn meets_target(hash: &[u8], fine: u32) -> bool {
    hash_below_target(hash, &target_from_fine(fine))
}

/// Median of the given timestamps (callers pass up to MTP_WINDOW of them).
pub fn median_of(mut ts: Vec<i64>) -> i64 {
    if ts.is_empty() {
        return 0;
    }
    ts.sort();
    ts[ts.len() / 2]
}

/// Fork 2 timestamp rule: strictly above the median of the last 11 blocks and
/// not too far ahead of this node's clock.
pub fn fork2_timestamp_ok(ts: i64, mtp: i64, now: i64) -> bool {
    ts > mtp && ts <= now + FORK2_FUTURE_LIMIT_SECS
}

#[cfg(test)]
mod fork2_tests {
    use super::*;

    fn rng(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    fn rand_hash(seed: &mut u64, leading_zero_bits: u32) -> [u8; 32] {
        let mut h = [0u8; 32];
        for i in 0..4 {
            h[i * 8..i * 8 + 8].copy_from_slice(&rng(seed).to_be_bytes());
        }
        // force exactly `leading_zero_bits` leading zeros
        for b in 0..leading_zero_bits as usize {
            h[b / 8] &= !(0x80u8 >> (b % 8));
        }
        let b = leading_zero_bits as usize;
        if b < 256 {
            h[b / 8] |= 0x80u8 >> (b % 8);
        }
        h
    }

    #[test]
    fn whole_bits_identical_to_old_rule() {
        let mut s = 0x1234_5678_9abc_def1u64;
        for bits in 20u32..=64 {
            for lz in bits.saturating_sub(2)..=bits + 2 {
                for _ in 0..50 {
                    let h = rand_hash(&mut s, lz);
                    assert_eq!(
                        meets_difficulty(&h, bits),
                        meets_target(&h, bits << FP_SHIFT),
                        "bits={} lz={}",
                        bits,
                        lz
                    );
                }
            }
        }
    }

    #[test]
    fn target_known_values() {
        // 35.0 bits -> 2^221 -> bit 221 -> byte index 31-27=4, bit 5
        let t = target_from_fine(35 << FP_SHIFT);
        let mut expect = [0u8; 32];
        expect[31 - 221 / 8] = 1 << (221 % 8);
        assert_eq!(t, expect);
        // 35.5 bits -> mantissa for 2^0.5: 92674 at shift 204 (python-verified)
        let t2 = target_from_fine((35 << FP_SHIFT) + 32768);
        let mut m: u64 = 0;
        for k in 0..17u32 {
            let pos = 204 + k;
            if t2[31 - (pos / 8) as usize] & (1u8 << (pos % 8)) != 0 {
                m |= 1 << k;
            }
        }
        assert_eq!(m, 92674);
    }

    #[test]
    fn target_monotonic_and_close_to_true_value() {
        let mut prev = target_from_fine(20 << FP_SHIFT);
        let mut f = (20u32 << FP_SHIFT) + 1;
        while f < (60u32 << FP_SHIFT) {
            let t = target_from_fine(f);
            assert!(t <= prev, "target must not increase as difficulty rises (f={})", f);
            prev = t;
            f += 977; // odd step, hits many fractions
        }
        // accuracy of the cubic: mantissa within 0.02% of 2^frac
        for frac in (0u32..65536).step_by(257) {
            let approx = 65536u64 + exp2_factor(frac);
            let exact = 65536f64 * (frac as f64 / 65536.0).exp2();
            let err = (approx as f64 - exact).abs() / exact;
            assert!(err < 0.0002, "frac {} err {}", frac, err);
        }
    }

    #[test]
    fn next_fine_adjusts_toward_target() {
        let base = 35u32 << FP_SHIFT;
        assert_eq!(next_fine(base, 300), base);
        assert_eq!(next_fine(base, 150), base + 2730); // (150*65536)/3600
        assert_eq!(next_fine(base, 600), base - 5461); // truncates toward zero
        // clamps
        assert_eq!(next_fine(FORK2_MIN_FP, 100_000), FORK2_MIN_FP);
        assert_eq!(next_fine(FORK2_MAX_FP, -100_000), FORK2_MAX_FP);
    }

    #[test]
    fn pacing_at_212s_cannot_freeze_difficulty() {
        // The exploit: every 10-block window summing to 2123s. Under the new
        // rule, 212.3s blocks must raise difficulty continuously.
        let mut f = 35u32 << FP_SHIFT;
        for _ in 0..100 {
            f = next_fine(f, 212);
        }
        // 100 blocks * 88s / 3600s ~ +2.44 bits
        let gained = (f - (35 << FP_SHIFT)) as f64 / 65536.0;
        assert!(gained > 2.3 && gained < 2.6, "gained {}", gained);
    }

    #[test]
    fn transition_and_emergency() {
        let h = FORK2_ACTIVATION_HEIGHT;
        // block H reads the old whole-bit value
        assert_eq!(parent_fine(35, h), 35 << FP_SHIFT);
        // block H+1 reads the stored fixed-point value as-is
        assert_eq!(parent_fine(2_300_000, h + 1), 2_300_000);
        // emergency easing matches the old rule for whole-bit baselines
        for gap in [0i64, 300, 3600, 3601, 4200, 9000, 20_000, 10_000_000] {
            let old = effective_difficulty_bits(35, h, gap);
            assert_eq!(required_fine(35, h, gap), old << FP_SHIFT, "gap {}", gap);
        }
        // eased value is not what gets stored
        let stored = next_fine(parent_fine(35, h), 18_000);
        assert!(stored >= FORK2_MIN_FP);
        assert_eq!(stored, ((35i64 << 16) + ((300 - 18_000) * 65536) / 3600) as u32);
    }

    #[test]
    fn timestamp_rule() {
        assert!(fork2_timestamp_ok(1001, 1000, 1000));
        assert!(!fork2_timestamp_ok(1000, 1000, 1000)); // must be strictly above median
        assert!(fork2_timestamp_ok(1900, 1000, 1000));
        assert!(!fork2_timestamp_ok(1901, 1000, 1000));
        assert_eq!(median_of(vec![5, 1, 3]), 3);
        assert_eq!(median_of(vec![]), 0);
    }
}
