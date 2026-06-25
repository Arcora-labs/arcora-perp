//! # bridge — privacy bridge for deposits/withdrawals (Phase 4, §13)
//!
//! "Dark" covers the order book and positions, but naive deposits/withdrawals
//! leak on the public ledger: an observer who sees `0x..A deposits $4,137` and
//! later `0x..B withdraws $4,137` links them. §13 Faz 4 names the fix —
//! **padding / batching / relayer + amount-bucket strategy**. This crate is the
//! Ethereum-direct model of that (the Aztec network integration is the heavier,
//! optional later step; §15 says ship Ethereum-direct first).
//!
//! Two mechanisms:
//!
//! 1. **Amount bucketing.** Every transfer is decomposed into fixed denominations
//!    (Tornado-style), so the ledger sees only standard amounts, never the exact
//!    figure. A non-divisible remainder is reported separately and *does* leak —
//!    callers should round to the unit (the model makes the leak explicit rather
//!    than hiding it).
//!
//! 2. **Batching / mixing.** A relayer collects many bucketed entries into one
//!    batch and shuffles them, so within a denomination the entries are mutually
//!    indistinguishable — the **anonymity set** for a transfer is the count of
//!    entries sharing its denomination in the batch. §9's caution about *dummy
//!    padding* applies to liquidation leakage, not here: for the bridge, the
//!    spec explicitly endorses amount-buckets + batching.

#![no_std]
#![cfg_attr(not(feature = "std"), forbid(unsafe_code))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use perp_core::fixed::QUOTE_SCALE;
use perp_core::hash::{word_i128, word_u64, Digest, Domain, Hasher, Keccak256};

/// Fixed denominations (USD), largest → smallest. Every bridged transfer is a
/// sum of these. Governance-set; chosen to balance anonymity-set size against the
/// number of entries per transfer.
pub fn denominations() -> [i128; 6] {
    [
        100_000 * QUOTE_SCALE,
        10_000 * QUOTE_SCALE,
        1_000 * QUOTE_SCALE,
        100 * QUOTE_SCALE,
        10 * QUOTE_SCALE,
        QUOTE_SCALE,
    ]
}

/// The smallest denomination (the bridging unit). Amounts below this can't be
/// bridged privately and surface as remainder.
pub fn unit() -> i128 {
    QUOTE_SCALE
}

/// Greedy decomposition of `amount` into denomination counts (aligned to
/// [`denominations`]), plus any sub-unit remainder that cannot be bucketed.
pub fn decompose(amount: i128) -> (Vec<(i128, u32)>, i128) {
    let denoms = denominations();
    let mut out = Vec::new();
    let mut rem = amount.max(0);
    for d in denoms {
        let count = (rem / d) as u32;
        if count > 0 {
            out.push((d, count));
            rem -= d * count as i128;
        }
    }
    (out, rem)
}

/// Whether to bridge into or out of the system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Deposit,
    Withdraw,
}

/// One bucketed entry in a mix batch: a single denomination plus a hiding
/// commitment. Two entries of the same denomination are indistinguishable on the
/// public ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub direction: Direction,
    pub denom: i128,
    /// Commitment hiding the owner/blinding behind the denomination.
    pub commitment: Digest,
}

/// A relayer mix batch (§13). Collects bucketed entries from many transfers; the
/// public view is only the shuffled multiset of denominations.
#[derive(Clone, Debug, Default)]
pub struct MixBatch {
    entries: Vec<Entry>,
}

impl MixBatch {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add a transfer: decompose it into bucket entries, each with a hiding
    /// commitment `H(owner, denom, blinding, index)`. Returns the sub-unit
    /// remainder that could not be bridged privately (0 if cleanly bucketed).
    pub fn add_transfer(
        &mut self,
        direction: Direction,
        owner: Digest,
        amount: i128,
        blinding: Digest,
    ) -> i128 {
        let (buckets, remainder) = decompose(amount);
        let mut idx = 0u64;
        for (denom, count) in buckets {
            for _ in 0..count {
                let commitment = Keccak256::hash_words(
                    Domain::NoteCommitment,
                    &[owner, word_i128(denom), blinding, word_u64(idx)],
                );
                self.entries.push(Entry {
                    direction,
                    denom,
                    commitment,
                });
                idx += 1;
            }
        }
        remainder
    }

    /// Deterministically shuffle the batch (Fisher–Yates with a Keccak PRNG seeded
    /// by `seed`). Mixing breaks the input-order ↔ output-order linkage; in
    /// production the seed is unpredictable (e.g. a VRF / beacon).
    pub fn mix(&mut self, seed: &Digest) {
        let n = self.entries.len();
        if n < 2 {
            return;
        }
        for i in (1..n).rev() {
            // `i` is a unique per-iteration nonce for the PRNG stream.
            let h = Keccak256::hash_words(Domain::StateRoot, &[*seed, word_u64(i as u64)]);
            // take 8 bytes as a u64 index
            let mut b = [0u8; 8];
            b.copy_from_slice(&h[..8]);
            let j = (u64::from_le_bytes(b) % (i as u64 + 1)) as usize;
            self.entries.swap(i, j);
        }
    }

    /// The public view: the (sorted) multiset of denominations an observer sees.
    pub fn public_denominations(&self) -> Vec<i128> {
        let mut v: Vec<i128> = self.entries.iter().map(|e| e.denom).collect();
        v.sort_unstable();
        v
    }

    /// Anonymity set for a denomination = how many entries share it. A transfer's
    /// privacy is the anonymity set of each of its buckets.
    pub fn anonymity_set(&self, denom: i128) -> usize {
        self.entries.iter().filter(|e| e.denom == denom).count()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn decompose_is_exact_when_divisible() {
        // $4,137 = 4*1000 + 1*100 + 3*10 + 7*1
        let amount = 4_137 * QUOTE_SCALE;
        let (buckets, rem) = decompose(amount);
        assert_eq!(rem, 0);
        let sum: i128 = buckets.iter().map(|(d, c)| d * *c as i128).sum();
        assert_eq!(sum, amount);
        assert_eq!(buckets, vec![
            (1_000 * QUOTE_SCALE, 4),
            (100 * QUOTE_SCALE, 1),
            (10 * QUOTE_SCALE, 3),
            (QUOTE_SCALE, 7),
        ]);
    }

    #[test]
    fn sub_unit_remainder_leaks_explicitly() {
        // 50 cents cannot be bucketed (unit is $1)
        let amount = QUOTE_SCALE / 2;
        let (buckets, rem) = decompose(amount);
        assert!(buckets.is_empty());
        assert_eq!(rem, QUOTE_SCALE / 2, "remainder reported, not hidden");
    }

    #[test]
    fn same_denomination_shares_anonymity_set() {
        // two different users each bridge $111 → both produce a $100, a $10, a $1
        let mut batch = MixBatch::new();
        batch.add_transfer(Direction::Deposit, [1u8; 32], 111 * QUOTE_SCALE, [0xA; 32]);
        batch.add_transfer(Direction::Withdraw, [2u8; 32], 111 * QUOTE_SCALE, [0xB; 32]);
        assert_eq!(batch.anonymity_set(100 * QUOTE_SCALE), 2);
        assert_eq!(batch.anonymity_set(10 * QUOTE_SCALE), 2);
        assert_eq!(batch.anonymity_set(QUOTE_SCALE), 2);
    }

    #[test]
    fn mix_preserves_multiset_but_reorders() {
        let mut batch = MixBatch::new();
        for i in 0..6u8 {
            batch.add_transfer(Direction::Deposit, [i; 32], 11 * QUOTE_SCALE, [i; 32]);
        }
        let before = batch.public_denominations();
        let order_before: Vec<Digest> = batch.entries().iter().map(|e| e.commitment).collect();
        batch.mix(&[0x5Eu8; 32]);
        let after = batch.public_denominations();
        let order_after: Vec<Digest> = batch.entries().iter().map(|e| e.commitment).collect();
        assert_eq!(before, after, "mixing preserves the denomination multiset");
        assert_ne!(order_before, order_after, "mixing reorders entries (breaks linkage)");
    }

    #[test]
    fn mix_is_deterministic_for_a_seed() {
        let build = || {
            let mut b = MixBatch::new();
            for i in 0..5u8 {
                b.add_transfer(Direction::Deposit, [i; 32], 23 * QUOTE_SCALE, [i; 32]);
            }
            b.mix(&[0x11u8; 32]);
            b.entries().iter().map(|e| e.commitment).collect::<Vec<_>>()
        };
        assert_eq!(build(), build());
    }
}
