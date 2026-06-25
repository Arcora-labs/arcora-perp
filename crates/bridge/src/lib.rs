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
/// [`denominations`]), plus any remainder that cannot be bucketed.
///
/// **Conservation-honest:** entries always sum with the remainder back to
/// `amount` — nothing is silently dropped. A non-positive `amount` is surfaced
/// *whole* as remainder (not zeroed away), and a per-denomination count that
/// would exceed `u32` is clamped, with the unbucketed surplus left in the
/// remainder rather than truncated via a lossy cast.
pub fn decompose(amount: i128) -> (Vec<(i128, u32)>, i128) {
    // Surface non-positive inputs as remainder instead of swallowing them — and
    // this keeps `rem` strictly non-negative below, so the `u32` cast is safe.
    if amount <= 0 {
        return (Vec::new(), amount);
    }
    let denoms = denominations();
    let mut out = Vec::new();
    let mut rem = amount;
    for d in denoms {
        let raw = rem / d; // >= 0 since rem > 0 and d > 0
        if raw > 0 {
            // Clamp instead of `as u32` truncation: any surplus that overflows a
            // u32 count stays in `rem` and surfaces as remainder.
            let count = u32::try_from(raw).unwrap_or(u32::MAX);
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
    /// commitment `H(owner, denom, blinding, index)`. Returns the remainder that
    /// could not be bridged privately (0 if cleanly bucketed).
    ///
    /// **Privacy caveat (model):** all buckets of one transfer share the same
    /// `owner` and `blinding`, differing only by `index`. Once a bucket is opened
    /// (e.g. on redemption, revealing `owner`+`blinding`), the remaining buckets of
    /// that *same* transfer become recomputable and thus linkable, collapsing them
    /// into one anonymity unit. A production scheme must draw **independent
    /// randomness per bucket** (Tornado-style) so each note stands alone.
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
                // Dedicated bridge domain — a mix-bucket commitment must never share
                // a preimage namespace with a spendable note commitment (§13).
                let commitment = Keccak256::hash_words(
                    Domain::BridgeCommitment,
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
            let m = i as u64 + 1;
            // Unbiased index in [0, i]. Plain `r % m` skews toward the low indices
            // when m does not divide 2^64 (modulo bias) — a non-uniform shuffle is a
            // non-uniform mix, which weakens the unlinkability the mixer exists for.
            // Reject the short tail and redraw (fresh PRNG word per attempt) so every
            // permutation is equally likely. (`zone` = largest multiple of m ≤ 2^64.)
            let zone = (u64::MAX / m) * m;
            let mut attempt = 0u64;
            let j = loop {
                let h = Keccak256::hash_words(
                    Domain::MixShuffle,
                    &[*seed, word_u64(i as u64), word_u64(attempt)],
                );
                let mut b = [0u8; 8];
                b.copy_from_slice(&h[..8]);
                let r = u64::from_le_bytes(b);
                if r < zone {
                    break (r % m) as usize;
                }
                attempt += 1;
            };
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
        assert_eq!(
            buckets,
            vec![
                (1_000 * QUOTE_SCALE, 4),
                (100 * QUOTE_SCALE, 1),
                (10 * QUOTE_SCALE, 3),
                (QUOTE_SCALE, 7),
            ]
        );
    }

    #[test]
    fn negative_amount_is_surfaced_not_swallowed() {
        // A negative magnitude must NOT silently vanish (and must never reach the
        // u32 cast, where -2 would wrap to ~4.29e9). It surfaces whole as remainder.
        let amount = -2 * QUOTE_SCALE;
        let (buckets, rem) = decompose(amount);
        assert!(buckets.is_empty());
        assert_eq!(rem, amount, "negative input surfaced verbatim");
    }

    #[test]
    fn entries_plus_remainder_always_equal_amount() {
        // Conservation: for any non-negative amount, Σ(denom·count) + remainder == amount.
        for amount in [
            0i128,
            7,
            QUOTE_SCALE / 2,
            4_137 * QUOTE_SCALE,
            999_999 * QUOTE_SCALE,
        ] {
            let (buckets, rem) = decompose(amount);
            let sum: i128 = buckets.iter().map(|(d, c)| d * *c as i128).sum();
            assert_eq!(sum + rem, amount, "decompose conserves value for {amount}");
        }
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
        assert_ne!(
            order_before, order_after,
            "mixing reorders entries (breaks linkage)"
        );
    }

    #[test]
    fn mix_commitment_is_domain_separated_from_note_commitment() {
        // A bridge bucket commitment must NOT collide with a spendable note
        // commitment built from the same word vector. Both are 4-word hashes; only
        // the domain tag separates them, so if the bridge ever reverted to
        // Domain::NoteCommitment the two would be equal for identical inputs.
        let owner = [9u8; 32];
        let blinding = [0xC; 32];
        let denom = 100 * QUOTE_SCALE;
        let mut batch = MixBatch::new();
        batch.add_transfer(Direction::Deposit, owner, denom, blinding);
        let bridge_cm = batch.entries()[0].commitment;

        let words = [owner, word_i128(denom), blinding, word_u64(0)];
        let as_note = Keccak256::hash_words(Domain::NoteCommitment, &words);
        let as_bridge = Keccak256::hash_words(Domain::BridgeCommitment, &words);
        assert_eq!(
            bridge_cm, as_bridge,
            "bridge uses the BridgeCommitment domain"
        );
        assert_ne!(
            bridge_cm, as_note,
            "a bridge commitment must not equal the note commitment of the same words"
        );
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
