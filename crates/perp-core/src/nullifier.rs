//! Nullifier set: spent-note tracking for double-spend prevention (Proof-v1).
//!
//! A note is consumed by inserting its nullifier. Re-inserting the same nullifier
//! is rejected — this is the on-chain-enforced "no double-spend" invariant. In
//! the circuit this becomes a non-membership proof against the nullifier
//! accumulator; in Phase 0 we model it as an explicit set so the accounting tests
//! are unambiguous.

use crate::hash::{Digest, Domain, Hasher};
use alloc::collections::BTreeSet;

/// Append-only set of revealed nullifiers.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NullifierSet {
    spent: BTreeSet<Digest>,
    /// Running hash-chain over the nullifiers in insertion order, so `digest()` is O(1) instead
    /// of re-hashing the whole append-only set every call (audit DP-002 perf follow-up; the set
    /// only ever grows). Order-dependent by construction — SOUND because the sole insert path is
    /// `consume_note` in deterministic transition order (identical native + zkVM guest), and this
    /// field is serialized into the witness, so a deserialized pre-state carries the exact chain
    /// (the set is never rebuilt by re-inserting members in a different order).
    chain: Digest,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self {
            spent: BTreeSet::new(),
            chain: [0u8; 32],
        }
    }

    pub fn len(&self) -> usize {
        self.spent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Has this nullifier already been revealed?
    pub fn contains(&self, nf: &Digest) -> bool {
        self.spent.contains(nf)
    }

    /// Insert a nullifier. Returns `false` (and does not mutate) on double-spend.
    /// Generic over the state hasher so the running digest chain can be advanced with the
    /// same `H` the state root uses.
    #[must_use]
    pub fn insert<H: Hasher>(&mut self, nf: Digest) -> bool {
        if !self.spent.insert(nf) {
            return false; // double-spend: leave the set and the chain untouched
        }
        // advance the running chain by this nullifier (O(1)); binds its contents + order
        self.chain = H::hash_words(Domain::StateRoot, &[self.chain, nf]);
        true
    }

    /// A deterministic digest binding the full spent-set CONTENTS (not just the count), committed
    /// into the state root so a forged pre-state cannot swap which notes were spent while
    /// preserving the size (audit DP-002). O(1): returns the running chain (maintained on each
    /// `insert`) rather than re-hashing the whole set — see the `chain` field for why the
    /// insertion-order dependence is sound. `H` matches the state hasher the chain was built with.
    pub fn digest<H: Hasher>(&self) -> Digest {
        self.chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Keccak256;

    #[test]
    fn double_spend_rejected() {
        let mut s = NullifierSet::new();
        let nf = [1u8; 32];
        assert!(s.insert::<Keccak256>(nf), "first spend ok");
        assert!(!s.insert::<Keccak256>(nf), "second spend rejected");
        assert_eq!(s.len(), 1);
    }

    // audit DP-002 perf follow-up: the digest is a running hash-chain (O(1), not an O(N) re-hash
    // of the whole append-only set), so it reflects insertion ORDER, not just the set members.
    // Two sets with the same members inserted in a different order have different digests. This is
    // sound because the only insert path is the deterministic transition (identical native + zkVM
    // guest order) and the field is serialized, never rebuilt by re-insert.
    #[test]
    fn digest_is_an_incremental_chain_over_insertion_order() {
        let mut a = NullifierSet::new();
        assert!(a.insert::<Keccak256>([1u8; 32]));
        assert!(a.insert::<Keccak256>([2u8; 32]));
        let mut b = NullifierSet::new();
        assert!(b.insert::<Keccak256>([2u8; 32]));
        assert!(b.insert::<Keccak256>([1u8; 32]));
        assert_ne!(
            a.digest::<Keccak256>(),
            b.digest::<Keccak256>(),
            "the running chain binds insertion order, not just the sorted set",
        );

        // a double-spend does not advance the chain (rejected insert leaves the digest unchanged)
        let before = a.digest::<Keccak256>();
        assert!(!a.insert::<Keccak256>([1u8; 32]));
        assert_eq!(
            a.digest::<Keccak256>(),
            before,
            "a rejected insert must not move the chain"
        );

        // contents are still bound: adding a new member changes the digest (DP-002 preserved)
        assert!(a.insert::<Keccak256>([3u8; 32]));
        assert_ne!(a.digest::<Keccak256>(), before);
    }
}
