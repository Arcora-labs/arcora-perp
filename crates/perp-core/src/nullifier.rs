//! Nullifier set: spent-note tracking for double-spend prevention (Proof-v1).
//!
//! A note is consumed by inserting its nullifier. Re-inserting the same nullifier
//! is rejected — this is the on-chain-enforced "no double-spend" invariant. In
//! the circuit this becomes a non-membership proof against the nullifier
//! accumulator; in Phase 0 we model it as an explicit set so the accounting tests
//! are unambiguous.

use crate::hash::Digest;
use alloc::collections::BTreeSet;

/// Append-only set of revealed nullifiers.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NullifierSet {
    spent: BTreeSet<Digest>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self {
            spent: BTreeSet::new(),
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
    #[must_use]
    pub fn insert(&mut self, nf: Digest) -> bool {
        self.spent.insert(nf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_spend_rejected() {
        let mut s = NullifierSet::new();
        let nf = [1u8; 32];
        assert!(s.insert(nf), "first spend ok");
        assert!(!s.insert(nf), "second spend rejected");
        assert_eq!(s.len(), 1);
    }
}
