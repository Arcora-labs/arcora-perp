//! Nullifier set: spent-note tracking for double-spend prevention (Proof-v1).
//!
//! A note is consumed by inserting its nullifier. Re-inserting the same nullifier
//! is rejected — this is the on-chain-enforced "no double-spend" invariant. In
//! the circuit this becomes a non-membership proof against the nullifier
//! accumulator; in Phase 0 we model it as an explicit set so the accounting tests
//! are unambiguous.
//!
//! # Serialized form
//!
//! A set is encoded as its insertion-order log and nothing else. The membership
//! index and the running digest are rebuilt on every decode by inserting the log
//! entries in order, and a repeated entry fails the decode. The digest is a hash
//! chain over the log, so two sets have equal digests exactly when they hold the
//! same nullifiers inserted in the same order (barring a hash collision). The
//! state root commits the digest, so it binds every encoded byte of the set.

use crate::error::WireError;
use crate::hash::{Digest, Domain, Hasher};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// Append-only set of revealed nullifiers, generic over the state hasher that
/// advances its digest.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "", try_from = "NullifierSetWire"))]
pub struct NullifierSet<H: Hasher> {
    /// Every nullifier ever inserted, in insertion order. The only serialized field.
    log: Vec<Digest>,
    /// Membership index over `log`. Derived; never serialized.
    spent: BTreeSet<Digest>,
    /// Hash chain over `log`: `chain_0 = 0`, `chain_{i+1} = H(StateRoot, [chain_i,
    /// log[i]])`. Maintained on each insert so `digest()` is O(1); derived on decode
    /// by replaying the log; never serialized.
    chain: Digest,
    _h: core::marker::PhantomData<H>,
}

/// The serialized shape of [`NullifierSet`] on decode. Every decode goes through
/// [`NullifierSet::from_log`], which replays the log and refuses a repeat.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "NullifierSet", deny_unknown_fields)]
struct NullifierSetWire {
    log: Vec<Digest>,
}

/// The serialized shape of [`NullifierSet`] on encode, borrowing the log.
#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
#[serde(rename = "NullifierSet")]
struct NullifierSetWireRef<'a> {
    log: &'a [Digest],
}

#[cfg(feature = "serde")]
impl<H: Hasher> TryFrom<NullifierSetWire> for NullifierSet<H> {
    type Error = WireError;

    fn try_from(w: NullifierSetWire) -> Result<Self, WireError> {
        Self::from_log(w.log)
    }
}

#[cfg(feature = "serde")]
impl<H: Hasher> serde::Serialize for NullifierSet<H> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = NullifierSetWireRef { log: &self.log };
        serde::Serialize::serialize(&wire, serializer)
    }
}

impl<H: Hasher> Default for NullifierSet<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hasher> NullifierSet<H> {
    pub fn new() -> Self {
        Self {
            log: Vec::new(),
            spent: BTreeSet::new(),
            chain: [0u8; 32],
            _h: core::marker::PhantomData,
        }
    }

    /// Rebuild a set from its insertion-order log, exactly as if each entry were
    /// passed to [`NullifierSet::insert`] in order (the same membership rule and the
    /// same chain step), reusing the log's allocation. Refuses a repeated entry:
    /// `insert` refuses one, so no honest log contains it.
    pub fn from_log(log: Vec<Digest>) -> Result<Self, WireError> {
        let mut spent = BTreeSet::new();
        let mut chain = [0u8; 32];
        for nf in &log {
            if !spent.insert(*nf) {
                return Err(WireError("repeated nullifier"));
            }
            chain = Self::link(&chain, nf);
        }
        Ok(Self {
            log,
            spent,
            chain,
            _h: core::marker::PhantomData,
        })
    }

    /// One step of the digest chain.
    fn link(chain: &Digest, nf: &Digest) -> Digest {
        H::hash_words(Domain::StateRoot, &[*chain, *nf])
    }

    pub fn len(&self) -> usize {
        self.log.len()
    }

    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// Has this nullifier already been revealed?
    pub fn contains(&self, nf: &Digest) -> bool {
        self.spent.contains(nf)
    }

    /// Every nullifier revealed so far, in insertion order.
    pub fn log(&self) -> &[Digest] {
        &self.log
    }

    /// Insert a nullifier. Returns `false` (and does not mutate) on double-spend.
    #[must_use]
    pub fn insert(&mut self, nf: Digest) -> bool {
        if !self.spent.insert(nf) {
            return false; // double-spend: leave the log, the index and the chain untouched
        }
        // advance the running chain by this nullifier (O(1)); binds its contents + order
        self.chain = Self::link(&self.chain, &nf);
        self.log.push(nf);
        true
    }

    /// The digest committed into the state root: the running hash chain over the
    /// insertion-order log (see the module docs). O(1). Binds the set's contents
    /// and its insertion order, so a forged pre-state cannot change which notes
    /// were spent without changing the root (audit DP-002).
    pub fn digest(&self) -> Digest {
        self.chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Keccak256;

    type Set = NullifierSet<Keccak256>;

    #[test]
    fn double_spend_rejected() {
        let mut s = Set::new();
        let nf = [1u8; 32];
        assert!(s.insert(nf), "first spend ok");
        assert!(!s.insert(nf), "second spend rejected");
        assert_eq!(s.len(), 1);
        assert_eq!(s.log(), &[nf]);
    }

    // audit DP-002 perf follow-up: the digest is a running hash-chain (O(1), not an O(N) re-hash
    // of the whole append-only set), so it reflects insertion ORDER, not just the set members.
    // Two sets with the same members inserted in a different order have different digests, and
    // the serialized form is that order itself.
    #[test]
    fn digest_is_an_incremental_chain_over_insertion_order() {
        let mut a = Set::new();
        assert!(a.insert([1u8; 32]));
        assert!(a.insert([2u8; 32]));
        let mut b = Set::new();
        assert!(b.insert([2u8; 32]));
        assert!(b.insert([1u8; 32]));
        assert_ne!(
            a.digest(),
            b.digest(),
            "the running chain binds insertion order, not just the sorted set",
        );

        // a double-spend does not advance the chain (rejected insert leaves the digest unchanged)
        let before = a.digest();
        assert!(!a.insert([1u8; 32]));
        assert_eq!(
            a.digest(),
            before,
            "a rejected insert must not move the chain"
        );

        // contents are still bound: adding a new member changes the digest (DP-002 preserved)
        assert!(a.insert([3u8; 32]));
        assert_ne!(a.digest(), before);
    }

    /// The chain formula: `chain_{i+1} = H(StateRoot, [chain_i, nf_i])` from zero.
    #[test]
    fn digest_formula_is_the_hash_chain_over_the_log() {
        let log = [[5u8; 32], [3u8; 32], [9u8; 32]];
        let mut s = Set::new();
        let mut chain = [0u8; 32];
        assert_eq!(s.digest(), chain);
        for nf in log {
            assert!(s.insert(nf));
            chain = Keccak256::hash_words(Domain::StateRoot, &[chain, nf]);
            assert_eq!(s.digest(), chain);
        }
    }

    #[test]
    fn from_log_replays_inserts_in_order() {
        let mut honest = Set::new();
        for nf in [[5u8; 32], [3u8; 32], [9u8; 32]] {
            assert!(honest.insert(nf));
        }
        let rebuilt = Set::from_log(honest.log().to_vec()).expect("valid log");
        assert_eq!(rebuilt.log(), honest.log());
        assert_eq!(rebuilt.digest(), honest.digest());
        assert_eq!(rebuilt.spent, honest.spent);
        assert_eq!(Set::from_log(Vec::new()).unwrap().digest(), [0u8; 32]);
    }

    #[test]
    fn from_log_refuses_a_repeated_entry() {
        let log = alloc::vec![[5u8; 32], [3u8; 32], [5u8; 32]];
        assert_eq!(
            Set::from_log(log).err(),
            Some(WireError("repeated nullifier"))
        );
    }

    /// The encoding is exactly `postcard(log)`; the index and the chain add nothing.
    #[cfg(feature = "serde")]
    #[test]
    fn encoding_is_the_insertion_order_log() {
        let mut s = Set::new();
        for nf in [[5u8; 32], [3u8; 32]] {
            assert!(s.insert(nf));
        }
        let bytes = postcard::to_allocvec(&s).unwrap();
        assert_eq!(bytes, postcard::to_allocvec(&s.log().to_vec()).unwrap());
        let back: Set = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.digest(), s.digest());
        assert!(back.contains(&[5u8; 32]) && back.contains(&[3u8; 32]));
        let repeated = postcard::to_allocvec(&alloc::vec![[5u8; 32], [5u8; 32]]).unwrap();
        assert!(postcard::from_bytes::<Set>(&repeated).is_err());
    }
}
