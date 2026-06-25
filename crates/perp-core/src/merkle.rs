//! Fixed-depth append-only Merkle tree of note commitments (§1, §7).
//!
//! The commitment tree is the public, shielded state root: leaves are note
//! commitments, the root is published with every batch and anchored on L1. A note
//! is *spent* by revealing a nullifier (tracked separately, see [`crate::nullifier`]),
//! never by mutating the tree — so the tree is strictly append-only, which is
//! exactly what the encrypted note archive (§7) needs to reconstruct state from
//! `batch_id → commitment` mappings after device loss.
//!
//! Generic over [`Hasher`] so the same structure proves out under Keccak now and
//! Poseidon in the circuit. Empty subtree roots are precomputed per level.

use crate::hash::{Digest, Domain, Hasher};
use alloc::vec::Vec;

/// An append-only Merkle accumulator of fixed depth.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct MerkleTree<H: Hasher> {
    depth: u8,
    /// Dense leaves appended so far.
    leaves: Vec<Digest>,
    /// `empty[i]` = root of an all-empty subtree of height `i`.
    empty: Vec<Digest>,
    #[cfg_attr(feature = "serde", serde(skip))]
    _h: core::marker::PhantomData<H>,
}

/// A membership proof: the sibling path from a leaf up to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub siblings: Vec<Digest>,
}

impl<H: Hasher> MerkleTree<H> {
    /// Create an empty tree of the given depth (capacity `2^depth` leaves).
    pub fn new(depth: u8) -> Self {
        assert!((1..=64).contains(&depth), "depth out of range");
        let mut empty = Vec::with_capacity(depth as usize + 1);
        empty.push(H::hash_words(Domain::MerkleEmpty, &[[0u8; 32]]));
        for i in 0..depth as usize {
            let lower = empty[i];
            empty.push(H::compress(Domain::MerkleNode, &lower, &lower));
        }
        Self {
            depth,
            leaves: Vec::new(),
            empty,
            _h: core::marker::PhantomData,
        }
    }

    /// Maximum number of leaves this tree can hold.
    pub fn capacity(&self) -> u128 {
        1u128 << self.depth
    }

    /// Number of leaves appended so far.
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append a leaf, returning its index. Errors if the tree is full.
    pub fn append(&mut self, leaf: Digest) -> Result<u64, MerkleError> {
        if (self.leaves.len() as u128) >= self.capacity() {
            return Err(MerkleError::Full);
        }
        let idx = self.leaves.len() as u64;
        self.leaves.push(leaf);
        Ok(idx)
    }

    /// Current root. Computed bottom-up over the dense leaves, padding each level
    /// with the precomputed empty-subtree root for that height.
    pub fn root(&self) -> Digest {
        if self.leaves.is_empty() {
            return self.empty[self.depth as usize];
        }
        let mut level: Vec<Digest> = self.leaves.clone();
        for h in 0..self.depth as usize {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let left = level[i];
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    self.empty[h]
                };
                next.push(H::compress(Domain::MerkleNode, &left, &right));
                i += 2;
            }
            level = next;
        }
        level[0]
    }

    /// Produce a membership proof for the leaf at `index`.
    pub fn prove(&self, index: u64) -> Result<MerkleProof, MerkleError> {
        if index >= self.len() {
            return Err(MerkleError::OutOfRange);
        }
        let mut siblings = Vec::with_capacity(self.depth as usize);
        let mut level: Vec<Digest> = self.leaves.clone();
        let mut idx = index as usize;
        for h in 0..self.depth as usize {
            let sibling = if idx ^ 1 < level.len() {
                level[idx ^ 1]
            } else {
                self.empty[h]
            };
            siblings.push(sibling);
            // build next level
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                let left = level[i];
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    self.empty[h]
                };
                next.push(H::compress(Domain::MerkleNode, &left, &right));
                i += 2;
            }
            level = next;
            idx /= 2;
        }
        Ok(MerkleProof {
            leaf_index: index,
            siblings,
        })
    }

    /// Verify a proof against a given root and leaf. Stateless w.r.t. `self`
    /// except for depth — this is the check the circuit will encode.
    pub fn verify(root: &Digest, leaf: &Digest, proof: &MerkleProof) -> bool {
        let mut node = *leaf;
        let mut idx = proof.leaf_index;
        for sib in &proof.siblings {
            node = if idx & 1 == 0 {
                H::compress(Domain::MerkleNode, &node, sib)
            } else {
                H::compress(Domain::MerkleNode, sib, &node)
            };
            idx >>= 1;
        }
        node == *root
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleError {
    Full,
    OutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{word_u64, Keccak256};

    type T = MerkleTree<Keccak256>;

    #[test]
    fn empty_root_stable() {
        let a = T::new(8);
        let b = T::new(8);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn append_changes_root() {
        let mut t = T::new(8);
        let r0 = t.root();
        t.append(word_u64(1)).unwrap();
        assert_ne!(r0, t.root());
    }

    #[test]
    fn proofs_verify_for_all_leaves() {
        let mut t = T::new(6);
        for i in 0..20u64 {
            t.append(word_u64(i + 100)).unwrap();
        }
        let root = t.root();
        for i in 0..20u64 {
            let proof = t.prove(i).unwrap();
            let leaf = word_u64(i + 100);
            assert!(T::verify(&root, &leaf, &proof), "leaf {i} must verify");
            // wrong leaf must fail
            assert!(!T::verify(&root, &word_u64(999), &proof));
        }
    }

    #[test]
    fn capacity_enforced() {
        let mut t = T::new(2); // capacity 4
        for i in 0..4 {
            t.append(word_u64(i)).unwrap();
        }
        assert_eq!(t.append(word_u64(5)), Err(MerkleError::Full));
    }
}
