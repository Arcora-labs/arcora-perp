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
//!
//! # L1-settlement trees (no_std)
//!
//! This module is also the SINGLE source of truth for the withdrawals, ordered, and
//! rejected trees: [`withdrawal_leaf`], [`inclusion_leaf`], [`rejection_leaf`],
//! [`merkle_root`], [`ordered_root`], [`rejected_root`], [`withdrawals_root`].
//! Byte-for-byte identical to the shapes the L1 contracts verify (CollateralVault /
//! DarkPerpSettlement / MerkleLib): sorted-pair internal node (`keccak(min||max)`, no
//! tag), 65-byte domain-tagged challenge leaves, `keccak(to||amount||nonce)`
//! withdrawal leaves. `crates/gateway/src/withdrawals.rs` re-exports these so
//! off-chain and in-circuit trees are provably the same code.

use crate::hash::{Digest, Domain, Hasher};
use alloc::vec::Vec;
use tiny_keccak::{Hasher as _, Keccak};

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

    /// Hash a stored leaf into its level-0 node under the dedicated leaf domain.
    /// This is what makes the tree second-preimage safe: a level-0 node carries the
    /// `MerkleLeaf` tag while inner nodes carry `MerkleNode`, so an inner node value
    /// can never be replayed as a leaf (RFC-6962-style separation). Stored leaves
    /// remain the raw note commitments (the archive maps `batch_id → commitment`).
    fn leaf_node(leaf: &Digest) -> Digest {
        H::hash_words(Domain::MerkleLeaf, &[*leaf])
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
        let mut level: Vec<Digest> = self.leaves.iter().map(Self::leaf_node).collect();
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
        let mut level: Vec<Digest> = self.leaves.iter().map(Self::leaf_node).collect();
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
        // hash the claimed leaf into its level-0 node under the leaf domain, so an
        // inner node value can never be accepted as a leaf (second-preimage safety).
        let mut node = Self::leaf_node(leaf);
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

// ---------------------------------------------------------------------------
// L1-settlement trees — no_std Merkle tree + domain-separated leaves, moved from
// `crates/gateway/src/withdrawals.rs` so the zkVM guest and the gateway share one
// implementation. See the module docs ("L1-settlement trees") for the byte layout.
// ---------------------------------------------------------------------------

fn keccak(parts: &[&[u8]]) -> Digest {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// A withdrawal tree leaf: `keccak(to(20) || amount(uint256 BE) || nonce(uint256 BE))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawalLeaf {
    pub to: [u8; 20],
    pub amount: u128,
    pub nonce: u64,
}

/// `keccak256(abi.encodePacked(address to, uint256 amount, uint256 nonce))`.
pub fn withdrawal_leaf(to: &[u8; 20], amount: u128, nonce: u64) -> Digest {
    let mut amt = [0u8; 32];
    amt[16..].copy_from_slice(&amount.to_be_bytes()); // u128 → low 16 bytes
    let mut non = [0u8; 32];
    non[24..].copy_from_slice(&nonce.to_be_bytes()); // u64 → low 8 bytes
    keccak(&[to, &amt, &non])
}

/// `keccak256(abi.encodePacked(uint8(0), uint256 batchId, bytes32 orderHash))`.
pub fn inclusion_leaf(batch_id: u64, order_hash: &Digest) -> Digest {
    let mut bid = [0u8; 32];
    bid[24..].copy_from_slice(&batch_id.to_be_bytes());
    keccak(&[&[0x00u8], &bid, order_hash])
}

/// `keccak256(abi.encodePacked(uint8(1), uint256 batchId, bytes32 orderHash))`.
pub fn rejection_leaf(batch_id: u64, order_hash: &Digest) -> Digest {
    let mut bid = [0u8; 32];
    bid[24..].copy_from_slice(&batch_id.to_be_bytes());
    keccak(&[&[0x01u8], &bid, order_hash])
}

fn hash_pair(a: Digest, b: Digest) -> Digest {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    keccak(&[&lo, &hi])
}

fn next_level(level: &[Digest]) -> Vec<Digest> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        if i + 1 < level.len() {
            next.push(hash_pair(level[i], level[i + 1]));
            i += 2;
        } else {
            next.push(level[i]); // odd node promoted unchanged
            i += 1;
        }
    }
    next
}

/// Sorted-pair Merkle root (odd node promoted). Empty → `0x0`, matching the contract's
/// unset `withdrawalsRoot` (nothing claimable).
pub fn merkle_root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// Merkle root of a batch's ordered order-hashes (the `orderedRoot` in the commitment).
pub fn ordered_root(batch_id: u64, ordered: &[Digest]) -> Digest {
    let leaves: Vec<Digest> = ordered
        .iter()
        .map(|oh| inclusion_leaf(batch_id, oh))
        .collect();
    merkle_root(&leaves)
}

/// Merkle root of a batch's validly-rejected order-hashes (the `rejectedRoot`).
pub fn rejected_root(batch_id: u64, rejected: &[Digest]) -> Digest {
    let leaves: Vec<Digest> = rejected
        .iter()
        .map(|oh| rejection_leaf(batch_id, oh))
        .collect();
    merkle_root(&leaves)
}

/// Merkle root of this batch's withdrawal leaves (the incremental `withdrawalsRoot`).
pub fn withdrawals_root(leaves: &[WithdrawalLeaf]) -> Digest {
    let hashed: Vec<Digest> = leaves
        .iter()
        .map(|w| withdrawal_leaf(&w.to, w.amount, w.nonce))
        .collect();
    merkle_root(&hashed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Domain;
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
    fn proof_is_bound_to_its_leaf_index() {
        // The leaf index drives the left/right parity at every level, so a valid
        // sibling path must not verify if re-pointed at a different index — this is
        // what stops a proof for one slot being replayed for another.
        let mut t = T::new(6);
        for i in 0..10u64 {
            t.append(word_u64(i + 1)).unwrap();
        }
        let root = t.root();
        let mut p = t.prove(3).unwrap();
        let leaf = word_u64(4); // the leaf stored at index 3
        assert!(T::verify(&root, &leaf, &p));
        p.leaf_index = 5;
        assert!(!T::verify(&root, &leaf, &p), "proof bound to its index");
    }

    #[test]
    fn tampered_sibling_rejected() {
        let mut t = T::new(6);
        for i in 0..10u64 {
            t.append(word_u64(i + 1)).unwrap();
        }
        let root = t.root();
        let mut p = t.prove(2).unwrap();
        p.siblings[0] = word_u64(0xDEAD);
        assert!(
            !T::verify(&root, &word_u64(3), &p),
            "tampered path rejected"
        );
    }

    #[test]
    fn internal_node_is_not_a_valid_leaf() {
        // Second-preimage resistance: leaves (note commitments) and inner nodes are
        // hashed under DIFFERENT domains, so an inner node value cannot be passed off
        // as a leaf. Re-deriving the level-0 node and offering it as a leaf at the
        // parent index must not verify against the root.
        let mut t = T::new(4);
        for i in 0..4u64 {
            t.append(word_u64(i + 1)).unwrap();
        }
        let root = t.root();
        // the actual inner node covering leaves 0,1 (its children are leaf-domained)
        let l0 = Keccak256::hash_words(Domain::MerkleLeaf, &[word_u64(1)]);
        let l1 = Keccak256::hash_words(Domain::MerkleLeaf, &[word_u64(2)]);
        let inner = Keccak256::compress(Domain::MerkleNode, &l0, &l1);
        // try to use that inner node as a leaf with the path from level 1 up
        let p = t.prove(0).unwrap();
        let forged = MerkleProof {
            leaf_index: 0,
            siblings: p.siblings[1..].to_vec(),
        };
        assert!(
            !T::verify(&root, &inner, &forged),
            "an inner node must not be accepted as a leaf (it is re-hashed under the leaf domain)"
        );
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

/// Byte-identity tests for the L1-settlement tree builders. Every pinned literal is
/// copied VERBATIM from `crates/gateway/src/withdrawals.rs`'s tests
/// (`leaf_matches_solidity_abi_encode_packed`, `challenge_leaves_match_solidity`),
/// which are themselves locked to the Solidity contracts via
/// `cast keccak $(cast abi-encode --packed ...)`.
#[cfg(test)]
mod settlement_tests {
    use super::*;

    fn h(s: &str) -> Digest {
        // deterministic 32-byte fixture from an ascii label
        let mut out = [0u8; 32];
        let b = s.as_bytes();
        out[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
        out
    }

    // keccak256(abi.encodePacked(address(0x..A11c), uint256(2_000_000_000), uint256(7)))
    // = 0x23364960683ed6fd90133ecd0211d3fdf2945779e400729471f69c45cb699932
    // (gateway test `leaf_matches_solidity_abi_encode_packed`, first vector).
    const EXPECTED_WITHDRAWAL_LEAF: Digest = [
        0x23, 0x36, 0x49, 0x60, 0x68, 0x3e, 0xd6, 0xfd, 0x90, 0x13, 0x3e, 0xcd, 0x02, 0x11, 0xd3,
        0xfd, 0xf2, 0x94, 0x57, 0x79, 0xe4, 0x00, 0x72, 0x94, 0x71, 0xf6, 0x9c, 0x45, 0xcb, 0x69,
        0x99, 0x32,
    ];

    // keccak256(abi.encodePacked(address(0), uint256(1), uint256(1)))
    // = 0x4e641f195fa577e5e909e012d9b75354bf06ec15a5d1aa2dca05d496c62ab460
    // (gateway test `leaf_matches_solidity_abi_encode_packed`, second vector).
    const EXPECTED_WITHDRAWAL_LEAF_ZERO_1_1: Digest = [
        0x4e, 0x64, 0x1f, 0x19, 0x5f, 0xa5, 0x77, 0xe5, 0xe9, 0x09, 0xe0, 0x12, 0xd9, 0xb7, 0x53,
        0x54, 0xbf, 0x06, 0xec, 0x15, 0xa5, 0xd1, 0xaa, 0x2d, 0xca, 0x05, 0xd4, 0x96, 0xc6, 0x2a,
        0xb4, 0x60,
    ];

    // Locked against contracts/src/CollateralVault.sol `keccak256(abi.encodePacked(
    // address to, uint256 amount, uint256 nonce))` — the same vector the gateway's
    // `leaf_matches_solidity_abi_encode_packed` test asserts.
    #[test]
    fn withdrawal_leaf_matches_solidity_vector() {
        // to = address(0x..A11c), amount = 2_000_000_000 (2,000 USDC), nonce = 7
        let mut to = [0u8; 20];
        to[18] = 0xA1;
        to[19] = 0x1c;
        assert_eq!(
            withdrawal_leaf(&to, 2_000_000_000, 7),
            EXPECTED_WITHDRAWAL_LEAF
        );
        // address(0), amount = 1, nonce = 1
        assert_eq!(
            withdrawal_leaf(&[0u8; 20], 1, 1),
            EXPECTED_WITHDRAWAL_LEAF_ZERO_1_1
        );
    }

    /// inclusion/rejection leaves byte-locked to `DarkPerpSettlement.inclusionLeaf` /
    /// `rejectionLeaf` — the same pinned vectors as the gateway's
    /// `challenge_leaves_match_solidity` test.
    #[test]
    fn challenge_leaves_match_solidity_vectors() {
        let oh = [0x11u8; 32];
        // keccak256(abi.encodePacked(uint8(0), uint256(0), oh))
        assert_eq!(
            inclusion_leaf(0, &oh),
            [
                0xfb, 0x6a, 0x66, 0xd6, 0xde, 0x8c, 0xab, 0x57, 0x46, 0x09, 0xdf, 0x74, 0xaf, 0xac,
                0x53, 0x59, 0x39, 0xf6, 0xf5, 0x7d, 0x84, 0x88, 0x97, 0xc3, 0x67, 0x47, 0xdf, 0xfe,
                0x5a, 0xf1, 0x22, 0x86,
            ]
        );
        // keccak256(abi.encodePacked(uint8(1), uint256(0), oh))
        assert_eq!(
            rejection_leaf(0, &oh),
            [
                0x88, 0x44, 0x49, 0xc1, 0xb0, 0x0c, 0xe2, 0xad, 0x1d, 0xff, 0xd3, 0x5d, 0xd2, 0x82,
                0xd2, 0xb8, 0x9c, 0xb6, 0x90, 0x53, 0xce, 0x7d, 0xaf, 0x1a, 0xd5, 0xe3, 0x19, 0x65,
                0x38, 0x87, 0xdf, 0xdb,
            ]
        );
        // keccak256(abi.encodePacked(uint8(0), uint256(5), oh)) — batchId is bound
        assert_eq!(
            inclusion_leaf(5, &oh),
            [
                0xc1, 0xa2, 0xbf, 0x30, 0xc9, 0x9f, 0x52, 0xc7, 0x94, 0xd4, 0xaf, 0x1c, 0xcf, 0xd5,
                0xa8, 0x58, 0xa8, 0xfd, 0x85, 0xe1, 0x0c, 0xd5, 0x9f, 0xdc, 0xd7, 0xd1, 0xcf, 0xc2,
                0x63, 0x4f, 0xc1, 0x4b,
            ]
        );
    }

    #[test]
    fn challenge_leaves_domain_separated() {
        let oh = h("order-1");
        assert_ne!(inclusion_leaf(0, &oh), rejection_leaf(0, &oh));
        assert_ne!(inclusion_leaf(0, &oh), inclusion_leaf(5, &oh)); // batch-bound
    }

    #[test]
    fn empty_merkle_root_is_zero() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn ordered_root_matches_manual_tree() {
        let a = h("a");
        let b = h("b");
        let manual = merkle_root(&[inclusion_leaf(3, &a), inclusion_leaf(3, &b)]);
        assert_eq!(ordered_root(3, &[a, b]), manual);
    }

    #[test]
    fn rejected_and_withdrawals_roots_compose_their_leaves() {
        let a = h("rejected-1");
        // single-leaf tree: root == the (domain-tagged) leaf
        assert_eq!(rejected_root(9, &[a]), rejection_leaf(9, &a));
        let w = WithdrawalLeaf {
            to: [0x22u8; 20],
            amount: 5_000_000,
            nonce: 42,
        };
        assert_eq!(
            withdrawals_root(&[w]),
            withdrawal_leaf(&w.to, w.amount, w.nonce)
        );
    }
}
