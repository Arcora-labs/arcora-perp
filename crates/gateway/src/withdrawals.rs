//! Off-chain construction of the cumulative withdrawals Merkle tree the
//! `CollateralVault` releases USDC against (§3). The leaf and tree shape must match
//! `contracts/src/CollateralVault.sol` + `MerkleLib.sol` EXACTLY, or a proof built
//! here would not verify on-chain:
//!   - leaf = `keccak256(abi.encodePacked(address to, uint256 amount, uint256 nonce))`
//!   - internal node = `keccak256(min(a,b) || max(a,b))` (sorted-pair, no domain tag)
//!
//! The gateway keeps a list of every authorized-but-unclaimed withdrawal, prunes the
//! ones the vault already marks `claimed`, and rebuilds the **cumulative** root each
//! L1 settle — honoring the prover-side invariant documented on
//! `CollateralVault.publishWithdrawals` (a new root must carry forward every leaf
//! that is still unclaimed, else it strands the user).

use sha3::{Digest, Keccak256};

/// One authorized withdrawal: `amount` USDC base units released to the 20-byte
/// address `to` on L1, unique by `nonce`. `owner` is the off-chain engine account it
/// belongs to (NOT part of the leaf) — used only to filter `/v1/accounts/withdrawals`.
#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub owner: [u8; 32],
    pub to: [u8; 20],
    pub amount: u128,
    pub nonce: u64,
}

impl Withdrawal {
    pub fn leaf(&self) -> [u8; 32] {
        withdrawal_leaf(&self.to, self.amount, self.nonce)
    }
}

/// `keccak256(abi.encodePacked(to(20), amount(uint256 big-endian), nonce(uint256 big-endian)))`.
pub fn withdrawal_leaf(to: &[u8; 20], amount: u128, nonce: u64) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(to);
    let mut amt = [0u8; 32];
    amt[16..].copy_from_slice(&amount.to_be_bytes()); // u128 → low 16 bytes of the uint256
    h.update(amt);
    let mut non = [0u8; 32];
    non[24..].copy_from_slice(&nonce.to_be_bytes()); // u64 → low 8 bytes of the uint256
    h.update(non);
    h.finalize().into()
}

fn hash_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Keccak256::new();
    h.update(lo);
    h.update(hi);
    h.finalize().into()
}

fn next_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
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

/// Sorted-pair Merkle root over `leaves` (odd node promoted). Empty → `0x0`, which
/// matches the contract's unset `withdrawalsRoot` (nothing is claimable).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// Merkle proof (sibling path) for `leaves[index]`, verifiable by `MerkleLib.verify`.
pub fn merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    let mut idx = index;
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let sib = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx.wrapping_sub(1)
        };
        if sib < level.len() {
            proof.push(level[sib]);
        }
        idx /= 2;
        level = next_level(&level);
    }
    proof
}

/// `MerkleLib.verify`, replicated for tests and a self-check before publishing a root.
#[allow(dead_code)]
pub fn verify(root: [u8; 32], leaf: [u8; 32], proof: &[[u8; 32]]) -> bool {
    let mut computed = leaf;
    for p in proof {
        computed = hash_pair(computed, *p);
    }
    computed == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        let h = s.strip_prefix("0x").unwrap_or(s);
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// The leaf encoding is byte-locked to Solidity's `abi.encodePacked` — these
    /// vectors come from `cast keccak $(cast abi-encode --packed ...)`.
    #[test]
    fn leaf_matches_solidity_abi_encode_packed() {
        // address(0x..A11c), amount = 2_000_000_000 (2,000 USDC), nonce = 7
        let mut to = [0u8; 20];
        to[18] = 0xA1;
        to[19] = 0x1c;
        assert_eq!(
            withdrawal_leaf(&to, 2_000_000_000, 7),
            h("0x23364960683ed6fd90133ecd0211d3fdf2945779e400729471f69c45cb699932"),
        );
        // address(0), amount = 1, nonce = 1
        assert_eq!(
            withdrawal_leaf(&[0u8; 20], 1, 1),
            h("0x4e641f195fa577e5e909e012d9b75354bf06ec15a5d1aa2dca05d496c62ab460"),
        );
    }

    #[test]
    fn empty_tree_is_zero_root() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_is_the_leaf_with_empty_proof() {
        let l = withdrawal_leaf(&[1u8; 20], 5, 9);
        assert_eq!(merkle_root(&[l]), l);
        assert!(merkle_proof(&[l], 0).is_empty());
        assert!(verify(l, l, &[]));
    }

    /// Two-leaf root matches the exact construction the Solidity test uses:
    /// `root = la <= lb ? keccak(la,lb) : keccak(lb,la)`, and each proof verifies.
    #[test]
    fn two_leaf_round_trip() {
        let mut alice = [0u8; 20];
        alice[19] = 0xCE;
        let mut bob = [0u8; 20];
        bob[19] = 0x0B;
        let la = withdrawal_leaf(&alice, 2_000_000_000, 1);
        let lb = withdrawal_leaf(&bob, 1_000_000_000, 2);
        let leaves = [la, lb];
        let root = merkle_root(&leaves);
        assert_eq!(root, hash_pair(la, lb));
        // alice's proof is [lb] and verifies; bob's is [la] and verifies
        assert_eq!(merkle_proof(&leaves, 0), vec![lb]);
        assert!(verify(root, la, &merkle_proof(&leaves, 0)));
        assert!(verify(root, lb, &merkle_proof(&leaves, 1)));
    }

    /// Every leaf's proof verifies against the root for trees of size 1..=9 (covers
    /// odd-node promotion at multiple levels).
    #[test]
    fn n_leaf_proofs_all_verify() {
        for n in 1..=9usize {
            let leaves: Vec<[u8; 32]> = (0..n)
                .map(|i| withdrawal_leaf(&[i as u8; 20], (i as u128 + 1) * 1_000_000, i as u64))
                .collect();
            let root = merkle_root(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = merkle_proof(&leaves, i);
                assert!(verify(root, *leaf, &proof), "n={n} i={i} proof must verify");
            }
        }
    }
}
