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

// The leaf + merkle builders now live in perp-core (no_std) so the zkVM guest and
// the gateway share one implementation — byte-identical trees off-chain and
// in-circuit. The tests below pin them to Solidity vectors, proving the moved code
// hashes exactly what the contracts verify.
pub use perp_core::merkle::{
    inclusion_leaf, merkle_proof, merkle_root, rejection_leaf, withdrawal_leaf,
};
// SEC-019: the blinded owner binding `ownerCommit = keccak(owner ‖ deposit_blind)`, used
// by the gateway credit path (misattribution guard) and the authorization endpoint.
pub use perp_core::merkle::owner_commit;
// The deposit hash-chain leaf/fold are exercised only from #[cfg(test)] (the credit-path
// vault-fold parity test); the re-export exists as a shared test oracle so a byte-drift
// between the gateway fold and the vault chain is caught locally — same posture as `verify`.
#[allow(unused_imports)]
pub use perp_core::merkle::{deposit_chain_fold, deposit_leaf};
// `verify` is only exercised from #[cfg(test)] code (the original local fn carried
// #[allow(dead_code)] for the same reason: it exists as a self-check + test oracle).
#[allow(unused_imports)]
pub use perp_core::merkle::verify;

/// One authorized withdrawal: `amount` USDC base units released to the 20-byte
/// address `to` on L1, unique by `nonce`. `owner` is the off-chain engine account it
/// belongs to (NOT part of the leaf) — used only to filter `/v1/accounts/withdrawals`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    fn h(s: &str) -> [u8; 32] {
        let h = s.strip_prefix("0x").unwrap_or(s);
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// Test-local replica of MerkleLib's sorted-pair node (`keccak(min||max)`), kept
    /// INDEPENDENT of perp-core so `two_leaf_round_trip` still asserts the internal
    /// node shape from first principles rather than trusting the code under test.
    fn hash_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let mut h = Keccak256::new();
        h.update(lo);
        h.update(hi);
        h.finalize().into()
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

    /// inclusion/rejection leaves are byte-locked to DarkPerpSettlement.inclusionLeaf /
    /// rejectionLeaf (audit DP-004). Vectors: cast keccak $(cast abi-encode --packed ...).
    #[test]
    fn challenge_leaves_match_solidity() {
        let oh = [0x11u8; 32];
        // domain-tagged (0x00) inclusion leaf — cast keccak of 0x00 ‖ uint256(batch) ‖ oh
        assert_eq!(
            inclusion_leaf(0, &oh),
            h("0xfb6a66d6de8cab574609df74afac535939f6f57d848897c36747dffe5af12286"),
        );
        assert_eq!(
            rejection_leaf(0, &oh),
            h("0x884449c1b00ce2ad1dffd35dd282d2b89cb69053ce7daf1ad5e319653887dfdb"),
        );
        // batchId is bound (a different batch → a different leaf)
        assert_eq!(
            inclusion_leaf(5, &oh),
            h("0xc1a2bf30c99f52c794d4af1ccfd5a858a8fd85e10cd59fdcd7d1cfc2634fc14b"),
        );
        // inclusion and rejection leaves never collide at the same (batch, order)
        assert_ne!(inclusion_leaf(0, &oh), rejection_leaf(0, &oh));
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
