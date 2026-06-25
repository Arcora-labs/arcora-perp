// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MerkleLib
/// @notice Standard sorted-pair keccak256 Merkle membership verification.
/// @dev SECURITY: leaves and internal nodes share the same hash shape (32 bytes,
/// no domain tag), so callers MUST pass a `leaf` that is itself a hash of
/// structured data — never a raw, caller-chosen 32-byte value — otherwise an
/// attacker could present an internal node as a "leaf". Both call sites comply:
/// `CollateralVault.claim` uses `keccak256(to,amount,nonce)` and
/// `DarkPerpSettlement.answerChallenge` uses `inclusionLeaf(batchId, orderHash)`
/// (audit F1).
library MerkleLib {
    /// @return true iff `leaf` is a member of the tree with root `root`.
    function verify(bytes32 root, bytes32 leaf, bytes32[] calldata proof) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            computed = computed <= p
                ? keccak256(abi.encodePacked(computed, p))
                : keccak256(abi.encodePacked(p, computed));
        }
        return computed == root;
    }
}
