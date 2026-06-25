// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MerkleLib
/// @notice Standard sorted-pair keccak256 Merkle membership verification, used by
/// the inclusion-challenge game (§2): a user proves their order hash is a leaf of
/// a sealed batch's `orderedRoot`. Sorted-pair hashing is position-independent and
/// matches widely-audited implementations.
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
