// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IZkVerifier
/// @notice The batch validity-proof verifier (§4). A real implementation is the
/// Solidity verifier generated from the SP1/Risc0 circuit; `publicCommitment` is the
/// binding from `crates/prover::PublicInputs::commitment` / `perp_core::commitment::
/// DerivedRoots::commitment`:
/// `keccak256(abi.encodePacked(uint8(7), prevRoot, manifestHash, newRoot, orderedRoot,
/// withdrawalsRoot, rejectedRoot))`, where `7` is perp-core's `Domain::StateRoot` tag.
interface IZkVerifier {
    /// @param publicCommitment the proof's public-input commitment
    /// @param proof opaque proof bytes
    /// @return ok true iff the proof is valid for `publicCommitment`
    function verify(bytes32 publicCommitment, bytes calldata proof) external view returns (bool ok);
}
