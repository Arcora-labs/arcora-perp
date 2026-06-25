// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkVerifier} from "../interfaces/IZkVerifier.sol";

/// @title MockZkVerifier
/// @notice Test/testnet stand-in for the real ZK verifier (see docs/PROVING.md).
/// Accepts a proof iff it equals `abi.encode(publicCommitment)`, mirroring the
/// commitment-based `CommitmentProver` in `crates/prover`. NOT sound; never
/// deploy to mainnet. A `forceReject` switch lets tests simulate a bad proof.
contract MockZkVerifier is IZkVerifier {
    bool public forceReject;

    function setForceReject(bool v) external {
        forceReject = v;
    }

    function verify(bytes32 publicCommitment, bytes calldata proof) external view returns (bool) {
        if (forceReject) return false;
        return proof.length == 32 && bytes32(proof) == publicCommitment;
    }
}
