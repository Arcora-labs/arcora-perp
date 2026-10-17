// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkVerifier} from "../../src/interfaces/IZkVerifier.sol";

/// @title MockClockVerifier
/// @notice Test-only verifier with the shape DarkPerpSettlement's constructor requires
/// of a clock-bound verifier (`proofVersion() == 2`, `settlement() == address(0)`), and
/// MockZkVerifier's acceptance rule: a proof is valid iff it is exactly the 32-byte
/// commitment (`abi.encode(c)` or `abi.encodePacked(c)`). No clock is enforced. NOT
/// sound; never deploy.
contract MockClockVerifier is IZkVerifier {
    /// Reported proof version; 2 unless a test changes it with `setShape`.
    uint64 public proofVersion = 2;
    /// Reported bound settlement; zero unless a test changes it with `setShape`.
    address public settlement;
    /// When true every proof is rejected.
    bool public forceReject;

    function setForceReject(bool v) external {
        forceReject = v;
    }

    /// Changes what the shape getters report, to exercise the constructor's refusal.
    function setShape(uint64 version, address boundSettlement) external {
        proofVersion = version;
        settlement = boundSettlement;
    }

    function verify(bytes32 publicCommitment, bytes calldata proof) external view returns (bool) {
        if (forceReject) return false;
        return proof.length == 32 && bytes32(proof) == publicCommitment;
    }
}
