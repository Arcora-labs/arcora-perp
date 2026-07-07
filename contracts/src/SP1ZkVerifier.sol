// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkVerifier} from "./interfaces/IZkVerifier.sol";
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";

/// @title SP1ZkVerifier
/// @notice Real SP1 (Groth16) validity-proof verifier — the mainnet replacement for
/// MockZkVerifier. Adapts SP1's revert-based `ISP1Verifier` to DarkPerpSettlement's bool
/// `IZkVerifier`. The guest commits exactly the 32-byte publicCommitment via
/// `commit_slice`, so SP1's `publicValues == abi.encodePacked(publicCommitment)`.
/// `programVKey` pins THIS guest program (vkey binding) — a proof for any other program
/// fails. Targets the SP1VerifierGateway so it stays valid across SP1 verifier versions
/// (the proof's 4-byte prefix selects the version). `DarkPerpSettlement.verifier` is
/// immutable, so swapping MockZkVerifier for this is a redeploy.
contract SP1ZkVerifier is IZkVerifier {
    bytes32 public immutable programVKey;
    ISP1Verifier public immutable gateway;

    constructor(ISP1Verifier _gateway, bytes32 _programVKey) {
        gateway = _gateway;
        programVKey = _programVKey;
    }

    /// @inheritdoc IZkVerifier
    /// @dev SP1's `verifyProof` reverts on an invalid proof; map revert → false to satisfy
    /// the bool contract `settleBatch` expects (it reverts `BadProof` when this returns false).
    function verify(bytes32 publicCommitment, bytes calldata proof)
        external
        view
        returns (bool)
    {
        try gateway.verifyProof(programVKey, abi.encodePacked(publicCommitment), proof) {
            return true;
        } catch {
            return false;
        }
    }
}
