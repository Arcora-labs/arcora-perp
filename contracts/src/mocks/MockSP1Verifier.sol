// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISP1Verifier} from "../interfaces/ISP1Verifier.sol";

/// @title MockSP1Verifier
/// @notice Test/dev double for the SP1VerifierGateway. `verifyProof` reverts unless
/// `(programVKey, publicValues, proofBytes)` equal the configured expected tuple —
/// mirroring SP1's revert-on-invalid-proof behavior. NOT sound; test-only.
contract MockSP1Verifier is ISP1Verifier {
    bytes32 public expectedVKey;
    bytes public expectedPublicValues;
    bytes public expectedProof;

    error MockProofRejected();

    function setExpected(bytes32 vkey, bytes calldata publicValues, bytes calldata proof) external {
        expectedVKey = vkey;
        expectedPublicValues = publicValues;
        expectedProof = proof;
    }

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes)
        external
        view
    {
        if (
            programVKey != expectedVKey
                || keccak256(publicValues) != keccak256(expectedPublicValues)
                || keccak256(proofBytes) != keccak256(expectedProof)
        ) {
            revert MockProofRejected();
        }
    }
}
