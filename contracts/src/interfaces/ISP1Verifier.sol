// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISP1Verifier — Succinct SP1 on-chain verifier interface (copied from
/// Succinct's sp1-contracts ISP1Verifier.sol). `verifyProof` is `view`, returns
/// nothing, and REVERTS if the proof is invalid. The first 4 bytes of `proofBytes`
/// select the verifier version (VERIFIER_HASH), which the SP1VerifierGateway routes on.
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}
