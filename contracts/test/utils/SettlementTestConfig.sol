// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "./MiniTest.sol";
import {DarkPerpSettlement} from "../../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../../src/CollateralVault.sol";
import {IZkVerifier} from "../../src/interfaces/IZkVerifier.sol";

/// @title SettlementTestConfig
/// @notice Test helpers for building `DarkPerpSettlement.Config` and for signing the
/// two off-chain authorizations the contracts verify (enclave challenge authorization,
/// gateway deposit permit). The digests are computed locally, never by calling the
/// target, so the helpers can be used inline after `vm.prank` / `vm.expectRevert`.
/// Test-only.
library SettlementTestConfig {
    uint256 internal constant LIVENESS_BLOCKS = 100;
    uint256 internal constant CHALLENGE_GRACE_BLOCKS = 50;
    uint256 internal constant CHALLENGE_BOND = 1 ether;
    uint256 internal constant INCLUSION_DEADLINE_SECS = 600;
    uint256 internal constant FINAL_SETTLE_GRACE_BLOCKS = 10;
    uint256 internal constant PROGRESS_BATCHES = 2;
    uint256 internal constant SLASH_PAYOUT_CAP = 1_000e6;
    bytes32 internal constant CHALLENGE_AUTH_TAG = keccak256("arcora:l1-inclusion-challenge:v1");
    bytes32 internal constant DEPOSIT_PERMIT_TAG = keccak256("arcora:deposit-permit:v2");

    /// Test defaults: governance = `sequencer`, liveness 100 blocks, challenge grace 50
    /// blocks, challenge bond 1 ether, inclusion deadline 600 s, final-settle grace 10
    /// blocks, 2 progress batches, slash cap 1,000e6. Override fields on the returned
    /// memory struct before deploying.
    function defaults(address sequencer, address enclaveSigner, IZkVerifier verifier, bytes32 genesisRoot)
        internal
        pure
        returns (DarkPerpSettlement.Config memory c)
    {
        c.sequencer = sequencer;
        c.enclaveSigner = enclaveSigner;
        c.verifier = verifier;
        c.genesisRoot = genesisRoot;
        c.livenessTimeoutBlocks = LIVENESS_BLOCKS;
        c.challengeGraceBlocks = CHALLENGE_GRACE_BLOCKS;
        c.challengeBond = CHALLENGE_BOND;
        c.inclusionDeadlineSecs = INCLUSION_DEADLINE_SECS;
        c.governance = sequencer;
        c.finalSettleGraceBlocks = FINAL_SETTLE_GRACE_BLOCKS;
        c.progressBatches = PROGRESS_BATCHES;
        c.slashPayoutCap = SLASH_PAYOUT_CAP;
    }

    /// The previous ten constructor arguments, in their order (the old challenge window
    /// becomes `challengeGraceBlocks`), plus the default progress batches and slash cap.
    function legacy(
        address sequencer,
        address enclaveSigner,
        IZkVerifier verifier,
        bytes32 genesisRoot,
        uint256 livenessTimeoutBlocks,
        uint256 challengeGraceBlocks,
        uint256 challengeBond,
        uint256 inclusionDeadlineSecs,
        address governance,
        uint256 finalSettleGraceBlocks
    ) internal pure returns (DarkPerpSettlement.Config memory c) {
        c.sequencer = sequencer;
        c.enclaveSigner = enclaveSigner;
        c.verifier = verifier;
        c.genesisRoot = genesisRoot;
        c.livenessTimeoutBlocks = livenessTimeoutBlocks;
        c.challengeGraceBlocks = challengeGraceBlocks;
        c.challengeBond = challengeBond;
        c.inclusionDeadlineSecs = inclusionDeadlineSecs;
        c.governance = governance;
        c.finalSettleGraceBlocks = finalSettleGraceBlocks;
        c.progressBatches = PROGRESS_BATCHES;
        c.slashPayoutCap = SLASH_PAYOUT_CAP;
    }

    /// Constructor arguments (twelve words) for etching a settlement at a fixed address.
    function encode(DarkPerpSettlement.Config memory c) internal pure returns (bytes memory) {
        return abi.encode(c);
    }

    /// Same preimage as `DarkPerpSettlement.challengeAuthDigest`, computed locally (no
    /// external call, so it is safe as an argument after `vm.prank`/`vm.expectRevert`).
    function challengeAuthDigest(
        address settlement,
        bytes32 orderHash,
        uint64 seqNo,
        uint64 recvTimeMs,
        uint64 batchIdHint,
        address beneficiary
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                CHALLENGE_AUTH_TAG, block.chainid, settlement, orderHash, seqNo, recvTimeMs, batchIdHint, beneficiary
            )
        );
    }

    /// Same preimage as `CollateralVault.permitDigest`, computed locally.
    function permitDigest(address vault, address from, bytes32 ownerCommit, uint256 amount, uint64 validUntil)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(DEPOSIT_PERMIT_TAG, block.chainid, vault, from, ownerCommit, amount, uint256(validUntil))
        );
    }

    /// `r‖s‖v` enclave signature over the challenge authorization at the current chain.
    function challengeSig(
        Vm vm,
        uint256 enclavePk,
        DarkPerpSettlement s,
        bytes32 orderHash,
        uint64 seqNo,
        uint64 recvTimeMs,
        uint64 batchIdHint,
        address beneficiary
    ) internal view returns (bytes memory) {
        bytes32 digest = challengeAuthDigest(address(s), orderHash, seqNo, recvTimeMs, batchIdHint, beneficiary);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(enclavePk, digest);
        return abi.encodePacked(r, sg, v);
    }

    /// `r‖s‖v` gateway signature over the deposit permit at the current chain.
    function permitSig(
        Vm vm,
        uint256 gatewayPk,
        CollateralVault vault,
        address from,
        bytes32 ownerCommit,
        uint256 amount,
        uint64 validUntil
    ) internal view returns (bytes memory) {
        bytes32 digest = permitDigest(address(vault), from, ownerCommit, amount, validUntil);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(gatewayPk, digest);
        return abi.encodePacked(r, sg, v);
    }
}
