// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

contract DarkPerpSettlementTest is MiniTest {
    DarkPerpSettlement internal s;
    MockZkVerifier internal verifier;

    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    address internal enclaveSigner;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    uint256 internal constant LIVENESS = 100;
    uint256 internal constant CHALLENGE_WINDOW = 50;

    // this contract is the sequencer
    function setUp() public {
        verifier = new MockZkVerifier();
        enclaveSigner = vm.addr(ENCLAVE_PK);
        s = new DarkPerpSettlement(
            address(this), enclaveSigner, verifier, GENESIS, LIVENESS, CHALLENGE_WINDOW
        );
    }

    function _proofFor(bytes32 prev, bytes32 manifest, bytes32 newRoot) internal view returns (bytes memory) {
        return abi.encode(s.publicCommitment(prev, manifest, newRoot));
    }

    function test_settle_advances_root() public {
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m0");
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), _proofFor(GENESIS, manifest, newRoot));
        assertEq(s.currentStateRoot(), newRoot, "root advanced");
        assertEq(s.batchCount(), 1, "batch counted");
    }

    function test_settle_rejects_bad_prev_root() public {
        bytes32 wrongPrev = bytes32(uint256(99));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proofFor(wrongPrev, manifest, newRoot);
        vm.expectRevert(DarkPerpSettlement.BadPrevRoot.selector);
        s.settleBatch(wrongPrev, manifest, newRoot, bytes32(0), bytes32(0), proof);
    }

    function test_settle_rejects_bad_proof() public {
        verifier.setForceReject(true);
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proofFor(GENESIS, manifest, newRoot);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), proof);
    }

    function test_liveness_triggers_close_only() public {
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
        vm.roll(block.number + LIVENESS + 1);
        s.triggerCloseOnly();
        assertTrue(s.closeOnly(), "close-only after liveness timeout");
    }

    function test_settle_blocked_in_close_only() public {
        vm.roll(block.number + LIVENESS + 1);
        s.triggerCloseOnly();
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proofFor(GENESIS, manifest, newRoot);
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), proof);
    }

    function test_inclusion_answered_clears_challenge() public {
        // settle a batch whose orderedRoot is a single leaf = orderHash
        bytes32 orderHash = keccak256("order-1");
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        s.settleBatch(GENESIS, manifest, newRoot, orderHash, bytes32(0), _proofFor(GENESIS, manifest, newRoot));

        // user challenges with an enclave-signed receipt
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 7, 1000, 0));
        address challenger = address(0xBEEF);
        vm.prank(challenger);
        s.challengeInclusion(orderHash, 7, 1000, 0, v, r, sig);

        // sequencer answers with an empty Merkle proof (single-leaf tree)
        bytes32[] memory proof = new bytes32[](0);
        s.answerChallenge(orderHash, 0, proof);
        (,,, bool open) = s.challenges(orderHash);
        assertFalse(open, "challenge cleared");
    }

    function test_inclusion_unanswered_slashes_bond() public {
        // sequencer posts a bond
        uint256 bond = 5 ether;
        vm.deal(address(this), bond);
        s.postBond{value: bond}();
        assertEq(s.sequencerBond(), bond, "bond posted");

        // user challenges a withheld order
        bytes32 orderHash = keccak256("withheld");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        address challenger = address(0xCAFE);
        vm.prank(challenger);
        s.challengeInclusion(orderHash, 1, 1, 0, v, r, sig);

        // sequencer never answers; window expires
        vm.expectRevert(DarkPerpSettlement.ChallengeNotExpired.selector);
        s.slashUnanswered(orderHash);
        vm.roll(block.number + CHALLENGE_WINDOW + 1);
        s.slashUnanswered(orderHash);

        assertTrue(s.slashed(), "sequencer slashed");
        assertTrue(s.closeOnly(), "slash forces close-only");
        assertEq(s.sequencerBond(), 0, "bond drained");
        assertEq(challenger.balance, bond, "bond paid to challenger");
    }

    function test_bad_receipt_signature_rejected() public {
        bytes32 orderHash = keccak256("x");
        // sign with the WRONG key
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(0xBADBAD, s.receiptDigest(orderHash, 1, 1, 0));
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion(orderHash, 1, 1, 0, v, r, sig);
    }

    receive() external payable {}
}
