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
    uint256 internal constant CHALLENGE_BOND = 1 ether;

    // this contract is the sequencer
    function setUp() public {
        verifier = new MockZkVerifier();
        enclaveSigner = vm.addr(ENCLAVE_PK);
        s = new DarkPerpSettlement(
            address(this), enclaveSigner, verifier, GENESIS, LIVENESS, CHALLENGE_WINDOW, CHALLENGE_BOND
        );
    }

    function _proof(bytes32 prev, bytes32 m, bytes32 n, bytes32 ord, bytes32 wd)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(s.publicCommitment(prev, m, n, ord, wd));
    }

    function test_settle_advances_root() public {
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m0");
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), _proof(GENESIS, manifest, newRoot, bytes32(0), bytes32(0)));
        assertEq(s.currentStateRoot(), newRoot, "root advanced");
        assertEq(s.batchCount(), 1, "batch counted");
    }

    function test_settle_binds_withdrawals_root() public {
        // a proof valid for one withdrawalsRoot must NOT settle with a different
        // withdrawalsRoot (audit F2): the roots are part of the commitment.
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proof(GENESIS, manifest, newRoot, bytes32(0), keccak256("authorized"));
        // attacker swaps in a malicious withdrawals root with the same proof
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), keccak256("attacker"), proof);
        // the correct withdrawals root settles
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), keccak256("authorized"), proof);
        assertEq(s.currentStateRoot(), newRoot, "settled with bound withdrawals root");
    }

    function test_settle_rejects_bad_prev_root() public {
        bytes32 wrongPrev = bytes32(uint256(99));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proof(wrongPrev, manifest, newRoot, bytes32(0), bytes32(0));
        vm.expectRevert(DarkPerpSettlement.BadPrevRoot.selector);
        s.settleBatch(wrongPrev, manifest, newRoot, bytes32(0), bytes32(0), proof);
    }

    function test_settle_rejects_bad_proof() public {
        verifier.setForceReject(true);
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proof(GENESIS, manifest, newRoot, bytes32(0), bytes32(0));
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
        bytes memory proof = _proof(GENESIS, manifest, newRoot, bytes32(0), bytes32(0));
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), proof);
    }

    function test_inclusion_answered_clears_challenge() public {
        // settle a batch whose orderedRoot is the single domain-separated leaf
        bytes32 orderHash = keccak256("order-1");
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        s.settleBatch(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0)));

        // user challenges with an enclave-signed receipt (canonical via vm.sign)
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 7, 1000, 0));
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 7, 1000, 0, v, r, sig);

        // sequencer answers with an empty proof (single-leaf tree); stake forfeits
        bytes32[] memory proof = new bytes32[](0);
        s.answerChallenge(orderHash, 0, proof);
        (,,,,, bool open) = s.challenges(orderHash);
        assertFalse(open, "challenge cleared");
    }

    function test_answer_cannot_use_batch_settled_after_challenge() public {
        // a censoring sequencer must not manufacture a fresh batch to escape (F1)
        bytes32 orderHash = keccak256("withheld");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);

        // sequencer now settles a NEW batch containing the orderHash
        vm.roll(block.number + 1);
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("late");
        s.settleBatch(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0)));

        // answering against that fresh batch is rejected
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(DarkPerpSettlement.BatchNotOlderThanChallenge.selector);
        s.answerChallenge(orderHash, 0, proof);
    }

    function test_inclusion_unanswered_slashes_bond() public {
        uint256 bond = 5 ether;
        vm.deal(address(this), bond);
        s.postBond{value: bond}();

        bytes32 orderHash = keccak256("withheld");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        address challenger = address(0xCAFE);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);

        vm.expectRevert(DarkPerpSettlement.ChallengeNotExpired.selector);
        s.slashUnanswered(orderHash);
        vm.roll(block.number + CHALLENGE_WINDOW + 1);
        s.slashUnanswered(orderHash);

        assertTrue(s.slashed(), "sequencer slashed");
        assertTrue(s.closeOnly(), "slash forces close-only");
        assertEq(s.sequencerBond(), 0, "bond drained");
        // challenger receives the slashed bond + its refunded stake
        assertEq(challenger.balance, bond + CHALLENGE_BOND, "slashed bond + refunded stake");
    }

    function test_challenge_requires_bond() public {
        bytes32 orderHash = keccak256("x");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        vm.expectRevert(DarkPerpSettlement.WrongChallengeBond.selector);
        s.challengeInclusion(orderHash, 1, 1, 0, v, r, sig); // no value
    }

    function test_non_canonical_signature_rejected() public {
        bytes32 orderHash = keccak256("x");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        // flip s to its high (non-canonical) complement and adjust v
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(n - uint256(sig));
        uint8 flippedV = v == 27 ? 28 : 27;
        vm.deal(address(this), CHALLENGE_BOND);
        vm.expectRevert(DarkPerpSettlement.NonCanonicalSignature.selector);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, flippedV, r, highS);
    }

    function test_bad_receipt_signature_rejected() public {
        bytes32 orderHash = keccak256("x");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(0xBADBAD, s.receiptDigest(orderHash, 1, 1, 0));
        vm.deal(address(this), CHALLENGE_BOND);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);
    }

    receive() external payable {}
}
