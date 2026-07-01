// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

contract DarkPerpSettlementTest is MiniTest {
    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockZkVerifier internal verifier;

    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    address internal enclaveSigner;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    uint256 internal constant LIVENESS = 100;
    uint256 internal constant CHALLENGE_WINDOW = 50;
    uint256 internal constant CHALLENGE_BOND = 1 ether;
    uint256 internal constant USD = 1e6;

    // this contract is the sequencer
    function setUp() public {
        verifier = new MockZkVerifier();
        enclaveSigner = vm.addr(ENCLAVE_PK);
        s = new DarkPerpSettlement(
            address(this), enclaveSigner, verifier, GENESIS, LIVENESS, CHALLENGE_WINDOW, CHALLENGE_BOND
        );
        // wire a vault so the USDC sequencer bond can be posted; left unfunded, so
        // requiredBond() is 0 and the settle tests need no bond (audit Q1 floor = 0).
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc));
        s.setVault(address(vault));
    }

    /// The sequencer (this contract) posts a USDC bond of `amount`.
    function _bond(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    function _proof(bytes32 prev, bytes32 m, bytes32 n, bytes32 ord, bytes32 wd)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(s.publicCommitment(prev, m, n, ord, wd, bytes32(0)));
    }

    function test_settle_advances_root() public {
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m0");
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), _proof(GENESIS, manifest, newRoot, bytes32(0), bytes32(0)));
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
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), keccak256("attacker"), bytes32(0), proof);
        // the correct withdrawals root settles
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), keccak256("authorized"), bytes32(0), proof);
        assertEq(s.currentStateRoot(), newRoot, "settled with bound withdrawals root");
    }

    function test_settle_rejects_bad_prev_root() public {
        bytes32 wrongPrev = bytes32(uint256(99));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proof(wrongPrev, manifest, newRoot, bytes32(0), bytes32(0));
        vm.expectRevert(DarkPerpSettlement.BadPrevRoot.selector);
        s.settleBatch(wrongPrev, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), proof);
    }

    function test_settle_rejects_bad_proof() public {
        verifier.setForceReject(true);
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proof(GENESIS, manifest, newRoot, bytes32(0), bytes32(0));
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), proof);
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
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), proof);
    }

    function test_inclusion_answered_clears_challenge() public {
        // settle a batch whose orderedRoot is the single domain-separated leaf
        bytes32 orderHash = keccak256("order-1");
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        s.settleBatch(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0), _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0)));

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

    function test_answer_with_batch_settled_after_challenge_succeeds() public {
        // P2: settlement is async, so an order routinely settles AFTER a fresh
        // receipt could be challenged. Proving inclusion in that later (genuinely
        // settled) batch must answer the challenge — otherwise anyone could
        // free-slash the honest sequencer by challenging before the order settles.
        bytes32 orderHash = keccak256("settles-late");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);

        // the order's batch settles one block AFTER the challenge opened
        vm.roll(block.number + 1);
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("late");
        s.settleBatch(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0), _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0)));

        // the sequencer answers with that batch — inclusion is the cure, not an escape
        bytes32[] memory proof = new bytes32[](0);
        s.answerChallenge(orderHash, 0, proof);
        (,,,,, bool open) = s.challenges(orderHash);
        assertFalse(open, "challenge answered by genuine late inclusion");
    }

    function test_answer_rejected_when_batch_lacks_order() public {
        // anti-forge (the real F1 property, preserved): the leaf is bound to
        // (batchId, orderHash) over the batch's immutable orderedRoot, so the
        // sequencer cannot answer with a settled batch that does NOT contain the order.
        bytes32 orderHash = keccak256("withheld");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);

        // settle a batch whose orderedRoot commits to a DIFFERENT order
        bytes32 orderedRoot = s.inclusionLeaf(0, keccak256("some-other-order"));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("unrelated");
        s.settleBatch(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0), _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0)));

        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(DarkPerpSettlement.NotIncluded.selector);
        s.answerChallenge(orderHash, 0, proof);
    }

    function test_valid_rejection_answers_challenge() public {
        // audit DP-004: an order the sequencer VALIDLY REJECTED (e.g. an unfillable FOK)
        // still carries an enclave ACCEPTED receipt, so a user can open an inclusion
        // challenge the sequencer cannot answer by inclusion. Proving the order is in the
        // batch's committed rejectedRoot must clear the challenge — no wrongful slash.
        bytes32 orderHash = keccak256("validly-rejected");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);

        // settle a batch whose rejectedRoot is the single leaf for this order (it was
        // rejected, not ordered — orderedRoot commits to a different, real order)
        bytes32 rejectedRoot = s.rejectionLeaf(0, orderHash);
        bytes32 orderedRoot = s.inclusionLeaf(0, keccak256("some-ordered-order"));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("rej");
        bytes memory proof0 =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), rejectedRoot));
        s.settleBatch(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), rejectedRoot, proof0);

        bytes32[] memory proof = new bytes32[](0);
        s.answerByRejection(orderHash, 0, proof);
        (,,,,, bool open) = s.challenges(orderHash);
        assertFalse(open, "challenge answered by valid rejection, no wrongful slash");
    }

    function test_answer_by_rejection_requires_membership() public {
        // a sequencer cannot fabricate a rejection: an order NOT in the batch's committed
        // rejectedRoot cannot be answered by rejection, so real censorship stays slashable.
        bytes32 orderHash = keccak256("actually-withheld");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);

        // settle a batch whose rejectedRoot commits to a DIFFERENT order
        bytes32 rejectedRoot = s.rejectionLeaf(0, keccak256("some-other-rejected"));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("unrelated-rej");
        bytes memory proof0 =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), rejectedRoot));
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), rejectedRoot, proof0);

        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(DarkPerpSettlement.NotRejected.selector);
        s.answerByRejection(orderHash, 0, proof);
    }

    function test_answer_refund_is_pull_not_push() public {
        // audit DP-011: the challenger stake is CREDITED to the sequencer's pull-payment
        // balance on a successful answer, never pushed — so a non-payable sequencer can
        // still answer a challenge instead of being bricked and then slashed.
        bytes32 orderHash = keccak256("pull-order");
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        s.settleBatch(
            GENESIS, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0),
            _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0))
        );

        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 7, 1000, 0));
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 7, 1000, 0, v, r, sig);

        bytes32[] memory proof = new bytes32[](0);
        s.answerChallenge(orderHash, 0, proof);
        // credited for pull, not pushed
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "stake credited to the sequencer");

        // and the sequencer can pull it
        uint256 balBefore = address(this).balance;
        s.claimEth();
        assertEq(address(this).balance, balBefore + CHALLENGE_BOND, "sequencer pulls the refund");
        assertEq(s.pendingEth(address(this)), 0, "pending cleared after claim");
    }

    function _depositToVault(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(vault), amount);
        vault.deposit(amount);
    }

    function test_withdraw_excess_bond() public {
        // vault empty → requiredBond 0 → the whole bond is excess and reclaimable
        _bond(5000 * USD);
        uint256 before = usdc.balanceOf(address(this));
        s.withdrawBond(2000 * USD);
        assertEq(s.sequencerBond(), 3000 * USD, "bond reduced");
        assertEq(usdc.balanceOf(address(this)) - before, 2000 * USD, "USDC returned to sequencer");
    }

    function test_cannot_withdraw_bond_below_required_floor() public {
        _depositToVault(100_000 * USD); // TVL 100k → requiredBond 5k USDC
        _bond(6000 * USD); // 1k USDC of excess over the 5k floor
        assertEq(s.requiredBond(), 5000 * USD, "floor from TVL");
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(2000 * USD); // exceeds the 1k excess
        s.withdrawBond(1000 * USD); // exactly the excess → leaves the floor
        assertEq(s.sequencerBond(), 5000 * USD, "bond can't drop below the floor");
    }

    function test_cannot_withdraw_bond_after_slash() public {
        _bond(5000 * USD);
        // force a slash via an unanswered inclusion challenge
        bytes32 orderHash = keccak256("withheld");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        address challenger = address(0xCAFE);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);
        vm.roll(block.number + CHALLENGE_WINDOW + 1);
        s.slashUnanswered(orderHash);
        vm.expectRevert(DarkPerpSettlement.AlreadySlashed.selector);
        s.withdrawBond(1);
    }

    function test_inclusion_unanswered_slashes_bond() public {
        uint256 bond = 5000 * USD; // USDC bond
        _bond(bond);

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
        // challenger receives the slashed USDC bond directly; its native ETH stake is
        // credited for pull (DP-011) and reclaimed via claimEth.
        assertEq(usdc.balanceOf(challenger), bond, "slashed USDC bond paid to challenger");
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "ETH stake credited to challenger for pull");
        vm.prank(challenger);
        s.claimEth();
        assertEq(challenger.balance, CHALLENGE_BOND, "challenger pulls its ETH stake");
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
