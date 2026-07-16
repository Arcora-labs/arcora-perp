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
    uint256 internal constant INCLUSION_DEADLINE = 600;
    uint256 internal constant USD = 1e6;
    uint256 internal constant GRACE = 10;

    // this contract is the sequencer
    function setUp() public {
        verifier = new MockZkVerifier();
        enclaveSigner = vm.addr(ENCLAVE_PK);
        s = new DarkPerpSettlement(
            address(this),
            enclaveSigner,
            verifier,
            GENESIS,
            LIVENESS,
            CHALLENGE_WINDOW,
            CHALLENGE_BOND,
            INCLUSION_DEADLINE,
            address(this),
            GRACE
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

    function _proof(bytes32 prev, bytes32 m, bytes32 n, bytes32 ord, bytes32 wd) internal view returns (bytes memory) {
        return abi.encode(s.publicCommitment(prev, m, n, ord, wd, bytes32(0)));
    }

    /// Settles a fresh batch whose `orderedRoot` is a single-leaf tree containing
    /// `orderHash`, and returns the (batchId, proof) an inclusion answer can use.
    function _settleBatchWithOrder(bytes32 orderHash) internal returns (uint256 batchId, bytes32[] memory proof) {
        batchId = s.batchCount();
        bytes32 ordered = s.inclusionLeaf(batchId, orderHash); // single-leaf root
        bytes32 prev = s.currentStateRoot();
        bytes32 newRoot = keccak256(abi.encodePacked("next", batchId));
        // MockZkVerifier accepts proof == publicCommitment; mirror the existing settle helpers.
        bytes32 commitment = s.publicCommitment(prev, bytes32("m"), newRoot, ordered, bytes32(0), bytes32(0));
        s.settleBatch(prev, bytes32("m"), newRoot, ordered, bytes32(0), bytes32(0), abi.encodePacked(commitment));
        proof = new bytes32[](0);
    }

    function test_settle_advances_root() public {
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m0");
        s.settleBatch(
            GENESIS,
            manifest,
            newRoot,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            _proof(GENESIS, manifest, newRoot, bytes32(0), bytes32(0))
        );
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

    /// AUDIT (#11): once the system is in close-only, the vault must reject NEW deposits.
    /// Otherwise a user could deposit into a dead/slashed system and have the funds
    /// permanently locked — no settled withdrawals root will ever authorize them.
    function test_deposit_blocked_in_close_only() public {
        usdc.mint(address(this), 1000 * USD);
        usdc.approve(address(vault), 1000 * USD);
        // a deposit works while the system is live
        vault.deposit(100 * USD);
        // enter close-only via a liveness timeout
        vm.roll(block.number + LIVENESS + 1);
        s.triggerCloseOnly();
        // a further deposit must now revert
        vm.expectRevert(CollateralVault.InCloseOnly.selector);
        vault.deposit(100 * USD);
    }

    function test_inclusion_answered_clears_challenge() public {
        // settle a batch whose orderedRoot is the single domain-separated leaf
        bytes32 orderHash = keccak256("order-1");
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        s.settleBatch(
            GENESIS,
            manifest,
            newRoot,
            orderedRoot,
            bytes32(0),
            bytes32(0),
            _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0))
        );

        // user challenges with an enclave-signed receipt (canonical via vm.sign)
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 7, 1000, 0));
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
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
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);

        // the order's batch settles one block AFTER the challenge opened
        vm.roll(block.number + 1);
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("late");
        s.settleBatch(
            GENESIS,
            manifest,
            newRoot,
            orderedRoot,
            bytes32(0),
            bytes32(0),
            _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0))
        );

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
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);

        // settle a batch whose orderedRoot commits to a DIFFERENT order
        bytes32 orderedRoot = s.inclusionLeaf(0, keccak256("some-other-order"));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("unrelated");
        s.settleBatch(
            GENESIS,
            manifest,
            newRoot,
            orderedRoot,
            bytes32(0),
            bytes32(0),
            _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0))
        );

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
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
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
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
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
            GENESIS,
            manifest,
            newRoot,
            orderedRoot,
            bytes32(0),
            bytes32(0),
            _proof(GENESIS, manifest, newRoot, orderedRoot, bytes32(0))
        );

        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 7, 1000, 0));
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
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

    function test_answer_forced_inclusion_refunds_challenger() public {
        // ripe challenge, then the order settles in a batch that post-dates the challenge.
        bytes32 orderHash = keccak256("withheld");
        uint64 recvTimeMs = 1000;
        bytes32 digest = s.receiptDigest(orderHash, 1, recvTimeMs, 0);
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, digest);
        address challenger = address(0xC0FFEE);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, sig);

        // settle a batch AFTER the challenge opened (block-advance so settledAtBlock
        // genuinely postdates openedBlock, mirroring
        // test_answer_with_batch_settled_after_challenge_succeeds), containing
        // orderHash in orderedRoot.
        vm.roll(block.number + 1);
        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(orderHash);

        s.answerChallenge(orderHash, batchId, proof);

        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "victim refunded");
        assertEq(s.pendingEth(address(this)), 0, "sequencer not paid");
        assertFalse(s.slashed(), "answer never slashes");
        assertFalse(s.closeOnly(), "answer never trips close-only");
    }

    function test_answer_presettled_forfeits_to_sequencer() public {
        // the order is already in a settled batch BEFORE the challenge opens.
        bytes32 orderHash = keccak256("already-in");
        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(orderHash);

        uint64 recvTimeMs = 1000;
        bytes32 digest = s.receiptDigest(orderHash, 1, recvTimeMs, 0);
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, digest);
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, sig);

        s.answerChallenge(orderHash, batchId, proof);
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "griefer forfeits to sequencer");
        assertEq(s.pendingEth(challenger), 0, "challenger not refunded");
    }

    function test_rejection_answer_always_forfeits() public {
        // Even if the rejection batch post-dates the challenge, answerByRejection pays the sequencer.
        bytes32 orderHash = keccak256("rejected-order");
        uint64 recvTimeMs = 1000;
        bytes32 digest = s.receiptDigest(orderHash, 1, recvTimeMs, 0);
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, digest);
        address challenger = address(0xD00D);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, sig);

        // settle a batch (after the challenge) whose rejectedRoot contains orderHash.
        uint256 batchId = s.batchCount();
        bytes32 rejected = s.rejectionLeaf(batchId, orderHash);
        bytes32 prev = s.currentStateRoot();
        bytes32 newRoot = keccak256(abi.encodePacked("rej", batchId));
        bytes32 commitment = s.publicCommitment(prev, bytes32("m"), newRoot, bytes32(0), bytes32(0), rejected);
        s.settleBatch(prev, bytes32("m"), newRoot, bytes32(0), bytes32(0), rejected, abi.encodePacked(commitment));

        s.answerByRejection(orderHash, batchId, new bytes32[](0));
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "rejection forfeits to sequencer");
        assertEq(s.pendingEth(challenger), 0, "challenger not refunded on valid rejection");
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
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
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
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);

        vm.expectRevert(DarkPerpSettlement.ChallengeNotExpired.selector);
        s.slashUnanswered(orderHash);
        vm.roll(block.number + CHALLENGE_WINDOW + 1);
        s.slashUnanswered(orderHash);

        assertTrue(s.slashed(), "sequencer slashed");
        assertTrue(s.closeOnly(), "slash forces close-only");
        assertEq(s.sequencerBond(), 0, "bond drained");
        // audit Tier-3: BOTH the slashed USDC bond and the ETH stake are credited for
        // PULL, never pushed — so a pausable/blacklisting USDC or a non-payable challenger
        // can never brick the slash (which would leave the order permanently unslashable).
        assertEq(usdc.balanceOf(challenger), 0, "slashed USDC not pushed directly");
        assertEq(s.pendingUsdc(challenger), bond, "slashed USDC credited to challenger for pull");
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "ETH stake credited to challenger for pull");
        // the challenger pulls each refund
        vm.prank(challenger);
        s.claimUsdc();
        assertEq(usdc.balanceOf(challenger), bond, "challenger pulls the slashed USDC bond");
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
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
        vm.expectRevert(DarkPerpSettlement.NonCanonicalSignature.selector);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, flippedV, r, highS);
    }

    function test_bad_receipt_signature_rejected() public {
        bytes32 orderHash = keccak256("x");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(0xBADBAD, s.receiptDigest(orderHash, 1, 1, 0));
        vm.deal(address(this), CHALLENGE_BOND);
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);
    }

    function test_challenge_reverts_before_ripe() public {
        bytes32 orderHash = keccak256("ripe-order");
        uint64 recvTimeMs = 1000; // receipt "issued" at t=1s
        bytes32 digest = s.receiptDigest(orderHash, 1, recvTimeMs, 0);
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, digest);
        // block.timestamp is still 1 (< 1 + INCLUSION_DEADLINE): not yet ripe.
        vm.expectRevert(DarkPerpSettlement.NotRipe.selector);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, sig);
    }

    function test_challenge_allowed_after_ripe() public {
        bytes32 orderHash = keccak256("ripe-order");
        uint64 recvTimeMs = 1000;
        bytes32 digest = s.receiptDigest(orderHash, 1, recvTimeMs, 0);
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, digest);
        vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1); // now ripe
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, sig);
        (,,,,, bool open) = s.challenges(orderHash);
        assertTrue(open, "challenge opened once ripe");
    }

    // --- EXIT-001: governance finalSettle wind-down escape --------------------

    function _enterCloseOnlyViaLiveness() internal {
        vm.roll(block.number + LIVENESS + 1);
        s.triggerCloseOnly();
        assertTrue(s.closeOnly(), "close-only entered via liveness timeout");
    }

    /// Builds a fixed (prev, manifest, newRoot, wroot, proof) finalSettle fixture.
    /// Split out from `_governanceFinalSettle` so callers wrapping the actual
    /// `finalSettle` call in `vm.expectRevert` can compute these args (which are
    /// themselves external view calls into `s`) BEFORE arming the cheatcode —
    /// `vm.expectRevert` binds to the very next external call, so any read here
    /// made after arming it would be mistaken for the call under test.
    function _finalSettleArgs()
        internal
        view
        returns (bytes32 prev, bytes32 manifestHash, bytes32 newRoot, bytes32 wroot, bytes memory proof)
    {
        prev = s.currentStateRoot();
        manifestHash = bytes32("m");
        newRoot = keccak256("wind-down");
        wroot = keccak256("withdrawals");
        bytes32 commitment = s.publicCommitment(prev, manifestHash, newRoot, bytes32(0), wroot, bytes32(0));
        proof = abi.encodePacked(commitment);
    }

    function _governanceFinalSettle() internal {
        (bytes32 prev, bytes32 manifestHash, bytes32 newRoot, bytes32 wroot, bytes memory proof) = _finalSettleArgs();
        s.finalSettle(prev, manifestHash, newRoot, bytes32(0), wroot, bytes32(0), proof);
    }

    /// Opens a ripe inclusion challenge for `keccak256("withheld-order")` and rolls
    /// past the challenge window, leaving it ready for `slashUnanswered` (models
    /// `test_inclusion_unanswered_slashes_bond`).
    function _openAndExpireChallenge() internal {
        bytes32 orderHash = keccak256("withheld-order");
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, s.receiptDigest(orderHash, 1, 1, 0));
        address challenger = address(0xCAFE);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.prank(challenger);
        vm.warp(block.timestamp + INCLUSION_DEADLINE + 1);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, 1, 0, v, r, sig);
        vm.roll(block.number + CHALLENGE_WINDOW + 1);
    }

    function test_finalSettle_reverts_when_not_closeOnly() public {
        (bytes32 prev, bytes32 manifestHash, bytes32 newRoot, bytes32 wroot, bytes memory proof) = _finalSettleArgs();
        vm.expectRevert(DarkPerpSettlement.NotCloseOnly.selector);
        s.finalSettle(prev, manifestHash, newRoot, bytes32(0), wroot, bytes32(0), proof);
    }

    function test_finalSettle_reverts_before_grace() public {
        _enterCloseOnlyViaLiveness();
        // grace not yet elapsed
        (bytes32 prev, bytes32 manifestHash, bytes32 newRoot, bytes32 wroot, bytes memory proof) = _finalSettleArgs();
        vm.expectRevert(DarkPerpSettlement.GraceNotExpired.selector);
        s.finalSettle(prev, manifestHash, newRoot, bytes32(0), wroot, bytes32(0), proof);
    }

    function test_finalSettle_reverts_non_governance() public {
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        (bytes32 prev, bytes32 manifestHash, bytes32 newRoot, bytes32 wroot, bytes memory proof) = _finalSettleArgs();
        vm.prank(address(0xBAD));
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.finalSettle(prev, manifestHash, newRoot, bytes32(0), wroot, bytes32(0), proof);
    }

    function test_finalSettle_publish_then_claim() public {
        // fund the vault BEFORE close-only (deposits revert once the system trips
        // close-only, per test_deposit_blocked_in_close_only).
        address to = address(0xFEED);
        uint256 amount = 100 * USD;
        _depositToVault(amount);

        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        uint256 before = s.batchCount();

        // publish a withdrawals root that is itself a real single-leaf claim, so the
        // escape is verified end-to-end through the vault, not just via batchCount.
        uint256 nonce = 1;
        bytes32 leaf = keccak256(abi.encodePacked(to, amount, nonce));
        bytes32 prev = s.currentStateRoot();
        bytes32 newRoot = keccak256("wind-down");
        bytes32 commitment = s.publicCommitment(prev, bytes32("m"), newRoot, bytes32(0), leaf, bytes32(0));
        s.finalSettle(prev, bytes32("m"), newRoot, bytes32(0), leaf, bytes32(0), abi.encodePacked(commitment));
        assertEq(s.batchCount(), before + 1, "final settle advanced batchCount");

        bytes32[] memory proof = new bytes32[](0);
        vault.claim(to, amount, nonce, leaf, proof);
        assertEq(usdc.balanceOf(to), amount, "withdrawal claimable via the vault after finalSettle");
    }

    function test_finalSettle_works_when_slashed() public {
        // slash the sequencer, then governance winds down after grace despite `slashed`.
        _openAndExpireChallenge();
        s.slashUnanswered(keccak256("withheld-order"));
        assertTrue(s.slashed(), "sequencer slashed");
        vm.roll(block.number + GRACE + 1);
        uint256 before = s.batchCount();
        _governanceFinalSettle();
        assertEq(s.batchCount(), before + 1, "wind-down lands even when slashed");
    }

    receive() external payable {}
}
