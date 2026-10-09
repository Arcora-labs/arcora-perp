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
    /// Stand-in shielded-note owner: these tests exercise settlement/bonding, not the
    /// SEC-019 deposit hash chain (see CollateralVault.t.sol for that).
    bytes32 internal constant TEST_OWNER_COMMIT = keccak256("dark-perp.test.note-owner");
    /// SEC-019 (Task 6c): the gateway signing key the vault is deployed with, so deposits
    /// in these tests carry a valid gateway authorization.
    uint256 internal constant GW_PK = 0x6A7E;

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
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
    }

    /// SEC-019 (Task 6c): gateway signature over the canonical deposit digest for a
    /// deposit of `amount`/`commit` by `from` into `vault`.
    function _gwSig(address from, uint256 amount, bytes32 commit) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(vault), from, commit, amount));
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(GW_PK, digest);
        return abi.encodePacked(r, sg, v);
    }

    /// The sequencer (this contract) posts a USDC bond of `amount`.
    function _bond(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    function _proof(bytes32 prev, bytes32 m, bytes32 n, bytes32 ord, bytes32 wd) internal view returns (bytes memory) {
        return abi.encode(s.publicCommitment(prev, m, n, ord, wd, bytes32(0), vault.depositChainTip()));
    }

    /// The vault's live SEC-019 deposit head, which `settleBatch`/`finalSettle` now
    /// pin against. Read into locals BEFORE arming `vm.expectRevert` — these are
    /// external staticcalls, and the cheatcode binds to the very next external call,
    /// so reading them inline as settle arguments would consume the expectation.
    function _head() internal view returns (bytes32 tip, uint64 count) {
        return (vault.depositChainTip(), vault.depositCount());
    }

    /// Settles a batch with the given roots at the vault's live SEC-019 deposit head,
    /// building the matching proof. Extracted into a helper so the (now 9-argument)
    /// settle call does not blow the stack in tests that already hold many locals.
    function _settle(bytes32 prev, bytes32 manifest, bytes32 newRoot, bytes32 ord, bytes32 wd, bytes32 rej) internal {
        (bytes32 dTip, uint64 dCount) = _head();
        bytes32 commitment = s.publicCommitment(prev, manifest, newRoot, ord, wd, rej, dTip);
        s.settleBatch(prev, manifest, newRoot, ord, wd, rej, dTip, dCount, abi.encode(commitment));
    }

    /// Settles a fresh batch whose `orderedRoot` is a single-leaf tree containing
    /// `orderHash`, and returns the (batchId, proof) an inclusion answer can use.
    function _settleBatchWithOrder(bytes32 orderHash) internal returns (uint256 batchId, bytes32[] memory proof) {
        batchId = s.batchCount();
        bytes32 ordered = s.inclusionLeaf(batchId, orderHash); // single-leaf root
        bytes32 prev = s.currentStateRoot();
        bytes32 newRoot = keccak256(abi.encodePacked("next", batchId));
        (bytes32 dTip, uint64 dCount) = _head();
        // MockZkVerifier accepts proof == publicCommitment; mirror the existing settle helpers.
        bytes32 commitment = s.publicCommitment(prev, bytes32("m"), newRoot, ordered, bytes32(0), bytes32(0), dTip);
        s.settleBatch(
            prev, bytes32("m"), newRoot, ordered, bytes32(0), bytes32(0), dTip, dCount, abi.encodePacked(commitment)
        );
        proof = new bytes32[](0);
    }

    function test_local_s4_non_sequencer_cannot_configure_bond_or_settle() public {
        address outsider = address(0xBAD);
        vm.startPrank(outsider);
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.setVault(address(vault));
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.postBond(0);
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.withdrawBond(0);
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.settleBatch(GENESIS, bytes32(0), bytes32(uint256(2)), bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, hex"");
        vm.stopPrank();
        assertEq(s.currentStateRoot(), GENESIS, "unauthorized calls preserve root");
        assertEq(s.batchCount(), 0, "unauthorized calls preserve batch identity");
        assertEq(s.sequencerBond(), 0, "unauthorized calls preserve bond");
    }

    function test_settle_advances_root() public {
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m0");
        _settle(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0));
        assertEq(s.currentStateRoot(), newRoot, "root advanced");
        assertEq(s.batchCount(), 1, "batch counted");
    }

    /// SEC-025-B (whole-branch review item 8): pin the nine-parameter signature the
    /// off-chain callers hard-code (the gateway's `SETTLE_BATCH_SIG` in
    /// `crates/gateway/src/l1.rs` and both runbooks' `cast send` lines) to the
    /// COMPILED contract's selector. The Rust-side test can only compare two Rust
    /// strings written from the same reading of this contract; this assertion is the
    /// one check that actually breaks when the Solidity arity changes — the
    /// recurrence guard for the stale seven-parameter selector this branch fixed.
    function test_settleBatch_selector_matches_nine_param_signature() public pure {
        assertEq(
            bytes32(bytes4(keccak256("settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)"))),
            bytes32(DarkPerpSettlement.settleBatch.selector),
            "nine-parameter settleBatch signature must hash to the compiled selector"
        );
    }

    function test_settle_binds_withdrawals_root() public {
        // a proof valid for one withdrawalsRoot must NOT settle with a different
        // withdrawalsRoot (audit F2): the roots are part of the commitment.
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proof(GENESIS, manifest, newRoot, bytes32(0), keccak256("authorized"));
        (bytes32 dTip, uint64 dCount) = _head();
        // attacker swaps in a malicious withdrawals root with the same proof
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), keccak256("attacker"), bytes32(0), dTip, dCount, proof);
        // the correct withdrawals root settles
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), keccak256("authorized"), bytes32(0), dTip, dCount, proof);
        assertEq(s.currentStateRoot(), newRoot, "settled with bound withdrawals root");
    }

    function test_settle_rejects_bad_prev_root() public {
        bytes32 wrongPrev = bytes32(uint256(99));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proof(wrongPrev, manifest, newRoot, bytes32(0), bytes32(0));
        (bytes32 dTip, uint64 dCount) = _head();
        vm.expectRevert(DarkPerpSettlement.BadPrevRoot.selector);
        s.settleBatch(wrongPrev, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, proof);
    }

    function test_settle_rejects_bad_proof() public {
        verifier.setForceReject(true);
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = _proof(GENESIS, manifest, newRoot, bytes32(0), bytes32(0));
        (bytes32 dTip, uint64 dCount) = _head();
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, proof);
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
        (bytes32 dTip, uint64 dCount) = _head();
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, proof);
    }

    /// AUDIT (#11): once the system is in close-only, the vault must reject NEW deposits.
    /// Otherwise a user could deposit into a dead/slashed system and have the funds
    /// permanently locked — no settled withdrawals root will ever authorize them.
    function test_deposit_blocked_in_close_only() public {
        usdc.mint(address(this), 1000 * USD);
        usdc.approve(address(vault), 1000 * USD);
        // a deposit works while the system is live
        vault.deposit(100 * USD, TEST_OWNER_COMMIT, _gwSig(address(this), 100 * USD, TEST_OWNER_COMMIT));
        // enter close-only via a liveness timeout
        vm.roll(block.number + LIVENESS + 1);
        s.triggerCloseOnly();
        // a further deposit must now revert — closeOnly is checked before the sig gate,
        // so it reverts InCloseOnly even with a valid gateway signature
        bytes memory sig = _gwSig(address(this), 100 * USD, TEST_OWNER_COMMIT);
        vm.expectRevert(CollateralVault.InCloseOnly.selector);
        vault.deposit(100 * USD, TEST_OWNER_COMMIT, sig);
    }

    function test_inclusion_answered_clears_challenge() public {
        // settle a batch whose orderedRoot is the single domain-separated leaf
        bytes32 orderHash = keccak256("order-1");
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        _settle(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0));

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
        _settle(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0));

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
        _settle(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0));

        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(DarkPerpSettlement.NotIncluded.selector);
        s.answerChallenge(orderHash, 0, proof);
    }

    function test_declared_rejection_membership_answers_challenge() public {
        // audit DP-004: membership in rejectedRoot clears the challenge. This test
        // uses MockZkVerifier and proves neither a rejection reason nor matcher
        // correctness. R04 remains open even with the real Proof-v1 verifier.
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
        (bytes32 dTip, uint64 dCount) = _head();
        bytes memory proof0 =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), rejectedRoot, dTip));
        s.settleBatch(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), rejectedRoot, dTip, dCount, proof0);

        bytes32[] memory proof = new bytes32[](0);
        s.answerByRejection(orderHash, 0, proof);
        (,,,,, bool open) = s.challenges(orderHash);
        assertFalse(open, "challenge answered by declared rejection membership");
    }

    function test_answer_by_rejection_requires_membership() public {
        // An order outside the committed rejectedRoot cannot answer by membership.
        // A dishonest order already IN that list is a separate, still-open R04 gap.
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
        (bytes32 dTip, uint64 dCount) = _head();
        bytes memory proof0 =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), rejectedRoot, dTip));
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), rejectedRoot, dTip, dCount, proof0);

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
        _settle(GENESIS, manifest, newRoot, orderedRoot, bytes32(0), bytes32(0));

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

    function test_same_block_forced_inclusion_refunds_challenger() public {
        bytes32 orderHash = keccak256("same-block-withheld");
        address challenger = address(0xC0FFEE);
        _openRipeChallenge(orderHash, challenger);
        uint256 challengeBlock = block.number;

        // Transaction order matters even when the block number is identical.
        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(orderHash);
        s.answerChallenge(orderHash, batchId, proof);

        assertEq(block.number, challengeBlock, "no block advance");
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "same-block forced inclusion refunds challenger");
        assertEq(s.pendingEth(address(this)), 0, "sequencer cannot confiscate same-block forced inclusion stake");
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.answerChallenge(orderHash, batchId, proof);
    }

    function _openRipeChallenge(bytes32 orderHash, address challenger) internal {
        uint64 recvTimeMs = 1000;
        bytes32 digest = s.receiptDigest(orderHash, 1, recvTimeMs, 0);
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, digest);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, sig);
    }

    function _settleRejectionBatch(bytes32 orderHash) internal returns (uint256 batchId) {
        batchId = s.batchCount();
        bytes32 rejected = s.rejectionLeaf(batchId, orderHash); // single-leaf root
        bytes32 prev = s.currentStateRoot();
        bytes32 newRoot = keccak256(abi.encodePacked("rej", batchId));
        (bytes32 dTip, uint64 dCount) = _head();
        bytes32 commitment =
            s.publicCommitment(prev, bytes32("m"), newRoot, bytes32(0), bytes32(0), rejected, dTip);
        s.settleBatch(
            prev, bytes32("m"), newRoot, bytes32(0), bytes32(0), rejected, dTip, dCount, abi.encodePacked(commitment)
        );
    }

    function test_rejection_answer_postdating_challenge_refunds() public {
        // 2026-10-08 review: mirror of answerChallenge's SEQ-001 gate. If the rejecting
        // batch settles only AFTER the (ripe) challenge opened, the challenger is what
        // forced the order's on-chain disposition to be published — the bond refunds
        // to the challenger instead of paying the sequencer.
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
        vm.roll(block.number + 1);
        uint256 batchId = _settleRejectionBatch(orderHash);

        s.answerByRejection(orderHash, batchId, new bytes32[](0));
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "post-challenge rejection refunds the challenger");
        assertEq(s.pendingEth(address(this)), 0, "sequencer not paid for a late-published rejection");
    }

    function test_rejection_answer_presettled_forfeits_to_sequencer() public {
        // The rejecting batch settled BEFORE the challenge opened: the reject
        // disposition was already public and checkable, so the challenge was mistaken
        // (or griefing) and the stake forfeits to the sequencer.
        bytes32 orderHash = keccak256("rejected-order");
        uint256 batchId = _settleRejectionBatch(orderHash);

        uint64 recvTimeMs = 1000;
        bytes32 digest = s.receiptDigest(orderHash, 1, recvTimeMs, 0);
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ENCLAVE_PK, digest);
        address challenger = address(0xBEEF);
        vm.deal(challenger, CHALLENGE_BOND);
        vm.warp(recvTimeMs / 1000 + INCLUSION_DEADLINE + 1);
        vm.roll(block.number + 1);
        vm.prank(challenger);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, recvTimeMs, 0, v, r, sig);

        s.answerByRejection(orderHash, batchId, new bytes32[](0));
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "pre-settled rejection forfeits to sequencer");
        assertEq(s.pendingEth(challenger), 0, "challenger not refunded");
    }

    function test_same_block_late_rejection_refunds_challenger() public {
        bytes32 orderHash = keccak256("same-block-late-rejection");
        address challenger = address(0xD00D);
        _openRipeChallenge(orderHash, challenger);
        uint256 challengeBlock = block.number;

        uint256 batchId = _settleRejectionBatch(orderHash);
        s.answerByRejection(orderHash, batchId, new bytes32[](0));

        assertEq(block.number, challengeBlock, "no block advance");
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "same-block late rejection refunds challenger");
        assertEq(s.pendingEth(address(this)), 0, "sequencer cannot confiscate same-block late rejection stake");
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.answerByRejection(orderHash, batchId, new bytes32[](0));
    }

    function test_same_block_presettled_rejection_forfeits_to_sequencer() public {
        bytes32 orderHash = keccak256("same-block-presettled-rejection");
        address challenger = address(0xD00D);
        uint256 batchId = _settleRejectionBatch(orderHash);
        uint256 settledBlock = block.number;
        _openRipeChallenge(orderHash, challenger);

        s.answerByRejection(orderHash, batchId, new bytes32[](0));

        assertEq(block.number, settledBlock, "no block advance");
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "same-block prior settlement forfeits stake");
        assertEq(s.pendingEth(challenger), 0, "preexisting rejection does not refund challenger");
    }

    function test_reopened_challenge_uses_current_settlement_boundary() public {
        bytes32 orderHash = keccak256("reopened-challenge");
        address challenger = address(0xD00D);
        _openRipeChallenge(orderHash, challenger);
        uint256 batchId = _settleRejectionBatch(orderHash);
        s.answerByRejection(orderHash, batchId, new bytes32[](0));
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "first challenge forced publication");

        _openRipeChallenge(orderHash, challenger);
        s.answerByRejection(orderHash, batchId, new bytes32[](0));
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "repeated challenge earns no second refund");
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "already settled batch forfeits reopened stake");
    }

    function testFuzz_same_block_refund_follows_transaction_order(
        uint8 priorBatches,
        bool rejection,
        bool settleFirst
    ) public {
        // Exercise a nonzero boundary as well as genesis; every operation stays
        // in one block, so a block-number comparison cannot distinguish cases.
        for (uint256 i; i < priorBatches % 4; ++i) {
            _settleBatchWithOrder(keccak256(abi.encodePacked("prior", i)));
        }
        bytes32 orderHash = keccak256("fuzz-challenged-order");
        address challenger = address(0xD00D);
        uint256 batchId = s.batchCount();
        if (!settleFirst) _openRipeChallenge(orderHash, challenger);
        if (rejection) _settleRejectionBatch(orderHash);
        else _settleBatchWithOrder(orderHash);
        if (settleFirst) _openRipeChallenge(orderHash, challenger);

        if (rejection) s.answerByRejection(orderHash, batchId, new bytes32[](0));
        else s.answerChallenge(orderHash, batchId, new bytes32[](0));

        assertEq(s.pendingEth(challenger), settleFirst ? 0 : CHALLENGE_BOND, "refund follows transaction order");
        assertEq(s.pendingEth(address(this)), settleFirst ? CHALLENGE_BOND : 0, "forfeit follows transaction order");
    }

    function _depositToVault(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(vault), amount);
        vault.deposit(amount, TEST_OWNER_COMMIT, _gwSig(address(this), amount, TEST_OWNER_COMMIT));
    }

    // --- SEC-019: credited deposits are pinned to the L1 deposit hash chain ----

    /// Known-answer vector shared byte-for-byte with `crates/prover/tests/vectors.rs`
    /// (`public_commitment_vector`): the SEVEN-word commitment over
    /// prev=0x01.., manifest=0x02.., new=0x03.., ordered=0x04.., withdrawals=0x05..,
    /// rejected=0x06.., deposits=0x07.. — `depositsRoot` appended LAST. If this ever
    /// drifts from Rust, the circuit's public input and this contract's recomputation
    /// disagree and no genuine proof can settle at all.
    bytes32 internal constant KAT_COMMIT7 = 0x27e3e52688359d5759ff4c7b0bea4d25a14b3c81652a4083d531592f827d8902;

    function test_public_commitment_7word_matches_rust() public view {
        bytes32 c = s.publicCommitment(
            bytes32(uint256(0x0101010101010101010101010101010101010101010101010101010101010101)),
            bytes32(uint256(0x0202020202020202020202020202020202020202020202020202020202020202)),
            bytes32(uint256(0x0303030303030303030303030303030303030303030303030303030303030303)),
            bytes32(uint256(0x0404040404040404040404040404040404040404040404040404040404040404)),
            bytes32(uint256(0x0505050505050505050505050505050505050505050505050505050505050505)),
            bytes32(uint256(0x0606060606060606060606060606060606060606060606060606060606060606)),
            bytes32(uint256(0x0707070707070707070707070707070707070707070707070707070707070707))
        );
        assertEq(c, KAT_COMMIT7, "7-word public commitment must match crates/prover::PublicInputs::commitment");
    }

    /// The core SEC-019 property: a batch may only credit deposits that ACTUALLY
    /// HAPPENED on L1. Here the sequencer holds a proof that is internally valid for
    /// a FABRICATED deposit chain (the mock verifier accepts it), so the ZK layer
    /// offers no protection whatsoever — the only thing standing between the attacker
    /// and minting collateral out of thin air is the pin to the vault's live tip.
    function test_settle_reverts_on_deposit_root_mismatch() public {
        _depositToVault(1000 * USD);
        _bond(s.requiredBond());

        bytes32 fabricatedTip = keccak256("deposit-that-never-happened");
        uint64 count = vault.depositCount();
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        // a proof the verifier ACCEPTS for the fabricated chain — everything except
        // the L1 pin passes. Computed before arming the cheatcode (external calls).
        bytes memory proof = abi.encode(
            s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), fabricatedTip)
        );

        vm.expectRevert(abi.encodeWithSignature("Error(string)", "deposits: root != L1 chain prefix"));
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), fabricatedTip, count, proof);
        // and nothing moved
        assertEq(s.currentStateRoot(), GENESIS, "fabricated deposit chain never advances the root");
        assertEq(s.batchCount(), 0, "no batch settled");
    }

    /// The tip must belong to the prefix being claimed. Presenting a REAL chain tip
    /// against the wrong `newDepositCount` is still a lie about what was credited, and
    /// is rejected — the pin is (count, tip) as a pair, not a tip floating free.
    function test_settle_reverts_on_wrong_prefix_root() public {
        _depositToVault(1000 * USD);
        _depositToVault(500 * USD);
        _bond(s.requiredBond());

        bytes32 headTip = vault.depositChainTip(); // the genuine tip at prefix 2
        assertEq(uint256(vault.depositCount()), 2, "two deposits landed on L1");

        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), headTip));

        // claiming prefix 1 while presenting prefix 2's tip
        vm.expectRevert(abi.encodeWithSignature("Error(string)", "deposits: root != L1 chain prefix"));
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), headTip, 1, proof);
        assertEq(s.batchCount(), 0, "no batch settled on a mismatched prefix");
        assertEq(s.currentStateRoot(), GENESIS, "root untouched");
    }

    /// SEC-019 Task 6b: a batch proven over prefix N settles even though the vault head
    /// has ALREADY moved past N. This is the exact scenario the earlier consume-all-to-head
    /// rule reverted on: any deposit landing between proof-build and tx-mine invalidated
    /// the in-flight settle. Concurrent deposits must simply land in a later batch.
    function test_settle_accepts_a_proven_prefix_while_head_moved() public {
        _depositToVault(1000 * USD);
        // the sequencer builds its proof here, over prefix 1
        bytes32 prefixTip = vault.depositChainTip();
        uint64 prefixCount = vault.depositCount();

        // ...and a genuine user deposit lands while the settle tx is in flight
        _depositToVault(500 * USD);
        _bond(s.requiredBond());
        assertEq(uint256(vault.depositCount()), 2, "head advanced past the proven prefix");
        assertTrue(vault.depositChainTip() != prefixTip, "head tip now differs from the proven prefix");

        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), prefixTip));

        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), prefixTip, prefixCount, proof);
        assertEq(s.currentStateRoot(), newRoot, "a proven prefix settles even after the head moved");
        assertEq(s.batchCount(), 1, "batch counted");
    }

    /// REGRESSION GUARD for the settle-stall DoS the consume-all-to-head rule introduced.
    /// `deposit(0, junk)` costs only gas — no USDC, no approval, any address — yet it
    /// advances `depositCount`/`depositChainTip`. Under the old live-head pin, an
    /// adversary repeating it once per settle interval halted settlement (and therefore
    /// L1 finality and every withdrawal claim) indefinitely. Under the prefix pin the
    /// in-flight settle is untouched by it.
    function test_zero_value_deposit_cannot_stall_settlement() public {
        _depositToVault(1000 * USD);
        _bond(s.requiredBond());

        // the sequencer builds and signs its settle over the current prefix
        bytes32 prefixTip = vault.depositChainTip();
        uint64 prefixCount = vault.depositCount();
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), prefixTip));

        // a mid-flight, gateway-authorized deposit front-runs the settle (zero-value, but
        // it still advances the head). With the SEC-019 (Task 6c) gate a random third
        // party can no longer do this un-authorized; the point here is that even an
        // authorized deposit landing between build and settle does not stall settlement.
        address griefer = address(0x6217EF);
        bytes memory gsig = _gwSig(griefer, 0, keccak256("junk"));
        vm.prank(griefer);
        vault.deposit(0, keccak256("junk"), gsig);
        assertEq(uint256(vault.depositCount()), uint256(prefixCount) + 1, "griefing deposit did advance the head");
        assertTrue(vault.depositChainTip() != prefixTip, "and did move the head tip");

        // ...and the settle lands anyway
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), prefixTip, prefixCount, proof);
        assertEq(s.currentStateRoot(), newRoot, "settlement is immune to head-advancing griefing");
        assertEq(s.batchCount(), 1, "batch counted despite the griefing deposit");
    }

    /// The happy path over a NON-EMPTY chain: settling exactly at the L1 head (the
    /// longest prefix) passes and lands end-to-end. Guards against a fix that simply
    /// makes every settle revert.
    function test_settle_at_l1_deposit_head_succeeds() public {
        _depositToVault(1000 * USD);
        _depositToVault(500 * USD);
        _bond(s.requiredBond());

        bytes32 tip = vault.depositChainTip();
        uint64 count = vault.depositCount();
        assertTrue(tip != bytes32(0), "chain tip is non-genesis, so the pin is meaningful");

        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), tip));

        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), tip, count, proof);
        assertEq(s.currentStateRoot(), newRoot, "settled at the L1 deposit head");
        assertEq(s.batchCount(), 1, "batch counted");
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
        returns (
            bytes32 prev,
            bytes32 manifestHash,
            bytes32 newRoot,
            bytes32 wroot,
            bytes32 dTip,
            uint64 dCount,
            bytes memory proof
        )
    {
        prev = s.currentStateRoot();
        manifestHash = bytes32("m");
        newRoot = keccak256("wind-down");
        wroot = keccak256("withdrawals");
        // the SEC-019 head is read here too, for exactly the reason above: these are
        // external staticcalls that must not be made after `vm.expectRevert` is armed.
        (dTip, dCount) = _head();
        bytes32 commitment = s.windDownCommitment(prev, manifestHash, newRoot, bytes32(0), wroot, bytes32(0), dTip, 1);
        proof = abi.encodePacked(commitment);
    }

    function _governanceFinalSettle() internal {
        (
            bytes32 prev,
            bytes32 manifestHash,
            bytes32 newRoot,
            bytes32 wroot,
            bytes32 dTip,
            uint64 dCount,
            bytes memory proof
        ) = _finalSettleArgs();
        s.finalSettle(prev, manifestHash, newRoot, bytes32(0), wroot, bytes32(0), dTip, dCount, proof);
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
        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount, bytes memory pf) =
            _finalSettleArgs();
        vm.expectRevert(DarkPerpSettlement.NotCloseOnly.selector);
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, pf);
    }

    function test_finalSettle_reverts_before_grace() public {
        _enterCloseOnlyViaLiveness();
        // grace not yet elapsed
        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount, bytes memory pf) =
            _finalSettleArgs();
        vm.expectRevert(DarkPerpSettlement.GraceNotExpired.selector);
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, pf);
    }

    function test_finalSettle_reverts_non_governance() public {
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount, bytes memory pf) =
            _finalSettleArgs();
        vm.prank(address(0xBAD));
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, pf);
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
        // a real deposit was made above, so the wind-down must pin a NON-genesis
        // chain tip — this exercises finalSettle's SEC-019 check against live state.
        (bytes32 dTip, uint64 dCount) = _head();
        assertTrue(dTip != bytes32(0), "wind-down pins a non-genesis deposit chain");
        bytes32 commitment = s.windDownCommitment(prev, bytes32("m"), newRoot, bytes32(0), leaf, bytes32(0), dTip, 1);
        s.finalSettle(
            prev, bytes32("m"), newRoot, bytes32(0), leaf, bytes32(0), dTip, dCount, abi.encodePacked(commitment)
        );
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

    /// I-1 (whole-branch review): a slash that happens while ALREADY in close-only
    /// must not push `closeOnlyBlock` forward — it latches to the FIRST close-only
    /// transition, which is what `finalSettle`'s grace deadline is anchored to.
    /// Before the fix, `slashUnanswered` set `closeOnlyBlock = block.number`
    /// unconditionally; since `challengeInclusion` has no close-only guard and a
    /// slash refunds the challenger's stake and frees the order (`delete
    /// challenges[orderHash]`), an attacker already in close-only could repeatedly
    /// open a challenge, wait the window, and call `slashUnanswered` — each time
    /// pushing the grace deadline out at gas-only cost and griefing the EXIT-001
    /// escape hatch's liveness.
    function test_slash_after_closeOnly_does_not_reset_grace() public {
        // enter close-only via the liveness path FIRST — this is the transition
        // closeOnlyBlock (and the grace deadline) must be anchored to.
        _enterCloseOnlyViaLiveness();
        uint256 entry = s.closeOnlyBlock();

        // open a ripe inclusion challenge while already in close-only and let its
        // window expire (rolls block.number strictly forward past entry), then slash.
        _openAndExpireChallenge();
        assertTrue(block.number > entry, "slash happens strictly after the original close-only entry");
        s.slashUnanswered(keccak256("withheld-order"));
        assertTrue(s.slashed(), "sequencer slashed");
        assertTrue(s.closeOnly(), "still close-only after the second slash");

        // the latch: closeOnlyBlock must still read the FIRST entry, not the later slash block.
        assertEq(s.closeOnlyBlock(), entry, "closeOnlyBlock latched to first close-only entry, not the later slash");

        // the grace deadline computed from that original entry already holds by the
        // time of the slash (current block > entry + GRACE) — finalSettle succeeds
        // per the ORIGINAL deadline despite the later slash re-arming close-only.
        uint256 before = s.batchCount();
        _governanceFinalSettle();
        assertEq(s.batchCount(), before + 1, "wind-down lands per the original grace deadline despite the later slash");
    }


    function test_a06_finalSettle_rejects_ordinary_phase_zero_proof() public {
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount,) = _finalSettleArgs();
        bytes32 ordinary = s.publicCommitment(p, mh, nr, bytes32(0), wr, bytes32(0), dTip);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, abi.encodePacked(ordinary));
    }

    function test_a06_settleBatch_rejects_phase_one_proof() public {
        bytes32 prev = s.currentStateRoot();
        bytes32 mh = bytes32("phase1");
        bytes32 nr = keccak256("phase1-root");
        (bytes32 dTip, uint64 dCount) = _head();
        bytes32 phase1 = s.windDownCommitment(prev, mh, nr, bytes32(0), bytes32(0), bytes32(0), dTip, 1);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(prev, mh, nr, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, abi.encodePacked(phase1));
    }

    function test_a06_final_settle_is_one_shot_and_phase_two_exit_is_repeatable() public {
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        _governanceFinalSettle();
        assertTrue(s.windDownSettled(), "phase 1 latched");

        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount,) = _finalSettleArgs();
        bytes32 again = s.windDownCommitment(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, 1);
        vm.expectRevert(bytes("wind-down already settled"));
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, abi.encodePacked(again));

        for (uint256 i = 0; i < 2; i++) {
            bytes32 prev = s.currentStateRoot();
            bytes32 manifest = keccak256(abi.encodePacked("exit", i));
            bytes32 next = keccak256(abi.encodePacked("exit-root", i));
            (bytes32 tip, uint64 count) = _head();
            bytes32 phase2 = s.windDownCommitment(prev, manifest, next, bytes32(0), bytes32(0), bytes32(0), tip, 2);
            s.finalExit(prev, manifest, next, bytes32(0), bytes32(0), bytes32(0), tip, count, abi.encodePacked(phase2));
            assertEq(s.currentStateRoot(), next, "phase 2 advanced root");
        }
    }

    function test_a06_finalExit_rejects_before_phase_one() public {
        _enterCloseOnlyViaLiveness();
        bytes32 prev = s.currentStateRoot();
        (bytes32 tip, uint64 count) = _head();
        bytes32 c = s.windDownCommitment(prev, bytes32("x"), bytes32("y"), bytes32(0), bytes32(0), bytes32(0), tip, 2);
        vm.expectRevert(bytes("wind-down not settled"));
        s.finalExit(prev, bytes32("x"), bytes32("y"), bytes32(0), bytes32(0), bytes32(0), tip, count, abi.encodePacked(c));
    }

    function test_a06_finalExit_reverts_non_governance() public {
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        _governanceFinalSettle();
        bytes32 prev = s.currentStateRoot();
        (bytes32 tip, uint64 count) = _head();
        bytes32 commitment =
            s.windDownCommitment(prev, bytes32("x"), bytes32("y"), bytes32(0), bytes32(0), bytes32(0), tip, 2);

        vm.prank(address(0xBAD));
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.finalExit(
            prev, bytes32("x"), bytes32("y"), bytes32(0), bytes32(0), bytes32(0), tip, count, abi.encodePacked(commitment)
        );
        assertEq(s.currentStateRoot(), prev, "unauthorized exit cannot advance state");
    }

    receive() external payable {}
}
