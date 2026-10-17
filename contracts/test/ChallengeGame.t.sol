// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";

/// Cheatcodes this suite needs beyond the vendored MiniTest subset.
interface ChallengeGameVm {
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData, address emitter) external;
}

/// The inclusion-challenge game. An enclave-signed authorization names the beneficiary
/// of any fine; each order hash is challenged at most once; answers are permissionless
/// and batched; a slash needs `progressBatches` phase-0 batches plus a block grace, pays
/// at most `slashPayoutCap` and does not stop the exchange; a challenge that close-only
/// made unreachable is released.
contract ChallengeGameTest is MiniTest {
    ChallengeGameVm internal constant vmx = ChallengeGameVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;

    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    uint256 internal constant GW_PK = 0x6A7E;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    bytes32 internal constant M = bytes32("manifest");
    bytes32 internal constant Z = bytes32(0);
    uint64 internal constant SEQ = 1;
    uint64 internal constant RECV_MS = 1_000;
    uint64 internal constant HINT = 0;
    uint256 internal constant LIVENESS = 7200;
    uint256 internal constant STAKE = SettlementTestConfig.CHALLENGE_BOND;
    uint256 internal constant CAP = SettlementTestConfig.SLASH_PAYOUT_CAP;
    uint256 internal constant GRACE = SettlementTestConfig.CHALLENGE_GRACE_BLOCKS;
    uint256 internal constant P = SettlementTestConfig.PROGRESS_BATCHES;
    uint256 internal constant WIND_DOWN_GRACE = SettlementTestConfig.FINAL_SETTLE_GRACE_BLOCKS;
    uint256 internal constant BOND = 500_000e6;
    /// secp256k1 group order.
    uint256 internal constant SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    address internal constant GOV = address(0x60F);
    address internal trader = address(0x71C7);
    address internal outsider = address(0xBAD);
    address internal relayer = address(0x7E1A);
    address internal anyone = address(0xCAFE);

    function setUp() public {
        vm.roll(1000);
        vm.warp(10_000);
        DarkPerpSettlement.Config memory cfg =
            SettlementTestConfig.defaults(address(this), vm.addr(ENCLAVE_PK), new MockClockVerifier(), GENESIS);
        cfg.governance = GOV;
        cfg.livenessTimeoutBlocks = LIVENESS;
        s = new DarkPerpSettlement(cfg);
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
        _postBond(BOND);
    }

    receive() external payable {}

    // --- helpers ---------------------------------------------------------------------

    function _postBond(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    function _order(string memory tag, uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encode(tag, i));
    }

    function _sig(bytes32 h, address beneficiary) internal view returns (bytes memory) {
        return SettlementTestConfig.challengeSig(vm, ENCLAVE_PK, s, h, SEQ, RECV_MS, HINT, beneficiary);
    }

    /// `staker` submits the enclave authorization for `h` naming `beneficiary`.
    function _open(bytes32 h, address beneficiary, address staker) internal {
        bytes memory sig = _sig(h, beneficiary);
        vm.deal(staker, staker.balance + STAKE);
        vm.prank(staker);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, beneficiary, sig);
    }

    /// Local copies of the settlement's leaf encodings (no external call).
    function _incl(uint256 batchId, bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(0x00), batchId, h));
    }

    function _rej(uint256 batchId, bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(0x01), batchId, h));
    }

    function _settleRoots(bytes32 ordered, bytes32 rejected) internal returns (uint256 id) {
        id = s.batchCount();
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256(abi.encode("root", id));
        uint64 n = vault.depositCount();
        bytes32 tip = vault.depositTipAt(n);
        bytes32 c = s.publicCommitment(prev, M, next, ordered, Z, rejected, tip);
        s.settleBatch(prev, M, next, ordered, Z, rejected, tip, n, abi.encode(c));
    }

    function _settleEmpty() internal returns (uint256) {
        return _settleRoots(Z, Z);
    }

    function _settleWith(bytes32 h) internal returns (uint256 id) {
        id = s.batchCount();
        _settleRoots(_incl(id, h), Z);
    }

    function _settleRejecting(bytes32 h) internal returns (uint256 id) {
        id = s.batchCount();
        _settleRoots(Z, _rej(id, h));
    }

    /// Settles a batch whose ordered root covers `hs`.
    function _settleOrders(bytes32[] memory hs) internal returns (uint256 id) {
        id = s.batchCount();
        _settleRoots(_root(_inclLeaves(id, hs)), Z);
    }

    function _inclLeaves(uint256 batchId, bytes32[] memory hs) internal pure returns (bytes32[] memory leaves) {
        leaves = new bytes32[](hs.length);
        for (uint256 i = 0; i < hs.length; i++) {
            leaves[i] = _incl(batchId, hs[i]);
        }
    }

    function _rejLeaves(uint256 batchId, bytes32[] memory hs) internal pure returns (bytes32[] memory leaves) {
        leaves = new bytes32[](hs.length);
        for (uint256 i = 0; i < hs.length; i++) {
            leaves[i] = _rej(batchId, hs[i]);
        }
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _copy(bytes32[] memory a) internal pure returns (bytes32[] memory b) {
        b = new bytes32[](a.length);
        for (uint256 i = 0; i < a.length; i++) {
            b[i] = a[i];
        }
    }

    /// Sorted-pair Merkle root; an odd node is carried up unchanged.
    function _root(bytes32[] memory leaves) internal pure returns (bytes32) {
        if (leaves.length == 0) return Z;
        bytes32[] memory layer = _copy(leaves);
        uint256 n = layer.length;
        while (n > 1) {
            uint256 m = (n + 1) / 2;
            for (uint256 i = 0; i < m; i++) {
                layer[i] = 2 * i + 1 < n ? _hashPair(layer[2 * i], layer[2 * i + 1]) : layer[2 * i];
            }
            n = m;
        }
        return layer[0];
    }

    function _proof(bytes32[] memory leaves, uint256 idx) internal pure returns (bytes32[] memory proof) {
        bytes32[] memory layer = _copy(leaves);
        bytes32[] memory buf = new bytes32[](64);
        uint256 k;
        uint256 n = layer.length;
        while (n > 1) {
            uint256 sib = idx ^ 1;
            if (sib < n) buf[k++] = layer[sib];
            uint256 m = (n + 1) / 2;
            for (uint256 i = 0; i < m; i++) {
                layer[i] = 2 * i + 1 < n ? _hashPair(layer[2 * i], layer[2 * i + 1]) : layer[2 * i];
            }
            idx >>= 1;
            n = m;
        }
        proof = new bytes32[](k);
        for (uint256 i = 0; i < k; i++) {
            proof[i] = buf[i];
        }
    }

    function _none() internal pure returns (bytes32[] memory) {
        return new bytes32[](0);
    }

    function _isOpen(bytes32 h) internal view returns (bool open) {
        (,,,,, open) = s.challenges(h);
    }

    /// Rolls to the first block at which a slash of a challenge opened at
    /// `openBatchCount` is allowed (the progress gate must already be met).
    function _rollPastGrace(uint256 openBatchCount) internal {
        (,,, uint256 settledAt) = s.batches(openBatchCount + P - 1);
        vm.roll(settledAt + GRACE + 1);
    }

    /// The open set reads back exactly `expected`, in order.
    function _assertOpenSet(bytes32[] memory expected) internal view {
        assertEq(s.openChallengeCount(), expected.length, "open count");
        bytes32[] memory page = s.openChallenges(0, 512);
        assertEq(page.length, expected.length, "page length");
        for (uint256 i = 0; i < expected.length; i++) {
            assertEq(page[i], expected[i], "open set order");
            assertTrue(_isOpen(page[i]), "listed challenge is open");
        }
    }

    function _list(bytes32 a) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](1);
        l[0] = a;
    }

    function _list(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        l[0] = a;
        l[1] = b;
    }

    function _list(bytes32 a, bytes32 b, bytes32 c) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](3);
        l[0] = a;
        l[1] = b;
        l[2] = c;
    }

    function _list(bytes32 a, bytes32 b, bytes32 c, bytes32 d) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](4);
        l[0] = a;
        l[1] = b;
        l[2] = c;
        l[3] = d;
    }

    /// The settlement's ETH covers every credited refund plus every open stake, and its
    /// USDC covers the bond plus every credited fine, exactly (for the listed parties).
    function _assertSolvent(address[] memory parties) internal view {
        uint256 eth = s.openChallengeCount() * STAKE;
        uint256 fines;
        for (uint256 i = 0; i < parties.length; i++) {
            eth += s.pendingEth(parties[i]);
            fines += s.pendingUsdc(parties[i]);
        }
        assertEq(address(s).balance, eth, "ETH = pending refunds + open stakes");
        assertEq(usdc.balanceOf(address(s)), s.sequencerBond() + fines, "USDC = bond + pending fines");
    }

    function _parties() internal view returns (address[] memory p) {
        p = new address[](5);
        p[0] = address(this);
        p[1] = trader;
        p[2] = outsider;
        p[3] = relayer;
        p[4] = anyone;
    }

    // --- authorization binding and single-use order hashes -------------------------

    function test_leaf_encodings_match_the_settlement() public view {
        bytes32 h = _order("leaf", 0);
        assertEq(_incl(7, h), s.inclusionLeaf(7, h), "inclusion leaf");
        assertEq(_rej(7, h), s.rejectionLeaf(7, h), "rejection leaf");
        assertEq(
            s.challengeAuthDigest(h, SEQ, RECV_MS, HINT, trader),
            SettlementTestConfig.challengeAuthDigest(address(s), h, SEQ, RECV_MS, HINT, trader),
            "authorization digest"
        );
        assertEq(s.CHALLENGE_AUTH_TAG(), keccak256("arcora:l1-inclusion-challenge:v1"), "authorization tag");
    }

    function test_third_party_submission_keeps_the_signed_beneficiary() public {
        bytes32 h = _order("trader-order", 0);
        bytes memory sig = _sig(h, trader);

        // Someone else lands the trader's authorization first.
        vm.deal(outsider, STAKE);
        vmx.expectEmit(true, true, false, true, address(s));
        emit DarkPerpSettlement.InclusionChallenged(h, trader, outsider, 0);
        vm.prank(outsider);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, sig);
        (address beneficiary,,,,,) = s.challenges(h);
        assertEq(beneficiary, trader, "the signed beneficiary is stored");

        vm.deal(trader, STAKE);
        vm.prank(trader);
        vm.expectRevert(DarkPerpSettlement.ChallengeExists.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, sig);

        // Never settled: after progress and grace the fine goes to the trader, the stake
        // back to whoever posted it.
        _settleEmpty();
        _settleEmpty();
        _rollPastGrace(0);
        vm.prank(outsider);
        s.slashUnanswered(h);
        assertEq(s.pendingUsdc(trader), CAP, "fine to the signed beneficiary");
        assertEq(s.pendingUsdc(outsider), 0, "nothing to the submitter");
        assertEq(s.pendingEth(outsider), STAKE, "stake back to the submitter");
        _assertSolvent(_parties());

        uint256 before = usdc.balanceOf(trader);
        vm.prank(trader);
        s.claimUsdc();
        assertEq(usdc.balanceOf(trader), before + CAP, "beneficiary pulls the fine");
    }

    function test_answered_order_cannot_be_challenged_again() public {
        bytes32 h = _order("included-long-ago", 0);
        uint256 id = _settleWith(h);
        bytes memory sig = _sig(h, trader);
        _open(h, trader, outsider);
        s.answerChallenge(h, id, _none());
        assertTrue(s.challengeResolved(h), "resolved");
        assertEq(s.pendingEth(address(this)), STAKE, "pre-settled order forfeits the stake");

        vm.deal(outsider, STAKE);
        vm.prank(outsider);
        vm.expectRevert(DarkPerpSettlement.AlreadyResolved.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, sig);
        assertEq(s.openChallengeCount(), 0, "nothing reopened");
    }

    function test_slashed_order_cannot_be_challenged_again() public {
        bytes32 h = _order("never-settled", 0);
        bytes memory sig = _sig(h, trader);
        _open(h, trader, trader);
        _settleEmpty();
        _settleEmpty();
        _rollPastGrace(0);
        s.slashUnanswered(h);

        vm.deal(trader, STAKE);
        vm.prank(trader);
        vm.expectRevert(DarkPerpSettlement.AlreadyResolved.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, sig);
        assertEq(s.slashCount(), 1, "one fine per order hash");
    }

    function test_released_order_stays_resolved() public {
        bytes32 h = _order("released", 0);
        bytes memory sig = _sig(h, trader);
        _open(h, trader, trader);
        vm.prank(GOV);
        s.enterCloseOnly();
        s.releaseStaleChallenge(h);
        assertTrue(s.challengeResolved(h), "resolved");
        vm.deal(trader, STAKE);
        vm.prank(trader);
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, sig);
    }

    function test_authorization_is_bound_to_beneficiary_chain_and_settlement() public {
        bytes32 h = _order("bound", 0);
        vm.deal(outsider, 10 * STAKE);

        // Signed for the trader, submitted naming someone else.
        bytes memory forTrader = _sig(h, trader);
        vm.prank(outsider);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, outsider, forTrader);

        // Signed on another chain.
        uint256 chain = block.chainid;
        vm.chainId(chain + 1);
        bytes memory otherChain = _sig(h, trader);
        vm.chainId(chain);
        vm.prank(outsider);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, otherChain);

        // Signed for another settlement.
        bytes32 foreign = SettlementTestConfig.challengeAuthDigest(address(0xDEAD), h, SEQ, RECV_MS, HINT, trader);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(ENCLAVE_PK, foreign);
        vm.prank(outsider);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, abi.encodePacked(r, sg, v));

        // Signed over different receipt fields.
        vm.prank(outsider);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ + 1, RECV_MS, HINT, trader, forTrader);

        // Signed by a key other than the enclave's.
        bytes32 digest = SettlementTestConfig.challengeAuthDigest(address(s), h, SEQ, RECV_MS, HINT, trader);
        (v, r, sg) = vm.sign(0xBEEF, digest);
        vm.prank(outsider);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, abi.encodePacked(r, sg, v));

        assertEq(s.openChallengeCount(), 0, "nothing opened");
    }

    function test_raw_receipt_signature_is_not_an_authorization() public {
        bytes32 h = _order("raw-receipt", 0);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(ENCLAVE_PK, s.receiptDigest(h, SEQ, RECV_MS, HINT));
        vm.deal(outsider, STAKE);
        vm.prank(outsider);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, outsider, abi.encodePacked(r, sg, v));
    }

    function test_challenge_input_checks() public {
        bytes32 h = _order("inputs", 0);
        bytes memory sig = _sig(h, trader);
        vm.deal(trader, 10 * STAKE);

        vm.startPrank(trader);
        vm.expectRevert(DarkPerpSettlement.WrongChallengeBond.selector);
        s.challengeInclusion{value: STAKE - 1}(h, SEQ, RECV_MS, HINT, trader, sig);
        vm.expectRevert(DarkPerpSettlement.WrongChallengeBond.selector);
        s.challengeInclusion{value: STAKE + 1}(h, SEQ, RECV_MS, HINT, trader, sig);
        vm.expectRevert(DarkPerpSettlement.BadBeneficiary.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, address(0), sig);

        // Malformed or malleable signatures.
        vm.expectRevert(DarkPerpSettlement.NonCanonicalSignature.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, hex"1234");
        bytes32 digest = SettlementTestConfig.challengeAuthDigest(address(s), h, SEQ, RECV_MS, HINT, trader);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(ENCLAVE_PK, digest);
        bytes memory highS = abi.encodePacked(r, bytes32(SECP_N - uint256(sg)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(DarkPerpSettlement.NonCanonicalSignature.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, highS);
        vm.expectRevert(DarkPerpSettlement.NonCanonicalSignature.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, abi.encodePacked(r, sg, v - 27));

        // A fresh order is not ripe yet.
        uint64 fresh = uint64(block.timestamp * 1000);
        bytes memory freshSig = SettlementTestConfig.challengeSig(vm, ENCLAVE_PK, s, h, SEQ, fresh, HINT, trader);
        vm.expectRevert(DarkPerpSettlement.NotRipe.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, fresh, HINT, trader, freshSig);
        vm.stopPrank();

        vm.warp(block.timestamp + SettlementTestConfig.INCLUSION_DEADLINE_SECS);
        vm.prank(trader);
        s.challengeInclusion{value: STAKE}(h, SEQ, fresh, HINT, trader, freshSig);
        assertTrue(_isOpen(h), "ripe exactly at the deadline");
    }

    // --- many challenges, one left unanswered ------------------------------------

    function test_one_unanswered_challenge_among_many_pays_at_most_the_cap_and_settlement_continues() public {
        // TVL at the full capacity the bond covers.
        _largeDeposit(s.depositCapacity());
        assertEq(s.requiredBond(), BOND, "bond exactly covers the floor");

        bytes32[] memory hs = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) {
            hs[i] = _order("many", i);
            _open(hs[i], outsider, outsider);
        }
        // The sequencer includes four of them in the next batch and answers in one call.
        bytes32[] memory four = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            four[i] = hs[i];
        }
        _answerAll(_settleOrders(four), four);
        assertEq(s.openChallengeCount(), 1, "one left open");

        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        s.slashUnanswered(hs[4]);
        _settleEmpty();
        vm.expectRevert(DarkPerpSettlement.ChallengeNotExpired.selector);
        s.slashUnanswered(hs[4]);
        (,,, uint256 settledAt) = s.batches(P - 1);
        vm.roll(settledAt + GRACE);
        vm.expectRevert(DarkPerpSettlement.ChallengeNotExpired.selector);
        s.slashUnanswered(hs[4]);

        vm.roll(settledAt + GRACE + 1);
        vmx.expectEmit(true, true, false, true, address(s));
        emit DarkPerpSettlement.SequencerSlashed(hs[4], outsider, CAP);
        vm.prank(anyone);
        s.slashUnanswered(hs[4]);

        assertEq(s.pendingUsdc(outsider), CAP, "capped fine, not the whole bond");
        assertEq(s.sequencerBond(), BOND - CAP, "bond reduced by the cap");
        assertEq(s.slashCount(), 1, "one slash");
        assertFalse(s.closeOnly(), "the exchange keeps running");
        assertEq(s.pendingEth(outsider), 5 * STAKE, "every stake back: four forced in, one fined");
        _assertSolvent(_parties());

        // Settlement continues; deposits wait for a top-up.
        _settleEmpty();
        assertEq(s.depositCapacity(), 0, "no capacity after the fine");
        _depositRefused(trader, 1);
        _postBond(2 * CAP);
        assertEq(s.depositCapacity(), 20 * CAP, "capacity restored by the top-up");
        _largeDeposit(1);
    }

    function _answerAll(uint256 batchId, bytes32[] memory hs) internal {
        bytes32[] memory leaves = _inclLeaves(batchId, hs);
        bytes32[][] memory proofs = new bytes32[][](hs.length);
        for (uint256 i = 0; i < hs.length; i++) {
            proofs[i] = _proof(leaves, i);
        }
        uint256 answered = s.answerChallenges(batchId, hs, new bool[](hs.length), proofs);
        assertEq(answered, hs.length, "all answered");
    }

    function _largeDeposit(uint256 amount) internal {
        address depositor = address(0x3A1E);
        bytes32 commit = keccak256(abi.encode("large-deposit", vault.depositCount()));
        uint64 until = uint64(block.timestamp + 3600);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, depositor, commit, amount, until);
        usdc.mint(depositor, amount);
        vm.startPrank(depositor);
        usdc.approve(address(vault), amount);
        vault.deposit(amount, commit, until, sig);
        vm.stopPrank();
    }

    function _depositRefused(address who, uint256 amount) internal {
        bytes32 commit = keccak256(abi.encode("refused", who, amount));
        uint64 until = uint64(block.timestamp + 3600);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, who, commit, amount, until);
        usdc.mint(who, amount);
        vm.startPrank(who);
        usdc.approve(address(vault), amount);
        vm.expectRevert(CollateralVault.BondCapacityExceeded.selector);
        vault.deposit(amount, commit, until, sig);
        vm.stopPrank();
    }

    // --- a slow honest prover --------------------------------------------------------

    function test_slow_prover_cannot_be_slashed_without_progress() public {
        bytes32 h = _order("fresh-order", 0);
        _open(h, trader, trader);

        // The batch takes far longer than any block window to prove.
        vm.roll(block.number + LIVENESS - 1);
        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        s.slashUnanswered(h);

        uint256 id = _settleWith(h);
        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        s.slashUnanswered(h);

        vm.prank(anyone);
        s.answerChallenge(h, id, _none());
        assertEq(s.pendingEth(trader), STAKE, "late inclusion refunds the challenger");
        assertEq(s.pendingUsdc(trader), 0, "no fine for an order that was included");
        assertEq(s.sequencerBond(), BOND, "bond intact");
        assertEq(s.slashCount(), 0, "never slashed");
    }

    function test_answer_stays_valid_past_the_grace_until_a_slash_lands() public {
        bytes32 h = _order("late-answer", 0);
        _open(h, trader, trader);
        uint256 id = _settleWith(h);
        _settleEmpty();
        _rollPastGrace(0);
        vm.roll(block.number + 1_000);

        vm.prank(anyone);
        s.answerChallenge(h, id, _none());
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.slashUnanswered(h);
        assertEq(s.slashCount(), 0, "the answer won the race");
    }

    // --- permissionless, batched answers ----------------------------------------------

    function test_anyone_can_answer_and_the_stake_follows_the_open_batch_count() public {
        // Already settled when challenged: the stake goes to the sequencer.
        bytes32 a = _order("pre-settled", 0);
        uint256 idA = _settleWith(a);
        _open(a, trader, trader);
        // Settled after the challenge opened: the stake goes back to the submitter.
        bytes32 b = _order("forced-in", 0);
        _open(b, outsider, relayer);
        uint256 idB = _settleWith(b);

        vmx.expectEmit(true, false, false, true, address(s));
        emit DarkPerpSettlement.InclusionAnswered(a, idA);
        vm.prank(anyone);
        s.answerChallenge(a, idA, _none());
        vm.prank(anyone);
        s.answerChallenge(b, idB, _none());

        assertEq(s.pendingEth(address(this)), STAKE, "pre-settled order forfeits to the sequencer");
        assertEq(s.pendingEth(trader), 0, "no refund for a pre-settled order");
        assertEq(s.pendingEth(relayer), STAKE, "forced inclusion refunds the submitter");
        assertEq(s.pendingEth(anyone), 0, "the answerer earns nothing");
        _assertSolvent(_parties());

        uint256 before = address(this).balance;
        s.claimEth();
        assertEq(address(this).balance, before + STAKE, "stakes are pulled, not pushed");
    }

    function test_rejection_answers_route_like_inclusion_answers() public {
        bytes32 a = _order("rejected-before", 0);
        uint256 idA = _settleRejecting(a);
        _open(a, trader, trader);
        bytes32 b = _order("rejected-after", 0);
        _open(b, trader, relayer);
        uint256 idB = _settleRejecting(b);

        vmx.expectEmit(true, false, false, true, address(s));
        emit DarkPerpSettlement.RejectionAnswered(b, idB);
        vm.prank(anyone);
        s.answerByRejection(b, idB, _none());
        vm.prank(anyone);
        s.answerByRejection(a, idA, _none());
        assertEq(s.pendingEth(relayer), STAKE, "late rejection refunds the submitter");
        assertEq(s.pendingEth(address(this)), STAKE, "earlier rejection forfeits to the sequencer");
    }

    function test_single_answers_check_batch_and_membership() public {
        bytes32 h = _order("answer-checks", 0);
        bytes32 other = _order("someone-else", 0);
        _open(h, trader, trader);

        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.answerChallenge(other, 0, _none());
        vm.expectRevert(DarkPerpSettlement.BatchNotSettled.selector);
        s.answerChallenge(h, 0, _none());
        vm.expectRevert(DarkPerpSettlement.BatchNotSettled.selector);
        s.answerByRejection(h, 0, _none());

        // A batch that does not hold the order cannot answer for it, either way.
        uint256 idOther = _settleWith(other);
        vm.expectRevert(DarkPerpSettlement.NotIncluded.selector);
        s.answerChallenge(h, idOther, _none());
        vm.expectRevert(DarkPerpSettlement.NotRejected.selector);
        s.answerByRejection(h, idOther, _none());

        // An inclusion leaf is not a rejection leaf, and a leaf is bound to its batch.
        uint256 id = _settleWith(h);
        vm.expectRevert(DarkPerpSettlement.NotRejected.selector);
        s.answerByRejection(h, id, _none());
        vm.expectRevert(DarkPerpSettlement.NotIncluded.selector);
        s.answerChallenge(h, idOther, _none());
        s.answerChallenge(h, id, _none());
        assertFalse(_isOpen(h), "answered");
    }

    function test_batched_answers_resolve_one_hundred_challenges_in_one_call() public {
        uint256 n = 100;
        bytes32[] memory hs = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            hs[i] = _order("batched", i);
            _open(hs[i], address(uint160(0x5000 + i)), relayer);
        }
        uint256 id = _settleOrders(hs);
        bytes32[] memory leaves = _inclLeaves(id, hs);

        // Three were answered individually first (a concurrent answerer).
        s.answerChallenge(hs[5], id, _proof(leaves, 5));
        s.answerChallenge(hs[17], id, _proof(leaves, 17));
        s.answerChallenge(hs[99], id, _proof(leaves, 99));

        // All 100 plus a duplicate entry.
        bytes32[] memory batch = new bytes32[](n + 1);
        bytes32[][] memory proofs = new bytes32[][](n + 1);
        for (uint256 i = 0; i < n; i++) {
            batch[i] = hs[i];
            proofs[i] = _proof(leaves, i);
        }
        batch[n] = hs[0];
        proofs[n] = proofs[0];

        vm.prank(anyone);
        uint256 gasBefore = gasleft();
        uint256 answered = s.answerChallenges(id, batch, new bool[](n + 1), proofs);
        uint256 used = gasBefore - gasleft();
        assertEq(answered, n - 3, "every still-open challenge answered once");
        assertEq(s.openChallengeCount(), 0, "open set empty");
        assertEq(s.pendingEth(relayer), n * STAKE, "every stake refunded");
        assertTrue(used < 10_000_000, "100 answers fit well inside one block");
        _assertSolvent(_parties());
    }

    function test_batched_answers_mix_inclusions_and_rejections() public {
        bytes32 a = _order("mix", 0);
        bytes32 b = _order("mix", 1);
        bytes32 c = _order("mix", 2);
        _open(a, trader, relayer);
        _open(b, trader, relayer);
        _open(c, trader, relayer);

        uint256 id = s.batchCount();
        bytes32[] memory ordered = _inclLeaves(id, _list(a, c));
        bytes32[] memory rejected = _rejLeaves(id, _list(b));
        _settleRoots(_root(ordered), _root(rejected));

        bool[] memory byRejection = new bool[](3);
        byRejection[1] = true;
        bytes32[][] memory proofs = new bytes32[][](3);
        proofs[0] = _proof(ordered, 0);
        proofs[1] = _none();
        proofs[2] = _proof(ordered, 1);
        assertEq(s.answerChallenges(id, _list(a, b, c), byRejection, proofs), 3, "three answered");
        assertEq(s.openChallengeCount(), 0, "all closed");
        assertTrue(s.challengeResolved(b), "rejection resolves too");
    }

    function test_batched_answers_revert_on_any_bad_proof() public {
        bytes32 a = _order("partial", 0);
        bytes32 b = _order("partial", 1);
        bytes32 c = _order("partial", 2);
        _open(a, trader, relayer);
        _open(b, trader, relayer);
        _open(c, trader, relayer);
        bytes32[] memory held = _list(a, b);
        uint256 id = _settleOrders(held);
        bytes32[] memory leaves = _inclLeaves(id, held);

        bytes32[][] memory proofs = new bytes32[][](3);
        proofs[0] = _proof(leaves, 0);
        proofs[1] = _proof(leaves, 1);
        proofs[2] = _proof(leaves, 1);
        bytes32[] memory all = _list(a, b, c);
        bool[] memory flags = new bool[](3);
        vm.expectRevert(DarkPerpSettlement.NotIncluded.selector);
        s.answerChallenges(id, all, flags, proofs);
        assertEq(s.openChallengeCount(), 3, "nothing answered by the failed call");

        flags[2] = true;
        vm.expectRevert(DarkPerpSettlement.NotRejected.selector);
        s.answerChallenges(id, all, flags, proofs);
        assertEq(s.openChallengeCount(), 3, "still nothing answered");
    }

    function test_batched_answers_check_lengths_and_batch() public {
        bytes32 a = _order("lengths", 0);
        _open(a, trader, relayer);
        bytes32[] memory one = _list(a);
        bytes32[][] memory oneProof = new bytes32[][](1);
        oneProof[0] = _none();

        vm.expectRevert(DarkPerpSettlement.LengthMismatch.selector);
        s.answerChallenges(0, one, new bool[](2), oneProof);
        vm.expectRevert(DarkPerpSettlement.LengthMismatch.selector);
        s.answerChallenges(0, one, new bool[](1), new bytes32[][](0));
        vm.expectRevert(DarkPerpSettlement.BatchNotSettled.selector);
        s.answerChallenges(0, one, new bool[](1), oneProof);

        uint256 id = _settleWith(a);
        assertEq(s.answerChallenges(id, one, new bool[](1), oneProof), 1, "answered");
        assertEq(s.answerChallenges(id, one, new bool[](1), oneProof), 0, "a closed entry is skipped");
    }

    // --- the enumerable open set -----------------------------------------------------

    function test_open_set_paging_stays_consistent_across_answer_slash_and_release() public {
        bytes32 h0 = _order("set", 0);
        bytes32 h1 = _order("set", 1);
        bytes32 h2 = _order("set", 2);
        bytes32 h3 = _order("set", 3);
        bytes32 h4 = _order("set", 4);
        _open(h0, trader, relayer);
        _open(h1, trader, relayer);
        _open(h2, trader, relayer);
        _open(h3, trader, relayer);
        _assertOpenSet(_list(h0, h1, h2, h3));

        // Answer h1: the last entry moves into its slot.
        s.answerChallenge(h1, _settleWith(h1), _none());
        _assertOpenSet(_list(h0, h3, h2));
        bytes32[] memory page = s.openChallenges(0, 2);
        assertEq(page.length, 2, "first page");
        assertEq(page[1], h3, "first page order");
        page = s.openChallenges(2, 2);
        assertEq(page.length, 1, "short last page");
        assertEq(page[0], h2, "last page entry");
        assertEq(s.openChallenges(3, 5).length, 0, "start at the end");
        assertEq(s.openChallenges(10, 1).length, 0, "start past the end");
        assertEq(s.openChallenges(0, 0).length, 0, "empty page");
        assertEq(s.openChallenges(1, type(uint256).max).length, 2, "max is clamped, not refused");

        // A later challenge, then slash h0 once the progress gate and grace have passed.
        _settleEmpty();
        _open(h4, trader, relayer);
        _assertOpenSet(_list(h0, h3, h2, h4));
        _rollPastGrace(0);
        s.slashUnanswered(h0);
        _assertOpenSet(_list(h4, h3, h2));

        // Close-only before h4 could reach the gate: release it; h2 and h3 stay slashable.
        vm.prank(GOV);
        s.enterCloseOnly();
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h2);
        s.releaseStaleChallenge(h4);
        _assertOpenSet(_list(h2, h3));
        s.slashUnanswered(h3);
        _assertOpenSet(_list(h2));
        s.slashUnanswered(h2);
        _assertOpenSet(new bytes32[](0));
        assertEq(s.slashCount(), 3, "three fines");
        _assertSolvent(_parties());
    }

    function test_open_set_pages_are_capped_at_512_entries() public {
        for (uint256 i = 0; i < 513; i++) {
            _open(_order("page-cap", i), trader, relayer);
        }
        assertEq(s.openChallengeCount(), 513, "all open");
        bytes32[] memory page = s.openChallenges(0, 10_000);
        assertEq(page.length, 512, "a page never exceeds 512 entries");
        assertEq(page[0], _order("page-cap", 0), "first entry");
        assertEq(page[511], _order("page-cap", 511), "last entry of the first page");
        bytes32[] memory rest = s.openChallenges(512, 512);
        assertEq(rest.length, 1, "the remainder is on the next page");
        assertEq(rest[0], _order("page-cap", 512), "remaining entry");
    }

    /// Random interleavings of open, answer, settle and slash over eight order hashes
    /// (all of them already held by batch 0): the open set always equals the challenges
    /// the model expects to be open, and the books balance.
    function testFuzz_open_set_tracks_open_challenges(uint256 seed) public {
        bytes32[] memory hs = new bytes32[](8);
        for (uint256 i = 0; i < 8; i++) {
            hs[i] = _order("fuzz-set", i);
        }
        bytes32[] memory leaves = _inclLeaves(0, hs);
        _settleRoots(_root(leaves), Z);
        bool[] memory model = new bool[](8);

        for (uint256 step = 0; step < 24; step++) {
            uint256 r = uint256(keccak256(abi.encode(seed, step)));
            uint256 i = (r >> 8) % 8;
            uint256 op = r % 4;
            if (op == 0) {
                if (_tryOpen(hs[i])) model[i] = true;
            } else if (op == 1) {
                try s.answerChallenge(hs[i], 0, _proof(leaves, i)) {
                    model[i] = false;
                } catch {}
            } else if (op == 2) {
                _settleEmpty();
                vm.roll(block.number + GRACE / 2);
            } else {
                try s.slashUnanswered(hs[i]) {
                    model[i] = false;
                } catch {}
            }
            _checkModel(hs, model);
        }

        vm.prank(GOV);
        s.enterCloseOnly();
        vm.roll(block.number + 10 * GRACE);
        for (uint256 i = 0; i < 8; i++) {
            if (!model[i]) continue;
            try s.releaseStaleChallenge(hs[i]) {}
            catch {
                s.slashUnanswered(hs[i]);
            }
            model[i] = false;
            _checkModel(hs, model);
        }
        assertEq(s.openChallengeCount(), 0, "every challenge ended");
        _assertSolvent(_parties());
    }

    function _tryOpen(bytes32 h) internal returns (bool ok) {
        bytes memory sig = _sig(h, trader);
        vm.deal(relayer, relayer.balance + STAKE);
        vm.prank(relayer);
        try s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, sig) {
            ok = true;
        } catch {}
    }

    function _checkModel(bytes32[] memory hs, bool[] memory model) internal view {
        uint256 expected;
        for (uint256 i = 0; i < hs.length; i++) {
            assertTrue(_isOpen(hs[i]) == model[i], "challenge state matches the model");
            if (model[i]) expected++;
        }
        assertEq(s.openChallengeCount(), expected, "open count matches the model");
        bytes32[] memory page = s.openChallenges(0, 512);
        for (uint256 j = 0; j < page.length; j++) {
            assertTrue(_isOpen(page[j]), "only open challenges are listed");
            for (uint256 k = j + 1; k < page.length; k++) {
                assertTrue(page[j] != page[k], "no duplicates");
            }
        }
    }

    // --- a bond below the cap -------------------------------------------------------

    /// Below the cap the beneficiary decides when to take the reduced fine. A submitter
    /// that is not the beneficiary may close the challenge (and recover its stake) only
    /// a further liveness window after the slash became possible; nobody else ever may.
    function test_short_bond_slash_is_restricted_to_the_beneficiary_or_the_staker() public {
        s.withdrawBond(BOND - 400e6);
        bytes32 a = _order("short", 0);
        bytes32 b = _order("short", 1);
        _open(a, trader, relayer);
        _open(b, outsider, relayer);
        _settleEmpty();
        _settleEmpty();
        _rollPastGrace(0);
        uint256 firstSlashBlock = block.number;

        vm.prank(anyone);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(a);
        vm.prank(relayer);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(a);
        vm.prank(trader);
        s.slashUnanswered(a);
        assertEq(s.pendingUsdc(trader), 400e6, "the whole short bond, below the cap");
        assertEq(s.sequencerBond(), 0, "bond exhausted");

        vm.prank(trader);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(b);
        vm.prank(relayer);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(b);
        vm.roll(firstSlashBlock - 1 + LIVENESS);
        vm.prank(relayer);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(b);

        vm.roll(firstSlashBlock + LIVENESS);
        vm.prank(anyone);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(b);
        vm.prank(relayer);
        s.slashUnanswered(b);
        assertEq(s.pendingUsdc(outsider), 0, "nothing left to pay");
        assertEq(s.pendingEth(relayer), 2 * STAKE, "both stakes returned");
        assertEq(s.slashCount(), 2, "both resolved by slash");
        _assertSolvent(_parties());
    }

    /// A third party that landed someone else's authorization cannot close it for a
    /// reduced fine while the beneficiary waits for a bond top-up; after the top-up the
    /// beneficiary takes the full cap.
    function test_submitter_waits_for_the_beneficiary_on_a_short_bond() public {
        s.withdrawBond(BOND - CAP);
        bytes32 first = _order("short-fine", 0);
        bytes32 second = _order("short-fine", 1);
        _open(first, relayer, relayer);
        _open(second, trader, outsider);
        _settleEmpty();
        _settleEmpty();
        _rollPastGrace(0);

        vm.prank(anyone);
        s.slashUnanswered(first);
        assertEq(s.sequencerBond(), 0, "the first fine took the whole bond");

        vm.prank(outsider);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(second);
        assertTrue(_isOpen(second), "still open for the beneficiary");

        _postBond(CAP);
        vm.prank(trader);
        s.slashUnanswered(second);
        assertEq(s.pendingUsdc(trader), CAP, "the beneficiary takes the full cap");
        assertEq(s.pendingEth(outsider), STAKE, "the submitter's stake is returned");
        _assertSolvent(_parties());
    }

    // --- releasing challenges close-only made unreachable --------------------------

    function test_stale_challenge_is_released_after_a_liveness_close_only() public {
        bytes32 h = _order("stale-liveness", 0);
        _open(h, trader, relayer);
        _settleEmpty();
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h);

        vm.roll(block.number + LIVENESS + 1);
        s.triggerCloseOnly();
        assertEq(s.closeOnlyBatchCount(), 1, "one phase-0 batch after the challenge");

        // Wind-down batches do not count as progress.
        vm.roll(block.number + WIND_DOWN_GRACE);
        bytes32 prev = s.currentStateRoot();
        bytes32 wd = s.windDownCommitment(prev, M, keccak256("wd"), Z, Z, Z, Z, 1);
        vm.prank(GOV);
        s.finalSettle(prev, M, keccak256("wd"), Z, Z, Z, Z, 0, abi.encode(wd));
        vm.roll(block.number + 10 * GRACE);
        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        s.slashUnanswered(h);

        vmx.expectEmit(true, false, false, true, address(s));
        emit DarkPerpSettlement.ChallengeReleased(h);
        vm.prank(anyone);
        s.releaseStaleChallenge(h);
        assertEq(s.pendingEth(relayer), STAKE, "stake refunded to the submitter");
        assertTrue(s.challengeResolved(h), "resolved");
        assertEq(s.openChallengeCount(), 0, "removed from the open set");
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.slashUnanswered(h);
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h);
        assertEq(s.sequencerBond(), BOND, "no fine");
    }

    function test_stale_challenge_is_released_after_a_governance_close_only() public {
        bytes32 h = _order("stale-governance", 0);
        _open(h, trader, relayer);
        vm.prank(GOV);
        s.enterCloseOnly();
        s.releaseStaleChallenge(h);
        assertEq(s.pendingEth(relayer), STAKE, "stake refunded");
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.slashUnanswered(h);
    }

    function test_release_is_refused_while_the_slash_is_reachable() public {
        bytes32 h = _order("reachable", 0);
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h);
        _open(h, trader, relayer);
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h);

        // Enough phase-0 progress before close-only: the slash stays available.
        _settleEmpty();
        _settleEmpty();
        vm.prank(GOV);
        s.enterCloseOnly();
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h);
        vm.expectRevert(DarkPerpSettlement.ChallengeNotExpired.selector);
        s.slashUnanswered(h);
        _rollPastGrace(0);
        s.slashUnanswered(h);
        assertEq(s.pendingUsdc(trader), CAP, "fined in close-only");
        assertTrue(s.closeOnly(), "still close-only");
    }

    // --- other rules -------------------------------------------------------------------

    function test_challenges_are_refused_in_close_only() public {
        bytes32 h = _order("closed", 0);
        bytes memory sig = _sig(h, trader);
        vm.prank(GOV);
        s.enterCloseOnly();
        vm.deal(trader, STAKE);
        vm.prank(trader);
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.challengeInclusion{value: STAKE}(h, SEQ, RECV_MS, HINT, trader, sig);
    }

    function test_withdraw_bond_reserves_the_cap_for_every_open_challenge() public {
        bytes32 a = _order("reserve", 0);
        bytes32 b = _order("reserve", 1);
        bytes32 c = _order("reserve", 2);
        uint256 idA = _settleWith(a);
        _open(a, trader, relayer);
        _open(b, trader, relayer);
        _open(c, trader, relayer);

        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(BOND - 3 * CAP + 1);
        s.withdrawBond(BOND - 3 * CAP);
        assertEq(s.sequencerBond(), 3 * CAP, "one cap per open challenge");

        s.answerChallenge(a, idA, _none());
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(CAP + 1);
        s.withdrawBond(CAP);

        // Every remaining challenge is still payable in full.
        _settleEmpty();
        _settleEmpty();
        _rollPastGrace(1);
        s.slashUnanswered(b);
        s.slashUnanswered(c);
        assertEq(s.pendingUsdc(trader), 2 * CAP, "both paid the full cap");
        assertEq(s.sequencerBond(), 0, "reserve used exactly");

        // The deposit floor dominates once it exceeds the reserve, also in close-only.
        _postBond(100e6);
        _largeDeposit(1_000e6);
        vm.prank(GOV);
        s.enterCloseOnly();
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(50e6 + 1);
        s.withdrawBond(50e6);
    }

    /// Within one block, whether the stake is refunded depends only on whether the order's
    /// batch settled before or after the challenge opened.
    function testFuzz_same_block_stake_routing_follows_transaction_order(
        uint8 priorBatches,
        bool rejection,
        bool settleFirst
    ) public {
        for (uint256 i; i < priorBatches % 4; ++i) {
            _settleWith(_order("prior", i));
        }
        bytes32 h = _order("same-block", 0);
        uint256 id = s.batchCount();
        uint256 blockAt = block.number;
        if (!settleFirst) _open(h, trader, relayer);
        if (rejection) _settleRejecting(h);
        else _settleWith(h);
        if (settleFirst) _open(h, trader, relayer);
        (,,, uint256 openBatchCount,,) = s.challenges(h);
        assertEq(openBatchCount, settleFirst ? id + 1 : id, "open batch count follows the order");

        if (rejection) s.answerByRejection(h, id, _none());
        else s.answerChallenge(h, id, _none());

        assertEq(block.number, blockAt, "one block");
        assertEq(s.pendingEth(relayer), settleFirst ? 0 : STAKE, "refund follows the transaction order");
        assertEq(s.pendingEth(address(this)), settleFirst ? STAKE : 0, "forfeit follows the transaction order");
    }
}

/// Test-only stand-in for a stablecoin with a blocklist: a transfer to or from a
/// blocked address reverts.
contract BlocklistUSDC {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blocked;

    function setBlocked(address who, bool on) external {
        blocked[who] = on;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _move(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        return _move(from, to, amount);
    }

    function _move(address from, address to, uint256 amount) internal returns (bool) {
        require(!blocked[from] && !blocked[to], "blocked");
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// Cheatcodes the redirect suite needs beyond the vendored MiniTest subset.
interface ClaimRedirectVm {
    function etch(address target, bytes calldata code) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData, address emitter) external;
}

/// A credited fine or stake can be paid to another address chosen by its owner, so an
/// account the token refuses to pay, or one that cannot receive ETH, still recovers it.
contract ClaimRedirectTest is MiniTest {
    ClaimRedirectVm internal constant vmx = ClaimRedirectVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    BlocklistUSDC internal usdc;

    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    uint256 internal constant GW_PK = 0x6A7E;
    bytes32 internal constant M = bytes32("manifest");
    bytes32 internal constant Z = bytes32(0);
    uint256 internal constant STAKE = SettlementTestConfig.CHALLENGE_BOND;
    uint256 internal constant CAP = SettlementTestConfig.SLASH_PAYOUT_CAP;
    address internal beneficiary = address(0xBE4E);
    address internal staker = address(0x57A4);
    address internal rescue = address(0x5AFE);

    function setUp() public {
        vm.roll(1000);
        vm.warp(10_000);
        s = new DarkPerpSettlement(
            SettlementTestConfig.defaults(
                address(this), vm.addr(ENCLAVE_PK), new MockClockVerifier(), bytes32(uint256(1))
            )
        );
        usdc = new BlocklistUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
        usdc.mint(address(this), CAP);
        usdc.approve(address(s), CAP);
        s.postBond(CAP);

        // An order that is never settled: after the progress gate and grace, a full-cap
        // fine goes to the beneficiary and the stake back to its submitter.
        bytes32 h = keccak256("withheld");
        bytes memory sig = SettlementTestConfig.challengeSig(vm, ENCLAVE_PK, s, h, 1, 1_000, 0, beneficiary);
        vm.deal(staker, STAKE);
        vm.prank(staker);
        s.challengeInclusion{value: STAKE}(h, 1, 1_000, 0, beneficiary, sig);
        _settleEmpty();
        _settleEmpty();
        vm.roll(block.number + SettlementTestConfig.CHALLENGE_GRACE_BLOCKS + 1);
        s.slashUnanswered(h);
        assertEq(s.pendingUsdc(beneficiary), CAP, "fine credited");
        assertEq(s.pendingEth(staker), STAKE, "stake credited");
    }

    function _settleEmpty() internal {
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256(abi.encode("root", s.batchCount()));
        bytes32 c = s.publicCommitment(prev, M, next, Z, Z, Z, Z);
        s.settleBatch(prev, M, next, Z, Z, Z, Z, 0, abi.encode(c));
    }

    function test_blocked_beneficiary_redirects_its_fine() public {
        usdc.setBlocked(beneficiary, true);
        vm.prank(beneficiary);
        vm.expectRevert();
        s.claimUsdc();
        assertEq(s.pendingUsdc(beneficiary), CAP, "a failed claim keeps the credit");

        vm.prank(beneficiary);
        vm.expectRevert(DarkPerpSettlement.BadRecipient.selector);
        s.claimUsdcTo(address(0));

        vmx.expectEmit(true, true, false, true, address(s));
        emit DarkPerpSettlement.UsdcClaimed(beneficiary, rescue, CAP);
        vm.prank(beneficiary);
        s.claimUsdcTo(rescue);
        assertEq(usdc.balanceOf(rescue), CAP, "paid to the chosen address");
        assertEq(s.pendingUsdc(beneficiary), 0, "credit spent");
        assertEq(usdc.balanceOf(address(s)), s.sequencerBond(), "only the bond remains");

        // A redirect only ever spends the caller's own credit.
        vm.prank(staker);
        s.claimUsdcTo(staker);
        assertEq(usdc.balanceOf(staker), 0, "nothing credited to the staker");
    }

    function test_staker_that_cannot_receive_eth_redirects_its_stake() public {
        vmx.etch(staker, hex"60006000fd"); // reverts on any call, including a plain transfer
        vm.prank(staker);
        vm.expectRevert(DarkPerpSettlement.TransferFailed.selector);
        s.claimEth();
        assertEq(s.pendingEth(staker), STAKE, "a failed claim keeps the credit");

        vm.prank(staker);
        vm.expectRevert(DarkPerpSettlement.BadRecipient.selector);
        s.claimEthTo(address(0));

        vmx.expectEmit(true, true, false, true, address(s));
        emit DarkPerpSettlement.EthClaimed(staker, rescue, STAKE);
        vm.prank(staker);
        s.claimEthTo(rescue);
        assertEq(rescue.balance, STAKE, "paid to the chosen address");
        assertEq(s.pendingEth(staker), 0, "credit spent");
        assertEq(address(s).balance, 0, "nothing left in the settlement");
    }

    function test_plain_claims_pay_the_credited_account() public {
        vmx.expectEmit(true, true, false, true, address(s));
        emit DarkPerpSettlement.UsdcClaimed(beneficiary, beneficiary, CAP);
        vm.prank(beneficiary);
        s.claimUsdc();
        assertEq(usdc.balanceOf(beneficiary), CAP, "fine pulled");

        vmx.expectEmit(true, true, false, true, address(s));
        emit DarkPerpSettlement.EthClaimed(staker, staker, STAKE);
        vm.prank(staker);
        s.claimEth();
        assertEq(staker.balance, STAKE, "stake pulled");
    }
}
