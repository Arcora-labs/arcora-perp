// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";
import {IZkVerifier} from "../src/interfaces/IZkVerifier.sol";

/// Cheatcodes this suite needs beyond the vendored MiniTest subset.
interface ClockTestVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function chainId(uint256 chainId_) external;
    function snapshotState() external returns (uint256);
    function revertToState(uint256 snapshotId) external returns (bool);
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// Tests exercise REAL settlement entrypoints with an explicitly mock proof
/// backend. They do not establish SP1 proof soundness or deployed-vkey identity.
contract ClockBoundVerifierTest is MiniTest {
    ClockTestVm internal constant xvm = ClockTestVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    ClockBoundVerifier c;
    DarkPerpSettlement s;
    MockZkVerifier inner;
    bytes32 constant ROOT = bytes32(uint256(1));
    bytes32 constant NEXT = bytes32(uint256(2));
    bytes32 constant M = bytes32(uint256(3));
    bytes32 constant Z = bytes32(0);

    /// Same value as `ClockBoundVerifier.DOMAIN`, kept local so proof construction makes
    /// no external call (safe to use right after `vm.prank`).
    bytes32 constant DOMAIN = keccak256("arcora:clock-bound-proof:v2");
    uint64 constant MAX_WINDOW_MS = 10_000;
    uint64 constant SKEW_MS = 2_000;
    /// The fixture's anchor timeout: 60 s of block time.
    uint64 constant TIMEOUT_MS = 60_000;
    /// `ClockCancelled(uint64,uint8,bytes32)`, from `cast keccak`.
    bytes32 constant CLOCK_CANCELLED_TOPIC = 0xfaa0971776597d114f0c99710538f5b1d23c25afc07fcd6c9b7d724f6d405815;
    /// A governance address distinct from the sequencer (this contract).
    address constant GOV = address(0x60F);

    function setUp() public {
        vm.warp(100);
        vm.roll(1);
        inner = new MockZkVerifier();
        (c, s) = _stack(address(this), MAX_WINDOW_MS, SKEW_MS, TIMEOUT_MS);
    }

    /// A clock over the mock inner verifier, wired to a fresh settlement whose sequencer
    /// is this contract and whose governance is `gov`.
    function _stack(address gov, uint64 maxWindowMs, uint64 skewMs, uint64 timeoutMs)
        internal
        returns (ClockBoundVerifier clock, DarkPerpSettlement st)
    {
        clock = new ClockBoundVerifier(inner, maxWindowMs, skewMs, timeoutMs);
        st = new DarkPerpSettlement(
            SettlementTestConfig.legacy(address(this), address(0x123), clock, ROOT, 100, 50, 1 ether, 600, gov, 10)
        );
        clock.bindSettlement(IClockSettlement(address(st)));
    }

    function base() internal view returns (bytes32) {
        return s.publicCommitment(s.currentStateRoot(), M, NEXT, Z, Z, Z, Z);
    }

    function register(uint64 first, uint64 last, uint64 count) internal returns (bytes32) {
        return c.register(uint64(s.batchCount()), s.currentStateRoot(), base(), first, last, count, 0);
    }

    function proof(bytes32 b, bytes32 receipt) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(DOMAIN, b, receipt)));
    }

    function settle(bytes memory p) internal {
        s.settleBatch(s.currentStateRoot(), M, NEXT, Z, Z, Z, Z, 0, p);
    }

    function registerFails(uint64 first, uint64 last, uint64 count) internal {
        bytes memory data =
            abi.encodeCall(c.register, (uint64(s.batchCount()), s.currentStateRoot(), base(), first, last, count, 0));
        (bool ok,) = address(c).call(data);
        assertTrue(!ok, "registration must fail");
    }

    function settleFails(bytes memory pr) internal {
        bytes memory data = abi.encodeCall(s.settleBatch, (s.currentStateRoot(), M, NEXT, Z, Z, Z, Z, 0, pr));
        (bool ok,) = address(s).call(data);
        assertTrue(!ok, "settlement must fail");
    }

    /// Calls `target` with `data` as `who` and requires a revert with custom error `sel`.
    /// `data` is built by the caller before the prank, so no other call consumes it.
    function _revertsAs(address who, address target, bytes memory data, bytes4 sel, string memory m) internal {
        vm.prank(who);
        (bool ok, bytes memory ret) = target.call(data);
        assertTrue(!ok, m);
        assertTrue(ret.length >= 4 && bytes4(ret) == sel, m);
    }

    function _reverts(address target, bytes memory data, bytes4 sel, string memory m) internal {
        _revertsAs(address(this), target, data, sel, m);
    }

    function _cancelData(uint64 batchId, uint8 phase_, bytes32 receipt) internal view returns (bytes memory) {
        return abi.encodeCall(c.cancel, (batchId, phase_, receipt));
    }

    /// Calldata for each settle entrypoint with the fixture's fixed manifest and zero
    /// side roots.
    function _settleData(bytes32 prev, bytes32 newRoot, bytes memory p) internal view returns (bytes memory) {
        return abi.encodeCall(s.settleBatch, (prev, M, newRoot, Z, Z, Z, Z, 0, p));
    }

    function _finalSettleData(bytes32 prev, bytes32 newRoot, bytes memory p) internal view returns (bytes memory) {
        return abi.encodeCall(s.finalSettle, (prev, M, newRoot, Z, Z, Z, Z, 0, p));
    }

    function _finalExitData(bytes32 prev, bytes32 newRoot, bytes memory p) internal view returns (bytes memory) {
        return abi.encodeCall(s.finalExit, (prev, M, newRoot, Z, Z, Z, Z, 0, p));
    }

    function test_actual_settlement_requires_registration() public {
        bytes32 b = base();
        settleFails(abi.encodePacked(b));
        assertEq(s.batchCount(), 0, "no advance");
    }

    function test_legacy_proof_cannot_bypass_registered_clock() public {
        bytes32 b = base();
        register(99_000, 100_000, 2);
        settleFails(abi.encodePacked(b));
    }

    function test_bound_proof_settles_through_existing_entrypoint() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        settle(proof(b, r));
        assertEq(s.batchCount(), 1, "one batch");
        assertEq(s.currentStateRoot(), NEXT, "root");
    }

    function test_proof_delay_keeps_original_receipt() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        vm.warp(10_000);
        assertEq(register(99_000, 100_000, 2), r, "retry cannot restamp");
        settle(proof(b, r));
    }

    function test_registration_is_immutable_even_with_valid_new_clock() public {
        register(99_000, 100_000, 2);
        registerFails(99_001, 100_000, 2);
    }

    function test_wrong_manifest_cannot_replace_same_batch() public {
        register(99_000, 100_000, 2);
        vm.expectRevert();
        c.register(0, ROOT, bytes32(uint256(999)), 99_000, 100_000, 2, 0);
    }

    function test_clock_does_not_replace_root_continuity() public {
        bytes32 b = base();
        vm.expectRevert();
        c.register(0, NEXT, b, 99_000, 100_000, 2, 0);
    }

    function test_clock_does_not_accept_future_batch() public {
        bytes32 b = base();
        vm.expectRevert();
        c.register(1, ROOT, b, 99_000, 100_000, 2, 0);
    }

    function test_registration_requires_role_authorization() public {
        bytes32 b = base();
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        c.register(0, ROOT, b, 99_000, 100_000, 2, 0);
    }

    function test_only_bound_settlement_can_call_verify() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        assertTrue(!c.verify(b, proof(b, r)), "wrong caller");
    }

    function test_previous_anchor_cannot_be_used_for_next_batch() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        bytes memory pr = proof(b, r);
        settle(pr);
        settleFails(pr);
        assertEq(s.batchCount(), 1, "no replay");
    }

    function test_batch_time_monotonicity_crosses_settlement() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        settle(proof(b, r));
        registerFails(99_000, 100_001, 2);
    }

    function test_refuses_backdated_window() public {
        registerFails(90_000, 97_999, 2);
    }

    function test_refuses_future_window() public {
        registerFails(100_000, 102_001, 2);
    }

    function test_refuses_overlong_window() public {
        registerFails(89_999, 100_000, 2);
    }

    function test_refuses_reversed_window() public {
        registerFails(100_001, 100_000, 2);
    }

    function test_price_free_window_has_canonical_zero_bounds() public {
        registerFails(100_000, 100_000, 0);
        bytes32 b = base();
        bytes32 r = register(0, 0, 0);
        settle(proof(b, r));
    }

    function test_rebinding_is_impossible() public {
        vm.expectRevert();
        c.bindSettlement(IClockSettlement(address(s)));
    }

    function test_time_overflow_rejected() public {
        vm.warp(type(uint256).max);
        registerFails(0, 0, 0);
    }

    function test_terminal_settlement_and_exit_also_require_bound_proofs() public {
        vm.roll(102);
        s.enterCloseOnly();
        vm.roll(112);
        bytes32 b = s.windDownCommitment(ROOT, M, NEXT, Z, Z, Z, Z, 1);
        vm.expectRevert();
        s.finalSettle(ROOT, M, NEXT, Z, Z, Z, Z, 0, abi.encodePacked(b));
        bytes32 r = c.register(0, ROOT, b, 0, 0, 0, 1);
        s.finalSettle(ROOT, M, NEXT, Z, Z, Z, Z, 0, proof(b, r));
        assertTrue(s.windDownSettled(), "phase1");
        bytes32 n = bytes32(uint256(4));
        b = s.windDownCommitment(NEXT, M, n, Z, Z, Z, Z, 2);
        vm.expectRevert();
        s.finalExit(NEXT, M, n, Z, Z, Z, Z, 0, abi.encodePacked(b));
        r = c.register(1, NEXT, b, 0, 0, 0, 2);
        s.finalExit(NEXT, M, n, Z, Z, Z, Z, 0, proof(b, r));
        assertEq(s.batchCount(), 2, "phase2");
    }

    function test_reorg_removes_anchor_and_old_proof_cannot_authorize_new_receipt() public {
        uint256 checkpoint = xvm.snapshotState();
        bytes32 b = base();
        bytes32 oldReceipt = register(99_000, 100_000, 2);
        bytes memory oldProof = proof(b, oldReceipt);
        settle(oldProof);
        assertEq(s.batchCount(), 1, "original branch settled");
        assertTrue(xvm.revertToState(checkpoint), "owned test-chain reorg");
        assertEq(s.batchCount(), 0, "reorg restored batch");
        settleFails(oldProof);
        vm.warp(101);
        bytes32 newReceipt = register(99_000, 100_000, 2);
        assertTrue(oldReceipt != newReceipt, "registration block time changed");
        settleFails(oldProof);
        settle(proof(b, newReceipt));
        assertEq(s.batchCount(), 1, "only canonical receipt settles");
    }

    function test_stored_receipt_cannot_replay_after_chain_id_change() public {
        uint256 originalChain = block.chainid;
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        bytes memory valid = proof(b, r);
        xvm.chainId(originalChain + 1);
        settleFails(valid);
        assertEq(s.batchCount(), 0, "wrong-chain record must not advance state");
        xvm.chainId(originalChain);
        settle(valid);
        assertEq(s.batchCount(), 1, "original domain still accepts its valid proof");
    }

    function test_solidity_v2_encoding_matches_rust() public pure {
        bytes32 domain = keccak256("arcora:clock-bound-proof:v2");
        bytes32 r = keccak256(
            abi.encode(
                domain,
                uint256(84532),
                address(0x1111111111111111111111111111111111111111),
                address(0x2222222222222222222222222222222222222222),
                uint64(7),
                bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333)),
                bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444)),
                uint8(0),
                uint64(9000),
                uint64(10000),
                uint64(2),
                uint64(11000),
                uint64(5000),
                uint64(1000)
            )
        );
        require(r == 0xcbfb7dcc2d499142a37c266092a6fa09588217870260d0141df68e3cb256f411, "Rust receipt");
        require(
            keccak256(
                abi.encode(
                    domain, bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444)), r
                )
            ) == 0x5b443bd8d8b1939c024bb51c33edcb759be76402d0a06b6ecd67f703261fb77b,
            "Rust commitment"
        );
    }

    // --- constructor and settlement wiring -------------------------------------------

    function test_constructor_records_anchor_timeout() public view {
        assertEq(c.anchorTimeoutMs(), TIMEOUT_MS, "anchor timeout");
        assertEq(c.maxWindowMs(), MAX_WINDOW_MS, "max window");
        assertEq(c.clockSkewMs(), SKEW_MS, "skew");
        assertEq(uint256(c.proofVersion()), 2, "proof version");
    }

    function test_constructor_refuses_anchor_timeout_below_one_second() public {
        vm.expectRevert(ClockBoundVerifier.InvalidConfiguration.selector);
        new ClockBoundVerifier(inner, MAX_WINDOW_MS, SKEW_MS, 0);
        vm.expectRevert(ClockBoundVerifier.InvalidConfiguration.selector);
        new ClockBoundVerifier(inner, MAX_WINDOW_MS, SKEW_MS, 999);
        ClockBoundVerifier floor = new ClockBoundVerifier(inner, MAX_WINDOW_MS, SKEW_MS, 1000);
        assertEq(floor.anchorTimeoutMs(), 1000, "the one-second floor is accepted");
    }

    function test_constructor_keeps_existing_refusals() public {
        vm.expectRevert(ClockBoundVerifier.InvalidConfiguration.selector);
        new ClockBoundVerifier(IZkVerifier(address(0xC0FFEE)), MAX_WINDOW_MS, SKEW_MS, TIMEOUT_MS);
        vm.expectRevert(ClockBoundVerifier.InvalidConfiguration.selector);
        new ClockBoundVerifier(inner, 0, SKEW_MS, TIMEOUT_MS);
    }

    function test_settlement_accepts_only_an_unbound_clock() public {
        // `c` is already bound to `s`: a second settlement cannot adopt it.
        DarkPerpSettlement.Config memory cfg =
            SettlementTestConfig.legacy(address(this), address(0x123), c, ROOT, 100, 50, 1 ether, 600, GOV, 10);
        vm.expectRevert(DarkPerpSettlement.InvalidConfig.selector);
        new DarkPerpSettlement(cfg);
        // A bare proof verifier lacks the clock shape.
        cfg.verifier = inner;
        vm.expectRevert(DarkPerpSettlement.InvalidConfig.selector);
        new DarkPerpSettlement(cfg);
    }

    /// The receipt preimage is unchanged by the timeout: it is not one of its fields.
    function test_receipt_preimage_excludes_anchor_timeout() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        bytes32 expected = keccak256(
            abi.encode(
                DOMAIN,
                block.chainid,
                address(c),
                address(s),
                uint64(0),
                ROOT,
                b,
                uint8(0),
                uint64(99_000),
                uint64(100_000),
                uint64(2),
                uint64(100_000),
                MAX_WINDOW_MS,
                SKEW_MS
            )
        );
        assertEq(r, expected, "receipt preimage");
        // The anchor getter still returns eight words.
        (bool ok, bytes memory ret) = address(c).staticcall(abi.encodeCall(c.anchor, (0, 0)));
        assertTrue(ok && ret.length == 256, "anchor() is eight words");
        ClockBoundVerifier.Anchor memory a = c.anchor(0, 0);
        assertTrue(a.exists, "exists");
        assertEq(a.receipt, r, "stored receipt");
        assertEq(uint256(a.anchoredAtMs), 100_000, "anchored at");
    }

    // --- anchor cancel: timing ---------------------------------------------------------

    function test_cancel_refused_before_timeout_and_replacement_stays_forbidden() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        vm.warp(100 + TIMEOUT_MS / 1000 - 1);
        _reverts(address(c), _cancelData(0, 0, r), ClockBoundVerifier.InvalidTime.selector, "too early");
        bytes memory replace = abi.encodeCall(c.register, (0, ROOT, b, 99_001, 100_000, 2, 0));
        _reverts(address(c), replace, ClockBoundVerifier.ReplacementForbidden.selector, "still immutable");
        bytes32 other = s.publicCommitment(ROOT, M, bytes32(uint256(0xBEEF)), Z, Z, Z, Z);
        replace = abi.encodeCall(c.register, (0, ROOT, other, 99_000, 100_000, 2, 0));
        _reverts(address(c), replace, ClockBoundVerifier.ReplacementForbidden.selector, "other commitment");
        assertTrue(c.anchor(0, 0).exists, "anchor kept");
        assertTrue(!c.cancelledReceipt(r), "not cancelled");
        // The anchor is still provable throughout.
        settle(proof(b, r));
        assertEq(s.batchCount(), 1, "settled before the timeout");
    }

    function test_cancel_allowed_exactly_at_timeout() public {
        bytes32 r = register(99_000, 100_000, 2);
        vm.warp(100 + TIMEOUT_MS / 1000);
        c.cancel(0, 0, r);
        assertTrue(c.cancelledReceipt(r), "cancelled at the boundary");
        assertTrue(!c.anchor(0, 0).exists, "anchor removed");
    }

    function test_cancel_emits_event_and_clears_anchor() public {
        bytes32 r = register(99_000, 100_000, 2);
        vm.warp(100 + TIMEOUT_MS / 1000 + 5);
        xvm.recordLogs();
        c.cancel(0, 0, r);
        ClockTestVm.Log[] memory logs = xvm.getRecordedLogs();
        bool seen;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(c) || logs[i].topics[0] != CLOCK_CANCELLED_TOPIC) continue;
            assertEq(logs[i].topics.length, 3, "two indexed fields");
            assertEq(logs[i].topics[1], bytes32(uint256(0)), "batch id topic");
            assertEq(logs[i].topics[2], bytes32(uint256(0)), "phase topic");
            assertEq(keccak256(logs[i].data), keccak256(abi.encode(r)), "receipt data");
            seen = true;
        }
        assertTrue(seen, "ClockCancelled emitted");
        ClockBoundVerifier.Anchor memory a = c.anchor(0, 0);
        assertTrue(!a.exists, "exists cleared");
        assertEq(a.receipt, bytes32(0), "receipt cleared");
        assertEq(a.baseCommitment, bytes32(0), "commitment cleared");
        assertEq(uint256(a.anchoredAtMs), 0, "time cleared");
        assertTrue(c.cancelledReceipt(r), "receipt recorded as cancelled");
        assertEq(s.batchCount(), 0, "settlement untouched");
        assertEq(s.currentStateRoot(), ROOT, "root untouched");
    }

    // --- anchor cancel: authorization and context -------------------------------------

    function test_cancel_requires_registrant_role_for_phase_zero() public {
        (c, s) = _stack(GOV, MAX_WINDOW_MS, SKEW_MS, TIMEOUT_MS);
        bytes32 r = register(99_000, 100_000, 2);
        vm.warp(100 + TIMEOUT_MS / 1000);
        bytes memory data = _cancelData(0, 0, r);
        _revertsAs(GOV, address(c), data, ClockBoundVerifier.Unauthorized.selector, "governance cannot cancel phase 0");
        _revertsAs(address(0xBEEF), address(c), data, ClockBoundVerifier.Unauthorized.selector, "stranger");
        // A phase-1 cancel needs governance, even for the sequencer.
        _reverts(address(c), _cancelData(0, 1, r), ClockBoundVerifier.Unauthorized.selector, "sequencer, phase 1");
        // Governance passes the role check for phase 1 but the live phase is 0.
        _revertsAs(GOV, address(c), _cancelData(0, 1, r), ClockBoundVerifier.BadContext.selector, "wrong phase");
        c.cancel(0, 0, r);
        assertTrue(c.cancelledReceipt(r), "sequencer cancels its own phase");
    }

    function test_cancel_refuses_wrong_batch_and_wrong_receipt() public {
        _reverts(address(c), _cancelData(0, 0, bytes32(uint256(7))), ClockBoundVerifier.MissingAnchor.selector, "none");
        bytes32 r = register(99_000, 100_000, 2);
        vm.warp(100 + TIMEOUT_MS / 1000);
        _reverts(address(c), _cancelData(1, 0, r), ClockBoundVerifier.BadContext.selector, "future batch");
        bytes32 wrong = bytes32(uint256(r) ^ 1);
        _reverts(address(c), _cancelData(0, 0, wrong), ClockBoundVerifier.MissingAnchor.selector, "receipt mismatch");
        c.cancel(0, 0, r);
        _reverts(address(c), _cancelData(0, 0, r), ClockBoundVerifier.MissingAnchor.selector, "already cancelled");
    }

    function test_cancel_refuses_anchor_of_settled_batch() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        settle(proof(b, r));
        vm.warp(100 + TIMEOUT_MS / 1000);
        _reverts(address(c), _cancelData(0, 0, r), ClockBoundVerifier.BadContext.selector, "batch already settled");
        assertTrue(!c.cancelledReceipt(r), "a consumed receipt is never marked cancelled");
    }

    function test_cancel_on_unbound_clock_refused() public {
        ClockBoundVerifier unbound = new ClockBoundVerifier(inner, MAX_WINDOW_MS, SKEW_MS, TIMEOUT_MS);
        vm.expectRevert(ClockBoundVerifier.InvalidConfiguration.selector);
        unbound.cancel(0, 0, bytes32(0));
    }

    // --- anchor cancel: old proofs stay dead -------------------------------------------

    function test_cancelled_receipt_never_verifies_again() public {
        bytes32 b = base();
        bytes32 r = register(0, 0, 0);
        bytes memory oldProof = proof(b, r);
        vm.warp(100 + TIMEOUT_MS / 1000);
        c.cancel(0, 0, r);
        bytes memory data = _settleData(ROOT, NEXT, oldProof);
        _reverts(address(s), data, DarkPerpSettlement.BadProof.selector, "cancelled anchor cannot settle");
        // An identical registration later is stamped later, so its receipt differs.
        bytes32 r2 = register(0, 0, 0);
        assertTrue(r2 != r, "re-registration yields a new receipt");
        assertTrue(!c.cancelledReceipt(r2), "new receipt is live");
        _reverts(address(s), data, DarkPerpSettlement.BadProof.selector, "old proof still dead");
        settle(proof(b, r2));
        assertEq(s.batchCount(), 1, "the re-registered anchor settles");
        assertEq(s.currentStateRoot(), NEXT, "root");
    }

    /// Phase 0: an unprovable registration no longer holds the batch forever.
    function test_phase0_bad_anchor_cancel_then_good_settles() public {
        bytes32 badNew = bytes32(uint256(0xdead));
        bytes32 bad = s.publicCommitment(ROOT, M, badNew, Z, Z, Z, Z);
        bytes32 rBad = c.register(0, ROOT, bad, 0, 0, 0, 0);
        bytes32 good = base();
        bytes memory replace = abi.encodeCall(c.register, (0, ROOT, good, 0, 0, 0, 0));
        _reverts(address(c), replace, ClockBoundVerifier.ReplacementForbidden.selector, "replacement before timeout");
        vm.warp(100 + TIMEOUT_MS / 1000);
        c.cancel(0, 0, rBad);
        bytes32 rGood = c.register(0, ROOT, good, 0, 0, 0, 0);
        // The cancelled commitment's bound proof cannot land either.
        bytes memory oldBad = _settleData(ROOT, badNew, proof(bad, rBad));
        _reverts(address(s), oldBad, DarkPerpSettlement.BadProof.selector, "cancelled commitment");
        settle(proof(good, rGood));
        assertEq(s.batchCount(), 1, "good batch settled");
        assertEq(s.currentStateRoot(), NEXT, "good root");
    }

    /// Phase 1: governance cancels a bad SettleAll anchor and lands the corrected one.
    function test_phase1_governance_cancels_and_final_settle_lands() public {
        (c, s) = _stack(GOV, MAX_WINDOW_MS, SKEW_MS, TIMEOUT_MS);
        // A phase-0 anchor registered before close-only is unaffected by phase-1 cancels.
        bytes32 r0 = c.register(0, ROOT, base(), 0, 0, 0, 0);
        vm.prank(GOV);
        s.enterCloseOnly();
        assertEq(uint256(c.phase()), 1, "phase 1");
        vm.roll(block.number + 10);
        bytes32 badNew = bytes32(uint256(0xbad));
        bytes32 bad = s.windDownCommitment(ROOT, M, badNew, Z, Z, Z, Z, 1);
        bytes32 good = s.windDownCommitment(ROOT, M, NEXT, Z, Z, Z, Z, 1);
        vm.prank(GOV);
        bytes32 rBad = c.register(0, ROOT, bad, 0, 0, 0, 1);
        _revertsAs(
            GOV,
            address(c),
            abi.encodeCall(c.register, (0, ROOT, good, 0, 0, 0, 1)),
            ClockBoundVerifier.ReplacementForbidden.selector,
            "phase-1 replacement before timeout"
        );
        bytes memory goodSettle = _finalSettleData(ROOT, NEXT, proof(good, rBad));
        _revertsAs(GOV, address(s), goodSettle, DarkPerpSettlement.BadProof.selector, "refused before the cancel");
        vm.warp(100 + TIMEOUT_MS / 1000);
        bytes memory data = _cancelData(0, 1, rBad);
        _reverts(address(c), data, ClockBoundVerifier.Unauthorized.selector, "sequencer cannot cancel phase 1");
        _reverts(address(c), _cancelData(0, 0, r0), ClockBoundVerifier.BadContext.selector, "phase 0 not live");
        vm.prank(GOV);
        c.cancel(0, 1, rBad);
        assertTrue(c.cancelledReceipt(rBad), "cancelled");
        assertTrue(c.anchor(0, 0).exists, "phase-0 anchor of the same batch untouched");
        vm.prank(GOV);
        bytes32 rGood = c.register(0, ROOT, good, 0, 0, 0, 1);
        assertTrue(rGood != rBad, "fresh receipt");
        bytes memory p = proof(good, rGood);
        vm.prank(GOV);
        s.finalSettle(ROOT, M, NEXT, Z, Z, Z, Z, 0, p);
        assertTrue(s.windDownSettled(), "SettleAll landed");
        assertEq(s.batchCount(), 1, "one batch");
    }

    /// Phase 2: a dead exit anchor is cancelled and the next exit batch lands.
    function test_phase2_exit_anchor_cancel_lets_the_next_exit_land() public {
        (c, s) = _stack(GOV, MAX_WINDOW_MS, SKEW_MS, TIMEOUT_MS);
        vm.roll(200);
        vm.prank(GOV);
        s.enterCloseOnly();
        vm.roll(300);
        bytes32 n1 = bytes32(uint256(5));
        bytes32 b1 = s.windDownCommitment(ROOT, M, n1, Z, Z, Z, Z, 1);
        vm.prank(GOV);
        bytes32 r1 = c.register(0, ROOT, b1, 0, 0, 0, 1);
        bytes memory p1 = proof(b1, r1);
        vm.prank(GOV);
        s.finalSettle(ROOT, M, n1, Z, Z, Z, Z, 0, p1);
        assertEq(uint256(c.phase()), 2, "phase 2");

        bytes32 badNew = bytes32(uint256(0xbad));
        bytes32 bad = s.windDownCommitment(n1, M, badNew, Z, Z, Z, Z, 2);
        vm.prank(GOV);
        bytes32 rBad = c.register(1, n1, bad, 0, 0, 0, 2);
        bytes32 n2 = bytes32(uint256(6));
        bytes32 good = s.windDownCommitment(n1, M, n2, Z, Z, Z, Z, 2);
        _revertsAs(
            GOV,
            address(c),
            abi.encodeCall(c.register, (1, n1, good, 0, 0, 0, 2)),
            ClockBoundVerifier.ReplacementForbidden.selector,
            "exit replacement before timeout"
        );
        bytes memory goodExitOld = _finalExitData(n1, n2, proof(good, rBad));
        _revertsAs(GOV, address(s), goodExitOld, DarkPerpSettlement.BadProof.selector, "exit refused before the cancel");

        vm.warp(100 + TIMEOUT_MS / 1000);
        _revertsAs(GOV, address(c), _cancelData(1, 1, rBad), ClockBoundVerifier.BadContext.selector, "phase 1 is over");
        vm.prank(GOV);
        c.cancel(1, 2, rBad);
        bytes memory badExit = _finalExitData(n1, badNew, proof(bad, rBad));
        _revertsAs(GOV, address(s), badExit, DarkPerpSettlement.BadProof.selector, "cancelled exit proof is dead");
        vm.prank(GOV);
        bytes32 rGood = c.register(1, n1, good, 0, 0, 0, 2);
        bytes memory p2 = proof(good, rGood);
        vm.prank(GOV);
        s.finalExit(n1, M, n2, Z, Z, Z, Z, 0, p2);
        assertEq(s.batchCount(), 2, "exit batch landed");
        assertEq(s.currentStateRoot(), n2, "exit root");
    }

    // --- anchor cancel: clock monotonicity --------------------------------------------

    function test_cancel_keeps_last_timed_ms_monotonic() public {
        // One-second timeout so a fresh window can still overlap the cancelled one.
        (c, s) = _stack(address(this), MAX_WINDOW_MS, SKEW_MS, 1000);
        bytes32 r = register(99_000, 100_000, 2);
        assertEq(uint256(c.lastTimedMs()), 100_000, "advanced by the registration");
        vm.warp(101);
        c.cancel(0, 0, r);
        assertEq(uint256(c.lastTimedMs()), 100_000, "not rolled back by the cancel");
        // A window starting before the cancelled one's end is still refused.
        bytes32 b = base();
        bytes memory early = abi.encodeCall(c.register, (0, ROOT, b, 99_500, 101_000, 2, 0));
        _reverts(address(c), early, ClockBoundVerifier.InvalidTime.selector, "window behind the clock");
        bytes32 r2 = register(100_000, 101_000, 2);
        assertEq(uint256(c.lastTimedMs()), 101_000, "clock moves forward only");
        settle(proof(b, r2));
        assertEq(s.batchCount(), 1, "fresh window settles");
    }

    function test_repeated_cancels_each_need_a_full_timeout() public {
        bytes32 r1 = register(0, 0, 0);
        vm.warp(100 + TIMEOUT_MS / 1000);
        c.cancel(0, 0, r1);
        bytes32 r2 = register(0, 0, 0);
        // The new anchor's own age counts, not the first one's.
        _reverts(address(c), _cancelData(0, 0, r2), ClockBoundVerifier.InvalidTime.selector, "fresh anchor");
        vm.warp(100 + 2 * (TIMEOUT_MS / 1000));
        c.cancel(0, 0, r2);
        assertTrue(c.cancelledReceipt(r1) && c.cancelledReceipt(r2), "both cancelled");
        assertTrue(r1 != r2, "distinct receipts");
    }
}
