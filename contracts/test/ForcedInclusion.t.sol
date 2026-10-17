// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {MockSequencerUptime} from "./utils/MockSequencerUptime.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {ChainlinkOracleVerifier, IChainlinkStreamsVerifier} from "../src/ChainlinkOracleVerifier.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// Cheatcodes this suite needs beyond the vendored MiniTest subset.
interface ForcedInclusionVm {
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData, address emitter) external;
}

/// Close-only triggers: a stalled root (liveness), a deposit the settled state has left
/// unconsumed for longer than the liveness window even though batches keep settling
/// (forced inclusion), and governance. Each is irreversible and opens refunds at once.
contract ForcedInclusionTest is MiniTest {
    ForcedInclusionVm internal constant vmx = ForcedInclusionVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;

    uint256 internal constant GW_PK = 0x6A7E;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    bytes32 internal constant M = bytes32("manifest");
    bytes32 internal constant Z = bytes32(0);
    uint256 internal constant LIVENESS = SettlementTestConfig.LIVENESS_BLOCKS;
    uint256 internal constant GRACE = SettlementTestConfig.FINAL_SETTLE_GRACE_BLOCKS;
    uint256 internal constant START = 1000;
    address internal constant GOV = address(0x60F);
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal anyone = address(0xCAFE);

    function setUp() public {
        vm.roll(START);
        vm.warp(1_000_000);
        DarkPerpSettlement.Config memory cfg =
            SettlementTestConfig.defaults(address(this), address(0xE), new MockClockVerifier(), GENESIS);
        cfg.governance = GOV;
        s = new DarkPerpSettlement(cfg);
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
        usdc.mint(address(this), 1_000_000e6);
        usdc.approve(address(s), 1_000_000e6);
        s.postBond(1_000_000e6);
    }

    function _commit(address who) internal pure returns (bytes32) {
        return keccak256(abi.encode("owner-commit", who));
    }

    function _deposit(address who, uint256 amount) internal returns (uint64 id) {
        usdc.mint(who, amount);
        uint64 until = uint64(block.timestamp + 3600);
        bytes32 commit = _commit(who);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, who, commit, amount, until);
        id = vault.depositCount();
        vm.startPrank(who);
        usdc.approve(address(vault), amount);
        vault.deposit(amount, commit, until, sig);
        vm.stopPrank();
    }

    /// Settles a batch that consumed the vault's first `n` deposits.
    function _settleAt(uint64 n) internal {
        uint256 id = s.batchCount();
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256(abi.encode("root", id));
        bytes32 tip = vault.depositTipAt(n);
        bytes32 c = s.publicCommitment(prev, M, next, Z, Z, Z, tip);
        s.settleBatch(prev, M, next, Z, Z, Z, tip, n, abi.encode(c));
    }

    function _expectNoTrigger() internal {
        vm.prank(anyone);
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
    }

    function _expectTrigger(string memory reason) internal {
        vmx.expectEmit(false, false, false, true, address(s));
        emit DarkPerpSettlement.CloseOnlyEntered(reason);
        vm.prank(anyone);
        s.triggerCloseOnly();
        assertTrue(s.closeOnly(), "close-only entered");
        assertEq(s.closeOnlyBlock(), block.number, "entry block latched");
    }

    // --- forced inclusion ---------------------------------------------------------

    function test_unconsumed_deposit_forces_close_only_while_batches_keep_settling() public {
        uint64 id = _deposit(alice, 7_500e6);
        uint256 landed = block.number;
        assertEq(vault.depositBlock(id), landed, "landing block recorded");

        // A live sequencer keeps settling, but never consumes the deposit.
        for (uint256 k = 1; k <= 5; k++) {
            vm.roll(landed + 20 * k);
            _settleAt(0);
            _expectNoTrigger();
        }
        assertEq(block.number, landed + LIVENESS, "at the window boundary");
        assertEq(s.batchCount(), 5, "batches kept landing");

        vm.roll(landed + LIVENESS + 1);
        assertTrue(block.number - s.lastProgressBlock() <= LIVENESS, "the root is not stalled");
        _expectTrigger("deposit inclusion timeout");
        assertEq(s.closeOnlyBatchCount(), 5, "phase-0 batch count latched");

        // The held deposit is refundable at once, by anyone, to its payer.
        vm.prank(anyone);
        vault.refundDeposit(id, alice, _commit(alice), 7_500e6, alice);
        assertEq(usdc.balanceOf(alice), 7_500e6, "refunded at principal");
    }

    function test_consuming_the_oldest_deposit_restarts_the_timer_at_the_next_one() public {
        uint256 first = block.number;
        _deposit(alice, 1_000e6);
        vm.roll(first + 40);
        uint64 second = _deposit(bob, 2_000e6);
        uint256 secondLanded = block.number;

        vm.roll(first + 60);
        _settleAt(1);
        assertEq(uint256(s.consumedDepositCount()), 1, "oldest deposit consumed");

        // Past the first deposit's deadline, but the oldest unconsumed one is younger.
        vm.roll(first + LIVENESS + 1);
        _expectNoTrigger();
        vm.roll(first + 120);
        _settleAt(1);
        vm.roll(secondLanded + LIVENESS);
        _settleAt(1);
        _expectNoTrigger();

        vm.roll(secondLanded + LIVENESS + 1);
        _expectTrigger("deposit inclusion timeout");

        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(0, alice, _commit(alice), 1_000e6, alice);
        vault.refundDeposit(second, bob, _commit(bob), 2_000e6, bob);
        assertEq(usdc.balanceOf(bob), 2_000e6, "held deposit refunded");
    }

    /// The timer follows the oldest unconsumed deposit: a newer deposit landing while
    /// batches keep settling at the old prefix does not push the deadline back.
    function test_a_newer_deposit_does_not_restart_the_timer_of_an_older_one() public {
        uint64 held = _deposit(alice, 1_000e6);
        uint256 landed = block.number;
        uint64 newer;
        for (uint256 k = 1; k <= 5; k++) {
            vm.roll(landed + 20 * k);
            if (k == 3) newer = _deposit(bob, 2_000e6);
            _settleAt(0);
            _expectNoTrigger();
        }
        assertEq(vault.depositBlock(newer), landed + 60, "the newer deposit landed later");
        assertEq(uint256(s.consumedDepositCount()), 0, "neither deposit consumed");

        vm.roll(landed + LIVENESS + 1);
        _expectTrigger("deposit inclusion timeout");
        vault.refundDeposit(held, alice, _commit(alice), 1_000e6, alice);
        vault.refundDeposit(newer, bob, _commit(bob), 2_000e6, bob);
        assertEq(usdc.balanceOf(alice), 1_000e6, "the held deposit is refunded");
        assertEq(usdc.balanceOf(bob), 2_000e6, "and so is the newer one");
    }

    function test_without_pending_deposits_only_the_liveness_path_applies() public {
        // Nothing deposited: only a stalled root can trigger.
        vm.roll(START + 30);
        _settleAt(0);
        uint256 settled = block.number;
        vm.roll(settled + LIVENESS);
        _expectNoTrigger();

        // Every deposit consumed: an old deposit block is irrelevant.
        _deposit(alice, 1_000e6);
        _settleAt(1);
        settled = block.number;
        vm.roll(settled + LIVENESS);
        _expectNoTrigger();

        vm.roll(settled + LIVENESS + 1);
        _expectTrigger("liveness timeout");
    }

    function test_stalled_root_reports_liveness_even_with_a_pending_deposit() public {
        _deposit(alice, 1_000e6);
        vm.roll(START + LIVENESS);
        _expectNoTrigger();
        vm.roll(START + LIVENESS + 1);
        _expectTrigger("liveness timeout");
    }

    /// Settles every 40 blocks at prefix 0 from the deposit block onward; the trigger
    /// succeeds exactly when the deposit is older than the liveness window.
    function testFuzz_forced_inclusion_boundary(uint16 delayRaw) public {
        uint256 delay = uint256(delayRaw) % (3 * LIVENESS);
        _deposit(alice, 1_000e6);
        uint256 landed = block.number;
        for (uint256 b = landed + 40; b <= landed + delay; b += 40) {
            vm.roll(b);
            _settleAt(0);
        }
        vm.roll(landed + delay);
        if (delay > LIVENESS) {
            _expectTrigger("deposit inclusion timeout");
        } else {
            _expectNoTrigger();
        }
    }

    // --- governance close-only ------------------------------------------------------

    function test_governance_close_only_is_restricted_irreversible_and_opens_refunds() public {
        uint64 id = _deposit(alice, 3_000e6);
        _settleAt(0);

        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.enterCloseOnly();
        vm.prank(anyone);
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.enterCloseOnly();
        assertFalse(s.closeOnly(), "still live");

        vmx.expectEmit(false, false, false, true, address(s));
        emit DarkPerpSettlement.CloseOnlyEntered("governance");
        vm.prank(GOV);
        s.enterCloseOnly();
        uint256 entered = block.number;
        assertTrue(s.closeOnly(), "close-only");
        assertEq(s.closeOnlyBlock(), entered, "entry block");
        assertEq(s.closeOnlyBatchCount(), 1, "phase-0 batches latched");
        assertFalse(s.acceptingDeposits(), "deposits closed");

        // Refunds are open in the same block.
        vault.refundDeposit(id, alice, _commit(alice), 3_000e6, alice);
        assertEq(usdc.balanceOf(alice), 3_000e6, "refunded immediately");

        // Re-entry is a no-op: nothing is re-latched.
        vm.roll(entered + 5);
        vm.prank(GOV);
        s.enterCloseOnly();
        vm.prank(anyone);
        s.triggerCloseOnly();
        assertEq(s.closeOnlyBlock(), entered, "entry block unchanged");

        // Nothing reopens the ordinary path, deposits or challenges.
        bytes32 prev = s.currentStateRoot();
        bytes32 c = s.publicCommitment(prev, M, bytes32(uint256(9)), Z, Z, Z, Z);
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.settleBatch(prev, M, bytes32(uint256(9)), Z, Z, Z, Z, 0, abi.encode(c));
        vm.expectRevert(CollateralVault.InCloseOnly.selector);
        vault.deposit(1, _commit(bob), uint64(block.timestamp), hex"");
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.challengeInclusion(keccak256("order"), 1, 1000, 0, alice, hex"");

        // Not even a completed wind-down.
        vm.roll(entered + GRACE);
        bytes32 wd = s.windDownCommitment(prev, M, keccak256("wd"), Z, Z, Z, vault.depositTipAt(0), 1);
        vm.prank(GOV);
        s.finalSettle(prev, M, keccak256("wd"), Z, Z, Z, Z, 0, abi.encode(wd));
        assertTrue(s.closeOnly(), "close-only survives wind-down");
        assertFalse(s.acceptingDeposits(), "deposits stay closed");
    }

    function test_trigger_is_a_noop_once_close_only() public {
        vm.prank(GOV);
        s.enterCloseOnly();
        uint256 entered = block.number;
        vm.roll(entered + 10 * LIVENESS);
        vm.prank(anyone);
        s.triggerCloseOnly();
        assertEq(s.closeOnlyBlock(), entered, "first entry wins");
    }
}

/// A clock anchor that can never be proven does not hold its batch: once it is
/// `anchorTimeoutMs` old, the role that registered it cancels it and a fresh
/// registration settles. The receipt of a cancelled anchor never verifies again.
contract ClockAnchorRecoveryTest is MiniTest {
    ForcedInclusionVm internal constant vmx = ForcedInclusionVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    ClockBoundVerifier internal clock;
    DarkPerpSettlement internal s;

    bytes32 internal constant ROOT = bytes32(uint256(1));
    bytes32 internal constant NEXT = bytes32(uint256(2));
    bytes32 internal constant M = bytes32(uint256(3));
    bytes32 internal constant Z = bytes32(0);
    uint64 internal constant TIMEOUT_MS = 3_600_000;
    uint256 internal constant T0 = 100;
    uint256 internal constant GRACE = SettlementTestConfig.FINAL_SETTLE_GRACE_BLOCKS;
    address internal constant GOV = address(0x60F);
    bytes32 internal constant CLOCK_DOMAIN = keccak256("arcora:clock-bound-proof:v2");

    function setUp() public {
        vm.warp(T0);
        vm.roll(1);
        (clock, s) = _stack(2_000);
        assertEq(clock.DOMAIN(), CLOCK_DOMAIN, "clock proof domain");
        assertEq(uint256(clock.anchorTimeoutMs()), TIMEOUT_MS, "anchor timeout");
    }

    function _stack(uint64 skewMs) internal returns (ClockBoundVerifier c, DarkPerpSettlement st) {
        c = new ClockBoundVerifier(new MockZkVerifier(), 10_000, skewMs, TIMEOUT_MS);
        DarkPerpSettlement.Config memory cfg = SettlementTestConfig.defaults(address(this), address(0x123), c, ROOT);
        cfg.governance = GOV;
        st = new DarkPerpSettlement(cfg);
        c.bindSettlement(IClockSettlement(address(st)));
    }

    /// The bound proof MockZkVerifier accepts behind the clock. Computed locally (no
    /// external call), so it is safe as an argument after `vm.prank`/`vm.expectRevert`.
    function _bound(bytes32 base, bytes32 receipt) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(CLOCK_DOMAIN, base, receipt)));
    }

    function _base(bytes32 next) internal view returns (bytes32) {
        return s.publicCommitment(ROOT, M, next, Z, Z, Z, Z);
    }

    function _settleFails(bytes32 next, bytes memory proof) internal {
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(ROOT, M, next, Z, Z, Z, Z, 0, proof);
    }

    function _toCloseOnlyAfterGrace() internal {
        vm.prank(GOV);
        s.enterCloseOnly();
        vm.roll(block.number + GRACE);
    }

    function test_unprovable_phase0_anchor_is_cancelled_after_timeout_and_a_fresh_batch_settles() public {
        bytes32 unprovable = _base(bytes32(uint256(0xdead)));
        bytes32 stuck = clock.register(0, ROOT, unprovable, 0, 0, 0, 0);
        bytes32 good = _base(NEXT);

        // Before the timeout the anchor is immutable and blocks every other batch 0.
        vm.expectRevert(ClockBoundVerifier.ReplacementForbidden.selector);
        clock.register(0, ROOT, good, 0, 0, 0, 0);
        _settleFails(NEXT, _bound(good, bytes32(0)));
        vm.warp(T0 + TIMEOUT_MS / 1000 - 1);
        vm.expectRevert(ClockBoundVerifier.InvalidTime.selector);
        clock.cancel(0, 0, stuck);

        vm.warp(T0 + TIMEOUT_MS / 1000);
        // Only the phase-0 registrant, only for the live batch and phase, only this receipt.
        vm.prank(GOV);
        vm.expectRevert(ClockBoundVerifier.Unauthorized.selector);
        clock.cancel(0, 0, stuck);
        vm.prank(address(0xBAD));
        vm.expectRevert(ClockBoundVerifier.Unauthorized.selector);
        clock.cancel(0, 0, stuck);
        vm.expectRevert(ClockBoundVerifier.MissingAnchor.selector);
        clock.cancel(0, 0, keccak256("other receipt"));
        vm.expectRevert(ClockBoundVerifier.BadContext.selector);
        clock.cancel(1, 0, stuck);
        vm.prank(GOV);
        vm.expectRevert(ClockBoundVerifier.BadContext.selector);
        clock.cancel(0, 1, stuck);

        vmx.expectEmit(true, true, false, true, address(clock));
        emit ClockBoundVerifier.ClockCancelled(0, 0, stuck);
        clock.cancel(0, 0, stuck);
        assertTrue(clock.cancelledReceipt(stuck), "receipt recorded as cancelled");
        assertFalse(clock.anchor(0, 0).exists, "anchor removed");
        vm.expectRevert(ClockBoundVerifier.MissingAnchor.selector);
        clock.cancel(0, 0, stuck);

        // The old bound proof no longer verifies; a fresh registration settles batch 0.
        _settleFails(bytes32(uint256(0xdead)), _bound(unprovable, stuck));
        bytes32 fresh = clock.register(0, ROOT, good, 0, 0, 0, 0);
        s.settleBatch(ROOT, M, NEXT, Z, Z, Z, Z, 0, _bound(good, fresh));
        assertEq(s.batchCount(), 1, "batch 0 settled");
        assertEq(s.currentStateRoot(), NEXT, "root advanced");
        assertFalse(s.closeOnly(), "no forced wind-down");
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
    }

    function test_cancelled_receipt_never_verifies_again_even_for_the_same_commitment() public {
        bytes32 base = _base(NEXT);
        bytes32 first = clock.register(0, ROOT, base, 0, 0, 0, 0);
        vm.warp(T0 + TIMEOUT_MS / 1000);
        clock.cancel(0, 0, first);

        bytes32 second = clock.register(0, ROOT, base, 0, 0, 0, 0);
        assertTrue(second != first, "re-registration is stamped later");
        _settleFails(NEXT, _bound(base, first));
        s.settleBatch(ROOT, M, NEXT, Z, Z, Z, Z, 0, _bound(base, second));
        assertEq(s.batchCount(), 1, "settled with the fresh receipt");
    }

    function test_last_timed_ms_is_not_rolled_back_by_cancel() public {
        // A wide skew, so only the monotonic clock rule can refuse the replacement window.
        (ClockBoundVerifier wide, DarkPerpSettlement st) = _stack(10_000_000);
        bytes32 base = st.publicCommitment(ROOT, M, NEXT, Z, Z, Z, Z);
        bytes32 r = wide.register(0, ROOT, base, 100_000, 100_000, 1, 0);
        assertEq(uint256(wide.lastTimedMs()), 100_000, "clock advanced");

        vm.warp(T0 + TIMEOUT_MS / 1000);
        wide.cancel(0, 0, r);
        assertEq(uint256(wide.lastTimedMs()), 100_000, "clock not restored");
        vm.expectRevert(ClockBoundVerifier.InvalidTime.selector);
        wide.register(0, ROOT, base, 99_999, 99_999, 1, 0);
        wide.register(0, ROOT, base, 100_000, 100_000, 1, 0);
        assertTrue(wide.anchor(0, 0).exists, "a non-regressing window registers");
    }

    function test_unprovable_wind_down_anchor_is_cancelled_by_governance_and_settles() public {
        _toCloseOnlyAfterGrace();
        bytes32 n1 = bytes32(uint256(5));
        bytes32 bad = s.windDownCommitment(ROOT, M, bytes32(uint256(0xbad)), Z, Z, Z, Z, 1);
        vm.prank(GOV);
        bytes32 stuck = clock.register(0, ROOT, bad, 0, 0, 0, 1);

        vm.warp(T0 + TIMEOUT_MS / 1000);
        vm.expectRevert(ClockBoundVerifier.Unauthorized.selector);
        clock.cancel(0, 1, stuck);
        vm.prank(GOV);
        clock.cancel(0, 1, stuck);

        bytes32 good = s.windDownCommitment(ROOT, M, n1, Z, Z, Z, Z, 1);
        vm.prank(GOV);
        bytes32 fresh = clock.register(0, ROOT, good, 0, 0, 0, 1);
        vm.prank(GOV);
        s.finalSettle(ROOT, M, n1, Z, Z, Z, Z, 0, _bound(good, fresh));
        assertTrue(s.windDownSettled(), "wind-down settled after the cancel");
    }

    function test_unprovable_exit_anchor_is_cancelled_and_exits_resume() public {
        _toCloseOnlyAfterGrace();
        bytes32 n1 = bytes32(uint256(5));
        bytes32 b1 = s.windDownCommitment(ROOT, M, n1, Z, Z, Z, Z, 1);
        vm.prank(GOV);
        bytes32 r1 = clock.register(0, ROOT, b1, 0, 0, 0, 1);
        vm.prank(GOV);
        s.finalSettle(ROOT, M, n1, Z, Z, Z, Z, 0, _bound(b1, r1));

        // An exit batch whose proof never materialises.
        uint256 registeredAt = block.timestamp;
        bytes32 bad = s.windDownCommitment(n1, M, bytes32(uint256(0xbad)), Z, Z, Z, Z, 2);
        vm.prank(GOV);
        bytes32 stuck = clock.register(1, n1, bad, 0, 0, 0, 2);
        bytes32 n2 = bytes32(uint256(6));
        bytes32 good = s.windDownCommitment(n1, M, n2, Z, Z, Z, Z, 2);
        vm.prank(GOV);
        vm.expectRevert(ClockBoundVerifier.ReplacementForbidden.selector);
        clock.register(1, n1, good, 0, 0, 0, 2);

        vm.warp(registeredAt + TIMEOUT_MS / 1000);
        vm.prank(GOV);
        clock.cancel(1, 2, stuck);
        vm.prank(GOV);
        bytes32 fresh = clock.register(1, n1, good, 0, 0, 0, 2);
        vm.prank(GOV);
        s.finalExit(n1, M, n2, Z, Z, Z, Z, 0, _bound(good, fresh));
        assertEq(s.batchCount(), 2, "exit batch landed");
        assertEq(s.currentStateRoot(), n2, "exit root");

        // Exits stay repeatable afterwards.
        bytes32 n3 = bytes32(uint256(7));
        bytes32 next = s.windDownCommitment(n2, M, n3, Z, Z, Z, Z, 2);
        vm.prank(GOV);
        bytes32 r3 = clock.register(2, n2, next, 0, 0, 0, 2);
        vm.prank(GOV);
        s.finalExit(n2, M, n3, Z, Z, Z, Z, 0, _bound(next, r3));
        assertEq(s.batchCount(), 3, "second exit landed");
    }
}

/// Test-only DON double: returns a pre-registered body for an exact full report.
contract AnchorRecoveryStreams is IChainlinkStreamsVerifier {
    mapping(bytes32 => bytes) internal bodies;

    function allow(bytes memory full, bytes memory body) external {
        bodies[keccak256(full)] = body;
    }

    function verify(bytes calldata full, bytes calldata) external payable returns (bytes memory) {
        bytes memory body = bodies[keccak256(full)];
        require(body.length != 0, "unknown report");
        return body;
    }
}

/// The oracle-bound route: a sequencer status change between registration and settle
/// makes the registered reports unusable. The anchor is cancelled after the timeout and
/// re-registered with fresh reports, and batch 0 settles; the old record never verifies again.
contract OracleAnchorRecoveryTest is MiniTest {
    ChainlinkOracleVerifier internal o;
    ClockBoundVerifier internal c;
    DarkPerpSettlement internal s;
    AnchorRecoveryStreams internal don;
    MockSequencerUptime internal uptime;

    bytes32 internal constant R = bytes32(uint256(1));
    bytes32 internal constant N = bytes32(uint256(2));
    bytes32 internal constant M = bytes32(uint256(3));
    bytes32 internal constant Z = bytes32(0);
    bytes32 internal constant PH = keccak256("policy");
    uint64 internal constant TIMEOUT_MS = 3_600_000;

    function setUp() public {
        vm.chainId(84532);
        vm.warp(100);
        vm.roll(1);
        don = new AnchorRecoveryStreams();
        uptime = new MockSequencerUptime(); // healthy since t=1, round 1
        o = new ChainlinkOracleVerifier(new MockZkVerifier(), don, PH, address(uptime), 10);
        c = new ClockBoundVerifier(o, 10_000, 2_000, TIMEOUT_MS);
        DarkPerpSettlement.Config memory cfg = SettlementTestConfig.defaults(address(this), address(0x123), c, R);
        s = new DarkPerpSettlement(cfg);
        c.bindSettlement(IClockSettlement(address(s)));
        o.bindClock(c);
    }

    function _feed(uint8 n) internal pure returns (bytes32) {
        return (bytes32(uint256(n) * (type(uint256).max / 255)) & bytes32(type(uint256).max >> 16))
            | bytes32(uint256(3) << 240);
    }

    function _body(bool quote, uint32 validFrom, uint32 observed, uint32 expires) internal pure returns (bytes memory) {
        return abi.encode(
            _feed(quote ? 2 : 1),
            validFrom,
            observed,
            uint192(0),
            uint192(0),
            expires,
            quote ? int192(1e8) : int192(60_000e8),
            quote ? int192(1e8) : int192(59_999e8),
            quote ? int192(1e8) : int192(60_001e8)
        );
    }

    function _full(bytes memory body) internal pure returns (bytes memory) {
        bytes32[3] memory ctx;
        return abi.encode(ctx, body, new bytes32[](1), new bytes32[](1), bytes32(0));
    }

    /// One entry at `nowMs` with reports valid over [validFrom, expires] seconds.
    function _entries(uint64 nowMs, uint32 validFrom, uint32 expires)
        internal
        returns (ChainlinkOracleVerifier.Entry[] memory e)
    {
        bytes memory b = _body(false, validFrom, validFrom, expires);
        bytes memory q = _body(true, validFrom, validFrom, expires);
        don.allow(_full(b), b);
        don.allow(_full(q), q);
        e = new ChainlinkOracleVerifier.Entry[](1);
        e[0] = ChainlinkOracleVerifier.Entry(0, nowMs, _full(b), _full(q));
    }

    function _registerProof(bytes32 base, uint64 atMs, uint32 validFrom, uint32 expires)
        internal
        returns (bytes32 receipt, bytes memory proof)
    {
        receipt = c.register(0, R, base, atMs, atMs, 1, 0);
        bytes32 cb = keccak256(abi.encode(c.DOMAIN(), base, receipt));
        bytes32 h = o.register(0, 0, _entries(atMs, validFrom, expires));
        proof = abi.encodePacked(o.boundCommitment(cb, h));
    }

    function test_sequencer_status_change_is_recovered_by_cancel_and_fresh_reports() public {
        bytes32 base = s.publicCommitment(R, M, N, Z, Z, Z, Z);
        (bytes32 receipt, bytes memory oldProof) = _registerProof(base, 100_000, 100, 160);

        // The sequencer status blips (down at 105, up at 106) before the settle lands.
        uptime.set(2, 1, 105);
        uptime.set(3, 0, 106);
        vm.warp(10_000);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(R, M, N, Z, Z, Z, Z, 0, oldProof);

        // Past the anchor timeout the sequencer cancels the anchor ...
        c.cancel(0, 0, receipt);
        assertTrue(c.cancelledReceipt(receipt), "cancelled");
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(R, M, N, Z, Z, Z, Z, 0, oldProof);

        // ... and registers the same transition again with fresh reports in the new epoch.
        (bytes32 fresh, bytes memory newProof) = _registerProof(base, 10_000_000, 9_990, 10_060);
        assertTrue(fresh != receipt, "fresh receipt");
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(R, M, N, Z, Z, Z, Z, 0, oldProof);
        s.settleBatch(R, M, N, Z, Z, Z, Z, 0, newProof);
        assertEq(s.batchCount(), 1, "batch 0 settled");
        assertFalse(s.closeOnly(), "no forced wind-down");
    }
}
