// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// Cheatcodes this suite needs beyond the vendored MiniTest subset.
interface DepositRefundVm {
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData, address emitter) external;
}

/// End-to-end refund path for vault deposits the settled state never consumed. The
/// settlement records the consumed deposit count on every settle path and freezes it in
/// close-only; the vault then refunds every deposit at or above it, at principal, to the
/// payer bound in the deposit leaf.
contract DepositRefundTest is MiniTest {
    DepositRefundVm internal constant vmx = DepositRefundVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockClockVerifier internal zk;

    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    uint256 internal constant GW_PK = 0x6A7E;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    bytes32 internal constant M = bytes32("manifest");
    bytes32 internal constant Z = bytes32(0);
    uint256 internal constant LIVENESS = SettlementTestConfig.LIVENESS_BLOCKS;
    uint256 internal constant GRACE = SettlementTestConfig.FINAL_SETTLE_GRACE_BLOCKS;
    uint256 internal constant BOND = 1_000_000e6;
    uint256 internal constant PERMIT_TTL = 3600;

    address internal constant GOV = address(0x60F);
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal carol = address(0xCA201);
    address internal anyone = address(0xCAFE);

    function setUp() public {
        vm.roll(1000);
        vm.warp(1_000_000);
        zk = new MockClockVerifier();
        DarkPerpSettlement.Config memory cfg =
            SettlementTestConfig.defaults(address(this), vm.addr(ENCLAVE_PK), zk, GENESIS);
        cfg.governance = GOV;
        s = new DarkPerpSettlement(cfg);
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
        _bond(BOND);
    }

    // --- helpers ---------------------------------------------------------------

    function _bond(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    function _commit(address who, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode("owner-commit", who, salt));
    }

    /// `who` deposits `amount` for `commit` with a fresh gateway permit; returns the id.
    function _deposit(address who, uint256 amount, bytes32 commit) internal returns (uint64 id) {
        usdc.mint(who, amount);
        uint64 until = uint64(block.timestamp + PERMIT_TTL);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, who, commit, amount, until);
        id = vault.depositCount();
        vm.startPrank(who);
        usdc.approve(address(vault), amount);
        vault.deposit(amount, commit, until, sig);
        vm.stopPrank();
    }

    /// Settles one ordinary batch that consumed the vault's first `n` deposits and
    /// publishes `withdrawalsRoot`.
    function _settleAt(uint64 n, bytes32 withdrawalsRoot) internal returns (uint256 id) {
        id = s.batchCount();
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256(abi.encode("root", id));
        bytes32 tip = vault.depositTipAt(n);
        bytes32 c = s.publicCommitment(prev, M, next, Z, withdrawalsRoot, Z, tip);
        s.settleBatch(prev, M, next, Z, withdrawalsRoot, Z, tip, n, abi.encode(c));
    }

    function _closeByLiveness() internal {
        vm.roll(block.number + LIVENESS + 1);
        vm.prank(anyone);
        s.triggerCloseOnly();
        assertTrue(s.closeOnly(), "close-only entered");
    }

    function _closeByGovernance() internal {
        vm.prank(GOV);
        s.enterCloseOnly();
        assertTrue(s.closeOnly(), "close-only entered");
    }

    function _windDown(uint64 n) internal {
        vm.roll(s.closeOnlyBlock() + GRACE);
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256("wind-down");
        bytes32 tip = vault.depositTipAt(n);
        bytes32 c = s.windDownCommitment(prev, M, next, Z, Z, Z, tip, 1);
        vm.prank(GOV);
        s.finalSettle(prev, M, next, Z, Z, Z, tip, n, abi.encode(c));
    }

    function _leaf(address to, uint256 amount, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(to, amount, nonce));
    }

    function _pair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _one(bytes32 x) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](1);
        p[0] = x;
    }

    // --- deposits land after liveness expiry; refunds open in close-only --------

    function test_deposit_after_liveness_expiry_still_lands_and_settles() public {
        vm.roll(block.number + LIVENESS + 1);
        uint64 id = _deposit(alice, 2_000e6, _commit(alice, 1));
        assertEq(uint256(id), 0, "first deposit id");
        assertEq(uint256(vault.depositCount()), 1, "deposit landed after liveness expiry");

        // Nobody triggered close-only, so the next settle still lands and credits it.
        _settleAt(1, Z);
        assertEq(uint256(s.consumedDepositCount()), 1, "deposit consumed");
        assertFalse(s.closeOnly(), "still live");

        // The settle restarted the liveness clock and nothing is pending.
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
    }

    function test_unconsumed_deposits_refund_at_principal_after_close_only() public {
        bytes32 aliceCommit = _commit(alice, 1);
        bytes32 bobCommit = _commit(bob, 1);
        // The in-flight proof was built at prefix 0, so the next settle credits nothing.
        _deposit(alice, 10_000e6, aliceCommit);
        _settleAt(0, Z);

        // The prover stalls past the liveness timeout; a further deposit still lands.
        vm.roll(block.number + LIVENESS + 1);
        _deposit(bob, 5_000e6, bobCommit);
        assertEq(uint256(vault.depositCount()), 2, "two deposits in the chain");

        vm.prank(anyone);
        s.triggerCloseOnly();
        assertTrue(s.closeOnly(), "close-only");
        assertEq(uint256(s.consumedDepositCount()), 0, "nothing consumed");

        // The ordinary settle path stays closed.
        bytes32 tip2 = vault.depositTipAt(2);
        bytes32 c1 = s.publicCommitment(s.currentStateRoot(), M, bytes32(uint256(3)), Z, Z, Z, tip2);
        bytes32 prev = s.currentStateRoot();
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.settleBatch(prev, M, bytes32(uint256(3)), Z, Z, Z, tip2, 2, abi.encode(c1));

        assertEq(usdc.balanceOf(address(vault)), 15_000e6, "funds held");
        assertEq(vault.tvl(), 15_000e6, "tvl before refunds");
        assertEq(vault.refundableOutstanding(), 15_000e6, "both deposits refundable");

        // Anyone may push the refund; it is paid to the payer bound in the leaf.
        vmx.expectEmit(true, true, false, true, address(vault));
        emit CollateralVault.DepositRefunded(0, alice, alice, 10_000e6);
        vm.prank(anyone);
        vault.refundDeposit(0, alice, aliceCommit, 10_000e6, alice);
        assertEq(usdc.balanceOf(alice), 10_000e6, "alice repaid at principal");
        assertEq(usdc.balanceOf(address(vault)), 5_000e6, "vault balance dropped by the refund");
        assertEq(vault.tvl(), 5_000e6, "tvl dropped by the refund");
        assertEq(vault.totalRefunded(), 10_000e6, "refund accounted");
        assertTrue(vault.depositRefunded(0), "id marked");

        vm.prank(bob);
        vault.refundDeposit(1, bob, bobCommit, 5_000e6, bob);
        assertEq(usdc.balanceOf(bob), 5_000e6, "bob repaid at principal");
        assertEq(usdc.balanceOf(address(vault)), 0, "vault emptied");
        assertEq(vault.tvl(), 0, "tvl zero");
        assertEq(vault.refundableOutstanding(), 0, "nothing outstanding");
    }

    function test_deposit_in_close_only_reverts_and_earlier_deposit_is_refundable() public {
        bytes32 commit = _commit(alice, 1);
        _deposit(alice, 100e6, commit);
        _closeByLiveness();

        bytes32 commit2 = _commit(alice, 2);
        usdc.mint(alice, 100e6);
        uint64 until = uint64(block.timestamp + PERMIT_TTL);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, alice, commit2, 100e6, until);
        vm.startPrank(alice);
        usdc.approve(address(vault), 100e6);
        vm.expectRevert(CollateralVault.InCloseOnly.selector);
        vault.deposit(100e6, commit2, until, sig);
        // The deposit that landed before close-only is still refundable.
        vault.refundDeposit(0, alice, commit, 100e6, alice);
        vm.stopPrank();
        assertEq(usdc.balanceOf(alice), 200e6, "principal returned, second deposit never taken");
    }

    function test_settled_prefix_is_not_refundable_but_later_ids_are() public {
        bytes32 aliceCommit = _commit(alice, 1);
        bytes32 bobCommit = _commit(bob, 1);
        _deposit(alice, 1_000e6, aliceCommit);
        _deposit(bob, 700e6, bobCommit);
        _settleAt(1, Z);
        assertEq(uint256(s.consumedDepositCount()), 1, "id 0 consumed");
        _closeByGovernance();

        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(0, alice, aliceCommit, 1_000e6, alice);

        vault.refundDeposit(1, bob, bobCommit, 700e6, bob);
        assertEq(usdc.balanceOf(bob), 700e6, "unconsumed deposit refunded");
        assertEq(usdc.balanceOf(address(vault)), 1_000e6, "consumed principal stays for withdrawals");
        assertEq(vault.tvl(), 1_000e6, "tvl keeps the credited deposit");
    }

    // --- refund guards -----------------------------------------------------------

    function test_refund_rejects_a_second_refund_of_the_same_id() public {
        bytes32 commit = _commit(alice, 1);
        _deposit(alice, 1_000e6, commit);
        _closeByGovernance();
        vault.refundDeposit(0, alice, commit, 1_000e6, alice);
        vm.expectRevert(CollateralVault.AlreadyRefunded.selector);
        vault.refundDeposit(0, alice, commit, 1_000e6, alice);
        assertEq(usdc.balanceOf(alice), 1_000e6, "paid once");
    }

    function test_refund_rejects_any_preimage_other_than_the_leaf() public {
        bytes32 aliceCommit = _commit(alice, 1);
        bytes32 bobCommit = _commit(bob, 1);
        _deposit(alice, 1_000e6, aliceCommit);
        _deposit(bob, 1_000e6, bobCommit);
        _closeByGovernance();

        // wrong payer (paid to that payer, so the recipient rule passes)
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, carol, aliceCommit, 1_000e6, carol);
        // wrong owner commit
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, alice, bobCommit, 1_000e6, alice);
        // wrong amount, both directions
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, alice, aliceCommit, 1_000e6 + 1, alice);
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, alice, aliceCommit, 1_000e6 - 1, alice);
        // a valid leaf presented at another id
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(1, alice, aliceCommit, 1_000e6, alice);
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, bob, bobCommit, 1_000e6, bob);

        assertEq(vault.totalRefunded(), 0, "nothing refunded");
        assertEq(usdc.balanceOf(address(vault)), 2_000e6, "nothing moved");
    }

    function test_refund_requires_close_only() public {
        bytes32 commit = _commit(alice, 1);
        _deposit(alice, 1_000e6, commit);
        vm.expectRevert(CollateralVault.NotCloseOnly.selector);
        vault.refundDeposit(0, alice, commit, 1_000e6, alice);

        // Still refused right up to the liveness boundary.
        vm.roll(block.number + LIVENESS);
        vm.expectRevert(CollateralVault.NotCloseOnly.selector);
        vault.refundDeposit(0, alice, commit, 1_000e6, alice);
    }

    function test_refund_rejects_an_id_beyond_the_chain() public {
        bytes32 commit = _commit(alice, 1);
        _deposit(alice, 1_000e6, commit);
        _closeByGovernance();
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(1, alice, commit, 1_000e6, alice);
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(type(uint64).max, alice, commit, 1_000e6, alice);
    }

    function test_refund_recipient_rules() public {
        bytes32 aliceCommit = _commit(alice, 1);
        bytes32 bobCommit = _commit(bob, 1);
        _deposit(alice, 1_000e6, aliceCommit);
        _deposit(bob, 300e6, bobCommit);
        _closeByGovernance();

        // A third party cannot redirect the refund.
        vm.prank(anyone);
        vm.expectRevert(CollateralVault.BadRefundRecipient.selector);
        vault.refundDeposit(0, alice, aliceCommit, 1_000e6, anyone);
        // Nobody can send it to the zero address, not even the payer.
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadRefundRecipient.selector);
        vault.refundDeposit(0, alice, aliceCommit, 1_000e6, address(0));

        // The payer may redirect its own refund.
        vmx.expectEmit(true, true, false, true, address(vault));
        emit CollateralVault.DepositRefunded(0, alice, carol, 1_000e6);
        vm.prank(alice);
        vault.refundDeposit(0, alice, aliceCommit, 1_000e6, carol);
        assertEq(usdc.balanceOf(carol), 1_000e6, "redirected by the payer");
        assertEq(usdc.balanceOf(alice), 0, "payer chose another recipient");

        // A third party may push a refund to the payer itself.
        vm.prank(anyone);
        vault.refundDeposit(1, bob, bobCommit, 300e6, bob);
        assertEq(usdc.balanceOf(bob), 300e6, "pushed to the payer");
        assertEq(usdc.balanceOf(anyone), 0, "pusher gains nothing");
    }

    // --- the consumed count: pinned on L1, frozen in wind-down -------------------

    function test_wind_down_cannot_move_the_consumed_count() public {
        bytes32 bobCommit = _commit(bob, 1);
        _deposit(alice, 1_000e6, _commit(alice, 1));
        _deposit(bob, 400e6, bobCommit);
        _settleAt(1, Z);
        _closeByGovernance();
        vm.roll(s.closeOnlyBlock() + GRACE);

        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256("wind-down");
        // Crediting the pending deposit in wind-down is refused...
        bytes32 tip2 = vault.depositTipAt(2);
        bytes32 c2 = s.windDownCommitment(prev, M, next, Z, Z, Z, tip2, 1);
        vm.prank(GOV);
        vm.expectRevert(DarkPerpSettlement.DepositsFrozen.selector);
        s.finalSettle(prev, M, next, Z, Z, Z, tip2, 2, abi.encode(c2));
        // ...and so is rolling the count back.
        bytes32 c0 = s.windDownCommitment(prev, M, next, Z, Z, Z, Z, 1);
        vm.prank(GOV);
        vm.expectRevert(DarkPerpSettlement.DepositsFrozen.selector);
        s.finalSettle(prev, M, next, Z, Z, Z, Z, 0, abi.encode(c0));

        _windDown(1);
        assertTrue(s.windDownSettled(), "wind-down landed at the frozen count");
        assertEq(uint256(s.consumedDepositCount()), 1, "count unchanged by finalSettle");

        // Exit batches are held to the same count.
        prev = s.currentStateRoot();
        bytes32 exitRoot = keccak256("exit");
        bytes32 tip1 = vault.depositTipAt(1);
        bytes32 e2 = s.windDownCommitment(prev, M, exitRoot, Z, Z, Z, tip2, 2);
        vm.prank(GOV);
        vm.expectRevert(DarkPerpSettlement.DepositsFrozen.selector);
        s.finalExit(prev, M, exitRoot, Z, Z, Z, tip2, 2, abi.encode(e2));
        bytes32 e1 = s.windDownCommitment(prev, M, exitRoot, Z, Z, Z, tip1, 2);
        vm.prank(GOV);
        s.finalExit(prev, M, exitRoot, Z, Z, Z, tip1, 1, abi.encode(e1));
        assertEq(uint256(s.consumedDepositCount()), 1, "count unchanged by finalExit");
        assertEq(s.batchCount(), 3, "settle, wind-down and exit recorded");

        // The pending deposit is still refundable after the whole wind-down.
        vault.refundDeposit(1, bob, bobCommit, 400e6, bob);
        assertEq(usdc.balanceOf(bob), 400e6, "refunded after wind-down");
    }

    function test_settle_rejects_counts_outside_the_vault_chain() public {
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256("next");
        // Empty chain: a zero root with a non-zero count is refused (the tip beyond the
        // head reads as zero, so the count bound is what catches it).
        bytes32 c = s.publicCommitment(prev, M, next, Z, Z, Z, Z);
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        s.settleBatch(prev, M, next, Z, Z, Z, Z, 5, abi.encode(c));

        _deposit(alice, 100e6, _commit(alice, 1));
        _deposit(bob, 100e6, _commit(bob, 1));
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        s.settleBatch(prev, M, next, Z, Z, Z, Z, 3, abi.encode(c));

        // A count inside the chain must come with that prefix's tip.
        bytes32 tip1 = vault.depositTipAt(1);
        bytes32 cWrong = s.publicCommitment(prev, M, next, Z, Z, Z, tip1);
        vm.expectRevert(bytes("deposits: root != L1 chain prefix"));
        s.settleBatch(prev, M, next, Z, Z, Z, tip1, 2, abi.encode(cWrong));

        _settleAt(2, Z);
        assertEq(uint256(s.consumedDepositCount()), 2, "two consumed");

        // The count can never go back.
        prev = s.currentStateRoot();
        bytes32 cBack = s.publicCommitment(prev, M, next, Z, Z, Z, tip1);
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        s.settleBatch(prev, M, next, Z, Z, Z, tip1, 1, abi.encode(cBack));
        bytes32 cZero = s.publicCommitment(prev, M, next, Z, Z, Z, Z);
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        s.settleBatch(prev, M, next, Z, Z, Z, Z, 0, abi.encode(cZero));

        // Re-settling at the same count is fine (nothing new credited).
        _settleAt(2, Z);
        assertEq(uint256(s.consumedDepositCount()), 2, "same count accepted");
    }

    function test_every_settle_path_records_the_consumed_count() public {
        _deposit(alice, 100e6, _commit(alice, 1));
        _deposit(bob, 100e6, _commit(bob, 1));
        _deposit(carol, 100e6, _commit(carol, 1));
        assertEq(uint256(s.consumedDepositCount()), 0, "starts at zero");
        _settleAt(1, Z);
        assertEq(uint256(s.consumedDepositCount()), 1, "settleBatch stores 1");
        _settleAt(3, Z);
        assertEq(uint256(s.consumedDepositCount()), 3, "settleBatch stores 3");

        _closeByGovernance();
        _windDown(3);
        assertEq(uint256(s.consumedDepositCount()), 3, "finalSettle stores the frozen count");

        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256("exit");
        bytes32 tip3 = vault.depositTipAt(3);
        bytes32 e = s.windDownCommitment(prev, M, next, Z, Z, Z, tip3, 2);
        vm.prank(GOV);
        s.finalExit(prev, M, next, Z, Z, Z, tip3, 3, abi.encode(e));
        assertEq(uint256(s.consumedDepositCount()), 3, "finalExit stores the frozen count");

        // Everything was consumed, so nothing is refundable.
        assertEq(vault.refundableOutstanding(), 0, "nothing outstanding");
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(2, carol, _commit(carol, 1), 100e6, carol);
    }

    // --- permits ---------------------------------------------------------------

    function test_expired_permit_is_refused_and_deadline_is_inclusive() public {
        bytes32 commit = _commit(alice, 1);
        uint64 until = uint64(block.timestamp + 60);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, alice, commit, 500e6, until);
        usdc.mint(alice, 500e6);
        vm.prank(alice);
        usdc.approve(address(vault), 500e6);

        vm.warp(uint256(until) + 1);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.PermitExpired.selector);
        vault.deposit(500e6, commit, until, sig);

        vm.warp(until);
        vm.prank(alice);
        vault.deposit(500e6, commit, until, sig);
        assertEq(uint256(vault.depositCount()), 1, "accepted at the deadline itself");
    }

    function test_owner_commit_enters_the_chain_once_whatever_the_deadline() public {
        bytes32 commit = _commit(alice, 1);
        _deposit(alice, 500e6, commit);
        assertTrue(vault.usedOwnerCommit(commit), "commit marked");

        // The gateway re-signs the same commit with a later deadline: a new digest, the
        // same commitment.
        uint64 later = uint64(block.timestamp + 2 * PERMIT_TTL);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, alice, commit, 500e6, later);
        usdc.mint(alice, 500e6);
        vm.startPrank(alice);
        usdc.approve(address(vault), 500e6);
        vm.expectRevert(CollateralVault.OwnerCommitUsed.selector);
        vault.deposit(500e6, commit, later, sig);
        vm.stopPrank();
        assertEq(uint256(vault.depositCount()), 1, "one leaf per commit");
    }

    function test_permit_is_bound_to_depositor_amount_and_deadline() public {
        bytes32 commit = _commit(alice, 1);
        uint64 until = uint64(block.timestamp + PERMIT_TTL);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, alice, commit, 500e6, until);
        usdc.mint(bob, 1_000e6);
        vm.startPrank(bob);
        usdc.approve(address(vault), 1_000e6);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(500e6, commit, until, sig);
        vm.stopPrank();

        usdc.mint(alice, 1_000e6);
        vm.startPrank(alice);
        usdc.approve(address(vault), 1_000e6);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(500e6 + 1, commit, until, sig);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(500e6, commit, until + 1, sig);
        vault.deposit(500e6, commit, until, sig);
        vm.stopPrank();
        assertEq(uint256(vault.depositCount()), 1, "only the exact permit lands");
    }

    // --- amount bounds ---------------------------------------------------------------

    function test_amount_must_be_positive_and_fit_int128() public {
        uint256 maxAmount = uint256(uint128(type(int128).max));
        // Room for the largest deposit: the capacity gate is not what this test is about.
        _bond(maxAmount);

        bytes32 commit = _commit(alice, 1);
        uint64 until = uint64(block.timestamp + PERMIT_TTL);
        bytes memory zeroSig = SettlementTestConfig.permitSig(vm, GW_PK, vault, alice, commit, 0, until);
        bytes memory overSig = SettlementTestConfig.permitSig(vm, GW_PK, vault, alice, commit, maxAmount + 1, until);
        bytes memory maxSig = SettlementTestConfig.permitSig(vm, GW_PK, vault, alice, commit, maxAmount, until);
        usdc.mint(alice, maxAmount + 1);
        vm.startPrank(alice);
        usdc.approve(address(vault), type(uint256).max);
        vm.expectRevert(CollateralVault.BadAmount.selector);
        vault.deposit(0, commit, until, zeroSig);
        vm.expectRevert(CollateralVault.BadAmount.selector);
        vault.deposit(maxAmount + 1, commit, until, overSig);
        vault.deposit(maxAmount, commit, until, maxSig);
        vm.stopPrank();
        assertEq(vault.totalDeposited(), maxAmount, "int128.max accepted");
    }

    // --- pairing -----------------------------------------------------------------

    function test_unpaired_vault_refuses_deposits_and_refunds() public {
        // A settlement that never had its vault set.
        DarkPerpSettlement lone = new DarkPerpSettlement(
            SettlementTestConfig.defaults(address(this), vm.addr(ENCLAVE_PK), new MockClockVerifier(), GENESIS)
        );
        CollateralVault orphan = new CollateralVault(address(lone), address(usdc), vm.addr(GW_PK));
        // A second vault naming the already-paired settlement.
        CollateralVault foreign = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));

        bytes32 commit = _commit(alice, 1);
        uint64 until = uint64(block.timestamp + PERMIT_TTL);
        bytes memory sigOrphan = SettlementTestConfig.permitSig(vm, GW_PK, orphan, alice, commit, 100e6, until);
        bytes memory sigForeign = SettlementTestConfig.permitSig(vm, GW_PK, foreign, alice, commit, 100e6, until);
        usdc.mint(alice, 200e6);
        vm.startPrank(alice);
        usdc.approve(address(orphan), 100e6);
        usdc.approve(address(foreign), 100e6);
        vm.expectRevert(CollateralVault.DepositsPaused.selector);
        orphan.deposit(100e6, commit, until, sigOrphan);
        vm.expectRevert(CollateralVault.DepositsPaused.selector);
        foreign.deposit(100e6, commit, until, sigForeign);
        vm.stopPrank();

        // Neither can refund against a settlement it is not paired with.
        _closeByGovernance();
        vm.expectRevert(CollateralVault.NotPaired.selector);
        foreign.refundDeposit(0, alice, commit, 100e6, alice);
        vm.expectRevert(CollateralVault.NotPaired.selector);
        orphan.refundDeposit(0, alice, commit, 100e6, alice);
    }

    // --- claim reserve for uncredited principal ------------------------------------------

    function test_claims_cannot_draw_on_uncredited_principal() public {
        address overpaid = address(0xBAD);
        bytes32 bobCommit = _commit(bob, 1);
        _deposit(alice, 1_000e6, _commit(alice, 1));
        _deposit(bob, 500e6, bobCommit);

        // An over-credited root: it authorizes 1,500e6 to one party although only alice's
        // 1,000e6 was credited (prefix 1), next to alice's own sound 1,000e6 claim.
        bytes32 bad = _leaf(overpaid, 1_500e6, 1);
        bytes32 good = _leaf(alice, 1_000e6, 2);
        bytes32 root = _pair(bad, good);
        _settleAt(1, root);
        assertEq(vault.refundableOutstanding(), 500e6, "bob's principal is uncredited");

        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(overpaid, 1_500e6, 1, root, _one(good));

        // The sound claim leaves exactly the reserve behind.
        vault.claim(alice, 1_000e6, 2, root, _one(bad));
        assertEq(usdc.balanceOf(alice), 1_000e6, "sound claim paid");
        assertEq(usdc.balanceOf(address(vault)), 500e6, "reserve intact");

        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(overpaid, 1_500e6, 1, root, _one(good));

        // The reserve holds in close-only too, and the refund is still fully covered.
        _closeByGovernance();
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(overpaid, 1_500e6, 1, root, _one(good));
        vault.refundDeposit(1, bob, bobCommit, 500e6, bob);
        assertEq(usdc.balanceOf(bob), 500e6, "uncredited principal returned in full");
        assertEq(usdc.balanceOf(overpaid), 0, "over-credit never paid out of principal");
    }

    function test_sound_claims_are_unaffected_by_the_reserve() public {
        _deposit(alice, 1_000e6, _commit(alice, 1));
        _deposit(bob, 500e6, _commit(bob, 1));
        bytes32 a = _leaf(alice, 1_000e6, 1);
        bytes32 b = _leaf(bob, 500e6, 2);
        bytes32 root = _pair(a, b);
        _settleAt(2, root);
        assertEq(vault.refundableOutstanding(), 0, "everything credited");

        vault.claim(alice, 1_000e6, 1, root, _one(b));
        vault.claim(bob, 500e6, 2, root, _one(a));
        assertEq(usdc.balanceOf(address(vault)), 0, "fully withdrawn");
        assertEq(vault.tvl(), 0, "tvl zero");
    }

    function test_refundable_outstanding_tracks_unconsumed_deposits_minus_refunds() public {
        bytes32 bc = _commit(bob, 1);
        bytes32 cc = _commit(carol, 1);
        _deposit(alice, 100e6, _commit(alice, 1));
        _deposit(bob, 200e6, bc);
        _deposit(carol, 300e6, cc);
        assertEq(vault.refundableOutstanding(), 600e6, "nothing consumed yet");
        assertEq(vault.cumulativeDepositedAt(0), 0, "empty prefix");
        assertEq(vault.cumulativeDepositedAt(1), 100e6, "prefix 1");
        assertEq(vault.cumulativeDepositedAt(3), 600e6, "prefix 3");
        assertEq(vault.cumulativeDepositedAt(4), 0, "beyond the head");

        _settleAt(1, Z);
        assertEq(vault.refundableOutstanding(), 500e6, "ids 1 and 2 outstanding");

        _closeByGovernance();
        vault.refundDeposit(2, carol, cc, 300e6, carol);
        assertEq(vault.refundableOutstanding(), 200e6, "after one refund");
        vault.refundDeposit(1, bob, bc, 200e6, bob);
        assertEq(vault.refundableOutstanding(), 0, "after both refunds");
        assertEq(usdc.balanceOf(address(vault)), 100e6, "credited principal remains");
    }

    /// Random chain length and consumed prefix: every id at or above the prefix refunds
    /// exactly its amount, no id below it refunds, and the vault keeps exactly the
    /// consumed principal.
    function testFuzz_refunds_cover_exactly_the_unconsumed_suffix(uint8 countRaw, uint8 prefixRaw, uint256 seed)
        public
    {
        uint64 count = uint64(1 + (countRaw % 6));
        uint64 prefix = uint64(prefixRaw % (count + 1));
        uint256[] memory amounts = new uint256[](count);
        for (uint64 i = 0; i < count; i++) {
            amounts[i] = 1 + (uint256(keccak256(abi.encode(seed, i))) % 1e12);
            _deposit(_payer(i), amounts[i], _commit(_payer(i), seed));
        }
        _settleAt(prefix, Z);
        _closeByGovernance();

        uint256 consumed = vault.cumulativeDepositedAt(prefix);
        uint256 suffix = vault.cumulativeDepositedAt(count) - consumed;
        assertEq(vault.refundableOutstanding(), suffix, "outstanding is the unconsumed suffix");

        uint256 refunded;
        for (uint64 i = 0; i < count; i++) {
            if (i < prefix) {
                vm.expectRevert(CollateralVault.NotRefundable.selector);
                vault.refundDeposit(i, _payer(i), _commit(_payer(i), seed), amounts[i], _payer(i));
            } else {
                vm.prank(anyone);
                vault.refundDeposit(i, _payer(i), _commit(_payer(i), seed), amounts[i], _payer(i));
                assertEq(usdc.balanceOf(_payer(i)), amounts[i], "refund at principal");
                refunded += amounts[i];
            }
        }
        assertEq(refunded, suffix, "refunds equal the unconsumed suffix");
        assertEq(vault.totalRefunded(), suffix, "accounted");
        assertEq(vault.refundableOutstanding(), 0, "nothing left outstanding");
        assertEq(usdc.balanceOf(address(vault)), consumed, "consumed principal stays");
        assertEq(vault.tvl(), consumed, "tvl equals consumed principal");
    }

    function _payer(uint64 i) internal pure returns (address) {
        return address(uint160(0x1000 + i));
    }
}

/// The same refund path on the clock-bound verifier stack, where every settle path
/// needs a registered anchor and the wind-down batch can only settle the consumed
/// prefix.
contract ClockStackDepositRefundTest is MiniTest {
    ClockBoundVerifier internal clock;
    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;

    bytes32 internal constant ROOT = bytes32(uint256(1));
    bytes32 internal constant M = bytes32(uint256(3));
    bytes32 internal constant Z = bytes32(0);
    uint256 internal constant GW_PK = 0x6A7E;
    uint256 internal constant LIVENESS = SettlementTestConfig.LIVENESS_BLOCKS;
    uint256 internal constant GRACE = SettlementTestConfig.FINAL_SETTLE_GRACE_BLOCKS;
    address internal constant GOV = address(0x60F);
    address internal constant USER = address(0xBEEF);
    address internal constant ANYONE = address(0xCAFE);
    bytes32 internal constant COMMIT = keccak256("owner-and-blind");

    function setUp() public {
        vm.warp(100);
        vm.roll(1);
        clock = new ClockBoundVerifier(new MockZkVerifier(), 10_000, 2_000, 3_600_000);
        DarkPerpSettlement.Config memory cfg = SettlementTestConfig.defaults(address(this), address(0x123), clock, ROOT);
        cfg.governance = GOV;
        s = new DarkPerpSettlement(cfg);
        clock.bindSettlement(IClockSettlement(address(s)));
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
        usdc.mint(address(this), 100_000e6);
        usdc.approve(address(s), 100_000e6);
        s.postBond(100_000e6);
    }

    function _bound(bytes32 base, bytes32 receipt) internal view returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(clock.DOMAIN(), base, receipt)));
    }

    function _userDeposit(uint256 amount) internal {
        usdc.mint(USER, amount);
        uint64 until = uint64(block.timestamp + 3600);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, USER, COMMIT, amount, until);
        vm.startPrank(USER);
        usdc.approve(address(vault), amount);
        vault.deposit(amount, COMMIT, until, sig);
        vm.stopPrank();
    }

    function test_deposit_landing_before_close_only_refunds_after_wind_down() public {
        _userDeposit(1_000_000);
        assertEq(uint256(vault.depositCount()), 1, "deposit 0 landed");

        // Liveness timeout: anyone forces close-only.
        vm.roll(1 + LIVENESS + 1);
        vm.prank(ANYONE);
        s.triggerCloseOnly();
        assertTrue(s.closeOnly(), "close-only");

        // The ordinary path that could credit the deposit is closed.
        bytes32 tip1 = vault.depositTipAt(1);
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.settleBatch(ROOT, M, ROOT, Z, Z, Z, tip1, 1, hex"00");

        // Governance winds down at the consumed prefix (0).
        vm.roll(s.closeOnlyBlock() + GRACE);
        bytes32 n1 = bytes32(uint256(5));
        bytes32 b1 = s.windDownCommitment(ROOT, M, n1, Z, Z, Z, Z, 1);
        vm.prank(GOV);
        bytes32 receipt = clock.register(0, ROOT, b1, 0, 0, 0, 1);
        bytes memory proof = _bound(b1, receipt);
        vm.prank(GOV);
        s.finalSettle(ROOT, M, n1, Z, Z, Z, Z, 0, proof);
        assertTrue(s.windDownSettled(), "phase 1 landed");
        assertEq(uint256(s.consumedDepositCount()), 0, "deposit never consumed");

        // The deposit is refunded at principal; nothing stays locked.
        vm.prank(ANYONE);
        vault.refundDeposit(0, USER, COMMIT, 1_000_000, USER);
        assertEq(usdc.balanceOf(USER), 1_000_000, "principal returned");
        assertEq(usdc.balanceOf(address(vault)), 0, "nothing locked in the vault");

        // And the vault takes no new money into the wound-down system.
        vm.expectRevert(CollateralVault.InCloseOnly.selector);
        vault.deposit(1, COMMIT, uint64(block.timestamp), hex"");
    }

    function test_deposit_refunds_without_any_governance_action() public {
        _userDeposit(2_500_000);
        vm.roll(1 + LIVENESS + 1);
        vm.prank(ANYONE);
        s.triggerCloseOnly();
        // No wind-down batch, no grace wait: the refund is available at once.
        vm.prank(USER);
        vault.refundDeposit(0, USER, COMMIT, 2_500_000, USER);
        assertEq(usdc.balanceOf(USER), 2_500_000, "refunded with no governance step");
        assertEq(s.batchCount(), 0, "no batch was needed");
    }
}
