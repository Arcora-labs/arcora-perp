// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest, Vm} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";

/// The bond-capacity gate: the settlement refuses, at the vault's entrance, any deposit
/// that would lift `BOND_BPS` of the vault's TVL above the posted bond. Settlement itself
/// never checks the bond, so an uncredited deposit can never halt it.
contract BondCapacityTest is MiniTest {
    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;

    uint256 internal constant GW_PK = 0x6A7E;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    bytes32 internal constant M = bytes32("manifest");
    bytes32 internal constant Z = bytes32(0);
    uint256 internal constant BOND = 100e6;
    /// Largest TVL a 100e6 bond covers: floor(((100e6 + 1) * 10_000 - 1) / 500).
    uint256 internal constant CAPACITY_AT_100E6 = 2_000_000_019;
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    uint256 internal salt;

    function setUp() public {
        vm.roll(1000);
        vm.warp(1_000_000);
        s = new DarkPerpSettlement(
            SettlementTestConfig.defaults(address(this), address(0xE), new MockClockVerifier(), GENESIS)
        );
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
        _postBond(BOND);
    }

    function _postBond(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    /// Signs, funds and approves a deposit for `who`; returns the arguments.
    function _prepare(address who, uint256 amount) internal returns (bytes32 commit, uint64 until, bytes memory sig) {
        commit = keccak256(abi.encode("owner-commit", who, ++salt));
        until = uint64(block.timestamp + 3600);
        sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, who, commit, amount, until);
        usdc.mint(who, amount);
        vm.prank(who);
        usdc.approve(address(vault), amount);
    }

    function _deposit(address who, uint256 amount) internal {
        (bytes32 commit, uint64 until, bytes memory sig) = _prepare(who, amount);
        vm.prank(who);
        vault.deposit(amount, commit, until, sig);
    }

    function _depositRefused(address who, uint256 amount) internal {
        (bytes32 commit, uint64 until, bytes memory sig) = _prepare(who, amount);
        vm.prank(who);
        vm.expectRevert(CollateralVault.BondCapacityExceeded.selector);
        vault.deposit(amount, commit, until, sig);
    }

    function _settleAt(uint64 n, bytes32 withdrawalsRoot) internal {
        uint256 id = s.batchCount();
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256(abi.encode("root", id));
        bytes32 tip = vault.depositTipAt(n);
        bytes32 c = s.publicCommitment(prev, M, next, Z, withdrawalsRoot, Z, tip);
        s.settleBatch(prev, M, next, Z, withdrawalsRoot, Z, tip, n, abi.encode(c));
    }

    // --- an uncredited deposit cannot halt settlement ----------------------------------

    function test_oversized_deposit_is_refused_at_the_entrance_and_settlement_continues() public {
        // MockUSDC is open-mint and the permit covers any positive int128 amount.
        _depositRefused(alice, 1e36);
        assertEq(uint256(vault.depositCount()), 0, "nothing entered the chain");
        assertEq(s.requiredBond(), 0, "the floor did not move");

        _settleAt(0, Z);
        assertEq(s.batchCount(), 1, "settlement continues at prefix 0");
    }

    function test_capacity_boundary_is_exact() public {
        assertEq(s.depositCapacity(), CAPACITY_AT_100E6, "capacity of a 100e6 bond");
        _depositRefused(alice, CAPACITY_AT_100E6 + 1);

        _deposit(alice, CAPACITY_AT_100E6);
        assertEq(vault.tvl(), CAPACITY_AT_100E6, "filled to capacity");
        assertEq(s.depositCapacity(), 0, "no capacity left");
        assertEq(s.requiredBond(), BOND, "the bond exactly covers the floor");
        _depositRefused(bob, 1);

        // Settling the full prefix, or an older one, is never blocked by the bond.
        _settleAt(0, Z);
        _settleAt(1, Z);
        assertEq(uint256(s.consumedDepositCount()), 1, "credited");
    }

    function test_settle_at_an_older_prefix_survives_deposits_up_to_capacity() public {
        _deposit(alice, 1_000e6);
        // The proof is built at prefix 1 ...
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256("proved-at-1");
        bytes32 tip1 = vault.depositTipAt(1);
        bytes memory proof = abi.encode(s.publicCommitment(prev, M, next, Z, Z, Z, tip1));

        // ... while further deposits fill the remaining capacity before it lands.
        _deposit(bob, s.depositCapacity());
        assertEq(s.depositCapacity(), 0, "capacity used up");
        s.settleBatch(prev, M, next, Z, Z, Z, tip1, 1, proof);
        assertEq(uint256(s.consumedDepositCount()), 1, "the proven prefix settles");

        _settleAt(2, Z);
        assertEq(uint256(s.consumedDepositCount()), 2, "and the next batch takes the rest");
    }

    function test_donation_moves_neither_capacity_nor_floor() public {
        _deposit(alice, 500e6);
        uint256 cap = s.depositCapacity();
        uint256 floor = s.requiredBond();
        usdc.mint(address(this), 1e30);
        usdc.transfer(address(vault), 1e30);
        assertEq(vault.tvl(), 500e6, "tvl counts deposits, not balance");
        assertEq(s.depositCapacity(), cap, "capacity unchanged");
        assertEq(s.requiredBond(), floor, "floor unchanged");
    }

    // --- the bond can only be withdrawn above the floor -----------------------------

    function test_withdraw_bond_is_limited_to_the_excess_over_the_floor() public {
        _deposit(alice, 1_000e6);
        assertEq(s.requiredBond(), 50e6, "5% of 1,000e6");

        vm.prank(alice);
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.withdrawBond(1);
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(50e6 + 1);

        uint256 before = usdc.balanceOf(address(this));
        s.withdrawBond(50e6);
        assertEq(usdc.balanceOf(address(this)), before + 50e6, "excess returned to the sequencer");
        assertEq(s.sequencerBond(), s.requiredBond(), "bond sits at the floor");
        // floor(((50e6 + 1) * 10_000 - 1) / 500) - 1_000e6
        assertEq(s.depositCapacity(), 19, "only rounding headroom left");
        _depositRefused(bob, 20);
        _deposit(bob, 19);
        assertTrue(s.sequencerBond() >= s.requiredBond(), "still covered");
    }

    function test_claims_restore_capacity_and_refunds_release_bond_in_close_only() public {
        _deposit(alice, CAPACITY_AT_100E6);
        bytes32 leaf = keccak256(abi.encodePacked(alice, uint256(1_000e6), uint256(1)));
        _settleAt(1, leaf);
        vault.claim(alice, 1_000e6, 1, leaf, new bytes32[](0));
        assertEq(s.depositCapacity(), 1_000e6, "a claim frees capacity");
        _deposit(bob, 1_000e6);
        assertEq(s.depositCapacity(), 0, "refilled");

        // Close-only: the pending deposit is refunded and the bond above the new floor
        // can be withdrawn.
        vm.prank(s.governance());
        s.enterCloseOnly();
        uint256 floorBefore = s.requiredBond();
        vault.refundDeposit(1, bob, keccak256(abi.encode("owner-commit", bob, salt)), 1_000e6, bob);
        assertEq(s.requiredBond(), floorBefore - 50e6, "the refund lowered the floor");
        s.withdrawBond(50e6);
        assertEq(s.sequencerBond(), BOND - 50e6, "withdrawn in close-only");
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(1);
    }

    // --- gate, capacity and pairing views -------------------------------------------

    function test_gate_codes_and_views() public {
        assertEq(uint256(s.depositGate(0)), 3, "callers other than the vault are unpaired");
        vm.prank(address(vault));
        assertEq(uint256(s.depositGate(CAPACITY_AT_100E6)), 0, "within capacity");
        vm.prank(address(vault));
        assertEq(uint256(s.depositGate(CAPACITY_AT_100E6 + 1)), 2, "over capacity");
        assertTrue(s.acceptingDeposits(), "accepting");

        vm.prank(s.governance());
        s.enterCloseOnly();
        vm.prank(address(vault));
        assertEq(uint256(s.depositGate(0)), 1, "close-only wins over capacity");
        assertFalse(s.acceptingDeposits(), "not accepting in close-only");

        DarkPerpSettlement bare = new DarkPerpSettlement(
            SettlementTestConfig.defaults(address(this), address(0xE), new MockClockVerifier(), GENESIS)
        );
        assertEq(bare.depositCapacity(), 0, "no capacity without a vault");
        assertEq(bare.requiredBond(), 0, "no floor without a vault");
        assertFalse(bare.acceptingDeposits(), "not accepting without a vault");
    }

    /// When both refusals apply, the gate reports close-only: a caller learns the stack is
    /// closed and refunding, not that it should wait for a bond top-up.
    function test_close_only_is_reported_before_capacity() public {
        _deposit(alice, CAPACITY_AT_100E6);
        uint256 over = vault.tvl() + 1;
        vm.prank(address(vault));
        assertEq(uint256(s.depositGate(over)), 2, "over capacity while live");

        vm.prank(s.governance());
        s.enterCloseOnly();
        vm.prank(address(vault));
        assertEq(uint256(s.depositGate(over)), 1, "close-only reported first");
        (bytes32 commit, uint64 until, bytes memory sig) = _prepare(bob, 1);
        vm.prank(bob);
        vm.expectRevert(CollateralVault.InCloseOnly.selector);
        vault.deposit(1, commit, until, sig);
    }

    /// The gate admits a deposit exactly when it fits `depositCapacity()`, and an admitted
    /// deposit always leaves the bond above the floor.
    function testFuzz_gate_admits_exactly_the_reported_capacity(uint64 extraBond, uint64 first, uint128 amountRaw)
        public
    {
        _postBond(uint256(extraBond) % 1e13);
        uint256 a0 = 1 + uint256(first) % (s.depositCapacity() + 1);
        if (a0 <= s.depositCapacity()) _deposit(alice, a0);
        uint256 cap = s.depositCapacity();
        // Half the runs probe the exact edge (capacity, capacity + 1).
        uint256 mode = uint256(amountRaw) % 4;
        uint256 amount = mode == 0 ? cap : mode == 1 ? cap + 1 : 1 + (uint256(amountRaw) >> 2) % (2 * cap + 2);
        if (amount == 0) amount = 1;
        bool fits = ((vault.tvl() + amount) * s.BOND_BPS()) / 10_000 <= s.sequencerBond();
        assertTrue(fits == (amount <= cap), "capacity matches the gate");
        if (fits) {
            _deposit(bob, amount);
            assertTrue(s.sequencerBond() >= s.requiredBond(), "covered after an admitted deposit");
        } else {
            _depositRefused(bob, amount);
        }
    }
}

/// Drives deposits (some over capacity), bond top-ups and withdrawals (some above the
/// excess), settle-and-claim rounds and, rarely, close-only plus refunds.
contract BondCapacityHandler {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    uint256 internal constant GW_PK = 0x6A7E;
    bytes32 internal constant M = bytes32("manifest");
    bytes32 internal constant Z = bytes32(0);

    DarkPerpSettlement public s;
    CollateralVault public vault;
    MockUSDC public usdc;
    /// Set when the gate or the withdrawal floor disagreed with the expected rule.
    bool public mismatch;
    uint256 public calls;

    struct Leaf {
        address from;
        bytes32 commit;
        uint256 amount;
    }

    Leaf[] internal leaves;
    uint256 internal nonce;

    constructor() {
        DarkPerpSettlement.Config memory cfg =
            SettlementTestConfig.defaults(address(this), address(0xE), new MockClockVerifier(), bytes32(uint256(1)));
        s = new DarkPerpSettlement(cfg);
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
        _post(100e6);
    }

    function _post(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    function deposit(uint256 amountSeed, uint8 who) external {
        calls++;
        if (s.closeOnly()) return;
        uint256 cap = s.depositCapacity();
        uint256 amount = _nearBoundary(amountSeed, cap);
        if (amount == 0) amount = 1;
        if (amount > uint256(uint128(type(int128).max))) return;
        address from = address(uint160(0x1000 + who % 8));
        bytes32 commit = keccak256(abi.encode("handler-commit", ++nonce));
        uint64 until = uint64(block.timestamp + 3600);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, from, commit, amount, until);
        usdc.mint(from, amount);
        vm.prank(from);
        usdc.approve(address(vault), amount);
        bool fits = ((vault.tvl() + amount) * s.BOND_BPS()) / 10_000 <= s.sequencerBond();
        vm.prank(from);
        try vault.deposit(amount, commit, until, sig) {
            if (!fits) mismatch = true;
            leaves.push(Leaf(from, commit, amount));
        } catch (bytes memory err) {
            if (fits || bytes4(err) != CollateralVault.BondCapacityExceeded.selector) mismatch = true;
        }
    }

    /// Half the time exactly `limit` or `limit + 1`, otherwise anywhere in [0, 2 * limit + 1].
    function _nearBoundary(uint256 seed, uint256 limit) internal pure returns (uint256) {
        uint256 mode = seed % 4;
        if (mode == 0) return limit;
        if (mode == 1) return limit + 1;
        return (seed >> 2) % (2 * limit + 2);
    }

    function postBond(uint256 amountSeed) external {
        calls++;
        _post(amountSeed % 1e12);
    }

    function withdrawBond(uint256 amountSeed) external {
        calls++;
        uint256 floor = s.requiredBond();
        uint256 reserve = s.openChallengeCount() * s.slashPayoutCap();
        if (reserve > floor) floor = reserve;
        uint256 bond = s.sequencerBond();
        uint256 excess = bond > floor ? bond - floor : 0;
        uint256 amount = _nearBoundary(amountSeed, excess);
        try s.withdrawBond(amount) {
            if (amount > excess) mismatch = true;
        } catch {
            if (amount <= excess) mismatch = true;
        }
    }

    /// Settles every deposit so far and claims part of the credited, unwithdrawn value.
    function settleAndClaim(uint256 amountSeed) external {
        calls++;
        if (s.closeOnly()) return;
        uint64 n = vault.depositCount();
        uint256 available = vault.cumulativeDepositedAt(n) - vault.totalWithdrawn();
        uint256 amount = available == 0 ? 0 : 1 + amountSeed % available;
        address to = address(uint160(0x2000 + amountSeed % 4));
        uint256 id = ++nonce;
        bytes32 root = amount == 0 ? Z : keccak256(abi.encodePacked(to, amount, id));
        _settle(n, root, id);
        if (amount != 0) vault.claim(to, amount, id, root, new bytes32[](0));
    }

    function _settle(uint64 n, bytes32 root, uint256 id) internal {
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256(abi.encode("handler-root", id));
        bytes32 tip = vault.depositTipAt(n);
        bytes32 c = s.publicCommitment(prev, M, next, Z, root, Z, tip);
        s.settleBatch(prev, M, next, Z, root, Z, tip, n, abi.encode(c));
    }

    /// Rarely enters close-only; once there, refunds up to `count` unconsumed deposits.
    function closeAndRefund(uint8 count, uint8 chance) external {
        calls++;
        if (!s.closeOnly()) {
            if (chance % 16 != 0) return;
            s.enterCloseOnly();
        }
        uint64 c = s.consumedDepositCount();
        for (uint256 i = c; i < leaves.length && count > 0; i++) {
            if (vault.depositRefunded(uint64(i))) continue;
            Leaf memory l = leaves[i];
            vault.refundDeposit(uint64(i), l.from, l.commit, l.amount, l.from);
            count--;
        }
    }
}

contract BondCapacityInvariantTest is MiniTest {
    BondCapacityHandler internal handler;

    function setUp() public {
        vm.roll(1000);
        vm.warp(1_000_000);
        handler = new BondCapacityHandler();
    }

    function targetContracts() public view returns (address[] memory t) {
        t = new address[](1);
        t[0] = address(handler);
    }

    /// While no slash happened the bond covers the floor; the gate and the withdrawal
    /// floor follow their rules; the vault's accounting is exact and always covers the
    /// uncredited principal.
    /// forge-config: default.invariant.runs = 48
    /// forge-config: default.invariant.depth = 40
    function invariant_bond_covers_floor_and_vault_stays_exact() public view {
        DarkPerpSettlement s = handler.s();
        CollateralVault vault = handler.vault();
        MockUSDC usdc = handler.usdc();
        if (s.slashCount() == 0) assertTrue(s.sequencerBond() >= s.requiredBond(), "bond covers the floor");
        assertFalse(handler.mismatch(), "gate and withdrawal floor follow their rules");
        uint256 bal = usdc.balanceOf(address(vault));
        assertEq(
            bal + vault.totalWithdrawn() + vault.totalRefunded(), vault.totalDeposited(), "vault accounting is exact"
        );
        assertTrue(bal >= vault.refundableOutstanding(), "uncredited principal stays covered");
        assertEq(usdc.balanceOf(address(s)), s.sequencerBond(), "settlement holds exactly the bond");
    }
}
