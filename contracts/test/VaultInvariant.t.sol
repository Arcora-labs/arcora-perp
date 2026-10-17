// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest, Vm} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockSettlementGate} from "./mocks/MockSettlementGate.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";

/// Drives the vault through random deposits, credits, withdrawal roots (within the
/// credited funds, and over-credited ones), claims, close-only, refunds and donations.
/// The handler is the vault's settlement (through MockSettlementGate) and keeps its own
/// ledger of what every action should have done. It flags any payout the rules forbid
/// and any action the rules allow that the vault refused.
contract VaultHandler {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    uint256 internal constant GW_PK = 0x6A7E;
    uint256 internal constant MAX_DEPOSITS = 40;
    uint256 internal constant MAX_LEAVES = 40;
    uint256 internal constant MAX_AMOUNT = 5_000e6;
    uint256 internal constant MAX_OVER_CREDIT = 20_000e6;
    uint256 internal constant MAX_DONATION = 1_000e6;

    CollateralVault public immutable vault;
    MockUSDC public immutable usdc;
    MockSettlementGate public immutable gate;
    address[4] internal actors;

    // Deposit ledger, indexed by deposit id.
    address[] internal depFrom;
    bytes32[] internal depCommit;
    uint256[] internal depAmount;
    bool[] internal depRefunded;

    struct Leaf {
        address to;
        uint256 amount;
        uint256 nonce;
        bool withinCredit;
        bool paid;
    }

    Leaf[] internal leaves;

    uint64 public consumed;
    bool public closed;
    uint256 public ghostDeposited;
    uint256 public ghostRefunded;
    uint256 public ghostClaimed;
    uint256 public ghostDonated;
    /// Total authorized by roots that stay within the credited deposits.
    uint256 public authorizedWithinCredit;
    /// Total paid against over-credited roots.
    uint256 public overCreditPaid;
    uint256 internal seq;

    // Violations; each must stay false.
    bool public doublePaid;
    bool public refundOutsideRules;
    bool public payoutMismatch;
    bool public claimRefusedForOtherReason;
    bool public reserveBreached;
    bool public coveredClaimRefused;
    bool public creditedClaimRefused;
    bool public validRefundRefused;
    bool public validDepositRefused;

    // Coverage counters.
    uint256 public depositsDone;
    uint256 public refundsDone;
    uint256 public refundsRefused;
    uint256 public claimsDone;
    uint256 public reservedRefusals;

    constructor(CollateralVault v, MockUSDC u, MockSettlementGate g) {
        vault = v;
        usdc = u;
        gate = g;
        actors[0] = address(0xA11CE);
        actors[1] = address(0xB0B);
        actors[2] = address(0xCA201);
        actors[3] = address(0xD0D0);
    }

    // ------------------------------------------------------------------
    // actions
    // ------------------------------------------------------------------

    function deposit(uint256 actorSeed, uint256 amountSeed) external {
        if (closed || depFrom.length >= MAX_DEPOSITS) return;
        address who = actors[actorSeed % actors.length];
        uint256 amount = 1 + (amountSeed % MAX_AMOUNT);
        bytes32 commit = keccak256(abi.encodePacked("vault-invariant/commit", seq++));
        uint64 until = uint64(block.timestamp + 30 minutes);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, who, commit, amount, until);
        usdc.mint(who, amount);
        vm.startPrank(who);
        usdc.approve(address(vault), amount);
        try vault.deposit(amount, commit, until, sig) {
            depFrom.push(who);
            depCommit.push(commit);
            depAmount.push(amount);
            depRefunded.push(false);
            ghostDeposited += amount;
            depositsDone++;
        } catch {
            validDepositRefused = true;
        }
        vm.stopPrank();
    }

    /// A settled batch consumes one or two more deposits (live mode only). It fires on
    /// about half the calls, so an uncredited backlog usually exists at close-only.
    function credit(uint256 seed) external {
        if (closed || seed % 2 == 0) return;
        uint64 head = uint64(depFrom.length);
        if (head == consumed) return;
        uint64 step = (seed >> 8) % 2 == 0 || head - consumed == 1 ? 1 : 2;
        consumed += step;
        gate.setConsumedDepositCount(consumed);
    }

    /// Publishes a one-leaf root that stays within the credited deposits.
    function publishWithinCredit(uint256 amountSeed, uint256 actorSeed) external {
        if (leaves.length >= MAX_LEAVES) return;
        uint256 credited = _cum(consumed);
        if (credited <= authorizedWithinCredit) return;
        uint256 amount = 1 + (amountSeed % (credited - authorizedWithinCredit));
        authorizedWithinCredit += amount;
        _publishLeaf(actors[actorSeed % actors.length], amount, true);
    }

    /// Publishes a one-leaf root authorizing more than the credited state could hold.
    /// Fires on about a quarter of the calls.
    function publishOverCredited(uint256 amountSeed, uint256 actorSeed) external {
        if (leaves.length >= MAX_LEAVES || (amountSeed >> 128) % 4 != 0) return;
        _publishLeaf(actors[actorSeed % actors.length], 1 + (amountSeed % MAX_OVER_CREDIT), false);
    }

    function claim(uint256 idxSeed) external {
        if (leaves.length == 0) return;
        Leaf storage l = leaves[idxSeed % leaves.length];
        bytes32 leaf = keccak256(abi.encodePacked(l.to, l.amount, l.nonce));
        uint256 before = usdc.balanceOf(l.to);
        // Ledger model of the reserve: payable iff the held balance covers the amount and
        // what remains still covers every uncredited, unrefunded deposit.
        uint256 held = ghostDeposited + ghostDonated - ghostClaimed - ghostRefunded;
        bool covered = held >= l.amount && held - l.amount >= _outstanding();
        try vault.claim(l.to, l.amount, l.nonce, leaf, new bytes32[](0)) {
            if (l.paid) doublePaid = true;
            if (!covered) reserveBreached = true;
            l.paid = true;
            ghostClaimed += l.amount;
            if (!l.withinCredit) overCreditPaid += l.amount;
            if (usdc.balanceOf(l.to) != before + l.amount) payoutMismatch = true;
            claimsDone++;
        } catch (bytes memory err) {
            bytes4 sel = bytes4(err);
            if (l.paid) {
                if (sel != CollateralVault.AlreadyClaimed.selector) claimRefusedForOtherReason = true;
            } else {
                // The root is published and the proof is valid: only the reserve may refuse.
                if (sel != CollateralVault.ReservedForUncredited.selector) claimRefusedForOtherReason = true;
                else reservedRefusals++;
                if (covered) coveredClaimRefused = true;
                // Within-credit claims are always payable unless over-credited claims
                // already took part of the credited funds.
                if (l.withinCredit && overCreditPaid == 0) creditedClaimRefused = true;
            }
        }
    }

    /// Close-only, irreversible. Fires on roughly one call in twenty-four, so most runs
    /// build up a deposit history first and some never leave live mode.
    function enterCloseOnly(uint256 seed) external {
        if (closed || seed % 24 != 0) return;
        closed = true;
        gate.setCloseOnly(true);
    }

    /// mode 0: payer to itself; 1: payer redirects; 2: third party pays the payer;
    /// 3: third party redirects (forbidden); 4: wrong amount in the preimage (forbidden).
    function refund(uint256 idSeed, uint256 modeSeed, uint256 callerSeed) external {
        uint256 n = depFrom.length;
        if (n == 0) return;
        // Half the time aim at the unconsumed suffix, where refunds can succeed.
        uint64 id = (idSeed >> 128) % 2 == 1 && n > consumed
            ? uint64(consumed + (idSeed % (n - consumed)))
            : uint64(idSeed % n);
        address from = depFrom[id];
        uint256 mode = modeSeed % 5;
        uint256 amount = depAmount[id];
        address caller = from;
        address to = from;
        if (mode == 1) {
            to = _other(from, callerSeed);
        } else if (mode == 2) {
            caller = _other(from, callerSeed);
        } else if (mode == 3) {
            caller = _other(from, callerSeed);
            to = _other(from, (callerSeed % actors.length) + 1);
        } else if (mode == 4) {
            amount += 1;
        }
        bool allowed = closed && id >= consumed && !depRefunded[id] && mode <= 2;
        uint256 before = usdc.balanceOf(to);
        vm.prank(caller);
        try vault.refundDeposit(id, from, depCommit[id], amount, to) {
            if (!allowed) {
                refundOutsideRules = true;
            } else {
                depRefunded[id] = true;
                ghostRefunded += amount;
                refundsDone++;
            }
            if (usdc.balanceOf(to) != before + amount) payoutMismatch = true;
        } catch {
            if (allowed) validRefundRefused = true;
            refundsRefused++;
        }
    }

    /// A bare token transfer into the vault.
    function donate(uint256 seed) external {
        uint256 amount = 1 + (seed % MAX_DONATION);
        usdc.mint(address(vault), amount);
        ghostDonated += amount;
    }

    function advance(uint256 seed) external {
        vm.warp(block.timestamp + 1 + (seed % 1 hours));
        vm.roll(block.number + 1 + (seed % 50));
    }

    // ------------------------------------------------------------------
    // ledger views
    // ------------------------------------------------------------------

    function depositCount() external view returns (uint256) {
        return depFrom.length;
    }

    /// Principal of ids at or above the consumed count.
    function unconsumedPrincipal() public view returns (uint256 sum) {
        for (uint256 i = consumed; i < depAmount.length; i++) {
            sum += depAmount[i];
        }
    }

    /// Principal of ids at or above the consumed count that were not refunded.
    function outstandingPrincipal() external view returns (uint256) {
        return _outstanding();
    }

    /// True if some id below the consumed count was refunded.
    function refundedBelowBoundary() external view returns (bool) {
        for (uint256 i = 0; i < consumed && i < depRefunded.length; i++) {
            if (depRefunded[i]) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // internals
    // ------------------------------------------------------------------

    function _outstanding() internal view returns (uint256 sum) {
        for (uint256 i = consumed; i < depAmount.length; i++) {
            if (!depRefunded[i]) sum += depAmount[i];
        }
    }

    function _cum(uint64 k) internal view returns (uint256 sum) {
        for (uint256 i = 0; i < k; i++) {
            sum += depAmount[i];
        }
    }

    function _other(address from, uint256 seed) internal view returns (address a) {
        uint256 i = seed % actors.length;
        a = actors[i];
        if (a == from) a = actors[(i + 1) % actors.length];
    }

    function _publishLeaf(address to, uint256 amount, bool withinCredit) internal {
        uint256 nonce = seq++;
        leaves.push(Leaf({to: to, amount: amount, nonce: nonce, withinCredit: withinCredit, paid: false}));
        gate.publishTo(address(vault), keccak256(abi.encodePacked(to, amount, nonce)), nonce);
    }
}

contract VaultInvariantTest is MiniTest {
    uint256 internal constant GW_PK = 0x6A7E;

    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockSettlementGate internal gate;
    VaultHandler internal handler;

    function setUp() public {
        vm.warp(1_760_000_000);
        vm.roll(1_000);
        usdc = new MockUSDC();
        gate = new MockSettlementGate();
        vault = new CollateralVault(address(gate), address(usdc), vm.addr(GW_PK));
        gate.setVault(address(vault));
        handler = new VaultHandler(vault, usdc, gate);
    }

    /// Restricts the invariant fuzzer to the handler (read by selector; no forge-std).
    function targetContracts() public view returns (address[] memory t) {
        t = new address[](1);
        t[0] = address(handler);
    }

    /// Every token unit that entered (deposits and bare transfers) is either still held
    /// or left exactly once, through a claim or a refund.
    /// forge-config: default.invariant.runs = 96
    /// forge-config: default.invariant.depth = 256
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_accounting_identity() public view {
        assertEq(
            usdc.balanceOf(address(vault)) + vault.totalWithdrawn() + vault.totalRefunded(),
            vault.totalDeposited() + handler.ghostDonated(),
            "balance + withdrawn + refunded == deposited + donated"
        );
        uint256 out = vault.totalWithdrawn() + vault.totalRefunded();
        uint256 expectedTvl = vault.totalDeposited() > out ? vault.totalDeposited() - out : 0;
        assertEq(vault.tvl(), expectedTvl, "tvl is deposits net of withdrawals and refunds, saturating");
        assertEq(vault.totalDeposited(), handler.ghostDeposited(), "deposits match the ledger");
        assertEq(vault.totalWithdrawn(), handler.ghostClaimed(), "withdrawals match the ledger");
        assertEq(vault.totalRefunded(), handler.ghostRefunded(), "refunds match the ledger");
    }

    /// Claims never take the balance below the principal of uncredited, unrefunded
    /// deposits, and that principal is exactly the ledger's.
    /// forge-config: default.invariant.runs = 96
    /// forge-config: default.invariant.depth = 256
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_uncredited_principal_stays_covered() public view {
        uint256 outstanding = vault.refundableOutstanding();
        assertTrue(usdc.balanceOf(address(vault)) >= outstanding, "balance covers uncredited principal");
        assertEq(outstanding, handler.outstandingPrincipal(), "outstanding matches the ledger");
        assertTrue(vault.totalRefunded() <= handler.unconsumedPrincipal(), "refunds never exceed the unconsumed suffix");
        assertFalse(handler.refundedBelowBoundary(), "no consumed id was refunded");
    }

    /// No claim leaf pays twice, no refund breaks the boundary, once-per-id or recipient
    /// rules, and every payout lands on its recipient exactly.
    /// forge-config: default.invariant.runs = 96
    /// forge-config: default.invariant.depth = 256
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_no_forbidden_payout() public view {
        assertFalse(handler.doublePaid(), "a withdrawal leaf paid twice");
        assertFalse(handler.refundOutsideRules(), "a refund the rules forbid was paid");
        assertFalse(handler.payoutMismatch(), "a payout did not land exactly on its recipient");
        assertFalse(handler.claimRefusedForOtherReason(), "a claim reverted for an unexpected reason");
        assertFalse(handler.reserveBreached(), "a claim was paid out of uncredited principal");
    }

    /// What the rules allow is served: permitted deposits, rule-abiding refunds, and
    /// claims within the credited funds (absent over-credited payouts).
    /// forge-config: default.invariant.runs = 96
    /// forge-config: default.invariant.depth = 256
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_allowed_actions_are_served() public view {
        assertFalse(handler.validDepositRefused(), "a permitted deposit was refused");
        assertFalse(handler.validRefundRefused(), "a rule-abiding refund was refused");
        assertFalse(handler.creditedClaimRefused(), "a claim within the credited funds was refused");
        assertFalse(handler.coveredClaimRefused(), "a claim the balance covered beyond the reserve was refused");
    }

    /// The chain head, the prefix sums and the consumed boundary stay consistent.
    /// forge-config: default.invariant.runs = 96
    /// forge-config: default.invariant.depth = 256
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_chain_and_boundary_consistent() public view {
        uint64 n = vault.depositCount();
        assertEq(n, handler.depositCount(), "deposit count matches the ledger");
        assertEq(vault.depositTipAt(n), vault.depositChainTip(), "the head prefix is the live tip");
        assertEq(vault.cumulativeDepositedAt(n), vault.totalDeposited(), "the full prefix sum is the total");
        assertEq(gate.consumedDepositCount(), handler.consumed(), "boundary matches the ledger");
        assertTrue(handler.consumed() <= n, "the boundary never passes the head");
    }

    /// A fixed walk through the handler, so the invariants above are not vacuous: every
    /// path they guard is taken at least once.
    function test_handler_walk_reaches_every_path() public {
        handler.deposit(0, 1_000e6 - 1); // alice 1,000e6
        handler.deposit(1, 500e6 - 1); // bob 500e6
        handler.deposit(2, 250e6 - 1); // carol 250e6
        handler.credit(1); // consumes id 0
        handler.publishWithinCredit(400e6 - 1, 3); // within credit
        handler.publishOverCredited(1_500e6 - 1, 2); // over-credited
        handler.claim(0);
        handler.claim(1); // reserved
        handler.claim(0); // already paid
        handler.donate(10e6 - 1);
        handler.enterCloseOnly(0);
        handler.refund(0, 0, 0); // consumed id: refused
        handler.refund(1, 3, 0); // third-party redirect: refused
        handler.refund(1, 4, 0); // wrong preimage: refused
        handler.refund(1, 2, 0); // third party pays the payer
        handler.refund(1, 0, 0); // already refunded: refused
        handler.refund(2, 1, 0); // payer redirects
        handler.claim(1); // still reserved by the balance

        assertEq(handler.depositsDone(), 3, "deposits");
        assertEq(handler.claimsDone(), 1, "claims paid");
        assertEq(handler.reservedRefusals(), 2, "reserve refusals");
        assertEq(handler.refundsDone(), 2, "refunds paid");
        assertEq(handler.refundsRefused(), 4, "refunds refused");
        assertFalse(handler.doublePaid(), "doublePaid");
        assertFalse(handler.refundOutsideRules(), "refundOutsideRules");
        assertFalse(handler.payoutMismatch(), "payoutMismatch");
        assertFalse(handler.claimRefusedForOtherReason(), "claimRefusedForOtherReason");
        assertFalse(handler.validRefundRefused(), "validRefundRefused");
        assertFalse(handler.creditedClaimRefused(), "creditedClaimRefused");
        assertFalse(handler.reserveBreached(), "reserveBreached");
        assertFalse(handler.coveredClaimRefused(), "coveredClaimRefused");
        invariant_accounting_identity();
        invariant_uncredited_principal_stays_covered();
        invariant_chain_and_boundary_consistent();
        assertEq(vault.refundableOutstanding(), 0, "every uncredited deposit was refunded");
        assertEq(usdc.balanceOf(address(vault)), 1_000e6 + 10e6 - 400e6, "credited principal and the donation remain");
    }
}

/// Random deposit histories, a random consumed prefix, close-only, then refunds of
/// every id: exactly the unconsumed suffix is paid back, once, and nothing below the
/// boundary is refundable.
contract VaultRefundFuzzTest is MiniTest {
    uint256 internal constant GW_PK = 0x6A7E;

    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockSettlementGate internal gate;

    function setUp() public {
        vm.warp(1_760_000_000);
        vm.roll(1_000);
        usdc = new MockUSDC();
        gate = new MockSettlementGate();
        vault = new CollateralVault(address(gate), address(usdc), vm.addr(GW_PK));
        gate.setVault(address(vault));
    }

    function _payer(uint256 i) internal pure returns (address) {
        return address(uint160(0x5000 + (i % 3)));
    }

    function _amount(uint256 seed, uint256 i) internal pure returns (uint256) {
        return 1 + (uint256(keccak256(abi.encodePacked(seed, i))) % 10_000e6);
    }

    function _commit(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("vault-refund-fuzz/commit", i));
    }

    function _deposit(address who, uint256 amount, bytes32 commit) internal {
        usdc.mint(who, amount);
        uint64 until = uint64(block.timestamp + 30 minutes);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, who, commit, amount, until);
        vm.startPrank(who);
        usdc.approve(address(vault), amount);
        vault.deposit(amount, commit, until, sig);
        vm.stopPrank();
    }

    function testFuzz_refunds_pay_back_exactly_the_unconsumed_suffix(uint8 nSeed, uint8 cSeed, uint256 amountSeed)
        public
    {
        uint256 n = 1 + (uint256(nSeed) % 12);
        uint64 c = uint64(uint256(cSeed) % (n + 1));
        uint256 suffix;
        for (uint256 i = 0; i < n; i++) {
            uint256 a = _amount(amountSeed, i);
            _deposit(_payer(i), a, _commit(i));
            if (i >= c) suffix += a;
            vm.roll(block.number + 1);
        }
        gate.setConsumedDepositCount(c);
        gate.setCloseOnly(true);
        assertEq(vault.refundableOutstanding(), suffix, "outstanding is the unconsumed suffix");

        uint256 balanceBefore = usdc.balanceOf(address(vault));
        for (uint64 i = 0; i < n; i++) {
            address from = _payer(i);
            uint256 a = _amount(amountSeed, i);
            if (i < c) {
                vm.expectRevert(CollateralVault.NotRefundable.selector);
                vault.refundDeposit(i, from, _commit(i), a, from);
            } else {
                vault.refundDeposit(i, from, _commit(i), a, from);
            }
        }
        assertEq(vault.totalRefunded(), suffix, "refunds total the unconsumed suffix");
        assertEq(usdc.balanceOf(address(vault)), balanceBefore - suffix, "balance dropped by the suffix");
        assertEq(usdc.balanceOf(address(vault)), vault.cumulativeDepositedAt(c), "the consumed prefix stays");
        assertEq(vault.refundableOutstanding(), 0, "nothing left outstanding");

        // A second pass pays nothing.
        for (uint64 i = c; i < n; i++) {
            address from = _payer(i);
            uint256 a = _amount(amountSeed, i);
            vm.expectRevert(CollateralVault.AlreadyRefunded.selector);
            vault.refundDeposit(i, from, _commit(i), a, from);
        }
        assertEq(vault.totalRefunded(), suffix, "second pass paid nothing");
    }
}
