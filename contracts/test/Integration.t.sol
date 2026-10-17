// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// Full on-chain wiring over the same stack the testnet harness deploys: MockZkVerifier
/// behind a real ClockBoundVerifier, the settlement, MockUSDC and the vault. A user
/// deposits USDC under a gateway permit, a clock-anchored batch settles and publishes its
/// withdrawals root to the vault, and the user claims from it. Funds release only from
/// SETTLED state, via the vault, never by the sequencer directly. Deposits are admitted
/// only while the sequencer bond covers the resulting TVL, and deposits the settled state
/// never credited are refunded at principal once close-only begins.
contract IntegrationTest is MiniTest {
    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    ClockBoundVerifier internal clock;
    MockUSDC internal usdc;
    MockZkVerifier internal inner;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    uint256 internal constant USD = 1e6;
    /// The gateway permit key the vault is deployed with.
    uint256 internal constant GW_PK = 0x6A7E;
    /// The enclave key (challenge authorizations; unused by these flows).
    uint256 internal constant ENCLAVE_PK = 0xE1C1A7E;
    /// Permit lifetime used by the helpers.
    uint64 internal constant PERMIT_TTL = 1800;

    /// Distinct owner commitments: each one may enter the deposit chain only once.
    uint256 internal commitNonce;

    // this contract is the sequencer and governance
    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(100);
        inner = new MockZkVerifier();
        clock = new ClockBoundVerifier(inner, 30_000, 30_000, 3_600_000);
        s = new DarkPerpSettlement(SettlementTestConfig.defaults(address(this), vm.addr(ENCLAVE_PK), clock, GENESIS));
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
        clock.bindSettlement(IClockSettlement(address(s)));
    }

    function _nextCommit() internal returns (bytes32) {
        return keccak256(abi.encode("dark-perp.test.note-owner", commitNonce++));
    }

    /// Funds `who`, approves the vault and returns a fresh gateway permit, so a caller can
    /// arm `vm.expectRevert` right before the deposit itself.
    function _prepareDeposit(address who, uint256 amount)
        internal
        returns (bytes32 commit, uint64 validUntil, bytes memory sig)
    {
        commit = _nextCommit();
        validUntil = uint64(block.timestamp + PERMIT_TTL);
        sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, who, commit, amount, validUntil);
        usdc.mint(who, amount);
        vm.prank(who);
        usdc.approve(address(vault), amount);
    }

    function _deposit(address who, uint256 amount) internal returns (bytes32 commit) {
        uint64 validUntil;
        bytes memory sig;
        (commit, validUntil, sig) = _prepareDeposit(who, amount);
        vm.prank(who);
        vault.deposit(amount, commit, validUntil, sig);
    }

    /// The sequencer (this contract) posts a USDC bond of `amount`.
    function _bond(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    /// Registers the clock anchor for the next batch in `phase` and returns the proof the
    /// mock inner verifier accepts for it (the clock-bound commitment).
    function _clockProof(bytes32 prev, bytes32 base, uint8 phase) internal returns (bytes memory) {
        bytes32 receipt = clock.register(uint64(s.batchCount()), prev, base, 0, 0, 0, phase);
        return abi.encode(keccak256(abi.encode(clock.DOMAIN(), base, receipt)));
    }

    /// Settles a phase-0 batch that consumes the vault's first `count` deposits.
    function _settle(bytes32 prev, bytes32 manifest, bytes32 next, bytes32 wd, uint64 count) internal {
        bytes32 dRoot = vault.depositTipAt(count);
        bytes32 base = s.publicCommitment(prev, manifest, next, bytes32(0), wd, bytes32(0), dRoot);
        bytes memory proof = _clockProof(prev, base, 0);
        s.settleBatch(prev, manifest, next, bytes32(0), wd, bytes32(0), dRoot, count, proof);
    }

    function test_deposit_settle_then_claim_from_vault() public {
        // the bond covers 5% of the TVL the deposit will create: 250 USDC for 5,000 USDC.
        _bond(250 * USD);
        // a user deposits USDC into the vault (off-chain a note is minted)
        _deposit(alice, 5000 * USD);
        assertEq(vault.tvl(), 5000 * USD, "vault funded");
        assertEq(s.requiredBond(), 250 * USD, "floor = 5% of TVL");
        assertEq(vault.refundableOutstanding(), 5000 * USD, "uncredited until a batch consumes it");

        // settlement settles a batch that credits the deposit and authorizes alice to
        // withdraw 2,000 USDC. Single-leaf withdrawals tree: root == leaf, empty proof.
        uint256 amount = 2000 * USD;
        uint256 nonce = 7;
        bytes32 leaf = keccak256(abi.encodePacked(alice, amount, nonce));
        bytes32 newRoot = bytes32(uint256(2));
        _settle(GENESIS, keccak256("batch-0"), newRoot, leaf, 1);

        // the vault now carries that settled withdrawals root, and the deposit is consumed
        assertEq(vault.withdrawalsRoot(), leaf, "vault got the settled withdrawals root");
        assertEq(uint256(s.consumedDepositCount()), 1, "the batch consumed the deposit");
        assertEq(vault.refundableOutstanding(), 0, "nothing left uncredited");

        // alice claims; USDC releases from the vault, gated on SETTLED state
        bytes32[] memory proof = new bytes32[](0);
        uint256 before = usdc.balanceOf(alice);
        vault.claim(alice, amount, nonce, vault.withdrawalsRoot(), proof);
        assertEq(usdc.balanceOf(alice) - before, amount, "alice withdrew USDC from settled state");
        assertEq(vault.tvl(), 3000 * USD, "tvl net of the claim");

        // the state root advanced on L1
        assertEq(s.currentStateRoot(), newRoot, "root advanced to settled batch");
        assertEq(s.batchCount(), 1, "one settled batch");
    }

    function test_deposit_requires_bond_capacity() public {
        // A batch that credits no deposit settles without any bond.
        assertEq(s.sequencerBond(), 0, "no bond yet");
        _settle(GENESIS, keccak256("empty"), bytes32(uint256(2)), bytes32(0), 0);
        assertEq(s.batchCount(), 1, "prefix-0 settle needs no bond");

        // With no bond, only the rounding slack below one bond unit is admitted.
        assertEq(s.depositCapacity(), 19, "zero bond admits only rounding dust");
        (bytes32 c0, uint64 v0, bytes memory sig0) = _prepareDeposit(alice, 10_000 * USD);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BondCapacityExceeded.selector);
        vault.deposit(10_000 * USD, c0, v0, sig0);

        // 500 USDC of bond admits up to 10,000.000019 USDC of TVL.
        _bond(500 * USD);
        uint256 cap = s.depositCapacity();
        assertEq(cap, 10_000_000_019, "capacity = largest TVL the bond covers");
        _deposit(alice, cap);
        assertEq(vault.tvl(), cap, "deposit up to exactly the capacity");
        assertEq(s.depositCapacity(), 0, "capacity used up");
        assertEq(s.requiredBond(), 500 * USD, "the bond still covers the floor");

        // one more unit is refused
        (bytes32 c1, uint64 v1, bytes memory sig1) = _prepareDeposit(bob, 1);
        vm.prank(bob);
        vm.expectRevert(CollateralVault.BondCapacityExceeded.selector);
        vault.deposit(1, c1, v1, sig1);

        // the bond above the floor is the only part that can be withdrawn
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(1);

        // settlement itself never checks the bond: the deposit gate already kept it at
        // the floor, so a batch crediting the deposit settles at full capacity.
        uint256 amount = 4000 * USD;
        bytes32 leaf = keccak256(abi.encodePacked(alice, amount, uint256(1)));
        _settle(bytes32(uint256(2)), keccak256("b1"), bytes32(uint256(3)), leaf, 1);
        assertEq(s.batchCount(), 2, "settles at full capacity");

        // a claim lowers the TVL and frees capacity for new deposits
        vault.claim(alice, amount, 1, leaf, new bytes32[](0));
        assertEq(s.depositCapacity(), amount, "a claim frees its amount of capacity");
        vm.prank(bob);
        vault.deposit(1, c1, v1, sig1);
        assertEq(uint256(vault.depositCount()), 2, "admitted once capacity returned");

        // topping up the bond raises the capacity by 20x the top-up
        _bond(100 * USD);
        assertEq(s.depositCapacity(), amount - 1 + 2000 * USD, "100 USDC of bond adds 2,000 USDC");
    }

    function test_bond_floor_immune_to_donations() public {
        // requiredBond and the deposit capacity scale off ACCOUNTED net deposits, not the
        // raw token balance, so a bare token.transfer (a donation, bypassing deposit)
        // cannot move either of them.
        _bond(500 * USD);
        _deposit(alice, 10_000 * USD);
        assertEq(s.requiredBond(), 500 * USD, "floor = 5% of accounted deposits");
        uint256 capBefore = s.depositCapacity();
        usdc.mint(address(this), 1_000_000 * USD);
        usdc.transfer(address(vault), 1_000_000 * USD); // donation, not a deposit()
        assertEq(vault.tvl(), 10_000 * USD, "tvl ignores donations");
        assertEq(s.requiredBond(), 500 * USD, "floor unchanged by a donation");
        assertEq(s.depositCapacity(), capBefore, "capacity unchanged by a donation");
    }

    function test_withdrawals_only_from_settled_batches() public {
        // before any settlement, the vault has no withdrawals root → nothing claims
        _bond(500 * USD);
        _deposit(address(this), 10_000 * USD);
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(alice, 1000 * USD, 1, bytes32(0), proof);
    }

    function test_settle_requires_the_clock_anchor() public {
        // The settlement verifies only clock-bound proofs: the plain commitment (what the
        // mock inner verifier would accept on its own) is refused with or without an
        // anchor, and the bound proof settles once the anchor is registered.
        bytes32 next = bytes32(uint256(2));
        bytes32 m = keccak256("b0");
        bytes32 base = s.publicCommitment(GENESIS, m, next, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, m, next, bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, abi.encode(base));
        bytes memory bound = _clockProof(GENESIS, base, 0);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, m, next, bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, abi.encodePacked(base));
        s.settleBatch(GENESIS, m, next, bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, bound);
        assertEq(s.currentStateRoot(), next, "bound proof settles");
        // the anchor is consumed: the same proof cannot settle the next batch
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(next, m, bytes32(uint256(3)), bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, bound);
    }

    function test_uncredited_deposit_is_refunded_after_close_only() public {
        _bond(500 * USD);
        _deposit(alice, 1000 * USD); // id 0: credited below
        bytes32 bobCommit = _deposit(bob, 2000 * USD); // id 1: never credited

        // the batch consumes only id 0 and authorizes alice's 1,000 USDC withdrawal
        bytes32 leaf = keccak256(abi.encodePacked(alice, 1000 * USD, uint256(1)));
        _settle(GENESIS, keccak256("b0"), bytes32(uint256(2)), leaf, 1);
        assertEq(vault.refundableOutstanding(), 2000 * USD, "bob's principal is uncredited");

        // no refund while live
        vm.expectRevert(CollateralVault.NotCloseOnly.selector);
        vault.refundDeposit(1, bob, bobCommit, 2000 * USD, bob);

        // governance (this contract) enters close-only; the consumed count freezes at 1
        s.enterCloseOnly();
        assertTrue(s.closeOnly(), "close-only");
        assertFalse(s.acceptingDeposits(), "no new deposits");
        (bytes32 c2, uint64 v2, bytes memory sig2) = _prepareDeposit(alice, 1);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.InCloseOnly.selector);
        vault.deposit(1, c2, v2, sig2);

        // the credited deposit is not refundable; the uncredited one is, to its payer
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(0, alice, bytes32(0), 1000 * USD, alice);
        uint256 bobBefore = usdc.balanceOf(bob);
        vault.refundDeposit(1, bob, bobCommit, 2000 * USD, bob); // permissionless
        assertEq(usdc.balanceOf(bob) - bobBefore, 2000 * USD, "principal refunded to the payer");
        vm.expectRevert(CollateralVault.AlreadyRefunded.selector);
        vault.refundDeposit(1, bob, bobCommit, 2000 * USD, bob);
        assertEq(vault.refundableOutstanding(), 0, "nothing left to refund");

        // the settled withdrawal stays claimable in close-only
        vault.claim(alice, 1000 * USD, 1, leaf, new bytes32[](0));
        assertEq(usdc.balanceOf(alice), 1000 * USD + 1, "alice claimed (plus her unused faucet unit)");
        assertEq(vault.tvl(), 0, "vault fully drained by claim + refund");
        assertEq(usdc.balanceOf(address(vault)), 0, "no stranded balance");

        // the bond is withdrawable in close-only once no TVL needs it
        s.withdrawBond(500 * USD);
        assertEq(s.sequencerBond(), 0, "bond returned");
    }

    function test_claim_never_draws_on_uncredited_principal() public {
        _bond(500 * USD);
        _deposit(alice, 1000 * USD); // id 0: credited
        bytes32 bobCommit = _deposit(bob, 2000 * USD); // id 1: uncredited
        // an over-crediting root (accepted by the mock prover) authorizes 1,500 USDC to
        // alice against her 1,000 USDC deposit
        bytes32 over = keccak256(abi.encodePacked(alice, 1500 * USD, uint256(1)));
        _settle(GENESIS, keccak256("b0"), bytes32(uint256(2)), over, 1);
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(alice, 1500 * USD, 1, over, new bytes32[](0));
        // bob's principal stays whole for his refund
        s.enterCloseOnly();
        vault.refundDeposit(1, bob, bobCommit, 2000 * USD, bob);
        assertEq(usdc.balanceOf(bob), 2000 * USD, "uncredited principal refunded in full");
    }

    receive() external payable {}
}
