// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";

/// @title WindDownSinkClaimTest
/// @notice The wind-down's reserve payout as the vault sees it. The final settlement
/// (phase 1) publishes a withdrawals root that is one leaf: the reserves paid to the
/// genesis-bound wind-down recipient with the next withdrawal nonce. The leaf is an
/// ordinary withdrawal leaf, so the permissionless claim pays it with an empty proof,
/// once; and a deposit the settled state never credited stays refundable in full
/// beside it. Mock proofs only (MockClockVerifier: MockZkVerifier's acceptance rule
/// behind the clock-verifier shape the settlement requires); no contract source is
/// changed by this test.
contract WindDownSinkClaimTest is MiniTest {
    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockClockVerifier internal verifier;

    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    uint256 internal constant GW_PK = 0x6A7E;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    uint256 internal constant GRACE = SettlementTestConfig.FINAL_SETTLE_GRACE_BLOCKS;
    uint256 internal constant PERMIT_TTL = 1_800;
    uint256 internal constant USD = 1e6;

    /// The wind-down recipient bound in the genesis root.
    address internal constant RECIPIENT = address(0xC0FFEE);
    address internal constant USER = address(0xFEED);
    address internal constant LATE = address(0x1A7E);

    uint256 internal commitNonce;

    function setUp() public {
        verifier = new MockClockVerifier();
        s = new DarkPerpSettlement(SettlementTestConfig.defaults(address(this), vm.addr(ENCLAVE_PK), verifier, GENESIS));
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
    }

    // --- helpers ----------------------------------------------------------------

    function _bond(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    /// A permitted deposit of `amount` by `from`, with the bond topped up to cover it.
    function _deposit(address from, uint256 amount) internal returns (uint64 id, bytes32 commit) {
        uint256 need = ((vault.tvl() + amount) * s.BOND_BPS()) / 10_000;
        uint256 have = s.sequencerBond();
        if (need > have) _bond(need - have);
        commit = keccak256(abi.encodePacked("owner-commit", ++commitNonce));
        uint64 validUntil = uint64(block.timestamp + PERMIT_TTL);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, from, commit, amount, validUntil);
        usdc.mint(from, amount);
        vm.prank(from);
        usdc.approve(address(vault), amount);
        id = vault.depositCount();
        vm.prank(from);
        vault.deposit(amount, commit, validUntil, sig);
    }

    /// An ordinary batch that credits the first `n` deposits and publishes `wroot`.
    function _settle(uint64 n, bytes32 wroot) internal {
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256(abi.encodePacked("batch", s.batchCount()));
        bytes32 tip = vault.depositTipAt(n);
        bytes32 commitment = s.publicCommitment(prev, bytes32("m"), next, bytes32(0), wroot, bytes32(0), tip);
        s.settleBatch(prev, bytes32("m"), next, bytes32(0), wroot, bytes32(0), tip, n, abi.encode(commitment));
    }

    /// The phase-1 final settlement at the frozen consumed prefix, publishing `wroot`.
    function _finalSettle(bytes32 wroot) internal {
        bytes32 prev = s.currentStateRoot();
        uint64 n = s.consumedDepositCount();
        bytes32 tip = vault.depositTipAt(n);
        bytes32 next = keccak256("wind-down");
        bytes32 commitment = s.windDownCommitment(prev, bytes32("m"), next, bytes32(0), wroot, bytes32(0), tip, 1);
        s.finalSettle(prev, bytes32("m"), next, bytes32(0), wroot, bytes32(0), tip, n, abi.encode(commitment));
    }

    function _leaf(address to, uint256 amount, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(to, amount, nonce));
    }

    // --- tests ------------------------------------------------------------------

    /// Before close-only the user withdraws 40 of a credited 100 (nonce 1), and a late
    /// deposit of 50 lands that no settled batch credits. The final settlement's root
    /// is the single sink leaf: the remaining 60 to the recipient with nonce 2, the
    /// last nonce plus one. Anyone may claim it with an empty proof, it pays once, and
    /// the late deposit is refunded in full beside it.
    function test_the_sink_leaf_is_claimed_once_with_an_empty_proof() public {
        _deposit(USER, 100 * USD);
        bytes32 userLeaf = _leaf(USER, 40 * USD, 1);
        _settle(1, userLeaf);
        vault.claim(USER, 40 * USD, 1, userLeaf, new bytes32[](0));
        assertEq(usdc.balanceOf(USER), 40 * USD, "the live withdrawal pays");

        (uint64 lateId, bytes32 lateCommit) = _deposit(LATE, 50 * USD);
        s.enterCloseOnly();
        vm.roll(block.number + GRACE);

        uint256 lastNonce = 1;
        bytes32 sink = _leaf(RECIPIENT, 60 * USD, lastNonce + 1);
        _finalSettle(sink);
        assertEq(vault.refundableOutstanding(), 50 * USD, "the late deposit is reserved");

        // The claim is permissionless: an outsider submits it, the recipient is paid.
        vm.prank(address(0xBAD));
        vault.claim(RECIPIENT, 60 * USD, lastNonce + 1, sink, new bytes32[](0));
        assertEq(usdc.balanceOf(RECIPIENT), 60 * USD, "the sink leaf pays the recipient");

        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(RECIPIENT, 60 * USD, lastNonce + 1, sink, new bytes32[](0));

        vault.refundDeposit(lateId, LATE, lateCommit, 50 * USD, LATE);
        assertEq(usdc.balanceOf(LATE), 50 * USD, "uncredited principal refunded in full");
        assertEq(vault.refundableOutstanding(), 0, "nothing left reserved");
        assertEq(usdc.balanceOf(address(vault)), 0, "every credited and uncredited unit has left");
    }

    /// The sink leaf cannot draw on the principal reserved for the uncredited deposit:
    /// a payout larger than the credited remainder is refused, whatever the root says.
    function test_the_sink_leaf_cannot_draw_on_uncredited_principal() public {
        _deposit(USER, 100 * USD);
        _settle(1, bytes32(0));
        (uint64 lateId, bytes32 lateCommit) = _deposit(LATE, 50 * USD);
        s.enterCloseOnly();
        vm.roll(block.number + GRACE);

        bytes32 sink = _leaf(RECIPIENT, 120 * USD, 1);
        _finalSettle(sink);
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(RECIPIENT, 120 * USD, 1, sink, new bytes32[](0));

        vault.refundDeposit(lateId, LATE, lateCommit, 50 * USD, LATE);
        assertEq(usdc.balanceOf(LATE), 50 * USD, "uncredited principal refunded in full");
    }
}
