// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";

contract CollateralVaultTest is MiniTest {
    CollateralVault internal vault;
    MockUSDC internal usdc;
    // this contract acts as the settlement authority
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    // USDC has 6 decimals; use whole-dollar units scaled by 1e6.
    uint256 internal constant USD = 1e6;

    function setUp() public {
        usdc = new MockUSDC();
        vault = new CollateralVault(address(this), address(usdc));
    }

    /// Mint USDC to `who`, then (as `who`) approve + deposit `amount` into the vault.
    function _deposit(address who, uint256 amount) internal {
        usdc.mint(who, amount);
        vm.startPrank(who);
        usdc.approve(address(vault), amount);
        vault.deposit(amount);
        vm.stopPrank();
    }

    function test_deposit_accrues_total() public {
        _deposit(alice, 3000 * USD);
        assertEq(vault.totalDeposited(), 3000 * USD, "deposit tracked");
        assertEq(usdc.balanceOf(address(vault)), 3000 * USD, "vault holds USDC");
        assertEq(vault.tvl(), 3000 * USD, "tvl reflects custodied USDC");
    }

    function test_deposit_requires_approval() public {
        usdc.mint(alice, 100 * USD);
        vm.prank(alice);
        // no approval → transferFrom reverts inside deposit
        vm.expectRevert(MockUSDC.InsufficientAllowance.selector);
        vault.deposit(100 * USD);
    }

    function test_only_settlement_publishes_root() public {
        vm.prank(alice);
        vm.expectRevert(CollateralVault.NotSettlement.selector);
        vault.publishWithdrawals(keccak256("r"), 1);
    }

    function test_claim_against_settled_root() public {
        // fund the vault
        _deposit(address(this), 10_000 * USD);

        // a single-leaf withdrawals root authorizing alice to withdraw 2,000 USDC
        uint256 amount = 2000 * USD;
        uint256 nonce = 1;
        bytes32 leaf = keccak256(abi.encodePacked(alice, amount, nonce));
        // single-leaf tree: root == leaf, empty proof
        vault.publishWithdrawals(leaf, 0);

        bytes32[] memory proof = new bytes32[](0);
        uint256 before = usdc.balanceOf(alice);
        vault.claim(alice, amount, nonce, proof);
        assertEq(usdc.balanceOf(alice) - before, amount, "alice received USDC");
        assertEq(vault.totalWithdrawn(), amount, "withdrawn tracked");

        // double-claim rejected
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(alice, amount, nonce, proof);
    }

    function test_claim_with_bad_proof_rejected() public {
        _deposit(address(this), 10_000 * USD);
        vault.publishWithdrawals(keccak256("some-other-root"), 0);

        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(bob, 1000 * USD, 1, proof);
    }

    function test_two_leaf_merkle_claim() public {
        _deposit(address(this), 10_000 * USD);

        // build a 2-leaf tree: leaves L_alice, L_bob; root = hash(sorted(pair))
        bytes32 la = keccak256(abi.encodePacked(alice, uint256(2000 * USD), uint256(1)));
        bytes32 lb = keccak256(abi.encodePacked(bob, uint256(1000 * USD), uint256(2)));
        bytes32 root = la <= lb ? keccak256(abi.encodePacked(la, lb)) : keccak256(abi.encodePacked(lb, la));
        vault.publishWithdrawals(root, 0);

        // alice claims; her proof is [lb]
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = lb;
        uint256 before = usdc.balanceOf(alice);
        vault.claim(alice, 2000 * USD, 1, proof);
        assertEq(usdc.balanceOf(alice) - before, 2000 * USD, "alice claimed via 2-leaf proof");
    }

    function test_publishing_a_new_root_strands_an_unclaimed_leaf() public {
        // Documents P6: publishWithdrawals OVERWRITES the root, so a withdrawal
        // authorized in one batch is unclaimable once the next batch publishes a root
        // that does not carry it forward. The cumulative-root invariant (prover-side)
        // is what prevents this in production — see CollateralVault.publishWithdrawals
        // and the gateway's cumulative-root builder.
        _deposit(address(this), 10_000 * USD);

        uint256 amount = 2000 * USD;
        uint256 nonce = 1;
        bytes32 leaf = keccak256(abi.encodePacked(alice, amount, nonce));
        vault.publishWithdrawals(leaf, 0); // batch 0 authorizes alice

        // batch 1 settles with a root that does NOT carry alice's (unclaimed) leaf
        vault.publishWithdrawals(keccak256("batch-1-without-alice"), 1);

        // alice can no longer claim — her authorized withdrawal is stranded
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(alice, amount, nonce, proof);
    }
}
