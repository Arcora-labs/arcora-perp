// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {CollateralVault} from "../src/CollateralVault.sol";

contract CollateralVaultTest is MiniTest {
    CollateralVault internal vault;
    // this contract acts as the settlement authority
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        vault = new CollateralVault(address(this));
    }

    function test_deposit_accrues_total() public {
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        vault.deposit{value: 3 ether}();
        assertEq(vault.totalDeposited(), 3 ether, "deposit tracked");
        assertEq(address(vault).balance, 3 ether, "vault holds funds");
    }

    function test_only_settlement_publishes_root() public {
        vm.prank(alice);
        vm.expectRevert(CollateralVault.NotSettlement.selector);
        vault.publishWithdrawals(keccak256("r"), 1);
    }

    function test_claim_against_settled_root() public {
        // fund the vault
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 10 ether}();

        // a single-leaf withdrawals root authorizing alice to withdraw 2 ETH
        uint256 amount = 2 ether;
        uint256 nonce = 1;
        bytes32 leaf = keccak256(abi.encodePacked(alice, amount, nonce));
        // single-leaf tree: root == leaf, empty proof
        vault.publishWithdrawals(leaf, 0);

        bytes32[] memory proof = new bytes32[](0);
        uint256 before = alice.balance;
        vault.claim(alice, amount, nonce, proof);
        assertEq(alice.balance - before, amount, "alice received funds");

        // double-claim rejected
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(alice, amount, nonce, proof);
    }

    function test_claim_with_bad_proof_rejected() public {
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 10 ether}();
        vault.publishWithdrawals(keccak256("some-other-root"), 0);

        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(bob, 1 ether, 1, proof);
    }

    function test_two_leaf_merkle_claim() public {
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 10 ether}();

        // build a 2-leaf tree: leaves L_alice, L_bob; root = hash(sorted(pair))
        bytes32 la = keccak256(abi.encodePacked(alice, uint256(2 ether), uint256(1)));
        bytes32 lb = keccak256(abi.encodePacked(bob, uint256(1 ether), uint256(2)));
        bytes32 root = la <= lb ? keccak256(abi.encodePacked(la, lb)) : keccak256(abi.encodePacked(lb, la));
        vault.publishWithdrawals(root, 0);

        // alice claims; her proof is [lb]
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = lb;
        uint256 before = alice.balance;
        vault.claim(alice, 2 ether, 1, proof);
        assertEq(alice.balance - before, 2 ether, "alice claimed via 2-leaf proof");
    }

    receive() external payable {}
}
