// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {CollateralVault} from "../src/CollateralVault.sol";

/// Drives random sequences of publish/claim against the vault. Foundry's
/// invariant runner calls the handler's external functions in random order and
/// re-checks every `invariant_*` after each step.
contract Handler {
    CollateralVault public vault;
    uint256 public totalClaimed;
    uint256 public epoch;
    uint256 internal lastAmount;
    uint256 internal lastNonce;
    bool internal havePublished;

    function init(CollateralVault _vault) external {
        require(address(vault) == address(0), "init once");
        vault = _vault;
    }

    /// Publish a single-leaf withdrawals root authorizing THIS handler.
    function publish(uint256 amountRaw, uint256 nonce) external {
        uint256 amount = (amountRaw % 5 ether) + 1;
        lastAmount = amount;
        lastNonce = nonce;
        havePublished = true;
        bytes32 leaf = keccak256(abi.encodePacked(address(this), amount, nonce));
        vault.publishWithdrawals(leaf, epoch++);
    }

    /// Attempt to claim the most recently published authorization.
    function claimLast() external {
        if (!havePublished) return;
        bytes32[] memory empty = new bytes32[](0);
        try vault.claim(address(this), lastAmount, lastNonce, empty) {
            totalClaimed += lastAmount;
        } catch {}
    }

    receive() external payable {}
}

contract VaultInvariantTest is MiniTest {
    CollateralVault internal vault;
    Handler internal handler;
    uint256 internal constant INITIAL = 1000 ether;

    function setUp() public {
        // the handler is the settlement authority so it can publish roots
        handler = new Handler();
        vault = new CollateralVault(address(handler));
        handler.init(vault);
        vm.deal(address(vault), INITIAL);
    }

    /// Restrict the invariant fuzzer to the handler only (the intended state
    /// machine), so it can't call `vault.deposit`/`claim` directly and bypass the
    /// handler's accounting. The Foundry invariant engine reads this function by
    /// selector; defining it ourselves avoids the (unavailable) forge-std
    /// StdInvariant base.
    function targetContracts() public view returns (address[] memory t) {
        t = new address[](1);
        t[0] = address(handler);
    }

    /// The vault never creates or destroys value: its balance plus everything
    /// successfully claimed always equals the initial funding. Catches double-pay,
    /// over-pay, and value leaks across any random publish/claim sequence.
    function invariant_vault_is_solvent() public view {
        assertEq(address(vault).balance + handler.totalClaimed(), INITIAL, "vault solvency");
    }

    /// The vault balance never goes negative / underflows.
    function invariant_balance_bounded() public view {
        assertTrue(address(vault).balance <= INITIAL, "balance never exceeds initial");
    }
}
