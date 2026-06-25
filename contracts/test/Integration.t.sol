// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// Full on-chain wiring: settlement publishes a settled batch's withdrawals root
/// to the vault, and the user claims their funds from it. This exercises the §3
/// guarantee end-to-end on L1 — funds release only from SETTLED state, via the
/// vault, never by the sequencer directly.
contract IntegrationTest is MiniTest {
    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockZkVerifier internal verifier;

    address internal alice = address(0xA11CE);
    bytes32 internal constant GENESIS = bytes32(uint256(1));

    // this contract is the sequencer
    function setUp() public {
        verifier = new MockZkVerifier();
        s = new DarkPerpSettlement(address(this), address(0xE), verifier, GENESIS, 100, 50);
        vault = new CollateralVault(address(s));
        s.setVault(address(vault));
    }

    function _proof(bytes32 prev, bytes32 m, bytes32 n) internal view returns (bytes memory) {
        return abi.encode(s.publicCommitment(prev, m, n));
    }

    function test_deposit_settle_then_claim_from_vault() public {
        // a user deposits into the vault (off-chain a note is minted)
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        vault.deposit{value: 5 ether}();
        assertEq(address(vault).balance, 5 ether, "vault funded");

        // settlement settles a batch that authorizes alice to withdraw 2 ETH.
        // single-leaf withdrawals tree → root == leaf, empty proof.
        uint256 amount = 2 ether;
        uint256 nonce = 7;
        bytes32 leaf = keccak256(abi.encodePacked(alice, amount, nonce));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("batch-0");
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), leaf, _proof(GENESIS, manifest, newRoot));

        // the vault now carries that settled withdrawals root
        assertEq(vault.withdrawalsRoot(), leaf, "vault got the settled withdrawals root");

        // alice claims; funds release from the vault, gated on SETTLED state
        bytes32[] memory proof = new bytes32[](0);
        uint256 before = alice.balance;
        vault.claim(alice, amount, nonce, proof);
        assertEq(alice.balance - before, amount, "alice withdrew from settled state");

        // the state root advanced on L1
        assertEq(s.currentStateRoot(), newRoot, "root advanced to settled batch");
    }

    function test_withdrawals_only_from_settled_batches() public {
        // before any settlement, the vault has no withdrawals root → nothing claims
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 10 ether}();
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(alice, 1 ether, 1, proof);
    }

    receive() external payable {}
}
