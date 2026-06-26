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
        s = new DarkPerpSettlement(address(this), address(0xE), verifier, GENESIS, 100, 50, 0);
        vault = new CollateralVault(address(s));
        s.setVault(address(vault));
    }

    function _proof(bytes32 prev, bytes32 m, bytes32 n, bytes32 ord, bytes32 wd)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(s.publicCommitment(prev, m, n, ord, wd));
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
        // the bond must cover the TVL at risk before settling (audit Q1).
        vm.deal(address(this), 1 ether);
        s.postBond{value: 1 ether}();
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), leaf, _proof(GENESIS, manifest, newRoot, bytes32(0), leaf));

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

    function test_settle_requires_a_bond_scaled_to_tvl() public {
        // The bond floor scales with custodied TVL (audit Q1): with 10 ETH in the
        // vault the floor is 5% = 0.5 ETH. Settling under-bonded reverts; once the
        // bond meets the floor it settles; and the floor grows as TVL grows.
        vm.deal(alice, 100 ether);
        vm.prank(alice);
        vault.deposit{value: 10 ether}();
        assertEq(s.requiredBond(), 0.5 ether, "floor = 5% of 10 ETH TVL");

        bytes32 newRoot = bytes32(uint256(2));
        bytes32 m = keccak256("b0");
        bytes memory proof = _proof(GENESIS, m, newRoot, bytes32(0), bytes32(0));

        // under-bonded → cannot advance state
        vm.expectRevert(DarkPerpSettlement.UnderBonded.selector);
        s.settleBatch(GENESIS, m, newRoot, bytes32(0), bytes32(0), proof);

        // post exactly the floor → settles
        vm.deal(address(this), 10 ether);
        s.postBond{value: 0.5 ether}();
        s.settleBatch(GENESIS, m, newRoot, bytes32(0), bytes32(0), proof);
        assertEq(s.currentStateRoot(), newRoot, "settled once adequately bonded");

        // TVL grows 10x → the floor grows past the posted bond again
        vm.prank(alice);
        vault.deposit{value: 90 ether}(); // TVL now 100 ETH → floor 5 ETH
        assertEq(s.requiredBond(), 5 ether, "floor tracks TVL up");
        bytes32 newRoot2 = bytes32(uint256(3));
        bytes32 m2 = keccak256("b1");
        bytes memory proof2 = _proof(newRoot, m2, newRoot2, bytes32(0), bytes32(0));
        vm.expectRevert(DarkPerpSettlement.UnderBonded.selector);
        s.settleBatch(newRoot, m2, newRoot2, bytes32(0), bytes32(0), proof2);
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
