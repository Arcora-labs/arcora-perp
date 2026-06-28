// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// Full on-chain wiring: a user deposits USDC, settlement publishes a settled
/// batch's withdrawals root to the vault, and the user claims their USDC from it.
/// This exercises the §3 guarantee end-to-end on L1 — funds release only from
/// SETTLED state, via the vault, never by the sequencer directly — with the
/// USDC-denominated sequencer bond gating settlement (audit Q1).
contract IntegrationTest is MiniTest {
    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockZkVerifier internal verifier;

    address internal alice = address(0xA11CE);
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    uint256 internal constant USD = 1e6;

    // this contract is the sequencer
    function setUp() public {
        verifier = new MockZkVerifier();
        s = new DarkPerpSettlement(address(this), address(0xE), verifier, GENESIS, 100, 50, 0);
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc));
        s.setVault(address(vault));
    }

    function _proof(bytes32 prev, bytes32 m, bytes32 n, bytes32 ord, bytes32 wd)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(s.publicCommitment(prev, m, n, ord, wd));
    }

    function _deposit(address who, uint256 amount) internal {
        usdc.mint(who, amount);
        vm.startPrank(who);
        usdc.approve(address(vault), amount);
        vault.deposit(amount);
        vm.stopPrank();
    }

    /// The sequencer (this contract) posts a USDC bond of `amount`.
    function _bond(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    function test_deposit_settle_then_claim_from_vault() public {
        // a user deposits USDC into the vault (off-chain a note is minted)
        _deposit(alice, 5000 * USD);
        assertEq(vault.tvl(), 5000 * USD, "vault funded");

        // the bond must cover 5% of TVL = 250 USDC before settling (audit Q1).
        _bond(250 * USD);

        // settlement settles a batch that authorizes alice to withdraw 2,000 USDC.
        // single-leaf withdrawals tree → root == leaf, empty proof.
        uint256 amount = 2000 * USD;
        uint256 nonce = 7;
        bytes32 leaf = keccak256(abi.encodePacked(alice, amount, nonce));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("batch-0");
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), leaf, _proof(GENESIS, manifest, newRoot, bytes32(0), leaf));

        // the vault now carries that settled withdrawals root
        assertEq(vault.withdrawalsRoot(), leaf, "vault got the settled withdrawals root");

        // alice claims; USDC releases from the vault, gated on SETTLED state
        bytes32[] memory proof = new bytes32[](0);
        uint256 before = usdc.balanceOf(alice);
        vault.claim(alice, amount, nonce, proof);
        assertEq(usdc.balanceOf(alice) - before, amount, "alice withdrew USDC from settled state");

        // the state root advanced on L1
        assertEq(s.currentStateRoot(), newRoot, "root advanced to settled batch");
    }

    function test_settle_requires_a_bond_scaled_to_tvl() public {
        // The bond floor scales with custodied TVL (audit Q1): with 10,000 USDC in
        // the vault the floor is 5% = 500 USDC. Settling under-bonded reverts; once
        // the bond meets the floor it settles; and the floor grows as TVL grows.
        _deposit(alice, 10_000 * USD);
        assertEq(s.requiredBond(), 500 * USD, "floor = 5% of 10,000 USDC TVL");

        bytes32 newRoot = bytes32(uint256(2));
        bytes32 m = keccak256("b0");
        bytes memory proof = _proof(GENESIS, m, newRoot, bytes32(0), bytes32(0));

        // under-bonded → cannot advance state
        vm.expectRevert(DarkPerpSettlement.UnderBonded.selector);
        s.settleBatch(GENESIS, m, newRoot, bytes32(0), bytes32(0), proof);

        // post exactly the floor → settles
        _bond(500 * USD);
        s.settleBatch(GENESIS, m, newRoot, bytes32(0), bytes32(0), proof);
        assertEq(s.currentStateRoot(), newRoot, "settled once adequately bonded");

        // TVL grows 10x → the floor grows past the posted bond again
        _deposit(alice, 90_000 * USD); // TVL now 100,000 USDC → floor 5,000 USDC
        assertEq(s.requiredBond(), 5000 * USD, "floor tracks TVL up");
        bytes32 newRoot2 = bytes32(uint256(3));
        bytes32 m2 = keccak256("b1");
        bytes memory proof2 = _proof(newRoot, m2, newRoot2, bytes32(0), bytes32(0));
        vm.expectRevert(DarkPerpSettlement.UnderBonded.selector);
        s.settleBatch(newRoot, m2, newRoot2, bytes32(0), bytes32(0), proof2);
    }

    function test_bond_floor_immune_to_donations() public {
        // requiredBond scales off ACCOUNTED net deposits, not the raw token balance,
        // so a bare token.transfer (donation, bypassing deposit) cannot inflate the
        // floor and stall settlement (review fix).
        _deposit(alice, 10_000 * USD);
        assertEq(s.requiredBond(), 500 * USD, "floor = 5% of accounted deposits");
        usdc.mint(address(this), 1_000_000 * USD);
        usdc.transfer(address(vault), 1_000_000 * USD); // donation, not a deposit()
        assertEq(vault.tvl(), 10_000 * USD, "tvl ignores donations");
        assertEq(s.requiredBond(), 500 * USD, "floor unchanged by a donation");
    }

    function test_withdrawals_only_from_settled_batches() public {
        // before any settlement, the vault has no withdrawals root → nothing claims
        _deposit(address(this), 10_000 * USD);
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(alice, 1000 * USD, 1, proof);
    }

    receive() external payable {}
}
