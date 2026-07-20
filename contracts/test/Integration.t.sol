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
    /// Stand-in shielded-note owner: these tests exercise the end-to-end flow, not the
    /// SEC-019 deposit hash chain (see CollateralVault.t.sol for that).
    bytes32 internal constant TEST_OWNER_COMMIT = keccak256("dark-perp.test.note-owner");

    // this contract is the sequencer
    function setUp() public {
        verifier = new MockZkVerifier();
        s = new DarkPerpSettlement(address(this), address(0xE), verifier, GENESIS, 100, 50, 0, 0, address(this), 0);
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc));
        s.setVault(address(vault));
    }

    function _proof(bytes32 prev, bytes32 m, bytes32 n, bytes32 ord, bytes32 wd) internal view returns (bytes memory) {
        return abi.encode(s.publicCommitment(prev, m, n, ord, wd, bytes32(0), vault.depositChainTip()));
    }

    /// The vault's live SEC-019 deposit head, which `settleBatch` now pins against.
    /// Read into locals BEFORE arming `vm.expectRevert` — these are external
    /// staticcalls, and the cheatcode binds to the very next external call.
    function _head() internal view returns (bytes32 tip, uint64 count) {
        return (vault.depositChainTip(), vault.depositCount());
    }

    /// Settles a batch with the given roots at the vault's live deposit head, building
    /// the matching proof. Extracted so the (now 9-argument) settle call does not blow
    /// the stack in tests that already hold many locals.
    function _settle(bytes32 prev, bytes32 manifest, bytes32 newRoot, bytes32 ord, bytes32 wd) internal {
        (bytes32 dTip, uint64 dCount) = _head();
        bytes32 commitment = s.publicCommitment(prev, manifest, newRoot, ord, wd, bytes32(0), dTip);
        s.settleBatch(prev, manifest, newRoot, ord, wd, bytes32(0), dTip, dCount, abi.encode(commitment));
    }

    function _deposit(address who, uint256 amount) internal {
        usdc.mint(who, amount);
        vm.startPrank(who);
        usdc.approve(address(vault), amount);
        vault.deposit(amount, TEST_OWNER_COMMIT);
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
        // the batch credits alice's real deposit, so it settles exactly at the L1 head
        _settle(GENESIS, manifest, newRoot, bytes32(0), leaf);

        // the vault now carries that settled withdrawals root
        assertEq(vault.withdrawalsRoot(), leaf, "vault got the settled withdrawals root");

        // alice claims; USDC releases from the vault, gated on SETTLED state
        bytes32[] memory proof = new bytes32[](0);
        uint256 before = usdc.balanceOf(alice);
        vault.claim(alice, amount, nonce, vault.withdrawalsRoot(), proof);
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
        (bytes32 dTip, uint64 dCount) = _head();

        // under-bonded → cannot advance state (the bond floor is checked before the
        // SEC-019 deposit pin, and these args satisfy the pin anyway)
        vm.expectRevert(DarkPerpSettlement.UnderBonded.selector);
        s.settleBatch(GENESIS, m, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, proof);

        // post exactly the floor → settles
        _bond(500 * USD);
        s.settleBatch(GENESIS, m, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, proof);
        assertEq(s.currentStateRoot(), newRoot, "settled once adequately bonded");

        // TVL grows 10x → the floor grows past the posted bond again
        _deposit(alice, 90_000 * USD); // TVL now 100,000 USDC → floor 5,000 USDC
        assertEq(s.requiredBond(), 5000 * USD, "floor tracks TVL up");
        bytes32 newRoot2 = bytes32(uint256(3));
        bytes32 m2 = keccak256("b1");
        bytes memory proof2 = _proof(newRoot, m2, newRoot2, bytes32(0), bytes32(0));
        // the second deposit advanced the L1 head, so re-read it
        (bytes32 dTip2, uint64 dCount2) = _head();
        vm.expectRevert(DarkPerpSettlement.UnderBonded.selector);
        s.settleBatch(newRoot, m2, newRoot2, bytes32(0), bytes32(0), bytes32(0), dTip2, dCount2, proof2);
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
        vault.claim(alice, 1000 * USD, 1, bytes32(0), proof);
    }

    receive() external payable {}
}
