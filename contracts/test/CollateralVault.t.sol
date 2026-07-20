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

    /// Stand-in owner COMMIT (`keccak256(owner ‖ blind)`, spec §1a) for the vault
    /// tests that are not about the SEC-019 deposit hash-chain itself (they only need
    /// *some* well-formed 32-byte field; the vault never interprets it).
    bytes32 internal constant DEFAULT_TEST_OWNER_COMMIT = keccak256("dark-perp.test.default-owner");

    // ---------------------------------------------------------------------
    // SEC-019 canonical known-answer vectors. These are pinned by the Rust side
    // (`crates/perp-core/src/merkle.rs`, KAT_DEPOSIT_LEAF / KAT_DEPOSIT_TIP2) and
    // MUST be reproduced byte-for-byte here: the in-circuit `deposits_root` is only
    // a binding to real L1 deposits if L1 and the circuit fold the *same* bytes.
    // Leaf: keccak256(abi.encodePacked(address from, bytes32 ownerCommit, uint256 amount, uint256 id))
    // Fold: keccak256(abi.encodePacked(bytes32 tip, bytes32 leaf)), genesis tip = bytes32(0)
    // ---------------------------------------------------------------------
    address internal constant KAT_FROM_0 = address(0x1111111111111111111111111111111111111111);
    bytes32 internal constant KAT_OWNER_COMMIT_0 = bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222));
    uint256 internal constant KAT_AMOUNT_0 = 1000;

    address internal constant KAT_FROM_1 = address(0x3333333333333333333333333333333333333333);
    bytes32 internal constant KAT_OWNER_COMMIT_1 = bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444));
    uint256 internal constant KAT_AMOUNT_1 = 500;

    /// deposit_leaf(0x11*20, 0x22*32, 1000, id=0) — Rust KAT_DEPOSIT_LEAF.
    bytes32 internal constant KAT_LEAF = 0xc73050f50b59f4f5e979a977daca61b851dde0b8783079f19612eaa372eea829;
    /// fold(fold(0, leaf0), leaf1) — Rust KAT_DEPOSIT_TIP2.
    bytes32 internal constant KAT_TIP2 = 0x5b73a880215f57b806542be075aff06956e28269482bf9b0db854b480e7ee5ca;

    function setUp() public {
        usdc = new MockUSDC();
        vault = new CollateralVault(address(this), address(usdc));
    }

    /// This contract stands in as the settlement authority; the vault reads its
    /// close-only state on deposit, which stays false throughout these vault tests.
    function closeOnly() external pure returns (bool) {
        return false;
    }

    /// Mint USDC to `who`, then (as `who`) approve + deposit `amount` into the vault,
    /// crediting the shielded note to the owner committed to by `ownerCommit`.
    function _depositAs(address who, uint256 amount, bytes32 ownerCommit) internal {
        usdc.mint(who, amount);
        vm.startPrank(who);
        usdc.approve(address(vault), amount);
        vault.deposit(amount, ownerCommit);
        vm.stopPrank();
    }

    /// `_depositAs` with a stand-in commit, for tests that don't exercise the hash chain.
    function _deposit(address who, uint256 amount) internal {
        _depositAs(who, amount, DEFAULT_TEST_OWNER_COMMIT);
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
        vault.deposit(100 * USD, DEFAULT_TEST_OWNER_COMMIT);
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
        vault.claim(alice, amount, nonce, vault.withdrawalsRoot(), proof);
        assertEq(usdc.balanceOf(alice) - before, amount, "alice received USDC");
        assertEq(vault.totalWithdrawn(), amount, "withdrawn tracked");

        // double-claim rejected
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(alice, amount, nonce, leaf, proof);
    }

    function test_claim_with_bad_proof_rejected() public {
        _deposit(address(this), 10_000 * USD);
        vault.publishWithdrawals(keccak256("some-other-root"), 0);

        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(bob, 1000 * USD, 1, keccak256("some-other-root"), proof);
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
        vault.claim(alice, 2000 * USD, 1, vault.withdrawalsRoot(), proof);
        assertEq(usdc.balanceOf(alice) - before, 2000 * USD, "alice claimed via 2-leaf proof");
    }

    function test_older_published_root_is_still_claimable() public {
        // audit DP-012: publishing a LATER cumulative root that omits an older
        // authorized-but-unclaimed leaf must NOT strand it. The claim proves against the
        // older root (still remembered via rootPublished), so a lost/incomplete off-chain
        // rebuild — or a mere overwrite — can no longer make an authorized withdrawal
        // unclaimable; claimed[leaf] still prevents double-claim.
        _deposit(address(this), 10_000 * USD);

        uint256 amount = 2000 * USD;
        uint256 nonce = 1;
        bytes32 leaf = keccak256(abi.encodePacked(alice, amount, nonce));
        bytes32 batch0Root = leaf; // single-leaf tree: the root IS the leaf
        vault.publishWithdrawals(batch0Root, 0); // batch 0 authorizes alice

        // batch 1 settles with a root that does NOT carry alice's (unclaimed) leaf
        vault.publishWithdrawals(keccak256("batch-1-without-alice"), 1);

        // alice claims against the batch-0 root she was published in — no longer stranded
        bytes32[] memory proof = new bytes32[](0);
        uint256 balBefore = usdc.balanceOf(alice);
        vault.claim(alice, amount, nonce, batch0Root, proof);
        assertEq(usdc.balanceOf(alice), balBefore + amount, "claimed against the older published root");
        assertTrue(vault.claimed(leaf), "leaf marked claimed");

        // and it cannot be double-claimed against any root
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(alice, amount, nonce, batch0Root, proof);
    }

    function test_zero_root_is_never_a_valid_claim_root() public {
        // audit DP-012 review: an empty batch's cumulative root is bytes32(0); it must NOT be
        // registered as a published root, and a claim against the zero root must always revert.
        vault.publishWithdrawals(bytes32(0), 0);
        assertFalse(vault.rootPublished(bytes32(0)), "the zero root is never registered as published");
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(alice, 1, 1, bytes32(0), proof);
    }

    // =====================================================================
    // SEC-019: deposit hash-chain accumulator
    // =====================================================================

    /// The leaf preimage is `abi.encodePacked(address, bytes32, uint256, uint256)` —
    /// 20 + 32 + 32 + 32 = 116 bytes, address NOT left-padded. Recomputed here
    /// independently of the vault and checked against the Rust-pinned KAT, so a
    /// silent encoding drift (padded address, uint64 id word, added domain tag)
    /// fails here rather than desyncing L1 from the circuit at settlement time.
    function test_deposit_leaf_encoding() public pure {
        bytes memory preimage = abi.encodePacked(
            bytes20(KAT_FROM_0), KAT_OWNER_COMMIT_0, bytes32(KAT_AMOUNT_0), bytes32(uint256(0))
        );
        assertEq(preimage.length, 116, "packed leaf preimage is 20+32+32+32 bytes");
        assertEq(keccak256(preimage), KAT_LEAF, "hand-packed leaf matches Rust KAT_DEPOSIT_LEAF");

        // ...and the exact expression the vault uses agrees with that hand-packing.
        assertEq(
            keccak256(abi.encodePacked(KAT_FROM_0, KAT_OWNER_COMMIT_0, KAT_AMOUNT_0, uint256(0))),
            KAT_LEAF,
            "vault leaf expression matches Rust KAT_DEPOSIT_LEAF"
        );
    }

    /// Two real `deposit()` calls, from the canonical senders in canonical order, must
    /// drive `depositChainTip` to the tip the Rust engine folds for the same events.
    /// This is the byte-parity acceptance criterion for SEC-019.
    function test_deposit_advances_chain_matching_rust_KAT() public {
        assertEq(vault.depositChainTip(), bytes32(0), "genesis tip is zero");
        assertEq(vault.depositCount(), 0, "genesis count is zero");

        _depositAs(KAT_FROM_0, KAT_AMOUNT_0, KAT_OWNER_COMMIT_0);
        assertEq(vault.depositCount(), 1, "one deposit folded");
        assertEq(
            vault.depositChainTip(),
            keccak256(abi.encodePacked(bytes32(0), KAT_LEAF)),
            "tip after one deposit is fold(0, KAT_LEAF)"
        );

        _depositAs(KAT_FROM_1, KAT_AMOUNT_1, KAT_OWNER_COMMIT_1);
        assertEq(vault.depositCount(), 2, "two deposits folded");
        assertEq(vault.depositChainTip(), KAT_TIP2, "tip matches Rust KAT_DEPOSIT_TIP2");
    }

    /// `id` is the PRE-increment `depositCount`, so the first deposit carries id 0.
    /// If it were post-increment the KAT above would fail, but pin it directly too.
    function test_deposit_id_is_pre_increment_count() public {
        _depositAs(KAT_FROM_0, KAT_AMOUNT_0, KAT_OWNER_COMMIT_0);
        // leaf with id=0 is the one that was folded; id=1 would give a different tip
        assertEq(
            vault.depositChainTip(),
            keccak256(abi.encodePacked(bytes32(0), KAT_LEAF)),
            "first deposit folded with id 0"
        );
    }

    /// The chain is order-sensitive: the same two deposits in the opposite order must
    /// NOT produce KAT_TIP2. Ordering is the whole point of a hash chain over a set
    /// commitment — it is what stops a sequencer from reordering or replaying credits.
    function test_deposit_chain_is_order_sensitive() public {
        CollateralVault other = new CollateralVault(address(this), address(usdc));
        usdc.mint(KAT_FROM_1, KAT_AMOUNT_1);
        vm.startPrank(KAT_FROM_1);
        usdc.approve(address(other), KAT_AMOUNT_1);
        other.deposit(KAT_AMOUNT_1, KAT_OWNER_COMMIT_1);
        vm.stopPrank();
        usdc.mint(KAT_FROM_0, KAT_AMOUNT_0);
        vm.startPrank(KAT_FROM_0);
        usdc.approve(address(other), KAT_AMOUNT_0);
        other.deposit(KAT_AMOUNT_0, KAT_OWNER_COMMIT_0);
        vm.stopPrank();

        assertEq(other.depositCount(), 2, "two deposits folded");
        assertTrue(other.depositChainTip() != KAT_TIP2, "reordered deposits give a different tip");
    }

    /// A reverted deposit must not advance the chain: the accumulator has to track
    /// exactly the credited deposits, never attempted ones.
    function test_failed_deposit_does_not_advance_chain() public {
        usdc.mint(alice, 100 * USD);
        vm.prank(alice);
        vm.expectRevert(MockUSDC.InsufficientAllowance.selector);
        vault.deposit(100 * USD, DEFAULT_TEST_OWNER_COMMIT);
        assertEq(vault.depositChainTip(), bytes32(0), "tip unchanged after failed deposit");
        assertEq(vault.depositCount(), 0, "count unchanged after failed deposit");
    }
}
