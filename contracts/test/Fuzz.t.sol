// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// Property/fuzz tests (Foundry fuzzes any parameterized test). These hammer the
/// two security-critical guarantees with randomized inputs: a withdrawal claim
/// only ever releases the EXACT authorized leaf, and settlement binds the
/// ordered/withdrawals roots (audit F2).
contract FuzzTest is MiniTest {
    CollateralVault internal vault;
    MockUSDC internal usdc;
    DarkPerpSettlement internal s;
    MockZkVerifier internal verifier;
    bytes32 internal constant GENESIS = bytes32(uint256(1));

    // this contract is the settlement authority / sequencer
    function setUp() public {
        usdc = new MockUSDC();
        vault = new CollateralVault(address(this), address(usdc));
        usdc.mint(address(vault), 1_000_000_000_000); // 1,000,000 USDC
        verifier = new MockZkVerifier();
        s = new DarkPerpSettlement(address(this), address(0xE), verifier, GENESIS, 100, 50, 0, 0, address(this), 0);
    }

    /// A claim succeeds only for the exact authorized (to, amount, nonce); any
    /// deviation fails. Releases never exceed what was authorized.
    function testFuzz_claim_only_exact_leaf(address to, uint96 amountRaw, uint96 nonce) public {
        vm.assume(uint160(to) > 20 && to != address(vault) && to != address(this));
        vm.assume(to.code.length == 0);
        uint256 amount = (uint256(amountRaw) % 100_000_000) + 1; // up to 100 USDC
        bytes32 leaf = keccak256(abi.encodePacked(to, amount, uint256(nonce)));
        vault.publishWithdrawals(leaf, 0);

        bytes32[] memory empty = new bytes32[](0);
        // a different amount must not claim
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(to, amount + 1, nonce, leaf, empty);
        // a different nonce must not claim
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(to, amount, uint256(nonce) + 1, leaf, empty);

        // the exact leaf claims exactly the authorized amount, once
        uint256 before = usdc.balanceOf(to);
        vault.claim(to, amount, nonce, vault.withdrawalsRoot(), empty);
        assertEq(usdc.balanceOf(to) - before, amount, "claimed exactly authorized");
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(to, amount, nonce, leaf, empty);
    }

    /// A proof valid for one (orderedRoot, withdrawalsRoot) must not settle a batch
    /// with any different roots — they're bound into the proven commitment (F2).
    function testFuzz_settle_binds_roots(bytes32 ordered, bytes32 withdrawals, bytes32 ordered2, bytes32 wd2) public {
        vm.assume(ordered != ordered2 || withdrawals != wd2);
        bytes32 newRoot = keccak256(abi.encodePacked(ordered, withdrawals));
        bytes32 manifest = keccak256("m");
        // `s` has no vault wired here, so the SEC-019 deposit head is genesis
        // (bytes32(0), 0) — the only value that settles.
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, ordered, withdrawals, bytes32(0), bytes32(0)));

        // swapping in any different roots breaks the proof
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, manifest, newRoot, ordered2, wd2, bytes32(0), bytes32(0), 0, proof);

        // the exact roots settle
        s.settleBatch(GENESIS, manifest, newRoot, ordered, withdrawals, bytes32(0), bytes32(0), 0, proof);
        assertEq(s.currentStateRoot(), newRoot, "settled with the bound roots");
    }

    /// The inclusion leaf is injective in (batchId, orderHash) for distinct inputs
    /// (no cross-batch leaf reuse that would let one proof answer another batch).
    function testFuzz_inclusion_leaf_distinct(uint256 b1, bytes32 h1, uint256 b2, bytes32 h2) public {
        vm.assume(b1 != b2 || h1 != h2);
        assertTrue(s.inclusionLeaf(b1, h1) != s.inclusionLeaf(b2, h2), "leaves distinct");
    }

    /// AUDIT (inclusionLeaf domain separation): the leaf preimage must be domain-tagged
    /// so it can NEVER collide with a MerkleLib internal node, which is a bare
    /// keccak256(abi.encodePacked(bytes32, bytes32)). Otherwise a censoring sequencer
    /// could present a crafted internal node of the ordered tree as an "inclusion leaf"
    /// for an order it never processed and evade the §2 slash. `rejectionLeaf` was
    /// already tagged; `inclusionLeaf` must be too.
    function testFuzz_inclusion_leaf_is_not_an_internal_node(uint256 batchId, bytes32 orderHash) public {
        // the untagged 2x32-byte node shape the leaf must be distinct from
        bytes32 nodeShape = keccak256(abi.encodePacked(bytes32(batchId), orderHash));
        assertTrue(
            s.inclusionLeaf(batchId, orderHash) != nodeShape, "inclusion leaf must not equal a bare internal-node hash"
        );
    }

    receive() external payable {}
}
