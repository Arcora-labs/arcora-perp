// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {RealSP1TestBase} from "./RealSP1TestBase.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {IZkVerifier} from "../src/interfaces/IZkVerifier.sol";

interface ClockFixtureVm {
    function etch(address, bytes calldata) external;
}

/// Real cryptographic proof through the actual clock adapter, settlement and vault.
/// The ERC20 and payer are synthetic fixtures: the legacy proof uses a zero payer,
/// impersonated only in this owned EVM. This is not live deposit provenance, HTTP
/// gateway orchestration, order matching, or a complete production lifecycle.
contract ClockBoundRealProofTest is RealSP1TestBase {
    address internal constant CLOCK = address(bytes20(hex"1111111111111111111111111111111111111111"));
    address internal constant SETTLEMENT = address(bytes20(hex"2222222222222222222222222222222222222222"));
    address internal constant RECIPIENT = address(bytes20(hex"abababababababababababababababababababab"));
    bytes32 internal constant PREV = 0x9f4cbddf0c586b57fb0387886eb7c10907d79754845d1561fee555119e7baeb6;
    bytes32 internal constant MANIFEST = 0xd4fcf92fb9e62ae2742d3dd064e8af5e81c031bac602484de13afbd9497ea0fe;
    bytes32 internal constant NEXT = 0x158c26cd2d8f192fea4c799d8f587318927aa35b9cc8299b389f8d1e783a280f;
    bytes32 internal constant WITHDRAWALS = 0x69e35192c9cc77522e280e62a67d000ffb45cd7fedc84e3e28597502e855a19d;
    bytes32 internal constant DEPOSITS = 0x31610b84e613e8639848850d1588501d732f62bf1ec3460ba732167f11ccbc4b;
    bytes32 internal constant OWNER_COMMIT = 0x58a38b5c2483bc713b57ad8a8bcec3b2c8303fedda21fb800691cc7405235177;
    bytes32 internal constant BASE = 0xa94f1820a9e1f3cc571c1e18bb6aeecd2fe3a737b6c5aa84bd9e02745383aa5e;
    bytes32 internal constant RECEIPT = 0x255eb8deb1c4975362a787724d71be5c56f59b726bcc85bc22104c59abf73995;
    bytes32 internal constant BOUND = 0x6e382af92ac5b4872e4a1f6c0f6bdf6d1a246bb2ca6f834dc7aeb3748edab5ab;
    uint256 internal constant GW_KEY = 0x6A7E;
    ClockBoundVerifier internal clock;
    DarkPerpSettlement internal settlement;
    CollateralVault internal vault;
    MockUSDC internal token;
    bytes internal proof;

    /// Match the already-proven synthetic addresses without editing runtime logic.
    /// Same constructor-execution technique as forge-std deployCodeTo: creation
    /// bytecode is executed at the chosen address, then its returned runtime is
    /// installed. No state slot, verifier response or proof is mocked or patched.
    function _constructAt(string memory artifact, bytes memory args, address at) internal {
        ClockFixtureVm(address(vm)).etch(at, abi.encodePacked(realVm.getCode(artifact), args));
        (bool success, bytes memory runtime) = at.call("");
        require(success && runtime.length != 0, "fixture constructor failed");
        ClockFixtureVm(address(vm)).etch(at, runtime);
    }

    function setUp() public override {
        super.setUp();
        vm.chainId(84532);
        vm.warp(101);
        bytes32 key = realVm.envBytes32("ARCORA_REAL_PROGRAM_VKEY");
        require(key == 0x009cfc02120c4255b1a8c3eebbcc31f92a9ce0891c88641e78e0af23aae098ec, "wrong guest key");
        require(realVm.envBytes32("ARCORA_REAL_PUBLIC_COMMITMENT") == BOUND, "wrong clock digest");
        proof = realVm.envBytes("ARCORA_REAL_PROOF");
        require(proof.length == 356 && bytes4(proof) == SELECTOR, "real Groth16 proof required");
        IZkVerifier inner = IZkVerifier(address(_adapter(realGateway, key)));
        // The anchor timeout is not part of the receipt; the 12-word settlement config
        // keeps the previous ten words in order, then progress batches and slash cap.
        _constructAt(
            "ClockBoundVerifier.sol:ClockBoundVerifier",
            abi.encode(inner, uint64(10_000), uint64(2_000), uint64(3_600_000)),
            CLOCK
        );
        _constructAt(
            "DarkPerpSettlement.sol:DarkPerpSettlement",
            abi.encode(
                address(this),
                vm.addr(0xA11CE),
                IZkVerifier(CLOCK),
                PREV,
                uint256(100),
                uint256(50),
                uint256(1 ether),
                uint256(600),
                address(this),
                uint256(10),
                uint256(2),
                uint256(1_000e6)
            ),
            SETTLEMENT
        );
        clock = ClockBoundVerifier(CLOCK);
        settlement = DarkPerpSettlement(payable(SETTLEMENT));
        clock.bindSettlement(IClockSettlement(SETTLEMENT));
        token = new MockUSDC();
        vault = new CollateralVault(SETTLEMENT, address(token), vm.addr(GW_KEY));
        settlement.setVault(address(vault));

        // The bond must cover the deposit's TVL before the vault admits it.
        uint256 bond = (uint256(1_000_000) * settlement.BOND_BPS()) / 10_000;
        token.mint(address(this), bond);
        token.approve(SETTLEMENT, bond);
        settlement.postBond(bond);

        // Reproduce the exact public synthetic Deposit op with the actual vault gate. The
        // permit (and its deadline) is checked and discarded; it never enters the leaf.
        token.mint(address(0), 1_000_000);
        uint64 validUntil = uint64(block.timestamp + 1800);
        bytes32 digest = keccak256(
            abi.encodePacked(
                keccak256("arcora:deposit-permit:v2"),
                block.chainid,
                address(vault),
                address(0),
                OWNER_COMMIT,
                uint256(1_000_000),
                uint256(validUntil)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(GW_KEY, digest);
        vm.startPrank(address(0));
        token.approve(address(vault), 1_000_000);
        vault.deposit(1_000_000, OWNER_COMMIT, validUntil, abi.encodePacked(r, s, v));
        vm.stopPrank();
        assertEq(vault.depositChainTip(), DEPOSITS, "real vault prefix must equal proven deposit fold");
        assertEq(settlement.requiredBond(), bond, "bond covers the deposit exactly");
        assertEq(
            settlement.publicCommitment(PREV, MANIFEST, NEXT, bytes32(0), WITHDRAWALS, bytes32(0), DEPOSITS),
            BASE,
            "native/base identity"
        );
    }

    function _anchor() internal {
        bytes32 actual = clock.register(0, PREV, BASE, 100_000, 100_700, 2, 0);
        assertEq(actual, RECEIPT, "native/registered receipt identity");
    }

    function _settle(bytes memory supplied) internal {
        settlement.settleBatch(PREV, MANIFEST, NEXT, bytes32(0), WITHDRAWALS, bytes32(0), DEPOSITS, 1, supplied);
    }

    function test_real_clock_proof_settles_and_authorizes_only_proven_withdrawal() public {
        bytes32[] memory siblings = new bytes32[](0);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(RECIPIENT, 1_000_000, 1, WITHDRAWALS, siblings);
        _anchor();
        _settle(proof);
        assertEq(settlement.currentStateRoot(), NEXT, "proven state committed");
        assertEq(settlement.batchCount(), 1, "one consumed batch");
        assertEq(vault.withdrawalsRoot(), WITHDRAWALS, "only proven root published");
        vault.claim(RECIPIENT, 1_000_000, 1, WITHDRAWALS, siblings);
        assertEq(token.balanceOf(RECIPIENT), 1_000_000, "proven synthetic balance paid");
        assertEq(vault.totalWithdrawn(), 1_000_000, "accounting agrees");
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(RECIPIENT, 1_000_000, 1, WITHDRAWALS, siblings);
    }

    function test_real_clock_proof_without_anchor_is_rejected() public {
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        _settle(proof);
        assertEq(settlement.currentStateRoot(), PREV, "no unauthorized advance");
    }

    function test_tampered_real_clock_proof_is_rejected() public {
        _anchor();
        proof[proof.length - 1] ^= bytes1(uint8(1));
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        _settle(proof);
    }

    function test_real_clock_proof_cannot_use_restamped_anchor() public {
        vm.warp(102);
        bytes32 actual = clock.register(0, PREV, BASE, 100_000, 100_700, 2, 0);
        assertTrue(actual != RECEIPT, "different registration time must change receipt");
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        _settle(proof);
    }

    function test_real_clock_proof_cannot_replay_after_chain_change() public {
        _anchor();
        vm.chainId(84533);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        _settle(proof);
    }

    function test_real_clock_proof_cannot_authorize_next_batch() public {
        _anchor();
        _settle(proof);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settlement.settleBatch(
            NEXT, MANIFEST, bytes32(uint256(9)), bytes32(0), WITHDRAWALS, bytes32(0), DEPOSITS, 1, proof
        );
    }
}
