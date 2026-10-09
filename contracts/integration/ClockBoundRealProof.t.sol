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
    bytes32 internal constant PREV = 0x6fbba561df9077c35bee00b681c05d38fe34ecbf48a552663f39da1a32624926;
    bytes32 internal constant MANIFEST = 0x60a13678ae3ea1f965d200d9d4f9af75f0c756ae8f9440767db3918cd553593a;
    bytes32 internal constant NEXT = 0xf71b6a5fe2fd95435226915e4655bad2d228284d0d2558ccc79d1b03509e92b0;
    bytes32 internal constant WITHDRAWALS = 0x69e35192c9cc77522e280e62a67d000ffb45cd7fedc84e3e28597502e855a19d;
    bytes32 internal constant DEPOSITS = 0xbc57e60cf7286c5a124c5c646abf81bb81ff8c253761257d2b315cfc93865fce;
    bytes32 internal constant OWNER_COMMIT = 0xa52efa8ab2204b5f9ed6ad4d4d829c2831d051107bf113d630860e1dad97b52b;
    bytes32 internal constant BASE = 0x165346f95fea951af181727db5dad9e2f4bacfed5c398ab9461a52989ca78883;
    bytes32 internal constant RECEIPT = 0x172c01ec35867358859111bbffdadc1a257bff2dd412e8446e20fc376e62840f;
    bytes32 internal constant BOUND = 0x4fc574af6cf22bc0aaf7a4d72532aabc2a7db8f2cda8d3872c47cf07b18f139e;
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
        require(key == 0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353, "wrong guest key");
        require(realVm.envBytes32("ARCORA_REAL_PUBLIC_COMMITMENT") == BOUND, "wrong clock digest");
        proof = realVm.envBytes("ARCORA_REAL_PROOF");
        require(proof.length == 356 && bytes4(proof) == SELECTOR, "real Groth16 proof required");
        IZkVerifier inner = IZkVerifier(address(_adapter(realGateway, key)));
        _constructAt(
            "ClockBoundVerifier.sol:ClockBoundVerifier", abi.encode(inner, uint64(10_000), uint64(2_000)), CLOCK
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
                uint256(10)
            ),
            SETTLEMENT
        );
        clock = ClockBoundVerifier(CLOCK);
        settlement = DarkPerpSettlement(payable(SETTLEMENT));
        clock.bindSettlement(IClockSettlement(SETTLEMENT));
        token = new MockUSDC();
        vault = new CollateralVault(SETTLEMENT, address(token), vm.addr(GW_KEY));
        settlement.setVault(address(vault));

        // Reproduce the exact public synthetic Deposit op with the actual vault gate.
        token.mint(address(0), 1_000_000);
        bytes32 digest =
            keccak256(abi.encodePacked(block.chainid, address(vault), address(0), OWNER_COMMIT, uint256(1_000_000)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(GW_KEY, digest);
        vm.startPrank(address(0));
        token.approve(address(vault), 1_000_000);
        vault.deposit(1_000_000, OWNER_COMMIT, abi.encodePacked(r, s, v));
        vm.stopPrank();
        assertEq(vault.depositChainTip(), DEPOSITS, "real vault prefix must equal proven deposit fold");
        uint256 bond = settlement.requiredBond();
        token.mint(address(this), bond);
        token.approve(SETTLEMENT, bond);
        settlement.postBond(bond);
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
