// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
// Imported so sparse compilation emits the artifact Deploy.s.sol loads with getCode.
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";
import {SP1ZkVerifier} from "../src/SP1ZkVerifier.sol";
import {MockSP1Verifier} from "../src/mocks/MockSP1Verifier.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {IZkVerifier} from "../src/interfaces/IZkVerifier.sol";

/// Cheatcodes the Deploy env-override test needs beyond MiniTest's Vm subset
/// (same well-known cheatcode address; dispatched by selector).
interface VmExt {
    function setEnv(string calldata name, string calldata value) external;
    function chainId(uint256 newChainId) external;
    function toString(address value) external pure returns (string memory);
    function toString(uint256 value) external pure returns (string memory);
    function toString(bytes32 value) external pure returns (string memory);
}

/// The Deploy.s.sol testnet/dev harness: it always wires MockZkVerifier behind a fresh
/// ClockBoundVerifier, never an external verifier.
///   - default run: the clock is the settlement verifier, bound to the settlement, over
///     the mock, with the launch parameters; vault and settlement are paired;
///   - refusals: VERIFIER / INNER_VERIFIER, the mock on a non-testnet chain, a clock
///     parameter below 400 ms, and off the local anvil chain an unset ENCLAVE_SIGNER,
///     GOVERNANCE, GENESIS_ROOT, PRIVATE_KEY or GATEWAY_SIGNER (or a default anvil
///     account for the last two);
///   - the deployed stack settles only clock-bound proofs, on every settle path.
///
/// NOTE: every Deploy run lives in ONE test function on purpose — `vm.setEnv` mutates
/// the (process-global) env while forge runs test functions in parallel, so splitting
/// the branches into separate tests would race on the shared variables. The other tests
/// in this file never read the env.
contract DeployVerifierEnvTest is MiniTest {
    VmExt internal constant vmx = VmExt(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // Anvil's well-known keys #0 and #9 and address #1: public test material.
    string internal constant ANVIL_PK0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    uint256 internal constant ANVIL_KEY0 = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    string internal constant ANVIL_PK9 = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";
    address internal constant ANVIL_ADDR0 = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address internal constant ANVIL_ADDR1 = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    // A throwaway key that is not one of the default anvil accounts.
    string internal constant OPERATOR_PK = "0x000000000000000000000000000000000000000000000000000000000000beef";
    uint256 internal constant OPERATOR_KEY = 0xbeef;

    address internal constant REAL_SIGNER = 0x1111111111111111111111111111111111111111;
    address internal constant ENCLAVE = 0x2222222222222222222222222222222222222222;
    address internal constant GOV = 0x3333333333333333333333333333333333333333;
    bytes32 internal constant GENESIS = bytes32(uint256(0xC0FFEE));
    uint256 internal constant SEED_USDC = 1_000_000e6;

    string internal constant EXTERNAL_VERIFIER_REFUSED =
        "Deploy: VERIFIER/INNER_VERIFIER are not supported here; deploy real verifiers with scripts/local-verification/deploy_clock_stack.py and check them with release_manifest.py observe-target";
    string internal constant MOCK_GUARD =
        "Deploy: MockZkVerifier is unsound; refusing on a non-testnet chain (set ALLOW_MOCK_VERIFIER=1 to override, UNSAFE)";
    string internal constant CLOCK_FLOOR = "Deploy: clock parameters must be at least 400 ms";

    struct Stack {
        DarkPerpSettlement s;
        CollateralVault v;
        ClockBoundVerifier c;
        MockUSDC u;
    }

    Deploy internal d;

    // ---------------------------------------------------------------- env helpers

    /// Every variable Deploy.s.sol reads. An empty value parses as invalid, so `envOr`
    /// falls back to the script default exactly as if the variable were unset.
    function _clearEnv() internal {
        string[20] memory names = [
            "VERIFIER",
            "INNER_VERIFIER",
            "PRIVATE_KEY",
            "GATEWAY_SIGNER",
            "ENCLAVE_SIGNER",
            "GOVERNANCE",
            "GENESIS_ROOT",
            "ALLOW_MOCK_VERIFIER",
            "ALLOW_PUBLIC_DEV_KEYS",
            "LIVENESS_BLOCKS",
            "CHALLENGE_GRACE_BLOCKS",
            "CHALLENGE_BOND",
            "INCLUSION_DEADLINE_SECS",
            "FINAL_SETTLE_GRACE_BLOCKS",
            "PROGRESS_BATCHES",
            "SLASH_PAYOUT_CAP",
            "MAX_WINDOW_MS",
            "CLOCK_SKEW_MS",
            "ANCHOR_TIMEOUT_MS",
            "INITIAL_BOND"
        ];
        for (uint256 i = 0; i < names.length; i++) {
            vmx.setEnv(names[i], "");
        }
    }

    function _run() internal returns (Stack memory x) {
        (x.s, x.v, x.c, x.u) = d.run();
    }

    /// A refusal raised before the broadcast starts.
    function _expectPreflight(string memory reason) internal {
        vm.expectRevert(bytes(reason));
        d.run();
    }

    /// A constructor revert passed through by the script. It fires after `startBroadcast`,
    /// and a reverted script leaves that broadcast active in the test EVM, so it is
    /// stopped here before the next run or prank.
    function _expectConstructorRevert(bytes4 selector) internal {
        vm.expectRevert(selector);
        d.run();
        vm.stopBroadcast();
    }

    // ---------------------------------------------------------------- stack checks

    function _assertDefaultStack(Stack memory x) internal {
        // the verifier is this clock, bound to this settlement, over a MockZkVerifier
        assertEq(address(x.s.verifier()), address(x.c), "settlement verifier is the clock");
        assertEq(uint256(x.c.proofVersion()), 2, "clock proof version");
        assertEq(address(x.c.settlement()), address(x.s), "clock bound to the settlement");
        address inner = address(x.c.innerVerifier());
        assertEq(inner.codehash, address(new MockZkVerifier()).codehash, "clock inner verifier is the mock");
        assertEq(uint256(x.c.maxWindowMs()), 30_000, "default max window");
        assertEq(uint256(x.c.clockSkewMs()), 30_000, "default clock skew");
        assertEq(uint256(x.c.anchorTimeoutMs()), 3_600_000, "default anchor timeout");
        assertEq(x.c.configurator(), ANVIL_ADDR0, "clock configured by the deployer");
        // settlement launch parameters
        assertEq(x.s.ABI_VERSION(), 3, "ABI version");
        assertEq(x.s.sequencer(), ANVIL_ADDR0, "local simulation defaults to the anvil deployer");
        assertEq(x.s.enclaveSigner(), ANVIL_ADDR0, "local enclave signer defaults to the sequencer");
        assertEq(x.s.governance(), ANVIL_ADDR0, "local governance defaults to the sequencer");
        assertEq(x.s.currentStateRoot(), bytes32(0), "local genesis root defaults to zero");
        assertEq(x.s.livenessTimeoutBlocks(), 43_200, "liveness 24 h of 2 s blocks");
        assertEq(x.s.challengeGraceBlocks(), 3_600, "challenge grace 2 h");
        assertEq(x.s.challengeBond(), 0.01 ether, "challenge stake");
        assertEq(x.s.inclusionDeadlineSecs(), 3_600, "inclusion deadline");
        assertEq(x.s.finalSettleGraceBlocks(), 300, "final-settle grace");
        assertEq(x.s.progressBatches(), 2, "progress batches");
        assertEq(x.s.slashPayoutCap(), 1_000e6, "slash payout cap");
        assertEq(x.s.batchCount(), 0, "fresh settlement");
        assertFalse(x.s.closeOnly(), "live");
        // vault pairing, token and bond
        assertEq(x.s.vault(), address(x.v), "settlement names the vault");
        assertEq(x.v.settlement(), address(x.s), "vault names the settlement");
        assertEq(address(x.v.token()), address(x.u), "vault holds the deployed MockUSDC");
        assertEq(x.v.gatewaySigner(), ANVIL_ADDR0, "local simulation defaults GATEWAY_SIGNER to the sequencer");
        assertEq(x.u.balanceOf(ANVIL_ADDR0), SEED_USDC, "deployer seeded with 1M USDC");
        assertEq(x.s.sequencerBond(), 0, "no bond by default");
        assertTrue(x.s.acceptingDeposits(), "paired and live");
    }

    function _assertOverriddenStack(Stack memory x) internal view {
        assertEq(x.s.enclaveSigner(), ENCLAVE, "explicit enclave signer");
        assertEq(x.s.governance(), GOV, "explicit governance");
        assertEq(x.s.currentStateRoot(), GENESIS, "explicit genesis root");
        assertEq(x.v.gatewaySigner(), REAL_SIGNER, "explicit gateway signer");
        assertEq(x.s.livenessTimeoutBlocks(), 7_200, "liveness override");
        assertEq(x.s.challengeGraceBlocks(), 1_200, "grace override");
        assertEq(x.s.challengeBond(), 1, "stake override");
        assertEq(x.s.inclusionDeadlineSecs(), 7_200, "deadline override");
        assertEq(x.s.finalSettleGraceBlocks(), 150, "final grace override");
        assertEq(x.s.progressBatches(), 16, "progress batches override (maximum)");
        assertEq(x.s.slashPayoutCap(), 500e6, "cap override");
        assertEq(uint256(x.c.maxWindowMs()), 400, "max window at the 400 ms floor");
        assertEq(uint256(x.c.clockSkewMs()), 20_000, "skew override");
        assertEq(uint256(x.c.anchorTimeoutMs()), 1_000, "anchor timeout at the clock's own floor");
        // the initial bond is minted on top of the seed and posted
        assertEq(x.s.sequencerBond(), 100e6, "initial bond posted");
        assertEq(x.u.balanceOf(x.s.sequencer()), SEED_USDC, "seed left after posting the bond");
        assertEq(x.u.balanceOf(address(x.s)), 100e6, "settlement custodies the bond");
        assertEq(x.s.depositCapacity(), 2_000_000_019, "100 USDC of bond admits 2,000.000019 USDC");
    }

    // ---------------------------------------------------------------- deployed-stack flows

    function _permitDeposit(Stack memory x, address who, uint256 amount, bytes32 commit) internal {
        uint64 validUntil = uint64(block.timestamp + 1800);
        bytes memory sig = SettlementTestConfig.permitSig(vm, ANVIL_KEY0, x.v, who, commit, amount, validUntil);
        x.u.mint(who, amount);
        vm.startPrank(who);
        x.u.approve(address(x.v), amount);
        x.v.deposit(amount, commit, validUntil, sig);
        vm.stopPrank();
    }

    function _register(Stack memory x, bytes32 prev, bytes32 base, uint8 phase) internal returns (bytes memory) {
        uint64 batchId = uint64(x.s.batchCount());
        vm.prank(ANVIL_ADDR0); // sequencer and governance on the local default stack
        bytes32 receipt = x.c.register(batchId, prev, base, 0, 0, 0, phase);
        return abi.encode(keccak256(abi.encode(x.c.DOMAIN(), base, receipt)));
    }

    /// Lands `r` (prev, manifest, next, ordered, withdrawals, rejected, deposits) through
    /// the entrypoint for `phase`: 0 settleBatch, 1 finalSettle, 2 finalExit. The plain
    /// commitment is refused before and after the clock anchor; the bound proof lands.
    function _landOnlyWithClock(Stack memory x, uint8 phase, bytes32[7] memory r, uint64 n) internal {
        bytes32 base = phase == 0
            ? x.s.publicCommitment(r[0], r[1], r[2], r[3], r[4], r[5], r[6])
            : x.s.windDownCommitment(r[0], r[1], r[2], r[3], r[4], r[5], r[6], phase);
        uint256 before = x.s.batchCount();
        _land(x, phase, r, n, abi.encodePacked(base), true);
        bytes memory bound = _register(x, r[0], base, phase);
        _land(x, phase, r, n, abi.encodePacked(base), true);
        _land(x, phase, r, n, bound, false);
        assertEq(x.s.batchCount(), before + 1, "the bound proof landed one batch");
        assertEq(x.s.currentStateRoot(), r[2], "root advanced");
        // the anchor is consumed by the advance: the same proof cannot land again
        // (the phase-1 entrypoint is one-shot and refuses before verifying)
        bytes32[7] memory again;
        for (uint256 i = 0; i < 7; i++) {
            again[i] = r[i];
        }
        again[0] = r[2];
        if (phase == 1) {
            vm.prank(ANVIL_ADDR0);
            vm.expectRevert(bytes("wind-down already settled"));
            x.s.finalSettle(again[0], again[1], again[2], again[3], again[4], again[5], again[6], n, bound);
        } else {
            _land(x, phase, again, n, bound, true);
        }
    }

    function _land(Stack memory x, uint8 phase, bytes32[7] memory r, uint64 n, bytes memory proof, bool refused)
        internal
    {
        vm.prank(ANVIL_ADDR0);
        if (refused) vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        if (phase == 0) x.s.settleBatch(r[0], r[1], r[2], r[3], r[4], r[5], r[6], n, proof);
        else if (phase == 1) x.s.finalSettle(r[0], r[1], r[2], r[3], r[4], r[5], r[6], n, proof);
        else x.s.finalExit(r[0], r[1], r[2], r[3], r[4], r[5], r[6], n, proof);
    }

    /// Deposit → settle → claim → close-only → finalSettle → finalExit → claim and refund,
    /// all on the stack the default run deployed.
    function _exerciseDefaultStack(Stack memory x) internal {
        address alice = address(0xA11CE);
        address bob = address(0xB0B);
        // deposits need bond capacity first
        vm.startPrank(ANVIL_ADDR0);
        x.u.approve(address(x.s), 100e6);
        x.s.postBond(100e6);
        vm.stopPrank();
        assertEq(x.s.depositCapacity(), 2_000_000_019, "100 USDC of bond admits 2,000.000019 USDC");
        _permitDeposit(x, alice, 1_000e6, keccak256("alice-note"));
        bytes32 bobCommit = keccak256("bob-note");
        _permitDeposit(x, bob, 500e6, bobCommit);

        // phase 0: credits alice's deposit (prefix 1) and authorizes 400 USDC to her
        bytes32 leaf0 = keccak256(abi.encodePacked(alice, uint256(400e6), uint256(1)));
        bytes32[7] memory r =
            [bytes32(0), keccak256("m0"), bytes32(uint256(1)), bytes32(0), leaf0, bytes32(0), x.v.depositTipAt(1)];
        _landOnlyWithClock(x, 0, r, 1);
        assertEq(uint256(x.s.consumedDepositCount()), 1, "one deposit consumed");
        x.v.claim(alice, 400e6, 1, leaf0, new bytes32[](0));

        // governance close-only, then the wind-down after its grace window
        vm.prank(ANVIL_ADDR0);
        x.s.enterCloseOnly();
        vm.roll(block.number + x.s.finalSettleGraceBlocks());
        r = [
            bytes32(uint256(1)),
            keccak256("m1"),
            bytes32(uint256(2)),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            x.v.depositTipAt(1)
        ];
        _landOnlyWithClock(x, 1, r, 1);
        assertTrue(x.s.windDownSettled(), "wind-down settled");

        // phase 2: alice's remaining 600 USDC exits
        bytes32 leaf2 = keccak256(abi.encodePacked(alice, uint256(600e6), uint256(2)));
        r = [
            bytes32(uint256(2)),
            keccak256("m2"),
            bytes32(uint256(3)),
            bytes32(0),
            leaf2,
            bytes32(0),
            x.v.depositTipAt(1)
        ];
        _landOnlyWithClock(x, 2, r, 1);
        assertEq(x.s.batchCount(), 3, "three batches landed");
        x.v.claim(alice, 600e6, 2, leaf2, new bytes32[](0));

        // bob's deposit was never consumed: refunded at principal in close-only
        x.v.refundDeposit(1, bob, bobCommit, 500e6, bob);
        assertEq(x.u.balanceOf(alice), 1_000e6, "alice withdrew her full deposit");
        assertEq(x.u.balanceOf(bob), 500e6, "bob refunded");
        assertEq(x.u.balanceOf(address(x.v)), 0, "vault empty");
        assertEq(x.v.tvl(), 0, "tvl zero");
    }

    // ---------------------------------------------------------------- the env test

    function test_deploy_env_overrides() public {
        d = new Deploy();
        // don't inherit stray shell overrides
        _clearEnv();

        // 1) Default local run: the clock-bound mock stack with the launch parameters.
        Stack memory x = _run();
        _assertDefaultStack(x);
        _exerciseDefaultStack(x);

        // 2) Local overrides are wired as given; INITIAL_BOND is minted and posted.
        vmx.setEnv("ENCLAVE_SIGNER", vmx.toString(ENCLAVE));
        vmx.setEnv("GOVERNANCE", vmx.toString(GOV));
        vmx.setEnv("GENESIS_ROOT", vmx.toString(GENESIS));
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(REAL_SIGNER));
        vmx.setEnv("LIVENESS_BLOCKS", "7200");
        vmx.setEnv("CHALLENGE_GRACE_BLOCKS", "1200");
        vmx.setEnv("CHALLENGE_BOND", "1");
        vmx.setEnv("INCLUSION_DEADLINE_SECS", "7200");
        vmx.setEnv("FINAL_SETTLE_GRACE_BLOCKS", "150");
        vmx.setEnv("PROGRESS_BATCHES", "16");
        vmx.setEnv("SLASH_PAYOUT_CAP", "500000000");
        vmx.setEnv("MAX_WINDOW_MS", "400");
        vmx.setEnv("CLOCK_SKEW_MS", "20000");
        vmx.setEnv("ANCHOR_TIMEOUT_MS", "1000");
        vmx.setEnv("INITIAL_BOND", "100000000");
        _assertOverriddenStack(_run());
        _clearEnv();

        // 3) An external verifier is refused on every chain, before anything else.
        address fake = 0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF;
        vmx.setEnv("VERIFIER", vmx.toString(fake));
        _expectPreflight(EXTERNAL_VERIFIER_REFUSED);
        vmx.setEnv("VERIFIER", "");
        vmx.setEnv("INNER_VERIFIER", vmx.toString(fake));
        _expectPreflight(EXTERNAL_VERIFIER_REFUSED);
        vmx.setEnv("INNER_VERIFIER", "");

        // 4) Clock parameters: below 400 ms or beyond uint64 refused by the script; the
        //    clock's own 1,000 ms anchor-timeout floor is passed through unchanged.
        vmx.setEnv("MAX_WINDOW_MS", "399");
        _expectPreflight(CLOCK_FLOOR);
        vmx.setEnv("MAX_WINDOW_MS", "");
        vmx.setEnv("CLOCK_SKEW_MS", "399");
        _expectPreflight(CLOCK_FLOOR);
        vmx.setEnv("CLOCK_SKEW_MS", "");
        vmx.setEnv("ANCHOR_TIMEOUT_MS", "399");
        _expectPreflight(CLOCK_FLOOR);
        vmx.setEnv("ANCHOR_TIMEOUT_MS", "999");
        _expectConstructorRevert(ClockBoundVerifier.InvalidConfiguration.selector);
        vmx.setEnv("ANCHOR_TIMEOUT_MS", "");
        vmx.setEnv("CLOCK_SKEW_MS", vmx.toString(uint256(type(uint64).max) + 1));
        _expectPreflight("Deploy: clock parameter exceeds uint64");
        vmx.setEnv("CLOCK_SKEW_MS", "");

        // 5) Settlement parameter limits are the constructor's, passed through unchanged.
        vmx.setEnv("PROGRESS_BATCHES", "0");
        _expectConstructorRevert(DarkPerpSettlement.InvalidConfig.selector);
        vmx.setEnv("PROGRESS_BATCHES", "17");
        _expectConstructorRevert(DarkPerpSettlement.InvalidConfig.selector);
        vmx.setEnv("PROGRESS_BATCHES", "");
        vmx.setEnv("SLASH_PAYOUT_CAP", "0");
        _expectConstructorRevert(DarkPerpSettlement.InvalidConfig.selector);
        vmx.setEnv("SLASH_PAYOUT_CAP", "");
        vmx.setEnv("LIVENESS_BLOCKS", "0");
        _expectConstructorRevert(DarkPerpSettlement.InvalidConfig.selector);
        vmx.setEnv("LIVENESS_BLOCKS", "");
        vmx.setEnv("CHALLENGE_GRACE_BLOCKS", "0");
        _expectConstructorRevert(DarkPerpSettlement.InvalidConfig.selector);
        vmx.setEnv("CHALLENGE_GRACE_BLOCKS", "");

        // 6) Off the local chain the deployer and gateway signer are mandatory, and every
        //    default anvil account is refused for both. The external-verifier refusal
        //    still comes first.
        vmx.chainId(1);
        vmx.setEnv("VERIFIER", vmx.toString(fake));
        _expectPreflight(EXTERNAL_VERIFIER_REFUSED);
        vmx.setEnv("VERIFIER", "");
        _expectPreflight("Deploy: PRIVATE_KEY is required off the local anvil chain");
        vmx.setEnv("PRIVATE_KEY", ANVIL_PK0);
        _expectPreflight("Deploy: PRIVATE_KEY is a public anvil account key");
        vmx.setEnv("PRIVATE_KEY", ANVIL_PK9);
        _expectPreflight("Deploy: PRIVATE_KEY is a public anvil account key");
        vmx.setEnv("PRIVATE_KEY", OPERATOR_PK);
        _expectPreflight("Deploy: GATEWAY_SIGNER is required off the local anvil chain");
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(ANVIL_ADDR0));
        _expectPreflight("Deploy: GATEWAY_SIGNER is a public anvil account");
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(ANVIL_ADDR1));
        _expectPreflight("Deploy: GATEWAY_SIGNER is a public anvil account");
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(REAL_SIGNER));

        // 7) The mock guard on a non-testnet chain, then (with the explicit UNSAFE override)
        //    the settlement roles and genesis root that have no default off 31337.
        _expectPreflight(MOCK_GUARD);
        vmx.setEnv("ALLOW_MOCK_VERIFIER", "1");
        _expectPreflight("Deploy: ENCLAVE_SIGNER is required off the local anvil chain");
        vmx.setEnv("ENCLAVE_SIGNER", vmx.toString(ENCLAVE));
        _expectPreflight("Deploy: GOVERNANCE is required off the local anvil chain");
        vmx.setEnv("GOVERNANCE", vmx.toString(GOV));
        _expectPreflight("Deploy: GENESIS_ROOT is required off the local anvil chain");
        vmx.setEnv("GENESIS_ROOT", vmx.toString(GENESIS));
        x = _run();
        assertEq(x.s.sequencer(), vm.addr(OPERATOR_KEY), "explicit deployer is the sequencer");
        assertEq(address(x.s.verifier()), address(x.c), "override still wires only the clock");
        vmx.setEnv("ALLOW_MOCK_VERIFIER", "0");

        // 8) A testnet needs no override, but the same explicit roles and genesis root.
        vmx.chainId(84532);
        x = _run();
        assertEq(x.s.sequencer(), vm.addr(OPERATOR_KEY), "testnet sequencer is the explicit deployer");
        assertEq(x.s.enclaveSigner(), ENCLAVE, "testnet enclave signer");
        assertEq(x.s.governance(), GOV, "testnet governance");
        assertEq(x.s.currentStateRoot(), GENESIS, "testnet genesis root");
        assertEq(x.v.gatewaySigner(), REAL_SIGNER, "vault pins the explicit GATEWAY_SIGNER");
        assertEq(address(x.c.settlement()), address(x.s), "testnet clock bound");
        vmx.setEnv("GENESIS_ROOT", "");
        _expectPreflight("Deploy: GENESIS_ROOT is required off the local anvil chain");
        vmx.setEnv("GENESIS_ROOT", vmx.toString(GENESIS));
        vmx.setEnv("GOVERNANCE", "");
        _expectPreflight("Deploy: GOVERNANCE is required off the local anvil chain");
        vmx.setEnv("GOVERNANCE", vmx.toString(GOV));
        vmx.setEnv("ENCLAVE_SIGNER", "");
        _expectPreflight("Deploy: ENCLAVE_SIGNER is required off the local anvil chain");
        vmx.setEnv("ENCLAVE_SIGNER", vmx.toString(ENCLAVE));

        // 9) A fork dry run may opt in to the public keys explicitly.
        vmx.setEnv("PRIVATE_KEY", ANVIL_PK0);
        vmx.setEnv("GATEWAY_SIGNER", vmx.toString(ANVIL_ADDR0));
        vmx.setEnv("ALLOW_PUBLIC_DEV_KEYS", "1");
        x = _run();
        assertEq(x.v.gatewaySigner(), ANVIL_ADDR0, "explicit opt-in accepts the public keys");

        vmx.chainId(31337);
        _clearEnv();
    }

    // ---------------------------------------------------------------- wiring refusals (no env)

    function _cfg(IZkVerifier verifier) internal view returns (DarkPerpSettlement.Config memory) {
        return SettlementTestConfig.defaults(address(this), address(0xE), verifier, bytes32(uint256(1)));
    }

    function test_settlement_refuses_a_verifier_without_the_clock_shape() public {
        // a bare proof verifier: the mock and the SP1 adapter
        MockZkVerifier mock = new MockZkVerifier();
        DarkPerpSettlement.Config memory c = _cfg(mock);
        vm.expectRevert(DarkPerpSettlement.InvalidConfig.selector);
        new DarkPerpSettlement(c);
        SP1ZkVerifier sp1 = new SP1ZkVerifier(ISP1Verifier(address(new MockSP1Verifier())), bytes32(uint256(1)));
        c = _cfg(sp1);
        vm.expectRevert(DarkPerpSettlement.InvalidConfig.selector);
        new DarkPerpSettlement(c);
        // no code at all
        c = _cfg(IZkVerifier(address(0xC0DE)));
        vm.expectRevert(DarkPerpSettlement.InvalidConfig.selector);
        new DarkPerpSettlement(c);

        // a clock that is already bound to another settlement
        ClockBoundVerifier clock = new ClockBoundVerifier(mock, 30_000, 30_000, 3_600_000);
        DarkPerpSettlement first = new DarkPerpSettlement(_cfg(clock));
        clock.bindSettlement(IClockSettlement(address(first)));
        c = _cfg(clock);
        vm.expectRevert(DarkPerpSettlement.InvalidConfig.selector);
        new DarkPerpSettlement(c);

        // the shape getters decide: wrong version or a bound settlement are refused
        MockClockVerifier shaped = new MockClockVerifier();
        shaped.setShape(1, address(0));
        c = _cfg(shaped);
        vm.expectRevert(DarkPerpSettlement.InvalidConfig.selector);
        new DarkPerpSettlement(c);
        shaped.setShape(2, address(first));
        vm.expectRevert(DarkPerpSettlement.InvalidConfig.selector);
        new DarkPerpSettlement(c);
        shaped.setShape(2, address(0));
        DarkPerpSettlement ok = new DarkPerpSettlement(c);
        assertEq(address(ok.verifier()), address(shaped), "an unbound version-2 verifier is accepted");
        assertEq(ok.ABI_VERSION(), 3, "ABI version");
    }

    function test_set_vault_requires_the_paired_vault() public {
        MockZkVerifier mock = new MockZkVerifier();
        ClockBoundVerifier clock = new ClockBoundVerifier(mock, 30_000, 30_000, 3_600_000);
        DarkPerpSettlement s = new DarkPerpSettlement(_cfg(clock));
        MockUSDC usdc = new MockUSDC();

        // an EOA
        vm.expectRevert(DarkPerpSettlement.VaultMismatch.selector);
        s.setVault(address(0xBEEF));
        // a contract without settlement()
        vm.expectRevert(DarkPerpSettlement.VaultMismatch.selector);
        s.setVault(address(usdc));
        // a vault deployed for another settlement
        CollateralVault foreign = new CollateralVault(address(0x5E77), address(usdc), address(0x6A7E));
        vm.expectRevert(DarkPerpSettlement.VaultMismatch.selector);
        s.setVault(address(foreign));
        assertEq(s.vault(), address(0), "nothing bound");
        assertFalse(s.acceptingDeposits(), "no deposits without a vault");

        // the vault that names this settlement binds, once
        CollateralVault paired = new CollateralVault(address(s), address(usdc), address(0x6A7E));
        s.setVault(address(paired));
        assertEq(s.vault(), address(paired), "paired vault bound");
        vm.expectRevert(bytes("vault set"));
        s.setVault(address(paired));
    }

    function test_only_the_sequencer_binds_the_vault() public {
        MockZkVerifier mock = new MockZkVerifier();
        MockUSDC usdc = new MockUSDC();
        DarkPerpSettlement s = new DarkPerpSettlement(_cfg(new ClockBoundVerifier(mock, 30_000, 30_000, 3_600_000)));
        CollateralVault v = new CollateralVault(address(s), address(usdc), address(0x6A7E));
        vm.prank(address(0xBAD));
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.setVault(address(v));
    }
}
