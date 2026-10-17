// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "../test/utils/MiniTest.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {IZkVerifier} from "../src/interfaces/IZkVerifier.sol";
import {DeployGuard} from "./DeployGuard.sol";

/// The one cheatcode this script needs beyond MiniTest's `Vm` subset.
interface DeployCheats {
    function getCode(string calldata artifactPath) external view returns (bytes memory);
}

/// @title Deploy
/// @notice Testnet / dev harness ONLY: deploys a clock-bound stack over the unsound
/// MockZkVerifier and wires it, in order: MockZkVerifier → ClockBoundVerifier →
/// DarkPerpSettlement → MockUSDC → CollateralVault → setVault → bindSettlement →
/// seed mint (+ optional bond). Release deployments use
/// `scripts/local-verification/deploy_clock_stack.py`, the only path the release
/// manifest's observe-target checks; this script refuses to wire any other verifier.
///
/// Usage (dry run):   forge script script/Deploy.s.sol
/// Usage (broadcast): PRIVATE_KEY=0x.. forge script script/Deploy.s.sol \
///                      --rpc-url $BASE_SEPOLIA_RPC --broadcast
///
/// Block counts assume Base's 2 s blocks (1,800 blocks ≈ 1 hour).
///
/// Env (optional with defaults, except where noted):
///   PRIVATE_KEY      deployer key. REQUIRED off the local anvil chain (31337);
///                    defaults to anvil account #0 only for a local simulation
///   ENCLAVE_SIGNER   secp256k1 address the enclave signs receipts and challenge
///                    authorizations with. REQUIRED off 31337 (local default: sequencer)
///   GATEWAY_SIGNER   secp256k1 address the gateway signs deposit permits with.
///                    REQUIRED off 31337 (local default: sequencer)
///   GOVERNANCE       wind-down / close-only governance. REQUIRED off 31337
///                    (local default: sequencer)
///   ALLOW_PUBLIC_DEV_KEYS  set to 1 to accept a default anvil account as deployer or
///                    GATEWAY_SIGNER off the local chain (fork dry runs only, UNSAFE)
///   ALLOW_MOCK_VERIFIER  set to 1 to deploy the mock on a chain outside DeployGuard's
///                    testnet allowlist (UNSAFE)
///   GENESIS_ROOT     initial state root. REQUIRED (non-zero) off 31337
///   LIVENESS_BLOCKS  close-only liveness timeout (default 43200 ≈ 24 h)
///   CHALLENGE_GRACE_BLOCKS  slash grace after the progress gate (default 3600 ≈ 2 h)
///   CHALLENGE_BOND   challenger stake in wei (default 0.01 ether)
///   INCLUSION_DEADLINE_SECS  seconds after receipt before an order is challengeable
///                    (default 3600)
///   FINAL_SETTLE_GRACE_BLOCKS  blocks after close-only before `finalSettle`
///                    (default 300 ≈ 10 min)
///   PROGRESS_BATCHES phase-0 batches a challenge must outlive before a slash (default 2)
///   SLASH_PAYOUT_CAP USDC base units one slash may pay (default 1,000e6)
///   MAX_WINDOW_MS    clock: widest timed window (default 30000, minimum 400)
///   CLOCK_SKEW_MS    clock: register-time skew bound (default 30000, minimum 400)
///   ANCHOR_TIMEOUT_MS  clock: anchor age before cancel (default 3600000)
///   INITIAL_BOND     USDC base units to post as the sequencer bond (default 0)
///
/// Refused: VERIFIER or INNER_VERIFIER set (this harness never wires a real verifier).
contract Deploy {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // Anvil account #0 (a published key): the local-simulation default deployer.
    uint256 internal constant ANVIL_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 internal constant LOCAL_CHAIN_ID = 31337;
    /// USDC seeded to the sequencer: 1,000,000 USDC (6 decimals).
    uint256 internal constant SEED_USDC = 1_000_000_000_000;
    uint256 internal constant MIN_CLOCK_PARAM = 400;

    function run()
        external
        returns (DarkPerpSettlement settlement, CollateralVault vault, ClockBoundVerifier clock, MockUSDC usdc)
    {
        // Preflight, all before any broadcast, in this order: external verifier, deployer
        // key, gateway signer, mock guard, settlement parameters, clock parameters.
        _refuseExternalVerifier();
        uint256 pk = _deployerKey();
        address sequencer = vm.addr(pk);
        _gatewaySigner(sequencer);
        // MockZkVerifier accepts proof == commitment (unsound): testnets only, unless
        // the operator explicitly overrides.
        require(
            DeployGuard.isTestnet(block.chainid) || vm.envOr("ALLOW_MOCK_VERIFIER", uint256(0)) == 1,
            "Deploy: MockZkVerifier is unsound; refusing on a non-testnet chain (set ALLOW_MOCK_VERIFIER=1 to override, UNSAFE)"
        );
        DarkPerpSettlement.Config memory cfg = _config(sequencer);
        (uint64 maxWindowMs, uint64 clockSkewMs, uint64 anchorTimeoutMs) = _clockParams();
        uint256 initialBond = vm.envOr("INITIAL_BOND", uint256(0));

        vm.startBroadcast(pk);

        IZkVerifier mock = IZkVerifier(_create("MockZkVerifier.sol:MockZkVerifier", ""));
        clock = ClockBoundVerifier(
            _create(
                "ClockBoundVerifier.sol:ClockBoundVerifier", abi.encode(mock, maxWindowMs, clockSkewMs, anchorTimeoutMs)
            )
        );
        cfg.verifier = clock;
        settlement = DarkPerpSettlement(_create("DarkPerpSettlement.sol:DarkPerpSettlement", abi.encode(cfg)));
        // USDC is the collateral asset (6 decimals). MockUSDC ships an open faucet.
        usdc = MockUSDC(_create("MockUSDC.sol:MockUSDC", ""));
        vault = CollateralVault(
            _create(
                "CollateralVault.sol:CollateralVault",
                abi.encode(address(settlement), address(usdc), _gatewaySigner(sequencer))
            )
        );
        settlement.setVault(address(vault));
        clock.bindSettlement(IClockSettlement(address(settlement)));

        // seed the deployer (sequencer) so it can post the bond and fund demo accounts.
        usdc.mint(sequencer, SEED_USDC + initialBond);
        if (initialBond != 0) {
            require(usdc.approve(address(settlement), initialBond), "Deploy: bond approve failed");
            settlement.postBond(initialBond);
        }

        vm.stopBroadcast();

        _checkWiring(settlement, vault, clock, mock);
    }

    /// CREATE from the compiled artifact's creation code plus `args`, bubbling a
    /// constructor revert. Loading the code through the cheatcode (instead of `new`)
    /// keeps this script's own bytecode from embedding every contract it deploys.
    function _create(string memory artifact, bytes memory args) internal returns (address addr) {
        bytes memory code = abi.encodePacked(DeployCheats(address(vm)).getCode(artifact), args);
        assembly {
            addr := create(0, add(code, 0x20), mload(code))
            if and(iszero(addr), gt(returndatasize(), 0)) {
                let p := mload(0x40)
                returndatacopy(p, 0, returndatasize())
                revert(p, returndatasize())
            }
        }
        require(addr != address(0), "Deploy: contract creation failed");
    }

    /// The settlement parameters (the verifier is filled in once the clock exists).
    function _config(address sequencer) internal view returns (DarkPerpSettlement.Config memory c) {
        bool local = block.chainid == LOCAL_CHAIN_ID;
        c.sequencer = sequencer;
        c.enclaveSigner = _requiredOffLocal("ENCLAVE_SIGNER", sequencer, local);
        c.governance = _requiredOffLocal("GOVERNANCE", sequencer, local);
        c.genesisRoot = bytes32(vm.envOr("GENESIS_ROOT", uint256(0)));
        require(local || c.genesisRoot != bytes32(0), "Deploy: GENESIS_ROOT is required off the local anvil chain");
        c.livenessTimeoutBlocks = vm.envOr("LIVENESS_BLOCKS", uint256(43_200));
        c.challengeGraceBlocks = vm.envOr("CHALLENGE_GRACE_BLOCKS", uint256(3_600));
        c.challengeBond = vm.envOr("CHALLENGE_BOND", uint256(0.01 ether));
        c.inclusionDeadlineSecs = vm.envOr("INCLUSION_DEADLINE_SECS", uint256(3_600));
        c.finalSettleGraceBlocks = vm.envOr("FINAL_SETTLE_GRACE_BLOCKS", uint256(300));
        c.progressBatches = vm.envOr("PROGRESS_BATCHES", uint256(2));
        c.slashPayoutCap = vm.envOr("SLASH_PAYOUT_CAP", uint256(1_000e6));
    }

    function _clockParams() internal view returns (uint64 maxWindowMs, uint64 clockSkewMs, uint64 anchorTimeoutMs) {
        uint256 w = vm.envOr("MAX_WINDOW_MS", uint256(30_000));
        uint256 k = vm.envOr("CLOCK_SKEW_MS", uint256(30_000));
        uint256 t = vm.envOr("ANCHOR_TIMEOUT_MS", uint256(3_600_000));
        require(
            w >= MIN_CLOCK_PARAM && k >= MIN_CLOCK_PARAM && t >= MIN_CLOCK_PARAM,
            "Deploy: clock parameters must be at least 400 ms"
        );
        require(
            w <= type(uint64).max && k <= type(uint64).max && t <= type(uint64).max,
            "Deploy: clock parameter exceeds uint64"
        );
        return (uint64(w), uint64(k), uint64(t));
    }

    /// This harness only ever wires its own clock over the mock. A real verifier goes
    /// through the reviewed Python deploy kit instead.
    function _refuseExternalVerifier() internal view {
        require(
            vm.envOr("VERIFIER", address(0)) == address(0) && vm.envOr("INNER_VERIFIER", address(0)) == address(0),
            "Deploy: VERIFIER/INNER_VERIFIER are not supported here; deploy real verifiers with scripts/local-verification/deploy_clock_stack.py and check them with release_manifest.py observe-target"
        );
    }

    /// Post-conditions: the verifier is this clock over this mock, the clock is bound to
    /// the settlement, and the vault and settlement name each other.
    function _checkWiring(
        DarkPerpSettlement settlement,
        CollateralVault vault,
        ClockBoundVerifier clock,
        IZkVerifier mock
    ) internal view {
        require(address(settlement.verifier()) == address(clock), "Deploy: settlement verifier is not the clock");
        require(address(clock.settlement()) == address(settlement), "Deploy: clock is not bound to the settlement");
        require(address(clock.innerVerifier()) == address(mock), "Deploy: clock inner verifier is not the mock");
        require(clock.proofVersion() == 2, "Deploy: clock proof version");
        require(
            settlement.vault() == address(vault) && vault.settlement() == address(settlement),
            "Deploy: vault and settlement are not paired"
        );
    }

    /// An address that must be set explicitly off the local chain; locally it defaults.
    function _requiredOffLocal(string memory name, address localDefault, bool local) internal view returns (address a) {
        a = vm.envOr(name, address(0));
        if (local) return a == address(0) ? localDefault : a;
        require(a != address(0), string.concat("Deploy: ", name, " is required off the local anvil chain"));
    }

    /// The deployer (sequencer) key. Off the local anvil chain it must be set explicitly
    /// and must not be a default anvil account: whoever holds the sequencer key settles.
    function _deployerKey() internal view returns (uint256 pk) {
        pk = vm.envOr("PRIVATE_KEY", uint256(0));
        if (block.chainid == LOCAL_CHAIN_ID) return pk == 0 ? ANVIL_PK : pk;
        require(pk != 0, "Deploy: PRIVATE_KEY is required off the local anvil chain");
        require(
            !_isPublicDevAccount(vm.addr(pk)) || _publicKeysAllowed(),
            "Deploy: PRIVATE_KEY is a public anvil account key"
        );
    }

    /// The vault's deposit-permit signer. Off the local anvil chain it must be set
    /// explicitly and must not be a default anvil account (the gateway's demo key is #0).
    function _gatewaySigner(address sequencer) internal view returns (address signer) {
        signer = vm.envOr("GATEWAY_SIGNER", address(0));
        if (block.chainid == LOCAL_CHAIN_ID) return signer == address(0) ? sequencer : signer;
        require(signer != address(0), "Deploy: GATEWAY_SIGNER is required off the local anvil chain");
        require(
            !_isPublicDevAccount(signer) || _publicKeysAllowed(), "Deploy: GATEWAY_SIGNER is a public anvil account"
        );
    }

    function _publicKeysAllowed() internal view returns (bool) {
        return vm.envOr("ALLOW_PUBLIC_DEV_KEYS", uint256(0)) == 1;
    }

    /// The ten default anvil/hardhat accounts (the published `test ... junk` mnemonic).
    function _isPublicDevAccount(address a) internal pure returns (bool) {
        return a == 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 || a == 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
            || a == 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC || a == 0x90F79bf6EB2c4f870365E785982E1f101E93b906
            || a == 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65 || a == 0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc
            || a == 0x976EA74026E726554dB657fA54763abd0C3a0aa9 || a == 0x14dC79964da2C08b23698B3D3cc7Ca32193d9955
            || a == 0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f || a == 0xa0Ee7A142d267C1f36714E4a8F75612F20a79720;
    }
}
