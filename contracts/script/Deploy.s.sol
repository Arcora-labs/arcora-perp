// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "../test/utils/MiniTest.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";
import {IZkVerifier} from "../src/interfaces/IZkVerifier.sol";
import {DeployGuard} from "./DeployGuard.sol";

/// @title Deploy
/// @notice Deploys the dark-perp L1 stack (Phase 0 / Sepolia testnet) and wires
/// it: verifier → settlement → vault. Parameters come from env vars with sane
/// defaults so a bare `forge script` simulates cleanly.
///
/// Usage (dry run):   forge script script/Deploy.s.sol
/// Usage (broadcast): PRIVATE_KEY=0x.. forge script script/Deploy.s.sol \
///                      --rpc-url $SEPOLIA_RPC --broadcast
///
/// Env (optional with defaults, except where noted):
///   PRIVATE_KEY      deployer key. REQUIRED off the local anvil chain (31337);
///                    defaults to anvil account #0 only for a local simulation
///   ENCLAVE_SIGNER   secp256k1 address the enclave signs receipts with
///   GATEWAY_SIGNER   secp256k1 address the gateway signs deposit authorizations with
///                    (SEC-019 Task 6c). REQUIRED off the local anvil chain; defaults
///                    to the sequencer only for a local simulation
///   ALLOW_PUBLIC_DEV_KEYS  set to 1 to accept a default anvil account as deployer or
///                    GATEWAY_SIGNER off the local chain (fork dry runs only, UNSAFE)
///   GENESIS_ROOT     initial state root
///   LIVENESS_BLOCKS  close-only liveness timeout (default 7200 ≈ 1 day)
///   CHALLENGE_BLOCKS inclusion challenge window (default 300 ≈ 1 hr)
///   CHALLENGE_BOND   challenger stake in wei (default 0.01 ether)
///   INCLUSION_DEADLINE_SECS  §2 inclusion SLA before an order is challengeable (default 600)
///   VERIFIER         address of an already-deployed real verifier (e.g. the
///                    SP1ZkVerifier) to bind; unset/zero deploys MockZkVerifier
///   GOVERNANCE       address allowed to call `finalSettle` (default: sequencer)
///   FINAL_SETTLE_GRACE_BLOCKS  blocks after close-only before `finalSettle` is
///                    allowed (default 300)
///
/// NOTE: without VERIFIER this ships MockZkVerifier — set VERIFIER to the real
/// SP1/Risc0 verifier before any non-testnet deploy (see docs/PROVING.md).
contract Deploy {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // Anvil account #0 (a published key): the local-simulation default deployer.
    uint256 internal constant ANVIL_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 internal constant LOCAL_CHAIN_ID = 31337;

    function run()
        external
        returns (DarkPerpSettlement settlement, CollateralVault vault, IZkVerifier verifier, MockUSDC usdc)
    {
        uint256 pk = _deployerKey();
        address sequencer = vm.addr(pk);
        // Preflight before any broadcast: a missing or public signer fails up front. Not
        // kept in a named local, to stay under the non-viaIR stack limit.
        _gatewaySigner(sequencer);
        address enclaveSigner = vm.envOr("ENCLAVE_SIGNER", sequencer);
        bytes32 genesis = bytes32(vm.envOr("GENESIS_ROOT", uint256(0)));
        uint256 liveness = vm.envOr("LIVENESS_BLOCKS", uint256(7200));
        uint256 challengeWindow = vm.envOr("CHALLENGE_BLOCKS", uint256(300));
        uint256 challengeBond = vm.envOr("CHALLENGE_BOND", uint256(0.01 ether));
        uint256 inclusionDeadline = vm.envOr("INCLUSION_DEADLINE_SECS", uint256(600));
        address governance = vm.envOr("GOVERNANCE", sequencer);
        uint256 finalSettleGrace = vm.envOr("FINAL_SETTLE_GRACE_BLOCKS", uint256(300));

        // Verifier selection: a set VERIFIER binds a real (e.g. SP1) verifier;
        // unset/zero deploys MockZkVerifier (dev/testnet only).
        address verifierEnv = vm.envOr("VERIFIER", address(0));
        if (verifierEnv == address(0)) {
            // audit DP-007: MockZkVerifier accepts proof == publicCommitment (unsound). Never
            // wire it on a real-value chain — the sequencer could publish any withdrawals root
            // and drain the vault. Testnets only, unless the operator explicitly overrides.
            // (A real VERIFIER needs no Mock guard.)
            require(
                DeployGuard.isTestnet(block.chainid) || vm.envOr("ALLOW_MOCK_VERIFIER", uint256(0)) == 1,
                "Deploy: MockZkVerifier is unsound; refusing on a non-testnet chain (set ALLOW_MOCK_VERIFIER=1 to override, UNSAFE)"
            );
        }

        vm.startBroadcast(pk);

        verifier = verifierEnv == address(0) ? IZkVerifier(address(new MockZkVerifier())) : IZkVerifier(verifierEnv);
        settlement = new DarkPerpSettlement(
            sequencer,
            enclaveSigner,
            verifier,
            genesis,
            liveness,
            challengeWindow,
            challengeBond,
            inclusionDeadline,
            governance,
            finalSettleGrace
        );
        // USDC is the collateral asset (6 decimals). MockUSDC ships an open faucet
        // for the testnet — replace with the canonical USDC address before mainnet.
        usdc = new MockUSDC();
        // SEC-019 (Task 6c): the gateway key that authorizes deposit entry. Only a local
        // simulation may default it to the sequencer (`_gatewaySigner`).
        vault = new CollateralVault(address(settlement), address(usdc), _gatewaySigner(sequencer));
        settlement.setVault(address(vault));

        // seed the deployer (sequencer) with 1,000,000 USDC so it can post the bond
        // and the demo can fund accounts without an external faucet.
        usdc.mint(sequencer, 1_000_000_000_000);

        vm.stopBroadcast();
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

    /// The vault's deposit-authorization signer. Off the local anvil chain it must be set
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
