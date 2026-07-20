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
/// Env (all optional, with defaults):
///   PRIVATE_KEY      deployer key (default: a well-known anvil key)
///   ENCLAVE_SIGNER   secp256k1 address the enclave signs receipts with
///   GATEWAY_SIGNER   secp256k1 address the gateway signs deposit authorizations with
///                    (SEC-019 Task 6c; default: sequencer)
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

    // default anvil account #0 (well-known; testnet only)
    uint256 internal constant DEFAULT_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run()
        external
        returns (DarkPerpSettlement settlement, CollateralVault vault, IZkVerifier verifier, MockUSDC usdc)
    {
        uint256 pk = vm.envOr("PRIVATE_KEY", DEFAULT_PK);
        address sequencer = vm.addr(pk);
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
        // SEC-019 (Task 6c): the gateway key that authorizes deposit entry. Read inline
        // (not via a named local) to stay under the non-viaIR stack limit. Defaults to the
        // sequencer for a clean local dry run; set GATEWAY_SIGNER to the real gateway
        // signer address for any shared/testnet deploy.
        vault = new CollateralVault(address(settlement), address(usdc), vm.envOr("GATEWAY_SIGNER", sequencer));
        settlement.setVault(address(vault));

        // seed the deployer (sequencer) with 1,000,000 USDC so it can post the bond
        // and the demo can fund accounts without an external faucet.
        usdc.mint(sequencer, 1_000_000_000_000);

        vm.stopBroadcast();
    }
}
