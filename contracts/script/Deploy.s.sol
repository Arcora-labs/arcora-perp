// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "../test/utils/MiniTest.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";
import {IZkVerifier} from "../src/interfaces/IZkVerifier.sol";

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
///   GENESIS_ROOT     initial state root
///   LIVENESS_BLOCKS  close-only liveness timeout (default 7200 ≈ 1 day)
///   CHALLENGE_BLOCKS inclusion challenge window (default 300 ≈ 1 hr)
///   CHALLENGE_BOND   challenger stake in wei (default 0.01 ether)
///
/// NOTE: ships with MockZkVerifier — replace with the real SP1/Risc0 verifier
/// before any non-testnet deploy (see docs/PROVING.md).
contract Deploy {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // default anvil account #0 (well-known; testnet only)
    uint256 internal constant DEFAULT_PK =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run()
        external
        returns (DarkPerpSettlement settlement, CollateralVault vault, IZkVerifier verifier)
    {
        uint256 pk = vm.envOr("PRIVATE_KEY", DEFAULT_PK);
        address sequencer = vm.addr(pk);
        address enclaveSigner = vm.envOr("ENCLAVE_SIGNER", sequencer);
        bytes32 genesis = bytes32(vm.envOr("GENESIS_ROOT", uint256(0)));
        uint256 liveness = vm.envOr("LIVENESS_BLOCKS", uint256(7200));
        uint256 challengeWindow = vm.envOr("CHALLENGE_BLOCKS", uint256(300));
        uint256 challengeBond = vm.envOr("CHALLENGE_BOND", uint256(0.01 ether));

        vm.startBroadcast(pk);

        verifier = new MockZkVerifier();
        settlement = new DarkPerpSettlement(
            sequencer, enclaveSigner, verifier, genesis, liveness, challengeWindow, challengeBond
        );
        vault = new CollateralVault(address(settlement));
        settlement.setVault(address(vault));

        vm.stopBroadcast();
    }
}
