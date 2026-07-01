// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {DeployGuard} from "../script/DeployGuard.sol";

/// audit DP-007: the unsound MockZkVerifier may only be deployed to testnets.
contract DeployGuardTest is MiniTest {
    function test_testnets_allow_the_mock_verifier() public {
        assertTrue(DeployGuard.isTestnet(84532), "Base Sepolia is a testnet");
        assertTrue(DeployGuard.isTestnet(11155111), "Sepolia is a testnet");
        assertTrue(DeployGuard.isTestnet(31337), "anvil is a testnet");
    }

    function test_real_value_chains_block_the_mock_verifier() public {
        assertFalse(DeployGuard.isTestnet(1), "Ethereum mainnet blocked");
        assertFalse(DeployGuard.isTestnet(8453), "Base mainnet blocked");
        assertFalse(DeployGuard.isTestnet(42161), "Arbitrum One blocked");
    }
}
