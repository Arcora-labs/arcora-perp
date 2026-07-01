// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DeployGuard
/// @notice Chain-id allowlist gating deployment of the unsound `MockZkVerifier`
/// (audit DP-007). The mock accepts `proof == publicCommitment`, so deploying it on a
/// real-value chain would let the sequencer publish any withdrawals root and drain the
/// vault. Only testnets may receive the mock; a real-value chain requires an explicit
/// `ALLOW_MOCK_VERIFIER=1` override at the deploy script.
library DeployGuard {
    /// @return true if `chainId` is a testnet the mock verifier may be deployed to.
    function isTestnet(uint256 chainId) internal pure returns (bool) {
        return chainId == 84532 // Base Sepolia
            || chainId == 11155111 // Sepolia
            || chainId == 421614 // Arbitrum Sepolia
            || chainId == 11155420 // OP Sepolia
            || chainId == 80002 // Polygon Amoy
            || chainId == 31337 // anvil / hardhat
            || chainId == 1337; // ganache
    }
}
