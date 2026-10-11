// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ChainlinkNativeContractBridgeTypes {
    // Static 32-word context emitted by actual EVM execution. Field order is
    // shared with the bounded external capture decoder, not a live RPC adapter.
    struct Context {
        uint64 chainId;
        uint8 network;
        address clockVerifier;
        address settlement;
        address oracleWrapper;
        address verifierProxy;
        address sp1Adapter;
        address sp1Gateway;
        address uptimeFeed;
        address prefixVault;
        bytes32 clockVerifierCodeHash;
        bytes32 settlementCodeHash;
        bytes32 oracleWrapperCodeHash;
        bytes32 verifierProxyCodeHash;
        bytes32 sp1AdapterCodeHash;
        bytes32 sp1GatewayCodeHash;
        bytes32 uptimeFeedCodeHash;
        bytes32 prefixVaultCodeHash;
        uint64 anchoredAtMs;
        uint64 maxWindowMs;
        uint64 clockSkewMs;
        uint80 uptimeRoundId;
        uint64 uptimeStartedAt;
        uint64 graceSeconds;
        bytes32 registeredReceipt;
        bytes32 clockCommitment;
        bytes32 sourceWitnessSha256;
        bytes32 baseCommitment;
        bytes32 policyHash;
        uint64 postConsumedDepositCount;
        bytes32 postConsumedDepositTip;
        bytes32 programVkey;
    }

    struct SourceData {
        bytes32 sourceWitnessSha256;
        // prev, manifest, new, ordered, withdrawals, rejected, deposits.
        bytes32[7] roots;
        uint64 depositCount;
        uint64 batchId;
        uint8 phase;
        bytes32 baseCommitment;
        bytes32 policyHash;
        bytes32 evidenceHash;
        bytes32 inputHash;
        uint64 firstMs;
        uint64 lastMs;
        uint64 timedOps;
        uint64 maxWindowMs;
        uint64 clockSkewMs;
        bytes entriesAbi;
    }

    struct VectorData {
        Context context;
        bytes32 witnessSha256;
        bytes32 nativeCommitment;
    }
}
