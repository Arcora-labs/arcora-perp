// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IChainlinkStreamsVerifier} from "../../src/ChainlinkOracleVerifier.sol";
import {ICollateralVault} from "../../src/DarkPerpSettlement.sol";

/// Test-only exact full-container allowlist. This is not a DON signature verifier.
/// Keep this file independent of generated fixtures: its runtime identity is
/// captured before the target-bound native witness is built.
contract BridgeExactStreams is IChainlinkStreamsVerifier {
    address public immutable owner = msg.sender;
    mapping(bytes32 => bytes) private bodies;
    bool public locked;
    error UnpinnedContainer();
    error ConfigurationLocked();

    function allow(bytes calldata full, bytes calldata body) external {
        require(msg.sender == owner, "mock DON owner");
        if (locked) revert ConfigurationLocked();
        require(full.length != 0 && body.length == 288, "mock DON fixture");
        bytes32 id = keccak256(full);
        bytes memory previous = bodies[id];
        require(previous.length == 0 || keccak256(previous) == keccak256(body), "mock DON body replacement");
        bodies[id] = body;
    }

    function lock() external {
        require(msg.sender == owner, "mock DON owner");
        locked = true;
    }

    function verify(bytes calldata full, bytes calldata parameters) external payable returns (bytes memory) {
        require(locked && msg.value == 0 && parameters.length == 0, "mock DON call");
        bytes memory body = bodies[keccak256(full)];
        if (body.length == 0) revert UnpinnedContainer();
        return body;
    }
}

/// Test-only ledger prefix for the source witness's nine synthetic deposits.
/// It has no assets and implements no claims. Count/root checks and publication
/// exercise the real settlement entrypoint without claiming collateral custody.
contract BridgeStrictPrefixVault is ICollateralVault {
    address public immutable publisher;
    uint64 public immutable depositCount;
    bytes32 public immutable depositChainTip;
    bytes32 public publishedRoot;
    uint256 public publishedEpoch;
    uint256 public publicationCount;
    error WrongPrefixCount();

    constructor(address publisher_, uint64 count_, bytes32 tip_) {
        require(publisher_ != address(0) && count_ == 9 && tip_ != bytes32(0), "synthetic prefix");
        publisher = publisher_;
        depositCount = count_;
        depositChainTip = tip_;
    }

    function tvl() external pure returns (uint256) {
        return 0;
    }

    function token() external pure returns (address) {
        return address(0);
    }

    function depositTipAt(uint64 count) external view returns (bytes32) {
        if (count != depositCount) revert WrongPrefixCount();
        return depositChainTip;
    }

    function publishWithdrawals(bytes32 root, uint256 epoch) external {
        require(msg.sender == publisher, "mock prefix publisher");
        publishedRoot = root;
        publishedEpoch = epoch;
        publicationCount++;
    }
}
