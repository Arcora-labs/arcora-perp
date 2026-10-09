// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Experimental pre-proof time registration. NOT used by settlement.
/// @dev This contract neither verifies proofs nor authenticates operation times.
/// A future coordinator must enforce canonical batch/root continuity, and the
/// guest must derive the original time bounds and bind this receipt into the
/// verified public commitment. On Base, block.timestamp is settlement-chain
/// (L2) time, not a direct Ethereum L1 timestamp attestation.
contract BatchClockAnchorPrototype {
    bytes32 public constant DOMAIN = keccak256("arcora:batch-clock-anchor:prototype:v1");
    address public immutable coordinator;
    uint64 public immutable maxWindowMs;
    uint64 public immutable clockSkewMs;

    struct Anchor {
        bytes32 contentHash;
        bytes32 commitment;
        uint64 anchoredAtMs;
        bool exists;
    }

    mapping(bytes32 => Anchor) private records;

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidRange();
    error Backdated();
    error FutureDated();
    error TimeOverflow();
    error ReplacementForbidden();
    error MissingAnchor();

    event Anchored(bytes32 indexed key, bytes32 commitment, uint64 firstOpMs, uint64 lastOpMs, uint64 anchoredAtMs);

    constructor(address coordinator_, uint64 maxWindowMs_, uint64 clockSkewMs_) {
        if (coordinator_ == address(0) || maxWindowMs_ == 0) revert InvalidConfiguration();
        coordinator = coordinator_;
        maxWindowMs = maxWindowMs_;
        clockSkewMs = clockSkewMs_;
    }

    function keyFor(uint64 batchId, bytes32 previousRoot) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, block.chainid, address(this), batchId, previousRoot));
    }

    /// @notice Register before expensive proving; do not rewrite the execution log.
    /// @dev Exact retries return the original receipt even after a long proof delay.
    /// Changing an already registered context is rejected, not silently refreshed.
    function register(uint64 batchId, bytes32 previousRoot, bytes32 manifestHash, uint64 firstOpMs, uint64 lastOpMs)
        external
        returns (bytes32)
    {
        if (msg.sender != coordinator) revert Unauthorized();
        bytes32 key = keyFor(batchId, previousRoot);
        bytes32 contentHash = keccak256(abi.encode(manifestHash, firstOpMs, lastOpMs));
        Anchor storage existing = records[key];
        if (existing.exists) {
            if (existing.contentHash != contentHash) revert ReplacementForbidden();
            return existing.commitment;
        }
        if (firstOpMs > lastOpMs || uint256(lastOpMs) - firstOpMs > maxWindowMs) revert InvalidRange();
        if (block.timestamp > type(uint64).max / 1000) revert TimeOverflow();
        uint64 nowMs = uint64(block.timestamp * 1000);
        if (uint256(lastOpMs) + clockSkewMs < nowMs) revert Backdated();
        if (uint256(lastOpMs) > uint256(nowMs) + clockSkewMs) revert FutureDated();
        bytes32 commitment = keccak256(abi.encode(DOMAIN, key, contentHash, nowMs));
        records[key] = Anchor(contentHash, commitment, nowMs, true);
        emit Anchored(key, commitment, firstOpMs, lastOpMs, nowMs);
        return commitment;
    }

    function getAnchor(uint64 batchId, bytes32 previousRoot) external view returns (Anchor memory) {
        Anchor memory record = records[keyFor(batchId, previousRoot)];
        if (!record.exists) revert MissingAnchor();
        return record;
    }
}
