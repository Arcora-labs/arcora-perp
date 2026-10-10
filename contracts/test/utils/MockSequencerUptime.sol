// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Explicitly synthetic uptime source. It authenticates no real network status.
contract MockSequencerUptime {
    bytes private response;
    bool private shouldRevert;

    constructor() {
        set(1, 0, 1);
    }

    function set(uint80 roundId, int256 status, uint64 startedAt) public {
        response = abi.encode(roundId, status, uint256(startedAt), uint256(startedAt), roundId);
        shouldRevert = false;
    }

    function setRaw(bytes calldata data, bool fail) external {
        response = data;
        shouldRevert = fail;
    }

    fallback() external {
        require(msg.sig == bytes4(keccak256("latestRoundData()")), "unexpected query");
        require(!shouldRevert, "synthetic feed unavailable");
        bytes memory data = response;
        assembly ("memory-safe") { return(add(data, 32), mload(data)) }
    }
}
