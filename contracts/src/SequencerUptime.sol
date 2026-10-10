// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Strict last-known sequencer status, not a price heartbeat or a finality proof.
/// The feed address and grace duration must be independently approved for deployment.
library SequencerUptime {
    struct Epoch {
        uint80 roundId;
        uint64 startedAt;
    }

    /// A fixed-size output buffer prevents a malformed feed from allocating arbitrary
    /// returndata. Any failed call, noncanonical ABI, down/unknown status, invalid
    /// clock or unfinished grace period returns false, never a healthy fallback.
    function read(address feed, uint64 graceSeconds) internal view returns (bool ready, Epoch memory epoch) {
        bytes memory request = abi.encodeWithSelector(bytes4(keccak256("latestRoundData()")));
        uint256[5] memory words;
        bool ok;
        uint256 size;
        assembly ("memory-safe") {
            ok := staticcall(gas(), feed, add(request, 32), mload(request), words, 160)
            size := returndatasize()
        }
        if (
            !ok || size != 160 || words[0] == 0 || words[0] > type(uint80).max || words[4] > type(uint80).max
                || words[1] != 0 || words[2] == 0 || words[2] > type(uint64).max || words[2] > block.timestamp
                || graceSeconds == 0
        ) return (false, epoch);
        // startedAt is the status-change time. An unchanged healthy status may be
        // old; applying an invented price-style heartbeat to updatedAt is incorrect.
        if (block.timestamp - words[2] <= graceSeconds) return (false, epoch);
        epoch = Epoch(uint80(words[0]), uint64(words[2]));
        return (true, epoch);
    }

    function same(Epoch memory a, Epoch memory b) internal pure returns (bool) {
        return a.roundId == b.roundId && a.startedAt == b.startedAt;
    }
}
