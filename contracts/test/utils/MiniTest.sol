// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal subset of the Foundry cheatcode interface. forge-std is unavailable in
/// this environment (the git proxy is repo-scoped), so we declare exactly what
/// the tests need against the well-known cheatcode address.
interface Vm {
    function roll(uint256) external;
    function warp(uint256) external;
    function chainId(uint256) external;
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function deal(address, uint256) external;
    function expectRevert() external;
    function expectRevert(bytes4) external;
    function expectRevert(bytes calldata) external;
    function assume(bool) external;
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
    function envOr(string calldata name, uint256 defaultValue) external view returns (uint256);
    function envOr(string calldata name, address defaultValue) external view returns (address);
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function label(address, string calldata) external;
}

/// Tiny test base: exposes `vm` and a few assertions that revert on failure so
/// `forge test` reports them. Any contract with `test*` functions is a test.
contract MiniTest {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function assertTrue(bool c, string memory m) internal pure {
        require(c, m);
    }

    function assertEq(uint256 a, uint256 b, string memory m) internal pure {
        require(a == b, m);
    }

    function assertEq(bytes32 a, bytes32 b, string memory m) internal pure {
        require(a == b, m);
    }

    function assertEq(address a, address b, string memory m) internal pure {
        require(a == b, m);
    }

    function assertFalse(bool c, string memory m) internal pure {
        require(!c, m);
    }
}
