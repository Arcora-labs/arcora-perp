// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {RealSP1TestBase} from "./RealSP1TestBase.sol";
import {SP1ZkVerifier} from "../src/SP1ZkVerifier.sol";

/// Structural rejection and deployment checks only; these are never evidence
/// that an Arcora proof was generated or accepted.
contract SP1RealVerifierGuardTest is RealSP1TestBase {
    SP1ZkVerifier internal adapter;
    bytes32 internal constant VKEY = bytes32(uint256(1));
    bytes32 internal constant COMMITMENT = bytes32(uint256(2));

    function setUp() public override {
        super.setUp();
        adapter = _adapter(realGateway, VKEY);
    }

    function test_pinned_verifier_identity_and_route() public view {
        assertEq(keccak256(bytes(realVerifier.VERSION())), keccak256("v6.1.0"), "version");
        assertEq(realVerifier.VERIFIER_HASH(), VERIFIER_HASH, "verifier hash");
        assertEq(realVerifier.VK_ROOT(), VK_ROOT, "recursion key root");
        (address route, bool frozen) = realGateway.routes(SELECTOR);
        assertEq(route, address(realVerifier), "gateway route");
        assertFalse(frozen, "route must be live");
        assertEq(address(adapter.gateway()), address(realGateway), "adapter gateway");
        assertEq(adapter.programVKey(), VKEY, "adapter program key");
    }

    function test_empty_proof_rejected() public view {
        assertFalse(adapter.verify(COMMITMENT, hex""), "empty proof");
    }

    function test_short_selector_rejected() public view {
        assertFalse(adapter.verify(COMMITMENT, hex"4388a2"), "short selector");
    }

    function test_selector_without_payload_rejected() public view {
        assertFalse(adapter.verify(COMMITMENT, abi.encodePacked(SELECTOR)), "missing payload");
    }

    function test_unknown_selector_rejected() public view {
        assertFalse(adapter.verify(COMMITMENT, hex"00000000"), "unknown selector");
    }

    function test_nonzero_exit_rejected() public view {
        uint256[8] memory points;
        bytes memory proof = abi.encodePacked(SELECTOR, abi.encode(uint256(1), uint256(VK_ROOT), uint256(0), points));
        assertFalse(adapter.verify(COMMITMENT, proof), "nonzero exit");
    }

    function test_wrong_recursion_root_rejected() public view {
        uint256[8] memory points;
        bytes memory proof = abi.encodePacked(SELECTOR, abi.encode(uint256(0), uint256(0), uint256(0), points));
        assertFalse(adapter.verify(COMMITMENT, proof), "wrong recursion root");
    }

    function test_zero_curve_points_rejected() public view {
        uint256[8] memory points;
        bytes memory proof = abi.encodePacked(SELECTOR, abi.encode(uint256(0), uint256(VK_ROOT), uint256(0), points));
        assertFalse(adapter.verify(COMMITMENT, proof), "zero curve points");
    }
}
