// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SP1ZkVerifier} from "../src/SP1ZkVerifier.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {MockSP1Verifier} from "../src/mocks/MockSP1Verifier.sol";

contract SP1ZkVerifierTest is MiniTest {
    MockSP1Verifier internal gateway;
    SP1ZkVerifier internal adapter;

    bytes32 internal constant VKEY = bytes32(uint256(0xA11CE));
    bytes32 internal constant COMMIT = bytes32(uint256(0xC0117));
    bytes internal PROOF = hex"11223344deadbeef"; // 4-byte version prefix + body (opaque here)

    function setUp() public {
        gateway = new MockSP1Verifier();
        adapter = new SP1ZkVerifier(ISP1Verifier(address(gateway)), VKEY);
    }

    /// A proof the gateway accepts (exact vkey + abi.encodePacked(commitment) + proof) → true.
    function test_verify_true_on_matching_proof() public {
        gateway.setExpected(VKEY, abi.encodePacked(COMMIT), PROOF);
        assertTrue(adapter.verify(COMMIT, PROOF), "matching proof must verify");
    }

    /// Gateway reverts on a different proof → adapter maps revert to false (NOT a bubbled revert).
    function test_verify_false_on_bad_proof() public {
        gateway.setExpected(VKEY, abi.encodePacked(COMMIT), PROOF);
        assertFalse(adapter.verify(COMMIT, hex"11223344ffff"), "bad proof must be false");
    }

    /// Proves publicValues == abi.encodePacked(publicCommitment): a different commitment
    /// changes the publicValues the adapter forwards → gateway rejects → false.
    function test_verify_false_on_wrong_commitment() public {
        gateway.setExpected(VKEY, abi.encodePacked(COMMIT), PROOF);
        assertFalse(adapter.verify(bytes32(uint256(0xBEEF)), PROOF), "wrong commitment must be false");
    }

    /// vkey binding: an adapter pinned to a different vkey than the gateway expects → false.
    function test_verify_false_on_wrong_vkey() public {
        SP1ZkVerifier wrong = new SP1ZkVerifier(ISP1Verifier(address(gateway)), bytes32(uint256(0xB0B)));
        gateway.setExpected(VKEY, abi.encodePacked(COMMIT), PROOF);
        assertFalse(wrong.verify(COMMIT, PROOF), "wrong vkey must be false");
    }

    /// Immutables are pinned from the constructor.
    function test_immutables_pinned() public view {
        assertEq(adapter.programVKey(), VKEY, "vkey pinned");
        assertEq(address(adapter.gateway()), address(gateway), "gateway pinned");
    }
}
