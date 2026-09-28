// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {RealSP1TestBase, RealSP1Gateway} from "./RealSP1TestBase.sol";
import {SP1ZkVerifier} from "../src/SP1ZkVerifier.sol";

/// Requires a real ordinary Arcora Groth16 proof, supplied by the strict Python
/// runner after artifact hash/binding validation. No fallback or skipped tests.
contract SP1RealProofTest is RealSP1TestBase {
    SP1ZkVerifier internal adapter;
    bytes32 internal vkey;
    bytes32 internal commitment;
    bytes internal proof;

    function setUp() public override {
        super.setUp();
        vkey = realVm.envBytes32("ARCORA_REAL_PROGRAM_VKEY");
        commitment = realVm.envBytes32("ARCORA_REAL_PUBLIC_COMMITMENT");
        proof = realVm.envBytes("ARCORA_REAL_PROOF");
        require(proof.length == 356, "SP1 v6.1 Groth16 payload length");
        require(bytes4(proof) == SELECTOR, "SP1 v6.1 verifier selector");
        adapter = _adapter(realGateway, vkey);
    }

    function test_real_verifier_accepts_arcora_proof() public view {
        realVerifier.verifyProof(vkey, abi.encodePacked(commitment), proof);
    }

    function test_real_gateway_accepts_arcora_proof() public view {
        realGateway.verifyProof(vkey, abi.encodePacked(commitment), proof);
    }

    function test_adapter_accepts_arcora_proof() public view {
        assertTrue(adapter.verify(commitment, proof), "actual Arcora proof must pass adapter");
    }

    function test_wrong_program_key_rejected_by_verifier_and_adapter() public {
        bytes32 wrong = bytes32(uint256(vkey) ^ 1);
        SP1ZkVerifier other = _adapter(realGateway, wrong);
        vm.expectRevert();
        realVerifier.verifyProof(wrong, abi.encodePacked(commitment), proof);
        assertFalse(other.verify(commitment, proof), "wrong program key");
    }

    function test_wrong_commitment_rejected_by_verifier_and_adapter() public {
        bytes32 wrong = bytes32(uint256(commitment) ^ 1);
        vm.expectRevert();
        realVerifier.verifyProof(vkey, abi.encodePacked(wrong), proof);
        assertFalse(adapter.verify(wrong, proof), "wrong public commitment");
    }

    function test_changed_proof_rejected_by_verifier_and_adapter() public {
        bytes memory changed = proof;
        changed[changed.length - 1] ^= bytes1(uint8(1));
        vm.expectRevert();
        realVerifier.verifyProof(vkey, abi.encodePacked(commitment), changed);
        assertFalse(adapter.verify(commitment, changed), "changed proof");
    }

    function test_truncated_proof_rejected_by_verifier_and_adapter() public {
        bytes memory truncated = new bytes(proof.length - 1);
        for (uint256 i; i < truncated.length; ++i) {
            truncated[i] = proof[i];
        }
        vm.expectRevert();
        realVerifier.verifyProof(vkey, abi.encodePacked(commitment), truncated);
        assertFalse(adapter.verify(commitment, truncated), "truncated proof");
    }

    function test_wrong_selector_rejected_by_verifier_and_adapter() public {
        bytes memory changed = proof;
        changed[0] ^= bytes1(uint8(1));
        vm.expectRevert();
        realVerifier.verifyProof(vkey, abi.encodePacked(commitment), changed);
        assertFalse(adapter.verify(commitment, changed), "wrong selector");
    }

    function test_frozen_gateway_route_rejects_valid_proof() public {
        realGateway.freezeRoute(SELECTOR);
        vm.expectRevert();
        realGateway.verifyProof(vkey, abi.encodePacked(commitment), proof);
        assertFalse(adapter.verify(commitment, proof), "frozen route");
    }

    function test_unconfigured_gateway_rejects_valid_proof() public {
        RealSP1Gateway unconfigured = _newGateway();
        SP1ZkVerifier other = _adapter(unconfigured, vkey);
        vm.expectRevert();
        unconfigured.verifyProof(vkey, abi.encodePacked(commitment), proof);
        assertFalse(other.verify(commitment, proof), "missing route");
    }
}
