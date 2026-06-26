// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {IDcapAttestation} from "../src/interfaces/IDcapAttestation.sol";
import {MockDcapAttestation} from "../src/mocks/MockDcapAttestation.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";

contract AttestationRegistryTest is MiniTest {
    MockDcapAttestation mock;
    bytes32 measurementHash;
    bytes mrTd; // 48 bytes
    bytes rtmrs; // 192 bytes (RTMR0..3)
    bytes reportData; // 64 bytes

    // The enclave signer carried in the first 20 bytes of the report data.
    address constant ENCLAVE = 0x1111111111111111111111111111111111111111;

    function setUp() public {
        mock = new MockDcapAttestation();
        // The pinned golden MRTD from the off-chain attestation vector.
        mrTd =
            hex"91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7";
        // Four RTMRs (RTMR0..3), 192 bytes; content is arbitrary-but-fixed here.
        rtmrs = new bytes(192);
        for (uint256 i = 0; i < 192; i++) {
            rtmrs[i] = 0x22;
        }
        // Identity binds the FULL measurement state, not MRTD alone.
        measurementHash = keccak256(bytes.concat(mrTd, rtmrs));

        reportData = new bytes(64);
        for (uint256 i = 0; i < 20; i++) {
            reportData[i] = 0x11;
        }
    }

    function _registry() internal returns (AttestationRegistry) {
        return new AttestationRegistry(IDcapAttestation(address(mock)), measurementHash);
    }

    function test_registers_a_current_matching_enclave() public {
        mock.setResult(true, 0, mrTd, rtmrs, reportData);
        AttestationRegistry reg = _registry();
        reg.register(hex"00");
        assertTrue(reg.registered(), "registered");
        assertEq(reg.enclaveSigner(), ENCLAVE, "signer bound from report data");
    }

    function test_accepts_sw_hardening_needed() public {
        // SWHardeningNeeded (status 1) is the common real-hardware case and is
        // accepted on-chain too, matching the off-chain `is_acceptable` set.
        mock.setResult(true, 1, mrTd, rtmrs, reportData);
        AttestationRegistry reg = _registry();
        reg.register(hex"00");
        assertTrue(reg.registered(), "SWHardeningNeeded accepted");
    }

    function test_rejects_an_unverified_quote() public {
        mock.setResult(false, 0, mrTd, rtmrs, reportData);
        AttestationRegistry reg = _registry();
        vm.expectRevert(AttestationRegistry.QuoteRejected.selector);
        reg.register(hex"00");
    }

    function test_rejects_a_degraded_tcb() public {
        mock.setResult(true, 5, mrTd, rtmrs, reportData); // 5 = OutOfDate
        AttestationRegistry reg = _registry();
        vm.expectRevert(abi.encodeWithSelector(AttestationRegistry.TcbNotAcceptable.selector, uint8(5)));
        reg.register(hex"00");
    }

    function test_rejects_a_measurement_mismatch() public {
        bytes memory wrong = mrTd;
        wrong[0] = 0x00; // one-byte MRTD difference → different measurement
        mock.setResult(true, 0, wrong, rtmrs, reportData);
        AttestationRegistry reg = _registry();
        vm.expectRevert(AttestationRegistry.MeasurementMismatch.selector);
        reg.register(hex"00");
    }

    function test_rejects_an_rtmr_mismatch() public {
        // RTMRs are part of identity: a different runtime measurement (same MRTD)
        // must be rejected — this is what makes the binding application-bound.
        bytes memory wrongRtmrs = rtmrs;
        wrongRtmrs[0] = 0x00;
        mock.setResult(true, 0, mrTd, wrongRtmrs, reportData);
        AttestationRegistry reg = _registry();
        vm.expectRevert(AttestationRegistry.MeasurementMismatch.selector);
        reg.register(hex"00");
    }

    function test_register_rejects_a_non_owner() public {
        // A stranger must not be able to (re-)bind the enclave signer by replaying
        // a valid quote for the expected measurement.
        mock.setResult(true, 0, mrTd, rtmrs, reportData);
        AttestationRegistry reg = _registry(); // owner = this test contract
        vm.prank(address(0xBEEF));
        vm.expectRevert(AttestationRegistry.NotOwner.selector);
        reg.register(hex"00");
    }

    function test_rejects_truncated_report_data() public {
        bytes memory shortRd = new bytes(8); // < 20 bytes
        mock.setResult(true, 0, mrTd, rtmrs, shortRd);
        AttestationRegistry reg = _registry();
        vm.expectRevert(AttestationRegistry.BadReportData.selector);
        reg.register(hex"00");
    }
}
