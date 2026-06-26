// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDcapAttestation} from "./interfaces/IDcapAttestation.sol";

/// @title AttestationRegistry
/// @notice Records a verified enclave: it calls the DCAP attestor and REQUIRES
/// that the quote verified, the platform TCB is acceptable, and the FULL
/// measurement state (MRTD ‖ RTMR0..3) matches the expected one, then binds the
/// enclave's L1 signer carried in the report data. This is the on-chain mirror of
/// the off-chain `VerifiedAttestation::enclave_measurement` gate
/// (`crates/attestation`): it binds the same MRTD+RTMR set (RTMRs matter — on
/// Azure CVMs MRTD alone is the shared host firmware, not the application) and
/// accepts the same TCB set ({UpToDate, SWHardeningNeeded}). The on-chain
/// `keccak256(MRTD‖RTMR0..3)` encoding is intentionally distinct from the
/// off-chain keccak fold and the two must never be unified.
///
/// Kept deliberately SEPARATE from `DarkPerpSettlement` so the byte-locked
/// CrossLayer public-input vectors stay frozen — settlement can read this
/// registry's `enclaveSigner` without changing its own ABI or constructor.
contract AttestationRegistry {
    /// `tcbStatus` values accepted for key release (matches off-chain
    /// `TcbStatus::is_acceptable`). See `IDcapAttestation` for the convention.
    uint8 internal constant TCB_UP_TO_DATE = 0;
    uint8 internal constant TCB_SW_HARDENING_NEEDED = 1;

    /// The on-chain DCAP verifier (a `MockDcapAttestation` locally, the Automata
    /// adapter on Sepolia).
    IDcapAttestation public immutable attestor;
    /// `keccak256(MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2 ‖ RTMR3)` of the expected enclave —
    /// the full attested program identity, not MRTD alone.
    bytes32 public immutable expectedMeasurementHash;

    /// The operator authorized to register / rotate the enclave. Without this gate
    /// anyone could (re-)submit a valid quote for the expected measurement and
    /// overwrite `enclaveSigner` — e.g. replay an old quote to revert the bound
    /// signer to a stale enclave instance.
    address public immutable owner;

    /// The enclave's L1 signer, bound from the first 20 bytes of the report data.
    address public enclaveSigner;
    bool public registered;

    error NotOwner();
    error QuoteRejected();
    error TcbNotAcceptable(uint8 status);
    error MeasurementMismatch();
    error BadReportData();

    event EnclaveRegistered(address indexed enclaveSigner, bytes32 measurementHash);

    constructor(IDcapAttestation _attestor, bytes32 _expectedMeasurementHash) {
        attestor = _attestor;
        expectedMeasurementHash = _expectedMeasurementHash;
        owner = msg.sender;
    }

    /// Verify `rawQuote` and, iff it is an acceptable-TCB, matching-measurement TDX
    /// platform, bind the enclave signer carried in the report data. Reverts (does
    /// not silently no-op) on any failure so a caller cannot mistake rejection for
    /// success.
    function register(bytes calldata rawQuote) external {
        if (msg.sender != owner) revert NotOwner();

        (bool ok, uint8 tcbStatus, bytes memory mrTd, bytes memory rtmrs, bytes memory reportData) =
            attestor.verifyTdxQuote(rawQuote);

        if (!ok) revert QuoteRejected();
        if (tcbStatus != TCB_UP_TO_DATE && tcbStatus != TCB_SW_HARDENING_NEEDED) {
            revert TcbNotAcceptable(tcbStatus);
        }
        // Bind the FULL measurement state — MRTD plus the four RTMRs — not MRTD
        // alone, which on the Azure CVM target is the shared host firmware.
        if (keccak256(bytes.concat(mrTd, rtmrs)) != expectedMeasurementHash) {
            revert MeasurementMismatch();
        }
        if (reportData.length < 20) revert BadReportData();

        // The enclave's L1 address is the first 20 bytes of the report data.
        bytes20 signer;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            signer := mload(add(reportData, 0x20))
        }

        enclaveSigner = address(signer);
        registered = true;
        emit EnclaveRegistered(address(signer), expectedMeasurementHash);
    }
}
