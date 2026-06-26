// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDcapAttestation} from "../interfaces/IDcapAttestation.sol";

/// @title MockDcapAttestation
/// @notice Test/testnet stand-in for an on-chain DCAP verifier (mirrors
/// `MockZkVerifier`). Returns configurable outputs so tests can exercise the
/// registry's accept/reject paths. NOT a real verifier — never deploy to mainnet;
/// the real path calls the Automata verifier behind an adapter (see
/// `IDcapAttestation`).
contract MockDcapAttestation is IDcapAttestation {
    bool public ok = true;
    uint8 public tcbStatus; // 0 = UpToDate, 1 = SWHardeningNeeded
    bytes public mrTd; // 48 bytes
    bytes public rtmrs; // 192 bytes (RTMR0..3)
    bytes public reportData; // 64 bytes

    function setResult(
        bool _ok,
        uint8 _tcbStatus,
        bytes calldata _mrTd,
        bytes calldata _rtmrs,
        bytes calldata _reportData
    ) external {
        ok = _ok;
        tcbStatus = _tcbStatus;
        mrTd = _mrTd;
        rtmrs = _rtmrs;
        reportData = _reportData;
    }

    function verifyTdxQuote(bytes calldata)
        external
        view
        returns (bool, uint8, bytes memory, bytes memory, bytes memory)
    {
        return (ok, tcbStatus, mrTd, rtmrs, reportData);
    }
}
