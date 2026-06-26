// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IDcapAttestation
/// @notice On-chain Intel TDX DCAP quote verification — the L1 mirror of the
/// off-chain `crates/attestation` verifier (Milestone C #4). Returns
/// `success = false` rather than reverting on an invalid quote, mirroring
/// Automata's `verifyAndAttestOnChain` so a thin `AutomataDcapAdapter` can
/// implement this by calling the deployed Automata verifier on Sepolia
/// (`0x27188ABA3a26CBb806eF4C67de9b05D7d792EC10`), decoding its Output, and
/// mapping Automata's TCB enum onto the `tcbStatus` convention below. The adapter
/// is wired in the confidential-VM step (#5); contracts here depend only on this
/// interface.
///
/// `tcbStatus` convention (the adapter MUST map Automata's enum onto it, and it
/// matches the off-chain Rust `TcbStatus` acceptance set):
///   0 = UpToDate, 1 = SWHardeningNeeded  → acceptable
///   any other value                      → degraded / rejected
interface IDcapAttestation {
    /// @param rawQuote the raw TDX DCAP quote bytes
    /// @return success    true iff the quote verified cryptographically
    /// @return tcbStatus  per the convention above (0/1 acceptable)
    /// @return mrTd       the 48-byte TD measurement (MRTD)
    /// @return rtmrs      the four runtime measurement registers, RTMR0..3
    ///                    concatenated (4 * 48 = 192 bytes)
    /// @return reportData the 64-byte report data (binds the enclave's L1 signer)
    function verifyTdxQuote(bytes calldata rawQuote)
        external
        returns (bool success, uint8 tcbStatus, bytes memory mrTd, bytes memory rtmrs, bytes memory reportData);
}
