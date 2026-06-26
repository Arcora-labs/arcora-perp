//! Hermetic offline verification of a real TDX DCAP quote.
//!
//! The quote + collateral are pinned bytes vendored from Phala's `dcap-qvl`
//! sample suite (commit 9bffe30b); the test does no network I/O and pins the
//! verification timestamp inside the collateral validity window, so it is fully
//! deterministic and CI-safe.

use dark_perp_attestation::{
    verify_tdx_quote, AttestationError, Collateral, TcbStatus, VerifiedAttestation,
};

const QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote");
const COLLATERAL: &[u8] = include_bytes!("fixtures/tdx_quote_collateral.json");

/// 2025-07-04T10:16:03Z — midpoint of the collateral window
/// [issueDate 2025-06-19 .. nextUpdate 2025-07-19].
const NOW_SECS: u64 = 1_751_624_163;

const OUTDATED_QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote_outdated");
const OUTDATED_COLLATERAL: &[u8] = include_bytes!("fixtures/tdx_quote_outdated_collateral.json");
/// Midpoint of the outdated vector's window [2026-02-18 .. 2026-03-20].
const OUTDATED_NOW: u64 = 1_772_708_331;

// A REAL Azure TDX confidential-VM quote (DC2es_v6, westus, Ubuntu 24.04 CVM),
// captured via the vTPM/HCL path → IMDS `/acc/tdquote`, with its live collateral.
const AZURE_QUOTE: &[u8] = include_bytes!("fixtures/azure/quote.bin");
const AZURE_COLLATERAL: &[u8] = include_bytes!("fixtures/azure/collateral.json");
/// Midpoint of the Azure collateral window [2026-06-26 .. 2026-07-26].
const AZURE_NOW: u64 = 1_783_775_325;
/// The captured Azure platform's MRTD (its guest-firmware measurement).
const AZURE_MRTD: &str = "7a27f95e1b4da54e7b67b1bf640c9e9914c29757fc49a168fed007a51db459042b0c685213dfe0796a706646c49205a5";

/// Golden values from the pinned Phala TDX v4 vector.
const GOLDEN_MRTD: &str = "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7";
const GOLDEN_RTMR0: &str = "44c0197b39157fdd7a4dcc44767f9d6b0bb3977c7a8e347b8492f827fe9d9e5c48aca29b220b80b6a540cf994b9bc9c0";
const GOLDEN_REPORT_DATA: &str = "9a9d48e7f6799642d3d1b34e1e5e1742d4bb02dd6ddd551862c1211d35c304f9eca3efdbb481601c163cf52493d6e44aed55d51ec39b7e518fadb92c2b523f20";

#[test]
fn verifies_pinned_tdx_quote_and_extracts_measurements() {
    let collateral = Collateral::from_json(COLLATERAL).expect("collateral JSON parses");
    let att = verify_tdx_quote(QUOTE, &collateral, NOW_SECS).expect("pinned quote verifies");

    assert_eq!(att.quote_version, 4, "Phala sample is a TDX v4 quote");
    assert_eq!(
        att.tcb_status,
        TcbStatus::UpToDate,
        "sample platform TCB is up to date"
    );
    assert_eq!(
        hex::encode(att.mr_td),
        GOLDEN_MRTD,
        "MRTD must match the pinned golden"
    );
    assert_eq!(
        hex::encode(att.rtmr[0]),
        GOLDEN_RTMR0,
        "RTMR0 must match the pinned golden"
    );
    assert_eq!(
        hex::encode(att.report_data),
        GOLDEN_REPORT_DATA,
        "report_data must match the pinned golden"
    );
}

#[test]
fn rejects_a_tampered_quote() {
    // Flip one byte inside the signed TD report (MRTD region, offset 184). The
    // ECDSA signature over the report must then fail — proving verification is a
    // real cryptographic check, not parse-and-trust.
    let collateral = Collateral::from_json(COLLATERAL).expect("collateral JSON parses");
    let mut tampered = QUOTE.to_vec();
    tampered[184] ^= 0x01;
    let err = verify_tdx_quote(&tampered, &collateral, NOW_SECS)
        .expect_err("a tampered quote must not verify");
    assert!(matches!(err, AttestationError::Verify(_)), "got {err:?}");
}

#[test]
fn measurement_is_deterministic_and_binds_mrtd_and_rtmrs() {
    let collateral = Collateral::from_json(COLLATERAL).expect("collateral JSON parses");
    let att = verify_tdx_quote(QUOTE, &collateral, NOW_SECS).expect("pinned quote verifies");

    // The only public path to a measurement is the TCB-gated one.
    let m = att
        .enclave_measurement()
        .expect("acceptable TCB releases the measurement");
    assert_eq!(
        m,
        att.enclave_measurement().unwrap(),
        "fold is deterministic"
    );
    assert_ne!(m, [0u8; 32], "fold is not the zero digest");
    assert_ne!(
        &m[..],
        &att.mr_td[..32],
        "fold is a hash, not an MRTD truncation"
    );

    // Bound to the MRTD: changing the firmware measurement changes the identity.
    let mut other_mrtd = att.clone();
    other_mrtd.mr_td[0] ^= 0x01;
    assert_ne!(
        other_mrtd.enclave_measurement().unwrap(),
        m,
        "a different MRTD yields a different measurement"
    );

    // Bound to the RTMRs too: on TDX platforms that measure boot into the RTMRs
    // (bare-metal / non-Azure), a different kernel/initrd/app changes the identity.
    // (On Azure CVMs the RTMRs are ZERO and app-identity lives in the vTPM instead
    // — see `verifies_a_real_azure_tdx_quote_offline`; folding RTMRs stays correct
    // and harmless either way.)
    let mut other_rtmr = att.clone();
    other_rtmr.rtmr[1][0] ^= 0x01;
    assert_ne!(
        other_rtmr.enclave_measurement().unwrap(),
        m,
        "a different RTMR yields a different measurement"
    );
}

#[test]
fn acceptable_platform_yields_a_measurement() {
    let collateral = Collateral::from_json(COLLATERAL).expect("collateral JSON parses");
    let att = verify_tdx_quote(QUOTE, &collateral, NOW_SECS).expect("pinned quote verifies");
    assert!(att.tcb_status.is_acceptable());
    assert!(
        att.enclave_measurement().is_ok(),
        "acceptable TCB releases the measurement"
    );
}

#[test]
fn rejects_an_outdated_platform_quote() {
    // NOTE: dcap-qvl's verify() rejects a quote outright only when its TCB SVN
    // matches NO known level (this vector) or the level is Revoked — it returns
    // Ok(status=OutOfDate) for an out-of-date platform that DOES match an OutOfDate
    // level. So verification is NOT the TCB gate; `is_acceptable()` /
    // `enclave_measurement()` is (see `key_release_gate_accepts_only_current_tcb`).
    // This vector's SVN matches no level, so verify() itself fails.
    let collateral = Collateral::from_json(OUTDATED_COLLATERAL).expect("collateral JSON parses");
    let err = verify_tdx_quote(OUTDATED_QUOTE, &collateral, OUTDATED_NOW)
        .expect_err("an outdated platform must not verify");
    assert!(matches!(err, AttestationError::Verify(_)), "got {err:?}");
}

/// A synthetic attestation with a chosen TCB status (all fields are public),
/// to exercise the key-release policy gate independent of a sample vector.
fn synthetic(status: TcbStatus) -> VerifiedAttestation {
    VerifiedAttestation {
        mr_td: [0x11; 48],
        rtmr: [[0u8; 48]; 4],
        report_data: [0u8; 64],
        tcb_status: status,
        advisory_ids: Vec::new(),
        quote_version: 4,
    }
}

#[test]
fn verifies_a_real_azure_tdx_quote_offline() {
    // Proves the verifier works on a REAL Azure TDX quote (not just the Phala
    // sample) — full PCK chain + TCB evaluation against its pinned collateral, no
    // network. Documents two facts the real quote revealed:
    //   1. report_data is the Azure HCL runtime-data hash (32 bytes + zero pad) —
    //      NOT app-settable, so a key/nonce must bind transitively via the vTPM AK.
    //   2. all four RTMRs are ZERO: Azure measures boot into the vTPM PCRs, not the
    //      TD RTMRs, so on this platform MRTD is firmware identity and application
    //      identity lives in the vTPM layer (folding RTMRs is harmless but adds
    //      nothing here — see docs/ATTESTATION.md).
    let collateral = Collateral::from_json(AZURE_COLLATERAL).expect("azure collateral parses");
    let att =
        verify_tdx_quote(AZURE_QUOTE, &collateral, AZURE_NOW).expect("real azure quote verifies");

    assert_eq!(att.quote_version, 4);
    assert_eq!(
        att.tcb_status,
        TcbStatus::UpToDate,
        "captured platform was up to date"
    );
    assert_eq!(hex::encode(att.mr_td), AZURE_MRTD, "real Azure MRTD");
    assert!(
        att.rtmr.iter().all(|r| r == &[0u8; 48]),
        "Azure leaves TD RTMRs zero (vTPM-measured boot)"
    );
    assert_ne!(
        &att.report_data[..32],
        &[0u8; 32],
        "report_data carries the HCL runtime-data hash"
    );
    assert!(
        att.enclave_measurement().is_ok(),
        "acceptable TCB releases the measurement"
    );
}

#[test]
fn key_release_gate_accepts_only_current_tcb() {
    assert!(synthetic(TcbStatus::UpToDate).enclave_measurement().is_ok());
    assert!(synthetic(TcbStatus::SwHardeningNeeded)
        .enclave_measurement()
        .is_ok());
    for bad in [
        TcbStatus::OutOfDate,
        TcbStatus::Revoked,
        TcbStatus::ConfigurationNeeded,
        TcbStatus::OutOfDateConfigurationNeeded,
        TcbStatus::Other("Unknown".into()),
    ] {
        let att = synthetic(bad.clone());
        assert!(
            matches!(att.enclave_measurement(), Err(AttestationError::TcbRejected(s)) if s == bad),
            "{bad:?} must be rejected for key release",
        );
    }
}
