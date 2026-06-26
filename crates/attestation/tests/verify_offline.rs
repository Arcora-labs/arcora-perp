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

    // Bound to the RTMRs: changing the runtime-loaded code (kernel/initrd/app)
    // changes the identity too — MRTD alone is the shared firmware on the Azure
    // target, so binding RTMRs is what makes the digest application-bound.
    let mut other_rtmr = att.clone();
    other_rtmr.rtmr[1][0] ^= 0x01;
    assert_ne!(
        other_rtmr.enclave_measurement().unwrap(),
        m,
        "a different RTMR yields a different measurement (application-bound)"
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
