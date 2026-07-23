//! Offline TDX DCAP quote verification (dark-perp Milestone C, increment #4).
//!
//! Verifies a real Intel TDX DCAP quote against **pinned** collateral, with no
//! network access, and extracts the security-relevant outputs — MRTD, the four
//! RTMRs, the 64-byte report data, and the evaluated TCB status. The verified
//! MRTD is what gates measurement-bound key release (`SealKeyProvider`) and
//! identifies the enclave (`EnclaveIdentity`).
//!
//! The crypto backend is pure-Rust (`rustcrypto`, no `ring`/asm), so the crate
//! builds clean under the workspace `unsafe_code = "forbid"` lint.

use dcap_qvl::QuoteCollateralV3;

mod handshake;
mod nvidia_cc;
pub mod vtpm;

pub use handshake::{
    ct_eq, dh_shared, ephemeral_keypair, session_secret, session_token, DEV_INSECURE_SESSION_TOKEN,
};
pub use nvidia_cc::NvidiaCcAttestor;

/// The verified, security-relevant outputs of a TDX DCAP quote.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    /// Measurement of the TD's initial contents — SHA-384, 48 bytes.
    pub mr_td: [u8; 48],
    /// Runtime-extended measurement registers RTMR0..3.
    pub rtmr: [[u8; 48]; 4],
    /// 64-byte report data (binds the enclave's key / a freshness nonce).
    pub report_data: [u8; 64],
    /// Evaluated platform TCB status.
    pub tcb_status: TcbStatus,
    /// Intel security-advisory IDs tied to the TCB level (empty when up to date).
    pub advisory_ids: Vec<String>,
    /// Quote structure version (4 = TD1.0 body, 5 = TD1.5 body).
    pub quote_version: u16,
}

/// Intel TCB evaluation status for the attested platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcbStatus {
    UpToDate,
    SwHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSwHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
    /// A status string the verifier reports that we don't model explicitly.
    Other(String),
}

/// Why a quote failed to verify.
#[derive(Debug, Clone)]
pub enum AttestationError {
    /// The pinned collateral JSON did not parse.
    Collateral(String),
    /// The quote could not be cryptographically verified against the collateral.
    Verify(String),
    /// The quote verified but is not a TDX (TD1.0/TD1.5) report.
    NotTdx,
    /// The quote verified cryptographically, but the platform's TCB is not
    /// acceptable for key release (out of date / revoked / configuration needed).
    TcbRejected(TcbStatus),
}

impl TcbStatus {
    /// Whether this TCB status is acceptable for measurement-bound key release.
    ///
    /// Accepts an up-to-date platform and one that only needs software hardening —
    /// the common real-hardware case, where Intel advisories are mitigated in
    /// software — and rejects out-of-date / revoked / configuration-needed.
    pub fn is_acceptable(&self) -> bool {
        matches!(self, TcbStatus::UpToDate | TcbStatus::SwHardeningNeeded)
    }
}

/// Pinned DCAP collateral (PCK chain + CRLs + TCB info + QE identity).
pub struct Collateral(QuoteCollateralV3);

impl Collateral {
    /// Parse a pinned collateral bundle (the Phala/Intel JSON layout).
    pub fn from_json(bytes: &[u8]) -> Result<Self, AttestationError> {
        serde_json::from_slice::<QuoteCollateralV3>(bytes)
            .map(Collateral)
            .map_err(|e| AttestationError::Collateral(e.to_string()))
    }
}

impl TcbStatus {
    /// Map the verifier's status string into our modelled status.
    fn from_status(s: &str) -> Self {
        match s {
            "UpToDate" => Self::UpToDate,
            "SWHardeningNeeded" => Self::SwHardeningNeeded,
            "ConfigurationNeeded" => Self::ConfigurationNeeded,
            "ConfigurationAndSWHardeningNeeded" => Self::ConfigurationAndSwHardeningNeeded,
            "OutOfDate" => Self::OutOfDate,
            "OutOfDateConfigurationNeeded" => Self::OutOfDateConfigurationNeeded,
            "Revoked" => Self::Revoked,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Verify a raw TDX DCAP `quote` against pinned `collateral` at a fixed
/// `now_secs`. `now_secs` MUST lie inside the collateral validity window — pass
/// a pinned value, never `SystemTime::now()`, so verification is deterministic.
pub fn verify_tdx_quote(
    quote: &[u8],
    collateral: &Collateral,
    now_secs: u64,
) -> Result<VerifiedAttestation, AttestationError> {
    let report = dcap_qvl::verify::verify(quote, &collateral.0, now_secs)
        .map_err(|e| AttestationError::Verify(format!("{e:?}")))?;

    // A TDX quote carries either a TD1.0 or a TD1.5 report body; TD1.5 embeds the
    // TD1.0 fields plus the service-TD measurement. Anything else is not TDX.
    use dcap_qvl::quote::Report;
    let (td, quote_version) = match &report.report {
        Report::TD10(td) => (td, 4u16),
        Report::TD15(td15) => (&td15.base, 5u16),
        _ => return Err(AttestationError::NotTdx),
    };

    Ok(VerifiedAttestation {
        mr_td: td.mr_td,
        rtmr: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
        report_data: td.report_data,
        tcb_status: TcbStatus::from_status(&report.status),
        advisory_ids: report.advisory_ids.clone(),
        quote_version,
    })
}

impl VerifiedAttestation {
    /// The attested enclave measurement (folded MRTD‖RTMR0..3) — but ONLY if the
    /// platform TCB is acceptable. This is the gate the engine boot path uses, so
    /// an out-of-date / revoked platform can never seed `EnclaveIdentity` nor
    /// authorize seal-key release. The ONLY public path to a measurement.
    pub fn enclave_measurement(&self) -> Result<[u8; 32], AttestationError> {
        if !self.tcb_status.is_acceptable() {
            return Err(AttestationError::TcbRejected(self.tcb_status.clone()));
        }
        Ok(measurement_of(self))
    }
}

/// Fold one 48-byte measurement register into two domain-hashed 32-byte words:
/// the first 32 bytes, then the trailing 16 right-padded with zeros.
pub(crate) fn fold48(words: &mut Vec<[u8; 32]>, b: &[u8; 48]) {
    let mut w0 = [0u8; 32];
    w0.copy_from_slice(&b[..32]);
    let mut w1 = [0u8; 32];
    w1[..16].copy_from_slice(&b[32..]);
    words.push(w0);
    words.push(w1);
}

/// Fold the verified measurement state — **MRTD plus all four RTMRs** — into the
/// repo's 32-byte measurement `Digest`, the single bridge from a DCAP quote to
/// `EnclaveIdentity` / `SealKeyProvider`.
///
/// MRTD alone is NOT application identity on the Azure CVM target: there MRTD is
/// the host-supplied guest-firmware measurement, shared across every tenant of
/// the SKU, while the kernel/initrd/runtime land in RTMR0..3. Binding all of
/// MRTD‖RTMR0..3 makes a different binary on the same SKU produce a different
/// digest — so measurement-bound release is application-bound, not merely
/// firmware-generation-bound.
///
/// Gated behind [`VerifiedAttestation::enclave_measurement`] (`pub(crate)`) so no
/// caller can obtain a measurement that skipped the TCB check. This off-chain
/// fold is an internal identity label (NOT cross-layer-committed): the on-chain
/// registry compares its own `keccak256(MRTD‖RTMR0..3)` — a deliberately distinct
/// encoding that must never be unified with this one.
pub(crate) fn measurement_of(att: &VerifiedAttestation) -> [u8; 32] {
    use perp_core::hash::{Domain, Hasher, Keccak256};
    let mut words = Vec::with_capacity(10);
    fold48(&mut words, &att.mr_td);
    for rtmr in &att.rtmr {
        fold48(&mut words, rtmr);
    }
    Keccak256::hash_words(Domain::Measurement, &words)
}

// ---------------------------------------------------------------------------
// SEC-020: the `Attestor` boundary — self-quote + peer verification, fail-closed.
// ---------------------------------------------------------------------------

/// The repo's 32-byte measurement digest (what `enclave_measurement` yields).
pub type Digest = [u8; 32];

/// Why an `Attestor` operation failed. Fail-closed: every arm is an error the
/// caller must refuse on — there is no "verified but degraded" success state.
#[derive(Debug)]
pub enum AttestError {
    /// The underlying TDX verification failed (crypto, collateral, or an
    /// unacceptable TCB) — the crate error is carried, not stringified.
    Tdx(AttestationError),
    /// The local confidential-computing mode is not enabled (NVIDIA CC backend;
    /// reserved here so callers can match on it before that backend lands).
    CcNotEnabled,
    /// The quote verified but its measurement is not the pinned `expected`.
    MeasurementMismatch,
    /// The quote verified but does not bind the caller's freshness nonce.
    NonceMismatch,
    /// The Azure vTPM chain (HCL binding / AK signature / PCR digest) failed.
    VtpmChain(String),
    /// The attestation backend itself failed (no quote source, unreadable
    /// artifacts, malformed collateral metadata).
    Backend(String),
}

/// A TEE attestation backend: produce this host's quote, verify a peer's.
pub trait Attestor {
    /// Produce this host's attestation quote over `nonce` (freshness/anti-replay).
    fn quote(&self, nonce: &[u8; 32]) -> Result<Vec<u8>, AttestError>;
    /// Verify a peer `quote` over `nonce`, requiring its measurement ==
    /// `expected`. Returns the verified measurement on success.
    fn verify(
        &self,
        quote: &[u8],
        expected: &Digest,
        nonce: &[u8; 32],
    ) -> Result<Digest, AttestError>;
}

/// Parse an Intel PCS UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`, as in collateral
/// `issueDate`/`nextUpdate`) into Unix seconds. Strict: any other shape or an
/// out-of-range field (or a pre-1970 date) is `None`, never a guess.
fn iso8601_epoch_secs(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: core::ops::Range<usize>| s.get(r)?.parse::<u64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&m)
        || !(1..=31).contains(&d)
        || hh > 23
        || mm > 59
        || ss > 59
    {
        return None;
    }
    // Days from civil (Hinnant's algorithm); u64-safe for y >= 1970 (min = 0).
    let ye = if m <= 2 { y - 1 } else { y };
    let era = ye / 400;
    let yoe = ye - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

/// The deterministic verification time pinned by the collateral itself: the
/// midpoint of the intersection of the TCB-info and QE-identity validity
/// windows. `verify_tdx_quote` demands a pinned time (never `SystemTime::now()`);
/// pinning the collateral IS the freshness decision, so the collateral carries
/// its own evaluation instant. Fail-closed when the windows are malformed or
/// don't intersect.
fn collateral_pinned_now(c: &Collateral) -> Result<u64, AttestError> {
    fn window(doc: &str, what: &str) -> Result<(u64, u64), AttestError> {
        let v: serde_json::Value = serde_json::from_str(doc)
            .map_err(|e| AttestError::Backend(format!("collateral {what}: {e}")))?;
        let t = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .and_then(iso8601_epoch_secs)
                .ok_or_else(|| AttestError::Backend(format!("collateral {what}: bad {k}")))
        };
        Ok((t("issueDate")?, t("nextUpdate")?))
    }
    let (tcb_issue, tcb_next) = window(&c.0.tcb_info, "tcb_info")?;
    let (qe_issue, qe_next) = window(&c.0.qe_identity, "qe_identity")?;
    let (lo, hi) = (tcb_issue.max(qe_issue), tcb_next.min(qe_next));
    if lo >= hi {
        return Err(AttestError::Backend(
            "collateral validity windows do not intersect".into(),
        ));
    }
    Ok(lo + (hi - lo) / 2)
}

/// The serialized tee-capture evidence one side sends the other: the TD quote
/// plus the full vTPM chain (HCL report, AK quote msg+sig, PCR list). Binary
/// fields are hex; `pcrs` is the raw `pcrs.txt` text. `quote()` assembles it from
/// `ATTESTATION_DIR`; `verify()` parses + checks the whole chain fail-closed.
#[derive(serde::Serialize, serde::Deserialize)]
struct AttestationBundle {
    quote: String,
    hcl_report: String,
    ak_quote_msg: String,
    ak_quote_sig: String,
    pcrs: String,
}

/// The Azure TDX attestation backend: verifies peer TD quotes against pinned
/// collateral, and serves this host's quote from the same source the §5c boot
/// self-attest uses (`ATTESTATION_DIR` — a live CVM points it at a fresh
/// `tee-capture` output; absent, `quote()` fails closed).
pub struct AzureTdxAttestor {
    /// Pinned DCAP collateral peers are verified against.
    collateral: Collateral,
    /// Deterministic verification time derived from that collateral.
    now_secs: u64,
    /// This host's quote source (`ATTESTATION_DIR` at construction).
    quote_dir: Option<std::path::PathBuf>,
}

impl AzureTdxAttestor {
    /// Build an attestor over a pinned collateral bundle. The verification time
    /// is derived from the collateral itself (deterministic); the self-quote
    /// source is `ATTESTATION_DIR`, exactly as the gateway boot self-attest.
    pub fn from_collateral_json(bytes: &[u8]) -> Result<Self, AttestError> {
        let collateral = Collateral::from_json(bytes).map_err(AttestError::Tdx)?;
        let now_secs = collateral_pinned_now(&collateral)?;
        let quote_dir = std::env::var_os("ATTESTATION_DIR").map(std::path::PathBuf::from);
        Ok(Self {
            collateral,
            now_secs,
            quote_dir,
        })
    }
}

impl Attestor for AzureTdxAttestor {
    // `_challenge` (the local ephemeral pubkey) is bound into the AK-extraData by
    // a LIVE `tee-capture` on a real CVM; here we read the STATIC captured bundle,
    // whose extraData is fixed, so the arg is a documented no-op locally. (This is
    // why a real-binary handshake is window-deferred, not asserted in local tests.)
    fn quote(&self, _challenge: &[u8; 32]) -> Result<Vec<u8>, AttestError> {
        let dir = self.quote_dir.as_ref().ok_or_else(|| {
            AttestError::Backend("no live quote source: ATTESTATION_DIR is not set".into())
        })?;
        let rd = |name: &str| -> Result<Vec<u8>, AttestError> {
            std::fs::read(dir.join(name))
                .map_err(|e| AttestError::Backend(format!("read {}/{name}: {e}", dir.display())))
        };
        let bundle = AttestationBundle {
            quote: hex::encode(rd("quote.bin")?),
            hcl_report: hex::encode(rd("hcl_report.bin")?),
            ak_quote_msg: hex::encode(rd("ak_quote_msg.bin")?),
            ak_quote_sig: hex::encode(rd("ak_quote_sig.bin")?),
            pcrs: String::from_utf8(rd("pcrs.txt")?)
                .map_err(|e| AttestError::Backend(format!("pcrs.txt not utf8: {e}")))?,
        };
        serde_json::to_vec(&bundle)
            .map_err(|e| AttestError::Backend(format!("serialize bundle: {e}")))
    }

    fn verify(
        &self,
        bundle: &[u8],
        expected: &Digest,
        challenge: &[u8; 32],
    ) -> Result<Digest, AttestError> {
        let b: AttestationBundle = serde_json::from_slice(bundle)
            .map_err(|e| AttestError::Backend(format!("bundle parse: {e}")))?;
        let dec = |h: &str, what: &str| -> Result<Vec<u8>, AttestError> {
            hex::decode(h).map_err(|e| AttestError::Backend(format!("bundle {what}: {e}")))
        };
        let quote = dec(&b.quote, "quote")?;
        let hcl = dec(&b.hcl_report, "hcl_report")?;
        let ak_msg = dec(&b.ak_quote_msg, "ak_quote_msg")?;
        let ak_sig = dec(&b.ak_quote_sig, "ak_quote_sig")?;
        let pcrs = crate::vtpm::parse_pcrs_txt(&b.pcrs)
            .map_err(|e| AttestError::Backend(format!("bundle pcrs: {e:?}")))?;

        // 1. TD quote crypto + TCB gate.
        let td =
            verify_tdx_quote(&quote, &self.collateral, self.now_secs).map_err(AttestError::Tdx)?;
        // 2. Full vTPM chain (HCL binding, AK sig, pcrDigest).
        let report = crate::vtpm::verify_azure_vtpm(&td, &hcl, &ak_msg, &ak_sig, &pcrs)
            .map_err(|e| AttestError::VtpmChain(format!("{e:?}")))?;
        // 3. C1: APP-level measurement (MRTD‖pcr_digest), not the firmware fold.
        let m = crate::vtpm::azure_app_measurement(&td, &report).map_err(AttestError::Tdx)?;
        if &m != expected {
            return Err(AttestError::MeasurementMismatch);
        }
        // 4. C2/C3: the AK-extraData freshness value must equal the caller's
        //    challenge (the peer's ephemeral pubkey on a live handshake).
        if report.nonce.len() != 32 || report.nonce[..] != challenge[..] {
            return Err(AttestError::NonceMismatch);
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The REAL captured Azure TDX CVM quote + its pinned collateral — the same
    // fixture bytes `tests/verify_offline.rs` verifies `verify_tdx_quote` with.
    const AZURE_QUOTE: &[u8] = include_bytes!("../tests/fixtures/azure/quote.bin");
    const AZURE_COLLATERAL: &[u8] = include_bytes!("../tests/fixtures/azure/collateral.json");
    /// Midpoint of the Azure collateral window [2026-06-26 .. 2026-07-26].
    const AZURE_NOW: u64 = 1_783_775_325;

    // The five tee-capture files that make an Azure evidence bundle.
    const AZURE_HCL: &[u8] = include_bytes!("../tests/fixtures/azure/hcl_report.bin");
    const AZURE_AK_MSG: &[u8] = include_bytes!("../tests/fixtures/azure/ak_quote_msg.bin");
    const AZURE_AK_SIG: &[u8] = include_bytes!("../tests/fixtures/azure/ak_quote_sig.bin");
    const AZURE_PCRS: &str = include_str!("../tests/fixtures/azure/pcrs.txt");

    /// Serialize the fixture into an AttestationBundle exactly as `quote()` would.
    fn azure_bundle() -> Vec<u8> {
        serde_json::to_vec(&AttestationBundle {
            quote: hex::encode(AZURE_QUOTE),
            hcl_report: hex::encode(AZURE_HCL),
            ak_quote_msg: hex::encode(AZURE_AK_MSG),
            ak_quote_sig: hex::encode(AZURE_AK_SIG),
            pcrs: AZURE_PCRS.to_string(),
        })
        .unwrap()
    }

    /// The app-level measurement + the AK-extraData nonce the fixture carries —
    /// the values a correct verify must key off (NOT the firmware-only fold).
    fn azure_app_expected() -> ([u8; 32], Vec<u8>) {
        let collateral = Collateral::from_json(AZURE_COLLATERAL).unwrap();
        let td = verify_tdx_quote(AZURE_QUOTE, &collateral, AZURE_NOW).unwrap();
        let pcrs = crate::vtpm::parse_pcrs_txt(AZURE_PCRS).unwrap();
        let report =
            crate::vtpm::verify_azure_vtpm(&td, AZURE_HCL, AZURE_AK_MSG, AZURE_AK_SIG, &pcrs)
                .unwrap();
        let m = crate::vtpm::azure_app_measurement(&td, &report).unwrap();
        (m, report.nonce)
    }

    #[test]
    fn azure_verify_accepts_the_bundle_at_app_level_with_matching_challenge() {
        let (expected, extradata) = azure_app_expected();
        // The challenge the peer proves it bound is the AK-extraData value; on a
        // live handshake that is the peer's ephemeral pubkey. Here it is the
        // fixture's captured extraData (32 bytes).
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&extradata[..32]);
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        let m = att.verify(&azure_bundle(), &expected, &challenge).unwrap();
        assert_eq!(m, expected, "verify returns the APP-level measurement");
    }

    #[test]
    fn azure_verify_rejects_a_firmware_only_expected_measurement() {
        // The C1 regression: the firmware-only enclave_measurement (MRTD‖RTMR0..3)
        // must NOT be what verify accepts — pinning it would let two app binaries
        // on one SKU cross-verify. Passing it as `expected` must MeasurementMismatch.
        let collateral = Collateral::from_json(AZURE_COLLATERAL).unwrap();
        let td = verify_tdx_quote(AZURE_QUOTE, &collateral, AZURE_NOW).unwrap();
        let firmware_only = td.enclave_measurement().unwrap();
        let (app_level, extradata) = azure_app_expected();
        assert_ne!(firmware_only, app_level, "the two measurements differ");
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&extradata[..32]);
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        assert!(matches!(
            att.verify(&azure_bundle(), &firmware_only, &challenge),
            Err(AttestError::MeasurementMismatch)
        ));
    }

    #[test]
    fn azure_verify_rejects_a_mismatched_challenge() {
        let (expected, _extradata) = azure_app_expected();
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        assert!(matches!(
            att.verify(&azure_bundle(), &expected, &[0x55u8; 32]),
            Err(AttestError::NonceMismatch)
        ));
    }

    #[test]
    fn azure_verify_rejects_a_malformed_bundle() {
        let (expected, _e) = azure_app_expected();
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        assert!(matches!(
            att.verify(b"not json", &expected, &[0u8; 32]),
            Err(AttestError::Backend(_))
        ));
    }

    #[test]
    fn azure_verify_rejects_a_tampered_quote_in_the_bundle() {
        let (expected, extradata) = azure_app_expected();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&extradata[..32]);
        let mut b: AttestationBundle = serde_json::from_slice(&azure_bundle()).unwrap();
        let mut q = hex::decode(&b.quote).unwrap();
        q[184] ^= 0x01; // flip a byte inside the signed TD report
        b.quote = hex::encode(q);
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        assert!(matches!(
            att.verify(&serde_json::to_vec(&b).unwrap(), &expected, &challenge),
            Err(AttestError::Tdx(AttestationError::Verify(_)))
        ));
    }

    #[test]
    fn azure_quote_assembles_the_full_bundle_and_round_trips() {
        let (expected, extradata) = azure_app_expected();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&extradata[..32]);
        let mut att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        att.quote_dir = Some(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/azure").into());
        // quote() reads all five files and serializes them; verify() round-trips.
        let bundle = att.quote(&challenge).expect("assembles the bundle");
        assert_eq!(
            att.verify(&bundle, &expected, &challenge).unwrap(),
            expected
        );
    }

    #[test]
    fn azure_quote_without_a_live_source_fails_closed() {
        let mut att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        att.quote_dir = None;
        assert!(matches!(
            att.quote(&[0u8; 32]),
            Err(AttestError::Backend(_))
        ));
    }

    #[test]
    fn pinned_now_parses_intel_pcs_timestamps() {
        // Golden epochs (the first is the exact NOW_SECS pinned in
        // tests/verify_offline.rs for 2025-07-04T10:16:03Z).
        assert_eq!(
            iso8601_epoch_secs("2025-07-04T10:16:03Z"),
            Some(1_751_624_163)
        );
        assert_eq!(
            iso8601_epoch_secs("2026-06-26T13:08:45Z"),
            Some(1_782_479_325)
        );
        assert_eq!(iso8601_epoch_secs("1970-01-01T00:00:00Z"), Some(0));
        // Malformed / out-of-range forms are refused, never mis-parsed.
        assert_eq!(iso8601_epoch_secs("2025-07-04 10:16:03Z"), None);
        assert_eq!(iso8601_epoch_secs("2025-07-04T10:16:03"), None);
        assert_eq!(iso8601_epoch_secs("2025-13-04T10:16:03Z"), None);
        assert_eq!(iso8601_epoch_secs("1969-12-31T23:59:59Z"), None);
    }

    #[test]
    fn pinned_now_lies_inside_the_collateral_windows() {
        // The attestor derives its deterministic verification time from the
        // pinned collateral itself; it must land inside the intersection of the
        // TCB-info and QE-identity validity windows (else dcap-qvl rejects).
        let collateral = Collateral::from_json(AZURE_COLLATERAL).expect("collateral parses");
        let now = collateral_pinned_now(&collateral).expect("derivable");
        // tcb_info window [2026-06-26T13:08:45Z .. 2026-07-26T13:08:45Z],
        // qe_identity window [2026-06-26T00:05:00Z .. 2026-07-26T00:05:00Z].
        assert!(now > 1_782_479_325 && now < 1_785_024_300, "now={now}");
    }
}
