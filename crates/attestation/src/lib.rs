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

pub mod vtpm;

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
