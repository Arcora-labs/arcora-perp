//! Azure vTPM trust-chain verification (Milestone C #5b).
//!
//! On Azure TDX confidential VMs the TD RTMRs are **zero** — measured boot goes
//! into the **vTPM PCRs**, not the TD report. So the application identity (kernel
//! / initrd / the sequencer binary) lives in the vTPM, and the TD DCAP quote
//! alone only attests the guest firmware (MRTD). This module verifies the chain
//! that links the DCAP-verified TD to those PCRs, so the engine can bind key
//! release to the real application identity:
//!
//! 1. **HCL binding** — the TD quote's `report_data` is `SHA-256(runtime_data)`,
//!    where `runtime_data` is the HCL JSON blob that carries the vTPM **AK**
//!    public key. Matching the hash binds that runtime data (and the AK in it) to
//!    the attested TD.
//! 2. **AK signature** — the AK (extracted from the runtime data) signs the TPM
//!    quote (`TPMS_ATTEST`) with RSASSA-PKCS#1 v1.5 / SHA-256.
//! 3. **PCR digest** — the quote's `pcrDigest` equals `SHA-256(PCR values)`,
//!    binding the measured-boot PCRs to the AK (and thus to the TD).
//!
//! Every byte layout here was confirmed against a real Azure DC2es_v6 quote +
//! vTPM capture (see `tests/fixtures/azure/`).

use base64::Engine;
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::VerifiedAttestation;

/// The verified outputs of the Azure vTPM chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureVtpmReport {
    /// `SHA-256` over the quoted PCR set — the measured-boot / application identity.
    pub pcr_digest: [u8; 32],
    /// The quote's `extraData` (the freshness nonce the AK echoed).
    pub nonce: Vec<u8>,
    /// The raw `TPML_PCR_SELECTION` bytes the AK quoted.
    pub pcr_select: Vec<u8>,
}

/// Why the Azure vTPM chain failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VtpmError {
    /// `report_data != SHA-256(runtime_data)` — the runtime data (and its AK) is
    /// not bound to the attested TD.
    HclBinding,
    /// The HCL runtime data / AK public key could not be parsed.
    AkParse,
    /// The AK signature over the TPM quote did not verify.
    Signature,
    /// The `TPMS_ATTEST` quote structure could not be parsed.
    AttestParse,
    /// `pcrDigest != SHA-256(PCR values)` — the supplied PCRs don't match the quote.
    PcrMismatch,
}

#[derive(Deserialize)]
struct RuntimeData {
    keys: Vec<Jwk>,
}
#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    key_ops: Vec<String>,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

/// A minimal big-endian cursor with bounds checks (no panics on malformed input).
struct Cur<'a> {
    b: &'a [u8],
    o: usize,
}
impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, o: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], VtpmError> {
        let s = self
            .b
            .get(self.o..self.o + n)
            .ok_or(VtpmError::AttestParse)?;
        self.o += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, VtpmError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, VtpmError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, VtpmError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    /// A `TPM2B_*`: a u16 length prefix followed by that many bytes.
    fn tpm2b(&mut self) -> Result<&'a [u8], VtpmError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

fn le_u32(b: &[u8], o: usize) -> Result<u32, VtpmError> {
    let s = b.get(o..o + 4).ok_or(VtpmError::HclBinding)?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}

/// Extract the HCL runtime-claims data (`var_data`) by its **fixed layout**, not
/// by brace-scanning (a stray `{"`/`}` in the binary TD report or trailing bytes
/// would otherwise corrupt the SHA-256 bound). The HCL attestation report is:
/// `"HCLA"` signature @0, the TD hw_report, then an `IgvmRequestData` header whose
/// `report_type` (TDX=4) / `report_data_hash_type` (SHA-256=1) / `variable_data_size`
/// gate and bound the runtime-claims JSON at offset 1236. Confirmed against a real
/// Azure DC2es_v6 capture.
fn runtime_data(hcl: &[u8]) -> Result<&[u8], VtpmError> {
    const VAR_DATA_OFFSET: usize = 1236;
    if hcl.get(0..4) != Some(b"HCLA") {
        return Err(VtpmError::HclBinding);
    }
    if le_u32(hcl, 1224)? != 4 {
        return Err(VtpmError::HclBinding); // report_type: TDX
    }
    if le_u32(hcl, 1228)? != 1 {
        return Err(VtpmError::HclBinding); // report_data_hash_type: SHA-256
    }
    let size = le_u32(hcl, 1232)? as usize; // variable_data_size
    hcl.get(VAR_DATA_OFFSET..VAR_DATA_OFFSET + size)
        .ok_or(VtpmError::HclBinding)
}

fn b64url(s: &str) -> Result<Vec<u8>, VtpmError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| VtpmError::AkParse)
}

/// Parse a `TPMT_SIGNATURE` and return the raw RSASSA signature bytes.
fn rsassa_sig(sig: &[u8]) -> Result<&[u8], VtpmError> {
    let mut c = Cur::new(sig);
    if c.u16().map_err(|_| VtpmError::Signature)? != 0x0014 {
        return Err(VtpmError::Signature); // TPM_ALG_RSASSA
    }
    let _hash = c.u16().map_err(|_| VtpmError::Signature)?; // TPM_ALG_SHA256
    c.tpm2b().map_err(|_| VtpmError::Signature)
}

/// The fields a `TPMS_ATTEST` quote yields.
struct QuoteFields<'a> {
    nonce: &'a [u8],
    pcr_select: &'a [u8],
    pcr_digest: &'a [u8],
}

/// Parse a `TPMS_ATTEST` of type `TPM_ST_ATTEST_QUOTE`.
fn parse_quote(msg: &[u8]) -> Result<QuoteFields<'_>, VtpmError> {
    let mut c = Cur::new(msg);
    if c.u32()? != 0xff54_4347 {
        return Err(VtpmError::AttestParse); // TPM_GENERATED_VALUE
    }
    if c.u16()? != 0x8018 {
        return Err(VtpmError::AttestParse); // TPM_ST_ATTEST_QUOTE
    }
    let _qualified_signer = c.tpm2b()?;
    let nonce = c.tpm2b()?; // extraData
    let _clock_info = c.take(17)?;
    let _firmware_version = c.take(8)?;
    // TPML_PCR_SELECTION
    let count = c.u32()?;
    let sel_start = c.o;
    for _ in 0..count {
        let _hash_alg = c.u16()?;
        let size = c.u8()? as usize;
        c.take(size)?;
    }
    let pcr_select = &msg[sel_start..c.o];
    let pcr_digest = c.tpm2b()?;
    Ok(QuoteFields {
        nonce,
        pcr_select,
        pcr_digest,
    })
}

/// Verify the full Azure vTPM trust chain.
///
/// `td` is the already-DCAP-verified TD attestation (for its `report_data` +
/// `mr_td`). `hcl_report` is the raw HCL report (vTPM NV `0x01400001`).
/// `ak_quote_msg` / `ak_quote_sig` are the AK-signed `TPMS_ATTEST` + its
/// `TPMT_SIGNATURE`. `pcr_values` are the individual PCR digests for exactly the
/// quoted selection, in ascending PCR index order.
pub fn verify_azure_vtpm(
    td: &VerifiedAttestation,
    hcl_report: &[u8],
    ak_quote_msg: &[u8],
    ak_quote_sig: &[u8],
    pcr_values: &[[u8; 32]],
) -> Result<AzureVtpmReport, VtpmError> {
    // 1. HCL binding: report_data == SHA-256(runtime_data) ‖ zero pad.
    let runtime = runtime_data(hcl_report)?;
    if Sha256::digest(runtime).as_slice() != &td.report_data[..32] {
        return Err(VtpmError::HclBinding);
    }
    if td.report_data[32..] != [0u8; 32] {
        return Err(VtpmError::HclBinding); // fail-closed: the 32-byte zero pad
    }

    // 2. Extract the vTPM AK public key from the (now TD-bound) runtime data.
    //    Strictly the signing AK (`HCLAkPub` with a `sign` op) — never the HCL
    //    *encryption* key (`HCLEkPub`), which would verify the quote under the
    //    wrong key.
    let rd: RuntimeData = serde_json::from_slice(runtime).map_err(|_| VtpmError::AkParse)?;
    let ak = rd
        .keys
        .iter()
        .find(|k| k.kid == "HCLAkPub" && k.key_ops.iter().any(|o| o == "sign"))
        .ok_or(VtpmError::AkParse)?;
    let ak_pub = RsaPublicKey::new(
        BigUint::from_bytes_be(&b64url(&ak.n)?),
        BigUint::from_bytes_be(&b64url(&ak.e)?),
    )
    .map_err(|_| VtpmError::AkParse)?;

    // 3. The AK signs the TPM quote (RSASSA-PKCS#1 v1.5 / SHA-256).
    let sig = rsassa_sig(ak_quote_sig)?;
    let hashed = Sha256::digest(ak_quote_msg);
    ak_pub
        .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, sig)
        .map_err(|_| VtpmError::Signature)?;

    // 4. The quote binds the measured-boot PCRs: pcrDigest == SHA-256(PCR values).
    let q = parse_quote(ak_quote_msg)?;
    let mut h = Sha256::new();
    for pcr in pcr_values {
        h.update(pcr);
    }
    if h.finalize().as_slice() != q.pcr_digest {
        return Err(VtpmError::PcrMismatch);
    }

    Ok(AzureVtpmReport {
        pcr_digest: q
            .pcr_digest
            .try_into()
            .map_err(|_| VtpmError::AttestParse)?,
        nonce: q.nonce.to_vec(),
        pcr_select: q.pcr_select.to_vec(),
    })
}

/// The Azure application measurement: folds the firmware MRTD together with the
/// measured-boot PCR digest. This is the identity the engine should key seal
/// release off on Azure — where the TD RTMRs are zero, the PCR digest is what
/// carries the kernel / initrd / application identity.
///
/// Returns `Err(TcbRejected)` when the platform TCB is not acceptable — the SAME
/// gate as [`crate::VerifiedAttestation::enclave_measurement`], so the Azure vTPM
/// boot path can never seed an enclave identity from an out-of-date / revoked
/// platform (audit DP-005).
pub fn azure_app_measurement(
    td: &VerifiedAttestation,
    vtpm: &AzureVtpmReport,
) -> Result<[u8; 32], crate::AttestationError> {
    use perp_core::hash::{Domain, Hasher, Keccak256};
    // audit DP-005: fail closed on an unacceptable TCB, mirroring enclave_measurement.
    if !td.tcb_status.is_acceptable() {
        return Err(crate::AttestationError::TcbRejected(td.tcb_status.clone()));
    }
    let mut words = Vec::with_capacity(3);
    crate::fold48(&mut words, &td.mr_td);
    words.push(vtpm.pcr_digest);
    Ok(Keccak256::hash_words(Domain::Measurement, &words))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TcbStatus, VerifiedAttestation};

    fn att(tcb: TcbStatus) -> VerifiedAttestation {
        VerifiedAttestation {
            mr_td: [1u8; 48],
            rtmr: [[0u8; 48]; 4],
            report_data: [0u8; 64],
            tcb_status: tcb,
            advisory_ids: Vec::new(),
            quote_version: 4,
        }
    }
    fn report() -> AzureVtpmReport {
        AzureVtpmReport {
            pcr_digest: [2u8; 32],
            nonce: Vec::new(),
            pcr_select: Vec::new(),
        }
    }

    // audit DP-005: the Azure vTPM measurement path must apply the SAME acceptable-TCB
    // gate as the generic verified-attestation path — an out-of-date / revoked platform
    // is refused, never seeding an enclave identity.
    #[test]
    fn app_measurement_applies_the_tcb_gate() {
        assert!(azure_app_measurement(&att(TcbStatus::OutOfDate), &report()).is_err());
        assert!(azure_app_measurement(&att(TcbStatus::Revoked), &report()).is_err());
        assert!(azure_app_measurement(&att(TcbStatus::ConfigurationNeeded), &report()).is_err());
        // an acceptable platform still yields a measurement
        assert!(azure_app_measurement(&att(TcbStatus::UpToDate), &report()).is_ok());
        assert!(azure_app_measurement(&att(TcbStatus::SwHardeningNeeded), &report()).is_ok());
    }
}
