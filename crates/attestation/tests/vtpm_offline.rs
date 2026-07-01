//! Hermetic offline verification of the Azure vTPM trust chain (#5b).
//!
//! Real artifacts captured once from an Azure DC2es_v6 CVM: the TD quote +
//! collateral, the HCL report (runtime data + AK pubkey), an AK-signed TPM quote
//! over the measured-boot PCRs, and the PCR values. No network, fully deterministic.

use dark_perp_attestation::vtpm::{self, VtpmError};
use dark_perp_attestation::{verify_tdx_quote, Collateral};

const AZURE_QUOTE: &[u8] = include_bytes!("fixtures/azure/quote.bin");
const AZURE_COLLATERAL: &[u8] = include_bytes!("fixtures/azure/collateral.json");
const AZURE_NOW: u64 = 1_783_775_325;

const HCL: &[u8] = include_bytes!("fixtures/azure/hcl_report.bin");
const AK_MSG: &[u8] = include_bytes!("fixtures/azure/ak_quote_msg.bin");
const AK_SIG: &[u8] = include_bytes!("fixtures/azure/ak_quote_sig.bin");

/// The captured sha256-bank PCRs 0..=16 (the quoted measured-boot set).
const PCRS: [&str; 17] = [
    "31bf2fb851bec5336faa27e5892e1ed3131437f324f6013bdc57afac5b1c6a01",
    "0160c04a7df1b318fde3794767aa19115caa8e902b87d90c1a48e7c76a5db3a5",
    "ad9881365302617b01ae6292541bf48eb3c3b6d994d2f2dd41e414948e35f4db",
    "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
    "61355f4c74d19f010d327507b016585ac7af3898eff5440ec77c750e97ddf573",
    "de86819291782b3d6af4915c21a7ba0ec868bcdaa28c22edd5d93531faa5f4a7",
    "c7db8a6828e8724c3beda07e205f52f1f035c3645880ec6c9af0c96305992330",
    "3b20e022416fdf61d72e4da32b4354781be3de0608116976d28ffdad8c341d2a",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "882e1ee7f99cfd32d42921c76ed70352619089602865032dfb1d395856288535",
    "518542292e256f6641caa878ccf22ef54c0bf542d93936282d8a7e2f311a599d",
    "1c79a2c9fe7fc1391f876db4dd5b5c0047c2239a6e3bda6df4ebb8feede9b4f2",
    "f1a142c53586e7e2223ec74e5f4d1a4942956b1fd9ac78fafcdf85117aa345da",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "306f9d8b94f17d93dc6e7cf8f5c79d652eb4c6c4d13de2dddc24af416e13ecaf",
    "1b5a4180cdf40e41be72fd8a997d57fdca702daebc68f59cbd75b3cd1d3ce929",
    "0000000000000000000000000000000000000000000000000000000000000000",
];

fn pcrs() -> Vec<[u8; 32]> {
    PCRS.iter()
        .map(|h| {
            let mut a = [0u8; 32];
            hex::decode_to_slice(h, &mut a).unwrap();
            a
        })
        .collect()
}

#[test]
fn verifies_the_real_azure_vtpm_chain() {
    let collateral = Collateral::from_json(AZURE_COLLATERAL).expect("collateral parses");
    let td = verify_tdx_quote(AZURE_QUOTE, &collateral, AZURE_NOW).expect("td quote verifies");
    let pcrs = pcrs();

    // Full chain: HCL binding (report_data == SHA256(runtime_data)) → AK extracted
    // → AK signature over the TPM quote → pcrDigest == SHA256(PCRs).
    let report = vtpm::verify_azure_vtpm(&td, HCL, AK_MSG, AK_SIG, &pcrs)
        .expect("azure vTPM chain verifies");

    // The application measurement (MRTD ‖ PCR digest) is the real Azure identity.
    // The captured platform is UpToDate, so the TCB gate (DP-005) releases it.
    let m = vtpm::azure_app_measurement(&td, &report).expect("acceptable TCB releases the measurement");
    assert_ne!(m, [0u8; 32]);
    assert_ne!(
        &m[..],
        &td.mr_td[..32],
        "app measurement is a hash, not a truncation"
    );
}

#[test]
fn a_different_measured_boot_pcr_breaks_the_chain() {
    let collateral = Collateral::from_json(AZURE_COLLATERAL).expect("collateral parses");
    let td = verify_tdx_quote(AZURE_QUOTE, &collateral, AZURE_NOW).expect("td quote verifies");
    let mut tampered = pcrs();
    tampered[4][0] ^= 0x01; // a changed kernel/boot measurement
    assert_eq!(
        vtpm::verify_azure_vtpm(&td, HCL, AK_MSG, AK_SIG, &tampered),
        Err(VtpmError::PcrMismatch),
    );
}

#[test]
fn a_corrupt_hcl_header_is_rejected() {
    // The fixed-layout parser validates the "HCLA" signature before trusting any
    // offset — a corrupted header must fail closed, not mis-locate the runtime data.
    let collateral = Collateral::from_json(AZURE_COLLATERAL).expect("collateral parses");
    let td = verify_tdx_quote(AZURE_QUOTE, &collateral, AZURE_NOW).expect("td quote verifies");
    let mut bad = HCL.to_vec();
    bad[0] ^= 0x01; // break the "HCLA" magic
    assert_eq!(
        vtpm::verify_azure_vtpm(&td, &bad, AK_MSG, AK_SIG, &pcrs()),
        Err(VtpmError::HclBinding),
    );
}

#[test]
fn a_tampered_hcl_report_breaks_the_td_binding() {
    let collateral = Collateral::from_json(AZURE_COLLATERAL).expect("collateral parses");
    let td = verify_tdx_quote(AZURE_QUOTE, &collateral, AZURE_NOW).expect("td quote verifies");
    let mut bad_hcl = HCL.to_vec();
    let p = bad_hcl.windows(2).position(|w| w == b"{\"").unwrap();
    bad_hcl[p + 12] ^= 0x01; // perturb the runtime data → report_data hash mismatch
    assert_eq!(
        vtpm::verify_azure_vtpm(&td, &bad_hcl, AK_MSG, AK_SIG, &pcrs()),
        Err(VtpmError::HclBinding),
    );
}
