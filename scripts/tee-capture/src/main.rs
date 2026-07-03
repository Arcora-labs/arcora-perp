//! Live Azure TDX capture: HCL report (read from the vTPM by `capture.sh`)
//! → TD report → IMDS TD quote → fresh Intel PCS collateral → offline verify.
//!
//! Produces `quote.bin` + `collateral.json` next to `hcl_report.bin` in the
//! output dir; `capture.sh` adds the AK-quote + PCR artifacts. The fixed HCL
//! layout (TD report @32, gates @1224/1228, var_data @1236) is byte-locked to
//! `crates/attestation/src/vtpm.rs::runtime_data` and was re-verified against
//! the pinned fixture capture before being encoded here.

use base64::Engine;

const IMDS_QUOTE_URL: &str = "http://169.254.169.254/acc/tdquote";

fn le_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

#[derive(serde::Deserialize)]
struct QuoteResponse {
    quote: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "attestation-live".into());
    let dir = std::path::Path::new(&out);
    let hcl = std::fs::read(dir.join("hcl_report.bin"))?;

    // The same fixed-layout gates as the verifier's runtime_data().
    if hcl.get(0..4) != Some(b"HCLA".as_slice()) {
        return Err("hcl_report.bin is not an HCL attestation report".into());
    }
    if le_u32(&hcl, 1224) != Some(4) {
        return Err("HCL report_type is not TDX".into());
    }
    let td_report = hcl.get(32..32 + 1024).ok_or("HCL report too short")?;

    // IMDS TD quote. NOTE the bare `application/json`: IMDS rejects the
    // `; charset=utf-8` suffix that send_json-style helpers append (HTTP 415).
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let body = serde_json::json!({ "report": b64.encode(td_report) }).to_string();
    let text = ureq::post(IMDS_QUOTE_URL)
        .header("Content-Type", "application/json")
        .send(body.as_bytes())?
        .body_mut()
        .read_to_string()?;
    let resp: QuoteResponse = serde_json::from_str(&text)?;
    let quote = b64.decode(resp.quote.trim_end_matches('='))?;
    std::fs::write(dir.join("quote.bin"), &quote)?;

    // Fresh collateral (Phala PCCS fronting Intel PCS), then an offline verify
    // sanity pass at the current time — exactly what the gateway redoes at boot.
    let url = dcap_qvl::PHALA_PCCS_URL.to_string();
    let collateral = dcap_qvl::collateral::CollateralClient::with_default_http(url)?
        .fetch(&quote)
        .await?;
    std::fs::write(dir.join("collateral.json"), serde_json::to_string(&collateral)?)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let report =
        dcap_qvl::verify::verify(&quote, &collateral, now).map_err(|e| format!("verify: {e:?}"))?;
    println!(
        "VERIFY_OK status={} advisories={:?}",
        report.status, report.advisory_ids
    );
    Ok(())
}
