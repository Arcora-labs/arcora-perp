//! Exact embedded PUBLIC SYNTHETIC inputs executed by the separately pinned
//! Chainlink candidate guest. CPU only: never requests or generates a proof.
use serde_json::{json, Value};
use sp1_host::{hex, sha256, Artifacts};
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Stdin, StatusCode};
use std::{fs::File, io::Read, path::Path, time::Instant};

const CANDIDATE_ELF_SHA256: &str =
    "48a8eb8e6acd96057a72ca74db5077ac9e85d30d2ec830518ef1f1ac3832ef1f";
const MANIFEST: &str =
    include_str!("../../../chainlink-oracle/tests/fixtures/replay-v1/manifest.json");
fn vectors() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("funding", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/funding.witness.bin").as_slice()),
        ("depeg-funding", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/depeg-funding.witness.bin").as_slice()),
        ("two-observations", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/two-observations.witness.bin").as_slice()),
        ("price-free-empty", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/price-free-empty.witness.bin").as_slice()),
        ("missing-evidence", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/missing-evidence.witness.bin").as_slice()),
        ("extra-evidence", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/extra-evidence.witness.bin").as_slice()),
        ("wrong-market", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/wrong-market.witness.bin").as_slice()),
        ("wrong-feed", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/wrong-feed.witness.bin").as_slice()),
        ("stale-quote", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/stale-quote.witness.bin").as_slice()),
        ("future-quote", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/future-quote.witness.bin").as_slice()),
        ("forged-funding", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/forged-funding.witness.bin").as_slice()),
        ("forged-fill", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/forged-fill.witness.bin").as_slice()),
        ("forged-liquidation", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/forged-liquidation.witness.bin").as_slice()),
        ("forged-unbind", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/forged-unbind.witness.bin").as_slice()),
        ("wrong-chain-context", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/wrong-chain-context.witness.bin").as_slice()),
        ("wrong-clock-context", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/wrong-clock-context.witness.bin").as_slice()),
        ("invalid-state-market", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/invalid-state-market.witness.bin").as_slice()),
        ("trailing-bytes", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/trailing-bytes.witness.bin").as_slice()),
        ("legacy-wire", include_bytes!("../../../chainlink-oracle/tests/fixtures/replay-v1/legacy-wire.witness.bin").as_slice()),
    ]
}
fn checked_elf(path: &Path) -> Result<Elf, Box<dyn std::error::Error>> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("candidate ELF must be a regular non-symlink file".into());
    }
    let mut input = File::open(path)?;
    if !input.metadata()?.is_file() || input.metadata()?.len() > 2 * 1024 * 1024 {
        return Err("candidate ELF input exceeds bounds".into());
    }
    let mut bytes = Vec::new();
    (&mut input)
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if sha256(&bytes) != CANDIDATE_ELF_SHA256 {
        return Err("candidate ELF differs from separately pinned program".into());
    }
    Ok(Elf::from(bytes))
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (elf_path, out_path) = match args.as_slice() {
        [e, elf, o, output] if e == "--elf" && o == "--output-dir" => {
            (Path::new(elf), Path::new(output))
        }
        _ => {
            return Err(
                "usage: replay-chainlink --elf PINNED_CANDIDATE_ELF --output-dir NEW_DIRECTORY"
                    .into(),
            )
        }
    };
    let elf = checked_elf(elf_path)?;
    let manifest: Value = serde_json::from_str(MANIFEST)?;
    assert_eq!(manifest["synthetic"], true);
    assert_eq!(manifest["real_chainlink_signatures"], false);
    assert_eq!(manifest["candidate_elf_sha256"], CANDIDATE_ELF_SHA256);
    let rows = manifest["cases"]
        .as_array()
        .ok_or("fixture cases missing")?;
    let vectors = vectors();
    assert_eq!(rows.len(), 19);
    assert_eq!(rows.len(), vectors.len());
    for (row, (name, bytes)) in rows.iter().zip(&vectors) {
        assert_eq!(row["name"], *name);
        assert_eq!(row["witness_sha256"], sha256(bytes));
        assert_eq!(row["witness_bytes"], bytes.len());
        assert!(matches!(row["outcome"].as_str(), Some("PASS" | "REJECT")));
    }
    // Create output before setup. Existing paths never become replacement evidence.
    let mut output = Artifacts::new(out_path)?;
    let client = ProverClient::builder().cpu().build().await;
    let setup_started = Instant::now();
    let pk = client.setup(elf.clone()).await?;
    let program_vkey = pk.verifying_key().bytes32();
    let setup_seconds = setup_started.elapsed().as_secs_f64();
    println!("CANDIDATE_VKEY={program_vkey}");
    let mut results = Vec::new();
    for (row, (name, bytes)) in rows.iter().zip(vectors) {
        let expected_success = row["outcome"] == "PASS";
        let expected_exit = if expected_success {
            StatusCode::SUCCESS
        } else {
            StatusCode::PANIC
        };
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(bytes.to_vec());
        let started = Instant::now();
        // Executor failures/timeouts are errors, NOT successful negative tests.
        let (values, report) = client
            .execute(elf.clone(), stdin)
            .expected_exit_code(expected_exit)
            .await?;
        assert_eq!(report.exit_code, if expected_success { 0 } else { 1 });
        if expected_success {
            assert_eq!(values.as_slice().len(), 32);
            assert_eq!(row["expected_commitment"], hex(values.as_slice()));
        } else {
            assert!(
                values.as_slice().is_empty(),
                "rejected input must not commit public values"
            );
        }
        output.write(&format!("{name}.public-values.bin"), values.as_slice())?;
        results.push(json!({"case":name,"expected_outcome":row["outcome"],
            "native_error":row["native_error"],"witness_sha256":sha256(bytes),
            "guest_exit_code":report.exit_code,"public_values_bytes":values.as_slice().len(),
            "public_values_hex":hex(values.as_slice()),"guest_cycles":report.total_instruction_count(),
            "guest_seconds":started.elapsed().as_secs_f64()}));
        println!(
            "EXECUTED {name} exit={} public_bytes={}",
            report.exit_code,
            values.as_slice().len()
        );
    }
    output.finish(json!({"status":"PASS","kind":"synthetic-chainlink-candidate-cpu-replay",
        "sdk_version":"6.1.0","candidate_elf_sha256":CANDIDATE_ELF_SHA256,
        "fixture_manifest_sha256":sha256(MANIFEST.as_bytes()),"program_vkey":program_vkey,
        "setup_seconds":setup_seconds,"synthetic_inputs":true,"guest_executed":true,
        "native_guest_equal":true,"proof_generated":false,"real_don_verified":false,
        "live_deployment":false,"fresh_guest_build_performed":false,
        "scope":"Pinned candidate ELF; four synthetic success cases and fifteen expected guest rejections. No actual Chainlink signatures, proof generation, wallet lifecycle, deployment or network proving.",
        "cases":results}))?;
    Ok(())
}
