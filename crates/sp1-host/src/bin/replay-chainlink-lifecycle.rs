//! Execute source-fingerprinted public synthetic gateway lifecycle witnesses.
//! CPU execution only; no registration, proof generation or broadcast route.
use serde_json::{json, Value};
use sp1_host::{hex, sha256, Artifacts};
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Stdin, StatusCode};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path, time::Instant};

const ELF_SHA: &str = "48a8eb8e6acd96057a72ca74db5077ac9e85d30d2ec830518ef1f1ac3832ef1f";
const VKEY: &str = "0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590";

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_file() || before.len() == 0 || before.len() > limit {
        return Err("lifecycle input is not a bounded regular file".into());
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
        return Err("lifecycle input identity changed".into());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.len() {
        return Err("lifecycle input size changed".into());
    }
    Ok(bytes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (elf_path, input, manifest_sha, output) = match args.as_slice() {
        [e, elf, i, input, m, manifest, o, output]
            if e == "--elf" && i == "--input-dir" && m == "--manifest-sha256" && o == "--output-dir" =>
        {
            (Path::new(elf), Path::new(input), manifest.to_str().ok_or("invalid manifest hash")?, Path::new(output))
        }
        _ => return Err("usage: replay-chainlink-lifecycle --elf PINNED_ELF --input-dir FIXTURES --manifest-sha256 EXPECTED_SHA --output-dir NEW_DIRECTORY".into()),
    };
    let elf_bytes = read_regular(elf_path, 2 * 1024 * 1024)?;
    if sha256(&elf_bytes) != ELF_SHA {
        return Err("candidate ELF pin mismatch".into());
    }
    let raw = read_regular(&input.join("manifest.json"), 256 * 1024)?;
    if sha256(&raw) != manifest_sha {
        return Err("lifecycle manifest pin mismatch".into());
    }
    let manifest: Value = serde_json::from_slice(&raw)?;
    if manifest["synthetic"] != true
        || manifest["real_don_verified"] != false
        || manifest["proof_generated"] != false
        || manifest["candidate_submission"] != "HOLD"
    {
        return Err("lifecycle fixture scope mismatch".into());
    }
    let cases = manifest["cases"]
        .as_array()
        .ok_or("lifecycle cases missing")?;
    if !(2..=32).contains(&cases.len()) {
        return Err("lifecycle case count out of bounds".into());
    }
    let mut inputs = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for case in cases {
        let name = case["name"].as_str().ok_or("case name missing")?;
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !names.insert(name)
            || case["witness_file"] != format!("{name}.witness.bin")
        {
            return Err("invalid or duplicate lifecycle case identity".into());
        }
        let bytes = read_regular(&input.join(format!("{name}.witness.bin")), 16 * 1024 * 1024)?;
        if case["witness_sha256"] != sha256(&bytes)
            || case["witness_bytes"] != bytes.len()
            || !matches!(case["outcome"].as_str(), Some("PASS" | "REJECT"))
        {
            return Err("lifecycle witness binding mismatch".into());
        }
        if case["outcome"] == "PASS" {
            let expected = case["expected_commitment"]
                .as_str()
                .ok_or("native commitment missing")?;
            if expected.len() != 64
                || !expected
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("native commitment encoding mismatch".into());
            }
        }
        inputs.push((name, case, bytes));
    }
    for required in ["normal-lifecycle", "liquidation"] {
        if !cases
            .iter()
            .any(|case| case["name"] == required && case["outcome"] == "PASS")
        {
            return Err("required real gateway lifecycle case missing".into());
        }
    }
    let mut artifacts = Artifacts::new(output)?;
    let elf = Elf::from(elf_bytes);
    let client = ProverClient::builder().cpu().build().await;
    let key = client.setup(elf.clone()).await?;
    let vkey = key.verifying_key().bytes32();
    if vkey != VKEY {
        return Err("candidate program key pin mismatch".into());
    }
    let mut results = Vec::new();
    for (name, case, bytes) in inputs {
        let success = case["outcome"] == "PASS";
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(bytes.clone());
        let started = Instant::now();
        let (values, report) = client
            .execute(elf.clone(), stdin)
            .expected_exit_code(if success {
                StatusCode::SUCCESS
            } else {
                StatusCode::PANIC
            })
            .await?;
        if report.exit_code != if success { 0 } else { 1 } {
            return Err("unexpected guest exit".into());
        }
        if success {
            if values.as_slice().len() != 32
                || case["expected_commitment"] != hex(values.as_slice())
            {
                return Err("native and candidate guest commitments differ".into());
            }
        } else if !values.as_slice().is_empty() {
            return Err("rejected witness committed public values".into());
        }
        artifacts.write(&format!("{name}.public-values.bin"), values.as_slice())?;
        results.push(json!({"name":name,"outcome":case["outcome"],"witness_sha256":sha256(&bytes),
            "guest_exit_code":report.exit_code,"public_values_hex":hex(values.as_slice()),
            "cycles":report.total_instruction_count(),"elapsed_seconds":started.elapsed().as_secs_f64()}));
        println!(
            "EXECUTED {name} exit={} public_bytes={}",
            report.exit_code,
            values.as_slice().len()
        );
    }
    artifacts.finish(
        json!({"status":"PASS","schema":"arcora-chainlink-lifecycle-cpu-v1",
        "fixture_manifest_sha256":manifest_sha,"candidate_elf_sha256":ELF_SHA,"program_vkey":vkey,
        "synthetic":true,"native_guest_equal":true,"guest_executed":true,"proof_generated":false,
        "real_don_verified":false,"candidate_submission":"HOLD","cases":results}),
    )?;
    Ok(())
}
