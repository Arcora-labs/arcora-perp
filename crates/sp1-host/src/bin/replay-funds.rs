//! Replay the exact four synthetic normal-wallet inputs exported by the owned
//! HTTP/Anvil lifecycle. No proving network, proof generation, or chain writes.
use perp_core::{clock::ClockWitness, commitment::derive_roots, hash::Keccak256};
use serde_json::{json, Value};
use sp1_host::{hex, sha256, Artifacts};
use sp1_sdk::{include_elf, Elf, Prover, ProverClient, SP1Stdin, StatusCode};
use std::{path::Path, time::Instant};

const ELF: Elf = include_elf!("perp-core-guest");
const REVIEWED_ELF: &str = "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5";

fn file(dir: &Path, name: &str) -> Vec<u8> {
    let path = dir.join(name);
    let metadata = std::fs::symlink_metadata(&path).expect("input file exists");
    assert!(
        metadata.file_type().is_file(),
        "regular input file required"
    );
    assert!(metadata.len() <= 16 * 1024 * 1024, "bounded fixture input");
    std::fs::read(path).unwrap()
}

/// Validate every input before executing any guest. Exported test data is public
/// and synthetic; the report is evidence linkage, not a signed chain attestation.
fn inputs(dir: &Path) -> (Vec<u8>, Vec<(Vec<u8>, [u8; 32], Value)>) {
    let manifest_bytes = file(dir, "lifecycle.json");
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["status"], "PASS");
    assert_eq!(manifest["syntheticWitnesses"], true);
    assert_eq!(manifest["chainId"], 31337);
    assert_eq!(manifest["gatewayTransport"], "real loopback HTTP");
    assert_eq!(
        manifest["proofBackend"],
        "native replay + real ClockBoundVerifier + MockZkVerifier (NOT SP1)"
    );
    let settlement = manifest["contracts"]["settlement"]
        .as_str()
        .unwrap()
        .to_ascii_lowercase();
    let clock_verifier = manifest["contracts"]["clockVerifier"]
        .as_str()
        .unwrap()
        .to_ascii_lowercase();
    let batches = manifest["batches"].as_array().expect("batch array");
    assert_eq!(batches.len(), 4, "complete four-window lifecycle required");
    let mut previous_root = None;
    let mut previous_count = 0;
    let mut previous_timed_ms = 0;
    let mut result = Vec::new();
    for (index, batch) in batches.iter().enumerate() {
        assert_eq!(batch["batch"], index as u64);
        let name = format!("batch-{index}.witness.bin");
        assert_eq!(batch["clock"]["filename"], name);
        let bytes = file(dir, &name);
        assert_eq!(
            batch["clock"]["witnessSha256"],
            format!("0x{}", sha256(&bytes))
        );
        assert_eq!(batch["clock"]["witnessBytes"], bytes.len());
        let body = bytes
            .strip_prefix(perp_core::clock::WIRE_MAGIC)
            .expect("clock-v2 input required");
        let ((mut state, ops, manifest, clock), rest): (ClockWitness, _) =
            postcard::take_from_bytes(body).unwrap();
        assert!(rest.is_empty(), "no trailing witness bytes");
        assert_eq!(manifest.batch_id, index as u64);
        assert_eq!(state.next_batch_id, index as u64);
        assert_eq!(clock.chain_id, 31337);
        assert_eq!(clock.phase, 0);
        assert_eq!(format!("0x{}", hex(&clock.settlement)), settlement);
        assert_eq!(format!("0x{}", hex(&clock.verifier)), clock_verifier);
        assert_eq!(clock.max_window_ms, 60_000);
        assert_eq!(clock.clock_skew_ms, 60_000);
        if let Some(root) = previous_root {
            assert_eq!(state.state_root(), root, "state-root continuity");
        } else {
            assert_eq!(state.consumed_deposit_count, 0, "empty deposit genesis");
            assert_eq!(state.external_in, 0, "no synthetic seeded collateral");
        }
        assert!(state.conservation_holds());
        let started = Instant::now();
        let roots = derive_roots(&mut state, &ops, &manifest).unwrap();
        clock.validate(index as u64, &roots, &ops).unwrap();
        let public = prover::public_from_witness(&bytes).unwrap();
        let commitment = public.commitment::<Keccak256>();
        assert_eq!(commitment, clock.commitment());
        assert_eq!(
            batch["clock"]["commitment"],
            format!("0x{}", hex(&commitment))
        );
        assert_eq!(
            batch["clock"]["receipt"],
            format!("0x{}", hex(&clock.receipt()))
        );
        assert_eq!(batch["clock"]["timedOps"], clock.timed_ops);
        assert_eq!(batch["clock"]["anchoredAtMs"], clock.anchored_at_ms);
        assert_eq!(
            batch["stateRoot"],
            format!("0x{}", hex(&roots.new_state_root))
        );
        assert_eq!(
            batch["depositTip"],
            format!("0x{}", hex(&roots.deposits_root))
        );
        assert_eq!(
            batch["withdrawalsRoot"],
            format!("0x{}", hex(&roots.withdrawals_root))
        );
        assert_eq!(batch["depositCount"], state.consumed_deposit_count);
        assert!(state.consumed_deposit_count >= previous_count);
        assert!(state.conservation_holds());
        if clock.timed_ops != 0 {
            assert!(clock.first_ms >= previous_timed_ms);
            previous_timed_ms = clock.last_ms;
        }
        previous_root = Some(roots.new_state_root);
        previous_count = state.consumed_deposit_count;
        result.push((
            bytes,
            commitment,
            json!({
                "batch": index, "operations": ops.len(), "timed_operations": clock.timed_ops,
                "native_replay_seconds": started.elapsed().as_secs_f64(),
                "commitment": format!("0x{}", hex(&commitment)),
                "state_root": format!("0x{}", hex(&roots.new_state_root)),
                "witness_sha256": batch["clock"]["witnessSha256"],
                "position_entries": state.positions.len(), "deposit_count": state.consumed_deposit_count,
            }),
        ));
    }
    assert_eq!(previous_count, 3);
    (manifest_bytes, result)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(args.len() >= 2, "usage: replay-funds SYNTHETIC_WITNESS_DIRECTORY NEW_OUTPUT_DIRECTORY [--native-only] [--elf REVIEWED_ELF]");
    let mut native_only = false;
    let mut explicit_elf = None;
    let mut options = args[2..].iter();
    while let Some(option) = options.next() {
        match option.as_str() {
            "--native-only" if !native_only => native_only = true,
            "--elf" if explicit_elf.is_none() => {
                explicit_elf = Some(options.next().expect("--elf needs a path"))
            }
            _ => panic!("unsupported or repeated option"),
        }
    }
    let elf = explicit_elf.map_or_else(
        || ELF.clone(),
        |path| {
            let path = Path::new(path);
            file(
                path.parent().unwrap(),
                path.file_name().unwrap().to_str().unwrap(),
            )
            .into()
        },
    );
    let (manifest, batches) = inputs(Path::new(&args[0]));
    // Refuse silently executing a stale or different program. Rebuild reviewed
    // guest sources with SP1 6.1.0; updating this pin needs a new proof review.
    assert_eq!(
        sha256(&elf),
        REVIEWED_ELF,
        "rebuilt ELF differs from reviewed clock guest"
    );
    let mut output = Artifacts::new(Path::new(&args[1])).expect("fresh output directory");
    let client = if native_only {
        None
    } else {
        Some(ProverClient::builder().cpu().build().await)
    };
    let mut evidence = Vec::new();
    for (bytes, commitment, mut row) in batches {
        if let Some(client) = &client {
            let started = Instant::now();
            let mut stdin = SP1Stdin::new();
            stdin.write_vec(bytes);
            let (values, report) = client
                .execute(elf.clone(), stdin)
                .expected_exit_code(StatusCode::SUCCESS)
                .await
                .expect("actual guest execution");
            assert_eq!(report.exit_code, 0);
            assert_eq!(
                values.as_slice(),
                commitment.as_slice(),
                "native/guest equality"
            );
            row["guest_seconds"] = json!(started.elapsed().as_secs_f64());
            row["guest_cycles"] = json!(report.total_instruction_count());
            row["guest_exit_code"] = json!(report.exit_code);
            output
                .write(
                    &format!("batch-{}.public-values.bin", row["batch"]),
                    values.as_slice(),
                )
                .unwrap();
        }
        evidence.push(row);
    }
    output.finish(json!({
        "status":"PASS", "kind":"synthetic-wallet-clock-v2-replay", "sdk_version":"6.1.0",
        "lifecycle_manifest_sha256":sha256(&manifest), "elf_sha256":sha256(&elf),
        "elf_origin": if explicit_elf.is_some() { "explicit reviewed artifact; no fresh build claim" } else { "host build output" },
        "native_guest_equal":!native_only, "guest_executed":!native_only,
        "proof_generated":false, "fresh_guest_build_performed":false, "target_contract_verified_with_real_proof":false,
        "scope":"Exact synthetic normal-wallet HTTP/Anvil lifecycle witnesses. Native replay and optional SP1 CPU execution; no fresh proof, production TEE/service loop, finality SLA, or proving capacity claim.",
        "batches":evidence,
    })).unwrap();
    println!("FUNDS_CLOCK_REPLAY_PASS guest_executed={}", !native_only);
}
