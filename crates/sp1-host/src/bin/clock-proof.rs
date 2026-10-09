//! Real local SP1 execution and optional Groth16 proof for clock-envelope v2.
//! Uses only synthetic data and public fixture keys; never submits transactions.
use perp_core::{
    clock::{ClockContext, TimeBounds, WIRE_MAGIC},
    engine::BatchOp,
    fixed::PRICE_SCALE,
    hash::Keccak256,
    oracle::{oracle_digest, OracleSig, OracleTranscript},
};
use serde_json::json;
use sp1_host::{hex, normal_witness, sha256};
use sp1_sdk::{
    include_elf, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin,
    StatusCode,
};
const ELF: Elf = include_elf!("perp-core-guest");
fn encode(w: &sp1_host::Witness, c: ClockContext) -> Vec<u8> {
    let mut bytes = WIRE_MAGIC.to_vec();
    bytes.extend(postcard::to_allocvec(&(&w.0, &w.1, &w.2, c)).unwrap());
    bytes
}
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(
        args.len() == 1 || (args.len() == 2 && args[1] == "--prove"),
        "usage: clock-proof NEW_OUTPUT_DIRECTORY [--prove]"
    );
    let dir = std::path::PathBuf::from(&args[0]);
    std::fs::create_dir(&dir).expect("fresh output directory");
    let mut w = normal_witness();
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let d = oracle_digest(0, 1000 * PRICE_SCALE, 100_000, 0, 1000 * PRICE_SCALE);
    let sig = OracleSig::sign(&key, &d);
    w.0.markets.get_mut(&0).unwrap().oracle_pubkey = sig.recover(&d).unwrap();
    for (now, mark) in [(100_000, 1001), (100_700, 999)] {
        let price = 1000 * PRICE_SCALE;
        let oracle = OracleTranscript {
            price,
            publish_time_ms: now,
            confidence: 0,
            backup_twap: price,
            signature: OracleSig::sign(&key, &oracle_digest(0, price, now, 0, price)),
        };
        w.1.push(BatchOp::AccrueFunding {
            market_id: 0,
            mark: mark * PRICE_SCALE,
            oracle,
            now_ms: now,
        });
    }
    w.2.previous_state_root = w.0.state_root();
    w.2.batch_time_ms = 100_700;
    let roots = perp_core::commitment::derive_roots(&mut w.0.clone(), &w.1, &w.2).unwrap();
    let bounds = TimeBounds::derive(&w.1).unwrap();
    let c = ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: w.2.batch_id,
        previous_root: roots.prev_state_root,
        base_commitment: roots.commitment::<Keccak256>(),
        phase: 0,
        first_ms: bounds.first_ms,
        last_ms: bounds.last_ms,
        timed_ops: bounds.count,
        anchored_at_ms: 101_000,
        max_window_ms: 10_000,
        clock_skew_ms: 2_000,
    };
    let bytes = encode(&w, c);
    let public = prover::public_from_witness(&bytes).unwrap();
    let expected = public.commitment::<Keccak256>();
    std::fs::write(dir.join("clock.witness.bin"), &bytes).unwrap();
    std::fs::write(dir.join("guest.elf"), &*ELF).unwrap();
    let client = ProverClient::builder().cpu().build().await;
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let (values, report) = client
        .execute(ELF, stdin)
        .expected_exit_code(StatusCode::SUCCESS)
        .await
        .expect("clock guest execution");
    assert_eq!(values.as_slice(), expected.as_slice());
    let mut negatives = Vec::new();
    for name in [
        "wrong-bounds",
        "wrong-count",
        "wrong-batch",
        "wrong-base",
        "backdated",
    ] {
        let mut bad = c;
        match name {
            "wrong-bounds" => bad.first_ms += 1,
            "wrong-count" => bad.timed_ops -= 1,
            "wrong-batch" => bad.batch_id += 1,
            "wrong-base" => bad.base_commitment[0] ^= 1,
            _ => bad.anchored_at_ms += 20_000,
        };
        let bytes = encode(&w, bad);
        assert!(prover::public_from_witness(&bytes).is_err());
        let mut input = SP1Stdin::new();
        input.write_vec(bytes.clone());
        let (v, r) = client
            .execute(ELF, input)
            .expected_exit_code(StatusCode::PANIC)
            .await
            .expect("actual guest rejects malformed clock");
        assert_eq!(r.exit_code, 1);
        assert!(v.as_slice().is_empty());
        negatives.push(json!({"name":name,"guest_exit":r.exit_code,"public_bytes":v.as_slice().len(),"witness_sha256":sha256(&bytes)}));
    }
    println!(
        "CLOCK_NATIVE_GUEST_PARITY_PASS cycles={}",
        report.total_instruction_count()
    );
    let pk = client.setup(ELF).await.expect("real setup");
    let vkey = pk.verifying_key().bytes32_raw();
    std::fs::write(dir.join("program-vkey.bin"), vkey).unwrap();
    let mut evidence = json!({"kind":"clock-v2-native-guest","sdk_version":"6.1.0",
        "elf_sha256":sha256(&ELF),"witness_sha256":sha256(&bytes),"program_vkey":format!("0x{}",hex(&vkey)),
        "native_guest_equal":true,"cycles":report.total_instruction_count(),"negatives":negatives,
        "commitment":format!("0x{}",hex(&expected)),"proof_generated":false,"target_contract_verified":false});
    std::fs::write(
        dir.join("execution.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    if args.len() == 2 {
        println!("CLOCK_GROTH16_START local CPU");
        let mut input = SP1Stdin::new();
        input.write_vec(bytes);
        let proof = client
            .prove(&pk, input)
            .groth16()
            .await
            .expect("real local Groth16 proof");
        let raw = sp1_host::groth16_payload_for_verification(&proof, &expected).unwrap();
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("local SP1 verifier");
        std::fs::write(dir.join("proof.bin"), raw).unwrap();
        std::fs::write(
            dir.join("proof.sdk.json"),
            serde_json::to_vec(&proof).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("public-values.bin"),
            proof.public_values.as_slice(),
        )
        .unwrap();
        evidence["proof_generated"] = json!(true);
        evidence["local_sdk_verified"] = json!(true);
        std::fs::write(
            dir.join("proof-evidence.json"),
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
        println!("CLOCK_GROTH16_VERIFIED");
    }
}
