//! SP1 host: prove native ⇄ zkVM equivalence.
//!
//! Runs the perp-core zkVM guest (`crates/sp1-guest`) in the SP1 RISC-V executor
//! over a witness, and asserts the public value it commits — the cross-layer
//! commitment — is byte-for-byte identical to the one native `perp-core` produces
//! for the same transition. This is the executable proof that "written once, run
//! natively AND in the zkVM" holds at the commitment level the L1 verifier checks.
//!
//! The witness is the 3-tuple `(state, ops, manifest)` — the four non-state roots
//! are DERIVED (natively here, and inside the guest) via the shared
//! `perp_core::commitment::derive_roots`, never accepted as trusted inputs (audit
//! F2). The batch includes a real `Withdraw { to: Some(..) }` so the derived
//! `withdrawals_root` is exercised end-to-end.
//!
//! Build the guest first, then run:
//!   cd ../sp1-guest && cargo prove build
//!   cd ../sp1-host  && cargo run --release

use perp_core::commitment::derive_roots;
use perp_core::engine::BatchOp;
use perp_core::hash::Keccak256;
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, Note};
use perp_core::order::BatchManifest;
use perp_core::DefaultState;
use sp1_sdk::{include_elf, Elf, Prover, ProverClient, SP1Stdin};

const ELF: Elf = include_elf!("perp-core-guest");

#[tokio::main]
async fn main() {
    // Deterministic witness: state + market + a deposit + a withdraw (exercises the
    // derived withdrawals_root). The withdraw consumes the freshly deposited note,
    // so note ownership (DP-003: owner = H(spend_key)) holds.
    let spend_key = [3u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&spend_key);
    let blind = [9u8; 32];
    let amount = 1_000_000i128;
    let mut state = DefaultState::new(16);
    state.add_market(Market::conservative(0));
    let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
    let ops = vec![
        BatchOp::Deposit { owner, asset_id: 0, amount, blinding: blind },
        BatchOp::Withdraw { note_commitment: cm, spend_key, to: Some([0xAB; 20]), nonce: 1 },
    ];
    let manifest = BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    };

    // Native reference commitment (what the sequencer/prover compute).
    let native_commit = derive_roots(&mut state.clone(), &ops, &manifest)
        .unwrap()
        .commitment::<Keccak256>();

    // Serialize the witness exactly as the guest reads it (postcard).
    let witness: (DefaultState, Vec<BatchOp>, BatchManifest) = (state, ops, manifest);
    let bytes = postcard::to_allocvec(&witness).unwrap();

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes);

    let client = ProverClient::builder().cpu().build().await;
    let (public_values, report) = client.execute(ELF, stdin).await.expect("guest executes");
    let zk_commit: [u8; 32] = public_values.as_slice().try_into().expect("32-byte commitment");

    println!("cycles            = {}", report.total_instruction_count());
    println!("native commitment = 0x{}", hex(&native_commit));
    println!("zkVM   commitment = 0x{}", hex(&zk_commit));
    assert_eq!(native_commit, zk_commit, "native and zkVM commitments MUST match");
    println!("MATCH: native perp-core == SP1 guest");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
