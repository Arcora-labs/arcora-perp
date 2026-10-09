//! Seal-client for the prover-service e2e: builds the deterministic Slice-1 test witness,
//! seals it to the service's stand-in measurement/root (SoftwareSeal), prints `SEALED=0x<hex>`
//! for `POST /prove`. No sp1-sdk — just builds + seals the witness.
use perp_core::engine::BatchOp;
use perp_core::hash::Keccak256;
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, Note};
use perp_core::order::BatchManifest;
use perp_core::DefaultState;
use prover::{SealedWitness, SoftwareSealProvider};

fn main() {
    // Same deterministic witness as the guest / sp1-host prove path (Slice 1).
    let spend_key = [3u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&spend_key);
    let blind = [9u8; 32];
    let amount = 1_000_000i128;
    let mut state = DefaultState::new(16);
    state.add_market(Market::conservative(0));
    let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
    let ops = vec![
        BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount,
            blinding: blind,
            // SEC-019: demo harness — a toy state whose first deposit is index 0. `from` and
            // `deposit_blind` are placeholders; nothing here is bound to a real L1 event.
            from: [0u8; 20],
            deposit_id: 0,
            deposit_blind: [0u8; 32],
        },
        BatchOp::Withdraw {
            note_commitment: cm,
            spend_key,
            to: Some([0xAB; 20]),
            nonce: 1,
        },
    ];
    let manifest = BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        // This fixture has no clock-carrying operations.
        batch_time_ms: 0,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    };
    let witness: (DefaultState, Vec<BatchOp>, BatchManifest) = (state, ops, manifest);
    let bytes = postcard::to_allocvec(&witness).unwrap();

    // Seal to the service's stand-in measurement (0xAB..) + seal root (0x5E.. default). Must match
    // crates/prover-service/src/main.rs `measurement()` / `seal_root()`.
    let m = [0xABu8; 32];
    let sealed = SealedWitness::seal(
        &bytes,
        &SoftwareSealProvider::new([0x5Eu8; 32], m),
        m,
        [0x11u8; 32],
    )
    .expect("seal");
    let out = postcard::to_allocvec(&sealed).unwrap();
    println!("SEALED=0x{}", hex::encode(out));
}
