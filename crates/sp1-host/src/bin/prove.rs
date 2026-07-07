//! Generates a real SP1 Groth16 proof for the perp-core guest over the same
//! deterministic witness as main.rs, and prints everything an on-chain settleBatch
//! needs: the 6 DERIVED roots, the vkey, the Groth16 proof bytes, and the public
//! values (== the 32-byte publicCommitment). CPU prover (Docker gnark wrap).
use perp_core::commitment::derive_roots;
use perp_core::engine::BatchOp;
use perp_core::hash::Keccak256;
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, Note};
use perp_core::order::BatchManifest;
use perp_core::DefaultState;
use sp1_sdk::{include_elf, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};

const ELF: Elf = include_elf!("perp-core-guest");

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::main]
async fn main() {
    // Same deterministic witness as main.rs (deposit + real withdraw).
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

    // The 6 derived roots — settleBatch(prevRoot, manifestHash, newRoot, orderedRoot,
    // withdrawalsRoot, rejectedRoot, proof). Printed BEFORE proving so we have them
    // even if proving is slow.
    let d = derive_roots(&mut state.clone(), &ops, &manifest).unwrap();
    println!("PREV_ROOT=0x{}", hx(&d.prev_state_root));
    println!("MANIFEST_HASH=0x{}", hx(&d.manifest_hash));
    println!("NEW_ROOT=0x{}", hx(&d.new_state_root));
    println!("ORDERED_ROOT=0x{}", hx(&d.ordered_root));
    println!("WITHDRAWALS_ROOT=0x{}", hx(&d.withdrawals_root));
    println!("REJECTED_ROOT=0x{}", hx(&d.rejected_root));
    println!("COMMITMENT=0x{}", hx(&d.commitment::<Keccak256>()));

    let witness: (DefaultState, Vec<BatchOp>, BatchManifest) = (state, ops, manifest);
    let bytes = postcard::to_allocvec(&witness).unwrap();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes);

    let client = ProverClient::builder().cpu().build().await;
    let pk = client.setup(ELF).await.unwrap();
    println!("VKEY={}", pk.verifying_key().bytes32());

    println!("PROVING_START groth16 (first run pulls the gnark Docker image, be patient)...");
    let proof = client.prove(&pk, stdin).groth16().await.unwrap();
    println!("PROOF=0x{}", hx(&proof.bytes()));
    println!("PUBLIC_VALUES=0x{}", hx(proof.public_values.as_slice()));
    println!("PROVING_DONE");
}
