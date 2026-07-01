//! SP1 host: prove native ⇄ zkVM equivalence.
//!
//! Runs the perp-core zkVM guest (`crates/sp1-guest`) in the SP1 RISC-V executor
//! over a witness, and asserts the public value it commits — the cross-layer
//! commitment — is byte-for-byte identical to the one native `perp-core` produces
//! for the same transition. This is the executable proof that "written once, run
//! natively AND in the zkVM" holds at the commitment level the L1 verifier checks.
//!
//! Build the guest first, then run:
//!   cd ../sp1-guest && cargo prove build
//!   cd ../sp1-host  && cargo run --release

use perp_core::engine::BatchOp;
use perp_core::hash::{Domain, Hasher, Keccak256};
use perp_core::market::Market;
use perp_core::DefaultState;
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sp1-guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/perp-core-guest"
));

#[tokio::main]
async fn main() {
    // Deterministic witness: fresh state + one market + a deposit.
    let mut state = DefaultState::new(16);
    state.add_market(Market::conservative(0));
    let ops = vec![BatchOp::Deposit { owner: [7u8; 32], asset_id: 0, amount: 1_000_000, blinding: [9u8; 32] }];
    let (mh, ord, wd, rej) = ([0x55u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);

    // Native reference commitment (what the sequencer/prover compute).
    let mut native = state.clone();
    let prev = native.state_root();
    native.apply_batch(&ops).unwrap();
    let new = native.state_root();
    let native_commit = Keccak256::hash_words(Domain::StateRoot, &[prev, mh, new, ord, wd, rej]);

    // Serialize the witness exactly as the guest reads it (postcard).
    let witness: (DefaultState, Vec<BatchOp>, [u8; 32], [u8; 32], [u8; 32], [u8; 32]) = (state, ops, mh, ord, wd, rej);
    let bytes = postcard::to_allocvec(&witness).unwrap();

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes);

    let client = ProverClient::builder().cpu().build().await;
    let (public_values, report) = client.execute(Elf::Static(ELF), stdin).await.expect("guest executes");
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
