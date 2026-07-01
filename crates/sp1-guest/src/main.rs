//! SP1 zkVM guest — the Proof-v1 validity program (§4, §10b).
//!
//! This runs `perp_core`'s deterministic state-transition engine — the **exact
//! same code** the sequencer executes natively on the hot path — inside the SP1
//! RISC-V zkVM, and commits the cross-layer public commitment as the proof's
//! public output. Because `perp-core` is `#![no_std]` (+ `alloc`) with no floats,
//! clocks, randomness, or I/O, it compiles unchanged to the zkVM target: "written
//! once, run in two places" is literal, not aspirational.
//!
//! The committed value is byte-identical to `prover::PublicInputs::commitment` and
//! to `DarkPerpSettlement.publicCommitment`, so the L1 verifier checks the same
//! digest the off-chain prover and this circuit produce.
#![no_main]

extern crate alloc;

sp1_zkvm::entrypoint!(main);

use alloc::vec::Vec;
use perp_core::engine::BatchOp;
use perp_core::hash::{Domain, Hasher, Keccak256};
use perp_core::DefaultState;

/// Private witness: pre-state, the batch ops, and the four roots the manifest /
/// settlement bind. Serialized with postcard (see `perp-core`'s serde feature and
/// the `serde_witness` round-trip test that locks this encoding).
type Witness = (DefaultState, Vec<BatchOp>, [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let (mut state, ops, manifest_hash, ordered_root, withdrawals_root, rejected_root): Witness =
        postcard::from_bytes(&bytes).expect("witness decode");

    // The transition: prove the post-state follows from the pre-state under `ops`.
    let prev_state_root = state.state_root();
    state.apply_batch(&ops).expect("valid transition");
    let new_state_root = state.state_root();

    // Public commitment — MUST match prover::PublicInputs::commitment and the L1
    // verifier's publicCommitment (Domain::StateRoot over the six roots).
    let commitment = Keccak256::hash_words(
        Domain::StateRoot,
        &[
            prev_state_root,
            manifest_hash,
            new_state_root,
            ordered_root,
            withdrawals_root,
            rejected_root,
        ],
    );
    sp1_zkvm::io::commit_slice(&commitment);
}
