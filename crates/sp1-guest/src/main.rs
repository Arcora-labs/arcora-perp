//! SP1 zkVM guest — the Proof-v1 validity program (§4, §10b).
//!
//! Runs perp-core's deterministic transition inside the SP1 RISC-V zkVM and commits
//! the cross-layer public commitment. The four non-state roots are DERIVED here (via
//! `perp_core::commitment::derive_roots`), not accepted as trusted witness inputs, so
//! under a real verifier the prover cannot supply an arbitrary withdrawals/ordered/
//! rejected root (audit F2). Byte-identical to `prover::run_transition` and
//! `DarkPerpSettlement.publicCommitment`.
#![no_main]

extern crate alloc;

sp1_zkvm::entrypoint!(main);

use alloc::vec::Vec;
use perp_core::commitment::derive_roots;
use perp_core::engine::BatchOp;
use perp_core::hash::Keccak256;
use perp_core::order::BatchManifest;
use perp_core::DefaultState;

/// Private witness: pre-state, the batch ops, and the manifest. The four non-state
/// roots are DERIVED from these — they are no longer witness inputs. Encoding locked
/// by `perp-core`'s `serde_witness` round-trip test.
type Witness = (DefaultState, Vec<BatchOp>, BatchManifest);

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let (mut state, ops, manifest): Witness =
        postcard::from_bytes(&bytes).expect("witness decode");

    let derived = derive_roots(&mut state, &ops, &manifest).expect("valid transition");
    sp1_zkvm::io::commit_slice(&derived.commitment::<Keccak256>());
}
