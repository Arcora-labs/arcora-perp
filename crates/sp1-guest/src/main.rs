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
    let commitment = if let Some(body) = bytes.strip_prefix(perp_core::clock::WIRE_MAGIC) {
        let ((mut state, ops, manifest, clock), rest): (perp_core::clock::ClockWitness, _) =
            postcard::take_from_bytes(body).expect("v2 witness decode");
        assert!(rest.is_empty(), "trailing witness bytes");
        let roots = derive_roots(&mut state, &ops, &manifest).expect("valid transition");
        clock.validate(manifest.batch_id, &roots, &ops).expect("clock context");
        clock.commitment()
    } else {
        let ((mut state, ops, manifest), rest): (Witness, _) =
            postcard::take_from_bytes(&bytes).expect("legacy witness decode");
        assert!(rest.is_empty(), "trailing witness bytes");
        derive_roots(&mut state, &ops, &manifest).expect("valid transition").commitment::<Keccak256>()
    };
    sp1_zkvm::io::commit_slice(&commitment);
}
