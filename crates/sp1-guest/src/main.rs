//! SP1 zkVM guest — the Proof-v1 validity program (§4, §10b).
//!
//! Runs perp-core's deterministic transition inside the SP1 RISC-V zkVM and commits
//! the clock-bound public commitment. The non-state roots are DERIVED here (via
//! `perp_core::clock::bind_transition`), not accepted as trusted witness inputs, so
//! under a real verifier the prover cannot supply an arbitrary withdrawals/ordered/
//! rejected root (audit F2).
//!
//! The only accepted input is `perp_core::clock::WIRE_MAGIC ‖
//! postcard(perp_core::clock::ClockWitness)` with no trailing bytes. Any other input
//! panics, so no proof exists for it. The committed value is
//! `BoundTransition::commitment`, the commitment `ClockBoundVerifier` checks. A native
//! entrypoint that stands in for this guest must apply the same strict rule.
#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let body = bytes
        .strip_prefix(perp_core::clock::WIRE_MAGIC)
        .expect("clock-bound witness required");
    let ((mut state, ops, manifest, clock), rest): (perp_core::clock::ClockWitness, _) =
        postcard::take_from_bytes(body).expect("witness decode");
    assert!(rest.is_empty(), "trailing witness bytes");
    // The decoded witness owns its data; free the raw bytes before the transition.
    drop(bytes);
    let bound = perp_core::clock::bind_transition(&mut state, &ops, &manifest, &clock)
        .expect("valid transition");
    sp1_zkvm::io::commit_slice(&bound.commitment);
}
