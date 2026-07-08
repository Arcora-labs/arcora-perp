//! Slice 3b-2a: the gateway's client for turning a sealed window into the six on-chain
//! roots + a proof. `MockProverClient` derives the roots in-process (no network, no
//! confidentiality boundary) and uses the commitment as the proof — accepted by the
//! on-chain MockZkVerifier (proof == commitment). Slice 3b-2b adds `HttpProverClient`
//! (seal → POST /prove → real Groth16 proof); this module's trait is that seam.

// Transitional: the gateway settle loop (next task in Slice 3b-2a) is the non-test
// consumer; until it lands only the Task-1 test exercises this module. Remove then.
#![allow(dead_code)]

use perp_core::commitment::derive_roots;
use perp_core::{Digest, EngineError, Keccak256};
use sequencer::WindowWitness;

/// The six on-chain roots + commitment + proof for one window's `settleBatch`.
#[derive(Clone, Debug)]
pub struct ProveOutcome {
    pub prev_root: Digest,
    pub manifest_hash: Digest,
    pub new_root: Digest,
    pub ordered_root: Digest,
    pub withdrawals_root: Digest,
    pub rejected_root: Digest,
    pub commitment: Digest,
    pub proof: Vec<u8>,
}

#[derive(Debug)]
pub enum ProverClientError {
    /// The window witness failed to replay (should not happen for a live-sealed window).
    Derive(EngineError),
    // Slice 3b-2b adds: Http(String), Decode(String), Seal.
}

/// Turns a sealed window into its six roots + a proof.
pub trait ProverClient: Send + Sync {
    fn prove(&self, witness: &WindowWitness) -> Result<ProveOutcome, ProverClientError>;
}

/// In-process client: derive the roots locally and use the commitment as the proof.
pub struct MockProverClient;

impl ProverClient for MockProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
        let mut state = w.pre_state.clone();
        let d = derive_roots(&mut state, &w.ops, &w.manifest).map_err(ProverClientError::Derive)?;
        let commitment = d.commitment::<Keccak256>();
        Ok(ProveOutcome {
            prev_root: d.prev_state_root,
            manifest_hash: d.manifest_hash,
            new_root: d.new_state_root,
            ordered_root: d.ordered_root,
            withdrawals_root: d.withdrawals_root,
            rejected_root: d.rejected_root,
            commitment,
            proof: commitment.to_vec(),
        })
    }
}
