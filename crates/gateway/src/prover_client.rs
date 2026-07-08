//! Slice 3b-2a: the gateway's client for turning a sealed window into the six on-chain
//! roots + a proof. `MockProverClient` derives the roots in-process (no network, no
//! confidentiality boundary) and uses the commitment as the proof — accepted by the
//! on-chain MockZkVerifier (proof == commitment). Slice 3b-2b adds `HttpProverClient`
//! (seal → POST /prove → real Groth16 proof); this module's trait is that seam.

// Transitional: the gateway settle loop (next task in Slice 3b-2a) is the non-test
// consumer; until it lands only the Task-1 test exercises this module. Remove then.
#![allow(dead_code)]

use crate::withdrawals::Withdrawal;
use perp_core::commitment::derive_roots;
use perp_core::merkle::{merkle_proof, merkle_root};
use perp_core::{Digest, EngineError, Keccak256};
use sequencer::WindowWitness;
use std::collections::BTreeMap;

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

/// The proven outcome plus the per-note claim proofs the gateway serves.
pub struct PreparedSettle {
    pub outcome: ProveOutcome,
    pub withdraw_proofs: BTreeMap<[u8; 32], (Digest, Vec<[u8; 32]>)>,
}

/// Prove a sealed window and prepare its claim proofs. Builds the window's withdrawal
/// tree from `ww` (op-application order) and asserts its root byte-matches the prover's
/// derived `withdrawals_root` — the two are the same `merkle_root` over the same
/// `withdrawal_leaf`s, so any divergence is a hard error, never silently published.
pub fn prove_and_prepare(
    client: &dyn ProverClient,
    witness: &WindowWitness,
    ww: &[Withdrawal],
) -> Result<PreparedSettle, String> {
    let outcome = client.prove(witness).map_err(|e| format!("prove: {e:?}"))?;

    let leaves: Vec<[u8; 32]> = ww.iter().map(|w| w.leaf()).collect();
    let wroot = merkle_root(&leaves);
    if wroot != outcome.withdrawals_root {
        return Err(format!(
            "withdrawals root mismatch: gateway tree {} vs prover {}",
            crate::hex32(&wroot),
            crate::hex32(&outcome.withdrawals_root)
        ));
    }
    let mut withdraw_proofs = BTreeMap::new();
    for (i, w) in ww.iter().enumerate() {
        withdraw_proofs.insert(w.leaf(), (outcome.withdrawals_root, merkle_proof(&leaves, i)));
    }
    Ok(PreparedSettle { outcome, withdraw_proofs })
}
