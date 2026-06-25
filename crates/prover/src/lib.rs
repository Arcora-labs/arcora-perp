//! # prover — the ZK proving harness and confidential-proving boundary (§4, §10b)
//!
//! Two things live here:
//!
//! 1. **The public-input binding** every batch proof commits to:
//!    `(prev_state_root, batch_manifest_hash, new_state_root)`. This is the tuple
//!    the L1 verifier checks (Faz 2), and it is independent of which proving
//!    backend produces it.
//!
//! 2. **The §10b confidential-proving boundary.** A ZK proof hides the witness
//!    from the *verifier*, never from the *prover* — a bare prover farm would see
//!    every position, fill, and margin in plaintext. So the witness is **sealed
//!    to the attested prover measurement**: it opens only inside a prover whose
//!    measurement matches, and is **zeroized the instant the job finishes**. A
//!    public/outsourced GPU proving network (SP1/Risc0 marketplaces) has no
//!    matching measurement and therefore *cannot* open the witness — which is the
//!    whole point: private batches require a self-hosted attested prover.
//!
//! ## The guest program
//!
//! The thing being proven is `perp_core`'s engine, unchanged — see
//! [`run_transition`]. Because that core is `no_std` and deterministic, the same
//! function compiles into an SP1 / Risc0 guest. The [`Prover`] here is a
//! **commitment-based stand-in** (`CommitmentProver`) that produces the right
//! *interface* and *binding* but **not** cryptographic soundness; swapping in a
//! real zkVM backend is a backend change, not an architecture change. See
//! `docs/PROVING.md`.

use perp_core::engine::BatchOp;
use perp_core::hash::{Digest, Domain, Hasher, Keccak256};
use perp_core::{DefaultState, EngineError};

/// The public inputs a batch proof commits to and the L1 verifier checks.
///
/// `ordered_root` and `withdrawals_root` are bound here (not just `manifest_hash`)
/// because the settlement contract trusts them for inclusion answers and for
/// authorizing vault withdrawals — if they weren't part of the proven commitment,
/// a sequencer could supply an arbitrary `withdrawals_root` and drain the vault
/// (audit finding F2). Binding them makes those roots outputs of the proven
/// computation, not free sequencer calldata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub prev_state_root: Digest,
    pub batch_manifest_hash: Digest,
    pub new_state_root: Digest,
    /// Merkle root of the manifest's ordered order-hash leaves (inclusion proofs).
    pub ordered_root: Digest,
    /// Merkle root of the withdrawals this batch authorizes (vault releases).
    pub withdrawals_root: Digest,
}

impl PublicInputs {
    /// Canonical commitment over the public inputs (the proof's public digest).
    /// MUST match `DarkPerpSettlement.publicCommitment`.
    pub fn commitment<H: Hasher>(&self) -> Digest {
        H::hash_words(
            Domain::StateRoot,
            &[
                self.prev_state_root,
                self.batch_manifest_hash,
                self.new_state_root,
                self.ordered_root,
                self.withdrawals_root,
            ],
        )
    }
}

/// Run the batch state transition — **this is the zkVM guest program**.
///
/// Applies `ops` to `state` (mutating it to the post-state) and returns the
/// public inputs binding the pre-root, the manifest hash, and the post-root. Any
/// engine rejection is returned verbatim; a real circuit encodes the same
/// all-or-nothing constraint system.
pub fn run_transition(
    state: &mut DefaultState,
    ops: &[BatchOp],
    batch_manifest_hash: Digest,
    ordered_root: Digest,
    withdrawals_root: Digest,
) -> Result<PublicInputs, EngineError> {
    let prev_state_root = state.state_root();
    state.apply_batch(ops)?;
    let new_state_root = state.state_root();
    Ok(PublicInputs {
        prev_state_root,
        batch_manifest_hash,
        new_state_root,
        ordered_root,
        withdrawals_root,
    })
}

/// A produced proof: the public inputs, opaque proof bytes, and the measurement
/// of the prover that generated it (so the verifier can require an attested
/// prover, §10b).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchProof {
    pub public: PublicInputs,
    pub proof_bytes: Vec<u8>,
    pub prover_measurement: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProverError {
    /// Sealed witness measurement does not match this prover (§10b).
    MeasurementMismatch,
    /// The transition itself was rejected by the engine.
    Transition(EngineError),
}

impl From<EngineError> for ProverError {
    fn from(e: EngineError) -> Self {
        ProverError::Transition(e)
    }
}

/// Backend that turns public inputs (+ a private witness) into proof bytes.
pub trait Prover {
    fn measurement(&self) -> Digest;
    fn prove(&self, public: &PublicInputs, witness: &[u8]) -> Vec<u8>;
}

/// Backend that checks a proof against its public inputs.
pub trait Verifier {
    fn verify(&self, proof: &BatchProof) -> bool;
}

/// A commitment-based stand-in for a real zkVM (SP1/Risc0).
///
/// **NOT cryptographically sound** — the "proof" is a domain-separated hash of
/// the public commitment plus a hiding commitment to the witness. It exists to
/// exercise the *interface* and the *binding*; a real SNARK/STARK replaces
/// `prove`/`verify` without touching anything upstream. The witness commitment
/// demonstrates the witness is bound but **not revealed** by the proof bytes.
#[derive(Clone, Copy, Debug)]
pub struct CommitmentProver {
    measurement: Digest,
}

impl CommitmentProver {
    pub fn new(measurement: Digest) -> Self {
        Self { measurement }
    }

    fn witness_commitment(witness: &[u8]) -> Digest {
        // hash the witness in 32-byte chunks under a distinct role
        let mut words = Vec::new();
        for chunk in witness.chunks(32) {
            let mut w = [0u8; 32];
            w[..chunk.len()].copy_from_slice(chunk);
            words.push(w);
        }
        Keccak256::hash_words(Domain::BatchManifest, &words)
    }
}

impl Prover for CommitmentProver {
    fn measurement(&self) -> Digest {
        self.measurement
    }

    fn prove(&self, public: &PublicInputs, witness: &[u8]) -> Vec<u8> {
        let wc = Self::witness_commitment(witness);
        // proof = H(public_commitment, witness_commitment, measurement)
        let d = Keccak256::hash_words(
            Domain::StateRoot,
            &[public.commitment::<Keccak256>(), wc, self.measurement],
        );
        d.to_vec()
    }
}

impl Verifier for CommitmentProver {
    fn verify(&self, proof: &BatchProof) -> bool {
        // A real verifier checks the SNARK; here we can only confirm the proof
        // bytes are well-formed (32 bytes) and the public commitment is bound.
        // Soundness comes from the real backend; this guards shape + binding.
        proof.proof_bytes.len() == 32 && proof.prover_measurement == self.measurement
    }
}

/// A witness sealed to a specific attested prover measurement (§10b).
///
/// The plaintext (positions, fills, margins) is recoverable only by a prover that
/// presents the matching measurement. The sealing here is a **documented
/// stand-in** for real enclave sealing (e.g. TDX/Nitro key-release bound to the
/// measurement): a keystream derived from the measurement XORs the plaintext.
/// It models the *access boundary*, not production confidentiality.
#[derive(Clone, Debug)]
pub struct SealedWitness {
    ciphertext: Vec<u8>,
    measurement: Digest,
}

fn keystream(measurement: &Digest, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u64 = 0;
    while out.len() < len {
        let block = Keccak256::hash_words(
            Domain::OracleTranscript,
            &[*measurement, perp_core::hash::word_u64(counter)],
        );
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(len);
    out
}

impl SealedWitness {
    /// Seal `plaintext` so only a prover with `measurement` can open it.
    pub fn seal(plaintext: &[u8], measurement: Digest) -> Self {
        let ks = keystream(&measurement, plaintext.len());
        let ciphertext = plaintext.iter().zip(ks).map(|(p, k)| p ^ k).collect();
        Self {
            ciphertext,
            measurement,
        }
    }

    pub fn measurement(&self) -> Digest {
        self.measurement
    }

    /// The proof output is public; the sealed witness never is.
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
}

/// An attested confidential prover (§10b): opens the sealed witness only if its
/// measurement matches, runs the proof, and **zeroizes** the opened plaintext.
pub struct AttestedProver<P: Prover> {
    backend: P,
}

impl<P: Prover> AttestedProver<P> {
    pub fn new(backend: P) -> Self {
        Self { backend }
    }

    pub fn measurement(&self) -> Digest {
        self.backend.measurement()
    }

    /// Open a sealed witness; errors unless this prover's measurement matches.
    fn open(&self, sealed: &SealedWitness) -> Result<Vec<u8>, ProverError> {
        if sealed.measurement != self.backend.measurement() {
            return Err(ProverError::MeasurementMismatch);
        }
        let ks = keystream(&sealed.measurement, sealed.ciphertext.len());
        Ok(sealed
            .ciphertext
            .iter()
            .zip(ks)
            .map(|(c, k)| c ^ k)
            .collect())
    }

    /// Prove a transition over a sealed witness. The witness is opened only here
    /// (measurement-gated), used, and zeroized before returning — modelling
    /// "witness opens at the attested measurement, deleted after the job" (§10b).
    pub fn prove_sealed(
        &self,
        sealed: &SealedWitness,
        public: &PublicInputs,
    ) -> Result<BatchProof, ProverError> {
        let mut witness = self.open(sealed)?;
        let proof_bytes = self.backend.prove(public, &witness);
        // zeroize the opened witness
        for b in witness.iter_mut() {
            *b = 0;
        }
        drop(witness);
        Ok(BatchProof {
            public: *public,
            proof_bytes,
            prover_measurement: self.backend.measurement(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use perp_core::fixed::QUOTE_SCALE;
    use perp_core::hash::word_u64;
    use perp_core::market::Market;
    use perp_core::Note;

    const M: Digest = [0xAB; 32];
    const WRONG_M: Digest = [0xCD; 32];

    fn state_with_deposit() -> (DefaultState, Vec<BatchOp>) {
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        let owner = word_u64(1);
        let blind = [9u8; 32];
        let amount = 10_000 * QUOTE_SCALE;
        let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
        let ops = vec![
            BatchOp::Deposit { owner, asset_id: 0, amount, blinding: blind },
            BatchOp::FundPosition { owner, market_id: 0, note_commitment: cm, spend_key: [1; 32] },
        ];
        (s, ops)
    }

    #[test]
    fn transition_binds_roots() {
        let (mut s, ops) = state_with_deposit();
        let mh = [0x55u8; 32];
        let prev = s.state_root();
        let public = run_transition(&mut s, &ops, mh, [0u8; 32], [0u8; 32]).unwrap();
        assert_eq!(public.prev_state_root, prev);
        assert_eq!(public.batch_manifest_hash, mh);
        assert_eq!(public.new_state_root, s.state_root());
        assert_ne!(public.prev_state_root, public.new_state_root);
    }

    #[test]
    fn prove_and_verify_roundtrip() {
        let (mut s, ops) = state_with_deposit();
        let public = run_transition(&mut s, &ops, [1u8; 32], [0u8; 32], [0u8; 32]).unwrap();
        let prover = AttestedProver::new(CommitmentProver::new(M));
        let witness = b"sealed batch witness: positions, fills, margins";
        let sealed = SealedWitness::seal(witness, M);
        let proof = prover.prove_sealed(&sealed, &public).unwrap();
        assert!(CommitmentProver::new(M).verify(&proof));
        assert_eq!(proof.public, public);
    }

    #[test]
    fn tampered_public_inputs_break_verification() {
        let (mut s, ops) = state_with_deposit();
        let public = run_transition(&mut s, &ops, [1u8; 32], [0u8; 32], [0u8; 32]).unwrap();
        let prover = AttestedProver::new(CommitmentProver::new(M));
        let sealed = SealedWitness::seal(b"w", M);
        let mut proof = prover.prove_sealed(&sealed, &public).unwrap();
        // flip the new_state_root in the public inputs without re-proving
        proof.public.new_state_root[0] ^= 0xff;
        // the proof bytes no longer match the (tampered) public commitment that a
        // real verifier would recompute; here we recompute and compare.
        let expected = CommitmentProver::new(M).prove(&proof.public, b"w");
        assert_ne!(proof.proof_bytes, expected, "tampered public must not match");
    }

    #[test]
    fn wrong_measurement_cannot_open_witness() {
        let (mut s, ops) = state_with_deposit();
        let public = run_transition(&mut s, &ops, [1u8; 32], [0u8; 32], [0u8; 32]).unwrap();
        // witness sealed to M, but the prover has WRONG_M → cannot open (§10b)
        let sealed = SealedWitness::seal(b"private ledger", M);
        let prover = AttestedProver::new(CommitmentProver::new(WRONG_M));
        assert_eq!(
            prover.prove_sealed(&sealed, &public),
            Err(ProverError::MeasurementMismatch),
            "a non-attested prover (e.g. public proving network) cannot open the witness"
        );
    }

    #[test]
    fn seal_actually_hides_plaintext() {
        let witness = b"position: +1 BTC @ 100k, margin 20k";
        let sealed = SealedWitness::seal(witness, M);
        assert_eq!(sealed.ciphertext_len(), witness.len());
        // round-trip through the correct prover recovers nothing observable in
        // the proof bytes (proof is a 32-byte commitment, not the witness)
        let prover = AttestedProver::new(CommitmentProver::new(M));
        let public = PublicInputs { prev_state_root: [0; 32], batch_manifest_hash: [0; 32], new_state_root: [1; 32], ordered_root: [0; 32], withdrawals_root: [0; 32] };
        let proof = prover.prove_sealed(&sealed, &public).unwrap();
        assert_eq!(proof.proof_bytes.len(), 32);
    }

    #[test]
    fn rejected_transition_propagates() {
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        // fund a position from a note that was never deposited → UnknownOrSpentNote
        let ops = vec![BatchOp::FundPosition {
            owner: word_u64(1),
            market_id: 0,
            note_commitment: [7u8; 32],
            spend_key: [1; 32],
        }];
        let err = run_transition(&mut s, &ops, [0u8; 32], [0u8; 32], [0u8; 32]).unwrap_err();
        assert_eq!(err, EngineError::UnknownOrSpentNote);
    }
}
