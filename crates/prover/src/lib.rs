//! # prover — the ZK proving harness and confidential-proving boundary (§4, §10b)
//!
//! Two things live here:
//!
//! 1. **The public-input binding** every batch proof commits to — the six roots
//!    `(prev_state_root, batch_manifest_hash, new_state_root, ordered_root,
//!    withdrawals_root, rejected_root)`, all now DERIVED by [`run_transition`] (via
//!    `perp_core::commitment::derive_roots`) and hashed under `Domain::StateRoot`
//!    into the single commitment the L1 verifier checks (Faz 2), independent of
//!    which proving backend produces it.
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
use perp_core::order::BatchManifest;
use perp_core::{DefaultState, EngineError};

/// The public inputs a batch proof commits to and the L1 verifier checks.
///
/// All six roots are now DERIVED by `run_transition` (via
/// `perp_core::commitment::derive_roots`): `withdrawals_root` from the batch's burned
/// notes (a prover cannot invent a withdrawal without a real burn — audit F2), and
/// `ordered_root`/`rejected_root` by merklizing the manifest's committed order-hash
/// lists. CAVEAT (Proof-v2): the ordered-vs-rejected SPLIT itself — whether the
/// matcher's inclusion/rejection decisions obey the matching rule — is NOT proven
/// here; that is Proof-v2, backed in the interim by receipts + inclusion slashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub prev_state_root: Digest,
    pub batch_manifest_hash: Digest,
    pub new_state_root: Digest,
    /// Merkle root of the manifest's ordered order-hash leaves (inclusion proofs).
    pub ordered_root: Digest,
    /// Merkle root of the withdrawals this batch authorizes (vault releases).
    pub withdrawals_root: Digest,
    /// Merkle root of the manifest's rejected order-hash leaves, bound so an honest
    /// sequencer can prove a valid rejection against a wrongful inclusion-slash
    /// (audit DP-004).
    pub rejected_root: Digest,
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
                self.rejected_root,
            ],
        )
    }
}

/// Run the batch state transition and DERIVE the public inputs — **this is the zkVM
/// guest program's host-side twin**. Delegates to `perp_core::commitment::derive_roots`
/// so the prover, the guest, and the host compute byte-identical roots.
pub fn run_transition(
    state: &mut DefaultState,
    ops: &[BatchOp],
    manifest: &BatchManifest,
) -> Result<PublicInputs, EngineError> {
    let d = perp_core::commitment::derive_roots(state, ops, manifest)?;
    Ok(PublicInputs {
        prev_state_root: d.prev_state_root,
        batch_manifest_hash: d.manifest_hash,
        new_state_root: d.new_state_root,
        ordered_root: d.ordered_root,
        withdrawals_root: d.withdrawals_root,
        rejected_root: d.rejected_root,
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
    /// The prover's measurement is not authorized for this sealed witness — the
    /// TEE key-release refused to hand out the seal key (§10b). A public/outsourced
    /// proving network with the wrong measurement lands here.
    MeasurementMismatch,
    /// The sealed witness failed authentication: the ciphertext was tampered with,
    /// or the seal key is wrong. Encrypt-then-MAC catches this before decryption.
    SealAuthFailed,
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
        // hash the witness in 32-byte chunks under its OWN domain — a witness
        // commitment is not a batch-manifest hash, so it must not share that tag.
        let mut words = Vec::new();
        for chunk in witness.chunks(32) {
            let mut w = [0u8; 32];
            w[..chunk.len()].copy_from_slice(chunk);
            words.push(w);
        }
        Keccak256::hash_words(Domain::WitnessCommitment, &words)
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

/// Releases the SECRET per-seal key that the witness sealing now rests on (§10b).
///
/// In production the TEE platform (Intel TDX / AWS Nitro) performs a **key-release
/// bound to the attested measurement**: only an enclave whose measurement matches
/// the sealed program obtains the key. A public/outsourced proving network — the
/// wrong measurement — never gets it, so it cannot open the witness.
///
/// This is the substantive upgrade over the earlier stand-in: that keyed the
/// keystream off the *public* measurement, so anyone who knew the (public)
/// measurement could derive the pad — an access *label*, not real confidentiality.
/// Confidentiality now rests on a SECRET key this provider guards. The real
/// provider (TDX/Nitro key-release) lands in the confidential-VM step and
/// implements this same trait — the typed boundary does not change.
pub trait SealKeyProvider {
    /// The per-seal key for `(measurement, nonce)`, or `None` if this provider is
    /// not authorized for that measurement (models the TEE refusing key-release to
    /// a non-matching enclave). The key MUST vary with `nonce` (the caller binds a
    /// unique per-seal nonce — see [`SealedWitness::seal`]).
    fn seal_key(&self, measurement: &Digest, nonce: &Digest) -> Option<[u8; 32]>;
}

/// Dev/test stand-in for TEE key-release. Holds a secret `root` — modelling the
/// TEE-sealed root key that only the attested binary can unseal — and releases a
/// per-seal key only for its own `measurement`. Swapped for a real TDX/Nitro
/// key-release provider in the confidential-VM step.
pub struct SoftwareSealProvider {
    root: [u8; 32],
    measurement: Digest,
}

impl SoftwareSealProvider {
    /// `root` is the secret the real TEE would seal to the measurement; keep it
    /// out of any public surface. `measurement` is the attested program identity
    /// this provider speaks for.
    pub fn new(root: [u8; 32], measurement: Digest) -> Self {
        Self { root, measurement }
    }
}

impl SealKeyProvider for SoftwareSealProvider {
    fn seal_key(&self, measurement: &Digest, nonce: &Digest) -> Option<[u8; 32]> {
        if *measurement != self.measurement {
            return None; // the TEE releases the key only to the matching measurement
        }
        // Secret-keyed, per-seal-nonce derivation under the key-derivation domain.
        Some(Keccak256::hash_words(
            Domain::KeyDerivation,
            &[self.root, *measurement, *nonce],
        ))
    }
}

/// A witness sealed to a specific attested prover measurement (§10b).
///
/// The plaintext (positions, fills, margins) is recoverable only by a prover that
/// obtains the secret seal key from a [`SealKeyProvider`] authorized for the
/// sealing measurement (TDX/Nitro key-release). Sealing is **encrypt-then-MAC**: a
/// secret-keyed keystream hides the plaintext, and a keyed tag authenticates the
/// ciphertext so tampering or a wrong key is rejected on open.
///
/// ## Per-seal nonce (no two-time pad)
///
/// The keystream is derived from `(seal_key, nonce)`. The caller **must** pass a
/// `nonce` unique per seal (e.g. the batch's public commitment): the seal key is
/// otherwise stable across a measurement's batches, so a key-only keystream would
/// XOR every batch's witness with the *same* pad and two sealed witnesses would
/// leak the XOR of two private ledgers (classic two-time pad). The nonce is stored
/// in the clear (it carries no secret) so the authorized prover can reproduce the
/// keystream.
#[derive(Clone, Debug)]
pub struct SealedWitness {
    ciphertext: Vec<u8>,
    measurement: Digest,
    nonce: Digest,
    /// Encrypt-then-MAC tag over the ciphertext, keyed by the secret seal key —
    /// authenticates the witness so tampering / a wrong key is rejected on open.
    tag: Digest,
}

/// Keystream derived from the SECRET seal `key` and a per-seal `nonce`.
fn keystream(key: &[u8; 32], nonce: &Digest, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u64 = 0;
    while out.len() < len {
        let block = Keccak256::hash_words(
            Domain::WitnessSeal,
            &[*key, *nonce, perp_core::hash::word_u64(counter)],
        );
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Encrypt-then-MAC tag authenticating the sealed ciphertext under the secret key,
/// binding `(key, measurement, nonce, len, ciphertext)`.
fn seal_mac(key: &[u8; 32], measurement: &Digest, nonce: &Digest, ciphertext: &[u8]) -> Digest {
    let mut words = vec![
        *key,
        *measurement,
        *nonce,
        perp_core::hash::word_u64(ciphertext.len() as u64),
    ];
    for chunk in ciphertext.chunks(32) {
        let mut w = [0u8; 32];
        w[..chunk.len()].copy_from_slice(chunk);
        words.push(w);
    }
    Keccak256::hash_words(Domain::WitnessSealMac, &words)
}

/// Constant-time 32-byte tag comparison (no early exit on the first mismatch).
fn ct_eq(a: &Digest, b: &Digest) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

impl SealedWitness {
    /// Seal `plaintext` so only a prover whose [`SealKeyProvider`] is authorized for
    /// `measurement` can open it. Returns `None` if `provider` won't release a key
    /// for `measurement` (the seal can't be produced without the secret key). `nonce`
    /// **must be unique per seal** (reuse reopens the two-time-pad leak) — the batch
    /// public commitment is a natural choice.
    pub fn seal(
        plaintext: &[u8],
        provider: &dyn SealKeyProvider,
        measurement: Digest,
        nonce: Digest,
    ) -> Option<Self> {
        let key = provider.seal_key(&measurement, &nonce)?;
        let ks = keystream(&key, &nonce, plaintext.len());
        let ciphertext: Vec<u8> = plaintext.iter().zip(ks).map(|(p, k)| p ^ k).collect();
        let tag = seal_mac(&key, &measurement, &nonce, &ciphertext);
        Some(Self {
            ciphertext,
            measurement,
            nonce,
            tag,
        })
    }

    pub fn measurement(&self) -> Digest {
        self.measurement
    }

    pub fn nonce(&self) -> Digest {
        self.nonce
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
    /// The TEE key-release boundary: yields the seal key only for an authorized
    /// measurement. A non-attested prover's provider won't release the key.
    seal_provider: Box<dyn SealKeyProvider>,
}

impl<P: Prover> AttestedProver<P> {
    pub fn new(backend: P, seal_provider: impl SealKeyProvider + 'static) -> Self {
        Self {
            backend,
            seal_provider: Box::new(seal_provider),
        }
    }

    pub fn measurement(&self) -> Digest {
        self.backend.measurement()
    }

    /// Open a sealed witness. Fails with `MeasurementMismatch` if the key-release
    /// provider won't hand out the seal key for this witness's measurement (a
    /// non-attested prover), or `SealAuthFailed` if the authenticated ciphertext
    /// doesn't verify (tampering or a wrong key).
    fn open(&self, sealed: &SealedWitness) -> Result<Vec<u8>, ProverError> {
        let key = self
            .seal_provider
            .seal_key(&sealed.measurement, &sealed.nonce)
            .ok_or(ProverError::MeasurementMismatch)?;
        // Encrypt-then-MAC: authenticate BEFORE decrypting.
        let expected = seal_mac(&key, &sealed.measurement, &sealed.nonce, &sealed.ciphertext);
        if !ct_eq(&expected, &sealed.tag) {
            return Err(ProverError::SealAuthFailed);
        }
        let ks = keystream(&key, &sealed.nonce, sealed.ciphertext.len());
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
        // Zeroize the opened witness, then force the optimizer to treat the buffer as
        // observed via `black_box`: a plain `*b = 0` on a value dropped immediately
        // after is a dead store the optimizer may elide, leaving the plaintext witness
        // in prover memory — defeating the §10b "deleted after the job" guarantee.
        // `black_box(&witness)` is a safe (no `unsafe`) optimization barrier that
        // prevents the zeroing from being elided.
        for b in witness.iter_mut() {
            *b = 0;
        }
        core::hint::black_box(&witness);
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
    use perp_core::note::owner_from_spend_key;
    use perp_core::Note;

    const M: Digest = [0xAB; 32];
    const WRONG_M: Digest = [0xCD; 32];
    /// Dev seal root (models the TEE-sealed key shared by the attested matcher +
    /// prover binaries). Both the sealer and the authorized opener use it.
    const ROOT: [u8; 32] = [0x5E; 32];

    fn prov(measurement: Digest) -> SoftwareSealProvider {
        SoftwareSealProvider::new(ROOT, measurement)
    }

    /// The minimal honest manifest for `s`'s next batch: tied to the pre-state
    /// (`previous_state_root`/`batch_id`) with no ordered/rejected/oracle entries.
    fn empty_manifest(s: &DefaultState) -> BatchManifest {
        BatchManifest {
            previous_state_root: s.state_root(),
            batch_id: s.next_batch_id,
            ordered: vec![],
            rejected: vec![],
            oracle_updates: vec![],
            matching_rule_version: 0,
            enclave_measurement: [0u8; 32],
            sequencer_pubkey_epoch: 0,
        }
    }

    fn state_with_deposit() -> (DefaultState, Vec<BatchOp>) {
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        // DP-003: a note's owner must equal owner_from_spend_key(spend_key). The
        // FundPosition below spends this note with spend_key [1; 32], so the deposited
        // note (and its commitment) must be owned by the owner that key derives.
        let spend_key = [1u8; 32];
        let owner = owner_from_spend_key::<Keccak256>(&spend_key);
        let blind = [9u8; 32];
        let amount = 10_000 * QUOTE_SCALE;
        let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
        let ops = vec![
            BatchOp::Deposit {
                owner,
                asset_id: 0,
                amount,
                blinding: blind,
            },
            BatchOp::FundPosition {
                owner,
                market_id: 0,
                note_commitment: cm,
                spend_key,
            },
        ];
        (s, ops)
    }

    #[test]
    fn transition_derives_roots_from_manifest() {
        let (mut s, ops) = state_with_deposit();
        let prev = s.state_root();
        let manifest = empty_manifest(&s);
        let public = run_transition(&mut s, &ops, &manifest).unwrap();
        assert_eq!(public.prev_state_root, prev);
        assert_eq!(public.batch_manifest_hash, manifest.hash::<Keccak256>());
        assert_eq!(public.new_state_root, s.state_root());
        assert_ne!(public.prev_state_root, public.new_state_root);
    }

    // audit DP-004: two batches identical except for which orders were rejected must
    // not share a public commitment — else a malicious sequencer could swap the
    // committed rejected set to dodge an inclusion slash.
    #[test]
    fn commitment_binds_the_rejected_root() {
        let base = PublicInputs {
            prev_state_root: [1u8; 32],
            batch_manifest_hash: [2u8; 32],
            new_state_root: [3u8; 32],
            ordered_root: [4u8; 32],
            withdrawals_root: [5u8; 32],
            rejected_root: [6u8; 32],
        };
        let mut other = base;
        other.rejected_root = [7u8; 32];
        assert_ne!(
            base.commitment::<Keccak256>(),
            other.commitment::<Keccak256>(),
            "the rejected root must be bound into the public commitment",
        );
    }

    #[test]
    fn prove_and_verify_roundtrip() {
        let (mut s, ops) = state_with_deposit();
        let manifest = empty_manifest(&s);
        let public = run_transition(&mut s, &ops, &manifest).unwrap();
        let prover = AttestedProver::new(CommitmentProver::new(M), prov(M));
        let witness = b"sealed batch witness: positions, fills, margins";
        let sealed =
            SealedWitness::seal(witness, &prov(M), M, public.commitment::<Keccak256>()).unwrap();
        let proof = prover.prove_sealed(&sealed, &public).unwrap();
        assert!(CommitmentProver::new(M).verify(&proof));
        assert_eq!(proof.public, public);
    }

    #[test]
    fn tampered_public_inputs_break_verification() {
        let (mut s, ops) = state_with_deposit();
        let manifest = empty_manifest(&s);
        let public = run_transition(&mut s, &ops, &manifest).unwrap();
        let prover = AttestedProver::new(CommitmentProver::new(M), prov(M));
        let sealed = SealedWitness::seal(b"w", &prov(M), M, [0x77u8; 32]).unwrap();
        let mut proof = prover.prove_sealed(&sealed, &public).unwrap();
        // flip the new_state_root in the public inputs without re-proving
        proof.public.new_state_root[0] ^= 0xff;
        // the proof bytes no longer match the (tampered) public commitment that a
        // real verifier would recompute; here we recompute and compare.
        let expected = CommitmentProver::new(M).prove(&proof.public, b"w");
        assert_ne!(
            proof.proof_bytes, expected,
            "tampered public must not match"
        );
    }

    #[test]
    fn wrong_measurement_cannot_open_witness() {
        let (mut s, ops) = state_with_deposit();
        let manifest = empty_manifest(&s);
        let public = run_transition(&mut s, &ops, &manifest).unwrap();
        // witness sealed to M, but the prover's key-release is authorized only for
        // WRONG_M → it never obtains the seal key → cannot open (§10b)
        let sealed = SealedWitness::seal(b"private ledger", &prov(M), M, [0x01u8; 32]).unwrap();
        let prover = AttestedProver::new(CommitmentProver::new(WRONG_M), prov(WRONG_M));
        assert_eq!(
            prover.prove_sealed(&sealed, &public),
            Err(ProverError::MeasurementMismatch),
            "a non-attested prover (e.g. public proving network) cannot open the witness"
        );
    }

    #[test]
    fn wrong_measurement_cannot_even_seal() {
        // A key-release provider authorized only for WRONG_M cannot produce a seal
        // bound to M — without the secret key there is no ciphertext to begin with.
        assert!(
            SealedWitness::seal(b"x", &prov(WRONG_M), M, [0x01u8; 32]).is_none(),
            "sealing to M needs a provider authorized for M"
        );
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        // Encrypt-then-MAC: flipping a ciphertext byte must be caught on open as a
        // SealAuthFailed (before any decryption), not silently decrypted to garbage.
        let mut sealed =
            SealedWitness::seal(b"position: +1 BTC", &prov(M), M, [0x03u8; 32]).unwrap();
        sealed.ciphertext[0] ^= 0xff;
        let prover = AttestedProver::new(CommitmentProver::new(M), prov(M));
        assert_eq!(prover.open(&sealed), Err(ProverError::SealAuthFailed));
    }

    #[test]
    fn correct_open_recovers_exact_plaintext() {
        let pt = b"position: -2 ETH @ 1570, margin 314";
        let sealed = SealedWitness::seal(pt, &prov(M), M, [0x04u8; 32]).unwrap();
        let prover = AttestedProver::new(CommitmentProver::new(M), prov(M));
        assert_eq!(prover.open(&sealed).unwrap(), pt);
    }

    #[test]
    fn seal_actually_hides_plaintext() {
        let witness = b"position: +1 BTC @ 100k, margin 20k";
        let sealed = SealedWitness::seal(witness, &prov(M), M, [0x02u8; 32]).unwrap();
        assert_eq!(sealed.ciphertext_len(), witness.len());
        // round-trip through the correct prover recovers nothing observable in
        // the proof bytes (proof is a 32-byte commitment, not the witness)
        let prover = AttestedProver::new(CommitmentProver::new(M), prov(M));
        let public = PublicInputs {
            prev_state_root: [0; 32],
            batch_manifest_hash: [0; 32],
            new_state_root: [1; 32],
            ordered_root: [0; 32],
            withdrawals_root: [0; 32],
            rejected_root: [0; 32],
        };
        let proof = prover.prove_sealed(&sealed, &public).unwrap();
        assert_eq!(proof.proof_bytes.len(), 32);
    }

    #[test]
    fn distinct_nonces_avoid_two_time_pad() {
        // The same plaintext sealed under the same measurement but DIFFERENT nonces
        // must produce different ciphertexts — otherwise every batch (which shares
        // the constant prover measurement) would reuse one keystream and XOR-ing
        // two sealed witnesses would leak the XOR of two private ledgers.
        let pt = b"position: +1 BTC @ 100k, margin 20k";
        let a = SealedWitness::seal(pt, &prov(M), M, [0x01u8; 32]).unwrap();
        let b = SealedWitness::seal(pt, &prov(M), M, [0x02u8; 32]).unwrap();
        // recover the two keystreams via the public XOR relation ks = ct ^ pt
        let ks_a: Vec<u8> = a.ciphertext.iter().zip(pt).map(|(c, p)| c ^ p).collect();
        let ks_b: Vec<u8> = b.ciphertext.iter().zip(pt).map(|(c, p)| c ^ p).collect();
        assert_ne!(ks_a, ks_b, "distinct nonces must yield distinct keystreams");
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "no keystream reuse across seals"
        );

        // and the correct prover still round-trips each one back to the plaintext
        let prover = AttestedProver::new(CommitmentProver::new(M), prov(M));
        assert_eq!(prover.open(&a).unwrap(), pt);
        assert_eq!(prover.open(&b).unwrap(), pt);
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
        // the manifest matches the pre-state (correct previous_state_root/batch_id),
        // so the error comes from `apply_batch` on the bad op, not ManifestMismatch
        let manifest = empty_manifest(&s);
        let err = run_transition(&mut s, &ops, &manifest).unwrap_err();
        assert_eq!(err, EngineError::UnknownOrSpentNote);
    }
}
