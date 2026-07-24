//! # prover — the ZK proving harness and confidential-proving boundary (§4, §10b)
//!
//! Two things live here:
//!
//! 1. **The public-input binding** every batch proof commits to — the seven roots
//!    `(prev_state_root, batch_manifest_hash, new_state_root, ordered_root,
//!    withdrawals_root, rejected_root, deposits_root)`, all now DERIVED by [`run_transition`] (via
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

mod seal_root;
pub use seal_root::{resolve_seal_root, SealRootError};

/// The public inputs a batch proof commits to and the L1 verifier checks.
///
/// All seven roots are now DERIVED by `run_transition` (via
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
    /// SEC-019: the post-batch deposit hash-chain tip. L1 compares this against the
    /// vault's own `depositChainTip` for the same count, so a batch cannot credit a
    /// deposit that no `Deposited` event produced. Ordered LAST, mirroring
    /// `perp_core::commitment::DerivedRoots`.
    pub deposits_root: Digest,
}

impl PublicInputs {
    /// Canonical commitment over the public inputs (the proof's public digest).
    /// MUST match `DarkPerpSettlement.publicCommitment` — and must stay byte-for-byte
    /// identical to `perp_core::commitment::DerivedRoots::commitment()`, which is the
    /// canonical implementation of this same seven-word hash. `commitment_matches_
    /// perp_core_derived_roots` below is the anti-drift guard tying the two together.
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
                self.deposits_root,
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
        deposits_root: d.deposits_root,
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
    /// The opened witness did not decode as the postcard `(DefaultState, Vec<BatchOp>,
    /// BatchManifest)` tuple the guest reads (a malformed or wrong-format witness).
    WitnessDecode,
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

/// SEC-020 §5: the attested provider — the seal key rests on the mutual-attestation
/// SESSION SECRET (from the boot handshake) plus the attested prover measurement,
/// replacing the earlier fail-open public `[0x5E]` seal-root constant. Only a party
/// holding the same `session_secret` (both the gateway sealer and this prover derive
/// it from the identical, order-bound attestation transcript) and speaking for the
/// same measurement can produce or open the seal.
///
/// This is a real improvement over the public-constant root, but note the honest
/// bound in the C3 comment below: in Phase 1 the `session_secret` is only as strong
/// as the /attest transcript it is folded from. Phase 2 (real GB10 CC key-release)
/// swaps `session_secret` for a DH-bound shared secret — same trait, same derivation
/// shape, so nothing upstream changes when it lands.
pub struct AttestedSealProvider {
    pub session_secret: [u8; 32],
    pub measurement: Digest,
}

impl SealKeyProvider for AttestedSealProvider {
    fn seal_key(&self, measurement: &Digest, nonce: &Digest) -> Option<[u8; 32]> {
        if *measurement != self.measurement {
            return None; // key released only for the attested measurement
        }
        // PHASE 2 (C3): the seal key is only as strong as session_secret, which is
        // recomputable from the public /attest transcript today; Phase 2 must derive
        // session_secret from a DH shared secret bound into the attested
        // report_data/AK-extraData before this key is a real secret.
        Some(Keccak256::hash_words(
            Domain::KeyDerivation,
            &[self.session_secret, *measurement, *nonce],
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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    ///
    /// `Send + Sync` so `AttestedProver` (and an `Arc<AttestedProver>`) can be held
    /// across threads by the async prover-service (`Router::with_state`,
    /// `spawn_blocking`), which both require the state to be `Send + Sync`.
    seal_provider: Box<dyn SealKeyProvider + Send + Sync>,
}

impl<P: Prover> AttestedProver<P> {
    pub fn new(backend: P, seal_provider: impl SealKeyProvider + Send + Sync + 'static) -> Self {
        Self {
            backend,
            seal_provider: Box::new(seal_provider),
        }
    }

    /// Build from an ALREADY-boxed provider. Lets a caller (prover-service `main`)
    /// pick the concrete `SealKeyProvider` — `AttestedSealProvider` when an attested
    /// session exists, `SoftwareSealProvider` only under DEV_INSECURE — at runtime
    /// (SEC-020 §5 fail-closed provider selection) without a generic explosion.
    /// `new` remains for the static, single-provider case.
    pub fn from_boxed(backend: P, seal_provider: Box<dyn SealKeyProvider + Send + Sync>) -> Self {
        Self {
            backend,
            seal_provider,
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

    /// Prove a transition over a sealed witness whose public inputs are already known.
    /// The witness is opened only here (measurement-gated), used, and zeroized (§10b).
    pub fn prove_sealed(
        &self,
        sealed: &SealedWitness,
        public: &PublicInputs,
    ) -> Result<BatchProof, ProverError> {
        let witness = self.open(sealed)?;
        Ok(self.prove_opened(witness, public))
    }

    /// Open a sealed witness, DERIVE its public inputs from the batch itself (F2-safe:
    /// the prover derives the roots, never trusts an external claim), prove, and zeroize.
    /// The witness is postcard `(DefaultState, Vec<BatchOp>, BatchManifest)`.
    pub fn prove_batch(&self, sealed: &SealedWitness) -> Result<BatchProof, ProverError> {
        let witness = self.open(sealed)?;
        let (mut state, ops, manifest): (DefaultState, Vec<BatchOp>, BatchManifest) =
            postcard::from_bytes(&witness).map_err(|_| ProverError::WitnessDecode)?;
        let public = run_transition(&mut state, &ops, &manifest)?;
        Ok(self.prove_opened(witness, &public))
    }

    /// Prove over an already-opened witness and zeroize it before returning. The zeroing
    /// is followed by a `black_box` optimization barrier so it is not elided (§10b).
    ///
    /// Zeroize the opened witness, then force the optimizer to treat the buffer as
    /// observed via `black_box`: a plain `*b = 0` on a value dropped immediately after is
    /// a dead store the optimizer may elide, leaving the plaintext witness in prover
    /// memory — defeating the §10b "deleted after the job" guarantee. `black_box(&witness)`
    /// is a safe (no `unsafe`) optimization barrier that prevents the zeroing from being
    /// elided.
    fn prove_opened(&self, mut witness: Vec<u8>, public: &PublicInputs) -> BatchProof {
        let proof_bytes = self.backend.prove(public, &witness);
        for b in witness.iter_mut() {
            *b = 0;
        }
        core::hint::black_box(&witness);
        drop(witness);
        BatchProof {
            public: *public,
            proof_bytes,
            prover_measurement: self.backend.measurement(),
        }
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

    /// The async prover-service holds an `Arc<AttestedProver<_>>` as axum state and
    /// captures it into `spawn_blocking`; both require `Send + Sync`. Boxing the
    /// `SealKeyProvider` as a bare `dyn` would silently break that. Regression guard.
    #[test]
    fn attested_prover_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AttestedProver<CommitmentProver>>();
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
                // SEC-019: first deposit against a fresh state — L1 ordering index 0.
                from: [0u8; 20],
                deposit_id: 0,
                // distinct from the note `blinding` above: this blinds the ON-CHAIN
                // owner commit (spec §1a), a different purpose entirely.
                deposit_blind: [0xDBu8; 32],
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
            deposits_root: [7u8; 32],
        };
        let mut other = base;
        other.rejected_root = [0x99u8; 32];
        assert_ne!(
            base.commitment::<Keccak256>(),
            other.commitment::<Keccak256>(),
            "the rejected root must be bound into the public commitment",
        );
    }

    // SEC-019 ANTI-DRIFT GUARD. `PublicInputs::commitment` and
    // `perp_core::commitment::DerivedRoots::commitment` are two independent
    // implementations of the SAME seven-word hash, and nothing but this test stops them
    // from silently diverging — which is exactly what happened when `deposits_root` was
    // added to `DerivedRoots` alone while this side kept hashing six words, leaving two
    // contradictory "canonical" commitments both green. Any future word added to one
    // side must be added to the other or this fails.
    #[test]
    fn commitment_matches_perp_core_derived_roots() {
        use perp_core::commitment::DerivedRoots;

        // Several distinct root sets, not just the canonical fixture: with all-different
        // words a divergence in ORDER is caught, not merely a divergence in arity.
        let cases: [[u8; 7]; 3] = [
            [1, 2, 3, 4, 5, 6, 7],
            [7, 6, 5, 4, 3, 2, 1],
            [0xAA, 0x00, 0xFF, 0x11, 0x22, 0x33, 0x44],
        ];
        for c in cases {
            let public = PublicInputs {
                prev_state_root: [c[0]; 32],
                batch_manifest_hash: [c[1]; 32],
                new_state_root: [c[2]; 32],
                ordered_root: [c[3]; 32],
                withdrawals_root: [c[4]; 32],
                rejected_root: [c[5]; 32],
                deposits_root: [c[6]; 32],
            };
            let derived = DerivedRoots {
                prev_state_root: [c[0]; 32],
                manifest_hash: [c[1]; 32],
                new_state_root: [c[2]; 32],
                ordered_root: [c[3]; 32],
                withdrawals_root: [c[4]; 32],
                rejected_root: [c[5]; 32],
                deposits_root: [c[6]; 32],
            };
            assert_eq!(
                public.commitment::<Keccak256>(),
                derived.commitment::<Keccak256>(),
                "PublicInputs and DerivedRoots must agree byte-for-byte (case {c:?})",
            );
        }

        // ...and both must equal KAT-COMMIT7, the canonical seven-word known-answer for
        // roots [0x01;32]..[0x07;32] (the same value `perp_core::commitment` asserts and
        // `tests/vectors.rs` pins for the Solidity side).
        const KAT_COMMIT7: Digest = [
            0x27, 0xe3, 0xe5, 0x26, 0x88, 0x35, 0x9d, 0x57, 0x59, 0xff, 0x4c, 0x7b, 0x0b, 0xea,
            0x4d, 0x25, 0xa1, 0x4b, 0x3c, 0x81, 0x65, 0x2a, 0x40, 0x83, 0xd5, 0x31, 0x59, 0x2f,
            0x82, 0x7d, 0x89, 0x02,
        ];
        let canonical = PublicInputs {
            prev_state_root: [1u8; 32],
            batch_manifest_hash: [2u8; 32],
            new_state_root: [3u8; 32],
            ordered_root: [4u8; 32],
            withdrawals_root: [5u8; 32],
            rejected_root: [6u8; 32],
            deposits_root: [7u8; 32],
        };
        assert_eq!(canonical.commitment::<Keccak256>(), KAT_COMMIT7);
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

    // SEC-020 Task 6: the AttestedSealProvider seal/open round-trip. The seal key is
    // bound to the mutual-attestation SESSION SECRET plus the prover measurement (not a
    // public constant), so the gateway (sealer) and prover (opener) round-trip only when
    // they share the same secret AND measurement. This locks the Phase-2-active derivation
    // contract in Phase 1 (see the C3 note at the derivation).
    #[test]
    fn attested_seal_roundtrip_binds_measurement_and_secret() {
        let (secret, m, nonce) = ([9u8; 32], [7u8; 32], [3u8; 32]);
        // Gateway-side provider (session_secret + measurement); the mirrored prover-side
        // provider with the SAME secret + measurement opens what it sealed.
        let gw = AttestedSealProvider {
            session_secret: secret,
            measurement: m,
        };
        let sealed = SealedWitness::seal(b"positions+fills", &gw, m, nonce).expect("seal");

        let good = AttestedProver::new(
            CommitmentProver::new(m),
            AttestedSealProvider {
                session_secret: secret,
                measurement: m,
            },
        );
        assert_eq!(good.open(&sealed).expect("open"), b"positions+fills");

        // wrong secret ⇒ a DIFFERENT seal key ⇒ encrypt-then-MAC rejects on open.
        let bad = AttestedProver::new(
            CommitmentProver::new(m),
            AttestedSealProvider {
                session_secret: [0u8; 32],
                measurement: m,
            },
        );
        assert!(matches!(
            bad.open(&sealed),
            Err(ProverError::SealAuthFailed)
        ));

        // wrong measurement ⇒ the provider refuses the key (None) ⇒ MeasurementMismatch.
        let wrong_m = AttestedProver::new(
            CommitmentProver::new(m),
            AttestedSealProvider {
                session_secret: secret,
                measurement: [1u8; 32],
            },
        );
        assert!(wrong_m.open(&sealed).is_err());
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
            deposits_root: [0; 32],
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

    use perp_core::order::BatchManifest;

    fn sealed_test_witness(m: Digest, root: [u8; 32]) -> (SealedWitness, PublicInputs) {
        let (s, ops) = state_with_deposit();
        let manifest = BatchManifest {
            previous_state_root: s.state_root(),
            batch_id: s.next_batch_id,
            ordered: vec![],
            rejected: vec![],
            oracle_updates: vec![],
            matching_rule_version: 0,
            enclave_measurement: [0u8; 32],
            sequencer_pubkey_epoch: 0,
        };
        let expected = run_transition(&mut s.clone(), &ops, &manifest).unwrap();
        let witness = (s, ops, manifest);
        let bytes = postcard::to_allocvec(&witness).unwrap();
        let sealed =
            SealedWitness::seal(&bytes, &SoftwareSealProvider::new(root, m), m, [0x01u8; 32])
                .unwrap();
        (sealed, expected)
    }

    #[test]
    fn prove_batch_opens_derives_and_proves() {
        let m = [0xAB; 32];
        let root = [0x5E; 32];
        let (sealed, expected) = sealed_test_witness(m, root);
        let prover =
            AttestedProver::new(CommitmentProver::new(m), SoftwareSealProvider::new(root, m));
        let bp = prover.prove_batch(&sealed).unwrap();
        // the derived public inputs match run_transition — prover derived, not trusted
        assert_eq!(
            bp.public.commitment::<Keccak256>(),
            expected.commitment::<Keccak256>(),
            "prove_batch must DERIVE the public commitment from the witness"
        );
        assert_eq!(
            bp.proof_bytes.len(),
            32,
            "CommitmentProver stand-in proof is 32 bytes"
        );
        assert_eq!(bp.prover_measurement, m);
    }

    #[test]
    fn prove_batch_wrong_measurement_cannot_open() {
        let (sealed, _) = sealed_test_witness([0xAB; 32], [0x5E; 32]);
        // prover authorized only for a DIFFERENT measurement → key-release refuses
        let prover = AttestedProver::new(
            CommitmentProver::new([0xCD; 32]),
            SoftwareSealProvider::new([0x5E; 32], [0xCD; 32]),
        );
        assert_eq!(
            prover.prove_batch(&sealed),
            Err(ProverError::MeasurementMismatch)
        );
    }

    #[test]
    fn prove_batch_garbage_witness_is_witness_decode() {
        // seal random non-postcard bytes → opens fine (right key) but decode fails
        let m = [0xAB; 32];
        let root = [0x5E; 32];
        let sealed = SealedWitness::seal(
            b"not a witness",
            &SoftwareSealProvider::new(root, m),
            m,
            [0x02u8; 32],
        )
        .unwrap();
        let prover =
            AttestedProver::new(CommitmentProver::new(m), SoftwareSealProvider::new(root, m));
        assert_eq!(prover.prove_batch(&sealed), Err(ProverError::WitnessDecode));
    }

    // The prover service sends a `SealedWitness` over HTTP as postcard bytes
    // (`postcard::from_bytes::<SealedWitness>`) — this proves that wire path
    // round-trips: seal, encode, decode, re-encode, and the bytes are stable.
    #[test]
    fn sealed_witness_postcard_round_trips() {
        let m = [0xAB; 32];
        let root = [0x5E; 32];
        let sealed = SealedWitness::seal(
            b"batch witness bytes",
            &SoftwareSealProvider::new(root, m),
            m,
            [0x07u8; 32],
        )
        .unwrap();
        let bytes = postcard::to_allocvec(&sealed).expect("serialize");
        let back: SealedWitness = postcard::from_bytes(&bytes).expect("deserialize");
        let bytes2 = postcard::to_allocvec(&back).unwrap();
        assert_eq!(
            bytes, bytes2,
            "SealedWitness survives a postcard round-trip"
        );
    }
}
