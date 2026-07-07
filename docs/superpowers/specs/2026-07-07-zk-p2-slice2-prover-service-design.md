# ZK Verifier P2 — Slice 2: Attested Prover Service (Design)

**Date:** 2026-07-07
**Status:** Approved (brainstorming) → ready for implementation plan
**Workstream:** ZK verifier P2. Slice 1 (on-chain `SP1ZkVerifier` adapter) is DONE and
end-to-end verified on Base Sepolia (a real Groth16 proof of the P1-derived commitment
was accepted on-chain). This spec is **Slice 2**: turn "produce a real Groth16 proof" into
a reusable **attested prover service** the sequencer/gateway can call. Later: Slice 3
(gateway per-engine-batch settlement + wire the settle path to this service), then the
live-stack migration, then P3 (real TDX/Nitro attested key-release).

---

## 1. Problem

Slice 1 proved the on-chain path works: `SP1ZkVerifier` (`0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF`
on Base Sepolia) verified a real SP1 Groth16 proof and advanced a settlement. But that proof
was produced by a one-off script (`sp1-host/src/bin/prove.rs`). For the sequencer to settle
with real proofs, "prove a batch" must be a reusable capability — and, per §10b, the prover
must be a SEPARATE attested process (a bare prover farm sees every position/fill in the
witness; SP1's public Prover Network would too). The `prover` crate already models this
boundary (`AttestedProver` + `SealedWitness` + `SealKeyProvider`), but its `Prover` backend is
the unsound `CommitmentProver` stand-in.

## 2. Goal

A standalone **prover service**: a persistent process that receives a witness **sealed to the
prover measurement**, opens it (measurement-gated), derives the batch's public roots, generates
a **real SP1 Groth16 proof**, zeroizes the plaintext, and returns `{ proof, 6 roots, commitment }`.
`sp1-sdk` stays out of the workspace (no gateway bloat, no arm64 CI break). The service is the
one place that holds the SP1 proving stack; the gateway will call it (Slice 3).

## 3. Resolved design decisions

- **New excluded crate `crates/prover-service`** (NOT an extension of `sp1-host`, which is the
  equivalence-gate harness). It is `exclude`d from the workspace (heavy `sp1-sdk`), built on the
  prover machine, and has its own guest `build.rs` (`sp1-build`) + `include_elf!("perp-core-guest")`.
- **Sealing IS included via the existing `SoftwareSealProvider` stand-in** (the full
  `AttestedProver` path: open sealed → derive → prove → zeroize). P3 swaps ONLY the
  `SealKeyProvider` for real TDX/Nitro key-release — the typed boundary does not change.

## 4. Architecture

```
sequencer/test-client                 prover-service (excluded crate, prover machine)
  witness = (state, ops, manifest)      ┌─────────────────────────────────────────────┐
  seal to (MEASUREMENT, ROOT) ──POST──▶ │ POST /prove: SealedWitness                   │
                                        │   AttestedProver<Sp1GnarkProver>(SoftwareSeal)│
                                        │     .prove_batch(sealed):                     │
                                        │       open (measurement-gated) → witness bytes│
                                        │       run_transition → PublicInputs (6 roots) │
                                        │       Sp1GnarkProver.prove → real Groth16     │
                                        │       zeroize opened plaintext                │
                                        │   → { proof, 6 roots, commitment }            │
                                        │ GET /vkey        → programVKey (bytes32)      │
                                        │ GET /measurement → attested measurement       │
                                        └─────────────────────────────────────────────┘
                                                     proof verifies on-chain against
                                                     SP1ZkVerifier (Slice 1)
```

### 4.1 `Sp1GnarkProver` — real SP1 backend (`impl prover::Prover`)

- Constructor does `ProverClient::builder().cpu().build()` + `client.setup(ELF)` ONCE, caching
  the proving key `pk` (setup + circuit load is expensive — do not repeat per request). Stores the
  attested `measurement` (for Slice 2: a fixed stand-in constant, e.g. the program vkey bytes; P3:
  the real enclave measurement).
- `measurement(&self) -> Digest` → the cached measurement.
- `prove(&self, public: &PublicInputs, witness: &[u8]) -> Vec<u8>`: `SP1Stdin::write_vec(witness)`,
  `block_on(client.prove(&pk, stdin).groth16())`, return `proof.bytes()`. (SP1 is async; the sync
  trait method blocks on a runtime handle.) A debug assertion checks the proof's `public_values`
  equal `public.commitment::<Keccak256>()` — the guest DERIVES the roots inside, so the proof's
  public value is the derived commitment; this catches a witness/public mismatch early.
- Excluded crate: `sp1-sdk = "6.0.0"`, `[build-dependencies] sp1-build`, `include_elf!`.

### 4.2 `prover` crate addition — `AttestedProver::prove_batch`

Add ONE method so the service is thin and the derivation stays inside the attested boundary
(F2-safe: the prover derives the roots, never trusts an external public-inputs claim):

```rust
// crates/prover/src/lib.rs  (prover crate depends on perp-core already)
impl<P: Prover> AttestedProver<P> {
    /// Open a sealed witness (measurement-gated), DERIVE its public inputs from the batch
    /// (state, ops, manifest) via `perp_core::commitment::derive_roots`, prove, and zeroize.
    /// The witness is postcard `(DefaultState, Vec<BatchOp>, BatchManifest)` — the same tuple
    /// the guest reads. Fails `MeasurementMismatch`/`SealAuthFailed` on a bad seal, or
    /// `Transition` on an invalid batch.
    pub fn prove_batch(&self, sealed: &SealedWitness) -> Result<BatchProof, ProverError>;
}
```

Internally: `open(sealed)` → `postcard::from_bytes::<(DefaultState, Vec<BatchOp>, BatchManifest)>` →
`derive_roots(&mut state, &ops, &manifest)` → `PublicInputs` → `backend.prove(&public, &opened)` →
zeroize `opened` → `BatchProof`. Reuses the existing `open`/zeroize logic from `prove_sealed`
(refactor `prove_sealed` to share it). No change to the `Prover`/`SealKeyProvider` traits.

### 4.3 HTTP service (axum)

Persistent service holding one `AttestedProver<Sp1GnarkProver>`:
- `POST /prove` — body: the sealed witness (postcard `SealedWitness`, hex or raw bytes). Response
  JSON: `{ prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, commitment, proof }`
  (all `0x`-hex). Derives the 6 roots (via `run_transition`/`derive_roots` on the opened witness —
  returned so the caller builds `settleBatch` args) and the real Groth16 `proof`.
- `GET /vkey` → `{ vkey }` (the `programVKey` bytes32 for the `SP1ZkVerifier` deploy).
- `GET /measurement` → `{ measurement }` (the measurement clients seal to).
- Config via env: `PROVER_BIND` (e.g. `127.0.0.1:8091`), `PROVER_SEAL_ROOT` (the SoftwareSeal
  stand-in root — P3 replaces this whole provider). Bind loopback by default (the sequencer and
  prover are co-located / on a trusted channel until P3's attested transport).

### 4.4 Sealing (the §10b boundary — stand-in this slice)

The client (test harness now; sequencer in Slice 3) seals: `SealedWitness::seal(witness_bytes,
&SoftwareSealProvider(ROOT, MEASUREMENT), MEASUREMENT, nonce)`. The service opens with the same
`SoftwareSealProvider(ROOT, MEASUREMENT)`. `ROOT` is a shared secret in Slice 2 (env). **P3
replaces `SoftwareSealProvider` with a real TDX/Nitro key-release provider** — measurement-bound,
so only an enclave whose measurement matches obtains the key; the public Prover Network cannot
open the witness. Nothing else changes.

## 5. Testing

- **Rust unit (workspace):** the `prover` crate's `prove_batch` — using the existing
  `CommitmentProver` stand-in as the backend (NOT sp1-sdk), assert: a correctly-sealed witness
  opens + derives the right `PublicInputs` + returns a `BatchProof`; a wrong-measurement seal →
  `MeasurementMismatch`; a tampered ciphertext → `SealAuthFailed`. This keeps the new
  boundary-logic tested in CI without the SP1 toolchain.
- **prover-service unit:** request/response (de)serialization round-trip; the service wiring with
  a `CommitmentProver` backend (feature/cfg) so the HTTP surface is testable without SP1.
- **Real end-to-end on the GB10 (the merge gate for the "real proof" claim):** run the service with
  `Sp1GnarkProver`; a test client seals the Slice-1 test witness and POSTs it; assert the returned
  `commitment == 0xad42…07f9`, the 6 roots match Slice 1, and the returned `proof` **verifies
  on-chain against the deployed `SP1ZkVerifier` `0xCbdD…20bcF`** (via `cast call` or a fresh
  `settleBatch` on a fresh test settlement). Confirms the service emits on-chain-verifiable proofs.
  (Runs where the SP1 toolchain + emulated gnark are — the GB10; documented in the runbook.)

## 6. File map

**Create:**
- `crates/prover-service/Cargo.toml` (excluded crate; `sp1-sdk`, `axum`, `tokio`, `perp-core`, `prover`, `postcard`, `serde_json`; `[build-dependencies] sp1-build`).
- `crates/prover-service/build.rs` (`sp1_build::build_program("../sp1-guest")`).
- `crates/prover-service/src/sp1_prover.rs` (`Sp1GnarkProver: prover::Prover`).
- `crates/prover-service/src/main.rs` (axum service: `/prove`, `/vkey`, `/measurement`).
- `crates/prover-service/tests/` (service (de)serialization + CommitmentProver-backed wiring).

**Modify:**
- `crates/prover/src/lib.rs` — add `AttestedProver::prove_batch`; refactor `prove_sealed` to share the open/zeroize path. Add `prove_batch` unit tests (CommitmentProver backend).
- Root `Cargo.toml` — add `crates/prover-service` to the `exclude` list (like `sp1-guest`/`sp1-host`).
- `docs/PROVING-RUNBOOK.md` — a "run the prover service + prove a batch" section (GB10).

## 7. Non-goals (Slice 2)

- No gateway settle-path integration and no per-engine-batch granularity — **Slice 3**.
- No real TDX/Nitro attestation — **P3** (uses the `SoftwareSealProvider` stand-in; `SealKeyProvider` swap only).
- No live-stack change; no on-chain deploy beyond re-using the Slice-1 `SP1ZkVerifier` for the e2e verify.
- No matching-fairness / ordered-rejected split (Proof-v2).
- No change to the `Prover`/`SealKeyProvider`/`Verifier` traits, the 6-field commitment, or the guest.
