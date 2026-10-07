# ZK Verifier P2 — Slice 2: Attested Prover Service Implementation Plan


**Goal:** A standalone attested prover service that receives a witness sealed to the prover measurement, opens it, derives the batch roots, generates a real SP1 Groth16 proof, zeroizes the plaintext, and returns `{proof, 6 roots, commitment}` — so the sequencer/gateway (Slice 3) can settle with real proofs.

**Architecture:** The CI-testable boundary logic (`AttestedProver::prove_batch` = open→derive→prove→zeroize) lands in the `prover` crate (workspace, tested against the `CommitmentProver` stand-in — no SP1). A new **excluded** crate `crates/prover-service` holds the real `Sp1GnarkProver` (`impl prover::Prover`, `sp1-sdk`) and an axum HTTP service. `sp1-sdk` never enters the workspace. Real proof generation is validated on the GB10 against the Slice-1 `SP1ZkVerifier`.

**Tech Stack:** Rust (std), `postcard`, `perp-core` (serde), `prover` crate, `sp1-sdk = "6.0.0"` + `sp1-build` (excluded crate only), `axum`/`tokio`.

**Spec:** `docs/superpowers/specs/2026-07-07-zk-p2-slice2-prover-service-design.md`

## Global Constraints

- **`sp1-sdk` stays OUT of the workspace.** It appears ONLY in `crates/prover-service`, which is `exclude`d from the root `Cargo.toml` (like `crates/sp1-guest`/`crates/sp1-host`). The `prover` crate must NOT gain an `sp1-sdk` dependency.
- **F2-safe derivation:** `prove_batch` DERIVES the public inputs from the opened witness via the `prover` crate's `run_transition` (= `perp_core::commitment::derive_roots`). It NEVER accepts an external public-inputs claim.
- **§10b boundary via the stand-in:** sealing uses the existing `SoftwareSealProvider` + `AttestedProver`. P3 swaps ONLY the `SealKeyProvider`. Do NOT change the `Prover`, `Verifier`, or `SealKeyProvider` traits, or `SealedWitness`.
- **Witness wire = postcard `(DefaultState, Vec<BatchOp>, BatchManifest)`** — the exact tuple the guest reads (locked by `perp-core/tests/serde_witness.rs`). The service seals/opens these bytes.
- **6-field commitment unchanged** (`Domain::StateRoot`, byte-identical to guest / `SP1ZkVerifier` / on-chain). The real proof's `public_values` == the 32-byte commitment.
- **Not buildable in this environment (no SP1 toolchain):** `crates/prover-service` (Tasks 2-3) is written here, verified against perp-core/prover/sp1-sdk APIs, and BUILT + RUN on the GB10 (`<operator>@<prover-host>`, SP1 v6.3.1 installed, qemu amd64 for the gnark wrap). Task 1 (`prover` crate) IS workspace-testable here.
- **GB10 real-proof gotchas (from Slice 1):** the gnark wrapper image is amd64-only → run with `DOCKER_DEFAULT_PLATFORM=linux/amd64` (qemu binfmt installed); `sp1-sdk` imports need `ProveRequest` (for `.groth16()`) + `ProvingKey` (for `.verifying_key()`) + `HashableKey` (for `.bytes32()`); the working prove pattern is in `crates/sp1-host/src/bin/prove.rs`.
- **Model policy:** NO Haiku; Fable exhausted → Opus (Sonnet OK for GB10-only crate transcription / docs).

## File Structure

- `crates/prover/src/lib.rs` **(modify)** — `ProverError::WitnessDecode`; refactor `prove_sealed` to share a private `prove_opened`; add `AttestedProver::prove_batch`; unit tests.
- `crates/prover/Cargo.toml` **(modify)** — enable `perp-core` `serde` feature; add `postcard`.
- `crates/prover-service/Cargo.toml` **(new, excluded)** — `sp1-sdk`, `axum`, `tokio`, `serde`/`serde_json`, `hex`, `postcard`, `perp-core` (serde), `prover`; `[build-dependencies] sp1-build`.
- `crates/prover-service/build.rs` **(new)** — `sp1_build::build_program("../sp1-guest")`.
- `crates/prover-service/src/sp1_prover.rs` **(new)** — `Sp1GnarkProver` (`impl prover::Prover`).
- `crates/prover-service/src/main.rs` **(new)** — axum service (`/prove`, `/vkey`, `/measurement`).
- Root `Cargo.toml` **(modify)** — add `crates/prover-service` to `exclude`.
- `docs/PROVING-RUNBOOK.md` **(modify)** — "run the prover service + prove a batch" section.

---

### Task 1: `prover` crate — `AttestedProver::prove_batch` (the CI-tested boundary)

**Files:**
- Modify: `crates/prover/src/lib.rs`
- Modify: `crates/prover/Cargo.toml`
- Test: inline `#[cfg(test)]` in `crates/prover/src/lib.rs`

**Interfaces:**
- Consumes: `run_transition(&mut DefaultState, &[BatchOp], &BatchManifest) -> Result<PublicInputs, EngineError>` (this crate, :81); `AttestedProver::open` (private); `SealedWitness`; `BatchProof`; `SoftwareSealProvider`; `CommitmentProver`.
- Produces: `pub fn AttestedProver::prove_batch(&self, sealed: &SealedWitness) -> Result<BatchProof, ProverError>`; `ProverError::WitnessDecode`.

- [ ] **Step 1: Add deps** to `crates/prover/Cargo.toml` `[dependencies]`:

```toml
perp-core = { path = "../perp-core", features = ["serde"] }
postcard = { version = "1", features = ["alloc"] }
```

(Replace the existing bare `perp-core = { path = "../perp-core" }` line with the serde-featured one.)

- [ ] **Step 2: Write the failing tests** — add to the `#[cfg(test)] mod tests` in `crates/prover/src/lib.rs`. `state_with_deposit()` already exists in that module.

```rust
    use perp_core::order::BatchManifest;

    fn sealed_test_witness(m: Digest, root: [u8; 32]) -> (SealedWitness, PublicInputs) {
        let (mut s, ops) = state_with_deposit();
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
            SealedWitness::seal(&bytes, &SoftwareSealProvider::new(root, m), m, [0x01u8; 32]).unwrap();
        (sealed, expected)
    }

    #[test]
    fn prove_batch_opens_derives_and_proves() {
        let m = [0xAB; 32];
        let root = [0x5E; 32];
        let (sealed, expected) = sealed_test_witness(m, root);
        let prover = AttestedProver::new(CommitmentProver::new(m), SoftwareSealProvider::new(root, m));
        let bp = prover.prove_batch(&sealed).unwrap();
        // the derived public inputs match run_transition — prover derived, not trusted
        assert_eq!(
            bp.public.commitment::<Keccak256>(),
            expected.commitment::<Keccak256>(),
            "prove_batch must DERIVE the public commitment from the witness"
        );
        assert_eq!(bp.proof_bytes.len(), 32, "CommitmentProver stand-in proof is 32 bytes");
        assert_eq!(bp.prover_measurement, m);
    }

    #[test]
    fn prove_batch_wrong_measurement_cannot_open() {
        let (sealed, _) = sealed_test_witness([0xAB; 32], [0x5E; 32]);
        // prover authorized only for a DIFFERENT measurement → key-release refuses
        let prover =
            AttestedProver::new(CommitmentProver::new([0xCD; 32]), SoftwareSealProvider::new([0x5E; 32], [0xCD; 32]));
        assert_eq!(prover.prove_batch(&sealed), Err(ProverError::MeasurementMismatch));
    }

    #[test]
    fn prove_batch_garbage_witness_is_witness_decode() {
        // seal random non-postcard bytes → opens fine (right key) but decode fails
        let m = [0xAB; 32];
        let root = [0x5E; 32];
        let sealed =
            SealedWitness::seal(b"not a witness", &SoftwareSealProvider::new(root, m), m, [0x02u8; 32]).unwrap();
        let prover = AttestedProver::new(CommitmentProver::new(m), SoftwareSealProvider::new(root, m));
        assert_eq!(prover.prove_batch(&sealed), Err(ProverError::WitnessDecode));
    }
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p prover prove_batch`
Expected: FAIL — `prove_batch` / `ProverError::WitnessDecode` undefined (won't compile).

- [ ] **Step 4: Add `ProverError::WitnessDecode`** to the `ProverError` enum (`crates/prover/src/lib.rs:108`), after `Transition`:

```rust
    /// The opened witness did not decode as the postcard `(DefaultState, Vec<BatchOp>,
    /// BatchManifest)` tuple the guest reads (a malformed or wrong-format witness).
    WitnessDecode,
```

- [ ] **Step 5: Refactor `prove_sealed` + add `prove_batch`.** Replace the `prove_sealed` body (`crates/prover/src/lib.rs:398-420`) so the prove+zeroize is a shared private `prove_opened`, and add `prove_batch`:

```rust
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
```

Note: `Vec`, `BatchOp`, `DefaultState`, `BatchManifest` are already imported at the top of the file. `run_transition` mutates the deserialized `state` (applies the batch) but the ORIGINAL `witness` bytes (pristine pre-state) are what go to `prove_opened` → the guest reads the pre-state. `ProverError: PartialEq` is required by the tests' `assert_eq!` — the enum already derives it (used by existing tests at :564); confirm and add `PartialEq, Eq` to the derive if missing.

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test -p prover`
Expected: PASS — the 3 new `prove_batch` tests plus the existing prover suite.

- [ ] **Step 7: Workspace + clippy green**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets`
Expected: green (adding `postcard` + `serde` to prover doesn't perturb others — `perp-core/serde` is already enabled workspace-wide by gateway/sequencer).

- [ ] **Step 8: Commit**

```bash
git add crates/prover/src/lib.rs crates/prover/Cargo.toml
git commit -m "feat(prover): AttestedProver::prove_batch — open, derive (F2-safe), prove, zeroize"
```

---

### Task 2: `crates/prover-service` scaffold + `Sp1GnarkProver`

**Files:**
- Create: `crates/prover-service/Cargo.toml`, `crates/prover-service/build.rs`, `crates/prover-service/src/sp1_prover.rs`
- Modify: root `Cargo.toml` (`exclude` list)

**Interfaces:**
- Consumes: `prover::{Prover, PublicInputs}`, `perp_core::hash::{Digest, Keccak256, Hasher}`, `sp1-sdk`.
- Produces: `Sp1GnarkProver` with `async fn new(measurement: Digest) -> Self`, `fn vkey(&self) -> String`, and `impl prover::Prover`.

**NOTE — not buildable in this environment (SP1 toolchain absent).** Write the code, verify the perp-core/prover/sp1-sdk APIs it uses (cite `crates/sp1-host/src/bin/prove.rs`, which built + ran these on the GB10). Do NOT run cargo here. Built + validated on the GB10 (Task 4 runbook).

- [ ] **Step 1: Add `crates/prover-service` to the root `Cargo.toml` `exclude`** list (next to `crates/sp1-guest`, `crates/sp1-host`):

```toml
exclude = ["crates/sp1-guest", "crates/sp1-host", "crates/prover-service"]
```

- [ ] **Step 2: Create `crates/prover-service/Cargo.toml`** (standalone, own `[workspace]` like sp1-host):

```toml
[package]
name = "prover-service"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
prover = { path = "../prover" }
perp-core = { path = "../perp-core", features = ["serde"] }
sp1-sdk = "6.0.0"
tokio = { version = "1", features = ["full"] }
axum = "0.7"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"
postcard = { version = "1", features = ["alloc"] }

[build-dependencies]
sp1-build = "6.0.0"

# standalone: not part of the host workspace
[workspace]
```

- [ ] **Step 3: Create `crates/prover-service/build.rs`** (auto-build the guest, same pattern as sp1-host):

```rust
//! Compiles the SP1 guest so `include_elf!("perp-core-guest")` resolves. Requires the
//! SP1 toolchain (`cargo prove`).
fn main() {
    sp1_build::build_program("../sp1-guest");
}
```

- [ ] **Step 4: Create `crates/prover-service/src/sp1_prover.rs`** — the real backend:

```rust
//! `Sp1GnarkProver` — a real SP1 Groth16 backend implementing `prover::Prover`. Caches
//! the SP1 proving key (setup is expensive) and blocks on the async SP1 client from the
//! sync trait method. Runs where the SP1 toolchain + (emulated) gnark are (the prover
//! machine), NOT in the workspace. Pattern validated by `crates/sp1-host/src/bin/prove.rs`.
use perp_core::hash::{Digest, Hasher, Keccak256};
use prover::{Prover, PublicInputs};
use sp1_sdk::{
    include_elf, Elf, HashableKey, ProveRequest, Prover as _, ProverClient, ProvingKey, SP1Stdin,
};
use std::sync::Arc;

const ELF: Elf = include_elf!("perp-core-guest");

/// Type aliases for the concrete SP1 CPU client + proving key (see prove.rs).
type Client = sp1_sdk::cpu::CpuProver;
type Pk = sp1_sdk::SP1ProvingKey;

pub struct Sp1GnarkProver {
    client: Arc<Client>,
    pk: Arc<Pk>,
    vkey: String,
    measurement: Digest,
    rt: tokio::runtime::Handle,
}

impl Sp1GnarkProver {
    /// Build the CPU prover, run `setup(ELF)` ONCE (cache pk), capture the vkey. Call from
    /// an async context (holds the current runtime handle for later `block_on`).
    pub async fn new(measurement: Digest) -> Self {
        let client = ProverClient::builder().cpu().build().await;
        let pk = client.setup(ELF).await.expect("sp1 setup");
        let vkey = pk.verifying_key().bytes32();
        Self {
            client: Arc::new(client),
            pk: Arc::new(pk),
            vkey,
            measurement,
            rt: tokio::runtime::Handle::current(),
        }
    }

    pub fn vkey(&self) -> String {
        self.vkey.clone()
    }
}

impl Prover for Sp1GnarkProver {
    fn measurement(&self) -> Digest {
        self.measurement
    }

    /// Generate a real Groth16 proof. `witness` is the postcard `(state, ops, manifest)`
    /// the guest reads; the guest DERIVES the roots inside, so the proof's public values
    /// equal `public.commitment()`. Blocks on the async SP1 client (call inside a
    /// blocking task — see the service).
    fn prove(&self, public: &PublicInputs, witness: &[u8]) -> Vec<u8> {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(witness.to_vec());
        let client = self.client.clone();
        let pk = self.pk.clone();
        let proof = self
            .rt
            .block_on(async move { client.prove(&pk, stdin).groth16().await })
            .expect("sp1 groth16 prove");
        // Sanity: the guest-derived public value must match the natively-derived commitment.
        debug_assert_eq!(
            proof.public_values.as_slice(),
            public.commitment::<Keccak256>().as_slice(),
            "proof public_values must equal the derived commitment"
        );
        proof.bytes()
    }
}
```

The `Client`/`Pk` type aliases (`sp1_sdk::cpu::CpuProver`, `sp1_sdk::SP1ProvingKey`) are the concrete types `ProverClient::builder().cpu().build()` and `client.setup()` return in sp1-sdk 6.x — **confirm the exact paths against sp1-sdk 6.3.1 on the GB10 (Task 4)**; if they differ, adjust the aliases (the method calls are validated by prove.rs). If `block_on`-inside-a-blocking-task deadlocks, switch `prove` to `tokio::task::block_in_place(|| Handle::current().block_on(...))`.

- [ ] **Step 5: Static self-check + commit** (no build here)

Run: `git diff --stat crates/prover-service` — confirm the 3 files + the root-Cargo `exclude` change.

```bash
git add crates/prover-service/Cargo.toml crates/prover-service/build.rs crates/prover-service/src/sp1_prover.rs Cargo.toml
git commit -m "feat(prover-service): Sp1GnarkProver — real SP1 Groth16 backend (excluded crate)"
```

---

### Task 3: `crates/prover-service` axum service

**Files:**
- Create: `crates/prover-service/src/main.rs`

**Interfaces:**
- Consumes: `Sp1GnarkProver` (Task 2), `prover::{AttestedProver, SoftwareSealProvider, SealedWitness, BatchProof}`, `perp_core::hash::Digest`.
- Produces: a binary with `POST /prove`, `GET /vkey`, `GET /measurement`.

**NOTE — not buildable here (SP1 toolchain absent).** Same stance as Task 2.

- [ ] **Step 1: Create `crates/prover-service/src/main.rs`:**

```rust
//! Attested prover HTTP service (§10b). Holds one `AttestedProver<Sp1GnarkProver>` and a
//! `SoftwareSealProvider` stand-in (P3 replaces the SealKeyProvider with real TDX/Nitro
//! key-release). `POST /prove` takes a sealed witness, opens+derives+proves+zeroizes, and
//! returns the 6 roots, the commitment, and the real Groth16 proof.
mod sp1_prover;

use axum::{extract::State, routing::{get, post}, Json, Router};
use perp_core::hash::Digest;
use prover::{AttestedProver, SealedWitness, SoftwareSealProvider};
use serde::{Deserialize, Serialize};
use sp1_prover::Sp1GnarkProver;
use std::sync::Arc;

/// Stand-in measurement + seal root (env-overridable). P3 supplies the real attested
/// measurement + TDX/Nitro key-release; here both sides share a software root.
fn measurement() -> Digest {
    [0xABu8; 32]
}
fn seal_root() -> [u8; 32] {
    let hex = std::env::var("PROVER_SEAL_ROOT").unwrap_or_default();
    let mut root = [0x5Eu8; 32];
    if let Ok(bytes) = hex::decode(hex.trim_start_matches("0x")) {
        if bytes.len() == 32 {
            root.copy_from_slice(&bytes);
        }
    }
    root
}

struct App {
    prover: AttestedProver<Sp1GnarkProver>,
    vkey: String,
    measurement: Digest,
}

#[derive(Deserialize)]
struct ProveReq {
    /// hex postcard-encoded `SealedWitness`.
    sealed: String,
}

#[derive(Serialize)]
struct ProveResp {
    prev_root: String,
    manifest_hash: String,
    new_root: String,
    ordered_root: String,
    withdrawals_root: String,
    rejected_root: String,
    commitment: String,
    proof: String,
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

async fn prove(State(app): State<Arc<App>>, Json(req): Json<ProveReq>) -> Result<Json<ProveResp>, String> {
    let raw = hex::decode(req.sealed.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    let sealed: SealedWitness = postcard::from_bytes(&raw).map_err(|e| e.to_string())?;
    // The SP1 prove blocks; run the whole open+derive+prove off the async worker.
    let app2 = app.clone();
    let bp = tokio::task::spawn_blocking(move || app2.prover.prove_batch(&sealed))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("{e:?}"))?;
    let p = &bp.public;
    Ok(Json(ProveResp {
        prev_root: hx(&p.prev_state_root),
        manifest_hash: hx(&p.batch_manifest_hash),
        new_root: hx(&p.new_state_root),
        ordered_root: hx(&p.ordered_root),
        withdrawals_root: hx(&p.withdrawals_root),
        rejected_root: hx(&p.rejected_root),
        commitment: hx(&p.commitment::<perp_core::hash::Keccak256>()),
        proof: hx(&bp.proof_bytes),
    }))
}

async fn vkey(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "vkey": app.vkey }))
}
async fn measurement_ep(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "measurement": hx(&app.measurement) }))
}

#[tokio::main]
async fn main() {
    let m = measurement();
    let backend = Sp1GnarkProver::new(m).await;
    let vkey = backend.vkey();
    let app = Arc::new(App {
        prover: AttestedProver::new(backend, SoftwareSealProvider::new(seal_root(), m)),
        vkey,
        measurement: m,
    });
    let router = Router::new()
        .route("/prove", post(prove))
        .route("/vkey", get(vkey))
        .route("/measurement", get(measurement_ep))
        .with_state(app);
    let bind = std::env::var("PROVER_BIND").unwrap_or_else(|_| "127.0.0.1:8091".into());
    println!("prover-service on {bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
```

`PublicInputs`' fields (`prev_state_root`, `batch_manifest_hash`, `new_state_root`, `ordered_root`, `withdrawals_root`, `rejected_root`) are all `pub` (see `crates/prover/src/lib.rs` `PublicInputs`). Confirm `AttestedProver`/`SoftwareSealProvider`/`SealedWitness` are re-exported from `prover` (they are `pub` in `prover::` — if any is not, add a `pub use`).

- [ ] **Step 2: Static self-check + commit**

Run: `git diff --stat crates/prover-service` — only `src/main.rs` added.

```bash
git add crates/prover-service/src/main.rs
git commit -m "feat(prover-service): axum service — /prove (sealed->real proof), /vkey, /measurement"
```

---

### Task 4: PROVING-RUNBOOK — run the service + GB10 e2e

**Files:**
- Modify: `docs/PROVING-RUNBOOK.md`

**Interfaces:** none. Operator doc for building/running the prover service and the GB10 e2e that verifies a real proof on-chain.

- [ ] **Step 1: Append a "Prover service (Slice 2)" section** to `docs/PROVING-RUNBOOK.md`:

````markdown
## Prover service (Slice 2) — real proofs on demand

On the SP1 machine (GB10), the prover service turns a sealed witness into a real
Groth16 proof the on-chain `SP1ZkVerifier` accepts.

### Build + run
```bash
cd crates/prover-service
DOCKER_DEFAULT_PLATFORM=linux/amd64 cargo run --release   # amd64 gnark under qemu (arm64 host)
# serves on 127.0.0.1:8091
curl -s localhost:8091/vkey          # -> {"vkey":"0x00f4…9024"}  (matches the deployed SP1ZkVerifier)
curl -s localhost:8091/measurement   # -> {"measurement":"0xabab…"}
```

### Prove a batch
A client seals the witness to the service measurement (SoftwareSeal stand-in) and POSTs it:
`POST /prove {"sealed":"0x<postcard SealedWitness>"}` → `{prev_root, manifest_hash, new_root,
ordered_root, withdrawals_root, rejected_root, commitment, proof}`.

### e2e verify on-chain (the merge gate)
Submit the returned 6 roots + proof to a fresh `DarkPerpSettlement` wired to the Slice-1
`SP1ZkVerifier` (`0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF`), genesis = `prev_root`:
```bash
cast send <SETTLEMENT> "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes)" \
  <prev_root> <manifest_hash> <new_root> <ordered_root> <withdrawals_root> <rejected_root> <proof> \
  --rpc-url https://sepolia.base.org --private-key $KEY
```
status 1 = the service's real proof was verified on-chain by SP1ZkVerifier. (Privacy: for real
batches the service must run on a self-hosted ATTESTED x86_64 prover — the gnark image is
amd64-only, so the arm64 GB10 is a dev/test prover; P3 adds real TDX/Nitro key-release.)
````

- [ ] **Step 2: Commit**

```bash
git add docs/PROVING-RUNBOOK.md
git commit -m "docs(zk-p2): runbook — prover service build/run + GB10 e2e verify"
```

---

## Final verification (after all tasks)

- [ ] `cargo test -p prover` — the 3 `prove_batch` tests green (CI merge gate for the boundary logic).
- [ ] `cargo test --workspace && cargo clippy --workspace --all-targets` — green (prover deps added, nothing else perturbed).
- [ ] `git diff --stat` — Task 2/3 touch only `crates/prover-service/**` + the root `Cargo.toml` `exclude`; `sp1-sdk` appears in NO workspace crate.
- [ ] **GB10 e2e (run by the controller, not a subagent — needs the GB10 SSH):** rsync the branch to the GB10, `cargo run --release` the service, seal + POST the Slice-1 test witness, confirm `commitment == 0xad42…07f9` + the 6 roots match Slice 1, and the returned proof verifies on-chain via a fresh `settleBatch` against `SP1ZkVerifier 0xCbdD…20bcF` (status 1). This is the "real proof from the service" gate.
```
