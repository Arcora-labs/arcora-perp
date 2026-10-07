# SEC-020 Attested-Prover Boundary (Phase 1) Implementation Plan


**Goal:** Close SEC-020's two active code holes — fail-open seal root and unauthenticated `/prove` — by making the seal root fail-CLOSED and gating `/prove` behind a startup mutual-attestation handshake, with pluggable `Attestor`s so the real GB10 CC key-release drops in later (Phase 2) without an interface change.

**Architecture:** New `Attestor` trait in `crates/attestation` (`AzureTdxAttestor` wrapping the existing `verify_tdx_quote`+`vtpm`; `NvidiaCcAttestor` wrapping the nv SDK, fail-closed until GPU CC is on). Gateway and prover run a mutual-attestation handshake at startup that mints a short-lived session token; `/prove` requires it. Seal roots come from `resolve_seal_root` (no `[0x5E]` default) and the runtime `SealKeyProvider` is chosen fail-closed. An explicit `DEV_INSECURE=1` escape (refused when `PROD=1`) keeps dev/testnet working until Phase 2.

**Tech Stack:** Rust workspace (`cargo`), `axum` HTTP (prover-service + gateway), `perp_core` keccak domain hashing (`Keccak256::hash_words` / `Domain`), `postcard`, `nv-attestation-sdk` / `nv-local-gpu-verifier` (subprocess), the existing `attestation` crate (DCAP + Azure vTPM).

## Global Constraints

- Rust workspace; `cargo fmt` + `cargo clippy --workspace --all-targets` clean before every commit; `cargo test --workspace` green.
- Reuse `perp_core::hash::{Keccak256, Domain}`; do NOT introduce a new hash. New domain separators go in `perp_core::hash::Domain` (append at the end of the enum).
- No circuit/guest change; no `SealedWitness` schema change; no `derive_roots` change.
- Production must NEVER silently degrade: no attestation ⇒ no proof (fail-closed). `DEV_INSECURE=1` is refused when `PROD=1`, and every dev path logs a one-line `WARN`.
- The `SealKeyProvider` trait and `SealedWitness` seal/open stay byte-compatible (gateway seals, prover opens — same root derivation on both sides).
- `NvidiaCcAttestor` shells out to the `nv-local-gpu-verifier` in a venv (`~/nvattest-venv` on the prover host); it returns `Err(AttestError::CcNotEnabled)` whenever the verifier reports `confidential compute = False`. No FFI in Phase 1.
- Commit after every task with `git add <exact paths>` (branch `fix/sec-020-attested-prover`).
- Where a step says "match the existing signature", open the cited file first and copy the real signature verbatim — do not invent parameter names.

---

### Task 1: Fail-closed seal root (`resolve_seal_root`)

Closes the fail-open half of SEC-020 on its own. Lowest risk; no attestation yet.

**Files:**
- Create: `crates/prover/src/seal_root.rs`
- Modify: `crates/prover/src/lib.rs` (add `mod seal_root; pub use`)
- Modify: `crates/prover-service/src/main.rs:19-28` (delete `fn seal_root`, call the shared helper in `main`)
- Modify: `crates/gateway/src/main.rs` (the gateway's seal-root read — grep `0x5E` / `PROVER_SEAL_ROOT`)
- Test: `crates/prover/src/seal_root.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Produces: `pub fn resolve_seal_root(prod: bool) -> Result<[u8; 32], SealRootError>` and
  `pub enum SealRootError { Unset, BadHex, DevInsecureInProd }` (derive `Debug`, impl `std::fmt::Display` + `std::error::Error`).
- Consumes: env `PROVER_SEAL_ROOT` (32-byte hex, `0x`-optional), `DEV_INSECURE` (`"1"`).

- [ ] **Step 1: Write the failing tests**

Add to `crates/prover/src/seal_root.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Serialize env-mutating tests: cargo runs tests in threads sharing the process env.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _g = ENV_LOCK.lock().unwrap();
        let saved: Vec<_> = vars.iter().map(|(k, _)| (*k, std::env::var(k).ok())).collect();
        for (k, v) in vars { match v { Some(v) => std::env::set_var(k, v), None => std::env::remove_var(k) } }
        f();
        for (k, v) in saved { match v { Some(v) => std::env::set_var(k, v), None => std::env::remove_var(k) } }
    }

    #[test]
    fn unset_and_not_dev_refuses() {
        with_env(&[("PROVER_SEAL_ROOT", None), ("DEV_INSECURE", None)], || {
            assert!(matches!(resolve_seal_root(false), Err(SealRootError::Unset)));
        });
    }

    #[test]
    fn explicit_hex_is_used() {
        let hex = "0x".to_string() + &"11".repeat(32);
        with_env(&[("PROVER_SEAL_ROOT", Some(&hex)), ("DEV_INSECURE", None)], || {
            assert_eq!(resolve_seal_root(true).unwrap(), [0x11u8; 32]);
        });
    }

    #[test]
    fn dev_insecure_gives_non_5e_root_in_nonprod() {
        with_env(&[("PROVER_SEAL_ROOT", None), ("DEV_INSECURE", Some("1"))], || {
            let root = resolve_seal_root(false).unwrap();
            assert_ne!(root, [0x5Eu8; 32], "dev root must not be the old fail-open constant");
        });
    }

    #[test]
    fn dev_insecure_refused_in_prod() {
        with_env(&[("PROVER_SEAL_ROOT", None), ("DEV_INSECURE", Some("1"))], || {
            assert!(matches!(resolve_seal_root(true), Err(SealRootError::DevInsecureInProd)));
        });
    }

    #[test]
    fn bad_hex_errors() {
        with_env(&[("PROVER_SEAL_ROOT", Some("zz")), ("DEV_INSECURE", None)], || {
            assert!(matches!(resolve_seal_root(true), Err(SealRootError::BadHex)));
        });
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p prover seal_root`
Expected: FAIL — `resolve_seal_root` / `SealRootError` undefined.

- [ ] **Step 3: Implement `resolve_seal_root`**

Top of `crates/prover/src/seal_root.rs`:
```rust
//! Fail-closed seal-root resolution (SEC-020). There is NO public default: an
//! unset root refuses to start rather than sealing under a repo-public constant.
//! An explicit `DEV_INSECURE=1` dev root is allowed only in non-prod builds and
//! is loudly logged by the caller.

/// A distinct, clearly-named dev root — NOT the old fail-open `[0x5E; 32]`.
const DEV_INSECURE_SEAL_ROOT: [u8; 32] = *b"DEV-INSECURE-seal-root-NOTPROD!!";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealRootError {
    /// No `PROVER_SEAL_ROOT` and not `DEV_INSECURE` — refuse to start (fail-closed).
    Unset,
    /// `PROVER_SEAL_ROOT` was set but not 32-byte hex.
    BadHex,
    /// `DEV_INSECURE=1` while `prod` — the insecure escape is prod-forbidden.
    DevInsecureInProd,
}

impl std::fmt::Display for SealRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SealRootError::Unset => "PROVER_SEAL_ROOT unset and DEV_INSECURE not enabled — refusing to seal under a public default (SEC-020)",
            SealRootError::BadHex => "PROVER_SEAL_ROOT is not 32-byte hex",
            SealRootError::DevInsecureInProd => "DEV_INSECURE is forbidden when PROD=1",
        };
        f.write_str(s)
    }
}
impl std::error::Error for SealRootError {}

/// Resolve the secret seal root, fail-closed. `prod` is the caller's production flag.
pub fn resolve_seal_root(prod: bool) -> Result<[u8; 32], SealRootError> {
    if let Ok(hex) = std::env::var("PROVER_SEAL_ROOT") {
        let bytes = hex::decode(hex.trim_start_matches("0x")).map_err(|_| SealRootError::BadHex)?;
        if bytes.len() != 32 {
            return Err(SealRootError::BadHex);
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        return Ok(root);
    }
    if std::env::var("DEV_INSECURE").as_deref() == Ok("1") {
        if prod {
            return Err(SealRootError::DevInsecureInProd);
        }
        return Ok(DEV_INSECURE_SEAL_ROOT);
    }
    Err(SealRootError::Unset)
}
```
Add to `crates/prover/src/lib.rs` (near the other `mod`/`pub use`):
```rust
mod seal_root;
pub use seal_root::{resolve_seal_root, SealRootError};
```
Confirm `hex` is a dependency of `crates/prover` (it is used by prover-service; if not present in `crates/prover/Cargo.toml`, add `hex = "0.4"` under `[dependencies]`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p prover seal_root`
Expected: PASS (5 tests).

- [ ] **Step 5: Wire the prover-service to the fail-closed root**

In `crates/prover-service/src/main.rs`: delete `fn seal_root() -> [u8;32] { ... }` (lines ~19-28). In `main`, replace the `SoftwareSealProvider::new(seal_root(), m)` construction with:
```rust
    let prod = std::env::var("PROD").as_deref() != Ok("0"); // released binary defaults prod
    let root = match prover::resolve_seal_root(prod) {
        Ok(r) => r,
        Err(e) => { eprintln!("prover-service: {e}"); std::process::exit(1); }
    };
    if !prod || std::env::var("DEV_INSECURE").as_deref() == Ok("1") {
        eprintln!("WARN prover-service: DEV_INSECURE seal root in use — NEVER production");
    }
    let app = Arc::new(App {
        prover: AttestedProver::new(backend, SoftwareSealProvider::new(root, m)),
        vkey: program_vkey,
        measurement: m,
    });
```
(The `SoftwareSealProvider` stays for now; Task 6 swaps it for `AttestedSealProvider`.)

- [ ] **Step 6: Wire the gateway seal-root read**

Grep the gateway for the fail-open default: `rg -n "0x5E|PROVER_SEAL_ROOT|seal_root" crates/gateway/src/main.rs`. Replace its `[0x5E;32]`-defaulting read with `prover::resolve_seal_root(self.prod)?` (map the error into the gateway's existing settle-path error type; if the seal-root is read at startup, refuse to boot the window-settle path when it errors — mirror the existing "`PROVER_URL` set but no prover" refusal). Keep the same variable feeding `SealedWitness::seal`.

- [ ] **Step 7: Build, fmt, clippy, full test, commit**

Run: `cargo fmt && cargo clippy -p prover -p prover-service -p gateway --all-targets && cargo test -p prover -p prover-service -p gateway`
Expected: clean + green.
```bash
git add crates/prover/src/seal_root.rs crates/prover/src/lib.rs crates/prover/Cargo.toml crates/prover-service/src/main.rs crates/gateway/src/main.rs
git commit -m "fix(prover): SEC-020 fail-closed seal root — no public [0x5E] default, DEV_INSECURE prod-refused"
```

---

### Task 2: `Attestor` trait + `AzureTdxAttestor`

**Files:**
- Modify: `crates/attestation/src/lib.rs` (add `Attestor` trait, `AttestError`, `AzureTdxAttestor`, `pub use`)
- Test: `crates/attestation/src/lib.rs` (`#[cfg(test)]`, reuse the real captured quote fixtures the crate already tests `verify_tdx_quote` with)

**Interfaces:**
- Consumes: existing `verify_tdx_quote(...) -> Result<VerifiedAttestation, AttestationError>` (open `crates/attestation/src/lib.rs:86` and match its real signature), `VerifiedAttestation::enclave_measurement() -> Result<[u8;32], AttestationError>`, `TcbStatus::is_acceptable()`, `Collateral::from_json`.
- Produces:
```rust
pub type Digest = [u8; 32];
#[derive(Debug)]
pub enum AttestError { Tdx(AttestationError), CcNotEnabled, MeasurementMismatch, NonceMismatch, Backend(String) }
pub trait Attestor {
    fn quote(&self, nonce: &[u8; 32]) -> Result<Vec<u8>, AttestError>;
    fn verify(&self, quote: &[u8], expected: &Digest, nonce: &[u8; 32]) -> Result<Digest, AttestError>;
}
pub struct AzureTdxAttestor { /* holds the collateral source + this host's quote source */ }
```

- [ ] **Step 1: Write the failing test**

Model on the crate's existing `verify_tdx_quote` fixture test (find it: `rg -n "verify_tdx_quote|include_bytes|fixtures" crates/attestation/src`). Reuse the SAME captured quote + collateral bytes. The `report_data` in the fixture pins the measurement + must encode the nonce (the crate's §5c self-attest already binds `report_data = SHA-256(runtime_data)`; the nonce rides in `runtime_data`). Test:
```rust
#[test]
fn azure_verify_accepts_fixture_with_pinned_measurement() {
    let (quote, collateral_json, nonce, expected_measurement) = tdx_fixture(); // reuse the crate's fixture loader
    let att = AzureTdxAttestor::from_collateral_json(&collateral_json).unwrap();
    let m = att.verify(&quote, &expected_measurement, &nonce).unwrap();
    assert_eq!(m, expected_measurement);
}

#[test]
fn azure_verify_rejects_wrong_measurement() {
    let (quote, collateral_json, nonce, _m) = tdx_fixture();
    let att = AzureTdxAttestor::from_collateral_json(&collateral_json).unwrap();
    assert!(matches!(att.verify(&quote, &[0u8; 32], &nonce), Err(AttestError::MeasurementMismatch)));
}
```
(If the fixture's captured `report_data` does not include a nonce, add a `nonce_from_report_data` helper that extracts the crate's existing freshness field, and pass that value as `nonce` in the test — do NOT invent a new binding; reuse whatever the §5c self-attest already put there.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p attestation azure_verify`
Expected: FAIL — `AzureTdxAttestor`/`Attestor` undefined.

- [ ] **Step 3: Implement the trait + `AzureTdxAttestor`**

Add the trait/enum above. `AzureTdxAttestor::verify` = call `verify_tdx_quote` (wrap its `AttestationError` in `AttestError::Tdx`), check `tcb_status.is_acceptable()`, derive the measurement via `enclave_measurement()`, compare to `expected` (→ `MeasurementMismatch`), verify the nonce is bound in `report_data` (→ `NonceMismatch`), return the measurement. `quote()` = read this host's live TD+vTPM quote — reuse the exact code path the §5c boot self-attest uses (find it: `rg -n "quote|report_data|attest" crates/gateway/src crates/attestation/src scripts/tee-capture`); if that path is a script, `quote()` may shell out to it or read the pre-captured `ATTESTATION_DIR` artifacts.

- [ ] **Step 4: Run to verify it passes + full crate suite**

Run: `cargo test -p attestation`
Expected: PASS (new + existing).

- [ ] **Step 5: fmt/clippy, commit**

Run: `cargo fmt && cargo clippy -p attestation --all-targets`
```bash
git add crates/attestation/src/lib.rs
git commit -m "feat(attestation): SEC-020 Attestor trait + AzureTdxAttestor (self-quote + peer verify, measurement+nonce bound)"
```

---

### Task 3: `NvidiaCcAttestor` (fail-closed until CC)

**Files:**
- Create: `crates/attestation/src/nvidia_cc.rs`
- Modify: `crates/attestation/src/lib.rs` (`mod nvidia_cc; pub use`)
- Modify: `crates/attestation/Cargo.toml` (no new deps — uses `std::process::Command` + `serde_json`)
- Test: `crates/attestation/src/nvidia_cc.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces: `pub struct NvidiaCcAttestor { verifier_cmd: Vec<String>, cc_state: fn() -> bool }` implementing `Attestor`; a seam `fn cc_enabled(&self) -> bool` (injectable in tests).
- Consumes: `Attestor`, `AttestError` from Task 2.

- [ ] **Step 1: Write the failing test (CC-off is fail-closed)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Attestor, AttestError};

    #[test]
    fn quote_fails_closed_when_cc_disabled() {
        let att = NvidiaCcAttestor::with_cc_state(false); // inject: is_cc_enabled == false (today's GB10)
        assert!(matches!(att.quote(&[0u8; 32]), Err(AttestError::CcNotEnabled)));
        assert!(matches!(att.verify(&[], &[0u8; 32], &[0u8; 32]), Err(AttestError::CcNotEnabled)));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p attestation nvidia_cc`
Expected: FAIL — `NvidiaCcAttestor` undefined.

- [ ] **Step 3: Implement (fail-closed gate first, real collection stubbed for Phase 2)**

```rust
//! NVIDIA GB10 (Grace-Blackwell) CC attestor over `nv-local-gpu-verifier`.
//! Phase 1: the ONLY guarantee is fail-closed — `quote`/`verify` return
//! `CcNotEnabled` unless the local verifier reports CC on. When Phase 2 enables
//! GB10 CC mode, `collect_evidence`/`verify_evidence` fill in; the trait is stable.
use crate::{AttestError, Attestor, Digest};

pub struct NvidiaCcAttestor {
    cc_enabled: bool,
    // Phase 2: venv verifier path, e.g. ~/nvattest-venv/bin/python -m verifier.cc_admin
}
impl NvidiaCcAttestor {
    /// Detect CC state by invoking the local verifier once at construction.
    pub fn detect() -> Self { Self { cc_enabled: probe_cc_enabled() } }
    #[cfg(test)]
    pub fn with_cc_state(cc_enabled: bool) -> Self { Self { cc_enabled } }
}
impl Attestor for NvidiaCcAttestor {
    fn quote(&self, _nonce: &[u8; 32]) -> Result<Vec<u8>, AttestError> {
        if !self.cc_enabled { return Err(AttestError::CcNotEnabled); }
        // Phase 2: `nv-local-gpu-verifier` collect_gpu_evidence(nonce) → serialized evidence.
        Err(AttestError::Backend("NVIDIA CC evidence collection is Phase 2".into()))
    }
    fn verify(&self, _quote: &[u8], _expected: &Digest, _nonce: &[u8; 32]) -> Result<Digest, AttestError> {
        if !self.cc_enabled { return Err(AttestError::CcNotEnabled); }
        Err(AttestError::Backend("NVIDIA CC evidence verification is Phase 2".into()))
    }
}
/// Probe CC state without requiring CC: the verifier prints "confidential compute is False"
/// and exits non-zero when CC is off. Absence of the tool ⇒ treat as CC-off (fail-closed).
fn probe_cc_enabled() -> bool {
    // Non-fatal, best-effort; any error ⇒ false (fail-closed).
    false // Phase 2 replaces with a real `python -m verifier.cc_admin` probe.
}
```
(Phase 1 deliberately keeps `probe_cc_enabled` returning `false`: today CC is off and the design REQUIRES fail-closed. Phase 2's task — separate — replaces `probe_cc_enabled`, `quote`, and `verify` with real `nv-local-gpu-verifier` calls once CC mode is enabled. The point of this task is the stable trait boundary + the enforced fail-closed default.)

- [ ] **Step 4: Run to verify it passes + crate suite**

Run: `cargo test -p attestation`
Expected: PASS.

- [ ] **Step 5: fmt/clippy, commit**
```bash
git add crates/attestation/src/nvidia_cc.rs crates/attestation/src/lib.rs
git commit -m "feat(attestation): SEC-020 NvidiaCcAttestor — fail-closed until GB10 CC enabled (Phase-2 drop-in)"
```

---

### Task 4: Mutual-attestation handshake + `/attest` endpoints

**Files:**
- Create: `crates/attestation/src/handshake.rs` (transcript → session secret/token; pure, testable)
- Modify: `crates/attestation/src/lib.rs` (`mod handshake; pub use`)
- Modify: `crates/prover-service/src/main.rs` (add `GET /attest?nonce=`, run handshake at boot; hold `session_token`)
- Modify: `crates/gateway/src/main.rs` (add `GET /attest`, run handshake to the prover at settle-path init)
- Test: `crates/attestation/src/handshake.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces:
```rust
/// Deterministic session secret from a completed mutual-attestation transcript.
pub fn session_secret(gw_nonce: &[u8;32], pv_nonce: &[u8;32], gw_meas: &Digest, pv_meas: &Digest) -> Digest;
/// Short-lived bearer token the prover checks on /prove (hash of the secret + a validity epoch).
pub fn session_token(secret: &Digest, epoch: u64) -> String;
```
- Consumes: `Attestor` (Tasks 2-3), `perp_core::hash::{Keccak256, Domain}`.

- [ ] **Step 1: Write the failing test (determinism + binding)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_is_deterministic_and_transcript_bound() {
        let (a, b, m1, m2) = ([1u8;32],[2u8;32],[3u8;32],[4u8;32]);
        assert_eq!(session_secret(&a,&b,&m1,&m2), session_secret(&a,&b,&m1,&m2));
        assert_ne!(session_secret(&a,&b,&m1,&m2), session_secret(&b,&a,&m1,&m2)); // order-bound
        assert_ne!(session_token(&session_secret(&a,&b,&m1,&m2), 1),
                   session_token(&session_secret(&a,&b,&m1,&m2), 2)); // epoch-bound
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p attestation handshake`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement the pure handshake math**

```rust
use crate::Digest;
use perp_core::hash::{Domain, Keccak256};
pub fn session_secret(gw_nonce: &[u8;32], pv_nonce: &[u8;32], gw_meas: &Digest, pv_meas: &Digest) -> Digest {
    Keccak256::hash_words(Domain::KeyDerivation, &[*gw_nonce, *pv_nonce, *gw_meas, *pv_meas])
}
pub fn session_token(secret: &Digest, epoch: u64) -> String {
    let d = Keccak256::hash_words(Domain::KeyDerivation, &[*secret, perp_core::hash::word_u64(epoch)]);
    format!("0x{}", hex::encode(d))
}
```
(Add `Domain::KeyDerivation` reuse — it already exists per `SoftwareSealProvider`. Confirm `hex` + `perp_core` are deps of `crates/attestation`.)

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p attestation handshake`
Expected: PASS.

- [ ] **Step 5: Wire the `/attest` endpoints + boot handshake**

Prover-service: add `GET /attest` returning `{ quote: hx(self_quote(nonce)) }` where `self_quote` uses the prover's `NvidiaCcAttestor::quote(nonce)` (fail-closed → `503` today unless `DEV_INSECURE`). At boot, before serving, the prover fetches the gateway's `/attest`, verifies it with `AzureTdxAttestor::verify(quote, GATEWAY_EXPECTED_MEASUREMENT, nonce)`, computes `session_secret`/`session_token`, stores the token in `App`. Gateway: symmetric — add `GET /attest` (its own `AzureTdxAttestor::quote`), and at settle-path init fetch the prover's `/attest`, verify with `NvidiaCcAttestor::verify(quote, PROVER_EXPECTED_MEASUREMENT, nonce)`, store the token for `/prove` calls. In `DEV_INSECURE` (non-prod) both sides skip verification with a `WARN` and use a fixed dev token. Read `GATEWAY_EXPECTED_MEASUREMENT` / `PROVER_EXPECTED_MEASUREMENT` from env (required unless `DEV_INSECURE`).

- [ ] **Step 6: Build, fmt, clippy, commit**

Run: `cargo fmt && cargo clippy --workspace --all-targets && cargo test --workspace`
```bash
git add crates/attestation/src/handshake.rs crates/attestation/src/lib.rs crates/prover-service/src/main.rs crates/gateway/src/main.rs
git commit -m "feat(sec-020): mutual-attestation handshake + /attest endpoints; session token minted from transcript"
```

---

### Task 5: `/prove` session-token gate

**Files:**
- Modify: `crates/prover-service/src/main.rs` (`prove` handler + `App` holds the expected token)
- Modify: `crates/gateway/src/main.rs` (`HttpProverClient` sends `Authorization: Bearer <token>`)
- Test: `crates/prover-service/src/main.rs` (`#[cfg(test)]` axum handler test)

**Interfaces:**
- Consumes: `session_token` (Task 4), `App.session_token: String`.
- Produces: `/prove` returns `401` without a valid `Authorization` bearer matching `App.session_token`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod prove_gate {
    // Build an App with a known session token, call `prove` with and without the header.
    // Use axum's `oneshot` (tower::ServiceExt) against the real router; reuse any existing
    // handler test in this file as the construction template.
    #[tokio::test]
    async fn prove_without_bearer_is_401() { /* assert StatusCode::UNAUTHORIZED */ }
    #[tokio::test]
    async fn prove_with_valid_bearer_reaches_handler() { /* not 401 (400/422 on the dummy body is fine) */ }
}
```
(Fill the bodies using the file's existing test/setup helpers; if none exist, construct `App` with a stub `AttestedProver` — reuse `CommitmentProver` from `crates/prover` as the `Prover` impl to avoid the heavy SP1 backend in a unit test.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p prover-service prove_gate`
Expected: FAIL — no auth check yet.

- [ ] **Step 3: Implement the gate**

In `prove`, take `headers: axum::http::HeaderMap` as the first extractor and, before decoding the body:
```rust
    let ok = headers.get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|t| t == app.session_token)
        .unwrap_or(false);
    if !ok { return Err((StatusCode::UNAUTHORIZED, "attestation session required".into())); }
```

- [ ] **Step 4: Gateway sends the token**

In `HttpProverClient` (grep `crates/gateway/src` for the `POST /prove` call), add the `Authorization: Bearer <session_token>` header from the handshake (Task 4). On a `401`, re-run the handshake once and retry (mirror the existing transient-retry pattern).

- [ ] **Step 5: Run + full suite**

Run: `cargo test -p prover-service && cargo test --workspace`
Expected: PASS.

- [ ] **Step 6: fmt/clippy, commit**
```bash
git add crates/prover-service/src/main.rs crates/gateway/src/main.rs
git commit -m "fix(prover-service): SEC-020 gate /prove behind the attestation session token (401 otherwise)"
```

---

### Task 6: `AttestedSealProvider` + prod provider selection

**Files:**
- Modify: `crates/prover/src/lib.rs` (add `AttestedSealProvider`)
- Modify: `crates/prover-service/src/main.rs` (select provider: `AttestedSealProvider` when attested, `SoftwareSealProvider` only under `DEV_INSECURE`)
- Modify: `crates/gateway/src/main.rs` (seal with the session-derived root, matching the prover)
- Test: `crates/prover/src/lib.rs` (seal round-trip under `AttestedSealProvider`)

**Interfaces:**
- Produces: `pub struct AttestedSealProvider { session_secret: [u8;32], measurement: Digest }` impl `SealKeyProvider`; key = `Keccak256::hash_words(Domain::KeyDerivation, [session_secret, measurement, nonce])`, `None` on measurement mismatch.
- Consumes: `SealKeyProvider`, `SealedWitness::{seal,open}`, `session_secret` (Task 4).

- [ ] **Step 1: Write the failing round-trip test**

```rust
#[test]
fn attested_seal_roundtrip_binds_measurement_and_secret() {
    let (secret, m, nonce) = ([9u8;32], [7u8;32], [3u8;32]);
    let gw = AttestedSealProvider { session_secret: secret, measurement: m };
    let pv = AttestedSealProvider { session_secret: secret, measurement: m };
    let sealed = SealedWitness::seal(b"positions+fills", &m, &nonce, &gw).expect("seal");
    assert_eq!(sealed.open(&pv).expect("open"), b"positions+fills");
    // wrong secret ⇒ SealAuthFailed
    let bad = AttestedSealProvider { session_secret: [0u8;32], measurement: m };
    assert!(matches!(sealed.open(&bad), Err(ProverError::SealAuthFailed)));
    // wrong measurement ⇒ no key ⇒ open fails
    let wrong_m = AttestedSealProvider { session_secret: secret, measurement: [1u8;32] };
    assert!(sealed.open(&wrong_m).is_err());
}
```
(Match `SealedWitness::seal`/`open`'s real signatures — open `crates/prover/src/lib.rs` around `impl SealedWitness`.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p prover attested_seal`
Expected: FAIL — `AttestedSealProvider` undefined.

- [ ] **Step 3: Implement `AttestedSealProvider`**

```rust
/// Phase-1 attested provider: the seal key rests on the mutual-attestation session
/// secret (not a public constant) + the attested prover measurement. Phase 2 swaps
/// `session_secret` for a real CC-measurement-bound key release — same trait, same
/// derivation shape.
pub struct AttestedSealProvider { pub session_secret: [u8; 32], pub measurement: Digest }
impl SealKeyProvider for AttestedSealProvider {
    fn seal_key(&self, measurement: &Digest, nonce: &Digest) -> Option<[u8; 32]> {
        if *measurement != self.measurement { return None; }
        Some(Keccak256::hash_words(Domain::KeyDerivation, &[self.session_secret, *measurement, *nonce]))
    }
}
```

- [ ] **Step 4: Run + select the provider at runtime**

Run: `cargo test -p prover attested_seal` → PASS.
In prover-service `main`: after the handshake (Task 4) yields `session_secret`, build the provider fail-closed:
```rust
    let provider: Box<dyn SealKeyProvider + Send + Sync> = if attested {
        Box::new(AttestedSealProvider { session_secret, measurement: m })
    } else if !prod && dev_insecure {
        eprintln!("WARN prover-service: SoftwareSealProvider (DEV_INSECURE)");
        Box::new(SoftwareSealProvider::new(root, m))
    } else {
        eprintln!("prover-service: no attested session and not DEV_INSECURE — refusing"); std::process::exit(1);
    };
```
(This requires `AttestedProver` to accept a boxed provider, OR generic `P: SealKeyProvider`. If it is generic today, add a `BoxProvider` newtype impl or make `AttestedProver` take `Box<dyn SealKeyProvider + Send + Sync>` — match its current definition in `crates/prover/src/lib.rs` and choose the smallest change.) The gateway seals with the same `session_secret`-derived key via a mirrored `AttestedSealProvider`.

- [ ] **Step 5: Full workspace suite + fmt/clippy + commit**

Run: `cargo fmt && cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: clean + green.
```bash
git add crates/prover/src/lib.rs crates/prover-service/src/main.rs crates/gateway/src/main.rs
git commit -m "feat(sec-020): AttestedSealProvider — seal key bound to attestation session + measurement (SoftwareSealProvider dev-only)"
```

---

## Self-Review

**Spec coverage:**
- Fail-closed seal root (§1) → Task 1. ✓
- `Attestor` trait + `AzureTdxAttestor` (§2) → Task 2. ✓
- `NvidiaCcAttestor` fail-closed until CC (§2) → Task 3. ✓
- Mutual-attestation handshake + `/attest` (§3) → Task 4. ✓
- `/prove` session-token gate (§4) → Task 5. ✓
- `AttestedSealProvider` + prod provider selection + `DEV_INSECURE` (§5, behavior matrix) → Tasks 1 (seal-root dev-gate) + 6. ✓
- Deferred Phase 2 (real CC) → out of scope, stable boundaries confirmed in Tasks 3 & 6. ✓

**Placeholder scan:** the honest hedges are all "open file X and match the real signature" implementer instructions (verify_tdx_quote params, SealedWitness seal/open, HttpProverClient, AttestedProver's provider generic, the crate's fixture loader / §5c self-quote path) — real existing symbols the implementer must read, not invented content. Task 3's `probe_cc_enabled`/`quote`/`verify` are intentionally stubbed fail-closed (Phase-1 requirement, Phase-2 fills in) — documented as such, not a gap.

**Type consistency:** `Digest = [u8;32]`, `AttestError` (with `CcNotEnabled`), `Attestor::{quote,verify}`, `session_secret`/`session_token`, `AttestedSealProvider { session_secret, measurement }`, `resolve_seal_root(prod) -> Result<_, SealRootError>` used consistently across tasks.

## Post-implementation verification

- `cargo test --workspace` green (new SEC-020 tests + pre-existing).
- `cargo fmt --check` + `cargo clippy --workspace --all-targets` clean.
- Manual: start prover-service with no `PROVER_SEAL_ROOT` and `PROD=1` → exits 1 with the SEC-020 message. `curl -XPOST /prove` without a bearer → `401`.
- Grep confirms no remaining `[0x5E` seal-root default in `crates/prover-service` or `crates/gateway`.
- Request an independent review of the branch.
- Phase 2 (separate plan, after GB10 CC enabled): implement `probe_cc_enabled`/`quote`/`verify` in `nvidia_cc.rs` + swap `AttestedSealProvider`'s secret source for real CC key-release.
```
