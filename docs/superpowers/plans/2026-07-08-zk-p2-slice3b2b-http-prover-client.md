# ZK P2 Slice 3b-2b — HttpProverClient + Real Groth16 Proof — Implementation Plan


**Goal:** Implement the `HttpProverClient` (curl subprocess) so `PROVER_URL=<url>` runs the gateway's
window-settle path against the real attested prover-service, plus the two 3b-2a review carry-forwards.

**Architecture:** `HttpProverClient` seals the `WindowWitness` with the `SoftwareSealProvider` stand-in the
service opens with, `curl`-POSTs the sealed hex to `/prove`, and parses the JSON response into a
`ProveOutcome` (validated downstream by the existing `prove_and_prepare`). The two pure steps (`seal_witness`,
`parse_prove_resp`) are unit-tested; the curl POST is external glue validated on the GB10. Carry-forwards:
(A) the new path prunes vault-claimed withdrawals like the legacy path; (B) the negative test is split to
cover both `prove_and_prepare` guard branches.

**Tech Stack:** Rust (gateway crate + the workspace `prover` crate for `SealedWitness`/`SoftwareSealProvider`),
`postcard` (witness/sealed encoding), `serde_json` (response parse), `curl` subprocess (mirrors `L1::cast`).

## Global Constraints

- **Add `prover = { path = "../prover" }` to `crates/gateway/Cargo.toml` `[dependencies]`** — a normal dep
  (seal happens in production code), workspace-internal, no `sp1-sdk`.
- **Seal params MUST match the prover-service:** seal root default `[0x5E; 32]` (env `PROVER_SEAL_ROOT`, a
  64-hex override parsed by `parse_hex32`); measurement `[0xAB; 32]`.
- **Nonce = the window `batch_id`** big-endian in the low 8 bytes of a `[u8; 32]` (unique per window →
  no keystream reuse; deterministic → testable).
- **Response parse uses the gateway's own hex helpers** — `parse_hex32` (six roots + commitment, 32 bytes
  each) and `decode_hex` (variable-length `proof`). The gateway has NO `hex` crate.
- **`curl` invocation:** `curl -s -S --fail --max-time <timeout> -X POST -H 'Content-Type: application/json'
  --data-binary @- <url>/prove`, body written to stdin from a spawned thread (avoid a large-body pipe
  deadlock). Timeout env `PROVER_TIMEOUT_SECS`, default `900` (a real Groth16 proof under qemu takes minutes).
- **Legacy path (`PROVER_URL` unset) stays byte-unchanged.**
- **`prove_and_prepare` runs the commitment cross-check BEFORE the withdrawals-root byte-match** — the (B)
  test split targets each branch with a distinct tampered client.
- Touch ONLY `crates/gateway/` (`prover_client.rs`, `main.rs`, `Cargo.toml`). NO perp-core / sequencer /
  contract / prover-crate change.
- Tests inline in `main.rs` `#[cfg(test)] mod tests`. Run single-filter: `cargo test -p gateway <name>`.

---

## Reference: exact current shapes (verbatim)

**`prover_client.rs`** (Slice 3b-2a): `use crate::withdrawals::Withdrawal; use
perp_core::commitment::{derive_roots, DerivedRoots}; use perp_core::merkle::{merkle_proof, merkle_root}; use
perp_core::{Digest, EngineError, Keccak256}; use sequencer::WindowWitness; use std::collections::BTreeMap;`.
`ProverClientError` today = `enum { Derive(EngineError) }` (+ a `// Slice 3b-2b adds:` comment).
`prove_and_prepare(client: &dyn ProverClient, witness: &WindowWitness, ww: &[Withdrawal]) -> Result<PreparedSettle, String>`
checks in order: prove → **commitment cross-check** (`DerivedRoots{..outcome's 6 roots}.commitment::<Keccak256>() != outcome.commitment` → `Err("commitment mismatch: ...")`) → **withdrawals byte-match**
(`merkle_root(ww leaves) != outcome.withdrawals_root` → `Err("withdrawals root mismatch: ...")`) → per-note
proofs. `ProveOutcome` fields: `prev_root, manifest_hash, new_root, ordered_root, withdrawals_root,
rejected_root, commitment: Digest, proof: Vec<u8>`.

**`prover` crate** (`crates/prover`, crate name `prover`; all at crate root): `pub struct SealedWitness`
(private fields, derives `serde::{Serialize,Deserialize}, Clone, Debug`; accessors `pub fn measurement(&self)
-> Digest`, `pub fn nonce(&self) -> Digest`, `pub fn ciphertext_len(&self) -> usize`);
`SealedWitness::seal(plaintext: &[u8], provider: &dyn SealKeyProvider, measurement: Digest, nonce: Digest)
-> Option<Self>`; `SoftwareSealProvider::new(root: [u8;32], measurement: Digest) -> Self`; `pub trait
SealKeyProvider`. The prover-service seals via `use prover::{AttestedProver, SealedWitness,
SoftwareSealProvider};` and decodes the tuple `(DefaultState, Vec<BatchOp>, BatchManifest)`.

**prover-service** (`crates/prover-service/src/main.rs`): `POST /prove` with `ProveReq { sealed: String }`
(hex postcard `SealedWitness`); `ProveResp { prev_root, manifest_hash, new_root, ordered_root,
withdrawals_root, rejected_root, commitment, proof }` — all `String`, each `0x`+lowercase hex (roots/commitment
32 bytes, proof variable).

**`main.rs` helpers:** `fn hex32(d: &Digest) -> String` (`:49`); `fn decode_hex(s: &str) -> Option<Vec<u8>>`
(`:929`, strips `0x`, byte-based, `None` on odd/nonhex); `fn parse_hex32(s: &str) -> Option<[u8;32]>` (`:3136`).
`prover_from_str(v: Option<&str>) -> Result<Option<Arc<dyn prover_client::ProverClient>>, String>` (`:4088`):
`None|Some("")→Ok(None)`, `Some("mock")→Ok(Some(Arc::new(MockProverClient)))`, `Some(url)→Err("...3b-2b...")`.
`App.prover: Option<Arc<dyn prover_client::ProverClient>>` (`:3050`). `Gw` fields `pending_withdrawals:
Vec<Withdrawal>` (`:618`), `withdraw_proofs: BTreeMap<[u8;32],(Digest,Vec<[u8;32]>)>` (`:625`). `Withdrawal`
(`withdrawals.rs:29`) `{owner:[u8;32], to:[u8;20], amount:u128, nonce:u64}`, `fn leaf(&self)->[u8;32]`.
New-path async branch (`main.rs:4658-4740`): section (A) bond+batch_count in spawn_blocking, (B) seal under
lock, (C) `prove_and_prepare`+`settle_proved`+bond in spawn_blocking → `commit_window_settle` under lock.
Legacy claimed-prune model: `for w in withdrawals { if l1c.claimed(&hex32(&leaf)).unwrap_or(false) {...} }`
then `pending_withdrawals.retain(|w| !cset.contains(&w.leaf()))`.

Test pattern for a `WindowWitness`: `let mut gw = Gw::boot(); gw.register_account(None); gw.account_deposit(&key, 0, 40_000*QUOTE_SCALE)?; gw.account_withdraw(&key, 0, 5_000*QUOTE_SCALE, [7u8;20])?; let bc =
gw.seq.state.next_batch_id; let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");`.

---

## Task 1: `prover` dep + `ProverClientError` variants + `seal_witness`

**Files:**
- Modify: `crates/gateway/Cargo.toml` (add the `prover` dep), `crates/gateway/src/prover_client.rs`
  (`ProverClientError` variants + `seal_witness`), `crates/gateway/src/main.rs` (round-trip test).

**Interfaces:**
- Consumes: `prover::{SealedWitness, SoftwareSealProvider}`, `sequencer::WindowWitness`, `postcard`.
- Produces: `ProverClientError::{Seal, Http(String), Decode(String)}` (added alongside `Derive`);
  `prover_client::seal_witness(w: &WindowWitness, root: &[u8;32], measurement: &Digest) -> Result<String, ProverClientError>`.

- [ ] **Step 1: Add the `prover` dependency**

In `crates/gateway/Cargo.toml`, in `[dependencies]` (next to `sequencer = { path = "../sequencer" }`), add:
```toml
# Slice 3b-2b: SealedWitness + SoftwareSealProvider to seal the window witness for the
# prover-service. Workspace-internal — does NOT pull in sp1-sdk (that's prover-service only).
prover = { path = "../prover" }
```

- [ ] **Step 2: Add the new error variants**

In `crates/gateway/src/prover_client.rs`, replace the `ProverClientError` enum:
```rust
#[derive(Debug)]
pub enum ProverClientError {
    /// The window witness failed to replay (should not happen for a live-sealed window).
    Derive(EngineError),
    /// Sealing refused (provider returned None for the measurement/nonce).
    Seal,
    /// Transport failure talking to the prover-service (curl error / non-2xx / timeout).
    Http(String),
    /// Malformed prover-service response (bad JSON, missing field, or bad hex).
    Decode(String),
}
```
(The `prove_and_prepare` `map_err` currently matches only `ProverClientError::Derive` exhaustively — after
adding variants it will not compile until you make that match non-exhaustive. Update it: in `prove_and_prepare`,
change the `.map_err(|e| match e { ProverClientError::Derive(err) => format!(...) })?` to a catch-all
`.map_err(|e| format!("prove: {e:?}"))?`. This keeps the Derive message informative via `{e:?}` and handles
the new variants a real client can return.)

- [ ] **Step 3: Write the failing test** (in `main.rs` `#[cfg(test)] mod tests`)

```rust
    #[test]
    fn seal_witness_is_well_formed_and_addressed() {
        use crate::prover_client::seal_witness;
        use prover::SealedWitness;

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, _ww) = gw.begin_window_settle(bc).unwrap().expect("some");

        let root = [0x5Eu8; 32];
        let measurement = [0xABu8; 32];
        let hexed = seal_witness(&witness, &root, &measurement).expect("seal");
        assert!(hexed.starts_with("0x"));

        // it must postcard-decode back into a SealedWitness addressed to the right
        // measurement, with the batch_id-derived nonce and the full plaintext length.
        let raw = decode_hex(&hexed).expect("hex");
        let sealed: SealedWitness = postcard::from_bytes(&raw).expect("decode sealed");
        assert_eq!(sealed.measurement(), measurement);
        let mut expect_nonce = [0u8; 32];
        expect_nonce[24..].copy_from_slice(&witness.batch_id.to_be_bytes());
        assert_eq!(sealed.nonce(), expect_nonce);
        let plaintext =
            postcard::to_allocvec(&(&witness.pre_state, &witness.ops, &witness.manifest)).unwrap();
        assert_eq!(sealed.ciphertext_len(), plaintext.len());
    }
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test -p gateway seal_witness_is_well_formed_and_addressed`
Expected: compile error (`seal_witness` / `prover` absent) until Steps 1-2 + Step 5 land.

- [ ] **Step 5: Implement `seal_witness`**

Append to `crates/gateway/src/prover_client.rs`:
```rust
/// Seal a window witness exactly as the prover-service's seal-client does, so the service
/// (same SoftwareSealProvider params) can open it. Plaintext is the postcard-encoded
/// `(pre_state, ops, manifest)` triple; the nonce is derived from the window batch_id
/// (unique per window). Returns 0x-prefixed hex of the postcard-encoded SealedWitness.
pub fn seal_witness(
    w: &WindowWitness,
    root: &[u8; 32],
    measurement: &Digest,
) -> Result<String, ProverClientError> {
    let bytes = postcard::to_allocvec(&(&w.pre_state, &w.ops, &w.manifest))
        .map_err(|e| ProverClientError::Decode(format!("witness encode: {e}")))?;
    let mut nonce = [0u8; 32];
    nonce[24..].copy_from_slice(&w.batch_id.to_be_bytes());
    let provider = prover::SoftwareSealProvider::new(*root, *measurement);
    let sealed = prover::SealedWitness::seal(&bytes, &provider, *measurement, nonce)
        .ok_or(ProverClientError::Seal)?;
    let out = postcard::to_allocvec(&sealed)
        .map_err(|e| ProverClientError::Decode(format!("sealed encode: {e}")))?;
    let mut hexed = String::with_capacity(2 + out.len() * 2);
    hexed.push_str("0x");
    for b in &out {
        hexed.push_str(&format!("{b:02x}"));
    }
    Ok(hexed)
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p gateway seal_witness_is_well_formed_and_addressed` → PASS. Then `cargo test -p gateway`
(full) → all pass; `cargo clippy -p gateway` → clean.

- [ ] **Step 7: Commit**

```bash
git add crates/gateway/Cargo.toml crates/gateway/src/prover_client.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): prover dep + ProverClientError Seal/Http/Decode + seal_witness"
```

---

## Task 2: `parse_prove_resp`

**Files:**
- Modify: `crates/gateway/src/prover_client.rs` (`parse_prove_resp`), `crates/gateway/src/main.rs` (tests).

**Interfaces:**
- Consumes: `serde_json`, `crate::parse_hex32`, `crate::decode_hex`, `ProveOutcome`, `ProverClientError`.
- Produces: `prover_client::parse_prove_resp(json: &str) -> Result<ProveOutcome, ProverClientError>`.

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn parse_prove_resp_decodes_all_fields() {
        use crate::prover_client::parse_prove_resp;
        let r32 = |b: u8| format!("0x{}", crate::hex32(&[b; 32]).trim_start_matches("0x"));
        let json = format!(
            r#"{{"prev_root":"{}","manifest_hash":"{}","new_root":"{}","ordered_root":"{}","withdrawals_root":"{}","rejected_root":"{}","commitment":"{}","proof":"0xdeadbeef"}}"#,
            r32(1), r32(2), r32(3), r32(4), r32(5), r32(6), r32(7)
        );
        let out = parse_prove_resp(&json).expect("parse");
        assert_eq!(out.prev_root, [1u8; 32]);
        assert_eq!(out.new_root, [3u8; 32]);
        assert_eq!(out.withdrawals_root, [5u8; 32]);
        assert_eq!(out.commitment, [7u8; 32]);
        assert_eq!(out.proof, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_prove_resp_rejects_malformed() {
        use crate::prover_client::parse_prove_resp;
        // not JSON
        assert!(parse_prove_resp("not json").is_err());
        // missing a field (no commitment/proof)
        assert!(parse_prove_resp(r#"{"prev_root":"0x00"}"#).is_err());
        // a root that isn't 32 bytes
        let bad = r#"{"prev_root":"0x1234","manifest_hash":"0x00","new_root":"0x00","ordered_root":"0x00","withdrawals_root":"0x00","rejected_root":"0x00","commitment":"0x00","proof":"0x00"}"#;
        assert!(parse_prove_resp(bad).is_err());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p gateway parse_prove_resp_decodes_all_fields` → compile error (`parse_prove_resp` absent).

- [ ] **Step 3: Implement `parse_prove_resp`**

Append to `crates/gateway/src/prover_client.rs`:
```rust
/// Parse the prover-service /prove JSON into a ProveOutcome. The six roots + commitment
/// are 32-byte hex (parse_hex32); the proof is variable-length hex (decode_hex). The
/// returned outcome is validated downstream by prove_and_prepare (commitment cross-check
/// + withdrawal-tree byte-match), so a tampered response is rejected before settleBatch.
pub fn parse_prove_resp(json: &str) -> Result<ProveOutcome, ProverClientError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        prev_root: String,
        manifest_hash: String,
        new_root: String,
        ordered_root: String,
        withdrawals_root: String,
        rejected_root: String,
        commitment: String,
        proof: String,
    }
    let r: Resp =
        serde_json::from_str(json).map_err(|e| ProverClientError::Decode(format!("json: {e}")))?;
    let root = |s: &str, name: &str| -> Result<Digest, ProverClientError> {
        crate::parse_hex32(s).ok_or_else(|| ProverClientError::Decode(format!("bad {name}: {s}")))
    };
    Ok(ProveOutcome {
        prev_root: root(&r.prev_root, "prev_root")?,
        manifest_hash: root(&r.manifest_hash, "manifest_hash")?,
        new_root: root(&r.new_root, "new_root")?,
        ordered_root: root(&r.ordered_root, "ordered_root")?,
        withdrawals_root: root(&r.withdrawals_root, "withdrawals_root")?,
        rejected_root: root(&r.rejected_root, "rejected_root")?,
        commitment: root(&r.commitment, "commitment")?,
        proof: crate::decode_hex(&r.proof)
            .ok_or_else(|| ProverClientError::Decode(format!("bad proof: {}", r.proof)))?,
    })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p gateway parse_prove_resp_decodes_all_fields` then
`cargo test -p gateway parse_prove_resp_rejects_malformed` → both PASS. Then `cargo test -p gateway` (full)
+ `cargo clippy -p gateway` → clean.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/prover_client.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): parse_prove_resp (prover-service JSON -> ProveOutcome)"
```

---

## Task 3: `http_post` + `HttpProverClient` + wire `prover_from_str`

**Files:**
- Modify: `crates/gateway/src/prover_client.rs` (`http_post`, `HttpProverClient`, `from_env`, its
  `ProverClient` impl), `crates/gateway/src/main.rs` (`prover_from_str` URL arm + update its test).

**Interfaces:**
- Consumes: `seal_witness`, `parse_prove_resp`, `ProverClientError`, `std::process::Command`.
- Produces: `prover_client::HttpProverClient` (`impl ProverClient`), `HttpProverClient::from_env(url: &str)
  -> Self`. `prover_from_str(Some(url))` now yields `Ok(Some(Arc::new(HttpProverClient::from_env(url))))`.

- [ ] **Step 1: Implement `http_post` + `HttpProverClient`**

Append to `crates/gateway/src/prover_client.rs`:
```rust
/// POST `body` as application/json to `<url>/prove` via curl (mirrors L1::cast: a
/// subprocess with a wall-clock cap), piping the body on stdin so a large sealed witness
/// never hits an argv limit. The stdin write runs on its own thread to avoid a pipe
/// deadlock when the body exceeds the OS pipe buffer.
fn http_post(url: &str, body: &str, timeout_secs: u64) -> Result<String, ProverClientError> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let endpoint = format!("{}/prove", url.trim_end_matches('/'));
    let mut child = Command::new("curl")
        .args([
            "-s", "-S", "--fail", "--max-time", &timeout_secs.to_string(),
            "-X", "POST", "-H", "Content-Type: application/json",
            "--data-binary", "@-", &endpoint,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ProverClientError::Http(format!("curl spawn: {e}")))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let body_owned = body.to_string();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(body_owned.as_bytes());
    });
    let out = child
        .wait_with_output()
        .map_err(|e| ProverClientError::Http(format!("curl wait: {e}")))?;
    let _ = writer.join();
    if !out.status.success() {
        return Err(ProverClientError::Http(format!(
            "curl exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The real transport: seal the window and POST it to the attested prover-service.
pub struct HttpProverClient {
    url: String,
    seal_root: [u8; 32],
    measurement: Digest,
    timeout_secs: u64,
}

impl HttpProverClient {
    /// Build from PROVER_URL, matching the prover-service's seal params: PROVER_SEAL_ROOT
    /// (64-hex, default 0x5E..) and the 0xAB.. stand-in measurement; PROVER_TIMEOUT_SECS
    /// (default 900 — a real Groth16 proof under qemu takes minutes).
    pub fn from_env(url: &str) -> Self {
        let seal_root = std::env::var("PROVER_SEAL_ROOT")
            .ok()
            .and_then(|s| crate::parse_hex32(&s))
            .unwrap_or([0x5Eu8; 32]);
        let timeout_secs = std::env::var("PROVER_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(900);
        Self { url: url.to_string(), seal_root, measurement: [0xABu8; 32], timeout_secs }
    }
}

impl ProverClient for HttpProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
        let sealed_hex = seal_witness(w, &self.seal_root, &self.measurement)?;
        let body = serde_json::json!({ "sealed": sealed_hex }).to_string();
        let resp = http_post(&self.url, &body, self.timeout_secs)?;
        parse_prove_resp(&resp)
    }
}
```

- [ ] **Step 2: Wire `prover_from_str` + update its test**

In `crates/gateway/src/main.rs`, change the URL arm of `prover_from_str` (the `Some(url) => Err(...)` arm):
```rust
        Some(url) => Ok(Some(std::sync::Arc::new(prover_client::HttpProverClient::from_env(url)))),
```
And update the existing `prover_from_str_selects_path` test's URL assertion from expecting an `Err` to
expecting `Some`:
```rust
        assert!(prover_from_str(Some("http://prover.local:8091")).unwrap().is_some());
```

- [ ] **Step 3: Run the test to verify it fails then passes**

Run: `cargo test -p gateway prover_from_str_selects_path`
Expected: FAILS first if run before Step 1-2 land the type (compile) / with the old assertion; PASSES after.
Then `cargo test -p gateway` (full) + `cargo clippy -p gateway` → clean. (`http_post`/`HttpProverClient::prove`
are external glue — not unit-tested; live-validated in the GB10 e2e.)

- [ ] **Step 4: Commit**

```bash
git add crates/gateway/src/prover_client.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): HttpProverClient (curl POST /prove) + PROVER_URL=<url> wiring"
```

---

## Task 4: Carry-forward (A) — `Gw::prune_claimed_withdrawals` + new-path pruning

**Files:**
- Modify: `crates/gateway/src/main.rs` (`Gw::prune_claimed_withdrawals` + the new-path async branch + a test).

**Interfaces:**
- Consumes: `Gw.pending_withdrawals`, `Gw.withdraw_proofs`, `Withdrawal::leaf`, `l1.claimed`.
- Produces: `Gw::prune_claimed_withdrawals(&mut self, claimed: &[[u8; 32]])`.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn prune_claimed_withdrawals_removes_only_claimed() {
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        let w1 = gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let w2 = gw.account_withdraw(&key, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        // seed proofs for both leaves as a settle would
        gw.withdraw_proofs.insert(w1.leaf(), ([0xAAu8; 32], vec![[0xBBu8; 32]]));
        gw.withdraw_proofs.insert(w2.leaf(), ([0xAAu8; 32], vec![[0xCCu8; 32]]));

        // claim w1 only
        gw.prune_claimed_withdrawals(&[w1.leaf()]);

        assert!(!gw.pending_withdrawals.iter().any(|w| w.leaf() == w1.leaf()));
        assert!(gw.pending_withdrawals.iter().any(|w| w.leaf() == w2.leaf()));
        assert!(!gw.withdraw_proofs.contains_key(&w1.leaf()));
        assert!(gw.withdraw_proofs.contains_key(&w2.leaf()));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p gateway prune_claimed_withdrawals_removes_only_claimed`
Expected: compile error (method absent).

- [ ] **Step 3: Implement the method** (in an `impl Gw` block)

```rust
    /// Slice 3b-2b: drop withdrawals the vault has already paid (claimed[leaf]) from both
    /// the listing (`pending_withdrawals`) and the served proofs (`withdraw_proofs`), so
    /// the new (per-window) settle path stays bounded and paid notes stop being listed —
    /// the same claimed-pruning the legacy cumulative path does at settle.
    fn prune_claimed_withdrawals(&mut self, claimed: &[[u8; 32]]) {
        if claimed.is_empty() {
            return;
        }
        let cset: std::collections::BTreeSet<[u8; 32]> = claimed.iter().copied().collect();
        self.pending_withdrawals.retain(|w| !cset.contains(&w.leaf()));
        for leaf in &cset {
            self.withdraw_proofs.remove(leaf);
        }
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p gateway prune_claimed_withdrawals_removes_only_claimed` → PASS.

- [ ] **Step 5: Wire the pruning into the new-path async branch**

In `crates/gateway/src/main.rs`, in the new-path branch (`if let Some(client) = app.prover.clone() { ... }`),
make three edits:

(a) In section (B), capture the current pending-withdrawal leaves alongside the seal. Change the `begun`
block from `Ok(Some(x)) => Some(x),` to also snapshot the candidates:
```rust
                    let begun = {
                        let mut gw = app.gw.lock().await;
                        match gw.begin_window_settle(bc) {
                            Ok(Some(x)) => {
                                let cand: Vec<[u8; 32]> =
                                    gw.pending_withdrawals.iter().map(|w| w.leaf()).collect();
                                Some((x, cand))
                            }
                            Ok(None) => None,
                            Err(e) => {
                                eprintln!("[l1] window settle skipped: {e}");
                                None
                            }
                        }
                    };
                    let Some(((witness, ww), prune_candidates)) = begun else { continue };
```

(b) In section (C)'s `spawn_blocking`, move `prune_candidates` in, query claimed after settling, and return
it. Change the closure signature + body:
```rust
                    let res = tokio::task::spawn_blocking(
                        move || -> Result<(prover_client::PreparedSettle, String, u128, Vec<[u8; 32]>), String> {
                            let prepared =
                                prover_client::prove_and_prepare(client.as_ref(), &witness, &ww)?;
                            let tx = l1c.settle_proved(&prepared.outcome)?;
                            let bond = l1c.sequencer_bond().unwrap_or(0);
                            // mirror the legacy path: drop leaves the vault already paid.
                            let claimed: Vec<[u8; 32]> = prune_candidates
                                .into_iter()
                                .filter(|leaf| l1c.claimed(&hex32(leaf)).unwrap_or(false))
                                .collect();
                            Ok((prepared, tx, bond, claimed))
                        },
                    )
                    .await;
```

(c) In the `Ok(Ok(...))` arm, bind the new `claimed` and prune after commit:
```rust
                        Ok(Ok((prepared, tx, bond, claimed))) => {
                            let status = L1Status {
                                settled_root: hex32(&prepared.outcome.new_root),
                                batch_count: batch_id + 1,
                                last_tx: tx.clone(),
                                bond: bond.to_string(),
                                withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
                            };
                            println!(
                                "[l1] window settled root {} batch {} tx {} (withdrawals root {})",
                                status.settled_root, status.batch_count, tx, status.withdrawals_root
                            );
                            {
                                let mut gw = app.gw.lock().await;
                                gw.commit_window_settle(batch_id, ordered, rejected, prepared, status);
                                gw.prune_claimed_withdrawals(&claimed);
                            }
                            let snap = { app.gw.lock().await.snapshot() };
                            let _ = app.tx.send(
                                serde_json::to_string(&WsMsg::State { state: snap }).unwrap(),
                            );
                        }
```

- [ ] **Step 6: Verify the branch compiles + full suite**

Run: `cargo build -p gateway` (the async branch compiles) + `cargo test -p gateway` (full — legacy + all new
tests green) + `cargo clippy -p gateway` → clean. (The claimed-query + prune wiring needs a live L1, so it is
reviewed by reading + live-validated in the GB10 e2e, like the rest of the branch.)

- [ ] **Step 7: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): new-path claimed-leaf pruning (Gw::prune_claimed_withdrawals + settle wiring)"
```

---

## Task 5: Carry-forward (B) — `prove_and_prepare` negative-test split

**Files:**
- Modify: `crates/gateway/src/main.rs` (replace the one `prove_and_prepare_rejects_withdrawals_root_mismatch`
  test with two targeted tests). Test-only; no logic change.

**Interfaces:**
- Consumes: `prove_and_prepare`, `MockProverClient`, `ProveOutcome`, `ProverClient`, `ProverClientError`,
  `perp_core::commitment::DerivedRoots`, `perp_core::Keccak256`.

- [ ] **Step 1: Replace the single negative test with two**

In `crates/gateway/src/main.rs`, delete the existing `prove_and_prepare_rejects_withdrawals_root_mismatch`
test (the one whose `TamperedClient` corrupts only `withdrawals_root`) and add these two in its place:

```rust
    #[test]
    fn prove_and_prepare_rejects_wroot_mismatch() {
        use crate::prover_client::{
            prove_and_prepare, MockProverClient, ProveOutcome, ProverClient, ProverClientError,
        };
        use perp_core::commitment::DerivedRoots;
        use perp_core::Keccak256;
        use sequencer::WindowWitness;

        // corrupts withdrawals_root AND recomputes commitment over the tampered roots, so
        // the commitment cross-check PASSES and the failure lands on the withdrawal-tree
        // byte-match branch.
        struct WrootTamper;
        impl ProverClient for WrootTamper {
            fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
                let mut out = MockProverClient.prove(w)?;
                out.withdrawals_root = [0xFFu8; 32];
                out.commitment = DerivedRoots {
                    prev_state_root: out.prev_root,
                    manifest_hash: out.manifest_hash,
                    new_state_root: out.new_root,
                    ordered_root: out.ordered_root,
                    withdrawals_root: out.withdrawals_root,
                    rejected_root: out.rejected_root,
                }
                .commitment::<Keccak256>();
                Ok(out)
            }
        }

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        assert!(!ww.is_empty());

        let err = prove_and_prepare(&WrootTamper, &witness, &ww).unwrap_err();
        assert!(err.contains("withdrawals root mismatch"), "got: {err}");
    }

    #[test]
    fn prove_and_prepare_rejects_commitment_mismatch() {
        use crate::prover_client::{
            prove_and_prepare, MockProverClient, ProveOutcome, ProverClient, ProverClientError,
        };
        use sequencer::WindowWitness;

        // corrupts only the commitment (roots stay consistent with the gateway tree) → the
        // commitment cross-check branch fires first.
        struct CommitTamper;
        impl ProverClient for CommitTamper {
            fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
                let mut out = MockProverClient.prove(w)?;
                out.commitment = [0xFFu8; 32];
                Ok(out)
            }
        }

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");

        let err = prove_and_prepare(&CommitTamper, &witness, &ww).unwrap_err();
        assert!(err.contains("commitment mismatch"), "got: {err}");
    }
```

- [ ] **Step 2: Run the tests — verify each targets its branch**

Run: `cargo test -p gateway prove_and_prepare_rejects_wroot_mismatch` then
`cargo test -p gateway prove_and_prepare_rejects_commitment_mismatch` → both PASS (each asserting its own
error string, proving it hit the intended guard). Then `cargo test -p gateway` (full) + `cargo clippy -p gateway`
→ clean.

- [ ] **Step 3: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "test(gateway): split prove_and_prepare negative test (wroot vs commitment branch)"
```

---

## Post-merge: GB10 end-to-end (greenlight-gated — NOT an SDD task)

After all five tasks merge and CI is green, validate the real path on the GB10 (needs an explicit user
greenlight — it deploys a contract and runs real proving; it does NOT touch `perp.arcoralabs.xyz`):

1. Run the Slice-2 prover-service on the GB10 (already built there); leave `PROVER_SEAL_ROOT`/measurement at
   the defaults (`0x5E`/`0xAB`).
2. Deploy a fresh test `DarkPerpSettlement` with the Slice-1 `SP1ZkVerifier` (vkey `0x00f4a710…`), with
   `_genesisRoot` set to the sequencer's window-0 `pre_state` root (the new path submits the witness-derived
   `prev_root`; `settleBatch` reverts unless `prevRoot == currentStateRoot`).
3. Run the gateway with `PROVER_URL=<gb10 service url>` at that settlement; drive a window (deposit + fill);
   confirm the settle loop seals → curl POSTs → real Groth16 → `settleBatch(6 roots, proof)` → **status 1**,
   `currentStateRoot` advances. GB10: `ssh <operator>@<prover-host>`.

---

## Self-Review (author checklist — completed)

**1. Spec coverage** (against `2026-07-08-zk-p2-slice3b2b-http-prover-client-design.md`):
- §3 prover dep → Task 1. ✅
- §4 HttpProverClient + ProverClientError variants + seal_witness (§4.1) + parse_prove_resp (§4.2) + http_post
  (§4.3) → Tasks 1, 2, 3. ✅
- §5 prover_from_str URL wiring → Task 3. ✅
- §6 (A) claimed-leaf pruning → Task 4. ✅
- §7 (B) negative-test split → Task 5. ✅
- §8 testing → each task's tests; http_post/async-wiring are glue (documented, GB10). ✅
- §9 GB10 e2e → post-merge greenlight step. ✅
- §10 non-goals (no 3b-3, no migration, no perp-core/sequencer/contract logic change) → respected; only
  gateway + Cargo.toml (`prover` dep). ✅

**2. Placeholder scan:** none; every code step is complete; every test asserts real behavior. ✅

**3. Type consistency:** `ProverClientError::{Derive, Seal, Http, Decode}`; `seal_witness(&WindowWitness,
&[u8;32], &Digest) -> Result<String, ProverClientError>`; `parse_prove_resp(&str) -> Result<ProveOutcome,
ProverClientError>`; `http_post(&str, &str, u64) -> Result<String, ProverClientError>`;
`HttpProverClient::from_env(&str) -> Self`; `prune_claimed_withdrawals(&mut self, &[[u8;32]])` — names/types
consistent across tasks and with the merged 3b-2a shapes (`ProveOutcome`, `prove_and_prepare`, `parse_hex32`,
`decode_hex`, `hex32`). ✅
