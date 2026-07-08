# ZK Verifier P2 — Slice 3b-2b: HttpProverClient + Real Groth16 Proof — Design

**Date:** 2026-07-08
**Status:** Approved (brainstorming) → ready for implementation plan
**Workstream:** ZK verifier P2. Slice 3b-2a (merge `4cca221`) wired `seal_window` into the gateway settle
path behind `PROVER_URL` and built the full settle plumbing (`begin_window_settle` → `prove_and_prepare` →
`L1::settle_proved` → `commit_window_settle`) against a local `MockProverClient` (derives the six roots,
`proof == commitment`). This slice, **3b-2b**, adds the **`HttpProverClient`** — the real transport: it
seals the `WindowWitness` and POSTs it to the attested prover-service (Slice 2, `crates/prover-service`),
which returns a real Groth16 proof + the six derived roots. `PROVER_URL=<url>` selects it; the `mock`/unset
states and all downstream plumbing are unchanged. It also folds in the two 3b-2a carry-forwards
((A) new-path claimed-leaf pruning, (B) the `prove_and_prepare` negative-test split) and is validated
end-to-end on the GB10 (gateway settle loop → prover-service → real Groth16 → on-chain `SP1ZkVerifier` →
`settleBatch` status 1). Next: 3b-3 (per-window rollback + inclusion/receipt re-keying), then the live-stack
migration.

---

## 1. Problem

3b-2a left `PROVER_URL=<url>` returning an error (`"HttpProverClient is Slice 3b-2b"`) — the real transport
was deliberately deferred. Everything downstream of `ProverClient::prove` (seal→settle→commit, incremental
withdrawals, the byte-match invariant, the counter guard, `ensure_bond`) is done and tested against the
mock. What remains is the one implementation of the `ProverClient` trait that actually reaches the
prover-service: seal the witness with the same `SoftwareSealProvider` stand-in the service opens with
(`root = 0x5E…`, `measurement = 0xAB…`), POST the sealed hex to `/prove`, and parse the JSON response into a
`ProveOutcome`. The gateway has no HTTP client crate; its only external-service call today (L1) shells out to
`cast` (`crates/gateway/src/l1.rs:138`), so the transport mirrors that subprocess pattern with `curl`.

Two 3b-2a review carry-forwards ride along because they touch the same new path: (A) the new path only ever
*extends* `withdraw_proofs`/`pending_withdrawals` — it never prunes claimed leaves the way the legacy path
does, so both grow unbounded and a claimed note keeps showing `claimable: true`; (B) the 3b-2a
`prove_and_prepare` negative test (`TamperedClient`) corrupts only `withdrawals_root`, which — because the
Task-5 commitment cross-check runs first — now trips the *commitment* branch, leaving the withdrawal-root
branch uncovered.

## 2. Goal

`PROVER_URL=<url>` runs the gateway's window-settle path against a real prover-service: each window is
sealed, POSTed, proven (real Groth16), and settled with the six derived roots + the real proof. The two
pure steps — `seal_witness` (produces the sealed hex the service can open) and `parse_prove_resp` (JSON →
`ProveOutcome`) — are unit-tested in CI; the `curl` POST is external glue, live-validated on the GB10. The
new path prunes claimed withdrawals like the legacy path, and the negative test covers both guard branches.
Legacy (`PROVER_URL` unset) stays byte-unchanged; the live stack stays on the mock verifier until the
migration slice.

## 3. Dependency

Add `prover = { path = "../prover" }` to `crates/gateway/Cargo.toml` `[dependencies]`. The `prover` crate
holds `SealedWitness`, `SealKeyProvider`, and `SoftwareSealProvider` and is workspace-internal — it does NOT
pull in `sp1-sdk` (that lives only in the excluded `prover-service`), so this is a light, workspace-safe
addition. (This is the slice's only `Cargo.toml` change.)

## 4. `HttpProverClient` (`crates/gateway/src/prover_client.rs`)

```rust
use prover::{SealedWitness, SoftwareSealProvider};

pub struct HttpProverClient {
    url: String,             // PROVER_URL, e.g. "http://127.0.0.1:8091"
    seal_root: [u8; 32],     // matches the service's PROVER_SEAL_ROOT (default 0x5E…)
    measurement: Digest,     // the stand-in measurement 0xAB… (matches the service)
    timeout_secs: u64,       // curl wall-clock cap; a real Groth16 proof takes minutes
}

impl ProverClient for HttpProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
        let sealed_hex = seal_witness(w, &self.seal_root, &self.measurement)?;
        let body = serde_json::json!({ "sealed": sealed_hex }).to_string();
        let resp = http_post(&self.url, "/prove", &body, self.timeout_secs)?;
        parse_prove_resp(&resp)
    }
}
```

New `ProverClientError` variants (3b-2a had only `Derive(EngineError)`):

```rust
pub enum ProverClientError {
    Derive(EngineError),
    Seal,             // SealedWitness::seal returned None (provider refused)
    Http(String),     // curl failure / non-2xx / timeout
    Decode(String),   // bad JSON, missing field, or bad hex in the response
}
```

### 4.1 `seal_witness` (pure, unit-tested)

```rust
/// Seal a window witness exactly as the prover-service's seal-client does, so the
/// service (same SoftwareSealProvider params) can open it. Returns 0x-prefixed hex.
pub fn seal_witness(w: &WindowWitness, root: &[u8; 32], measurement: &Digest)
    -> Result<String, ProverClientError>;
```

- The sealed plaintext is the witness triple `(w.pre_state.clone(), w.ops.clone(), w.manifest.clone())`
  postcard-encoded — the exact `(DefaultState, Vec<BatchOp>, BatchManifest)` tuple the service's
  `AttestedProver::prove_batch` decodes. `batch_id` is NOT in the tuple (the service re-derives it from
  `pre_state.next_batch_id`).
- `SealedWitness::seal(&bytes, &SoftwareSealProvider::new(*root, *measurement), *measurement, nonce)` →
  `postcard::to_allocvec(&sealed)` → `0x` + hex. `None` from `seal` → `ProverClientError::Seal`.
- **Nonce** is derived deterministically from the window's `batch_id` (unique per window): a `[u8; 32]` with
  the big-endian `batch_id` in the low 8 bytes. Uniqueness per window prevents keystream reuse across
  windows; determinism means a retried settle re-seals the *same* plaintext under the *same* nonce (safe —
  no new plaintext under a reused keystream) and makes the step testable. The nonce is transmitted inside
  the `SealedWitness`, so the service opens with `sealed.nonce` regardless.

### 4.2 `parse_prove_resp` (pure, unit-tested)

```rust
/// Parse the prover-service /prove JSON response into a ProveOutcome.
pub fn parse_prove_resp(json: &str) -> Result<ProveOutcome, ProverClientError>;
```

The response mirrors the service's `ProveResp` — eight hex string fields
`{prev_root, manifest_hash, new_root, ordered_root, withdrawals_root, rejected_root, commitment, proof}`.
Parse with `serde_json` into a local `#[derive(Deserialize)]` struct of `String`s, then hex-decode: the six
roots + `commitment` to `Digest` (`[u8; 32]`, error if not 32 bytes), `proof` to `Vec<u8>`. Any JSON error,
missing field, or bad hex → `ProverClientError::Decode`. The returned `ProveOutcome` is then validated
downstream by the existing `prove_and_prepare` (commitment cross-check + withdrawal-tree byte-match), so a
tampered or inconsistent response is rejected before `settleBatch`.

### 4.3 `http_post` (curl subprocess — external glue, live-validated)

```rust
/// POST `body` as application/json to `<url><path>` via curl, returning the response
/// body. Mirrors L1::cast (subprocess + wall-clock timeout), but pipes the body on
/// stdin (--data-binary @-) so a large sealed witness never hits an argv limit.
fn http_post(url: &str, path: &str, body: &str, timeout_secs: u64)
    -> Result<String, ProverClientError>;
```

Runs `curl -s -S --fail -X POST -H 'Content-Type: application/json' --data-binary @- <url><path>` with
`body` written to the child's stdin (`std::process::Command` + `Stdio::piped()`), a wall-clock timeout of
`timeout_secs` (a real Groth16 proof under qemu on the GB10 takes minutes, so the default is generous —
`PROVER_TIMEOUT_SECS`, default 900), and non-zero exit / timeout → `ProverClientError::Http`. Not
unit-tested (needs a live endpoint); exercised in the GB10 e2e.

## 5. `prover_from_str` wiring

`prover_from_str` (3b-2a) currently returns `Err` for a URL. Change the URL arm to construct the client:

```rust
    Some(url) => Ok(Some(std::sync::Arc::new(HttpProverClient::from_env(url)))),
```

`HttpProverClient::from_env(url)` reads `PROVER_SEAL_ROOT` (32-byte hex, default `[0x5E; 32]` — matching the
service's `seal_root()`), sets `measurement = [0xAB; 32]` (the stand-in, matching the service's
`measurement()`), and `timeout_secs` from `PROVER_TIMEOUT_SECS` (default 900). The unset/`""` → `None` and
`"mock"` → `MockProverClient` arms are unchanged. The 3b-2a `prover_from_str_selects_path` test is updated:
the URL case now yields `Some`, not `Err`.

## 6. Carry-forward (A): new-path claimed-leaf pruning

The legacy settle path prunes withdrawals the vault already paid (`l1.claimed(leaf)`) before building its
cumulative root, so `pending_withdrawals` stays bounded and paid notes drop out of `v1_withdrawals_json`.
The new path must do the same for its accumulated maps:

- **New method** `Gw::prune_claimed_withdrawals(&mut self, claimed: &[[u8; 32]])`: `pending_withdrawals`
  retains only leaves not in `claimed`; `withdraw_proofs` removes each claimed leaf. (Unit-tested: seed both
  maps, prune a subset, assert removed vs kept.)
- **Async-branch wiring:** in the new path, snapshot the current `pending_withdrawals` leaves under the lock
  (alongside the seal), query `l1.claimed(&hex32(leaf))` for each in the lock-free `spawn_blocking` section
  (mirroring the legacy loop), and call `prune_claimed_withdrawals(&claimed)` under the lock right after
  `commit_window_settle`. `commit_window_settle`'s signature is unchanged (pruning is a separate concern).

`claimable = proof.is_some()` in `v1_withdrawals_json` stays correct because claimed notes are now pruned.
This keeps the new path at parity with the legacy path's bounded-growth + claim-freshness behavior.

## 7. Carry-forward (B): `prove_and_prepare` negative-test split

3b-2a's `prove_and_prepare_rejects_withdrawals_root_mismatch` corrupts only `withdrawals_root`; since the
Task-5 commitment cross-check runs before the withdrawal-tree check, it now trips the *commitment* branch,
leaving the withdrawal-root branch untested. Replace it with two tests (test-only):

- **wroot-mismatch:** a client that corrupts `withdrawals_root` **and** recomputes `commitment` over the
  tampered six roots (so the commitment cross-check passes) → asserts `prove_and_prepare` returns `Err` at
  the withdrawal-tree byte-match branch.
- **commitment-mismatch:** a client that corrupts only `commitment` (roots consistent with the gateway
  tree) → asserts `Err` at the commitment cross-check branch.

Both prove a tampered outcome never reaches `settleBatch`, and each targets a distinct guard.

## 8. Testing (CI, gateway crate)

- **`seal_witness` well-formed:** seal a `Gw::boot()`-derived `WindowWitness`; postcard-decode the produced
  hex back into a `SealedWitness`; assert `measurement == [0xAB; 32]`, `nonce` == the batch_id-derived value,
  and `ciphertext.len()` == the plaintext (postcard tuple) length. (Real open by the service is the GB10
  e2e's job — CI proves the seal is well-formed and addressed to the right measurement.)
- **`parse_prove_resp`:** a canned JSON response with the eight hex fields → assert every `ProveOutcome`
  field decodes to the expected bytes (roots/commitment 32 bytes, proof the decoded length); malformed JSON,
  a missing field, and an odd-length/oversized hex root each → `Decode`.
- **`prover_from_str`:** unset/`""` → `None`; `"mock"` → `Some`; a URL → `Some` (an `HttpProverClient`).
- **The two (B) negative tests.**
- **Legacy regression:** `PROVER_URL` unset → existing suite green; `cargo clippy --workspace` clean.
- `http_post` is not unit-tested (needs a live service) — GB10 e2e.

## 9. GB10 end-to-end (greenlight-gated; live, like Slice 2)

After CI is green, validate the real path on the user's GB10 (needs an explicit greenlight — it deploys a
contract and runs real proving):

1. Run the Slice-2 prover-service on the GB10 (already built there), `PROVER_SEAL_ROOT`/measurement at the
   defaults.
2. Deploy a fresh test `DarkPerpSettlement` with the Slice-1 `SP1ZkVerifier` (vkey
   `0x00f4a710…`), **`_genesisRoot` set to the sequencer's window-0 `pre_state` root** (carry-forward (C):
   the new path submits the witness-derived `prev_root`, and `settleBatch` reverts unless
   `prevRoot == currentStateRoot`).
3. Run the gateway with `PROVER_URL=<gb10 service url>` pointed at that settlement; drive a window
   (deposit + fill); the settle loop seals → `curl` POSTs → the service returns a real Groth16 proof + roots
   → `settleBatch(6 roots, proof)` → **status 1**, `currentStateRoot` advances.

This proves the full gateway-driven chain (vs Slice 2's manual seal-client). It does NOT touch the live
`perp.arcoralabs.xyz` stack.

## 10. Non-goals (Slice 3b-2b)

- **No per-window rollback and no inclusion/receipt re-keying** — Slice 3b-3. The settle-failure desync
  wedge is still only guarded (skip + log), not recovered.
- **No live-stack migration.** `perp.arcoralabs.xyz` stays on `MockZkVerifier` with `PROVER_URL` unset until
  the migration slice (which deploys `SP1ZkVerifier`, sets `PROVER_URL`, aligns the genesis root, and resets
  the snapshot — postcard being positional, an in-place upgrade over an old snapshot fail-closes at boot).
- **No perp-core/sequencer/contract logic change** — the only non-gateway change is adding the `prover`
  path dependency to `crates/gateway/Cargo.toml`.
- No change to `derive_roots`, the six-field commitment, the witness format, or matching fairness
  (Proof-v2).
