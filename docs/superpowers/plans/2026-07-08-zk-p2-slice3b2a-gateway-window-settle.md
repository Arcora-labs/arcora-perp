# ZK P2 Slice 3b-2a — Gateway Window-Settle Path + Incremental Withdrawals — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the dormant `seq.seal_window()` into the gateway settle path behind a `ProverClient`
abstraction whose first impl is a local `MockProverClient`, and rework withdrawals publish from a cumulative
root to the incremental per-window root the circuit derives — all CI-testable, no prover-service/network.

**Architecture:** A new `crates/gateway/src/prover_client.rs` defines `ProverClient`/`ProveOutcome`/
`MockProverClient` (local `perp_core::commitment::derive_roots`, `proof == commitment`). The L1-settle task
gains a new-path branch selected by `PROVER_URL`: seal the window → prove → build the window withdrawal tree
(byte-matching the circuit's `withdrawals_root`) → `settleBatch` the six derived roots + proof. The pure
logic (seal + guard, prove + tree + proofs) lives in testable `Gw` methods / free functions; the async task
is thin glue over them. The legacy cumulative + mock path is preserved byte-for-byte and stays the default.

**Tech Stack:** Rust (workspace crates `gateway`, `perp-core`, `sequencer`), tokio async, `serde`,
`perp_core::merkle` (keccak Merkle), Foundry `cast` for L1 (unchanged).

## Global Constraints

- **Flag `PROVER_URL`, three states (verbatim):** unset/empty → legacy cumulative+mock path (default,
  behavior byte-unchanged); `"mock"` → new window-settle+incremental path with `MockProverClient`; any other
  value (a URL) → **error** `"HttpProverClient is Slice 3b-2b"` (implemented in 3b-2b, not here).
- **`MockProverClient` proof == commitment** — the 32-byte `DerivedRoots::commitment::<Keccak256>()` bytes,
  which the on-chain `MockZkVerifier` accepts.
- **Withdrawals byte-match invariant:** the gateway's per-window withdrawal tree root MUST equal the
  prover's `withdrawals_root` (both `merkle_root` over `withdrawal_leaf(to, amount, nonce)` leaves in the
  same op-application order). A mismatch is a hard error, never silently published.
- **No change** to `crates/perp-core`, `crates/sequencer`, the SP1 guest/host, the prover-service, or any
  Solidity contract. This slice touches only `crates/gateway`.
- **Counter alignment (happy path):** `seal_window` is called exactly once per settle; the window's
  `batch_id` (== `seq.state.next_batch_id` at seal time) MUST equal the on-chain `batchCount`. A mismatch
  skips the settle and logs (no rollback — that is Slice 3b-3).
- **serde compatibility:** every new `Gw` field is `#[serde(default)]` so pre-upgrade sealed snapshots still
  load (`Gw` derives `Serialize`/`Deserialize`; `boot_restored` deserializes).
- **Run tests from the repo root** `/Users/huseyinarslan/Desktop/dark-perp` with `cargo test -p gateway`.

---

## Reference: exact current shapes (verbatim, do not re-derive)

**`perp_core::commitment`** (`crates/perp-core/src/commitment.rs`):
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivedRoots {
    pub prev_state_root: Digest,
    pub manifest_hash: Digest,
    pub new_state_root: Digest,
    pub ordered_root: Digest,
    pub withdrawals_root: Digest,
    pub rejected_root: Digest,
}
impl DerivedRoots { pub fn commitment<H: Hasher>(&self) -> Digest { /* keccak_words(StateRoot, [6 roots]) */ } }
pub fn derive_roots(state: &mut DefaultState, ops: &[BatchOp], manifest: &BatchManifest)
    -> Result<DerivedRoots, EngineError>;
```
`Digest = [u8; 32]` (`perp_core::hash::Digest`, re-exported `perp_core::Digest`). `Keccak256` at
`perp_core::Keccak256`. `perp_core::merkle`: `merkle_root(&[Digest]) -> Digest`,
`merkle_proof(&[Digest], usize) -> Vec<Digest>`, `verify(Digest, Digest, &[Digest]) -> bool`,
`withdrawal_leaf(&[u8;20], u128, u64) -> Digest`.

**`sequencer::WindowWitness`** (`crates/sequencer/src/lib.rs:176`): `pub struct WindowWitness { pub batch_id: u64,
pub pre_state: DefaultState, pub ops: Vec<BatchOp>, pub manifest: BatchManifest }`. `seal_window(&mut self)
-> WindowWitness` bumps `state.next_batch_id` once and drains the window accumulators. `manifest.ordered:
Vec<Digest>`, `manifest.rejected: Vec<(Digest, RejectReason)>`.

**`gateway::withdrawals::Withdrawal`** (`crates/gateway/src/withdrawals.rs:29`): `{ owner: [u8;32], to:
[u8;20], amount: u128, nonce: u64 }`, `fn leaf(&self) -> [u8;32]`. `main.rs:46` imports `use
withdrawals::{inclusion_leaf, merkle_proof, merkle_root, rejection_leaf, Withdrawal};`.

**`Gw`** (`crates/gateway/src/main.rs:591`, derives `Serialize`/`Deserialize`) relevant fields:
`pending_withdrawals: Vec<Withdrawal>`, `next_withdraw_nonce: u64`, `withdraw_proofs:
std::collections::BTreeMap<[u8;32], Vec<[u8;32]>>`, `pending_ordered: Vec<Digest>`, `pending_rejected:
Vec<Digest>`, `batch_orders: std::collections::BTreeMap<u64, (Vec<Digest>, Vec<Digest>)>`, `l1_status:
Option<L1Status>`, `seq: Sequencer`. Constructor is `fn boot() -> Self` (`main.rs:938`, struct literal
`1018-1051`); `state_root_hex(&self) -> String = hex32(&self.seq.state.state_root())` (`main.rs:1833`).
`hex32(d: &Digest) -> String` at `main.rs:49`; `hex0x` (arbitrary-length) already used by
`v1_withdrawals_json`.

**`L1`** (`crates/gateway/src/l1.rs`): `settle(&self, prev, manifest, new, ordered, withdrawals, rejected:
&str) -> Result<String,String>` (381), private `send(&self, target, sig: &str, args: &[&str]) ->
Result<String,String>` (202), `current_root() -> Result<String,String>` (247), `batch_count() ->
Result<u64,String>` (273), `claimed(leaf: &str) -> Result<bool,String>` (323), `sequencer_bond() ->
Result<u128,String>` (used at settle), `ensure_bond()`. `L1Status` (`l1.rs:62`): `{ settled_root: String,
batch_count: u64, last_tx: String, bond: String, withdrawals_root: String }`.

**`App`** (`main.rs:2959`): `{ gw: Mutex<Gw>, tx, events_tx, reg_limit, l1: Option<L1>, candles }`; built at
`main.rs:4250`; `l1 = L1::from_env()` at `4133`; settle task gated by `if let Some(l1) = l1 {` at `4450`.
Tests inline in `main.rs` `#[cfg(test)] mod tests` (`4689`); helper `test_app()` (`4696`); models:
`build_challenge_answer_produces_a_verifying_proof` (`4986`), `snapshot_restart_round_trip_preserves_state`
(`4712`).

---

## Task 1: `ProverClient` module + `MockProverClient`

**Files:**
- Create: `crates/gateway/src/prover_client.rs`
- Modify: `crates/gateway/src/main.rs` (add `mod prover_client;` near the other `mod` declarations at the
  top; add the Task-1 test into `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `perp_core::commitment::{derive_roots, DerivedRoots}`, `perp_core::{Digest, Keccak256,
  EngineError}`, `perp_core::DefaultState`, `sequencer::WindowWitness`.
- Produces: `prover_client::ProveOutcome { prev_root, manifest_hash, new_root, ordered_root,
  withdrawals_root, rejected_root, commitment: Digest, proof: Vec<u8> }`; `prover_client::ProverClientError`
  (enum, `Debug`); `trait prover_client::ProverClient: Send + Sync { fn prove(&self, w: &WindowWitness) ->
  Result<ProveOutcome, ProverClientError>; }`; `prover_client::MockProverClient` (unit struct impl'ing it).

- [ ] **Step 1: Create the module with the impl**

Create `crates/gateway/src/prover_client.rs`:

```rust
//! Slice 3b-2a: the gateway's client for turning a sealed window into the six on-chain
//! roots + a proof. `MockProverClient` derives the roots in-process (no network, no
//! confidentiality boundary) and uses the commitment as the proof — accepted by the
//! on-chain MockZkVerifier (proof == commitment). Slice 3b-2b adds `HttpProverClient`
//! (seal → POST /prove → real Groth16 proof); this module's trait is that seam.

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
```

- [ ] **Step 2: Register the module**

In `crates/gateway/src/main.rs`, add alongside the other `mod` declarations near the top (e.g. next to
`mod withdrawals;`):

```rust
mod prover_client;
```

- [ ] **Step 3: Write the failing test** (in `main.rs` `#[cfg(test)] mod tests`)

```rust
    #[test]
    fn mock_prover_client_matches_derive_roots() {
        use crate::prover_client::{MockProverClient, ProverClient};
        use perp_core::commitment::derive_roots;
        use perp_core::Keccak256;

        // A realistic non-empty window: boot registers markets + funds (those ops land
        // in window_ops), so the first seal_window yields a valid, non-trivial witness.
        let mut gw = Gw::boot();
        let witness = gw.seq.seal_window();

        let out = MockProverClient.prove(&witness).expect("mock prove");

        // Independently derive the same roots and assert byte-equality.
        let mut state = witness.pre_state.clone();
        let d = derive_roots(&mut state, &witness.ops, &witness.manifest).expect("derive");
        assert_eq!(out.prev_root, d.prev_state_root);
        assert_eq!(out.manifest_hash, d.manifest_hash);
        assert_eq!(out.new_root, d.new_state_root);
        assert_eq!(out.ordered_root, d.ordered_root);
        assert_eq!(out.withdrawals_root, d.withdrawals_root);
        assert_eq!(out.rejected_root, d.rejected_root);
        assert_eq!(out.commitment, d.commitment::<Keccak256>());
        // MockZkVerifier accepts proof == commitment.
        assert_eq!(out.proof, out.commitment.to_vec());
    }
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test -p gateway mock_prover_client_matches_derive_roots`
Expected: FAIL to COMPILE first (module/types absent) until Steps 1-2 are in; once compiling, PASS. If it
fails on `seal_window` visibility or `Gw::boot`, confirm Steps 1-2 landed.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p gateway mock_prover_client_matches_derive_roots`
Expected: PASS (1 passed). Then `cargo clippy -p gateway` — expected: no warnings on the new file.

- [ ] **Step 6: Commit**

```bash
git add crates/gateway/src/prover_client.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): ProverClient trait + MockProverClient (local derive_roots, proof==commitment)"
```

---

## Task 2: `Gw` fields + `withdraw_proofs` type unification to `(root, proof)`

**Files:**
- Modify: `crates/gateway/src/main.rs` — `Gw` struct fields (`591-672`), `Gw::boot` literal (`1018-1051`),
  `account_withdraw` (`1264-1319`), `v1_withdrawals_json` (`1325-1353`), the legacy settle task's
  `SettleOut` alias + `proofs.insert` + `gw.withdraw_proofs = proofs` (`4531-4645`).

**Interfaces:**
- Consumes: `Withdrawal` (already imported), `Digest`.
- Produces: `Gw.window_withdrawals: Vec<Withdrawal>`; `Gw.last_settled_root: Digest`; `Gw.withdraw_proofs:
  std::collections::BTreeMap<[u8;32], (Digest, Vec<[u8;32]>)>` (was `BTreeMap<[u8;32], Vec<[u8;32]>>`).

- [ ] **Step 1: Change the `withdraw_proofs` field type + add the two new fields**

In the `Gw` struct (`main.rs:~623`), change:
```rust
    withdraw_proofs: std::collections::BTreeMap<[u8; 32], Vec<[u8; 32]>>,
```
to:
```rust
    /// Claim data per withdrawal leaf: (published root, sibling path). The root lets a
    /// note carry the specific window (incremental) or cumulative (legacy) root it was
    /// published under — CollateralVault.claim(to, amount, nonce, root, proof) accepts any
    /// published root (DP-012).
    withdraw_proofs: std::collections::BTreeMap<[u8; 32], (Digest, Vec<[u8; 32]>)>,
```
And add, right after the `withdraw_proofs` field:
```rust
    /// Slice 3b-2a: withdrawals created since the current window opened, in op-application
    /// order — the incremental per-window withdrawal set the circuit's `withdrawals_root`
    /// is derived from. Drained by the new (PROVER_URL) settle path. `#[serde(default)]`
    /// keeps pre-upgrade snapshots loadable.
    #[serde(default)]
    window_withdrawals: Vec<Withdrawal>,
    /// Slice 3b-2a: the state root of the last on-chain settle (genesis at boot). The new
    /// settle path uses `seq.state.state_root() != last_settled_root` as its RPC-free
    /// "is there anything to settle?" signal.
    #[serde(default)]
    last_settled_root: Digest,
```

- [ ] **Step 2: Initialize the new fields in `Gw::boot`**

`seq` is moved into the `Gw { .. }` literal at `main.rs:1019`, so capture the genesis root just before the
literal. Immediately before `let mut gw = Gw {` (`main.rs:1018`), add:
```rust
        let genesis_root = seq.state.state_root();
```
Then inside the literal, next to `withdraw_proofs: std::collections::BTreeMap::new(),`, add:
```rust
            window_withdrawals: Vec::new(),
            last_settled_root: genesis_root,
```

- [ ] **Step 3: Push to `window_withdrawals` in `account_withdraw`**

In `account_withdraw` (`main.rs:1317`), directly after `self.pending_withdrawals.push(w.clone());` add:
```rust
        // Slice 3b-2a: also record it in the current window's incremental set (same order
        // the BatchOp::Withdraw was applied), so the new settle path's window withdrawal
        // tree byte-matches the circuit's withdrawals_root.
        self.window_withdrawals.push(w.clone());
```

- [ ] **Step 4: Update `v1_withdrawals_json` to read `(root, proof)`**

Replace the `.map(|w| { .. })` closure body in `v1_withdrawals_json` (`main.rs:1338-1349`) with:
```rust
            .map(|w| {
                let leaf = w.leaf();
                let entry = self.withdraw_proofs.get(&leaf);
                serde_json::json!({
                    "to": hex0x(&w.to),
                    "amount": w.amount.to_string(),
                    "nonce": w.nonce,
                    "leaf": hex0x(&leaf),
                    // per-note published root (window root in the new path; the cumulative
                    // root in legacy); fall back to the last published root pre-publish.
                    "root": entry.map(|(r, _)| hex0x(r)).unwrap_or_else(|| current_root.clone()),
                    "claimable": entry.is_some(),
                    "proof": entry
                        .map(|(_, p)| p.iter().map(|n| hex0x(n)).collect::<Vec<_>>())
                        .unwrap_or_default(),
                })
            })
```
(`current_root` — the existing `l1_status.withdrawals_root` fallback string at `main.rs:1329-1334` — stays.)

- [ ] **Step 5: Update the legacy settle task for the new `withdraw_proofs` type**

In the legacy settle task, change the `SettleOut` tuple's proofs element (`main.rs:4534`) from:
```rust
                std::collections::BTreeMap<[u8; 32], Vec<[u8; 32]>>,
```
to:
```rust
                std::collections::BTreeMap<[u8; 32], (Digest, Vec<[u8; 32]>)>,
```
And the proofs-building loop (`main.rs:4607-4610`) from:
```rust
                        let mut proofs = std::collections::BTreeMap::new();
                        for (i, w) in surviving.iter().enumerate() {
                            proofs.insert(w.leaf(), merkle_proof(&leaves, i));
                        }
```
to:
```rust
                        let mut proofs = std::collections::BTreeMap::new();
                        for (i, w) in surviving.iter().enumerate() {
                            // legacy: every note shares the one cumulative root published this settle.
                            proofs.insert(w.leaf(), (wroot, merkle_proof(&leaves, i)));
                        }
```
(`wroot` is the `merkle_root(&leaves)` already computed at `main.rs:4580`.) The `gw.withdraw_proofs =
proofs;` assignment (`main.rs:4645`) now type-checks unchanged.

- [ ] **Step 6: Write the failing tests** (in `#[cfg(test)] mod tests`)

```rust
    #[test]
    fn account_withdraw_records_window_withdrawal() {
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        assert!(gw.window_withdrawals.is_empty());

        let to = [7u8; 20];
        let w = gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, to).expect("withdraw");

        assert_eq!(gw.window_withdrawals.len(), 1);
        assert_eq!(gw.window_withdrawals[0].to, to);
        assert_eq!(gw.window_withdrawals[0].nonce, w.nonce);
    }

    #[test]
    fn v1_withdrawals_json_serves_root_and_proof() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let w = gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();

        // seed a published (root, proof) for this leaf as the settle path would
        let leaf = w.leaf();
        let root = [0xAAu8; 32];
        gw.withdraw_proofs.insert(leaf, (root, vec![[0xBBu8; 32]]));
        let _ = owner;

        let json = gw.v1_withdrawals_json(&key).expect("json");
        let item = &json["withdrawals"][0];
        assert_eq!(item["claimable"], serde_json::json!(true));
        assert_eq!(item["root"], serde_json::json!(hex0x(&root)));
        assert_eq!(item["proof"], serde_json::json!([hex0x(&[0xBBu8; 32])]));
    }
```

- [ ] **Step 7: Run the tests to verify they fail, then pass**

Run: `cargo test -p gateway account_withdraw_records_window_withdrawal v1_withdrawals_json_serves_root_and_proof`
Expected: FAIL to compile before Steps 1-5, PASS after. Then run the FULL crate to confirm the type change
didn't break the legacy path: `cargo test -p gateway` — expected: all pass (0 failed). Then
`cargo clippy -p gateway` — expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): window_withdrawals + last_settled_root fields; withdraw_proofs carries (root, proof)"
```

---

## Task 3: `Gw::begin_window_settle` — nothing-to-settle check, desync guard, seal

**Files:**
- Modify: `crates/gateway/src/main.rs` (add the `begin_window_settle` method to the `impl Gw` block; add
  tests)

**Interfaces:**
- Consumes: `sequencer::WindowWitness`, `Withdrawal`, `Gw.last_settled_root`, `Gw.window_withdrawals`,
  `Gw.seq`.
- Produces: `Gw::begin_window_settle(&mut self, chain_batch_count: u64) -> Result<Option<(WindowWitness,
  Vec<Withdrawal>)>, String>` — `Ok(None)` when nothing changed since the last settle; `Err` when the
  window batch id would not match the on-chain count (no mutation performed); `Ok(Some((witness, ww)))`
  after sealing the window and taking its withdrawals.

- [ ] **Step 1: Add the import for `WindowWitness`**

At the top of `main.rs`, where `sequencer` items are imported, ensure `WindowWitness` is in scope (add to
the existing `use sequencer::{...};` or add `use sequencer::WindowWitness;`).

- [ ] **Step 2: Write the method** (inside an `impl Gw { .. }` block)

```rust
    /// Slice 3b-2a: begin a new-path window settle. Returns `None` if the engine root is
    /// unchanged since the last settle (nothing to prove). Errors WITHOUT mutating if the
    /// window's batch id would not match the on-chain `batchCount` (a desync a prior fault
    /// left behind — recovery is Slice 3b-3). Otherwise seals the window and takes its
    /// incremental withdrawal set.
    fn begin_window_settle(
        &mut self,
        chain_batch_count: u64,
    ) -> Result<Option<(WindowWitness, Vec<Withdrawal>)>, String> {
        if self.seq.state.state_root() == self.last_settled_root {
            return Ok(None); // no net state change since the last settle
        }
        // Pre-check the counter BEFORE sealing (which bumps it), so a desync leaves the
        // sequencer untouched instead of stranded ahead of the chain.
        let expected = self.seq.state.next_batch_id;
        if expected != chain_batch_count {
            return Err(format!(
                "batch_id desync: window {expected} vs chain {chain_batch_count} (recovery is 3b-3)"
            ));
        }
        let witness = self.seq.seal_window();
        let ww = core::mem::take(&mut self.window_withdrawals);
        Ok(Some((witness, ww)))
    }
```

- [ ] **Step 3: Write the failing tests**

```rust
    #[test]
    fn begin_window_settle_none_when_unchanged() {
        let mut gw = Gw::boot();
        // Force "no change since last settle": mark the current engine root as settled.
        gw.last_settled_root = gw.seq.state.state_root();
        let bc = gw.seq.state.next_batch_id;
        assert!(gw.begin_window_settle(bc).unwrap().is_none());
    }

    #[test]
    fn begin_window_settle_errors_on_desync_without_mutating() {
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let before_next = gw.seq.state.next_batch_id;
        let before_ww = gw.window_withdrawals.len();

        // chain count that does NOT match the window's next id → desync error, no mutation.
        let err = gw.begin_window_settle(before_next + 99).unwrap_err();
        assert!(err.contains("desync"));
        assert_eq!(gw.seq.state.next_batch_id, before_next); // not sealed
        assert_eq!(gw.window_withdrawals.len(), before_ww); // not drained
    }

    #[test]
    fn begin_window_settle_seals_and_takes_withdrawals() {
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;

        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        assert_eq!(witness.batch_id, bc);
        assert_eq!(ww.len(), 1); // the withdrawal was taken
        assert!(gw.window_withdrawals.is_empty()); // drained
        // the window op-log contains the real-exit withdraw op
        assert!(witness
            .ops
            .iter()
            .any(|op| matches!(op, perp_core::engine::BatchOp::Withdraw { to: Some(_), .. })));
    }
```
(If `BatchOp` is re-exported elsewhere, match the path the crate already uses; the import at the top of
`main.rs` for `BatchOp` is the canonical one — reuse it instead of the fully-qualified path if present.)

- [ ] **Step 4: Run the tests — fail, then pass**

Run: `cargo test -p gateway begin_window_settle`
Expected: compile-fail before Step 2, then 3 passed. Then `cargo test -p gateway` (full) — all pass;
`cargo clippy -p gateway` — clean.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): Gw::begin_window_settle (nothing-to-settle check + desync guard + seal)"
```

---

## Task 4: `prove_and_prepare` (withdrawal byte-match + proofs) + `commit_window_settle`

**Files:**
- Modify: `crates/gateway/src/prover_client.rs` (add `PreparedSettle` + `prove_and_prepare`),
  `crates/gateway/src/main.rs` (add `commit_window_settle` to `impl Gw`; tests)

**Interfaces:**
- Consumes: `ProverClient`, `ProveOutcome`, `WindowWitness`, `Withdrawal`, `perp_core::merkle::{merkle_root,
  merkle_proof}`, `Digest`.
- Produces:
  - `prover_client::PreparedSettle { outcome: ProveOutcome, withdraw_proofs:
    std::collections::BTreeMap<[u8;32], (Digest, Vec<[u8;32]>)> }`.
  - `prover_client::prove_and_prepare(client: &dyn ProverClient, witness: &WindowWitness, ww: &[Withdrawal])
    -> Result<PreparedSettle, String>` — proves, builds the window withdrawal tree, asserts its root ==
    `outcome.withdrawals_root`, and builds a per-note `(root, proof)` map.
  - `Gw::commit_window_settle(&mut self, batch_id: u64, ordered: Vec<Digest>, rejected: Vec<Digest>,
    prepared: PreparedSettle, l1_status: L1Status)` — applies the settle result to `Gw`.

- [ ] **Step 1: Add `PreparedSettle` + `prove_and_prepare` to `prover_client.rs`**

Append to `crates/gateway/src/prover_client.rs`:
```rust
use crate::withdrawals::Withdrawal;
use perp_core::merkle::{merkle_proof, merkle_root};
use std::collections::BTreeMap;

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
            hex::encode(wroot),
            hex::encode(outcome.withdrawals_root)
        ));
    }
    let mut withdraw_proofs = BTreeMap::new();
    for (i, w) in ww.iter().enumerate() {
        withdraw_proofs.insert(w.leaf(), (outcome.withdrawals_root, merkle_proof(&leaves, i)));
    }
    Ok(PreparedSettle { outcome, withdraw_proofs })
}
```
(`hex` is already a workspace dependency used across the gateway; if `prover_client.rs` lacks the import the
compiler will point it out — add `use hex;` is not needed, call `hex::encode` fully-qualified as above.)

- [ ] **Step 2: Add `commit_window_settle` to `impl Gw`** (`main.rs`)

```rust
    /// Slice 3b-2a: apply a completed new-path window settle to gateway state. Accumulates
    /// the window's per-note claim proofs (each window root is permanently claimable, so we
    /// EXTEND, never replace); advances `last_settled_root`; retains this batch's ordered/
    /// rejected hashes for DP-004 challenge answers (keyed by the on-chain batch id, which
    /// equals the window id); clears the now-redundant legacy pending accumulators; and
    /// records the published L1 status.
    fn commit_window_settle(
        &mut self,
        batch_id: u64,
        ordered: Vec<Digest>,
        rejected: Vec<Digest>,
        prepared: prover_client::PreparedSettle,
        l1_status: L1Status,
    ) {
        for (leaf, entry) in prepared.withdraw_proofs {
            self.withdraw_proofs.insert(leaf, entry);
        }
        self.last_settled_root = prepared.outcome.new_root;
        self.batch_orders.insert(batch_id, (ordered, rejected));
        // the window manifest is the source of truth for this batch's roots; the legacy
        // per-tick accumulators are unused by the new path — clear them so they can't grow.
        self.pending_ordered.clear();
        self.pending_rejected.clear();
        self.l1_status = Some(l1_status);
    }
```

- [ ] **Step 3: Write the failing tests**

```rust
    #[test]
    fn prove_and_prepare_withdrawal_tree_byte_matches_circuit() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        // two real-exit withdrawals in the window → a non-trivial withdrawals tree
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        gw.account_withdraw(&key, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;

        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        assert_eq!(ww.len(), 2);

        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prepare");

        // the byte-match invariant: the gateway tree root == the circuit's derived root
        let leaves: Vec<[u8; 32]> = ww.iter().map(|w| w.leaf()).collect();
        assert_eq!(merkle_root(&leaves), prepared.outcome.withdrawals_root);
        assert!(prepared.outcome.withdrawals_root != [0u8; 32]); // non-empty

        // each served proof verifies against that root the way the vault does
        for (i, w) in ww.iter().enumerate() {
            let (root, proof) = prepared.withdraw_proofs.get(&w.leaf()).expect("proof");
            assert_eq!(*root, prepared.outcome.withdrawals_root);
            assert!(withdrawals::verify(*root, w.leaf(), proof));
            assert_eq!(*proof, merkle_proof(&leaves, i));
        }
    }

    #[test]
    fn commit_window_settle_accumulates_and_advances() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;

        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        let ordered = witness.manifest.ordered.clone();
        let rejected: Vec<_> = witness.manifest.rejected.iter().map(|(h, _)| *h).collect();
        let batch_id = witness.batch_id;
        let leaf0 = ww[0].leaf();
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).unwrap();
        let new_root = prepared.outcome.new_root;

        let status = L1Status {
            settled_root: hex32(&new_root),
            batch_count: batch_id + 1,
            last_tx: "0xtx".into(),
            bond: "0".into(),
            withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
        };
        gw.commit_window_settle(batch_id, ordered, rejected, prepared, status);

        assert_eq!(gw.last_settled_root, new_root);
        assert!(gw.withdraw_proofs.contains_key(&leaf0));
        assert!(gw.batch_orders.contains_key(&batch_id));
        assert!(gw.pending_ordered.is_empty());
        assert!(gw.l1_status.is_some());
    }
```

- [ ] **Step 4: Run the tests — fail, then pass**

Run: `cargo test -p gateway prove_and_prepare_withdrawal_tree_byte_matches_circuit commit_window_settle_accumulates_and_advances`
Expected: compile-fail before Steps 1-2, then 2 passed. Then `cargo test -p gateway` (full) — all pass;
`cargo clippy -p gateway` — clean.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/prover_client.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): prove_and_prepare (withdrawal byte-match + per-note proofs) + commit_window_settle"
```

---

## Task 5: `L1::settle_proved` + `PROVER_URL` wiring + the async new-path branch

**Files:**
- Modify: `crates/gateway/src/l1.rs` (add `settle_proved`), `crates/gateway/src/main.rs` (add
  `prover_from_str` + `prover_from_env`; `App.prover` field; build+thread the client in `main`; the settle
  task's new-path branch; `test_app()` gets `prover: None`; a `prover_from_str` test)

**Interfaces:**
- Consumes: `prover_client::{ProverClient, MockProverClient, ProveOutcome, PreparedSettle, prove_and_prepare}`,
  `Gw::begin_window_settle`, `Gw::commit_window_settle`, `L1`, `hex32`.
- Produces: `L1::settle_proved(&self, out: &ProveOutcome) -> Result<String, String>`;
  `prover_from_str(v: Option<&str>) -> Result<Option<std::sync::Arc<dyn ProverClient>>, String>`;
  `App.prover: Option<std::sync::Arc<dyn ProverClient>>`.

- [ ] **Step 1: Add `L1::settle_proved`** (`crates/gateway/src/l1.rs`, next to `settle`)

```rust
    /// Slice 3b-2a: submit prover-derived roots + a real (or mock) proof directly — no
    /// `publicCommitment` synthesis. `out.proof` is the ZK proof (== the commitment bytes
    /// for MockProverClient, which the on-chain MockZkVerifier accepts).
    pub fn settle_proved(&self, out: &crate::prover_client::ProveOutcome) -> Result<String, String> {
        let proof_hex = format!("0x{}", hex::encode(&out.proof));
        self.send(
            &self.settlement.clone(),
            "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes)",
            &[
                &crate::hex32(&out.prev_root),
                &crate::hex32(&out.manifest_hash),
                &crate::hex32(&out.new_root),
                &crate::hex32(&out.ordered_root),
                &crate::hex32(&out.withdrawals_root),
                &crate::hex32(&out.rejected_root),
                &proof_hex,
            ],
        )
    }
```
(`hex32` lives in `main.rs`; reference it as `crate::hex32`. If `hex32` is not `pub`, make it
`pub(crate) fn hex32(...)` — a visibility-only change, no behavior change.)

- [ ] **Step 2: Add the `PROVER_URL` parser + `App.prover` field**

In `main.rs`, add the pure, testable parser (near the other free helpers like `production_mode`):
```rust
/// Slice 3b-2a: select the settle path's prover client from `PROVER_URL`.
/// unset/empty → legacy path (None); "mock" → in-process MockProverClient;
/// any URL → error (HttpProverClient is Slice 3b-2b).
fn prover_from_str(
    v: Option<&str>,
) -> Result<Option<std::sync::Arc<dyn prover_client::ProverClient>>, String> {
    match v {
        None | Some("") => Ok(None),
        Some("mock") => Ok(Some(std::sync::Arc::new(prover_client::MockProverClient))),
        Some(url) => Err(format!(
            "PROVER_URL={url}: HttpProverClient is Slice 3b-2b (not implemented); use `mock` or unset"
        )),
    }
}

fn prover_from_env() -> Result<Option<std::sync::Arc<dyn prover_client::ProverClient>>, String> {
    prover_from_str(std::env::var("PROVER_URL").ok().as_deref())
}
```
Add the field to `App` (`main.rs:2959`), after `l1: Option<L1>,`:
```rust
    /// Slice 3b-2a: the settle path's prover client (None ⇒ legacy cumulative+mock path).
    prover: Option<std::sync::Arc<dyn prover_client::ProverClient>>,
```
Update `test_app()` (`main.rs:4696`) to add `prover: None,` to its `App { .. }` literal.

- [ ] **Step 3: Build + thread the client in `main`**

Near `let l1 = L1::from_env();` (`main.rs:4133`), add:
```rust
    let prover = match prover_from_env() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[prover] {e}");
            std::process::exit(1);
        }
    };
    if prover.is_some() {
        println!("[prover] window-settle path ON (PROVER_URL)");
    }
```
In the `App { .. }` construction (`main.rs:4250`), add `prover: prover.clone(),`. The settle task is
spawned inside `if let Some(l1) = l1 {` (`main.rs:4450`) and captures `app`; it reads the client via
`app.prover` (already inside `App`), so no extra capture is needed.

- [ ] **Step 4: Add the new-path branch to the settle task**

Inside the settle loop (`main.rs`, right after `iv.tick().await;` and before the legacy
`let (new_root, manifest, ...) = { ... };` read), insert the new-path branch. It mirrors the legacy body's
structure (RPC in `spawn_blocking`, mutate under the lock) but seals+proves+`settle_proved`s:

```rust
                if let Some(client) = app.prover.clone() {
                    // (A) read the on-chain batch count (RPC, no lock)
                    let l1c = l1.clone();
                    let bc = match tokio::task::spawn_blocking(move || l1c.batch_count()).await {
                        Ok(Ok(bc)) => bc,
                        Ok(Err(e)) => { eprintln!("[l1] batch_count: {e}"); continue; }
                        Err(e) => { eprintln!("[l1] batch_count join: {e}"); continue; }
                    };
                    // (B) seal the window under the lock (or skip)
                    let begun = {
                        let mut gw = app.gw.lock().await;
                        match gw.begin_window_settle(bc) {
                            Ok(Some(x)) => Some(x),
                            Ok(None) => None,
                            Err(e) => { eprintln!("[l1] window settle skipped: {e}"); None }
                        }
                    };
                    let Some((witness, ww)) = begun else { continue; };
                    // capture the manifest's ordered/rejected for the DP-004 challenge store
                    let ordered = witness.manifest.ordered.clone();
                    let rejected: Vec<Digest> =
                        witness.manifest.rejected.iter().map(|(h, _)| *h).collect();
                    let batch_id = witness.batch_id;
                    // (C) prove + settle (lock-free)
                    let l1c = l1.clone();
                    let res = tokio::task::spawn_blocking(
                        move || -> Result<(prover_client::PreparedSettle, String, u128), String> {
                            let prepared =
                                prover_client::prove_and_prepare(client.as_ref(), &witness, &ww)?;
                            let tx = l1c.settle_proved(&prepared.outcome)?;
                            let bond = l1c.sequencer_bond().unwrap_or(0);
                            Ok((prepared, tx, bond))
                        },
                    )
                    .await;
                    match res {
                        Ok(Ok((prepared, tx, bond))) => {
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
                            }
                            let snap = { app.gw.lock().await.snapshot() };
                            let _ = app.tx.send(
                                serde_json::to_string(&WsMsg::State { state: snap }).unwrap(),
                            );
                        }
                        Ok(Err(e)) => eprintln!("[l1] window settle failed: {e}"),
                        Err(e) => eprintln!("[l1] window settle join: {e}"),
                    }
                    continue; // new path handled this tick; skip the legacy body
                }
```
Everything below this branch (the existing legacy body) is unchanged and runs only when `app.prover` is
`None`.

- [ ] **Step 5: Write the failing test** (the pure parser; the async loop is validated live in 3b-2b)

```rust
    #[test]
    fn prover_from_str_selects_path() {
        assert!(prover_from_str(None).unwrap().is_none());
        assert!(prover_from_str(Some("")).unwrap().is_none());
        assert!(prover_from_str(Some("mock")).unwrap().is_some());
        let err = prover_from_str(Some("http://prover.local:8091")).unwrap_err();
        assert!(err.contains("3b-2b"));
    }
```

- [ ] **Step 6: Run the test + full regression**

Run: `cargo test -p gateway prover_from_str_selects_path`
Expected: compile-fail before Steps 1-4, then PASS. Then the full crate to confirm the legacy path and all
prior tasks still hold: `cargo test -p gateway` — expected: all pass (0 failed). Then
`cargo build -p gateway` (confirm the async branch compiles) and `cargo clippy -p gateway` — expected: clean.

- [ ] **Step 7: Whole-workspace check**

Run: `cargo test` (workspace) and `cargo clippy --workspace` from the repo root.
Expected: all pass, no warnings — confirms no perp-core/sequencer/other-crate regression (there should be
none; this slice only touched `crates/gateway`).

- [ ] **Step 8: Commit**

```bash
git add crates/gateway/src/l1.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): L1::settle_proved + PROVER_URL window-settle branch (mock client, CI-tested)"
```

---

## Self-Review (author checklist — completed)

**1. Spec coverage** (against `2026-07-08-zk-p2-slice3b2a-gateway-window-settle-design.md`):
- §3 flag `PROVER_URL` three states → Task 5 `prover_from_str` (+ test). ✅
- §4.1 `ProverClient`/`ProveOutcome`/`MockProverClient` → Task 1. ✅
- §4.2 settle rewiring (local settle-needed check, seal, align guard, prove, settle_proved, tree+proofs,
  commit) → Tasks 3 (begin+guard), 4 (prove+tree+proofs+commit), 5 (async branch + settle_proved). ✅
- §4.3 incremental withdrawals (`window_withdrawals`, per-window tree, `withdraw_proofs` (root,proof),
  `v1_withdrawals_json`, drop cumulative re-prune in new path) → Task 2 (fields/JSON) + Task 4
  (tree/proofs) + Task 5 (commit accumulates, no cumulative rebuild). ✅
- §4.4 `L1::settle_proved` → Task 5. ✅
- §4.5 counter alignment (happy path) + fault-path guard → Task 3 desync guard + Task 5 skip+log. ✅
- §5 merge gate (mock==derive_roots; withdrawals byte-match; full new-path; legacy regression) → Task 1
  test, Task 4 byte-match test, Tasks 3-4 method tests, Task 5 full-crate regression. ✅
- §6 file map (create `prover_client.rs`; modify `main.rs`, `l1.rs`; no other crate) → matches Tasks. ✅
- §7 non-goals (no HTTP/real proof/GB10; no rollback/receipt re-keying; no contract change) → respected;
  URL state errors, fault-path only guards, no Solidity touched. ✅
- **Refinement beyond the spec's prose:** the new-path `commit_window_settle` also populates
  `batch_orders[batch_id]` (from the window manifest) and clears `pending_ordered`/`pending_rejected`. This
  is required so the new path does not regress the DP-004 inclusion-challenge answer path (which reads
  `batch_orders`) — it is challenge-store bookkeeping, distinct from the sequencer-internal receipt/
  `InclusionRecord` re-keying that §7 defers to 3b-3.

**2. Placeholder scan:** no TBD/TODO; every code step shows complete code; every test shows real
assertions. ✅

**3. Type consistency:** `ProveOutcome`, `PreparedSettle`, `withdraw_proofs: BTreeMap<[u8;32],(Digest,
Vec<[u8;32]>)>`, `begin_window_settle(u64) -> Result<Option<(WindowWitness, Vec<Withdrawal>)>, String>`,
`commit_window_settle(u64, Vec<Digest>, Vec<Digest>, PreparedSettle, L1Status)`, `prove_and_prepare(&dyn
ProverClient, &WindowWitness, &[Withdrawal]) -> Result<PreparedSettle, String>`, `settle_proved(&ProveOutcome)
-> Result<String,String>`, `prover_from_str(Option<&str>) -> Result<Option<Arc<dyn ProverClient>>, String>`
— names/types used identically across tasks. ✅
