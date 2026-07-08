# ZK P2 Slice 3b-4 — Off-Chain Receipt/Inclusion Re-Keying — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an enclave-signed `window_id` (Counter B) to the receipt and a finality-pruned A→B map so a user can reconcile a receipt against the on-chain window/challenge — additively (Approach B), keeping the per-tick Counter-A view.

**Architecture:** `Receipt` gains a signed `window_id` = `state.next_batch_id` at issue time (the rollback-stable on-chain window it settles into). The sequencer records a per-tick `tick_window: BTreeMap<CounterA, CounterB>` in `seal_batch`, pruned in `mark_settled`/`mark_failed`. The gateway surfaces it: `WReceipt.windowId`, `WBatch.windowId`, an `openWindowId` in the status JSON, and a `GET /v1/batch/:id` endpoint.

**Tech Stack:** Rust (perp-core, sequencer, gateway crates), axum (gateway routes), serde/serde_json.

## Global Constraints

- **`Receipt.window_id: u64`** = `self.state.next_batch_id` (Counter B) read in `issue_receipt`. Bound into `signing_digest` (appended after `batch_id_hint`). `batch_id_hint` (Counter A) is **preserved** everywhere it exists.
- **`tick_window: BTreeMap<u64, u64>`** on `Sequencer` (Counter-A tick id → Counter-B window). Populated in `seal_batch`: `self.tick_window.insert(batch_id, self.state.next_batch_id)`. Pruned: `mark_settled` → `split_off(&(batch_id+1))` (mirror `batch_orders`); `mark_failed` → `remove(b)` per dropped batch. **In-memory only** (the `Sequencer` is not boot-persisted — see `lib.rs:300-301`; `#[serde(default)]` so any snapshot serde still round-trips).
- **Accessors:** `current_window_id(&self) -> u64 { self.state.next_batch_id }`; `window_for_tick(&self, tick_batch: u64) -> Option<u64> { self.tick_window.get(&tick_batch).copied() }`.
- **Gateway surfacing:** `WReceipt.window_id` (JSON `windowId`) at every `WReceipt {` construction; `WBatch.window_id: Option<u64>` (JSON `windowId`) from `seq.window_for_tick(bid)`; `"openWindowId": self.seq.current_window_id()` in `v1_status_json`; `GET /v1/batch/:id` → `{counterA, windowId, settled}` where `settled = windowId.is_some_and(|m| m < batch_count)` and `batch_count = self.l1_status.as_ref().map(|s| s.batch_count).unwrap_or(0)`.
- **Out of scope / untouched:** internal Counter-A machinery (`snapshots`, soft-finality, `InclusionRecord`/`inclusion_violations`, liq/ADL tags, `SealedBatch`), the note-archive keying, and all contracts.
- Run tests: `cargo test -p perp-core`, `cargo test -p sequencer`, `cargo test -p gateway`, then `cargo test --workspace` + `cargo clippy --workspace`.

---

## Task 1: Signed `window_id` on the receipt + the A→B map (perp-core + sequencer)

Combined because `Receipt`'s only producer is `issue_receipt` — splitting would leave the sequencer crate non-compiling. After this task the whole workspace still compiles (the gateway's `WReceipt` is a separate struct, unaffected until Task 2).

**Files:**
- Modify: `crates/perp-core/src/order.rs` (Receipt struct + signing_digest + a test).
- Modify: `crates/sequencer/src/lib.rs` (field + init + issue_receipt + seal_batch + mark_settled + mark_failed + accessors + tests).

**Interfaces:**
- Produces: `Receipt.window_id: u64`; `Sequencer::current_window_id(&self) -> u64`; `Sequencer::window_for_tick(&self, u64) -> Option<u64>`. (Task 2 consumes all three.)

- [ ] **Step 1: perp-core — failing test that `signing_digest` binds `window_id`**

In `crates/perp-core/src/order.rs`, in the `#[cfg(test)] mod tests` (use the same `Hasher` the file's other tests use — the crate's `Keccak256`):

```rust
    #[test]
    fn signing_digest_binds_window_id() {
        let base = Receipt {
            order_hash: [1u8; 32],
            seq_no: 7,
            recv_time_ms: 100,
            batch_id_hint: 3,
            window_id: 1,
        };
        let other = Receipt { window_id: 2, ..base };
        assert_ne!(
            base.signing_digest::<Keccak256>(),
            other.signing_digest::<Keccak256>()
        );
    }
```

- [ ] **Step 2: Run it — fails to compile (`window_id` absent)**

Run: `cargo test -p perp-core signing_digest_binds_window_id`
Expected: FAIL — no field `window_id` on `Receipt`.

- [ ] **Step 3: perp-core — add the field + bind it in the digest**

`crates/perp-core/src/order.rs`, `Receipt` struct (currently ends `pub batch_id_hint: u64,`):

```rust
pub struct Receipt {
    pub order_hash: Digest,
    pub seq_no: u64,
    pub recv_time_ms: u64,
    pub batch_id_hint: u64,
    /// The on-chain window id (Counter B, `state.next_batch_id` at issue time) this order
    /// settles into — the id space of the on-chain `batchCount` / inclusion challenge.
    /// Enclave-signed (bound in `signing_digest`), so it is a verifiable promise (Slice 3b-4).
    pub window_id: u64,
}
```

`signing_digest` — append `window_id` after `batch_id_hint`:

```rust
    pub fn signing_digest<H: Hasher>(&self) -> Digest {
        H::hash_words(
            Domain::OrderHash,
            &[
                self.order_hash,
                word_u64(self.seq_no),
                word_u64(self.recv_time_ms),
                word_u64(self.batch_id_hint),
                word_u64(self.window_id),
            ],
        )
    }
```

- [ ] **Step 4: Run the perp-core test — passes**

Run: `cargo test -p perp-core signing_digest_binds_window_id` → PASS.
(`cargo test -p perp-core` overall may still fail to COMPILE only if a perp-core-internal `Receipt {` literal omits `window_id` — fix any such in-crate construction sites by adding `window_id`. The sequencer's `issue_receipt` is fixed in Step 6.)

- [ ] **Step 5: sequencer — add the `tick_window` field + init + accessors**

`crates/sequencer/src/lib.rs`, in the `Sequencer` struct right after the `batch_orders` field (`:283`):

```rust
    /// Maps each per-tick Counter-A batch id to the Counter-B window id (`state.next_batch_id`)
    /// it settles into, so a bare tick id (a `WBatch`, a log line) without a receipt can be
    /// reconciled to its on-chain window. In-memory only; shares the finality lifecycle of
    /// `batch_orders` (pruned in `mark_settled`/`mark_failed`) so it stays bounded (Slice 3b-4).
    #[serde(default)]
    tick_window: BTreeMap<u64, u64>,
```

In `Sequencer::new` (after `next_batch_id: 0,` at `:320`, keep field order consistent with the struct — place near the other map inits):

```rust
            tick_window: BTreeMap::new(),
```

Accessors — right after `current_batch_id` (`:403-405`):

```rust
    /// The currently open window id (Counter B) — the `batchCount`-space id that orders
    /// sequenced now will settle into. Directly comparable to the on-chain `batchCount`.
    pub fn current_window_id(&self) -> u64 {
        self.state.next_batch_id
    }

    /// The on-chain window (Counter B) a per-tick batch (Counter A) settled into, if still
    /// mapped. `None` once pruned (its soft-finality settled), or for an unknown/future tick.
    pub fn window_for_tick(&self, tick_batch: u64) -> Option<u64> {
        self.tick_window.get(&tick_batch).copied()
    }
```

- [ ] **Step 6: sequencer — stamp `window_id` in `issue_receipt` + record the map in `seal_batch` + prune**

`issue_receipt` (`:439-444`) — add `window_id`:

```rust
        let receipt = Receipt {
            order_hash,
            seq_no,
            recv_time_ms: now_ms,
            batch_id_hint: self.next_batch_id,
            window_id: self.state.next_batch_id,
        };
```

`seal_batch` — right after the `batch_orders.insert(batch_id, ...)` (`:832-833`), before the Counter-A bump:

```rust
        self.batch_orders
            .insert(batch_id, settled_order_hashes.clone());
        // Record which on-chain window (Counter B) this per-tick batch (Counter A) settles
        // into, for off-chain receipt/inclusion reconciliation (Slice 3b-4). state.next_batch_id
        // is the open window and is stable across the window's ticks.
        self.tick_window.insert(batch_id, self.state.next_batch_id);
```

`mark_settled` — after the `batch_orders` prune (`:977`):

```rust
        self.batch_orders = self.batch_orders.split_off(&(batch_id + 1));
        // the A→B map shares that finality lifecycle — drop settled tick ids too.
        self.tick_window = self.tick_window.split_off(&(batch_id + 1));
```

`mark_failed` — inside the `for b in &dropped` loop (`:994-1005`), alongside `self.snapshots.remove(b);`:

```rust
            self.snapshots.remove(b);
            // the dropped ticks are being re-sequenced; drop their stale window mapping.
            self.tick_window.remove(b);
```

- [ ] **Step 7: sequencer — tests (window_id, map exactness, rollback, prune)**

In `crates/sequencer/src/lib.rs` `#[cfg(test)] mod tests`, using the module's existing Sequencer construction + `seal_batch`/`seal_window`/`apply` helpers (mirror the nearest existing test's setup), add:

```rust
    #[test]
    fn receipt_window_id_is_open_window_and_map_tracks_it() {
        let mut seq = test_sequencer(); // reuse the module's existing constructor helper
        // window M = state.next_batch_id at the start.
        let m = seq.state.next_batch_id;
        let sealed0 = seq.seal_batch(&sample_orders(), now());
        // every receipt issued this tick carries window_id == the open window M.
        for sr in &sealed0.receipts {
            assert_eq!(sr.receipt.window_id, m);
        }
        // the A→B map records this tick (Counter A) -> window M.
        assert_eq!(seq.window_for_tick(sealed0.batch_id), Some(m));
        // a second tick in the same window still maps to M and current_window_id == M.
        let sealed1 = seq.seal_batch(&sample_orders(), now());
        assert_eq!(seq.window_for_tick(sealed1.batch_id), Some(m));
        assert_eq!(seq.current_window_id(), m);
        // close the window: Counter B advances; the next tick maps to M+1.
        let _w = seq.seal_window();
        assert_eq!(seq.current_window_id(), m + 1);
        let sealed2 = seq.seal_batch(&sample_orders(), now());
        assert_eq!(seq.window_for_tick(sealed2.batch_id), Some(m + 1));
    }

    #[test]
    fn rollback_keeps_the_window_map_correct() {
        let mut seq = test_sequencer();
        let m = seq.state.next_batch_id;
        let s = seq.seal_batch(&sample_orders(), now());
        let w = seq.seal_window(); // Counter B -> m+1
        seq.rollback_window(&w);    // restore Counter B to m
        assert_eq!(seq.current_window_id(), m);
        // the failed window's ticks still map to m; re-sealing keeps them at m.
        assert_eq!(seq.window_for_tick(s.batch_id), Some(m));
    }

    #[test]
    fn mark_settled_prunes_the_window_map() {
        let mut seq = test_sequencer();
        let s = seq.seal_batch(&sample_orders(), now());
        assert!(seq.window_for_tick(s.batch_id).is_some());
        seq.mark_settled(s.batch_id);
        assert!(seq.window_for_tick(s.batch_id).is_none()); // pruned with batch_orders
    }
```

(Adapt `test_sequencer()`/`sample_orders()`/`now()` to the actual helpers the existing tests use — read the surrounding `mod tests` first. If a test needs at least one settleable order for `batch_orders`/`tick_window` to be populated, mirror how the nearest existing `seal_batch` test builds its orders.)

- [ ] **Step 8: Run the sequencer + perp-core suites**

Run: `cargo test -p perp-core` and `cargo test -p sequencer` → all PASS. Then `cargo build --workspace` (the gateway still compiles — `WReceipt` unaffected). `cargo clippy -p sequencer -p perp-core` clean.

- [ ] **Step 9: Commit**

```bash
git add crates/perp-core/src/order.rs crates/sequencer/src/lib.rs
git commit -m "feat(sequencer): signed window_id on the receipt + finality-pruned A->B tick_window map"
```

---

## Task 2: Surface the window id in the gateway (WReceipt, WBatch, status, endpoint)

**Files:**
- Modify: `crates/gateway/src/main.rs` (WReceipt + all its construction sites; WBatch + annotation; v1_status_json; new v1_batch_json + get_v1_batch handler + route; tests).

**Interfaces:**
- Consumes: `Receipt.window_id`, `Sequencer::current_window_id`, `Sequencer::window_for_tick` (Task 1).

- [ ] **Step 1: `WReceipt` gains `window_id` + every construction site sets it**

`crates/gateway/src/main.rs`, `WReceipt` (`:398-405`):

```rust
struct WReceipt {
    order_hash: String,
    seq_no: u64,
    recv_time_ms: u64,
    batch_id_hint: u64,
    window_id: u64,
}
```

Then update EVERY `WReceipt {` literal (find them all: `git grep -n "WReceipt {" crates/gateway/src/main.rs` — there are at least the two at `:1773` and `~:2411`, both destructuring a `let r = &signed.receipt;`). Add to each, alongside `batch_id_hint: r.batch_id_hint,`:

```rust
            window_id: r.window_id,
```

- [ ] **Step 2: Run the gateway build — passes**

Run: `cargo build -p gateway`
Expected: PASS (every `WReceipt` literal now sets `window_id`; if the compiler flags a missing-field literal, that's an un-updated construction site — fix it).

- [ ] **Step 3: `WBatch` gains `window_id` + the batches builder annotates it**

`WBatch` (`:417-426`):

```rust
struct WBatch {
    batch_id: u64,
    window_id: Option<u64>,
    order_count: usize,
    manifest_hash: String,
    ordered_root: String,
    finality: String,
    sealed_ms: u64,
}
```

The batches builder (`:2939-2946`) — set `window_id` from the map (the `bid` here is the Counter-A `batch_id_hint`):

```rust
                WBatch {
                    batch_id: bid,
                    window_id: self.seq.window_for_tick(bid),
                    order_count: os.len(),
                    manifest_hash: pseudo_hash(&format!("manifest:{hashes}")),
                    ordered_root: pseudo_hash(&format!("ordered:{hashes}")),
                    finality: fin,
                    sealed_ms,
                }
```

- [ ] **Step 4: `v1_status_json` gains `openWindowId`**

`v1_status_json` (`:1931-1938`) — add the line after `nextBatchId`:

```rust
    fn v1_status_json(&self) -> serde_json::Value {
        serde_json::json!({
            "mode": if self.seq.state.mode == Mode::CloseOnly { "CloseOnly" } else { "Normal" },
            "insuranceFund": self.seq.state.insurance_fund.to_string(),
            "treasury": self.seq.state.treasury.to_string(),
            "nextBatchId": self.seq.current_batch_id(),
            "openWindowId": self.seq.current_window_id(),
            "accounts": self.accounts.len(),
        })
    }
```

- [ ] **Step 5: Write the failing test for `v1_batch_json`**

In `crates/gateway/src/main.rs` `#[cfg(test)] mod tests`, using the module's existing Gw construction helper (mirror the nearest existing gateway test), add:

```rust
    #[test]
    fn v1_batch_json_reconciles_tick_to_window() {
        let mut gw = test_gw(); // reuse the module's existing Gw test constructor
        // seal a tick so the sequencer records a tick->window entry.
        let s = gw.seq.seal_batch(&sample_orders(), now());
        let window = gw.seq.window_for_tick(s.batch_id).unwrap();
        // no L1 status yet (batch_count defaults to 0) -> not settled.
        let v = gw.v1_batch_json(s.batch_id);
        assert_eq!(v["counterA"], s.batch_id);
        assert_eq!(v["windowId"], window);
        assert_eq!(v["settled"], false);
        // an unknown tick id -> windowId null, settled false.
        let u = gw.v1_batch_json(s.batch_id + 9999);
        assert!(u["windowId"].is_null());
        assert_eq!(u["settled"], false);
    }
```

(Adapt `test_gw()`/`sample_orders()`/`now()` to the actual helpers — read the surrounding `mod tests`. If the harness can set an `l1_status` with a `batch_count > window`, add an assertion that `settled` becomes `true`; otherwise the not-settled path is sufficient.)

- [ ] **Step 6: Run it — fails (`v1_batch_json` absent)**

Run: `cargo test -p gateway v1_batch_json_reconciles_tick_to_window`
Expected: FAIL — no method `v1_batch_json`.

- [ ] **Step 7: Add `v1_batch_json` + the handler + the route**

`v1_batch_json` — a method on the same impl as `v1_status_json` (right after it):

```rust
    /// Reconcile a per-tick Counter-A batch id to its on-chain window (Counter B) + settle state.
    fn v1_batch_json(&self, tick_batch: u64) -> serde_json::Value {
        let window = self.seq.window_for_tick(tick_batch);
        let batch_count = self.l1_status.as_ref().map(|s| s.batch_count).unwrap_or(0);
        // window M has settled on-chain once batchCount has advanced past it.
        let settled = window.is_some_and(|m| m < batch_count);
        serde_json::json!({
            "counterA": tick_batch,
            "windowId": window,
            "settled": settled,
        })
    }
```

The handler (near `get_v1_status`, `:3744-3746`, mirroring the `Path<u64>` pattern of `get_v1_market` `:3661`):

```rust
async fn get_v1_batch(State(app): State<Shared>, Path(id): Path<u64>) -> impl IntoResponse {
    Json(app.gw.lock().await.v1_batch_json(id))
}
```

The route — in the `/v1` block, after `.route("/v1/system/status", get(get_v1_status))` (`:4265`):

```rust
        .route("/v1/batch/:id", get(get_v1_batch))
```

- [ ] **Step 8: Run the gateway test — passes**

Run: `cargo test -p gateway v1_batch_json_reconciles_tick_to_window` → PASS.

- [ ] **Step 9: Full gateway + workspace gates**

Run: `cargo test -p gateway` (all prior 84 + the new one green; `batch_id_hint` + per-tick grouping unchanged — regression), then `cargo test --workspace` and `cargo clippy --workspace` from the repo root → all pass, no warnings.

- [ ] **Step 10: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): surface window_id (WReceipt/WBatch), openWindowId status, GET /v1/batch/:id reconciliation"
```

---

## Self-Review (author checklist — completed)

**1. Spec coverage** (against `2026-07-08-zk-p2-slice3b4-offchain-receipt-rekeying-design.md`):
- §4.1 signed `window_id` (Receipt + signing_digest + issue_receipt + WReceipt) → Task 1 Steps 1-6, Task 2 Step 1. ✅
- §4.2 A→B map (field + populate + finality prune + rollback-correct + in-memory) → Task 1 Steps 5-6. ✅
- §4.3 surfacing (WBatch.windowId, openWindowId, GET /v1/batch/:id) → Task 2 Steps 3-7. ✅
- §4.4 reconciliation (settled = window < batchCount) → Task 2 Step 7 (`v1_batch_json`). ✅
- §5 untouched internals / note-archive out of scope → nothing in the tasks touches them. ✅
- §6 testing (window_id, signing bind, map exactness, rollback, prune, surfacing) → Task 1 Steps 1/7, Task 2 Steps 5/9. ✅

**2. Placeholder scan:** the sequencer/gateway test steps reference existing harness helpers (`test_sequencer`/`test_gw`/`sample_orders`/`now`) because those crates' `Sequencer`/`Gw` constructors are non-trivial — the implementer reuses the module's real helpers; the assertion bodies are complete. Every code edit shows full verbatim code. No TBD/TODO.

**3. Type consistency:** `window_id: u64` (Receipt, WReceipt) and `window_id: Option<u64>` (WBatch — nullable annotation); `current_window_id() -> u64`, `window_for_tick() -> Option<u64>`; `settled = window.is_some_and(|m| m < batch_count)` matches §4.4. `tick_window` keyed by Counter A, valued Counter B, pruned by `split_off(&(batch_id+1))` (mark_settled) / `remove(b)` (mark_failed) — consistent across steps.
