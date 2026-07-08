# ZK Verifier P2 — Slice 3b-1: Window Batch Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The sequencer accumulates a window's ops across ticks and produces one `WindowWitness { batch_id, pre_state, ops, manifest }` per `seal_window()` such that `derive_roots(pre_state, ops, manifest).new_state_root == the live window-end state_root`, advancing `state.next_batch_id` exactly once per window.

**Architecture:** `seal_batch` (per 700ms tick) keeps matching/settling/maintenance but now (a) appends its ops + ordered/rejected to a window accumulator and (b) no longer bumps `state.next_batch_id`. A new `seal_window()` builds the combined window manifest, bumps the counter once, and drains the accumulator into the witness. This reworks Slice 3a's per-tick witness/counter to per-window; 3a's op-emission (`MaintenanceOutcome.ops`, `seal_batch`'s fill collection) is reused to feed the accumulator. One cohesive change in `crates/sequencer/src/lib.rs`.

**Tech Stack:** Rust (std), `perp-core` (`BatchOp`, `BatchManifest`, `commitment::derive_roots`), `serde`.

**Spec:** `docs/superpowers/specs/2026-07-08-zk-p2-slice3b1-window-batch-model-design.md`

## Global Constraints

- **Per-window counter, not per-tick.** DELETE `seal_batch`'s `self.state.next_batch_id += 1;` (currently `lib.rs:808`, the 3a bump). `seal_window` adds the single per-window bump. The separate SEQUENCER field bump `self.next_batch_id += 1;` (`:810`) STAYS (internal per-tick id for receipts/inclusion).
- **Faithful, complete window op-log.** `window_ops` must contain EVERY op applied since the window opened, in application order: out-of-band deposits (`Sequencer::apply`), plus each tick's `[applied fills] ++ maintenance ops`. A missing op diverges the replayed root.
- **pre_state consistency.** `window_start_state` (captured at window open / after each `seal_window`) is the witness pre-state; its root == the combined `manifest.previous_state_root` and its `next_batch_id` == the window `batch_id`, so `derive_roots` accepts it (`commitment.rs:56-58`). `derive_roots` runs `apply_batch(ops)` which bumps the counter once → matches the live counter after `seal_window`'s single bump.
- **Reuses, does not re-implement, 3a's op-emission.** Keep `MaintenanceOutcome.ops` and `seal_batch`'s local `ops = [applied fills] ++ maintenance.ops`. Only its *destination* changes: append to `window_ops` instead of inserting into the per-tick `batch_ops` map (which is removed).
- **`Sequencer` is NOT persisted** (grep-confirmed: no serialize/deserialize of a `Sequencer` in `crates/node` or `crates/gateway`). So no old-snapshot migration concern. `DefaultState` has NO `Default` impl, so `window_start_state` is a plain serde field (it cannot and need not carry `#[serde(default)]`); the `Vec` accumulators carry `#[serde(default)]`.
- **Out of scope (do NOT touch):** `mark_settled`/`mark_failed`/`snapshots` rollback semantics stay per-tick (per-window rollback is deferred to 3b-2); inclusion/receipt re-keying stays per-tick (`seal_batch`'s internal `batch_id` uses the sequencer field); no gateway/network/contract/perp-core change; matching fairness stays Proof-v2. `seal_batch`'s own per-tick `BatchManifest`/`manifest_hash`/`SealedBatch` fields stay (internal).
- Model policy: NO Haiku; Fable quota full → Opus (delicate counter/witness refactor + intricate multi-tick test).

## File Structure

- `crates/sequencer/src/lib.rs` **(modify)** — window accumulator fields + `new` init; `WindowWitness` + `seal_window`; `seal_batch` append + remove counter bump + remove `batch_ops` insert; `Sequencer::apply` append; remove `batch_ops` field + `batch_witness` accessor + the two prunes.
- `crates/sequencer/tests/spine.rs` **(modify)** — window merge gate + two-tick round-trip; remove the two 3a per-tick `batch_witness_*` tests (superseded). Keep `run_maintenance_ops_replay_reproduces_state`.

---

### Task 1: Window batch model (accumulator + `seal_window` + merge gate)

**Files:**
- Modify: `crates/sequencer/src/lib.rs`
- Test: `crates/sequencer/tests/spine.rs`

**Interfaces:**
- Consumes: `perp_core::commitment::derive_roots(&mut DefaultState, &[BatchOp], &BatchManifest) -> Result<DerivedRoots, EngineError>`; `BatchManifest` (fields per `seal_batch`'s existing construction); `MaintenanceOutcome.ops` (3a).
- Produces: `pub struct WindowWitness { batch_id: u64, pre_state: DefaultState, ops: Vec<BatchOp>, manifest: BatchManifest }`; `pub fn seal_window(&mut self) -> WindowWitness`.

- [ ] **Step 1: Write the failing merge-gate test** in `crates/sequencer/tests/spine.rs`. A multi-tick window with a mid-window deposit + fill + funding + liquidation replays to the live window-end root. Adapt the account/order/oracle setup from the existing `batch_witness_replays_to_sealed_roots_with_fill_funding_liquidation` test (it already builds a fill + funding + liquidation) — but spread across ticks and add a mid-window `apply(Deposit)`:

```rust
#[test]
fn seal_window_replays_multi_tick_window_to_live_root() {
    // Setup adapted from batch_witness_replays_*: funded traders whose orders match
    // (the fill), plus a position made underwater by an oracle move (the liquidation).
    let mut seq = /* built per the existing liquidation test setup */;

    // ---- tick 1: a matched fill (seal_batch), window still open
    let _ = seq.seal_batch(&orders_tick1, 20_000);

    // ---- mid-window: an out-of-band deposit (must land in window_ops)
    seq.apply(&BatchOp::Deposit { owner: dep_owner, asset_id: 0, amount: 500_000, blinding: [7u8; 32] })
        .unwrap();

    // ---- tick 2: oracle already crashed → maintenance accrues funding + liquidates
    let _ = seq.seal_batch(&orders_tick2, 20_700);

    // ---- close the window
    let w = seq.seal_window();

    // the window op-log must span all four op kinds (else the gate is hollow)
    assert!(w.ops.iter().any(|o| matches!(o, BatchOp::Deposit { .. })), "mid-window deposit logged");
    assert!(w.ops.iter().any(|o| matches!(o, BatchOp::Fill { .. })), "a fill this window");
    assert!(w.ops.iter().any(|o| matches!(o, BatchOp::AccrueFunding { .. })), "funding accrued");
    assert!(w.ops.iter().any(|o| matches!(o, BatchOp::Liquidate { .. })), "a liquidation");

    // faithfulness: replay the window witness onto its pre-state == the live window-end state
    let live_root = seq.state.state_root();
    let derived = perp_core::commitment::derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest)
        .expect("derive_roots accepts the window witness");
    assert_eq!(derived.new_state_root, live_root, "window op-log must reproduce the live window-end root");
    assert_eq!(derived.manifest_hash, w.manifest.hash::<Keccak256>(), "manifest hash matches");
    assert_eq!(w.pre_state.next_batch_id, w.batch_id, "pre_state counter == window batch_id");
}

#[test]
fn seal_window_two_tick_fills_only_round_trips() {
    let mut seq = /* funded traders, matching orders across two ticks, no liquidation */;
    let _ = seq.seal_batch(&orders_a, 21_000);
    let _ = seq.seal_batch(&orders_b, 21_700);
    let w = seq.seal_window();
    let live_root = seq.state.state_root();
    let derived = perp_core::commitment::derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest).unwrap();
    assert_eq!(derived.new_state_root, live_root);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p sequencer seal_window`
Expected: FAIL to compile — `seal_window` / `WindowWitness` don't exist.

- [ ] **Step 3: Add the window accumulator fields** to the `Sequencer` struct (`crates/sequencer/src/lib.rs`, near `snapshots`/`batch_ops` at `:277-282`). REPLACE the `batch_ops` field with the window fields:

```rust
    /// Every op applied since the current window opened, in application order — the
    /// replayable op-log the window proof attests. Fed by `Sequencer::apply` (deposits)
    /// and each `seal_batch` (its `[fills] ++ maintenance` ops). Drained by `seal_window`.
    #[serde(default)]
    window_ops: Vec<BatchOp>,
    /// Union of the window's ticks' settled/rejected order hashes, for the combined manifest.
    #[serde(default)]
    window_ordered: Vec<Digest>,
    #[serde(default)]
    window_rejected: Vec<(Digest, RejectReason)>,
    /// The state at the current window's open — the witness pre-state. Re-captured after
    /// each `seal_window`. (Not `#[serde(default)]`: `DefaultState` has no `Default`; the
    /// Sequencer is not persisted, so no missing-field case arises.)
    window_start_state: DefaultState,
```

- [ ] **Step 4: Initialize the fields in `new`** (`:294-310`). Remove the `batch_ops: BTreeMap::new(),` line; add:

```rust
            window_ops: Vec::new(),
            window_ordered: Vec::new(),
            window_rejected: Vec::new(),
            window_start_state: DefaultState::new(tree_depth),
```

(`DefaultState::new(tree_depth)` is a fresh genesis identical to the just-constructed `state`, so `window_start_state.state_root() == state.state_root()` and both have `next_batch_id == 0`.)

- [ ] **Step 5: Add `WindowWitness` + `seal_window`.** Place near `seal_batch`. The manifest mirrors `seal_batch`'s construction but over the window accumulators:

```rust
/// The replayable witness for one settle window: `derive_roots(pre_state, ops, manifest)
/// .new_state_root` equals the live state root after this `seal_window`. This is the tuple
/// Slice 3b-2 seals and POSTs to the prover-service.
pub struct WindowWitness {
    pub batch_id: u64,
    pub pre_state: DefaultState,
    pub ops: Vec<BatchOp>,
    pub manifest: BatchManifest,
}

impl Sequencer {
    /// Close the current window: build the combined manifest, advance the batch counter
    /// once (mirroring `apply_batch`), drain the op-log into the witness, and reopen a
    /// fresh window from the current state.
    pub fn seal_window(&mut self) -> WindowWitness {
        let batch_id = self.state.next_batch_id;
        let oracle_updates: Vec<Digest> =
            self.oracles.values().map(|t| t.hash::<Keccak256>()).collect();
        let manifest = BatchManifest {
            previous_state_root: self.window_start_state.state_root(),
            batch_id,
            ordered: self.window_ordered.clone(),
            rejected: self.window_rejected.clone(),
            oracle_updates,
            matching_rule_version: self.matching_rule_version,
            enclave_measurement: self.enclave.measurement,
            sequencer_pubkey_epoch: self.enclave.epoch,
        };
        // the single per-window counter bump (mirrors apply_batch's engine.rs:156)
        self.state.next_batch_id += 1;
        let pre_state = self.window_start_state.clone();
        let ops = core::mem::take(&mut self.window_ops);
        // reopen the next window from the post-bump state
        self.window_ordered.clear();
        self.window_rejected.clear();
        self.window_start_state = self.state.clone();
        WindowWitness { batch_id, pre_state, ops, manifest }
    }
}
```

- [ ] **Step 6: `seal_batch` — append to the accumulator, stop bumping the state counter, stop inserting `batch_ops`.**

(a) Just before the `SealedBatch { ... }` literal, REPLACE the `self.batch_ops.insert(batch_id, (ops.clone(), manifest.clone()));` (`:841`) with the window appends (append the tick's ops + this tick's ordered/rejected to the window accumulator; `ops`/`manifest` are still moved into `SealedBatch` afterward):

```rust
        self.window_ops.extend_from_slice(&ops);
        self.window_ordered.extend_from_slice(&manifest.ordered);
        self.window_rejected.extend_from_slice(&manifest.rejected);
```

(b) DELETE the per-tick state-counter bump at `:808` (keep the comment-free single line removed; the sequencer-field bump at `:810` stays):

```rust
        // DELETE this line (the 3a per-tick bump — the counter now advances per window in seal_window):
        //     self.state.next_batch_id += 1;
        let new_state_root = self.state.state_root();
        self.next_batch_id += 1;
```

(Also delete the 4-line `// Mirror apply_batch's single per-batch counter bump ...` comment block above the deleted line.)

- [ ] **Step 7: `Sequencer::apply` — log the op.** In `apply` (`:341`), after the successful `self.state.apply_op(op)?`, push the op so out-of-band deposits/funds land in the window op-log at their real position. Find the `self.state.apply_op(op)` call and make the body:

```rust
    pub fn apply(&mut self, op: &BatchOp) -> Result<(), EngineError> {
        // (existing FundPosition tag-key capture stays above this)
        self.state.apply_op(op)?;
        self.window_ops.push(op.clone());
        Ok(())
    }
```

(Preserve the existing tag-key-capture logic that runs before the apply; only the apply+push tail changes. `apply_op` returns `Result<Option<WithdrawalOut>, _>` — the existing code already discards the `Option`; keep that.)

- [ ] **Step 8: Remove the dead per-tick witness.** Delete: the `batch_witness` accessor (`:367-374`); the `self.batch_ops = self.batch_ops.split_off(&(batch_id + 1));` line in `mark_settled` (`:889`); the `self.batch_ops.remove(b);` line in `mark_failed` (`:918`). (The `batch_ops` field itself was already replaced in Step 3.)

- [ ] **Step 9: Remove the superseded 3a tests.** In `crates/sequencer/tests/spine.rs`, delete `batch_witness_replays_to_sealed_roots_with_fill_funding_liquidation` (`:864`) and `batch_witness_round_trips_fills_only` (`:931`). KEEP `run_maintenance_ops_replay_reproduces_state` (`:792` — it tests `run_maintenance`'s ops, which still exist and feed `window_ops`).

- [ ] **Step 10: Run the merge gate**

Run: `cargo test -p sequencer seal_window`
Expected: PASS — both `seal_window_replays_multi_tick_window_to_live_root` and `seal_window_two_tick_fills_only_round_trips`.

- [ ] **Step 11: Full suite + clippy**

Run: `cargo test -p sequencer && cargo test --workspace && cargo clippy --workspace --all-targets`
Expected: green. If a non-3a test asserted a `SealedBatch.new_state_root` value or `state.next_batch_id` advancing per tick, update it — the per-tick counter no longer advances (it advances per `seal_window`). Report any such test touched.

- [ ] **Step 12: Commit**

```bash
git add crates/sequencer/src/lib.rs crates/sequencer/tests/spine.rs
git commit -m "feat(sequencer): per-window batch model — seal_window + window op-log witness"
```

---

## Final verification (after the task)

- [ ] `cargo test -p sequencer seal_window` — the multi-tick window (deposit + fill + funding + liquidation) replays through `derive_roots` to the live window-end root; the two-tick fills-only round-trips. This is the slice's whole point.
- [ ] `cargo test --workspace && cargo clippy --workspace --all-targets` — green.
- [ ] `git diff --stat` — only `crates/sequencer/src/lib.rs` + `crates/sequencer/tests/spine.rs`. No perp-core/guest/gateway/contract change. `git grep -n batch_witness crates/sequencer` and `git grep -n 'batch_ops' crates/sequencer` return nothing (the per-tick witness is fully removed).
