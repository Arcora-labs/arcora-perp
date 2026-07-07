# ZK Verifier P2 — Slice 3a: Provable Transition (Sequencer Op-Log) — Design

**Date:** 2026-07-07
**Status:** Approved (brainstorming) → ready for implementation plan
**Workstream:** ZK verifier P2. Slices 1 (on-chain `SP1ZkVerifier`) and 2 (attested prover-service) are
DONE and e2e-verified on-chain (main `517b047`). This is **Slice 3a**: make the sequencer's per-batch
state transition a **faithful, replayable `Vec<BatchOp>`**, so a real proof of a batch reproduces the
sealed `new_state_root` exactly. It is the foundation Slice 3b (gateway per-window witness assembly +
wire the settle path to the prover-service) stands on. Later: 3b, then the live-stack migration, then
P3 (real TDX/Nitro attested key-release).

---

## 1. Problem

The ZK guest proves `state.apply_batch(ops)` (perp-core). For a real proof of a batch to reproduce the
state the engine actually computed, the batch's **entire** transition must be a `Vec<BatchOp>` that,
replayed against the pre-state, yields the identical `new_state_root`. Today `seal_batch`
(`crates/sequencer/src/lib.rs:547`) does only part of this as ops:

- **Fills** — already `BatchOp::Fill` applied via `state.apply_op` (`lib.rs:637-647`), but the ops are
  dropped after applying (no log).
- **Funding accrual + liquidation** — done inside `run_maintenance` (`lib.rs:669-672`). Funding is
  *already* `state.apply_op(BatchOp::AccrueFunding{…})` (`lib.rs:502-507`); liquidation is
  `state.liquidate(…)` (`lib.rs:531`), documented in perp-core as **"the SAME state transition as
  `BatchOp::Liquidate`"** (both call the identical `op_liquidate`, incl. the deterministic ADL cascade).
  Neither is recorded as an op.

So the transition is *not* captured as a replayable op-log. Slice-2's e2e passed only because its witness
was a hand-built `Deposit + Withdraw` vector with no maintenance. A real batch with funding or a
liquidation would prove a different `new_state_root` than the engine computed → verification fails.

A parity investigation confirmed the fix is **MECHANICAL** (collect-while-applying), not a reconciliation
of two engines: the sequencer never duplicates funding/liquidation/ADL math — it computes ancillary
inputs (mark price, liquidation candidates) and feeds them into the exact perp-core functions the emitted
ops would invoke. `BatchOp::AccrueFunding` and `BatchOp::Liquidate` already exist; `apply_op` already
handles both; ADL runs inside `op_liquidate` (no separate op). No new engine code.

## 2. Goal

`seal_batch` emits and retains, per batch, the ordered `Vec<BatchOp>` it applied (fills + funding +
liquidation), such that
`perp_core::commitment::derive_roots(pre_state, ops, manifest).new_state_root == sealed.new_state_root`
and the ordered/rejected/withdrawals roots match — proven by a CI test over a batch that contains a fill,
a funding accrual, and a liquidation (with ADL). The retained `(pre_state, ops, manifest)` triple is the
witness Slice 3b will seal and POST to the prover-service.

## 3. Resolved design decisions

- **Per-`seal_batch` op-log, pre-state = the existing per-batch snapshot.** The snapshot taken at
  `seal_batch` start (`lib.rs:553-554`, `snapshots.insert(batch_id, (state.clone(), matcher.clone()))`)
  is the state *before* this batch's fills/funding/liquidation, and its root already equals
  `manifest.previous_state_root` (`prev_state_root`, `lib.rs:548,708`). So `(pre_state, ops, manifest)`
  is consistent **with no change to snapshot timing, `manifest.previous_state_root`, or rollback
  semantics**. The op-log = exactly the ops `seal_batch` applies, in application order.
- **Out-of-band deposits/funds are NOT in this op-log; they live in the pre-state.** Deposits applied via
  `Sequencer::apply` (`lib.rs:328-344`, out-of-band) before `seal_batch` are already baked into the
  snapshot, so per-batch faithfulness holds without logging them. **Folding deposits into the complete
  *window* witness — and the window-scoped pre-state / `previous_state_root` — is Slice 3b's concern**
  (window assembly), since deposits enter the proven transition when 3b concatenates a window's batches.
- **Collect while applying (no dual path).** Funding/liquidation keep executing exactly as today
  (`state.apply_op(AccrueFunding)`, `state.liquidate` — the latter still returns the `Vec<AdlHaircut>`
  the sequencer needs for `AdlReceipt`); the emitted op is *also* pushed onto the log. Because the op is
  provably the same transition (parity verdict), there is no divergence risk.

## 4. Architecture

### 4.1 `run_maintenance` emits its ops

`MaintenanceOutcome` (`crates/sequencer/src/lib.rs:180-183`) gains an ordered op log:

```rust
struct MaintenanceOutcome {
    liquidated: Vec<(PubKey, MarketId)>,
    adl: Vec<AdlHaircut>,
    ops: Vec<BatchOp>,   // NEW: AccrueFunding + Liquidate, in application order
}
```

`run_maintenance` (`lib.rs:~483-540`) pushes, per market in the existing `MarketId` BTreeMap iteration
order: the `BatchOp::AccrueFunding { market_id, mark, oracle, now_ms }` it already builds at `lib.rs:502-507`,
then, for each liquidated candidate (same order it calls `state.liquidate`), a
`BatchOp::Liquidate { owner, market_id, oracle, now_ms }`. Execution is unchanged (still `apply_op` /
`state.liquidate`); the ops are appended in lock-step so log order == application order.

### 4.2 `seal_batch` accumulates the batch op-log

`seal_batch` (`lib.rs:547`) builds a local `ops: Vec<BatchOp>`:
- In the fill loop (`lib.rs:637-663`), on a **successful** `state.apply_op(&op)` (the `Ok(_)` arm at
  `:649`), push that `BatchOp::Fill`. A fill that fails settlement (the `Err` arm) is NOT applied to state
  and MUST NOT be logged.
- After `run_maintenance` (`lib.rs:669-672`), `ops.extend(maintenance.ops)`.

The op-log order is therefore: `[applied fills…] ++ [per-market AccrueFunding/Liquidate…]` — exactly the
order the engine mutated state, so replaying it against the pre-state reproduces `new_state_root`.

Deposits are not in this list (§3); the fill/maintenance ops are the whole of what `seal_batch` itself
applies.

### 4.3 Retain the witness triple, pruned with snapshots

The pre-state is already in `snapshots[batch_id].0`. Retain the batch's `ops` + `manifest` alongside, and
expose the triple:

```rust
// new field on Sequencer
batch_ops: BTreeMap<u64, (Vec<BatchOp>, BatchManifest)>,

/// The replayable witness for a still-pending batch: (pre_state, ops, manifest).
/// Returns None once the batch is pruned (settled/failed) or unknown.
pub fn batch_witness(&self, batch_id: u64) -> Option<(DefaultState, Vec<BatchOp>, BatchManifest)>;
```

`batch_witness` combines `snapshots[batch_id].0.clone()` with `batch_ops[batch_id]`. `mark_settled`
(`lib.rs:797`, which already does `snapshots = snapshots.split_off(&(batch_id+1))` at `:813`) and
`mark_failed` (`lib.rs:826`) prune `batch_ops` on the same key range, so retention lifetime == the
existing snapshot lifetime (bounded by pending, unproven batches). No unbounded growth.

`SealedBatch` (seal_batch's return) additionally carries the `ops` for the just-sealed batch so a caller
(3b) can consume it immediately without a map lookup.

## 5. The merge gate (CI, sequencer crate)

A single test is the whole point of the slice — it proves the op-log is a faithful witness:

- Build a `Sequencer`, deposit/fund two accounts, submit orders that **produce at least one settled fill**,
  set an oracle such that the maintenance pass **accrues funding** and **liquidates** an underwater
  position (exercising the ADL cascade). Call `seal_batch`.
- Fetch `batch_witness(batch_id)` → `(pre_state, ops, manifest)`.
- Assert `ops` contains ≥1 `Fill`, ≥1 `AccrueFunding`, and ≥1 `Liquidate` (the gate must exercise all
  three op kinds, else it proves nothing about maintenance).
- Run `perp_core::commitment::derive_roots(&mut pre_state.clone(), &ops, &manifest)` and assert its
  `new_state_root == sealed.new_state_root`, and its ordered/rejected/withdrawals roots match the sealed
  manifest's. **If any state mutation happens off-log, `new_state_root` diverges and the test fails.**

Plus a lighter test: a fills-only batch (no maintenance) still round-trips, guarding the fill-logging path.

## 6. File map

**Modify:**
- `crates/sequencer/src/lib.rs` — `MaintenanceOutcome.ops`; `run_maintenance` emits AccrueFunding/Liquidate
  ops in application order; `seal_batch` accumulates the batch op-log; `Sequencer.batch_ops` map +
  `batch_witness` accessor; prune `batch_ops` in `mark_settled`/`mark_failed`; `SealedBatch` carries `ops`.
- `crates/sequencer/src/lib.rs` tests — the merge-gate test (fill + funding + liquidation) + the
  fills-only round-trip; update any existing test that constructs/asserts `MaintenanceOutcome` or
  `SealedBatch` for the new field.

**No change:** perp-core (all ops + `apply_op` handlers already exist), the guest, the prover-service, the
contracts, the gateway.

## 7. Non-goals (Slice 3a)

- **No gateway, network, or contract changes**, and no per-window concatenation — that is Slice 3b.
- **Out-of-band deposit/fund ops are not folded into the op-log** here; the complete window witness
  (deposits + all batches' ops, window-start pre-state, window `previous_state_root`) is Slice 3b.
- **No settle-path rewire, no prover-service call, no incremental-withdrawals rework** — Slice 3b.
- **Matcher order-book mutations stay off the op-log.** `cancel_owner_orders` (`lib.rs:673-675`) touches the
  `MatchingEngine`, which is not bound by `state_root` / `apply_batch`; it must NOT become a `BatchOp`.
- **Matching fairness stays Proof-v2.** The guest verifies the emitted fills *apply* (margin, reduce-only,
  etc.) and that funding/liquidation math is correct given the sequencer-provided mark/oracle — NOT that
  matching was fair or that the mark is honest.
- No change to the 6-field commitment, `derive_roots`, or the `(DefaultState, Vec<BatchOp>, BatchManifest)`
  witness format.
