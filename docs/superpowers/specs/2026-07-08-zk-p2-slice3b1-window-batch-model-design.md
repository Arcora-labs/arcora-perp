# ZK Verifier P2 — Slice 3b-1: Window Batch Model (Sequencer) — Design

**Date:** 2026-07-08
**Status:** Approved (brainstorming) → ready for implementation plan
**Workstream:** ZK verifier P2. Slices 1/2/3a are DONE and merged (main `141bdd1`). The chosen
settlement granularity is **per-L1-window (~30s): one proof + one `settleBatch` per window**, with the
engine's 700ms ticks staying internal/sub-batch (matching cadence). Slice 3a made each per-tick
`seal_batch` emit a faithful op-log, but its counter/witness were **per-tick**. This slice, **3b-1**,
reworks the sequencer's proven/on-chain batch unit from per-tick to **per-window**: the sequencer
accumulates a window's ops across ticks and produces ONE window witness whose `derive_roots` replays to
the live window-end state. Next: 3b-2 (gateway prover-client + settle rewire + incremental withdrawals +
inclusion re-keying), then the live-stack migration, then P3.

---

## 1. Problem

Per-window proving means one `apply_batch(window_ops)` per window — which advances the batch counter
(`state.next_batch_id`, bound in `state_root`, `state.rs:216`) exactly **once**. But 3a made each of the
window's ~42 per-tick `seal_batch` calls advance the counter, so the live engine's counter climbs ~42×
per window while a single window proof advances it once. The live window-end root would therefore diverge
from the proof's `new_state_root` (and batch ≥1 would fail `derive_roots`'s
`manifest.batch_id == state.next_batch_id` precondition). The mock verifier hides this; a real per-window
proof cannot verify against the live root.

Additionally, 3a's per-tick witness (`batch_witness`) does not span a window, and out-of-band deposits
(`Sequencer::apply`, between ticks) are captured in no op-log at all — so the window's complete op
sequence (deposits + every tick's fills/funding/liquidation) is not assembled anywhere.

## 2. Goal

The sequencer maintains a **window accumulator** — every op applied since the last window close, in
order, plus the window-start state and the window's ordered/rejected order hashes — and a new
`seal_window()` that produces ONE `WindowWitness { pre_state, ops, manifest }` such that
`derive_roots(pre_state, ops, manifest).new_state_root == the live window-end state_root`, proven by a CI
test over a window that spans multiple ticks and contains a mid-window deposit, fills, a funding accrual,
and a liquidation. `seal_window` advances `state.next_batch_id` exactly once per window. This is the
witness Slice 3b-2 seals and POSTs to the prover-service.

## 3. Resolved design decisions

- **Per-window counter, not per-tick.** `seal_batch` no longer advances `state.next_batch_id` (3a's bump
  is removed); `seal_window` advances it once. During a window `state.next_batch_id == W` (the window id)
  is constant; `seal_window` bumps `W → W+1` after building the manifest, so
  `derive_roots(pre_state[W], window_ops, manifest[batch_id=W])` (which `apply_batch`-bumps once to
  `W+1`) reproduces the live counter.
- **The sequencer owns the full window accumulator** (ops incl. out-of-band deposits, ordered, rejected),
  so 3b-1 is self-contained and CI-testable without the gateway. `seal_batch` and `Sequencer::apply`
  append to it; `seal_window` drains it.
- **3a's op-emission is preserved and reused.** `MaintenanceOutcome.ops` and `seal_batch`'s fill
  collection now feed `window_ops` instead of the per-tick `batch_ops` map. The per-tick
  `batch_ops`/`batch_witness`/per-tick-counter-bump/per-tick-merge-gate from 3a are **replaced** by the
  window equivalents (they proved a per-tick property this slice supersedes).
- **Matching stays per tick.** `seal_batch` still matches, settles fills, runs maintenance, issues
  receipts, and tracks inclusion per tick — unchanged except the counter bump and the accumulator append.
  Its internal per-tick `BatchManifest`/`manifest_hash` in the returned `SealedBatch` stay (internal); the
  ON-CHAIN manifest is the window manifest from `seal_window`.

## 4. Architecture

### 4.1 Window accumulator (new `Sequencer` fields)

```rust
// serde-derived Sequencer — new fields carry #[serde(default)] where needed
window_ops: Vec<BatchOp>,                        // every op since window open, in order
window_ordered: Vec<Digest>,                     // union of ticks' settled order hashes
window_rejected: Vec<(Digest, RejectReason)>,    // union of ticks' rejects
window_start_state: DefaultState,                // witness pre-state (state at window open)
```

`window_start_state` is initialized in `new` to the genesis `state.clone()` and re-captured at the end of
every `seal_window`. The three accumulators are cleared at the end of every `seal_window`.

### 4.2 `seal_batch` (per tick) — append, don't bump

- After building its local `ops` (`[applied fills] ++ maintenance.ops`, exactly as 3a), **append them to
  `self.window_ops`** (`self.window_ops.extend(ops)`), and append this tick's `manifest.ordered` to
  `self.window_ordered` and `manifest.rejected` to `self.window_rejected`.
- **Remove** 3a's `self.state.next_batch_id += 1;` (the per-tick bump). The separate *sequencer*
  `self.next_batch_id += 1;` (internal per-tick id for receipts/inclusion) stays.
- Remove the `self.batch_ops.insert(...)` (the per-tick witness map is gone). `SealedBatch.ops` may stay
  as the tick's own ops (informational) or be dropped — implementer's call; the plan keeps it.

### 4.3 `Sequencer::apply` (out-of-band deposits) — append

`apply(&mut self, op)` still `self.state.apply_op(op)?` immediately, and now also
`self.window_ops.push(op.clone());` — so a deposit/fund applied mid-window lands in the window op-log at
its real position (immediate application preserved; the op is recorded for the proof).

### 4.4 `seal_window` (per window) — build the witness

```rust
pub struct WindowWitness {
    pub batch_id: u64,               // the window's on-chain batch id (W)
    pub pre_state: DefaultState,     // window_start_state (root == manifest.previous_state_root)
    pub ops: Vec<BatchOp>,           // the full window op-log
    pub manifest: BatchManifest,     // the combined window manifest
}

/// Close the current window: build the combined manifest, advance the batch counter once, and return
/// the replayable witness. Resets the accumulators and captures the next window's start state.
pub fn seal_window(&mut self) -> WindowWitness;
```

Body:
1. `let batch_id = self.state.next_batch_id;` (== W, constant across the window).
2. Build the combined manifest: `previous_state_root = self.window_start_state.state_root()`,
   `batch_id`, `ordered = self.window_ordered.clone()`, `rejected = self.window_rejected.clone()`,
   `oracle_updates` = current `self.oracles` hashes (same construction as `seal_batch`),
   `matching_rule_version`/`enclave_measurement`/`sequencer_pubkey_epoch` as today.
3. `self.state.next_batch_id += 1;` (the single per-window bump, mirroring `apply_batch`).
4. Snapshot the witness triple to return: `pre_state = self.window_start_state.clone()`,
   `ops = core::mem::take(&mut self.window_ops)`, `manifest`.
5. Reset for the next window: clear `window_ordered`/`window_rejected`;
   `self.window_start_state = self.state.clone();`.
6. Return `WindowWitness { batch_id, pre_state, ops, manifest }`.

Consistency: `pre_state.state_root() == manifest.previous_state_root` and
`pre_state.next_batch_id == batch_id`, so `derive_roots` accepts the witness (`commitment.rs:56-58`);
replaying `ops` via `apply_batch` bumps the counter once to `batch_id+1`, matching the live state after
step 3.

## 5. The merge gate (CI, sequencer crate)

The slice's whole point — a multi-tick window replays to the live window-end root:

- Build a `Sequencer`; **open a window** (fresh, `window_start_state` = current). Across **several
  `seal_batch` ticks**: tick 1 has a **matched fill**; **between ticks, apply a deposit** via
  `Sequencer::apply` (so `window_ops` interleaves a `Deposit`); a later tick's maintenance **accrues
  funding and liquidates** an underwater position (set the oracle to make one liquidatable, adapting the
  3a `spine.rs` liquidation setup).
- Call `seal_window()` → `WindowWitness { batch_id, pre_state, ops, manifest }`.
- Assert `ops` contains ≥1 `Deposit`, ≥1 `Fill`, ≥1 `AccrueFunding`, ≥1 `Liquidate` (the window exercises
  all four; else the gate is hollow).
- `let live_root = seq.state.state_root();` (after `seal_window`'s counter bump).
- `derive_roots(&mut pre_state.clone(), &ops, &manifest)` → assert `.new_state_root == live_root` AND
  `.manifest_hash == manifest.hash::<Keccak256>()` (**no counter workaround** — the per-window bump makes
  full equality hold). Any state mutation left out of `window_ops` (e.g. a forgotten deposit) diverges the
  root and fails the test.
- Second test: a window with **two ticks and no maintenance** still round-trips (guards the multi-tick
  fill accumulation + the empty-maintenance path).

## 6. File map

**Modify:** `crates/sequencer/src/lib.rs` — the window accumulator fields + `new` init; `seal_batch`
append + remove per-tick counter bump + remove `batch_ops` insert; `Sequencer::apply` append;
`WindowWitness` struct + `seal_window`; remove 3a's `batch_ops` field / `batch_witness` accessor / their
pruning in `mark_settled`/`mark_failed`.
`crates/sequencer/tests/spine.rs` — the window merge gate + the two-tick round-trip; remove/replace 3a's
per-tick `batch_witness_replays_to_sealed_roots*` tests (superseded).

**No change:** perp-core, the guest, the prover-service, the contracts, the gateway.

## 7. Non-goals (Slice 3b-1)

- **No gateway/network/contract change**, no prover-service call — Slice 3b-2.
- **Per-window rollback is deferred.** `mark_settled`/`mark_failed` and the per-tick `snapshots` stay as
  they are (per-tick). A real per-window proof attests whatever transition actually happened, so it does
  not "fail to prove" on the happy path; per-window rollback/finality on the fault path is a 3b-2 (or
  later) refinement. This slice does not touch finality or rollback semantics.
- **Inclusion/receipt re-keying to the window id is deferred to 3b-2** (the DP-004 inclusion challenge
  keying, `issued_batch`/`seen_in_batch`). `seal_batch` keeps its per-tick internal ids; only the window
  manifest's `batch_id` is the window id here.
- No cumulative→incremental withdrawals rework (that lives in the gateway — 3b-2); `derive_roots` already
  produces an incremental `withdrawals_root` from the window ops.
- No change to `derive_roots`, the 6-field commitment, the `(DefaultState, Vec<BatchOp>, BatchManifest)`
  witness format, or matching fairness (Proof-v2).
