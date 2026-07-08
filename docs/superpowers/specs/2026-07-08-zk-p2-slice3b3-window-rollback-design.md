# ZK Verifier P2 — Slice 3b-3: Per-Window Rollback + Content-Derived Nonce — Design

**Date:** 2026-07-08
**Status:** Approved (brainstorming) → ready for implementation plan
**Workstream:** ZK verifier P2. Slices 1/2/3a/3b-1/3b-2a/3b-2b are DONE and merged (main `86d2165`); the
gateway-driven real-Groth16 settle was validated on Base Sepolia (GB10 e2e, tx `0x341fa876…` status 1). This
slice closes the last liveness gap in the new (PROVER_URL) settle path: a settle-tx or prove failure
**after** the window is sealed permanently wedges the sequencer past its desync guard. It adds a per-window
rollback and hardens the seal nonce so the rollback+re-seal can never reuse a keystream. The off-chain
receipt/inclusion re-keying (Counter-A → window id) is a separate concern deferred to **3b-4** (on-chain
challenge answers already key on the window id, so it is off-chain consistency only).

---

## 1. Problem

The settle path has two batch-id counters. **Counter A** = `Sequencer::next_batch_id` (bumped once per
700ms `seal_batch` tick; drives off-chain receipts, `InclusionRecord`, the sequencer's soft-finality
`snapshots`/`mark_settled`/`mark_failed`). **Counter B** = `state.next_batch_id` (in `perp_core::DefaultState`,
bound in `state_root`; bumped once per window in `seal_window`; drives the `WindowWitness`, the desync guard,
the on-chain `batchCount`, `Gw.batch_orders`, and the seal nonce). Within a ~30s window (~43 ticks) Counter A
advances ~43× and Counter B once.

`seal_window` (`crates/sequencer/src/lib.rs:894-922`) is **optimistic**: it bumps Counter B, drains
`window_ops`/`window_ordered`/`window_rejected`, and re-captures `window_start_state` — advancing the window
boundary immediately (correct for async proving, where a real proof takes minutes and the engine must keep
ticking). `Gw::begin_window_settle` (`main.rs:1350-1368`) also drains `window_withdrawals`. The new-path async
branch's Section C then proves + settles. **On any Section C failure** (`prove_and_prepare` error, or
`settle_proved` revert/error) the branch only logs and `continue`s (`main.rs:4760-4761`) — no rollback,
no commit. So Counter B has advanced (and the window accumulators drained) while the on-chain `batchCount`
has not. The next 30s tick re-reads Counter B (now ahead by 1), the desync guard
(`begin_window_settle`, `main.rs:1360-1364`) fires `Err("batch_id desync…")`, and **every subsequent window
is skipped permanently** — Counter B is persisted in the sealed snapshot, so a restart does not heal it.
`mark_failed` (the per-tick rollback) is never invoked in production and operates on Counter A, so it does
not address this.

A second, coupled problem: `seal_witness` derives the seal **nonce from Counter B** (the window id,
`prover_client.rs:135-136`). The rollback introduced here rewinds Counter B and re-seals a **different**
plaintext (a larger window: the failed ops plus the ticks accumulated since) under the **same** batch_id →
the same nonce for different plaintext under the same `SoftwareSealProvider(root, measurement)` → keystream
reuse observable to a network observer of both POSTs. The rollback makes this reachable, so it must be fixed
in the same slice.

## 2. Goal

A prove/settle failure in the new path **rolls the window back** to its exact pre-seal state — Counter B
restored, the failed window's ops/orders re-injected ahead of anything the tick loop added since,
`window_start_state` restored, `window_withdrawals` restored — so the next settle tick re-seals the (now
larger) window under the **same** batch_id (== on-chain `batchCount`) and retries. No window is ever
stranded; no op is ever lost. The seal nonce is derived from the **plaintext content**, so any re-seal of a
different window under the same batch_id gets a different nonce (no keystream reuse), while a legitimate
identical retry gets the same nonce (identical ciphertext — leaks nothing). The per-tick soft-finality
machinery is untouched; the off-chain receipt re-keying is deferred to 3b-4.

## 3. Resolved design decisions

- **Per-window rollback is a NEW mechanism, not a rework of the per-tick finality.** The existing
  `snapshots`/`mark_settled`/`mark_failed` are a bounded, tested, per-tick *soft*-finality mechanism
  (`Matched→Settled` in the tick loop, decoupled from L1; `mark_failed` unused in production). This slice
  leaves them entirely as-is and adds a separate `Sequencer::rollback_window` for the L1 settle-failure case.
- **Rollback on ANY Section C failure** (prove error OR settle error), not a proof-preserving retry. Simple
  and correct: the failed window's ops are re-injected, so nothing is lost; the retry re-seals fresh. It
  wastes a proof on a transient failure — a proof-preserving "retry-settle" is a documented future
  refinement, not built here.
- **Content-derived nonce**, not a persisted monotonic counter. `nonce = keccak256(plaintext)` is stateless,
  restart-safe, and inherently reuse-proof (different plaintext ⇒ different nonce; same plaintext ⇒ same
  nonce ⇒ same ciphertext ⇒ no leak). The nonce is transmitted inside the `SealedWitness`, so the
  prover-service opens with `sealed.nonce` regardless of how it was derived — full interop preserved.

## 4. Architecture

### 4.1 `Sequencer::rollback_window` (`crates/sequencer/src/lib.rs`)

```rust
/// Undo an optimistic `seal_window` after its off-chain settle failed: restore the
/// per-window counter and re-inject the failed window's ops/orders AHEAD of anything the
/// 700ms tick loop appended since the seal, and restore the window baseline. The next
/// `seal_window` then re-seals `[failed ops ++ intervening ops]` from the old baseline
/// under the SAME batch_id (== the unchanged on-chain batchCount), so no op is lost and
/// the desync guard is satisfied.
pub fn rollback_window(&mut self, w: &WindowWitness) {
    // seal_window bumped Counter B once; ticks never touch it, so restore the pre-seal id.
    self.state.next_batch_id = w.batch_id;
    let mut ops = w.ops.clone();
    ops.append(&mut self.window_ops);
    self.window_ops = ops;
    let mut ord = w.manifest.ordered.clone();
    ord.append(&mut self.window_ordered);
    self.window_ordered = ord;
    let mut rej = w.manifest.rejected.clone();
    rej.append(&mut self.window_rejected);
    self.window_rejected = rej;
    self.window_start_state = w.pre_state.clone();
}
```

To let the gateway keep a rollback copy across the lock-free Section C, `WindowWitness` (`lib.rs:176-181`)
gains `#[derive(Clone)]` **if** `BatchManifest` is already `Clone` (its `pre_state: DefaultState` and
`ops: Vec<BatchOp>` are). If `BatchManifest` is not `Clone`, do NOT add a `perp-core` derive (that violates
the non-goal) — instead capture only the fields `rollback_window` needs into a small sequencer-owned struct
`WindowRollback { batch_id: u64, pre_state: DefaultState, ops: Vec<BatchOp>, ordered: Vec<Digest>, rejected:
Vec<(Digest, RejectReason)> }` and have `rollback_window` take `&WindowRollback`. The plan picks whichever
compiles without touching perp-core.

**Correctness:** `seal_window`'s only mutations are the Counter-B bump, the three drains, and the
`window_start_state` re-capture (it does not apply ops — the engine state was already mutated per-tick by
`seal_batch`). The tick loop between seal and rollback only *appends* to `window_ops`/`window_ordered`/
`window_rejected` (`seal_batch`, `lib.rs:870-872`) and never touches `window_start_state` or Counter B. So
prepending the witness's captured ops/orders and restoring `state.next_batch_id`/`window_start_state`
returns the sequencer to "as if the window never sealed but the ticks kept coming." The per-tick
`snapshots`/`finality`/`inclusion`/Counter A are intentionally left untouched (they track the soft per-tick
finality, which is unaffected by an L1 settle failure).

### 4.2 Gateway rollback wiring (`crates/gateway/src/main.rs` new-path Section C)

- Before the Section C `spawn_blocking` (which moves `witness`/`ww`), keep rollback copies:
  `let witness_rb = witness.clone(); let ww_rb = ww.clone();`. (A per-settle `DefaultState` clone — 40× less
  frequent than the per-tick `snapshots` clone the engine already does — negligible.)
- Replace the two log-only failure arms (`main.rs:4760-4761`) with a rollback under the lock:

```rust
    Ok(Err(e)) => {
        eprintln!("[l1] window settle failed: {e} — rolling back the window");
        let mut gw = app.gw.lock().await;
        gw.seq.rollback_window(&witness_rb);
        gw.rollback_window_withdrawals(ww_rb);
    }
    Err(e) => {
        eprintln!("[l1] window settle join: {e} — rolling back the window");
        let mut gw = app.gw.lock().await;
        gw.seq.rollback_window(&witness_rb);
        gw.rollback_window_withdrawals(ww_rb);
    }
```

- New `Gw::rollback_window_withdrawals(&mut self, ww: Vec<Withdrawal>)` — re-inject the drained withdrawals
  ahead of any accumulated since (mirroring the op prepend):

```rust
    fn rollback_window_withdrawals(&mut self, mut ww: Vec<Withdrawal>) {
        ww.append(&mut self.window_withdrawals);
        self.window_withdrawals = ww;
    }
```

On the success arm, `commit_window_settle` runs (unchanged) and the rollback copies are dropped. On failure,
`commit_window_settle` did NOT run, so `last_settled_root`/`batch_orders`/`withdraw_proofs`/`l1_status` are
unchanged — only `begin_window_settle`'s mutations (the `seal_window` + the `window_withdrawals` drain) are
undone. The next 30s settle tick re-seals the larger window under the same batch_id and retries.

### 4.3 Content-derived nonce (`crates/gateway/src/prover_client.rs` `seal_witness`)

Replace the Counter-B nonce (`nonce[24..] = batch_id.to_be_bytes()`) with a keccak256 of the sealed
plaintext:

```rust
    // nonce = keccak256(plaintext): different plaintext (any window / any rollback re-seal)
    // yields a different nonce, so a re-seal under the same batch_id can never reuse a
    // keystream; an identical retry yields the same nonce (identical ciphertext, no leak).
    let nonce: [u8; 32] = keccak256(&bytes); // bytes = postcard(pre_state, ops, manifest)
```

using the gateway's existing keccak (`sha3::Keccak256`, already a dependency, or the shared perp_core
hasher). The `w.batch_id` parameter is no longer read for the nonce. The prover-service opens with the
transmitted `sealed.nonce`, so nothing else changes.

## 5. Testing (CI)

- **Rollback round-trip (sequencer merge gate)** — the slice's core property. Build a `Sequencer`; open a
  window with real ops (a fill + a deposit); `seal_window()` → witness (record its `batch_id`); apply a few
  MORE ops via `apply`/`seal_batch` (the "intervening ticks"); `rollback_window(&witness)`; assert
  `state.next_batch_id == witness.batch_id`, `window_start_state.state_root() == witness.pre_state.state_root()`,
  and `window_ops == [witness.ops ++ the intervening ops]` (order preserved). Then a fresh `seal_window()`
  yields a witness with the **same** `batch_id` whose `derive_roots(pre_state, ops, manifest).new_state_root`
  reproduces the live engine `state_root()` (falsifiable: a rollback that dropped ops or mis-ordered them
  diverges the root).
- **`rollback_window_withdrawals` (gateway)** — seed `window_withdrawals` with some entries, roll back a
  captured set, assert the rolled-back set is prepended and the accumulated set follows.
- **Content nonce (gateway)** — `seal_witness` for two different witnesses yields two different nonces (decode
  the `SealedWitness`, compare `nonce()`); the same witness twice yields the same nonce; the nonce equals
  `keccak256` of the postcard plaintext.
- The async-branch failure→rollback wiring needs a live L1, so it is glue — reviewed by reading (it calls the
  unit-tested `rollback_window`/`rollback_window_withdrawals` on the failure arms).

## 6. Non-goals (Slice 3b-3)

- **No off-chain receipt/inclusion re-keying** (Counter A → window id) — Slice **3b-4**. On-chain challenge
  answers already key on the window id (`Gw.batch_orders` + `inclusion_leaf`/`rejection_leaf`), so this is
  off-chain consistency only (the client's `Receipt.batch_id_hint`), and is orthogonal to the rollback.
- **No rework of the per-tick soft-finality** — `mark_settled`/`mark_failed`/`snapshots`/the Counter-A
  machinery stay exactly as they are (a bounded, tested, decoupled mechanism).
- **No proof-preserving "retry-settle"** — rollback-on-any-failure re-seals fresh; preserving an expensive
  proof across a transient settle failure is a future refinement.
- **No `perp-core` or contract change** — this slice touches only `crates/sequencer` (rollback_window +
  the `WindowWitness` Clone derive) and `crates/gateway` (the wiring + the nonce). No change to `derive_roots`,
  the witness format, the six-field commitment, or matching fairness (Proof-v2).
