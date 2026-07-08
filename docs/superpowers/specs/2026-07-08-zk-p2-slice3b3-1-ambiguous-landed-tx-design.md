# ZK Verifier P2 — Slice 3b-3.1: Ambiguous Landed-Tx Recovery — Design

**Date:** 2026-07-08
**Status:** Approved (brainstorming) → ready for implementation plan
**Workstream:** ZK verifier P2. Slice 3b-3 (merge `9ccf396`) added a per-window rollback so a prove/settle
failure re-seals the window instead of permanently wedging the sequencer. Its final review surfaced one
Important gap: the rollback assumes the settle **tx did not land**. This slice closes that gap — the required
fast-follow before the new (PROVER_URL) path goes live in the migration slice. Gateway-only; no
perp-core/sequencer/contract change.

---

## 1. Problem

The new-path Section C settles a sealed window in a `spawn_blocking` closure: `prove_and_prepare` →
`settle_proved` → success. `settle_proved` shells out to `cast send` which **broadcasts the tx, then waits
for the receipt** under a 90s wall-clock kill (`crates/gateway/src/l1.rs:25-31,138-194`). When that 90s
deadline hits (a wedged RPC — the exact scenario the kill exists for), `cast` kills the child and returns
`Err("cast timed out after 90s (RPC wedged)")` — but the `settleBatch` tx may already have been broadcast
and could still mine. The `Err` string carries **no** broadcast-vs-never-broadcast information.

Today both the `Ok(Err(e))` (any closure error) and `Err(e)` (join) arms unconditionally
`rollback_window` (`crates/gateway/src/main.rs:4772-4783`). If the tx actually mined, the rollback rewinds
the local per-window counter to `batch_id` while the on-chain `batchCount` is `batch_id+1` and
`currentStateRoot` is the window's new root. Result: a **reverse desync** — every later
`begin_window_settle` produces a witness whose `prev_root` ≠ the chain root, so no settle ever succeeds, and
a restart trips the boot continuity guard (`main.rs:4347-4379`, which `exit(1)`s when the restored
`l1_status.settled_root` ≠ on-chain `currentStateRoot`). Additionally, because the gateway thinks the settle
failed, it never records `batch_orders[batch_id]` — so an inclusion challenge on that (actually-settled)
window is **unanswerable**, and the sequencer bond is slashable.

This is a strict improvement over pre-3b-3 (where *any* failure wedged), but the ambiguous-landed case is a
real reverse-wedge + slashing risk that must be closed before the path runs against a live chain.

## 2. Goal

On a settle failure the gateway **re-reads the on-chain `batchCount`** to detect whether the tx actually
landed, and acts accordingly: if the chain is still at the pre-seal count, the tx did not land → roll back
(as today); if the chain advanced by one, the tx **landed despite the error** → roll **forward**
(`commit_window_settle`, recording `last_settled_root`/`withdraw_proofs`/`batch_orders` so the window's
bookkeeping is complete and its inclusion challenge is answerable); anything else, or an unreadable count →
**hold** (no mutation) with a loud log for operator attention. A `prove_and_prepare` failure — which never
reaches `settle_proved`, so no tx was broadcast — stays an unconditional rollback. The reverse-wedge and the
slashing exposure are closed; the common failures (prove error, on-chain revert, broadcast rejection) still
heal exactly as in 3b-3 (a reverted/rejected tx does not advance `batchCount`, so the re-read yields
`RollBack`).

## 3. Architecture

### 3.1 The pure decision (`crates/gateway/src/main.rs`)

```rust
/// What to do with a sealed-but-settle-failed window, given the on-chain batchCount
/// re-read after the failure. `sealed_batch_id` is the window's batch_id (== the
/// pre-seal on-chain count); `seal_window` bumped the local counter to `+1`.
#[derive(Debug, PartialEq, Eq)]
enum RollAction {
    RollBack,    // chain still at sealed_batch_id -> the tx did NOT land; undo the seal.
    RollForward, // chain advanced to sealed_batch_id+1 -> the tx LANDED; commit the bookkeeping.
    Hold,        // any other count -> unexpected; mutate nothing, log for the operator.
}

fn settle_failure_action(sealed_batch_id: u64, chain_batch_count: u64) -> RollAction {
    if chain_batch_count == sealed_batch_id {
        RollAction::RollBack
    } else if chain_batch_count == sealed_batch_id + 1 {
        RollAction::RollForward
    } else {
        RollAction::Hold
    }
}
```

This is the only unit-tested unit; the async wiring around it is glue (needs a live L1).

### 3.2 The Section C closure — distinguish prove vs settle failure, preserve `prepared`

Replace the closure's flat `Result<(PreparedSettle, String, u128, Vec<[u8;32]>), String>` with a 3-variant
result so the caller can tell a prove failure (no tx broadcast) from a settle failure (ambiguous), and so a
settle failure carries `prepared` forward for a roll-forward commit:

```rust
enum SettleAttempt {
    Ok { prepared: prover_client::PreparedSettle, tx: String, bond: u128, claimed: Vec<[u8; 32]> },
    ProveFailed(String),
    SettleFailed { err: String, prepared: prover_client::PreparedSettle },
}
```

The closure stops using `?`: `prove_and_prepare` error → `return SettleAttempt::ProveFailed(e)`;
`settle_proved` error → `return SettleAttempt::SettleFailed { err, prepared }` (keeping `prepared`); success
→ `SettleAttempt::Ok { .. }` (unchanged: `bond`, `claimed` computed as today). `PreparedSettle`/`ProveOutcome`
are `Clone` if a copy is needed, but moving `prepared` into the variant is sufficient.

### 3.3 The match-arm rewrite

- **`Ok(SettleAttempt::Ok { .. })`** — unchanged: build the success `L1Status`, `commit_window_settle`,
  `prune_claimed_withdrawals`, broadcast the snapshot.
- **`Ok(SettleAttempt::ProveFailed(e))`** — `prove_and_prepare` never reached `settle_proved`, so no tx was
  broadcast → unconditional rollback (`rollback_window(&witness_rb)` + `rollback_window_withdrawals(ww_rb)`),
  log `"[l1] prove failed: {e} — rolling back (no tx broadcast)"`.
- **`Ok(SettleAttempt::SettleFailed { err, prepared })`** — ambiguous. Re-read the on-chain count in a
  `spawn_blocking` (`l1c.batch_count()` and `l1c.sequencer_bond()` for the roll-forward status), then match
  `settle_failure_action(batch_id, now_bc)`:
  - **`RollBack`** — `rollback_window` + `rollback_window_withdrawals`; log `"…settle failed: {err} — the tx
    did not land (batchCount still {batch_id}); rolled back"`.
  - **`RollForward`** — the tx landed. Build `L1Status { settled_root: hex32(&prepared.outcome.new_root),
    batch_count: batch_id + 1, last_tx: "(recovered: landed despite cast error)".into(), bond:
    bond.to_string(), withdrawals_root: hex32(&prepared.outcome.withdrawals_root) }`, then
    `gw.commit_window_settle(batch_id, ordered, rejected, prepared, status)` — **no** `prune_claimed_withdrawals`
    (its `claimed` set was never computed on the settle-failure path; the next settle prunes). Log `"…settle
    reported {err} but the tx LANDED (batchCount {batch_id}→{}); rolled forward + committed bookkeeping"`.
    Broadcast the snapshot as on the success path.
  - **`Hold`** — `now_bc` is neither `batch_id` nor `batch_id+1` (should not happen). Mutate nothing; log
    loudly `"[l1] settle failed AND on-chain batchCount is {now_bc} for window {batch_id} — HOLDING (no
    rollback/commit); operator must reconcile"`.
  - If the `batch_count` re-read itself errors → treat as **Hold**: mutate nothing, log `"…settle failed and
    the batchCount re-read failed ({e}) — HOLDING"`. (A double RPC failure; rare, no worse than 3b-3, and
    the next tick re-reads.)
- **`Err(join)`** (the settle task panicked — `prepared` is lost) — re-read `batch_count`; roll back **only**
  if it confirms `== batch_id` (tx did not land); otherwise **Hold** (we cannot roll forward without
  `prepared`) with a loud log. A panic is a bug path; this avoids a reverse-wedge on a post-broadcast panic.

## 4. Testing (CI, gateway crate)

- **`settle_failure_action`** — `settle_failure_action(5, 5) == RollBack`; `(5, 6) == RollForward`;
  `(5, 7) == Hold`; `(5, 4) == Hold`. The complete decision surface.
- The closure restructure + the match arms + the `batch_count` re-read are **glue** (they need a live L1 —
  `settle_proved`/`batch_count` are `cast` subprocesses). Reviewed by reading; the plan documents a
  migration-time forced-failure probe (settle against a **wedged RPC**, not a dead prover, to exercise the
  broadcast-then-timeout path) to observe the roll-forward log + a clean next-window settle.
- Legacy path (`PROVER_URL` unset) and the success/prove-fail paths stay behavior-unchanged; full
  `cargo test -p gateway` green.

## 5. Non-goals (Slice 3b-3.1)

- **No automatic recovery of the `Hold` / join-error double-failure** — those log loudly for operator
  reconciliation (manual `batch_count` check → rollback or fresh snapshot). A rare double-RPC-failure or a
  panic; not made worse than 3b-3.
- **No `batch_count` re-read retry loop** — a single re-read; on failure, Hold. Retries are a future
  refinement.
- **No roll-forward `prune_claimed_withdrawals`** — the settle-failure path never computed `claimed`; the
  next successful settle prunes. (The one skipped prune is harmless housekeeping.)
- **No perp-core/sequencer/contract change** — the rollback primitive (`Sequencer::rollback_window`) and
  `commit_window_settle` are reused as-is; only the gateway's Section C failure handling changes.
