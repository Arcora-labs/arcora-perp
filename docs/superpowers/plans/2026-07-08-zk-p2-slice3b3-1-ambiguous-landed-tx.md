# ZK P2 Slice 3b-3.1 — Ambiguous Landed-Tx Recovery — Implementation Plan


**Goal:** On a settle failure, re-read the on-chain `batchCount` and roll back (tx didn't land), roll forward + commit (tx landed despite the error), or hold — closing the 3b-3 reverse-wedge + slashing gap.

**Architecture:** A pure `settle_failure_action(sealed_batch_id, chain_batch_count) -> RollAction` decides the recovery. The gateway's Section C `spawn_blocking` closure is restructured into a `SettleAttempt::{Ok, ProveFailed, SettleFailed{err, prepared}}` result so a settle failure preserves `prepared` for a roll-forward `commit_window_settle`; the match arms re-read `batch_count` on a settle failure and act on the decision.

**Tech Stack:** Rust (gateway crate), tokio async (`spawn_blocking`), Foundry `cast` for L1 (unchanged).

## Global Constraints

- **`settle_failure_action(sealed_batch_id: u64, chain_batch_count: u64) -> RollAction`**: `== sealed_batch_id` → `RollBack`; `== sealed_batch_id + 1` → `RollForward`; else → `Hold`. `RollAction` derives `Debug, PartialEq, Eq`.
- **Closure result `SettleAttempt`**: `Ok { prepared, tx: String, bond: u128, claimed: Vec<[u8;32]> }` | `ProveFailed(String)` (prove failed → no tx broadcast) | `SettleFailed { err: String, prepared: prover_client::PreparedSettle }` (settle failed → ambiguous, keep `prepared`).
- **Match arms:** `Ok` → success commit + prune (unchanged). `ProveFailed` → unconditional rollback. `SettleFailed` → re-read `batch_count` (+`sequencer_bond` for the roll-forward status): `RollBack` → rollback; `RollForward` → `commit_window_settle` (NO `prune_claimed_withdrawals`) with `L1Status.last_tx = "(recovered: landed despite cast error)"`; `Hold` (or a failed re-read) → mutate nothing + loud log. `Err(join)` → re-read; roll back ONLY if `batch_count == batch_id`, else Hold (no `prepared` to roll forward).
- **Roll-forward `L1Status`:** `settled_root: hex32(&prepared.outcome.new_root)`, `batch_count: batch_id+1`, `last_tx` the recovered-placeholder, `bond: bond.to_string()`, `withdrawals_root: hex32(&prepared.outcome.withdrawals_root)` — so the boot continuity guard (`settled_root` == on-chain `current_root()`) stays satisfied.
- **Gateway only. NO perp-core/sequencer/contract change.** Reuse `Sequencer::rollback_window`, `Gw::commit_window_settle`, `Gw::rollback_window_withdrawals` as-is.
- Run tests: `cargo test -p gateway <name>`.

---

## Reference: exact current shapes (verbatim)

**Current Section C** (`crates/gateway/src/main.rs:4679-4786`, inside `if let Some(client) = app.prover.clone() {`). Sections A (batch_count `bc` via spawn_blocking), B (`begin_window_settle` → `((witness, ww), prune_candidates)`; then `ordered`/`rejected`/`batch_id` captured; `witness_rb = witness.clone(); ww_rb = ww.clone();`), C (the closure below), then the match:
```rust
                    #[allow(clippy::type_complexity)]
                    let res = tokio::task::spawn_blocking(
                        move || -> Result<(prover_client::PreparedSettle, String, u128, Vec<[u8; 32]>), String> {
                            let prepared =
                                prover_client::prove_and_prepare(client.as_ref(), &witness, &ww)?;
                            let tx = l1c.settle_proved(&prepared.outcome)?;
                            let bond = l1c.sequencer_bond().unwrap_or(0);
                            let claimed: Vec<[u8; 32]> = prune_candidates
                                .into_iter()
                                .filter(|leaf| l1c.claimed(&hex32(leaf)).unwrap_or(false))
                                .collect();
                            Ok((prepared, tx, bond, claimed))
                        },
                    )
                    .await;
                    match res {
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
                        Ok(Err(e)) => {
                            eprintln!("[l1] window settle failed: {e} — rolling the window back");
                            let mut gw = app.gw.lock().await;
                            gw.seq.rollback_window(&witness_rb);
                            gw.rollback_window_withdrawals(ww_rb);
                        }
                        Err(e) => {
                            eprintln!("[l1] window settle join: {e} — rolling the window back");
                            let mut gw = app.gw.lock().await;
                            gw.seq.rollback_window(&witness_rb);
                            gw.rollback_window_withdrawals(ww_rb);
                        }
                    }
                    continue;
```
`Gw::commit_window_settle(&mut self, batch_id: u64, ordered: Vec<Digest>, rejected: Vec<Digest>, prepared: prover_client::PreparedSettle, l1_status: L1Status)` (consumes `prepared`/`ordered`/`rejected` by value; sets `last_settled_root = prepared.outcome.new_root`, inserts `batch_orders[batch_id]`, sets `l1_status`). `L1::batch_count() -> Result<u64,String>`, `L1::sequencer_bond() -> Result<u128,String>` (used as `.unwrap_or(0)`). `L1Status { settled_root: String, batch_count: u64, last_tx: String, bond: String, withdrawals_root: String }`. `hex32(&Digest) -> String`. `prepared.outcome.{new_root, withdrawals_root}: Digest`.

---

## Task 1: the `settle_failure_action` decision

**Files:**
- Modify: `crates/gateway/src/main.rs` (add `RollAction` enum + `settle_failure_action` fn + a unit test).

**Interfaces:**
- Produces: `enum RollAction { RollBack, RollForward, Hold }` (module-level); `fn settle_failure_action(sealed_batch_id: u64, chain_batch_count: u64) -> RollAction`.

- [ ] **Step 1: Write the failing test** (in `crates/gateway/src/main.rs` `#[cfg(test)] mod tests`)

```rust
    #[test]
    fn settle_failure_action_decides_by_batch_count() {
        use crate::RollAction;
        // chain still at the pre-seal count -> the tx did not land -> roll back.
        assert_eq!(crate::settle_failure_action(5, 5), RollAction::RollBack);
        // chain advanced by exactly one -> the tx landed despite the error -> roll forward.
        assert_eq!(crate::settle_failure_action(5, 6), RollAction::RollForward);
        // anything else is unexpected -> hold (no mutation).
        assert_eq!(crate::settle_failure_action(5, 7), RollAction::Hold);
        assert_eq!(crate::settle_failure_action(5, 4), RollAction::Hold);
        assert_eq!(crate::settle_failure_action(0, 0), RollAction::RollBack);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p gateway settle_failure_action_decides_by_batch_count`
Expected: FAIL to compile (`RollAction` / `settle_failure_action` absent).

- [ ] **Step 3: Implement the enum + fn** (module-level in `crates/gateway/src/main.rs`, near the other free helpers such as `hex32`)

```rust
/// What to do with a sealed-but-settle-failed window, given the on-chain batchCount
/// re-read AFTER the failure. `seal_window` bumped the local per-window counter to
/// `sealed_batch_id + 1`, so `chain_batch_count == sealed_batch_id` means the tx never
/// landed (undo the seal), `== sealed_batch_id + 1` means it landed despite the cast
/// error (commit the bookkeeping), and anything else is unexpected (hold, let the
/// operator reconcile — a rollback there could strand the sequencer either way).
#[derive(Debug, PartialEq, Eq)]
enum RollAction {
    RollBack,
    RollForward,
    Hold,
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

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p gateway settle_failure_action_decides_by_batch_count` → PASS. Then `cargo test -p gateway`
(full) — note `RollAction`/`settle_failure_action` are not yet used by non-test code, so add
`#[allow(dead_code)]` on BOTH the enum and the fn (Task 2 removes the allows when it wires them); confirm
`cargo clippy -p gateway` is clean.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): settle_failure_action (batch_count re-read -> RollBack/RollForward/Hold)"
```

---

## Task 2: restructure Section C — distinguish prove/settle failure + re-read on settle failure

**Files:**
- Modify: `crates/gateway/src/main.rs` (the new-path Section C closure + match arms; remove the Task-1 `#[allow(dead_code)]`).

**Interfaces:**
- Consumes: `RollAction`, `settle_failure_action` (Task 1); `Sequencer::rollback_window`, `Gw::commit_window_settle`, `Gw::rollback_window_withdrawals`, `L1::batch_count`, `L1::sequencer_bond`, `L1Status`, `hex32`.

- [ ] **Step 1: Replace the Section C closure with the `SettleAttempt` form**

In `crates/gateway/src/main.rs`, replace the `#[allow(clippy::type_complexity)] let res = tokio::task::spawn_blocking(move || -> Result<(prover_client::PreparedSettle, String, u128, Vec<[u8; 32]>), String> { … }).await;` (the closure shown in the Reference) with a local `SettleAttempt` enum + a closure returning it:

```rust
                    // (C) prove + settle (lock-free). Distinguish a prove failure (no tx
                    // was ever broadcast -> unconditional rollback) from a settle failure
                    // (cast send broadcasts THEN waits for the receipt, so a 90s-kill/RPC
                    // error is AMBIGUOUS: the tx may have landed -> keep `prepared` so we
                    // can roll forward and commit the bookkeeping if batch_count advanced).
                    enum SettleAttempt {
                        Ok {
                            prepared: prover_client::PreparedSettle,
                            tx: String,
                            bond: u128,
                            claimed: Vec<[u8; 32]>,
                        },
                        ProveFailed(String),
                        SettleFailed {
                            err: String,
                            prepared: prover_client::PreparedSettle,
                        },
                    }
                    let l1c = l1.clone();
                    let res = tokio::task::spawn_blocking(move || -> SettleAttempt {
                        let prepared =
                            match prover_client::prove_and_prepare(client.as_ref(), &witness, &ww) {
                                Ok(p) => p,
                                Err(e) => return SettleAttempt::ProveFailed(e),
                            };
                        match l1c.settle_proved(&prepared.outcome) {
                            Ok(tx) => {
                                let bond = l1c.sequencer_bond().unwrap_or(0);
                                let claimed: Vec<[u8; 32]> = prune_candidates
                                    .into_iter()
                                    .filter(|leaf| l1c.claimed(&hex32(leaf)).unwrap_or(false))
                                    .collect();
                                SettleAttempt::Ok { prepared, tx, bond, claimed }
                            }
                            Err(err) => SettleAttempt::SettleFailed { err, prepared },
                        }
                    })
                    .await;
```

- [ ] **Step 2: Rewrite the `match res` arms**

Replace the entire `match res { Ok(Ok(..)) => {..} Ok(Err(e)) => {..} Err(e) => {..} }` block (the one shown in the Reference) with:

```rust
                    match res {
                        Ok(SettleAttempt::Ok { prepared, tx, bond, claimed }) => {
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
                        Ok(SettleAttempt::ProveFailed(e)) => {
                            eprintln!("[l1] prove failed: {e} — rolling back (no tx was broadcast)");
                            let mut gw = app.gw.lock().await;
                            gw.seq.rollback_window(&witness_rb);
                            gw.rollback_window_withdrawals(ww_rb);
                        }
                        Ok(SettleAttempt::SettleFailed { err, prepared }) => {
                            // ambiguous: re-read batchCount (+ bond for a roll-forward status).
                            let l1c = l1.clone();
                            let recheck =
                                tokio::task::spawn_blocking(move || -> Result<(u64, u128), String> {
                                    let bc = l1c.batch_count()?;
                                    let bond = l1c.sequencer_bond().unwrap_or(0);
                                    Ok((bc, bond))
                                })
                                .await;
                            match recheck {
                                Ok(Ok((now_bc, bond))) => match settle_failure_action(batch_id, now_bc) {
                                    RollAction::RollBack => {
                                        eprintln!("[l1] settle failed: {err} — tx did not land (batchCount still {batch_id}); rolled back");
                                        let mut gw = app.gw.lock().await;
                                        gw.seq.rollback_window(&witness_rb);
                                        gw.rollback_window_withdrawals(ww_rb);
                                    }
                                    RollAction::RollForward => {
                                        let status = L1Status {
                                            settled_root: hex32(&prepared.outcome.new_root),
                                            batch_count: batch_id + 1,
                                            last_tx: "(recovered: landed despite cast error)".to_string(),
                                            bond: bond.to_string(),
                                            withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
                                        };
                                        eprintln!("[l1] settle reported '{err}' but the tx LANDED (batchCount {batch_id}->{now_bc}); rolled forward + committed bookkeeping");
                                        {
                                            let mut gw = app.gw.lock().await;
                                            gw.commit_window_settle(batch_id, ordered, rejected, prepared, status);
                                        }
                                        let snap = { app.gw.lock().await.snapshot() };
                                        let _ = app.tx.send(
                                            serde_json::to_string(&WsMsg::State { state: snap }).unwrap(),
                                        );
                                    }
                                    RollAction::Hold => {
                                        eprintln!("[l1] settle failed AND on-chain batchCount is {now_bc} for window {batch_id} — HOLDING (no rollback/commit); operator must reconcile");
                                    }
                                },
                                _ => {
                                    eprintln!("[l1] settle failed ({err}) and the batchCount re-read failed — HOLDING (no rollback/commit); operator must reconcile");
                                }
                            }
                        }
                        Err(join) => {
                            // the settle task panicked — `prepared` is lost, so we cannot roll
                            // forward. Re-read batchCount and roll back ONLY if it confirms the
                            // tx did not land; otherwise hold.
                            let l1c = l1.clone();
                            let re = tokio::task::spawn_blocking(move || l1c.batch_count()).await;
                            match re {
                                Ok(Ok(now_bc)) if now_bc == batch_id => {
                                    eprintln!("[l1] settle task join error: {join} — tx did not land; rolled back");
                                    let mut gw = app.gw.lock().await;
                                    gw.seq.rollback_window(&witness_rb);
                                    gw.rollback_window_withdrawals(ww_rb);
                                }
                                _ => {
                                    eprintln!("[l1] settle task join error: {join} — cannot confirm the tx did not land (no prepared to roll forward); HOLDING; operator must reconcile");
                                }
                            }
                        }
                    }
                    continue; // new path handled this tick; skip the legacy body
```

- [ ] **Step 3: Remove the Task-1 `#[allow(dead_code)]`**

`RollAction` and `settle_failure_action` are now used by the `SettleFailed` arm — delete the two
`#[allow(dead_code)]` attributes added in Task 1.

- [ ] **Step 4: Verify the branch compiles + full regression**

Run: `cargo build -p gateway` (the restructured branch + the local `SettleAttempt` enum compile; `RollAction`/`settle_failure_action` now consumed → no dead-code warning) + `cargo test -p gateway` (full — `settle_failure_action_decides_by_batch_count` + all prior tests green; the legacy path and the success path are behavior-unchanged) + `cargo clippy -p gateway` (clean). (The closure/arm/re-read wiring needs a live L1 — it's glue, reviewed by reading; the migration runbook adds a wedged-RPC forced-failure probe to observe the roll-forward.)

- [ ] **Step 5: Whole-workspace check**

Run: `cargo test` (workspace) and `cargo clippy --workspace` from the repo root. Expected: all pass, no warnings (gateway-only change).

- [ ] **Step 6: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): ambiguous landed-tx recovery — re-read batch_count, roll forward/back/hold on settle failure"
```

---

## Self-Review (author checklist — completed)

**1. Spec coverage** (against `2026-07-08-zk-p2-slice3b3-1-ambiguous-landed-tx-design.md`):
- §3.1 `settle_failure_action` + `RollAction` → Task 1. ✅
- §3.2 closure `SettleAttempt::{Ok, ProveFailed, SettleFailed{err,prepared}}` → Task 2 Step 1. ✅
- §3.3 match arms (ProveFailed unconditional rollback; SettleFailed re-read → RollBack/RollForward(commit, no prune)/Hold; failed re-read → Hold; Err(join) → rollback-only-if-confirmed-not-landed else Hold) → Task 2 Step 2. ✅
- §4 testing (settle_failure_action unit test; wiring glue) → Task 1 test; Task 2 regression. ✅
- §5 non-goals (no Hold/join auto-recovery; no re-read retry; no roll-forward prune; no perp-core/sequencer/contract change) → respected; gateway-only, reuses the existing primitives. ✅

**2. Placeholder scan:** none; every step shows complete code; the test asserts the full decision surface. ✅

**3. Type consistency:** `RollAction::{RollBack,RollForward,Hold}`, `settle_failure_action(u64,u64)->RollAction`, `SettleAttempt::{Ok,ProveFailed,SettleFailed}`, roll-forward `L1Status` fields match the success path's shape, `commit_window_settle(batch_id, ordered, rejected, prepared, status)` matches the merged signature — consistent across both tasks. ✅
