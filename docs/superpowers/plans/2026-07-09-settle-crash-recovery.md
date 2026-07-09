# Settle Crash-Recovery + ensure_bond Gas Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.
> Spec: `docs/superpowers/specs/2026-07-09-settle-crash-recovery-design.md` (read it first — it is the contract).

**Goal:** A gateway restart during an in-flight window settle recovers automatically at boot (rollback or roll-forward from a sealed sidecar journal) instead of wedging forever; and `ensure_bond`'s postBond no longer fails on drpc's lagging gas estimation.

**Architecture:** New `crates/gateway/src/rollback_journal.rs` module (sealed sidecar file `<DARKPERP_STATE>.rollback`, reusing `snapshot::{seal,open,write_atomic}`), wired into the settle loop (stage-1 write at seal + immediate snapshot, stage-2 write after prove, delete on every in-memory resolution) and into `main()` boot (pure `recovery_action` decision + apply). `l1.rs` gains a gas-limit-capable send used by `ensure_bond`'s postBond.

**Tech stack:** Rust, postcard, existing `snapshot` sealing, existing test patterns in `crates/gateway/src/main.rs` tests mod.

## Global Constraints

- **Snapshot format MUST NOT change** — `Gw`/`Sequencer` serde layout untouched; the journal is a separate file. (The live CVM snapshot must keep loading.)
- Journal plaintext MUST be sealed with `snapshot::seal(&plain, &enclave_seed)` — it contains private notes; never write it unsealed.
- Journal writes MUST be atomic (`snapshot::write_atomic`).
- Journal is best-effort on the WRITE side: a failed journal write logs loudly (eprintln) but never aborts a settle.
- Boot recovery HOLD messages MUST contain the substring `HOLDING` (the CVM health alert greps for it).
- Gates per task: named tests + `cargo test -p gateway` (Task 1 also `-p sequencer`); final gate `cargo test --workspace` + `cargo clippy --workspace --all-targets` clean.
- No contract, prover-service, or public-API change.

---

### Task 1: `rollback_journal` module + serde derives + `recovery_action`

**Files:**
- Modify: `crates/sequencer/src/lib.rs` — `WindowWitness` gains `#[derive(Clone, serde::Serialize, serde::Deserialize)]` (fields `DefaultState`, `Vec<BatchOp>`, `BatchManifest` are already serde; add the serde dep path used elsewhere in the crate).
- Modify: `crates/gateway/src/prover_client.rs` — `ProveOutcome` and `PreparedSettle` gain `Serialize, Deserialize` (fields: `Digest`=[u8;32], `Vec<u8>`, `BTreeMap<[u8;32],(Digest,Vec<[u8;32]>)>` — all serde-ready).
- Create: `crates/gateway/src/rollback_journal.rs` + `mod rollback_journal;` in `main.rs`.

**Interfaces (produces):**
```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RollbackJournal {
    pub batch_id: u64,
    pub witness: sequencer::WindowWitness,
    pub ww: Vec<Withdrawal>,                       // the gateway's existing Withdrawal type
    pub prepared: Option<crate::prover_client::PreparedSettle>,
}
/// `<state_path>.rollback`
pub fn journal_path(state_path: &std::path::Path) -> std::path::PathBuf;
/// postcard-encode + snapshot::seal + snapshot::write_atomic. Err = string for the caller to log.
pub fn write(path: &std::path::Path, j: &RollbackJournal, seed: &[u8; 32]) -> Result<(), String>;
/// read + snapshot::open + postcard-decode. Distinguishes NotFound (Ok(None)) from corrupt (Err).
pub fn read(path: &std::path::Path, seed: &[u8; 32]) -> Result<Option<RollbackJournal>, String>;
pub fn delete(path: &std::path::Path);            // best-effort, logs on failure

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryAction { Stale, SealNeverPersisted, RollBack, RollForward, Hold }
/// Pure decision over the spec's table. `b_snap` = restored Counter B, `chain_bc` = on-chain batchCount,
/// `root_matches_prepared` = chain currentStateRoot == journal.prepared.new_root (false when prepared None),
/// `root_matches_settled` = chain currentStateRoot == restored l1_status.settled_root.
pub fn recovery_action(j_batch: u64, has_prepared: bool, b_snap: u64, chain_bc: u64,
                       root_matches_prepared: bool, root_matches_settled: bool) -> RecoveryAction;
```

**Steps (TDD):**
- [ ] Failing tests in `rollback_journal.rs` `#[cfg(test)]`:
  - `journal_seal_round_trip` — build a `RollbackJournal` from a real sealed window (pattern: existing `begin_window_settle_seals_and_takes_withdrawals` test constructs a `Gw` + seals), `write` → `read` → assert `batch_id`, `ops.len()`, `ww` equal; `prepared: Some` round-trips too.
  - `journal_wrong_seed_fails_closed` — `read` with a different seed returns `Err`, never a decoded journal.
  - `journal_missing_is_none` — `read` on a nonexistent path is `Ok(None)`.
  - `recovery_action_full_matrix` — every row of the spec table, incl.: `(j=5,prep=any,B=6,bc=6,rm_prep=any,rm_settled=true)`→Stale; `(5,_,5,5,_,_)`→SealNeverPersisted; `(5,_,6,5,_,_)`→RollBack; `(5,true,6,6,true,false)`→RollForward; `(5,false,6,6,false,false)`→Hold; `(5,true,6,6,false,false)`→Hold; `(5,_,5,6,_,_)`→Hold; `(5,_,6,7,_,_)`→Hold; `(5,_,7,_,_,_)`→Hold.
- [ ] Implement; use the scratch-dir tempfile pattern already used by snapshot tests.
- [ ] `cargo test -p gateway -p sequencer` green; commit.

### Task 2: settle-loop wiring (stage-1/stage-2/delete)

**Files:** Modify `crates/gateway/src/main.rs` (settle loop ~4740-4935).

**Consumes:** Task 1's `rollback_journal::{RollbackJournal, journal_path, write, delete}`.

**Steps:**
- [ ] Plumb `state_path: Option<PathBuf>` + `enclave_seed: [u8;32]` clones into the settle task (both are in scope in `main()`; the loop only journals when `state_path.is_some()`).
- [ ] **Stage 1:** after `begin_window_settle` returns `Some` (right where `witness_rb`/`ww_rb` are cloned): `write` the journal (`prepared: None`) and then write an immediate state snapshot (`snapshot_plain` under a short lock → `snapshot::seal` → `write_atomic` to the state path — same three calls as the 30 s loop). Both best-effort with loud eprintln on failure.
- [ ] **Stage 2:** in the settle `spawn_blocking`, after `prove_and_prepare` succeeds and before `settle_proved`: re-`write` the journal with `prepared: Some(prepared.clone())`. (Move the needed clones in.)
- [ ] **Delete** on: `SettleAttempt::Ok` commit arm; ProveFailed rollback arm; SettleFailed→RollBack arm; SettleFailed→RollForward commit arm; join-error rollback arm. **Keep** on both HOLD arms.
- [ ] Test `settle_loop_journal_lifecycle` (or nearest feasible unit): seal via `begin_window_settle`, write stage-1 journal, simulate the rollback arm (call `rollback_window` + `rollback_window_withdrawals` + `delete`), assert file gone and a re-seal reproduces the window (existing rollback test shape).
- [ ] `cargo test -p gateway` green; commit.

### Task 3: boot recovery in `main()`

**Files:** Modify `crates/gateway/src/main.rs` (between snapshot restore ~4382 and the continuity check ~4408).

**Consumes:** Task 1's `read`/`recovery_action`/`delete`; existing `gw.seq.rollback_window`, `gw.rollback_window_withdrawals`, `gw.commit_window_settle`, `l1.batch_count()`, `l1.current_root()`, `l1.sequencer_bond()`.

**Steps:**
- [ ] After `gw` is restored and `l1` exists: if `journal_path(state_path)` has a journal (`read`):
  - `Err` (corrupt) → eprintln containing `HOLDING`, keep file, fall through.
  - `Ok(Some(j))` → read `chain_bc` + `chain_root` (spawn_blocking, like the continuity check); compute `recovery_action(...)`; apply per the spec table (RollBack: `rollback_window(&j.witness)` + `rollback_window_withdrawals(j.ww)` + delete + log; RollForward: `ordered = j.witness.manifest.ordered.clone()`, `rejected = j.witness.manifest.rejected.iter().map(|(h,_)| *h).collect()`, `L1Status { settled_root: hex32(&prepared.outcome.new_root), batch_count: j.batch_id+1, last_tx: "(recovered at boot)".into(), bond: bond.to_string(), withdrawals_root: hex32(&prepared.outcome.withdrawals_root) }`, `commit_window_settle(j.batch_id, ordered, rejected, prepared, status)` + delete + log; Stale/SealNeverPersisted: delete + log; Hold: eprintln with `HOLDING`, keep file). If the chain reads fail → treat as Hold (never guess).
  - The existing continuity check runs AFTER recovery, unchanged — it is the final arbiter.
- [ ] Tests (main.rs tests mod, no real L1 — exercise the `Gw` mutations directly):
  - `boot_recovery_rollback_restores_reseal` — restore a `Gw` from a post-seal snapshot (use `snapshot_plain`/`boot_restored` as `snapshot_restart_round_trip_preserves_state` does), apply the journal RollBack arm, assert Counter B rewound + a fresh `begin_window_settle(bc)` re-seals the ops under the same batch_id.
  - `boot_recovery_roll_forward_commits` — post-seal restored `Gw` + journal with `prepared: Some`, apply the RollForward arm, assert `l1_status.settled_root == hex32(new_root)`, withdraw proofs served, Counter B consistent (== batch_id+1) so `begin_window_settle(batch_id+1)` passes the desync guard.
- [ ] `cargo test -p gateway` green; commit.

### Task 4: `ensure_bond` explicit gas

**Files:** Modify `crates/gateway/src/l1.rs`.

**Steps:**
- [ ] Refactor `send` to `fn send_opts(&self, target, sig, args, gas_limit: Option<&str>)` (private) appending `--gas-limit <n>` before `--rpc-url` when `Some`; keep `send(...)` = `send_opts(..., None)` so all call sites are untouched.
- [ ] `ensure_bond`: postBond call → `send_opts(&self.settlement.clone(), "postBond(uint256)", &[&short], Some("300000"))`, with a comment explaining the drpc lagging-estimate race (spec Problem 2).
- [ ] Test: if arg construction isn't directly testable without a child process, factor the argv-building into a pure helper and assert `--gas-limit 300000` present for postBond and absent for plain sends.
- [ ] `cargo test -p gateway` green; commit.

### Task 5: honest SETTLED finality in window mode

**Problem (found live 2026-07-09):** the tick loop marks batches SETTLED after `SETTLE_TICKS = 5` ticks (~3.5 s) — a demo-era simulation (`crates/gateway/src/main.rs:2763-2773`). On the real-Groth16 window path, users see "SETTLED" while the proof is still proving (or even if settles are wedged), contradicting the public TestnetNotice ("SETTLED lags ~a proof interval"). Withdrawals are NOT affected (they gate on real claim proofs); this is finality reporting.

**Files:**
- Modify: `crates/sequencer/src/lib.rs` — new `pub fn mark_window_settled(&mut self, window_id: u64)`: find the max tick-batch id `A` with `tick_window[A] <= window_id` and call `self.mark_settled(A)` (no-op when none). `tick_window` is private — this is the accessor.
- Modify: `crates/gateway/src/main.rs`:
  - `Gw` gains `#[serde(skip)] window_settle_mode: bool` (default false — snapshot format untouched; set from `main()` right after boot/restore when the prover is configured, next to `gw.prod = prod`).
  - Tick loop: gate BOTH the `pending_settle.push(...)` and the `SETTLE_TICKS` drain/mark block behind `!self.window_settle_mode` (legacy path byte-identical; window mode must not leak a growing `pending_settle`).
  - `commit_window_settle`: call `self.seq.mark_window_settled(batch_id)` BEFORE `prune_tick_window_settled(batch_id + 1)` (prune keeps a grace, but mark first anyway — ordering must not depend on the grace).

**Steps (TDD):**
- [ ] Failing tests: sequencer `mark_window_settled_hardens_through_window` (seal two tick batches in window W, `mark_window_settled(W)` → both orders SETTLED; a tick batch in window W+1 stays MATCHED); gateway `window_mode_defers_settled_until_commit` (with `window_settle_mode = true`, run > SETTLE_TICKS ticks after a fill → finality still MATCHED; then the `commit_window_settle` test-shape from `commit_window_settle_accumulates_and_advances` → SETTLED) and `legacy_mode_settles_after_ticks_unchanged` (flag false → old behavior).
- [ ] Implement; `cargo test -p gateway -p sequencer` green; commit.

### Final gate

- [ ] `cargo test --workspace` green, `cargo clippy --workspace --all-targets` clean, whole-branch review, merge to main.
