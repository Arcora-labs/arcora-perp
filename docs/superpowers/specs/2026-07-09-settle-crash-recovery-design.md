# Settle Crash-Recovery (rollback journal) + ensure_bond gas fix — Design

**Date:** 2026-07-09 · **Scope:** gateway + sequencer (one serde derive). NO contract,
prover-service, or snapshot-format change. Pre-alpha hardening.

## Problem 1 — restart-mid-settle is an unrecoverable wedge (killed the 0xEa11 stack)

The window-settle path runs: `begin_window_settle` (seals the window; `seal_window`
bumps Counter B = `state.next_batch_id`) → prove on GB10 (~10-13 min) → `settle_proved`
→ `commit_window_settle` OR `rollback_window`+`rollback_window_withdrawals`. The
rollback inputs (`witness_rb: WindowWitness`, `ww_rb: Vec<Withdrawal>`) are **in-memory
clones only**. Meanwhile the snapshot loop persists the post-seal state (Counter B
advanced) every 30 s.

If the gateway dies during the prove/settle window:
- **tx never landed:** restored snapshot has Counter B = id+1, chain batchCount = id →
  `begin_window_settle`'s desync guard errors every tick, **settles skip forever**.
- **tx landed, commit lost:** restored `l1_status.settled_root` = old root ≠ chain
  `currentStateRoot` → the boot continuity check **refuses to start**.

Either way: operators must redeploy fresh contracts and wipe all user accounts. During
alpha (real users, ~13-min proof windows) this is the top survivability risk.

## Problem 2 — `ensure_bond` is flaky on drpc

`ensure_bond` sends mint → approve → postBond back-to-back. drpc load-balances across
backends, so postBond's `eth_estimateGas` can hit a node that hasn't seen the
just-mined approve → reverts "InsufficientAllowance" → the send fails. As TVL grows the
5%-floor top-up becomes mandatory; a persistent estimate failure stalls settles
(underbond). The 100 USDC bond on the live stack was posted manually because of this.

## Design 1 — sealed sidecar rollback journal

**File:** `<DARKPERP_STATE>.rollback` (e.g. `/var/lib/darkperp/state.snap.rollback`).
Snapshot format is untouched — the journal is a separate file, so the live CVM snapshot
keeps loading byte-identically.

**Sealing:** the journal contains the full `WindowWitness` (incl. `pre_state:
DefaultState` — private notes), so it MUST be sealed exactly like the snapshot:
`snapshot::seal`/`snapshot::open` under `ENCLAVE_SEED`, `snapshot::write_atomic`.

**Content (postcard, own MAGIC/versioning inside the sealed plaintext):**
```rust
struct RollbackJournal {
    batch_id: u64,
    witness: WindowWitness,          // needs #[derive(Serialize, Deserialize)] (fields already serde)
    ww: Vec<Withdrawal>,
    prepared: Option<PreparedSettle>, // None until the prove returns; PreparedSettle/ProveOutcome need serde derives
}
```

**Write points (settle loop in `main.rs`):**
1. **Stage 1** — right after `begin_window_settle` returns `Some`: write the journal
   with `prepared: None`, then **immediately write a fresh state snapshot** (same
   `snapshot_plain`→`seal`→`write_atomic` as the 30 s loop; the settle task gets
   `enclave_seed` + `state_path` clones). This makes the on-disk pair (post-seal
   snapshot + journal) consistent at seal time, closing the ≤30 s pre-seal-snapshot race.
   Journal write failure = loud eprintln, settle continues (best-effort journal, no
   behavior regression vs today).
2. **Stage 2** — inside the settle `spawn_blocking`, after `prove_and_prepare`
   succeeds and BEFORE `settle_proved`: rewrite the journal with `prepared: Some(...)`.
3. **Delete** — on every path that resolves the window in-memory today: commit
   (success arm AND roll-forward arm), and both rollback arms (prove-failed,
   settle-failed RollBack, join-error rollback). **Keep** the journal on Hold arms.

**Boot recovery (in `main()`, after snapshot restore, before the continuity check;
only when `l1` + journal file present):** read chain `batch_count` + `current_root`,
let `B` = restored `gw.seq.state.next_batch_id`, `J` = journal:

| case | condition | action |
|---|---|---|
| STALE | `B == J.batch_id+1 && bc == J.batch_id+1 && l1_status.settled_root == chain root` | commit already happened; delete journal |
| SEAL-NEVER-PERSISTED | `B == J.batch_id && bc == J.batch_id` | pre-seal snapshot + tx never landed → seal effectively never happened; delete journal |
| ROLLBACK | `B == J.batch_id+1 && bc == J.batch_id` | `gw.seq.rollback_window(&J.witness)` + `gw.rollback_window_withdrawals(J.ww)`; delete journal; log recovered |
| ROLL-FORWARD | `B == J.batch_id+1 && bc == J.batch_id+1 && J.prepared.is_some() && chain root == prepared.new_root` | derive `ordered`/`rejected` from `J.witness.manifest`, build `L1Status{last_tx:"(recovered at boot)", bond: chain read}`, `gw.commit_window_settle(...)`; delete journal; log recovered |
| HOLD | anything else | loud eprintln (contains "HOLDING" so the health alert fires); keep journal; fall through (the continuity check decides whether boot proceeds) |

An **unreadable/corrupt journal** (present but unopenable): treat as HOLD with a loud
message — never delete data the operator may need; never crash a recoverable boot.

The decision is a **pure function** (`recovery_action(j_batch, has_prepared, b_snap,
chain_bc, root_matches_prepared, root_matches_settled) -> RecoveryAction`) so the whole
matrix is unit-testable, mirroring `settle_failure_action`.

Precondition check: `rollback_window`'s debug_assert (`Counter B == batch_id+1`) is
exactly the ROLLBACK row's condition — safe on a restored sequencer.

## Design 2 — `ensure_bond` explicit gas limit

Same-sender txs execute in nonce order, so mint → approve → postBond is
*execution*-correct; only postBond's **estimation** races the lagging read node. Fix:
skip estimation. Add a gas-limit-capable send (`send` gains an `Option<&str>`
gas-limit param or a `send_with_gas` wrapper appending `--gas-limit <n>`), and
`ensure_bond` posts the bond with an explicit `--gas-limit 300000` (postBond =
transferFrom + storage ≈ 120k worst-case; 300k is comfortable headroom, unused gas is
refunded). mint/approve keep estimating (no cross-tx dependency).

## Non-goals

Sparse-witness proving (post-alpha), attested prover P3-B, persisting `tick_window`/
receipts differently, any snapshot-format or contract change.

## Testing gates

`cargo test -p gateway -p sequencer` green (all existing + new), `cargo clippy
--workspace` clean. New tests: journal seal round-trip + wrong-seed fail-closed,
recovery_action full matrix, boot-shaped rollback/roll-forward integration tests
(pattern-match the existing `begin_window_settle_*` / rollback tests), ensure_bond
gas-limit arg presence.

## Deployment

Gateway binary swap on the CVM only. Snapshot format unchanged → stop (settle-idle
window) → swap → start. No contract/prover redeploy, no snapshot wipe.
