# SEC-025-A Operator Insurance Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `BatchOp::FundInsurance` its first production caller — an admin-gated endpoint that routes the operator's own real L1 deposit into `insurance_fund`, tracked by a persisted state machine that survives crashes and cannot complete without a settled second leg.

**Architecture:** The operator is an ordinary registered account; the admin key only redirects the destination of value the operator itself paid in. The endpoint reuses the existing deposit path (gateway-signed entry, SEC-019 misattribution guard, in-order id gate, L1 leaf fold) by *refactoring* that path's validation and bookkeeping into a shared helper rather than duplicating it. A four-state `Bootstrap` record on `Gw` keys completion on the window carrying the **second** leg, and an acknowledged-snapshot primitive closes two crash windows.

**Tech Stack:** Rust (axum, tokio, postcard, serde), Foundry for the contract suite. No new dependencies.

## Global Constraints

- **`crates/perp-core` is NOT touched.** `op_fund_insurance` already exists and is unchanged. This piece therefore moves **no vkey and no root**. If a task seems to need a `perp-core` change, stop and report.
- **Snapshot magic `DPSNAP3` → `DPSNAP4`.** 025-D takes `DPSNAP5`; do not take v5 here.
- **The rollback journal magic does NOT move.** Nothing in this piece changes `ProveOutcome`, `PreparedSettle` or `WindowWitness`. It stays `DPRBJL4`.
- **Never deploy. Never push.** Commit on the branch only.
- `cargo fmt --all` before every commit — CI runs `--check` (`.github/workflows/ci.yml:19`). Implementers on this workstream have repeatedly forgotten this.
- Baselines to preserve: `cargo test --workspace` = **555 passed / 50 suites**; `cd contracts && forge test` = **85 passed**; `cargo clippy --workspace --all-targets` = 0 warnings.
- Comments explain **why**, not what. A claim in a comment must be one the code can actually perform — three specs in this workstream were rejected for asserting mitigations no code path implements.
- `crates/gateway` is a **bin-only** crate. `cargo test -p gateway --lib` fails with exit 101; use `cargo test -p gateway`.

## File Structure

| File | Responsibility |
|---|---|
| `crates/gateway/src/bootstrap.rs` **(new)** | The `Bootstrap` enum, `MIN_BOOTSTRAP_INSURANCE`, and the pure amount/transition predicates. New file because `main.rs` is ~11k lines and this is a self-contained state machine with its own unit tests. |
| `crates/gateway/src/snapshot.rs` | `MAGIC` bump to `DPSNAP4` with a v4 rationale paragraph. |
| `crates/gateway/src/main.rs` | The `Gw.bootstrap` field; the acknowledged-snapshot request channel on `App`; the shared deposit validation/bookkeeping refactor; `fund_insurance_backed`; the admin endpoint and its authz; the `Complete` transition in `commit_window_settle`; tripwire count updates. |
| `docs/API.md` | The new admin endpoint, and the plain statement that insurance is a one-way valve. |

---

### Task 1: The acknowledged snapshot primitive

The spec requires forcing a durable snapshot at two points, and today there is no mechanism: `snapshot_notify` (`main.rs:7017`) is a bare `tokio::sync::Notify` — asynchronous, best-effort, and a handler can neither await it nor learn whether the write succeeded.

The periodic writer task is already the single writer and its `write` closure already returns `bool`. So add a request channel with a oneshot reply, and a third arm in its `select!`.

**Files:**
- Modify: `crates/gateway/src/main.rs` — `struct App` (~`:4372`), the writer task (~`:7014-7060`), the `App` construction site.
- Test: `crates/gateway/src/main.rs` (the existing `#[cfg(test)]` module)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type SnapshotAck = tokio::sync::oneshot::Sender<bool>;`
  - `App.snapshot_req: Option<tokio::sync::mpsc::Sender<SnapshotAck>>` — `None` when persistence is off.
  - `async fn snapshot_now(req: &Option<tokio::sync::mpsc::Sender<SnapshotAck>>) -> Result<(), String>` — free function; `Ok(())` only when a write completed successfully. `Err` when persistence is off, the channel is closed, or the write failed.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)]` module in `crates/gateway/src/main.rs`:

```rust
#[tokio::test]
async fn snapshot_now_reports_the_writers_verdict_and_refuses_when_unconfigured() {
    // Persistence off ⇒ there is no writer, so a caller must NOT be told the state
    // is durable. This is the case that matters: the bootstrap barrier runs before
    // an irreversible L1 deposit.
    assert!(snapshot_now(&None).await.is_err());

    // A writer that succeeds.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            let _ = ack.send(true);
        }
    });
    assert!(snapshot_now(&Some(tx)).await.is_ok());

    // A writer that FAILS must surface as Err, not as a silent success — the whole
    // point of the ack is that the caller learns the write did not land.
    let (tx2, mut rx2) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
    tokio::spawn(async move {
        while let Some(ack) = rx2.recv().await {
            let _ = ack.send(false);
        }
    });
    assert!(snapshot_now(&Some(tx2)).await.is_err());

    // A dead writer (receiver dropped) must also be an Err, never a hang.
    let (tx3, rx3) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
    drop(rx3);
    assert!(snapshot_now(&Some(tx3)).await.is_err());
}
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `cargo test -p gateway snapshot_now_reports_the_writers_verdict`
Expected: FAIL to compile — `cannot find function 'snapshot_now'` and `cannot find type 'SnapshotAck'`.

- [ ] **Step 3: Add the type and the free function**

Place next to `struct App` in `crates/gateway/src/main.rs`:

```rust
/// Reply channel for one acknowledged snapshot: `true` iff the sealed write landed.
type SnapshotAck = tokio::sync::oneshot::Sender<bool>;

/// Force a snapshot and WAIT for the single writer task's verdict.
///
/// Exists because the periodic writer is fire-and-forget: `snapshot_notify` is a bare
/// `Notify`, so a caller can neither await it nor learn whether the write succeeded.
/// Two call sites need that guarantee before doing something irreversible — sending an
/// L1 deposit whose blind lives only in memory, and submitting a settle whose window
/// would otherwise be unrecoverable at boot (SEC-025-A §3, §9).
///
/// FAIL-CLOSED in every direction: persistence off, writer gone, or write failed all
/// return `Err`. A caller must never read "no error" as "durable".
async fn snapshot_now(req: &Option<tokio::sync::mpsc::Sender<SnapshotAck>>) -> Result<(), String> {
    let Some(tx) = req else {
        return Err("state persistence is not configured — cannot guarantee durability".into());
    };
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    tx.send(ack_tx)
        .await
        .map_err(|_| "snapshot writer is gone".to_string())?;
    match ack_rx.await {
        Ok(true) => Ok(()),
        Ok(false) => Err("snapshot write failed".into()),
        Err(_) => Err("snapshot writer dropped the request".into()),
    }
}
```

- [ ] **Step 4: Run the test to confirm it passes**

Run: `cargo test -p gateway snapshot_now_reports_the_writers_verdict`
Expected: PASS (1 passed).

- [ ] **Step 5: Wire the channel into `App` and the writer task**

Add the field to `struct App` (after `l1`, keeping the doc-comment style of its neighbours):

```rust
    /// SEC-025-A: acknowledged-snapshot requests, served by the single periodic writer.
    /// `None` when persistence is off. See `snapshot_now`.
    snapshot_req: Option<tokio::sync::mpsc::Sender<SnapshotAck>>,
```

In `main()`, immediately before the `App` is constructed, create the channel — unconditionally, so the `App` field is populated only when persistence is on:

```rust
    let (snapshot_req_tx, mut snapshot_req_rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    let snapshot_req = state_path.as_ref().map(|_| snapshot_req_tx);
```

Set `snapshot_req` in the `App { ... }` literal.

Then in the writer task's `select!` (inside `if let Some(path) = state_path.clone()`), add the third arm. Replace:

```rust
                    tokio::select! {
                        _ = iv.tick() => {}
                        _ = notify.notified() => {}
                    }
                    write().await;
```

with:

```rust
                    // Third arm (SEC-025-A): an ACKNOWLEDGED request. The reply carries
                    // the writer's real verdict so the caller can refuse to proceed with
                    // an irreversible action after a failed write. Kept in this task so
                    // there is still exactly ONE writer — a second writer could interleave
                    // `.tmp` renames and lose a snapshot.
                    let mut ack: Option<SnapshotAck> = None;
                    tokio::select! {
                        _ = iv.tick() => {}
                        _ = notify.notified() => {}
                        Some(a) = snapshot_req_rx.recv() => { ack = Some(a); }
                    }
                    let ok = write().await;
                    if let Some(a) = ack {
                        let _ = a.send(ok);
                    }
```

- [ ] **Step 6: Verify the wiring compiles and nothing regressed**

Run: `cargo fmt --all && cargo test -p gateway`
Expected: PASS, count = previous gateway count + 1.

- [ ] **Step 7: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): an acknowledged snapshot, so a caller can learn the write landed"
```

---

### Task 2: The `Bootstrap` record, the floor, and `DPSNAP4`

**Files:**
- Create: `crates/gateway/src/bootstrap.rs`
- Modify: `crates/gateway/src/main.rs` (module declaration; `Gw` field), `crates/gateway/src/snapshot.rs:40`
- Test: `crates/gateway/src/bootstrap.rs` (unit tests), `crates/gateway/src/main.rs` (round-trip)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub const MIN_BOOTSTRAP_INSURANCE: i128` — the shared floor. **025-D reads this same constant.**
  - `pub enum Bootstrap { NotStarted, DepositApplied { note_commitment: [u8; 32], spend_key: [u8; 32], deposit_id: u64 }, InsuranceApplied { window_id: u64 }, Complete }` — `Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize`.
  - `pub fn amount_meets_floor(amount: i128) -> bool`
  - `Gw.bootstrap: Bootstrap`

- [ ] **Step 1: Write the failing tests**

Create `crates/gateway/src/bootstrap.rs`:

```rust
//! SEC-025-A: the operator insurance bootstrap state machine.
//!
//! Four states, not three. Keying completion on the window carrying the bootstrap
//! DEPOSIT is wrong in two orderings: (a) if `Deposit` lands and `FundInsurance` fails,
//! the deposit alone moves the state root, so that window settles and completion would
//! be recorded although no `FundInsurance` ever settled; (b) the first leg's window can
//! seal before the endpoint applies the second leg, because proving runs without the
//! gateway lock. So the window that matters is the SECOND leg's.

/// The minimum operator capitalization, in quote base units (USDC, 6dp) — 10,000 USDC.
///
/// A deployment risk policy with no source-derivable value, so it is a compile-time
/// constant rather than an env var: an env change must not be able to alter a
/// roll-forward decision made by a different process invocation.
///
/// SEC-025-D gates launch on `insurance_fund >= MIN_BOOTSTRAP_INSURANCE` and reads THIS
/// constant. The bootstrap endpoint is one-shot, so accepting a below-floor amount here
/// would spend the one-shot, leave 025-D permanently closed, and give neither piece a
/// retry path — an unlaunchable deployment. Hence the check, and hence one constant.
pub const MIN_BOOTSTRAP_INSURANCE: i128 = 10_000 * 1_000_000;

/// Where the operator insurance bootstrap has got to. Persisted inside `Gw`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Bootstrap {
    NotStarted,
    /// The L1 deposit was credited but the insurance transfer has not applied. Carries
    /// exactly what the second leg needs, because a pair-RETRY cannot work: the first
    /// `Deposit` already advanced `consumed_deposit_count`, so a retry fails
    /// `DepositOutOfOrder` before ever reaching `FundInsurance`.
    DepositApplied {
        note_commitment: [u8; 32],
        spend_key: [u8; 32],
        deposit_id: u64,
    },
    /// `FundInsurance` applied into this window. Completion waits for THIS id to commit.
    InsuranceApplied { window_id: u64 },
    Complete,
}

/// Whether an operator bootstrap amount is large enough to be worth the one-shot.
pub fn amount_meets_floor(amount: i128) -> bool {
    amount >= MIN_BOOTSTRAP_INSURANCE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_floor_rejects_a_dust_bootstrap_and_accepts_exactly_the_floor() {
        // The whole reason the floor exists: `insurance_fund > 0` passes on one base unit.
        assert!(!amount_meets_floor(1));
        assert!(!amount_meets_floor(MIN_BOOTSTRAP_INSURANCE - 1));
        assert!(amount_meets_floor(MIN_BOOTSTRAP_INSURANCE));
        assert!(amount_meets_floor(MIN_BOOTSTRAP_INSURANCE + 1));
        // A non-positive amount can never satisfy the floor.
        assert!(!amount_meets_floor(0));
        assert!(!amount_meets_floor(-MIN_BOOTSTRAP_INSURANCE));
    }

    #[test]
    fn the_record_round_trips_through_postcard_in_every_state() {
        for st in [
            Bootstrap::NotStarted,
            Bootstrap::DepositApplied {
                note_commitment: [7u8; 32],
                spend_key: [9u8; 32],
                deposit_id: 3,
            },
            Bootstrap::InsuranceApplied { window_id: 11 },
            Bootstrap::Complete,
        ] {
            let bytes = postcard::to_allocvec(&st).expect("encode");
            let back: Bootstrap = postcard::from_bytes(&bytes).expect("decode");
            assert_eq!(st, back);
        }
    }
}
```

- [ ] **Step 2: Run to confirm it fails**

Run: `cargo test -p gateway bootstrap::`
Expected: FAIL — `file not found for module 'bootstrap'` (the module is not declared yet).

- [ ] **Step 3: Declare the module and add the `Gw` field**

In `crates/gateway/src/main.rs`, beside the other `mod` declarations, add:

```rust
mod bootstrap;
```

Add to `struct Gw`, after `last_settled_root`:

```rust
    /// SEC-025-A: the operator insurance bootstrap state machine. Persisted, because a
    /// crash between the two legs must not lose the `(cm, spend_key)` the second leg
    /// needs, and because `Complete` is what 025-D's launch gate reads.
    #[serde(default = "bootstrap_not_started")]
    bootstrap: bootstrap::Bootstrap,
```

and the default fn beside the other `default =` helpers:

```rust
fn bootstrap_not_started() -> bootstrap::Bootstrap {
    bootstrap::Bootstrap::NotStarted
}
```

**Note for the implementer:** `#[serde(default)]` here is documentation, not
compatibility — postcard is positional, so an old snapshot does not become loadable.
That is exactly why Step 4 bumps the magic. Do not write a comment claiming otherwise;
the tree already pins this behaviour (`main.rs:11008-11061`).

Initialize `bootstrap: bootstrap::Bootstrap::NotStarted` at every `Gw { .. }`
construction site (`boot_with`; the compiler will name any others).

- [ ] **Step 4: Bump the snapshot magic**

In `crates/gateway/src/snapshot.rs`, extend the `MAGIC` doc comment with a v4 paragraph in the same style as v2/v3, then change the constant:

```rust
/// v4: SEC-025-A added `Gw.bootstrap`, the operator insurance bootstrap record. `Gw` is
/// encoded positionally by postcard (`snapshot_plain` writes `(self, mkt_px)`), so a v3
/// snapshot read by a v4 binary shifts every field after it. `#[serde(default)]` does not
/// rescue that — postcard is not self-describing. SEC-025-D adds another `Gw` field and
/// takes DPSNAP5; do not reuse v4 for it.
const MAGIC: &[u8; 8] = b"DPSNAP4\0";
```

- [ ] **Step 5: Add the snapshot round-trip test**

In the `#[cfg(test)]` module of `crates/gateway/src/main.rs`:

```rust
#[test]
fn the_bootstrap_record_survives_a_snapshot_round_trip() {
    let mut gw = Gw::boot();
    gw.bootstrap = bootstrap::Bootstrap::InsuranceApplied { window_id: 42 };
    let plain = gw.snapshot_plain();
    let restored = Gw::boot_restored(&plain).expect("restore");
    // The launch gate 025-D will read this, so losing it across a restart would
    // silently reopen the question the record exists to answer.
    assert_eq!(
        restored.bootstrap,
        bootstrap::Bootstrap::InsuranceApplied { window_id: 42 }
    );
}
```

- [ ] **Step 6: Run the suite**

Run: `cargo fmt --all && cargo test -p gateway`
Expected: PASS. New tests: `bootstrap::tests::*` (2) and `the_bootstrap_record_survives_a_snapshot_round_trip` (1).

- [ ] **Step 7: Commit**

```bash
git add crates/gateway/src/bootstrap.rs crates/gateway/src/main.rs crates/gateway/src/snapshot.rs
git commit -m "feat(gateway): the bootstrap record, the shared floor, and DPSNAP4"
```

---

### Task 3: Factor the deposit guards out of `account_confirm_deposit`

The bootstrap must reach the *same* guards the user deposit path uses — tx-hash dedup, the `from` binding, the SEC-019 misattribution guard, the u128→i128 conversion, the in-order id gate, the note-blind derivation — and the *same* success bookkeeping. A raw `Deposit → FundInsurance` helper would reach none of them, which is why an earlier version of the spec asserted a test it could not have passed.

**Prefer the refactor over duplication.** Duplicated security bookkeeping is how one copy drifts.

**Files:**
- Modify: `crates/gateway/src/main.rs:1996-2141` (`account_confirm_deposit`)
- Test: `crates/gateway/src/main.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces, on `impl Gw`:
  - `fn validated_deposit(&self, key: &[u8;32], from: [u8;20], owner_commit_onchain: [u8;32], amount: u128, deposit_id: u64, tx: &str, market: u64) -> Result<ValidatedDeposit, String>` — every check, **no mutation**.
  - `struct ValidatedDeposit { wallet: Wallet, amt: i128, note_blind: [u8; 32], deposit_blind: [u8; 32] }`
  - `fn commit_deposit_bookkeeping(&mut self, key: &[u8;32], owner_commit_onchain: &[u8;32], tx: &str)` — bumps `deposit_counter`, removes the authorization, marks the tx processed.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn validated_deposit_checks_without_mutating_and_bookkeeping_is_separable() {
    let mut gw = Gw::boot();
    let key = gw.account_register_for_test();
    let (from, commit, amount, id) = gw.authorize_for_test(&key, 5_000_000);

    // The validation half must be pure: calling it twice must succeed twice, because
    // nothing it does can consume the authorization or advance a counter.
    let before = gw.accounts.get(&key).unwrap().deposit_counter;
    let v1 = gw
        .validated_deposit(&key, from, commit, amount, id, "0xtx", 0)
        .expect("first validate");
    let v2 = gw
        .validated_deposit(&key, from, commit, amount, id, "0xtx", 0)
        .expect("second validate must also succeed — validation must not mutate");
    assert_eq!(v1.note_blind, v2.note_blind);
    assert_eq!(gw.accounts.get(&key).unwrap().deposit_counter, before);
    assert!(gw.accounts.get(&key).unwrap().deposit_authorizations.contains_key(&commit));
    assert!(!gw.processed_deposit_txs.contains("0xtx"));

    // The bookkeeping half, applied once, must consume all three.
    gw.commit_deposit_bookkeeping(&key, &commit, "0xtx");
    assert_eq!(gw.accounts.get(&key).unwrap().deposit_counter, before + 1);
    assert!(!gw.accounts.get(&key).unwrap().deposit_authorizations.contains_key(&commit));
    assert!(gw.processed_deposit_txs.contains("0xtx"));

    // And the guards must now refuse a replay of the same tx.
    assert!(gw
        .validated_deposit(&key, from, commit, amount, id, "0xtx", 0)
        .is_err());
}
```

**Implementer note:** `account_register_for_test` and `authorize_for_test` are test
helpers you must add if they do not already exist — register an account, bind
`deposit_address` to a fixed 20-byte address, call `account_authorize_deposit`, and
return `(from, owner_commit, amount, deposit_id = seq.state.consumed_deposit_count)`.
Keep them `#[cfg(test)]`. If equivalents already exist in the test module, use those
instead of adding near-duplicates.

- [ ] **Step 2: Run to confirm it fails**

Run: `cargo test -p gateway validated_deposit_checks_without_mutating`
Expected: FAIL to compile — `no method named 'validated_deposit'`.

- [ ] **Step 3: Extract, without changing behaviour**

Split `account_confirm_deposit` (`main.rs:1996-2141`) into the two halves. Move every check from its body — market exists, tx dedup, `from == deposit_address` (fail-closed if unbound), the SEC-019 guard, the checked u128→i128, the in-order id gate, and the `0xB0 ‖ deposit_counter` note blind — into `validated_deposit`, returning `ValidatedDeposit`. Move the three success mutations at `:2133-2139` into `commit_deposit_bookkeeping`.

`account_confirm_deposit` then becomes: `validated_deposit(...)?` → `fund_amount(...)` with its existing two-arm error mapping **kept verbatim** → `commit_deposit_bookkeeping(...)` → `Ok(amt)`.

**Do not reword the two `FundAmountError` operator messages.** They document a real
asymmetry (a credited-but-unbound deposit is recoverable; a re-run is not) and are
load-bearing for an operator reading logs at 3am.

- [ ] **Step 4: Run the test and the whole gateway suite**

Run: `cargo fmt --all && cargo test -p gateway`
Expected: PASS. **Every pre-existing gateway test must still pass** — this task is a pure refactor and any behaviour change is a defect.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "refactor(gateway): split the deposit guards from their bookkeeping"
```

---

### Task 4: `fund_insurance_backed` and the admin endpoint

**Files:**
- Modify: `crates/gateway/src/main.rs` (new fn near `seed_insurance_unbacked` ~`:4238`; new handler near `post_v1_admin_resume` ~`:4998`; route registration ~`:6349`)
- Test: `crates/gateway/src/main.rs`

**Interfaces:**
- Consumes: `bootstrap::{Bootstrap, amount_meets_floor}` (Task 2); `Gw::validated_deposit`, `Gw::commit_deposit_bookkeeping`, `ValidatedDeposit` (Task 3); `snapshot_now`, `App.snapshot_req` (Task 1).
- Produces:
  - `fn fund_insurance_backed(seq: &mut Sequencer, wallet: &Wallet, amount: i128, note_blind: [u8;32], from: [u8;20], deposit_id: u64, deposit_blind: [u8;32]) -> Result<([u8;32], [u8;32]), String>` — applies `Deposit` then `FundInsurance`; returns `(note_commitment, spend_key)`.
  - `async fn post_v1_admin_insurance_bootstrap(State(app): State<Shared>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> impl IntoResponse`
  - Route: `POST /v1/admin/insurance/bootstrap`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn only_the_configured_operator_payer_can_reach_the_insurance_fund() {
    // THE central security property of this piece — and note what it does NOT claim.
    // This is an ENDPOINT property, not a protocol invariant: `FundInsurance` carries no
    // payer and the guest validates with `expected_owner = None`, so a compromised
    // sequencer can spend any custodied note directly. This test pins the endpoint.
    let mut gw = Gw::boot();
    let key = gw.account_register_for_test();
    let operator = [0xAAu8; 20];
    let attacker = [0xBBu8; 20];

    assert!(
        !insurance_bootstrap_payer_ok(&operator, &operator),
        "placeholder — replace with the real assertion below"
    );
}

#[test]
fn a_below_floor_bootstrap_is_refused_before_either_leg_applies() {
    // Without this, the one-shot is spent on dust, 025-D's launch gate stays closed,
    // and NEITHER piece has a retry path — an unlaunchable deployment.
    let mut gw = Gw::boot();
    let before_insurance = gw.seq.state.insurance_fund;
    let before_count = gw.seq.state.consumed_deposit_count;

    let err = gw
        .bootstrap_insurance_for_test(bootstrap::MIN_BOOTSTRAP_INSURANCE - 1)
        .expect_err("a below-floor amount must be refused");
    assert!(err.contains("minimum"), "message should name the floor: {err}");

    // "Before either leg" is the load-bearing part: no deposit may have been consumed.
    assert_eq!(gw.seq.state.insurance_fund, before_insurance);
    assert_eq!(gw.seq.state.consumed_deposit_count, before_count);
    assert_eq!(gw.bootstrap, bootstrap::Bootstrap::NotStarted);
}

#[test]
fn a_successful_bootstrap_raises_insurance_without_raising_external_in_twice() {
    // The SEC-024 property, re-pinned at this new call site: the Deposit leg raises
    // `external_in` exactly once; the FundInsurance leg is a TRANSFER and must not
    // touch it at all.
    let mut gw = Gw::boot();
    let ext_before = gw.seq.state.external_in;
    let ins_before = gw.seq.state.insurance_fund;
    let amount = bootstrap::MIN_BOOTSTRAP_INSURANCE;

    gw.bootstrap_insurance_for_test(amount).expect("bootstrap");

    assert_eq!(gw.seq.state.external_in, ext_before + amount);
    assert_eq!(gw.seq.state.insurance_fund, ins_before + amount);
    assert!(matches!(
        gw.bootstrap,
        bootstrap::Bootstrap::InsuranceApplied { .. }
    ));
}
```

Replace the placeholder body of the first test with the real one once
`bootstrap_insurance_for_test` exists — it must take an explicit payer address and assert
that a payer other than the configured operator is refused while the operator's succeeds,
with `insurance_fund` unchanged in the refused case.

- [ ] **Step 2: Run to confirm they fail**

Run: `cargo test -p gateway insurance_bootstrap`
Expected: FAIL to compile — the helpers do not exist.

- [ ] **Step 3: Implement `fund_insurance_backed`**

Place it directly after `seed_insurance_unbacked` so the contrast is visible:

```rust
/// SEC-025-A: the BACKED sibling of `seed_insurance_unbacked`, and the first production
/// caller of `BatchOp::FundInsurance`.
///
/// Exactly three fields differ from the demo funnel, and they are the three the demo
/// fabricates: `from` is the real L1 payer, `deposit_blind` is the authorization blind the
/// gateway actually issued, and `deposit_id` is the chain-assigned id. So this path folds
/// the SAME leaf the vault chained on-chain, and `_requireDepositPrefix` will match.
///
/// No `refuse_unbacked_mint` here: that guard stops value being asserted without backing,
/// and this path is backed by construction. Calling it would be cargo-culting a check whose
/// premise does not apply.
///
/// Deliberately no `archive.record`: the note is consumed in the same breath and no wallet
/// ever needs to decrypt it — same reasoning as the demo funnel.
fn fund_insurance_backed(
    seq: &mut Sequencer,
    wallet: &Wallet,
    amount: i128,
    note_blind: [u8; 32],
    from: [u8; 20],
    deposit_id: u64,
    deposit_blind: [u8; 32],
) -> Result<([u8; 32], [u8; 32]), String> {
    let cm = Note::new(wallet.owner, 0, amount, note_blind).commitment::<Keccak256>();
    seq.apply(&BatchOp::Deposit {
        owner: wallet.owner,
        asset_id: 0,
        amount,
        blinding: note_blind,
        from,
        deposit_id,
        deposit_blind,
    })
    .map_err(|e| format!("operator deposit leg failed (nothing applied): {e:?}"))?;
    seq.apply(&BatchOp::FundInsurance {
        note_commitment: cm,
        spend_key: wallet.spend_key,
    })
    .map_err(|e| {
        format!(
            "insurance transfer failed AFTER the operator note was minted: {e:?}. \
             The value is a live unspent note; resume the SECOND LEG ALONE. A pair-retry \
             cannot work — the deposit already advanced consumed_deposit_count, so it \
             would fail DepositOutOfOrder."
        )
    })?;
    Ok((cm, wallet.spend_key))
}
```

- [ ] **Step 4: Implement the `Gw` driver**

```rust
impl Gw {
    /// Drive the bootstrap. Ordering is load-bearing:
    /// floor check → validate → apply both legs → record → bookkeeping.
    /// The floor check runs FIRST so a below-floor amount cannot spend the one-shot.
    fn bootstrap_insurance(
        &mut self,
        key: &[u8; 32],
        expected_payer: [u8; 20],
        from: [u8; 20],
        owner_commit_onchain: [u8; 32],
        amount_u128: u128,
        deposit_id: u64,
        tx: &str,
        market: u64,
    ) -> Result<(), String> {
        if self.bootstrap == bootstrap::Bootstrap::Complete {
            return Err("insurance bootstrap already completed — this endpoint is one-shot".into());
        }
        // The only non-forgeable discriminator: the on-chain payer, taken from the parsed
        // receipt rather than the request body. Without it an admin key could route ANY
        // user's deposit into the fund, because the engine validates the spend with
        // `expected_owner = None` and the gateway custodies every account's spend key.
        if from != expected_payer {
            return Err("deposit payer is not the configured INSURANCE_OPERATOR_ADDRESS".into());
        }
        let amount = i128::try_from(amount_u128)
            .map_err(|_| "deposit amount does not fit i128".to_string())?;
        if !bootstrap::amount_meets_floor(amount) {
            return Err(format!(
                "bootstrap amount {amount} is below the minimum {} — refusing so the \
                 one-shot is not spent on an amount that would leave the launch gate closed",
                bootstrap::MIN_BOOTSTRAP_INSURANCE
            ));
        }
        let v = self.validated_deposit(
            key,
            from,
            owner_commit_onchain,
            amount_u128,
            deposit_id,
            tx,
            market,
        )?;
        let (cm, spend_key) = fund_insurance_backed(
            &mut self.seq,
            &v.wallet,
            v.amt,
            v.note_blind,
            from,
            deposit_id,
            v.deposit_blind,
        )
        .map_err(|e| {
            // Record what the second leg needs even when it failed, so a resume is possible.
            self.bootstrap = bootstrap::Bootstrap::DepositApplied {
                note_commitment: Note::new(v.wallet.owner, 0, v.amt, v.note_blind)
                    .commitment::<Keccak256>(),
                spend_key: v.wallet.spend_key,
                deposit_id,
            };
            e
        })?;
        let _ = (cm, spend_key);
        self.bootstrap = bootstrap::Bootstrap::InsuranceApplied {
            window_id: self.seq.state.next_batch_id,
        };
        self.commit_deposit_bookkeeping(key, &owner_commit_onchain, tx);
        Ok(())
    }
}
```

**Implementer note on the error arm:** the closure mutates `self.bootstrap` while
`self.seq` is borrowed by the call. If the borrow checker refuses, restructure to compute
the commitment *before* the call and assign the record in a `match` on the result — do not
work around it by dropping the record, which is what makes the resume path possible.

- [ ] **Step 5: Implement the endpoint**

Follow `post_v1_admin_resume` exactly for the authz shape. The handler reads
`INSURANCE_OPERATOR_ADDRESS` from env, parses the tx hash from the JSON body, calls
`api_key_from(&headers)` for the operator account, verifies the receipt through
`l1.verify_deposit_tx` on a blocking thread exactly as `post_v1_deposit_onchain` does,
then calls `bootstrap_insurance` **inside one `app.gw.lock()` hold** so the snapshot writer
cannot observe the state between the two legs.

Return: 503 when `FIN_ADMIN_KEY` is unset/empty; 401 on a missing/wrong admin key; 400 on a
missing/unparsable body or an unconfigured `INSURANCE_OPERATOR_ADDRESS`; 409 when the record
is already `Complete`; 200 with the resulting `bootstrap` state on success.

Register the route beside the existing admin route:

```rust
        .route(
            "/v1/admin/insurance/bootstrap",
            post(post_v1_admin_insurance_bootstrap),
        )
```

- [ ] **Step 6: Run the suite**

Run: `cargo fmt --all && cargo test -p gateway`
Expected: PASS, including the three new tests.

- [ ] **Step 7: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): the operator insurance bootstrap endpoint, payer-bound and floor-gated"
```

---

### Task 5: Completion, resume, and the durability barriers

**Files:**
- Modify: `crates/gateway/src/main.rs` — `commit_window_settle` (~`:2323`), the endpoint from Task 4, the settle loop's pre-submit path
- Test: `crates/gateway/src/main.rs`

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: no new public names; `Bootstrap::InsuranceApplied → Complete` transition inside `commit_window_settle`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn completion_requires_the_window_carrying_the_second_leg() {
    // The defect this whole four-state design exists to prevent: if the DEPOSIT's window
    // commits while FundInsurance has not applied, completion must NOT be recorded.
    let mut gw = Gw::boot();
    gw.bootstrap = bootstrap::Bootstrap::DepositApplied {
        note_commitment: [1u8; 32],
        spend_key: [2u8; 32],
        deposit_id: 0,
    };
    gw.commit_window_settle_for_test(0);
    assert_eq!(
        gw.bootstrap,
        bootstrap::Bootstrap::DepositApplied {
            note_commitment: [1u8; 32],
            spend_key: [2u8; 32],
            deposit_id: 0
        },
        "a deposit-only window must never complete the bootstrap"
    );

    // And a DIFFERENT window committing must not complete it either.
    gw.bootstrap = bootstrap::Bootstrap::InsuranceApplied { window_id: 7 };
    gw.commit_window_settle_for_test(6);
    assert_eq!(gw.bootstrap, bootstrap::Bootstrap::InsuranceApplied { window_id: 7 });

    // Only the matching window completes it.
    gw.commit_window_settle_for_test(7);
    assert_eq!(gw.bootstrap, bootstrap::Bootstrap::Complete);
}

#[test]
fn completion_is_not_reachable_from_a_fill_cut_or_a_liquidation_penalty() {
    // `insurance_fund` moves for reasons that are not a bootstrap. The RECORD must not.
    let mut gw = Gw::boot();
    let before = gw.bootstrap.clone();
    gw.seq.state.insurance_fund += bootstrap::MIN_BOOTSTRAP_INSURANCE * 10;
    assert_eq!(gw.bootstrap, before, "a balance is not a marker");
}
```

**Implementer note:** `commit_window_settle_for_test(batch_id)` is a `#[cfg(test)]` helper
that calls the real `commit_window_settle` with a minimal `PreparedSettle` and empty
manifests. Build it from the existing test helpers for `PreparedSettle` if any exist;
otherwise construct one directly. Do **not** add a parallel transition path for tests — the
test must exercise the real function, or it pins nothing.

Deliberately **not** tested: that a `finalSettle` cannot set `Complete`. The spec (§4)
chooses the weaker property on purpose — a `finalSettle` that committed this window means
the capitalization genuinely landed and was proof-verified, and the deployment is in
terminal close-only anyway. 025-D defends the strong property; this piece must not claim it.

- [ ] **Step 2: Run to confirm they fail**

Run: `cargo test -p gateway completion_requires_the_window`
Expected: FAIL — the transition does not exist, so `Complete` is never reached.

- [ ] **Step 3: Add the transition**

In `commit_window_settle`, after `self.last_settled_root = prepared.outcome.new_root;`:

```rust
        // SEC-025-A: the bootstrap completes only when the window carrying the SECOND leg
        // commits. Keyed on the id rather than on a predicate, because this function
        // receives no witness and no post-state — the replay built during proving is
        // discarded, with one scalar surviving it.
        if let bootstrap::Bootstrap::InsuranceApplied { window_id } = self.bootstrap {
            if window_id == batch_id {
                self.bootstrap = bootstrap::Bootstrap::Complete;
            }
        }
```

- [ ] **Step 4: Add the resume path to the endpoint**

In `bootstrap_insurance`, before the payer check, handle the resume case: when the record is
`DepositApplied { note_commitment, spend_key, deposit_id }`, apply **only**
`BatchOp::FundInsurance { note_commitment, spend_key }`, set
`InsuranceApplied { window_id: self.seq.state.next_batch_id }`, and return — never a second
`Deposit`. Add a test asserting that a resume from `DepositApplied` does not advance
`consumed_deposit_count`.

- [ ] **Step 5: Add the two durability barriers**

In the endpoint handler, after a successful `bootstrap_insurance` and **after releasing the
`gw` lock**, call `snapshot_now(&app.snapshot_req).await`. On `Err`, return 500 naming the
failure — the operator must learn the record is not durable, because a crash now loses the
`(cm, spend_key)` the resume path needs.

In the settle loop, when the sealed window's id equals an `InsuranceApplied { window_id }`,
require `snapshot_now` to succeed **before** submitting the settle. Rationale to put in the
comment: if that window lands on-chain before its post-seal snapshot persists, boot restores
Counter B at `J` while the chain reads `J+1`, the recovery table returns `Hold` rather than
`RollForward`, `commit_window_settle` never runs, and a genuinely settled bootstrap never
reaches `Complete` — with the one-shot already spent.

- [ ] **Step 6: Run the full workspace**

Run: `cargo fmt --all && cargo test --workspace && cargo clippy --workspace --all-targets`
Expected: workspace PASS (555 + the new tests), clippy 0 warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): complete on the second leg's window, resume, and make it durable"
```

---

### Task 6: Tripwires, docs, and the honest claims

**Files:**
- Modify: `crates/gateway/src/main.rs:8124-8197` (the call-site tripwire test), `docs/API.md`
- Test: the tripwire test itself

- [ ] **Step 1: Run the tripwire test to see it fail**

Run: `cargo test -p gateway unbacked_funding_has_exactly_the_known_call_sites`
Expected: FAIL — `BatchOp::Deposit` is now constructed in one more place (currently pinned at 5).

- [ ] **Step 2: Update the count and its prose**

Raise the `BatchOp::Deposit` count from 5 to 6 and extend the justification text to name the new site: `fund_insurance_backed`, the backed operator bootstrap, which uses real L1 leaf fields. **Update the prose, never the count alone** — the message is the mechanism by which the next reader judges whether a new site was legitimate.

Leave `fund_amount_unbacked` (7) and `fund_amount` (3) untouched; this piece adds neither.

- [ ] **Step 3: Document the endpoint**

Add `POST /v1/admin/insurance/bootstrap` to `docs/API.md` beside the existing admin route. State plainly:

- the three required bindings and every refusal code;
- the minimum amount and why it exists;
- that it is **one-shot**;
- that **insurance is a one-way valve** — no op removes value from the fund except covering bad debt, so the operator's USDC becomes permanently protocol-owned with no claim path. An operator must not discover this afterwards.

Do **not** write that this guarantees only operator funds can ever reach `insurance_fund`.
That is an endpoint property, not a protocol invariant — a compromised sequencer can spend
any custodied note directly. Say what is true.

- [ ] **Step 4: Full verification**

Run: `cargo fmt --all --check && cargo test --workspace && cargo clippy --workspace --all-targets && (cd contracts && forge test)`
Expected: workspace PASS, clippy clean, forge **85 passed** (unchanged — no contract change in this piece).

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/main.rs docs/API.md
git commit -m "docs(sec025a): the bootstrap endpoint, and what it does not promise"
```

---

## Branch completion

- [ ] `cargo test --workspace` green; `forge test` still **85**; fmt and clippy clean.
- [ ] Confirm which tests were verified to **fail before the change** — at minimum the payer binding, the below-floor refusal, and the second-leg window keying.
- [ ] Run `superpowers:requesting-code-review` on the whole branch, and send the diff to Codex (`mcp__codex__codex`, `sandbox: read-only`, `cwd` = repo). **Codex rejected this piece's spec twice and found three more issues on the third pass — expect it to find more in the implementation.** Verify every finding at source before accepting it.
- [ ] **Do not deploy.** No `perp-core` change, so no vkey and no root movement. `DPSNAP3 → DPSNAP4` means the cutover's state wipe is still required.
- [ ] **025-D must land before launch** and takes `DPSNAP5`. It reads `bootstrap::MIN_BOOTSTRAP_INSURANCE` — if that constant moves, both pieces move together.
- [ ] **SEC-028 remains open.** This piece works around its second cause (the authorization-durability window) with the snapshot barrier; it does not fix the replay wedge.
