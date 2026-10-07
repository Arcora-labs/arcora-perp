# SEC-025-D Trading Gate Implementation Plan


**Goal:** Keep order ingress closed on a fresh production deployment until it is genuinely capitalized and has demonstrably settled a normal `settleBatch`, and make sure a wind-down can never open it.

**Architecture:** A persisted `TradingGate` on `Gw`, flipped once in `commit_window_settle` from a predicate whose post-state terms ride in on `ProveOutcome`, gated by a **block-pinned** three-way L1 read that excludes `finalSettle`. Enforcement sits at every path that can put an order or a fill into a window, not just the HTTP handler.

**Tech Stack:** Rust (axum, tokio, postcard, serde), `cast` for L1 reads. No new dependencies.

## Global Constraints

- **`crates/perp-core` is NOT touched.** No vkey and no root movement. If a task seems to need one, stop and report.
- **Snapshot magic `DPSNAP4` → `DPSNAP5`.** 025-A already took v4. Two pieces claiming one magic means whichever lands second changes the positional schema without changing its guard — the exact hazard the magic exists for.
- **Rollback journal magic `DPRBJL4` → `DPRBJL5`,** because `PreparedSettle` is journaled and this plan adds fields to `ProveOutcome`.
- **`MIN_BOOTSTRAP_INSURANCE` already exists** in `crates/gateway/src/bootstrap.rs`, shared with 025-A. **Do not define a second constant.** 025-A and 025-D must ship as one artifact — a floor differing between the two builds recreates the deadlock the shared constant exists to prevent.
- **Never deploy. Never push.** Commit on the branch only.
- `cargo fmt --all` before every commit — CI runs `--check`, and CI runs clippy with `-D warnings` (`.github/workflows/ci.yml:21`), so a warning fails CI even though a local build exits 0.
- Baselines to preserve: `cargo test -p gateway` = **222**, `cargo test --workspace` = **572 / 50 suites**, `forge test` = **85**, clippy "No issues found".
- Comments explain **why**. A claim in a comment must be one the code can actually perform — every must-fix in the last branch's final review was prose that broke this rule.
- `crates/gateway` is **bin-only**: `cargo test -p gateway --lib` fails with exit 101.
- A call-site scanner in the test module pins `BatchOp::Deposit` at 7, `fund_amount(` at 3, `fund_amount_unbacked(` at 7, `fund_insurance_backed(` at 2. If your work moves any count, update the count **and** its prose breakdown. Note the scanner counts occurrences in its own source file, so naming an op inside a new comment inflates the count it describes.

## File Structure

| File | Responsibility |
|---|---|
| `crates/gateway/src/trading_gate.rs` **(new)** | The `TradingGate` enum, `GATE_OPEN_CONFIRMATIONS`, and the pure predicate + the pure `GateObservation` classifier. New file so the decision logic is unit-testable without an L1 or a settle loop. |
| `crates/gateway/src/prover_client.rs` | Two new `ProveOutcome` scalars, populated where the replayed post-state already exists. |
| `crates/gateway/src/rollback_journal.rs` | `MAGIC` → `DPRBJL5` with a v5 rationale. |
| `crates/gateway/src/snapshot.rs` | `MAGIC` → `DPSNAP5` with a v5 rationale. |
| `crates/gateway/src/l1.rs` | Block-pinned readers: a `closeOnly` bool, plus block-pinned variants of the root and count reads. |
| `crates/gateway/src/main.rs` | The `Gw.trading_gate` field; the opening check in `commit_window_settle`; enforcement at all four ingress paths. |

---

### Task 1: The gate type, the confirmation policy, and the pure predicate

**Files:**
- Create: `crates/gateway/src/trading_gate.rs`
- Modify: `crates/gateway/src/main.rs` (module declaration; `Gw` field; every `Gw { .. }` literal), `crates/gateway/src/snapshot.rs` (`MAGIC`)
- Test: `crates/gateway/src/trading_gate.rs`, `crates/gateway/src/main.rs`

**Interfaces:**
- Consumes: `bootstrap::MIN_BOOTSTRAP_INSURANCE`.
- Produces:
  - `pub enum TradingGate { Closed, Open }` — `Clone, Debug, PartialEq, Serialize, Deserialize`
  - `pub const GATE_OPEN_CONFIRMATIONS: u64 = 12;`
  - `pub enum GateObservation { OpensGate, StaysClosed, Inconclusive }`
  - `pub fn classify(chain_batch_count: u64, sealed_batch_id: u64, chain_root: [u8;32], our_new_root: [u8;32], close_only: bool) -> GateObservation`
  - `pub fn predicate_met(mode_is_normal: bool, insurance_fund: i128, deposit_count: u64, min_deposits: u64) -> bool`
  - `Gw.trading_gate: TradingGate`

- [ ] **Step 1: Write the failing tests**

Create `crates/gateway/src/trading_gate.rs`:

```rust
//! SEC-025-D: the launch gate. A **launch** gate, not a circuit breaker — it opens once
//! and never re-closes. Both `insurance_fund` and `Mode` are non-monotonic, so the
//! predicate can become false later; re-closing a blunt ingress gate would then block
//! reduce-only EXITS, trapping users exactly when they most need to leave. The answer to
//! a depleted fund is a separate exposure-increase breaker plus a recapitalization path;
//! neither exists yet, and both are recorded follow-ups.

use crate::bootstrap::MIN_BOOTSTRAP_INSURANCE;

/// How deep the pinned block must be before an observation may OPEN the gate. A reorg
/// that unwound the capitalization settle after opening would leave trading enabled
/// against a fund that no longer exists on L1. `cast` defaults to one confirmation;
/// inheriting that default silently is a policy choice made by accident.
pub const GATE_OPEN_CONFIRMATIONS: u64 = 12;

/// The minimum credited deposits a launch-ready deployment must show. The operator's own
/// bootstrap deposit is one, so this is deliberately small — it exists to reject a
/// deployment that has never credited anything, not to demand traffic.
pub const MIN_BOOTSTRAP_DEPOSITS: u64 = 1;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TradingGate {
    Closed,
    Open,
}

/// What one block-pinned L1 observation says about opening.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GateObservation {
    /// Our `settleBatch` demonstrably landed and the chain is not in close-only.
    OpensGate,
    /// A different transition landed, or the chain IS in close-only — commit closed.
    StaysClosed,
    /// The read failed or lagged. **Must not resolve the gate**; retry or hold.
    Inconclusive,
}

/// Classify one block-pinned observation.
///
/// `finalSettle` advances `currentStateRoot` and `batchCount` identically to
/// `settleBatch`, so neither alone excludes a wind-down. But `finalSettle` REQUIRES
/// `closeOnly == true`, and `closeOnly` is terminal on-chain — never cleared anywhere in
/// `contracts/`. So the three read together at ONE block exclude it.
///
/// The asymmetry is deliberate and load-bearing: only a SUCCESSFULLY OBSERVED mismatch
/// may commit the gate closed. The opening check runs once per commit and a commit is not
/// repeatable, so resolving an errored or lagging read against opening would burn the only
/// opportunity — and 025-A's bootstrap endpoint is one-shot and cannot manufacture another.
pub fn classify(
    chain_batch_count: u64,
    sealed_batch_id: u64,
    chain_root: [u8; 32],
    our_new_root: [u8; 32],
    close_only: bool,
) -> GateObservation {
    let Some(expected) = sealed_batch_id.checked_add(1) else {
        return GateObservation::Inconclusive;
    };
    if chain_batch_count < expected {
        // Lagging: the read landed on a block before our settle. Says nothing.
        return GateObservation::Inconclusive;
    }
    if chain_batch_count > expected || chain_root != our_new_root {
        return GateObservation::StaysClosed;
    }
    if close_only {
        return GateObservation::StaysClosed;
    }
    GateObservation::OpensGate
}

/// The capitalization half of the opening condition, judged on the PROVEN post-state.
pub fn predicate_met(
    mode_is_normal: bool,
    insurance_fund: i128,
    deposit_count: u64,
    min_deposits: u64,
) -> bool {
    mode_is_normal && insurance_fund >= MIN_BOOTSTRAP_INSURANCE && deposit_count >= min_deposits
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1: [u8; 32] = [1u8; 32];
    const R2: [u8; 32] = [2u8; 32];

    #[test]
    fn a_close_only_chain_never_opens_the_gate_even_on_a_perfect_match() {
        // The finalSettle defence. Count and root match exactly — the two values a
        // wind-down advances identically — and only `closeOnly` distinguishes it.
        assert_eq!(classify(8, 7, R1, R1, true), GateObservation::StaysClosed);
        assert_eq!(classify(8, 7, R1, R1, false), GateObservation::OpensGate);
    }

    #[test]
    fn a_lagging_read_is_inconclusive_and_a_diverged_one_is_not() {
        // Lagging must NOT resolve against opening: the commit is not repeatable, so a
        // stale block would burn the only opening opportunity.
        assert_eq!(classify(7, 7, R1, R1, false), GateObservation::Inconclusive);
        assert_eq!(classify(0, 7, R1, R1, false), GateObservation::Inconclusive);
        // A genuinely different transition is an OBSERVED mismatch, so it may close.
        assert_eq!(classify(9, 7, R1, R1, false), GateObservation::StaysClosed);
        assert_eq!(classify(8, 7, R2, R1, false), GateObservation::StaysClosed);
        // An impossible id cannot be reasoned about.
        assert_eq!(
            classify(0, u64::MAX, R1, R1, false),
            GateObservation::Inconclusive
        );
    }

    #[test]
    fn the_predicate_needs_every_term_and_a_dust_fund_does_not_pass() {
        assert!(predicate_met(true, MIN_BOOTSTRAP_INSURANCE, 1, 1));
        // `insurance_fund > 0` is NOT capitalization — one base unit must fail.
        assert!(!predicate_met(true, 1, 1, 1));
        assert!(!predicate_met(true, MIN_BOOTSTRAP_INSURANCE - 1, 1, 1));
        assert!(!predicate_met(false, MIN_BOOTSTRAP_INSURANCE, 1, 1));
        assert!(!predicate_met(true, MIN_BOOTSTRAP_INSURANCE, 0, 1));
    }
}
```

- [ ] **Step 2: Run to confirm it fails**

Run: `cargo test -p gateway trading_gate::`
Expected: FAIL — `file not found for module 'trading_gate'` once the declaration is added, or `0 passed, N filtered out` before it. Either way the tests do not run; note in your report which you actually observed, since a "red" that is really "absent" proves nothing.

- [ ] **Step 3: Declare the module, add the field, bump the magic**

In `main.rs`, add `mod trading_gate;` beside the other module declarations. Add to `struct Gw`, after `bootstrap`:

```rust
    /// SEC-025-D: the launch gate. `Closed` on a production genesis until a proven,
    /// block-pinned `settleBatch` shows the deployment capitalized — see `trading_gate`.
    #[serde(default = "trading_gate_closed")]
    trading_gate: trading_gate::TradingGate,
```

with the helper beside its siblings:

```rust
fn trading_gate_closed() -> trading_gate::TradingGate {
    trading_gate::TradingGate::Closed
}
```

`#[serde(default)]` here is documentation of intent, **not** compatibility — postcard is positional. Do not write a comment claiming otherwise.

Set it at every `Gw { .. }` literal: `TradingGate::Open` under `GenesisMode::Demo`, `TradingGate::Closed` otherwise. The compiler will name any literal you miss; there is also a `test_app()` helper in the test module that has tripped two prior tasks.

In `snapshot.rs`, extend the `MAGIC` doc with a v5 paragraph in the style of v3/v4 and set `b"DPSNAP5\0"`. State the real reason: `Gw.trading_gate` is inserted mid-struct, `Gw` is positional postcard, and 025-A already took v4.

- [ ] **Step 4: Add the round-trip test**

In `main.rs`'s test module:

```rust
#[test]
fn the_trading_gate_survives_a_snapshot_round_trip() {
    let mut gw = Gw::boot();
    gw.trading_gate = trading_gate::TradingGate::Closed;
    let plain = gw.snapshot_plain();
    let restored = Gw::boot_restored(&plain).expect("restore");
    // Losing this across a restart would silently re-open a deployment the gate had
    // deliberately kept shut — the failure this field exists to prevent.
    assert_eq!(restored.trading_gate, trading_gate::TradingGate::Closed);
}
```

**Mutation-verify it:** change the field to `#[serde(skip, default = ...)]`, run the test, confirm it fails, restore. Report the observed failure.

- [ ] **Step 5: Run the suites and commit**

Run: `cargo fmt --all && cargo test -p gateway && cargo clippy --workspace --all-targets`
Expected: PASS, gateway 222 + 4, clippy "No issues found".

```bash
git add crates/gateway/src/trading_gate.rs crates/gateway/src/main.rs crates/gateway/src/snapshot.rs
git commit -m "feat(gateway): the trading gate type, its confirmation policy, and DPSNAP5"
```

---

### Task 2: Carry the post-state terms on `ProveOutcome`

The predicate needs `mode` and `insurance_fund` **as proven**, and `commit_window_settle` receives neither — it takes `(batch_id, ordered, rejected, prepared, l1_status)`, with no witness and no state. The replayed post-state exists in `prove_and_prepare` and is discarded; exactly one scalar survives it today (`new_deposit_count`). Extend that precedent rather than re-deriving under the lock, which would run a full replay on the boot recovery path.

**Files:**
- Modify: `crates/gateway/src/prover_client.rs` (`ProveOutcome` at `:29`, populated at `:260`), `crates/gateway/src/rollback_journal.rs` (`MAGIC`), `crates/gateway/src/l1.rs:1135` and `crates/gateway/src/main.rs:8367` (the two other `ProveOutcome` literals, both in tests)
- Test: `crates/gateway/src/prover_client.rs`

**Interfaces:**
- Produces: `ProveOutcome.post_mode_is_normal: bool`, `ProveOutcome.post_insurance_fund: i128`.

- [ ] **Step 1: Write the failing test**

In `prover_client.rs`'s test module:

```rust
#[test]
fn the_outcome_carries_the_proven_post_state_terms_the_gate_judges() {
    // These ride here for one reason: `commit_window_settle` gets no witness and no
    // state, and `self.seq.state` is NOT the window's post-state — ticks run every
    // 700ms while a real proof takes minutes, so the live state has moved on.
    let (mut seq, witness) = fixture_window_with_a_deposit();
    let out = prove_and_prepare(&mut seq, &witness, &MockProverClient::default())
        .expect("prepare");
    assert!(out.outcome.post_mode_is_normal);
    assert_eq!(out.outcome.post_insurance_fund, expected_insurance_after_replay());
}
```

**Implementer note:** `fixture_window_with_a_deposit` and `expected_insurance_after_replay` are placeholders for whatever the file's existing fixtures provide — this module already has tests exercising `prove_and_prepare` (`new_deposit_count_is_cumulative_not_per_window`, `zero_deposit_window_submits_the_prestate_count`). **Reuse their fixture shape**; do not build a parallel one. If no fixture yields a non-default `insurance_fund`, assert against the pre-state value and say so in your report rather than inventing a fixture whose expected value you cannot derive.

- [ ] **Step 2: Run to confirm it fails**

Run: `cargo test -p gateway the_outcome_carries_the_proven_post_state`
Expected: FAIL to compile — no field `post_mode_is_normal`.

- [ ] **Step 3: Add the fields and populate them**

In `prover_client.rs`, after `new_deposit_count`:

```rust
    /// SEC-025-D: the proven post-state terms the launch gate judges. Derived from the
    /// SAME local replay as every root here, at the one point where the post-state
    /// exists — `commit_window_settle` receives neither a witness nor a state, and the
    /// live `seq.state` has advanced past this window by the time a proof returns.
    pub post_mode_is_normal: bool,
    pub post_insurance_fund: i128,
```

Populate them at `:260` from the same `post` the roots came from, before it is dropped.

Update the two test literals (`l1.rs:1135`, `main.rs:8367`).

- [ ] **Step 4: Bump the journal magic**

`PreparedSettle` embeds `ProveOutcome` and is serde-serialized into the rollback journal, so the positional layout moved. In `rollback_journal.rs`, extend the `MAGIC` doc with a v5 paragraph and set `b"DPRBJL5\0"`. Say why: a pre-025-D journal decoded by a post-025-D binary would misparse the outcome, and a roll-forward re-submits those roots to `_requireDepositPrefix`.

Check whether any journal test asserts a positional encoding and update it.

- [ ] **Step 5: Run and commit**

Run: `cargo fmt --all && cargo test -p gateway && cargo clippy --workspace --all-targets`

```bash
git add crates/gateway/src/prover_client.rs crates/gateway/src/rollback_journal.rs crates/gateway/src/l1.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): carry the proven post-state terms, and DPRBJL5"
```

---

### Task 3: Block-pinned L1 reads

**Files:**
- Modify: `crates/gateway/src/l1.rs`
- Test: `crates/gateway/src/l1.rs`

**Interfaces:**
- Produces, on `impl L1`:
  - `pub fn close_only_at(&self, block: u64) -> Result<bool, String>`
  - `pub fn batch_count_at(&self, block: u64) -> Result<u64, String>`
  - `pub fn current_root_at(&self, block: u64) -> Result<Digest, String>`
  - `pub fn head_block(&self) -> Result<u64, String>`

- [ ] **Step 1: Write the failing test**

`L1` shells out to `cast`, so a unit test cannot reach a chain. Test the **argument construction**, which is where the pinning either happens or silently does not:

```rust
#[test]
fn a_pinned_read_names_its_block_and_an_unpinned_one_cannot_be_confused_for_it() {
    // The whole safety argument is that the three reads see ONE block. Three "latest"
    // calls through a lagging or load-balanced RPC could observe different heights and
    // defeat it, and that failure is invisible at runtime — so pin the flag here.
    let args = pinned_call_args("0xVAULT", "closeOnly()(bool)", 1234);
    assert!(
        args.windows(2).any(|w| w[0] == "--block" && w[1] == "1234"),
        "a pinned read must pass --block: {args:?}"
    );
}
```

**Implementer note:** factor the argument construction into `pinned_call_args(addr, sig, block) -> Vec<String>` so it is testable, and have all three readers use it. If the existing `cast` invocation helper in this file already has a shape you can extend, extend it rather than adding a parallel one — say which you chose and why.

- [ ] **Step 2: Run to confirm it fails**

Run: `cargo test -p gateway a_pinned_read_names_its_block`
Expected: FAIL to compile — no `pinned_call_args`.

- [ ] **Step 3: Implement**

Add the four readers. `closeOnly()` is a public getter on `DarkPerpSettlement` (`contracts/src/DarkPerpSettlement.sol:82`). `head_block` is `cast block-number`.

Every reader takes the block explicitly — **no reader may default to `latest`**, because a caller that forgets would silently lose the pinning the design depends on.

- [ ] **Step 4: Run and commit**

```bash
git add crates/gateway/src/l1.rs
git commit -m "feat(gateway): block-pinned L1 reads for the gate's three-way observation"
```

---

### Task 4: The opening check

**Files:**
- Modify: `crates/gateway/src/main.rs` (`commit_window_settle` and its three call sites)
- Test: `crates/gateway/src/main.rs`

**Interfaces:**
- Consumes: everything from Tasks 1-3.
- Produces: `TradingGate::Closed → Open` inside `commit_window_settle`, from a `GateObservation` the caller supplies.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_wind_down_shaped_commit_does_not_open_the_gate() {
    // The finalSettle defence, at the transition rather than in the classifier: the
    // count and root match exactly, and only the observation distinguishes it.
    let mut gw = Gw::boot_production_for_test();
    assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
    gw.commit_window_settle_for_test_with(0, trading_gate::GateObservation::StaysClosed);
    assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
}

#[test]
fn an_inconclusive_observation_leaves_the_gate_unresolved_rather_than_closed() {
    // The liveness half. The commit is not repeatable, so resolving a failed or lagging
    // read AGAINST opening would burn the only opportunity — and 025-A's bootstrap
    // endpoint is one-shot and cannot manufacture another window.
    let mut gw = Gw::boot_production_for_test();
    gw.commit_window_settle_for_test_with(0, trading_gate::GateObservation::Inconclusive);
    assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
    // …and a later conclusive observation still opens it.
    gw.commit_window_settle_for_test_with(1, trading_gate::GateObservation::OpensGate);
    assert_eq!(gw.trading_gate, trading_gate::TradingGate::Open);
}

#[test]
fn an_undercapitalized_deployment_does_not_open_on_a_clean_settle() {
    // The predicate half: a perfect on-chain observation is not enough.
    let mut gw = Gw::boot_production_for_test();
    gw.set_prepared_post_state_for_test(true, 1, 1); // one base unit of insurance
    gw.commit_window_settle_for_test_with(0, trading_gate::GateObservation::OpensGate);
    assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
}

#[test]
fn the_gate_does_not_re_close_when_the_fund_is_later_drained() {
    // Deliberate: this is a LAUNCH gate. Re-closing a blunt ingress gate would block
    // reduce-only exits, trapping users exactly when they most need to leave.
    let mut gw = Gw::boot_production_for_test();
    gw.commit_window_settle_for_test_with(0, trading_gate::GateObservation::OpensGate);
    assert_eq!(gw.trading_gate, trading_gate::TradingGate::Open);
    gw.set_prepared_post_state_for_test(true, 0, 1);
    gw.commit_window_settle_for_test_with(1, trading_gate::GateObservation::OpensGate);
    assert_eq!(gw.trading_gate, trading_gate::TradingGate::Open);
}
```

**Implementer note:** `boot_production_for_test`, `commit_window_settle_for_test_with` and `set_prepared_post_state_for_test` are `#[cfg(test)]` helpers you add. `commit_window_settle_for_test_with` must call the **real** `commit_window_settle` — a parallel transition path pins nothing. There is an existing `commit_window_settle_for_test` from 025-A; extend it rather than duplicating.

- [ ] **Step 2: Run to confirm they fail**

Run: `cargo test -p gateway does_not_open_the_gate`
Expected: FAIL to compile — the helpers do not exist.

- [ ] **Step 3: Implement the transition**

Add a `GateObservation` parameter to `commit_window_settle` and, after `last_settled_root` advances:

```rust
        // SEC-025-D: open ONCE, and only on a proven, block-pinned normal settle over a
        // capitalized post-state. Never re-closes — see `trading_gate`'s module doc for
        // why a launch gate must not double as a circuit breaker.
        if self.trading_gate == trading_gate::TradingGate::Closed
            && observation == trading_gate::GateObservation::OpensGate
            && trading_gate::predicate_met(
                prepared.outcome.post_mode_is_normal,
                prepared.outcome.post_insurance_fund,
                prepared.outcome.new_deposit_count,
                trading_gate::MIN_BOOTSTRAP_DEPOSITS,
            )
        {
            self.trading_gate = trading_gate::TradingGate::Open;
        }
```

- [ ] **Step 4: Supply the observation at all three call sites**

The clean settle path performs the block-pinned three-way read after its receipt: take `head_block`, require it at least `GATE_OPEN_CONFIRMATIONS` deep past the settle's block, then read all three at that pinned height and `classify`. **A read error is `Inconclusive`, never `StaysClosed`.**

Both roll-forward arms (the settle-loop ambiguous arm and the boot recovery arm) do the same read — they are exactly where a `finalSettle` can be mistaken for ours, so they must not shortcut to `StaysClosed` either.

- [ ] **Step 5: Mutation-verify**

For each of the four tests, mutate the code it names — prefer **relocating** the predicate or the observation check over deleting it, since relocation tests ordering and deletion only tests presence — run it, and confirm it dies. Report any test you could not make die.

- [ ] **Step 6: Run and commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): open the gate once, on a pinned normal settle over a capitalized state"
```

---

### Task 5: Enforcement at every ingress

A gate in `account_place_order` alone is not sufficient. Two paths enter a window without going through `Sequencer::accept_order`.

**Files:**
- Modify: `crates/gateway/src/main.rs`
- Test: `crates/gateway/src/main.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn every_ingress_path_refuses_while_the_gate_is_closed() {
    let mut gw = Gw::boot_production_for_test();
    let key = gw.account_register_for_test();
    assert!(gw.account_place_order_for_test(&key).is_err(), "/v1/orders");
    assert!(gw.place_order_for_test().is_err(), "legacy place_order");
    assert!(gw.simulate_adl_for_test().is_err(), "simulate_adl");
}

#[test]
fn the_house_mm_injector_produces_no_counter_order_while_the_gate_is_closed() {
    // Asserted DIRECTLY, not via "no taker exists". The injector pushes straight into
    // the seal vector without touching `accept_order`, and it carries no `prod` gate of
    // its own — so a gate placed only in the handler leaves it live.
    let mut gw = Gw::boot_production_for_test();
    let before = gw.seq.window_op_count();
    gw.tick_for_test();
    assert_eq!(gw.seq.window_op_count(), before);
}
```

- [ ] **Step 2: Run to confirm they fail**

Run: `cargo test -p gateway every_ingress_path_refuses`
Expected: FAIL — the gate is not enforced yet, so the calls succeed.

- [ ] **Step 3: Implement**

Gate all four: `account_place_order` (production, `POST /v1/orders`), `place_order` (demo route, gated so a future re-mount cannot bypass it), the house-MM counter-order injector, and `simulate_adl` — the last with a **posture guard at the top of the function**. `simulate_adl` is refused in production today only because an unconditional `fund(...)` reaches `refuse_unbacked_mint` first; refusal that depends on an unrelated call's position is one refactor away from disappearing.

`Mode::CloseOnly` is **not** a substitute: it blocks only *opening*, so reduce-only flow, cancels, deposits and withdrawals all still pass. The two checks stack on the same handler and need distinct refusal messages, or an operator will read one and diagnose the other.

- [ ] **Step 4: Mutation-verify each**

Delete each enforcement point in turn and confirm the corresponding assertion dies. The MM injector one matters most — it is the path a handler-only gate misses.

- [ ] **Step 5: Run the full workspace and commit**

Run: `cargo fmt --all && cargo test --workspace && cargo clippy --workspace --all-targets && (cd contracts && forge test)`

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): refuse every ingress path while the gate is closed"
```

---

### Task 6: Documentation and the honest limits

**Files:**
- Modify: `docs/API.md`, `crates/gateway/src/trading_gate.rs` (module doc)

- [ ] **Step 1: Document the refusal**

Add to `docs/API.md`, beside the order endpoints: while the gate is closed, order submission returns a distinct refusal naming the launch gate — not close-only, which is a different condition with a different remedy.

- [ ] **Step 2: State the limits the code cannot fix**

Say plainly, in the module doc:

- The gate protects against opening an **uncapitalized** deployment. It does not make trading work — in production the house MM is funded by nothing, so a market order fabricates a counter-order that is rejected for insufficient margin and the taker fills only against genuine external resting liquidity.
- The latch is one-way. A fund later drained below the floor leaves the gate open; the answers are a separate exposure-increase circuit breaker and a recapitalization path, **neither of which exists**.
- `MIN_BOOTSTRAP_INSURANCE` is shared with 025-A, and **A and D must ship as one artifact**.

Do not claim the gate makes the deployment safe to trade on. It makes it safe to *open*.

- [ ] **Step 3: Full verification and commit**

Run: `cargo fmt --all --check && cargo test --workspace && cargo clippy --workspace --all-targets && (cd contracts && forge test)`

```bash
git add docs/API.md crates/gateway/src/trading_gate.rs
git commit -m "docs(sec025d): the launch gate, and what it does not make safe"
```

---

## Branch completion

- [ ] `cargo test --workspace` green; `forge test` still **85**; fmt and clippy clean.
- [ ] Confirm which tests were verified to **fail before the change**, and report any you could not make die.
- [ ] Request an independent review of the branch. **Codex rejected this piece's spec twice** — expect it to find more in the implementation. Verify every finding at source before accepting it.
- [ ] **Do not deploy.** No `perp-core` change, so no vkey or root moves. `DPSNAP5` and `DPRBJL5` both require the cutover's state wipe.
- [ ] **025-A and 025-D ship together.** They share `MIN_BOOTSTRAP_INSURANCE`, and a floor differing between builds recreates the deadlock.
- [ ] **025-E is still the honest blocker for opening to users** — it is not in the cutover bundle, but the gate should stay closed on any real deployment until execution reporting is honest.
