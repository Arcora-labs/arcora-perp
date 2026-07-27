# SEC-022 — Fill-price band + closed-position debt — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the hole where two accounts cross off-market, drive one side's collateral negative on a leg that ends `size == 0`, and withdraw the counterparty's fabricated gain from the real vault.

**Architecture:** Three composing gaps, fixed in dependency order. `perp-core` (Slice A, compiled into the SP1 guest) gains a per-market oracle-relative fill-price band, a conditional per-fill solvency postcondition, and a restructured `op_fill` in which no fallible operation follows the first mutation. `crates/sequencer` (Slice B, host only) then stops burning resting liquidity on the fills those new rules reject, by dry-running settlement against a cloned state before committing the book.

**Source spec:** `docs/superpowers/specs/2026-07-26-sec022-fill-price-band-and-bad-debt-design.md`. Threat model: `docs/superpowers/specs/2026-07-26-sec02x-threat-model.md` (canonical).

**Tech Stack:** Rust, `#![no_std]` + `alloc` (`perp-core`, `matcher`), `postcard` serde, `k256` recoverable ECDSA, SP1 zkVM guest.

## Global Constraints

Every task's requirements implicitly include this section.

- **`perp-core` compiles into the SP1 guest.** No floating point, no clocks, no RNG, no IO, no panics. Every arithmetic step is `checked_*`; **any** overflow returns an `EngineError` — never wrap, never `unwrap`, never panic in-guest.
- **`cargo fmt --all` before every commit.** CI runs `cargo fmt --all -- --check` (`.github/workflows/ci.yml:19`) and implementers on this workstream have repeatedly missed it.
- **`cargo clippy --workspace --all-targets` must be clean.**
- **The SEC-026 postcard pins MUST NOT move.** `crates/perp-core/src/state.rs:415-419` and `:447-451` pin the byte length and keccak of two serialized states. **Neither pinned state contains a market** (neither calls `add_market`), so adding a `Market` field must leave both pins byte-identical. If either pin fails, the change leaked into a state that should not carry it — **fix the code, never the pin.** The comment at `:386-391` says so explicitly.
- **`RejectReason` is append-only.** It has explicit `#[repr(u16)]` discriminants (`order.rs:127-148`) and is folded into `BatchManifest::hash` (`order.rs:179`). Append new variants; never renumber or reuse.
- **`EngineError` must stay `Copy`** (`error.rs:6`). Any payload added to a variant must itself be `Copy`.
- **Rejection is safe; it does not wedge the chain.** `seal_batch` omits rejected fills from the proven op-log and routes both orders to `manifest.rejected` (`sequencer/src/lib.rs:888-906`). Prefer fail-closed rejection everywhere.
- **Do not touch the bad-debt waterfall.** It stays in `op_liquidate` (`engine.rs:679-704`), its correct home. The first version of this spec tried to run it from `op_fill`; review showed that does not close the attack.
- **Liquidations do not flow through `op_fill`.** `BatchOp::Fill` and `BatchOp::Liquidate` dispatch separately (`engine.rs:263`, `:288`), and `op_liquidate` calls `Position::apply_fill` directly at the oracle price (`:676`). Neither the band nor the postcondition can or should block a liquidation. Every existing liquidation test must pass unchanged.

## Migration consequences (true for the branch as a whole, not any one task)

| Change | Consequence |
|---|---|
| `op_fill` band + postcondition, new `EngineError` variants | Guest ELF changes → **vkey re-pin** → new `SP1ZkVerifier` **and** `DarkPerpSettlement` deploy (`programVKey` and the verifier address are immutable) |
| New `Market` field → `markets_digest` → `state_root` | **`GENESIS_ROOT` moves** |
| New `Market` field → postcard encoding of any state **carrying a market** | Witness plaintext, sealed-witness ciphertext/nonce, gateway snapshots, sequencer snapshots, `window_start_state` and rollback journals all change shape. **Any pending witness or journal must be drained or explicitly invalidated before cutover.** Bump `DPSNAP1` (`gateway/src/snapshot.rs:32`) and `DPRBJL1` (`gateway/src/rollback_journal.rs:26`). |
| `RejectReason` append | New discriminants only; existing encodings unchanged |

`KAT_COMMIT7` does **not** move — it hashes fixed roots `[0x01;32]…[0x07;32]` independent of `Market` (`commitment.rs:236-246`). The Solidity cross-layer KAT is likewise unaffected. Do not "update" either.

## Two hazards to expect, and how to handle them

**1. A still-open leg below maintenance can no longer reduce.** Task 4's postcondition requires a leg that stays open to be maintenance-compliant. A position already below maintenance therefore cannot partially close — it must be liquidated (the designed resolution, with the waterfall) or topped up via `FundPosition`. This is the spec's intended rule and it survived adversarial review, but it is a real behavioural change. **If an existing test fails because an underwater position reduces, triage it — do not weaken the rule and do not edit the test's expectation without saying why in the commit message.** Surface it in the task's completion report.

**2. Existing fixtures fill at the oracle price, so the band should be non-disruptive.** Checked: `lifecycle.rs:151-159` fills at $108k with `oracle(108_000, …)`, and `perp-core/tests/fuzz.rs:144-145` uses `price: price * PRICE_SCALE` with `orc = oracle(price, now)` — deviation zero in both. Any test that *does* fill away from its mark must be fixed by aligning the fixture's oracle, **never** by widening the band.

---

# Slice A — `perp-core` (guest)

### Task 1: `Market::max_fill_deviation_ratio`, the joint coherence inequality, and digest binding

**Files:**
- Modify: `crates/perp-core/src/market.rs` (struct at `:18-58`, `conservative()` at `:63-78`, `is_coherent()` at `:115-139`)
- Modify: `crates/perp-core/src/state.rs` (`markets_digest()` at `:184-207`)
- Test: `crates/perp-core/src/market.rs` (`mod tests` at `:142`)
- Test: `crates/perp-core/src/state.rs` (`mod tests`, alongside `market_binds_max_mark_deviation_ratio_in_digest` at `:461-475`)

**Interfaces:**
- Produces: `Market.max_fill_deviation_ratio: i128` — a `RATE_SCALE`-scaled fraction, default `RATE_SCALE / 50` (2%). Consumed by Task 3's band check in `op_fill`.

- [ ] **Step 1: Write the failing tests**

Add to `crates/perp-core/src/market.rs` `mod tests`:

```rust
    #[test]
    fn fill_deviation_ratio_must_be_positive() {
        // SEC-022: the fill band gates the price two counterparties actually trade at.
        // A ZERO band would reject every fill except one exactly at the mark; a NEGATIVE
        // band is nonsense. Reject both at setup, like the sibling oracle `*_ratio` bounds.
        let mut m = Market::conservative(0);
        m.max_fill_deviation_ratio = 0;
        assert!(!m.is_coherent(), "zero fill band is incoherent");
        m.max_fill_deviation_ratio = -1;
        assert!(!m.is_coherent(), "negative fill band is incoherent");
        assert!(Market::conservative(0).is_coherent(), "the 2% default is coherent");
    }

    #[test]
    fn fill_band_and_taker_fee_are_jointly_bounded_by_maintenance() {
        // SEC-022 §2: enforcing `d < maintenance` and `f < maintenance` SEPARATELY is the
        // trap. d = 2% and f = 4.9999% each pass individually against a 5% maintenance
        // ratio, while together they consume ~7.10% of the maintenance buffer — enough to
        // deterministically bankrupt a maintenance-compliant position on a pure reduction.
        let mut m = Market::conservative(0);
        m.max_fill_deviation_ratio = RATE_SCALE / 50; // 2%
        m.taker_fee_ratio = 49_999; // 4.9999%, individually < 5% maintenance
        m.maker_rebate_ratio = 0;
        m.treasury_fee_ratio = 0;
        assert!(
            m.taker_fee_ratio < m.maintenance_margin_ratio,
            "precondition: the fee passes the OLD standalone bound",
        );
        assert!(
            m.max_fill_deviation_ratio < m.maintenance_margin_ratio,
            "precondition: the band passes a standalone bound too",
        );
        assert!(
            !m.is_coherent(),
            "jointly they exceed the maintenance buffer and must be rejected",
        );
    }

    #[test]
    fn live_fee_schedule_is_jointly_coherent() {
        // The live schedule: 5% maintenance, 10bp taker, 4bp maker, 2% band.
        // 2% + 0.1%·(1 + 2%) = 2.102% < 5%. Sound with a wide margin.
        let mut m = Market::with_fees(0, 10, 4);
        assert_eq!(m.max_fill_deviation_ratio, RATE_SCALE / 50);
        assert!(m.is_coherent(), "the live schedule must stay coherent");
        // and the boundary is real: a band at maintenance itself is not
        m.max_fill_deviation_ratio = m.maintenance_margin_ratio;
        assert!(!m.is_coherent(), "a band at the maintenance ratio is incoherent");
    }
```

Add to `crates/perp-core/src/state.rs` `mod tests`:

```rust
    // SEC-022: the per-market fill band bounds the price a fill may execute at relative
    // to the attested oracle mark. It MUST be bound into `markets_digest` — otherwise a
    // prover could widen (or null) the band under an unchanged state root, which is the
    // whole constraint. Two states differing ONLY in the fill band must not share a digest.
    #[test]
    fn market_binds_max_fill_deviation_ratio_in_digest() {
        let mut a: State<Keccak256> = State::new(16);
        let mut b: State<Keccak256> = State::new(16);
        a.add_market(Market::conservative(1)); // max_fill_deviation_ratio = 2%
        let mut mb = Market::conservative(1);
        mb.max_fill_deviation_ratio = 40_000; // same market, wider (4%) fill band
        b.add_market(mb);
        assert_ne!(
            a.markets_digest(),
            b.markets_digest(),
            "max_fill_deviation_ratio must be bound into markets_digest",
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p perp-core --lib`
Expected: FAIL — `no field 'max_fill_deviation_ratio' on type 'Market'` (compile error).

- [ ] **Step 3: Add the field, the default, the joint inequality, and the digest fold**

In `crates/perp-core/src/market.rs`, append to the `Market` struct after `max_mark_deviation_ratio` (`:57`):

```rust
    /// SEC-022: max |fill price − attested oracle mark| / mark tolerated on a settlement
    /// fill, as a [`RATE_SCALE`]-scaled fraction. Distinct from `max_mark_deviation_ratio`,
    /// which bounds the *funding* mark: this one bounds the price two counterparties
    /// actually trade at. It must be tight enough that no in-band fill can take a
    /// maintenance-compliant position below its maintenance requirement — see the joint
    /// inequality in [`Self::is_coherent`].
    pub max_fill_deviation_ratio: i128,
```

In `conservative()`, after `max_mark_deviation_ratio` (`:76`):

```rust
            max_fill_deviation_ratio: RATE_SCALE / 50, // 2%
```

In `is_coherent()`, append to the chain after the `max_mark_deviation_ratio` check (`:138`):

```rust
            // SEC-022: the fill band, like the sibling oracle bounds, must be strictly
            // positive — a zero band admits only a fill exactly at the mark.
            && self.max_fill_deviation_ratio > 0
            && Self::fill_band_fits_maintenance(
                self.max_fill_deviation_ratio,
                self.taker_fee_ratio,
                self.maintenance_margin_ratio,
            )
```

Add the helper to `impl Market`, after `is_coherent()`:

```rust
    /// SEC-022 §2 — the joint band / fee / maintenance inequality.
    ///
    /// The worst pure reduction is a taker closing at the far edge of the band, which
    /// consumes `d + f·(1 + d)` of the maintenance buffer. Bounding `d < maintenance` and
    /// `f < maintenance` SEPARATELY is not sufficient: `d = 2%` with `f = 4.9999%` passes
    /// both and together consumes ~7.10%. Scaled by `RATE_SCALE`, the sufficient joint
    /// condition is
    ///
    /// ```text
    /// d · RATE_SCALE  +  f · (RATE_SCALE + d)  <  maintenance · RATE_SCALE
    /// ```
    ///
    /// Governance sets these and they are otherwise arbitrary `i128`, so every step is
    /// `checked_*` and ANY overflow is incoherent (fail-closed) rather than a wrap.
    fn fill_band_fits_maintenance(d: i128, f: i128, maintenance: i128) -> bool {
        let Some(band_term) = d.checked_mul(RATE_SCALE) else {
            return false;
        };
        let Some(one_plus_d) = RATE_SCALE.checked_add(d) else {
            return false;
        };
        let Some(fee_term) = f.checked_mul(one_plus_d) else {
            return false;
        };
        let Some(lhs) = band_term.checked_add(fee_term) else {
            return false;
        };
        let Some(rhs) = maintenance.checked_mul(RATE_SCALE) else {
            return false;
        };
        lhs < rhs
    }
```

In `crates/perp-core/src/state.rs`, in `markets_digest()`, after the `max_mark_deviation_ratio` push (`:204`):

```rust
            // SEC-022: the fill band, bound like every other risk parameter so a prover
            // cannot widen the price constraint under an unchanged state root.
            words.push(word_i128(m.max_fill_deviation_ratio));
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p perp-core --lib`
Expected: PASS, including `sec026_postcard_encoding_is_pinned` **unchanged** — neither pinned state contains a market, so neither pin may move. If a pin fails, the field leaked somewhere it must not; fix the code.

- [ ] **Step 5: Run the whole workspace suite**

Run: `cargo test --workspace`
Expected: PASS. Genesis/state-root fixtures elsewhere may hold pinned roots for market-bearing states — those legitimately move (see Migration). Update only roots, with the reason in the commit message.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/perp-core/src/market.rs crates/perp-core/src/state.rs
git commit -m "feat(perp-core): SEC-022 — per-market fill-price band parameter

Adds Market::max_fill_deviation_ratio (default 2%), bound into markets_digest
so it cannot be widened under an unchanged state root, and gated by the joint
band/fee/maintenance inequality rather than a standalone bound — d and f each
below maintenance still lets them jointly exceed the buffer.

Enforcement lands in op_fill in a following commit."
```

---

### Task 2: `op_fill` atomicity — no fallible operation after the first mutation

This is a **pre-existing defect** surfaced by review, fixed first because Tasks 3 and 4 add further late failure points on top of it.

**Files:**
- Modify: `crates/perp-core/src/engine.rs:577-602` (the commit block of `op_fill`)
- Test: `crates/perp-core/tests/sec022_fill_band.rs` (create)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: an `op_fill` whose commit block is infallible. Tasks 3 and 4 add their checks *before* it.

- [ ] **Step 1: Write the failing tests**

Create `crates/perp-core/tests/sec022_fill_band.rs`:

```rust
//! SEC-022 — fill-price band, per-fill solvency postcondition, and `op_fill` atomicity.
//!
//! Spec: `docs/superpowers/specs/2026-07-26-sec022-fill-price-band-and-bad-debt-design.md`

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::Keccak256;
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::Side;
use perp_core::{DefaultState, EngineError, Market, Note};
// Task 4 adds `FillLeg` to this import.

const TREE_DEPTH: u8 = 20;

fn owner_of(sk: u8) -> [u8; 32] {
    owner_from_spend_key::<Keccak256>(&[sk; 32])
}

fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn oracle_addr() -> [u8; 20] {
    let d = oracle_digest(0, 1, 1, 0, 1);
    OracleSig::sign(&oracle_key(), &d).recover(&d).unwrap()
}

/// A transcript signed by the fixture publisher, at `price_usd`, for market 0.
fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    let price = price_usd * PRICE_SCALE;
    let confidence = 10 * PRICE_SCALE; // $10, well inside 1%
    let d = oracle_digest(0, price, now, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn deposit_commit(owner: [u8; 32], amount: i128, blinding: [u8; 32]) -> [u8; 32] {
    Note::new(owner, 0, amount, blinding).commitment::<Keccak256>()
}

/// A state with market 0 built from `m`, its oracle pubkey set to the fixture publisher.
fn state_with(m: Market) -> DefaultState {
    let mut m = m;
    m.oracle_pubkey = oracle_addr();
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(m);
    s
}

/// Deposit `amount` for `owner` and bind it all as position collateral on market 0.
fn fund(s: &mut DefaultState, owner: [u8; 32], sk: u8, amount: i128, blinding: [u8; 32], id: u64) {
    let cm = deposit_commit(owner, amount, blinding);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount,
            blinding,
            from: [0xA1u8; 20],
            deposit_id: id,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::FundPosition {
            owner,
            market_id: 0,
            note_commitment: cm,
            spend_key: [sk; 32],
        },
    ])
    .expect("deposit + fund");
}

/// Two funded accounts, $20k each, on a market built from `m`.
fn two_funded(m: Market) -> (DefaultState, [u8; 32], [u8; 32]) {
    let mut s = state_with(m);
    let (a, b) = (owner_of(1), owner_of(2));
    fund(&mut s, a, 1, 20_000 * QUOTE_SCALE, [0x11u8; 32], 0);
    fund(&mut s, b, 2, 20_000 * QUOTE_SCALE, [0x22u8; 32], 1);
    (s, a, b)
}

fn fill(a: [u8; 32], b: [u8; 32], side: Side, size: i128, price_usd: i128, now: u64) -> BatchOp {
    BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: side,
        size,
        price: price_usd * PRICE_SCALE,
        oracle: oracle(price_usd, now),
        now_ms: now,
    }
}

// ---------------------------------------------------------------- Task 2: atomicity

/// SEC-022 §4: `op_fill` committed `vault_pool` and both positions BEFORE the fallible
/// `treasury` / `insurance_fund` additions. A late overflow returned `Err` with state
/// already mutated — and the sequencer's rejection arm then omits the op entirely
/// (`sequencer/src/lib.rs:901-906`), leaving live host state diverged from what was
/// proven. Every fallible path must leave the state byte-for-byte unchanged.
///
/// `state_root()` binds the whole state — the note tree, nullifiers, notes, positions,
/// funding, market params, every balance counter, the mode and the counters — so root
/// equality IS whole-state equality, which is what the spec's test table demands.
#[test]
fn treasury_overflow_leaves_state_untouched() {
    let (mut s, a, b) = two_funded(Market::with_fees(0, 10, 4));
    s.treasury = i128::MAX;
    let before = s.state_root();
    let err = s
        .apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 100_000, 1_000))
        .expect_err("treasury overflow must reject");
    assert_eq!(err, EngineError::Overflow);
    assert_eq!(s.state_root(), before, "state must be byte-for-byte unchanged");
}

#[test]
fn insurance_overflow_leaves_state_untouched() {
    let (mut s, a, b) = two_funded(Market::with_fees(0, 10, 4));
    s.insurance_fund = i128::MAX;
    let before = s.state_root();
    let err = s
        .apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 100_000, 1_000))
        .expect_err("insurance overflow must reject");
    assert_eq!(err, EngineError::Overflow);
    assert_eq!(s.state_root(), before, "state must be byte-for-byte unchanged");
}

#[test]
fn vault_pool_overflow_leaves_state_untouched() {
    let (mut s, a, b) = two_funded(Market::with_fees(0, 10, 4));
    // Open, then close at a different price so the closing leg realizes PnL and moves
    // the pool — with `vault_pool` at the bound, that move overflows.
    s.apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 100_000, 1_000))
        .expect("open");
    s.vault_pool = i128::MIN;
    let before = s.state_root();
    let err = s
        .apply_op(&fill(a, b, Side::Sell, SIZE_SCALE, 101_000, 2_000))
        .expect_err("vault pool overflow must reject");
    assert_eq!(err, EngineError::Overflow);
    assert_eq!(s.state_root(), before, "state must be byte-for-byte unchanged");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p perp-core --test sec022_fill_band`
Expected: `treasury_overflow_leaves_state_untouched` and `insurance_overflow_leaves_state_untouched` FAIL on the final assert — the error is correct but `state_root()` has already moved, because positions and `vault_pool` were committed before the overflow. `vault_pool_overflow_leaves_state_untouched` should already pass (that add is the first mutation); keep it as a regression pin.

- [ ] **Step 3: Restructure the commit block**

In `crates/perp-core/src/engine.rs`, replace the block from `// commit` (`:577`) through the `insurance_fund` assignment (`:601`) with:

```rust
        // SEC-022 §4 — stage EVERY remaining fallible value BEFORE the first mutation.
        // This op used to commit `vault_pool` and both positions and only THEN run the
        // fallible `treasury` / `insurance_fund` additions, so a late overflow returned
        // `Err` with state already changed. The sequencer's rejection arm omits a failed
        // fill from the proven op-log (`sequencer/src/lib.rs:901-906`), so that divergence
        // is exactly what wedges the next proof. Nothing fallible may follow the commit.
        let new_vault_pool = self
            .vault_pool
            .checked_add(pool_delta)
            .ok_or(EngineError::Overflow)?;
        let new_treasury = self
            .treasury
            .checked_add(treasury_fee)
            .ok_or(EngineError::Overflow)?;
        // Conservation: taker −fee, maker +rebate, treasury +treasury_fee,
        // insurance +(fee − rebate − treasury_fee). `is_coherent` bounds the cut ≥ 0.
        let insurance_cut = taker_fee
            .checked_sub(maker_rebate)
            .ok_or(EngineError::Overflow)?
            .checked_sub(treasury_fee)
            .ok_or(EngineError::Overflow)?;
        let new_insurance_fund = self
            .insurance_fund
            .checked_add(insurance_cut)
            .ok_or(EngineError::Overflow)?;

        // commit — infallible from here down
        self.vault_pool = new_vault_pool;
        self.treasury = new_treasury;
        self.insurance_fund = new_insurance_fund;
        for (key, pos) in staged {
            self.positions.insert(key, pos);
        }
        Ok(())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p perp-core --test sec022_fill_band`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the whole workspace suite**

Run: `cargo test --workspace`
Expected: PASS, unchanged. This task is behaviour-preserving on every non-overflow path.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/perp-core/src/engine.rs crates/perp-core/tests/sec022_fill_band.rs
git commit -m "fix(perp-core): SEC-022 §4 — op_fill commits nothing before its last fallible step

op_fill committed vault_pool and both positions, then ran the fallible treasury
and insurance_fund additions. A late overflow returned Err with state already
mutated, while the sequencer drops a failed fill from the proven op-log — so live
state diverged from the proof. Stage all three balances, then commit infallibly.

Pre-existing defect; fixed first because the band and the solvency postcondition
each add another late failure point."
```

---

### Task 3: The fill-price band

**Files:**
- Modify: `crates/perp-core/src/error.rs` (add `FillPriceOutOfBand`)
- Modify: `crates/perp-core/src/engine.rs` (`op_fill`, after `oracle.validate` at `:501`)
- Modify: `crates/perp-core/src/order.rs:147` (append `RejectReason::FillPriceOutOfBand = 11`)
- Modify: `crates/sequencer/src/lib.rs:256-267` (`settlement_reason`)
- Test: `crates/perp-core/tests/sec022_fill_band.rs`

**Interfaces:**
- Consumes: `Market.max_fill_deviation_ratio` (Task 1); the infallible commit block (Task 2).
- Produces: `EngineError::FillPriceOutOfBand` (no payload) and `RejectReason::FillPriceOutOfBand = 11`. Task 5 maps the engine error to the **maker's** order hash.

- [ ] **Step 1: Write the failing tests**

Append to `crates/perp-core/tests/sec022_fill_band.rs`:

```rust
// ------------------------------------------------------------------- Task 3: the band

/// The headline attack: two accounts, one user, crossing far off-market. No credential
/// compromise, no operator involvement — the ordinary order API is enough.
#[test]
fn off_market_cross_is_rejected_with_state_unchanged() {
    let (mut s, a, b) = two_funded(Market::conservative(0));
    let before = s.state_root();
    // Oracle says $100k; they trade at $150k — 50% through the mark.
    let op = BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE,
        price: 150_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    };
    let err = s.apply_op(&op).expect_err("off-market fill must reject");
    assert_eq!(err, EngineError::FillPriceOutOfBand);
    assert_eq!(s.state_root(), before, "whole state and root unchanged");
    assert!(s.conservation_holds());
}

#[test]
fn fill_exactly_at_the_band_edge_is_accepted() {
    let (mut s, a, b) = two_funded(Market::conservative(0));
    // 2% band around a $100k mark → $102,000 is exactly the edge.
    let op = BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE,
        price: 102_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    };
    s.apply_op(&op).expect("the band edge is inclusive");
    assert!(s.conservation_holds());
}

#[test]
fn fill_just_outside_the_band_is_rejected_in_both_directions() {
    for price in [
        102_000 * PRICE_SCALE + 1, // one unit above the upper edge
        98_000 * PRICE_SCALE - 1,  // one unit below the lower edge
    ] {
        let (mut s, a, b) = two_funded(Market::conservative(0));
        let before = s.state_root();
        let op = BatchOp::Fill {
            taker: a,
            maker: b,
            market_id: 0,
            taker_side: Side::Buy,
            size: SIZE_SCALE,
            price,
            oracle: oracle(100_000, 1_000),
            now_ms: 1_000,
        };
        assert_eq!(
            s.apply_op(&op).expect_err("out of band"),
            EngineError::FillPriceOutOfBand,
        );
        assert_eq!(s.state_root(), before, "band is symmetric and fail-closed");
    }
}

/// The band's right-hand side multiplies the ATTESTED mark, never the untrusted `price`.
/// Anchoring to the value under attack would let a prover widen its own band.
#[test]
fn inflated_price_cannot_widen_its_own_band() {
    let (mut s, a, b) = two_funded(Market::conservative(0));
    // A price 100x the mark is 100x out of band — it must not scale the allowance.
    let op = BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE / 1_000,
        price: 10_000_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    };
    assert_eq!(
        s.apply_op(&op).expect_err("inflated price"),
        EngineError::FillPriceOutOfBand,
    );
}

/// An invalid publisher signature must be rejected by `validate()` BEFORE the band, so no
/// band check is ever reachable without a valid signature.
#[test]
fn unsigned_oracle_is_rejected_before_the_band() {
    let mut m = Market::conservative(0);
    m.oracle_pubkey = [0u8; 20]; // fail-closed: unset key refuses every price
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(m);
    let (a, b) = (owner_of(1), owner_of(2));
    fund(&mut s, a, 1, 20_000 * QUOTE_SCALE, [0x11u8; 32], 0);
    fund(&mut s, b, 2, 20_000 * QUOTE_SCALE, [0x22u8; 32], 1);
    let err = s
        .apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 150_000, 1_000))
        .expect_err("unsigned oracle");
    assert!(
        matches!(err, EngineError::Oracle(_)),
        "signature gate must fire before the band, got {err:?}",
    );
}

/// Overflow anywhere in the band arithmetic rejects — it never wraps and never panics
/// (this code runs in the SP1 guest).
#[test]
fn band_arithmetic_overflow_rejects_without_panicking() {
    let mut m = Market::conservative(0);
    m.max_fill_deviation_ratio = i128::MAX; // forces the RHS checked_mul to overflow
    let mut s = state_with(m);
    let (a, b) = (owner_of(1), owner_of(2));
    fund(&mut s, a, 1, 20_000 * QUOTE_SCALE, [0x11u8; 32], 0);
    fund(&mut s, b, 2, 20_000 * QUOTE_SCALE, [0x22u8; 32], 1);
    let before = s.state_root();
    assert_eq!(
        s.apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 101_000, 1_000))
            .expect_err("overflowing band"),
        EngineError::FillPriceOutOfBand,
    );
    assert_eq!(s.state_root(), before);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p perp-core --test sec022_fill_band`
Expected: FAIL — `no variant named 'FillPriceOutOfBand' found for enum 'EngineError'` (compile error).

- [ ] **Step 3: Add the error variant, the reject reason, and the band check**

In `crates/perp-core/src/error.rs`, append to `EngineError` after `MarkOutOfBand` (`:57`):

```rust
    /// SEC-022: a fill's execution price lies outside `max_fill_deviation_ratio` of the
    /// ATTESTED oracle mark. `op_fill` previously validated only `size > 0 && price > 0`
    /// and never compared `price` to `mark`, so two accounts could cross at any price and
    /// move value between them — the losing leg closing with negative collateral that no
    /// liquidation path revisits. An out-of-band price, or an overflow in the checked band
    /// arithmetic, is rejected fail-closed (never wrapped, never panicked in-guest).
    FillPriceOutOfBand,
```

In `crates/perp-core/src/order.rs`, append to `RejectReason` after `InvalidOrder = 10` (`:147`):

```rust
    /// SEC-022: the fill price lay outside the market's `max_fill_deviation_ratio` band
    /// around the attested oracle mark. Appending (rather than reusing `InvalidOrder`)
    /// changes no existing encoding — the discriminants are explicit and stable — and the
    /// manifest is what users and auditors read, so the reason must be specific.
    FillPriceOutOfBand = 11,
```

In `crates/perp-core/src/engine.rs`, in `op_fill`, immediately after `let mark = oracle.validate(&market, now_ms)?;` (`:501`):

```rust
        // SEC-022 §1 — bound the execution price to a symmetric band around the ATTESTED
        // mark: |price − mark| · RATE_SCALE <= max_fill_deviation_ratio · mark. Placed
        // after `validate` so no band check is reachable without a valid publisher
        // signature. Copied from `op_accrue_funding`'s mark band (ZK-001 Task 4), whose
        // properties were already reasoned through: division-free (both sides products);
        // the RHS multiplies the ATTESTED `mark`, never the untrusted `price`, so a prover
        // cannot widen its own band; every step `checked_*` with a catch-all reject, so
        // nothing wraps and nothing panics in-guest. `price > 0` is checked above and
        // `mark > 0` is guaranteed by `validate`.
        let fill_dev = match price.checked_sub(mark) {
            Some(d) => abs(d),
            None => return Err(EngineError::FillPriceOutOfBand),
        };
        match (
            fill_dev.checked_mul(RATE_SCALE),
            market.max_fill_deviation_ratio.checked_mul(mark),
        ) {
            (Some(lhs), Some(rhs)) if lhs <= rhs => {}
            _ => return Err(EngineError::FillPriceOutOfBand),
        }
```

`abs` and `RATE_SCALE` are already in scope in `engine.rs` (used by `op_accrue_funding` at `:627-632`); if not, import from `crate::fixed`.

In `crates/sequencer/src/lib.rs`, in `settlement_reason` (`:256`), add an arm before the catch-all:

```rust
        EngineError::FillPriceOutOfBand => RejectReason::FillPriceOutOfBand,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p perp-core --test sec022_fill_band`
Expected: PASS (9 tests).

- [ ] **Step 5: Run the whole workspace suite**

Run: `cargo test --workspace`
Expected: PASS. Fixtures fill at their oracle price (checked: `lifecycle.rs:151-159`, `perp-core/tests/fuzz.rs:144-145`), so the band should be non-disruptive. **If a test fails, align that fixture's oracle to its fill price — never widen the band.**

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/perp-core/src crates/perp-core/tests/sec022_fill_band.rs crates/sequencer/src/lib.rs
git commit -m "feat(perp-core): SEC-022 §1 — bound the fill price to the attested oracle mark

op_fill validated only size > 0 && price > 0 and obtained the mark solely for the
initial-margin check — price and mark were never compared, so two accounts could
cross at any price. Adds the symmetric band around the ATTESTED mark (RHS anchored
to mark, never to the untrusted price), plus a specific RejectReason rather than
the InvalidOrder catch-all."
```

---

### Task 4: The solvency postcondition

**Files:**
- Modify: `crates/perp-core/src/position.rs` (add `check_maintenance_margin` after `check_initial_margin` at `:201`)
- Modify: `crates/perp-core/src/error.rs` (add `FillLeg` + `FillWouldBankrupt(FillLeg)`)
- Modify: `crates/perp-core/src/engine.rs` (`op_fill` staging loop, after the fee/margin block at `:572-574`)
- Modify: `crates/perp-core/src/order.rs` (append `RejectReason::FillWouldBankrupt = 12`)
- Modify: `crates/sequencer/src/lib.rs` (`settlement_reason`)
- Test: `crates/perp-core/tests/sec022_fill_band.rs`

**Interfaces:**
- Consumes: Task 2's infallible commit block; Task 3's band.
- Produces: `pub enum FillLeg { Taker, Maker }` (`Copy`), `EngineError::FillWouldBankrupt(FillLeg)`, `RejectReason::FillWouldBankrupt = 12`, and `Position::check_maintenance_margin(&self, &Market, i128, i128) -> Result<(), RiskError>`. Task 5 reads the `FillLeg` payload.

- [ ] **Step 1: Write the failing tests**

Append to `crates/perp-core/tests/sec022_fill_band.rs`:

```rust
// --------------------------------------------------- Task 4: the solvency postcondition

/// A fill must not succeed leaving a CLOSED leg with negative collateral: nothing revisits
/// a flat position. Both `op_liquidate` and the sequencer's maintenance pass require
/// `is_open()` (`engine.rs:667`, `sequencer/src/lib.rs:744`), and `auto_deleverage` skips
/// `!pos.is_open()` — so the debt is parked forever while the winner withdraws normally.
#[test]
fn closed_leg_with_negative_collateral_is_rejected() {
    let mut s = state_with(Market::conservative(0));
    let (a, b) = (owner_of(1), owner_of(2));
    fund(&mut s, a, 1, 20_000 * QUOTE_SCALE, [0x11u8; 32], 0);
    fund(&mut s, b, 2, 200_000 * QUOTE_SCALE, [0x22u8; 32], 1);
    s.apply_op(&fill(a, b, Side::Buy, 2 * SIZE_SCALE, 100_000, 1_000))
        .expect("open 2 BTC on $20k (10x)");
    // Strip A's collateral so any realized loss closes it negative.
    s.positions.get_mut(&(a, 0)).unwrap().collateral = 0;
    let before = s.state_root();
    let err = s
        .apply_op(&BatchOp::Fill {
            taker: a,
            maker: b,
            market_id: 0,
            taker_side: Side::Sell,
            size: 2 * SIZE_SCALE,
            price: 98_000 * PRICE_SCALE,
            oracle: oracle(100_000, 2_000),
            now_ms: 2_000,
        })
        .expect_err("closing into debt must reject");
    assert_eq!(err, EngineError::FillWouldBankrupt(FillLeg::Taker));
    assert_eq!(s.state_root(), before, "whole state and root unchanged");
}

/// **The fragmentation regression.** The rule is CONDITIONAL, and that is load-bearing.
/// A flat `collateral >= 0` on every leg is a denial of service: `apply_fill` settles the
/// position's ENTIRE accrued funding while realizing PnL only on the closed fragment, so
/// an attacker posting many small resting orders makes every fragment of a solvent
/// aggregate close fail, each re-settling the full funding bill against unchanged state —
/// while the victim stays non-liquidatable. Requiring maintenance-compliance on a
/// still-OPEN leg sidesteps it: a partial close of a healthy position leaves it healthy.
#[test]
fn healthy_position_can_close_in_small_fragments() {
    let mut s = state_with(Market::conservative(0));
    let (a, b) = (owner_of(1), owner_of(2));
    fund(&mut s, a, 1, 30_000 * QUOTE_SCALE, [0x11u8; 32], 0);
    fund(&mut s, b, 2, 300_000 * QUOTE_SCALE, [0x22u8; 32], 1);
    s.apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 100_000, 1_000))
        .expect("open 1 BTC");
    // Close it in ten 0.1 BTC fragments. EVERY fragment must be accepted — rejection
    // must not count as success here.
    for i in 0..10u64 {
        s.apply_op(&fill(
            a,
            b,
            Side::Sell,
            SIZE_SCALE / 10,
            100_000,
            2_000 + i * 10,
        ))
        .unwrap_or_else(|e| panic!("fragment {i} must be accepted, got {e:?}"));
    }
    assert_eq!(s.position(&a, 0).unwrap().size, 0, "fully closed");
    assert!(s.conservation_holds());
}

/// Every pure reduction that satisfies the joint band/fee inequality must RETURN OK and
/// leave the position maintenance-compliant or cleanly closed. Property-style sweep —
/// rejection does not count as success (the earlier draft's version was vacuous).
#[test]
fn every_in_band_reduction_of_a_healthy_position_succeeds() {
    for price_usd in [98_000i128, 99_000, 100_000, 101_000, 102_000] {
        for denom in [1i128, 2, 4, 10] {
            let mut s = state_with(Market::with_fees(0, 10, 4));
            let (a, b) = (owner_of(1), owner_of(2));
            fund(&mut s, a, 1, 50_000 * QUOTE_SCALE, [0x11u8; 32], 0);
            fund(&mut s, b, 2, 500_000 * QUOTE_SCALE, [0x22u8; 32], 1);
            s.apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 100_000, 1_000))
                .expect("open 1 BTC on $50k — comfortably margined");
            s.apply_op(&fill(a, b, Side::Sell, SIZE_SCALE / denom, price_usd, 2_000))
                .unwrap_or_else(|e| {
                    panic!("in-band reduction at ${price_usd} size 1/{denom} rejected: {e:?}")
                });
            let pos = s.position(&a, 0).unwrap();
            assert!(
                !pos.is_open() || pos.collateral >= 0,
                "a closed leg never carries debt",
            );
            assert!(s.conservation_holds());
        }
    }
}

/// A still-OPEN leg left below maintenance is rejected, not merely left non-negative.
#[test]
fn fill_leaving_an_open_leg_below_maintenance_is_rejected() {
    let mut s = state_with(Market::conservative(0));
    let (a, b) = (owner_of(1), owner_of(2));
    fund(&mut s, a, 1, 20_000 * QUOTE_SCALE, [0x11u8; 32], 0);
    fund(&mut s, b, 2, 300_000 * QUOTE_SCALE, [0x22u8; 32], 1);
    s.apply_op(&fill(a, b, Side::Buy, 2 * SIZE_SCALE, 100_000, 1_000))
        .expect("open 2 BTC on $20k");
    // Leave a sliver of collateral: any partial close leaves the REMAINING open leg
    // below its maintenance requirement.
    s.positions.get_mut(&(a, 0)).unwrap().collateral = 100 * QUOTE_SCALE;
    let before = s.state_root();
    let err = s
        .apply_op(&fill(a, b, Side::Sell, SIZE_SCALE / 10, 99_000, 2_000))
        .expect_err("an open leg below maintenance must reject");
    assert_eq!(err, EngineError::FillWouldBankrupt(FillLeg::Taker));
    assert_eq!(s.state_root(), before);
}
```

Add `FillLeg` to the test file's imports: `use perp_core::{DefaultState, EngineError, FillLeg, Market, Note};` (re-export it from `lib.rs` alongside `EngineError`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p perp-core --test sec022_fill_band`
Expected: FAIL — `cannot find type 'FillLeg'` / `no variant named 'FillWouldBankrupt'` (compile errors).

- [ ] **Step 3: Add `check_maintenance_margin`, `FillLeg`, the error, the reason, and the postcondition**

In `crates/perp-core/src/position.rs`, after `check_initial_margin` (`:201`):

```rust
    /// SEC-022 §3: does this position satisfy MAINTENANCE margin? The checked,
    /// fail-CLOSED sibling of [`Self::is_liquidatable`].
    ///
    /// `is_liquidatable` deliberately returns `false` on overflow — for auto-liquidation
    /// that is the conservative direction (do not seize a position whose health we cannot
    /// compute). For a solvency POSTCONDITION the identical default is fail-OPEN: it would
    /// ACCEPT a fill whose resulting health could not be evaluated. So this returns
    /// `Err(RiskError::Overflow)` instead and the caller rejects the fill.
    pub fn check_maintenance_margin(
        &self,
        market: &Market,
        mark: i128,
        funding_index_now: i128,
    ) -> Result<(), RiskError> {
        let eq = self
            .equity(mark, funding_index_now)
            .ok_or(RiskError::Overflow)?;
        let mm = self
            .maintenance_required(market, mark)
            .ok_or(RiskError::Overflow)?;
        if eq < mm {
            return Err(RiskError::InsufficientMargin);
        }
        Ok(())
    }
```

In `crates/perp-core/src/error.rs`, above `EngineError`:

```rust
/// Which leg of a two-sided fill a rejection is attributable to (SEC-022 §6). Settlement
/// used to record the SAME reason against BOTH order hashes, so an innocent counterparty
/// was rejected alongside the offender. `Copy`, so `EngineError` stays `Copy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillLeg {
    Taker,
    Maker,
}
```

and append to `EngineError`:

```rust
    /// SEC-022: the fill would have left the identified leg either CLOSED with negative
    /// collateral — debt no liquidation path revisits, since `op_liquidate` and the
    /// maintenance pass both require `is_open()` — or still open and below maintenance
    /// margin. Two parties electing to trade always have "not trading" available, and it
    /// is strictly better for the protocol than parking unresolvable debt.
    FillWouldBankrupt(FillLeg),
```

Re-export from `crates/perp-core/src/lib.rs` wherever `EngineError` is re-exported:

```rust
pub use error::{EngineError, FillLeg};
```

In `crates/perp-core/src/order.rs`, append to `RejectReason`:

```rust
    /// SEC-022: the fill would have left a leg closed with negative collateral, or still
    /// open below maintenance margin. Rejected rather than settled into parked debt.
    FillWouldBankrupt = 12,
```

In `crates/perp-core/src/engine.rs`, in `op_fill`'s staging loop, replace the `if increasing { … }` block (`:572-574`) with:

```rust
            let leg = if i == 0 { FillLeg::Taker } else { FillLeg::Maker };
            if increasing {
                pos.check_initial_margin(&market, mark, funding_index)?;
            }
            // SEC-022 §3 — the solvency postcondition, checked on the STAGED leg before
            // anything commits. Conditional by design:
            //   * a leg ending CLOSED must not carry negative collateral — nothing
            //     revisits a flat position (`engine.rs` liquidation and ADL, and the
            //     sequencer's maintenance pass, all require `is_open()`), so that debt is
            //     parked forever while the winner withdraws normally; and
            //   * a leg that stays OPEN must still be maintenance-compliant.
            // A flat `collateral >= 0` on BOTH cases would be a denial of service:
            // `apply_fill` settles the position's ENTIRE accrued funding while realizing
            // PnL only on the closed fragment, so small resting orders could make every
            // fragment of a solvent aggregate close fail while the victim stays
            // non-liquidatable. Requiring maintenance-compliance on a still-open leg
            // sidesteps that — the funding settled is the funding maintenance equity
            // already accounts for.
            if pos.is_open() {
                if pos
                    .check_maintenance_margin(&market, mark, funding_index)
                    .is_err()
                {
                    return Err(EngineError::FillWouldBankrupt(leg));
                }
            } else if pos.collateral < 0 {
                return Err(EngineError::FillWouldBankrupt(leg));
            }
```

Import `FillLeg` in `engine.rs`.

In `crates/sequencer/src/lib.rs`, in `settlement_reason`, add before the catch-all:

```rust
        EngineError::FillWouldBankrupt(_) => RejectReason::FillWouldBankrupt,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p perp-core --test sec022_fill_band`
Expected: PASS (13 tests).

- [ ] **Step 5: Run the whole workspace suite and triage hazard 1**

Run: `cargo test --workspace`
Expected: PASS. **A failure where a below-maintenance position reduces is hazard 1 from the header** — the new rule blocks it deliberately; liquidation or `FundPosition` is the path. Triage each such failure and report it; do not weaken the rule or silently rewrite the expectation. Every existing **liquidation** test must pass unchanged (liquidations do not dispatch through `op_fill`).

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/perp-core/src crates/perp-core/tests/sec022_fill_band.rs crates/sequencer/src/lib.rs
git commit -m "feat(perp-core): SEC-022 §3 — per-fill solvency postcondition

A fill that left a leg closed with negative collateral was never resolved: the
bad-debt waterfall lives only in op_liquidate and is gated on is_open(), and ADL
skips flat positions — so the debt parked while the winner withdrew from the real
vault. Rejects instead, with a rule that is CONDITIONAL by design (closed leg:
collateral >= 0; open leg: maintenance-compliant) because a flat non-negativity
rule is a fragmentation DoS against a solvent aggregate close.

Adds Position::check_maintenance_margin — the fail-CLOSED sibling of
is_liquidatable, which returns false on overflow and would fail OPEN here."
```

---

# Slice B — `crates/sequencer` (host only, no guest change)

### Task 5: Attribute a failed fill to the offending leg only

**Files:**
- Modify: `crates/sequencer/src/lib.rs:901-906` (the settlement `Err` arm)
- Test: `crates/sequencer/src/lib.rs` `mod tests`

**Interfaces:**
- Consumes: `EngineError::FillWouldBankrupt(FillLeg)` and `EngineError::FillPriceOutOfBand` (Tasks 3–4).
- Produces: `fn offending_leg(&EngineError) -> Option<FillLeg>`, used again by Task 7 to decide which order to drop before rematching.

- [ ] **Step 1: Write the failing test**

Add to `crates/sequencer/src/lib.rs` `mod tests`:

```rust
    /// SEC-022 §6: settlement assigned the SAME reason to BOTH order hashes. When the
    /// resting maker supplied the out-of-band price, rejecting the innocent taker is the
    /// larger unfairness — and the reduce_only arm directly above already follows the
    /// opposite (correct) rule. A bankruptcy is attributable to one leg; the band price
    /// comes from the resting maker (`matcher/book.rs:295`), so it is the maker's.
    #[test]
    fn a_failed_fill_is_attributed_to_the_offending_leg_only() {
        assert_eq!(
            offending_leg(&EngineError::FillWouldBankrupt(FillLeg::Taker)),
            Some(FillLeg::Taker),
        );
        assert_eq!(
            offending_leg(&EngineError::FillWouldBankrupt(FillLeg::Maker)),
            Some(FillLeg::Maker),
        );
        assert_eq!(
            offending_leg(&EngineError::FillPriceOutOfBand),
            Some(FillLeg::Maker),
            "the execution price is the resting maker's, not the taker's limit",
        );
        // Errors with no attributable leg still reject both, as before.
        assert_eq!(offending_leg(&EngineError::Overflow), None);
        assert_eq!(offending_leg(&EngineError::UnknownMarket), None);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p sequencer offending_leg`
Expected: FAIL — `cannot find function 'offending_leg' in this scope`.

- [ ] **Step 3: Add `offending_leg` and use it in the rejection arm**

In `crates/sequencer/src/lib.rs`, next to `settlement_reason` (`:255`):

```rust
/// Which order a failed fill is attributable to, if the engine identified one (SEC-022 §6).
/// `None` means the failure is not attributable and both legs are recorded, as before.
fn offending_leg(e: &EngineError) -> Option<FillLeg> {
    match e {
        // The engine names the leg whose staged result violated the postcondition.
        EngineError::FillWouldBankrupt(leg) => Some(*leg),
        // The execution price is the RESTING MAKER's (`matcher/book.rs:295`); the taker
        // only supplied a limit it was willing to cross. An out-of-band price is therefore
        // the maker's order to cancel, not the taker's.
        EngineError::FillPriceOutOfBand => Some(FillLeg::Maker),
        _ => None,
    }
}
```

Replace the `Err(e)` arm at `:901-906` with:

```rust
                Err(e) => {
                    let reason = settlement_reason(&e);
                    // Attribute the rejection to the offending leg ONLY, never to an
                    // innocent counterparty — the same rule the reduce_only arm above
                    // already follows.
                    match offending_leg(&e) {
                        Some(FillLeg::Taker) => {
                            settlement_rejected.push((m.taker_order_hash, reason))
                        }
                        Some(FillLeg::Maker) => {
                            settlement_rejected.push((m.maker_order_hash, reason))
                        }
                        None => {
                            for oh in [m.taker_order_hash, m.maker_order_hash] {
                                settlement_rejected.push((oh, reason));
                            }
                        }
                    }
                }
```

Import `FillLeg` from `perp_core`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sequencer`
Expected: PASS.

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/sequencer/src/lib.rs
git commit -m "fix(sequencer): SEC-022 §6 — attribute a failed fill to the offending leg

Settlement recorded the same reason against both order hashes. The band price is
the resting maker's and a bankruptcy belongs to the leg the engine names, so the
innocent counterparty no longer lands in manifest.rejected."
```

---

### Task 6: Extract `settle_fills` — pure refactor, no behaviour change

Task 7 must run this logic twice (once against a probe clone, once for real) and the two runs must be *identical by construction*, not by inspection.

**Files:**
- Modify: `crates/sequencer/src/lib.rs:844-908` (the settlement loop in `seal_batch`), plus `exposure_increases`

**Interfaces:**
- Produces:
  ```rust
  struct FillSettlement {
      ops: Vec<BatchOp>,
      rejected: Vec<(Digest, RejectReason)>,
      settled_order_hashes: Vec<Digest>,
      /// SEC-022 §6: order hashes whose fill failed for an ATTRIBUTABLE reason
      /// (band / bankruptcy) and which Task 7 therefore drops before rematching.
      offenders: Vec<Digest>,
  }

  fn settle_fills(
      state: &mut DefaultState,
      oracles: &BTreeMap<MarketId, OracleTranscript>,
      fills: &[Match],
      now_ms: u64,
  ) -> FillSettlement;

  fn exposure_increases_in(
      state: &DefaultState,
      owner: &PubKey,
      market_id: MarketId,
      delta: i128,
  ) -> bool;
  ```
  `Sequencer::exposure_increases` becomes a thin delegate to `exposure_increases_in` so both callers share one definition.

- [ ] **Step 1: Pin current behaviour before touching anything**

Run: `cargo test --workspace 2>&1 | tail -20`
Expected: PASS. Record the counts — this task must not change a single one.

- [ ] **Step 2: Move the loop body into `settle_fills`**

Lift `crates/sequencer/src/lib.rs:844-908` verbatim into the free function above, substituting:
- `self.oracles.get(...)` → `oracles.get(...)`
- `self.state.apply_op(&op)` → `state.apply_op(&op)`
- `self.exposure_increases(...)` → `exposure_increases_in(state, ...)`
- the local `ops` / `settlement_rejected` / `settled_order_hashes` accumulators become fields of the returned `FillSettlement`

Populate `offenders` in the `Err` arm using `offending_leg` from Task 5 — the same hash pushed to `rejected`, and only when a leg was attributable:

```rust
                    match offending_leg(&e) {
                        Some(FillLeg::Taker) => {
                            out.rejected.push((m.taker_order_hash, reason));
                            out.offenders.push(m.taker_order_hash);
                        }
                        Some(FillLeg::Maker) => {
                            out.rejected.push((m.maker_order_hash, reason));
                            out.offenders.push(m.maker_order_hash);
                        }
                        None => {
                            for oh in [m.taker_order_hash, m.maker_order_hash] {
                                out.rejected.push((oh, reason));
                            }
                        }
                    }
```

In `seal_batch`, call it and destructure:

```rust
        let FillSettlement {
            mut ops,
            rejected: settlement_rejected,
            settled_order_hashes,
            offenders: _,
        } = settle_fills(&mut self.state, &self.oracles, &stream.fills, now_ms);
```

Only `ops` needs `mut` — it is extended with maintenance ops immediately below (`:918`). `settlement_rejected` and `settled_order_hashes` were `mut` only because the lifted loop pushed to them; after extraction both are read-only at the call site (`:928-936`, `:990`).

- [ ] **Step 3: Run the whole suite to verify nothing changed**

Run: `cargo test --workspace`
Expected: PASS with **identical counts** to Step 1. Any behavioural difference is a mistake in the lift — find it, don't accommodate it.

- [ ] **Step 4: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/sequencer/src/lib.rs
git commit -m "refactor(sequencer): extract settle_fills from seal_batch

No behaviour change. SEC-022 §6 needs this logic run against a probe clone and
then for real, and the two runs must be identical by construction."
```

---

### Task 7: Dry-run settlement, roll the book back, rematch

**The defect:** `process_stream` matches the whole stream and mutates the book (`matcher/book.rs:295-308` decrements or pops the resting maker) at `:821`, while settlement only discovers the fill is invalid at `:844`. The rejection arm records the hashes and never restores the book. Tasks 3–4 **materially increase** settlement-time rejections, so without this an attacker burns resting liquidity without ever executing.

A band check in `pre_trade_check` is not a substitute: the execution price comes from the resting maker rather than the incoming taker's limit; a `Gtc` maker admitted in-band drifts out of band as the oracle moves; and rejecting broad taker limits would discard orders whose actual fills would have been valid.

**Files:**
- Modify: `crates/sequencer/src/lib.rs` (`seal_batch` steps 1–3, `:820-908`)
- Test: `crates/sequencer/src/lib.rs` `mod tests`

**Interfaces:**
- Consumes: `settle_fills` / `FillSettlement.offenders` (Task 6), `offending_leg` (Task 5).

- [ ] **Step 1: Write the failing test**

Add to `crates/sequencer/src/lib.rs` `mod tests`. These build on the module's existing fixtures — `test_sequencer()` (which registers market 0 with a $100k signed oracle and funds owners 1 and 2 with $20k each), `t_order`, `fund` and `owner_id` — plus one new helper. `OrderBook::resting_size(side)` already exists (`crates/matcher/src/book.rs:127`); no new accessor is needed.

```rust
    /// A GTC order at an explicit limit price and size. `t_order` is pinned to
    /// $100k / 0.1 BTC; these tests need makers resting away from the mark.
    fn t_order_at(owner: u64, side: Side, price_usd: i128, size: i128, nonce: u64) -> Order {
        Order {
            limit_price: price_usd * PRICE_SCALE,
            size,
            ..t_order(owner, side, nonce)
        }
    }

    /// SEC-022 §6: an out-of-band match must not permanently consume resting liquidity.
    /// The matcher decrements the resting maker (`matcher/book.rs:295-308`) before
    /// settlement discovers the fill is invalid, and the rejection arm never restored it —
    /// so an attacker could burn a book without ever executing.
    #[test]
    fn a_rejected_fill_does_not_consume_resting_liquidity() {
        let mut sq = test_sequencer();
        fund(&mut sq, 3, 20_000, 0x33); // a third account, for the honest maker
        let size = SIZE_SCALE / 10; // 0.1 BTC — $10k notional, $1k initial margin

        // Owner 1 rests 50% above the $100k mark: any fill against it is out of band.
        // Owner 3 rests AT the mark. Owner 2 takes with a limit wide enough to cross both.
        let bad_maker = t_order_at(1, Side::Sell, 150_000, size, 100);
        let good_maker = t_order_at(3, Side::Sell, 100_000, size, 101);
        let taker = t_order_at(2, Side::Buy, 200_000, size, 102);
        let sealed = sq.seal_batch(&[bad_maker, good_maker, taker], now());

        let bad_h = bad_maker.order_hash::<Keccak256>();
        let taker_h = taker.order_hash::<Keccak256>();
        assert!(
            sealed
                .manifest
                .rejected
                .iter()
                .any(|(h, r)| *h == bad_h && *r == RejectReason::FillPriceOutOfBand),
            "the out-of-band MAKER is rejected, with a specific reason: {:?}",
            sealed.manifest.rejected,
        );
        assert!(
            !sealed.manifest.rejected.iter().any(|(h, _)| *h == taker_h),
            "the innocent taker must not be rejected alongside it",
        );
        assert!(
            sealed.manifest.ordered.contains(&taker_h),
            "on the rematch the taker really does trade, against the honest maker",
        );
        // The out-of-band maker's depth was returned to the book, not burned. Only the
        // honest maker's 0.1 BTC was consumed, by a fill that actually settled.
        let book = sq.matcher.book(0).expect("market 0");
        assert_eq!(
            book.resting_size(Side::Sell),
            size,
            "the rejected maker's depth is restored; only the filled maker's is consumed",
        );
    }

    /// **Fragmentation regression at the sequencer level** (the core-level twin lives in
    /// `perp-core/tests/sec022_fill_band.rs`). A solvent aggregate close must not become
    /// impossible because the counterparty fragmented it across many small resting orders.
    #[test]
    fn a_healthy_position_closes_against_fragmented_resting_liquidity() {
        let mut sq = test_sequencer();
        // Owner 1 opens 0.5 BTC long against owner 2, at the mark.
        let half = SIZE_SCALE / 2;
        sq.seal_batch(
            &[
                t_order_at(2, Side::Sell, 100_000, half, 200),
                t_order_at(1, Side::Buy, 100_000, half, 201),
            ],
            now(),
        );
        assert_eq!(sq.state.position(&owner_id(1), 0).unwrap().size, half);

        // Owner 2 fragments the other side into five 0.1 BTC resting bids at the mark;
        // owner 1 closes across all of them in one batch. Every fragment must settle.
        let mut orders: Vec<Order> = (0..5)
            .map(|i| t_order_at(2, Side::Buy, 100_000, SIZE_SCALE / 10, 300 + i))
            .collect();
        orders.push(t_order_at(1, Side::Sell, 100_000, half, 400));
        let sealed = sq.seal_batch(&orders, now() + 10);

        assert!(
            sealed.manifest.rejected.iter().all(|(_, r)| !matches!(
                r,
                RejectReason::FillWouldBankrupt | RejectReason::FillPriceOutOfBand
            )),
            "no fragment may be rejected as bankrupting or out of band: {:?}",
            sealed.manifest.rejected,
        );
        assert_eq!(
            sq.state.position(&owner_id(1), 0).unwrap().size,
            0,
            "the aggregate close completed across every fragment",
        );
        assert!(sq.state.conservation_holds());
    }

    /// The loop terminates when EVERY admitted order is offending: each round bans at
    /// least one, so it runs at most once per order and still produces a sealed batch.
    #[test]
    fn rematch_loop_terminates_when_every_fill_is_offending() {
        let mut sq = test_sequencer();
        let size = SIZE_SCALE / 100;
        // Four crossing pairs, all far off the mark — every resulting fill is out of band.
        let mut orders = Vec::new();
        for i in 0..4u64 {
            orders.push(t_order_at(1, Side::Sell, 150_000, size, 500 + i * 2));
            orders.push(t_order_at(2, Side::Buy, 160_000, size, 501 + i * 2));
        }
        let sealed = sq.seal_batch(&orders, now());
        assert!(
            !sealed.manifest.rejected.is_empty(),
            "every fill was out of band, so the batch rejects rather than hanging",
        );
        assert!(sq.state.conservation_holds());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p sequencer sec022 -- --list` then `cargo test -p sequencer a_rejected_fill_does_not_consume_resting_liquidity`
Expected: FAIL — the out-of-band maker's depth is consumed (`resting_size(Sell) == 0`, not `size`) and the taker is rejected alongside the maker.

- [ ] **Step 3: Wrap matching and settlement in a dry-run / rollback / rematch loop**

In `seal_batch`, replace steps 1–3 (`:820-908`) with:

```rust
        // 1. match, then DRY-RUN settlement against a probe clone before the book's
        //    mutation is allowed to stand (SEC-022 §6). The matcher consumes resting
        //    depth during `process_stream`, but settlement only discovers an out-of-band
        //    or bankrupting fill afterwards — so a rejected fill used to burn liquidity
        //    that never executed. On any attributable failure we restore the book,
        //    ban the offending order, and rematch. `MatchingEngine` is `Clone` and the
        //    restore carries `next_seq` with it, so the final pass assigns exactly the
        //    seq numbers it would have had if the banned orders had never arrived.
        let matcher_before = self.matcher.clone();
        let mut live: Vec<Order> = admitted;
        let mut banned: Vec<(Digest, RejectReason)> = Vec::new();
        let mut banned_set: BTreeSet<Digest> = BTreeSet::new();
        // Every iteration bans at least one order and `live` shrinks by at least one, so
        // the loop runs at most once per admitted order. The counter makes that bound
        // explicit rather than implied.
        let max_rounds = live.len() + 1;
        let mut rounds = 0usize;
        let stream = loop {
            rounds += 1;
            assert!(
                rounds <= max_rounds,
                "rematch loop must terminate: each round bans >= 1 of {} orders",
                max_rounds - 1,
            );
            let stream = self.matcher.process_stream(&live, now_ms);
            let mut probe = self.state.clone();
            let probed = settle_fills(&mut probe, &self.oracles, &stream.fills, now_ms);
            if probed.offenders.is_empty() {
                break stream;
            }
            // Roll the book back to exactly where this batch started, drop the offenders,
            // and match again. Each iteration bans at least one order, so this runs at
            // most `live.len()` times.
            self.matcher = matcher_before.clone();
            for oh in &probed.offenders {
                if banned_set.insert(*oh) {
                    let reason = probed
                        .rejected
                        .iter()
                        .find(|(h, _)| h == oh)
                        .map(|(_, r)| *r)
                        .unwrap_or(RejectReason::InvalidOrder);
                    banned.push((*oh, reason));
                }
            }
            live.retain(|o| !banned_set.contains(&o.order_hash::<Keccak256>()));
        };

        // 2. issue signed receipts for every accepted order in the FINAL stream. A banned
        //    order never entered the book on that pass, so it gets no receipt — it is
        //    resolved in `manifest.rejected` instead, which step 5b already treats as a
        //    justified rejection rather than censorship.
        let mut receipts = Vec::new();
        for p in &stream.processed {
            if !matches!(p.outcome.status, SubmitStatus::Rejected(_)) {
                receipts.push(self.issue_receipt(p.outcome.order_hash, now_ms));
            }
        }

        // 3. settle for real. The dry-run above ran the SAME function against the SAME
        //    pre-state with the SAME fills in the SAME order, so this cannot fail
        //    differently; `offenders` is empty by construction here.
        let FillSettlement {
            mut ops,
            rejected: settlement_rejected,
            settled_order_hashes,
            offenders,
        } = settle_fills(&mut self.state, &self.oracles, &stream.fills, now_ms);
        debug_assert!(
            offenders.is_empty(),
            "the committed pass must reproduce the dry run",
        );
```

Then fold `banned` into the manifest's rejected list at step 4 (`:945`):

```rust
        let mut rejected = pre_rejected.clone();
        rejected.extend_from_slice(&banned);
        rejected.extend_from_slice(&stream.rejected);
        rejected.extend_from_slice(&failed_unsettled);
```

Note `admitted` must become owned (`let mut live: Vec<Order> = admitted;`) — it is already built as a `Vec<Order>` at `:796`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sequencer`
Expected: PASS.

- [ ] **Step 5: Run the whole workspace suite**

Run: `cargo test --workspace`
Expected: PASS. **One intentional behaviour change to confirm and report:** an order banned before the final match no longer receives a receipt, where a settlement-rejected order used to get one. It still appears in `manifest.rejected` bound by `manifest_hash`, and step 5b clears no inclusion record for it because none was created. If a test asserts a receipt for a settlement-rejected order, that is this change — update it and say so.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/sequencer/src/lib.rs crates/matcher/src/book.rs
git commit -m "fix(sequencer): SEC-022 §6 — dry-run settlement before the book stands

process_stream mutates the book for the whole stream before settlement sees the
first fill, and the rejection arm never restored it. With the band and the
solvency postcondition rejecting materially more fills, that let an attacker burn
resting liquidity without ever executing. Settlement now dry-runs against a probe
clone; on an attributable failure the book is restored, the offending order is
banned, and the stream is rematched.

Terminates in at most one iteration per admitted order. Restoring the cloned
MatchingEngine carries next_seq, so the final pass assigns the same seq numbers
the banned orders' absence would have produced."
```

---

## Branch completion

- [ ] `cargo test --workspace` green; `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets` clean.
- [ ] Run `superpowers:requesting-code-review` on the whole branch, and send the diff to Codex (`mcp__codex__codex`, `sandbox: read-only`, `cwd` = repo) — **seven of eight specs in this workstream were broken on first review; verify every finding at source before accepting it.**
- [ ] Confirm hazard 1 (a below-maintenance position can no longer reduce) is reported explicitly to the user, with the tests that pin it.
- [ ] Do **not** deploy. This branch joins the cutover bundle (SEC-022 + SEC-024 + SEC-026 + 025-A/B/C/D) and forces a vkey re-pin, a `GENESIS_ROOT` move, fresh `Settlement`/`Vault`/`USDC`, and a snapshot + rollback-journal wipe. `crates/prover-service/src/bin/seal-client.rs` and `crates/sp1-host/src/{main.rs,bin/prove.rs}` **still do not build** (pre-SEC-019 four-field `BatchOp::Deposit`) and will stop the cutover at the prover — that is 025-B, tracked separately.
