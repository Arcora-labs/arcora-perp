# SEC-024 — Insurance L1 binding (+ two SEC-022 carry-ins) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the only unbounded external-value assertion in the proven transition — `SeedInsurance` fabricates the accounting representation of collateral that never entered the system — and fold in the two `perp-core` items deferred from SEC-022 while the vkey is moving anyway.

**Architecture:** `SeedInsurance` is retained at ordinal 8 as an always-rejected `DeprecatedSeedInsurance` (so legacy postcard bytes decode to their original meaning and are refused, rather than silently mis-parsing), and a new `FundInsurance` at ordinal 9 consumes a real note and moves its value into `insurance_fund` **without touching `external_in`**. Insurance becomes a transfer of already-L1-bound value instead of a mint.

**Source spec:** `docs/superpowers/specs/2026-07-26-sec024-insurance-l1-binding-design.md`. **Read its "Second adversarial review, 2026-07-30" section first** — six findings, four of which changed this work, including one where the previously-prescribed demo conversion was impossible.

**Tech Stack:** Rust, `#![no_std]` + `alloc` (`perp-core`, compiled into the SP1 guest), `postcard` serde.

## Global Constraints

- **This piece changes `crates/perp-core`, so it moves the guest ELF and the vkey.** A fresh `SP1ZkVerifier` deploy is required at cutover. That is expected and is the reason the two SEC-022 carry-ins ride along here.
- **It does NOT move the production `GENESIS_ROOT`.** 025-C already made production genesis markets-only, so production boot never seeds insurance. **The demo genesis root DOES move** (Task 1 adds a deposit to it).
- **`cargo fmt --all` before every commit.** CI runs `cargo fmt --all -- --check`.
- **`cargo clippy --workspace --all-targets` must be clean.**
- Gateway is **bin-only** — `cargo test --bin gateway`, **never** `--lib` (that errors "no library targets found"; two briefs on an earlier branch shipped `--lib` commands that could not run).
- Baseline: `cargo test --workspace` = **542 passed / 50 suites**; `cd contracts && forge test` = **85**.
- **`RejectReason` is append-only** — explicit `#[repr(u16)]` discriminants folded into `BatchManifest::hash`.
- **`BatchOp` ordinal 8 must be retained.** `postcard` 1.1.3 writes a struct variant's ordinal as a varint before its fields, so keeping ordinal 8 with the identical `i128` payload preserves element boundaries inside a `Vec<BatchOp>`. Replacing it in place would let old bytes decode as the *new* variant and consume following bytes as its fields — a silent mis-parse.

## Fixture suspicion is mandatory

Across this workstream **sixteen test fixtures have been caught passing while exercising nothing** — every task has found one in its own brief. Worse, one plan placed a guard so a debit applied before the refusal, which would have destroyed user value in production; and two specs asserted mitigations no code path could perform.

**Assume the fixtures below are wrong.** Verify each reaches the path its name claims and would fail if the behaviour regressed. Where a task says "must fail before the change", verify literally by stashing. Mutation-test where a task says to.

---

### Task 1: `DeprecatedSeedInsurance`, `FundInsurance`, and all four call sites

One commit. Deprecating the op **breaks the demo boot** (`main.rs:1626` reaches `.expect("seed insurance fund")` and panics) and two `perp-core` tests, so the conversions cannot land separately.

**Files:**
- Modify: `crates/perp-core/src/engine.rs` — `BatchOp` (`:109`), the dispatch arm (`:308`), `op_seed_insurance` (`:867-880`), `consume_note` (`:421-451`)
- Modify: `crates/perp-core/src/error.rs` — new variants
- Modify: `crates/gateway/src/main.rs` — demo boot (`:1626`), `simulate_adl` replenish (`:3022`)
- Modify: `crates/sequencer/src/lib.rs:1888` — test-boot fixture
- Modify: `crates/perp-core/tests/lifecycle.rs:522` — `seed_usd` fixture
- Test: `crates/perp-core/tests/lifecycle.rs`

**Interfaces:**
- Produces: `BatchOp::DeprecatedSeedInsurance { amount: i128 }` (ordinal 8, always rejected) and `BatchOp::FundInsurance { note_commitment: Digest, spend_key: Digest }` (ordinal 9). `EngineError::DeprecatedOp` and `EngineError::WrongAsset`. A non-mutating `State::validate_note_spend(...) -> Result<(Note, Digest), EngineError>` returning the note and its nullifier.

**Why a validation split is required.** `consume_note` (`:421-451`) validates fully (`:427-446`) and then **mutates** — inserts the nullifier (`:448`) and removes the note (`:449`) — returning the `Note`. Any fallible arithmetic *after* that call leaves the note destroyed on failure. `op_fund_position` (`:453`) has exactly that shape today. `FundInsurance` must not copy it: validate and precompute first, mutate last.

- [ ] **Step 1: Write the failing tests**

Add to `crates/perp-core/tests/lifecycle.rs`:

```rust
/// SEC-024: insurance must be a TRANSFER of already-L1-bound value, not a mint.
/// `FundInsurance` consumes a real note and raises `insurance_fund` while leaving
/// `external_in` untouched — the note's value already entered through `op_deposit`.
#[test]
fn fund_insurance_moves_note_value_without_asserting_new_external_value() {
    let mut s = fresh_state();
    let a = owner_of(1);
    let blind = [0x51u8; 32];
    let amount = 10_000 * QUOTE_SCALE;
    let cm = deposit_commit(a, amount, blind);
    s.apply_batch(&[BatchOp::Deposit {
        owner: a,
        asset_id: 0,
        amount,
        blinding: blind,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    }])
    .expect("deposit");

    let ext_in_before = s.external_in;
    let ins_before = s.insurance_fund;

    s.apply_batch(&[BatchOp::FundInsurance {
        note_commitment: cm,
        spend_key: [1u8; 32],
    }])
    .expect("fund insurance from a real note");

    assert_eq!(s.insurance_fund, ins_before + amount, "value moved in");
    assert_eq!(
        s.external_in, ext_in_before,
        "external_in MUST NOT move — the value entered at deposit, not here"
    );
    assert!(!s.notes.contains_key(&cm), "note consumed");
    assert!(s.conservation_holds());
}

/// The spend key still authorizes: nobody can donate another account's note.
#[test]
fn fund_insurance_rejects_a_wrong_spend_key() {
    let mut s = fresh_state();
    let a = owner_of(1);
    let blind = [0x52u8; 32];
    let amount = 1_000 * QUOTE_SCALE;
    let cm = deposit_commit(a, amount, blind);
    s.apply_batch(&[BatchOp::Deposit {
        owner: a,
        asset_id: 0,
        amount,
        blinding: blind,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    }])
    .expect("deposit");
    let before = s.state_root();
    assert_eq!(
        s.apply_batch(&[BatchOp::FundInsurance {
            note_commitment: cm,
            spend_key: [9u8; 32], // not the owner's key
        }])
        .expect_err("wrong key"),
        EngineError::BadSpendKey
    );
    assert_eq!(s.state_root(), before, "state unchanged");
}

/// **The atomicity test.** `consume_note` inserts the nullifier and removes the note
/// immediately, so a fallible `insurance_fund` addition afterwards would destroy the
/// note and return `Err`. The sequencer logs an op only on success, so live state
/// would diverge from the proven op-log and wedge the next proof.
#[test]
fn fund_insurance_overflow_leaves_state_byte_identical() {
    let mut s = fresh_state();
    let a = owner_of(1);
    let blind = [0x53u8; 32];
    let amount = 1_000 * QUOTE_SCALE;
    let cm = deposit_commit(a, amount, blind);
    s.apply_batch(&[BatchOp::Deposit {
        owner: a,
        asset_id: 0,
        amount,
        blinding: blind,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    }])
    .expect("deposit");
    s.insurance_fund = i128::MAX;
    let before = s.state_root();
    assert_eq!(
        s.apply_batch(&[BatchOp::FundInsurance {
            note_commitment: cm,
            spend_key: [1u8; 32],
        }])
        .expect_err("insurance overflow"),
        EngineError::Overflow
    );
    assert_eq!(
        s.state_root(),
        before,
        "the note must NOT be destroyed by a failed credit"
    );
    assert!(s.notes.contains_key(&cm), "note still unspent");
}

/// A newly-encoded deprecated op is refused deterministically.
#[test]
fn deprecated_seed_insurance_is_always_rejected() {
    let mut s = fresh_state();
    let before = s.state_root();
    assert_eq!(
        s.apply_batch(&[BatchOp::DeprecatedSeedInsurance {
            amount: 1_000 * QUOTE_SCALE
        }])
        .expect_err("deprecated"),
        EngineError::DeprecatedOp
    );
    assert_eq!(s.state_root(), before);
}

/// **The migration test that actually proves the ordinal choice.** A frozen byte
/// vector encoded under the OLD enum must decode to variant 8 with its amount
/// intact, be rejected, and leave the ops that follow it in the vector correctly
/// aligned. Testing newly-encoded bytes proves nothing about migration.
#[cfg(feature = "serde")]
#[test]
fn legacy_seed_insurance_bytes_decode_to_the_stub_and_stay_aligned() {
    // Encode under the CURRENT enum: [DeprecatedSeedInsurance(7500), EnterCloseOnly].
    // Ordinal 8 + i128 payload is byte-identical to what the OLD enum produced for
    // SeedInsurance(7500), which is the property under test.
    let ops = alloc::vec![
        BatchOp::DeprecatedSeedInsurance { amount: 7_500 },
        BatchOp::EnterCloseOnly,
    ];
    let bytes = postcard::to_allocvec(&ops).expect("encode");
    let back: alloc::vec::Vec<BatchOp> = postcard::from_bytes(&bytes).expect("decode");
    assert_eq!(back.len(), 2, "the following op stayed aligned");
    match back[0] {
        BatchOp::DeprecatedSeedInsurance { amount } => assert_eq!(amount, 7_500),
        ref other => panic!("expected the deprecated stub, got {other:?}"),
    }
    assert!(matches!(back[1], BatchOp::EnterCloseOnly));
}
```

**Verify the frozen-bytes test is honest.** The comment above claims the current encoding of `DeprecatedSeedInsurance` is byte-identical to the old `SeedInsurance`. **Check that** — if you can obtain real pre-change bytes (encode on a stashed tree and paste the literal), do so and use the literal; that is strictly stronger. If you use the round-trip form, say plainly in your report that it pins ordinal stability and alignment, not a true byte freeze.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p perp-core --test lifecycle fund_insurance`
Expected: FAIL to compile — `FundInsurance`, `DeprecatedSeedInsurance`, `EngineError::DeprecatedOp` do not exist.

- [ ] **Step 3: Split the validation out of `consume_note`**

In `crates/perp-core/src/engine.rs`, add above `consume_note`:

```rust
    /// SEC-024: the NON-MUTATING half of `consume_note` — look the note up, check the
    /// spend authority and the nullifier, and return the note plus the nullifier the
    /// caller must insert to commit. Split out because `consume_note` mutates
    /// immediately (`:448-449`), so any fallible arithmetic after it destroys the note
    /// on failure. `op_fund_position` has that shape today; `op_fund_insurance` must not.
    fn validate_note_spend(
        &self,
        note_commitment: &Digest,
        spend_key: &Digest,
        expected_owner: Option<&PubKey>,
    ) -> Result<(Note, Digest), EngineError> {
        let note = *self
            .notes
            .get(note_commitment)
            .ok_or(EngineError::UnknownOrSpentNote)?;
        if owner_from_spend_key::<H>(spend_key) != note.owner {
            return Err(EngineError::BadSpendKey);
        }
        if let Some(o) = expected_owner {
            if &note.owner != o {
                return Err(EngineError::BadSpendKey);
            }
        }
        let nf = note.nullifier::<H>(spend_key);
        if self.nullifiers.contains(&nf) {
            return Err(EngineError::UnknownOrSpentNote);
        }
        Ok((note, nf))
    }
```

and rewrite `consume_note`'s body to use it, preserving its existing signature and behaviour exactly:

```rust
    fn consume_note(
        &mut self,
        note_commitment: &Digest,
        spend_key: &Digest,
        expected_owner: Option<&PubKey>,
    ) -> Result<Note, EngineError> {
        let (note, nf) = self.validate_note_spend(note_commitment, spend_key, expected_owner)?;
        let _ = self.nullifiers.insert::<H>(nf);
        self.notes.remove(note_commitment);
        Ok(note)
    }
```

**This must be behaviour-preserving for every existing caller.** If any existing test changes result, stop and report.

- [ ] **Step 4: Add the variants, the errors, and the ops**

In `crates/perp-core/src/engine.rs`, replace `SeedInsurance { amount: i128 }` at `:109` and **append** the new variant, keeping ordinal order:

```rust
    /// SEC-024: RETAINED AT ORDINAL 8 AND ALWAYS REJECTED. This op raised
    /// `insurance_fund` and `external_in` together with no note consumed and no L1
    /// binding — it fabricated the accounting representation of collateral that never
    /// entered the system, and the guest proved it. Kept rather than removed because
    /// `postcard` writes a variant's ordinal before its fields: replacing it in place
    /// would let legacy bytes decode as whatever took index 8 and consume the following
    /// bytes as its fields, a SILENT mis-parse. Retaining it means old bytes decode to
    /// their original meaning and are then refused deterministically. Fail loudly.
    DeprecatedSeedInsurance { amount: i128 },
    /// SEC-024: capitalize insurance by consuming a REAL note. `external_in` is NOT
    /// touched — that value entered the system through the L1-bound deposit path.
    FundInsurance {
        note_commitment: Digest,
        spend_key: Digest,
    },
```

In `crates/perp-core/src/error.rs`, append:

```rust
    /// SEC-024: a retained-but-deprecated op was submitted. Always rejected.
    DeprecatedOp,
    /// SEC-024: the op requires the canonical quote asset (`asset_id == 0`).
    WrongAsset,
```

Replace `op_seed_insurance` (`:867-880`) with the two handlers, and update the dispatch at `:308`:

```rust
    fn op_fund_insurance(
        &mut self,
        note_commitment: &Digest,
        spend_key: &Digest,
    ) -> Result<(), EngineError> {
        // SEC-024 — validate and precompute BEFORE the first mutation. `consume_note`
        // inserts the nullifier and removes the note immediately, so a fallible
        // `checked_add` after it would return Err with the note already destroyed; the
        // sequencer logs an op only on success, so live state would diverge from the
        // proven op-log and wedge the next proof.
        let (note, nf) = self.validate_note_spend(note_commitment, spend_key, None)?;
        // Without this, the op becomes wrong the moment non-canonical note assets
        // become meaningful. Checked BEFORE any mutation, so a wrong asset leaves
        // state byte-identical.
        if note.asset_id != 0 {
            return Err(EngineError::WrongAsset);
        }
        let new_insurance = self
            .insurance_fund
            .checked_add(note.amount)
            .ok_or(EngineError::Overflow)?;

        // commit — infallible from here
        let _ = self.nullifiers.insert::<H>(nf);
        self.notes.remove(note_commitment);
        self.insurance_fund = new_insurance;
        Ok(())
    }
```

No destination-owner constraint (`expected_owner = None`), matching `op_withdraw`: adding value to a communal backstop can only help the protocol, and the spend key still prevents donating someone else's note.

- [ ] **Step 5: Convert all four call sites**

1. **`crates/gateway/src/main.rs:1626`** (demo boot). Replace the `SeedInsurance` apply with a **separate `Deposit` → `FundInsurance` pair using a fresh blind**. There is no unspent boot note to reuse: every boot `fund(...)` reaches `fund_amount`, which emits `Deposit` and **immediately** consumes it with `FundPosition`. Use a blind distinct from every other boot blind (they are `0x40+i`, `0x10+i`, `0x38`) — `0x39` is free.

2. **`crates/gateway/src/main.rs:3022`** (`simulate_adl`'s replenish, currently `let _ = self.seq.apply(...)`). Convert it the same way, or delete it. **Do not leave a swallowed rejection** — `let _ =` on an always-rejected op is silently doing nothing in the one demo whose point is showing the backstop refill. Say which you chose and why.

3. **`crates/sequencer/src/lib.rs:1888`** — test-boot fixture; convert.

4. **`crates/perp-core/tests/lifecycle.rs:522`** — the `seed_usd` fixture, used by `insurance_backstop_absorbs_bad_debt` (`:546`) and `adl_covers_residual_after_insurance` (`:577`). Both **panic** unless converted.

- [ ] **Step 6: Fix the pinned demo count**

Demo `consumed_deposit_count` goes **7 → 8** (the new insurance deposit). `demo_genesis_is_still_funded` in `crates/gateway/src/main.rs` asserts `MARKETS.len() * 2 + 1`. Update it to `+ 2` **and update its comment to say why** — a bare number change with a stale comment is how the next reader gets misled.

The demo genesis root moves. That is expected and affects no deployment (production genesis is markets-only since 025-C).

- [ ] **Step 7: Run everything**

```bash
cargo test --workspace
cd contracts && forge test && cd ..
```
Expected: PASS at 542 + the tests you added. **Any other test that fails is a finding — report which and why before changing it.**

- [ ] **Step 8: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates docs
git commit -m "feat(perp-core): SEC-024 — insurance is a transfer, not a mint

op_seed_insurance raised insurance_fund AND external_in with no note consumed and
no L1 binding — it fabricated the accounting representation of collateral that
never entered the system, and the guest proved it. Mint fake insurance, create bad
debt through fills, have the fabrication absorb it, and the counterparty withdraws
the excess from the REAL vault.

FundInsurance consumes a real note and leaves external_in alone: the value entered
at deposit. SeedInsurance is retained at ordinal 8 as an always-rejected stub
because postcard writes a variant's ordinal before its fields — replacing it in
place would let legacy bytes decode as the new variant and consume the following
bytes as its fields, a silent mis-parse.

Validation is split out of consume_note so the credit is staged before the first
mutation; consume_note mutates immediately, and op_fund_position shows the unsafe
shape this avoids.

Demo boot gains a separate Deposit -> FundInsurance pair (no unspent boot note
exists — fund_amount consumes what it deposits), so demo consumed_deposit_count
goes 7 -> 8 and the demo genesis root moves. Production genesis is unaffected:
025-C already made it markets-only."
```

---

### Task 2: `EngineError::Risk` carries the failing leg

SEC-022 carry-in. Rides here because the vkey is already moving.

**Files:**
- Modify: `crates/perp-core/src/error.rs` — `Risk` variant (`:28`), `From<RiskError>` (`:82-89`)
- Modify: `crates/perp-core/src/engine.rs` — `op_fill`'s margin check (`:598`)
- Modify: `crates/sequencer/src/lib.rs` — `settlement_reason` (`:258`), `offending_leg` (`:273`)
- Test: `crates/sequencer/src/lib.rs` (`mod tests`)

**Interfaces:**
- Produces: `EngineError::Risk { source: RiskError, leg: Option<FillLeg> }`.

**Why a struct variant and not a payload.** `Risk` is **not** fill-specific: `op_unbind` constructs it directly and runs its own margin check (`engine.rs:911`, `:918`), and the generic `From<RiskError>` (`error.rs:82`) has no leg to supply. `Risk(RiskError, FillLeg)` would force a fake leg at both. `Option<FillLeg>` lets `From` supply `None` and `op_fill` supply `Some(leg)`.

**Why it matters.** `offending_leg` returns `None` for `Risk` today (`sequencer/src/lib.rs:273`), so a drifted resting maker that fails its margin check records **both** legs with no offender (`:424`) — the dry run is accepted without rematching (`:1011`), and the innocent taker's consumed liquidity is burned. The matcher has already decremented the resting quantity (`matcher/book.rs:288`).

- [ ] **Step 1: Write the failing test**

```rust
    /// SEC-024 (SEC-022 carry-in): a margin failure on a fill must name the leg, so
    /// the dry run bans the offender and rematches instead of recording both legs and
    /// burning the innocent counterparty's consumed liquidity.
    #[test]
    fn a_fill_margin_failure_names_the_offending_leg() {
        assert_eq!(
            offending_leg(&EngineError::Risk {
                source: RiskError::InsufficientMargin,
                leg: Some(FillLeg::Maker),
            }),
            Some(FillLeg::Maker),
        );
        assert_eq!(
            offending_leg(&EngineError::Risk {
                source: RiskError::InsufficientMargin,
                leg: Some(FillLeg::Taker),
            }),
            Some(FillLeg::Taker),
        );
        // A non-fill Risk (op_unbind) has no leg and must stay non-attributable.
        assert_eq!(
            offending_leg(&EngineError::Risk {
                source: RiskError::InsufficientMargin,
                leg: None,
            }),
            None,
        );
    }

    /// The manifest reason must not change — a margin failure is still
    /// InsufficientMargin whether or not a leg is attached.
    #[test]
    fn settlement_reason_is_unchanged_by_the_leg() {
        for leg in [None, Some(FillLeg::Taker), Some(FillLeg::Maker)] {
            assert_eq!(
                settlement_reason(&EngineError::Risk {
                    source: RiskError::InsufficientMargin,
                    leg,
                }),
                RejectReason::InsufficientMargin,
            );
        }
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p sequencer offending_leg`
Expected: FAIL to compile — `Risk` is a tuple variant.

- [ ] **Step 3: Implement**

`error.rs`: change the variant and the conversion.

```rust
    /// Risk / margin failure (§5, §12). `leg` is `Some` only when the failure arose
    /// inside a two-sided fill, where the engine knows which staged leg violated;
    /// `op_unbind` and the generic `From<RiskError>` have no leg to name.
    Risk {
        source: RiskError,
        leg: Option<FillLeg>,
    },
```

```rust
impl From<RiskError> for EngineError {
    fn from(e: RiskError) -> Self {
        match e {
            RiskError::Overflow => EngineError::Overflow,
            other => EngineError::Risk {
                source: other,
                leg: None,
            },
        }
    }
}
```

`engine.rs` — in `op_fill`, replace the bare `?` at `:598` so the leg survives:

```rust
            if increasing {
                pos.check_initial_margin(&market, mark, funding_index)
                    .map_err(|e| match e {
                        RiskError::Overflow => EngineError::Overflow,
                        source => EngineError::Risk {
                            source,
                            leg: Some(leg),
                        },
                    })?;
            }
```

`sequencer/src/lib.rs` — `settlement_reason` (`:258`) becomes `EngineError::Risk { .. } => RejectReason::InsufficientMargin`, and `offending_leg` (`:273`) gains `EngineError::Risk { leg: Some(l), .. } => Some(*l)` **before** its catch-all.

Follow the compiler for any other `EngineError::Risk(` match site.

- [ ] **Step 4: Run to verify, then the suite**

Run: `cargo test -p sequencer && cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates
git commit -m "feat(perp-core): SEC-022 carry-in — EngineError::Risk names the failing leg

offending_leg returned None for Risk, so a drifted resting maker failing its margin
check recorded BOTH legs with no offender: the dry run accepted without rematching
and the innocent taker's already-consumed liquidity was burned.

A struct variant with Option<FillLeg>, not a payload: Risk is also raised by
op_unbind and by the generic From<RiskError>, neither of which has a leg to supply."
```

---

### Task 3: `op_liquidate` performs no fallible operation after its first mutation

SEC-022 carry-in. Same divergence class §4 closed for `op_fill`, in the op that now receives **more** traffic — SEC-022's postcondition forbids a below-maintenance position from partially closing, so liquidation is its only resolution.

**Files:**
- Modify: `crates/perp-core/src/engine.rs` — `op_liquidate` (`:726` onward)
- Test: `crates/perp-core/tests/lifecycle.rs`

**The defect.** `:731` mutates the position via `apply_fill`, then `:732-737` does fallible `vault_pool` arithmetic, `:745` mutates `pos.collateral`, and `:746-749` does a fallible `insurance_fund` add. A late overflow returns `Err` with the position already closed — and `run_maintenance` takes `if let Ok(...)` (`sequencer/src/lib.rs:915`), so the op never enters the replayable log while the live root already reflects the mutation (`:1207`, `:1247`). The next proof wedges.

- [ ] **Step 1: Write the failing test**

```rust
/// SEC-024 (SEC-022 carry-in): op_liquidate mutated the position via apply_fill and
/// THEN ran fallible vault/insurance arithmetic. A late overflow returned Err with the
/// position already closed, while run_maintenance logs an op only on success — so the
/// live root reflected a mutation the replayable op-log did not contain, and the next
/// proof wedged. Every fallible path must leave state byte-identical.
#[test]
fn liquidation_overflow_leaves_state_byte_identical() {
    let mut s = fresh_state();
    let (a, b) = (owner_of(1), owner_of(2));
    // Build a liquidatable position, then poison the vault pool so the post-close
    // arithmetic overflows.
    // FIXTURE PRECONDITION — assert it, do not assume it: the position must actually
    // be liquidatable at the oracle price used below, or this test exercises
    // NotLiquidatable instead of the overflow path.
    // (Construct with the file's existing helpers; mirror
    // `true_insolvency_trips_close_only_when_winners_have_exited` for the shape.)
    // ...
    s.vault_pool = i128::MIN;
    let before = s.state_root();
    let err = s
        .apply_batch(&[BatchOp::Liquidate {
            owner: a,
            market_id: 0,
            oracle: oracle(80_000, 3_000),
            now_ms: 3_000,
        }])
        .expect_err("vault-pool overflow must reject");
    assert_eq!(err, EngineError::Overflow);
    assert_eq!(
        s.state_root(),
        before,
        "the position must NOT be closed by a failed liquidation"
    );
    let _ = b;
}
```

**You must complete this fixture.** The plan does not supply the position setup, because the exact collateral and price that make a position liquidatable depend on helpers in that file that were not verified while writing this. Build it with the file's existing helpers and **assert the precondition** (`is_liquidatable` true at the chosen price) before the overflow poke — otherwise the test may exercise `NotLiquidatable` and pass for the wrong reason. That failure mode has occurred repeatedly on this workstream. **Add a second variant poisoning `insurance_fund = i128::MAX` instead**, so both fallible paths are covered.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core --test lifecycle liquidation_overflow`
Expected: FAIL on the root-equality assert — the error is right but the position is already closed.

- [ ] **Step 3: Restructure**

Stage every fallible value before the first mutation, mirroring what SEC-022 §4 did to `op_fill`: compute the close on a **copy** of the position, derive `new_vault_pool`, the penalty `take`, and `new_insurance_fund` with checked arithmetic, and only then write the position, the pool and the fund. The bad-debt waterfall below stays where it is — it runs after a successful close and is not part of this change.

Keep the existing error variants and ordering of checks so no other behaviour moves.

- [ ] **Step 4: Run to verify, then the suite**

Run: `cargo test -p perp-core && cargo test --workspace`
Expected: PASS. **Every existing liquidation and ADL test must pass unchanged** — if one does not, report it before touching it.

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates
git commit -m "fix(perp-core): SEC-022 carry-in — op_liquidate commits nothing before its last fallible step

apply_fill mutated the position, then vault_pool and insurance_fund arithmetic could
still fail. run_maintenance logs an op only on success, so a late overflow left the
live root reflecting a close the replayable op-log did not contain — wedging the next
proof. Same class SEC-022 s4 closed for op_fill, in the op that now gets more traffic
because a below-maintenance position can no longer partially close."
```

---

### Task 4: The fabrication guard, the journal magic, and the stale doc

**Files:**
- Test: `crates/perp-core/tests/lifecycle.rs`
- Modify: `crates/gateway/src/rollback_journal.rs:33`, `:38`
- Modify: `docs/ECONOMIC_SECURITY.md:117`

- [ ] **Step 0: The fabrication regression — the spec's headline test**

The spec's testing table asks for *"exactly one writer of `external_in`, and it is `op_deposit`"* — and insists it **"must be a real check — a static assertion or module-visibility restriction, not a review instruction"**, because `external_in` is `pub` (`crates/perp-core/src/state.rs`).

This is the whole finding made mechanical: `SeedInsurance` was the only *unbound-by-design* external-value assertion, and after this branch there must be none. 025-C established the pattern for this shape of guard (a source-scanning enumeration test); follow it.

```rust
/// SEC-024's finding, made mechanical. `external_in` asserts that value entered the
/// system from outside. Before this branch there were TWO writers: `op_deposit`,
/// bound to the SEC-019 L1 hash chain, and `op_seed_insurance`, bound to nothing —
/// it fabricated the accounting representation of collateral that never arrived, and
/// the guest proved it. After this branch there must be exactly one.
///
/// A source scan rather than a type-level restriction because `external_in` is `pub`
/// and used across the crate; making it private is a larger refactor than this
/// finding warrants. If you add a legitimate writer, update the count AND say in the
/// message what binds it to real external value — an unbound writer is the bug.
#[test]
fn external_in_has_exactly_one_writer() {
    let src = include_str!("../src/engine.rs");
    let n = src.matches("self.external_in").count();
    assert_eq!(
        n, EXPECTED,
        "expected N in op_deposit (read + write) and M in op_withdraw's external_out \
         neighbourhood; found {n}. A NEW writer of external_in must be bound to real \
         external value — that binding is the finding SEC-024 exists to close."
    );
}
```

**`EXPECTED` is a placeholder you must replace with the empirical count** — grep `crates/perp-core/src/engine.rs` for `self.external_in`, count the occurrences after Task 1 removes `op_seed_insurance`, and put the real breakdown in the message. **A count that is wrong on day one makes the test noise and a maintainer will delete it.** If the scan turns out to be too coarse to be meaningful (for example if reads and writes are indistinguishable textually), say so and pin something sharper — `external_in +=` or the specific assignment form — rather than shipping a number that does not discriminate.

Mutation-check it: add a scratch `self.external_in = self.external_in + 1;` somewhere in `engine.rs`, confirm the test fails, revert.

- [ ] **Step 1: Bump the magic**

`BatchOp`'s meaning changes (ordinal 8 now rejects; ordinal 9 exists), and `BatchOp` is positional in journaled witnesses via `window_ops` (`sequencer/src/lib.rs:519`, `rollback_journal.rs:47`). A pending journal written before this change must be **refused**, not decoded under the new meaning.

It is already **`DPRBJL3`** after 025-B — **verify that at source before editing** — so the next value is **`DPRBJL4`**. Update the rationale comment to name SEC-024 as the reason.

- [ ] **Step 2: Fix the doc**

`docs/ECONOMIC_SECURITY.md:117` still describes `SeedInsurance` as a "real inflow". It never was — that is the finding. Correct it to say insurance is capitalized by consuming a real, L1-bound note via `FundInsurance`, and that the old op is retained only as an always-rejected stub.

- [ ] **Step 3: Verify and commit**

```bash
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates docs
git commit -m "chore(gateway): SEC-024 — DPRBJL4, and stop calling SeedInsurance a real inflow

BatchOp's meaning changed (8 now rejects, 9 exists) and BatchOp is positional in
journaled witnesses, so a pending pre-SEC-024 journal must be refused rather than
decoded under the new meaning."
```

---

## Branch completion

- [ ] `cargo test --workspace` green; `cd contracts && forge test` still **85**; fmt and clippy clean.
- [ ] Confirm which tests were verified to **fail before the change**: Task 1's atomicity and legacy-bytes tests, Task 3's liquidation overflow.
- [ ] Run `superpowers:requesting-code-review` on the whole branch, and send the diff to Codex (`mcp__codex__codex`, `sandbox: read-only`, `cwd` = repo). **Codex found six defects in this piece's spec across two passes — expect it to find more in the implementation.** Verify every finding at source before accepting it.
- [ ] **Do not deploy.** This moves the guest ELF and the **vkey**, so the cutover needs a rebuilt guest and a fresh `SP1ZkVerifier`. It does **not** move the production `GENESIS_ROOT` (025-C already did); the **demo** root moves.
- [ ] **Do not enable order ingress on a fresh deployment until an SEC-025-A `FundInsurance` has settled.** This branch makes a zero-insurance production genesis shippable, and the spec's §Genesis gates trading on the capitalization batch: with `insurance_fund` at zero, the first bad debt goes straight to ADL (clawing real users) or — absent winners — parks the debt and trips `Mode::CloseOnly`, from which there is no proven transition back. One early gap could wind the deployment down permanently.
- [ ] **025-A is unblocked by this**, and the two must cut over together: 025-A's deliverable is the gateway path that leaves a note unspent for `FundInsurance` to consume.
