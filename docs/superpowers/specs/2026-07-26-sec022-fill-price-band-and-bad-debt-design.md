# SEC-022 — Fill-price band + bad-debt accounting — Design

**Finding:** SEC-022 [critical, protocol-soundness] — a fill can execute at **any** price relative to the oracle, and the resulting shortfall is never accounted for. Two accounts crossing at an off-market price move value between them at that price; the losing side's collateral can go negative; and because the position ends at `size == 0`, both liquidation entry points skip it (`engine.rs:644`, `sequencer/src/lib.rs:744` — each requires `pos.is_open()`), so the shortfall is **parked on a closed position forever**. The winning account then withdraws normally. Net: the vault pays out more than was ever deposited.

Three independent gaps compose into this:

1. **No fill-price band.** `op_fill` (`crates/perp-core/src/engine.rs:453-580`) validates only `size > 0 && price > 0` (`:465`). It obtains the attested oracle mark at `:478` and uses it **only** for `check_initial_margin` (`:550`). `price` and `mark` are never compared. The matcher supplies `price` verbatim from the resting maker (`crates/matcher/src/book.rs:295`) and has no access to an oracle at all.
2. **The reducing leg is unchecked.** `check_initial_margin` runs only when `increasing` (`engine.rs:549`); `Position::fits_initial_after` returns `true` immediately for any non-increasing delta (`crates/perp-core/src/position.rs:171-173`). The reducing leg is precisely where PnL is realized (`position.rs:251-265`), so an off-band reducing fill mints realized PnL out of `vault_pool` with nothing checking it. *(Skipping the initial-margin check on a reduce is correct and stays; the defect is that no bankruptcy path exists either.)*
3. **Bad debt from a fill is never handled.** The full waterfall — insurance backstop → ADL cascade → `CloseOnly` halt — exists only inside `op_liquidate` (`engine.rs:679-704`) and is gated on `is_open()`.

**Conservation does not catch any of this.** `conservation_holds()` (`crates/perp-core/src/state.rs:129-134`) is a **bookkeeping** identity, not a solvency one: `apply_fill` moves value between `pos.collateral` and `vault_pool`, both terms of `internal_value()`. A fill priced 50% away from the mark passes it cleanly, and `positions_collateral()` sums signed collateral with no clamp (`state.rs:118-120`), so a negative position is absorbed silently. `crates/perp-core/tests/lifecycle.rs:600-679` currently *pins the parked shortfall as correct behavior*.

**Exploitability without any credential compromise.** This needs no leaked key: one user with two funded accounts drains the vault. It is therefore strictly more fundamental than SEC-021's authorization gap, and it remains open even with perfect authorization. SEC-021's own final review identified it as the residual; this design closes it.

**Relationship to SEC-021 (A/B split).** Two defects were separated during design: **(A)** order placement is bearer-authorized for server-custody accounts (gateway-only fix, no vkey impact), and **(B)** this protocol-soundness hole. (B) is designed and fixed first because it is exploitable without (A), and because it forces a vkey redeploy that (A) can ride. (A) is tracked separately and should ship in the same cutover.

## Scope

- **`crates/perp-core`** (compiles into the SP1 guest — see Migration):
  - `op_fill` gains an oracle-relative price band.
  - `Market` gains `max_fill_deviation_ratio`.
  - `EngineError` gains `FillPriceOutOfBand`.
  - The bad-debt waterfall is extracted from `op_liquidate` into a shared helper and invoked from `op_fill`.
  - A `fill()` public wrapper mirroring `liquidate()`, returning `Vec<AdlHaircut>` for host-side receipt attribution.
- **`crates/sequencer`** (host, not in the guest): a `settlement_reason` arm for the new error; call the `fill()` wrapper so ADL receipts are issued for haircuts a fill caused.
- **Tests** across `perp-core` and `sequencer`, including inverting the test that currently pins the bug.

**Non-goals / deferred:**

- **(A) order-path signing** — separate spec, gateway-only, ships in the same cutover.
- **A matcher-side band.** `matcher` is not a guest dependency and has no oracle plumbing (`crates/matcher/Cargo.toml`). A host-side band is unproven and therefore not a security control here; it could later be added as a UX nicety that rejects doomed orders earlier, but it must never be the only band.
- **A hard solvency invariant** (e.g. `all collateral >= 0`) in `apply_batch`. The existing design deliberately uses the `CloseOnly` halt as the terminal signal; a hard in-circuit invariant would make an unprovable batch — i.e. a wedged chain — out of a recoverable accounting event.
- **Garbage-collecting parked positions.** Once the waterfall runs, a residual negative position still lingers; `op_fund_position` (`engine.rs:430-451`) silently repays it if the owner refunds. Out of scope, worth its own follow-up.
- **`op_seed_insurance` has no authorization** (`engine.rs:787-800`) — any `SeedInsurance` op mints `external_in`. Conservation-safe but unauthenticated. Noticed during this design; tracked separately.

## Current state (grounding)

- **`BatchOp::Fill`** (`engine.rs:59-68`) carries `oracle: OracleTranscript` **by value, per op**. `State` holds no oracle. Two fills in one batch may legally carry different transcripts.
- **The mark is attested and fully gated.** `oracle.validate(&market, now_ms)` (`crates/perp-core/src/oracle.rs:63-129`) checks the publisher signature **first** (fail-closed on a zero pubkey), then `price > 0`, staleness, confidence ratio, and TWAP deviation. `market.oracle_pubkey` is bound into `markets_digest → state_root` (`state.rs:200-204`), so a prover cannot swap the trust anchor.
- **The mark is available in-circuit at fill time.** The guest witness is `(DefaultState, Vec<BatchOp>, BatchManifest)` (`crates/sp1-guest/src/main.rs`) and `k256` is a real no-std dependency of `perp-core` specifically so recoverable-ECDSA runs in the guest. **A fill band needs no new witness data and no new plumbing** — `price`, `mark` and `market` are already in scope in the same function.
- **The precedent to copy is one op away.** `op_accrue_funding` (`engine.rs:593-612`, from ZK-001) already implements exactly this shape of band against the same attested index.
- **The rejected-fill path already exists.** On `Err`, `seal_batch` (`sequencer/src/lib.rs:899-906`) pushes both legs' order hashes into `settlement_rejected`, does **not** push the op into the proven op-log, and moves the orders into `manifest.rejected` (`:930-947`) while clearing their inclusion records (`:980-988`) so a justified rejection is not mistaken for censorship.
- **Liquidations close at the oracle price** (`engine.rs:633, 653`), so they are in-band by construction and unaffected.

## Design

### 1. The band

Inserted into `op_fill` **after** `oracle.validate(...)` (`engine.rs:478`), so no band check is reachable without a valid publisher signature:

```
dev = |price − mark|                                  // checked_sub; i128::MIN fail-closes
dev · RATE_SCALE  ≤  market.max_fill_deviation_ratio · mark
```

Three properties, copied verbatim from `op_accrue_funding` because each was already reasoned through and reviewed in ZK-001:

- **Division-free.** Both sides are products; no rounding, no divide-by-zero.
- **The right-hand side multiplies the *attested* `mark`, never the untrusted `price`.** Anchoring to the input under attack would let a prover widen its own band by inflating `price`. (`engine.rs:609` does the same with `index_price`.)
- **Every arithmetic step is `checked_*`, and every overflow rejects** via a catch-all `_ =>` arm. Nothing wraps; nothing panics in-guest.

The check is symmetric — it bounds fills that are too good *and* too bad for either side, because an off-market fill harms whichever leg is on the wrong side of it.

New `EngineError::FillPriceOutOfBand` (`crates/perp-core/src/error.rs`, beside `MarkOutOfBand`), plus a `settlement_reason` arm (`sequencer/src/lib.rs:256-267`) so a band rejection does not fall into the `InvalidOrder` catch-all. **Reuse an existing `RejectReason`** rather than adding a variant: `RejectReason` is hashed into `BatchManifest` (`order.rs:168-171`), and a new variant changes manifest bytes without buying anything a precise `EngineError` does not already give the operator.

### 2. `Market::max_fill_deviation_ratio`

A dedicated field rather than reusing `max_mark_deviation_ratio`, because the two constrain genuinely different things: the funding band constrains *the sequencer's book mid* against the index and should track it tightly; the fill band constrains *execution price* against the index and must tolerate real movement during the oracle's staleness window. Sharing one ratio would mean loosening the funding band later silently loosens the fill band — exactly the coupling to avoid.

**Default: `RATE_SCALE / 10` (10%)**, twice the funding band's 5%. The band's job is not to prevent all value transfer between consenting accounts — it is to make a *single catastrophic fill* impossible. The loss is already bounded by the loser's collateral, and §3 now catches the overflow; the band reduces per-fill damage from unbounded to ~10% of notional. Too tight a band is its own failure mode: it rejects legitimate trades during fast markets and makes the exchange look broken.

Follows the existing field's conventions exactly: `is_coherent()` rejects `<= 0` (mirroring `market.rs:138`), bound into `markets_digest` (`state.rs:200-204`), with its own binding test in the style of `state.rs:392-406`.

### 3. Bad-debt accounting

**Only one case is missing.** An *open* position with negative collateral already fails its maintenance check and is liquidatable, so the existing waterfall covers it. The gap is exactly `size == 0 && collateral < 0` — a position closed by an ordinary fill, which no liquidation path will ever revisit.

Extract the waterfall from `op_liquidate` (`engine.rs:679-704`) into a shared helper and call it from `op_fill` for any leg that ends in that state. **Extract, do not duplicate** — divergent copies of accounting logic are exactly how this class of bug appears.

The waterfall is unchanged: insurance backstop (`insurance_fund` covers what it can) → ADL cascade on the residual (`auto_deleverage`, capped at each victim's claimable so ADL can never mint fresh bad debt) → if still negative, `mode = CloseOnly`.

**The non-obvious consequence: receipts.** ADL produces `AdlHaircut`s, and haircut victims are owed `AdlReceipt`s (`sequencer/src/lib.rs:1025-1038`). `op_liquidate` returns them via the public `liquidate()` wrapper (`engine.rs:323-336`); `op_fill` returns `Result<()>`. In-circuit this does not matter — haircuts are recomputed deterministically — but the **host** cannot issue receipts for haircuts a fill caused. So `perp-core` gains a `fill()` wrapper mirroring `liquidate()`, and the sequencer calls it at `lib.rs:899` instead of the bare `apply_op`.

*Alternative considered and rejected:* insurance-only from fills, halting to `CloseOnly` if uncovered. It avoids the receipt plumbing but stops the whole exchange over a small residual, and it makes bad debt behave differently depending on which op produced it. Consistency is worth the plumbing.

**Expected frequency: rare and small.** With the band in place, a fill can only push collateral negative if it was already nearly exhausted — a state in which maintenance would normally have liquidated the position first. This path is a backstop, not a hot path. It must exist because today the shortfall is silently parked.

## Migration

This is the expensive part, and the timing is favourable — all of it rides one cutover that was already pending.

| Change | Consequence |
|---|---|
| `op_fill` band, new `EngineError` | Guest ELF changes → **vkey re-pin** → new `SP1ZkVerifier` deploy |
| New `Market` field → `markets_digest` → `state_root` | **`GENESIS_ROOT` moves** → every root KAT re-pins (`commitment.rs:241-246` `KAT_COMMIT7`, `state.rs` root tests) |
| Fresh `Settlement`/`Vault`/`USDC` | Already required by the merged-but-undeployed forge-audit remediation (`a413750`, 3 new constructor params) + the SEC-021 snapshot wipe |

`GATE-1` precedent applies: verify the built guest ELF's vkey **before** deploying the verifier, and deploy a fresh `SP1ZkVerifier` rather than assuming an existing one matches. The SEC-021 cutover items (state wipe, `L1_VAULT` exported before start, gateway+frontend together) all still apply and are additive to this one.

**(A) order-path signing is gateway-only and should ship in the same cutover** — it does not affect the vkey, but shipping the two halves of the same threat separately leaves a window where the cheap half is done and the expensive half is not.

## Testing

The suite must show three things: the attack is closed, the band bites exactly where intended, and nothing that worked before broke.

| Case | Expected |
|---|---|
| **Attack regression:** two accounts, off-market `Gtc` self-cross V→B | fill rejected `FillPriceOutOfBand`; V's collateral unchanged; state root unchanged |
| Fill exactly at the band edge | accepted |
| Fill just outside the band, **both directions** (price above and below mark) | rejected |
| `checked_sub` on `i128::MIN`, `checked_mul` overflow on either side | rejected, no panic |
| Inflated `price` cannot widen the band | rejected — RHS is anchored to the attested `mark` |
| Fill with an invalid oracle signature | rejected by `validate()` **before** the band is reached |
| **Liquidations unaffected** — they close at the oracle price | every existing liquidation test passes unchanged |
| Fill closing a position to `size == 0, collateral < 0`, insurance sufficient | covered from insurance; no ADL |
| …insurance insufficient | ADL cascade runs **and haircut victims receive receipts** |
| …both insufficient | `mode == CloseOnly` |
| **`lifecycle.rs:600-679`** — currently asserts the shortfall "is parked" | **inverted** — it pins today's bug as correct |
| Every scenario above | `conservation_holds()` |

The inverted test is the clearest single piece of evidence the fix landed: it currently encodes the defective behavior as intended.

Band-edge and overflow tests mirror the existing funding-band tests at `engine.rs:1055-1102`.
