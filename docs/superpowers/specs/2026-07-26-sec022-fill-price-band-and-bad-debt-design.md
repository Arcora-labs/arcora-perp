# SEC-022 — Fill-price band + closed-position debt — Design

> **Sequencing — corrected.** An earlier header said this was "third of three" and must wait for
> SEC-023/024. That contradicted the canonical threat model (`2026-07-26-sec02x-threat-model.md`) written
> afterwards, and was backwards: the prover cannot alter a sealed witness, so SEC-023/024 are Phase-1
> defence-in-depth, while **this is the only one of the four an ordinary user can reach.** Neither is a
> prerequisite for the solvency postcondition. All four still ship in one cutover because each changes the
> guest ELF, the genesis root, or a persisted format — but on priority, this one leads.

**Finding:** SEC-022 [critical, protocol-soundness] — a fill can execute at **any** price relative to the oracle, and a fill that leaves a position closed with negative collateral is never resolved. Two accounts crossing off-market move value between them at that price; the losing side's collateral goes negative; the position ends at `size == 0`, so no liquidation path will ever revisit it (`engine.rs:644`, `sequencer/src/lib.rs:744` — each requires `pos.is_open()`). The winning account withdraws normally. The vault pays out more than was deposited.

Three gaps compose:

1. **No fill-price band.** `op_fill` (`crates/perp-core/src/engine.rs:453-580`) validates only `size > 0 && price > 0` (`:465`). It obtains the attested mark at `:478` and uses it **only** for `check_initial_margin` (`:550`). `price` and `mark` are never compared. The matcher supplies `price` verbatim from the resting maker (`crates/matcher/src/book.rs:295`) and has no oracle access at all.
2. **The reducing leg has no risk check of any kind.** `check_initial_margin` runs only when `increasing` (`:549`); `fits_initial_after` returns `true` immediately for non-increasing deltas (`crates/perp-core/src/position.rs:171-173`). That leg is where PnL is realized (`position.rs:251-265`). Skipping *initial margin* on a reduce is correct and stays — the defect is that no bankruptcy check exists either.
3. **Closed-position debt is unresolvable after the fact.** The bad-debt waterfall lives only in `op_liquidate` (`engine.rs:679-704`) and is gated on `is_open()`.

**Conservation does not catch this.** `conservation_holds()` (`state.rs:129-134`) is a **bookkeeping** identity, not a solvency one: `apply_fill` moves value between `pos.collateral` and `vault_pool`, both terms of `internal_value()`, and `positions_collateral()` sums signed collateral with no clamp (`state.rs:118-120`). A fill priced 50% from the mark passes it cleanly.

**No credential compromise is needed** — one user with two funded accounts is sufficient. This is strictly more fundamental than SEC-021's authorization gap and remains open under perfect authorization.

**Severity confirmed: critical.** Of the four SEC-02x findings this is the only one an ordinary user can reach, through the ordinary order API, with no operator involvement — see `2026-07-26-sec02x-threat-model.md`. One scope correction to the band's rationale below: anchoring the band's right-hand side to the attested `mark` prevents a *prover* widening its own band, but the **operator** signs the oracle, so against a compromised gateway the anchor constrains nothing. That is ZK-001's documented Phase-1 posture, not a defect of this design — but this spec must not be read as making the fill price trustworthy against the operator.

## Correction history

The first version of this design proposed **running the existing liquidation waterfall from `op_fill`**. Adversarial review (Codex) showed that does not close the attack, and the claim was verified at source:

- **ADL cannot see a closed winner.** `auto_deleverage` skips `!pos.is_open()` (`engine.rs:736`). The natural shape of the attack closes *both* legs, so the profitable leg has `size == 0` and is invisible to the claw.
- **`CloseOnly` is not a vault halt.** It only blocks exposure-increasing fills (`engine.rs:491`). `op_withdraw` (`engine.rs:854`) never checks `mode` — it consumes the note and credits `external_out`. So the terminal state the waterfall falls back to does not stop the winner withdrawing.

Net: insurance is drained, ADL finds nothing to claw, the system halts to `CloseOnly`, and the attacker withdraws anyway. The waterfall was a no-op against the actual attack.

The argument the first version gave *against* a hard fill-level solvency check was also wrong. Rejecting a fill does not wedge the chain: `seal_batch` already omits rejected fills from the proven op-log (`sequencer/src/lib.rs:888-906`) and routes the orders to `manifest.rejected`. Rejection is the cheap, fail-closed option, and it was available all along.

## Scope

- **`crates/perp-core`** (compiles into the SP1 guest):
  - `op_fill` gains an oracle-relative price band.
  - `op_fill` gains a **solvency postcondition**: the fill fails if either leg ends with `collateral < 0`.
  - `Market` gains `max_fill_deviation_ratio`.
  - `EngineError` gains `FillPriceOutOfBand` and `FillWouldBankrupt`.
  - `op_fill` is restructured so **no fallible operation follows its first mutation** (see §4).
- **`crates/perp-core/src/order.rs`**: **append** `RejectReason::FillPriceOutOfBand` and `RejectReason::FillWouldBankrupt`.
- **`crates/sequencer`** (host, not in the guest): explicit `settlement_reason` arms for both new errors — without them `FillWouldBankrupt` lands in the `InvalidOrder` catch-all (`sequencer/src/lib.rs:255`), which is actively misleading; **and match-time validation + rollback (§6)**.

**Non-goals / deferred, each with its own tracking:**

- **SEC-023 — oracle time-binding.** `now_ms` is a private per-op field with no public clock. A prover can replay a historical signed transcript and set `now_ms` near its `publish_time_ms`, passing the 10 s freshness gate (`oracle.rs:93`). `BatchManifest` has no time field (`order.rs:157`), and `derive_roots` (`commitment.rs:53`) does not constrain it. Affects `Fill`, `Liquidate`, `Unbind`, `AccrueFunding`. **Own spec, higher priority than this one.**
- **SEC-024 — `SeedInsurance` fabricates external collateral.** `op_seed_insurance` (`engine.rs:787-800`) raises both `insurance_fund` and `external_in` with no note consumed and no L1 binding, and the guest proves it. Mint fake insurance → create bad debt → cover it → withdraw the winner's excess from the real vault. Must be L1-deposit-bound or removed from the proven op set. **Own spec, higher priority than this one.**
- **Funding remains steerable.** Funding uses the book mid (`sequencer/src/lib.rs:682`) and the rate clamps at a 0.05% hourly premium (`funding.rs:23`) while the mark band permits 5% — so the existing band bounds a rate that is already clamped, and two accounts parking non-crossing quotes can choose the funding sign. ≈1.2% of notional per day. *(An earlier draft said ≈12%; that was off by 10×.)* **Follow-up.**
- **`op_fund_position` silently repays parked debt** (`engine.rs:430-451`). It consumes a real note, so it mints nothing — but a new deposit can vanish into old debt while the system stays `CloseOnly`. Make repayment explicit or refuse to fund a debt-parked position. **Follow-up.**
- **A hard global solvency invariant** in `apply_batch`. The per-fill postcondition below is the targeted version; a global one risks converting a recoverable accounting state into an unprovable batch.

## Current state (grounding)

- **`BatchOp::Fill`** (`engine.rs:59-68`) carries `oracle: OracleTranscript` **by value, per op**. Two fills in one batch may carry different transcripts.
- **`oracle.validate`** (`oracle.rs:63-129`) checks the publisher signature first (fail-closed on a zero pubkey), then `price > 0`, staleness, confidence, TWAP deviation. `market.oracle_pubkey` is bound into `markets_digest → state_root` (`state.rs:200-204`). **But freshness is only relative to the op's own `now_ms` — see SEC-023.**
- **The mark is available in-circuit at fill time.** `price`, `mark` and `market` are all in scope in `op_fill`; `k256` is a real no-std dependency of `perp-core` so recoverable-ECDSA runs in the guest. The band needs **no new witness data**.
- **The precedent is one op away.** `op_accrue_funding` (`engine.rs:593-612`, from ZK-001) implements this band shape against the same attested index.
- **The rejected-fill path already exists** (`sequencer/src/lib.rs:899-906`): both legs' hashes go to `settlement_rejected`, the op is not pushed to the op-log, and the orders move to `manifest.rejected` with inclusion records cleared.
- **Margin defaults** (`market.rs:63-64`): `initial_margin_ratio` 10%, `maintenance_margin_ratio` **5%**.
- **Liquidations do not go through `op_fill` at all.** `BatchOp::Fill` and `BatchOp::Liquidate` dispatch separately (`engine.rs:263`, `:288`); `op_liquidate` calls `Position::apply_fill` directly at the oracle price (`:650`). So neither the band nor the postcondition can block a liquidation. *(An earlier draft said liquidations were "in-band by construction" — the outcome is right, the reasoning was wrong: no band check is invoked.)* Note also that `op_liquidate` has its own partial-mutation ordering (`:651`, `:663` mutate before fallible arithmetic); out of scope here, but this spec should not be read as implying liquidation is atomic.

## Design

### 1. The band

Inserted into `op_fill` **after** `oracle.validate(...)`, so no band check is reachable without a valid publisher signature:

```
dev = |price − mark|                                  // checked_sub; i128::MIN fail-closes
dev · RATE_SCALE  ≤  market.max_fill_deviation_ratio · mark
```

Copied verbatim from `op_accrue_funding` because each property was already reasoned through in ZK-001:

- **Division-free** — both sides are products.
- **The RHS multiplies the attested `mark`, never the untrusted `price`.** Anchoring to the value under attack would let a prover widen its own band.
- **Every step is `checked_*`; every overflow rejects** via a catch-all `_ =>`. Nothing wraps, nothing panics in-guest.

Symmetric: an off-market fill harms whichever leg is on the wrong side, so both directions are bounded.

### 2. Band calibration

**The first version proposed 10% and justified it with "the loss is bounded by the loser's collateral". That is false**, and the correction drives this section. With `maintenance_margin_ratio` at 5% (`market.rs:64`), a position sitting just above maintenance can be closed 10% through the mark and finish roughly 5% of notional **negative**, before fees — because the reducing leg has no risk check at all. A 10% band therefore permits deterministic bankruptcy of maintenance-safe positions.

**The band must be tight enough that no in-band fill can take a maintenance-compliant position below its maintenance requirement.** "Strictly tighter than the maintenance margin" — an earlier draft's rule — is **not sufficient**, because the taker fee is charged on top of the deviation.

The worst pure reduction is a taker closing at the far edge of the band, which consumes `d + f·(1 + d)` of the maintenance buffer. So the sufficient joint condition is:

```
d · RATE_SCALE  +  f · (RATE_SCALE + d)   <   maintenance_margin_ratio · RATE_SCALE
```

where `d = max_fill_deviation_ratio` and `f = taker_fee_ratio`.

**Proposed default `d = RATE_SCALE / 50` (2%)** against the live schedule — 5% maintenance (`market.rs:60`), 10 bp taker (`gateway/main.rs:296`): `2% + 0.1%·1.02 = 2.102% < 5%`. Sound with a wide margin.

Enforcing `d < maintenance` and the existing `liquidation_fee_ratio < maintenance` (`market.rs:114`) **separately** is the trap: `d = 2%` and `f = 4.9999%` each pass individually while together consuming ~7.10%. The postcondition would then reject rather than bankrupt — safe, but the guarantee "a maintenance-compliant position can always close in-band" would be false, which is exactly the property users rely on.

Two constraints on the field:

- **`is_coherent()` enforces the joint inequality above**, not a standalone bound. It is the right place because `add_market` hard-asserts coherence (`state.rs:104-107`), making it a genuine configuration boundary.
- Bound into `markets_digest` (`state.rs:200-204`) with its own binding test, in the style of `state.rs:392-406`.

No additive allowance for funding is needed: maintenance equity already subtracts funding owed, and `apply_fill` settles that same amount.

The band alone is not the solvency guarantee — §3 is. The band's job is to keep normal trading inside a sane envelope and make the bankruptcy path rare.

### 3. The solvency postcondition

**A fill must not succeed with unresolved closed-position debt.** After both legs are staged, the fill fails with `FillWouldBankrupt` — committing nothing — if either leg violates its rule:

| Staged leg ends | Rule |
|---|---|
| **closed** (`size == 0`) | `collateral >= 0` |
| **still open** | maintenance-compliant |

**The rule is conditional, and that is load-bearing.** A flat `collateral >= 0` on every leg — which an earlier draft proposed — creates a denial of service, because `apply_fill` settles the position's **entire** accrued funding (`position.rs:205-217`, `settle_funding`) while realizing PnL only on the **closed fragment** (`:251-258`, `closed = min(|delta|, |size|)`).

Concretely, at the live 10 bp taker fee: long 1 BTC from $90k, mark $100k, collateral $1k, unrealized PnL $10k, funding owed $5k. Equity is $6k, so the position is maintenance-safe against a $5k requirement. Closing the whole position ends at `1 − 5 + 10 − 0.1 = $5.9k` — accepted. Closing 0.1 BTC ends at `1 − 5 + 1 − 0.01 = −$3.01k` — rejected under a flat rule. An attacker posting ten 0.1 BTC resting orders makes every fragment fail, each one re-settling the full $5k funding bill against unchanged state, so **a solvent aggregate close becomes impossible while the victim stays non-liquidatable.** Reducing orders pass `pre_trade_check` unconditionally (`position.rs:171-173`), so nothing upstream catches it.

Requiring maintenance-compliance on a still-open leg — rather than mere non-negativity — sidesteps this entirely: a partial close of a healthy position leaves it healthy, and the funding settled is the same funding maintenance equity already accounts for.

This replaces the first version's "run the waterfall from `op_fill`", which the correction history above shows does not work.

Why rejection is right here and the waterfall is right in `op_liquidate`:

- **Liquidation** is the protocol *choosing* to close a position that is already underwater. There is no alternative to socializing whatever the collateral cannot cover, so insurance → ADL → halt is the correct policy.
- **A fill** is two parties electing to trade. If the trade would bankrupt one of them, not trading is always available and strictly better for the protocol. The position stays open, stays maintenance-checked, and gets liquidated by the normal path if it deteriorates — where the waterfall *can* reach an open winner.

Rejection cannot wedge the chain: `seal_batch` omits rejected fills from the proven op-log and routes the orders to `manifest.rejected`.

**The waterfall is not touched by this design.** It stays in `op_liquidate`, its correct home.

### 4. Atomic failure

`op_fill` currently commits `vault_pool` and positions (`engine.rs:554-566`) **before** the fallible `treasury` and `insurance_fund` additions (`:567-578`). A late `checked_add` failure returns `Err` while state has already changed — the sequencer then takes the rejection arm and omits the op, leaving live host state diverged from what was proven.

The postcondition in §3 adds another late failure point, so this must be fixed as part of this work: **`op_fill` must perform no fallible operation after its first mutation.** Compute everything into staged values, run the band and the solvency postcondition against the staged result, and only then commit.

This is a real pre-existing defect surfaced by review, not new risk introduced here.

### 5. Reject reasons

**Append** `RejectReason::FillPriceOutOfBand` rather than reusing `InvalidOrder`. The first version proposed reuse to avoid changing manifest bytes; that reasoning was wrong on both halves — `RejectReason` has explicit stable discriminants (`order.rs:127-148`), so appending does not change any existing encoding, and `EngineError` is internal while the manifest is what users and auditors see. Hiding a band rejection inside a generic `InvalidOrder` costs debuggability for nothing.

### 6. Match-time validation and rollback — no longer deferrable

The matcher decrements or removes the resting maker (`matcher/book.rs:295-301`) **before** settlement discovers the fill is invalid, and the rejection arm records both order hashes without restoring the book (`sequencer/src/lib.rs:888-906`). An earlier draft deferred this. It cannot be deferred any more, because this design **materially increases settlement-time rejections** — every out-of-band fill and every bankrupting fill now rejects, including the fragmentation case above. Deferring it means an attacker can burn resting liquidity without ever executing.

A band in `pre_trade_check` alone is **not** a substitute, for three reasons: the execution price comes from the resting maker, not the incoming taker's limit; a `Gtc` maker admitted in-band drifts out of band as the oracle moves; and rejecting broad taker limits would discard orders whose actual fills would have been valid.

What is needed is host-side validation **at match time against the current oracle**, plus either transactional rollback with rematching or a settlement dry-run before the book is mutated. Solvency failures need the same protection as band failures.

**A second, related defect:** settlement assigns the *same* reason to both orders (`sequencer/src/lib.rs:901`). When the resting maker supplied the out-of-band price, rejecting the innocent taker instead of cancelling the maker and rematching is the larger unfairness. The engine error should identify **which staged leg failed**, so the host can act on the right one.

## Dependencies

Implement **after** SEC-023 and SEC-024. Both let a prover assert values the band depends on:

- Without SEC-023, `mark` is "a signed price" but not "a current price" — a prover can select a favourable historical transcript per fill, so the band's anchor is partly under the attacker's control.
- Without SEC-024, an attacker can mint the insurance that would otherwise absorb whatever the band lets through.

SEC-022 is still worth doing — it closes the unbounded-price hole and the closed-debt hole — but its guarantee is only as good as the anchor, and the anchor is SEC-023's job.

## Migration

| Change | Consequence |
|---|---|
| `op_fill` band + postcondition, new `EngineError` variants | Guest ELF changes → **vkey re-pin** → new `SP1ZkVerifier` deploy |
| New `Market` field → `markets_digest` → `state_root` | **`GENESIS_ROOT` moves**; relational market-binding tests in `state.rs` update |
| New `Market` field → **postcard encoding of `DefaultState`** | Witness plaintext, **sealed-witness ciphertext/nonce**, gateway snapshots, sequencer snapshots, `window_start_state`, and rollback journals all change shape. **Any pending witness or journal must be drained or explicitly invalidated before cutover** — this is the item the first version missed entirely. |
| `RejectReason` append | New discriminant only; existing encodings unchanged |
| Fresh `Settlement`/`Vault`/`USDC` | Already required by the merged-but-undeployed forge-audit remediation (`a413750`) + the SEC-021 snapshot wipe |

**Correction:** the first version claimed `KAT_COMMIT7` moves. It does not — it hashes fixed roots `[0x01;32]…[0x07;32]` independent of `Market` (`commitment.rs:236-246`), and the Solidity cross-layer KAT is likewise unaffected.

`GATE-1` precedent applies: verify the built guest ELF's vkey **before** deploying the verifier. All SEC-021 cutover items remain and are additive.

**The gateway-only order-signing half (SEC-021 "A") must be a hard release dependency, not a suggestion.** Bearer-authorized orders let an attacker deliberately walk a victim through every adverse edge this design still permits.

## Testing

| Case | Expected |
|---|---|
| **Attack regression:** two accounts, off-market cross closing **both** legs | rejected; **whole state and state root unchanged** (not just the two collateral fields) |
| **Fragmentation regression:** maintenance-safe position with funding owed > raw collateral, closed in small fragments | **each fragment accepted** — pins that the conditional rule, not a flat `collateral >= 0`, is implemented. Repeat at both core and sequencer level |
| Fill leaving a **closed** leg at `collateral < 0` | rejected `FillWouldBankrupt` |
| Fill leaving a **still-open** leg below maintenance | rejected `FillWouldBankrupt` |
| Fill exactly at the band edge | accepted |
| Fill just outside the band, both directions | rejected `FillPriceOutOfBand` |
| `checked_mul` overflow on either side of the band | rejected, no panic |
| Inflated `price` cannot widen the band | rejected — RHS anchored to `mark` |
| Invalid oracle signature | rejected by `validate()` **before** the band |
| **Every pure reduction satisfying the joint band/fee inequality returns `Ok`**, and leaves the position maintenance-compliant or cleanly closed | property test — *rejection must not count as success* |
| `is_coherent()` rejects params violating the **joint** inequality (e.g. `d = 2%`, `f = 4.9999%`) | rejected at market construction |
| Late-failure atomicity: force overflow on the **vault**, **treasury** and **insurance** paths | `Err` with **state unchanged**, each path |
| Liquidations (separate dispatch, not via `op_fill`) | every existing liquidation test passes unchanged |
| Host: an out-of-band or bankrupting match does not permanently consume resting liquidity | book restored or never mutated (§6) |
| Every scenario | `conservation_holds()` |

Two corrections to an earlier draft's table. "A maintenance-safe position cannot be bankrupted" was **vacuous** as written — rejection satisfied it trivially; the property must require that valid reductions *succeed*. And the `i128::MIN` subtraction case is **unreachable through `op_fill`**, since both `price` and the validated `mark` are positive (`engine.rs:465`, `oracle.rs:90`); keep it only as a helper-level arithmetic test.

**The first version proposed inverting `lifecycle.rs:600-679`. That was wrong** — that test is `true_insolvency_trips_close_only_when_winners_have_exited`, a *liquidation* insolvency case deliberately constructed with the winner already exited (`lifecycle.rs:601`, `:662`). It does not pin fill-created parked debt, and inverting it would contradict correct liquidation behavior. It must keep passing unchanged. This design needs its **own** fill-specific regression test.
