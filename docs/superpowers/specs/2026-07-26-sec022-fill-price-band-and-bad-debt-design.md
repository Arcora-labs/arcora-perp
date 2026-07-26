# SEC-022 — Fill-price band + closed-position debt — Design

> **Sequencing: this is the THIRD of three findings and must not be implemented first.**
> SEC-023 (oracle time-binding) and SEC-024 (`SeedInsurance` fabricates external collateral) both let a
> prover assert arbitrary values inside the proven transition. While either is open, this design's band
> is anchored to something a prover controls, so implementing SEC-022 alone buys far less than it appears
> to. See "Dependencies".

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
- **`crates/perp-core/src/order.rs`**: **append** a `RejectReason::FillPriceOutOfBand` variant.
- **`crates/sequencer`** (host, not in the guest): `settlement_reason` arms for the new errors.

**Non-goals / deferred, each with its own tracking:**

- **SEC-023 — oracle time-binding.** `now_ms` is a private per-op field with no public clock. A prover can replay a historical signed transcript and set `now_ms` near its `publish_time_ms`, passing the 10 s freshness gate (`oracle.rs:93`). `BatchManifest` has no time field (`order.rs:157`), and `derive_roots` (`commitment.rs:53`) does not constrain it. Affects `Fill`, `Liquidate`, `Unbind`, `AccrueFunding`. **Own spec, higher priority than this one.**
- **SEC-024 — `SeedInsurance` fabricates external collateral.** `op_seed_insurance` (`engine.rs:787-800`) raises both `insurance_fund` and `external_in` with no note consumed and no L1 binding, and the guest proves it. Mint fake insurance → create bad debt → cover it → withdraw the winner's excess from the real vault. Must be L1-deposit-bound or removed from the proven op set. **Own spec, higher priority than this one.**
- **Matcher liquidity is consumed before rejection.** The matcher decrements/removes the resting maker (`matcher/book.rs:301`) *before* settlement discovers the fill is out of band, and the rejection arm has no rollback (`sequencer/src/lib.rs:901`). An attacker can burn out-of-band resting liquidity without executing and reject an innocent taker alongside it. The in-circuit band stays the security control; this needs an atomic restore or a host-side pre-filter. **Follow-up.**
- **Funding remains steerable.** Funding uses the book mid (`sequencer/src/lib.rs:682`) and the rate clamps at a 0.05% premium (`funding.rs:23`) while the mark band permits 5% — so the existing band bounds a rate that is already clamped, and two accounts parking non-crossing quotes can choose the funding sign. ≈12% of notional per day. **Follow-up.**
- **`op_fund_position` silently repays parked debt** (`engine.rs:430-451`). It consumes a real note, so it mints nothing — but a new deposit can vanish into old debt while the system stays `CloseOnly`. Make repayment explicit or refuse to fund a debt-parked position. **Follow-up.**
- **A hard global solvency invariant** in `apply_batch`. The per-fill postcondition below is the targeted version; a global one risks converting a recoverable accounting state into an unprovable batch.

## Current state (grounding)

- **`BatchOp::Fill`** (`engine.rs:59-68`) carries `oracle: OracleTranscript` **by value, per op**. Two fills in one batch may carry different transcripts.
- **`oracle.validate`** (`oracle.rs:63-129`) checks the publisher signature first (fail-closed on a zero pubkey), then `price > 0`, staleness, confidence, TWAP deviation. `market.oracle_pubkey` is bound into `markets_digest → state_root` (`state.rs:200-204`). **But freshness is only relative to the op's own `now_ms` — see SEC-023.**
- **The mark is available in-circuit at fill time.** `price`, `mark` and `market` are all in scope in `op_fill`; `k256` is a real no-std dependency of `perp-core` so recoverable-ECDSA runs in the guest. The band needs **no new witness data**.
- **The precedent is one op away.** `op_accrue_funding` (`engine.rs:593-612`, from ZK-001) implements this band shape against the same attested index.
- **The rejected-fill path already exists** (`sequencer/src/lib.rs:899-906`): both legs' hashes go to `settlement_rejected`, the op is not pushed to the op-log, and the orders move to `manifest.rejected` with inclusion records cleared.
- **Margin defaults** (`market.rs:63-64`): `initial_margin_ratio` 10%, `maintenance_margin_ratio` **5%**.
- **Liquidations close at the oracle price** (`engine.rs:633, 653`) — in-band by construction, unaffected.

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

**The band must be strictly tighter than the maintenance margin**, so that no in-band fill can take a maintenance-compliant position below zero. Proposed default: `max_fill_deviation_ratio = RATE_SCALE / 50` (2%), against a 5% maintenance margin, leaving headroom for fees and funding drift.

Two constraints on the field itself:

- `is_coherent()` must enforce **both** `> 0` **and an upper bound relative to `maintenance_margin_ratio`** — a `> 0` check alone would let governance configure an arbitrarily wide band and silently reintroduce this finding.
- Bound into `markets_digest` (`state.rs:200-204`) with its own binding test, in the style of `state.rs:392-406`.

The band alone is not the solvency guarantee — §3 is. The band's job is to keep normal trading inside a sane envelope and make the bankruptcy path rare.

### 3. The solvency postcondition

**A fill must not succeed with unresolved closed-position debt.** After both legs are staged, if either ends with `collateral < 0`, the whole fill fails with `FillWouldBankrupt` — no state is committed.

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
| **Attack regression:** two accounts, off-market cross closing **both** legs | rejected; no state committed; both accounts' collateral unchanged |
| Fill that would leave either leg `collateral < 0`, in-band price | rejected `FillWouldBankrupt` |
| Fill exactly at the band edge | accepted |
| Fill just outside the band, both directions | rejected `FillPriceOutOfBand` |
| `checked_sub` on `i128::MIN`; `checked_mul` overflow either side | rejected, no panic |
| Inflated `price` cannot widen the band | rejected — RHS anchored to `mark` |
| Invalid oracle signature | rejected by `validate()` **before** the band |
| A maintenance-safe position cannot be bankrupted by any in-band fill | property test over the band/maintenance relationship |
| `is_coherent()` rejects a band ≥ maintenance margin | rejected at market construction |
| Late-failure atomicity: force the insurance `checked_add` to overflow | `Err` with **state unchanged** |
| Liquidations unaffected (they close at the oracle price) | every existing liquidation test passes unchanged |
| Every scenario | `conservation_holds()` |

**The first version proposed inverting `lifecycle.rs:600-679`. That was wrong** — that test is `true_insolvency_trips_close_only_when_winners_have_exited`, a *liquidation* insolvency case deliberately constructed with the winner already exited (`lifecycle.rs:601`, `:662`). It does not pin fill-created parked debt, and inverting it would contradict correct liquidation behavior. It must keep passing unchanged. This design needs its **own** fill-specific regression test.
