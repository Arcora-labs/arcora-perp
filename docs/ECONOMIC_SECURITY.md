# Economic security

What stops a confidential perp from quietly insolvency-spiraling, and who pays
when a position goes bad? This document answers seven hard liquidity- and
economic-security questions head-on. Each answer states the **mechanism**, points
at the **code** that enforces it, and is blunt about the **limits** — where the
protocol guarantees something and where it does not.

The honest one-line summary: the protocol guarantees that solvent value can always
**exit**, and that protocol-level bad debt is absorbed by a capital stack
(penalty → insurance → auto-deleverage → halt) before it can socialize silently.
It does **not** guarantee that a trader who loses a trade is made whole — that is
not a property a perpetual can have, and any design that claims it is hiding a
subsidy. The line between "recoverable" and "not recoverable" is drawn explicitly
in Q2.

All of the mechanisms below default to **off / zero** (`Market::conservative` sets
both fee ratios to 0; the insurance fund starts empty; liquidations carry no fee
unless configured), so enabling them never disturbs the byte-locked cross-layer
proof vectors — `Market` is not part of the state digest, and liquidations are not
committed to any proof or manifest.

---

## Q1 — How big is the sequencer bond, and is it sized to what it secures?

**Mechanism.** The bond floor scales with live custodied TVL rather than being a
fixed constant. `requiredBond() = vault.balance * BOND_BPS / 10_000` with
`BOND_BPS = 500` (5%); `settleBatch` reverts `UnderBonded` if the posted bond is
below the floor. As deposits grow the value at risk, the floor grows with it; as
users withdraw, it relaxes. — `contracts/src/DarkPerpSettlement.sol`, test
`test_settle_requires_a_bond_scaled_to_tvl` (commit `68dd03e`).

**Why it can't be gamed.** The TVL the floor reads is user collateral held in the
vault; the sequencer cannot lower it (there is no sequencer-controlled withdrawal
path), and the bond itself has **no withdrawal function** — it is only ever
released by a successful slash. So the sequencer cannot post a bond, settle, and
claw the bond back in the same breath. Forced ETH (`selfdestruct`) into the vault
only *raises* the floor, which grieves the sequencer, not the users.

**Limit.** 5% is a policy parameter, not a theorem; it is defensible as covering
the latency cost of a liquidation/ADL cascade on a TVL-sized book, but a venue with
unusually fat tails should raise it. An adversarial review of this mechanism
returned **SOUND** with no exploitable path.

## Q2 — If a user loses money, how do they recover it?

This is the question that forces honesty, so answer it in layers — by *what caused*
the loss, because the protocol's obligation is different for each.

1. **Sequencer fault** (invalid state transition, withheld data, equivocation).
   Recoverable. The fault is provable on L1, the bond is slashed (Q1), and the
   honest state is the one backed by the valid proof. The bond is the user-facing
   insurance against operator misbehavior, which is why it is sized to TVL.
2. **Protocol bad debt** (a position goes underwater faster than it can be
   liquidated, leaving a deficit). Recoverable up to the capital stack: the
   insurance fund absorbs it first, and only a *true* depletion socializes — and
   even then via the deterministic, attributable ADL path, never silently (Q3/Q7).
3. **Counterparty/ADL haircut** (you were a winner clawed to cover someone else's
   deficit). Bounded and attributable: ADL only ever claws *unrealized* profit
   above your own collateral, pro-rata, in a deterministic order, and the system
   goes close-only the moment the stack is exhausted so the haircut can't compound
   in the dark (Q3/Q7).
4. **Your own trading loss** (the market moved against your open position). **Not
   recoverable, by construction.** A perpetual is a zero-sum transfer between longs
   and shorts; "recovering" a trading loss would mean a counterparty or the
   insurance fund subsidizing it, which would make the venue insolvent on a long
   enough timeline. The protocol's guarantee here is narrower and real: your
   *remaining* collateral can always be withdrawn from a settled state via the
   vault, with no sequencer in the release path.

So "recovery" is fully specified — faults and protocol deficits are backstopped by
slashing and insurance; trading P&L is not, and the design says so rather than
implying otherwise.

**Transparency receipt (built).** The one remaining piece — making a socialized
haircut *visible* rather than silent — is now a mechanism, not a TODO. The
auto-deleverage cascade used to claw a winner's collateral and discard who was hit;
it now returns the per-winner attribution (`AdlHaircut { owner, clawed }`), and the
sealed batch publishes an **ADL receipt** for each: a secret-keyed tag
`adl_tag(adl_tag_key(spend_key), market, batch)` paired with the amount clawed. The
clawed account recomputes its own tag to find its haircut and read what it cost; an
observer who knows only the public owner id cannot link it — the same
privacy construction as the liquidation tag (Q6), under a distinct domain so the
two events never collide. So a socialized loss is now recorded and self-detectable
after the fact, while staying unlinkable. — `crates/perp-core/src/engine.rs`
(`State::liquidate`, `auto_deleverage`), `crates/sequencer/src/lib.rs`
(`AdlReceipt`, `adl_tag`); tests `adl_surfaces_the_per_winner_haircut_attribution`
and `auto_deleverage_publishes_an_attributable_receipt`. Critically, this rode in
on a *return value*, not new proven state: `BatchOp::Liquidate` still discards the
attribution, so the zkVM replay path and every byte-locked cross-layer vector are
unchanged.

## Q3 / Q7 — What feeds the insurance fund, and what happens when it's empty?

**Mechanism — the liquidation waterfall.** `op_liquidate` no longer just seizes a
penalty and hopes. When a liquidation leaves a deficit (bad debt), the engine runs
a fixed cascade:

1. take the liquidation penalty out of the position's remaining collateral;
2. draw `min(bad_debt, insurance_fund)` from the **insurance fund** to cover it;
3. if a residual deficit remains, **auto-deleverage** (`auto_deleverage`) it onto
   the winning side — collecting every counterparty whose clawable profit
   (`min(unrealized_pnl, collateral)`) is positive and haircutting them
   floor-pro-rata with a deterministic remainder pass (a `BTreeMap` keyed walk, so
   the prover reproduces the exact same haircut);
4. if *still* negative — the winners have already exited and there is nothing left
   to claw — flip the whole market to `Mode::CloseOnly` (the depletion halt).

— `crates/perp-core/src/engine.rs`, tests in `crates/perp-core/tests/lifecycle.rs`
(`insurance_backstop_absorbs_bad_debt`, `adl_covers_residual_after_insurance`,
`bad_debt_is_clawed_from_the_winners_via_adl`,
`adl_distributes_pro_rata_across_multiple_winners`,
`true_insolvency_trips_close_only_when_winners_have_exited`). Commits `5500cc5`,
`c3f2930`.

**What feeds the fund.** Two real inflows, not a hand-wave: an explicit
capitalization op (`BatchOp::FundInsurance` / `op_fund_insurance`, SEC-024), which
consumes a real, L1-bound note — a transfer inside the shielded pool, never a mint;
`external_in` is untouched because the note's value already entered through the
deposit path's L1 hash-chain binding — and the **insurance cut of every trade**
(Q4): the slice of the taker fee not rebated to the maker flows straight into the
fund. So the backstop grows with volume instead of sitting at the genesis balance.

*(History: the fund used to be capitalized by `BatchOp::SeedInsurance` /
`op_seed_insurance`, which this document once described as a "real inflow". It
never was — it raised `insurance_fund` AND `external_in` with no note consumed and
no L1 binding, fabricating the accounting representation of collateral that never
arrived; that is the SEC-024 finding. The op is retained at ordinal 8 only as an
always-rejected stub, so a legacy encoding fails loudly instead of mis-parsing
under postcard's positional layout.)*

**Conservation.** Every branch of the waterfall is collateral-neutral and is
re-checked against the conservation identity after each op (`apply_batch`
debug-asserts `Σnotes + Σcollateral + insurance + vault_pool == external_in −
external_out`). An adversarial review confirmed the cascade and its conservation;
the fixes from that pass are in commit `8aa3559`.

## Q4 — Why would a market-maker provide liquidity here?

**Mechanism.** A per-market taker fee + maker rebate.
`Market::with_fees(id, taker_bps, maker_bps)` turns them on;
`taker_fee_ratio`/`maker_rebate_ratio` are `RATE_SCALE` fractions. In `op_fill` the
taker is charged the fee on the fill notional **before** the margin check (so a
taker who can't afford fee-plus-margin on an opening fill is rejected), the resting
maker is credited the rebate (the actual incentive to quote), and the remainder
(`taker_fee − maker_rebate`) funds insurance — which is the Q4→Q3 connection above.
— `crates/perp-core/src/{market.rs,engine.rs}`, test
`trading_fees_pay_the_maker_and_fund_insurance` (a 10/4 bps market pays the maker
$40, charges the taker $100, funds insurance $60 on a $100k fill). Commits
`7cb9eea`, `1c1c34a`.

**Coherence bound (review hardening).** `is_coherent` enforces
`0 ≤ maker_rebate ≤ taker_fee < maintenance_margin_ratio`. The upper bound on the
fee — mirroring the existing liquidation-fee bound — closes two issues an
adversarial pass found in a *misconfigured* (incoherent) market: a fee on a
reducing fill skips the initial-margin re-check and could otherwise drain a
still-open position into fee-induced bad debt, and a same-size rebate could
otherwise satisfy a position's *initial* margin from the fee alone (a maker opening
with no real skin in the game). With the fee strictly below the maintenance buffer,
neither is reachable; realistic bps-scale fees are orders of magnitude below it.
Commit `1c1c34a`.

**Limit.** This is the *on-venue* maker incentive (fees/rebates). It does **not**
solve the maker's *inventory* problem — that is Q5.

## Q5 — How is a market-maker protected from inventory/directional risk?

Fees (Q4) pay a maker to quote, but a maker who accumulates a one-sided book still
carries directional risk an on-chain perp cannot neutralize by itself. The split of
responsibility here is the whole answer, and it is deliberate.

**What the protocol owns — the hedging signal (built).** The protocol emits a
deterministic, provable **hedge signal** per market: `Position::hedge_signal(mark)`
returns the maker's net `inventory` (signed base size), the `hedge_target`
(its negation — the offset to take elsewhere for delta-neutrality), and the
`notional` exposure. Any keeper, on any venue, hedges against this number; it is the
"what to hedge", computed from state, not a venue integration. — `crates/perp-core/
src/position.rs` (`HedgeSignal`), test
`hedge_signal_reports_the_offsetting_external_position`; surfaced live in the
gateway snapshot (`mmHedge`) and the Health panel's "Market-maker hedge" card.

**What the protocol deliberately does NOT own — the hedge execution.** The actual
hedge is an **external** delta-neutral keeper reading the signal and placing
offsetting orders on another venue (a CEX or a deep DEX). The protocol never
custodies or routes that hedge — doing so would make it a centralized hedge desk
and import the very counterparty/custody risk the dark perp avoids. So the venue,
the custody of the hedge margin, and the keeper's rebalance/neutrality-proof policy
are the **operator's** choices, not protocol constants. The integration contract is
exactly: read `mmHedge[market].hedge_target`, hold that position externally,
re-read each batch.

**Net.** The maker's protection is the sum of three protocol-owned pieces — the
fee/rebate economics (Q4), the depth-protecting liquidation privacy (Q6), and now
the hedging signal (Q5) — plus their own external keeper, which the venue-agnostic
signal makes a thin, well-defined integration rather than a bespoke build.

## Q6 — Doesn't liquidating in a shallow market leak who's about to get hit?

**Mechanism.** Liquidations are published as **secret-keyed tags**, never as
cleartext owner keys. `SealedBatch` carries `liquidation_tags: Vec<Digest>` where
each tag is derived under a per-owner secret:
`liquidation_tag_key(spend_key) = H(Domain::Liquidation, spend_key)`, then
`liquidation_tag(tag_key, market, batch)`. Only a party holding the position's
spend key can recognize its own liquidation; an observer sees an unlinkable tag,
not an address. — `crates/sequencer/src/lib.rs`, `spine.rs` tests. Commit
`7e9186d`.

**Why secret-keyed and not just hashed.** The first cut keyed the tag on the
*public* owner key, which an adversarial review correctly flagged as a **membership
oracle** — anyone could grind public keys against the tag and confirm who was
liquidated. Keying on the secret spend key (the same trick the nullifier uses)
removes the oracle: the tag is unforgeable and unlinkable without the secret. Fix
in commit `8aa3559`; the regression test asserts a public-key-keyed tag does *not*
match.

**Limit.** This hides *identity*, not the *fact* of a liquidation or its market
impact. A determined observer still sees that *a* liquidation happened and can
watch the price; what they can't do is single out *whose* position it was or build
a hit list of soon-to-be-liquidated addresses.

---

## Scorecard

| # | Question | Status | Where |
|---|----------|--------|-------|
| Q1 | Bond sizing | **Done**, review: sound | `DarkPerpSettlement.sol` (`68dd03e`) |
| Q2 | Loss recovery | **Done** — layered model + ADL transparency receipt | this doc + `engine.rs`/`sequencer` (`4f972cc`) |
| Q3 | Insurance feed | **Done** | `engine.rs` (`5500cc5`) |
| Q4 | MM incentive | **Done** + review hardening | `market.rs`/`engine.rs` (`7cb9eea`,`1c1c34a`) |
| Q5 | MM hedge / inventory | **Done (protocol side)** — hedge signal; external keeper is the operator's | `perp-core/src/position.rs` + gateway/UI |
| Q6 | Liquidation privacy | **Done** + review fix | `sequencer/src/lib.rs` (`7e9186d`,`8aa3559`) |
| Q7 | Bad-debt attribution | **Done** (ADL + halt) | `engine.rs` (`c3f2930`) |

All seven now have their protocol-owned mechanism in code with tests, each through
an adversarial review pass. Q2's layered recovery rests on those mechanisms with the
ADL transparency receipt built; Q5's hedging *signal* is built and the hedge
*execution* is, by design, an external keeper the operator runs against that signal
— not a protocol gap. The only work that remains is intentionally outside the
protocol boundary: the operator's choice of hedge venue and custody.
