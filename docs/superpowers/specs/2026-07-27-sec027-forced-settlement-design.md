# SEC-027 — Forced settlement: a terminating wind-down — Design

> Threat model: `2026-07-26-sec02x-threat-model.md`. Independent of SEC-022…SEC-026, but interacts
> with SEC-025 (see below). **This is a rewrite; the first version was reviewed and rejected.**

**Finding:** SEC-027 [high, fund loss by liveness] — collateral inside an open position can be trapped permanently, and **the documented wind-down procedure has a termination assumption that does not hold.**

## The trap, verified link by link

`Mode::CloseOnly` is the bad-debt terminal (`engine.rs:725`) or is set by the unconditional `EnterCloseOnly` op (`:304-306`). Once there:

- **It is absorbing.** `mode` is written in exactly two places, both to `CloseOnly`. `Mode::Normal` appears only at genesis (`state.rs:86`). There is no transition back.
- **Nobody can take the other side.** A fill is rejected if *either* leg increases exposure (`engine.rs:515-520`). A close is still a two-legged fill.
- **Liquidation cannot help a healthy position** — it requires `is_liquidatable` (`:644`).
- **ADL does not reduce exposure** — it claws `collateral`, never `size` (`:764-790`).
- **`Unbind` cannot release it** — it re-checks initial margin while open (`:835`).
- **No unilateral force-close exists** in `BatchOp`.

So "withdrawals remain permitted in close-only" applies **only to existing notes**. Collateral inside an open position has no exit.

## The runbook assumes a loop that need not terminate

`docs/FINAL_SETTLE_RUNBOOK.md` is EXIT-001's wind-down escape. Its premise (`:5-6`) is that "users can still submit reduce-only closes off-chain", and its termination condition (`:92`) is "repeat … **until all open positions have been reduced to zero**".

Reducing to zero requires counterparts who want to close **simultaneously, at a compatible price**. One absent or unwilling counterparty strands the other side and the loop never terminates. `finalSettle` is the right vehicle and is not the problem — it lands any proof-valid transition (`DarkPerpSettlement.sol:365-404`). The gap is that `perp-core` has no transition that closes a position without a counterparty: **EXIT-001 can land closes that happen; it cannot make them happen.**

*(The runbook is separately ABI-stale — it documents six roots and the old selector at `:52-80` while Solidity now requires `depositsRoot` and `newDepositCount`. Fix belongs with SEC-025 025-B.)*

## Correction history — what the first version got wrong

All four verified at source.

1. **"Zero-sum by construction" was false.** The argument assumed all outstanding size is still paired fill legs. **Liquidation breaks the pairing**: it closes one position with `-pos.size` and never touches its counterpart (`engine.rs:673-676`), so after any liquidation `Σsize ≠ 0` and the clearing house holds directional exposure. `vault_pool`'s own doc comment states the precondition I failed to check — *"**with matched long/short fills** at one price, the pool … nets to zero when all positions close"* (`state.rs:47-51`).

   Concretely: A and B open ±0.5 BTC at \$100k. A is liquidated at \$80k, the pool absorbing A's loss; B is still short. Settle at \$70k: B realizes \$15k and `vault_pool` ends at **−\$5k**. Every *account* balance is positive, so a "haircut the negative balances" rule finds no deficit — yet paying B in full authorizes \$5k more than the vault holds. `conservation_holds()` passes throughout, because it counts the negative pool (`state.rs:123-134`).

   VWAP flooring (`position.rs:236-250`), partial closes and flips (`:251-269`), and per-position funding division (`:92-100`, `:203-215`) each break exactness further.

2. **It skipped the debt it was meant to clear.** Iterating open positions misses already-flat negative ones — exactly the state the canonical insolvency test ends in (`lifecycle.rs:662-678`).

3. **The CloseOnly gate was a rug primitive.** `EnterCloseOnly` is unconditional (`engine.rs:304-306`), so a witness can put `EnterCloseOnly` then the settlement op **in one ordinary batch** and land it through `settleBatch` during normal operation — the same proof format and public commitment are accepted by both entry points. Nothing in the proof says "this is a wind-down".

   Relatedly, the claim that CloseOnly is "reachable on L1" was **false**: `triggerCloseOnly()` sets only the Solidity `closeOnly` flag (`DarkPerpSettlement.sol:406-413`) and never touches the proven `State.mode`. They are two unrelated flags.

4. **Per-market was the wrong granularity.** `insurance_fund` and `vault_pool` are **global** (`state.rs:44-52`), so settling market-by-market lets the first market consume global insurance, lets a healthy market mint claimable withdrawals before a later market reveals a pool deficit, and makes who gets haircut depend on market order. Published withdrawal roots are permanently claimable (`CollateralVault.sol:40-46`) and cannot be clawed back.

## Design

### 1. One atomic `SettleAll`, not per-market

A single transition settling **every** open position across **every** market, at one validated oracle price per market. Global, because the pools it must reconcile are global.

### 2. Eligibility bound to L1, not to a mode the witness can set

A preceding `EnterCloseOnly` must **not** authorize settlement. Instead:

- The proof's public inputs gain a **wind-down flag**.
- `settleBatch` **rejects** proofs carrying it; `finalSettle` **requires** it.
- The circuit binds settlement eligibility to that flag.

This makes the authorization L1-enforced rather than witness-declared, which is the property the first version claimed and did not have. It also composes with `finalSettle`'s existing governance + grace-period guards.

### 3. Leave value as collateral; do not mint notes

The first version minted a note per settled position. **Drop that entirely** — leave the non-negative settled amount as collateral on the now-flat position, and let the existing `Unbind → Withdraw` path consume it.

This removes, at a stroke: blinding derivation and distribution for mass-minted notes; SEC-026 historical-uniqueness collision risk across a large batch; note-archive plumbing (`OpOutput` cannot even return minted notes today, `engine.rs:159-168`); and all-or-nothing Merkle tree-capacity failure (`merkle.rs:119-136`).

It also fixes an end-to-end break the first version had: the production withdrawal endpoint checks free **position collateral** and always does `Unbind → Withdraw` (`gateway/src/main.rs:2126-2157`, `:2317-2329`). A minted note would have been invisible to it — the "user can withdraw afterwards" test could not have passed.

### 3a. The wind-down batch grammar — without it, everything above is bypassable

**`apply_batch` accepts an arbitrary op sequence** (`engine.rs:183-203`): it iterates `&[BatchOp]` with no constraint on what may appear. So binding the settlement price — or any settlement rule — constrains only the *settlement op*, not the batch that contains it.

The bypass, which defeats the entire design:

1. Liquidate or trade selected positions using a **gateway-signed** `OracleTranscript` at a chosen price. `op_liquidate` demonstrably uses its transcript price to close and to move `vault_pool` (`engine.rs:656`, `:673`).
2. Collateral, insurance, ADL haircuts and `vault_pool` are now whatever the witness wanted.
3. Run `SettleAll` at the honest, L1-verified price.
4. End flat, satisfying every terminal postcondition.

The honest price is applied to a state the attacker already shaped.

**Therefore a wind-down proof must contain exactly one staged `SettleAll` and no other state-changing op.** Every ordinary price-consuming operation — `Fill`, `AccrueFunding`, `Liquidate`, `Unbind` — must be forbidden in that batch. Later exits are a separate phase (SEC-027a §4).

This is the single most important constraint in this design, and the first version did not have it.

### 4. Terminal postcondition — solvency, not just flatness

The transition must end with **all** of:

- no open position anywhere;
- **no negative position collateral, including already-flat records**;
- no negative `vault_pool`;
- total spendable claims ≤ `external_in − external_out`;
- a defined disposition for residual `vault_pool`, `insurance_fund` and `treasury`.

The fourth is the one that catches the counterexample in correction 1, which every per-account check passes.

### 5. Socialization — one global snapshot, once

Deficit = whatever the terminal postcondition is short by, after insurance. It is covered by a **single global haircut over all remaining claimants**, computed from one atomic snapshot:

- **Cap each take at the claimant's balance** so a haircut can never push anyone negative.
- **No saturating arithmetic** in the pro-rata — saturation distorts shares (the existing ADL uses `saturating_mul`/`saturating_add`, `engine.rs:756-780`, which is acceptable there and is not here).
- Remainder assignment must be deterministic **and** documented as grindable-in-dust, since ADL's earliest-BTreeMap-key rule is (`:781-790`).
- An **explicit failure policy** when insurance plus all eligible balances still cannot cover the deficit.

**Stated honestly: any claimant set is a policy choice, not a derivation.** Haircutting "remaining claimants" excludes users who closed or withdrew earlier, and weights loss by remaining balance rather than by profit — a conservatively margined trader pays more than a leveraged winner with the same PnL. That is a bankruptcy policy and must be written down as one.

### 6. Failure atomicity

`apply_batch` returns at the first failing op with no rollback (`engine.rs:183-203`), and the sequencer logs an op only on success (`sequencer/src/lib.rs:468-486`). A partial `SettleAll` would leave native state mutated with no witness entry — a wedged next proof.

So: **stage the entire transition before its first mutation.** Precompute every resulting position, pool movement, insurance draw and haircut; check all arithmetic without saturation; only then commit.

### 7. Oracle — the unresolved dependency

"Validated oracle price" does **not** mean current price. SEC-023 is unimplemented, so a favourable historical signed transcript can be replayed by pairing it with a matching witness `now_ms` (`oracle.rs:93-97`; `BatchManifest` has no clock, `order.rs:157-166`). Under Phase 1 the gateway holds the publisher key anyway. **This design must not claim validation removes price discretion.**

There is also a contradiction to resolve rather than paper over: if close-only was triggered *because the gateway died*, governance may hold no fresh oracle signature at all — and once SEC-023 lands, replay stops working, so the escape could become unusable exactly when it is needed. **Final settlement needs an explicit emergency price source and timing policy.** Until that is decided, this design is not implementable.

## Scope beyond `perp-core`

The first version's migration table was incomplete. This needs: sequencer op production and attributable haircut receipts; gateway withdrawal handling for flat positions; governance prepared-data export and `finalSettle` submission; the wind-down public input across `DerivedRoots`, `prover::PublicInputs` and both Solidity entry points; SP1 host/prover-service rebuild and vkey re-pin; and the ABI-stale runbook.

Appending the `BatchOp` variant is correct and preserves existing serde indices — but it needs a frozen old-byte fixture and a pinned discriminant, per SEC-024's lesson that `postcard` does not require full input consumption.

## Testing

| Case | Expected |
|---|---|
| **The trap regression:** healthy open position, close-only, no counterparty | collateral released and claimable after `SettleAll` |
| **The liquidation counterexample** (A liquidated, B settled later at a worse price) | detected — terminal claims ≤ `external_in − external_out`; **fails today under a per-account check** |
| Already-flat negative position | included in the deficit, not skipped |
| `EnterCloseOnly` + settle in one batch via `settleBatch` | **rejected** — the wind-down flag is not witness-declarable |
| `finalSettle` without the wind-down flag | rejected |
| Haircut caps at each claimant's balance | nobody pushed negative |
| Two different position iteration orders | identical resulting state |
| Any op failing mid-settlement | **state byte-for-byte unchanged** |
| Settled account | withdraws via the existing `Unbind → Withdraw` path |
| The runbook's loop | terminates |
| Every scenario | `conservation_holds()` **and** the terminal solvency postcondition |

Rows 2 and 4 are the ones the first version would have failed.

## Status

**The price question is resolved** — `2026-07-27-sec027a-settlement-price-design.md` §1 settles at each position's own `entry_price`, needing no oracle at all, so the wind-down terminates unconditionally and cannot have a deficit manufactured for it by an unavailable or manipulated price. An L1-verified feed price remains an optional improvement (§2), not a prerequisite.

**Remaining before implementable:**

- **The batch grammar (§3a)** — a wind-down proof must carry exactly one staged `SettleAll` and nothing else. Without it every other guarantee here is bypassable.
- **Who produces the Phase-2 exits.** SEC-027a §4 splits wind-down into a one-shot `SettleAll` and a price-free exit phase permitting only flat `Unbind`/`Withdraw`. If the gateway is dead, nothing currently specifies how users submit those exits or how governance obtains the private state and witness to prove them. This is the same shape as the runbook's termination assumption: the escape assumes a live actor that may be exactly what failed.
