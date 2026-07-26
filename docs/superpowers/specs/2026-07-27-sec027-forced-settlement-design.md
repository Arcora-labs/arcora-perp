# SEC-027 — Forced settlement: a terminating wind-down — Design

> Threat model: `2026-07-26-sec02x-threat-model.md`. Independent of SEC-022…SEC-026.
> Not part of the cutover bundle, but it interacts with it — see "Interaction with SEC-025".

**Finding:** SEC-027 [high, fund loss by liveness] — collateral inside an open position can be trapped permanently, and **the documented wind-down procedure has a termination assumption that does not hold.**

## The trap, verified link by link

`Mode::CloseOnly` is reachable two ways: the bad-debt terminal (`engine.rs:725`) and, on L1, by anyone after the liveness timeout (`DarkPerpSettlement.sol:406-413`). Once there:

- **It is absorbing.** `mode` is written in exactly two places, `engine.rs:305` (`EnterCloseOnly`) and `:725` — both to `CloseOnly`. `Mode::Normal` appears only at genesis (`state.rs:86`). **There is no transition back.**
- **Nobody can take the other side.** A fill is rejected if *either* leg increases exposure (`engine.rs:515-520`). A close is still a fill with two legs, so a user closing a long needs a counterparty who is *also* reducing.
- **Liquidation cannot help a healthy position.** `op_liquidate` requires `is_liquidatable` (`engine.rs:644`), so a solvent position is ineligible.
- **ADL does not reduce exposure.** `auto_deleverage` claws `collateral` and never touches `size` (`engine.rs:764-790`), so unmatched open interest survives the waterfall.
- **`Unbind` cannot release it.** It re-checks initial margin while the position is open (`engine.rs:835`).
- **There is no unilateral force-close** anywhere in `BatchOp`.

So "withdrawals remain permitted in close-only" — true, and stated across the SEC-02x specs — applies **only to existing notes**. Collateral inside an open position has no exit.

## The runbook assumes a loop that need not terminate

`docs/FINAL_SETTLE_RUNBOOK.md` is EXIT-001's wind-down escape. Its premise (`:5-6`):

> users can still submit reduce-only closes off-chain, and those closes need a way to become claimable withdrawals

and its termination condition (`:92`):

> Repeat steps 2–3 for each subsequent wind-down window **until all open positions have been reduced to zero**

Open interest nets to zero globally — every fill created one long and one short — so in principle every position *has* a counterpart. But reducing to zero requires those counterparts to **want to close, simultaneously, at a mutually acceptable price**. One absent or unwilling counterparty strands the other side indefinitely, and the loop never terminates.

**`finalSettle` is the right vehicle and is not the problem.** It lands *any* proof-valid transition (`DarkPerpSettlement.sol:365-404`) — governance cannot fabricate a balance, but it can land whatever the circuit permits. The gap is that `perp-core` has no transition that closes a position without a counterparty. EXIT-001 can land closes that happen; it cannot make them happen.

## Interaction with SEC-025

SEC-025's alpha posture disables the house MM. Previously the MM could absorb one side of a wind-down close; with no house, **every close needs a real user on the other side**, so SEC-027 becomes strictly more likely to bite. The two decisions must be taken together: an alpha with no house liquidity and no forced settlement has no guaranteed exit for open positions.

## Design

**A forced settlement transition: close every open position in a market at the validated oracle price.**

```
BatchOp::SettleMarket { market_id, oracle, now_ms }
```

- **Permitted only in `Mode::CloseOnly`.** In `Normal` it must be rejected — otherwise it is a rug primitive.
- **Price = `oracle.validate(&market, now_ms)`**, the same attested value `op_liquidate` already closes at (`engine.rs:633, 650`). No new price authority, and it inherits every ZK-001 sanity gate.
- **For each open position in the market:** settle funding, realize PnL at the settlement price, zero `size` and `entry_price`, and release the remaining collateral as a fresh note — the same shape `op_unbind` uses to turn collateral into a spendable note, minus the margin re-check that makes `Unbind` unusable here.
- **Deterministic order.** Iterate positions in `BTreeMap` order so the native and guest executions agree, exactly as `auto_deleverage` already does.

### Conservation and the deficit

Closing every position at one price is **zero-sum by construction**: every fill created equal and opposite `size` at the same `entry_price`, so `Σ size = 0` and `Σ size·entry = 0`, hence `Σ realized = P·0 − 0 = 0`. Conservation therefore holds through `vault_pool` the same way `apply_fill` already maintains it.

What is *not* guaranteed is that every position ends non-negative. Positions already carrying parked bad debt (SEC-022's case, and ADL-haircut winners whose collateral was reduced without reducing size) can settle negative.

**The waterfall used by liquidation does not work here.** `auto_deleverage` claws from *open, profitable* positions — and a settlement closes everyone at once, so by the time a deficit is known there are no open winners left to claw. Attempting ADL mid-settlement would make the outcome depend on iteration order, which is exactly the determinism property the design must preserve.

**Instead:** insurance absorbs first, and any residual deficit is socialized as a **pro-rata haircut on the positive settled balances** before they become notes. That is what a real exchange's final settlement does, it is order-independent, and it makes the shortfall explicit rather than parking it on a closed position forever.

Each haircut must be attributable, mirroring `AdlHaircut`, so a socialized loss can be reported to the account rather than vanishing.

### What this deliberately does not do

- **It does not exit `CloseOnly`.** The mode stays absorbing; this design gives the *positions* an exit, not the *system*. Re-opening a halted exchange is a separate decision with its own risk.
- **It does not choose when to fire.** `SettleMarket` is a transition; governance decides to include it in a wind-down window and lands it via `finalSettle`. Automation is explicitly out of scope — the runbook already flags that gateway close-only routing is manual (`FINAL_SETTLE_RUNBOOK.md:96-101`).

## Migration

| Change | Consequence |
|---|---|
| New `BatchOp` variant (**appended**, so no discriminant shifts) | guest ELF changes → **vkey re-pin** |
| No new `State` field if the haircut is computed within the transition | `state_root` and `GENESIS_ROOT` unchanged |

Appending the variant keeps every existing discriminant stable, so old witnesses decode unchanged — the lesson SEC-024 recorded about `postcard` not requiring full input consumption applies: never replace a variant in place.

If it ships with the cutover bundle it rides that vkey re-pin; if it ships later it needs its own.

## Testing

| Case | Expected |
|---|---|
| **The trap regression:** a healthy open position, `CloseOnly`, no counterparty | before: no path to release collateral. After `SettleMarket`: closed, collateral released as a claimable note |
| `SettleMarket` in `Mode::Normal` | **rejected** — it must not be a rug primitive |
| Long and short settled at one price | `Σ realized == 0`; `conservation_holds()` |
| A position carrying parked bad debt | settles negative, absorbed by insurance |
| Insurance insufficient | residual haircut pro-rata across positive balances, **attributable**, and order-independent |
| Positions iterated in a different insertion order | identical resulting state — pins determinism for the guest |
| Every settled account | can `Withdraw` the released note and claim on L1 |
| The runbook's loop | now terminates: after `SettleMarket` there are no open positions left to reduce |
| Every scenario | `conservation_holds()` |

The last two rows are the finding: today the loop can run forever, and the funds behind it are unreachable.
