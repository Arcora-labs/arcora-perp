# SEC-025-E — decomposition

**Status:** decomposition. 025-E is bigger than the decomposition document describes, and the
extra work is not more of the same shape — it spans the matcher, the sequencer, the gateway and
the frontend. Splitting it the way SEC-025 itself was split.

**Not in the cutover bundle.** 025-E gates whether the alpha is *usable and honest*, not whether
it settles. It is independent of A–D and can proceed in parallel.

---

## What the recon changed

The decomposition framed 025-E as "carry the matcher's real outcomes through `SealedBatch` to
the API". That is one of four problems, and not the largest.

**Refuted outright** — do not re-plan these, 025-C already did them: OpenAPI no longer advertises
production LP routes (`crates/gateway/src/main.rs:5739-5763`, `!prod` only, pinned at
`:8208-8233`), and `mm_hedge` is prod-gated to empty (`:4074-4094`). Only `lp` still leaks
unconditionally (`:4139-4152`).

**Easier than described:** `SealedBatch.ops` already carries every applied `BatchOp::Fill` with
size and price (`crates/sequencer/src/lib.rs:176`), witness-committed. It is keyed by
`(taker, maker)` pubkeys rather than order hash, so what is missing is the **order-hash → fill
association**, not the fill data.

**Harder than described**, and the reason for this split:

- The production frontend **cannot see its own account at all** — see E1.
- A sealed resting order is **uncancellable** — see E2.
- `Finality` **regresses `Settled → Matched`** (`sequencer/src/lib.rs:1116` overwrites
  unconditionally).
- Publishing real depth needs a **new public accessor on `matcher`**, a `no_std` crate compiled
  into the zkVM guest (`OrderBook`'s `bids`/`asks` are private, `book.rs:99-100`).
- There are **nine** terminal cases, not five.

**A recon claim this document rejects.** The recon reported that three silent book removals
(self-trade prevention, expiry reap, liquidation cancel) leave no on-chain record, making a
challenge unanswerable and slashing an **honest sequencer** via `slashUnanswered` plus terminal
close-only. Verified false: `process_stream`'s `_ =>` arm files `Resting` under `ordered`
(`crates/matcher/src/lib.rs:128-142`), so every order lands in its submission batch's manifest
and `build_challenge_answer` can always answer. The real harm is the banned-order harm repeated:
the order dies silently, the user challenges, and **the user forfeits the bond** because
`answerChallenge` refunds only when `settledAtBlock > openedBlock`
(`contracts/src/DarkPerpSettlement.sol:527-531`).

---

## E1 — the production frontend reads the wrong account *(do this first)*

**Not a reporting problem. The prod UI is disconnected from the user's real state.**

`/api/state` serves only the shared demo wallet, deliberately — the LIQ-001 public-feed
invariant is stated at `main.rs:4003-4006` and must not be widened. And `self.orders` is written
only by `place_order` (`:3509`) and the demo `cancel_order` (`:3633`), both reachable only
through `/api/order` and `/api/cancel`, which are **not mounted in production**
(`:6292-6307`).

So a production browser shows a permanently empty order list, the **demo wallet's** balance,
the **demo wallet's** positions, and `pseudo_hash` batch placeholders — while the user's sealed
orders execute invisibly against their `/v1` account.

`RealDarkPerpClient` never calls `GET /v1/orders`, `GET /v1/positions`, or `/v1/ws`
(`frontend/src/api/realClient.ts:481-505`, `:602-624`). It calls seven routes that 404 in
production: `/api/cancel`, `/api/close`, `/api/deposit`, `/api/mode`, `/api/simulate-adl`,
`/api/recover`, `/api/lp/*`.

**Scope:** move every authenticated read to `/v1` (`/v1/orders`, `/v1/positions`,
`/v1/accounts/me`, `/v1/ws`), route cancel to `DELETE /v1/orders/:id`, and delete or
demo-gate the dead call sites. `mockClient.ts` must move with it — it fabricates identically
(`:370-371`), so mock and gateway are consistently wrong together and UI tests cannot catch the
regression.

**Why first:** every later piece is invisible to users until this lands. Shipping an execution
status the frontend never reads is the same mistake in a new place.

---

## E2 — a sealed resting order is uncancellable *(small, and blocks E3's value)*

`account_cancel` (`main.rs:2770`) refuses any order with `sealed == true`, and every order
becomes sealed within one 700 ms tick (`:3829`). With no house MM, **resting is the normal
case**, so `DELETE /v1/orders/:id` is dead exactly where it matters. A user cannot withdraw a
quote.

`MatchingEngine::cancel_order` (`crates/matcher/src/lib.rs:86`) already exists and works; it has
exactly one caller — SEC-022's ban loop.

**Scope:** let a cancel reach the resting book for an order that is sealed but still live, and
give it a manifest entry so the cancellation is provable. Note the ordering hazard: a cancel
racing a fill in the same tick must resolve deterministically, because the sequencer is replayed
in-circuit.

---

## E3 — the execution-status model *(the largest piece; a state-model change)*

`Finality` (`crates/perp-core/src/order.rs:209-216`) is a three-state protocol axis and must
stay one. Execution status is a **separate** axis: `RESTING` / `PARTIALLY_FILLED` / `FILLED` /
`CANCELLED` / `REJECTED`, with remaining size, cumulative filled, cumulative notional, and the
reject reason where one exists.

This is **not a reporting change**. A per-order execution record needs its own lifecycle that
survives across batches and windows, keyed by order hash, fed from `BatchOp::Fill`. Nothing like
it exists:

- Any successful fill marks the **whole** order `Matched` regardless of remaining size
  (`sequencer/src/lib.rs:411-422`, `:1115-1117`).
- The gateway stops observing an order after `SETTLED` (`main.rs:3884-3886`), while the
  remainder keeps resting in the matcher's book — record and book diverge permanently after the
  first fill.
- `finality.insert(oh, Finality::Matched)` at `:1116` **overwrites `Settled`**, so a Gtc order
  that settles a partial and later fills again regresses.

**All nine terminal cases must be representable**, not the five the decomposition names:
pre-trade rejection (four reasons — and this is the production market-order case), expiry at
submission, non-positive size / negative limit, post-only would take, FOK unfillable, unknown
market, the SEC-022 ban (the only case terminating an order from a *different* batch than it was
submitted in), all-fills-failed, and the three silent book removals.

Two reasons become user-visible strings here and are **both wrong**: `MarketCloseOnly` for an
unknown market (`matcher/lib.rs:107-116`) and `Cancelled` for a malformed order
(`book.rs:207-218`). Fix them as part of this, since 025-E is what exposes them.

**Delete the fabrication with it**, both sites: `main.rs:3817-3825` (demo, unconditional at
seal — a pre-trade-rejected order currently reports `filled = size`) and `:3892-3896` (`/v1` —
the transition is real, the quantity and price are invented; a market order reports
`avgFillPrice: "0"` because `limit_price == 0`).

Also here: the banned-order and silent-removal cases get a terminal status and a surfaced
reason, which is the actual fix for the bond-forfeiture harm. The user challenges because the
silence gives them no other move.

---

## E4 — the depth decision and the honesty sweep

`book_around` (`main.rs:3969-3994`) emits a fixed four-level ladder that **never touches the
matcher**. It reaches `GET /v1/markets/:id/orderbook` (production, unauthenticated, polled every
1.5 s by `realClient.ts:665`), the `/v1/ws` frames, and `/api/state` + legacy `/ws`.

**Decide explicitly; fabricated depth is not an option.**

- *Publish real aggregate depth* — exposes every distinct resting price level and summed size
  per market. Against a thin alpha book that approaches per-order disclosure: differencing
  consecutive snapshots recovers a single maker's quote, and `manifest.ordered` plus the
  receipt `seq_no` makes it linkable. Requires a **new public accessor on `matcher`**, which is
  `no_std` and compiled into the zkVM guest — not a gateway-only edit.
- *Report depth as unavailable* — gateway and frontend only, but breaks `refreshSelected`'s
  parse contract and `OrderBook`'s bar rendering.

**Recommendation: report it as unavailable for the alpha.** A dark book with no house MM has no
honest depth to publish, and the privacy cost of publishing it lands on exactly the market
makers the alpha needs to attract. Revisit when there is real resting liquidity.

**The honesty sweep**, all still overstating: `docs/API.md:79-80` ("guaranteed fill",
contradicted six lines later) and `:54` (documents `/v1/lp/deposit` as live); the litepaper's
house-MM model (`docs/litepaper/arcora-perp-litepaper.md:76`, `:157`); `LpVault.tsx:17-20`
("earn the house edge"); `OrderBook.tsx:46-49` ("depth here is the internal market-maker seed");
`HealthPanel.tsx:136-170` — which in production renders "*The market-maker is flat — no
inventory to hedge*", itself false, since there is no market maker at all;
`docs/FINAL_SETTLE_RUNBOOK.md:155`; `docs/ECONOMIC_SECURITY.md:149`, `:177`, `:241-242`.

---

## Sequencing

E1 → E2 → E3 → E4. E1 first because nothing later is visible without it; E2 before E3 because an
execution status for an order the user cannot cancel is half a feature; E4 last because the
depth decision is independent and the honesty sweep should describe the system as it ends up.

## Carry-ins for whichever piece touches them

- **`Gw::batch_orders` is never pruned** (`main.rs:2335` inserts, `:2953` reads) and **is
  serialized into the snapshot** — unbounded growth. Fix in whichever piece touches it.
- **The regression test the decomposition proposes is worth adding** and nothing pins it today:
  `build_challenge_answer` returns the submission batch's inclusion proof only because
  `batch_orders` is a `BTreeMap` scanned ascending with `ordered` checked before `rejected`. A
  switch to `HashMap` or a reordered check silently flips the answer to `answerByRejection`,
  whose bond forfeit is **unconditional** (`DarkPerpSettlement.sol:563`) — strictly worse for
  the user than the conditional refund.
- **The house-MM counter-order injector** (`main.rs:3721-3744`, `:3767-3796`) has **no `prod`
  gate**. Under the no-house posture it should be removed, not merely starved. 025-D gates it;
  whichever lands second should delete it.
