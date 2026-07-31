# SEC-025-E3 — the execution-status model

**Status:** design. Third of four in the 025-E decomposition. **The largest piece in the
workstream**, and a state-model change rather than a reporting one.

**Do not deploy from this spec.** Merge only.

Depends on **E1** (the frontend must read the user's own account before any status is visible)
and **E2** (a status for an order the user cannot cancel is half a feature).

---

## The gap

`Finality` (`crates/perp-core/src/order.rs:209-216`) has exactly three variants —
`Accepted`, `Matched`, `Settled` — and they are a **protocol-finality** axis: how far an order
has progressed through sealing and settlement. They are not, and should not become, an
execution axis.

The matcher already distinguishes six real outcomes (`crates/matcher/src/book.rs:40-53`:
`FilledFull`, `FilledResting`, `FilledCancelled`, `Resting`, `CancelledNoFill`, `Rejected`), and
`SubmitOutcome` carries `fills: Vec<Match>` with per-fill size and price. `SealedBatch` keeps
only hashes (`crates/sequencer/src/lib.rs:146-177`), so the gateway invents the rest:

- `crates/gateway/src/main.rs:3817-3825` — the demo path, **unconditionally at seal**:
  `filled = order.size`, `avg_fill = limit_price`. No consultation of the matcher, the manifest,
  or finality. **An order rejected pre-trade reports `filled = size`.**
- `main.rs:3892-3896` — the `/v1` path. The *transition* is real, but the quantity and price are
  invented: a 10 %-filled resting order reports 100 %; a multi-level sweep reports the limit
  price rather than the volume-weighted execution price; a market order reports
  `avgFillPrice: "0"` because `limit_price == 0`.

`sealed.settlement_rejected` is **never read anywhere in the gateway**.

**Easier than it looks in one respect:** `SealedBatch.ops` (`sequencer/src/lib.rs:176`) already
carries every applied `BatchOp::Fill` with size and price, witness-committed — keyed by
`(taker, maker)` pubkeys rather than order hash. So the fill *data* exists and is already
proven. What is missing is the **order-hash → fill association** and the non-filling statuses.

## Why this is a state-model change

Three facts, each verified, that together mean a new per-order record is unavoidable:

1. **Any successful fill marks the whole order `Matched`**, regardless of remaining size
   (`sequencer/src/lib.rs:411-422`, `:1115-1117`).
2. **The gateway stops observing an order after `SETTLED`** (`main.rs:3884-3886`), while the
   remainder keeps resting in the matcher's book — so the gateway's record and the book diverge
   permanently after the first fill.
3. **`Finality` regresses.** `finality.insert(oh, Finality::Matched)` at `sequencer/src/lib.rs:1116`
   **overwrites `Settled`**, so a `Gtc` order that settles a partial in window W and fills again
   in W+k goes backwards. This is a bug in its own right and this piece must fix or explicitly
   quarantine it.

So: a per-order execution record with its own lifecycle — remaining size, cumulative filled,
cumulative notional — keyed by order hash, fed from `BatchOp::Fill`, surviving across batches and
windows. `Finality` cannot carry it: `Finality` is per-hash idempotent and assumed monotone.

## Nine terminal cases, not five

The decomposition names five. The real set is nine, and **today all nine look identical to the
user**: `ACCEPTED`, `filled 0`, forever — because `accept_order` inserts `Finality::Accepted` at
ingress (`sequencer/src/lib.rs:791-793`) and nothing ever demotes it.

**Recorded in the manifest** (a reason exists; the gateway discards it at `main.rs:3809-3810`
and `:7347`, both `.map(|(h, _)| *h)`):

1. Pre-trade rejection — `InvalidOrder`, `OracleUnavailable`, `ReduceOnlyViolation`,
   `InsufficientMargin` (`sequencer/src/lib.rs:976-991`, `:819-853`). **This is the production
   market-order case**, since the fabricated house-MM counter-order fails margin here.
2. Expiry at submission (`matcher/book.rs:203-206`).
3. Non-positive size / negative limit (`book.rs:207-218`) — filed as `RejectReason::Cancelled`,
   a **misleading** name for a malformed order.
4. Post-only would take (`book.rs:233-244`), including the market-post-only case.
5. FOK unfillable (`book.rs:251-256`).
6. Unknown market (`matcher/lib.rs:107-116`) — filed as `MarketCloseOnly`, which is **wrong**:
   an unknown market is not close-only.
7. The SEC-022 ban (`sequencer/src/lib.rs:1032-1052`) — the only case that terminates an order
   from a **different batch than it was submitted in**.
8. All fills failed (`sequencer/src/lib.rs:1143-1149`).

**Recorded nowhere** — the three silent book removals:

9. Self-trade prevention and expired-maker pop (`book.rs:277-283`), `reap_expired` (`:403`, every
   tick), and liquidation `cancel_owner_orders` (`sequencer/src/lib.rs:1128-1130`).

**A correction the recon got wrong and this spec must not inherit.** It reported that the silent
removals leave no on-chain record, making a challenge unanswerable and slashing an *honest
sequencer* via `slashUnanswered` plus terminal close-only. **False.**
`MatchingEngine::process_stream`'s `_ =>` arm files `Resting` under `ordered`
(`matcher/lib.rs:128-142`), so every order lands in its submission batch's manifest and the
challenge is always answerable. The real harm is the banned-order harm repeated: the order dies
silently, the user challenges, the sequencer answers with the submission batch, and
`answerChallenge` refunds only when `settledAtBlock > openedBlock` — false for a long-settled
batch — so **the user forfeits the bond** (`contracts/src/DarkPerpSettlement.sol:527-531`).

Cases 6 and 3 become user-visible strings under this piece and are both wrong; fix them here,
since this is what exposes them.

## Scope

- A separate **execution status** — `RESTING` / `PARTIALLY_FILLED` / `FILLED` / `CANCELLED` /
  `REJECTED` — with remaining size, cumulative filled, cumulative notional, and the reject reason
  where one exists. `Finality` stays `ACCEPTED → MATCHED → SETTLED`.
- Carry the order-hash → fill association through `SealedBatch` so the gateway stops inventing.
- **Delete both fabrication sites.** Not soften — delete.
- Surface the reason for the SEC-022 ban and the silent removals, which is the actual fix for
  the bond-forfeiture harm: the user challenges because silence gives them no other move.
- Fix `MarketCloseOnly`-for-unknown-market and `Cancelled`-for-malformed.
- Resolve the `Finality` regression at `sequencer/src/lib.rs:1116`, or quarantine it in writing.

## Carry-ins

- **`Gw::batch_orders` is never pruned** (`main.rs:2335` inserts, `:2953` reads) and **is
  serialized into the snapshot** — unbounded growth. This piece touches that map; fix it here.
- **The regression test the decomposition proposes, and nothing pins today:**
  `build_challenge_answer` returns the submission batch's inclusion proof only because
  `batch_orders` is a `BTreeMap` scanned ascending with `ordered` checked before `rejected`. A
  switch to `HashMap`, or a reordered check, silently flips the answer to `answerByRejection` —
  whose bond forfeit is **unconditional** (`DarkPerpSettlement.sol:563`), strictly worse for the
  user than the conditional refund. Add it.

## Hazards

- **`crates/perp-core` is in the guest.** If the execution record or any new reason variant
  lands in `perp-core`, it **moves the vkey and the roots**. Decide deliberately whether the
  record is guest state (proven, expensive) or gateway state (cheap, unproven) — and say which
  the user-visible status is, because "proven" and "shown in the UI" are different guarantees.
- **`mockClient.ts` fabricates identically** (`frontend/src/api/mockClient.ts:370-371`), so UI
  tests cannot catch a regression here until it moves too.
- Multi-batch resting fills are currently unrepresentable; that is the hardest part of the
  record's lifecycle and the reason this is not a field addition.

## What must be tested

1. Each of the nine terminal cases produces its own status and, where one exists, its reason —
   asserted per case, not in aggregate.
2. A partially-filled resting order reports its **real** remaining size and a volume-weighted
   average price, across **more than one batch**. This is the case the current model cannot
   represent at all, so it must fail before the fix for a structural reason, not a numeric one.
3. A pre-trade-rejected order does **not** report `filled = size` — the current demo path's
   unconditional fabrication.
4. The `Finality` regression: an order that settles a partial and fills again does not go
   backwards.
5. The `build_challenge_answer` ordering pin described above.
