# SEC-025-E4 — the depth decision and the honesty sweep

**Status:** design. Last of four in the 025-E decomposition. Two unrelated jobs that belong
together because both are about the system describing itself truthfully.

**Do not deploy from this spec.** Merge only.

Goes **last**, so the honesty sweep describes the system as it ends up rather than as it was
mid-flight.

---

## Part 1 — the depth decision

`book_around` (`crates/gateway/src/main.rs:3969-3994`) computes `step = mid / 5000` and emits a
fixed four-level ladder at multipliers `[0, 2, 8, 16]` with sizes `[0.5, 1, 2, 3] × SIZE_SCALE`,
symmetric around the mid. **It never touches the matcher.** With no house market maker funding
quotes, it advertises liquidity that does not exist and cannot be hit.

It reaches three production surfaces:

| call site | endpoint | consumer |
|---|---|---|
| `main.rs:2889` | `GET /v1/markets/:id/orderbook`, unauthenticated | `realClient.ts:665`, polled every 1.5 s; documented in `docs/API.md:62` and OpenAPI |
| `main.rs:2932` | `/v1/ws` initial frame and every tick | documented at `docs/API.md:331`; **no frontend consumer today** |
| `main.rs:4111` | `GET /api/state` and the legacy `/ws` | `realClient.ts:483`, `:491` → `OrderBook.tsx` |

**Fabricated depth is not an option.** Choose:

- **Publish real aggregate depth** — exposes every distinct resting price level and the summed
  size at each. Against a thin alpha book that approaches per-order disclosure: differencing
  consecutive snapshots recovers a single maker's quote, and combined with the public
  `manifest.ordered` hashes and a receipt's `seq_no` it becomes linkable. It also needs a **new
  public accessor on `matcher`** — `OrderBook`'s `bids`/`asks` are private
  (`crates/matcher/src/book.rs:99-100`), only `best_bid`, `best_ask`, `resting_size(side)` and
  `market_id` are exposed, and `crossable_liquidity` is private. **`matcher` is `no_std` and
  compiled into the zkVM guest**, so this is not a gateway-only edit.
- **Report depth as unavailable** — gateway and frontend only, but it breaks `refreshSelected`'s
  parse contract and `OrderBook`'s bar rendering.

**Recommendation: report it as unavailable for the alpha.** A dark book with no house MM has no
honest depth to publish, and the privacy cost of publishing it falls on exactly the market makers
the alpha needs to attract. Revisit when there is real resting liquidity. `OrderBook.tsx:46-49`
currently tells users their resting orders are "operator-blind in production" — publishing real
depth would contradict the product's own promise, which is a stronger argument than the leak
arithmetic.

## Part 2 — the honesty sweep

Every item verified as still overstating at the time of writing. **Re-verify each before
editing** — some were already fixed by 025-C, and two claims the decomposition made are refuted:

**Refuted, do not "fix":**
- OpenAPI no longer advertises production LP routes — 025-C gated them
  (`main.rs:5739-5763`, `!prod` only, pinned by a test at `:8208-8233`).
- `mm_hedge` is prod-gated to empty (`main.rs:4074-4094`). Only `lp` still leaks
  unconditionally (`:4139-4152`) — that one is real.

**Still overstating:**

| location | claim |
|---|---|
| `docs/API.md:79-80` | "`Ioc`/`Fok` are takers (crossed against the resting market-maker, **guaranteed fill**)" — contradicted six lines later at `:83-89` |
| `docs/API.md:54` | documents `POST /v1/lp/deposit` as a live route |
| `docs/litepaper/arcora-perp-litepaper.md:76` | "A gateway-internal **house market maker** … so takers always have a counterparty; users can stake USDC into the LP pool and hold shares of the market maker's PnL" |
| `docs/litepaper/arcora-perp-litepaper.md:157` | "sealed order in, **house-MM fill**, receipt in milliseconds" |
| `frontend/src/components/LpVault.tsx:17-20` | "deposit USDC to take the other side of every trader, **earn the house edge**" |
| `frontend/src/components/OrderBook.tsx:46-49` | "Depth here is the **internal market-maker seed**" |
| `frontend/src/components/HealthPanel.tsx:136-170` | renders "**The market-maker is flat — no inventory to hedge**" in production — itself false, since there is no market maker at all |
| `docs/FINAL_SETTLE_RUNBOOK.md:155` | "the house MM emits a …" |
| `docs/ECONOMIC_SECURITY.md:149`, `:177`, `:241-242` | Q4/Q5 marked "Done" assuming a house MM |

## The decision this sweep cannot make

Every item above is downstream of one product question this workstream has deliberately not
answered: **fund a real house MM, or go no-house?**

- **Fund it** — the operator becomes a counterparty with real capital and real risk, and needs a
  funding path that does not fabricate value (the problem 025-A solved for insurance).
- **No-house** — remove the injector rather than merely starve it, require genuine market makers,
  and ship E3 so their orders report honest execution.

**DECIDED 2026-07-31 by the operator: no-house.** This is no longer an assumption — Part 2's
sweep and the injector deletion below both proceed on it. Recorded here because the prose
changes are irreversible in practice (the litepaper is a published document) and a future reader
should know the decision was made rather than inferred.

## Carry-in

The **house-MM counter-order injectors** (`main.rs:3721-3744` and `:3767-3796`) are gated by
025-D but not removed. Under the no-house posture they should be **deleted**, not left starved —
a gate is a runtime condition, and the next person to read `tick()` will reasonably assume the
injector is a supported feature. Whichever of E4 and a house-MM decision lands second should do
the deletion.

## What must be tested

1. No production surface emits fabricated depth. A source-scan tripwire over `book_around`'s
   call sites is the durable form, matching the repo's existing idiom
   (`unbacked_funding_has_exactly_the_known_call_sites`) — and note that such a scan counts its
   own source file, so naming the symbol in a new comment inflates the count it describes.
2. `GET /v1/markets/:id/orderbook` and the `/v1/ws` frame agree on the chosen representation, and
   the frontend renders the unavailable case without throwing.
3. The `lp` block is prod-gated like `mm_hedge` already is.
4. **No test is needed for the prose**, and none should be invented. The check is a human reading
   the litepaper and `docs/API.md` against the shipped system — say so in the plan rather than
   fabricating a doc-lint that pins nothing.
