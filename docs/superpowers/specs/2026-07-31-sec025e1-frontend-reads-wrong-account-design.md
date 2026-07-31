# SEC-025-E1 — the production frontend reads the wrong account

**Status:** design. First of four pieces in the 025-E decomposition
(`docs/superpowers/specs/2026-07-30-sec025e-decomposition.md`).

**Not in the cutover bundle.** 025-E gates whether the alpha is usable and honest, not whether
it settles.

**Do not deploy from this spec.** Merge only.

---

## The gap

This is not a reporting problem. **In a production deployment the browser is disconnected from
the user's real state**, and has been the whole time.

`GET /api/state` serves only the shared demo wallet, and does so deliberately — the LIQ-001
public-feed invariant is stated at `crates/gateway/src/main.rs:4003-4006` and must **not** be
widened. Meanwhile `self.orders` and `self.user`, the fields that endpoint reads, are written
only by `place_order` and the demo `cancel_order`, which are reachable only through `/api/order`
and `/api/cancel` — and **neither route is mounted in production** (`main.rs:6292-6307`).

So a production browser shows:

- a **permanently empty** order list,
- the **demo wallet's** balance,
- the **demo wallet's** positions,
- `pseudo_hash(...)` placeholders where batch roots should be,

while the user's sealed orders execute invisibly against their own `/v1` account.

`RealDarkPerpClient` bootstraps from `/api/state` and streams the legacy `/ws`
(`frontend/src/api/realClient.ts:481-505`, `:602-624`). It **never** calls `GET /v1/orders`,
`GET /v1/positions`, or `/v1/ws`. Its only `/v1` reads are `/v1/enclave/epoch`,
`/v1/accounts/me`, `/v1/accounts/withdrawals`, and the market endpoints.

## Seven routes it calls that 404 in production

| `realClient.ts` | route | effect today |
|---|---|---|
| `:889` `cancelOrder` | `POST /api/cancel` | cancel silently impossible |
| `:888` `closePosition` | `POST /api/close` | close button dead |
| `:758` `deposit` (primary) | `POST /api/deposit` | throws; the `/v1` mirror at `:764` runs only after |
| `:877` withdrawal mirror | `POST /api/withdraw` | caught and warned — benign |
| `:882-883` mode controls | `POST /api/mode` | `void`-swallowed |
| `:885` `simulateAdl` | `POST /api/simulate-adl` | throws |
| `:912` `recover` | `POST /api/recover` | throws |
| `LpVault.tsx:58`,`:66` | `POST /api/lp/*` | LP tab dead |

Only `placeOrder` (`:751-755` → `POST /v1/orders`) and the withdrawal path are correctly on
`/v1`.

## Scope

**Move every authenticated read and write to `/v1`:**

- orders → `GET /v1/orders`
- positions → `GET /v1/positions`
- account → `GET /v1/accounts/me` (already correct)
- the live stream → `/v1/ws`, authenticated, replacing the legacy `/ws` subscription
- cancel → `DELETE /v1/orders/:id`

**Delete or demo-gate the dead call sites.** A route that 404s in production is not a fallback;
it is a silent failure the UI reports as success in three of the seven cases above.

**`mockClient.ts` moves with it.** It fabricates identically (`:370-371`), so mock and gateway
are consistently wrong together — a UI test cannot currently catch this regression class. If the
mock keeps the old shape while the real client moves, the tests pin the wrong contract.

## What this piece deliberately does NOT do

- **It does not widen `/api/state`.** The LIQ-001 invariant is correct: that endpoint is a
  public feed and must not iterate real accounts. The fix is to stop reading account state from
  it, not to make it serve more.
- **It does not fix execution reporting.** `filledSize` and `avgFillPrice` are fabricated at
  `main.rs:3817-3825` and `:3892-3896`, and will still be fabricated after this piece — the
  frontend will simply be reading the *right account's* fabricated values. That is E3.
- **It does not make orders cancellable.** `account_cancel` refuses any order with
  `sealed == true`, which every order becomes within one 700 ms tick, so `DELETE /v1/orders/:id`
  is wired here but remains ineffective for resting orders until **E2**. Wire it anyway: the
  route is correct and E2 makes it work.

Say all three in the code and the PR, because a reviewer seeing `/v1` reads land will otherwise
assume the reporting problem went with them.

## Risks

- **The `/v1/ws` contract differs from the legacy `/ws`.** `/v1/ws` is authenticated and filters
  by owner; the legacy stream is a public broadcast. The frontend's reducer assumes the latter's
  shape. Expect the message-handling path to change, not just the URL.
- **`parseState`'s contract is load-bearing.** `realClient.ts:101` maps the wire fields
  verbatim; changing the source changes what is present, and a missing field currently reads as
  a default rather than an error.
- **`/v1` reads are authenticated per account.** The legacy path needed no key, so anything that
  renders before the user has a key must degrade rather than throw.

## What must be tested

1. A production-posture client shows **the caller's own** orders and positions, not the demo
   wallet's. Must fail before the fix — and the fixture must use an account whose state
   *differs* from the demo wallet's, or it passes for the wrong reason.
2. No production call path targets a route that is unmounted in production. A source-scan
   tripwire over `realClient.ts` is the cheapest durable form, and matches the repo's existing
   idiom for exactly this (`unbacked_funding_has_exactly_the_known_call_sites`).
3. Cancel routes to `DELETE /v1/orders/:id` and surfaces the gateway's refusal rather than
   swallowing it — including the `sealed` refusal E2 will later remove.
4. `mockClient` and the real client agree on the new shape, asserted against one shared
   fixture rather than two hand-written ones.
