# SEC-025-E1 Frontend Reads Its Own Account — Implementation Plan


**Goal:** Make the production browser show the caller's own orders, positions and balance instead of the shared demo wallet's.

**Architecture:** Move every authenticated read from the legacy `/api/state` + `/ws` pair to the authenticated `/v1` surfaces, and delete or demo-gate the call sites that 404 in production. The public feed keeps its LIQ-001 invariant untouched.

**Tech Stack:** TypeScript (the `frontend/` client), no gateway change expected — but see Task 2's decision, which may require one.

## Global Constraints

- **Do NOT widen `/api/state`.** Its LIQ-001 public-feed invariant is stated at `crates/gateway/src/main.rs:4003-4006` and is correct: it must not iterate real accounts. The fix is to stop reading account state from a public feed.
- **This piece does not fix execution reporting.** `filledSize` and `avgFillPrice` are fabricated at `main.rs:3817-3825` and `:3892-3896` and stay fabricated — afterwards the frontend reads the **right account's** fabricated values. That is E3. Say so in the PR; a reviewer seeing `/v1` reads land will otherwise assume the reporting problem went with them.
- **This piece does not make orders cancellable.** `account_cancel` refuses `sealed == true`, which every order becomes within one 700 ms tick, so `DELETE /v1/orders/:id` is wired here but stays ineffective for resting orders until **E2**. Wire it anyway — the route is correct.
- Baselines: `cargo test --workspace` = **593 / 50 suites**, `forge test` = **89**. Both must be **unchanged** unless Task 2's decision requires a gateway change, in which case the gateway count moves and the reason is reported.
- Never deploy. Never push. Commit on the branch only.

## Verified starting facts

Re-derive anything you rely on; these were read at plan time and this workstream has shipped four stale citations.

- `RealDarkPerpClient.bootstrap` fetches `/api/state` (`frontend/src/api/realClient.ts:491`) and the constructor opens the legacy `/ws` (`:484`).
- `/v1/orders` returns a **flat** shape from `Gw::v1_orders_json` (`main.rs:3276-3299`): `orderId`, `marketId`, `side`, `size`, `limitPrice`, `tif`, `reduceOnly`, `orderHash`, `finality`, `filledSize`, `avgFillPrice`, `createdMs`.
- `TrackedOrder` (`frontend/src/domain/types.ts:109-118`) is `{ id, input, receipt, finality, filledSize, avgFillPrice, createdMs }`, and `pOrder` (`realClient.ts:97-103`) maps a **nested** `input` plus a `receipt`.

---

### Task 1: Read orders and positions from `/v1`

**The mismatch you must resolve first.** `/v1/orders` has **no `receipt` field**, and `TrackedOrder.receipt` is required. `/api/state` supplied it; `/v1` does not. Three options — **pick one and record why in the code**:

- **(a) Client-side join.** Keep receipts the client already holds from its own `placeOrder` responses, keyed by `orderHash`, and attach them. Orders placed in another session have no receipt. Frontend-only.
- **(b) Make `receipt` optional** on `TrackedOrder` and render its absence. Frontend-only, and honest — the client genuinely does not have it.
- **(c) Add `receipt` to `v1_orders_json`.** Gateway change; moves the gateway test count and needs its own test.

**(a) or (b) is preferred** because this task is meant to be frontend-only. If you choose (c), say so in your report — it changes this plan's baseline claim.

**Files:**
- Modify: `frontend/src/api/realClient.ts`, `frontend/src/domain/types.ts` (only if (b) or (c))
- Test: the frontend's test suite (locate it; if there is none for this client, say so rather than inventing a harness)

- [ ] **Step 1: Write the failing test**

Assert that a client bootstrapped against a gateway where the caller's account differs from the demo wallet shows **the caller's** orders. **The fixture must make the two differ** — an account whose state matches the demo wallet's passes for the wrong reason, which is the single most common defect shape in this workstream.

- [ ] **Step 2: Run it and confirm it fails** for the right reason: the client is reading `/api/state`, so it returns the demo wallet's list. Report the observed failure, not just "it failed".

- [ ] **Step 3: Add `getOrders()` and `getPositions()`** hitting `GET /v1/orders` and `GET /v1/positions` with the account's `X-Api-Key`, mapping the flat shape above into `TrackedOrder` / `Position` per your chosen receipt decision.

- [ ] **Step 4: Route the bootstrap and refresh through them**, leaving `/api/state` for genuinely public data only (markets, oracle, batches).

- [ ] **Step 5: Run the test and the suites.** `cargo test --workspace` and `forge test` must be unchanged.

- [ ] **Step 6: Commit.**

---

### Task 2: The live stream

**Files:** `frontend/src/api/realClient.ts`

`/v1/ws` is authenticated and filters by owner; the legacy `/ws` is a public broadcast, and the reducer assumes that shape. **Expect the message-handling path to change, not just the URL.** Read `main.rs:5773-5835` for what `/v1/ws` actually sends before writing anything.

- [ ] **Step 1: Write a failing test** that an event for another account does not reach this client's state.
- [ ] **Step 2: Confirm it fails** — today every account's events arrive on the shared feed.
- [ ] **Step 3: Subscribe to `/v1/ws` with auth**, and keep the legacy `/ws` only for public data if anything still needs it. If nothing does, drop it.
- [ ] **Step 4: Handle the pre-key window.** `/v1` reads are authenticated; anything rendering before the user has a key must degrade, not throw.
- [ ] **Step 5: Run the suites. Commit.**

---

### Task 3: Delete the dead call sites, and pin that they stay dead

Seven routes the client calls 404 in production. Three report failure to the user as success.

| `realClient.ts` | route |
|---|---|
| `:889` `cancelOrder` | `POST /api/cancel` → `DELETE /v1/orders/:id` |
| `:888` `closePosition` | `POST /api/close` |
| `:758` `deposit` (primary) | `POST /api/deposit` — the `/v1` mirror at `:764` runs only after |
| `:877` withdrawal mirror | `POST /api/withdraw` |
| `:882-883` mode controls | `POST /api/mode` |
| `:885` `simulateAdl` | `POST /api/simulate-adl` |
| `:912` `recover` | `POST /api/recover` |
| `LpVault.tsx:58`,`:66` | `POST /api/lp/*` |

- [ ] **Step 1: Write the tripwire first.** A source scan over `realClient.ts` asserting no production path targets an unmounted route, with a prose breakdown naming each remaining `/api/*` use and why it is legitimate. This is the repo's established idiom (`unbacked_funding_has_exactly_the_known_call_sites`) — **and note it counts occurrences in its own source, so naming a route inside the new comment inflates the count it describes.** That has failed an edit twice.
- [ ] **Step 2: Confirm it fails** listing the current offenders.
- [ ] **Step 3: Route cancel to `DELETE /v1/orders/:id`** and surface the gateway's refusal rather than swallowing it — including the `sealed` refusal E2 will later remove. A user must see why, even while the answer is unsatisfying.
- [ ] **Step 4: Delete or demo-gate the rest.** A route that 404s is not a fallback.
- [ ] **Step 5: Run the tripwire and the suites. Commit.**

---

### Task 4: Move the mock with it

`frontend/src/api/mockClient.ts` fabricates identically (`:370-371`), so mock and gateway are consistently wrong together and no UI test can catch this class. If the mock keeps the old shape while the real client moves, the tests pin the wrong contract.

- [ ] **Step 1: Write a test asserting both clients satisfy one shared fixture** — not two hand-written ones, which is how they drifted.
- [ ] **Step 2: Confirm it fails.**
- [ ] **Step 3: Move the mock to the new shape.**
- [ ] **Step 4: Run everything. Commit.**

---

## Branch completion

- [ ] Frontend suite green; `cargo test --workspace` **593 / 50** and `forge test` **89**, both unchanged unless Task 1 chose option (c) — in which case say so.
- [ ] Report which receipt option Task 1 chose and why.
- [ ] Report any test you could not make die.
- [ ] Request an independent review of the branch. **Every whole-branch review in this workstream has held the merge for prose claiming more than the code performs** — sweep comments, names and `docs/API.md` before submitting.
- [ ] **Do not deploy.**
- [ ] **E2 is the follow-up that makes cancel work**, and E3 is what makes the numbers real. Neither is done by this branch, and the PR must say so.
