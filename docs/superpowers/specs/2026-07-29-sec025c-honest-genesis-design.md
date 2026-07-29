# SEC-025 025-C — Honest genesis — Design

> Decomposition: `2026-07-26-sec025-decomposition.md`. Threat model: `2026-07-26-sec02x-threat-model.md`
> (canonical). Depends on **025-B** (`a2a2f56`, merged 2026-07-29), which closed four settle-path
> breaks and left this one standing.

**Finding:** the gateway cannot settle against a real vault, because its genesis fabricates deposits the L1 chain will never match. The decomposition framed 025-C as *honesty and alpha posture*; 025-B's whole-branch review established it is also **the hard prerequisite for settling at all**.

## Verified at source

| Claim | Evidence |
|---|---|
| **Boot emits seven unbacked deposits.** Pass 2 funds MM + user for each of 3 markets, then an extra market-0 grant for the LP demo | `crates/gateway/src/main.rs:1553-1578` (`fund` → `fund_amount_unbacked`), `MARKETS.len() == 3` |
| Each fabricates a `Deposit` with **sentinel** L1 fields (`from=[0;20]`, `deposit_blind=[0;32]`, `deposit_id` = the live count) | `main.rs:4059-4075`; the fn's own doc says these "fold a `consumed_deposit_tip` the on-chain vault chain will NOT match" |
| `op_deposit` folds every leaf into the tip and increments the count | `crates/perp-core/src/engine.rs:385-389` |
| Boot also applies `SeedInsurance` | `main.rs:1580-1584` |
| **`_requireDepositPrefix` runs before proof verification** and compares the submitted `depositsRoot` against `depositTipAt(newDepositCount)` | `contracts/src/DarkPerpSettlement.sol:301-307`, called at `:334` — *before* `verifier.verify` at `:337` |
| So a fresh vault (`depositCount == 0`) returns `bytes32(0)` for `depositTipAt(7)` and the settle **reverts** | mapping default; same on `finalSettle` (`:385`) and identically under `PROVER_URL=mock` |

**The fix is derivable, not assumed.** `State::new` sets `consumed_deposit_tip = [0u8; 32]` and `consumed_deposit_count = 0` (`crates/perp-core/src/state.rs:89-90`), pinned by a test at `:349`. The vault states explicitly that **"`depositTipAt[0]` is never written: the mapping default `bytes32(0)` IS the genesis tip"** (`CollateralVault.sol:59-62`). A markets-only genesis therefore produces exactly the pair a fresh vault expects, and the prefix pin passes.

### Cleaning genesis alone is not enough

`fund_amount_unbacked` has **three runtime call sites** besides boot. Each re-corrupts the tip *after* a clean genesis:

| Site | What it is | Guarded today? |
|---|---|---|
| `main.rs:2386` | self-service deposit | **Yes, at the call site** — `if self.prod { return Err(…) }` (audit DP-001) |
| `main.rs:3060` | LP `pool_transfer` credit | **No.** And `/v1/lp`, `/v1/lp/deposit`, `/v1/lp/withdraw` are mounted at `main.rs:6107-6109`, **outside** the `if !prod` block (which starts at `:6071` and covers only the legacy `/api/*` routes) |
| `main.rs:3419` | legacy `Gw::deposit` (demo) | **Route-mounting only** — the method itself has no guard |

**`/v1/lp/*` in production is a live corruption path**, not a hypothetical one: a single LP transfer after a clean genesis advances the tip off the vault chain and settling breaks again.

That is why the decomposition says *"enforced at the call sites"*. **Route-mounting is not enforcement** — it is a property of one caller, invisible to the next one added, and one of the three sites is not even route-gated.

## Design

### 1. The invariant

**In production, `consumed_deposit_tip` and `consumed_deposit_count` advance only via a real L1 deposit** — `fund_amount` as called by `account_confirm_deposit`, with the payer's real `from`, the deposit's L1 `id`, and the authorized `deposit_blind`. Every other writer is unreachable in production.

One property, checkable by enumeration rather than by imagining an attack. That is the method that made SEC-024 the only spec in this workstream whose core survived review intact, and it is the method the decomposition's own inventory failed to apply — twice, producing break 4 and then this fifth blocker.

### 2. Genesis is markets-only in production

`Gw::boot()` registers markets and oracles (Pass 1) and then funds (Pass 2). In production, Pass 2 does not run: no `fund`, no LP-demo grant, no `SeedInsurance`. Genesis is `(consumed_deposit_tip = [0;32], consumed_deposit_count = 0)`, zero notes, zero positions, zero insurance, `external_in = 0`.

**The mode must be a parameter of `Gw::boot()`, not a field read inside it.** `gw.prod` is assigned at `main.rs:6397`, two lines *after* `Gw::boot()` is called at `:6395` — by then the seven deposits already exist. This is not a style preference; the flag physically cannot guard the funding.

**Keep `Gw::boot()` as the demo-mode entry point** and add `Gw::boot_with(GenesisMode)`. There are ~80 `Gw::boot()` call sites, nearly all in tests; changing the signature would churn all of them for no benefit and bury the real diff. `boot()` becomes `boot_with(GenesisMode::Demo)`.

`seal_genesis_baseline()` still runs (it is what makes window 0 open from the genesis root); with no Pass-2 ops it simply folds nothing.

**Coordination with SEC-024:** that spec turns `SeedInsurance` into an always-rejected stub and capitalizes insurance through a real deposit + `FundInsurance`. 025-C stops *calling* it in production; SEC-024 removes the op. No conflict, and neither blocks the other.

### 3. Enforcement at the call site, structurally

`fund_amount_unbacked` gains a `prod: bool` parameter and returns `Err` when it is set.

This is deliberately the compiler-forcing shape: every call site must supply the flag, so a future caller cannot inherit unbacked minting by omission. A guard placed only inside each caller would leave the next caller unprotected — which is exactly how `/v1/lp` came to be a live path while self-service was correctly closed.

`/v1/lp/*` is additionally not mounted in production. That is defence in depth; **the call-site guard is the load-bearing half**, because it survives a routing change.

### 4. Fresh boot verifies its genesis against the deployed contract

Today `main.rs:6355` compares only when `l1_status` already exists, and a fresh genesis sets it to `None` (`:1610`) — so the one boot that most needs the check skips it.

A fresh production boot reads the deployed `currentStateRoot` and refuses to start if it does not equal the local genesis root, before accepting any deposit. A gateway whose genesis disagrees with its contract cannot settle anything; failing at boot is strictly better than discovering it at the first settle, after users have deposited.

### 5. What this does not change

The demo path is untouched: `Gw::boot()` still funds MM, user and the LP demo, and demo/dev settling continues to work through `PROVER_URL=mock`.

## Scope

**In:** `crates/gateway` — `Gw::boot` mode parameter, `fund_amount_unbacked`'s `prod` parameter and its four call sites, `/v1/lp/*` prod mounting, the fresh-boot genesis check.

**Not in:**

- **`crates/perp-core` — nothing.** No guest change, so **no vkey move**. (`GENESIS_ROOT` does move; see Migration.)
- **`SeedInsurance`'s removal as an op** — SEC-024.
- **The operator insurance bootstrap** (`FIN_ADMIN_KEY`, confirm-then-fund) — 025-A. Until it lands, a production deployment starts with **zero insurance**, so the first bad debt goes straight to ADL or trips `Mode::CloseOnly`. **025-C makes settling possible; it does not make launching safe.** That gate is 025-D.
- **House-MM counter-orders, OpenAPI/docs/litepaper honesty, execution reporting** — 025-E, and the decomposition's alpha-posture bullets beyond the invariant above.
- **Operational items** (bond against projected TVL, liveness window in blocks) — runbook, at cutover.

## Migration

| Change | Consequence |
|---|---|
| Production genesis is markets-only | **`GENESIS_ROOT` moves.** A fresh `DarkPerpSettlement` must be deployed with the new root, and the gateway's snapshot wiped |
| No `perp-core` change | **No vkey move, no verifier redeploy** originates here |
| `fund_amount_unbacked` signature | Compile error at every call site — intended |
| `/v1/lp/*` absent in production | Any client depending on it in prod breaks; it was never usable there without corrupting settlement |

The cutover bundle remains SEC-022 + SEC-024 + SEC-026 + 025-A/B/C/D. **025-B + 025-C are the smallest set that produces a successful settle**, but a *safe* launch also needs 025-A (insurance) and 025-D (the trading gate).

## Testing

| Case | Expected |
|---|---|
| **The invariant, by enumeration:** every writer of `consumed_deposit_tip` / `consumed_deposit_count` | must be a real check — a test that fails if a new unbacked writer is added, not a review instruction. The `external_in` row of SEC-024's table is the precedent |
| **Production genesis** | `consumed_deposit_tip == [0;32]`, `consumed_deposit_count == 0`, zero notes, zero positions, `insurance_fund == 0`, `external_in == 0` |
| **The pair matches a fresh vault** | assert the genesis pair equals `(bytes32(0), 0)` — the values `depositTipAt(0)` returns. **This is the row that proves the fifth blocker is closed** |
| **Demo genesis** | still funded — MM, user, LP demo, insurance. Must be explicitly demo-scoped, not a global expectation |
| **`fund_amount_unbacked` with `prod = true`** | `Err`, and **state byte-for-byte unchanged** (assert on `state_root()`, which binds the whole state) |
| **A production LP transfer** | refused. **Must fail before the change** — this is the live corruption path today |
| Legacy `Gw::deposit` in production | refused at the call site, not merely unrouted |
| Self-service deposit in production | still refused (DP-001 regression) |
| Fresh production boot whose genesis ≠ deployed `currentStateRoot` | refuses to start, naming both roots. **Must fail before the change** |
| Fresh production boot whose genesis matches | starts |

Rows marked "must fail before the change" are what establish the tests are testing something. On the preceding two branches, **twelve fixtures passed while exercising nothing** — including one where a *rejected* order satisfied every precondition meant to prove an *accepted* one. Verify each new test reaches the path its name claims.

## Open risks

1. **Production genesis has zero insurance until 025-A.** Named above, restated here because it is the one way this piece could make things *worse* if 025-C ships and a deployment opens for trading before 025-D's gate exists.
2. **~80 `Gw::boot()` call sites.** The `boot()`/`boot_with()` split keeps the diff small, but if any *non-test* caller needs production mode and is missed, it silently gets a funded genesis. Enumerate the non-test callers explicitly rather than trusting the default.
3. **The fresh-boot root check needs an L1 read at boot.** If the RPC is unavailable the gateway must fail closed rather than skip the check — a skipped check on an unreachable RPC is how `main.rs:6355`'s conditional came to be vacuous in the first place.
