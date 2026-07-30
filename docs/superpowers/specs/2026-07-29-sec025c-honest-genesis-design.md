# SEC-025 025-C — Honest genesis — Design

> Decomposition: `2026-07-26-sec025-decomposition.md`. Threat model: `2026-07-26-sec02x-threat-model.md`
> (canonical). Depends on **025-B** (`a2a2f56`, merged 2026-07-29). **This is a rewrite; the first
> version was reviewed and six findings came back, four of which changed the design.**

**Finding:** the gateway cannot settle against a real vault, because its genesis fabricates deposits the L1 chain will never match. The decomposition framed 025-C as *honesty and alpha posture*; 025-B's whole-branch review established it is also **the hard prerequisite for settling at all**.

## Verified at source

| Claim | Evidence |
|---|---|
| **Boot emits seven unbacked deposits** — MM + user per market across 3 markets, plus an extra market-0 grant for the LP demo | `crates/gateway/src/main.rs:1553-1578` (`fund` → `fund_amount_unbacked`) |
| Each fabricates a `Deposit` with **sentinel** L1 fields (`from=[0;20]`, `deposit_blind=[0;32]`, `deposit_id` = the live count) | `main.rs:4059-4075`; the fn's own doc says these "fold a `consumed_deposit_tip` the on-chain vault chain will NOT match" |
| `op_deposit` folds every leaf into the tip and increments the count | `crates/perp-core/src/engine.rs:343`, `:387` |
| Boot also applies `SeedInsurance` | `main.rs:1580-1584` |
| **`_requireDepositPrefix` runs before proof verification**, comparing `depositsRoot` against `depositTipAt(newDepositCount)` | `contracts/src/DarkPerpSettlement.sol:301-307`, called at `:334` — *before* `verifier.verify` at `:337`; same on `finalSettle` (`:385`) |
| A fresh vault therefore returns `bytes32(0)` for `depositTipAt(7)` and the settle **reverts** | mapping default; identical under `PROVER_URL=mock` |

### The core derivation — confirmed sound by adversarial review

`State::new` initializes `consumed_deposit_tip = [0u8; 32]`, `consumed_deposit_count = 0` (`crates/perp-core/src/state.rs:73`, pinned at `:349`), and market registration touches neither (`:99`). `derive_roots` takes the post-replay tip (`crates/perp-core/src/commitment.rs:53`) and the guest commits that derivation (`crates/sp1-guest/src/main.rs:27`); `depositsRoot` is the seventh public-commitment word (`commitment.rs:32`, mirrored at `DarkPerpSettlement.sol:255`). The vault states explicitly that **"`depositTipAt[0]` is never written: the mapping default `bytes32(0)` IS the genesis tip"** (`CollateralVault.sol:59`).

So `_requireDepositPrefix(bytes32(0), 0)` passes, and a markets-only genesis settles. *(`newDepositCount` is not itself proof-committed — the gateway derives it locally at `prover_client.rs:260` and Solidity uses it only to select the vault prefix. That does not weaken the zero-prefix settle.)*

**No sixth blocker exists.** Review traced boot → deposit → order → seal → prove → `settleBatch` on a clean deployment: bond top-up happens before window sealing (`main.rs:6965`), liveness does not auto-enter close-only, and empty state and trees are accepted. Correct sequencer, verifier, `setVault`, genesis root, RPC and bond funding remain deployment prerequisites — not new blockers.

### Cleaning genesis alone is not enough — and the writer inventory was incomplete

There are **five** syntactic `fund_amount_unbacked` calls, not four, and the fifth changes the design:

| Site | What it is | Guarded today? |
|---|---|---|
| `main.rs:2386` | self-service deposit | **Yes, at the call site** — `if self.prod { return Err(…) }` (audit DP-001) |
| `main.rs:3060` | LP `pool_transfer` credit | **No.** `/v1/lp`, `/v1/lp/deposit`, `/v1/lp/withdraw` are mounted at `main.rs:6107-6109`, **outside** the `if !prod` block that begins at `:6071` and covers only legacy `/api/*`. Authentication exists (`:5179`) but no mode gate. Reached via `pool_transfer` (`:3088` → `:3060`) |
| `main.rs:3419` | legacy `Gw::deposit` | **Route-mounting only** |
| **`main.rs:4041`** | **the `fund` wrapper** | **and `fund` is not boot-only — `Gw::simulate_adl` calls it twice at runtime (`:2911`, `:2930`), protected only by `/api/simulate-adl` sitting inside `if !prod` (`:6083`)** |
| `main.rs:7512` | test fixture | n/a |

**`/v1/lp/*` in production is a live corruption path**, and `simulate_adl` is a second one behind route-mounting alone — which is exactly the enforcement this spec calls insufficient.

**The first version's mechanism was also wrong.** Adding `prod: bool` to `fund_amount_unbacked` forces `fund` to supply *some* boolean, but `fund` has no mode input, so it does not force the *correct* one. The mode must be threaded through `fund` as well; `simulate_adl` already has `self.prod` in scope, and boot has its genesis mode.

Direct field mutation is otherwise centralized: production advances the accumulator only in `op_deposit`, and the gateway constructs `BatchOp::Deposit` only in `fund_amount` (`main.rs:4136`). **But snapshot deserialization is a second way production state acquires these fields — see §4.**

## Design

### 1. The invariant

**In production, `consumed_deposit_tip` and `consumed_deposit_count` advance only via a real L1 deposit** — `fund_amount` as called by `account_confirm_deposit`, with the payer's real `from`, the deposit's L1 `id`, and the authorized `deposit_blind` — **or arrive in a snapshot whose continuity with the chain has been verified (§4).**

One property, checkable by enumeration. The first version stated it and then enumerated incompletely, which is the same failure that produced this piece's existence.

### 2. Genesis is markets-only, and the mode is a parameter

In production, `Gw::boot()`'s Pass 2 does not run: no `fund`, no LP-demo grant, no `SeedInsurance`. Genesis is `(tip = [0;32], count = 0)`, zero notes, zero positions, zero insurance, `external_in = 0`.

**The mode must be a parameter of `Gw::boot()`.** `gw.prod` is assigned at `main.rs:6397`, two lines *after* `Gw::boot()` at `:6395` — the flag physically cannot guard the funding. Keep `Gw::boot()` as `boot_with(GenesisMode::Demo)` and add `Gw::boot_with(GenesisMode)`. **There is exactly one non-test caller** — `main()` at `:6395`; every other call site is after the test module begins at `:7331`. So the split is safe and the diff stays small.

`seal_genesis_baseline()` still runs; with no Pass-2 ops it folds nothing.

**Coordination with SEC-024:** that spec turns `SeedInsurance` into an always-rejected stub and capitalizes insurance through a real deposit + `FundInsurance`. 025-C stops *calling* it in production; SEC-024 removes the op. Neither blocks the other.

### 3. Enforcement threaded to every caller that knows the mode

`fund_amount_unbacked` **and `fund`** both take the mode and return `Err` in production. Every call site must then supply it, so a future caller cannot inherit unbacked minting by omission — which is how `/v1/lp` and `simulate_adl` came to be reachable while self-service was correctly closed.

`/v1/lp/*` is additionally not mounted in production, and `/api/simulate-adl` stays unmounted. That is defence in depth; **the threaded guard is the load-bearing half**, because it survives a routing change.

### 4. Continuity is checked on every L1-configured boot, not only a fresh one

The first version proposed a check for a *fresh* production boot and left the existing `l1_status`-gated check for restored ones. **Review found the gap that leaves: a snapshot taken before the first successful settle.**

`l1_status` stays `None` until `commit_window_settle` succeeds (`main.rs:1098`, `:2252`), the gateway persists periodically regardless (`:1656`, `:6685`), and restore deserializes the whole `Gw` including its deposit accumulator (`:1669`). The existing check runs only when `gw.l1_status` is `Some` (`:6588`). So a pre-first-settle snapshot is checked by neither. Worse, **`prod` is deliberately not persisted and is overwritten from the environment after restore** (`:1122`, `:6397`) — so a *demo* snapshot carrying unbacked deposits can be restored under production posture.

**Comparing the restored live `state_root()` is the wrong test:** a legitimate pre-first-settle snapshot may hold real pending deposits and correctly differ from L1 genesis.

The universal continuity value already exists. `last_settled_root` is initialized to genesis and advanced only after a settle lands (`main.rs:1071`, `:1618`, `:2236`). So, for **every** L1-configured boot — fresh or restored, whatever `l1_status` holds — require after recovery:

```
on-chain currentStateRoot == gw.last_settled_root
```

and refuse to start otherwise, naming both roots. If the RPC is unreachable the boot fails closed; a check skipped because a node was down is how the existing conditional came to be vacuous.

### 5. What this does not change

Pure no-L1 demo behaviour is untouched: `Gw::boot()` still funds MM, user and the LP demo.

## DECIDED: genesis mode keys on `production_mode` (any L1-configured deployment)

**Resolved 2026-07-29.** Genesis mode follows `production_mode` — i.e. **any** deployment with L1 configured gets a markets-only genesis, including Base Sepolia and local anvil. The reasoning and its cost are below; the cost is real and accepted.

Consequence for the current live testnet: after the cutover it loses its funded MM, demo user, LP pool and insurance. **Testnet liquidity must be re-established through real deposits** — faucet → `CollateralVault.deposit` → `account_confirm_deposit` — which is the same path production uses. That is additional cutover work and belongs in the runbook.

**The first version claimed "demo/dev settling under `PROVER_URL=mock` is untouched." That is false.** Production posture is `l1_enabled || DARKPERP_PROD` (`main.rs:5844`, `:6132`), independent of the prover. So keying genesis mode on `production_mode` means a Base Sepolia or local-anvil deployment loses its funded MM, demo user, LP pool and insurance — including the current live testnet.

The two options are genuinely in tension and the choice is a product decision, not a derivation:

- **Key genesis on `production_mode` (any L1).** Every L1-configured deployment can settle. Cost: testnet MM liquidity must come from *real* deposits through the vault (faucet → `deposit` → `account_confirm_deposit`), which is more setup but is the same path production uses.
- **Key genesis on `DARKPERP_PROD=1` alone**, reusing 025-B's `strict_production()`. Testnets keep their demo state — but **cannot settle**, because the unbacked deposits still break the prefix pin. A testnet that cannot settle cannot validate the cutover.

**Recommendation: key on `production_mode`.** The purpose of this piece is to make settling possible, and a deployment that cannot settle is not a useful rehearsal for one that must. Losing unbacked testnet liquidity is the honest consequence; the replacement is a faucet-funded real deposit.

## Scope

**In:** `crates/gateway` — `Gw::boot` mode parameter, the mode threaded through `fund` and `fund_amount_unbacked` to all five call sites, `/v1/lp/*` prod mounting, the boot continuity check.

**Not in:** `crates/perp-core` — nothing, so **no vkey move**. `SeedInsurance`'s removal as an op (SEC-024). The operator insurance bootstrap (025-A). House-MM counter-orders, OpenAPI/docs honesty, execution reporting (025-E). Bond-against-projected-TVL and the liveness window (runbook, at cutover).

**Consequence to state plainly:** a production deployment starts with **zero insurance** until 025-A. Fills and liquidation penalties do capitalize it before any bad debt arrives (`engine.rs:640`, `:740`), so "the first bad debt goes straight to ADL" is too absolute — but the backstop starts empty, and nothing here gates trading on it. That gate is 025-D. **025-C makes settling possible; it does not make launching safe.**

## Migration

| Change | Consequence |
|---|---|
| Production genesis is markets-only | **`GENESIS_ROOT` moves.** Fresh `DarkPerpSettlement` deploy with the new root; gateway snapshot wiped |
| No `perp-core` change | No vkey move originates **here** — but this row under-plans the cutover if read alone. **SEC-022 (`50e6c17`, `52d4123`, `5a25197`, all ancestors of this branch) did change `perp-core`**, which `crates/sp1-guest` compiles into the guest. The cutover therefore needs a **rebuilt guest and a new `SP1ZkVerifier`**. `docs/REDEPLOY-CC-RUNBOOK.md:119-122` states this correctly; consult it rather than this row |
| Mode threaded through `fund` / `fund_amount_unbacked` | Compile error at every call site — intended |
| Continuity check on every L1 boot | A gateway whose `last_settled_root` disagrees with the chain now refuses to start rather than settling into a fork |
| `/v1/lp/*` absent in production | Never usable there without corrupting settlement |

**025-B + 025-C are the smallest set that produces a successful settle**; a *safe* launch also needs 025-A and 025-D.

## Testing

| Case | Expected |
|---|---|
| **The invariant, by enumeration** | a real check that fails if a new unbacked writer appears — not a review instruction. SEC-024's `external_in` row is the precedent |
| **Production genesis** | `(tip, count) == ([0;32], 0)`, zero notes, positions, insurance, `external_in` |
| **End-to-end, the row that actually proves closure** | from `boot_with(Production)`: seal a window, run `prove_and_prepare`, submit the resulting zero-prefix tuple to a freshly wired settlement + vault, and assert it **lands**. Asserting the constants `(bytes32(0), 0)` proves only two constants — it would not catch `main()` still calling demo boot, a sentinel op left in `window_ops`, or a wrong witness pre-state. *(Contract-side tests already show a zero-prefix settle succeeds — `DarkPerpSettlement.t.sol:48`, `:82`, `:107` — but nothing connects them to the boot mode.)* |
| **Demo genesis** | still funded — explicitly demo-scoped, not a global expectation |
| **`fund` / `fund_amount_unbacked` in production** | `Err`, **and nothing mutated** — assert the `perp_core::State` root **and** the sequencer's `window_ops` **and** the note archive. `state_root()` alone is **not** sufficient here: both functions take `&mut Sequencer` and `&mut NoteArchive`, and `state_root()` commits only `State` (`state.rs:212`), so a buggy rejected call could mutate `Sequencer.window_ops` (`sequencer/src/lib.rs:519`) or the archive's records (`note-archive/src/lib.rs:157`) invisibly |
| **A production LP transfer** | refused. **Must fail before the change** — the live path today |
| **A production `simulate_adl`** | refused at the call site, not merely unrouted |
| Legacy `Gw::deposit` in production | refused at the call site |
| Self-service deposit in production | still refused (DP-001 regression) |
| **A pre-first-settle snapshot restored under production posture** | continuity check runs and refuses on mismatch. **Must fail before the change** — neither existing check covers it |
| A demo snapshot restored under production posture | refused |
| L1 boot whose `last_settled_root` matches the chain | starts |
| RPC unreachable at boot with L1 configured | fails closed |

Rows marked "must fail before the change" are what establish the tests test something. Across the two preceding branches **twelve fixtures passed while exercising nothing**, including one where a *rejected* order satisfied every precondition meant to prove an *accepted* one.

## Open risks

1. **~~Testnet liquidity after the cutover.~~ RETRACTED — the mitigation I wrote is not implementable, and the consequence is larger than "a thinner book".**

   The original text said the MM would be re-funded "through real deposits — faucet → `CollateralVault.deposit` → `account_confirm_deposit`". **That path cannot credit the house MM.** `account_confirm_deposit` credits `self.accounts[key].wallet` (`main.rs:1957-1959`), and every account wallet is derived from `csprng_bytes32()` at registration (`:1779`). `gw.mm` is `Wallet::from_seed([2u8; 32])` (`:1544`) and **is not an account at all**. Every path that could credit it — boot Pass 2, `fund`, `pool_transfer` via `lp_deposit` — is refused or unmounted by this very design.

   The consequence is concrete, not cosmetic. `Gw::tick` injects a house-MM counter-order for every crossing `Ioc`/`Fok` (`main.rs:3669`, `:3721`). With a zero-collateral MM that counter is engine-rejected, so **market orders never fill in production** unless two real accounts happen to cross resting `Gtc` orders.

   This is not a defect in 025-C's implementation — it is faithful to this spec. It is a defect in this spec: I asserted a mitigation without checking that the code could perform it. **Resolving it is a prerequisite for opening trading, not for merging.** Two candidate shapes, neither designed here: an operator-owned *registered account* acting as MM and quoting through `/v1/orders` like any participant, or 025-E owning market-making explicitly as part of the no-house posture it already scopes. `docs/API.md:79`'s "guaranteed fill" claim is false in production until one of them lands.

2. **The demo-snapshot residual strands real USDC, and a cheap mechanical detector exists.** §4's check is root *equality*, not a posture detector: a deployment whose contract `GENESIS_ROOT` was itself demo-derived (as the live stack's `0x4d1ae1d2` was) matches its own demo snapshot and boots with the seven deposits intact. The failure is worse than a wedged settle — `account_confirm_deposit` refuses every real deposit (`deposit_id 0 is not next-in-line (expected 7)`), `settleBatch` reverts at `_requireDepositPrefix`, **and `finalSettle` reverts on the same pin** (`DarkPerpSettlement.sol:378`), so the wind-down escape is bricked and users' collateral is permanently unclaimable.

   Two `cast call`s beside the root check would detect it mechanically:

   ```
   require gw.seq.state.consumed_deposit_count <= vault.depositCount()
   require vault.depositTipAt(consumed_deposit_count) == consumed_deposit_tip
   ```

   The first has no false positives — the gateway can only have credited deposits the vault actually holds, so `count > depositCount` is *exactly* the unbacked-deposit condition. The second catches sentinel leaves even when the counts coincide. **This is a hard gate on the cutover** and the highest-value follow-up to this piece; it converts operator discipline into a fail-closed boot.
2. **Zero insurance until 025-A.** Restated because it is the one way this piece could make things worse if a deployment opens for trading before 025-D exists.
3. **The continuity check needs an L1 read at boot.** Fail-closed on an unreachable RPC is specified; it must not be softened to a warning under operational pressure, which is how the existing check became vacuous.
