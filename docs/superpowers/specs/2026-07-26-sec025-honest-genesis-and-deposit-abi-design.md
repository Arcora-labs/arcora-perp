# SEC-025 — Honest genesis + SEC-019 deposit wiring — Design

> **Threat model:** see `2026-07-26-sec02x-threat-model.md`. This finding is threat-model
> independent — it is not an attack, it is that the repo does not settle end-to-end and that genesis
> asserts collateral that does not exist.
>
> **Not independently deployable.** Its bootstrap needs `FundInsurance`, which SEC-024 introduces.
> SEC-025 and SEC-024 land together; SEC-022 and SEC-023 ride the same cutover because all four
> change the guest ELF, the genesis root, or a persisted format.

**Finding:** SEC-025 [critical, deployment-blocking] — the SEC-019 deposit binding is **not connected across three boundaries**, and genesis asserts $20.04M of collateral that was never deposited.

## The three broken boundaries

Each verified at source. Any one of them stops a settle.

**1. prover-service → gateway (fails first).** The gateway's response parser declares `deposits_root` as a required field (`crates/gateway/src/prover_client.rs:241`, no `Option`, no `serde(default)`), but `ProveResp` never emits it (`crates/prover-service/src/main.rs:70-80`). A real prove response therefore **fails JSON decoding before settlement is attempted**.

**2. gateway → Solidity.** `DarkPerpSettlement.settleBatch` takes seven roots plus `newDepositCount` and checks the root against the vault's chain prefix (`contracts/src/DarkPerpSettlement.sol:311-320`). Both gateway paths call the old six-root selector: `L1::settle_proved` (`crates/gateway/src/l1.rs:439`) and the legacy `L1::settle` (`:385-419`). Production can select the legacy path with `PROVER_URL` unset (`crates/gateway/src/main.rs:5689-5704`), so both must be fixed or the legacy path forbidden whenever a SEC-019 contract is configured.

**3. `finalSettle` has no gateway path at all.** It exists only in Solidity (`DarkPerpSettlement.sol:365-388`) and requires governance, close-only, grace expiry, the deposit prefix and a proof. The first version of this spec said to "give it the same treatment"; there is nothing to give it treatment to.

The live testnet settles today only because the deployed contract predates SEC-019 (deployment metadata records 2026-07-11, `contracts/deployments/base-sepolia.json:6-15`; the frontend labels those addresses pre-SEC-019, `frontend/src/api/wallet.ts:17-21`). **The system works because the check that would catch it is not deployed.**

## Genesis asserts collateral that does not exist

Boot funds every market's MM and the demo user before genesis (`crates/gateway/src/main.rs:1543`) via `fund()` → `fund_amount_unbacked` (`:3930`), whose own comment states the problem (`:3949`):

> an UNBACKED credit — a `Deposit` op with SENTINEL L1-leaf fields (`from=[0;20]`, `deposit_blind=[0;32]`, `deposit_id` = the live consumed count so the strict in-order gate passes) … those fold a `consumed_deposit_tip` the on-chain vault chain will NOT match, so they can never settle in `prod`.

The comment's reasoning is that production disables the self-service paths (DP-001). But **boot calls it unconditionally**, and `seal_genesis_baseline` folds the result into the genesis root (`:1572`). Seven fabricated deposits totalling **$20,015,000**, plus `SeedInsurance`'s $25,000 — **$20,040,000**.

Consequence: against a SEC-019 contract the first settle presents a non-zero `depositsRoot` while an empty vault's `depositTipAt` returns the mapping default of zero (`contracts/src/CollateralVault.sol:59-70`, `DarkPerpSettlement.sol:301-306`) — revert on batch one. Later real deposits fold **on top of** the fake tip and cannot repair it.

**Permanent for that deployment, not globally.** `finalSettle` performs the same prefix check (`:379-388`); the vault binding is set once (`:194-199`); the admin resume endpoint only requests a retry and cannot alter roots (`main.rs:4644-4684`). Recovery means new contracts, a state wipe, and abandoning the wedged deployment — which strands any real funds already in the old vault.

**There is a second, live fabrication path.** `pool_transfer` (`main.rs:2936-2974`) burns via `Withdraw{to:None}` and re-credits via `fund_amount_unbacked`. It is net-zero externally and conservation holds, so it fabricates no *value* — but it advances the deposit count and folds a leaf the vault never saw, i.e. **it corrupts the tip exactly like genesis does**. `/v1/lp/deposit` and `/v1/lp/withdraw` are mounted in production (`main.rs:5896-5899`), so removing unbacked funding from boot alone is insufficient.

## Correction history

The first version of this spec was rejected in review. Three errors, all verified:

1. **It claimed to be a prerequisite for SEC-024 while its own bootstrap required SEC-024's `FundInsurance`** — a circular dependency. Corrected: they ship together.
2. **The bootstrap was not constructible.** Deposit confirmation binds to a registered account's randomly-generated wallet (`main.rs:1900-1903`, `:1721-1744`), while the MM is a fixed demo wallet `Wallet::from_seed([2u8;32])` (`:1504-1505`). There is no production path to deposit into the MM or to leave a note for insurance. Resolved by the alpha posture below.
3. **The trading gate was hand-waving.** `/v1/orders` is always mounted in production (`main.rs:5852-5914`) and its handler calls `account_place_order` with no bootstrap check (`:5128-5146`). "Keep the server private" does not implement it, because the gateway must be online to register accounts and confirm the bootstrap deposits.

Review also surfaced that `gw.prod` is assigned **after** `Gw::boot()` has already seeded funds (`main.rs:5921-5925`, `:6143-6168`), so the field cannot guard boot funding — the mode must be passed *into* boot.

## Design

### 1. Alpha posture: no house MM, no LP

Both are disabled in production. Two things this genuinely buys, and one earlier claim that was overstated:

- The MM needs no capitalization, so **that** half of the unconstructible bootstrap disappears. (The insurance half does not — see §1a.)
- `pool_transfer` becomes unreachable in production, closing the live tip-corruption path. Verified: its only callers are LP deposit/withdraw (`main.rs:2977`, `:3007`), and the legacy `/api/lp/*` routes are already `!prod`-only (`:5860`).
- ~~LP ownership capture~~ — **overstated in an earlier draft.** With honest genesis and no MM, pool equity and shares are both zero, so the first LP depositor mints shares equal to its own contribution and owns exactly that (`main.rs:2994`). Capture would require MM equity to accumulate while `lp_total_shares == 0`, which cannot happen with no MM. Disabling LP is still right — for `pool_transfer` — but not for this reason.

Cost: **the alpha has no house liquidity.** Users match only against each other.

Mechanically: do not mount `/v1/lp/*` in production, and do not generate house-MM counter-orders. `fund_amount_unbacked` stays for demo/dev builds but must be unreachable when `prod` is set — enforced at the call sites, not by an assert inside the helper, which would turn a request into a panic.

### 1a. The insurance bootstrap needs a gateway path that does not yet exist

`FundInsurance` consumes an **unspent** note. But every confirmed L1 deposit runs `Deposit` and then immediately `FundPosition` in the same helper (`main.rs:1962` → `fund_amount`, `:3987-4013`), and `FundPosition` consumes the note (`engine.rs:430`). **So no production path leaves a note for `FundInsurance` to spend.** Removing the house MM fixed the wallet problem; it did not fix this one, and neither SEC-024 nor the earlier draft of this spec scoped it. This is deployment-blocking.

**In scope here:** an operator-only path that confirms a real L1 deposit and stops after `Deposit`, leaving the note unspent, so `FundInsurance` can then consume it. Two shapes are acceptable — a `fund_amount`-without-`FundPosition` variant behind the operator gate, or a dedicated confirm-then-fund-insurance method that emits both ops in one step. The second is preferable: it never leaves a dangling unspent note if the process dies between the two.

The `FIN_ADMIN_KEY` gate (`main.rs:4579-4601`, constant-time, fail-closed when unset) is the existing precedent for an operator-only endpoint and should be reused rather than inventing a second admin surface.

### 1b. No-house honesty work — required, not optional

A no-house alpha exposes reporting the gateway currently gets away with only because a house fill is guaranteed. Shipping without fixing these would mean an exchange that misreports its own book and fills:

- **`/v1/markets/:id/orderbook` publishes synthetic depth**, not the matcher book — `book_around` fabricates a fixed ladder around the mid (`main.rs:3742-3752`), and the websocket publishes the same invented liquidity (`:2749`). With no house, this advertises liquidity that does not exist.
- **Partial fills are reported as full**: on any non-`ACCEPTED` finality the gateway sets `o.filled = o.order.size` and `o.avg_fill = o.order.limit_price` (`main.rs:3667-3668`).
- **IOC/market orders with no liquidity** are correctly cancelled by the matcher (`book.rs:318`) but remain displayed as `ACCEPTED` indefinitely (`main.rs:3660`).
- **A sealed resting order cannot be cancelled** through the API (`main.rs:2589`), even though the book has the primitive (`book.rs:422`). With no house to fill against, resting orders are the normal case rather than the exception.

These are gateway-reporting fixes with no proven-state impact, but they gate whether the alpha is usable and honest.

### 2. Honest genesis

Genesis contains **markets only**: zero notes, zero positions, zero insurance, `external_in == 0`, `external_out == 0`, deposit count zero, deposit tip zero.

This is viable — `State::new` initializes every relevant field to zero (`crates/perp-core/src/state.rs:73-90`) and market registration installs only market and default-funding state (`:94-109`). Empty note and position sets are supported.

`seal_genesis_baseline` becomes unnecessary in this shape, because `add_market` already refreshes `window_start_state` (`crates/sequencer/src/lib.rs:430-450`). Keep the call but make it **assert** the honest invariants in production rather than silently folding unexpected boot ops.

The mode must reach `Gw::boot()` as a parameter; `gw.prod` is set too late to guard it.

### 3. Complete the SEC-019 wiring

- `ProveResp` emits `deposits_root` **and** the post-state deposit count; `ProveOutcome`, the HTTP parser, and the gateway's commitment cross-check carry both. The prover service currently discards the mutated post-state after `run_transition` and its `BatchProof` public fields have no count (`prover/src/lib.rs:49`, `:474`), so this needs a host-only `post_deposit_count` field — it does **not** enter the guest commitment.
- **The gateway MUST derive the count from its own witness**, not merely prefer to. The existing cross-check re-hashes fields the prover returned; it does not replay the witness (`prover_client.rs:115`). Replay once in `prove_and_prepare`, compare every derived root, and take the count **and the insurance balance** from that post-state — the gate in §4 needs both.
- `L1::settle_proved` uses the seven-root + count selector. "Refuse the legacy path when a SEC-019 contract is configured" is **not implementable as written** — the gateway has no ABI-version discriminator. Do the reachable thing instead: **refuse production L1 startup when `PROVER_URL` is unset or `mock`** (both are accepted today, `main.rs:5689-5704`), which removes the legacy path from production entirely.
- **`finalSettle` is a scoped deliverable, not a note.** The contract entrypoint exists (`DarkPerpSettlement.sol:365`) but neither `L1` nor the deploy scripts provide a callable path, nor any way for governance to obtain the prepared roots, count and proof. Since governance may hold a different key from the sequencer (`contracts/script/Deploy.s.sol:57`), the deliverable is a **script plus an export path for the prepared settle data** — not a gateway method. This matters more than it looks: `finalSettle` is the only recovery if close-only trips during bootstrap.

### 4. The bootstrap sequence and the trading gate

1. Boot with an honest genesis; compute `GENESIS_ROOT` from it.
2. Deploy `SP1ZkVerifier`, `DarkPerpSettlement` (constructed with that root) and `CollateralVault`.
3. Post the settlement bond — deposits raise `requiredBond` and settlement rejects while underbonded (`DarkPerpSettlement.sol:324-325`).
4. Make **real** vault deposits for insurance capital and any operator float.
5. Prove and settle a **bootstrap batch**: the resulting `Deposit` ops followed by `FundInsurance`.
6. **Enable order ingress only after that batch settles.**

Step 6 needs a real mechanism, not a procedure — and the mechanism has four constraints that review surfaced:

- **The flag lives inside serialized `Gw`**, not `App` and not a `#[serde(skip)]` runtime field, because `Gw` is what `snapshot_plain` persists (`main.rs:1027`, `:1642`).
- **Its transition is centralized in `commit_window_settle`**, which is the single point reached by clean settlement (`main.rs:6893`), ambiguous-but-landed settlement (`:7005`), and boot roll-forward from the rollback journal (`:195`).
- **The predicate must read the sealed witness's independently derived post-state, not a live root.** Capturing "the bootstrap root" when `FundInsurance` is applied locally does not work: funding maintenance runs every 700 ms even on empty markets (`sequencer/src/lib.rs:692`, `main.rs:6533`), so the live root keeps moving. `PreparedSettle` (`prover_client.rs:100`) therefore needs the post-state deposit count and insurance balance from the gateway's own replay (§3), so roll-forward can evaluate the same predicate without inspecting a later live state.
- **The check belongs in `account_place_order`**, with a real-router test against `POST /v1/orders` — that keeps the invariant centralized while still exercising the HTTP boundary.

Both formats change: a persisted gate bumps the snapshot magic `DPSNAP1` (`snapshot.rs:32`), and extending `PreparedSettle` bumps the rollback-journal magic `DPRBJL1` (`rollback_journal.rs:26`).

**One durability gap the gate does not repair, and this spec does not close:** `post_v1_deposit_authorize` records the secret blind in memory and returns the signature immediately (`main.rs:1865`, `:4911`), while snapshots run every 30 s (`:305`, `:6452`). A crash after the user submits that authorization on-chain but before the snapshot loses the blind, producing an uncreditable head-of-line deposit. Worth its own follow-up; during bootstrap, mitigate operationally by snapshotting between the authorize and the on-chain send.

Why it matters rather than being ceremony: with zero insurance the first bad debt goes straight to ADL against real users or, absent winners, parks the debt and trips `Mode::CloseOnly` (`engine.rs:697`) — from which there is **no proven transition back**; only `EnterCloseOnly` exists (`engine.rs:304`). A later `FundInsurance` cannot repair an already-closed negative position, because liquidation requires an open one (`engine.rs:640`), and withdrawals stay permitted in close-only (`engine.rs:854`). One early gap can wind the deployment down permanently.

*(SEC-022's per-fill solvency postcondition makes fill-created bad debt impossible, which is what makes launching with modest insurance defensible at all. That is another reason the four ship together.)*

## Scope

- **`crates/gateway`**: mode passed into `Gw::boot()`; boot stops fabricating deposits and insurance; `/v1/lp/*` and house-MM generation not mounted in prod; `fund_amount_unbacked` unreachable in prod; `ProveOutcome` + parser carry `deposits_root` and the count; `settle_proved` uses the new ABI; legacy `settle` updated or refused; the bootstrap gate.
- **`crates/prover-service`**: `ProveResp` emits `deposits_root` and the count.
- **Runbook**: the six-step bootstrap, the trading gate, and the operational items below.

**Non-goals:** changing the SEC-019 accumulator (it is correct, it was unconnected); redesigning LP accounting (disabled instead); a migration path for existing live state (the cutover already requires fresh contracts and a wipe); `TreasuryToInsurance` (tracked with SEC-024).

## Migration

No proven-code change of its own, so **no vkey impact from this spec** — but it lands with three specs that do, and it moves `GENESIS_ROOT` by emptying genesis.

The contract is constructed **with** the genesis root, so the honest genesis must be computed **before** deployment.

Operational items the runbook must cover, each verified:

- `GENESIS_ROOT` defaults to zero in the deploy script (`contracts/script/Deploy.s.sol:49-53`) and omitting `VERIFIER` silently deploys `MockZkVerifier` (`:60-76`). **Documenting these is too weak** — the script permits both without acknowledgement on Base Sepolia. The runbook must *require* a non-zero genesis and an explicit `VERIFIER`, then **verify `currentStateRoot`, the verifier address and `programVKey` on-chain before authorizing any deposit.**
- **A fresh gateway boot never compares its local genesis against the deployed contract.** Continuity checking only runs when `gw.l1_status` already exists (`main.rs:6355`), and fresh genesis initializes it to `None` (`:1610`). So a wrong or zero deployed genesis is accepted, deposits are taken, and the mismatch only surfaces at the first settle. Add the comparison at boot.
- **Bond ordering was wrong in an earlier draft.** The contract checks the bond *at settlement*, not before proving (`DarkPerpSettlement.sol:324-325`), and `requiredBond` scales with post-deposit TVL (`:228`). So the bond must be posted against **projected** TVL before step 4, or re-posted after step 4 and before proving.
- Anyone can trigger close-only after the liveness timeout (`:406-413`), after which deposits are refused (`CollateralVault.sol:186-191`) and normal bootstrap settlement becomes impossible. **Express the window in blocks** (`livenessTimeoutBlocks`, default 7200, `Deploy.s.sol:53`) — not wall-clock, which is not stable across chains. Bootstrap must complete inside it.
- **Correction:** an earlier draft claimed the wipe must remove the rollback journal "or the dishonest genesis survives". **That is false** — with the snapshot absent the gateway fresh-boots and explicitly deletes a leftover journal without applying it (`main.rs:6227`); only the snapshot can make `boot_restored` win (`:6143`). Wiping both is still required, but for the format cutover, not for genesis honesty.

## Testing

| Case | Expected |
|---|---|
| Encoded settle selector vs `DarkPerpSettlement.settleBatch` | byte-identical — the mismatch is the current bug |
| A real prove response decodes | passes — pins boundary 1, which fails today |
| Settle with `depositsRoot` + count against a vault prefix | accepted on match, reverts on mismatch |
| **Production boot** | zero notes, positions, insurance, `external_in`; deposit tip and count zero |
| `fund_amount_unbacked` reachable in prod | impossible — asserted at the call sites |
| `/v1/lp/*` mounted in prod | not mounted |
| House-MM counter-order generated in prod | none |
| Demo/dev boot | unchanged — the seeded demo still works |
| **First settle after an honest genesis, empty vault, no deposits** | accepted (`depositsRoot` == zero prefix) — pins that an empty genesis does not wedge |
| Bootstrap batch: `Deposit` → `FundInsurance` | settles against the real vault prefix |
| Order ingress before the bootstrap batch settles | refused, through the **real HTTP handler** (`POST /v1/orders`) |
| Gate survives a restart mid-bootstrap | still closed; rolls forward correctly from the journal |
| **Operator confirm-deposit-then-fund-insurance** (§1a) | leaves no dangling unspent note on either success or mid-failure |
| Boot against a contract whose genesis root differs from the local one | refused at boot, **before** any deposit is accepted |
| Production start with `PROVER_URL` unset or `mock` | refused |
| `/v1/markets/:id/orderbook` with an empty book | reports empty — **not** synthetic depth |
| A partially filled order | reports the real filled size and average, not the full order size |
| An IOC with no liquidity | reports cancelled, not `ACCEPTED` |
| A sealed resting order | cancellable through the API |

The last three are the ones that would have caught the original design: the gate was specified as a procedure, and a procedure cannot be tested.
