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

Both are disabled in production. This is a scope decision, and it removes three problems at once:

- The MM needs no capitalization, so the unconstructible bootstrap disappears.
- `pool_transfer` becomes unreachable in production, so the live tip-corruption path closes.
- `lp_total_shares` starting at zero would otherwise let the first LP depositor mint shares equal to their deposit while redeeming against total pool equity (`main.rs:2994-3026`) — an ownership-capture bug that only exists *because* genesis becomes honest. Disabling LP closes it rather than requiring a redesign of LP accounting.

Cost, stated plainly: **the alpha has no house liquidity.** Users match only against each other. That is the honest trade for an exchange that cannot yet capitalize an MM with real funds.

Mechanically: do not mount `/v1/lp/*` in production, and do not generate house-MM counter-orders. `fund_amount_unbacked` stays for demo/dev builds but must be unreachable when `prod` is set — enforced at the call sites, not by an assert inside the helper, which would turn a request into a panic.

### 2. Honest genesis

Genesis contains **markets only**: zero notes, zero positions, zero insurance, `external_in == 0`, `external_out == 0`, deposit count zero, deposit tip zero.

This is viable — `State::new` initializes every relevant field to zero (`crates/perp-core/src/state.rs:73-90`) and market registration installs only market and default-funding state (`:94-109`). Empty note and position sets are supported.

`seal_genesis_baseline` becomes unnecessary in this shape, because `add_market` already refreshes `window_start_state` (`crates/sequencer/src/lib.rs:430-450`). Keep the call but make it **assert** the honest invariants in production rather than silently folding unexpected boot ops.

The mode must reach `Gw::boot()` as a parameter; `gw.prod` is set too late to guard it.

### 3. Complete the SEC-019 wiring

- `ProveResp` emits `deposits_root` **and** the post-state deposit count; `ProveOutcome`, the HTTP parser, and the gateway's independent commitment cross-check carry both.
- Prefer deriving the count from the gateway's **own** witness in `prove_and_prepare` rather than trusting the service's response — the count is otherwise an unbound field from an untrusted service.
- `L1::settle_proved` uses the seven-root + count selector. The legacy `L1::settle` is either updated or **refused** when a SEC-019 contract is configured; silently taking the stale path is how this stayed hidden.
- `finalSettle`: decide explicitly whether it is an external governance runbook/tool or a gateway method. Governance may be a different key from the sequencer (`contracts/script/Deploy.s.sol:57`), so a gateway method raises key-custody questions. **Recommendation: runbook + script, not a gateway method.**

### 4. The bootstrap sequence and the trading gate

1. Boot with an honest genesis; compute `GENESIS_ROOT` from it.
2. Deploy `SP1ZkVerifier`, `DarkPerpSettlement` (constructed with that root) and `CollateralVault`.
3. Post the settlement bond — deposits raise `requiredBond` and settlement rejects while underbonded (`DarkPerpSettlement.sol:324-325`).
4. Make **real** vault deposits for insurance capital and any operator float.
5. Prove and settle a **bootstrap batch**: the resulting `Deposit` ops followed by `FundInsurance`.
6. **Enable order ingress only after that batch settles.**

Step 6 needs a real mechanism, not a procedure. It requires: a durable, fail-closed bootstrap flag; a predicate on the *actual* expected state (bootstrap root and deposit count, and a non-zero insurance balance) rather than `batchCount > 0`; correct roll-forward across a crash or restart; and a test that drives the real HTTP handler, since the gateway is necessarily online during bootstrap to register accounts and confirm deposits.

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

- `GENESIS_ROOT` defaults to zero in the deploy script (`contracts/script/Deploy.s.sol:49-53`); a markets-only root is non-zero.
- Omitting `VERIFIER` silently deploys `MockZkVerifier` (`:60-76`).
- The bond must be funded and posted before proving (`DarkPerpSettlement.sol:324-325`).
- Anyone can trigger close-only after the liveness timeout (`:406-413`), after which deposits are refused (`CollateralVault.sol:186-191`) and normal bootstrap settlement becomes impossible — so bootstrap must complete inside that window.
- **The state wipe must remove the snapshot *and* the rollback journal**, or `boot_restored` wins over `Gw::boot()` (`main.rs:6143-6166`) and the dishonest genesis survives the cutover.

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
| Order ingress before the bootstrap batch settles | refused, through the **real HTTP handler** |
| Gate survives a restart mid-bootstrap | still closed; rolls forward correctly |

The last three are the ones that would have caught the original design: the gate was specified as a procedure, and a procedure cannot be tested.
