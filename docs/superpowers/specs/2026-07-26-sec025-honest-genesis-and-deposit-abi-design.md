# SEC-025 — Honest genesis + SEC-019 deposit ABI wiring — Design

> **Sequencing: PREREQUISITE for SEC-022, SEC-023 and SEC-024.** All three reason about a proven
> transition whose external value is L1-bound. Until this lands, it is not — and the first settle
> against a SEC-019 contract reverts. This is the finding that actually blocks the pending cutover.

**Finding:** SEC-025 [critical, deployment-blocking + proof-soundness] — the deposit binding SEC-019 designed is **not wired end-to-end**, and genesis contains fabricated collateral that the on-chain accumulator will reject.

Two independent halves, both verified at source:

### Half 1 — the gateway calls the wrong ABI

`DarkPerpSettlement.settleBatch` takes seven roots including `depositsRoot`, and checks it against the vault's chain prefix (`contracts/src/DarkPerpSettlement.sol:305-318`, `:311` — `require(depositsRoot == prefixTip, "deposits: root != L1 chain prefix")`).

The gateway calls the **six-root selector**:

```rust
// crates/gateway/src/l1.rs:439
"settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes)"
```

It supplies neither `depositsRoot` nor the post-state deposit count, and `ProveOutcome` carries a `deposits_root` but no count (`crates/gateway/src/prover_client.rs:19`).

So repo gateway and repo Solidity are out of sync. **Against the current Solidity source every settlement call hits the wrong selector and reverts.** Settlement works on the live testnet only because the deployed contract predates SEC-019 (the live stack was deployed 2026-07-11; SEC-019 merged after), so nothing checks the deposit prefix today.

### Half 2 — genesis fabricates collateral

Boot funds every market's MM and the demo user *before* genesis (`crates/gateway/src/main.rs:1543`), via `fund()` → `fund_amount_unbacked` (`main.rs:3930`). That helper's own comment states the problem (`main.rs:3949`):

> an UNBACKED credit — a `Deposit` op with SENTINEL L1-leaf fields (`from=[0;20]`, `deposit_blind=[0;32]`, `deposit_id` = the live consumed count so the strict in-order gate passes) … those fold a `consumed_deposit_tip` the on-chain vault chain will NOT match, so they can never settle in `prod`.

The reasoning behind that comment is that production disables the self-service paths (DP-001). But **boot calls it unconditionally**, and `seal_genesis_baseline` folds the result into the genesis root (`main.rs:1572`). So a production genesis carries fabricated deposits *and* an advanced `consumed_deposit_tip`.

Consequence: the moment a SEC-019 contract is deployed, the first settle presents a non-zero `depositsRoot` against an empty vault whose prefix reads zero (`DarkPerpSettlement.sol:301`, `contracts/src/CollateralVault.sol:59`) — **revert, permanently, on batch one.**

### Why this outranks the other three

SEC-022, SEC-023 and SEC-024 all reason about a system whose external value is anchored to L1. SEC-024's central claim is literally "after this change `external_in` has exactly one writer and it is L1-bound". That is false while Half 1 is open, and genesis is dishonest while Half 2 is open — by roughly three orders of magnitude more value than the insurance seed SEC-024 removes.

## Design

### 1. Complete the SEC-019 submission path

- `ProveOutcome` carries the post-state deposit **count** alongside `deposits_root`.
- `L1::settle_proved` calls the seven-root selector and supplies both.
- The same treatment for `finalSettle` (`DarkPerpSettlement.sol:387`), which independently recomputes `publicCommitment`.

This is integration wiring, not new protocol: the circuit already derives `deposits_root`, and the contract already knows how to check it. Nothing about the binding needs redesigning — it simply was never connected.

### 2. An honest genesis

Genesis contains **markets only**. Specifically: zero notes, zero positions, zero insurance, `external_in == 0`, `external_out == 0`, deposit count zero, deposit tip zero.

`fund_amount_unbacked` is removed from the boot path. It may remain for demo/dev builds, but it must be unreachable when `prod` is set — the same fail-closed posture `account_deposit` already takes (`main.rs:2285-2294`, audit DP-001).

### 3. The bootstrap sequence

Capitalization becomes an explicit, ordered cutover procedure rather than a fiction folded into genesis:

1. Boot with an honest genesis; compute `GENESIS_ROOT` from it.
2. Deploy `SP1ZkVerifier`, `DarkPerpSettlement` (with that genesis root) and `CollateralVault`.
3. Make **real** vault deposits: MM working capital, insurance capital, and any demo/user float.
4. Prove and settle a **bootstrap batch** containing the resulting `Deposit` ops followed by `FundPosition` / `FundInsurance`.
5. **Enable order ingress only after that batch settles.**

Step 5 is not ceremony. With zero insurance, the first bad debt goes straight to ADL against real users or — absent winners — parks the debt and trips `Mode::CloseOnly`, from which there is **no proven transition back** (only `EnterCloseOnly` exists, `engine.rs:304`), while withdrawals stay permitted (`engine.rs:854`). Opening trading before the backstop is real risks winding the deployment down permanently on the first gap.

## Scope

- **`crates/gateway`**: `ProveOutcome` gains the deposit count; `L1::settle_proved` and the `finalSettle` path use the seven-root ABI; boot stops calling `fund_amount_unbacked`; `fund_amount_unbacked` becomes unreachable in `prod`.
- **`crates/prover-service`** / **`crates/prover`**: surface the post-state deposit count in the prove response if not already carried.
- **Runbook**: the five-step bootstrap above, with the trading gate.

**Non-goals:**

- **Changing the SEC-019 accumulator design.** It is correct; it was not connected.
- **A migration path for the existing live state.** The pending cutover already requires fresh contracts and a state wipe; there is nothing to migrate.
- **The `TreasuryToInsurance` gap** (`state.rs:53` claims a backstop that does not exist) — tracked with SEC-024.
- SEC-022, SEC-023, SEC-024, each its own spec.

## Migration

This spec changes no proven code, so **no vkey impact of its own** — but it lands in the same cutover as three specs that do, and it changes `GENESIS_ROOT` by emptying genesis.

| Change | Consequence |
|---|---|
| Boot no longer fabricates deposits/insurance | **`GENESIS_ROOT` moves**; deposit tip and count start at zero |
| Gateway settle ABI | host-only; must match the deployed contract exactly |
| Bootstrap batch before trading | operational — new cutover steps |

Deploy order matters: the contract is constructed **with** the genesis root, so the honest genesis must be computed before deployment, not after.

## Testing

| Case | Expected |
|---|---|
| **ABI regression:** the encoded selector matches `DarkPerpSettlement.settleBatch` | byte-identical — a mismatch is the current bug |
| A settle carrying `depositsRoot` + count against a vault prefix | accepted on match, reverts on mismatch |
| **Production boot** | genesis has zero notes, zero positions, zero insurance, `external_in == 0`, deposit tip and count zero |
| `fund_amount_unbacked` reachable in `prod` | impossible — assert at the call sites, mirroring DP-001's posture |
| Demo/dev boot | unchanged — the seeded demo still works |
| Deposit → `FundPosition`/`FundInsurance` bootstrap batch | settles against a real vault prefix |
| First settle after an honest genesis, empty vault, no deposits | accepted (`depositsRoot` == zero prefix) — pins that an empty genesis does **not** wedge |
| Order ingress before the bootstrap batch settles | refused by the gate |

The last two rows are the ones that would have caught this: today's genesis produces a non-zero tip against a zero prefix, and nothing tests that combination because the deployed contract never checks it.
