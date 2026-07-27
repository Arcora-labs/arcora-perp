# SEC-024 — Insurance capitalization must be L1-bound — Design

> **Sequencing.** Four findings now ship in one cutover. **SEC-025 (honest genesis + SEC-019 ABI
> wiring) is a prerequisite for all of them** — until it lands, `op_deposit` is not L1-bound
> end-to-end and this spec's central argument does not hold. The only other real dependency is
> SEC-023 → SEC-022 (the fill band needs a current oracle anchor). SEC-024 is otherwise independent;
> its position in the implementation order is not security-relevant, only the atomic release is.

**Finding:** SEC-024 [critical, proof-soundness] — `BatchOp::SeedInsurance` asserts that external collateral entered the system, with nothing binding that assertion to anything real. The guest proves it.

`op_seed_insurance` (`crates/perp-core/src/engine.rs:787-800`) raises `insurance_fund` and `external_in` together, consuming no note, referencing no L1 event, and requiring no authorization. Its own comment — *"Conservation-safe: `insurance_fund` and `external_in` rise together"* (`:786`) — is true and beside the point: the arithmetic balances precisely **because** the op fabricates both halves. What it manufactures is the accounting representation of external collateral.

**Exploit.** Mint fake insurance → create bad debt through fills → have the fabricated insurance absorb it → withdraw the counterparty's excess from the **real** vault. The withdrawal itself is legitimate — bound to a real `withdrawals_root` leaf, and the vault pays it. The fabrication happened upstream, in the accounting that made the position look solvent.

**Trust model.** See `2026-07-26-sec02x-threat-model.md`, which is canonical. No **production** API surface emits this op — the non-production `/api/simulate-adl` route does reach the replenish call (`main.rs:5615`, `:5872`) — and the prover cannot inject it, since the witness it receives is sealed. Only the gateway can, and a compromised gateway can already forge the oracle price outright. **So this is defence-in-depth under Phase 1, not a critical live hole.** It remains worth doing: it is cheap, and it removes the only *unbounded* external-value assertion in the circuit — a property worth having regardless of who can currently reach it.

## How this was found

Rather than reasoning from a named attack, every writer of external value in the proven transition was enumerated:

| Op | Assertion | Bound to |
|---|---|---|
| `op_deposit` (`engine.rs:371`) | `external_in +=` | The SEC-019 deposit hash-chain accumulator, whose tip is the 7th commitment word — **in `perp-core` and in Solidity. See the correction below: it is *not* bound on the live submission path.** |
| `op_withdraw` (`engine.rs:862`) | `external_out +=` | The paying path is bound to a `withdrawals_root` leaf; the vault pays only against a published root. `to = None` is an internal burn that pays nobody. |
| **`op_seed_insurance` (`engine.rs:795`)** | `external_in +=` | **Nothing.** |

`SeedInsurance` is the only *unbound-by-design* external-value assertion in the circuit.

## Correction history

Adversarial review (Codex) found three errors, all verified at source. The design survived; the claims around it did not.

1. **"`op_deposit` is L1-bound" is not true end-to-end.** `perp-core` folds the leaf and `DarkPerpSettlement.settleBatch` requires `depositsRoot` (`contracts/src/DarkPerpSettlement.sol:318`), but the gateway still calls the **six-root selector** and supplies neither `depositsRoot` nor the deposit count (`crates/gateway/src/l1.rs:439`). Repo gateway and repo Solidity are out of sync; the live deployment predates SEC-019, which is why settlement works today. **This is now SEC-025**, and this spec depends on it.
2. **The migration claim was wrong.** `SeedInsurance` is the **last** `BatchOp` variant (`engine.rs:109`), so replacing it in place shifts no earlier discriminant. Worse, the assumed fail-closed behaviour is false: `postcard::from_bytes` does not require the whole input to be consumed, so old `SeedInsurance` bytes would **silently mis-decode** into whatever variant took index 8 rather than failing.
3. **"Ownership is unconstrained" was imprecise.** `consume_note` still requires `H(spend_key) == note.owner` (`engine.rs:408`). The accurate statement is that there is **no destination-owner constraint** — the spender must still hold the note's spend key.

Review also corrected the sequencing: SEC-024 is independent of SEC-022 (which does not read insurance and leaves the waterfall untouched); only SEC-023 → SEC-022 is a genuine ordering dependency.

## Design

`op_fund_position` (`engine.rs:430-451`) already demonstrates the correct pattern: consume a real note, move its value, never touch `external_in`. Apply it to insurance.

```
variant 8: DeprecatedSeedInsurance { amount }            // retained, ALWAYS rejected
variant 9: FundInsurance { note_commitment, spend_key }  // consumes a real note
```

**Retain variant 8 as a rejected stub rather than removing it.** Replacing it in place would let old encodings decode as `FundInsurance` and consume subsequent bytes as its fields — a silent mis-parse. Keeping the discriminant means old bytes decode to their *original* meaning and are then deterministically rejected. Fail loudly, not quietly.

`FundInsurance` consumes a note and moves its value into `insurance_fund`. **`external_in` is not touched** — the value entered the system earlier through the L1-bound deposit path. Fabrication becomes impossible **without inventing an authorization mechanism**: the operator must actually send money. Authorization would prove permission; it would not prove collateral.

**`FundInsurance` needs a gateway path that does not exist yet — see SEC-025 §1a.** Every confirmed L1 deposit runs `Deposit` then immediately `FundPosition` in the same helper (`main.rs:1962` → `fund_amount`, `:3987-4013`), and `FundPosition` consumes the note (`engine.rs:430`). So there is no unspent note for `FundInsurance` to spend. SEC-025 scopes the operator-gated confirm-then-fund-insurance path; without it this op is unreachable in production.

**Constraints:**

- `consume_note(commitment, spend_key, None)` — no destination-owner constraint, the same form `op_withdraw` uses. Adding value to a communal backstop can only help the protocol, and letting third parties capitalize it is a feature. The spend key is still required, so nobody can donate another's note.
- **Require `asset_id == 0`** (the canonical quote asset). Without it this becomes wrong the moment non-canonical note assets become meaningful.

**Atomicity — required, not hygiene.** `consume_note` inserts the nullifier and removes the note immediately (`engine.rs:397-424`). A fallible `insurance_fund.checked_add(...)` afterwards would return `Err` with the note already destroyed; the sequencer logs an op only after successful application (`sequencer/src/lib.rs:468-482`), so live state would diverge from the op-log and wedge the next proof. Therefore: authenticate the note and precompute the new balance with checked arithmetic **first**, then insert the nullifier, remove the note, and commit. A test must force the insurance addition to overflow and assert byte-for-byte state equality.

*(The same partial-mutation ordering already exists in `Deposit`, `FundPosition`, `Withdraw`, `SeedInsurance` — `engine.rs:369, 440, 791, 861` — **and `Liquidate`**, which mutates the position through `apply_fill` before fallible vault and insurance arithmetic (`:651, :654, :666`) while maintenance records the op only on `Ok` (`sequencer/src/lib.rs:749`). Fixing them is out of scope here; SEC-022 fixes `op_fill`'s instance.)*

**Staging note:** the ordering above cannot be achieved by calling the current `consume_note` first — it inserts the nullifier and removes the note immediately. Validation must fetch the note, verify the spend key, asset and nullifier, and precompute the new insurance balance **before** anything is inserted or removed. With exclusive `&mut State`, the final nullifier insertion, note removal and balance assignment are then infallible.

**Fee accrual is unchanged.** `op_fill` still credits `taker_fee − maker_rebate − treasury_fee` (`engine.rs:569-578`) and liquidation penalties still flow in (`:663-669`) — internal, value-preserving transfers that were never part of this finding.

### Genesis

Boot currently applies `SeedInsurance` directly (`crates/gateway/src/main.rs:1567-1571`) and folds it into the genesis baseline. That stops.

**`insurance_fund` starts at 0**, capitalized after deploy by a real L1 deposit followed by `FundInsurance`. There was never real collateral behind the genesis insurance — the op asserted it.

**But removing this seed does not by itself make genesis honest.** Boot also funds the MM and demo user through `fund_amount_unbacked`, whose own comment admits the ops carry sentinel L1 fields and fold a tip the vault will not match (`main.rs:3949`) — roughly three orders of magnitude more fabricated value than the insurance seed. **That is SEC-025**, and this spec's genesis change is incomplete without it.

**Capitalization must settle before trading is enabled.** With zero insurance, the first bad debt goes straight to ADL (clawing real users) or, absent winners, parks the debt and trips `Mode::CloseOnly` (`engine.rs:697`) — from which **there is no proven transition back**; only `EnterCloseOnly` exists (`engine.rs:304`). A later `FundInsurance` cannot repair an already-closed negative position, because liquidation requires an open one (`engine.rs:640`), and withdrawals remain permitted in close-only (`engine.rs:854`). One early gap could therefore wind the deployment down permanently. Gate order ingress on the bootstrap batch being settled.

## Scope

- **`crates/perp-core`** (guest): `SeedInsurance` → always-rejected `DeprecatedSeedInsurance`; add `FundInsurance` + `op_fund_insurance` with the staged-mutation ordering above; new `EngineError` variants.
- **`crates/gateway`**: boot no longer seeds insurance; the demo replenish path (`main.rs:2892`) is removed or converted.
- **`crates/sequencer`**: the test-boot construction site (`lib.rs:1614`).
- **Runbook**: post-deploy capitalization becomes an explicit cutover step, gated before trading.

**Non-goals:**

- **An insurance withdrawal path.** None exists; none added.
- **Fixing the other ops' partial-mutation ordering.** Noted above, tracked separately.
- **`TreasuryToInsurance`.** `state.rs:53` claims treasury can be paid out **or** injected into insurance as a final backstop. **Neither path exists**, and the waterfall goes insurance → ADL → CloseOnly (`engine.rs:684`). So with insurance at zero, users are ADL'd while treasury funds sit stranded. Correct the doubly-false comment now even though both features stay deferred; an operator-directed transfer would need authorization, since it confiscates operator revenue. **Follow-up.**
- **SEC-026 / SEC-027** — see `2026-07-26-sec026-sec027-open-findings.md`. SEC-026 (a real deposit can be permanently unspendable, because commitment uniqueness is checked against the live UTXO set while nullifiers are retained forever) directly threatens this spec's bootstrap, which deliberately leaves a note unspent between `Deposit` and `FundInsurance`. SEC-027 (CloseOnly can strand collateral in unmatched open positions) is what makes "insurance starts at zero" a live risk *after* launch, which SEC-025's pre-launch gate does not cover.
- SEC-025, SEC-023 and SEC-022, each its own spec.

## Migration

| Change | Consequence |
|---|---|
| Variant 8 becomes a rejected stub; `FundInsurance` added at 9 | **No discriminant shift.** Old `SeedInsurance` bytes decode to their original meaning and are rejected deterministically |
| Guest ELF changes | **vkey re-pin** → new `SP1ZkVerifier` **and** Settlement deploy (`programVKey` and the verifier address are immutable — `SP1ZkVerifier.sol:12`, `DarkPerpSettlement.sol:70`) |
| `insurance_fund` no longer seeded at boot | genesis `state_root` differs → **`GENESIS_ROOT` moves** |

The cutover must explicitly bump or invalidate: the snapshot magic, **now `DPSNAP2`** (`crates/gateway/src/snapshot.rs`, `MAGIC`), the rollback-journal magic, **now `DPRBJL2`** (`crates/gateway/src/rollback_journal.rs`, `MAGIC`) — both bumped from `…1` when SEC-022 added a `Market` field, so grep for the constant name rather than the value — any pending sealed-witness plaintext, gateway snapshots carrying `Sequencer.window_ops`, and the recorded genesis root / vkey in deployment metadata. SEC-022 and SEC-023 already force a full format break; the point here is that **SEC-024's stated reason for one was wrong**, and the magic-bump requirement is the real mechanism.

## Testing

| Case | Expected |
|---|---|
| **Fabrication regression:** exactly one writer of `external_in`, and it is `op_deposit` | must be a real check — a static assertion or module-visibility restriction, **not** a review instruction. `external_in` is currently `pub` (`state.rs:57`) |
| `FundInsurance` with a valid note | `insurance_fund` rises by the note amount; `external_in` **unchanged**; note consumed |
| Wrong spend key | rejected, no state change |
| Already-consumed note, including twice in one batch | rejected (nullifier) |
| `asset_id != 0` | rejected with **byte-for-byte unchanged state** — otherwise an implementation could call the mutating `consume_note` and only then check the asset |
| Wrong spend key / double-spend | rejected, **state unchanged** (not merely "no credit") |
| **Insurance `checked_add` forced to overflow** | `Err` with **byte-for-byte identical state** — the note must not be destroyed |
| `DeprecatedSeedInsurance` newly encoded | rejected deterministically |
| **A frozen legacy fixture encoded under the OLD enum** | decodes as variant 8, the amount survives, it is rejected, and surrounding ops in the vector stay aligned — this is what actually proves the migration; testing newly-encoded bytes does not |
| **Production** boot | `insurance_fund == 0` |
| **Demo/dev** boot | still seeded — SEC-025 keeps the demo path intact, so both this test and the replenish behaviour must be explicitly prod-versus-demo scoped, not one global expectation |
| Deposit → `FundInsurance` → bad debt → waterfall draws it | insurance absorbs; `conservation_holds()` |
| Fee accrual during fills | unchanged |
| Every scenario | `conservation_holds()` |

The first row is checkable by enumeration rather than imagination — and it only becomes *true* once SEC-025 lands.

## Carried in from SEC-022 (added 2026-07-27)

**These are not SEC-024's findings. They are `perp-core` changes deliberately deferred to this branch because it re-pins the vkey anyway**, and doing them here costs nothing extra. SEC-022's whole-branch review argued for folding them into *its* branch on the same reasoning; they were deferred here instead because `DeprecatedSeedInsurance`/`FundInsurance` already moves the guest ELF within the same cutover bundle, so the marginal cost is identical and SEC-022 stays single-concern.

**If this spec is descoped or resequenced, these must move with it, not be dropped.** `SP1ZkVerifier.programVKey` and `DarkPerpSettlement`'s verifier address are both immutable, so once the bundle deploys, either item costs a full live cutover on its own.

1. **`EngineError::Risk` carries no failing leg** (`engine.rs:598`). `check_initial_margin(...)?` discards the `leg` variable that is already in scope three lines above. Consequence: SEC-022's dry-run bans and rolls back the book only for *attributable* failures, and `Risk` → `InsufficientMargin` is not attributable — so the drifted-resting-maker case, which `settle_fills`' own doc comment calls the canonical one, still matches, consumes the innocent counterparty's depth, and is dropped at settlement. Fix: give `Risk` the same `FillLeg` payload `FillWouldBankrupt` already carries, then add it to `offending_leg`. `EngineError` must stay `Copy`.

2. **`op_liquidate` is not failure-atomic.** `engine.rs:733` mutates the position via `apply_fill`, then `:734` and `:748` perform fallible arithmetic; `Sequencer::run_maintenance` (`sequencer/src/lib.rs:906`) takes `if let Ok(...)` and **silently drops a failed liquidation without logging the op**. That is exactly the host/guest divergence class SEC-022 §4 closed for `op_fill` — mutated live state, no op in the replayable log, wedged next proof. It matters more now than before: SEC-022's solvency postcondition forbids a below-maintenance position from partially closing, so liquidation is its only resolution and receives strictly more traffic. Fix mirrors §4: stage every fallible value before the first mutation.

`op_liquidate`'s partial-mutation ordering is also listed among the known gaps in `2026-07-26-sec02x-threat-model.md`'s sibling notes; this is the same defect, now with a concrete reason to fix it.
