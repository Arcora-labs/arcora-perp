# SEC-024 — Insurance capitalization must be L1-bound — Design

> **Sequencing: SECOND of three findings** split out of the SEC-022 review. SEC-023 (oracle
> time-binding) is first; SEC-022 (fill-price band + closed-position debt) is third. All three ship in
> one cutover — each changes the postcard encoding of the proven state or op set.

**Finding:** SEC-024 [critical, proof-soundness] — `BatchOp::SeedInsurance` asserts that external collateral entered the system, with nothing binding that assertion to anything real. The guest proves it.

`op_seed_insurance` (`crates/perp-core/src/engine.rs:787-800`) raises `insurance_fund` and `external_in` together, consuming no note, referencing no L1 event, and requiring no authorization. Its own comment — *"Conservation-safe: `insurance_fund` and `external_in` rise together"* (`:786`) — is true and beside the point: the arithmetic balances precisely **because** the op fabricates both halves. What it manufactures is the accounting representation of external collateral.

## How this was found, and why it is the only one

Rather than reasoning from a named attack, every writer of external value in the proven transition was enumerated. There are exactly three:

| Op | Assertion | Bound to |
|---|---|---|
| `op_deposit` (`engine.rs:371`) | `external_in +=` | **L1.** `from` + `deposit_id` + `deposit_blind` fold into the SEC-019 deposit hash-chain accumulator, whose tip is the 7th commitment word and is compared on-chain against the vault's own `depositChainTip`. A deposit cannot be fabricated. |
| `op_withdraw` (`engine.rs:862`) | `external_out +=` | The paying path is bound to a `withdrawals_root` leaf, and the vault only pays against a published root. The `to = None` path is an internal burn that pays nobody. |
| **`op_seed_insurance` (`engine.rs:795`)** | `external_in +=` | **Nothing.** |

So `SeedInsurance` is the *only* unbound external-value assertion in the circuit. That is a stronger statement than "here is a bug", and it is what makes the fix below sufficient rather than merely helpful.

**Exploit.** Mint fake insurance → create bad debt through fills → have the fabricated insurance absorb it → withdraw the counterparty's excess from the **real** vault. The withdrawal itself is entirely legitimate: it is bound to a real `withdrawals_root` leaf, and the vault pays it. The fabrication happened upstream, in the accounting that made the position look solvent.

**Trust model.** Not reachable through normal order ingress — no API surface emits this op. It is exploitable by whoever produces the witness, which is exactly the party the zk layer exists so as not to trust. "The operator wouldn't" is not a defence, and this is why it cannot be deferred behind the two findings that *are* reachable by users.

## Design

`op_fund_position` (`engine.rs:430-451`) already demonstrates the correct pattern: consume a real note, move its value into a destination, and never touch `external_in`. The value entered the system earlier, through the L1-bound deposit path.

Apply that pattern to insurance:

```
BatchOp::SeedInsurance { amount }                      →  REMOVED
BatchOp::FundInsurance { note_commitment, spend_key }  →  consumes a real note,
                                                          moves its value into insurance_fund
```

`external_in` is not touched. Value reaches the insurance fund only after entering the system as a genuine, SEC-019-bound L1 deposit. Fabrication becomes impossible **without inventing an authorization mechanism** — the operator must actually send money, which is the property that was missing.

**Note ownership is deliberately unconstrained.** `consume_note(commitment, spend_key, None)` — the same form `op_withdraw` uses — rather than binding to a designated owner. Adding value to a communal backstop can only help the protocol; there is no authorization concern to defend, and permitting third parties to capitalize the fund is a feature, not a gap. The spend key is still required, so nobody can donate someone else's note.

**Fee accrual is unchanged.** `op_fill` continues to credit `taker_fee − maker_rebate − treasury_fee` to `insurance_fund` (`engine.rs:569-578`), and liquidation penalties continue to flow in (`:663-669`). Both are internal, value-preserving transfers between terms of `internal_value()` and were never part of this finding.

### Genesis consequence — insurance starts at zero

Boot currently applies `SeedInsurance` directly (`crates/gateway/src/main.rs:1567-1571`, "capitalize the insurance fund so the backstop is visible from genesis") and folds it into the genesis baseline.

That is no longer possible, and the reason is the finding itself: **at genesis there is no L1 deposit, because the vault is empty.** There was never any real collateral behind the genesis insurance — the op simply asserted it.

So: **`insurance_fund` starts at 0**, and is capitalized after deploy by a real L1 deposit followed by `FundInsurance`. This is an operational change to the cutover, not a regression. The backstop is only load-bearing when bad debt occurs, and it grows from fees regardless; starting empty is the honest state rather than a fabricated one.

The boot sequence's genesis-baseline handling (`seal_genesis_baseline`, added during the 2026-07-09 migration) still applies to the remaining boot ops — one fewer op is folded in.

## Scope

- **`crates/perp-core`** (guest): remove `BatchOp::SeedInsurance` and `op_seed_insurance`; add `BatchOp::FundInsurance` and `op_fund_insurance`; a new `EngineError` variant if note consumption needs one beyond the existing note errors.
- **`crates/gateway`**: boot no longer seeds insurance; the demo replenish path (`main.rs:2892`) is removed or converted to the note-consuming form.
- **`crates/sequencer`**: any `SeedInsurance` construction sites (`lib.rs:1614` test boot).
- **Operational runbook**: post-deploy insurance capitalization becomes an explicit cutover step.

**Non-goals:**

- **An insurance withdrawal path.** None exists today and none is added; the fund is drawn only by the bad-debt waterfall.
- **A minimum-insurance policy or solvency gate.** Out of scope; SEC-022 governs what happens when the fund is insufficient.
- SEC-023 and SEC-022, each its own spec.

## Migration

| Change | Consequence |
|---|---|
| `BatchOp` variant removed and added | **Discriminants shift** → postcard witness encoding changes; the guest ELF changes → **vkey re-pin** |
| `insurance_fund` no longer seeded at boot | `state_root` at genesis differs → **`GENESIS_ROOT` moves** |
| Gateway boot + demo paths | host-only |

The `BatchOp` discriminant shift is the notable one: **any pending witness or rollback journal encoded under the old op set becomes undecodable.** They must be drained or explicitly invalidated before cutover — the same requirement SEC-022 and SEC-023 already impose for their `DefaultState` encoding changes.

All three findings must ship in **one cutover**. `GATE-1` applies: verify the built guest ELF's vkey **before** deploying the verifier.

## Testing

| Case | Expected |
|---|---|
| **Fabrication regression:** no op can raise `external_in` without a note or an L1-bound deposit | enumerable — assert the only `external_in` writer left is `op_deposit` |
| `FundInsurance` with a valid note | `insurance_fund` rises by the note amount; `external_in` **unchanged**; note consumed |
| `FundInsurance` with a wrong spend key | rejected, no state change |
| `FundInsurance` with an already-consumed note | rejected (double-spend) |
| Genesis boot | `insurance_fund == 0` |
| Deposit → `FundInsurance` → bad debt → waterfall draws it | insurance absorbs, `conservation_holds()` |
| Fee accrual to insurance during fills | unchanged from today |
| Every scenario | `conservation_holds()` |

The first row is the one that matters most, and it is checkable by enumeration rather than by imagination: after this change, `external_in` must have exactly one writer, and that writer is bound to L1. That is the property the finding was really about.
