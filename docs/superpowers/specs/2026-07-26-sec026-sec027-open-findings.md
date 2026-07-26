# SEC-026 and SEC-027 — open findings, not yet designed

Both surfaced during the SEC-024 review and are **independent of SEC-022…SEC-025**. Recorded precisely rather than designed, because each needs its own cycle and this workstream has already shown what happens when a spec is written before its ground is checked.

Threat model: `2026-07-26-sec02x-threat-model.md`.

---

## SEC-026 [high, fund loss] — a real deposit can be permanently unspendable

**Commitment uniqueness is checked against the live UTXO set; nullifiers are retained forever.** The two do not agree.

`op_deposit` rejects a duplicate only if the commitment is in the *current* unspent map (`crates/perp-core/src/engine.rs:365-367`):

```rust
let cm = note.commitment::<H>();
if self.notes.contains_key(&cm) {
    return Err(EngineError::DuplicateCommitment);
}
```

`consume_note` inserts the nullifier permanently and removes the note (`engine.rs:420-422`):

```rust
let _ = self.nullifiers.insert::<H>(nf);
self.notes.remove(note_commitment);
```

So for a note `(owner, asset_id, amount, blinding)`:

1. Spend it — nullifier retained, commitment leaves `notes`.
2. A later **real L1 deposit** reconstructs the same tuple, so the same commitment.
3. `notes.contains_key(cm)` is now false, so the deposit is **accepted**: `external_in` rises, the leaf folds into the deposit chain, the vault holds the money.
4. Any later `FundPosition` / `Withdraw` / `FundInsurance` derives the same nullifier, hits `nullifiers.contains(nf)`, and returns `UnknownOrSpentNote`.

**The deposit is credited and permanently unspendable.** Conservation still holds — the value is simply frozen — which is why no existing invariant catches it.

Blinds are derived from per-account counters (`fund_amount` uses `0xB0` + `deposit_counter`; `account_withdraw` uses `0xD0` + nonce; `pool_transfer` uses `0xE0`/`0xE1` + `lp_counter`), so the normal path does not repeat a tuple while a counter advances monotonically. Reachability therefore hinges on whether any counter can reset or collide across namespaces — which is exactly the kind of assumption that should be enforced, not relied upon.

**The invariant is wrong as written: commitment uniqueness must be historical, not UTXO-set uniqueness.** The existing test only covers duplication while the first note is still unspent (`crates/perp-core/tests/lifecycle.rs:827`).

Directly relevant to SEC-025 §1a: its bootstrap deliberately leaves a note unspent between `Deposit` and `FundInsurance`, so it must not be able to recreate a spent commitment.

---

## SEC-027 [high, liveness] — `CloseOnly` can permanently strand collateral in open positions

`CloseOnly` is reachable by design as the bad-debt terminal (`engine.rs:697`) and by anyone after the L1 liveness timeout (`contracts/src/DarkPerpSettlement.sol:406-413`). Once entered, some users may have no path out.

The chain, each step verified:

- Liquidation closes **only the bankrupt side** (`engine.rs:650`).
- ADL haircuts a winner's **collateral without reducing its size** (`engine.rs:708`).
- So unmatched open interest remains after the waterfall.
- In `CloseOnly`, a fill is rejected if **either** leg increases exposure (`engine.rs:491`), so nobody may open the counter-position a stranded winner needs to close against.
- There is **no unilateral force-close** in `BatchOp`.
- `Unbind` cannot release the collateral either — it re-checks initial margin while the position is open (`engine.rs:835`).

So "withdrawals remain permitted in close-only" — true, and stated in the SEC-02x specs — applies only to **existing notes**. Collateral sitting inside an unmatched open position has no proven exit. `finalSettle` does not help: it lands proof-valid transitions, it does not manufacture a missing close.

Zero-genesis insurance (SEC-024) does not cause this, and SEC-025's trading gate does not prevent it: the gate protects the pre-launch window, while this bites after trading begins, whenever a gap exhausts finite insurance and available ADL headroom.

**This needs either a forced-exit / settlement-price close transition, or an explicit, documented launch limitation with a regression test pinning the stranded case.** It should not be discovered by a user.

---

## Folded into SEC-024 rather than tracked here

- `op_liquidate` has the same partial-mutation ordering as the ops SEC-024 lists — it mutates the position through `apply_fill` before fallible vault and insurance arithmetic (`engine.rs:651`, `:654`, `:666`), and maintenance records the op only on `Ok` (`sequencer/src/lib.rs:749`), so an overflow mutates live state without an op-log entry.
- `state.rs:53` claims treasury can be paid out **or** injected into insurance. **Neither path exists.** Correct the comment even though both features stay deferred.
- Unchecked `sum`/addition in `notes_value`, `positions_collateral`, `internal_value` (`state.rs:112-127`) can panic or wrap at extreme i128 scale, weakening the conservation checker itself. No practical mint was found through it; hardening defect.
