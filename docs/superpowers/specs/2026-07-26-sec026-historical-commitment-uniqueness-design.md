# SEC-026 — Historical commitment uniqueness — Design

> **Sequencing: first of the cutover bundle.** SEC-025's decomposition puts this ahead of 025-A,
> because 025-A's failure mode *is* this bug: a `Deposit` that commits, followed by a `FundInsurance`
> that cannot spend the resulting note. Fixing uniqueness removes that class of partial mutation from
> the bootstrap. Threat model: `2026-07-26-sec02x-threat-model.md`.

**Finding:** SEC-026 [high, fund loss] — a real L1 deposit can be credited and then be permanently unspendable, because commitment uniqueness is checked against the **live UTXO set** while nullifiers are retained **forever**. The two disagree.

`op_deposit` rejects a duplicate only if the commitment is still unspent (`crates/perp-core/src/engine.rs:365-367`):

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

1. Spend it. The nullifier is retained; the commitment leaves `notes`.
2. A later **real L1 deposit** reconstructs the same four fields, hence the same commitment.
3. `notes.contains_key(cm)` is false, so the deposit is **accepted** — `external_in` rises, the leaf folds into the SEC-019 deposit chain, and the vault genuinely holds the money.
4. Every later spend (`FundPosition`, `Withdraw`, `FundInsurance`) recomputes `nullifier = H(cm, spend_key)`, hits `nullifiers.contains(nf)`, and returns `UnknownOrSpentNote`.

**The money is credited and frozen.** `conservation_holds()` still passes — the value is inside `notes_value()`, simply unspendable — which is why no existing invariant catches it.

## Reachability

The commitment is fully determined by `(owner, asset_id, amount, blinding)` (`note.rs:43-56`), so a collision needs all four to repeat. Blinds are derived from per-account or per-flow counters — `fund_amount` uses `0xB0` + `deposit_counter`, `account_withdraw` uses `0xD0` + nonce, `pool_transfer` uses `0xE0`/`0xE1` + `lp_counter` — so the ordinary path does not repeat a tuple while its counter advances monotonically.

**But the invariant is not enforced anywhere; it is merely a property of how the gateway happens to pick blinds today.** Anything that resets or re-derives a counter — a snapshot restore that rewinds it, a namespace collision between the `0xB0`/`0xD0`/`0xE0` prefixes, or a future caller that chooses its own blind — reintroduces it. And `blinding` is a caller-supplied field of `BatchOp::Deposit` (`engine.rs:41-49`), so the circuit accepts whatever the host provides.

The existing duplicate test only covers duplication while the first note is **still unspent** (`crates/perp-core/tests/lifecycle.rs:827`), which is exactly the case that already works.

## Design

**Uniqueness must be historical, not UTXO-set.** Add a permanent, append-only set of every commitment ever created, and check `op_deposit` against it.

```rust
// crates/perp-core/src/state.rs
pub commitments: CommitmentSet,   // append-only, mirrors NullifierSet
```

`op_deposit` checks `self.commitments.contains(&cm)` instead of `self.notes.contains_key(&cm)`, and inserts on success.

**Why this shape rather than something cleverer.** The nullifier set is already an unbounded, append-only, state-root-bound `BTreeSet<Digest>` with an O(1) running hash chain (`crates/perp-core/src/nullifier.rs:15-60`). A commitment set is the same shape, the same growth profile, and the same soundness argument — insertion happens only on the deterministic transition path, so the chain is order-stable in both the native and guest executions. Reusing an established, reviewed pattern is worth more here than inventing one.

Growth is one 32-byte digest per deposit, permanently. That is the cost the nullifier set already pays and which the design already accepts.

### Alternative considered and rejected

**Bind `deposit_id` into the commitment preimage.** `deposit_id` is strictly monotonic and already enforced (`engine.rs:358-360`, `DepositOutOfOrder`), so including it would make repeats impossible *by construction* with no new state and no growth. Rejected because it changes `Note::commitment`, which is a wider blast radius than the bug warrants: the commitment KAT, every merkle leaf, the note archive, and client-side note reconstruction all key on it. If growth ever becomes a real constraint, this is the upgrade path.

**Deriving the blind in-circuit** was also considered and is wrong: `blinding` is the hiding factor, and a value the circuit derives deterministically is not hiding.

### Where the check belongs

In `op_deposit` only. `consume_note` is unchanged — the nullifier set already does its job correctly; the defect is entirely on the creation side.

Note that the *tree* (`state.rs:37`) already appends every commitment permanently, but a Merkle accumulator cannot answer membership by value without an index — which is what the new set is.

## Migration

| Change | Consequence |
|---|---|
| New `State.commitments` field bound into `state_root` | **`GENESIS_ROOT` moves**; guest ELF changes → **vkey re-pin** |
| `DefaultState` postcard encoding changes | witness plaintext, sealed-witness ciphertext, gateway + sequencer snapshots, `window_start_state`, rollback journals |

Both are already required by the rest of the cutover bundle (SEC-022's `Market` field, SEC-024's `BatchOp` change), so this adds no *new* class of migration — it rides the same wipe and the same vkey re-pin.

**Backfill:** on a fresh genesis the set starts empty, which is correct and needs no migration. The cutover already wipes state, so there is no live set to reconstruct.

## Testing

| Case | Expected |
|---|---|
| **Fund-loss regression:** deposit → spend → deposit the *same* `(owner, asset, amount, blinding)` again | second deposit **rejected** `DuplicateCommitment` — today it is accepted and the money is frozen |
| Duplicate while the first note is still unspent | rejected (existing behaviour, `lifecycle.rs:827`, must keep passing) |
| Two deposits differing only in `blinding` | both accepted |
| Rejected duplicate | **state byte-for-byte unchanged** — no tree append, no `external_in`, no deposit-count advance |
| A note spent and its commitment never reusable thereafter | property test over deposit/spend/deposit sequences |
| `commitments` participates in `state_root` | binding test, in the style of `state.rs:392-406` |
| Genesis | `commitments` empty |
| Every scenario | `conservation_holds()` |

The first row is the whole finding: it fails today by *accepting* the deposit, and the failure is silent — the money is credited, the accounting balances, and only the eventual spend reveals it.
