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

**Reachability today, checked rather than assumed: there is no ordinary production HTTP sequence that triggers it.** The five blind namespaces cannot collide with each other — the fifth, `0xA0 ‖ deposit_counter` in self-service `account_deposit` (`main.rs:2310`), shares the counter with the `0xB0` path but differs in its trailing tag bytes — each overwrites only the first eight bytes, leaving the trailing 24 as `B0`/`D0`/`E0`/`E1` respectively (`main.rs:1956`, `:2077`, `:2946`). The counters are serialized fields of `Account`/`Gw` (`main.rs:949`, `:1027`) and snapshots serialize the whole `Gw` under one lock (`:1642`, `:6461`), so a restore rewinds counters and engine state *together*. A restored snapshot with a stale settled root is rejected outright (`:6351`). Account re-registration restarts the counter but generates a **new random wallet**, hence a different `owner` (`:1721`). Window rollback requeues ops without restoring gateway counters (`sequencer/src/lib.rs:1121`).

So the bug is **genuinely latent under the current production API**, not presently user-exploitable. It is immediately reachable by a host-supplied `BatchOp` sequence, and the non-production demo does repeat blinds on a `tick % 60` cycle (`main.rs:3318`, `:3334`) — but those mutation routes are omitted in production (`:5849`).

**The invariant is nonetheless unenforced; it is a property of how the gateway happens to pick blinds.** `blinding` is a caller-supplied field of `BatchOp::Deposit` and `BatchOp::Unbind` (`engine.rs:41-49`), so the circuit accepts whatever the host provides — which is exactly the kind of assumption that should be structural rather than incidental.

The existing duplicate test only covers duplication while the first note is **still unspent** (`crates/perp-core/tests/lifecycle.rs:827`), which is exactly the case that already works.

## There are TWO mint paths, not one

An earlier draft of this design checked `op_deposit` only, and contradicted itself by claiming to cover "every commitment ever created". **`op_unbind` is structurally identical to the vulnerable half of `op_deposit`**: it builds a note, checks only the live `notes` map, appends to the tree and inserts (`engine.rs:803`, `:843`, `:845`).

So the bug has three more shapes beyond the deposit one:

- `Unbind → Withdraw → Unbind` with the same tuple — the second unbind debits position collateral and mints an unspendable note.
- `Unbind → spend → Deposit` — bypasses a set populated only by deposits.
- `Deposit → spend → Unbind` — bypasses a check performed only in `op_deposit`.

**Every successful `tree.append(cm)` / `notes.insert(cm, note)` must be gated, through a single shared mint primitive** rather than two parallel checks that can drift. Nothing legitimately depends on reuse: the tree is explicitly permanent (`merkle.rs`), and the note archive keys ciphertexts by commitment (`crates/note-archive/src/lib.rs:147`), so a reused commitment would collide there too.

## Design — the historical list already exists; index it

**Chosen at implementation time, after verifying a fact both earlier options had missed:** `MerkleTree.leaves` is a dense, insertion-ordered `Vec<Digest>` that **is serialized** (`merkle.rs:28-36` — the struct derives `Serialize`/`Deserialize` and `leaves` carries no `serde(skip)`), and the tree root is bound into `state_root`. So the authoritative, root-bound list of every commitment ever appended is **already in state**.

That makes both options below unnecessary:

- A separate `CommitmentSet` would **duplicate** that list and reintroduce exactly the divergence risk documented for `NullifierSet` — two structures that can disagree, with only one of them anchored.
- The creation counter would change `BatchOp` semantics and client reconstruction for a guarantee the existing data can already provide.

**Design:** a membership index over `tree.leaves`, held as a `#[serde(skip)]` field and rebuilt on construction and on deserialize, consulted by a **single shared mint primitive** that both `op_deposit` and `op_unbind` call.

Properties this buys:

- **No new serialized state.** `state_root` is unchanged, `GENESIS_ROOT` does not move, and the postcard encoding of `DefaultState` is untouched — so unlike the rest of the cutover bundle, **SEC-026 needs no state migration at all.** Only the guest ELF changes, hence a vkey re-pin.
- **The index cannot diverge from the anchor**, because it is derived from it rather than maintained beside it. That is precisely the failure mode `NullifierSet` has.
- O(log n) membership instead of the O(N)-per-mint scan the alternative would have cost, at the price of an O(n log n) index build per deserialize — on data the guest already deserializes.

Bound: leaves are capped by the tree depth (24 at the current `Sequencer::new(enclave, 24)`, ≈16.7M).

## Alternatives considered (superseded by the above)

**Mix a state-bound, globally monotonic note-creation counter into the blind at every mint path.**

```
blind = H(Domain::NoteBlind, [caller_entropy, note_creation_counter])
```

with `note_creation_counter` a `State` field incremented on every mint (deposit and unbind alike). Collisions become impossible **by construction**: two mints can never share a counter value, so they can never share a commitment.

Why this over a historical set, having reconsidered the costs review raised:

- **Constant state.** A set grows once per *deposit and unbind*, forever, and duplicates commitments the Merkle tree already stores in `leaves` (`merkle.rs:33`). `digest()` being O(1) does **not** make witness size, postcard decoding, `BTreeSet` insertion, or SP1 guest memory O(1) — and this runs in the circuit.
- **No membership lookup at all**, in or out of circuit. The alternative of scanning `MerkleTree.leaves` avoids a second structure but is O(N) per mint inside the guest, growing without bound.
- **It sidesteps a real flaw in the pattern the earlier draft proposed to copy** — see below.

`blinding` stays hiding: `H(domain, caller_entropy, counter)` is hiding as long as `caller_entropy` is secret. An earlier draft's claim that "a value the circuit derives is not hiding" was too broad — what breaks hiding is a *fully public* derivation, not a keyed one.

Cost, stated honestly: this changes `BatchOp::Deposit`/`Unbind` semantics and client-side note reconstruction, since the client must reproduce the blind from its entropy plus the counter. It does **not** change `Note::commitment`, so merkle leaves, the archive layout and the note format are untouched. *(An earlier draft claimed a pinned commitment KAT would break — there is none; `note.rs:85` has relational binding/hiding tests only.)*

**Fallback if the counter proves impractical:** the permanent `CommitmentSet`, applied at both mint paths, accepting the growth and witness cost above. Whichever is chosen must be benchmarked for witness size and proving cycles before implementation, not assumed.

### Consequences outside `perp-core` — both are `.expect()` on a now-fallible operation

Making uniqueness historical means a mint can fail where it previously could not, and the gateway's `fund_amount` `.expect("deposit")`s its `seq.apply` calls (`main.rs:3990-3998`). Two consequences, both found in review:

- **The demo TUI panics.** Its blind is `0x80 + (tick % 60)` (`:3322`), so the same demo account depositing the same amount 60 ticks apart now trips the historical check — and the handler panics rather than reporting. Demo/dev only, but a regression introduced by this change.
- **The same `.expect` is on the real L1 credit path** (`account_confirm_deposit`, `:1956-1971`). Not reachable today (production blinds are `0xB0 ‖ deposit_counter`, monotonic per account), but the consequence is worse than a panic: `op_deposit` enforces `deposit_id == consumed_deposit_count` (`engine.rs:358`), so **one rejected deposit stalls the entire SEC-019 ordered stream** and every later deposit fails `DepositOutOfOrder`. Recovery is possible in principle — the note `blinding` is independent of the L1 leaf's `deposit_blind`, so the same leaf can be retried with a fresh note blind — but nothing implements it, and there is no `DuplicateCommitment` handling anywhere outside `perp-core`.

`fund_amount` is therefore made fallible and the demo blind widened. **Automatic retry-with-a-fresh-blind is deliberately NOT added here** — it is a cutover design decision, not a fix to smuggle into a bug branch, and it belongs on the cutover checklist alongside the rest of the SEC-019 wiring.

### A prerequisite defect in `NullifierSet` — the pattern is not what it claims

An earlier draft justified the set by calling `NullifierSet` a "state-root-bound `BTreeSet`". **It is not.** `NullifierSet` derives `Deserialize` over two independently encoded fields, `spent` and `chain` (`nullifier.rs:13`); `digest()` returns only `chain` (`:60`); and `state_root` commits only that digest (`state.rs:218`). So a deserialized state can carry the anchored chain alongside a *different* `spent` set — the one `contains()` actually consults — with no deserializer or validation linking them. The chain cannot even be recomputed from the set, because the sorted `BTreeSet` has lost insertion order.

Under the canonical threat model this is not user-exploitable (the prover cannot alter the sealed witness; the gateway is trusted), but it is a latent proof-soundness weakness, and **copying the pattern would double it**. The chosen design avoids it entirely — the index is derived from the anchor, so it cannot present a view the anchor disagrees with. `NullifierSet` itself must still be either fixed (validated ordered representation, or an order-independent accumulator) or explicitly documented as a trusted-snapshot invariant. Recorded here because this design's review found it; it belongs to `NullifierSet`, not to SEC-026.

**A related, smaller one in the same file:** `MerkleTree.empty` is accepted from the wire unvalidated. `root()`/`prove()` index it unconditionally (`merkle.rs:158, 169, 191, 201`), so a wire tree with `empty.len() <= depth` panics. Recomputing it in `From<MerkleTreeWire>` would be cheap (≈depth+1 keccaks) and would **not** change any encoding, since `Serialize` still emits the stored field and the recomputed values are canonical — so byte-parity is not the reason it was left alone; scope is. If it is done later, guard the recomputation rather than delegating to `new()`, whose `assert!` (`merkle.rs:94`) would just move the panic for a hostile `depth`.

## Migration

| Change | Consequence |
|---|---|
| Guest ELF changes (new check on both mint paths) | **vkey re-pin** |
| **No serialized-state change** | `state_root` unchanged, **`GENESIS_ROOT` does not move**, postcard encoding of `DefaultState` untouched |

**This is the practical payoff of indexing the existing list rather than adding a set: SEC-026 requires no state migration.** It still rides the cutover bundle's vkey re-pin (SEC-022 and SEC-024 change the guest anyway), but it does not itself force a wipe, and it would be independently deployable if the bundle slipped.

**Backfill:** none. The index is derived from `tree.leaves` on load, so any existing state produces a correct index without migration.

## Testing

| Case | Expected |
|---|---|
| **Fund-loss regression:** `Deposit → spend → Deposit` with the same tuple | second mint **rejected** — today it is accepted and the money is frozen |
| **`Unbind → Withdraw → Unbind`** with the same tuple | rejected — the path the earlier draft missed entirely |
| **`Unbind → spend → Deposit`** | rejected |
| **`Deposit → spend → Unbind`** | rejected |
| Duplicate while the first note is still unspent | rejected (existing behaviour, `lifecycle.rs:827`, must keep passing) |
| Two mints differing only in caller entropy | both accepted |
| ~~Structural test over both mint paths~~ | **Met by construction instead, and that is stronger.** There is exactly one `tree.append` and one non-test `notes.insert` in all of `crates/*/src`, both inside `mint_note`, with exactly two callers. A source-grep test would be brittle; the invariant is enforced by there being one primitive. |
| Rejected duplicate | **full postcard bytes unchanged**, not merely `state_root` — no tree append, no `external_in`, no deposit-count advance |
| **Failure atomicity:** tree-full, and `external_in` overflow | state unchanged. Note `tree` and `notes` currently mutate **before** `external_in.checked_add` (`engine.rs:369`), so inserting new bookkeeping ahead of the fallible work would add a partial-mutation case rather than remove one |
| **Index/anchor consistency:** serialize a state, deserialize it, and assert the rebuilt index exactly matches `tree.leaves` | equal — the property that makes divergence structurally impossible, and the one `NullifierSet` lacks |
| **No serialized-state change:** postcard bytes of a `DefaultState` before and after this change | identical for the same logical state — pins that `GENESIS_ROOT` does not move |
| Genesis | index empty |
| Every scenario | `conservation_holds()` |

The first four rows are the finding: each fails today by *accepting* the mint, and the failure is silent — the money is credited, the accounting balances, and only the eventual spend reveals it.
