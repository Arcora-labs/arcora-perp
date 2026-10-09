# R04 rejection accountability, R06 oracle trust, and R07 wind-down checks

Scope: current custodial alpha, based on
`b2a3c357c6b345726a7a85b5cc55484d6bef8c98` plus the local changes below.
These results are local native/EVM tests. No deployment, live funds, new SP1
proof, independent oracle, or permissionless exit is claimed.

## R04: same-block challenge stake refund fixed

Both `answerChallenge` and `answerByRejection` compared
`settledAtBlock > openedBlock` to decide whether a challenge forced publication.
If the sequencer settled **after** the challenge transaction in the **same**
block, that comparison was false and the sequencer received the victim's stake.

The settlement contract now records `batchCount` when the challenge opens. A
batch with `batchId >= captured batchCount` was unsettled at that instant and
refunds the challenger. A previously settled batch still forfeits the stake to
the sequencer, including when both transactions share a block. Answering and
slashing clear the recorded boundary; reopening takes a fresh snapshot. The
public six-word `challenges(bytes32)` getter remains unchanged. Contract
bytecode changes; the historical PR31 deployment/proof evidence is not evidence
of this contract being deployed.

Fail-before command, after adding the three first regression tests but before
changing the contract:

```sh
cd contracts
forge test --match-contract DarkPerpSettlementTest --match-test test_same_block -vv
```

Observed: two failures, `same-block forced inclusion refunds challenger` and
`same-block late rejection refunds challenger`; the previously settled
same-block rejection test passed. After the fix, these pass, as do duplicate
answer rejection, reopened challenge, and a 256-run fuzz test covering both
answer paths, both transaction orders, and zero/nonzero prior batch counts.

Final `forge test --summary`: **126 passed, 0 failed, 0 skipped**, 12 suites.
The settlement and vault invariant suites each ran 256 campaigns with 128,000
calls. Their verifier dependencies include mocks; this checks contract behavior,
not SNARK soundness.

## R04: rejection legitimacy and matching fairness remain open

`derive_roots` receives `(state, ops, manifest)`. The manifest contains declared
hashes and reasons; the guest has neither authenticated order bodies nor a
committed matcher book/lifecycle with which to verify those claims. Deriving a
root from the list binds the list; it does not prove the list is justified.

`crates/perp-core/tests/rejection_boundary.rs` explicitly characterizes three
currently accepted cases:

- A non-expiring GTC order is declared `Expired` or `PostOnlyWouldTake` without
  any matching operations, and root derivation succeeds.
- The manifest's claimed order sequence changes without changing operations or
  the resulting state.
- Duplicate and overlapping ordered/rejected entries are accepted. Rejecting
  every overlap would also break legitimate multi-tick partial-fill/remainder
  lifecycles; a blanket disjointness check is not the missing proof.

These **three passing characterization tests demonstrate the limitation**. They
must not count as R04 security acceptance. Native matcher tests separately pass
**22/22**, covering price/time priority, partial fills, FOK, IOC, post-only,
expiry, self-trade, determinism and fuzzed invariants. They are not guest replay.

Receipts and inclusion slashing do not prevent a malicious sequencer from
declaring a valid order rejected and answering by membership. Documentation and
contract comments now state this directly. We retain the rejection answer path:
disabling it without a replacement would wrongfully slash honest rejections.

A complete R04 release gate still needs authenticated intent/body binding,
receipt sequence and replay rules, committed book and remaining quantities,
deterministic matching/risk replay, and reason-bound challenge evidence. That
changes the witness/state/proof protocol and needs its own design and release
verification; this alpha hardening does not silently choose those rules.

## R06: the configured publisher remains a trust boundary

`oracle_trust_boundary.rs` uses real secp256k1 signatures to demonstrate that a
trusted publisher can sign a primary price 100 times lower or higher than the
scenario's fixed external observation, set backup TWAP to that same fabricated
price, and pass validation. Freshness, confidence and agreement between two
values from the same signer do not authenticate an independent price source.

The characterization passed. The existing **nine oracle unit tests** also
passed, including stale/future prices, wide confidence, overflow, missing
backup, backup deviation, malformed/missing signature, wrong publisher,
cross-market replay, unset publisher, and signed-field tampering. Those gates
work; publisher compromise remains an accepted alpha trust dependency, not a
closed independent-oracle security property.

## R07: current loss allocation and governance gate verified

The existing **four** `a06_wind_down` tests pass: healthy price-free exit,
mixed-grammar rejection before mutation, global pool-deficit conservation, and
atomic rejection when haircut note reissue exceeds tree capacity.

The added `wind_down_policy.rs` regression fixes the expected amounts for three
existing-policy cases: insurance absorbs losses first, treasury second, then
both positive position collateral and unspent notes receive the same pro-rata
haircut. It checks the owner, exact resulting amounts, flattened position, and
conservation. No economic implementation changed.

**Eleven** Solidity wind-down/governance/grace cases pass, including the added
`test_a06_finalExit_reverts_non_governance`. The suite checks both phase gates,
one-shot phase 1, repeated phase 2, original close-only grace, non-governance
rejection, and vault claim publication. These checks confirm governance is
required for final exit publication. They do not prove user exit availability
if governance, the prover, gateway, or required state data is unavailable.

## Reproduce the native checks

From the repository root, using the installed Rust 1.99 toolchain:

```sh
rustup run 1.99.0 cargo test --locked -p perp-core --test rejection_boundary --test oracle_trust_boundary --test a06_wind_down --test wind_down_policy
rustup run 1.99.0 cargo test --locked -p perp-core --lib oracle::tests
rustup run 1.99.0 cargo test --locked -p matcher
```

`perp-core/src` and `sp1-guest` were unchanged in this work. Existing proof
evidence remains historical; no new real proof was generated for this change.

Relevant local SHA-256 fingerprints:

| File | SHA-256 |
| --- | --- |
| `contracts/src/DarkPerpSettlement.sol` | `510e9ae8a21d4e34989969b0767d40bc80b6ff400cd95e754be481f5cb036f94` |
| `contracts/test/DarkPerpSettlement.t.sol` | `4280aab041bb3f5bbfe31359a194066c1264a8b9a96a1fa0dd520a14304c5bf3` |
| `crates/perp-core/tests/rejection_boundary.rs` | `bed0ee3dd9224901ff402e99b90245afa95aae38917f499aafd1fdab006afd8a` |
| `crates/perp-core/tests/oracle_trust_boundary.rs` | `f4ff71cabfa1f0c1fc2fa5f1c7816b13a9003bdb8cf3226bea590066e09405f8` |
| `crates/perp-core/tests/wind_down_policy.rs` | `40e5c6653bb94fc8f624b961f92f1cf3217a5c0775b93b685bde359fd50e862b` |
