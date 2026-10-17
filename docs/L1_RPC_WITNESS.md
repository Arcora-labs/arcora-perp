# Corroborated L1 state observations

Set `L1_RPC_WITNESS` to a second HTTP(S) RPC endpoint to require agreement for
authoritative gateway state reads. Both providers must serve the startup chain,
agree on the selected canonical block hash, and return matching ABI words at that
hash. Every multi-word decision uses one snapshot. Canonical hashes are checked
again before a result is returned. Errors hold the affected operation; no configured
witness can silently become optional and no unsupported pin falls back to `latest`.

## Explicit anchor policies

| Decision | Anchor and terms |
| --- | --- |
| Settlement boot recovery / failed-send reconciliation | Finalized: batch count, current root, bond together. |
| Snapshot root continuity | Finalized current root. |
| Boot deposit posture | Finalized vault count and `depositTipAt(consumed_count)` together. |
| Claimed withdrawal pruning | Every candidate at one finalized hash; any failure rejects the whole returned set. |
| Trading gate opening | Primary latest height minus `GATE_OPEN_CONFIRMATIONS` (currently 12). Each provider must have this depth and agree on the historical hash; batch count, root and `closeOnly` share it. |
| Terminal CloseOnly check | Latest canonical hash, with witness agreement. Waiting for finality here would delay the terminal check. |
| Next settlement batch count / current bond display | Latest canonical hash. |
| Bond top-up decision | Latest canonical required bond, current bond and `slashCount` together; no stale finalized value can repeatedly trigger a top-up, and a new slash pauses top-ups until acknowledged. |
| Liveness and keepalive | Latest canonical `lastProgressBlock` and `livenessTimeoutBlocks` with the head, with witness agreement. |
| Open challenge set | Latest canonical hash, with witness agreement: `openChallengeCount()`, then `openChallenges(i, 512)` pages, then the six-word `challenges(h)` tuple for each hash, all at that one hash. Strict address, batch hint, opened block, open batch count, stake and boolean; `openedBlock` must not exceed the head and `openBatchCount` must not exceed `batchCount`. A failed read fails that tick's settle (nothing is sealed without a successful read); there is no log cursor. |
| Deposit intake | Existing finalized whole-block prefix/log validation remains. The witness now corroborates each chain/header/hash-pinned word/code/log observation before the page validator can credit it. |

Finalized observations allow a witness ahead in finalized height if it also serves
the same historical anchor. Gate observations similarly allow a witness ahead,
but refuse one without the required confirmation depth. Latest observations refuse
a witness behind the selected primary block. These are distinct named policies;
there is no automatic downgrade between them.

ABI integers reject overflow, booleans accept only exact zero/one words, and
malformed or trailing ABI bytes cannot become permissive answers. Deposit count
and tip are no longer separate moving-head calls. A claim read never yields a
partially pruned set. The open-challenge set is read as ABI words at one canonical
hash and compared between providers like any other read; a count, page or tuple that
disagrees, or that fails the sanity bounds, fails the tick.

The settlement keeps the open challenges as an enumerable on-chain set, so the
watcher reconciles against the set each tick instead of scanning logs. Nothing is
reconstructed from a log window at restart; the set itself is the pending work. Open
hashes are grouped by the settled batch that answers them and answered with
`answerChallenges`, a bounded number per transaction, from the separate answer key
when one is configured. A failed answer or not-yet-retained batch is retried while
other batches can still progress. Answers have no deadline: an open challenge stays
answerable until a slash or release lands. A hash found in no settled batch and no
in-flight window raises an alert; it does not hold settlement.

Deposit pages require hash-pinned `eth_call`/`eth_getCode`, a `blockHash` filter
for logs, and finalized or explicit-height block reads. Their existing prefix-fold
and canonical-recheck logic remains binding. Raw log responses are compared
strictly: provider-specific extra fields or ordering differences can cause a
conservative refusal, never an acceptance based on unequal responses.

## Configuration and limits

Unset `L1_RPC_WITNESS` for the same canonical/ABI policies with one provider. An
empty configured value is an error. With `L1_ALLOW_MOCK_PROOF=1` for a disposable
local fixture, witness mode requires explicit nonzero decimal `L1_CHAIN_ID`.
The two URLs must have different normalized hosts; changing only path, port or
credentials is insufficient. This rejects obvious aliases but does not establish
independent operators, DNS resolution or upstream infrastructure.

The witness receives only reads, no signing material or transactions. Provider
errors, credential-bearing URLs and response bodies are omitted from observation
errors. Transaction submission, signer nonce selection, receipt confirmation and
key derivation retain their existing primary-provider transport. This option is
not consensus, complete transaction-transport quorum, production deployment
identity, or protection against two cooperating providers.

The local fixture tests do not establish live provider availability or deployment
bytecode identity, and do not close the original full-funds S6-03 acceptance gate.

## Verification

```sh
cargo test --locked -p gateway l1::
cargo test --locked -p gateway runtime_witness_native_cast -- --ignored
cargo test --locked -p gateway runtime_state_native_cast -- --ignored
```

The ignored suites require real Foundry `cast`. They cross the real subprocess and
loopback HTTP boundary, asserting EIP-1898 calldata, confirmation/latest policies,
canonical rechecks, paired vault/claim observations, strict ABI failures, the
open-challenge set (short or malformed pages, duplicates, a listed hash that is not
open, the head and batch-count bounds, provider disagreement), the boot posture and
bond terms, and credential redaction. The gate tests invoke the
production `observe_gate_once` classifier through an `L1` instance. Test servers
receive no signing calls and submit no chain transactions.
