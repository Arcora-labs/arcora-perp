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
| Bond top-up decision | Latest canonical required bond and current bond together; no stale finalized value can repeatedly trigger a top-up. |
| Challenge watcher initialization | Latest canonical head and challenge window together; no guessed window on error. |
| Inclusion challenge state | Latest canonical six-word challenge tuple; strict address, batch hint, opened/deadline blocks and boolean. Only open entries at or before the deadline are answerable. |
| Challenge event discovery | Up to 1,024 blocks per numeric range, capped at the observed latest height. Both providers must return identical events. End hash and each event block hash must agree and be canonical; the end is checked again before returning the cursor and its end hash. The next poll revalidates that saved hash both before and after discovery; a confirmed replacement rewinds the challenge window. Provider disagreement holds the cursor. |
| Deposit intake | Existing finalized whole-block prefix/log validation remains. The witness now corroborates each chain/header/hash-pinned word/code/log observation before the page validator can credit it. |

Finalized observations allow a witness ahead in finalized height if it also serves
the same historical anchor. Gate observations similarly allow a witness ahead,
but refuse one without the required confirmation depth. Latest observations refuse
a witness behind the selected primary block. These are distinct named policies;
there is no automatic downgrade between them.

ABI integers reject overflow, booleans accept only exact zero/one words, and
malformed or trailing ABI bytes cannot become permissive answers. Deposit count
and tip are no longer separate moving-head calls. A claim read never yields a
partially pruned set. Challenge logs reject omissions visible as provider
disagreement, removed logs, wrong contracts/topics, invalid metadata, duplicate
positions and events not bound to the canonical range. Both providers returning
the same omitted logs remains outside this two-provider threat model.

Unanswered challenge hashes stay in a bounded pending set independently of page
advancement. A failed answer or not-yet-retained batch is retried while later pages
and other pending hashes can still progress. Expired open challenges are skipped
using the contract's inclusive deadline rule; they cannot indefinitely block live
ones. Pending work is reconstructed from the on-chain challenge window at restart.

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
canonical rechecks, paired vault/claim observations, strict ABI failures, expiry
boundaries and revalidation of the previous scan anchor across polls, challenge
log omission/reorg handling and credential redaction. The gate tests invoke the
production `observe_gate_once` classifier through an `L1` instance. Test servers
receive no signing calls and submit no chain transactions.
