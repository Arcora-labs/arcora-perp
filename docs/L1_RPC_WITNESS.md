# Settlement recovery RPC witness

Set `L1_RPC_WITNESS` to a second HTTP(S) RPC endpoint to require agreement during
gateway settlement boot recovery and failed-settlement reconciliation. Both
providers must serve the startup chain, agree on the primary's finalized block
hash, return identical `batchCount()`, `currentStateRoot()` and `sequencerBond()`
ABI words at that hash, and still report that hash as canonical afterward. The
witness may be ahead in finalized height, but cannot be behind the chosen anchor.

A missing, malformed, unavailable or conflicting required observation leaves
recovery on hold. There is no automatic fallback when the witness is configured.
Unset the variable to retain the existing single-provider policy; an empty value
is a configuration error. If `L1_ALLOW_MOCK_PROOF=1` is used for a disposable local
fixture, witness mode also requires an explicit nonzero decimal `L1_CHAIN_ID`.
The witness receives read calls only and no signing material or transactions.
Provider errors and credential-bearing endpoint details are omitted from the
settlement observation errors.

The two URLs must have different normalized hosts; changing only path, port or
credentials is insufficient. This rejects obvious hostname/IP aliases, but does
not establish independent operators, DNS resolution or upstream infrastructure.
Choose and verify independent providers separately.

This option currently covers only settlement recovery observations. Deposit
intake, the periodic trading-gate reader and transaction submission retain their
existing behavior. It does not establish full gateway RPC quorum, production
deployment identity, or protection against two cooperating providers.

With Foundry `cast` installed, execute the real subprocess/HTTP regression matrix:

```sh
cargo test --locked -p gateway runtime_witness_native_cast -- --ignored
```

Those tests use isolated loopback fixtures and injected faults. They are separate
from live provider evidence; the normal test suite also checks the parser/policy.
