# R01 local funds lifecycle

The opt-in test `funds_lifecycle_tests::real_http_evm_funds_lifecycle_with_native_mock_proof`
starts its own loopback Anvil and real HTTP gateway listener. It creates fresh
contracts, starts the gateway from empty production genesis, and uses nonzero
EOA wallets with signed ERC20 and vault transactions. It never reads a configured
chain RPC or uses a configured wallet for transactions.

```sh
forge build --root contracts
ARCORA_FUNDS_EVIDENCE="$PWD/docs/audits/2026-10-09-remaining-work/funds-lifecycle.json" \
  cargo test -p gateway funds_lifecycle_tests --locked -- --ignored --nocapture
```

Requires the repository's supported Rust toolchain plus `anvil`, `cast`, and
`curl`. The test is ignored in ordinary unit runs because it owns external test
processes; the A11 gateway-drills job invokes it explicitly. Runtime account API
keys, deposit blinds and wallet seeds are not included in the evidence JSON.
The source's fixed EOA keys are public test fixtures only.

The assertions join these paths in one run:

- HTTP registration, signature-bound payer registration and durable deposit
  authorization; ERC20 allowance, vault deposit and hash-pinned finalized
  `VaultSource` ingestion. Restore the encrypted authorization snapshot before
  ingestion to prove the persisted blind still credits the intended account.
- Operator insurance capitalization plus two user deposits: three deposits,
  50,000 test USDC credited exactly once. The gateway's deposit count and tip
  reconcile to the deployed vault; duplicate confirmations credit nothing new.
- Caller-signed, encrypted HTTP orders open equal opposite positions, then close
  both in another batch. Four orders and four consecutive settlement batches
  retain their roots and EVM transaction hashes in JSON.
- Two signed 10,000 USDC withdrawals; settlement is mined before local bookkeeping
  commits, then the encrypted snapshot and prepared WAL are read from disk and
  existing boot recovery rolls forward. Both users retrieve Merkle paths over
  HTTP and claim ERC20 from the vault. The vault finishes with 30,000 USDC,
  reconciling 50,000 deposited less 20,000 withdrawn and engine conservation.
- Missing allowance, wrong deposit tuple, reused deposit authorization, wrong
  order signer, duplicate orders, modified withdrawal destination, duplicate
  withdrawal authorization, unpublished claim, invalid mock proof and duplicate
  claim fail. Replay deposits retain enough balance and allowance for another
  transfer, so allowance exhaustion cannot mask a missing replay guard. A
  nonexistent deposit returns pending with zero credited, and cannot change the
  consumed prefix.

`funds-lifecycle.json` and `funds-lifecycle.log` contain the current local result.
The JSON records elapsed wall time, host architecture/CPU, Rust toolchain and
Anvil build. The elapsed time measures this entire native/mock flow, including
HTTP, subprocess and local EVM work; it is **not SP1 proving time or R03 capacity
acceptance evidence**.

The proof backend is explicitly native replay plus **MockZkVerifier**. This test
uses real token transfer and settlement/vault code but does not establish proof
soundness. PR #31's separate real clock/SP1 evidence remains valid for its recorded
fixture; combining this wallet lifecycle with a freshly generated real clock
proof is still an R01 release gate. This test does not run a clock adapter,
production background settlement service, hardware attestation, target-chain
finality policy or an OS-level process crash. Recovery is a same-process reload
of actual encrypted snapshot and WAL files using mined local EVM facts. None of
this authorizes deployment, fund migration or a non-custodial claim.
