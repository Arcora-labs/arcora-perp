# Clock release identity preflight

`release_manifest.py` binds the reviewed PR #31 clock guest (source hashes, ELF,
SP1 6.1.0 and setup key) to **current local** Solidity compiler artifacts and a
strictly public gateway/prover configuration. It rejects an old guest/key mixed
with the new clock stack, stale compiler sources, changed source/artifact files,
and mismatched gateway chain/address settings. Added untracked source files are
included in the source fingerprint; a Git commit alone does not describe a dirty
checkout.

The manifest closes an offline identity check. The optional `observe-target`
command adds finalized chain/runtime/contract-binding verification. Neither closes
R02 as a whole, and both always record `release_gate: HOLD`. They do not assert a
fresh reproducible guest build, a running prover's identity, operator-policy
approval, or a state/withdrawal migration rehearsal. They reuse the established
PR #31 guest identity and do not negate or rerun that release's real proof.
Current contract bytecode is identified separately from that historical proof.
The validator and manifest must come from a trusted release process: checksums
are integrity bindings, not a release signature.

## Build and record

Requires Python 3.11+, Git, Foundry (`forge` and `cast`), Solidity 0.8.24 for the
application and 0.8.20 for the vendored SP1 contracts. SP1 dependency locks and
vendor provenance are checked using the existing release guard. Start from a
clean release checkout for publishing; the script also supports local dirty
worktrees by recording all covered source hashes.

```sh
forge build --root contracts
forge build --root contracts/vendor/sp1-contracts
python3.11 scripts/local-verification/release_manifest.py create \
  --config /path/to/public-release-config.json \
  --output /path/to/release-manifest.json
python3.11 scripts/local-verification/release_manifest.py validate \
  --config /path/to/public-release-config.json \
  --manifest /path/to/release-manifest.json
```

`create` refuses to overwrite an existing manifest. Build metadata is checked
against current source contents with Keccak-256; the artifact file, creation
bytecode and runtime **template** are then SHA-256 pinned. Constructor immutable
placeholders are not represented as an actual deployed runtime hash. Source,
artifact, configuration, or manifest scope changes require a new manifest.
The source commit is also bound: generate the manifest after the intended source
commit is final. Checked-in audit manifests document the checkout at their
creation; they are historical evidence after any covered file or commit changes,
and must not be reused as current release authorization.

The public configuration shape is below. **Every address in this example is
synthetic, and chain 31337 is local only.** Replace them from the actual reviewed
setup before using the preflight for a release. Timing values are illustrative,
not a measured capacity recommendation. No private keys, RPC credentials,
attestation secrets or `.env` files may be supplied; unknown fields are refused.
The `prover` section declares the expected binary identity; it is not a remote
prover observation.

```json
{
  "chain_id": 31337,
  "addresses": {
    "settlement": "0x0000000000000000000000000000000000000001",
    "vault": "0x0000000000000000000000000000000000000002",
    "token": "0x0000000000000000000000000000000000000003",
    "clock_verifier": "0x0000000000000000000000000000000000000004",
    "sp1_adapter": "0x0000000000000000000000000000000000000005",
    "sp1_gateway": "0x0000000000000000000000000000000000000006",
    "sp1_verifier": "0x0000000000000000000000000000000000000007"
  },
  "program_vkey": "0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353",
  "clock": {"max_window_ms": 30000, "clock_skew_ms": 10000},
  "gateway": {
    "L1_CHAIN_ID": "31337",
    "L1_SETTLEMENT": "0x0000000000000000000000000000000000000001",
    "L1_VAULT": "0x0000000000000000000000000000000000000002",
    "L1_USDC": "0x0000000000000000000000000000000000000003",
    "CLOCK_BOUND_VERIFIER": "0x0000000000000000000000000000000000000004",
    "L1_ALLOW_MOCK_PROOF": "0"
  },
  "prover": {
    "program_vkey": "0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353",
    "guest_elf_sha256": "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5"
  }
}
```

An operator may add `validate --check-process-env` as a service pre-start check.
This compares the six allowlisted gateway variables against the manifest and
fails before startup on a mismatch. It does not install a startup hook or change
running services; that integration must be configured in the target environment.
No key values are read or emitted by the environment check.

## Reject a legacy deployment record

```sh
python3.11 scripts/local-verification/release_manifest.py check-deployment \
  --deployment contracts/deployments/base-sepolia.json
```

The checked-in July Base Sepolia record is expected to fail: its program key is
`0x000a2f…bda5ed`, whereas the reviewed clock guest uses `0x001789…4b8353`.
This is an offline record check, not a claim about current chain state. A passing
record check checks only the guest key, clock presence, chain-ID range and address
shape; it does not compare runtime bytecode or prove mutual contract bindings.

## Observe the configured clock deployment

With a manifest for the current checkout and reviewed public target configuration:

```sh
python3.11 scripts/local-verification/release_manifest.py observe-target \
  --config /path/to/public-release-config.json \
  --manifest /path/to/release-manifest.json \
  --rpc https://PUBLIC_TARGET_RPC \
  --output /path/to/target-observation.json
```

The command uses only `eth_chainId`, `eth_getBlockByNumber`, `eth_getCode` and
`eth_call`. It does not deploy, transact, import keys, change services or repair a
bad binding. The endpoint must support the `finalized` tag and EIP-1898 block-hash
parameters with `requireCanonical: true`. Unsupported finality/hash pinning is a
failure; there is no `latest` or block-number fallback. The finalized anchor and
chain ID are checked again after the observation. Redirects, malformed envelopes,
RPC errors and oversized responses fail closed. Provider error text and URL paths
are not written to the evidence. Existing output files are never overwritten.

For each of the six compiled contracts, it checks the full runtime, including
metadata. Only the compiler's immutable reference words may differ from the
template. Each repeated occurrence of one immutable must contain the same value;
out-of-bounds, overlapping, non-word and nonzero-placeholder references are
rejected. Every observed immutable word is recorded by its compiler identifier;
this is reconstruction of the actual deployed template, not blanket masking of
all constructor-dependent bytes. An altered opcode or metadata byte fails.

At that same block it checks settlement ↔ vault, settlement ↔ clock verifier,
clock → SP1 adapter → SP1 gateway, vault → token, the reviewed guest key, clock
bounds, proof version 2, the SP1 verifier hash, and the selector's active,
unfrozen route to the configured verifier. Zero/unbound or old direct-adapter
configurations fail. The token must have code; its implementation is not among
the six compiled artifacts.

A successful report says `VERIFIED_AT_FINALIZED_BLOCK`, with runtime and target
observation fields set true. It still records `release_gate: HOLD`. RPC responses
are trusted; this is not a light-client check or independent RPC consensus. The
sequencer, enclave signer, governance, gateway signer, SP1 gateway owner and
settlement timing/bond parameters are recorded for review, but the current public
configuration does not approve those values. `operator_and_settlement_policy_approved`
therefore remains false, even if the observed value is zero. The token's runtime,
proxy/admin/issuance policy, service config/identity, real proof generation,
capacity, custody loss and state migration remain separate acceptance gates.

The opt-in integration test owns a new disposable Anvil, deploys the real six
compiled contracts and a mock token through their actual constructors, binds the
stack, and obtains a successful hash-pinned observation. It then freezes the
actual SP1 route and requires the next finalized observation to fail. No existing
node, supplied RPC, credentials or public network can be selected by this test.

```sh
forge build --root contracts
forge build --root contracts/vendor/sp1-contracts
ARCORA_RUN_MANIFEST_ANVIL=1 \
  python3.11 -m unittest discover -s scripts/local-verification \
  -p test_release_manifest.py -v
```

Optional `ARCORA_MANIFEST_ANVIL_EVIDENCE=/path/to/local-observation.json` captures
both observations. This is local contract/RPC evidence with a mock token; it does
not generate or settle a proof, attest a service, or verify a public deployment.

## Remaining R02 acceptance gates

Before a target release is accepted, independently reproduce the guest with the
pinned toolchain; verify its setup key; run `observe-target` against the actual
reviewed deployment; approve the observed operator identities and settlement
policy; independently review the token; and verify the actual gateway/prover
runtime configuration. Rehearse preservation of existing state, notes, deposit
accounting and withdrawal rights. A local Anvil observation does not substitute
for target deployment evidence, and this tool never migrates funds or resets state.

```sh
python3.11 -m unittest discover -s scripts/local-verification \
  -p test_release_manifest.py -v
```
