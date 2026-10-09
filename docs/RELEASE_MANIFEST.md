# Clock release identity preflight

`release_manifest.py` binds the reviewed PR #31 clock guest (source hashes, ELF,
SP1 6.1.0 and setup key) to **current local** Solidity compiler artifacts and a
strictly public gateway/prover configuration. It rejects an old guest/key mixed
with the new clock stack, stale compiler sources, changed source/artifact files,
and mismatched gateway chain/address settings. Added untracked source files are
included in the source fingerprint; a Git commit alone does not describe a dirty
checkout.

This closes an offline identity check, not R02 as a whole. The manifest always
records `release_gate: HOLD`. It does not assert a fresh reproducible guest build,
a live chain observation, deployed runtime equivalence, a running prover's
identity, or a state/withdrawal migration rehearsal. It reuses the established
PR #31 guest identity and does not negate or rerun that release's real proof.
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

## Remaining R02 acceptance gates

Before a target release is accepted, independently reproduce the guest with the
pinned toolchain; verify its setup key; compare full deployed runtime including
immutables at a finalized target-chain block; check chain ID, all contract links,
SP1 gateway route and clock policy; and verify the actual gateway/prover runtime
configuration. Rehearse preservation of existing state, notes, deposit accounting
and withdrawal rights. None of these steps is implied by local manifest PASS,
and this tool never migrates funds or resets state.

```sh
python3.11 -m unittest discover -s scripts/local-verification \
  -p test_release_manifest.py -v
```
