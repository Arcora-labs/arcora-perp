# Offline Chainlink candidate identity

`scripts/local-verification/candidate_identity_manifest.py` creates and validates
`arcora-chainlink-candidate-offline/v1` manifests using local public inputs. Its
purpose is to detect a stale or substituted candidate program, source inventory,
compiler artifact or declared configuration. A successful result always retains
`release_gate: HOLD`. It does not approve deployment, enable the candidate route,
or attest a running service.

The existing reviewed v2 `release_manifest.py` schema, key, proof checks and
`observe-target` command remain separate. This new tool has only `create` and
`validate`: it accepts no RPC option, reads no process configuration or
credentials, and performs no discovery, build, setup, proof or transaction.
Its local checks use Git queries, the existing dependency/provenance guard and
`cast keccak` over local source bytes.

## Bound local identities

The manifest binds the committed candidate ELF and its metadata from
`contracts/integration/fixtures/chainlink-candidate-v1`, the historical candidate
key, the existing 21 reviewed source pins and nine candidate source pins. It
separately pins two existing auxiliary test files at merged base
`f9a0f2f59ffae651163fc10a43a995054a07ebcc`: `chainlink-oracle/src/tests.rs`
(SHA-256 `42396d0053fc92062acb33f67ecd253c590a09a18bb23cda72566e5092b9702f`)
and `chainlink-oracle/src/replay_vectors.rs`
(`512a4966a886231ceb94fd034f94135b98b4ee4dfc3e894e45912da93ca1b54c`).
The pinned library declares `tests` under `#[cfg(test)]`, and that pinned test
module declares `replay_vectors`; they do not enter the candidate runtime pin
map. These two hashes appear in `candidate_auxiliary_test_sources_sha256`.
The tool refuses changed pins, any other added candidate source file and
candidate build overrides. The candidate's `DPCLK3` witness domain remains distinct from the
inner clock proof version `2`.

The candidate ELF SHA-256 is
`48a8eb8e6acd96057a72ca74db5077ac9e85d30d2ec830518ef1f1ac3832ef1f`.
Its historical measured program key is
`0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590`.
Reading these committed identities does not derive a fresh setup key. The
metadata's earlier same-machine rebuild result remains historical evidence;
this command does not rerun that rebuild or claim independent reproducibility.

The covered inventory includes public source and build inputs under `crates`,
`vendor`, `contracts/src`, `contracts/vendor` and
`scripts/local-verification`, plus root `Cargo.toml`, `Cargo.lock` and
`contracts/foundry.toml`. It records each SHA-256 and the builder script identity.
Generated `target`/`out` directories and dependency caches are excluded.
Dotenv paths and credential, secret or private-key named paths are excluded
without reading their contents. Explicit compiler inputs are still restricted
to regular, nonsymlinked repository paths. The manifest is a checksum binding,
not a signature or an approval; the caller must trust the builder and its input
checkout.

Existing local compiler artifacts are required for seven roles: `settlement`,
`vault`, `sp1_adapter`, `clock_verifier`, `sp1_gateway`, `sp1_verifier` and
`oracle_wrapper`. Paths are the existing release tool's six artifact paths plus
`contracts/out/ChainlinkOracleVerifier.sol/ChainlinkOracleVerifier.json`. The
tool checks compiler version, compilation target, optimizer settings, source
Keccak bindings and unlinked bytecode, then records the artifact, creation
bytecode and runtime **template** SHA-256 values. It neither invokes Forge nor
proves that an artifact was produced by a trusted compiler. Immutable values in
a deployed runtime cannot be inferred or verified from these template hashes.

## Public declaration and commands

Provide a public JSON configuration with exactly these fields:

| Field | Accepted declaration |
| --- | --- |
| `chain_id`, `network` | Base Sepolia `(84532, 0)` or Base `(8453, 1)` |
| `addresses` | Ten distinct, nonzero 20-byte addresses for the seven compiler roles above plus `token`, `verifier_proxy` and `uptime_feed` |
| `expected_runtime_code_hashes` | Nonzero 32-byte declarations for the same ten roles |
| `program_vkey` | The exact historical candidate key above |
| `clock.max_window_ms` | Integer `1..2^64-1` |
| `clock.clock_skew_ms` | Integer `0..2^64-1` |
| `oracle_policy_hash` | Nonzero 32-byte declaration |
| `sequencer_grace_seconds` | Integer `1..2^64-1` |

Booleans do not count as integers. Addresses, expected runtime hashes, policy,
uptime feed and grace values are caller declarations, not observed deployment
facts or approved operator/economic policy. The identity parser's ranges follow
the relevant constructor boundaries; they do not establish gateway cadence or
operational policy acceptance.

Run from the repository root with Python 3.11+ and local `cast` available. The
compiler artifacts must already exist; these commands create none:

```sh
python3 scripts/local-verification/candidate_identity_manifest.py create \
  --config /absolute/path/public-candidate-config.json \
  --output /absolute/path/new-candidate-identity.json \
  --code-commit <tested-code-commit>

python3 scripts/local-verification/candidate_identity_manifest.py validate \
  --config /absolute/path/public-candidate-config.json \
  --manifest /absolute/path/new-candidate-identity.json
```

`--code-commit` is optional and defaults to the current local HEAD. It is an
informational commit that must be an ancestor of the current HEAD. A later
metadata-only publication commit can therefore validate the same manifest if
all covered source, builder and artifact fingerprints remain identical. An
ancestor relationship alone never makes stale fingerprints pass.

`create` exclusively creates a new output pathname; it refuses to replace an
existing file. It does not provide a durable transaction for this public JSON
output. A failure during a new write can leave an incomplete new file, which
must not be used as a validated manifest. Configurations and manifests are
limited to 2 MiB, compiler artifacts and individual source inputs to 64 MiB,
JSON nesting to 64 levels, and the covered source inventory to 8,192 files.
Duplicate JSON keys, nonfinite or excessively nested JSON, foreign schemas,
missing or extra fields, unsafe source
paths, wrong keys and stale identities fail. Errors do not echo rejected
configuration values or unsupported endpoint arguments.

## Verification boundary

The self-contained test command is:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/local-verification -p test_candidate_identity_manifest.py -v
```

The 19 tests copy the committed ELF, metadata, 21/9 source pins and the two
fixed auxiliary test files unchanged. They include the actual allowed source
layout and reject changed auxiliary files.
They use explicitly synthetic compiler artifacts and public configurations,
with mocked compiler Keccak, dependency guard and ancestry interfaces. They
exercise validation, bounds, wrong versions, stale fingerprints, no-clobber and
fixed HOLD behavior. They require neither Forge outputs nor a GPU and do not
establish real compiled-runtime identity or current compiler/provenance
acceptance.

Manifest validation always keeps target observation, deployed runtime checks,
running-service attestation, fresh guest build, fresh setup, proof generation,
real DON verification, custody acceptance, operator approval and candidate
submission disabled in its scope. Those gates, including independent review and
live deployment/service acceptance, remain open under [ACTIVE_WORK.md](ACTIVE_WORK.md).
This packet closes only the offline identity-manifest software boundary.
