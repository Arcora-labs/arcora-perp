# Public service identity and offline preflight

Gateway and the existing prover expose read-only `GET /identity` responses with
`Cache-Control: no-store`. They describe public values already resolved by the
service and a source checksum baked into its build. The response is explicitly
`self_reported_unattested`: it does not authenticate the binary, its process,
its host, its operator or an approved deployment.

The identity request does not run setup or proving, fetch an attestation quote,
read accounts, release a key, call L1, register reports or change a submission
gate. The normal prover may have performed its existing setup at startup; the
identity route only describes its already included ELF and captured key. It
does not change the prover's clock-bound (`DPCLK4`) proving or its
bearer/attestation rules. Candidate
submission remains unsupported and disabled, and release remains **HOLD**.

## Response schema

The exact envelope has nine fields:

| Field | Value |
| --- | --- |
| `schema` | `arcora-public-service-identity/v1` |
| `service` | `gateway` or `prover` |
| `evidence_kind` | `self_reported_unattested` |
| `build` | The four-field build identity below |
| `program` | `null` for gateway; the prover program descriptor below |
| `public_config` | The resolved public role configuration below |
| `public_config_sha256` | SHA-256 of recursively key-sorted compact JSON of `public_config` |
| `capabilities` | Both `candidate_submission_supported` and `candidate_submission_enabled` are `false` |
| `scope` | `running_services_attested`, `operator_policy_approved`, `proof_generated_by_identity_request` are `false`; `release_gate` is `HOLD` |

`build` contains exactly `schema: arcora-service-build-identity/v1`,
`algorithm: sha256-canonical-source-map-v1`, `source_files` and `source_sha256`.
Its SHA-256 is the checksum of the canonical public source map at helper time.
It is not an executable checksum, reproducible-build result, compiler identity,
signature or process attestation. Git HEAD alone is not a build identity.

The build helper excludes generated output, caches and private paths, registers
exact file watches and selected safe directory watches, and embeds its generated
JSON from `OUT_DIR`. A new package layout outside the watched directories needs
an explicit rebuild and current-source comparison. Do not attribute an older
baked checksum to newly added sources merely because Cargo reused a binary.
Guest/core sources, existing ELF/vkey pins and candidate/v2 schemas remain
separate from this host-only descriptor.

Both host builds require `python3` on the build PATH to resolve to Python 3.11+
for the existing public-inventory modules. The helper fails rather than baking
a substitute checksum when that prerequisite is missing. This requirement does
not make Python part of the running identity handler.

The prover descriptor has exactly `sdk_version: 6.1.0`, `elf_sha256`, `elf_bytes`,
`program_vkey` and `supported_witness_domains`. Its ELF
checksum is taken from the actual `include_elf!("perp-core-guest")` bytes used
by the existing backend; its key is the value captured by the existing setup.
`supported_witness_domains` is `["DPCLK4"]` only when that ELF checksum is listed
with `DPCLK4` in the service's reviewed program table
(`PROGRAM_WITNESS_DOMAINS` in `crates/prover-service/src/identity.rs`); for any
other ELF, including the earlier clock-v2 guest, it is `[]`. In production
(`PROD` unset or not `0`) the service refuses to start when its embedded ELF is
not listed with `DPCLK4`. `test_pin_coherence.py` requires the reviewed guest's
ELF to be listed with `DPCLK4` once that pin changes.
The checker accepts a declared `elf_bytes` from 1 byte through 64 MiB as a
software refusal bound; this is not measured proving capacity.
The route does not substitute the candidate fixture ELF or infer a key from a
source checksum. The service supports only the clock-bound backend: `/prove`
refuses every body without the `DPCLK4` framing, including the earlier unframed
tuple and `DPCLK2` framing, before proving. It does not support candidate
`DPCLK3`. A key or source response alone cannot change that fact.

Gateway `public_config` has exactly:

| Field | Shape |
| --- | --- |
| `chain_id` | Nonzero uint64 |
| `vault` | 20-byte address; development zero is retained |
| `gateway_signer` | Nonzero public 20-byte signer address |
| `l1` | `null`, or `{settlement, vault, token, clock}`; settlement is nonzero, vault/token can be `null`, clock is `null` or `{chain_id, verifier}` |
| `prover_configured`, `clocked_prover_configured` | Booleans describing the selected transport |
| `candidate_archive_required` | Boolean runtime requirement |
| `candidate_archive` | `null`, or `{policy_binding, oracle_policy_hash}` with 32-byte values |

Prover `public_config` has exactly `{measurement, dev_insecure, admission}`.
`measurement` is a 32-byte declaration; the present software placeholder does
not become a verified hardware measurement by being served. `dev_insecure` is
a boolean. `admission` contains the resolved `max_concurrent` (1–8), `body_bytes`
(1 byte–512 MiB) and `body_timeout_ms` (1–300 seconds, in whole milliseconds from the
integer-second setting). Missing configuration stays `null` rather than being
filled with an approved target. Unavailable or required-but-missing archive
identity is refused, without inventing a policy hash.

The route exposes no URLs, raw environment, seal root, token/session secret,
keystore/archive/snapshot paths, quote bundle, account body or signing key.

## Independent expectations and file-only comparison

`scripts/local-verification/service_identity_preflight.py` reads only explicitly
supplied public JSON files. It has no HTTP, RPC, environment, runtime-process,
credential or discovery mode. Operators capture the two public responses
separately. The checker does not contact, launch or attest those services.

Its expectation document has exactly this structure:

```text
schema: arcora-public-service-expectations/v1
gateway:
  build: <independently expected complete four-field build object>
  public_config_sha256: <independently expected 64-hex checksum>
  program: null
prover:
  build: <independently expected complete four-field build object>
  public_config_sha256: <independently expected 64-hex checksum>
  program: <independently expected complete five-field prover descriptor>
```

The expectation values must come from the operator's independent expected
build/configuration record. The tool offers no “learn expectations” operation
and never generates them from a response. It cannot establish the provenance or
independent approval of a caller's expectation file; copying returned values
into that file does not provide independent verification.

The checker validates the exact current role schemas, recomputes each config
checksum and compares the whole build/program descriptors plus expected config
hashes. It rejects changed role, version, key, ELF, domain, config, build, type,
scope or capability claims, including attested/enabled/DPCLK3 promotions. It
does not invent a positive future candidate format. Booleans are distinct from
integers; private/unknown fields, duplicate keys, nonfinite or deeply nested JSON
and malformed hashes fail.

Rust/Python checksum agreement applies to this fixed schema's ASCII keys, hex
strings, fixed labels, integers, booleans and nulls. It does not establish a
general canonical JSON convention for arbitrary Unicode strings or floats.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/local-verification/service_identity_preflight.py \
  --expectations /absolute/path/independent-public-expectations.json \
  --gateway /absolute/path/captured-gateway-identity.json \
  --prover /absolute/path/captured-prover-identity.json \
  --output /absolute/path/new-service-preflight.json
```

`DECLARATIONS_MATCH` and exit 0 mean that the supplied self-reported snapshots
match the supplied expectations. The separate `candidate_compatibility` remains
`REFUSED`, `compatible: false`, with the reason that current services do not
support candidate DPCLK3 submission. This is not candidate acceptance or a
running-service attestation. Invalid or different inputs produce `BLOCKED` and
a nonzero exit; unsupported arguments never echo a submitted key, endpoint or
path. All outcomes retain HOLD and false attestation/approval/candidate flags.

Each input is limited to 64 KiB. Public-path checks exclude dotenv/secret/key
paths and symlinks. Inputs are rechecked before publication for content and file
identity changes. Output creation is exclusive and never replaces previous
bytes. These are cooperative file checks and public JSON output, not a hostile
filesystem transaction or a durable checkpoint protocol; a failed new write can
leave an incomplete new file. Malformed initial input or existing output can
refuse without creating an output file.

## Verification and remaining gates

The self-contained test command is:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/local-verification -p test_service_identity_preflight.py -v
```

Tests use explicitly synthetic independently authored expectations and captured
response objects. Each semantic negative first proves a complete positive
baseline. They exercise strict matching, capability/type/version refusals,
bounds, input changes, privacy and no-clobber; they establish no live process,
real SP1 setup/proof or hardware attestation result. Endpoint/router tests and
build-helper evidence are recorded separately by their owners.

Actual approved public target, policy and gateway/prover configuration inputs
remain missing. The user's live-feed discovery deferral remains in force; no
credential or discovery request is restarted. A captured response proves only
that an endpoint returned bytes, and a proxy or malicious process may imitate
matching declarations. Real target/service observation, nonce-bound verified
app/CC evidence and key release, DON/uptime health, new proof/settlement/claim,
custody, capacity/finality and independent review remain separate open gates.
[ACTIVE_WORK.md](ACTIVE_WORK.md) continues to govern production HOLD.
