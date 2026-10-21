# Verified proof of the reviewed clock guest

Public synthetic test data only. There are no production keys, account records
or live user deposits here. The witness is the reviewed normal fixture of
`../clock-pkg3-reviewed/` (same bytes, same guest ELF, same setup key); every key,
owner and deposit in it is a public test value from the `sp1-host` fixture code.

This directory is `PROOF_FIXTURE["dir"]` in
`scripts/local-verification/verify_clock_proof.py`. Its proof is a proof of the
reviewed fixture under the reviewed guest, so `proof_status()` reads `PROVEN`.

| File | Content |
| --- | --- |
| `proof.bin` | The 356-byte Groth16 proof (verifier selector `4388a21c`), SHA-256 `28d6804949242eac9a44e0d90542674a4e3325c15fbac30f258215505e6084db`; `../clock-v2/verified-calldata/proof.bin` is the same bytes |
| `public-values.bin` | The proof's public value, the bound commitment `0x6e382af92ac5b4872e4a1f6c0f6bdf6d1a246bb2ca6f834dc7aeb3748edab5ab` |
| `proof.sdk.json` | The SP1 SDK proof object |
| `proof-evidence.json` | The `clock-proof --prove` record: identity, cycles, the 22 negatives, the prover backend and wall times |
| `execution.json` | The same run's execution record (fixture, cases, negatives, setup key) |
| `guest.elf`, `program-vkey.bin`, `clock.witness.bin` | Byte-identical to `../clock-pkg3-reviewed/` |

The run also wrote the case and negative witnesses; they are byte-identical to
`../clock-pkg3-reviewed/cases/` and `negatives/` and are not repeated here.

## How it was produced

On 2026-10-21, on a rented single NVIDIA H100 80 GB HBM3 (driver 595.91.07,
CUDA 13.2 host; 26 vCPU), from commit `6fb38a5` of this repository:

```sh
SP1_SKIP_PROGRAM_BUILD=true cargo build --release --locked \
  --manifest-path crates/sp1-host/Cargo.toml --features cuda --bin clock-proof
python3 scripts/local-verification/download_clock_circuit.py ~/.sp1/circuits/groth16/v6.1.0
crates/sp1-host/target/release/clock-proof \
  --elf contracts/integration/fixtures/clock-pkg3-reviewed/guest.elf OUT --prove
```

- The guest ran on SP1 6.1.0's GPU prover, `sp1-gpu-server` 6.1.0 from the
  `v6.1.0` SP1 release (`sp1_gpu_server_v6.1.0_x86_64.tar.gz`, SHA-256
  `f76d0430df8602dbeeda881453580936acb976179d743f5e31a8f42ddb1719c0`, checked
  before use; the server binary's SHA-256 is
  `eede5df89e9e8957f5d06cf9abdca3e979a80224c25d84796a60f47766ab58da`).
- The Groth16 wrap used the pinned circuit files that `download_clock_circuit.py`
  verifies (verifying key `4388a21c…`).
- `clock-proof` first checked native == guest on the fixture, the nine cases and
  the 22 negatives. It then generated the proof and verified it with the SP1 SDK
  verifier (`local_sdk_verified` true).
- The Groth16 proof took 78.2 s of wall time, including about 25 s of one-time
  circuit loading.

## Verify

Run from the repository root:

```sh
python3 scripts/local-verification/verify_clock_proof.py --output-dir /tmp/arcora-clock-proof-verification
```

The runner checks the pinned guest sources, ELF, setup key, witness, public
commitment, vendor provenance and proof shape before executing 24 real-verifier
Solidity checks, including the actual clock adapter, settlement and vault.

The token is mocked and fixed synthetic addresses are installed by running the
real constructors. The zero payer is impersonated inside an owned local EVM.
These tests do not establish live deposit provenance, matching fairness, a full
HTTP/order/production lifecycle, deployability, or a completed fund migration.
