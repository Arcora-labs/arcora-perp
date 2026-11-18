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
| `proof.bin` | The 356-byte Groth16 proof (verifier selector `4388a21c`), SHA-256 `81239e2e80fdba37ceea96eee67155b7cb7e8d1590ebea2bd3a03af68e97e2c7` |
| `public-values.bin` | The proof's public value, the bound commitment `0x6e382af92ac5b4872e4a1f6c0f6bdf6d1a246bb2ca6f834dc7aeb3748edab5ab` |
| `proof.sdk.json` | The SP1 SDK proof object |
| `proof-evidence.json` | The `clock-proof --prove` record: identity, cycles, the 22 negatives, the prover backend and wall times |
| `execution.json` | The same run's execution record (fixture, cases, negatives, setup key) |
| `guest.elf`, `program-vkey.bin`, `clock.witness.bin` | Byte-identical to `../clock-pkg3-reviewed/` |

The run also wrote the case and negative witnesses; they are byte-identical to
`../clock-pkg3-reviewed/cases/` and `negatives/` and are not repeated here.

This proof replaces the proof of the earlier reviewed guest (proof `28d68049…`,
2026-10-21), which the audit 2026-11-16 PC-1 and PC-2 fixes to `crates/perp-core`
and the k256 0.14 upgrade (RUSTSEC-2026-0387) superseded. The normal fixture's
witness and bound commitment did not change; the guest ELF and its setup key did.

## How it was produced

On 2026-11-18, on a Google Colab VM with a single NVIDIA A100 (40,960 MiB, driver
580.82.07, CUDA 13.0 host; 12 vCPU, 83 GB), from commit `8b569ec` with this change's
k256 0.14 upgrade and its re-pin of `REVIEWED_GUEST` and of the `sp1-host`
`REVIEWED_ELF` constants applied:

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
  `eede5df89e9e8957f5d06cf9abdca3e979a80224c25d84796a60f47766ab58da`). The image
  ships CUDA 13 only, so the server's `libcudart.so.12` came from NVIDIA's
  `nvidia-cuda-runtime-cu12` 12.9.79 wheel preinstalled on it, prepended to
  `LD_LIBRARY_PATH` ahead of the driver directory.
- The Groth16 wrap used the pinned circuit files that `download_clock_circuit.py`
  verifies (verifying key `4388a21c…`); the archive was fetched over parallel
  connections and checked by that script's own verification.
- `clock-proof` first checked native == guest on the fixture, the nine cases and
  the 22 negatives. It then generated the proof and verified it with the SP1 SDK
  verifier (`local_sdk_verified` true).
- The Groth16 proof took 102.4 s of wall time, including about 32 s of one-time
  circuit loading (R1CS 27.8 s, proving key 4.2 s); the gnark prover itself took
  48.1 s.

The run record is `docs/audits/2026-11-18-guest-reproof/reproof.json`.

## Verify

Run from the repository root:

```sh
python3 scripts/local-verification/verify_clock_proof.py --output-dir /tmp/arcora-clock-proof-verification
```

The runner checks the pinned guest sources, ELF, setup key, witness, public
commitment, vendor provenance and proof shape before executing 27 real-verifier
Solidity checks, including the actual clock adapter, settlement and vault. Its
output for this proof is in `docs/audits/2026-11-18-guest-reproof/real-clock-proof/`.

The token is mocked and fixed synthetic addresses are installed by running the
real constructors. The zero payer is impersonated inside an owned local EVM.
These tests do not establish live deposit provenance, matching fairness, a full
HTTP/order/production lifecycle, deployability, or a completed fund migration.
