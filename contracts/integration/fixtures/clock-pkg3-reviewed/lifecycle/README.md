# Funds lifecycle witnesses

Public synthetic test data written by the gateway's funds lifecycle test
(`crates/gateway/src/funds_lifecycle_tests.rs`, see `docs/FUNDS_LIFECYCLE.md`).
The test runs an owned loopback HTTP gateway against a disposable Anvil chain
(chain id 31337) with fixed public test wallets, a mock token and the mock inner
verifier behind the real `ClockBoundVerifier`. No configured chain, credentials,
user state or real funds are involved.

| File | Content |
| --- | --- |
| `batch-0.witness.bin` … `batch-3.witness.bin` | The four wallet windows, exact clock-bound witnesses (`DPCLK4` framing) |
| `keepalive-batch-4.witness.bin` | The idle gateway's empty, untimed keepalive window |
| `lifecycle.json` | The run's manifest: every hash, transaction, commitment and root |

`lifecycle.json` lists the four wallet windows under `batches` and the
keepalive under `keepalive`.

## Readers

- `replay-funds` (`crates/sp1-host/src/bin/replay-funds.rs`) replays the four
  wallet windows. It checks the manifest, witness hashes, strict decoding and
  re-encoding, chain and contract identity, state-root continuity, conservation,
  the deposit prefix, withdrawal roots, commitments and clock receipts.
- `scripts/local-verification/verify_funds_replay.py` pins every file here
  (`LIFECYCLE_DIR`, `LIFECYCLE_MANIFEST_SHA256`, `LIFECYCLE_WITNESSES`). It
  refuses this directory when a file is changed, missing or added, before any
  replay. It then runs the native positive control and the negative controls.
  `test_verify_funds_replay.py` ties the pins to the files, the manifest and
  this README.

`replay-funds` requires `--elf` to name the ELF that its `REVIEWED_ELF`
constant pins, the reviewed guest in `../guest.elf`. `--native-only` checks
that hash but executes no guest; without it the guest runs every witness too.

## Provenance

The run reads no wall clock and no OS entropy where they reach engine state.
`lifecycle.json` records both under `injectedClock`:

- the epoch is 2026-01-01T00:00:00Z (`epochMs` 1767225600000), which is also the
  chain's genesis timestamp;
- each later block is one second after the one before it;
- after each transaction or mined block, the gateway's clock moves to the
  latest block's timestamp;
- account seeds, API keys and deposit blinds come from a keccak256 stream of a
  fixed test seed.

The source was the working tree on top of commit
`8820eb58490788aea2dfac2ef831155a364d2153`. The host was macOS on aarch64 with
Rust 1.99.0 and Foundry (forge and anvil) 1.7.2-nightly `dea99c5`. The
contracts were built with `forge build --root contracts`.

Two exports on this host, into two fresh directories, were byte-identical in
every file. `lifecycle.json` also has a `host` block that names the machine, so
an export from another host differs at least there. The release-evidence
workflow's drill job (`.github/workflows/a11-release-evidence.yml`, step
"Lifecycle export equals the committed lifecycle witnesses") exports them again
on a Linux runner and fails unless every `*.witness.bin` equals the file here
byte for byte; `lifecycle.json` is not compared.

## Regenerate

A new export is a deliberate re-pin. From the repository root:

    forge build --root contracts
    ARCORA_FUNDS_WITNESS_DIR=<new absolute directory> \
      cargo test -p gateway funds_lifecycle_tests --locked -- --ignored --nocapture

The directory must not exist. Export twice and compare the two directories
before you replace these files. Then update `verify_funds_replay.py`, the list
below and the source commit above.

## Native replay

With `SP1_SKIP_PROGRAM_BUILD=true` and an empty stub file in place of the
embedded guest:

    cargo build --release --locked --manifest-path crates/sp1-host/Cargo.toml --bin replay-funds
    <target>/release/replay-funds \
      contracts/integration/fixtures/clock-pkg3-reviewed/lifecycle <new directory> \
      --native-only --elf contracts/integration/fixtures/clock-pkg3-reviewed/guest.elf
    python3 scripts/local-verification/verify_funds_replay.py \
      --binary <target>/release/replay-funds \
      --elf contracts/integration/fixtures/clock-pkg3-reviewed/guest.elf \
      --witness-dir contracts/integration/fixtures/clock-pkg3-reviewed/lifecycle \
      --output-dir <new directory>

The replay printed `FUNDS_CLOCK_REPLAY_PASS guest_executed=false`, and the
harness passed its native positive control and every negative control. Run
without `--native-only`, the same command executes the reviewed guest on all
four windows and prints `FUNDS_CLOCK_REPLAY_PASS guest_executed=true`
(39,587,472 cycles in total).

## SHA-256

    8d0f6c540bfe0624ab08204e1c3aebe9e24dff2306d34a7e3d47010ddfff1cb7  batch-0.witness.bin
    d5b0f13ae8925fe5975b2c67b324ab3869cbb0e94eb82c254d1dcf11226a2c98  batch-1.witness.bin
    79161f155882a14e9db392f8e07c6b8e7e3f74cef000d9ca851b1695eb43767b  batch-2.witness.bin
    97b3965c29aeeac57c8d28acadf968cc8dce871f35daa3b91a11bc5826115a57  batch-3.witness.bin
    5c78b6e48ecd8d57e2006afb8e75100ac6840d4880e70a7df7dd51594333379a  keepalive-batch-4.witness.bin
    fa4c04ae1b08b17d7beb56696fc2876b558f5042644f2fb224382a6bf9b1b1f3  lifecycle.json
