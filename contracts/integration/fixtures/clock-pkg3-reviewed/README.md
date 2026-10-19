# Reviewed clock guest: identity and CPU execution record

Public synthetic test data only. There are no production keys, account records
or live user deposits here. Every key, owner and deposit is a public test value
from the `sp1-host` fixture code (`crates/sp1-host/src/lib.rs`,
`crates/sp1-host/src/cases.rs`); the deposit is not an observed L1 event.

This directory is `REVIEWED_GUEST["identity_dir"]` in
`scripts/local-verification/verify_clock_proof.py`. It holds the guest program
the checkout is reviewed to build, its setup key, and its outputs on the normal
fixture, the case witnesses and the negatives (`REVIEWED_FIXTURE`). It holds no
proof. The Solidity real-proof gate still verifies the committed proof of the
earlier clock-v2 guest in `../clock-v2-verified/`, so `proof_status()` reads
`PENDING_REPROOF` until a proof of this fixture under this guest is committed.

| File | Content |
| --- | --- |
| `guest.elf` | The reviewed guest ELF, 535904 bytes, SHA-256 `a6d516488c542673ef750c6c6d7cd0fb6b9c004d0cb6c82eb5b4bc57d630e7df` |
| `program-vkey.bin` | Its 32-byte setup key, `0x009cfc02120c4255b1a8c3eebbcc31f92a9ce0891c88641e78e0af23aae098ec` |
| `clock.witness.bin` | The normal fixture witness (`DPCLK4` framing), SHA-256 `70b90edcb2cf4e673053ca91b3b811865ca917388ff28a9a0aa696b740f5fa4a` |
| `execution.json` | The `clock-proof --no-prove` record: hashes, commitments and cycle counts of the fixture, every case and every negative |
| `cases/` | The nine case witnesses, `NAME.witness.bin` |
| `negatives/` | The 22 negative witnesses, `NAME.witness.bin` |
| `lifecycle/` | The funds-lifecycle export, described by its own README |

## Normal fixture

Its shape is the one `contracts/integration/ClockBoundRealProof.t.sol` sets up:
chain 84532, verifier `0x11…11`, settlement `0x22…22`, batch 0, anchored at
101,000 ms with a 10,000 ms window and 2,000 ms skew. Its four operations:

- a deposit of 1,000,000 with deposit id 0 from payer address(0), whose owner is
  bound by a blinded owner commit;
- a withdrawal of that note, 1,000,000 to `0xAB…AB` with nonce 1 (the batch's only
  withdrawal leaf);
- two funding ticks, the batch's only timed operations, at 100,000 ms and
  100,700 ms. The first commits the open span at the stored non-zero rate,
  carrying the funding remainder, and adopts a new rate; the second commits its
  700 ms at that rate, which moves the funding index.

The pre-state is hand-built: a fresh settlement's batch counter, deposit
accumulator and withdrawal nonce, on a depth-24 tree with a wind-down recipient.
Three notes are allocated outside the deposit accumulator and counted as external
value in, so conservation holds. The engine's own operations then bind two of
them as collateral (two nullifiers, in an insertion order that is not their
sorted order), open a long against a short, and run two funding ticks, which
leave a non-zero stored rate, funding remainder and recorded price. The third
note stays unspent.

The bound commitment (the guest's public value) is
`0x6e382af92ac5b4872e4a1f6c0f6bdf6d1a246bb2ca6f834dc7aeb3748edab5ab`. The guest
executes the fixture in 5,750,329 cycles.

## Cases and negatives

| Case | Wind-down phase | Cycles |
| --- | --- | --- |
| `epoch-price-refresh` | 0 | 2,971,773 |
| `pause-reopen-fill` | 0 | 5,740,006 |
| `bad-debt-treasury-adl` | 0 | 2,981,347 |
| `debt-top-up-prune` | 0 | 252,270 |
| `debt-top-up-next-batch` | 0 | 2,972,380 |
| `full-exit-prune` | 0 | 5,755,654 |
| `empty-keepalive` | 0 | 251,800 |
| `settle-all-two-markets` | 1 | 290,552 |
| `phase-two-exit` | 2 | 318,416 |

Each case is accepted natively and by the guest with the same commitment. Each
negative is refused natively with its expected error and by the guest with exit
code 1 and no public value: the five clock-context negatives of the normal
fixture, three engine refusals of the normal fixture, eight engine refusals of
case-derived and fresh batches, and six framings the guest does not accept.

## Provenance

Built from the working tree on top of commit
`8820eb58490788aea2dfac2ef831155a364d2153`, whose guest inputs are the 21
`REVIEWED_GUEST["sources"]` pins. The host was macOS on aarch64.

1. `rebuild_reviewed_guest.py` with the pinned succinct rustc 1.93.0-dev and
   Cargo 1.99.0 (`--locked --offline`, the tiny-keccak precompile patch already
   checked out in `CARGO_HOME`), into two fresh output directories. Both runs
   reported `PASS_BYTE_EXACT_REVIEWED_ELF_REBUILD` with the ELF above, and the
   two ELFs were byte-identical.
2. `vkey --elf guest.elf` from an `sp1-host` built with
   `SP1_SKIP_PROGRAM_BUILD=true` and an empty stub in place of the build-script
   guest. It printed the setup key above, the same for both ELFs.
   `program-vkey.bin` is that key's 32 bytes.
3. `clock-proof --elf guest.elf <new directory> --no-prove`, once per ELF. The two
   output directories were byte-identical; `guest.elf`, `clock.witness.bin`,
   `execution.json`, `cases/` and `negatives/` here are that output, unchanged.

No proof was generated and no setup ran in step 3.

## Check

From the repository root, with the two hosts built as in step 2:

    cargo build --release --locked --manifest-path crates/sp1-host/Cargo.toml \
      --bin vkey --bin clock-proof
    python3 scripts/local-verification/check_reviewed_guest_execution.py \
      --vkey-bin <target>/release/vkey \
      --clock-proof-bin <target>/release/clock-proof \
      --output-dir <new directory>

It requires the checkout's guest sources to be `REVIEWED_GUEST`'s, re-derives the
setup key from `guest.elf`, executes the fixture, every case and every negative
on CPU, and compares every output with `REVIEWED_GUEST` and `REVIEWED_FIXTURE`.
CI runs it in the "reviewed guest execution (CPU)" job.
