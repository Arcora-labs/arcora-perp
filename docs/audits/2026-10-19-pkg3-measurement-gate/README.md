# History measurement gate: guest cost against state size

PRODUCTION RELEASE HOLD. No proof was generated, no program key was derived, and no
chain, RPC or service was contacted. All inputs are public synthetic test data.

Date: 2026-10-19. Source: `ced4b0bf6e3404c5805fe397f251faaa15feefb7` on
`fix/perp-core-hardening-20261017`, with the measurement tool
`crates/sp1-host/src/bin/measure-history.rs` not yet committed. The 21 guest input
files and their hashes are listed in `measurement.json` (`source`). Every number
below comes from `measurement.json`.

## Summary

- Every batch proof decodes the whole pre-state and derives the state root before
  and after the batch, so its cost grows with the history the state carries: note-tree
  leaves plus spent nullifiers, `H`. The cost is linear in `H`. Phase 0 and the solvent
  phase 1 take about 30,000 guest cycles per unit of `H`. The phase-1 variant with a
  shortfall, which reissues every note, takes about 38,000. At the gate sizes 91 to 96%
  of the cycles are software Keccak.
- No GPU proving rate is recorded in this repository, so the conversion to proving time
  assumes one. The launch prover budget is 900 s per proof. With a 2x margin, the
  recorded 250 s Groth16 wrap and an assumed sustained rate of 1,000,000 cycles/s, a
  proof can take at most 200,000,000 cycles. The shortfall phase 1 sets the bound: it
  measures 198,725,972 cycles at `H` = 5,280 and 201,728,802 at 5,360.
- Recommended admission bounds: `MAX_PROVABLE_HISTORY` = 5,280 (soft cap 4,224),
  positions 528, notes 1,056. They hold for both the software and the precompile build,
  and are re-derived from the precompile ELF's measured cycles and from the GPU-day rate.
- Keccak precompile: **adopt**. Without it the bound is 5,280, below the planned
  100,000 (the provisional bound in `crates/gateway/src/admission.rs`). Software Keccak
  reaches 100,000 only at a sustained 19.0 M cycles/s. The precompile is projected to
  cut the cost per unit of history by about 2.1x, so 100,000 would then need 8.9 M
  cycles/s.

## Guest ELF

`b6da3317197b3dcde44929606f5375c980bb05f523c818122ecfabacec01e9f2`, 536,264 bytes, taken
from `<out>/target/riscv64im-succinct-zkvm-elf/release/perp-core-guest`. It is not
taken from a `build.rs` guest build.

Running `scripts/local-verification/rebuild_reviewed_guest.py` unchanged stops before
building. It reports `guest source changed; rebuild and reprove:
crates/perp-core/src/clock.rs`, because the reviewed source pins are regenerated only
after this gate. So a scratch driver called the recipe's `build()` with one difference:
the source hashes of the current tree stand in for the 21 reviewed pins. They are read
once at the start and checked again on every compiler invocation. Every other part of
the recipe ran unchanged:

- the pinned succinct rustc 1.93.0-dev and cargo 1.99.0;
- `--locked --offline --release --target riscv64im-succinct-zkvm-elf`, `CARGO_BUILD_JOBS=2`
  and the recipe's rustc flags;
- the crate-metadata normalization and the path remap;
- the source-unchanged-during-build check;
- the final comparison with the reviewed ELF pin. It failed, as expected until the pins
  are regenerated.

The recipe's 900 s process timeout was raised to 3,600 s for this loaded host. It bounds
only the build process. Two builds in two fresh output directories, of 1,115 s and
334 s, produced the same SHA-256.

## Measurement tool

`measure-history --elf GUEST_ELF --out NEW_JSON [--history H[,H...]] [--batch ...]`
builds conservation-consistent pre-states from public perp-core and prover APIs only.
It frames each witness with `sp1_host::encode_clock_witness` and executes it on the
sp1-sdk 6.1.0 light client: execute only, no setup, no proving. Each run checks that the
guest's public value equals the native commitment and records:

- cycles and SP1 gas;
- guest execution wall time;
- peak RSS (`getrusage`);
- witness size and SHA-256;
- the Keccak work of the same transition run natively over a counting `Hasher`: calls,
  absorbed bytes and keccak-f permutations, in total and per stage.

Three calibration witnesses differ only in tree depth (8, 36 and 64). Each level adds
three 65-byte node hashes. They give 8,040.3 cycles per hash, and the midpoint error is
0.0%. The Keccak share of a run is its counted permutations times that cost, divided by
its cycles. A fixed few dozen permutations per batch run outside the `Hasher` and are not
counted: the clock receipt, the settlement-tree roots, deposit leaves and oracle-signer
recovery.

The binary (`18ce6445...`) was built with `SP1_SKIP_PROGRAM_BUILD=true` and an empty stub
ELF. There is no dependency or lockfile change. The committed file builds to this
binary, `cargo clippy` reports no warning for it and `rustfmt --check` passes. The 10,000 to 100,000 runs used a build
taken before a rustfmt and comment-only pass, whose code lines are identical. The final
build re-ran all three 10,000 batches and reproduced the same witness hashes,
commitments, cycles, gas and Keccak counts.

## Size mapping

`H` is a multiple of 80, and:

- unspent notes `N = H/5`;
- positions `P = H/10`, over 4 markets;
- tree leaves `L = (H + N)/2 = 3N`;
- spent nullifiers `F = H - L = L - N`.

So 500,000 gives 50,000 positions and 100,000 notes. The ratio is that of the
provisional gateway bounds.

Per batch the Keccak work is about:

- 4 permutations per leaf: each state root hashes every leaf and its tree node;
- 1 per nullifier: the decode rebuilds the nullifier chain;
- 2.4 per note and 2.8 per position: the notes and positions digests.

That is about `2.5 H + 3.9 N + 2.8 P` permutations, and it matches the counted runs to
0.1%. It grows with each of `H`, `N` and `P`. The three bounds are enforced separately,
so a state with all three at their bounds is the costliest one they admit. That is the
shape measured.

The pre-states have:

- 4 fee-bearing markets with recorded prices and a non-zero stored funding rate and
  carry;
- trader pairs holding opposite positions;
- reserves of 8,000 USD;
- tree depth 24, and a wind-down recipient set.

The batches:

- `phase0`: one deposit; two fills between the same two traders (a taker buy that grows
  both positions, then a partial reverse); one L1 withdrawal; two AccrueFunding ticks.
  That is 4 timed ops in 700 ms.
- `phase1`: SettleAll over the whole state with no shortfall. The reserves leave as one
  wind-down recipient withdrawal leaf.
- `phase1-haircut`: SettleAll with recorded prices at twice the entry and empty
  reserves. The pro-rata haircut reissues every unspent note, adding `N` leaves before
  the post-state root.

## Results

The host was an Apple M4 (10 cores, 16 GiB) on macOS 26.5.1, a shared workstation. Other
build, test, virtual-machine and interactive workloads were running, the load average
was between about 5 and 24, and swap was in use. Cycles, gas and Keccak counts are
deterministic. Wall time and memory are this host's at that load.

| Batch | H | Witness bytes | Cycles | Gas | Keccak share | Execute s | Peak RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| phase0 | 10,000 | 605,472 | 308,746,303 | 295,889,915 | 0.928 | 30 | 1,199 |
| phase0 | 50,000 | 3,021,671 | 1,502,477,548 | 1,449,330,698 | 0.951 | 158 | 2,226 |
| phase0 | 100,000 | 6,041,909 | 2,999,864,877 | 2,904,173,833 | 0.953 | 177 | 4,646 |
| phase0 | 250,000 | 15,102,625 | 7,510,362,229 | 7,315,619,453 | 0.951 | 499 | 2,778 |
| phase0 | 500,000 | 30,203,809 | 15,046,445,208 | 14,713,084,559 | 0.949 | 185 | 5,314 |
| phase1 | 10,000 | 604,652 | 298,700,156 | 286,035,914 | 0.959 | 33 | 1,168 |
| phase1 | 50,000 | 3,020,849 | 1,497,032,162 | 1,443,667,660 | 0.955 | 98 | 3,622 |
| phase1 | 100,000 | 6,041,087 | 3,001,361,013 | 2,912,030,724 | 0.952 | 182 | 4,272 |
| phase1 | 250,000 | 15,101,803 | 7,530,928,440 | 7,354,955,977 | 0.948 | 282 | 4,431 |
| phase1 | 500,000 | 30,202,987 | 15,098,764,685 | 14,799,885,608 | 0.946 | 123 | 5,754 |
| phase1-haircut | 10,000 | 604,640 | 376,597,213 | 357,954,194 | 0.926 | 48 | 1,458 |
| phase1-haircut | 50,000 | 3,020,837 | 1,893,242,378 | 1,814,975,658 | 0.919 | 117 | 4,636 |
| phase1-haircut | 100,000 | 6,041,075 | 3,800,185,818 | 3,661,259,645 | 0.915 | 208 | 5,164 |
| phase1-haircut | 250,000 | 15,101,791 | 9,547,532,149 | 9,255,667,343 | 0.911 | 171 | 4,642 |
| phase1-haircut | 500,000 | 30,202,975 | 19,166,171,669 | 18,654,225,573 | 0.907 | 247 | 6,341 |

Every size was measured, so none is extrapolated. No run came near the 5,400 s
per-process limit. The longest process took 508 s.

Peak RSS is the resident peak. Under this host's memory pressure it is not monotone in
`H`, because pages were compressed and swapped. A 10 s sample of the physical footprint
(resident plus compressed) peaked at 8,570 MiB at 250,000 and at 9,367 MiB at 500,000,
both in phase 1.

The cap region was also measured at 2,000, 4,000, 5,280, 5,360, 6,000 and 8,000. The
bounds are interpolated between measured points, not taken from the global fit.

| Batch | 4,000 | 5,280 | 5,360 | 6,000 |
|---|---:|---:|---:|---:|
| phase0 | 130,465,453 | 168,453,424 | 170,829,072 | 189,809,940 |
| phase1 | 119,722,171 | 157,856,282 | 160,247,755 | 179,300,863 |
| phase1-haircut | 150,541,634 | 198,725,972 | 201,728,802 | 225,819,369 |

Least squares over the five gate sizes give `-2.0 M + 30,086 H` cycles for phase 0,
`-13.5 M + 30,213 H` for phase 1 and `-24.9 M + 38,361 H` for the shortfall variant.
Across the gate sizes the cycles per unit of history stay within 3%:

- phase 0: 29,999 to 30,875;
- phase 1: 29,870 to 30,198;
- shortfall variant: 37,660 to 38,332.

The fit's largest residual, 4.8%, is at 10,000. That is why the bounds come from the
measured points.

At `H` = 100,000 the counted permutations split as follows:

- phase 0 and phase 1: 11.3% decode, 44.4% each state root, ~0% batch and commitment;
- shortfall variant: 9.3% decode, 36.4% pre-root, 9.2% batch (the reissue) and 45.1%
  post-root.

## Conversion to proving time

`T(H) = fixed + cycles(H) / R`. A size fits when `T(H) <= budget / 2` for all three
batches.

- **Budget, 900 s.** `PROVER_TIMEOUT_SECS` defaults to 900 s and bounds each `/prove`
  call (`crates/gateway/src/prover_client.rs`). The gateway refuses to boot unless
  `anchorTimeoutMs >= (2 x 1,200 + PROVER_TIMEOUT_SECS + 300) x 1000`
  (`crates/gateway/src/l1.rs`, with `FINALITY_BUDGET` in
  `crates/gateway/src/clock_wait.rs`). The launch `anchor_timeout_ms` is 3,600,000
  (`docs/REDEPLOY-CC-RUNBOOK.md`, `docs/RELEASE_MANIFEST.md`), which leaves 900 s for
  proving.
- **Fixed, 250 s.** The Groth16 wrap of the clock-v2 proof took 249.8 s of container
  time with 4 CPUs and 13 GB (`docs/audits/2026-10-09-clock-final/generation.json`,
  `.github/workflows/clock-proof-wrap.yml`). Its input is the constant-size recursion
  output, so it does not grow with the program.
- **Rate `R`, assumed.** The committed clock-v2 proof
  (`contracts/integration/fixtures/clock-v2-verified`) records 6,035,092 cycles, but not
  its core and recursion time. So `R`, the sustained core-plus-recursion rate of the
  launch prover, is assumed at 1,000,000 cycles/s. The value is taken at the low end
  because the hard cap protects a one-shot wind-down proof. It is raised only by a
  measured rate.

The cap scales linearly with `R` and with the compute seconds per proof,
`(anchorTimeoutMs / 1000 - 2,700) / 2 - 250`.

| R (cycles/s) | Max cycles per proof | Cap, software Keccak | Cap, precompile (projection) |
|---:|---:|---:|---:|
| 0.5 M | 100 M | 2,652 | 5,848 |
| 1 M | 200 M | 5,313 | 11,608 |
| 2 M | 400 M | 10,617 | 22,919 |
| 4 M | 800 M | 21,166 | 45,541 |
| 8 M | 1,600 M | 42,266 | 89,925 |
| 16 M | 3,200 M | 84,263 | 177,290 |
| 32 M | 6,400 M | 167,852 | 350,427 |

Precompile projection: suppose every counted keccak-f ran as SP1's `KECCAK_PERMUTE`
syscall. Each permutation then saves the gas of the 6,437 `tiny_keccak::keccakf`
instructions in this ELF (6,119 gas at the measured gas per cycle of Keccak code) minus
the syscall's 1,625 gas. The syscall cost comes from SP1 6.1.0's own cost tables:
`sp1-core-executor` `cost_and_height_per_syscall`, `rv64im_costs.json`, the `gas.rs`
complexity mapping and the `report.rs` normalization. Absorb, padding and loop code
stay in software. This is a projection: the precompile build needs a network fetch and
is measured once it is built.

## Recommendation

| Bound | Value |
|---|---:|
| `MAX_PROVABLE_HISTORY` | 5,280 |
| soft cap (80%) | 4,224 |
| positions | 528 |
| notes | 1,056 |
| adopt the Keccak precompile | yes |

The shortfall phase 1 is the costliest batch at every measured size and sets the
bound. Phase 0 and the solvent phase 1 alone would allow about 6,300 and 6,700.
Positions and notes keep the measured ratios `H/10` and `H/5`. The bound is measured on
the software build and also holds for the precompile build, which only lowers the cost.

After the precompile ELF is built with the reviewed recipe, run this tool on it and set
the bounds from its measured cycles with the same formula. The projection at 1 M
cycles/s is about 11,600, with 1,160 positions and 2,320 notes. At the launch budget, the
planned 100,000 needs a measured `R` of at least 8.9 M cycles/s with the precompile, or a
larger `anchorTimeoutMs` at deploy.

## Reproduce

```sh
# toolchain: rustc/cargo 1.99.0; PROTOC and PROTOC_INCLUDE set; CARGO_TARGET_DIR=<target>
mkdir -p $CARGO_TARGET_DIR/elf-compilation/riscv64im-succinct-zkvm-elf/release
touch $CARGO_TARGET_DIR/elf-compilation/riscv64im-succinct-zkvm-elf/release/perp-core-guest
SP1_SKIP_PROGRAM_BUILD=true cargo build --release --locked --offline \
  --manifest-path crates/sp1-host/Cargo.toml --bin measure-history
$CARGO_TARGET_DIR/release/measure-history --elf <guest ELF> --out <new>.json \
  --history 10000 --batch phase0
```

Each (`H`, batch) pair ran as its own process so that peak RSS is per run. Histories
ran in increasing order, with a 5,400 s wall limit per process. The tool refuses to
overwrite an existing output file.

## GPU day

GPU day re-measures. It proves phase 0, phase 1 and the shortfall variant at the
configured bound on the launch prover, records the proving time and the sustained rate
`R`, and re-derives the bound with the formula above. This gate settles the program
decision, the precompile, before the program key freezes. The bounds are admission
policy and change without a new program key.
