# History measurement gate: guest cost against state size

PRODUCTION RELEASE HOLD. No proof was generated, no program key was derived, and no
chain, RPC or service was contacted. All inputs are public synthetic test data.

Date: 2026-10-19. Two builds of the same program sources were measured:

- the **software build** (Keccak in RISC-V code), from
  `ced4b0bf6e3404c5805fe397f251faaa15feefb7`, in a first session;
- the **precompile build**, from `8820eb58490788aea2dfac2ef831155a364d2153` plus the
  `crates/sp1-guest/Cargo.toml` and `Cargo.lock` change that adds the tiny-keccak
  patch, in a second session. The other 19 guest inputs are byte-identical to the
  software build's.

Both on `fix/perp-core-hardening-20261017`. The guest input files and their hashes
are listed in `measurement.json` (`source`, `builds.software.source`). Every number
below comes from `measurement.json`.

## Summary

- Every batch proof decodes the whole pre-state and derives the state root before
  and after the batch, so its cost grows with the history the state carries: note-tree
  leaves plus spent nullifiers, `H`. The cost is close to linear in `H`. The phase-1
  variant with a shortfall, which reissues every note, is the costliest batch at
  every measured size.
- **Keccak precompile: adopted.** The guest takes tiny-keccak 2.0.2 from Succinct's
  patch (`https://github.com/sp1-patches/tiny-keccak`, commit
  `957430a459f7a2332ab5bab4a12f9b473bb95c87`, tag `patch-2.0.2-sp1-6.0.0`). On the
  zkVM target it runs keccak-f as SP1's `KECCAK_PERMUTE` syscall; the host code path
  is unchanged and so are all outputs: every witness, commitment and post-state is
  the same in both builds.
- **Measured saving.** One 65-byte node hash costs 1,608 cycles and 2,671 SP1 gas
  in the precompile build, against 8,040 cycles and 7,643 gas in the software build.
  Across the gate sizes the precompile build takes 3.6 to 4.3 times fewer cycles and
  2.4 to 2.6 times less gas.
- **Cost metric.** The executor counts a syscall as one instruction, so the
  precompile build's cycle count leaves out the work of proving the permutation.
  SP1 gas, its estimate of proving cost, includes it. The bound therefore uses
  cost-equivalent cycles: the software build's cycles for the same witness, scaled
  by the measured gas ratio. For the software build they are its cycles.
- **Budget.** No GPU proving rate is recorded in this repository, so the conversion
  to proving time assumes one. The launch prover budget is 900 s per proof. With a
  2x margin, the recorded 250 s Groth16 wrap and an assumed sustained rate of
  1,000,000 cycles/s, a proof can take at most 200,000,000 cost-equivalent cycles.
- **Admission bounds, from the precompile build:** `MAX_PROVABLE_HISTORY` = 13,280
  (soft cap 10,624), positions 1,328, notes 2,656. The shortfall phase 1 measures
  198,828,755 cost-equivalent cycles at `H` = 13,280 and 200,064,036 at 13,360. The
  software build's bound would be 5,280. GPU day re-derives the bounds from the
  measured proving rate.

## Guest ELFs

| Build | SHA-256 | Bytes | Builds |
|---|---|---:|---|
| software | `b6da3317197b3dcde44929606f5375c980bb05f523c818122ecfabacec01e9f2` | 536,264 | 1,115 s and 334 s |
| precompile | `a6d516488c542673ef750c6c6d7cd0fb6b9c004d0cb6c82eb5b4bc57d630e7df` | 535,904 | 57.5 s and 55.5 s |

Each ELF is taken from `<out>/target/riscv64im-succinct-zkvm-elf/release/perp-core-guest`,
not from a `build.rs` guest build. Each was built twice, in two fresh output
directories, and both builds gave the same SHA-256.

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
- for the precompile build, the recipe's check of the guest's dependency sources and
  of the patch's checkout in `CARGO_HOME` against its pinned source tree, before and
  after the build (the build is offline, from that checkout);
- the final comparison with the reviewed ELF pin. It failed, as expected until the pins
  are regenerated.

The scratch driver raised the recipe's 900 s process timeout to 3,600 s, which the
loaded host of the first session needed. It bounds only the build process.

The precompile ELF embeds one source path of the patch, under
`$CARGO_HOME/git/checkouts/tiny-keccak-39e1bab27f4c71da/957430a/`, next to the
registry source paths it already embedded. The cold rebuild maps its fresh
`CARGO_HOME` onto the reviewed one for both.

After this gate the reviewed source pins were regenerated. The unchanged recipe
then rebuilt the precompile ELF in two more fresh output directories, and both runs
reported `PASS_BYTE_EXACT_REVIEWED_ELF_REBUILD` with the SHA-256 above. The measured
precompile ELF is therefore `REVIEWED_GUEST["elf"]`; it is committed in
`contracts/integration/fixtures/clock-pkg3-reviewed/`.

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
three 65-byte node hashes. They give the per-hash costs above, and the midpoint error
is 0.0% in both builds. The Keccak share of a run is its counted permutations times the
per-hash cycles, divided by its cycles. A fixed few dozen permutations per batch run
outside the `Hasher` and are not counted: the clock receipt, the settlement-tree roots,
deposit leaves and oracle-signer recovery.

The second session rebuilt the tool from the same source
(`crates/sp1-host/src/bin/measure-history.rs`, unchanged since `8820eb5`) with
`SP1_SKIP_PROGRAM_BUILD=true` and an empty stub ELF. Its binary is `19ca217d...`; cargo
reported that stripping debug info failed in this toolchain install, so it keeps its
debug info. With the software ELF it reproduced the first session's records at 8,000
and 10,000 for all three batches exactly: witness, commitment, withdrawals root,
post-state, cycles, gas and Keccak counts. The first session's binaries are listed in
`measurement.json` (`measurement_tool`).

## Size mapping

`H` is a multiple of 80, and:

- unspent notes `N = H/5`;
- positions `P = H/10`, over 4 markets;
- tree leaves `L = (H + N)/2 = 3N`;
- spent nullifiers `F = H - L = L - N`.

So 500,000 gives 50,000 positions and 100,000 notes. The admission bounds keep the
same ratio.

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

The host was an Apple M4 (10 cores, 16 GiB) on macOS 26.5.1, a shared workstation.
Cycles, gas and Keccak counts are deterministic. Wall time and memory are this host's
at the time:

- first session (the software build's gate sizes): other build, test, virtual-machine
  and interactive workloads were running, the load average was between about 5 and
  24, and swap was in use;
- second session (both precompile builds, every precompile run and the software
  re-runs from 8,000 to 20,000): lighter load, a load average of about 1.4 to 2.6
  when sampled after the runs.

Wall times of the two sessions are not comparable.

Precompile build, gate sizes. "Cost-eq." is the cost-equivalent cycles; "ratio" is
software over precompile for the same witness.

| Batch | H | Cycles | Gas | Cost-eq. cycles | Cycles ratio | Gas ratio | Execute s | Peak RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| phase0 | 10,000 | 79,265,407 | 118,477,138 | 123,624,958 | 3.90 | 2.50 | 1.6 | 570 |
| phase0 | 50,000 | 358,906,540 | 559,254,278 | 579,762,091 | 4.19 | 2.59 | 6.9 | 2,460 |
| phase0 | 100,000 | 713,681,229 | 1,121,525,707 | 1,158,479,406 | 4.20 | 2.59 | 10.7 | 3,177 |
| phase0 | 250,000 | 1,796,302,069 | 2,831,192,725 | 2,906,559,457 | 4.18 | 2.58 | 23.7 | 4,386 |
| phase0 | 500,000 | 3,619,257,528 | 5,781,095,176 | 5,912,079,922 | 4.16 | 2.54 | 48.7 | 4,728 |
| phase1 | 10,000 | 69,399,356 | 108,762,369 | 113,577,824 | 4.30 | 2.63 | 1.4 | 543 |
| phase1 | 50,000 | 353,641,250 | 553,284,146 | 573,736,037 | 4.23 | 2.61 | 6.6 | 2,442 |
| phase1 | 100,000 | 715,363,893 | 1,123,975,022 | 1,158,454,402 | 4.20 | 2.59 | 10.5 | 3,759 |
| phase1 | 250,000 | 1,817,048,376 | 2,850,624,114 | 2,918,827,289 | 4.14 | 2.58 | 23.9 | 4,548 |
| phase1 | 500,000 | 3,671,763,533 | 5,855,383,831 | 5,973,631,482 | 4.11 | 2.53 | 48.0 | 4,574 |
| phase1-haircut | 10,000 | 97,615,645 | 142,272,289 | 149,682,134 | 3.86 | 2.52 | 2.0 | 700 |
| phase1-haircut | 50,000 | 501,306,122 | 730,153,235 | 761,639,442 | 3.78 | 2.49 | 7.8 | 2,946 |
| phase1-haircut | 100,000 | 1,017,104,442 | 1,484,756,833 | 1,541,095,800 | 3.74 | 2.47 | 14.7 | 3,868 |
| phase1-haircut | 250,000 | 2,590,970,389 | 3,803,312,028 | 3,923,244,269 | 3.69 | 2.43 | 37.3 | 4,591 |
| phase1-haircut | 500,000 | 5,253,704,213 | 7,819,346,132 | 8,033,940,070 | 3.65 | 2.39 | 68.3 | 4,796 |

Software build, gate sizes (first session):

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

The witness bytes are the same for the precompile build. Every size was measured, so
none is extrapolated. No run came near the 5,400 s per-process limit: the longest
software process took 508 s, the longest precompile process 72 s.

Peak RSS is the resident peak. Under the first session's memory pressure it is not
monotone in `H`, because pages were compressed and swapped. A 10 s sample of the
physical footprint (resident plus compressed) peaked at 8,570 MiB at 250,000 and at
9,367 MiB at 500,000, both in phase 1 of the software build. The second session took
no footprint sample.

In the precompile build the Keccak share of the cycles is 0.66 to 0.83 at the gate
sizes, and its gas per cycle is 1.30 to 1.60 across all its runs, against 0.95 to 0.98
for the software build.

The cap region was measured for the precompile build at 2,000, 4,000, 5,280, 5,360,
6,000, 8,000, 12,000, 13,200, 13,280, 13,360, 14,000, 16,000 and 20,000, and for the
software build at 2,000 to 8,000 (first session) and 12,000 to 20,000 (second session),
so that every precompile run has its software counterpart. The bounds are interpolated
between measured points, not taken from a global fit.

| Batch | 12,000 | 13,280 | 13,360 | 14,000 | 16,000 |
|---|---:|---:|---:|---:|---:|
| phase0 | 146,020,314 | 160,439,362 | 161,333,332 | 168,708,754 | 191,269,855 |
| phase1 | 136,299,367 | 150,847,009 | 151,751,865 | 159,188,343 | 181,939,893 |
| phase1-haircut | 179,620,951 | 198,828,755 | 200,064,036 | 209,749,364 | 239,200,235 |

(precompile build, cost-equivalent cycles)

The software build's cap-region points from the first session are unchanged: the
shortfall phase 1 takes 198,725,972 cycles at 5,280 and 201,728,802 at 5,360.

Least squares over the five gate sizes, in cycles per unit of history: software
30,086 (phase 0), 30,213 (phase 1) and 38,361 (shortfall); precompile, cost-equivalent,
11,819, 11,963 and 16,108. The precompile build's fit has its largest residual, 26%,
at 10,000, because its fixed per-batch cost is a larger part of the total there. That
is why the bounds come from the measured points.

At `H` = 100,000 the counted permutations split as follows:

- phase 0 and phase 1: 11.3% decode, 44.4% each state root, ~0% batch and commitment;
- shortfall variant: 9.3% decode, 36.4% pre-root, 9.2% batch (the reissue) and 45.1%
  post-root.

## Conversion to proving time

`T(H) = fixed + cost(H) / R`, with the cost in cost-equivalent cycles. A size fits when
`T(H) <= budget / 2` for all three batches.

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
  launch prover in plain RISC-V cycles, is assumed at 1,000,000 cycles/s. The value is
  taken at the low end because the hard cap protects a one-shot wind-down proof. It is
  raised only by a measured rate.

The cap scales linearly with `R` and with the compute seconds per proof,
`(anchorTimeoutMs / 1000 - 2,700) / 2 - 250`.

| R (cycles/s) | Max cost per proof | Cap, software build | Cap, precompile build |
|---:|---:|---:|---:|
| 0.5 M | 100 M | 2,652 | 6,708 |
| 1 M | 200 M | 5,313 | 13,355 |
| 2 M | 400 M | 10,621 | 26,487 |
| 4 M | 800 M | 21,192 | 52,460 |
| 8 M | 1,600 M | 42,272 | 103,709 |
| 16 M | 3,200 M | 84,263 | 204,458 |
| 32 M | 6,400 M | 167,852 | 400,628 |

At the launch budget, 100,000 history needs a measured `R` of at least 7.7 M cycles/s
with the precompile build (19.0 M with software Keccak), or a larger `anchorTimeoutMs`
at deploy.

Taken in raw cycles, the precompile build's cap at 1 M cycles/s would be 20,160. That
figure is recorded but not used, because raw cycles leave out the precompile's proving
work.

The first session's projection of the precompile build (from SP1 6.1.0's cost tables,
before the build existed) gave a cap of 11,600. The measured build saves 4,973 gas per
65-byte hash against the projected 4,494, so its cap is higher. The projection is kept
in `measurement.json` (`precompile_projection`) and is superseded.

## Recommendation

| Bound | Value |
|---|---:|
| `MAX_PROVABLE_HISTORY` | 13,280 |
| soft cap (80%) | 10,624 |
| positions | 1,328 |
| notes | 2,656 |
| adopt the Keccak precompile | yes |

The shortfall phase 1 is the costliest batch at every measured size and sets the
bound. Phase 0 and the solvent phase 1 alone would allow about 16,800 and 17,600.
Positions and notes keep the measured ratios `H/10` and `H/5`. The bounds are those
of the precompile build, which the program adopts; `crates/gateway/src/admission.rs`
applies them.

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

Each (ELF, `H`, batch) triple ran as its own process so that peak RSS is per run.
Histories ran in increasing order, with a 5,400 s wall limit per process. The tool
refuses to overwrite an existing output file. A precompile run's cost-equivalent
cycles need the software build's run of the same witness: `cycles_software x
gas_precompile / gas_software`.

## GPU day

GPU day re-measures. It proves phase 0, phase 1 and the shortfall variant at the
configured bound on the launch prover, records the proving time and the sustained rate
`R`, and re-derives the bound with the formula above from the measured rate. This gate
settled the program decision, the precompile, before the program key freezes. The
bounds are admission policy and change without a new program key.
