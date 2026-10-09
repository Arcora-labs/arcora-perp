# Reviewed guest reproduction, 2026-10-10

The current reviewed source reproduced the existing reviewed ELF byte-for-byte
in two new targets. Fresh SP1 CPU setup of the first rebuilt ELF derived the same
program key. The packaged recipe produced identical bytes in 40.62 seconds;
the diagnostic build took 38.03 seconds and CPU setup took 33.91 seconds.

- ELF SHA-256: `df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5`
- ELF size: 525,824 bytes.
- Program key: `0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353`
- Scope: same ARM64 Mac, installed compiler and cached registry dependencies,
  newly created empty targets, Cargo `--locked --offline`. No fresh proof,
  independent cold environment, target deployment or running-service claim.

The [aggregate verification](verification.json) binds the logs, source and compiler
argument records. [Recipe verification](recipe-verification.json) includes all 21
source hashes and exact tool versions. [CPU setup verification](vkey-verification.json)
uses the first diagnostic rebuilt ELF; direct byte comparison also confirmed that
the packaged recipe ELF and reviewed fixture contain identical bytes. It does not
claim that setup was run a second time on the packaged output.

## Cause and controlled normalization

The [initial report](../verification.json) preserves both earlier mismatches.
Source paths in panic strings explain the first difference. Path remapping alone
was insufficient: its `.text` still differed in two Debug forwarding thunks and
`.rodata` contained their swapped pointers, while section layout and printable
strings matched. Original/current Cargo crate fingerprints and symbol identities
also differed even though all 21 reviewed source pins matched.

Original compiler arguments were captured from the original checkout using an
owned APFS copy-on-write target clone at `/tmp/arcora-original-target-probe-20261010`.
The original source and target were preserved. The wrapper first intercepted
`perp_core` with exit 86, then allowed that pinned crate to compile only in the
clone so it could intercept `perp_core_guest` with exit 86. These intentional
probe exits are in the [core](original-core-probe.log) and
[guest](original-guest-probe.log) logs; they are not successful build claims.
The [captured original arguments](original-compiler-invocations.jsonl) establish:

| RISC-V workspace crate | Reviewed `-C metadata` |
| --- | --- |
| `perp_core` | `85153213d10819ef` |
| `perp_core_guest` | `2c8a895641ad00f3` |

For those two exact source entrypoints only, the wrapper changes the existing
metadata value and appends `--remap-path-prefix` from the current checkout to
`/Users/huseyinarslan/kimi-bridge/worktrees/Arcora-labs__arcora-perp/clock-anchor-20261009`.
Cargo output filenames, dependencies, source files and other arguments are
retained. Before/after arguments are preserved for the
[diagnostic](diagnostic-compiler-invocations.jsonl) and
[packaged recipe](recipe-compiler-invocations.jsonl). No ELF bytes are patched,
no fixture is copied into the build output, and no reviewed pin is changed.

## Reuse

From the repository root, with Python 3.11+, the recorded Cargo 1.99.0 shim and
SP1 ARM64 Mac compiler installed:

```sh
python3.11 scripts/local-verification/rebuild_reviewed_guest.py \
  --cargo "$HOME/.cargo/bin/cargo" \
  --rustc "$HOME/.sp1/toolchains/z4qbuzauUe/bin/rustc" \
  --output-dir /tmp/arcora-reviewed-build-NEW
```

The output must not exist and must be outside the source checkout. Its `target`
directory is created empty; existing targets and source are never overwritten.
The recipe rejects changed pins, extra source files, symlinked source ancestors,
and additional workspace build/config inputs before invoking tools, on every
compiler-wrapper entry, and after compilation. A success manifest is written
last, only if the compiled ELF matches the independent reviewed SHA-256 pin and
both required workspace compiler invocations were recorded. Eight guard tests
passed, including source/config additions and rustup Cargo shim dispatch.

The exact compiler is `rustc 1.93.0-dev`, LLVM 21.1.8,
`aarch64-apple-darwin`; the recipe checks its full recorded version and records
the binary hash. It uses two Cargo jobs and the full SP1 flags in the manifest.
Environment and dependency caches are those of this machine; no hermetic or
cross-machine reproducibility guarantee is made. A changed compiler or source
requires a separately reviewed build and proof, not updates to this recipe's pins.

The resulting ELF can be supplied to `replay-funds --elf`; retain this build
manifest separately because replay cannot establish its input's build provenance.
Fresh proofs for the four lifecycle witnesses, real verifier settlement and target
service/finality/load evidence remain required.
