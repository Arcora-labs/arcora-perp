# Local SP1 evidence

Guest, host and prover-service pin the reviewed SP1/slop release family to 6.1.0.
This replaces affected 6.0.0 for [GHSA-63x8-x938-vx33](https://github.com/succinctlabs/sp1/security/advisories/GHSA-63x8-x938-vx33).
Use the 6.1.0 `cargo-prove` CLI, the Succinct Rust toolchain, and `protoc`. Put
rustup's shims before a system/Homebrew Rust installation so `rustc +succinct`
selects the actual RISC-V compiler. Python 3.11 or newer is required for the
manifest/lock guard:

```sh
python3 scripts/local-verification/check_sp1_release.py
cd crates/sp1-guest
cargo prove build --locked
cd ../sp1-host
cargo run --locked --release --bin sp1-host -- --check-negatives --output-dir /tmp/arcora-normal-new-run
```

The output directory must not already exist. Without CLI options, the host keeps
its one-positive-execution behavior. With the options shown, it persists the
exact ordinary synthetic witness, ELF, public bytes and hash manifest; it checks
native/guest equality plus guest rejection of a bad manifest and an unauthorized
withdrawal. An infrastructure failure is not a passing negative case. These are
ordinary Deposit/Withdraw inputs, not A06 phase 1/2 or observed L1 deposits.

The synthetic witness uses the one framing the guest accepts, `DPCLK4` followed by
the postcard clock witness, with no trailing bytes. The `vkey` binary performs setup
only. The earlier `prove` binary is retired. `clock-proof --elf <reviewed ELF>
<new dir>` executes the reviewed clock-bound fixture, its case witnesses and its
negatives against an explicit ELF whose SHA-256 must equal the reviewed pin. The
reviewed ELF, its setup key and the `--no-prove` output are committed in
`contracts/integration/fixtures/clock-pkg3-reviewed/`. `--no-prove` stops after
execution, and `--prove` adds a real local CPU Groth16 proof, which requires working
Docker/gnark plus appropriate compute. It emits successful proof artifacts only after
matching the native public bytes and verifying with the SDK. Neither code preparation nor native guest execution is
proof production or target-contract acceptance. The September 28 continuation
did not execute Groth16, the held A06 guest draft, or a chain transaction.

The guest runs Keccak through SP1's `KECCAK_PERMUTE` precompile. It takes
tiny-keccak 2.0.2 from Succinct's patch, pinned by repository and commit in its
`[patch.crates-io]` table: `https://github.com/sp1-patches/tiny-keccak` at
`957430a459f7a2332ab5bab4a12f9b473bb95c87` (tag `patch-2.0.2-sp1-6.0.0`, for SP1
>= 6.0.0 and < 6.2). The patch changes only how the permutation runs on the zkVM
target; the host build and every output are unchanged. It is the only locked
dependency of any SP1 application that is not a crates.io package or a local path:
`check_sp1_release.py` refuses another git or registry source, another commit, or a
branch or tag selector, and the rebuild recipes compare the patch's checked-out files
with its pinned source tree (`GUEST_GIT_DEPENDENCY`). `cargo audit` matches only
crates.io packages against advisories, so CI audits the guest lock a second time with
the patch under its upstream crates.io identity
(`check_sp1_release.py --upstream-audit-lock NEW_PATH`); the patch's own identity rests
on the pin.
`cargo prove build --locked` fetches it on first use, and an offline build needs it
fetched beforehand.

Do not reuse an older ELF/vkey deployment identity after an SP1 upgrade. Rebuild,
record the source/toolchain/ELF/vkey hashes, and separately validate a genuine
proof through the intended on-chain verifier before any release. The guard checks
reviewed version consistency, not cryptographic correctness or all advisories.
The current SP1 6.1.0 graph still contains `lru` 0.12.5 unsoundness advisories;
these are recorded in the audit report and keep the release risk review open.
No advisory is ignored. See [current evidence](audits/2026-09-28-post-merge/README.md).
