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

The `vkey` binary performs setup only. The `prove` binary prepares a real local CPU
Groth16 proof and requires working Docker/gnark plus appropriate compute. It emits
successful proof artifacts only after matching the native public bytes and
verifying with the SDK. Neither code preparation nor native guest execution is
proof production or target-contract acceptance. The September 28 continuation
did not execute Groth16, the held A06 guest draft, or a chain transaction.

Do not reuse an older ELF/vkey deployment identity after an SP1 upgrade. Rebuild,
record the source/toolchain/ELF/vkey hashes, and separately validate a genuine
proof through the intended on-chain verifier before any release. The guard checks
reviewed version consistency, not cryptographic correctness or all advisories.
The current SP1 6.1.0 graph still contains `lru` 0.12.5 unsoundness advisories;
these are recorded in the audit report and keep the release risk review open.
No advisory is ignored. See [current evidence](audits/2026-09-28-post-merge/README.md).
