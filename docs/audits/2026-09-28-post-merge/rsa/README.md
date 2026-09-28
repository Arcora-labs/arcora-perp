# RSA dependency gate and attestation verification

The runtime RSA dependency was removed without an advisory ignore or a lockfile
edit. DCAP and Azure vTPM verification now use ring. The offline DCAP collateral,
Intel trust chain, SHA-256 / RSASSA-PKCS1-v1.5 algorithm, HCL binding, PCR binding,
and application TCB acceptance gates remain enforced.

## Evidence and acceptance

- `attestation-vendor`: 39 tests passed, including the real captured Intel/Azure
  signatures, modified signature/message, invalid key parameters, malformed TPM
  envelopes, PCR mismatch and stale TCB rejection. Five new test functions cover
  multiple negative inputs. `attestation-clippy`: all targets passed with warnings
  denied.
- `workspace-audit`, `prover-audit`, `tee-audit-fixed`: actual cargo-audit exits 0,
  zero `vulnerabilities`, and empty `settings.ignore`. The workspace audit fetched
  RustSec commit `ef03605143a913024f864d2edf476adad5720c93`; subsequent checks reused
  that database.
- All three application dependency trees and lockfiles contain no rsa package.
  The archived upstream vendor lockfile is retained solely as provenance and is
  not an application lockfile.
- `tee-check-fixed`: the capture-tool consumer typechecks. Gateway consumer tests
  are recorded by the runtime RPC lane. `../checks/rsa-prover-service-final`
  compiled the SP1 6.1.0 service and passed all eight service tests; its one
  ignored entry is the subprocess fixture launched by the SIGTERM parents.
  The test embeds the root-built guest ELF `82938f5d...7918d7`, with its exact
  build output, dependency file and hash recorded in `prover-elf-binding.json`.
  The first service run used an older ELF in the reused target directory and is
  not accepted as new-artifact evidence; the second recompiled after replacement.
  Neither run executed a real proof. Two existing GenericArray deprecation
  warnings appear under the standalone prover dependency versions.
- `verification.json` compares relevant input hashes before/after each command
  and with current files. Parallel work changed unrelated repository files, so
  a whole-repository equality claim is deliberately not used for those checks.

## Why the vendored manifest is needed

Changing to ring removes RSA from actual builds, but did not remove it from the
lockfiles: the upstream `alloc` feature references `rsa?/default`. This is the
known open [Cargo weak dependency lockfile issue](https://github.com/rust-lang/cargo/issues/10801).
The first ring-only audit failure is retained in `ring-only-audit.*`.

The exact crates.io package is vendored with unchanged Rust files and license.
Only the manifest moves RSA defaults from the generic alloc feature to the
rustcrypto feature. `vendor-provenance.json` verifies 29 archive files including
20 unchanged Rust source files and the exact manifest transformation. Selecting
rustcrypto still resolves rsa 0.9.10, confirmed by the independent temporary
consumer in `rustcrypto-counterfactual.*`; the advisory is not concealed.

The patch causes rustcrypto builds to enable RSA defaults even without std. This
repository selects only ring+std; no cross-target/no-std promise is made for the
unused rustcrypto configuration. `vendor/dcap-qvl-webpki/PATCH.md` documents the
removal condition and provenance checker.

## Explicit behavior changes

Azure AK moduli must be 2048–4096 bits. The old 4096-bit upper bound, odd public
components, exponent limits, and leading-zero normalization are retained; weak
keys below 2048 bits now fail before verification. The real Azure fixture uses
2048 bits and still verifies. The TPM signature envelope must explicitly declare
RSASSA/SHA-256 and must end at its declared signature length; wrong algorithms,
truncation and trailing bytes are rejected.

The original advisory concerns private-key timing leakage. This application used
RSA public-key verification, so this change does not claim a reproduced private
key leak. It removes the affected package and the dependency-release blocker.
[RustSec RSA advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html),
[ring verification API](https://docs.rs/ring/0.17.14/ring/signature/struct.RsaPublicKeyComponents.html).

## Other dependency changes and remaining warnings

The capture tool's separate lock had two additional vulnerabilities. Cargo
updated crossbeam-epoch 0.9.18→0.9.20 and rustls 0.23.41→0.23.45, with rustls's
required aws-lc/webpki updates. `tee-audit.*` records the failure and
`tee-audit-fixed.*` the clean vulnerability result.

At root's request, prover-service sp1-sdk/sp1-build are exactly 6.1.0. All 47
SP1/slop lock entries resolve to 6.1.0 and P3 to 0.3.2-succinct. Cargo generated the
lock using temporary exact family constraints, then those temporary manifest
constraints were removed. No lockfile contents were edited manually. Proof/guest
execution did not take place in this lane.

Zero vulnerability findings does not mean every dependency concern is closed.
The workspace retains atomic-polyfill unmaintained and spin yanked warnings; the
capture tool retains a chacha20 yanked warning. The prover graph retains eight
unmaintained warnings and two lru 0.12.5 unsoundness advisories. The actual path is
`prover-service → sp1-sdk 6.1.0 → sp1-prover 6.1.0 → lru 0.12.5`. SP1 requires
`^0.12.4`; fixes require at least 0.16.3 (iterator aliasing) and 0.18.2 (panic-safe
pop), so a compatible lockfile-only upgrade cannot fix them.

Read-only source triage found LruCache use in SP1's worker setup cache (get/put)
and normalization cache (get/push), with no direct LruCache pop/iter_mut call in
those consumers. This is not proof of non-exposure and does not suppress either
warning. A reviewed upstream SP1 dependency migration or a separately reviewed
patch remains necessary.
[Iterator advisory](https://rustsec.org/advisories/RUSTSEC-2026-0002.html),
[Pop panic safety advisory](https://rustsec.org/advisories/RUSTSEC-2026-0253.html).
