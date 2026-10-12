# Public service identity: local software verification

Gateway and prover now expose `GET /identity` with covered source/configuration
checksums. The prover also declares its existing loaded program descriptor. The
offline preflight compares supplied snapshots with independently supplied public
expectations. This closes the software observability gap; **PRODUCTION HOLD**,
candidate submission disabled, and actual service/operator acceptance remain open.

Base main: `8f5e97bc690c1d9a6d796fdc3725526d283e077d` (#54).
Code commit: `9c7347870d7212ec2ca66a92729ee5b433ca9efb`.
The subsequent publication commit adds documentation and this local evidence;
its GitHub CI and merge observations are recorded separately after publication.

| Local check | Result | Evidence |
| --- | --- | --- |
| Full gateway suite | 679 passed, 0 failed, 23 intentional ignored tests | `receipts/checks--gateway-final.json`, raw logs |
| New Python guards | 25 passed: 9 builder + 16 preflight | `receipts/checks--new-python-final.json` |
| Neighboring Python guards | 148 run, OK, 1 optional legacy Anvil skip | `receipts/checks--neighbors-final.json` |
| Production gateway identity subset | 6 passed, including shared canonical checksum unit | `receipts/gateway--post-intake-repair1.json` |
| Production prover identity in dependency-light harness | 6 passed; Clippy passed | `receipts/prover--prover-identity-verification.json` |
| Actual prover-service SDK typecheck | PASS, 90.481 seconds, offline/locked Rust 1.99 | `receipts/prover--actual-typecheck-verification.json` |
| Workspace/harness format and workspace Clippy | PASS | `receipts/checks--*.json` |
| Preserved provenance | 21 reviewed v2 + 9 candidate runtime + 2 auxiliary sources unchanged | `receipts/checks--pins-final.json` |

The six final root check receipts bind before/after checksums of all **371**
covered source files to
`7fd564c8bf0ec2bd3434635a06ff046e9faec759996c78a2c6db47ed85b5619d`.
Documentation, audit logs and workflow metadata are outside that service source
inventory. `artifact-ledger.json` binds each retained artifact and the final
code inputs by SHA-256. Root `Cargo.toml` and `Cargo.lock` remain byte-identical.
Only one existing-version `sha2` dependency-list entry was added to the standalone
prover lock. No guest/core/contract/ELF/key changes were made.

The actual prover typecheck used an owned copy of the existing reviewed
525824-byte ELF and existing compiler helpers, with program build skipped.
The native runner was a compile override and was never executed. No full prover
service, backend setup, proof generation, GPU, attestation or real deployment was
started. The isolated HTTP tests use the production identity handler/router,
but the injected reviewed ELF in the harness is a test input, not evidence of a
running deployment. Existing CI's empty ELF stub is also only a typecheck input.

`self_reported_unattested` is explicit in every response. Build checksums record
the helper-time public source map; they do not attest a compiled binary, atomic
build, process or machine. Configuration checksums cover only typed public
fields. No private keys, credentials, URLs, account bodies or raw environment values
are included. The preflight's `DECLARATIONS_MATCH` means supplied declarations
match supplied expectations; expectation provenance must be established
independently. It never learns expected values from the response. Current prover
supports legacy/DPCLK2 and explicitly refuses DPCLK3 candidate compatibility.
All candidate capability flags and approval/attestation flags remain false.

The bounded admission middleware, existing v2 financial routes, backend setup,
prove and handshake bodies are preserved. Gateway snapshot access uses the
existing lock order with a nonblocking archive lock; unavailable required
archive data returns 503. Requests use `Cache-Control: no-store`. Python 3.11+
is a fail-closed build prerequisite through `PATH`, not a request-time runtime.
Canonical Rust/Python interoperability covers this schema's fixed ASCII labels,
hex strings, integers, booleans and null; it makes no arbitrary Unicode/float
canonicalization claim. File output guards do not provide a durable transaction.

## Retained failed-before / passed-after evidence

- Builder's initial Python 3.9 import failed before assertions; Python 3.11
  then passed all nine tests. A receipt-wrapper key error and a diagnostic
  missing output-parent error are retained as instrumentation failures.
- Gateway's first root smoke build used the wrong shim path and fell through
  to Python 3.9; no test ran. After correcting only the owned tooling path,
  five tests passed and one new POST test failed. That test incorrectly assumed
  body intake never ran. Only the new test was corrected to verify existing
  bounded intake (405 for a small POST, 413 for 17 bytes with a 16-byte limit)
  and unchanged gateway state. Six tests and then the full 679-test suite passed.
  The initial QA finding Q1 and its explicit closure are both retained.
- Preflight's first run passed 14 with two fixture errors because macOS `/var`
  traverses a symlink. Only the new owned fixture parents were resolved; the
  checker symlink guard was preserved. All 16 then passed. Those early runs
  lacked full before/after source maps; the later root receipt supplies them.
- Harness lock preparation initially selected newer cached versions; it was
  corrected to the existing root version graph before compiling. Historical
  lock receipts are retained, rather than counted as final runtime evidence.

## Remaining acceptance inputs

No approved current Chainlink deployment public config or actual candidate
gateway/prover public config was found. The old July deployment and stopped
Anvil fixtures are historical/synthetic inputs. Live feed discovery remains
user-deferred. This work made no public HTTP/RPC/feed discovery calls.

Next: independently establish approved public target, oracle policy and service
expectations; collect current public service declarations and pinned finalized
target observations; reconcile them without treating declarations as attestation.
Fresh candidate proof, measured service attestation, economic/custody/operational
approval and production release remain separate open gates.

The preservation receipts verify the three original worktrees' heads/status,
seven staged documents, and all 82 dirty file checksums. Those worktrees and
their services/user data were preserved. #54's post-merge main CI is now all
successful, recorded as prior-base evidence in `receipts/main-refresh.json`;
it is not the new publication head's CI.

Usage and exact schemas: [PUBLIC_SERVICE_IDENTITY.md](../../PUBLIC_SERVICE_IDENTITY.md).
