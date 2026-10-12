# Legacy service curl response limits

The gateway and prover-service use the same bounded subprocess capture module
for their boot-time attestation GET. The gateway also uses it for the existing
legacy `/prove` POST. This changes HTTP transport admission and diagnostics;
it does not enable candidate proving or production release.

| Captured data | Limit |
| --- | --- |
| Attestation GET response | 1 MiB |
| `/prove` response body | 4 MiB |
| Curl stderr, per request | 16 KiB |

The POST stdout allowance includes the fixed HTTP status trailer in addition
to the body limit. Both readers check their byte counts while consuming the
pipes. They run concurrently with the optional stdin writer, so large sealed
requests and simultaneous output cannot wedge each other by filling a pipe.
The writer borrows the existing request bytes rather than cloning the body.

Overflow, pipe errors or the supervisor deadline refuse the request. The
direct curl child is killed and waited for before the pipe workers are joined.
Worker creation is fallible; its failure follows the same cleanup path. The
cleanup guard also lives inside the thread scope, so it runs before implicit
joins during an unwind. This supervises the direct curl child, not arbitrary
substitute executables that leave descendants holding pipes open.

The GET retains curl's 10-second connect and 30-second total timeout. Its
supervisor budget is 35 seconds. POST retains the 20-second connect timeout,
30-second TCP keepalive and configured `PROVER_TIMEOUT_SECS` total timeout;
the supervisor permits five additional seconds for cleanup. Zero or
unrepresentable timeout budgets refuse before process creation. The existing
900-second default is unchanged.

Curl receives `-q` first, which disables default curl configuration files.
The URL follows `--`, so it cannot introduce another command option. Existing
proxy environment behavior remains available. Tests remove proxies only from
their own child commands and use kernel-assigned loopback ports.

GET retains `--fail` and does not follow redirects. POST retains explicit
status capture without `--fail`: a complete, bounded HTTP 401 remains
`Unauthorized`. Only that typed result can trigger the existing single
re-handshake and fresh-session reseal. Overflow, truncation, pipe failures and
invalid status markers are transport errors and cannot trigger that retry.

Returned transport and JSON/hex decoding errors contain fixed labels, status
numbers or local field names. They exclude curl stderr, peer error bodies,
invalid remote values, endpoint URLs and bearer tokens. Successful response
bodies still pass to the existing proof parsing and local replay checks.

## Verification and remaining scope

The shared tests use actual curl against owned GET/POST fixtures and a private
native child for pipe pressure, early stdin close, overflow and deadline
cleanup. PID existence checks require the child to be gone after return.
Gateway caller tests exercise exact limits and one byte over with
Content-Length, chunked and connection-close framing, typed 401 and redacted
errors. The private child worker is intentionally ignored by the ordinary test
runner and is invoked explicitly by its parent tests.

The two production GET wrappers are identical. A dependency-light probe
imports their exact source and the shared capture implementation; actual
prover-service typechecking remains separate from runtime probing. No SP1
setup, backend startup, quote acceptance, key release or proof generation is
part of these checks. Existing native 401/session/recovery tests retain their
original assertions. See the source-bound local results in
`audits/2026-10-12-curl-response-bounds/`.

Actual deployment response compatibility and production acceptance still
require approved public service inputs and independent evidence. Reviewed
guest/core, ELF/vkey, root Cargo and custodial-alpha economics are unchanged.
**DPCLK3 compatibility remains REFUSED; PRODUCTION RELEASE HOLD.**
