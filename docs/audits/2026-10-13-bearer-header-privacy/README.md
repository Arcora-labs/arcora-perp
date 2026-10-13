# Prover bearer excluded from curl argv

Base: `76f658433882e5448c12c05c3f80bd7f3d78de39` (normal PR62 merge).
Its three main workflows and all 14 jobs were read back SUCCESS; no open PR
existed before this work. Strict 11 required checks and no bypass remain.

## Change and limits

Each authenticated `/prove` POST now creates a fresh exclusive directory with
Unix mode 0700 and a `create_new` header file with mode 0600 (umask may restrict
further). The file contains the same `Authorization: Bearer ...` header. Curl
receives `-H @<path>`; the token does not travel in argv. The filename contains
no token. JSON still streams through `--data-binary @-`. No-auth `None` creates
no header owner and sends no Authorization header.

Timeout, endpoint and outbound byte admission run before header creation. The
request owner survives shared transport child supervision and pipe-worker
joins, then attempts nonrecursive file/directory cleanup on normal and error
returns. Every POST, including a fresh attempt after typed 401, owns a separate
file. Existing one-shot re-handshake/reseal/session logic is unchanged.

CR/LF/NUL values are rejected with a fixed diagnostic before child creation:
the header file is line-oriented and must not reinterpret or truncate a token.
This is an explicit transport representation change; no hex-only grammar was
added. Production handshake tokens are already `0x` + hex. Other valid token
formats are preserved in the file; a public Unicode/space synthetic value was
also verified byte-exact on the owned HTTP fixture. This does not establish
real prover authorization for arbitrary token formats.

Authenticated requests fail closed on non-Unix platforms where these Unix
permission guarantees are unavailable. Linux/macOS evidence is separate from
unexecuted other-platform behavior. This mitigation reduces incidental local
process-list/log visibility. Same UID/root access to files/memory, hostile
TMPDIR/parent replacement, replacement of curl and guaranteed SIGKILL cleanup
are outside its scope. Cleanup is best effort if filesystem state changes.

## Actual evidence

[Native final receipt](native/final-readback.json): **15 cases / 7 actual native
curl HTTP requests**, from the first 14-case run plus a fresh Unicode positive.
Both compile/run attempts passed first time; no repair history is invented.
The std-only probe compiles the exact production POST/args/status functions and
unchanged header module, rather than running a backend or full gateway.

Only the exact owned curl PID/PPID and its own argv-disclosed header path were
inspected while the fixture held the response. Observed files had mode0600,
private directory mode0700, owner match and nlink1; the synthetic token was
absent from full process argv and present in the actual HTTP header. A 160KiB
body remained byte-exact on stdin. None/200 is only a no-auth fixture transport
control. HTTP500, native curl timeout (1.4202s), a separate owned Python child
supervisor deadline (6.0545s), and independent 401 then fresh-token/200 POSTs
preserved redaction/typed status and observed cleanup. These two POSTs are not
a whole attested re-handshake; existing session tests supply separate coverage.

CR, LF and NUL refusals each produced zero child markers and peer requests,
with no input echoed. URL/body/timeout prechecks were preserved. Spawn failure
proved fixed error, empty owned temp tree after return and source ordering;
its header pathname was not observed in flight. No stronger observation is
claimed. All observed header paths were absent after return and private
owned temp roots were empty. SIGKILL cleanup was not tested or guaranteed.

| Actual local validation | Result |
| --- | --- |
| Client/session/body/header tests | 39 PASS; four new helper tests |
| Real-curl HTTP caller tests | 20 PASS; one new three-value malformed-header test |
| Clippy | PASS; 7.1611 seconds |
| Format | PASS; 0.6688 seconds |

The previous 19 HTTP tests are an exact byte prefix. Previous 35 client test
functions remain, with one intentional argv expectation update; four helper
tests are added. Shared transport, wire/seal/session logic, core/guest and
Cargo inputs outside the three paths are byte-exact. Other 376 covered public
sources, reviewed21/candidate9/auxiliary2 pins and eight manifests/locks are
unchanged. The full gateway suite was not rerun locally: **754/0/24 is only the
new CI expectation**, until publication logs are independently checked.

[ledger.json](ledger.json) binds **116 copied public files**; this README and
ledger are separate. Native executables/caches/full archives/raw HTTP bodies,
input blobs, argv/PID materials and runtime header files are excluded. Only
PUBLIC synthetic tokens were used. The 379-source map SHA-256 is
`87262139b3b44c0348df3cee3ccc9fe389c4b64370a32daaeccb335cfbf90cc2`.
The 3,212 non-active historical public entries and outside checkout HEAD/status/
staged/public-body evidence were rechecked unchanged.

## Remaining work

Plaintext allocation before the existing sealed-expansion guard needs a separate
bounded-counting design and CPU/performance contract. This packet does not bound
initial witness/state allocations, total RSS or proving capacity. Live approved
target/service identity, DPCLK3 backend/recovery, fresh proof, real CC/key release,
custody/operations and independent release gates remain open. Candidate submission
stays disabled. **PRODUCTION RELEASE HOLD**.
