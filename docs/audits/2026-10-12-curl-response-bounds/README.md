# Legacy curl response bounds — local evidence

Code commit: `70fcaf195f6fb8ff641b9ec14758603558fe640e`.
Base main: `756397dbf73b18b77cefc7efcf5baaa8994457e3` (#58).
Covered public source: 378 files,
`8eddb300301a51cb4122c78a658db326013d61bdfcae2ac5ffa6e5844d8ec3b5`.

The [local final record](local-final-verification.json) and
[artifact ledger](artifact-ledger.json) bind 158 exact copied evidence files.
This README is explanatory and is outside that immutable file ledger.
The ledger binds all six code files to the code commit. GitHub publication CI
and merge are separately verified after this local capture.

| Current local check | Result |
| --- | --- |
| Full gateway | 732 PASS / 0 FAIL / 24 intentional IGNORE; 756 discovered |
| New gateway callers | 8 PASS; included in the full gateway result |
| New shared transport | 7 regular tests; included in full gateway, plus one private worker ignored by ordinary discovery and invoked by parent tests |
| New strict status parser | 1 PASS; included in full gateway |
| Workspace Clippy / format | PASS |
| Service identity Python neighbors | 25 PASS |
| Actual prover-service typecheck | PASS; final source map, no backend/setup/prove |

The full debug gateway run took 1,937.032 seconds including Cargo startup;
its test runtime was 1,928.34 seconds. Existing cumulative-retention and
coordinator fault matrices are included. Counts overlap and must not be summed.

Two genuine before-regressions are retained: the unchanged GET accepted
32 MiB valid synthetic JSON, and the exact old POST returned a synthetic 503
peer body in its error (test exit 101). The fixed GET accepts 1 KiB and the
exact 1 MiB cap, refuses cap+1 and 32 MiB, and the same POST error-content
regression passes. These are transport checks, not handshake/proof acceptance.

Initial new fixture runs are historical failures, not accepted production
regressions. macOS inherited the nonblocking listener flag on accepted sockets;
backpressure caused `WouldBlock`, incomplete responses and curl exit 18.
The [independent diagnosis](independent-fixture-capture-probe/diagnosis.json)
retains four failures in 12 cases and the blocking-only control's 12 expected
outcomes. Both new fixture helpers now explicitly restore blocking I/O while
retaining their budgets and assertions. Initial source maps, failed runs and
prover typechecks remain distinct from the final 378-file map.

Native executable/cache paths and hashes remain in their scoped receipts;
the source and raw logs are copied here, not native binaries or Cargo caches.
The existing inline 195 test bodies and other old test files are unchanged.
Root/service Cargo files, reviewed 21/candidate 9/AUX2 and ELF/vkey artifacts
remain unchanged. The three original dirty checkouts preserve 82 public bodies.

See [limits and semantics](../../CURL_RESPONSE_LIMITS.md). Cleanup supervises
the direct curl child. No real quote/key release, approved service, public chain
submission or fresh proof is accepted. **PRODUCTION RELEASE HOLD.**
