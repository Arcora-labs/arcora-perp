# Prover SIGTERM drain: reproduced failure and correction

A real owned-child test exposed a shutdown defect after HTTP cancellation.
Axum could finish draining because the request future was gone while its
`spawn_blocking` proof worker still ran. Returning from async main then began
Tokio teardown. The real `Sp1GnarkProver` uses a captured Tokio handle to run
async proof code from that worker. A bounded synthetic operation using the same
pattern reproduced the failure: the timer panicked with `A Tokio 1.x context
was found, but it is being shutdown`, and the child exited without completing
its operation. The connected-request case passed. Before-fix result: exit 101,
1 passed and 1 failed (`prover-shutdown-before-drain.log`).

The service now uses `serve_until_shutdown`: first drain Axum, then explicitly
close and drain all admitted operations while the runtime is still alive, then
return. `ProofAdmission::run_blocking` is the shared production/test boundary
that moves the permit into the actual worker. Permit drop returns capacity
before notifying the drain waiter; the waiter subscribes before checking
capacity to avoid a missed final wake-up. Listener errors take the same drain
path. Backend panics remain errors and release capacity without stranding
shutdown.

The two Unix process tests spawn this crate's own test binary and use real
loopback HTTP and SIGTERM. Signal handlers are installed before readiness is
published. Production and the fixture construct SIGTERM/SIGINT streams
synchronously before binding the listener, so coverage does not depend on a
test-only pre-poll of a lazy signal future. An intermediate rerun also exposed
a fixture readiness race: the parent could read the address file before its
contents were written. Readiness now publishes by atomic rename, and the
cancelled-client case waits for actual handler-drop evidence before checking
the retained slot. Its failure log is preserved separately. Each child runs
exactly one admitted synthetic worker; the parent
holds it for a bounded observation interval, then releases it. The worker uses
its captured Tokio runtime handle after release, so a blocking thread merely
surviving runtime teardown cannot satisfy the test.

Both final process scenarios passed:

- Connected request: admission closes, the listener refuses new connections,
  process remains alive while work is unfinished, and the accepted request
  receives HTTP 200 with the actual synthetic result before process exit 0.
- Cancelled client: the transport actually drops its handler, the worker retains
  the only slot and another valid request gets 503, SIGTERM closes the listener,
  and the detached worker completes its runtime-dependent operation before exit.
  The closed gate still returns 503 after drain and its sole slot is released.

The final standalone release suite passed **8 tests, 0 failed**. One displayed
ignored test is the owned-child fixture, explicitly invoked by both parent
process tests; it is not skipped shutdown coverage. The log also includes an
intentional injected worker panic whose test verifies it remains an error.
`prover-tests-final.json` records exact command/environment, source hashes,
unchanged-source checks, process observations and all log SHA-256 hashes.
`Cargo.toml` and `Cargo.lock` were unchanged in this runtime lane.
The standalone crate also passes `cargo fmt --manifest-path
crates/prover-service/Cargo.toml -- --check`; `prover-format.json` records that
separate check because the workspace formatter excludes this crate. Final test
and source hashes were refreshed after the formatting-only adjustment.

```bash
CARGO_TARGET_DIR=/tmp/arcora-prover-service-target \
PROTOC=/tmp/arcora-tools/protoc-29.3/bin/protoc \
PATH=<cargo-home>/bin:/tmp/arcora-tools/sp1-6.0.0:$PATH \
cargo test --release --locked --offline --manifest-path crates/prover-service/Cargo.toml -- --nocapture
```

Limits: no real SP1 proof, guest execution/A06, TEE or external service was used.
Production attestation and backend code were not replaced. The child writes a
synthetic outcome file solely as evidence; production still has no durable
proof-result cache or retrieval API for a disconnected caller. Draining means
work finished, not that every work result succeeded or reached a cancelled
client. A genuinely stuck backend still delays graceful shutdown indefinitely;
no forced-kill deadline or automatic proof cancellation is introduced.
