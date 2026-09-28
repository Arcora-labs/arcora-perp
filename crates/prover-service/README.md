# Prover-service admission and shutdown

`POST /prove` requires the existing unexpired attested bearer session. The
parts-only admission extractor checks it before reading the body, then reserves
a proof slot. Missing, incorrect, expired, absent-server-token or duplicate
credentials return 401. A full or closed admission pool returns 503 without
polling the body. No production attestation requirement is relaxed.

| Variable | Default | Accepted range |
| --- | ---: | ---: |
| `PROVER_MAX_CONCURRENT` | 1 | 1–8 |
| `PROVER_MAX_BODY_BYTES` | 536,870,912 (512 MiB) | 1–536,870,912 |
| `PROVER_BODY_TIMEOUT_SECS` | 30 | 1–300 |

Invalid settings fail startup before backend initialization. The retained body
default supports the existing hex-encoded full-state witness. Set a smaller
cap when the deployment's witness size permits. Authorized oversized bodies
return 413; a stalled body returns 408. The receiving timeout is cooperative:
the byte cap, rather than a CPU preemption deadline, bounds synchronous JSON
parsing. The admission slot also covers hex/postcard decoding.

The slot moves into the actual blocking proof worker. Disconnecting an HTTP
client or cancelling its async waiter cannot admit another proof while that
worker still runs. Invalid bodies and completed or panicked workers release
their slot automatically. There is no unbounded queue of proof requests.

Unix signal handlers are installed before binding the listener. On SIGTERM or
Ctrl-C, admission closes first and Axum stops accepting and drains
in-flight requests. The service then explicitly waits for every admitted worker
before returning from async main, including workers whose HTTP client disconnected.
This keeps Tokio's timers, I/O and async tasks alive while the SP1 backend uses
its captured runtime handle; merely waiting during runtime teardown is too late.
Proof execution is not cancellable: a stuck backend can delay shutdown
indefinitely. This is an orderly drain, not a bounded forced-termination policy.
The session's existing expiry and attestation behavior are unchanged.

Admission tests use in-process routes and bounded synthetic workers. On Unix,
two tests also spawn owned child processes, use actual loopback HTTP and SIGTERM,
and verify both a connected request and a cancelled HTTP client. The synthetic
worker exercises the production runtime-handle pattern without generating an
SP1 proof. The ignored `owned_shutdown_child` test is a subprocess fixture that
these two parent tests execute explicitly; do not run it directly.

A cancelled HTTP client cannot receive its proof response. The service has no
durable proof-result cache or retrieval API; the tests' outcome file is only
test evidence. Draining proves the worker finished, not that a disconnected
caller received or can retrieve a successful result. Worker panics remain
errors, and the normal connected handler maps them to HTTP 500.

Build/test the real SP1 service with the configured `cargo prove` toolchain and
protoc, for example:

```bash
cargo test --release --locked --manifest-path crates/prover-service/Cargo.toml
```

The build script still compiles the real guest ELF. Do not replace it with a
dummy guest or disable the bearer/attestation gate to run these tests.
