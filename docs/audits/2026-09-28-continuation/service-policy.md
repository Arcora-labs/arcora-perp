# S4-07 service resource-policy continuation

Scope: local source changes, in-process HTTP tests, and bounded loopback sockets.
No real proof generation, external-service requests, chain sends, network load,
attestation bypass, advisory suppression or A06 rerun.

Implemented:

- Prover admission authenticates bearer/session expiry before body polling and
  limits concurrent reception/decoding/proving. Default capacity is one; overload
  returns 503 immediately. The owned slot moves into the blocking worker so a
  cancelled HTTP waiter cannot release live proof capacity. Body size is
  configurable up to the existing 512 MiB cap; stalled reception returns 408.
- The prover closes admission on SIGTERM/Ctrl-C, then asks Axum to stop accepting
  and drain in-flight HTTP work. Blocking proof work is allowed to finish.
- Gateway HTTP and both WebSocket paths enforce an explicit browser-origin
  allowlist before handlers. Dev defaults preserve localhost/127.0.0.1 at
  ports 5173 and 4173. Production browser origins require explicit configuration;
  native requests without Origin remain supported with existing business auth.
- Both WebSocket paths share a connection semaphore and explicit incoming
  frame/message and outgoing write-buffer caps. Incoming messages consume a
  per-connection one-second budget before JSON/auth parsing. All sends have a
  configurable deadline; private writes retain their existing credential fence.
  The legacy socket now receives idle disconnects and releases its slot.

Configuration and operational limits are documented in `crates/gateway/README.md`
and `crates/prover-service/README.md`.

Evidence:

| Check | Result | Evidence |
| --- | --- | --- |
| Actual standalone prover release tests, real guest build toolchain | 5 passed, 0 failed | `service-prover-tests-final.log`, `service-prover-tests.json` |
| Integrated gateway suite | 393 passed, 0 failed, 1 pre-existing ignored | `checks/gateway-final.log` |
| Actual-router origin rejection and both WS paths | Included in the 393 tests | `service_policy_integration_tests` in gateway log |
| Loopback backpressure and unrelated-account progress | Passed: 8 MiB bounded fixture, 3 connections, 2,090 ms lease release, 1 ms unrelated-account delivery, 0 remaining subscriptions | `service-backpressure-tests.log` |

Prover tests assert rejected bodies are never polled (the body stream panics if
polled), malformed and oversized authorized requests release their slot, stalled
body reception times out, overload and shutdown reject before body polling,
expiry/duplicate-token/config boundaries fail closed, and aborting the waiter for
an already-running synthetic blocking worker retains capacity until actual work
finishes. No test initializes or invokes a real proof backend.

The first prover build selected Homebrew rustc, which has no succinct target.
`service-prover-tests.log` records that environment failure. Prepending the
installed rustup and pinned cargo-prove directories uses rustc 1.93.0-dev for the
real guest and passes; see the exact environment in `service-prover-tests.json`.
The first combined gateway run also repeated the four policy tests via a
standalone include harness. That temporary duplicate harness was removed after
integration; the 393 count is the distinct binary-test result.

The old backpressure test's 8 MiB frame was correctly rejected immediately by
the new 1 MiB production write-buffer cap. Its loopback fixture now explicitly
configures a 16 MiB maximum only for that test so the existing lease-timeout,
rotation, unrelated-owner progress and cleanup assertions still exercise actual
TCP backpressure. Production defaults remain at 1 MiB.

Residuals: S4-07 remains PARTIAL. No process-signal shutdown test, real proof or
stuck-backend termination test was run. Blocking proof execution has no safe
cancellation deadline, so orderly drain may wait indefinitely. The body deadline
cannot preempt synchronous JSON parsing. HTTP connection/idle limits, per-IP WS
fairness, all endpoint rate limits and business-authorization permutations,
rate-map/account cardinality, snapshot serialization memory, gateway shutdown
versus accepted writes, malformed-wire permutations and capacity/p95/p99 remain
outside this bounded slice. WebSocket caps do not limit pre-upgrade TCP sockets.
