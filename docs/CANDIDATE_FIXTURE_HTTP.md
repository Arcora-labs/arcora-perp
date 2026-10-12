# Candidate fixture HTTP transport and durable recovery

This packet tests the candidate transport boundary over caller-owned loopback
HTTP sockets. `candidate_fixture_transport` and its tests are compiled only with
`cfg(test)`. They implement the existing preparation/broadcast traits for an
explicit synthetic peer; they add no production route, backend, configuration
flag or legacy `ProverClient` fallback. Actual DPCLK3 proving/service acceptance
remains open, candidate submission disabled, and **PRODUCTION HOLD** applies.

The fixed normal/liquidation corpus reuses its original candidate witness and
full containers. Archive metadata, clock/report observations, opaque mock proof,
sender/nonce, outcomes and finality declarations remain fixtures. Native replay
and matching public values do not authenticate a proof, DON report, running
service, operator or chain. The current production prover remains legacy/DPCLK2;
the separate public identity preflight continues to return DPCLK3 compatibility
`REFUSED`.

## Transport boundary

The constructor validates the independently configured complete candidate
request/trusted pins before connecting. Candidate wire domain is DPCLK3; clock
version remains 2. Expected program, target, witness/material and plan values
are not learned from returned declarations.

The peer address is a literal owned IPv4 `127.0.0.1` socket with a nonzero port. The
path is fixed to `POST /candidate-fixture/v1/exchange`; content type is
`application/x-arcora-candidate-fixture-v1`. There is no URL/DNS/environment/
proxy/credential selection, redirect following or request retry. This fixture
restriction is not authenticated peer identity or a production transport policy.

The binary request/response domains are `DPCFREQ1`/`DPCFRES1`, version 1. The
160-byte header binds operation, complete request SHA-256, candidate program
SHA-256, exchange ID, request payload length/SHA-256 and response payload
length/SHA-256. Fixture-only/HOLD bits are fixed and all approval/proof/
submission bits are false. Payloads must be canonical, fully consumed postcard;
response bindings must match the outstanding request. Bounds are 20 MiB per
frame and 8 KiB per HTTP header, with stricter bounded proof/registration/revert
payload visitors. These are refusal limits, not measured proving capacity.

There is one HTTP exchange for each requested action. Non-success status,
ambiguous length/framing, transfer encoding, unsupported content type, trailing
bytes, malformed or cross-request/cross-operation responses and deadline
failure return coded errors. No raw response body is used as a diagnostic.
The default I/O budget is two seconds. Local native validation, serialization
and decoding are bounded computations, not a preemptible proving/runtime SLA.
The process counter starts from a nonzero random 64-bit seed and refuses wrap.
An exchange identifier is correlation data; this protocol provides no signed
freshness, durable uniqueness or service authentication guarantee.

## Durability remains with the existing coordinator

`DPCINT4`, `DPCREG1`, `DPCBTX1`, their exact staged payloads and physical lanes
remain unchanged. The adapter creates no second journal or retry coordinator.
The source and broadcast leases remain owned by the existing handoff; native,
request, source-cut and immutable plan validation still surround callbacks.

| Lost acknowledgement | Actual fixture effect and recovery rule |
| --- | --- |
| Clock registration | The clock may be registered although the HTTP reply is lost. `ClockPending` persists. Resume only looks up; it never registers the clock again or invents a later report registration. If reports do not exist, it remains `ReportsPending` with an Absent/HOLD result. |
| Report registration | The report fixture effect may exist despite the missing reply. `ReportsPending` persists. Resume uses lookup; a matching recorded effect can reach durable Prepared without a second report registration. |
| Broadcast | The fixture outcome may exist despite a lost reply. The broadcast lane stays Pending. Resume only looks up that exact immutable attempt/plan; it never broadcasts again. A terminal replay performs no HTTP action. |

Wrong constructor pins can prevent all socket work. A wrong peer response
after a mutation cannot prove the mutation had no effect; it leaves Pending and
blocks later actions. Absent, Unknown, Pending or Reorg observations are HOLD,
not permission to retry a mutation. These are fixture/cooperative recovery
properties, not exactly-once delivery on a real chain.

## Verification and remaining work

```sh
# python3 on the build PATH must resolve to Python 3.11+ for the existing helper.
cargo +1.99.0 test --locked -p gateway --bin gateway \
  candidate_fixture_transport_tests -- --nocapture
```

Tests use temporary directories and ephemeral listeners they own; listeners and
threads are joined on teardown. One process-local barrier runs both actual
normal/liquidation HTTP positive flows before any semantic refusal matrix.
All matrices share that same frozen code/config/corpus baseline; each refusal
still uses its own fresh directory, listener, remote state and durable lane.
Actual operation/effect counts, durable source/lane
stages and no-retry behavior distinguish transport evidence from an in-memory
callback-only test. Final source-bound test counts, raw logs, preservation and
publication-head CI are retained separately in the evidence packet.

Real candidate backend/proof generation, authenticated and sealed witness
transport, current target/service public configuration, receipt/nonce/finality
on a real chain, CC/key release, DON/uptime health, custody, capacity and
independent production approval remain separate requirements. Live feed
discovery remains user-deferred. Existing closed offline software subcriteria
are not reopened; the broader release gate remains HOLD.

[Active work and acceptance gates](ACTIVE_WORK.md) ·
[Current production service identity boundary](PUBLIC_SERVICE_IDENTITY.md).
