# Candidate signed/sealed fixture channel

This is a `cfg(test)` software-key-possession and message-binding boundary for the
owned candidate HTTP fixture. It does not start a production route/backend,
create an approved service/attestation identity, generate an SP1 proof or permit
candidate submission. **PRODUCTION HOLD** remains. Production public identities
remain self-reported/unattested; the existing prover remains legacy/DPCLK2 and
its public preflight refuses DPCLK3 candidate compatibility.

`FixtureTransport::new` retains the separate plain fixture behavior.
`with_sealed_channel` explicitly attaches an independently configured fixture
channel and refuses mismatched request/program pins before any socket work.
There is no ambient URL/key/session/config discovery, production flag, plaintext
fallback or automatic retry. Only owned literal IPv4 loopback listeners are used.

The outer signed/sealed format uses `/candidate-fixture/sealed/v1/exchange`,
`application/x-arcora-candidate-fixture-sealed-v1`, magic `DPCFSEA1` and its own
signature/AAD domain. Its fixed header is 330 bytes; sealed-box and signature
overhead makes the outer length exactly inner length + 467 bytes (minimum 627,
maximum 20 MiB + 467). The
existing DPCFREQ1/DPCFRES1 frame is its exact inner message. The channel pins both
peers' compressed signing and X25519 public keys, a caller-owned session, and
request/program hashes. Direction, operation, exchange identity, request-payload
binding, inner length/digest and configured peers are authenticated together.
Keys are independently injected fixture expectations, never learned from a peer
response. Fixture secrets are not Debug/Serialize outputs or environment values.
Sender authentication establishes configured ECDSA signing-key possession.
Static X25519 public pins are signed/AAD-bound, and the actual recipient key
decrypts. Anonymous ephemeral encryption alone does not prove the sender's
static-X25519 private-key possession; this is not mutual attestation/key release.

Existing k256 signing and sealed-box X25519/HKDF-SHA256/XChaCha20-Poly1305 are
used without replacing primitives or changing guest/core/ELF/vkey dependencies.
The existing pure DH contributory check rejects unusable peer/ephemeral points;
using that helper does not verify a hardware quote or approve an operator.
Canonical signature verification precedes ciphertext decoding/decryption and
inner typed payload processing. AEAD AAD binds the signed metadata. Outer and
operation-specific response bounds are checked before body allocation, with
the original strict HTTP header/EOF and total exchange deadline guards.

Replay protection is bounded and scoped to the owned peer/session. Authenticated
exchange IDs and mutation-effect bindings are reserved before fixture effects;
capacity exhaustion refuses without eviction or mutation retry. A fresh session,
recreated peer or discarded replay state does not establish durable/global
exactly-once delivery. The existing preparation/handoff coordinators remain the
source/checkpoint/lease authority; old stores and physical broadcast lanes are
unchanged.

Lost clock ACK still reconciles lookups and holds if reports do not exist.
Lost report/broadcast ACK reconciles the existing fixture effect without a second
mutation. Bad authentication before a request's effect can establish zero fixture
mutation; a bad response after an accepted effect leaves Pending and cannot prove
that the effect never happened. Prepared preparation Resume is local; a new
Prepared-to-Fresh handoff may exchange packets. Only completed-outcome terminal
handoff replay makes no HTTP call. ReportsObserved mock proving may repeat.

Tests retain the original normal/liquidation full witness/container corpus,
native roots/count/canonical calldata, and exact durable-stage/effect assertions.
Both complete sealed positive flows form a baseline before semantic fault
families. Each owned HTTP fault scenario uses fresh fixture keys/session,
listener/state/directories/lanes; pure codec matrices may reuse their local
pair/input across field mutations and perform no peer effect.
Wire confidentiality assertions concern captured synthetic bytes only. Native
validation still uses plaintext in process memory; whole-process zeroization,
malicious-host confidentiality and production/CC protection are not claimed.
Opaque fixture proof, observation, finality and settlement declarations remain
mocks even when their envelope signature is valid.

```sh
# Build PATH python3 must be Python 3.11+ for the existing public identity helper.
cargo +1.99.0 test --locked -p gateway --bin gateway \
  candidate_fixture_seal_tests -- --nocapture
cargo +1.99.0 test --locked -p gateway --bin gateway \
  candidate_fixture_transport_tests -- --nocapture
```

Source-bound actual results, failed-before repairs, raw command outputs and
publication-head CI are recorded separately in the audit packet. This document
specifies scope; it does not substitute for those execution records.

A real candidate backend, authenticated/sealed deployment transport, approved
public target/service/policy/key expectations, fresh proof/verifier/settlement/
claim, actual CC measurement/quote/handshake/key release, DON/uptime/economics,
custody/exit/recovery and independent release approval remain open. Live feed
discovery remains user-deferred.

[Plain fixture boundary](CANDIDATE_FIXTURE_HTTP.md) ·
[Public service identity](PUBLIC_SERVICE_IDENTITY.md) ·
[Active work and acceptance gates](ACTIVE_WORK.md).
