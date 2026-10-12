# Candidate signed/sealed fixture: software verification

Base main: `60eceef733613fe6d491548d35eb4fdb7c0809bd` (#56).
Code: `52600351c4a3e5a9ad0c565175dc3c9561f30dfd`.
This packet adds only `cfg(test)` signed/sealed messages for the existing owned
HTTP fixture. It establishes configured **ECDSA signing-key possession** and
exact message/context binding, with recipient fixture-key decryption. It does
not establish sender static-X25519 private-key possession, service/quote/operator
approval, real SP1 proof, DON/chain/finality/custody or production acceptance.
Submission stays disabled and **PRODUCTION HOLD** remains.

| Actual local check | Result |
| --- | --- |
| New signed/sealed tests | **19 PASS / 0 FAIL / 0 IGNORE**, 20.44 s test / 34.621 s total, compile and execution passed first attempt |
| Full gateway, including new19 and unchanged plain18 | **716 PASS / 0 FAIL / 23 intentional IGNORE**, 384.27 s test / 384.651 s total |
| Python builder/preflight | **25 PASS** |
| Workspace format and Clippy | PASS, warnings denied |
| Reviewed/candidate/auxiliary pins | 21/9/2 unchanged |

The five command receipts bind **375** covered source files before/after to
`ec07ccd9cba6f2b52b7600e149715805bd7d58e84195c4a947e4c75102cf9b89`.
The pin receipt is a single same-map snapshot. `artifact-ledger.json` binds raw
outputs, receipts, six code-commit files and portable copies. Independent source
review was captured before the full gateway finished; it does not claim that
reviewer ran tests. Full execution is its separate command receipt.

The fixed outer header is 330 bytes, with total overhead467/minimum627/global
maximum20MiB+467. It signs the separate magic/version/domain/path/type, direction,
session, both configured signing/X25519 public pins, operation/request/program/
exchange/request-payload binding and inner length/SHA. Canonical low-S configured
signature verification precedes bounded sealed-box decoding, contributory DH,
decryption and exact old inner-frame parsing. Existing primitives are unchanged.

The actual normal/liquidation full-container/native flows form the process
baseline. Each owned HTTP fault has fresh keys/session/listener/state/dirs/lanes;
pure codec field matrices may reuse their local Pair/input and have no peer
effect. Valid-signed corrupt tag/AAD reaches Decryption; signed wrongboxversion
reaches Framing; authenticated low-order/noncanonical ephemeral keys reach Key.
Independent primitive opening succeeds for re-encrypted wrong inner digest/action,
then the codec refuses Context. A genuine high-S equivalent is refused Signature.

Bounded session exchange/mutation-effect reservations precede peer effects.
Ciphertext replay and a same mutation under a new exchange are refused; capacity
exhaustion never evicts an old mutation. Client responses require the exact
previously wrapped request context and are accepted once. Session pins cannot
silently reset an existing receiver. New peer/session/state does not create a
durable/global exactly-once guarantee.

Owned wire captures contain no original witness/full-report literal plaintext
and open exactly with the configured recipient key. This is a wire assertion;
native validation still has process plaintext, and no whole-process/CC memory
confidentiality is promised. Signed mock proof/finality/outcome remains mock.
Request auth/plaintext failure before acceptance has zero fixture effects. Bad
ACK/cipher/reflection/plaintext after a valid clock effect preserves ClockPending,
one prior effect and no fallback/later mutation. Lost clock ACK Resume holds if
reports do not exist; lost report/broadcast ACK reconciles the existing effect
through lookup, preserving exact source/plan/lane. Terminal completed outcome
replay performs no HTTP; pure mock proving may repeat at ReportsObserved.

Original plain18 tests stay byte-identical. Old DPCINT4/DPCREG1/DPCBTX1 stores,
coordinator leases, fixtures, guest/core/ELF/vkey, root Cargo and pins are unchanged.
A11 has one additive named sealed fixture step, with old guards/timeouts retained.
The 3003 baseline paths and original82 dirty files are checked independently;
final preservation is a separate receipt. No source failure/lint bypass was needed.

Prior #56's three main push runs are all SUCCESS; `main-refresh.json` and raw ZIP
archives record only that base. Publication-head CI and normal merge are delivered
separately after they occur. Approved target/policy/service/key inputs, real
candidate backend/deployment transport, fresh proof/verifier/settlement/claim,
actual CC/key release/DON/uptime/custody/operations and independent release remain
open. Live feed discovery remains deferred.

[Channel scope and usage](../../CANDIDATE_FIXTURE_SEALED_CHANNEL.md) ·
[Active work](../../ACTIVE_WORK.md) ·
[Plain HTTP evidence](../2026-10-12-candidate-fixture-http/README.md).
