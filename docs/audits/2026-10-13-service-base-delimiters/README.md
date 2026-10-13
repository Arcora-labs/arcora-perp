# Service BASE query/fragment refusal before curl

Base: `1caae328fe73a5ab96bb4200d5e28d926807d201` (normal PR60 merge).
All three main-push workflows on that commit completed successfully before
this work. This packet changes the gateway `/prove` join and both services'
`/attest` joins to one shared, std-only `service_endpoint` helper.

The helper rejects raw `?` or `#` with `Error::Endpoint`, displayed as the fixed
`invalid HTTP service base URL`, before curl is spawned. Other inputs retain
the exact previous `trim_end_matches('/')` plus trusted constant service-path
join. Percent-encoded delimiters are not decoded. This is a narrow BASE rule,
not a general URL parser, scheme/authority validator or host allowlist.

## Actual before/after evidence

Exact base functions and all three join expressions were compiled into an
owned native harness. On BASE, twelve loopback calls returned low-level OK:
three normal controls and nine query/fragment/empty-query cases. The latter
sent requests to `/base?x=1/prove`, `/base?x=1/attest`, `/base` or
`/base?/prove|attest`; the appended endpoint did not become the intended path.
The fixture returned synthetic 200 JSON; no real service or proof was accepted.

The fixed replay passed all **17 cases** on its first run. The same three
normal controls made one request each. Twelve raw delimiter refusals,
including empty `?` and empty `#`, produced **zero child markers and zero
peer requests**. Two direct full-URL GET query controls still made requests
and parsed JSON. BASE validation was not added to the complete-URL GET helper.
The normal 160 KiB POST body/bearer and both byte-identical GET functions were
preserved. [Comparison](recovery/after-comparison.json).

GET tests exercise mechanically extracted caller joins and exact GET helpers;
they do not execute the whole handshake, read operator pins/collateral, mint
session tokens or establish quote/key-release acceptance. Production handshake
pin/collateral checks keep their original ordering before the join. The refusal
claim is pre-spawn/pre-peer-request, not before all local work or sealing.

## Actual local validation

| Check | Result |
| --- | --- |
| Real curl HTTP caller tests | 16 PASS / 0 FAIL; four new regressions |
| Existing prover-client/session tests | 32 PASS / 0 FAIL |
| Shared std-only transport/builder tests | 9 PASS / 0 FAIL; one private worker helper IGNORE |
| Python service-identity neighbors | 25 PASS |
| Workspace/all-targets/locked Clippy | PASS; 22.9678 seconds |
| Workspace format | PASS; 3.3075 seconds |
| Actual offline/locked prover-service typecheck | PASS; 16.5568 seconds; no boot/setup/prove |

The six added test functions cover raw/empty/combined delimiter refusal without
echoing values, pre-spawn POST refusal with a nonexistent command, unchanged
address forms, nested/trailing-slash and encoded paths reaching exact HTTP
routes, and preserved direct GET query support. IPv6/HTTPS builder forms are
string compatibility checks; no live IPv6 or TLS acceptance is claimed.

The covered inventory is 378 files, SHA-256
`e399e633da9ddac4827bc615b7285e6203f0d7424df71be370cea78b12192dbd`.
Only six source files differ. All 207 existing inline tests, the old twelve
caller tests, seven shared tests/private worker, and other 372 public sources
are intact. Capture/deadline code, curl flags, body/bearer streaming, response
parser and single-401 refresh are unchanged. Reviewed 21, candidate 9 and
auxiliary 2 pins, root/service Cargo files, separate TEE lock and frozen
ELF/vkey artifacts are unchanged.

[ledger.json](ledger.json) binds **132 copied public artifacts**. README and
ledger are outside that map. Executables, caches, full source archives and
synthetic request-body binaries are excluded. Publication CI is recorded for
its exact head separately; the full gateway suite was not rerun locally here.

## Remaining scope

URLs are operator configuration; this is not evidence of remote critical SSRF
or an attestation bypass. The next GPU-free audit concerns an outbound body-size
contract compatible with the receiver's configurable 512 MiB maximum and the
earlier serialization/allocation steps. Bearer argv visibility remains separate.
No request cap, token grammar, new dependency or URI normalization was added.
Fresh proof, live target/service identity, DPCLK3 backend, real CC/key release,
custody/operations and independent release gates remain open. Candidate
submission stays disabled. **PRODUCTION RELEASE HOLD**.
