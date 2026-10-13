# Outbound /prove JSON byte budget

Base: `c33e3824c2557a32f796dd6234aa6f504f1c93c2` (normal PR61 merge).
Before this work, its three main-push workflows and all 14 jobs were read back
SUCCESS, with no open PR. The existing receiver default/maximum **512 MiB JSON
HTTP body** ceiling is shared with the client. Its environment range 1..536870912 bytes (512 MiB)
and configured lower limits remain unchanged. A lower peer may still return 413.
This does not define plaintext/witness, aggregate memory or proving capacity.

## Change and precise allocation scope

After plaintext postcard serialization (including the existing DPCLK2 branch),
a checked calculation bounds the current sealed format before nonce hashing,
provider invocation or seal allocation: `C=P+varint_len(P)+96`, then
`JSON=15+2*C`. All additions/multiplication are checked. The actual sealed
postcard length is checked again before hex expansion. The final HTTP body
uses `str::len()` bytes before curl arguments/spawn, and the shared curl runner
also checks any stdin input against the same fixed ceiling before spawning.

Plaintext and existing witness/state allocations have already happened.
The clocked path's temporary serialization/magic copy also precedes the guard.
These checks do not bound those allocations or total RSS, and do not establish
a live peer's effective config or a proving/RAM capacity. The curl writer still
borrows the body slice without a full-body clone. Existing wire format, nonce,
seal providers, bearer, deadline/capture, flags, parsing and single 401 refresh
stay intact for admitted requests. No lower operational cap was invented.

## Actual evidence

The exact-source native replay passed on its first compile/run: six small
HTTP cases, three actual native curl requests. A 160 KiB exact-budget body/bearer,
a UTF8 exact-byte body and typed 401 control were preserved. ASCII budget+1,
UTF8 character-count budget and zero budget refusals produced **zero child
markers and zero peer requests**, with fixed diagnostics that echo no values.
These use small injected caller limits, not a 512 MiB native payload.

Seven native small synthetic postcard/JSON containers (ciphertext<=16KiB)
matched the checked helpers; the unit format regression separately checks eight
such containers. Synthetic containers are not authenticated seals. Isolated
source-extracted early/actual-wire guard cuts use inert continuation sentinels:
467-byte boundary accepted,466-byte budget refused before continuation. These
cuts do not execute a whole provider, key release, sealing or handshake.

The 512 MiB and usize-overflow checks are **integer/source evidence only**, with
no giant allocation. Current JSON shape has odd length: plaintext 268435348
maps to 536870911 bytes (ceiling-1); one more maps to 536870913 (ceiling+1).
The generic byte guard accepts exact equality, but this encoded format cannot
hit the even 512 MiB ceiling exactly. This is a format calculation, not witness
acceptance, proof or capacity testing. [Native receipt](native/result.json).

| Actual local validation | Result |
| --- | --- |
| Curl HTTP caller tests | 19 PASS; three new regressions |
| Prover-client/session and body tests | 35 PASS; three new tests |
| Shared std-only transport tests | 10 PASS; one private worker helper IGNORE |
| Python service identity | 25 PASS |
| Clippy / format | PASS; 3.3923 / 0.6942 seconds |
| Actual offline/locked prover-service typecheck | PASS; 3.0433 seconds; receiver alias compiled; no boot/setup/prove |

Five sources changed. The other 373 covered public sources, old 32 client tests,
old 16 HTTP tests and old shared 9 tests/private worker are preserved. Full reverse
reconstruction of the former client/shared transport validates old seal/POST
bodies after removing only new guards. Reviewed 21 / candidate 9 / auxiliary 2 pins,
eight manifests/locks and nine proof/program artifacts are unchanged. All 2525
historical immutable inputs outside the authorized five sources are unchanged.
The full gateway suite was not rerun locally; **749/0/24 is only the expected
new CI count** until actual publication logs are checked.

[ledger.json](ledger.json) binds **68 copied public artifacts**; README and
ledger are outside that map. Native executables, caches, full source archives
and raw body/request bins are excluded. The source inventory is 378 files,
SHA-256 `927f59e24220da93a52a21b7b3e1d1472859c885a33323d5891e9e23ef38fd9d`.
No repair history or earlier failed runtime is invented; all new recorded
local tests and native probes passed their first run.

## Remaining acceptance

Earlier plaintext allocation protection needs its own bounded-counting design
and performance contract. Local bearer argv visibility remains separate.
Fresh proof, approved live target/service identity, DPCLK3 backend, actual
CC/key release, custody/operations and independent release gates remain open.
CPU/typecheck or CI success is not production acceptance. Candidate submission
stays disabled. **PRODUCTION RELEASE HOLD**.
