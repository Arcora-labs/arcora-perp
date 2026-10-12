# Legacy curl: one HTTP(S) transfer per configured endpoint

Base: `c56a6114fbc2a43be8e3b414fef00be91f5efa5f` (merged PR59).
The two attestation GET callers and the gateway proof POST now pass
`--globoff --proto =http,https` immediately after the existing first `-q`.
The endpoint still follows `--`; timeout, bounded capture, redirect behavior,
body streaming, response parsing and the single 401 refresh remain unchanged.

## Confirmed before/after behavior

Exact base functions were compiled into an owned native harness and exercised
with `/usr/bin/curl` 8.7.1 against an ephemeral loopback server. A configured
`/case{a,b}` base caused two POSTs, to `/casea/prove` and `/caseb/prove`, carrying
the same 160 KiB synthetic body and bearer. The server returned 401 then 200.
The old HTTP helper used the final status and returned a concatenated body;
JSON parsing rejected that body. This is **not evidence of an accepted proof**.

The fixed functions send one literal `/case{a,b}/prove` POST and preserve its
401 as `Unauthorized`. The normal 160 KiB control still sends one POST and
returns the same JSON. Both byte-identical GET helpers previously accepted an
owned public `file://` JSON fixture; they now return the existing static
transport-exit error. No operator file or credential was opened by the probe.
See [the comparison](recovery-design/native-before-after-comparison.json).

The first AFTER harness run asserted an invented GET diagnostic. The actual
protocol refusal already worked; only the harness expectation was corrected
to the diagnostic in the unchanged application error path. The failed output,
old helper and [repair receipt](recovery-design/after-helper-repair.json) are
retained. The final replay passed with unchanged application sources.

## Actual local validation

| Check | Result |
| --- | --- |
| Real curl caller regressions | 12 PASS / 0 FAIL; four new tests cover literal brace/range paths, owned FILE refusal and scheme-less loopback compatibility |
| Existing prover-client/session neighbors | 32 PASS / 0 FAIL |
| Shared bounded transport | 7 PASS / 0 FAIL / 1 private worker helper IGNORE |
| Clippy, workspace/all-targets/locked | PASS; 25.2347 seconds |
| Workspace format | PASS; 3.9854 seconds |
| Python service-identity neighbors | 25 PASS |
| Actual prover-service offline/locked typecheck | PASS; 15.0003 seconds; no backend, setup or prove execution |

The frozen public source inventory contains 378 files and hashes to
`678ae9e19a08d73b05df8653478e48a8d8b85d31a85992ff83bef68d8f39385b`.
Only gateway main/client/HTTP tests and prover-service main differ. Removing
the fourteen production additions reconstructs all three base files exactly;
the old eight caller tests are an exact prefix of the current test file.
All 207 existing inline test functions and the other 374 public sources are
unchanged. Reviewed 21, candidate 9 and auxiliary 2 pins, root/service Cargo
files, frozen ELF/vkey artifacts and the separate TEE capture lock are intact.

[ledger.json](ledger.json) binds **73 copied public artifacts**; README and the
ledger itself are outside that map. Native executables, caches, full source
archives and synthetic request-body binaries are excluded. This packet contains
local validation; publication CI is recorded separately for its exact head.
The full gateway suite was not rerun locally in this packet.

## Scope and next audit

Endpoint URLs come from trusted operator configuration. Production session
tokens are derived locally from the verified handshake. These fixtures do not
establish remote critical SSRF, bearer injection or attestation bypass.
The flags constrain curl's target protocol and URL expansion; they are not a
host allowlist or a complete URL parser. [The curl manual](https://curl.se/docs/manpage.html)
documents the selected options.

Base query/fragment suffix behavior, an outbound body-size contract consistent
with the receiver's configurable maximum (512 MiB), and local bearer argv
visibility remain separate audit candidates. No arbitrary request cap or new
token grammar was added. GPU/proof, live service/target binding, real CC/key
release, custody/operations and independent release acceptance remain open.
Candidate submission remains disabled. **PRODUCTION RELEASE HOLD**.
