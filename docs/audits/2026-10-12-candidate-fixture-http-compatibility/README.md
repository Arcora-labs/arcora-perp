# Candidate fixture HTTP: compiler compatibility and initial CI failure

Initial PR56 publication `8181880a41dcd1bf1f1117270c0d0067e4c7b15f` was **not merged**.
Its CI lint and A11 release regression rejected `AtomicU64::fetch_update` as
 deprecated under the newer CI compiler with `-D warnings`. Raw failed job logs
are retained. No warning guard, workflow requirement or repository rule was disabled.

Compatibility code: `90ab7e2acb0c173fb0e76a311ac9377e4363636f`.
Only the fixture counter changes executable behavior spelling: a checked
`compare_exchange_weak` loop with Relaxed success/failure ordering, old-ID return,
race/spurious-failure retry and exhaustion refusal before wrap. Random process
seed and correlation-only scope remain. All 18 existing HTTP test bodies are
byte-exact. Independent inverse comparison reconstructs the previous core;
it does not claim a fresh exhaustive saturation or concurrency test.

| Current local check | Result |
| --- | --- |
| Focused owned HTTP | **18 PASS / 0 FAIL / 0 IGNORE**, 57.39 s test / 64.017 s total |
| Python builder/preflight | **25 PASS** |
| Workspace Clippy and format | PASS, warnings denied |
| Reviewed/candidate/auxiliary pins | 21/9/2 unchanged |

The four command receipts bind **373** covered source files before/after to
`644a6c7c5f18a3557d619abacd2cb8a5acfed726f25ad5c7b23a5aff87c29db0`;
the pin receipt is a single same-map snapshot. This focused compatibility run is
separate from the original full **697/0/23** run at source `69e33918…`.
The immutable [original packet](../2026-10-12-candidate-fixture-http/README.md)
stays historical; only new publication-head CI can establish the current full-suite result.

The initial arcora-labs preview separately failed with Vercel `git_info_fail`
before any build log line was available. Public-only exact project/head metadata
is retained. No application compilation error was observed; no configuration or
manual redeploy was requested. The next-head preview must be checked independently.

Both packets concern `cfg(test)` owned loopback HTTP and opaque mock
proof/observations/outcomes. No production backend, sealed witness transport,
fresh proof, actual DON/chain, custody/CC/key release or operator approval is
established. Submission stays disabled and **PRODUCTION HOLD** remains.
[Transport scope](../../CANDIDATE_FIXTURE_HTTP.md) · [Active work](../../ACTIVE_WORK.md).
