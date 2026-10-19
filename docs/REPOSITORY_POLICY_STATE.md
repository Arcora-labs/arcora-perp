# Repository policy: applied state and recommended template

Read-only observation: 12 October 2026, 00:06 UTC (03:06 Europe/Istanbul).
Repository: `Arcora-labs/arcora-perp`, main ruleset `24812584`, active.
The ruleset and effective main-branch rules were read from GitHub; no policy
was changed by this documentation update.

| Setting | Applied GitHub ruleset | Checked-in recommended template |
|---|---|---|
| Required approving reviews | **0** | **1** |
| Approval after the last push | **false** | **true** |
| Resolve review threads | true | true |
| Strict required status checks | true | true |
| Required status-check contexts | **11** | **12** |

The recommended template is [.github/main-ruleset.json](../.github/main-ruleset.json).
Its contents do not describe the current applied approval requirement, and the
file does not apply itself to GitHub. The template now also lists a twelfth
context, `reviewed guest execution (CPU)` (the CPU execution of the reviewed
guest, `.github/workflows/ci.yml`). The applied ruleset still requires the 11
contexts below until the repository owner applies the template; until then the
new job runs on every pull request but GitHub does not require it to pass. The stricter one-review/last-push-approval
settings remain a recommendation requiring a separate policy decision. Neither
this note nor a successful merge silently applies them.

The 11 applied required contexts are:

- `rust (lint, 1.99)`
- `rust (workspace)`
- `prover crates (excluded, typecheck)`
- `contracts (foundry)`
- `frontend (vite)`
- `dependency advisories`
- `release regression`
- `foundry release gate`
- `gateway RPC, crash and alert drills`
- `frontend release gate`
- `prover source / deployment binding`

The fresh readback of merged PR #52's publication head,
`41c1ed8bc561b2cf29868d94619fd223732068c9`, observed **19 successful check/status
contexts**: 17 check-run names and two Vercel commit-status contexts. This is the
observed publication result for that head, not a claim that the ruleset requires
19 contexts or that another head has passed. Every later publication head needs
its own readback. The applied rules also prohibit deletion and non-fast-forward
updates and retain strict checks; zero required reviews does not remove those
protections.

The published [selected API observation](audits/2026-10-12-chainlink-offline-finalization/checks/ruleset-observation-public.json)
contains the relevant ruleset, effective-branch, PR/head, check-run and status
fields, timestamp, source fingerprints and hashes of the full raw responses.
The full responses are retained locally at
`target/handoff-validation-20261012/ruleset-observation.json`; unnecessary GitHub
author/account fields are excluded from the public copy. The enclosing audit
ledger binds that selected copy. Earlier snapshots, including the October 9
one-review policy, remain historical evidence and must not be presented as this
current state.

GitHub merge eligibility and passing CI do not establish an independent protocol
review, fresh cryptographic proof, deployment/servicing identity, custody
acceptance or release approval. **PRODUCTION RELEASE HOLD** and the independent
review gate remain open; this document reconciles policy wording only.
