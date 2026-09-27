# CI coverage and evidence identity

Live base CI `36337867266` at `098e4952c189f92e4293ed7d49f81222b626e406` completed all four jobs successfully. Local edits have not been pushed, so that remote run proves the base only. Local results carry base SHA/tree plus content fingerprints in `checks/*.json`. Historical evidence and failed setup attempts are retained and never counted as final passes.

| Workflow | Coverage after local change | Limit |
|---|---|---|
| ci.yml | Main pushes and all PRs; Rust fmt/clippy/workspace, no_std, frontend, Foundry and excluded typecheck | Excluded CI uses a stub ELF; no real SP1 execution/proof. Local host/service use real ELF separately. |
| a01-ingestion | Existing A01 paths plus root Cargo.toml | Its native-cast ignored case needs Foundry explicitly; local macOS inherited nonblocking socket was fixed and case ran1/1. |
| a07-integration-hotfix | All PRs; named historical branch push only | Does not represent proof verification. |
| a11-release-evidence | Existing paths plus crates/** and local verification scripts | Correct RELEASE profile flags now actually checked by an independent Rust control. |

Test-control negative evidence: two assertions fail with the old TEST-profile-only environment and pass with RELEASE debug/overflow checks. Runtime code regressions have separate failed-before assertions; dependency/compiler/toolchain failures are not counted as behavioral negative controls. Successful build/typecheck is not a test count. Overlapping core/workspace/gateway selections must not be summed.

Tool drift is recorded: local Rust1.95, Node24.12/pnpm11.5 versus CI Node22/pnpm10; Foundry1.7.2 nightly; SP1 direct and sp1/slop family lock resolution6.0.0 plus succinct Rust1.93.0-dev. Both nested SP1 .gitignore files now allow Cargo.lock tracking. Runtime dependency hashes and tool provenance are in the final manifest. Unpatched RSA and remaining Vite/Vitest dev advisories are open, not suppressed.

Proposed repository policy: require current-head Rust/frontend/Foundry/typecheck jobs, A01/A11 for affected paths, and a separately provisioned real-guest/proof job before release. Review stale branch-specific workflows, pin third-party actions to reviewed immutable commits, and use a protected release branch with independent review. No GitHub protection, collaborator or action setting was changed.
