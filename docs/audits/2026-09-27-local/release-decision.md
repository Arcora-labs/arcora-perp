# Release decision: HOLD

The authorized local delivery is a separate worktree, fixes, task-level evidence and a reviewable progress guide. It is not a release authorization. Twelve of27 guide cards meet their bounded criteria; ten are partial and five blocked. `graph-gate.json` must remain CLOSED while mandatory cards are incomplete.

Release blockers, in remediation order:

1. **Settlement durability and ambiguous chain outcomes.** Configured journal write failure now stops progression. The seal/periodic-snapshot ordering, every ACK/fsync/rename crash boundary, unpinned ambiguous count/root reads and late previously-broadcast transaction reconciliation remain open. This is a funds-liveness gate; passing native journal tests is insufficient.
2. **Actual proof chain.** Real6.0.0 ELF, local vkey and normal native/guest execution exist. A06 phase1/phase2 guest verification was stopped by automatic safety review; its unexecuted draft is retained separately and the host remains the previously tested normal harness. No Groth16 proof, target-verifier receipt or real-proof full token lifecycle exists for this source. Docker gnark is not currently running; no network or paid prover was used.
3. **Browser/runtime and endpoint resource policy.** Actual extension wallet and browser connected to the real gateway remain untested. The fixture CSP is not production deployment configuration. Permissive CORS, missing WS origin/connection limits, large prover pre-auth body exposure and request-draining shutdown need design and fault tests.
4. **Dependency and deployment verification.** Rustls advisory was patched; RSA and Vite/Vitest dev advisories remain. Public Base Sepolia observation returned403. Repository July configuration is historical, not live code/key/role evidence. Local tool versions differ from remote CI; local edits have not run on GitHub.
5. **Operations and review.** Live incident owners, escalation destinations, measured canary limits, actual alarm delivery/failure drills and full independent/external review are absent. The local review covered specified source changes and produced IR-01, which was fixed and tested; it is not external assurance.

The next single engineering task is a deterministic S4-03 fixture covering the seal→journal→snapshot and pending-transaction reconciliation boundaries. Keep the real-proof branch blocked until its automatic review/environment gate can be handled through the supported process. Do not reset state, bypass a proof verifier, reroute a blocked test through another agent, or repurpose old testnet evidence as a workaround.

Gateway custody and oracle trust remain architectural assumptions. All final summaries must distinguish local engine tests, mocked contract verifiers, real guest execution and actual cryptographic proof verification.
