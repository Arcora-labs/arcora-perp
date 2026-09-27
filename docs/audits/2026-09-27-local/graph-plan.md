# Arcora local verification graph

Base: `098e4952c189f92e4293ed7d49f81222b626e406`; branch `audit/arcora-local-20260927`.
Source: user-supplied Arcora local guide, 27 task cards. Exact guide digest and dependencies are in `task-status.json`.

## Contract

Complete authorized local implementation and verification, preserve the original dirty checkout, and produce current source-bound evidence. Only criteria with actual evidence may pass. Historical audit counts are reference material, not results of this run.

Delivery is this local worktree, changes, reproducible checks, evidence and open gates. No push, PR, merge, live deployment, paid proving, external fund transaction, real disk exhaustion or physical power cut is authorized by this guide. Local test processes and fixtures are disposable; user processes and state are not.

Jev was evaluated: these tasks concern deterministic authorization, state, parsing and tests; no free-text semantic decision belongs in those paths, so no TypeSafe service is introduced.

## Nodes and transition rules

| Node | Input | Responsibility / output | Validator | Side effect | Next |
|---|---|---|---|---|---|
| B-01 | GitHub main + original checkout | Isolated source and environment identity | Git SHA/tree, CI run, original file hashes | Fetch/new worktree | B-02, S1, S3, S4-08 |
| B-02 | isolated checkout | Loopback-only test configuration | Binding tests and live listener inspection | Own test processes | Browser and socket tests |
| S1 | current auth code | Authority / socket matrices | Actual Rust assertions + socket EOF | Test-only accounts | S2/S4-07 |
| S2 | current frontend | Two-tab, migration, mutations, CSP | Browser + unit + build evidence | Frontend test code / narrow fixes | S6 where dependencies pass |
| S3 | snapshot format | Framing, historical fixtures, bounded mutation corpus | Parser assertions and state comparisons | Fixture and parser fixes | S4/S5 |
| S4 | protocol/current CI | Layer matrices, regression suites, CI gaps | Rust, Foundry, source-backed review | Narrow fixes and tests | S5 |
| S5 | toolchain + candidate | Real ELF/parity/proof identity | Actual SP1 and target verifier | Local tooling and proof only | S6 or BLOCKED |
| S6 | real proof + browser | Full local flow, crashes, RPC | Token deltas, durable state, roots | Own fixtures/processes | S7 or BLOCKED |
| S7 | all evidence | Operational runbooks and independent review | Cross-check manifest and explicit release limits | Documents | Local delivery; no release |

Each card retains its finer dependencies in `task-status.json`. PASS advances the applicable branch; assertion failure gets an evidence-based narrow repair; missing environment/authority marks only that branch BLOCKED. Partial coverage remains RUNNING/PENDING, never PASS. Each distinct defect permits an initial attempt and two targeted repair rounds; additional attempts require a documented new hypothesis.

## Parallel ownership

- Root: baseline, bind configuration in `main.rs`, CI, aggregate runs, remaining protocol/prover/operation checks and manifest.
- Recovery agent: `s1_recovery_ws_tests.rs`, `credential_session.rs`, recovery tests and recovery evidence.
- Snapshot agent: `snapshot.rs`, `account_recovery.rs`, snapshot fixtures/tests and snapshot evidence.
- Frontend agent: `frontend/` and frontend evidence.

Shared-file edits require coordination. Final combined checks follow integration. Test records include before/after file fingerprints; changes during a check limit that evidence to its captured compilation input and require affected tests to run again after integration.

## Current execution

Live status is recorded in `task-status.json`; detailed command records are in `checks/` and the owning lane's evidence directory. Main CI run 36337867266 was re-read and all four jobs succeeded, including Rust; the excluded prover job is typecheck with a stub ELF and provides no proof evidence. Local `cargo prove` is initially unavailable and will be investigated separately.
