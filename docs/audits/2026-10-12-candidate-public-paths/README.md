# Public JSON path checks — local evidence, 12 October 2026

Code `bcdb52d24ce4ba363d566a0f398f4bff84186d46` on merged #57 base `788d46fe793180b73aff2cb33eaf79c744b091ec` refuses prohibited path components,
symlink files and ancestor directories before public JSON I/O. Relative paths
are qualified against the physical current directory without resolving caller
symlinks. Both CLIs preflight all supplied paths and existing output before JSON
reads, compiler/build or RPC construction. Exclusive output creation rechecks
the path. These cooperative checks are not an atomic hostile-filesystem defense.

The code commit contains four Python files and two guides. Old 47 test bodies
are preserved; 25 identity + 31 observer tests include nine new regressions.
Schemas, configured runtime/build/program expectations, Rust and contract code,
reviewed21/candidate9/AUX2 pins and root Cargo files remain unchanged.

| Actual local check | Result |
| --- | --- |
| Accepted before-fix full suite | 55 tests; 30 negative subcase failures; old47 and both new regular CLI positives pass |
| Separate before-fix relative-cwd case | 1 test; 2 negative subcase failures, regular public relative-path positive passes |
| Final identity + observer | 56 PASS / 0 FAIL / 0 SKIP |
| Neighbor tools | 125 PASS / 1 optional legacy Anvil SKIP / 0 FAIL |
| Owned candidate Anvil | 1 PASS, seven real compiled roles, three explicit mocks, 12 BLOCKED refusals |
| Actual gateway build | cargo +1.99.0 check --locked -p gateway --bin gateway PASS; no new full local gateway test claim |

The first `regression-before` draft is **not accepted before-fix evidence**:
a new positive test used a MagicMock in place of a class and failed isinstance.
Its raw output is retained. `regression-before-valid` uses the repaired positive
harness; `relative-before` then adds the separate relative-cwd regression.
The final source map is 375 files / `1e3c1af3f823ca0ed2d74b277b98f11c28140a94c776e2e7ee19bcdfc7715345`. All four final command receipts
bind the same before/after map; each historical failure retains its own map.

Read [test preservation](test-addition-preservation-final.json),
[final source review](review/final-source-qa-v2.json),
[preservation](preservation-final.json) and [artifact ledger](artifact-ledger.json).
Check/raw-output receipts are under `checks/`. `base-main-refresh/` is only #57's
historical push evidence (three workflows / fourteen jobs SUCCESS), not this
code's publication CI. Publication-head CI and normal merge are recorded later.

The baseline is 3045 tracked files. The eight allowed existing paths include
the six code files plus .gitattributes and ACTIVE_WORK metadata. Original three
dirty worktrees and their 82 public dirty-file bodies/status/staged diffs, and
#57's delivered 247 files/reports/pointer, are preserved by the local audit.
Copied helper scripts document provenance; execute originals in the ignored
validation directory rather than relocating them as standalone commands.

No real secret was opened, no public target RPC or feed discovery was called,
no gateway/prover service was started, and no
new proof, candidate backend, attestation/key release, transaction, custody or
independent approval was obtained. Actual approved target/policy/service/key
inputs are missing. Live-feed discovery remains deferred; production HOLD.
