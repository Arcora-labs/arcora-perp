# Final dependency check

The final installed frontend dependencies were audited with `pnpm audit --json`
in this verification checkout. Exit code: **0**. Findings: **0** across all
severities, down from the earlier **7** (5 moderate, 1 high, 1 critical) recorded
in `frontend-audit.json`. Raw output is in `dependencies-final.log`; exact command,
counts, manifest/lockfile hashes and installed versions are in
`dependencies-final.json`.

The final manifest pins and actual installed packages agree exactly:

| Package | Exact version |
| --- | --- |
| Vite | 6.4.3 |
| Vitest | 4.1.11 |
| `@types/node` | 22.20.4 |

The audit did not change `frontend/package.json` or `frontend/pnpm-lock.yaml`.
This check reports advisory database findings; it is not a complete application
security assessment.

Rust remains unresolved: the existing `cargo-audit.json` reports **rsa 0.9.10**
affected by **RUSTSEC-2023-0071** (Marvin timing side-channel), with an empty
patched-version list. No suppression or blanket dependency downgrade was added.
That report also retains the `atomic-polyfill` unmaintained and `spin 0.9.8`
yanked warnings. Cargo audit was not rerun in this final frontend-only check.

The original `<repo>` checkout still matches the
recorded baseline: identical porcelain status and all **19** recorded file
SHA-256 hashes. `original-worktree-preservation.json` records this comparison.
The baseline did not hash the contents of collapsed untracked directories or
record HEAD, so this claim is limited to the evidence originally captured.
