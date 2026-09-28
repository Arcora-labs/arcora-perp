# Local LRU dependency correction

This is the complete published `sp1-prover 6.1.0` crates.io archive. Its original
manifest, lockfile, Rust sources, circuit data and verification keys are
retained. The published archive omits license files, so `LICENSE-MIT` and
`LICENSE-APACHE` are restored byte-for-byte from the exact upstream Git commit
recorded in the archive. Their URLs and hashes are recorded separately. `PROVENANCE.json` records the archive checksum and every upstream file.

Only the normalized `Cargo.toml` changes: `[dependencies.lru]` moves from
`0.12.4` to exact `=0.18.4`. No prover, circuit or verifier source is modified.
The two standalone consumers use this package through `[patch.crates-io]`.

The patched upstream LRU release addresses
[RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002.html) and
[RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253.html).
SP1's two caches call `new`, `get`, `put` and `push`; neither calls the affected
`iter_mut` or `pop` methods. This is dependency remediation, not evidence of an
exploit in this application. No advisory is ignored or suppressed.

This local manifest patch is not an upstream SP1 release. Remove it when the
selected upstream SP1 release depends on a patched LRU version. Run
`python3 vendor/sp1-prover/verify_provenance.py` from the repository root to check
the complete file set and reconstruct the original manifest byte-for-byte.

The bundled upstream `Cargo.lock` is archival evidence, not an application
lockfile and not used by the host or service build. Application locks pin the
patched LRU package and all SP1 versions remain `6.1.0`.
