# Local manifest correction

The complete crates.io archive is retained, including its source, license and
original manifest. `PROVENANCE.json` pins the archive and each original file.
Only the normalized `Cargo.toml` is changed:

- Remove `rsa?/default` from `alloc`.
- Add `rsa/default` to `rustcrypto`.

The selected `ring` backend no longer retains the unused vulnerable RSA package
in Cargo.lock due to [Cargo issue 10801](https://github.com/rust-lang/cargo/issues/10801).
Selecting `rustcrypto` still resolves RSA and enables its default features; this
patch does not conceal its advisory. It enables RSA defaults for every rustcrypto
build, including no-std consumers; this repository uses only ring with std.
No certificate parsing, signature implementation, trust policy or Rust code was
changed. `verify_provenance.py` checks all original file hashes and the exact
two-line manifest transformation. Remove this patch when the upstream manifest
no longer produces the unused RSA lock entry.

The upstream crate's bundled Cargo.lock is archival provenance, not one of the
application lockfiles; it is retained unmodified and is not used by root builds.
