# Local real SP1 target verification

The runner compiles the unmodified pinned SP1 v6.1.0 Groth16 verifier and official
gateway with Solidity 0.8.20, then deploys their creation bytecode into Arcora's
Solidity 0.8.24 Foundry test EVM. It uses no RPC, fork, broadcast or mock verifier.
Vendored source and license hashes are checked before compilation. The runner
pins the reviewed provenance manifest's digest, so rewriting source files and
their hash entries without a separate reviewed pin update is rejected.
The on-disk vendor inventory must exactly match the reviewed source/license set
and its three local metadata/configuration files; extra source files and all
vendor symlinks are rejected.

From the repository root, with Python 3.9+ and Foundry available:

```sh
python3 scripts/local-verification/verify_real_proof.py \
  --guards-only --output-dir /tmp/arcora-real-verifier-guards-new

python3 scripts/local-verification/verify_real_proof.py \
  --artifact-dir /path/to/completed-ordinary-groth16-proof \
  --output-dir /tmp/arcora-real-proof-verification-new
```

Both output directories must be new. The proof directory must be a successful
`sp1-host` `prove --output-dir` run: witness, ELF, program key, proof, 32-byte public
commitment, SDK proof JSON, and their completion manifest. Missing artifacts,
hash mismatches, a mock or wrong-version payload, missing SDK verification, failed
tests, and skipped tests fail the runner. There is no fallback fixture.

The runner also pins the current Arcora guest ELF SHA256 and program key from
`docs/audits/2026-09-28-post-merge/release-manifest.json`; the ELF has a separate
clean-rebuild record in that directory's `elf-reproducibility.json`. A different
ELF or key is rejected even if an input manifest supplies matching replacement
hashes. A guest upgrade requires a reviewed rebuild, fresh setup-derived key,
updated release records, and an explicit code review of both runner pins. There
is no command-line identity override.

The eight guard tests verify pinned circuit identity, routing and malformed-proof
rejection. **Their PASS does not establish Arcora proof generation or acceptance.**
The ten additional tests require the actual application proof and cover direct
verifier, gateway and adapter acceptance, wrong program key, wrong commitment,
changed or truncated proof, wrong selector, frozen route and missing route.

Default `forge test` does not select this integration directory. The runner selects
the explicit `real_proof` profile and records every required test result, compiler
version, creation-bytecode hash, source hash, and input artifact hash in a fresh
`verification.json`. Running the proof profile without artifact environment
variables fails; it never silently skips the positive tests.

These tests concern ordinary local proof acceptance. They do not execute A06,
settle real funds, prove a full token lifecycle, or authorize production deployment.
