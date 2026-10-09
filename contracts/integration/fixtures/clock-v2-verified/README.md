# Verified clock-v2 proof fixture

Public synthetic test data only. There are no production keys, account records,
or live user deposits here. The synthetic input uses the public test keys and
zero payer from the existing host fixture.

The real SP1 CPU prover generated the recursive witness. GitHub Actions run
37973162992 completed the last Groth16 wrapping stage with pinned upstream
SP1 6.1.0 code and circuit files, without network access inside the wrapper.
The completed proof was then cryptographically verified using the upstream
`sp1-verifier` 6.1.0 library and the independently setup-derived guest key.
A complete CPU proving backend does not need to be initialized again to verify.
`local_sdk_verified` is deliberately false; `rust_sp1_verifier_verified` records
the actual verification backend rather than relabeling it as a new SDK setup.

Run from the repository root:

```sh
python3 scripts/local-verification/verify_clock_proof.py \
  --artifact-dir contracts/integration/fixtures/clock-v2-verified \
  --output-dir /tmp/arcora-clock-proof-verification
```

The runner checks the pinned guest sources, ELF, setup key, witness, public
commitment, vendor provenance and proof shape before executing 24 real-verifier
Solidity checks, including the actual clock adapter, settlement and vault.
The source gate refuses reuse after a guest input changes. Rebuilding the guest
and generating a newly verified proof is required to update these pins.

The token is mocked and fixed synthetic addresses are installed by running the
real constructors. The zero payer is impersonated inside an owned local EVM.
These tests do not establish live deposit provenance, matching fairness, a full
HTTP/order/production lifecycle, deployability, or a completed fund migration.
