# Verified clock-v2 calldata fixture

This 356-byte file is a **real Groth16 proof**, not a mock proof. It was
produced from the public synthetic SP1 witness by the pinned upstream CPU
wrapper in GitHub run `37973162992`. The wrapper output was decoded using
upstream bincode layout and the SDK calldata format; no proof bytes were invented.

SHA-256: `67d11ec454839405ebb89c0a197dd34772071edf0897a6b776eaded80b0dcb89`.

Verify in an owned local EVM:

```sh
python3 scripts/local-verification/verify_clock_fixture.py --output-dir /tmp/clock-proof-verification
```

The runner pins the proof, guest source, program vkey and public commitment,
then requires all 24 real verifier / clock-adapter / settlement / vault tests
to pass. Changed guest source cannot silently reuse the passing old proof.
This gate makes no claim about successful execution of the separate high-level
SDK wrapper utility: target-contract cryptographic verification is independent.

The clock and settlement constructors execute at fixed fixture addresses.
The token and zero-address payer are synthetic. Successful withdrawal in this
fixture is not live deposit provenance or the entire HTTP/order/production
lifecycle. No live chain was modified, and no production deployment is approved.
