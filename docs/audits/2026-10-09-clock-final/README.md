# Clock integration: final real-proof verification

**PASS for the documented development verification scope. Not a production release.**

A real Groth16 proof was produced and accepted cryptographically by the official
SP1 Rust verifier and by unmodified upstream Solidity verification code. The
actual Arcora clock adapter, settlement and vault accepted the matching proof
and paid the synthetic withdrawal. No live contract or vault was deployed.

## Results

- Actual SP1 guest execution and native public output match; the recorded run
  used 6,035,092 guest cycles. Five malformed contexts failed without public output.
- Real Groth16 wrapping succeeded in GitHub Actions run 37973162992. The proof
  was produced from the actual recursive witness, not a substituted mock.
- Official `sp1-verifier` 6.1.0 accepted the 356-byte proof. Three altered-proof,
  altered-public-value and altered-program-key cases were rejected.
- The local EVM executed **24 passing tests**: 8 verifier guards, 10 real proof
  binding tests, and 6 clock/settlement/vault tests.
- Clock tests reject a missing anchor, proof tampering, a restamped registration,
  another chain and another batch. The positive path requires proof verification
  before withdrawal and refuses a second claim.
- Guest input source hashes are checked independently of artifact metadata.
  Changing a guest input invalidates the reusable verification fixture.
- The same real-proof gate is wired into A11 CI. Exact final-head CI and merge
  results are recorded in PR #31 after its checks complete.

## Evidence

`verification.json` contains the guest/key/digest pins, input hashes, compiled
contract/compiler identities and source hashes. `generation.json` records the
isolated generation run, circuit hashes and process result. `tests.json` records
every Solidity test outcome. `commands.json` records executed local commands.
The reusable public proof bundle is in
`contracts/integration/fixtures/clock-v2-verified`.

An initial local attempt to initialize the full CPU proving backend was terminated
before it returned a verification result. It is not counted as a passing check.
The final verification used the upstream verifier-only library with the already
independently derived and pinned guest key; `local_sdk_verified` remains false.
A supplemental local guest rebuild command hit its time limit; the previously
built actual ELF and all 21 pinned guest source inputs were independently checked.
No failed attempt was relabeled as successful.

## Boundaries

The proof is real, but the token and payer are synthetic. Fixed contract addresses
are created by executing the real constructors in an owned local EVM. This does
not establish live payer provenance, a full HTTP/order/prover/production lifecycle,
matching or rejection fairness, or universal correctness of all inputs.

The clock is settlement-chain time (Base L2), not an Ethereum L1-origin attestation.
Deployment timing policy, new verifier/settlement identities, coordinated rollout,
full live-like end-to-end lifecycle and any vault migration still require their
own release review. Existing on-chain verification keys do not change on merge.
Custody/privacy and emergency-exit economics remain separate work.
