# Proving Runbook — real SP1 verification (P2 Slice 1)

Run these on an **SP1-capable machine** (Linux, Docker for Groth16, ample RAM/GPU).
The coding repo ships only the on-chain adapter + host fix; proof generation and
deployment happen here.

## 0. Privacy rule (read first)
The batch witness contains plaintext positions/fills. **Do NOT use Succinct's public
Prover Network** for real batches — it would see the witness. Proving must run on the
**self-hosted, attested prover** (§10b): a public network gets `MeasurementMismatch`
and cannot open a sealed witness. A Groth16-capable **attested** VM is required (the
current `DC2es_v6` CVM may be too small — size up as an infra decision).

## 1. Install the SP1 toolchain
```bash
curl -L https://sp1up.succinct.xyz | bash
sp1up          # installs `cargo prove` + the riscv32im-succinct-zkvm-elf target
cargo prove --version
```

## 2. Build the guest (optional — verification only)
```bash
cd crates/sp1-guest && cargo prove build
```
Produces the `perp-core-guest` ELF. This step is now optional: `crates/sp1-host/build.rs`
(`sp1_build::build_program("../sp1-guest")`) auto-builds the guest whenever you `cargo run`
the host in step 3. Run this step standalone only if you want to sanity-check the guest
builds in isolation before invoking the host.

## 3. Equivalence gate (validates P1 in the real zkVM)
```bash
cd crates/sp1-host && cargo run --release
```
Asserts `native derive_roots(...).commitment == the guest's committed value`. This is
the first execution of the P1 circuit in the SP1 zkVM. Must print the equality/success
before proceeding. (If include_elf! can't find the guest ELF, run the standalone build
first — `cd crates/sp1-guest && cargo prove build` — and if it still isn't found, as a
last resort edit `crates/sp1-host/src/main.rs` to embed it directly with `include_bytes!`
of `target/elf-compilation/riscv32im-succinct-zkvm-elf/release/perp-core-guest`, the
guest's real SP1 target path.)

## 4. Get the vkey + a real Groth16 proof
In an `sp1-sdk` script (or extend `sp1-host` with a `--prove` mode on your machine):
```rust
use sp1_sdk::{include_elf, Elf, HashableKey, ProverClient, SP1Stdin};
const ELF: Elf = include_elf!("perp-core-guest");

let client = ProverClient::from_env().await;      // MUST resolve to the local/attested prover, NOT the network
let pk = client.setup(ELF).await.unwrap();
let vkey: String = pk.verifying_key().bytes32();  // <-- the bytes32 for the SP1ZkVerifier constructor
let mut stdin = SP1Stdin::new();
stdin.write_vec(witness_bytes);                    // postcard (DefaultState, Vec<BatchOp>, BatchManifest)
let proof = client.prove(&pk, stdin).groth16().await.unwrap();
let proof_bytes = proof.bytes();                   // <-- settleBatch `proof` arg
let public_values = proof.public_values.as_slice();// == the 32-byte publicCommitment
```
Record `vkey` (bytes32) and `proof_bytes`.

## 5. Deploy the on-chain verifier
- Find the Base Sepolia **SP1VerifierGateway** address in
  `github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments`.
- Deploy `SP1ZkVerifier(gateway, vkey)` (from this repo's `contracts/src/SP1ZkVerifier.sol`).

## 6. Redeploy the settlement pointing at it
`DarkPerpSettlement.verifier` is immutable, so swapping MockZkVerifier is a redeploy:
```
new DarkPerpSettlement(sequencer, enclaveSigner, SP1ZkVerifier_addr, genesisRoot,
                       livenessTimeoutBlocks, challengeWindowBlocks, challengeBond)
```
Then rewire the CollateralVault + repost the sequencer bond per the existing redeploy
flow. MockZkVerifier is retired for this deployment.

## 7. End-to-end
Submit a real settlement:
```
settleBatch(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, proof_bytes)
```
`publicCommitment = publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot,
withdrawalsRoot, rejectedRoot)` must equal the 32-byte `public_values` from step 4, and
the SP1 gateway must accept `proof_bytes` under the pinned `vkey`. On success the derived
commitment is now enforced on-chain by real ZK.

## Notes / gotchas
- Proving latency + resources set the L1 settle cadence.
- **Slice 2 (not done):** the gateway still publishes the CUMULATIVE `withdrawalsRoot`
  over `pending_withdrawals` and aggregates multiple engine batches per L1 settle, while
  the circuit derives a PER-ENGINE-BATCH incremental root. For the on-chain
  `withdrawalsRoot` to match the proof, the gateway must switch to per-engine-batch
  settlement (Slice 2) — until then, a real proof only matches if you settle one engine
  batch at a time with its own incremental root.
