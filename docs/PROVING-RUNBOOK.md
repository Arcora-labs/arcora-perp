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
cd crates/sp1-host && cargo run --release --bin sp1-host
```
(`--bin sp1-host` is required: the crate has a second bin target, `prove`, so a bare
`cargo run` errors with "could not determine which binary to run". Run with
`SP1_SKIP_PROGRAM_BUILD` **unset** — CI's typecheck job sets it, and with it set the
guest ELF this gate executes is never built.)
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
Submit a real settlement (SEC-025-B: `settleBatch` takes NINE parameters — seven
roots including the SEC-019 `depositsRoot`, the cumulative `uint64 newDepositCount`,
and the proof):
```
settleBatch(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot,
            depositsRoot, newDepositCount, proof_bytes)
```
`publicCommitment = publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot,
withdrawalsRoot, rejectedRoot, depositsRoot)` must equal the 32-byte `public_values`
from step 4, and the SP1 gateway must accept `proof_bytes` under the pinned `vkey`. On
success the derived commitment is now enforced on-chain by real ZK.

## Notes / gotchas
- Proving latency + resources set the L1 settle cadence.
- **Slice 2 (not done):** the gateway still publishes the CUMULATIVE `withdrawalsRoot`
  over `pending_withdrawals` and aggregates multiple engine batches per L1 settle, while
  the circuit derives a PER-ENGINE-BATCH incremental root. For the on-chain
  `withdrawalsRoot` to match the proof, the gateway must switch to per-engine-batch
  settlement (Slice 2) — until then, a real proof only matches if you settle one engine
  batch at a time with its own incremental root.

## Prover service (Slice 2) — real proofs on demand

On the SP1 machine (GB10), the prover service (`crates/prover-service`, excluded from
the workspace) turns a sealed witness into a real Groth16 proof the on-chain
`SP1ZkVerifier` accepts.

### Build + run
```bash
# one-time on an arm64 host: register the amd64 emulator for the gnark (amd64-only) image
docker run --privileged --rm tonistiigi/binfmt --install amd64

cd crates/prover-service
DOCKER_DEFAULT_PLATFORM=linux/amd64 cargo run --release   # amd64 gnark under qemu (arm64 host)
# serves on 127.0.0.1:8091 by default (override with PROVER_BIND=host:port)
curl -s localhost:8091/vkey          # -> {"vkey":"0x00f4a7109bcff4e78a6f5e2a6d30ed39582f4386d58b71c025e0822fdc8c9024"}
curl -s localhost:8091/measurement   # -> {"measurement":"0xabab…"}  (SoftwareSeal stand-in, all-0xAB)
```
`vkey` is the `programVKey` the service's SP1 setup derives for the guest ELF — it must
match the deployed `SP1ZkVerifier`'s immutable `programVKey`
(`0x00f4a7109bcff4e78a6f5e2a6d30ed39582f4386d58b71c025e0822fdc8c9024` for the Slice-1
Base Sepolia deploy below). The seal root the service opens sealed witnesses against is
`PROVER_SEAL_ROOT` (env, hex; defaults to all-`0x5E` if unset) — must match whatever the
caller sealed the witness to.

### Prove a batch
A client seals the witness to the service's `/measurement` (SoftwareSeal stand-in) and
POSTs it:
`POST /prove {"sealed":"0x<hex postcard-encoded SealedWitness>"}` →
`{prev_root, manifest_hash, new_root, ordered_root, withdrawals_root, rejected_root,
commitment, proof}` (all hex-prefixed).

### Seal + POST (client side)
The service opens a witness sealed to its measurement (`0xAB…AB`, the stand-in) with the
seal root (`PROVER_SEAL_ROOT`, default `0x5E…5E`). A client builds the batch witness, seals it,
and POSTs the hex:
```rust
// (in a small client bin or extend sp1-host) — build the (state, ops, manifest) witness bytes,
// then:
let m = [0xABu8; 32];
let sealed = prover::SealedWitness::seal(
    &witness_bytes,
    &prover::SoftwareSealProvider::new([0x5Eu8; 32], m),  // must match the service's root+measurement
    m,
    nonce,
).unwrap();
let hex = format!("0x{}", hex::encode(postcard::to_allocvec(&sealed).unwrap()));
// curl -s localhost:8091/prove -H 'content-type: application/json' -d "{\"sealed\":\"$hex\"}"
```
SEC-025-B: take ONLY the `proof` bytes from the response. The service's itemised
roots are DIAGNOSTIC — the response carries no `depositsRoot` at all, and the roots
submitted on-chain come from the gateway's own LOCAL replay of the witness
(`perp_core::commitment::derive_roots`, exactly what `prove_and_prepare` in
`crates/gateway/src/prover_client.rs` does). Derive all seven roots + the post-replay
`consumed_deposit_count` locally, check the service's `commitment` equals the keccak
commitment over YOUR seven derived roots, then pair your roots with its `proof`.

(If `PROVER_SEAL_ROOT` is unset the service uses `0x5E…`; if set, the client must use the same value.)

### e2e verify on-chain (the merge gate)
Submit your seven locally derived roots, the cumulative `newDepositCount`, and the
service's proof to a fresh `DarkPerpSettlement` wired to the Slice-1 `SP1ZkVerifier`
(`0xCbdD7381766f3021C5fae2a5bBeAe5CF0Fc20bcF` on Base Sepolia), genesis = `prev_root`.
`newDepositCount` is the **cumulative** post-state `consumed_deposit_count`, not a
per-window count (a zero-deposit window over a pre-state that already consumed five
deposits submits **5**); `_requireDepositPrefix` pins `depositsRoot` to the vault's
deposit-chain tip at exactly that count, before the proof is even verified:
```bash
cast send <SETTLEMENT> \
  "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)" \
  <prev_root> <manifest_hash> <new_root> <ordered_root> <withdrawals_root> <rejected_root> \
  <deposits_root> <new_deposit_count> <proof> \
  --rpc-url https://sepolia.base.org --private-key $KEY
```
`$KEY` must be the deployed settlement's `sequencer` (`settleBatch` is `onlySequencer`).
Status 1 = the service's real proof was verified on-chain by `SP1ZkVerifier`. (Privacy:
for real batches the service must run on a self-hosted **ATTESTED** x86_64 prover — the
gnark image is amd64-only, so the arm64 GB10 is a dev/test prover, not a production
attested one; P3 adds real TDX/Nitro key-release.)
