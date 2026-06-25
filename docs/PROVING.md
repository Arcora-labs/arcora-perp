# Proving — harness today, real zkVM tomorrow (§4, §10b)

This document explains what `crates/prover` is, what it deliberately is **not**
yet, and exactly how a real zkVM backend slots in.

## The binding (stable, backend-independent)

Every batch proof commits to five public values:

```
PublicInputs = (prev_state_root, batch_manifest_hash, new_state_root,
                ordered_root, withdrawals_root)
```

`ordered_root` (Merkle root of the batch's ordered order-hash leaves) and
`withdrawals_root` (Merkle root of the withdrawals this batch authorizes) are
bound into the commitment — not left as free sequencer calldata — so the
sequencer cannot publish an arbitrary withdrawals root to drain the vault, nor a
fake ordered root to dodge inclusion challenges (security audit findings F1/F2).

`run_transition()` runs the **perp-core engine** — the same `apply_batch` used on
the hot path — over the batch's ops and returns this tuple. The L1 verifier (Faz
2) will check a proof against exactly these inputs and, on success, advance the
anchored state root from `prev` to `new`. Nothing about this tuple depends on the
proving system, so it is fixed now.

## What the harness is NOT (yet)

`CommitmentProver` is a **stand-in, not a SNARK**. Its "proof" is a
domain-separated hash of the public commitment plus a hiding commitment to the
witness. It exercises the *interface* and the *binding*; it does **not** provide
soundness — anyone can recompute it. This is intentional for Phase 0/1, where (per
§10b, "Faz timing") there is no real position privacy to protect on a testnet and
the priority is accounting soundness. Do not deploy it as a real verifier.

## Swapping in SP1 / Risc0

The guest program already exists: `perp_core` is `#![no_std]`, deterministic, and
free of clocks/RNG/IO, so it compiles to a RISC-V zkVM guest unchanged.

> **Sandbox note (attempted).** `sp1up` was run in this environment: it installs
> `cargo-prove`, but installing the succinct Rust toolchain fails because the
> sandbox's git/network proxy is scoped to this single repo and denies
> `api.github.com/repos/succinctlabs/rust/releases` (the same restriction that
> blocks `forge-std`). So the real guest **cannot be compiled here** — it builds
> in any unrestricted environment with `sp1up && cargo prove build`. That is the
> only reason the `CommitmentProver` stand-in is still in place.

1. **Guest.** A thin `main` that reads `(initial_state, ops, manifest_hash,
   ordered_root, withdrawals_root)` from the zkVM input, runs the perp-core
   transition, and commits the `PublicInputs` commitment to the journal:

   ```rust
   // zkvm/sp1-guest/src/main.rs  (built with the SP1 toolchain, not the workspace)
   #![no_main]
   sp1_zkvm::entrypoint!(main);
   use perp_core::{DefaultState, engine::BatchOp, hash::{Domain, Hasher, Keccak256}};

   fn main() {
       // Witness is sealed to the attested measurement (see §10b) and read here
       // inside the zkVM. Requires a serde/borsh witness encoding — add a
       // `serde` feature to perp-core deriving (De)Serialize on the public types.
       let mut state: DefaultState = sp1_zkvm::io::read();
       let ops: Vec<BatchOp>       = sp1_zkvm::io::read();
       let manifest_hash: [u8;32]  = sp1_zkvm::io::read();
       let ordered_root: [u8;32]   = sp1_zkvm::io::read();
       let withdrawals_root:[u8;32]= sp1_zkvm::io::read();

       let prev = state.state_root();
       state.apply_batch(&ops).expect("valid transition"); // constraints fail ⇒ no proof
       let new = state.state_root();

       // commitment == DarkPerpSettlement.publicCommitment == PublicInputs::commitment
       let commit = Keccak256::hash_words(Domain::StateRoot,
           &[prev, manifest_hash, new, ordered_root, withdrawals_root]);
       sp1_zkvm::io::commit(&commit);
   }
   ```

2. **Host.** Replace `CommitmentProver::prove` with the backend prove call:

   ```rust
   let client = sp1_sdk::ProverClient::new();
   let (pk, vk) = client.setup(GUEST_ELF);
   let mut stdin = sp1_sdk::SP1Stdin::new();
   stdin.write(&state); stdin.write(&ops); stdin.write(&manifest_hash);
   stdin.write(&ordered_root); stdin.write(&withdrawals_root);
   let proof = client.prove(&pk, stdin).groth16().run()?; // on-chain-verifiable
   ```

   Generate the Solidity verifier with `client`/`sp1-contracts` and drop it in for
   `MockZkVerifier`; its `verify(publicCommitment, proof)` then checks the real
   Groth16 proof against the journal commitment.
3. **Public inputs.** `PublicInputs::commitment` (Rust) == the guest journal
   commitment == `DarkPerpSettlement.publicCommitment` (Solidity) — already locked
   byte-for-byte by `crates/prover/tests/vectors.rs` ↔ `CrossLayer.t.sol`. So the
   on-chain verifier and the off-chain prover agree the moment the real backend is
   dropped in; no protocol change.

**Prerequisite — DONE.** `perp-core` has a `serde` feature (default off) deriving
`(De)Serialize` on the public types, so the host can serialize the witness into
`SP1Stdin` and the guest reads it back identically. It compiles in both std and the
`no_std` guest config (`--no-default-features --features serde`), and
`crates/perp-core/tests/serde_witness.rs` proves a full `State` and the batch `ops`
round-trip losslessly (state root preserved, ops replay to the same root) with the
no_std-friendly `postcard` binary format — exactly the encoding an SP1/Risc0
`io::read`/`io::commit` uses. So the only thing standing between this repo and a
real proof is running `cargo prove build` with the SP1 toolchain in an
unrestricted environment.

Per §10b, the proving order is **SP1-first → hand-optimized Noir/Plonky3** for the
hot circuits, *because* the confidential prover's enclave memory envelope forces
the hottest circuits to get tighter — not for aesthetics.

## The confidential-proving boundary (§10b) — already modelled

A ZK proof hides the witness from the **verifier**, never from the **prover**. A
bare prover farm would see every position, fill, and margin in plaintext. So:

- The witness is **sealed to the attested prover measurement** (`SealedWitness`).
- `AttestedProver::prove_sealed` opens it **only if its measurement matches**, and
  **zeroizes** the plaintext the moment the job finishes.
- A prover with the wrong measurement — e.g. a **public/outsourced GPU proving
  network (SP1/Risc0 marketplaces)** — gets `MeasurementMismatch` and cannot open
  the witness. Hence: *private batches require a self-hosted attested prover.*

The sealing in the harness (a `(measurement, nonce)`-derived keystream XOR) is a
**documented stand-in** for real enclave key-release bound to the measurement
(TDX/Nitro). It models the *access boundary*, not production confidentiality.
The keystream is bound to a **per-seal nonce** (the batch public commitment), not
the measurement alone: the measurement is constant across every batch, so a
measurement-only pad would seal every batch's witness identically and XOR-ing two
sealed witnesses would leak the XOR of two private ledgers (a two-time pad). The
nonce uniqueness requirement is exactly what a real AEAD/key-release scheme also
demands. Replacing the stand-in with real attested sealing is a backend change;
the typed boundary (`SealedWitness` + `AttestedProver` + zeroization) stays.

### Future hardening (post-v1, §10b)

- **Hybrid witness split.** Users client-side-prove their own note consume/create;
  the TEE prover proves only cross-user matching/aggregation, minimizing what the
  TEE prover sees.
- **Length leakage.** Normalize proof/execution length with fixed-size (padded)
  circuits or recursion so batch composition doesn't leak via proof size.
- **MPC / collaborative proving.** Secret-share the witness across provers so no
  single prover sees all of it (cryptographic, hardware-free, slower).
