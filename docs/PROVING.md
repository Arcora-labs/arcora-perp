# Proving — harness today, real zkVM tomorrow (§4, §10b)

This document explains what `crates/prover` is, what it deliberately is **not**
yet, and exactly how a real zkVM backend slots in.

## The binding (stable, backend-independent)

Every batch proof commits to seven public values, hashed under `Domain::StateRoot`
(tag 7) into the single commitment the L1 verifier checks:

```
PublicInputs = (prev_state_root, batch_manifest_hash, new_state_root,
                ordered_root, withdrawals_root, rejected_root, deposits_root)
```

All seven roots are now **DERIVED** inside the circuit by
`perp_core::commitment::derive_roots` — the guest, the prover's `run_transition`,
and the SP1 host all call it, so they compute byte-identical roots. They are **not**
trusted-sequencer calldata: `withdrawals_root` is derived from the batch's burned
notes (a prover cannot invent a withdrawal without a real burn — audit F2), and
`ordered_root` / `rejected_root` by merklizing the manifest's committed order-hash
lists. So the sequencer cannot publish an arbitrary withdrawals root to drain the
vault, nor a fake ordered root to dodge inclusion challenges (security audit
findings F1/F2).

CAVEAT (Proof-v2): the ordered-vs-rejected SPLIT itself — whether the matcher's
inclusion/rejection decisions obey the matching rule — is **not** proven here; that
is Proof-v2, constrained in the interim by receipts + inclusion slashing. And this
derivation only *enforces* anything under a real verifier + vkey binding (the P2
gate); under `MockZkVerifier` it is a stand-in, not on-chain enforcement today.

`run_transition()` runs the **perp-core engine** — the same `apply_batch` used on
the hot path — over the batch's ops and returns these derived public inputs. The L1
verifier (Faz 2) will check a proof against exactly these inputs and, on success,
advance the anchored state root from `prev` to `new`. Nothing about this commitment
depends on the proving system, so it is fixed now.

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

> **DONE — the guest builds for real.** The real SP1 guest now lives at
> [`crates/sp1-guest`](../crates/sp1-guest) and **compiles `perp-core`'s engine,
> unchanged, to a `riscv32im-succinct-zkvm-elf` ELF** with `cargo prove build`. It is
> excluded from the host workspace (it targets RISC-V and depends on `sp1-zkvm`), so
> `cargo build --workspace` and CI never touch it; build it with the SP1 toolchain.
>
> Getting here in the sandbox needed one workaround: `cargo-prove`'s toolchain
> installer uses a reqwest+rustls client that ignores the proxy CA bundle, so
> `install-toolchain` fails its `api.github.com` fetch. The fix is to download the
> succinct Rust toolchain tarball with a CA-aware client (`curl`, which trusts
> `/root/.ccr/ca-bundle.crt`) and `rustup toolchain link succinct <dir>` it — after
> that `cargo prove build` works. The `CommitmentProver` stand-in remains the
> *default* host backend only because full STARK proving + `sp1-sdk` are heavy and
> not run in CI; the guest itself is now the genuine article, and the witness it
> reads is the postcard encoding locked by the `serde_witness` test.
>
> **EXECUTED — native ⇄ zkVM equivalence verified.** [`crates/sp1-host`](../crates/sp1-host)
> runs the guest in the SP1 RISC-V executor over a real witness and checks the
> committed public value against the one native `perp-core` produces for the same
> transition. They are **byte-for-byte identical**:
>
> ```text
> cycles            = 248477
> native commitment = 0xd4b958c34b6479983788d84133121bc23d4f98e49619ce4f3602552e9c4ee2f2
> zkVM   commitment = 0xd4b958c34b6479983788d84133121bc23d4f98e49619ce4f3602552e9c4ee2f2
> MATCH: native perp-core == SP1 guest
> ```
>
> So "written once, run natively AND in the zkVM" is not just compiled but
> *executed and verified equal* at the exact commitment the L1 verifier checks.
> Generating the full STARK proof (vs. executing) is the same call with `.prove()`
> instead of `.execute()` — heavier CPU, identical interface.

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
