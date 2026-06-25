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

1. **Guest.** A thin `main` that reads `(initial_state, ops, manifest_hash)` from
   the zkVM input, calls `run_transition`, and commits `PublicInputs` to the
   journal. (The host seals the witness; the guest reads it inside the zkVM.)
2. **Host.** Replace `CommitmentProver::prove` with the backend's prove call
   (`sp1_sdk` / `risc0_zkvm`), returning the real receipt bytes; replace
   `verify` with the backend verifier (or generate the Solidity verifier for L1).
3. **Public inputs.** Map `PublicInputs::commitment` to the journal digest the
   on-chain verifier checks. The contract in `contracts/` consumes this.

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

The sealing in the harness (measurement-derived keystream XOR) is a **documented
stand-in** for real enclave key-release bound to the measurement (TDX/Nitro). It
models the *access boundary*, not production confidentiality. Replacing it with
real attested sealing is a backend change; the typed boundary
(`SealedWitness` + `AttestedProver` + zeroization) stays.

### Future hardening (post-v1, §10b)

- **Hybrid witness split.** Users client-side-prove their own note consume/create;
  the TEE prover proves only cross-user matching/aggregation, minimizing what the
  TEE prover sees.
- **Length leakage.** Normalize proof/execution length with fixed-size (padded)
  circuits or recursion so batch composition doesn't leak via proof size.
- **MPC / collaborative proving.** Secret-share the witness across provers so no
  single prover sees all of it (cryptographic, hardware-free, slower).
