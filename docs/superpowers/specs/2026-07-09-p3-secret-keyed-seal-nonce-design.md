# P3 Slice A — Secret-keyed seal-witness nonce (design)

**Date:** 2026-07-09
**Status:** design, ready for plan
**Scope:** gateway-only cryptographic hardening; no contract, prover-service, or snapshot change.

## Context

The gateway seals each per-window witness `(pre_state, ops, manifest)` before POSTing it to the
prover (`crates/gateway/src/prover_client.rs::seal_witness`). Sealing is encrypt-then-MAC
(`crates/prover/src/lib.rs::SealedWitness`): a secret-keyed keystream hides the plaintext and a
keyed tag authenticates it. The seal key is `keccak_words(KeyDerivation, [seal_root, measurement,
nonce])` — it needs the secret `seal_root`, so an interceptor cannot decrypt or forge.

The **nonce** is stored in the clear inside the `SealedWitness` (it "carries no secret" so the
authorized prover can reproduce the keystream). It is currently derived as
`nonce = keccak256(plaintext)` (prover_client.rs ~139-140). This was chosen (slice 3b-3) to be
*content-derived*: identical plaintext (an identical rollback re-seal / retry) yields an identical
nonce — so a re-seal under the same `batch_id` can never reuse a keystream on *different* content
(a two-time-pad leak), while an identical retry yields identical ciphertext (no new information).

## Problem

Because `nonce = keccak256(plaintext)` is a **public** function of the plaintext, the clear nonce is
a **plaintext-confirmation oracle**. The seal's confidentiality (ciphertext, tag) rests on the secret
`seal_root`, so an interceptor of a `SealedWitness` cannot decrypt it — but they *can* confirm a
**guessed** witness: compute `keccak256(guess)` and match it against the clear nonce. A perp witness
(a window's positions, fills, margins) has low entropy for small/known accounts, so this confirmation
oracle is a real privacy leak. It is the last plaintext-confirmation path in the seal (the key,
keystream, and MAC all require the secret `seal_root`; only the nonce does not).

## Design

Key the nonce with the secret `seal_root` so it can no longer be computed — or matched — without it:

```
nonce = keccak_words(Domain::SealNonce, [ seal_root, keccak256(plaintext) ])
```

- **Closes the confirmation oracle.** An interceptor without `seal_root` cannot compute the nonce for
  a guessed plaintext, so cannot confirm a guess. (The security scales with `seal_root`'s secrecy,
  which the current stub keeps in code/env; **P3 Slice B — attested key-release — hardens that secret.
  This slice is the correct *structure* for when the secret becomes real, and is strictly better than
  a fully-public nonce even under the stub.**)
- **Preserves the content-derived properties** slice 3b-3 relies on: still deterministic in the
  plaintext (given a fixed `seal_root`), so identical retry/rollback re-seal → identical nonce (no
  two-time pad, no new leak), and different plaintext → different nonce.
- **Domain-separated.** A new `Domain::SealNonce` keeps this preimage disjoint from every other
  keccak use (the codebase's one-domain-one-purpose discipline). `keccak256(plaintext)` first reduces
  the variable-length plaintext to one 32-byte word so it fits `hash_words`'s word array.

### Why the nonce alone changes (nothing else)

The nonce is **produced only by the sealer (the gateway)** and stored in the `SealedWitness`. The
prover **reads** `self.nonce` from the struct to derive the key/keystream/MAC on open — it never
re-derives or validates the nonce against the plaintext (`SealedWitness::open`, prover-service). So:

- **No prover-service change**, no `SealedWitness::open` change, no seal-client change (seal-client
  already uses a fixed test nonce `[0x11;32]`).
- **No contract change** (the nonce is off-chain, prover-only) and **no snapshot/migration** (the
  `SealedWitness` is transient — sealed fresh per window, POSTed, never persisted). The postcard
  snapshot schema is untouched.
- **No locked test-vector change** (the seal nonce is not baked into `prover/src/vectors.rs` or
  `sequencer/src/fixture.rs`).

## Files

- `crates/perp-core/src/hash.rs` — add `Domain::SealNonce = 31` (appended last, after the current
  final variant `OrderLogChain = 30`, so no existing committed hash is renumbered), with a one-line
  doc noting it's a non-cross-layer-committed off-chain seal value (like `WitnessSeal`/
  `WitnessSealMac`).
- `crates/gateway/src/prover_client.rs` — in `seal_witness(w, seal_root, measurement)`, replace
  `let nonce = keccak256(bytes)` with `plaintext_hash = keccak256(bytes)` then
  `nonce = Keccak256::hash_words(Domain::SealNonce, &[*seal_root, plaintext_hash])`
  (`Keccak256` and `seal_root` are already in scope). Update the `nonce = keccak256(plaintext)` doc
  comment (~126-138) to describe the keyed derivation and the confirmation-oracle it closes.

## Testing

A unit test in `crates/gateway/src/prover_client.rs` (or its test module) that, for a sample
`seal_root` and plaintext bytes:

1. **Closes the oracle:** the produced nonce `!= keccak256(plaintext)` (the old public value).
2. **Deterministic:** same `(seal_root, plaintext)` → same nonce (rollback/retry-safe).
3. **Content-varying:** different plaintext (same root) → different nonce; different root (same
   plaintext) → different nonce.
4. **Round-trip intact:** a witness sealed via `seal_witness` (new keyed nonce) still opens correctly
   through the prover's `SoftwareSealProvider` for the matching measurement (the prover reads the
   stored nonce), and fails to open under a wrong measurement — i.e. the seal contract is unchanged.

Gates: `cargo test -p perp-core -p gateway` green, `cargo clippy -p perp-core -p gateway` clean.
No live redeploy is required for correctness; the running gateway adopts it on its next rebuild.

## Out of scope (P3 Slice B, later cycle)

The **real attested prover** — replacing the `0xAB` stub measurement + `SoftwareSealProvider` with a
real TDX-attested measurement and attestation-gated key-release on x86_64 TDX hardware (gnark is
amd64-only; GB10 is arm64 and cannot do real TDX). That hinges on a hardware decision (co-locate the
prover on the CVM's TDX vs a separate x86_64 TDX box) and earns its own spec.
