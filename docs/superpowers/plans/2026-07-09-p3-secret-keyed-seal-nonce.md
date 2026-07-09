# P3 Slice A — Secret-keyed seal-witness nonce Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Key the clear seal-witness nonce with the secret `seal_root` so it stops being a plaintext-confirmation oracle, while preserving its content-derived rollback/retry safety.

**Architecture:** The gateway seals each window witness before POSTing it to the prover. The nonce is stored in the clear in `SealedWitness`; today it is `keccak256(plaintext)`, a public function anyone can match against a guessed witness. Change it to `keccak_words(Domain::SealNonce, [seal_root, keccak256(plaintext)])`. This is a gateway + perp-core change only — the prover *reads* the stored nonce (never re-derives it), so no prover-service, contract, snapshot, or test-vector change.

**Tech Stack:** Rust; `perp_core::hash::{Domain, Hasher, Keccak256}` (domain-tagged keccak); `sha3` (raw keccak for the plaintext digest); `postcard` (witness encoding).

## Global Constraints

- New nonce derivation (exact): `nonce = Keccak256::hash_words(Domain::SealNonce, &[*seal_root, keccak256(plaintext_bytes)])`.
- `Domain::SealNonce = 31` — **appended last** after the current final variant `OrderLogChain = 30`; never renumber an existing variant (existing committed hashes must be byte-unchanged).
- Preserve the content-derived properties: deterministic in `(seal_root, plaintext)`; different plaintext → different nonce; identical retry/rollback re-seal → identical nonce (no two-time pad).
- Gateway + perp-core only. **No** change to prover-service, `crates/prover` (`SealedWitness`/`open`), seal-client, contracts, the postcard snapshot schema, or `prover/src/vectors.rs` / `sequencer/src/fixture.rs`.
- Gates: `cargo test -p perp-core -p gateway` green; `cargo clippy -p perp-core -p gateway` clean.

---

### Task 1: Secret-keyed seal nonce

**Files:**
- Modify: `crates/perp-core/src/hash.rs` (add `Domain::SealNonce = 31` after `OrderLogChain = 30`, ~line 154)
- Modify: `crates/gateway/src/prover_client.rs` (extract a `seal_nonce` helper; rewire `seal_witness` ~line 129-152; update the doc comment ~line 124-138)
- Test: `crates/gateway/src/prover_client.rs` (unit tests in the existing/added `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `fn seal_nonce(seal_root: &[u8; 32], plaintext: &[u8]) -> perp_core::Digest` in `prover_client.rs` — the keyed nonce derivation, called by `seal_witness`.
- Consumes: `perp_core::hash::Hasher::hash_words(Domain, &[Digest]) -> Digest` (trait method — `Hasher` must be in scope); `Domain::SealNonce`; `sha3::Keccak256` for `keccak256(plaintext)`.

- [ ] **Step 1: Write the failing tests**

Add to `crates/gateway/src/prover_client.rs`. If a `#[cfg(test)] mod tests { use super::*; … }` already exists in the file, add these there; otherwise create one at the end of the file.

```rust
#[cfg(test)]
mod seal_nonce_tests {
    use super::seal_nonce;

    fn raw_keccak(bytes: &[u8]) -> [u8; 32] {
        use sha3::{Digest as _, Keccak256 as RawKeccak};
        RawKeccak::digest(bytes).into()
    }

    #[test]
    fn nonce_is_not_the_public_plaintext_hash() {
        // The whole point: the clear nonce must NOT equal keccak256(plaintext),
        // or an interceptor could confirm a guessed witness by matching it.
        let root = [0x5Eu8; 32];
        let pt = b"positions/fills/margins for one window";
        assert_ne!(seal_nonce(&root, pt), raw_keccak(pt));
    }

    #[test]
    fn nonce_is_deterministic_for_same_root_and_plaintext() {
        // Rollback/retry safety: an identical re-seal must reproduce the nonce.
        let root = [0x5Eu8; 32];
        let pt = b"same witness bytes";
        assert_eq!(seal_nonce(&root, pt), seal_nonce(&root, pt));
    }

    #[test]
    fn nonce_varies_with_plaintext_and_with_root() {
        let root = [0x5Eu8; 32];
        let other_root = [0x11u8; 32];
        let pt1 = b"witness A";
        let pt2 = b"witness B";
        assert_ne!(seal_nonce(&root, pt1), seal_nonce(&root, pt2), "different plaintext");
        assert_ne!(seal_nonce(&root, pt1), seal_nonce(&other_root, pt1), "different root");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p gateway seal_nonce 2>&1 | tail -20`
Expected: FAIL to compile — `cannot find function seal_nonce in this scope` (the helper does not exist yet).

- [ ] **Step 3: Add the `Domain::SealNonce` variant**

In `crates/perp-core/src/hash.rs`, immediately after the `OrderLogChain = 30,` variant (currently the last one, ~line 154), before the closing `}` of `pub enum Domain`, add:

```rust
    /// Secret-keyed seal-witness nonce: `keccak_words(SealNonce, [seal_root,
    /// keccak256(plaintext)])`. Keying the (clear) nonce with the secret seal root
    /// removes the plaintext-confirmation oracle a public `keccak256(plaintext)`
    /// nonce would expose, while staying content-derived (rollback/retry-safe). A
    /// dedicated tag so it never shares a preimage structure with the witness seal
    /// stream (`WitnessSeal`) or key derivation. Appended last so existing committed
    /// hashes are unchanged. Not a cross-layer-committed value.
    SealNonce = 31,
```

- [ ] **Step 4: Extract `seal_nonce` and rewire `seal_witness`**

In `crates/gateway/src/prover_client.rs`:

(a) Ensure the domain-tagged hasher is importable. `Keccak256` and `Digest` are already imported (`use perp_core::{Digest, EngineError, Keccak256};`). Add the `Domain` + `Hasher` imports near the top imports of the file:

```rust
use perp_core::hash::{Domain, Hasher};
```

(b) Add the helper just above `pub fn seal_witness` (replacing the reliance on an inline raw-keccak nonce):

```rust
/// The clear per-seal nonce, secret-keyed with `seal_root`:
/// `keccak_words(SealNonce, [seal_root, keccak256(plaintext)])`. Still deterministic
/// in the plaintext (identical rollback re-seal / retry reproduces it — no two-time
/// pad; different plaintext → different nonce), but no longer a public function of the
/// plaintext, so an interceptor of the sealed witness cannot confirm a guessed witness
/// by matching the clear nonce. Its strength scales with `seal_root`'s secrecy (P3
/// Slice B — attested key-release — hardens that secret).
pub(crate) fn seal_nonce(seal_root: &[u8; 32], plaintext: &[u8]) -> Digest {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let plaintext_hash: Digest = RawKeccak::digest(plaintext).into();
    Keccak256::hash_words(Domain::SealNonce, &[*seal_root, plaintext_hash])
}
```

(c) In `seal_witness`, replace the inline nonce block (currently):

```rust
    // nonce = keccak256(plaintext): different plaintext (any window / any rollback re-seal)
    // yields a different nonce, so a re-seal under the same batch_id can never reuse a
    // keystream; an identical retry yields the same nonce (identical ciphertext, no leak).
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let nonce: [u8; 32] = RawKeccak::digest(&bytes).into();
```

with:

```rust
    // Secret-keyed, content-derived nonce (see `seal_nonce`): keyed with `root` so the
    // clear nonce is not a plaintext-confirmation oracle, while identical re-seals still
    // reproduce it (rollback/retry-safe, no two-time pad).
    let nonce = seal_nonce(root, &bytes);
```

(d) Update the `seal_witness` doc comment (~line 124-128) sentence "the nonce is `keccak256` of the plaintext (content-derived; reuse-proof across rollback re-seals)" to: "the nonce is the secret-keyed `seal_nonce(root, plaintext)` (content-derived and reuse-proof across rollback re-seals, but keyed with `root` so the clear nonce can't confirm a guessed witness)".

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p gateway seal_nonce 2>&1 | tail -20`
Expected: PASS — `nonce_is_not_the_public_plaintext_hash`, `nonce_is_deterministic_for_same_root_and_plaintext`, `nonce_varies_with_plaintext_and_with_root` all green.

- [ ] **Step 6: Run the full gates**

Run: `cargo test -p perp-core -p gateway 2>&1 | tail -15`
Expected: PASS — perp-core suites green (the new enum variant is additive), gateway suites green (existing seal/prove/settle tests unaffected — the prover reads the stored nonce, so the seal contract is unchanged).

Run: `cargo clippy -p perp-core -p gateway --all-targets 2>&1 | tail -8`
Expected: no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/perp-core/src/hash.rs crates/gateway/src/prover_client.rs
git commit -m "feat(gateway): secret-key the seal-witness nonce (P3 Slice A)

nonce = keccak_words(SealNonce, [seal_root, keccak256(plaintext)]) instead of
the public keccak256(plaintext), closing the plaintext-confirmation oracle on the
clear nonce while keeping the content-derived rollback/retry safety. Adds
Domain::SealNonce = 31 (appended last). Gateway + perp-core only; the prover reads
the stored nonce, so no prover-service/contract/snapshot/vector change."
```

---

## Self-Review (author checklist — completed)

**1. Spec coverage** (against `2026-07-09-p3-secret-keyed-seal-nonce-design.md`):
- Design formula `keccak_words(SealNonce, [seal_root, keccak256(plaintext)])` → Task 1 Step 4(b). ✅
- `Domain::SealNonce` appended last (spec fixed to = 31 after `OrderLogChain = 30`) → Step 3. ✅
- Gateway-only, no prover-service/contract/snapshot/vector change → Global Constraints + Step 4 touches only the two files. ✅
- Tests: nonce ≠ keccak256(plaintext); deterministic; content/root-varying → Step 1 (three tests). The spec's optional "round-trip still opens" is covered structurally (the prover reads the stored nonce; the seal mechanism is unchanged) and by the existing gateway/prover-service suites staying green (Step 6) — an explicit cross-crate open test is omitted because `AttestedProver::open` is private (no public `SealedWitness::open`), so it would add reimplementation cost for no additional coverage. ✅

**2. Placeholder scan:** No TBD/TODO; every code step shows complete code and exact commands. ✅

**3. Type consistency:** `seal_nonce(&[u8;32], &[u8]) -> Digest` (Digest = `[u8;32]`) matches its call `seal_nonce(root, &bytes)` in `seal_witness` (`root: &[u8;32]`, `bytes: Vec<u8>`), and the value flows into `SealedWitness::seal(.., nonce)` which takes `nonce: Digest`. `Keccak256::hash_words(Domain, &[Digest]) -> Digest` matches the confirmed signature. ✅
