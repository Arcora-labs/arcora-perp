# Privacy / Encryption Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the XOR note-encryption stand-in and add client→enclave encrypted order ingress plus a hash-chained encrypted order log, all on one production-grade `sealed-box` primitive.

**Architecture:** A new `crates/sealed-box` provides `seal`/`unseal` (X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305), byte-compatible with a `@noble` TS mirror. Three consumers use it: `note-archive` (seal notes to an owner viewing key), `gateway` order ingress (client seals to the enclave's attested epoch key), and a `gateway` order log (seal + hash-chain, head anchored in the on-chain batch manifest).

**Tech Stack:** Rust (RustCrypto: `x25519-dalek`, `hkdf`, `sha2`, `chacha20poly1305`), TypeScript (`@noble/curves`, `@noble/hashes`, `@noble/ciphers`), existing `perp-core`/`note-archive`/`gateway`/frontend.

## Global Constraints

- Encryption scheme is **X25519 → HKDF-SHA256 → XChaCha20-Poly1305** everywhere; **secp256k1 stays** for signing/identity only.
- Nonce is **24-byte random** (XChaCha20). Never a counter. Never reused.
- Raw ECDH output is **never** used as a key — always HKDF first.
- All multi-byte integers **little-endian** (matches `perp-core`).
- `SealedBox` wire = `version(0x01) ‖ epk(32) ‖ nonce(24) ‖ ct||tag`.
- Aggregate orderbook **depth stays public** — no task may hide it.
- Custody stays **server-side**; order ingress encrypts to the enclave key, not a user key.
- New `Domain` discriminants start at **24** (last existing = `SnapshotSealMac = 23`).
- Cross-language **byte-exact test vectors** are a merge gate for the crypto core.
- `sealed-box` must build **`no_std` + alloc** (shared with `note-archive`/guest paths).
- Frontend adds only pinned `@noble/*` submodule imports (currently zero crypto deps).
- Threat boundary: protects against operator/host/network; **not** a compromised TEE.

---

## File Structure

**New:**
- `crates/sealed-box/Cargo.toml` — crypto-core crate manifest.
- `crates/sealed-box/src/lib.rs` — `SealedBox`, `seal`, `unseal`, `x25519_keypair_from_ikm`, `domain_aad`.
- `crates/sealed-box/tests/vectors.rs` — reads shared JSON fixtures, asserts byte-exact.
- `tests/fixtures/sealed-box-vectors.json` — shared Rust↔TS fixtures (repo root `tests/`).
- `crates/gateway/src/enclave_epoch.rs` — enclave order-epoch keypair + rotation + signed publication.
- `crates/gateway/src/order_log.rs` — hash-chained encrypted append-only order log.
- `frontend/src/api/sealedBox.ts` — TS mirror of `seal`/`unseal`.
- `frontend/src/api/sealedBox.test.ts` — TS side of the cross-language vectors.

**Modified:**
- `crates/perp-core/src/hash.rs` — add `Domain` variants 24–29.
- `Cargo.toml` (workspace) — add `crates/sealed-box` member + shared deps.
- `crates/note-archive/Cargo.toml` + `src/lib.rs` — X25519 viewing keypair; seal/unseal replaces XOR.
- `crates/gateway/Cargo.toml` + `src/main.rs` — epoch endpoint, sealed order ingress, log wiring, manifest head.
- `frontend/src/api/realClient.ts` — fetch+verify epoch key, seal orders.
- `frontend/package.json` — `@noble/curves`, `@noble/hashes`, `@noble/ciphers`.
- `docs/ROADMAP.md` — flip the three rows to ✅ as each phase lands.

---

# Phase 1 — `sealed-box` crypto core

### Task 1: Scaffold the `sealed-box` crate

**Files:**
- Create: `crates/sealed-box/Cargo.toml`
- Create: `crates/sealed-box/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Produces: crate `sealed-box` compiling `no_std + alloc`.

- [ ] **Step 1: Add the crate manifest**

`crates/sealed-box/Cargo.toml`:
```toml
[package]
name = "sealed-box"
version = "0.0.1"
edition = "2021"

[dependencies]
x25519-dalek = { version = "2", default-features = false, features = ["static_secrets"] }
chacha20poly1305 = { version = "0.10", default-features = false, features = ["alloc"] }
hkdf = { version = "0.12", default-features = false }
sha2 = { version = "0.10", default-features = false }
rand_core = { version = "0.6", default-features = false }

[dev-dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"
rand_core = { version = "0.6", features = ["getrandom"] }

[features]
default = ["std"]
std = ["rand_core/std"]
```

- [ ] **Step 2: Minimal lib with a smoke test**

`crates/sealed-box/src/lib.rs`:
```rust
#![no_std]
extern crate alloc;

/// Placeholder to prove the crate builds; replaced in Task 2.
pub const SEALED_BOX_VERSION: u8 = 0x01;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_one() {
        assert_eq!(SEALED_BOX_VERSION, 0x01);
    }
}
```

- [ ] **Step 3: Register the crate in the workspace**

Add `"crates/sealed-box",` to the `members` array in the root `Cargo.toml`.

- [ ] **Step 4: Build + test**

Run: `cargo test -p sealed-box`
Expected: PASS (1 test), crate compiles.

- [ ] **Step 5: Commit**

```bash
git add crates/sealed-box Cargo.toml
git commit -m "feat(sealed-box): scaffold crypto-core crate"
```

---

### Task 2: Key derivation + `domain_aad`

**Files:**
- Modify: `crates/sealed-box/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub fn x25519_keypair_from_ikm(ikm: &[u8], info: &[u8]) -> ([u8;32], [u8;32])` → `(secret, public)`; secret is HKDF-derived then X25519-clamped, public = `X25519(secret, basepoint)`.
  - `pub fn domain_aad(domain: u8, extra: &[u8]) -> alloc::vec::Vec<u8>` → `[domain] ++ extra`.

- [ ] **Step 1: Write failing tests**

Append to `crates/sealed-box/src/lib.rs`:
```rust
#[cfg(test)]
mod kdf_tests {
    use super::*;
    #[test]
    fn keypair_is_deterministic() {
        let (s1, p1) = x25519_keypair_from_ikm(b"seed-ikm", b"arcora/view");
        let (s2, p2) = x25519_keypair_from_ikm(b"seed-ikm", b"arcora/view");
        assert_eq!(s1, s2);
        assert_eq!(p1, p2);
    }
    #[test]
    fn different_info_gives_different_key() {
        let (_, p1) = x25519_keypair_from_ikm(b"seed-ikm", b"arcora/view");
        let (_, p2) = x25519_keypair_from_ikm(b"seed-ikm", b"arcora/order");
        assert_ne!(p1, p2);
    }
    #[test]
    fn domain_aad_prefixes_the_byte() {
        assert_eq!(domain_aad(27, b"xy"), alloc::vec![27u8, b'x', b'y']);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p sealed-box kdf_tests`
Expected: FAIL (functions not defined).

- [ ] **Step 3: Implement**

Add to `crates/sealed-box/src/lib.rs` (above the test modules):
```rust
use alloc::vec::Vec;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Derive a deterministic X25519 keypair from input key material.
/// `ikm` is a high-entropy seed; `info` is the domain-separation context.
pub fn x25519_keypair_from_ikm(ikm: &[u8], info: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32 is a valid HKDF length");
    // StaticSecret::from clamps to a valid X25519 scalar.
    let secret = StaticSecret::from(okm);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// AAD = one domain-tag byte followed by the caller's context bytes.
pub fn domain_aad(domain: u8, extra: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + extra.len());
    v.push(domain);
    v.extend_from_slice(extra);
    v
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p sealed-box kdf_tests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/sealed-box/src/lib.rs
git commit -m "feat(sealed-box): deterministic X25519 key derivation + domain_aad"
```

---

### Task 3: `seal` / `unseal`

**Files:**
- Modify: `crates/sealed-box/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub struct SealedBox { pub epk: [u8;32], pub nonce: [u8;24], pub ct: Vec<u8> }`
  - `pub fn seal(recipient_pub: &[u8;32], plaintext: &[u8], aad: &[u8], rng: impl RngCore + CryptoRng) -> SealedBox`
  - `pub fn unseal(recipient_secret: &[u8;32], sb: &SealedBox, aad: &[u8]) -> Option<Vec<u8>>`
  - `SealedBox::to_bytes(&self) -> Vec<u8>` / `SealedBox::from_bytes(&[u8]) -> Option<SealedBox>` (wire: `0x01 ‖ epk ‖ nonce ‖ ct`).

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod seal_tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn roundtrip() {
        let (rsk, rpk) = x25519_keypair_from_ikm(b"recipient", b"ctx");
        let sb = seal(&rpk, b"hello dark", b"aad-1", OsRng);
        assert_eq!(unseal(&rsk, &sb, b"aad-1").as_deref(), Some(&b"hello dark"[..]));
    }
    #[test]
    fn wrong_key_fails() {
        let (_, rpk) = x25519_keypair_from_ikm(b"recipient", b"ctx");
        let (wrong_sk, _) = x25519_keypair_from_ikm(b"attacker", b"ctx");
        let sb = seal(&rpk, b"secret", b"aad", OsRng);
        assert_eq!(unseal(&wrong_sk, &sb, b"aad"), None);
    }
    #[test]
    fn aad_mismatch_fails() {
        let (rsk, rpk) = x25519_keypair_from_ikm(b"recipient", b"ctx");
        let sb = seal(&rpk, b"secret", b"aad-A", OsRng);
        assert_eq!(unseal(&rsk, &sb, b"aad-B"), None);
    }
    #[test]
    fn tamper_fails() {
        let (rsk, rpk) = x25519_keypair_from_ikm(b"recipient", b"ctx");
        let mut sb = seal(&rpk, b"secret", b"aad", OsRng);
        sb.ct[0] ^= 0xff;
        assert_eq!(unseal(&rsk, &sb, b"aad"), None);
    }
    #[test]
    fn wire_roundtrips() {
        let (_, rpk) = x25519_keypair_from_ikm(b"r", b"c");
        let sb = seal(&rpk, b"x", b"a", OsRng);
        let back = SealedBox::from_bytes(&sb.to_bytes()).unwrap();
        assert_eq!(back.epk, sb.epk);
        assert_eq!(back.nonce, sb.nonce);
        assert_eq!(back.ct, sb.ct);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p sealed-box seal_tests`
Expected: FAIL (`seal`/`unseal`/`SealedBox` undefined).

- [ ] **Step 3: Implement**

Add to `crates/sealed-box/src/lib.rs`:
```rust
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, RngCore};

pub struct SealedBox {
    pub epk: [u8; 32],
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

/// Derive the AEAD key from the ECDH shared secret. Salt binds ephemeral+recipient
/// public keys; info fixes the construction version. Raw ECDH is never the key.
fn derive_key(shared: &[u8; 32], epk: &[u8; 32], rpk: &[u8; 32]) -> [u8; 32] {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk);
    salt[32..].copy_from_slice(rpk);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hk.expand(b"arcora/sealed-box/v1", &mut key).expect("32 ok");
    key
}

pub fn seal(recipient_pub: &[u8; 32], plaintext: &[u8], aad: &[u8], mut rng: impl RngCore + CryptoRng) -> SealedBox {
    let esk = StaticSecret::random_from_rng(&mut rng);
    let epk = PublicKey::from(&esk).to_bytes();
    let shared = esk.diffie_hellman(&PublicKey::from(*recipient_pub)).to_bytes();
    let key = derive_key(&shared, &epk, recipient_pub);
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("encrypt");
    SealedBox { epk, nonce, ct }
}

pub fn unseal(recipient_secret: &[u8; 32], sb: &SealedBox, aad: &[u8]) -> Option<Vec<u8>> {
    let rsk = StaticSecret::from(*recipient_secret);
    let shared = rsk.diffie_hellman(&PublicKey::from(sb.epk)).to_bytes();
    let rpk = PublicKey::from(&rsk).to_bytes();
    let key = derive_key(&shared, &sb.epk, &rpk);
    let cipher = XChaCha20Poly1305::new((&key).into());
    cipher.decrypt(XNonce::from_slice(&sb.nonce), Payload { msg: &sb.ct, aad }).ok()
}

impl SealedBox {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 32 + 24 + self.ct.len());
        v.push(0x01);
        v.extend_from_slice(&self.epk);
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ct);
        v
    }
    pub fn from_bytes(b: &[u8]) -> Option<SealedBox> {
        if b.len() < 1 + 32 + 24 + 16 || b[0] != 0x01 {
            return None;
        }
        let mut epk = [0u8; 32];
        let mut nonce = [0u8; 24];
        epk.copy_from_slice(&b[1..33]);
        nonce.copy_from_slice(&b[33..57]);
        Some(SealedBox { epk, nonce, ct: b[57..].to_vec() })
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p sealed-box seal_tests`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/sealed-box/src/lib.rs
git commit -m "feat(sealed-box): seal/unseal (X25519+HKDF+XChaCha20-Poly1305) + wire format"
```

---

### Task 4: Cross-language vectors (Rust side)

**Files:**
- Create: `tests/fixtures/sealed-box-vectors.json`
- Create: `crates/sealed-box/tests/vectors.rs`
- Modify: `crates/sealed-box/src/lib.rs` (add a deterministic `seal_with_ephemeral` test hook)

**Interfaces:**
- Produces: `pub fn seal_with_ephemeral(recipient_pub: &[u8;32], plaintext: &[u8], aad: &[u8], esk_bytes: &[u8;32], nonce: &[u8;24]) -> SealedBox` (deterministic; used only for vectors).

- [ ] **Step 1: Add the deterministic hook + refactor `seal` to use it**

Replace `seal` in `crates/sealed-box/src/lib.rs` so it derives `esk`/`nonce` from the rng then calls the deterministic core:
```rust
pub fn seal_with_ephemeral(recipient_pub: &[u8; 32], plaintext: &[u8], aad: &[u8], esk_bytes: &[u8; 32], nonce: &[u8; 24]) -> SealedBox {
    let esk = StaticSecret::from(*esk_bytes);
    let epk = PublicKey::from(&esk).to_bytes();
    let shared = esk.diffie_hellman(&PublicKey::from(*recipient_pub)).to_bytes();
    let key = derive_key(&shared, &epk, recipient_pub);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ct = cipher.encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad }).expect("encrypt");
    SealedBox { epk, nonce: *nonce, ct }
}

pub fn seal(recipient_pub: &[u8; 32], plaintext: &[u8], aad: &[u8], mut rng: impl RngCore + CryptoRng) -> SealedBox {
    let mut esk = [0u8; 32];
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut esk);
    rng.fill_bytes(&mut nonce);
    seal_with_ephemeral(recipient_pub, plaintext, aad, &esk, &nonce)
}
```

- [ ] **Step 2: Write the fixture (generated once, then pinned)**

Create `tests/fixtures/sealed-box-vectors.json` with fields as lowercase hex (regenerate the `sealed` value by running the Rust vector test once with an `eprintln!`, then paste — the value below is a template; the test in Step 3 fails until you pin the real bytes):
```json
{
  "recipient_ikm": "726563697069656e74",
  "recipient_info": "637478",
  "esk": "0101010101010101010101010101010101010101010101010101010101010101",
  "nonce": "020202020202020202020202020202020202020202020202",
  "domain": 27,
  "aad_extra": "636f6d6d69746d656e74",
  "plaintext": "68656c6c6f206461726b",
  "sealed_hex": "PIN_AFTER_FIRST_RUN"
}
```

- [ ] **Step 3: Write the vector test**

`crates/sealed-box/tests/vectors.rs`:
```rust
use sealed_box::*;

#[derive(serde::Deserialize)]
struct Vec1 {
    recipient_ikm: String, recipient_info: String, esk: String, nonce: String,
    domain: u8, aad_extra: String, plaintext: String, sealed_hex: String,
}
fn h(s: &str) -> Vec<u8> { hex::decode(s).unwrap() }

#[test]
fn cross_language_vector() {
    let v: Vec1 = serde_json::from_str(include_str!("../../../tests/fixtures/sealed-box-vectors.json")).unwrap();
    let (_, rpk) = x25519_keypair_from_ikm(&h(&v.recipient_ikm), &h(&v.recipient_info));
    let aad = domain_aad(v.domain, &h(&v.aad_extra));
    let esk: [u8;32] = h(&v.esk).try_into().unwrap();
    let nonce: [u8;24] = h(&v.nonce).try_into().unwrap();
    let sb = seal_with_ephemeral(&rpk, &h(&v.plaintext), &aad, &esk, &nonce);
    let got = hex::encode(sb.to_bytes());
    if v.sealed_hex == "PIN_AFTER_FIRST_RUN" {
        eprintln!("PIN THIS into sealed-box-vectors.json: {got}");
        panic!("vector not pinned");
    }
    assert_eq!(got, v.sealed_hex);
}
```

- [ ] **Step 4: Run, pin, re-run**

Run: `cargo test -p sealed-box --test vectors -- --nocapture`
Expected: first run FAILS printing `PIN THIS into...`. Copy that hex into `sealed_hex`. Re-run → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sealed-box tests/fixtures/sealed-box-vectors.json
git commit -m "test(sealed-box): pinned cross-language vector + deterministic seal hook"
```

---

### Task 5: TS mirror + cross-language parity

**Files:**
- Modify: `frontend/package.json`
- Create: `frontend/src/api/sealedBox.ts`
- Create: `frontend/src/api/sealedBox.test.ts`

**Interfaces:**
- Produces (TS): `x25519KeypairFromIkm(ikm, info) → {secret, public}`, `domainAad(domain, extra) → Uint8Array`, `seal(recipientPub, plaintext, aad) → Uint8Array` (wire), `sealWithEphemeral(recipientPub, plaintext, aad, esk, nonce) → Uint8Array`, `unseal(recipientSecret, wire, aad) → Uint8Array | null`.

- [ ] **Step 1: Add deps**

In `frontend/package.json` `dependencies`, add pinned exact versions:
```json
"@noble/curves": "1.9.0",
"@noble/hashes": "1.8.0",
"@noble/ciphers": "1.3.0"
```
Run: `cd frontend && npm install`

- [ ] **Step 2: Write the TS mirror**

`frontend/src/api/sealedBox.ts`:
```ts
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";

export function x25519KeypairFromIkm(ikm: Uint8Array, info: Uint8Array) {
  const okm = hkdf(sha256, ikm, undefined, info, 32);
  const secret = okm; // x25519 clamps internally on scalarMultBase
  const pub = x25519.getPublicKey(secret);
  return { secret, public: pub };
}
export function domainAad(domain: number, extra: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + extra.length);
  out[0] = domain; out.set(extra, 1); return out;
}
function deriveKey(shared: Uint8Array, epk: Uint8Array, rpk: Uint8Array): Uint8Array {
  const salt = new Uint8Array(64); salt.set(epk, 0); salt.set(rpk, 32);
  return hkdf(sha256, shared, salt, new TextEncoder().encode("arcora/sealed-box/v1"), 32);
}
export function sealWithEphemeral(recipientPub: Uint8Array, pt: Uint8Array, aad: Uint8Array, esk: Uint8Array, nonce: Uint8Array): Uint8Array {
  const epk = x25519.getPublicKey(esk);
  const shared = x25519.getSharedSecret(esk, recipientPub);
  const key = deriveKey(shared, epk, recipientPub);
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(pt);
  const wire = new Uint8Array(1 + 32 + 24 + ct.length);
  wire[0] = 1; wire.set(epk, 1); wire.set(nonce, 33); wire.set(ct, 57);
  return wire;
}
export function seal(recipientPub: Uint8Array, pt: Uint8Array, aad: Uint8Array): Uint8Array {
  const esk = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  return sealWithEphemeral(recipientPub, pt, aad, esk, nonce);
}
export function unseal(recipientSecret: Uint8Array, wire: Uint8Array, aad: Uint8Array): Uint8Array | null {
  if (wire.length < 57 + 16 || wire[0] !== 1) return null;
  const epk = wire.slice(1, 33), nonce = wire.slice(33, 57), ct = wire.slice(57);
  const shared = x25519.getSharedSecret(recipientSecret, epk);
  const rpk = x25519.getPublicKey(recipientSecret);
  const key = deriveKey(shared, epk, rpk);
  try { return xchacha20poly1305(key, nonce, aad).decrypt(ct); } catch { return null; }
}
```

- [ ] **Step 3: Write the parity test against the SAME fixture**

`frontend/src/api/sealedBox.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { x25519KeypairFromIkm, domainAad, sealWithEphemeral, unseal } from "./sealedBox";
const hx = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));

describe("sealed-box cross-language parity", () => {
  const v = JSON.parse(readFileSync(new URL("../../../tests/fixtures/sealed-box-vectors.json", import.meta.url), "utf8"));
  it("produces the pinned Rust ciphertext byte-for-byte", () => {
    const { public: rpk } = x25519KeypairFromIkm(hx(v.recipient_ikm), hx(v.recipient_info));
    const aad = domainAad(v.domain, hx(v.aad_extra));
    const wire = sealWithEphemeral(rpk, hx(v.plaintext), aad, hx(v.esk), hx(v.nonce));
    expect(Buffer.from(wire).toString("hex")).toBe(v.sealed_hex);
  });
  it("unseals a Rust-sealed box", () => {
    const { secret } = x25519KeypairFromIkm(hx(v.recipient_ikm), hx(v.recipient_info));
    const aad = domainAad(v.domain, hx(v.aad_extra));
    const pt = unseal(secret, hx(v.sealed_hex), aad);
    expect(pt && Buffer.from(pt).toString("hex")).toBe(v.plaintext);
  });
});
```

- [ ] **Step 4: Run**

Run: `cd frontend && npm test -- sealedBox`
Expected: PASS (2 tests). If the ciphertext differs, the Rust and TS HKDF/AEAD inputs are misaligned — reconcile before proceeding (this test is the crypto merge gate).

- [ ] **Step 5: Commit**

```bash
git add frontend/src/api/sealedBox.ts frontend/src/api/sealedBox.test.ts frontend/package.json frontend/package-lock.json
git commit -m "feat(frontend): sealed-box TS mirror + cross-language parity test"
```

---

### Task 6: Add `Domain` variants

**Files:**
- Modify: `crates/perp-core/src/hash.rs` (after `SnapshotSealMac = 23`)

**Interfaces:**
- Produces: `Domain::{X25519ViewKey=24, X25519OrderEpoch=25, X25519LogKey=26, NoteEncryptAad=27, OrderEncryptAad=28, LogEncryptAad=29}`.

- [ ] **Step 1: Write a failing test**

Add to `crates/perp-core/src/hash.rs` tests:
```rust
#[test]
fn new_encryption_domains_are_stable() {
    assert_eq!(Domain::X25519ViewKey as u8, 24);
    assert_eq!(Domain::LogEncryptAad as u8, 29);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p perp-core new_encryption_domains_are_stable`
Expected: FAIL (variants undefined).

- [ ] **Step 3: Add the variants**

In the `Domain` enum, after `SnapshotSealMac = 23,`:
```rust
    /// X25519 note-viewing keypair derivation label.
    X25519ViewKey = 24,
    /// X25519 enclave order-ingress epoch keypair derivation label.
    X25519OrderEpoch = 25,
    /// X25519 enclave order-log keypair derivation label.
    X25519LogKey = 26,
    /// AEAD AAD domain tag for note ciphertexts.
    NoteEncryptAad = 27,
    /// AEAD AAD domain tag for order ciphertexts.
    OrderEncryptAad = 28,
    /// AEAD AAD domain tag for order-log entries.
    LogEncryptAad = 29,
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p perp-core new_encryption_domains_are_stable`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/src/hash.rs
git commit -m "feat(perp-core): add X25519/AEAD domain-separation tags (24-29)"
```

---

# Phase 2 — Real note encryption

### Task 7: X25519 viewing keypair on `Wallet`

**Files:**
- Modify: `crates/note-archive/Cargo.toml` (add `sealed-box`, `perp-core` already present)
- Modify: `crates/note-archive/src/lib.rs`

**Interfaces:**
- Consumes: `sealed_box::x25519_keypair_from_ikm`, `Domain::X25519ViewKey`.
- Produces: `Wallet::view_x25519_secret(&self) -> [u8;32]`, `Wallet::view_x25519_public(&self) -> [u8;32]`.

- [ ] **Step 1: Add `sealed-box` dep** to `crates/note-archive/Cargo.toml`:
```toml
sealed-box = { path = "../sealed-box", default-features = false }
```

- [ ] **Step 2: Write failing test**

```rust
#[test]
fn viewing_keypair_is_deterministic_and_scoped() {
    let w = Wallet::from_seed([7u8; 32]);
    assert_eq!(w.view_x25519_public(), Wallet::from_seed([7u8;32]).view_x25519_public());
    assert_ne!(w.view_x25519_public(), Wallet::from_seed([8u8;32]).view_x25519_public());
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p note-archive viewing_keypair`
Expected: FAIL (methods undefined).

- [ ] **Step 4: Implement** on `impl Wallet` (the seed is already stored/derivable; if `Wallet` does not retain the seed, derive from `spend_key`+`view_key` material — retain the seed by adding a `seed: [u8;32]` field set in `from_seed`):
```rust
    pub fn view_x25519_secret(&self) -> [u8; 32] {
        let info = [Domain::X25519ViewKey as u8];
        sealed_box::x25519_keypair_from_ikm(&self.seed, &info).0
    }
    pub fn view_x25519_public(&self) -> [u8; 32] {
        let info = [Domain::X25519ViewKey as u8];
        sealed_box::x25519_keypair_from_ikm(&self.seed, &info).1
    }
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p note-archive viewing_keypair`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/note-archive
git commit -m "feat(note-archive): per-wallet X25519 viewing keypair"
```

---

### Task 8: Seal notes to the viewing key (replace XOR)

**Files:**
- Modify: `crates/note-archive/src/lib.rs`

**Interfaces:**
- Consumes: `sealed_box::{seal, unseal, domain_aad, SealedBox}`, `Domain::NoteEncryptAad`, `Wallet::view_x25519_{secret,public}`.
- Produces: `NoteArchive::record(batch_id, note, owner_view_pub: &[u8;32])` (signature change: view **public** key now), `NoteArchive::scan(view_secret: &[u8;32]) -> Vec<RecoveredNote>` (signature change: view **secret**). `encrypt_note`, `keystream`, `LABEL_VIEW` XOR path deleted.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn sealed_note_scans_for_owner_only() {
    let w = Wallet::from_seed([1u8; 32]);
    let other = Wallet::from_seed([2u8; 32]);
    let note = w.note(0, 5_000_000, [9u8; 32]);
    let mut arch = NoteArchive::new();
    arch.record(1, &note, &w.view_x25519_public());
    assert_eq!(arch.scan(&w.view_x25519_secret()).len(), 1);
    assert_eq!(arch.scan(&other.view_x25519_secret()).len(), 0);
}
#[test]
fn archive_host_without_key_reads_nothing() {
    let w = Wallet::from_seed([3u8; 32]);
    let mut arch = NoteArchive::new();
    arch.record(1, &w.note(0, 42, [1u8;32]), &w.view_x25519_public());
    // ciphertext bytes never equal the plaintext note serialization
    let raw = &arch.notes()[0].ciphertext;
    assert!(!raw.windows(8).any(|win| win == &42i128.to_le_bytes()[..8]));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p note-archive sealed_note`
Expected: FAIL (signatures changed / `notes()` accessor).

- [ ] **Step 3: Implement** — replace `encrypt_note`/`keystream`/XOR `scan` with:
```rust
pub fn seal_note(note: &Note, owner_view_pub: &[u8; 32]) -> Vec<u8> {
    let commitment = note.commitment::<Keccak256>();
    let aad = sealed_box::domain_aad(Domain::NoteEncryptAad as u8, &commitment);
    sealed_box::seal(owner_view_pub, &serialize_note(note), &aad, rand_core::OsRng).to_bytes()
}
// in impl NoteArchive:
pub fn record(&mut self, batch_id: u64, note: &Note, owner_view_pub: &[u8; 32]) {
    let commitment = note.commitment::<Keccak256>();
    self.notes.push(ArchivedNote { batch_id, commitment, ciphertext: seal_note(note, owner_view_pub) });
}
pub fn scan(&self, view_secret: &[u8; 32]) -> Vec<RecoveredNote> {
    let mut out = Vec::new();
    for rec in &self.notes {
        let Some(sb) = sealed_box::SealedBox::from_bytes(&rec.ciphertext) else { continue };
        let aad = sealed_box::domain_aad(Domain::NoteEncryptAad as u8, &rec.commitment);
        if let Some(pt) = sealed_box::unseal(view_secret, &sb, &aad) {
            if let Some(note) = deserialize_note(&pt) {
                if note.commitment::<Keccak256>() == rec.commitment {
                    out.push(RecoveredNote { commitment: rec.commitment, amount: note.amount, asset_id: note.asset_id });
                }
            }
        }
    }
    out
}
pub fn notes(&self) -> &[ArchivedNote] { &self.notes }
```
(Keep/rename existing `serialize`/`deserialize` note helpers as `serialize_note`/`deserialize_note`.)

- [ ] **Step 4: Update `recover_balance`** to derive from `Wallet::view_x25519_secret()` instead of the keccak `view_key`. Update all callers in `crates/gateway/src/main.rs` (the `fund`/recovery paths) to pass `wallet.view_x25519_public()` to `record` and `wallet.view_x25519_secret()` to `scan`.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p note-archive && cargo test -p gateway`
Expected: PASS. Fix any caller signature breaks surfaced by the compiler.

- [ ] **Step 6: Commit**

```bash
git add crates/note-archive crates/gateway/src/main.rs
git commit -m "feat(note-archive): real sealed-box note encryption (drop XOR stand-in)"
```

---

# Phase 3 — Encrypted order ingress

### Task 9: Enclave order-epoch keypair + signed publication

**Files:**
- Create: `crates/gateway/src/enclave_epoch.rs`
- Modify: `crates/gateway/src/main.rs` (module decl, `/v1/enclave/epoch` route + handler)

**Interfaces:**
- Consumes: `sealed_box::x25519_keypair_from_ikm`, `Domain::X25519OrderEpoch`, the enclave `ENCLAVE_SEED`, the secp256k1 signing identity used for receipts.
- Produces: `EpochKey { epoch_id: u64, secret: [u8;32], public: [u8;32], not_after_ms: u64 }`; `EnclaveEpochs::current(&self) -> &EpochKey`; `EnclaveEpochs::secret_for(&self, epoch_id) -> Option<&[u8;32]>`; handler `get_v1_enclave_epoch` returning `{epochId,x25519Pub,notAfterMs,measurement,sig}`.

- [ ] **Step 1: Write failing test** in `crates/gateway/src/enclave_epoch.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn epoch_key_is_seed_scoped_and_stable() {
        let e = EnclaveEpochs::derive([5u8; 32], 1, 0, 3_600_000);
        assert_eq!(e.current().public, EnclaveEpochs::derive([5u8;32], 1, 0, 3_600_000).current().public);
        assert_ne!(e.current().public, EnclaveEpochs::derive([6u8;32], 1, 0, 3_600_000).current().public);
    }
    #[test]
    fn old_epoch_secret_retained_for_grace() {
        let mut e = EnclaveEpochs::derive([5u8;32], 1, 0, 3_600_000);
        let old = e.current().epoch_id;
        e.rotate(3_600_001, 3_600_000);
        assert!(e.secret_for(old).is_some());
        assert_ne!(e.current().epoch_id, old);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p gateway epoch_key_is_seed_scoped`
Expected: FAIL (module/types undefined).

- [ ] **Step 3: Implement** `crates/gateway/src/enclave_epoch.rs`:
```rust
use perp_core::hash::Domain;

pub struct EpochKey { pub epoch_id: u64, pub secret: [u8; 32], pub public: [u8; 32], pub not_after_ms: u64 }
pub struct EnclaveEpochs { seed: [u8; 32], cur: EpochKey, prev: Option<EpochKey> }

fn derive_epoch(seed: &[u8; 32], epoch_id: u64, now_ms: u64, ttl_ms: u64) -> EpochKey {
    let mut info = [0u8; 1 + 8];
    info[0] = Domain::X25519OrderEpoch as u8;
    info[1..].copy_from_slice(&epoch_id.to_le_bytes());
    let (secret, public) = sealed_box::x25519_keypair_from_ikm(seed, &info);
    EpochKey { epoch_id, secret, public, not_after_ms: now_ms + ttl_ms }
}
impl EnclaveEpochs {
    pub fn derive(seed: [u8; 32], epoch_id: u64, now_ms: u64, ttl_ms: u64) -> Self {
        Self { seed, cur: derive_epoch(&seed, epoch_id, now_ms, ttl_ms), prev: None }
    }
    pub fn current(&self) -> &EpochKey { &self.cur }
    pub fn secret_for(&self, epoch_id: u64) -> Option<&[u8; 32]> {
        if self.cur.epoch_id == epoch_id { Some(&self.cur.secret) }
        else { self.prev.as_ref().filter(|p| p.epoch_id == epoch_id).map(|p| &p.secret) }
    }
    pub fn rotate(&mut self, now_ms: u64, ttl_ms: u64) {
        let next_id = self.cur.epoch_id + 1;
        let next = derive_epoch(&self.seed, next_id, now_ms, ttl_ms);
        self.prev = Some(core::mem::replace(&mut self.cur, next));
    }
}
```

- [ ] **Step 4: Wire the module + route** in `crates/gateway/src/main.rs`: add `mod enclave_epoch;`, hold an `EnclaveEpochs` in `Gw` derived from `ENCLAVE_SEED` at boot, add `.route("/v1/enclave/epoch", get(get_v1_enclave_epoch))`, and a handler that signs `keccak(Domain::X25519OrderEpoch ‖ epochId ‖ x25519Pub ‖ notAfterMs)` with the existing enclave secp256k1 signer and returns the JSON in §5.1 of the spec.

- [ ] **Step 5: Run**

Run: `cargo test -p gateway epoch_ && cargo build -p gateway`
Expected: PASS + builds.

- [ ] **Step 6: Commit**

```bash
git add crates/gateway
git commit -m "feat(gateway): enclave order-epoch keypair + signed /v1/enclave/epoch"
```

---

### Task 10: Accept sealed orders in the enclave

**Files:**
- Modify: `crates/gateway/src/main.rs` (`OrderReq`, `post_v1_order`, `account_place_order`)

**Interfaces:**
- Consumes: `EnclaveEpochs::secret_for`, `sealed_box::{unseal, domain_aad, SealedBox}`, `Domain::OrderEncryptAad`.
- Produces: `OrderReq` gains `epoch_id: Option<u64>` + `sealed: Option<String>` (0x-hex wire); when present the plaintext order fields are ignored and derived from the decrypted payload. Production mode (`gw.prod`) rejects unsealed orders.

- [ ] **Step 1: Write failing test**
```rust
#[test]
fn sealed_order_decrypts_and_opens_position() {
    // build a Gw, read its current epoch pubkey, seal an order client-side with sealed_box::seal,
    // POST it, assert a position opens at the mark and depth is still served.
    // (Mirror the existing order_opens_position_and_advances_finality test, but seal the order.)
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p gateway sealed_order_decrypts`
Expected: FAIL.

- [ ] **Step 3: Implement** the decrypt branch at the top of `account_place_order`: if `req.sealed` is set, `unseal` with `epochs.secret_for(req.epoch_id?)` and AAD `domain_aad(OrderEncryptAad, epoch_id_le ‖ owner)`, `deserialize` the canonical terms, and overwrite the working order fields; else if `gw.prod` return `Err("production requires sealed order ingress")`. The `ciphertext_commit`/`order_hash` binding and caller signature check run on the decrypted terms unchanged.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p gateway sealed_order_decrypts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): decrypt sealed order ingress inside the enclave"
```

---

### Task 11: Client seals orders

**Files:**
- Modify: `frontend/src/api/realClient.ts`

**Interfaces:**
- Consumes: `sealedBox.seal`, `sealedBox.domainAad`, `GET /v1/enclave/epoch`.
- Produces: `RealDarkPerpClient` fetches + verifies the epoch key at bootstrap and seals every order before POST.

- [ ] **Step 1: Write failing test** (`frontend/src/api/realClient.test.ts` or extend existing): mock `/v1/enclave/epoch`, assert `placeOrder` POSTs `{epochId, sealed}` and never the raw `size`/`limitPrice`.

- [ ] **Step 2: Run to verify failure** — Run: `cd frontend && npm test -- realClient` → FAIL.

- [ ] **Step 3: Implement:** at `bootstrap`, GET `/v1/enclave/epoch`, verify `sig` recovers to the pinned enclave signer and `measurement` matches; cache `{epochId, pub}`. In `placeOrder`, build canonical terms bytes, `aad = domainAad(28, epochIdLE ‖ owner)`, `sealed = toHex(seal(pub, terms, aad))`, POST `{epochId, sealed}`.

- [ ] **Step 4: Run** — Run: `cd frontend && npm test -- realClient` → PASS.

- [ ] **Step 5: Commit**
```bash
git add frontend/src/api/realClient.ts frontend/src/api/realClient.test.ts
git commit -m "feat(frontend): seal orders to the attested enclave epoch key"
```

---

# Phase 4 — Encrypted order log

### Task 12: Hash-chained encrypted log

**Files:**
- Create: `crates/gateway/src/order_log.rs`
- Modify: `crates/gateway/src/main.rs` (module decl, append on ingest, fold head into manifest)

**Interfaces:**
- Consumes: `sealed_box::{seal, domain_aad}`, `Domain::LogEncryptAad`, the log X25519 pubkey (`x25519_keypair_from_ikm(ENCLAVE_SEED, [Domain::X25519LogKey])`).
- Produces: `OrderLog::append(&mut self, commitment: &Digest, canonical: &[u8]) -> Digest` (returns new head); `OrderLog::head(&self) -> Digest`.

- [ ] **Step 1: Write failing test** in `order_log.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn append_chains_and_is_tamper_evident() {
        let (_, pk) = sealed_box::x25519_keypair_from_ikm(&[9u8;32], &[perp_core::hash::Domain::X25519LogKey as u8]);
        let mut log = OrderLog::new(pk);
        let h1 = log.append(&[1u8;32], b"order-a");
        let h2 = log.append(&[2u8;32], b"order-b");
        assert_ne!(h1, h2);
        assert_eq!(log.head(), h2);
        // recomputing from entries reproduces the head; flipping a byte diverges
        assert_eq!(log.recompute_head(), h2);
    }
}
```

- [ ] **Step 2: Run to verify failure** — Run: `cargo test -p gateway append_chains` → FAIL.

- [ ] **Step 3: Implement** `OrderLog` with entries `{ commitment, entry_ct, entry_hash }`, `append` sealing `canonical` to the log pubkey (AAD `domain_aad(LogEncryptAad, seq_le)`) and chaining `entry_hash = keccak(prev ‖ commitment ‖ entry_ct)`; `head`/`recompute_head` accessors.

- [ ] **Step 4: Wire into the ingest path + manifest:** call `order_log.append(&commitment, &canonical)` for each accepted order in `account_place_order`; include `order_log.head()` in the batch manifest hash computed at seal (`Domain::BatchManifest`). Persist the log in the sealed snapshot alongside state.

- [ ] **Step 5: Run** — Run: `cargo test -p gateway order_log && cargo test -p gateway` → PASS.

- [ ] **Step 6: Commit**
```bash
git add crates/gateway/src/order_log.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): hash-chained encrypted order log anchored in the manifest"
```

---

### Task 13: Full-suite green + roadmap flip + e2e

**Files:**
- Modify: `docs/ROADMAP.md`

- [ ] **Step 1:** Run `cargo test` (workspace) + `cd frontend && npm run typecheck && npm test`. Expected: all green. Fix any fallout.
- [ ] **Step 2:** Flip the three `docs/ROADMAP.md` rows (note encryption, encrypted order ingress, encrypted order log) to ✅.
- [ ] **Step 3:** Manual e2e against a local gateway: fetch `/v1/enclave/epoch`, seal an order via the frontend, confirm it matches and depth is served, confirm a sealed note scans back with the view key.
- [ ] **Step 4: Commit**
```bash
git add docs/ROADMAP.md
git commit -m "docs(roadmap): note enc + order ingress + order log now real (✅)"
```

---

## Self-Review

**Spec coverage:** sealed-box core (Tasks 1–5) ✓ · Domain tags (6) ✓ · note encryption incl. view/spend split + host-can't-read (7–8) ✓ · epoch key + attestation-bound publication (9) ✓ · sealed ingress + prod-gate + depth-public (10–11) ✓ · encrypted hash-chained log + manifest anchor + snapshot persistence (12) ✓ · cross-language vectors (4–5) ✓ · testing (each task) ✓ · ZK verifier explicitly deferred (spec §9; not a task here) ✓.

**Placeholder scan:** Task 4 fixture `sealed_hex` is intentionally pinned at execution time (the step shows exactly how); Task 10/11 test bodies describe the mirror-an-existing-test construction with exact assertions named — acceptable because the referenced existing tests supply the harness. No `TODO`/`add error handling`/`similar to Task N`.

**Type consistency:** `seal`/`unseal`/`SealedBox`/`domain_aad`/`x25519_keypair_from_ikm` names identical across Rust (Tasks 2–3) and TS (Task 5); `record`/`scan` new signatures (view public vs secret) consistent between Task 8 definition and Task 9+ callers; `EnclaveEpochs::secret_for` used in Task 10 matches Task 9 definition; `OrderLog::{append,head}` consistent Task 12.

## Execution Handoff

See the offer below.
