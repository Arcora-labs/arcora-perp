// TypeScript mirror of crates/sealed-box — MUST stay byte-for-byte compatible
// with the Rust implementation (cross-language parity is pinned by
// tests/fixtures/sealed-box-vectors.json and enforced in sealedBox.test.ts).
//
// Scheme: X25519 ECDH → HKDF-SHA256 (salt = epk‖recipient_pub,
// info = "arcora/sealed-box/v1") → XChaCha20-Poly1305 (24-byte nonce).
// Wire format: 0x01 ‖ epk(32) ‖ nonce(24) ‖ ct||tag.
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";

/**
 * Derive a deterministic X25519 keypair from input key material.
 * Mirrors Rust `x25519_keypair_from_ikm`: HKDF-SHA256(no salt, ikm, info) → okm.
 *
 * Interop note (clamp-at-use): x25519-dalek 2.x stores the secret UNCLAMPED
 * (`StaticSecret::to_bytes()` returns the raw okm) and clamps at use; @noble's
 * `getPublicKey`/`getSharedSecret` also clamp at use. So the stored secret here
 * is the raw okm — never pre-clamp it, and always derive the public key from it
 * canonically via `x25519.getPublicKey`.
 */
export function x25519KeypairFromIkm(ikm: Uint8Array, info: Uint8Array) {
  const okm = hkdf(sha256, ikm, undefined, info, 32);
  const secret = okm; // x25519 clamps internally on scalarMultBase
  const pub = x25519.getPublicKey(secret);
  return { secret, public: pub };
}

/** AAD = one domain-tag byte followed by the caller's context bytes. */
export function domainAad(domain: number, extra: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + extra.length);
  out[0] = domain;
  out.set(extra, 1);
  return out;
}

/**
 * Derive the AEAD key from the ECDH shared secret. Salt binds ephemeral +
 * recipient public keys; info fixes the construction version. Raw ECDH output
 * is never used as the key directly.
 */
function deriveKey(shared: Uint8Array, epk: Uint8Array, rpk: Uint8Array): Uint8Array {
  const salt = new Uint8Array(64);
  salt.set(epk, 0);
  salt.set(rpk, 32);
  return hkdf(sha256, shared, salt, new TextEncoder().encode("arcora/sealed-box/v1"), 32);
}

/**
 * Deterministic core of `seal`: the caller supplies the ephemeral secret and
 * nonce. Used for cross-language test vectors; production code should use
 * `seal`, which draws fresh randomness.
 */
export function sealWithEphemeral(
  recipientPub: Uint8Array,
  pt: Uint8Array,
  aad: Uint8Array,
  esk: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  const epk = x25519.getPublicKey(esk);
  const shared = x25519.getSharedSecret(esk, recipientPub);
  const key = deriveKey(shared, epk, recipientPub);
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(pt);
  const wire = new Uint8Array(1 + 32 + 24 + ct.length);
  wire[0] = 1;
  wire.set(epk, 1);
  wire.set(nonce, 33);
  wire.set(ct, 57);
  return wire;
}

export function seal(recipientPub: Uint8Array, pt: Uint8Array, aad: Uint8Array): Uint8Array {
  const esk = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  return sealWithEphemeral(recipientPub, pt, aad, esk, nonce);
}

/**
 * Open a sealed box. Returns the plaintext, or null on ANY failure (bad
 * version byte, truncated wire, bad keys, AAD mismatch, tag mismatch) —
 * mirroring Rust `unseal`'s Option semantics.
 *
 * Interop note (fail-closed): @noble's `getSharedSecret` THROWS on a
 * low-order/all-zero shared secret, whereas Rust's `diffie_hellman` returns
 * the zero value and then fails AEAD decryption (→ None). The try/catch here
 * therefore wraps the ENTIRE body — including `getSharedSecret` and
 * `getPublicKey` — so both implementations fail closed to null on the same
 * inputs. Do not narrow it to just `decrypt`.
 *
 * The recipient public key for the HKDF salt is derived canonically FROM the
 * stored (unclamped) secret via `x25519.getPublicKey`, exactly as Rust derives
 * `PublicKey::from(&rsk)` — never taken from the caller or assumed pre-clamped.
 */
export function unseal(
  recipientSecret: Uint8Array,
  wire: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (wire.length < 57 + 16 || wire[0] !== 1) return null;
  try {
    const epk = wire.slice(1, 33);
    const nonce = wire.slice(33, 57);
    const ct = wire.slice(57);
    const shared = x25519.getSharedSecret(recipientSecret, epk);
    const rpk = x25519.getPublicKey(recipientSecret);
    const key = deriveKey(shared, epk, rpk);
    return xchacha20poly1305(key, nonce, aad).decrypt(ct);
  } catch {
    return null;
  }
}
