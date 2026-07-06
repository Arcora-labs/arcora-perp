#![no_std]
extern crate alloc;

/// Wire-format version byte — the first byte of every serialized [`SealedBox`]
/// (`version ‖ epk(32) ‖ nonce(24) ‖ ct‖tag`). [`SealedBox::from_bytes`] rejects
/// any other value, so the construction (X25519 ECDH → HKDF-SHA256 with
/// `info = "arcora/sealed-box/v1"` → XChaCha20-Poly1305) can be evolved behind a
/// version bump without silently misparsing old wires. Mirrored byte-for-byte by
/// the TS client (`frontend/src/api/sealedBox.ts`).
pub const SEALED_BOX_VERSION: u8 = 0x01;

use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
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

/// Deterministic core of `seal`: the caller supplies the ephemeral secret and
/// nonce instead of drawing them from an rng. Used only for cross-language test
/// vectors; production code should use `seal`, which draws fresh randomness.
pub fn seal_with_ephemeral(
    recipient_pub: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    esk_bytes: &[u8; 32],
    nonce: &[u8; 24],
) -> SealedBox {
    let esk = StaticSecret::from(*esk_bytes);
    let epk = PublicKey::from(&esk).to_bytes();
    let shared = esk.diffie_hellman(&PublicKey::from(*recipient_pub)).to_bytes();
    let key = derive_key(&shared, &epk, recipient_pub);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ct = cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("encrypt");
    SealedBox { epk, nonce: *nonce, ct }
}

pub fn seal(
    recipient_pub: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    mut rng: impl RngCore + CryptoRng,
) -> SealedBox {
    let mut esk = [0u8; 32];
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut esk);
    rng.fill_bytes(&mut nonce);
    seal_with_ephemeral(recipient_pub, plaintext, aad, &esk, &nonce)
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
        v.push(SEALED_BOX_VERSION);
        v.extend_from_slice(&self.epk);
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ct);
        v
    }
    pub fn from_bytes(b: &[u8]) -> Option<SealedBox> {
        if b.len() < 1 + 32 + 24 + 16 || b[0] != SEALED_BOX_VERSION {
            return None;
        }
        let mut epk = [0u8; 32];
        let mut nonce = [0u8; 24];
        epk.copy_from_slice(&b[1..33]);
        nonce.copy_from_slice(&b[33..57]);
        Some(SealedBox { epk, nonce, ct: b[57..].to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_one() {
        assert_eq!(SEALED_BOX_VERSION, 0x01);
    }
}

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
