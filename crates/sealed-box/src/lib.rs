#![no_std]
extern crate alloc;

/// Placeholder to prove the crate builds; replaced in Task 2.
pub const SEALED_BOX_VERSION: u8 = 0x01;

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_one() {
        assert_eq!(SEALED_BOX_VERSION, 0x01);
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
