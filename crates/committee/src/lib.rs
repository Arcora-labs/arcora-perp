//! # committee — committee-of-enclaves (Phase 5, §11)
//!
//! The single-enclave design is a defensible mainnet-beta (§11), but a single
//! enclave is a single point of confidentiality/integrity failure. The committee
//! is the **fast-follow** that removes it, at the cost of quorum round-trips that
//! tax the very latency we optimize for. Two redundancy properties are modelled
//! here:
//!
//! 1. **Threshold order encryption** ([`shamir`]): an order's symmetric key is
//!    Shamir `t`-of-`n` split across enclaves, so **no single enclave can decrypt
//!    an order alone** — confidentiality survives the compromise of up to `t-1`
//!    enclaves.
//!
//! 2. **Quorum preconfirmation** ([`QuorumCertificate`]): a MATCHED preconf is
//!    only valid with `t`-of-`n` distinct enclave signatures, so integrity (a
//!    correct preconf) survives a minority of malicious/faulty enclaves.
//!
//! This is **redundancy**, not a substitute for protocol completeness (§11
//! taxonomy): the order log, forced exit, oracle transcript, and note archive are
//! required in *every* version regardless of enclave count.

pub mod shamir;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use perp_core::hash::Digest;
use sha3::{Digest as _, Keccak256 as RawKeccak};

pub use shamir::{combine, split, Share};

/// Ethereum-style address of a secp256k1 key (matches L1 ecrecover).
pub fn eth_address(vk: &VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false);
    let hash = RawKeccak::digest(&point.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&hash[12..]);
    a
}

/// One enclave's signature over a digest (recoverable secp256k1).
#[derive(Clone, Copy, Debug)]
pub struct EnclaveSig {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl EnclaveSig {
    pub fn sign(key: &SigningKey, digest: &Digest) -> Self {
        let (sig, recid) = key.sign_prehash_recoverable(digest).expect("sign");
        let b = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&b[..32]);
        s.copy_from_slice(&b[32..]);
        Self {
            r,
            s,
            v: 27 + recid.to_byte(),
        }
    }

    /// Recover the signer's address, or `None` if malformed.
    pub fn recover(&self, digest: &Digest) -> Option<[u8; 20]> {
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&self.r);
        rs[32..].copy_from_slice(&self.s);
        let sig = Signature::from_slice(&rs).ok()?;
        let recid = self.v.checked_sub(27).and_then(RecoveryId::from_byte)?;
        let vk = VerifyingKey::recover_from_prehash(digest, &sig, recid).ok()?;
        Some(eth_address(&vk))
    }
}

/// The committee: the set of enclave addresses and the quorum threshold.
#[derive(Clone, Debug)]
pub struct Committee {
    members: Vec<[u8; 20]>,
    threshold: usize,
}

impl Committee {
    /// `threshold`-of-`members.len()` quorum. Panics if threshold is out of range.
    pub fn new(members: Vec<[u8; 20]>, threshold: usize) -> Self {
        assert!(
            threshold >= 1 && threshold <= members.len(),
            "bad threshold"
        );
        Self { members, threshold }
    }

    pub fn size(&self) -> usize {
        self.members.len()
    }
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn is_member(&self, addr: &[u8; 20]) -> bool {
        self.members.contains(addr)
    }
}

/// A quorum preconfirmation certificate over a digest (e.g. a fill preconf).
#[derive(Clone, Debug, Default)]
pub struct QuorumCertificate {
    pub digest: Digest,
    pub sigs: Vec<EnclaveSig>,
}

impl QuorumCertificate {
    pub fn new(digest: Digest) -> Self {
        Self {
            digest,
            sigs: Vec::new(),
        }
    }

    pub fn add(&mut self, sig: EnclaveSig) {
        self.sigs.push(sig);
    }

    /// Valid iff at least `threshold` **distinct committee members** signed the
    /// digest. Non-member signatures and duplicate signers are ignored.
    pub fn verify(&self, committee: &Committee) -> bool {
        let mut signers: Vec<[u8; 20]> = Vec::new();
        for sig in &self.sigs {
            if let Some(addr) = sig.recover(&self.digest) {
                if committee.is_member(&addr) && !signers.contains(&addr) {
                    signers.push(addr);
                }
            }
        }
        signers.len() >= committee.threshold
    }

    /// How many distinct valid members have signed.
    pub fn weight(&self, committee: &Committee) -> usize {
        let mut signers: Vec<[u8; 20]> = Vec::new();
        for sig in &self.sigs {
            if let Some(addr) = sig.recover(&self.digest) {
                if committee.is_member(&addr) && !signers.contains(&addr) {
                    signers.push(addr);
                }
            }
        }
        signers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        let mut seed = [0u8; 32];
        seed[31] = n;
        SigningKey::from_bytes((&seed).into()).unwrap()
    }

    fn committee_of(n: u8, t: usize) -> (Committee, Vec<SigningKey>) {
        let keys: Vec<SigningKey> = (1..=n).map(key).collect();
        let members = keys
            .iter()
            .map(|k| eth_address(k.verifying_key()))
            .collect();
        (Committee::new(members, t), keys)
    }

    #[test]
    fn quorum_reached_with_threshold_signers() {
        let (committee, keys) = committee_of(5, 3);
        let digest = [0x42u8; 32];
        let mut qc = QuorumCertificate::new(digest);
        for k in keys.iter().take(3) {
            qc.add(EnclaveSig::sign(k, &digest));
        }
        assert!(qc.verify(&committee), "3-of-5 reaches quorum");
        assert_eq!(qc.weight(&committee), 3);
    }

    #[test]
    fn below_threshold_fails() {
        let (committee, keys) = committee_of(5, 3);
        let digest = [0x07u8; 32];
        let mut qc = QuorumCertificate::new(digest);
        for k in keys.iter().take(2) {
            qc.add(EnclaveSig::sign(k, &digest));
        }
        assert!(!qc.verify(&committee), "2-of-5 is short of quorum");
    }

    #[test]
    fn duplicate_signer_counts_once() {
        let (committee, keys) = committee_of(5, 3);
        let digest = [0x09u8; 32];
        let mut qc = QuorumCertificate::new(digest);
        // same enclave signs three times → weight 1, not 3
        for _ in 0..3 {
            qc.add(EnclaveSig::sign(&keys[0], &digest));
        }
        assert_eq!(qc.weight(&committee), 1);
        assert!(!qc.verify(&committee));
    }

    #[test]
    fn non_member_signature_ignored() {
        let (committee, _) = committee_of(3, 2);
        let outsider = key(99);
        let digest = [0x11u8; 32];
        let mut qc = QuorumCertificate::new(digest);
        qc.add(EnclaveSig::sign(&outsider, &digest));
        assert_eq!(qc.weight(&committee), 0, "outsider doesn't count");
    }

    #[test]
    fn wrong_digest_signature_does_not_count() {
        let (committee, keys) = committee_of(3, 2);
        let digest = [0x22u8; 32];
        let other = [0x33u8; 32];
        let mut qc = QuorumCertificate::new(digest);
        // member signs a DIFFERENT digest → recovers to a different/again wrong addr
        qc.add(EnclaveSig::sign(&keys[0], &other));
        qc.add(EnclaveSig::sign(&keys[1], &digest));
        assert_eq!(
            qc.weight(&committee),
            1,
            "only the correct-digest sig counts"
        );
    }
}
