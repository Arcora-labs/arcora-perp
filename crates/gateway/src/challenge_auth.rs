//! The enclave-signed authorization that opens an L1 inclusion challenge.
//!
//! `DarkPerpSettlement.challengeInclusion` accepts only a signature over
//! `challengeAuthDigest`, which binds the order, its receipt fields, the chain,
//! the settlement contract and the beneficiary that a slash would pay. The
//! preimage is built here rather than in perp-core so the order hash and the
//! receipt encodings stay unchanged:
//!
//! ```text
//! keccak256(abi.encode(CHALLENGE_AUTH_TAG, uint256 chainid, address settlement,
//!     bytes32 orderHash, uint64 seqNo, uint64 recvTimeMs, uint64 batchIdHint,
//!     address beneficiary))
//! ```
//!
//! Eight static ABI words (256 bytes). It shares no length with the perp-core
//! receipt digest or the enclave epoch digests.
use perp_core::hash::Digest;
use sha3::{Digest as _, Keccak256};

/// Preimage of `DarkPerpSettlement.CHALLENGE_AUTH_TAG`.
pub(crate) const CHALLENGE_AUTH_DOMAIN: &[u8] = b"arcora:l1-inclusion-challenge:v1";

/// `keccak256("arcora:l1-inclusion-challenge:v1")`.
pub(crate) fn challenge_auth_tag() -> Digest {
    Keccak256::digest(CHALLENGE_AUTH_DOMAIN).into()
}

/// Every field the settlement hashes into a challenge authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChallengeAuth {
    pub chain_id: u64,
    pub settlement: [u8; 20],
    pub order_hash: Digest,
    pub seq_no: u64,
    pub recv_time_ms: u64,
    pub batch_id_hint: u64,
    pub beneficiary: [u8; 20],
}

fn uint_word(n: u64) -> [u8; 32] {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

fn address_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0; 32];
    w[12..].copy_from_slice(a);
    w
}

impl ChallengeAuth {
    /// The exact 256-byte `abi.encode` preimage.
    pub(crate) fn preimage(&self) -> [u8; 256] {
        let words = [
            challenge_auth_tag(),
            uint_word(self.chain_id),
            address_word(&self.settlement),
            self.order_hash,
            uint_word(self.seq_no),
            uint_word(self.recv_time_ms),
            uint_word(self.batch_id_hint),
            address_word(&self.beneficiary),
        ];
        let mut out = [0; 256];
        for (slot, word) in out.as_chunks_mut::<32>().0.iter_mut().zip(words) {
            slot.copy_from_slice(&word);
        }
        out
    }

    /// `challengeAuthDigest(orderHash, seqNo, recvTimeMs, batchIdHint, beneficiary)`
    /// as the settlement at `settlement` computes it on `chain_id`.
    pub(crate) fn digest(&self) -> Digest {
        Keccak256::digest(self.preimage()).into()
    }

    /// The `r ‖ s ‖ v` signature `challengeInclusion` takes (low-s, v in {27, 28}).
    pub(crate) fn sign(&self, enclave: &sequencer::EnclaveIdentity) -> [u8; 65] {
        let (r, s, v) = enclave.sign_prehash(&self.digest());
        let mut sig = [0; 65];
        sig[..32].copy_from_slice(&r);
        sig[32..64].copy_from_slice(&s);
        sig[64] = v;
        sig
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors pinned in contracts/test/CrossLayer.t.sol, computed by the deployed
    // settlement code etched at a fixed address on chain 84532.
    const KAT_SETTLEMENT: [u8; 20] = [0x22; 20];
    const KAT_BENEFICIARY: [u8; 20] = [0x33; 20];
    const ORDER_HASH: &str = "0x0c1646898f0e7370046e707059dd7cb9eba4b66af66f67671f69101d508231c5";
    const TAG: &str = "0x69f32c88aac1254085ee4ba164b69f2f12fb02828e83d559eff228842bdcc42a";
    const AUTH_A_DIGEST: &str =
        "0xc97f5f187d95859ac2b5787fc5a2b4aaab47da927688f0b2038e0a03ff6f337d";
    const AUTH_A_SIG: &str = "0x490ce9b286399686afb9dfb81f58c2fa2622d492fb468f27682b22fc15ed81644c1c3b569abd8431ff2e339bb14d1022a5ef5d58dad371b6cfe314ad28e414821b";
    const AUTH_B_DIGEST: &str =
        "0x72e7483a96cc46922628812fa90ac8351fb95784c7883861a34836b14f882225";
    /// The sequencer fixture enclave (seed 0x07…07), as in crates/sequencer/tests/fixture.rs.
    const FIXTURE_ENCLAVE: &str = "0x4a62316623ad457f02cdc5d997ded67a383ec569";

    fn auth_a() -> ChallengeAuth {
        ChallengeAuth {
            chain_id: 84532,
            settlement: KAT_SETTLEMENT,
            order_hash: crate::parse_hex32(ORDER_HASH).unwrap(),
            seq_no: 0,
            recv_time_ms: 1000,
            batch_id_hint: 0,
            beneficiary: KAT_BENEFICIARY,
        }
    }

    #[test]
    fn challenge_auth_tag_matches_the_contract_constant() {
        assert_eq!(crate::hex32(&challenge_auth_tag()), TAG);
    }

    #[test]
    fn challenge_auth_digest_matches_the_solidity_vectors() {
        assert_eq!(crate::hex32(&auth_a().digest()), AUTH_A_DIGEST);
        // Every integer field differs from A, so a field-order slip shows.
        let b = ChallengeAuth {
            order_hash: [0x12; 32],
            seq_no: 7,
            recv_time_ms: 123_456_789,
            batch_id_hint: 3,
            ..auth_a()
        };
        assert_eq!(crate::hex32(&b.digest()), AUTH_B_DIGEST);
    }

    #[test]
    fn challenge_auth_digest_binds_chain_settlement_and_beneficiary() {
        let a = auth_a();
        for other in [
            ChallengeAuth {
                chain_id: 84533,
                ..a
            },
            ChallengeAuth {
                settlement: [0x23; 20],
                ..a
            },
            ChallengeAuth {
                beneficiary: [0x34; 20],
                ..a
            },
        ] {
            assert_ne!(other.digest(), a.digest());
        }
        assert_eq!(a.preimage().len(), 256);
    }

    #[test]
    fn fixture_enclave_signature_matches_the_solidity_vector() {
        let enclave = sequencer::EnclaveIdentity::from_seed([7; 32], 1, [0xAB; 32]);
        assert_eq!(crate::hex0x(&enclave.eth_address()), FIXTURE_ENCLAVE);
        assert_eq!(crate::hex0x(&auth_a().sign(&enclave)), AUTH_A_SIG);
    }
}
