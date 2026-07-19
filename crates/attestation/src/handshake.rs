//! SEC-020 mutual-attestation handshake — the pure transcript math.
//!
//! After each side verifies its peer's quote (`Attestor::verify`), both hold the
//! same transcript: the gateway's nonce, the prover's nonce, and the two pinned
//! (verify-enforced) measurements. `session_secret` folds that transcript into a
//! shared secret and `session_token` mints the short-lived bearer token the
//! prover's `/prove` gate checks. Pure functions — no I/O, no clock, no env —
//! so both binaries derive byte-identical values from the same transcript.

use crate::Digest;
use perp_core::hash::{Domain, Hasher, Keccak256};

/// The fixed session token used ONLY under `DEV_INSECURE` (non-prod): a plain,
/// clearly-named constant — deliberately NOT derived from any quote or secret —
/// so a dev session can never be mistaken for (or forged into) an attested one.
/// Production refuses `DEV_INSECURE` outright, so this value never gates a
/// production `/prove`.
pub const DEV_INSECURE_SESSION_TOKEN: &str = "dev-insecure-session-token-NEVER-production";

/// Deterministic session secret from a completed mutual-attestation transcript.
///
/// Order-bound: gateway nonce/measurement first, prover second — both sides MUST
/// call with the same orientation, so the two roles can never be swapped without
/// changing the secret. Reuses `Domain::KeyDerivation` (the seed key-derivation
/// tag, as `SoftwareSealProvider` does) — not a cross-layer-committed value.
pub fn session_secret(
    gw_nonce: &[u8; 32],
    pv_nonce: &[u8; 32],
    gw_meas: &Digest,
    pv_meas: &Digest,
) -> Digest {
    Keccak256::hash_words(
        Domain::KeyDerivation,
        &[*gw_nonce, *pv_nonce, *gw_meas, *pv_meas],
    )
}

/// Short-lived bearer token the prover checks on `/prove` (hash of the secret +
/// a validity epoch). The token reveals nothing about the secret beyond a
/// domain-separated hash, and rotating `epoch` invalidates old tokens without
/// re-running the handshake.
pub fn session_token(secret: &Digest, epoch: u64) -> String {
    let d = Keccak256::hash_words(
        Domain::KeyDerivation,
        &[*secret, perp_core::hash::word_u64(epoch)],
    );
    format!("0x{}", hex::encode(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_deterministic_and_transcript_bound() {
        let (a, b, m1, m2) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        assert_eq!(
            session_secret(&a, &b, &m1, &m2),
            session_secret(&a, &b, &m1, &m2)
        );
        assert_ne!(
            session_secret(&a, &b, &m1, &m2),
            session_secret(&b, &a, &m1, &m2)
        ); // order-bound
        assert_ne!(
            session_token(&session_secret(&a, &b, &m1, &m2), 1),
            session_token(&session_secret(&a, &b, &m1, &m2), 2)
        ); // epoch-bound
    }
}
