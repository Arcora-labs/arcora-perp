//! SEC-020 mutual-attestation handshake — the pure transcript math.
//!
//! Phase-2 (C3): each side draws a fresh ephemeral x25519 keypair per handshake
//! and binds its public key into its own attested evidence (the `challenge` the
//! `Attestor` verifies). The session secret folds the x25519 ECDH `shared` point
//! together with the two verified measurements and the two ephemeral pubkeys, so
//! it is NOT reconstructible from the public `/attest` transcript alone — an
//! attacker without an ephemeral private key cannot derive it. `session_token`
//! binds a `not_after` expiry (C5). Pure functions — no I/O, no clock, no env —
//! so both binaries derive byte-identical values from the same transcript.

use crate::{AttestError, Digest};
use perp_core::hash::{word_u64, Domain, Hasher, Keccak256};
use x25519_dalek::{PublicKey, StaticSecret};

/// The fixed session token used ONLY under `DEV_INSECURE` (non-prod): a plain,
/// clearly-named constant — deliberately NOT derived from any quote or secret —
/// so a dev session can never be mistaken for (or forged into) an attested one.
/// Production refuses `DEV_INSECURE` outright, so this value never gates a
/// production `/prove`.
pub const DEV_INSECURE_SESSION_TOKEN: &str = "dev-insecure-session-token-NEVER-production";

/// A fresh ephemeral x25519 keypair from caller-supplied IKM (OS-CSPRNG bytes at
/// the call site). Deterministic in the IKM so the handshake math is unit-testable;
/// `StaticSecret::from` clamps to a valid scalar (mirrors `sealed-box`). Returns
/// the secret + the 32-byte public key (the value bound as the attestation challenge).
pub fn ephemeral_keypair(ikm: &[u8; 32]) -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::from(*ikm);
    let public = PublicKey::from(&secret).to_bytes();
    (secret, public)
}

/// The x25519 ECDH shared point between our ephemeral secret and the peer's
/// ephemeral public key. Symmetric: both sides compute the identical value.
///
/// Reject non-contributory peers before exposing any shared bytes. Attestation
/// binding a peer key does not make that key contributory: low-order points
/// force a public all-zero result (RFC 7748 sections 6/7). Use dalek's
/// constant-time check, including for non-canonical encodings and aliases.
pub fn dh_shared(my_secret: &StaticSecret, peer_pub: &[u8; 32]) -> Result<[u8; 32], AttestError> {
    let shared = my_secret.diffie_hellman(&PublicKey::from(*peer_pub));
    if !shared.was_contributory() {
        return Err(AttestError::NonContributoryKey);
    }
    Ok(shared.to_bytes())
}

/// Refuse to mint session material for a transcript that has already expired.
/// Check immediately before derivation, after potentially slow I/O/verification.
/// `not_after_ms` is inclusive, matching the prover's `/prove` admission gate.
/// The clock is supplied by the caller; transcript/token encoding is unchanged.
pub fn validate_session_expiry(not_after_ms: u64, now_ms: u64) -> Result<(), AttestError> {
    if now_ms > not_after_ms {
        return Err(AttestError::SessionExpired {
            not_after_ms,
            now_ms,
        });
    }
    Ok(())
}

/// Deterministic session secret from a completed DH mutual-attestation transcript.
///
/// Folds the ECDH `shared` point with both verified measurements and both
/// ephemeral pubkeys. Order-bound: gateway fields first, prover second — both
/// sides MUST call with the same orientation. Reuses `Domain::KeyDerivation` (as
/// `SoftwareSealProvider` does). Because `shared` requires an ephemeral private
/// key, this secret is NOT derivable from the public transcript (C3).
pub fn session_secret(
    shared: &[u8; 32],
    gw_meas: &Digest,
    pv_meas: &Digest,
    gw_ephpub: &[u8; 32],
    pv_ephpub: &[u8; 32],
) -> Digest {
    Keccak256::hash_words(
        Domain::KeyDerivation,
        &[*shared, *gw_meas, *pv_meas, *gw_ephpub, *pv_ephpub],
    )
}

/// Short-lived bearer token the prover checks on `/prove` (hash of the secret + a
/// `not_after` expiry in Unix ms). Rotating/expiring `not_after` invalidates old
/// tokens; the prover's gate rejects a presented token past its `not_after` (C5).
pub fn session_token(secret: &Digest, not_after_ms: u64) -> String {
    let d = Keccak256::hash_words(Domain::KeyDerivation, &[*secret, word_u64(not_after_ms)]);
    format!("0x{}", hex::encode(d))
}

/// Derive the session secret AND the /prove token from a completed DH-handshake
/// transcript, in ONE place — the single source of truth for the convergence
/// property. The gateway, the prover, and the orchestration test all call this
/// with (shared, gateway-measurement, prover-measurement, gw_ephpub, pv_ephpub,
/// not_after) — gateway fields first — so all three fold the identical tuple and
/// mint the identical (secret, token). Orientation cannot drift between them.
pub fn derive_session(
    shared: &[u8; 32],
    gw_meas: &Digest,
    pv_meas: &Digest,
    gw_ephpub: &[u8; 32],
    pv_ephpub: &[u8; 32],
    not_after_ms: u64,
) -> (Digest, String) {
    let secret = session_secret(shared, gw_meas, pv_meas, gw_ephpub, pv_ephpub);
    let token = session_token(&secret, not_after_ms);
    (secret, token)
}

/// Constant-time byte equality for the bearer-token compare (prover `/prove`
/// gate, C5). Length is not secret (the token is fixed-length hex), so a length
/// mismatch short-circuits; equal-length inputs are compared in constant time.
/// Hand-rolled because `prover-service` is a standalone workspace without `subtle`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinct IKM per party — the ephemeral keys the handshake would draw fresh.
    const GW_IKM: [u8; 32] = [0x11; 32];
    const PV_IKM: [u8; 32] = [0x22; 32];

    #[test]
    fn dh_agrees_from_both_directions() {
        let (gw_sk, gw_pk) = ephemeral_keypair(&GW_IKM);
        let (pv_sk, pv_pk) = ephemeral_keypair(&PV_IKM);
        // Each side computes ECDH with its own secret + the peer's public.
        let shared_gw = dh_shared(&gw_sk, &pv_pk).unwrap();
        let shared_pv = dh_shared(&pv_sk, &gw_pk).unwrap();
        assert_eq!(shared_gw, shared_pv, "x25519 ECDH is symmetric");
        assert_ne!(shared_gw, [0u8; 32], "a real shared point, not zero");
    }

    #[test]
    fn secret_is_deterministic_transcript_and_shared_bound() {
        let (gw_sk, gw_pk) = ephemeral_keypair(&GW_IKM);
        let (pv_sk, pv_pk) = ephemeral_keypair(&PV_IKM);
        let shared = dh_shared(&gw_sk, &pv_pk).unwrap();
        let (m1, m2) = ([3u8; 32], [4u8; 32]);
        let s = session_secret(&shared, &m1, &m2, &gw_pk, &pv_pk);
        // Deterministic.
        assert_eq!(s, session_secret(&shared, &m1, &m2, &gw_pk, &pv_pk));
        // Both sides derive the identical secret (pv computes the same shared).
        let shared_pv = dh_shared(&pv_sk, &gw_pk).unwrap();
        assert_eq!(s, session_secret(&shared_pv, &m1, &m2, &gw_pk, &pv_pk));
        // Order-bound: swapping the gateway/prover halves changes it.
        assert_ne!(s, session_secret(&shared, &m2, &m1, &pv_pk, &gw_pk));
        // Shared-bound: a different shared secret ⇒ a different session secret.
        assert_ne!(s, session_secret(&[9u8; 32], &m1, &m2, &gw_pk, &pv_pk));
    }

    #[test]
    fn public_transcript_alone_cannot_reproduce_the_secret() {
        // The C3 property: an attacker who sees every PUBLIC value (both ephemeral
        // pubkeys + both measurements) but neither ephemeral SECRET cannot derive
        // the session secret, because it folds the DH `shared` — which needs a
        // private key. We model "public transcript" as the attacker's best guess:
        // hashing the public tuple. It must NOT equal the real secret.
        let (gw_sk, gw_pk) = ephemeral_keypair(&GW_IKM);
        let (_pv_sk, pv_pk) = ephemeral_keypair(&PV_IKM);
        let shared = dh_shared(&gw_sk, &pv_pk).unwrap();
        let (m1, m2) = ([3u8; 32], [4u8; 32]);
        let real = session_secret(&shared, &m1, &m2, &gw_pk, &pv_pk);
        // The attacker lacks `shared`; substituting anything public (e.g. a zero
        // placeholder, or a pubkey) yields a different secret.
        assert_ne!(real, session_secret(&[0u8; 32], &m1, &m2, &gw_pk, &pv_pk));
        assert_ne!(real, session_secret(&gw_pk, &m1, &m2, &gw_pk, &pv_pk));
    }

    #[test]
    fn token_binds_secret_and_not_after() {
        let s = [7u8; 32];
        assert_eq!(session_token(&s, 1_000), session_token(&s, 1_000)); // deterministic
        assert_ne!(session_token(&s, 1_000), session_token(&s, 2_000)); // not_after-bound
        assert_ne!(session_token(&s, 1_000), session_token(&[8u8; 32], 1_000)); // secret-bound
        assert!(session_token(&s, 1_000).starts_with("0x"));
    }

    #[test]
    fn ct_eq_matches_semantic_equality() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab")); // length mismatch
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn dh_matches_rfc7748_section_6_1() {
        let alice_ikm =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let bob_pub =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap()
                .try_into()
                .unwrap();
        let (alice_sk, _) = ephemeral_keypair(&alice_ikm);
        assert_eq!(
            hex::encode(dh_shared(&alice_sk, &bob_pub).unwrap()),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[test]
    fn secret_erasure_features_are_enabled_in_this_crate() {
        // This crate must request erasing Drop rather than relying on another
        // workspace member to enable it through Cargo feature unification.
        assert!(std::mem::needs_drop::<StaticSecret>());
        assert!(std::mem::needs_drop::<x25519_dalek::SharedSecret>());
        assert!(std::mem::needs_drop::<zeroize::Zeroizing<[u8; 32]>>());
        let (mut secret, _) = ephemeral_keypair(&[0x11; 32]);
        zeroize::Zeroize::zeroize(&mut secret);
        assert_eq!(secret.as_bytes(), &[0; 32]);
    }

    #[test]
    fn session_expiry_matches_inclusive_admission_boundary() {
        assert!(validate_session_expiry(1_000, 999).is_ok());
        assert!(validate_session_expiry(1_000, 1_000).is_ok());
        assert!(matches!(
            validate_session_expiry(1_000, 1_001),
            Err(AttestError::SessionExpired {
                not_after_ms: 1_000,
                now_ms: 1_001
            })
        ));
        assert!(matches!(
            validate_session_expiry(0, 1),
            Err(AttestError::SessionExpired { .. })
        ));
        assert!(validate_session_expiry(u64::MAX, u64::MAX).is_ok());
    }
}
