//! SEC-020 Phase-2 (C3) — the ephemeral-DH mutual-attestation handshake
//! ORCHESTRATION, driven end-to-end with a mock `Attestor`.
//!
//! Why a mock: `AzureTdxAttestor::quote` reads the STATIC tee-capture fixture,
//! whose AK-`extraData` is a captured constant — it cannot bind a FRESH
//! `eph_pub`, so a real gateway↔prover handshake `verify` would `NonceMismatch`
//! locally (that end-to-end is window-deferred). The mock's `quote` DOES echo
//! the challenge, so this file exercises the exact orchestration both binaries
//! run — generate ephemeral key → verify peer bundle over the peer's advertised
//! `eph_pub` → `dh_shared` → `derive_session` (the ONE shared secret+token
//! derivation, gateway fields first on BOTH sides) — without any TEE evidence,
//! and proves:
//!   1. both sides derive the IDENTICAL secret + token (the orientation check);
//!   2. a tampered / malformed peer bundle fails closed (no token);
//!   3. a wrong peer measurement fails closed (`MeasurementMismatch`);
//!   4. an `eph_pub` that the peer's bundle does not bind fails closed
//!      (`NonceMismatch`) — the MITM-key-substitution case.
//!
//! `gateway_half` mirrors `prover_handshake` (crates/gateway/src/main.rs);
//! `prover_half` mirrors `boot_handshake` (crates/prover-service/src/main.rs).

use dark_perp_attestation::{
    derive_session, dh_shared, ephemeral_keypair, session_token, AttestError, Attestor, Digest,
    StaticSecret,
};

/// A mock `Attestor`: `quote(challenge)` emits `measurement ‖ challenge`
/// (64 bytes); `verify(bundle, expected, challenge)` parses that back and
/// enforces the SAME fail-closed contract the real backends do — measurement
/// must equal the pinned `expected`, the bound challenge must equal the
/// caller's `challenge` — minus the cryptographic evidence.
struct MockAttestor {
    measurement: Digest,
}

impl Attestor for MockAttestor {
    fn quote(&self, challenge: &[u8; 32]) -> Result<Vec<u8>, AttestError> {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&self.measurement);
        b.extend_from_slice(challenge);
        Ok(b)
    }

    fn verify(
        &self,
        bundle: &[u8],
        expected: &Digest,
        challenge: &[u8; 32],
    ) -> Result<Digest, AttestError> {
        if bundle.len() != 64 {
            return Err(AttestError::Backend("mock bundle: not 64 bytes".into()));
        }
        let mut meas = [0u8; 32];
        meas.copy_from_slice(&bundle[..32]);
        if &meas != expected {
            return Err(AttestError::MeasurementMismatch);
        }
        if bundle[32..] != challenge[..] {
            return Err(AttestError::NonceMismatch);
        }
        Ok(meas)
    }
}

// The two pinned (expected) measurements and the session expiry the prover owns.
const GW_MEAS: Digest = [0xAA; 32];
const PV_MEAS: Digest = [0xBB; 32];
const NOT_AFTER_MS: u64 = 1_900_000_000_000;

// Distinct per-party IKM — the fresh OS-CSPRNG draw each boot performs.
const GW_IKM: [u8; 32] = [0x11; 32];
const PV_IKM: [u8; 32] = [0x22; 32];

/// The GATEWAY's half (mirrors `prover_handshake`): verify the prover's
/// advertised `{bundle, eph_pub, not_after}` — the challenge is the prover's
/// OWN `eph_pub` — then fold the ECDH shared point into the session secret
/// with the gateway fields FIRST, and mint the token under the PROVER's
/// advertised `not_after`. `gw_expected` stands in for our own measurement.
#[allow(clippy::too_many_arguments)] // a flat handshake transcript; a params struct adds only ceremony
fn gateway_half(
    verifier: &dyn Attestor,
    gw_sk: &StaticSecret,
    gw_pub: &[u8; 32],
    gw_expected: &Digest,
    pv_expected: &Digest,
    pv_bundle: &[u8],
    pv_pub: &[u8; 32],
    not_after: u64,
) -> Result<(String, Digest), AttestError> {
    let pv_meas = verifier.verify(pv_bundle, pv_expected, pv_pub)?;
    let shared = dh_shared(gw_sk, pv_pub);
    let (secret, token) = derive_session(&shared, gw_expected, &pv_meas, gw_pub, pv_pub, not_after);
    Ok((token, secret))
}

/// The PROVER's half (mirrors `boot_handshake`): verify the gateway's
/// advertised `{bundle, eph_pub}` — the challenge is the gateway's OWN
/// `eph_pub` — then fold the ECDH shared point into the session secret with
/// the SAME orientation (gateway fields first), minting under our own
/// `not_after` (the prover owns expiry). `pv_expected` stands in for our own
/// measurement.
#[allow(clippy::too_many_arguments)] // a flat handshake transcript; a params struct adds only ceremony
fn prover_half(
    verifier: &dyn Attestor,
    pv_sk: &StaticSecret,
    pv_pub: &[u8; 32],
    gw_expected: &Digest,
    pv_expected: &Digest,
    gw_bundle: &[u8],
    gw_pub: &[u8; 32],
    not_after: u64,
) -> Result<(String, Digest), AttestError> {
    let gw_meas = verifier.verify(gw_bundle, gw_expected, gw_pub)?;
    let shared = dh_shared(pv_sk, gw_pub);
    let (secret, token) = derive_session(&shared, &gw_meas, pv_expected, gw_pub, pv_pub, not_after);
    Ok((token, secret))
}

#[test]
fn both_sides_derive_the_identical_secret_and_token() {
    // Each side draws its ephemeral keypair and attests, binding its OWN eph_pub.
    let (gw_sk, gw_pub) = ephemeral_keypair(&GW_IKM);
    let (pv_sk, pv_pub) = ephemeral_keypair(&PV_IKM);
    let gw_att = MockAttestor {
        measurement: GW_MEAS,
    };
    let pv_att = MockAttestor {
        measurement: PV_MEAS,
    };
    let gw_bundle = gw_att.quote(&gw_pub).unwrap();
    let pv_bundle = pv_att.quote(&pv_pub).unwrap();

    // Each side verifies the PEER's bundle over the peer's advertised eph_pub.
    let (gw_token, gw_secret) = gateway_half(
        &pv_att,
        &gw_sk,
        &gw_pub,
        &GW_MEAS,
        &PV_MEAS,
        &pv_bundle,
        &pv_pub,
        NOT_AFTER_MS,
    )
    .expect("gateway half completes");
    let (pv_token, pv_secret) = prover_half(
        &gw_att,
        &pv_sk,
        &pv_pub,
        &GW_MEAS,
        &PV_MEAS,
        &gw_bundle,
        &gw_pub,
        NOT_AFTER_MS,
    )
    .expect("prover half completes");

    // THE orientation check: both sides fold the identical transcript tuple.
    assert_eq!(gw_secret, pv_secret, "both sides derive the SAME secret");
    assert_eq!(gw_token, pv_token, "both sides mint the SAME token");
    assert!(gw_token.starts_with("0x"));
    // And the token is not_after-bound: a different expiry ⇒ a different token.
    assert_ne!(gw_token, session_token(&gw_secret, NOT_AFTER_MS + 1));
}

#[test]
fn a_tampered_peer_bundle_fails_closed() {
    let (gw_sk, gw_pub) = ephemeral_keypair(&GW_IKM);
    let (_pv_sk, pv_pub) = ephemeral_keypair(&PV_IKM);
    let pv_att = MockAttestor {
        measurement: PV_MEAS,
    };
    let mut tampered = pv_att.quote(&pv_pub).unwrap();
    tampered[0] ^= 0x01; // flip a byte in the attested measurement
    assert!(
        gateway_half(
            &pv_att,
            &gw_sk,
            &gw_pub,
            &GW_MEAS,
            &PV_MEAS,
            &tampered,
            &pv_pub,
            NOT_AFTER_MS,
        )
        .is_err(),
        "a tampered bundle must abort the handshake — no token"
    );
    // A malformed (truncated) bundle is equally refused, as a Backend error.
    assert!(matches!(
        gateway_half(
            &pv_att,
            &gw_sk,
            &gw_pub,
            &GW_MEAS,
            &PV_MEAS,
            b"short",
            &pv_pub,
            NOT_AFTER_MS,
        ),
        Err(AttestError::Backend(_))
    ));
}

#[test]
fn a_wrong_peer_measurement_fails_closed() {
    // The prover attests with a measurement that is NOT the pinned PV_MEAS —
    // a different binary. The gateway's verify must MeasurementMismatch.
    let (gw_sk, gw_pub) = ephemeral_keypair(&GW_IKM);
    let (_pv_sk, pv_pub) = ephemeral_keypair(&PV_IKM);
    let evil_att = MockAttestor {
        measurement: [0xEE; 32],
    };
    let evil_bundle = evil_att.quote(&pv_pub).unwrap();
    assert!(matches!(
        gateway_half(
            &evil_att,
            &gw_sk,
            &gw_pub,
            &GW_MEAS,
            &PV_MEAS,
            &evil_bundle,
            &pv_pub,
            NOT_AFTER_MS,
        ),
        Err(AttestError::MeasurementMismatch)
    ));
    // Symmetric on the prover's half: a wrong gateway measurement is refused.
    let (pv_sk, pv_pub2) = ephemeral_keypair(&PV_IKM);
    let evil_gw = evil_att.quote(&gw_pub).unwrap();
    assert!(matches!(
        prover_half(
            &evil_att,
            &pv_sk,
            &pv_pub2,
            &GW_MEAS,
            &PV_MEAS,
            &evil_gw,
            &gw_pub,
            NOT_AFTER_MS,
        ),
        Err(AttestError::MeasurementMismatch)
    ));
}

#[test]
fn a_mismatched_eph_pub_fails_closed() {
    // MITM key substitution: the peer's bundle binds ITS eph_pub, but the
    // /attest response advertises a DIFFERENT pubkey (the attacker's DH key).
    // verify(bundle, expected, advertised_pub) must NonceMismatch — the bundle
    // does not prove the advertised key, so no secret is ever derived from it.
    let (gw_sk, gw_pub) = ephemeral_keypair(&GW_IKM);
    let (_pv_sk, pv_pub) = ephemeral_keypair(&PV_IKM);
    let (_mitm_sk, mitm_pub) = ephemeral_keypair(&[0x99; 32]);
    let pv_att = MockAttestor {
        measurement: PV_MEAS,
    };
    let pv_bundle = pv_att.quote(&pv_pub).unwrap(); // binds pv_pub…
    assert!(matches!(
        gateway_half(
            &pv_att,
            &gw_sk,
            &gw_pub,
            &GW_MEAS,
            &PV_MEAS,
            &pv_bundle,
            &mitm_pub, // …not mitm_pub
            NOT_AFTER_MS,
        ),
        Err(AttestError::NonceMismatch)
    ));
}
