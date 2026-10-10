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
//!   5. a low-order key fails closed even when the test attestor binds it;
//!   6. an already-expired transcript cannot mint session material.
//!
//! `gateway_half` mirrors `prover_handshake` (crates/gateway/src/main.rs);
//! `prover_half` mirrors `boot_handshake` (crates/prover-service/src/main.rs).

use dark_perp_attestation::{
    derive_session, dh_shared, ephemeral_keypair, session_token, validate_session_expiry,
    AttestError, Attestor, Digest, StaticSecret,
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
const NOW_MS: u64 = NOT_AFTER_MS - 1_000;

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
    let shared = dh_shared(gw_sk, pv_pub)?;
    validate_session_expiry(not_after, NOW_MS)?;
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
    let shared = dh_shared(pv_sk, gw_pub)?;
    validate_session_expiry(not_after, NOW_MS)?;
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
    // Captured from the pre-hardening implementation using only these public
    // synthetic test fixtures. Pin bytes as well as convergence to detect drift.
    assert_eq!(
        hex::encode(gw_secret),
        "aec05f965c995ab2b23360f1a49901cda11dbc2a2186b100c09d0f0dc6c7ecab"
    );
    assert_eq!(
        gw_token,
        "0x88c8e06f048162a492c491b8caa5c2b168afb80477d3738c3cfeff53cee3c48d"
    );
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

// The seven small-order encodings from libsodium's ref10 X25519 blocklist:
// https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c
// Also exercise their high-bit aliases (RFC 7748 section 5 masks that bit).
fn low_order_peer_keys() -> Vec<[u8; 32]> {
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ]
    .into_iter()
    .flat_map(|s| {
        let key: [u8; 32] = hex::decode(s).unwrap().try_into().unwrap();
        let mut alias = key;
        alias[31] |= 0x80;
        [key, alias]
    })
    .collect()
}

#[test]
fn gateway_rejects_attested_low_order_peer_keys() {
    let (gw_sk, gw_pub) = ephemeral_keypair(&GW_IKM);
    let att = MockAttestor {
        measurement: PV_MEAS,
    };
    let mut unexpected = Vec::new();
    for peer in low_order_peer_keys() {
        let bundle = att.quote(&peer).unwrap();
        assert_eq!(att.verify(&bundle, &PV_MEAS, &peer).unwrap(), PV_MEAS);
        if !matches!(
            gateway_half(
                &att,
                &gw_sk,
                &gw_pub,
                &GW_MEAS,
                &PV_MEAS,
                &bundle,
                &peer,
                NOT_AFTER_MS
            ),
            Err(AttestError::NonContributoryKey)
        ) {
            unexpected.push(hex::encode(peer));
        }
    }
    assert!(
        unexpected.is_empty(),
        "peers not rejected as NonContributoryKey: {unexpected:?}"
    );
}

#[test]
fn prover_rejects_attested_low_order_peer_keys() {
    let (pv_sk, pv_pub) = ephemeral_keypair(&PV_IKM);
    let att = MockAttestor {
        measurement: GW_MEAS,
    };
    let mut unexpected = Vec::new();
    for peer in low_order_peer_keys() {
        let bundle = att.quote(&peer).unwrap();
        assert_eq!(att.verify(&bundle, &GW_MEAS, &peer).unwrap(), GW_MEAS);
        if !matches!(
            prover_half(
                &att,
                &pv_sk,
                &pv_pub,
                &GW_MEAS,
                &PV_MEAS,
                &bundle,
                &peer,
                NOT_AFTER_MS
            ),
            Err(AttestError::NonContributoryKey)
        ) {
            unexpected.push(hex::encode(peer));
        }
    }
    assert!(
        unexpected.is_empty(),
        "peers not rejected as NonContributoryKey: {unexpected:?}"
    );
}

#[test]
fn both_directions_reject_expired_sessions() {
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
    for expired in [0, NOW_MS - 1] {
        let gw = gateway_half(
            &pv_att, &gw_sk, &gw_pub, &GW_MEAS, &PV_MEAS, &pv_bundle, &pv_pub, expired,
        );
        let pv = prover_half(
            &gw_att, &pv_sk, &pv_pub, &GW_MEAS, &PV_MEAS, &gw_bundle, &gw_pub, expired,
        );
        assert!(
            matches!(gw, Err(AttestError::SessionExpired { not_after_ms, now_ms }) if not_after_ms == expired && now_ms == NOW_MS)
        );
        assert!(
            matches!(pv, Err(AttestError::SessionExpired { not_after_ms, now_ms }) if not_after_ms == expired && now_ms == NOW_MS)
        );
    }
}

#[test]
fn dh_rejects_low_order_peer_keys_for_multiple_local_secrets() {
    for ikm in [GW_IKM, PV_IKM, [0; 32], [0xff; 32]] {
        let (secret, _) = ephemeral_keypair(&ikm);
        for peer in low_order_peer_keys() {
            assert!(
                matches!(
                    dh_shared(&secret, &peer),
                    Err(AttestError::NonContributoryKey)
                ),
                "low-order peer {} was not rejected",
                hex::encode(peer)
            );
        }
    }
}
