//! The guest's oracle-signature recovery refuses a malleated high-`s` twin.
//!
//! For a valid `(r, s, v)` the twin `(r, n − s, v ⊕ 1)` recovers the SAME key, so
//! ecdsa 0.17's `recover_from_prehash` alone would accept it (0.16's re-verified the
//! signature and refused it). `OracleSig::recover` re-verifies against the
//! recovered key, which for secp256k1 refuses a high-`s` signature, so the twin
//! recovers to nothing, as before the k256 0.14 upgrade.
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::scalar::IsHigh;
use perp_core::oracle::OracleSig;

#[test]
fn a_high_s_twin_of_an_oracle_signature_does_not_recover() {
    let key = SigningKey::from_slice(&[0x17; 32]).unwrap();
    let digest = [0x5a; 32];
    let signature = OracleSig::sign(&key, &digest);
    let signer = signature
        .recover(&digest)
        .expect("the signed low-s signature recovers");

    let s = k256::Scalar::from_repr(signature.s.into()).unwrap();
    let twin = OracleSig {
        r: signature.r,
        s: (-s).to_bytes().into(),
        v: if signature.v == 27 { 28 } else { 27 },
    };
    assert_ne!(twin.s, signature.s, "the twin is a different (r, s, v)");
    assert_eq!(
        twin.recover(&digest),
        None,
        "the high-s twin is refused at recovery"
    );
    assert_eq!(signature.recover(&digest), Some(signer));
}

#[test]
fn signing_produces_low_s_with_a_matching_recovery_id() {
    // k256 normalizes s when signing and flips the recovery id with it, so every
    // signature the host produces is the one the guest and L1 `ecrecover` accept.
    for seed in 1u8..=16 {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let digest = [seed.wrapping_mul(29); 32];
        let signature = OracleSig::sign(&key, &digest);
        let s = k256::Scalar::from_repr(signature.s.into()).unwrap();
        assert!(
            !bool::from(s.is_high()),
            "seed {seed}: high-s signature produced"
        );
        assert!(signature.v == 27 || signature.v == 28);
        assert!(
            signature.recover(&digest).is_some(),
            "seed {seed}: own signature must recover"
        );
    }
}
