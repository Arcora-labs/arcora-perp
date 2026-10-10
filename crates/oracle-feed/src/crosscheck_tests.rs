use super::*;
use crate::{signer_address, transcript_from_ticker};
use k256::ecdsa::SigningKey;
const NOW: u64 = 1_000_000;
fn key() -> SigningKey {
    SigningKey::from_slice(&[0x33; 32]).unwrap()
}
fn pair() -> SpotPair {
    SpotPair::new("BTC", "USDT").unwrap()
}
fn market() -> Market {
    let mut m = Market::conservative(0);
    m.oracle_pubkey = signer_address(&key());
    m
}
fn gate() -> CrosscheckGate {
    CrosscheckGate::new(pair(), 0, CrosscheckPolicy::new(1_000).unwrap())
}
fn tick(exchange: Exchange, price: &str, ts: u64) -> SourceTick {
    SourceTick {
        exchange,
        pair: pair(),
        transcript: transcript_from_ticker(price, price, price, ts, 0, &key()).unwrap(),
    }
}
fn observations() -> (SourceTick, SourceTick) {
    (
        tick(Exchange::CryptoCom, "100", NOW - 200),
        tick(Exchange::Okx, "100.01", NOW - 100),
    )
}
#[test]
fn two_venues_preserve_primary_commitment_signature_and_legacy_backup() {
    let (p, s) = observations();
    let accepted = gate().accept(&p, &s, &market(), NOW).unwrap();
    assert_eq!(accepted, p.transcript);
    assert_eq!(accepted.backup_twap, p.transcript.price);
    assert_ne!(accepted.backup_twap, s.transcript.backup_twap);
    assert_eq!(accepted.validate(&market(), NOW), Ok(accepted.price));
}
#[test]
fn same_venue_wrong_base_quote_order_or_market_is_not_independent_evidence() {
    let (p, s) = observations();
    assert!(gate().accept(&p, &p, &market(), NOW).is_err());
    assert!(gate().accept(&s, &p, &market(), NOW).is_err());
    for bad_pair in [
        SpotPair::new("ETH", "USDT").unwrap(),
        SpotPair::new("BTC", "USDC").unwrap(),
    ] {
        let mut bad = s.clone();
        bad.pair = bad_pair;
        assert!(gate().accept(&p, &bad, &market(), NOW).is_err());
    }
    let mut m = market();
    m.id = 1;
    assert!(gate().accept(&p, &s, &m, NOW).is_err());
}
#[test]
fn source_identity_is_not_publisher_independence() {
    let p = tick(Exchange::CryptoCom, "500", NOW - 200);
    let s = tick(Exchange::Okx, "500", NOW - 100);
    // Deliberately fabricated at the trusted host boundary with one test key.
    // This continues to pass: a compromised host/publisher is NOT solved here.
    assert!(gate().accept(&p, &s, &market(), NOW).is_ok());
}
#[test]
fn either_stale_future_zero_negative_confidence_or_wrong_signer_fails() {
    let (p, s) = observations();
    for ts in [0, NOW + 1, NOW - market().max_oracle_staleness_ms - 1] {
        let bad_p = tick(Exchange::CryptoCom, "100", ts);
        let bad_s = tick(Exchange::Okx, "100", ts);
        assert!(gate().accept(&bad_p, &s, &market(), NOW).is_err());
        assert!(gate().accept(&p, &bad_s, &market(), NOW).is_err());
    }
    let mut bad = s.clone();
    bad.transcript.confidence = -1;
    assert!(gate().accept(&p, &bad, &market(), NOW).is_err());
    let mut m = market();
    m.oracle_pubkey = [1; 20];
    assert!(gate().accept(&p, &s, &m, NOW).is_err());
}
#[test]
fn both_sources_revalidated_after_second_fetch_and_gateway_queue() {
    let p = tick(
        Exchange::CryptoCom,
        "100",
        NOW - market().max_oracle_staleness_ms,
    );
    let s = tick(Exchange::Okx, "100", NOW);
    assert!(gate().accept(&p, &s, &market(), NOW).is_ok());
    assert!(gate().accept(&p, &s, &market(), NOW + 1).is_err());
}
#[test]
fn old_but_advancing_independent_tape_never_becomes_fresh() {
    for offset in [0, 1, 100, 1_000] {
        let p = tick(Exchange::CryptoCom, "100", NOW + offset);
        let s = tick(Exchange::Okx, "100", NOW - 60_000 + offset);
        assert!(gate().accept(&p, &s, &market(), NOW + offset).is_err());
    }
}
#[test]
fn both_source_watermarks_must_advance_and_failure_is_atomic() {
    let (p, s) = observations();
    let mut g = gate();
    g.accept(&p, &s, &market(), NOW).unwrap();
    let previous = (g.primary_time, g.secondary_time);
    for (pt, st) in [
        (NOW - 200, NOW - 99),
        (NOW - 199, NOW - 100),
        (NOW - 201, NOW - 99),
        (NOW - 199, NOW - 101),
    ] {
        assert!(g
            .accept(
                &tick(Exchange::CryptoCom, "100", pt),
                &tick(Exchange::Okx, "100", st),
                &market(),
                NOW
            )
            .is_err());
        assert_eq!((g.primary_time, g.secondary_time), previous);
    }
    let p = tick(Exchange::CryptoCom, "100", NOW - 199);
    let bad = tick(Exchange::Okx, "105", NOW - 99);
    assert!(g.accept(&p, &bad, &market(), NOW).is_err());
    assert_eq!((g.primary_time, g.secondary_time), previous);
    assert!(g
        .accept(&p, &tick(Exchange::Okx, "100", NOW - 99), &market(), NOW)
        .is_ok());
}
#[test]
fn explicit_symmetric_deviation_is_inclusive_without_rounding_loophole() {
    let policy = CrosscheckPolicy::new(1_000).unwrap();
    assert!(policy.agrees(100_000, 100_100));
    assert!(policy.agrees(100_100, 100_000));
    assert!(!policy.agrees(100_000, 100_101));
    assert!(!policy.agrees(100_101, 100_000));
    assert!(!policy.agrees(0, 1));
    assert!(!policy.agrees(-1, 1));
    assert!(!policy.agrees(i128::MAX, 1));
    assert!(!policy.agrees(i128::MAX, i128::MAX));
    assert!(CrosscheckPolicy::new(0).unwrap().agrees(1, 1));
    assert!(!CrosscheckPolicy::new(0).unwrap().agrees(1, 2));
}
#[test]
fn matching_last_does_not_hide_disagreeing_order_books() {
    let (p, mut s) = observations();
    s.transcript = transcript_from_ticker("100", "100.5", "100.5", NOW - 100, 0, &key()).unwrap();
    assert!(s.transcript.validate(&market(), NOW).is_ok());
    assert!(gate().accept(&p, &s, &market(), NOW).is_err());
}
#[test]
fn quote_units_and_spot_contracts_are_never_implicitly_substituted() {
    assert_eq!(SpotPair::bind("BTC/USDT", "BTC_USDT").unwrap(), pair());
    for (symbol, instrument) in [
        ("BTC/USDC", "BTC_USDT"),
        ("BTC/USD", "BTC_USDT"),
        ("BTC/USDT", "BTCUSD-PERP"),
        ("BTC/USDT", "BTC_USDT-PERP"),
        ("BTC/USDT/SWAP", "BTC_USDT"),
        ("ETH/USDT", "BTC_USDT"),
        ("BTC", "BTC_USDT"),
    ] {
        assert!(SpotPair::bind(symbol, instrument).is_err());
    }
    for asset in ["", "btc", "BTC_", "BTC-SWAP", "BTC/USDT", " BTC", "₿TC"] {
        assert!(SpotPair::new(asset, "USDT").is_err());
    }
}
#[test]
fn configuration_never_invents_thresholds_or_repairs_malformed_values() {
    use std::env::VarError;
    assert_eq!(
        CrosscheckPolicy::from_value(Err(VarError::NotPresent)).unwrap(),
        None
    );
    for input in [
        "", " ", "0.1", "+1", "-1", "1e3", "1000001", "10000000", "1 ",
    ] {
        assert!(CrosscheckPolicy::from_value(Ok(input.into())).is_err());
    }
    for input in ["0", "1", "1000", "1000000"] {
        assert!(CrosscheckPolicy::from_value(Ok(input.into()))
            .unwrap()
            .is_some());
    }
    assert!(CrosscheckPolicy::new(-1).is_err());
    assert!(CrosscheckPolicy::new(i128::MAX).is_err());
    assert!(CrosscheckPolicy::from_value(Err(VarError::NotUnicode("sentinel".into()))).is_err());
}

#[test]
fn older_secondary_cannot_hide_behind_fresher_primary_guest_timestamp() {
    let p = tick(Exchange::CryptoCom, "100", NOW);
    let s = tick(Exchange::Okx, "100", NOW - 1);
    assert!(p.transcript.validate(&market(), NOW).is_ok());
    assert!(s.transcript.validate(&market(), NOW).is_ok());
    assert!(gate().accept(&p, &s, &market(), NOW).is_err());
    let s = tick(Exchange::Okx, "100", NOW);
    assert!(gate().accept(&p, &s, &market(), NOW).is_ok());
}
