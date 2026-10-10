//! Before/after host conversion regressions; no HTTP, operational key or proof.
use k256::ecdsa::SigningKey;
use oracle_feed::{parse_price, transcript_from_ticker};

fn ticker(last: &str, bid: &str, ask: &str) -> Option<perp_core::oracle::OracleTranscript> {
    let key = SigningKey::from_slice(&[0x33; 32]).unwrap();
    transcript_from_ticker(last, bid, ask, 1_000, 0, &key)
}

#[test]
fn missing_book_cannot_be_replaced_by_last_trade() {
    for (bid, ask) in [("", ""), ("100", ""), ("", "100")] {
        assert!(ticker("100", bid, ask).is_none());
    }
}
#[test]
fn malformed_or_nonpositive_book_is_not_a_valid_backup() {
    for side in ["bogus", "-100", "0", "--100"] {
        assert!(ticker("100", side, "101").is_none());
        assert!(ticker("100", "99", side).is_none());
    }
}
#[test]
fn crossed_book_is_refused_instead_of_absolutizing_spread() {
    assert!(ticker("100", "101", "99").is_none());
}
#[test]
fn duplicate_sign_and_exponent_cannot_become_positive_price() {
    for text in ["--5", "-+5", "+5", "1e3", "1..0"] {
        assert_eq!(parse_price(text), None, "invalid price shape");
    }
}
#[test]
fn individually_representable_book_prices_do_not_overflow_midpoint() {
    let large = (i128::MAX / perp_core::fixed::PRICE_SCALE).to_string();
    let outcome = std::panic::catch_unwind(|| ticker(&large, &large, &large));
    assert!(
        outcome.is_ok(),
        "external prices must not panic the poll worker"
    );
    let t = outcome.unwrap().unwrap();
    assert_eq!(t.price, t.backup_twap);
}
