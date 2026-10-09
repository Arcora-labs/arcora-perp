//! R06 trust-boundary characterization for the custodial alpha. A passing test
//! demonstrates reliance on the configured publisher, not price-source safety.

use k256::ecdsa::SigningKey;
use perp_core::fixed::PRICE_SCALE;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::Market;

fn signed_price(key: &SigningKey, price: i128, now_ms: u64) -> OracleTranscript {
    OracleTranscript {
        price,
        publish_time_ms: now_ms,
        confidence: 0,
        backup_twap: price,
        signature: OracleSig::sign(key, &oracle_digest(0, price, now_ms, 0, price)),
    }
}

#[test]
fn trusted_publisher_can_reprice_primary_and_backup_together() {
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let now_ms = 1_000_000;
    let observed_market_price = 100_000 * PRICE_SCALE;
    let honest = signed_price(&key, observed_market_price, now_ms);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = honest
        .signature
        .recover(&oracle_digest(
            market.id,
            honest.price,
            now_ms,
            honest.confidence,
            honest.backup_twap,
        ))
        .unwrap();
    assert_eq!(honest.validate(&market, now_ms), Ok(observed_market_price));

    // In this scenario the external observation stays fixed. A compromised
    // authorized publisher signs a 100x lower or higher price AND matching TWAP.
    // Both are accepted: signature, freshness and internal agreement do not
    // authenticate either price against an independently verified market source.
    for fabricated_price in [observed_market_price / 100, observed_market_price * 100] {
        let fabricated = signed_price(&key, fabricated_price, now_ms);
        assert_ne!(fabricated.price, observed_market_price);
        assert_eq!(
            fabricated.validate(&market, now_ms),
            Ok(fabricated_price),
            "the current trust model accepts the configured publisher's coherent lie"
        );
    }
}
