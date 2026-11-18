//! The entry minimum (audit G1-1): with `Sequencer::set_min_entry_collateral` set,
//! no order adds exposure to a position entry that holds less collateral, neither
//! when the order is admitted nor when a fill of it settles, so an order that
//! rests from when its entry held the minimum does not fill once a trading loss
//! took the entry below it. Reductions are never held to it, nor is the house
//! market maker, and with 0 (the default) it holds no one.

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{Order, RejectReason, Side, TimeInForce};
use perp_core::Note;
use sequencer::{EnclaveIdentity, Sequencer};

const NOW: u64 = 1_800_000_000_000;

/// The entry minimum the gateway sets: 100 USDC.
const FLOOR: i128 = 100 * QUOTE_SCALE;

fn owner_id(owner: u64) -> PubKey {
    owner_from_spend_key::<Keccak256>(&[owner as u8; 32])
}

fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).expect("valid dev scalar")
}

fn oracle_addr() -> [u8; 20] {
    let probe = oracle_digest(0, 0, 0, 0, 0);
    OracleSig::sign(&oracle_key(), &probe)
        .recover(&probe)
        .expect("fresh signature recovers")
}

/// A market-0 transcript at `price_usd` whole dollars, published at `now`.
fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    let price = price_usd * PRICE_SCALE;
    let confidence = 10 * PRICE_SCALE;
    let d = oracle_digest(0, price, now, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

/// A market-0 order at `price_usd` whole dollars for `size` (size-scaled).
fn order(
    owner: u64,
    side: Side,
    size: i128,
    price_usd: i128,
    tif: TimeInForce,
    nonce: u64,
) -> Order {
    Order {
        owner: owner_id(owner),
        market_id: 0,
        side,
        size,
        limit_price: price_usd * PRICE_SCALE,
        tif,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: word_u64(nonce.wrapping_mul(13) ^ owner),
    }
}

fn fund(seq: &mut Sequencer, owner: u64, amount: i128, blind: u8) {
    let o = owner_id(owner);
    let cm = Note::new(o, 0, amount, [blind; 32]).commitment::<Keccak256>();
    let deposit_id = seq.state.consumed_deposit_count;
    seq.apply(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount,
        blinding: [blind; 32],
        from: [0u8; 20],
        deposit_id,
        deposit_blind: [0u8; 32],
    })
    .unwrap();
    seq.apply(&BatchOp::FundPosition {
        owner: o,
        market_id: 0,
        note_commitment: cm,
        spend_key: [owner as u8; 32],
    })
    .unwrap();
}

/// Market 0 at $100k with the entry minimum `floor`; owner 2 (the counterparty)
/// funded with $20k.
fn setup(floor: i128) -> Sequencer {
    let mut s = Sequencer::new(EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]), 20);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = oracle_addr();
    s.add_market(market);
    s.set_oracle(0, oracle(100_000, NOW));
    s.set_min_entry_collateral(floor);
    fund(&mut s, 2, 20_000 * QUOTE_SCALE, 0x22);
    s
}

/// A fill of `size` at `price_usd` between taker `taker` (on `side`) and `maker`,
/// applied directly: a trade of an earlier batch.
fn fill(seq: &mut Sequencer, taker: u64, maker: u64, side: Side, size: i128, price_usd: i128) {
    seq.apply(&BatchOp::Fill {
        taker: owner_id(taker),
        maker: owner_id(maker),
        market_id: 0,
        taker_side: side,
        size,
        price: price_usd * PRICE_SCALE,
        oracle: oracle(100_000, NOW),
        now_ms: NOW,
    })
    .unwrap();
}

fn collateral(seq: &Sequencer, owner: u64) -> i128 {
    seq.state
        .position(&owner_id(owner), 0)
        .map_or(0, |p| p.collateral)
}

fn size(seq: &Sequencer, owner: u64) -> i128 {
    seq.state
        .position(&owner_id(owner), 0)
        .map_or(0, |p| p.size)
}

/// 0.001 BTC: $100 of notional at $100k.
const LOT: i128 = 100_000;

#[test]
fn audit_1116_g11_below_the_entry_minimum_no_order_adds_exposure_at_admission() {
    let mut seq = setup(FLOOR);
    fund(&mut seq, 1, FLOOR - 1, 0x11);
    fund(&mut seq, 3, FLOOR, 0x33);
    let buy = |owner, nonce| order(owner, Side::Buy, LOT, 100_000, TimeInForce::Gtc, nonce);
    assert_eq!(
        seq.pre_trade_check(&buy(1, 1), NOW),
        Err(RejectReason::InsufficientMargin)
    );
    assert_eq!(seq.pre_trade_check(&buy(3, 1), NOW), Ok(()));
    // No entry at all is below it too.
    assert_eq!(
        seq.pre_trade_check(&buy(4, 1), NOW),
        Err(RejectReason::InsufficientMargin)
    );
    // The house market maker is not held to it, and 0 holds no one.
    seq.set_minimum_exempt_owner(Some(owner_id(1)));
    assert_eq!(seq.pre_trade_check(&buy(1, 2), NOW), Ok(()));
    seq.set_minimum_exempt_owner(None);
    seq.set_min_entry_collateral(0);
    assert_eq!(seq.pre_trade_check(&buy(1, 3), NOW), Ok(()));

    // An entry below it that holds a position may reduce, not grow or flip.
    fill(&mut seq, 1, 2, Side::Buy, LOT, 100_000);
    seq.set_min_entry_collateral(FLOOR);
    let sell = |size, nonce| order(1, Side::Sell, size, 100_000, TimeInForce::Gtc, nonce);
    assert_eq!(seq.pre_trade_check(&sell(LOT / 2, 4), NOW), Ok(()));
    assert_eq!(seq.pre_trade_check(&sell(LOT, 5), NOW), Ok(()));
    assert_eq!(
        seq.pre_trade_check(&sell(2 * LOT, 6), NOW),
        Err(RejectReason::InsufficientMargin)
    );
    assert_eq!(
        seq.pre_trade_check(&buy(1, 7), NOW),
        Err(RejectReason::InsufficientMargin)
    );
}

/// The PoC C pattern: owner 1 rests a buy while its entry holds the minimum, then
/// a round trip at the edges of the 2% fill band takes the entry below it. When
/// owner 2 sells into the resting buy, the fill would add exposure below the
/// minimum: the buy is refused (and banned from the book), and owner 1 stays flat.
/// Without the floor the same buy fills.
#[test]
fn audit_1116_g11_a_resting_opener_does_not_fill_once_its_entry_is_below_the_minimum() {
    for floor in [FLOOR, 0] {
        let mut seq = setup(floor);
        fund(&mut seq, 1, FLOOR, 0x11);
        let resting = order(1, Side::Buy, LOT, 99_500, TimeInForce::Gtc, 1);
        let sealed = seq.seal_batch(&[resting], NOW);
        assert!(
            sealed.manifest.rejected.is_empty(),
            "{:?}",
            sealed.manifest.rejected
        );
        // 800 USDC bought at +1.99% and sold back at -1.99%.
        fill(&mut seq, 1, 2, Side::Buy, 8 * LOT, 101_990);
        fill(&mut seq, 1, 2, Side::Sell, 8 * LOT, 98_010);
        let left = collateral(&seq, 1);
        assert!(left < FLOOR && left > FLOOR / 2, "{left}");
        assert_eq!(size(&seq, 1), 0);

        let taker = order(2, Side::Sell, LOT, 99_500, TimeInForce::Ioc, 2);
        let sealed = seq.seal_batch(&[taker], NOW);
        let hash = resting.order_hash::<Keccak256>();
        if floor > 0 {
            assert!(
                sealed
                    .manifest
                    .rejected
                    .contains(&(hash, RejectReason::InsufficientMargin)),
                "{:?}",
                sealed.manifest.rejected
            );
            assert_eq!(
                size(&seq, 1),
                0,
                "the resting opener filled below the minimum"
            );
            assert_eq!(collateral(&seq, 1), left);
            assert_eq!(
                seq.book(0).unwrap().remaining_for(&owner_id(1), &hash),
                None
            );
        } else {
            assert_eq!(size(&seq, 1), LOT, "without the floor the opener fills");
        }
    }
}

/// A reduction of an entry below the minimum settles: the floor holds only fills
/// that add exposure.
#[test]
fn audit_1116_g11_an_entry_below_the_minimum_still_reduces() {
    let mut seq = setup(FLOOR);
    fund(&mut seq, 1, FLOOR, 0x11);
    fill(&mut seq, 1, 2, Side::Buy, 8 * LOT, 101_990);
    fill(&mut seq, 1, 2, Side::Sell, 7 * LOT, 98_010);
    assert!(collateral(&seq, 1) < FLOOR);
    assert_eq!(size(&seq, 1), LOT);
    let bid = order(2, Side::Buy, LOT, 100_000, TimeInForce::Gtc, 1);
    let close = order(1, Side::Sell, LOT, 100_000, TimeInForce::Ioc, 2);
    let sealed = seq.seal_batch(&[bid, close], NOW);
    assert!(
        sealed.manifest.rejected.is_empty(),
        "{:?}",
        sealed.manifest.rejected
    );
    assert_eq!(size(&seq, 1), 0);
}
