//! End-to-end sequencer tests: signed receipts (§2), match→settle→manifest flow,
//! finality transitions (§3), and inclusion-violation detection (§2).

use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::order::{Finality, Order, Side, TimeInForce};
use perp_core::oracle::OracleTranscript;
use perp_core::Note;
use sequencer::{EnclaveIdentity, Sequencer};

fn enclave() -> EnclaveIdentity {
    EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32])
}

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: price_usd * PRICE_SCALE,
        publish_time_ms: now,
        confidence: 10 * PRICE_SCALE,
        backup_twap: price_usd * PRICE_SCALE,
    }
}

fn order(owner: u64, side: Side, size: i128, price: i128, nonce: u64) -> Order {
    Order {
        owner: word_u64(owner),
        market_id: 0,
        side,
        size,
        limit_price: price,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: word_u64(nonce.wrapping_mul(13)),
    }
}

/// Fund a trader: deposit a note and bind it to a market-0 position.
fn fund(seq: &mut Sequencer, owner: u64, amount_usd: i128, blind: u8) {
    let o = word_u64(owner);
    let amount = amount_usd * QUOTE_SCALE;
    let cm = Note::new(o, 0, amount, [blind; 32]).commitment::<Keccak256>();
    seq.apply(&BatchOp::Deposit { owner: o, asset_id: 0, amount, blinding: [blind; 32] }).unwrap();
    seq.apply(&BatchOp::FundPosition { owner: o, market_id: 0, note_commitment: cm, spend_key: [owner as u8; 32] }).unwrap();
}

fn setup() -> Sequencer {
    let mut s = Sequencer::new(enclave(), 20);
    s.add_market(Market::conservative(0));
    s.set_oracle(0, oracle(100_000, 1_000));
    fund(&mut s, 1, 20_000, 0x11);
    fund(&mut s, 2, 20_000, 0x22);
    s
}

#[test]
fn receipt_is_signed_and_verifies() {
    let mut s = setup();
    let r = s.accept_order(&order(1, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 1), 1_000);
    assert!(r.verify(), "honest receipt must verify");

    // tamper with the receipt body → signature no longer matches
    let mut bad = r.clone();
    bad.receipt.seq_no += 1;
    assert!(!bad.verify(), "tampered receipt must fail verification");

    // tamper with the signature
    let mut bad2 = r.clone();
    bad2.r[0] ^= 0xff;
    assert!(!bad2.verify());
}

#[test]
fn match_settles_and_advances_finality() {
    let mut s = setup();
    let maker = order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1);
    let taker = order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2);
    let sealed = s.seal_batch(&[maker, taker], 1_000);

    assert_eq!(sealed.batch_id, 0);
    assert_ne!(sealed.prev_state_root, sealed.new_state_root, "state advanced");
    assert_eq!(sealed.settlement_rejected, vec![]);
    assert_eq!(sealed.manifest.ordered.len(), 2);
    assert_eq!(sealed.receipts.len(), 2);
    assert!(sealed.receipts.iter().all(|r| r.verify()));

    // both positions opened
    assert_eq!(s.state.position(&word_u64(2), 0).unwrap().size, SIZE_SCALE);
    assert_eq!(s.state.position(&word_u64(1), 0).unwrap().size, -SIZE_SCALE);
    assert!(s.state.conservation_holds());

    // finality: MATCHED after sealing, SETTLED only after proof verified (§3)
    let taker_hash = taker.order_hash::<Keccak256>();
    assert_eq!(s.finality_of(&taker_hash), Some(Finality::Matched));
    assert!(!Finality::Matched.is_withdrawable());

    s.mark_settled(0);
    assert_eq!(s.finality_of(&taker_hash), Some(Finality::Settled));
    assert!(Finality::Settled.is_withdrawable());
}

#[test]
fn manifest_hash_is_stable_and_binds_roots() {
    let mut s = setup();
    let sealed = s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    assert_eq!(sealed.manifest_hash, sealed.manifest.hash::<Keccak256>());
    assert_eq!(sealed.manifest.previous_state_root, sealed.prev_state_root);
}

#[test]
fn pre_trade_risk_rejects_unmarginable_before_matching() {
    // With pre-trade risk (Phase 3) an underfunded order is rejected BEFORE
    // matching — so it never matches-but-fails-to-settle. It appears in the
    // manifest's rejected list with InsufficientMargin, never opens a position,
    // and settlement_rejected stays empty.
    let mut s = setup();
    fund(&mut s, 3, 1_000, 0x33); // only $1k
    let maker = order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 10);
    let taker = order(3, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 11); // needs $10k initial
    let taker_hash = taker.order_hash::<Keccak256>();
    let sealed = s.seal_batch(&[maker, taker], 1_000);

    assert!(sealed.settlement_rejected.is_empty(), "no match-but-unsettleable fills");
    assert!(
        sealed.manifest.rejected.iter().any(|(h, r)| *h == taker_hash
            && *r == perp_core::order::RejectReason::InsufficientMargin),
        "unmarginable order rejected pre-trade in the manifest"
    );
    assert!(!sealed.manifest.ordered.contains(&taker_hash), "never sequenced");
    assert!(s.state.conservation_holds());
    assert!(s.state.position(&word_u64(3), 0).is_none_or(|p| p.size == 0));
    // the maker (well-funded) rested fine and got a receipt
    assert!(sealed.receipts.iter().any(|r| r.verify()));
}

#[test]
fn maintenance_liquidates_underwater_position() {
    let mut s = setup();
    // A short 1 BTC, B long 1 BTC at $100k (each funded $20k, $10k initial).
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    assert_eq!(s.state.position(&word_u64(2), 0).unwrap().size, SIZE_SCALE);

    // price crashes to $84k → B (long) equity ~$4k < ~$4.2k maintenance.
    s.set_oracle(0, oracle(84_000, 5_000));
    let sealed = s.seal_batch(&[], 5_000);

    assert!(sealed.liquidations.contains(&word_u64(2)), "long B liquidated");
    assert!(!sealed.liquidations.contains(&word_u64(1)), "short A healthy");
    assert_eq!(s.state.position(&word_u64(2), 0).unwrap().size, 0, "B closed");
    assert!(s.state.insurance_fund > 0, "liquidation fee funded insurance");
    assert!(s.state.conservation_holds());
}

#[test]
fn honest_flow_has_no_inclusion_violations() {
    let mut s = setup();
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    assert!(s.inclusion_violations(1).is_empty());
}

#[test]
fn withheld_order_becomes_inclusion_violation() {
    let mut s = setup();
    // user's order is ACCEPTED (receipt issued) ...
    let withheld = order(1, Side::Buy, SIZE_SCALE, 99_000 * PRICE_SCALE, 99);
    let r = s.accept_order(&withheld, 1_000);
    assert!(r.verify());
    let oh = withheld.order_hash::<Keccak256>();

    // ... but the sequencer seals batches WITHOUT ever including it (censorship)
    for _ in 0..3 {
        s.seal_batch(&[], 2_000);
    }
    // after the inclusion timeout, the withheld order surfaces as a violation
    let violations = s.inclusion_violations(2);
    assert!(violations.contains(&oh), "withheld order must be flagged for slashing");

    // had it been included, no violation
    let mut s2 = setup();
    let included = order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1);
    s2.seal_batch(&[included], 1_000);
    assert!(s2.inclusion_violations(0).is_empty());
}
