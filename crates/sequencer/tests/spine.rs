//! End-to-end sequencer tests: signed receipts (§2), match→settle→manifest flow,
//! finality transitions (§3), and inclusion-violation detection (§2).

use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::oracle::OracleTranscript;
use perp_core::order::{Finality, Order, Side, TimeInForce};
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
    seq.apply(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount,
        blinding: [blind; 32],
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

fn setup() -> Sequencer {
    let mut s = Sequencer::new(enclave(), 20);
    s.add_market(Market::conservative(0));
    s.set_oracle(0, oracle(100_000, 1_000));
    fund(&mut s, 1, 20_000, 0x11);
    fund(&mut s, 2, 20_000, 0x22);
    s
}

fn order_m(owner: u64, market: u64, side: Side, size: i128, price: i128, nonce: u64) -> Order {
    let mut o = order(owner, side, size, price, nonce);
    o.market_id = market;
    o
}

#[test]
fn multi_market_positions_are_isolated() {
    let mut s = Sequencer::new(enclave(), 20);
    s.add_market(Market::conservative(0)); // BTC-PERP
    s.add_market(Market::conservative(1)); // ETH-PERP
    s.set_oracle(0, oracle(100_000, 1_000));
    s.set_oracle(1, oracle(3_000, 1_000));

    // fund traders 1 & 2 on BOTH markets with distinct notes
    for owner in [1u64, 2] {
        for (mkt, blind) in [(0u64, 0xA0 | owner as u8), (1u64, 0xB0 | owner as u8)] {
            let o = word_u64(owner);
            let amt = 20_000 * QUOTE_SCALE;
            let cm = Note::new(o, 0, amt, [blind; 32]).commitment::<Keccak256>();
            s.apply(&BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: amt,
                blinding: [blind; 32],
            })
            .unwrap();
            s.apply(&BatchOp::FundPosition {
                owner: o,
                market_id: mkt,
                note_commitment: cm,
                spend_key: [owner as u8; 32],
            })
            .unwrap();
        }
    }

    // trade on BOTH markets in one batch
    let sealed = s.seal_batch(
        &[
            order_m(1, 0, Side::Buy, SIZE_SCALE / 10, 100_000 * PRICE_SCALE, 1),
            order_m(2, 0, Side::Sell, SIZE_SCALE / 10, 100_000 * PRICE_SCALE, 2),
            order_m(1, 1, Side::Sell, SIZE_SCALE, 3_000 * PRICE_SCALE, 3),
            order_m(2, 1, Side::Buy, SIZE_SCALE, 3_000 * PRICE_SCALE, 4),
        ],
        1_000,
    );
    assert!(sealed.settlement_rejected.is_empty());

    // positions are isolated per market: trader 1 long BTC, short ETH; 2 opposite
    assert_eq!(
        s.state.position(&word_u64(1), 0).unwrap().size,
        SIZE_SCALE / 10
    );
    assert_eq!(s.state.position(&word_u64(1), 1).unwrap().size, -SIZE_SCALE);
    assert_eq!(
        s.state.position(&word_u64(2), 0).unwrap().size,
        -SIZE_SCALE / 10
    );
    assert_eq!(s.state.position(&word_u64(2), 1).unwrap().size, SIZE_SCALE);
    assert!(s.state.conservation_holds());

    // an ETH-only price move must not touch BTC positions
    s.set_oracle(1, oracle(2_400, 5_000)); // ETH −20%
    s.seal_batch(&[], 5_000);
    assert_eq!(
        s.state.position(&word_u64(1), 0).unwrap().size,
        SIZE_SCALE / 10,
        "BTC unaffected by ETH move"
    );
    assert_eq!(
        s.state.position(&word_u64(2), 0).unwrap().size,
        -SIZE_SCALE / 10,
        "BTC unaffected by ETH move"
    );
    assert!(s.state.conservation_holds());
}

#[test]
fn receipt_is_signed_and_verifies() {
    let mut s = setup();
    let r = s.accept_order(
        &order(1, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
        1_000,
    );
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
    assert_ne!(
        sealed.prev_state_root, sealed.new_state_root,
        "state advanced"
    );
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

    assert!(
        sealed.settlement_rejected.is_empty(),
        "no match-but-unsettleable fills"
    );
    assert!(
        sealed
            .manifest
            .rejected
            .iter()
            .any(|(h, r)| *h == taker_hash
                && *r == perp_core::order::RejectReason::InsufficientMargin),
        "unmarginable order rejected pre-trade in the manifest"
    );
    assert!(
        !sealed.manifest.ordered.contains(&taker_hash),
        "never sequenced"
    );
    assert!(s.state.conservation_holds());
    assert!(s
        .state
        .position(&word_u64(3), 0)
        .is_none_or(|p| p.size == 0));
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

    assert!(
        sealed.liquidations.contains(&word_u64(2)),
        "long B liquidated"
    );
    assert!(
        !sealed.liquidations.contains(&word_u64(1)),
        "short A healthy"
    );
    assert_eq!(
        s.state.position(&word_u64(2), 0).unwrap().size,
        0,
        "B closed"
    );
    assert!(
        s.state.insurance_fund > 0,
        "liquidation fee funded insurance"
    );
    assert!(s.state.conservation_holds());
}

#[test]
fn liquidation_cancels_resting_orders() {
    // A liquidated owner's resting orders are cancelled, so they can't fill later
    // as a bad-debt account and fail to settle (the maker-drift fix).
    let mut s = setup();
    // trader 2 goes long 1 BTC and also rests a (reducing) sell 0.1 @ $120k.
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
            order(2, Side::Sell, SIZE_SCALE / 10, 120_000 * PRICE_SCALE, 3),
        ],
        1_000,
    );
    assert_eq!(
        s.book(0).unwrap().resting_size(Side::Sell),
        SIZE_SCALE / 10,
        "ask resting"
    );

    // crash → trader 2 (long) is liquidated; its resting ask must be cancelled.
    s.set_oracle(0, oracle(84_000, 5_000));
    let sealed = s.seal_batch(&[], 5_000);
    assert!(sealed.liquidations.contains(&word_u64(2)));
    assert_eq!(
        s.book(0).unwrap().resting_size(Side::Sell),
        0,
        "resting order cancelled on liquidation"
    );
}

/// The manifest's ordered set and rejected set must never overlap (§2).
fn assert_disjoint(sealed: &sequencer::SealedBatch) {
    for (h, _) in &sealed.manifest.rejected {
        assert!(
            !sealed.manifest.ordered.contains(h),
            "ordered/rejected must be disjoint"
        );
    }
    // every settled order must be in `ordered`
    for h in &sealed.settled_order_hashes {
        assert!(
            sealed.manifest.ordered.contains(h),
            "settled order must be ordered"
        );
    }
}

#[test]
fn manifest_ordered_rejected_disjoint_invariant() {
    let mut s = setup();
    fund(&mut s, 3, 1_000, 0x33); // underfunded → pre-trade reject
    let sealed = s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
            order(3, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 3), // rejected
        ],
        1_000,
    );
    assert_disjoint(&sealed);
}

#[test]
fn accept_then_seal_keeps_one_seq() {
    // accept_order issues a receipt; sealing the SAME order must reuse the seq and
    // not emit a divergent second receipt seq (the accept_order seq fix).
    let mut s = setup();
    let o = order(1, Side::Buy, SIZE_SCALE, 99_000 * PRICE_SCALE, 7);
    let r1 = s.accept_order(&o, 1_000);
    let sealed = s.seal_batch(&[o], 1_000);
    let r2 = sealed
        .receipts
        .iter()
        .find(|r| r.receipt.order_hash == o.order_hash::<Keccak256>())
        .unwrap();
    assert_eq!(
        r1.receipt.seq_no, r2.receipt.seq_no,
        "one stable seq across accept + seal"
    );
    assert!(r1.verify() && r2.verify());
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
fn failed_batch_rolls_back_to_hard_state() {
    // §3 failure matrix: a sealed batch that fails to prove is rolled back — state
    // reverts, and its fills go from MATCHED back to ACCEPTED (never binding).
    let mut s = setup();
    let (a, b) = (word_u64(1), word_u64(2));

    // batch 0: open positions, then prove it (hard).
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    s.mark_settled(0);
    let hard_root = s.state.state_root();
    let a_size_hard = s.state.position(&a, 0).unwrap().size;

    // batch 1: more trading (provisional / MATCHED).
    let o_taker = order(2, Side::Sell, SIZE_SCALE / 2, 100_000 * PRICE_SCALE, 3);
    let sealed1 = s.seal_batch(
        &[
            order(1, Side::Buy, SIZE_SCALE / 2, 100_000 * PRICE_SCALE, 4),
            o_taker,
        ],
        2_000,
    );
    assert_ne!(
        s.state.state_root(),
        hard_root,
        "batch 1 advanced the live state"
    );
    let th = o_taker.order_hash::<Keccak256>();
    assert_eq!(s.finality_of(&th), Some(Finality::Matched));

    // batch 1 fails to prove → rollback.
    assert!(s.mark_failed(sealed1.batch_id));
    assert_eq!(
        s.state.state_root(),
        hard_root,
        "state reverted to last hard root"
    );
    assert_eq!(
        s.state.position(&a, 0).unwrap().size,
        a_size_hard,
        "positions reverted"
    );
    assert_eq!(
        s.finality_of(&th),
        Some(Finality::Accepted),
        "matched fill reverted to accepted"
    );
    assert!(s.state.conservation_holds());
    let _ = b;

    // re-sequencing resumes from the failed batch id.
    assert_eq!(s.current_batch_id(), sealed1.batch_id);
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
    assert!(
        violations.contains(&oh),
        "withheld order must be flagged for slashing"
    );

    // had it been included, no violation
    let mut s2 = setup();
    let included = order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1);
    s2.seal_batch(&[included], 1_000);
    assert!(s2.inclusion_violations(0).is_empty());
}

#[test]
fn rejected_for_cause_is_not_an_inclusion_violation() {
    // An order ACCEPTED (receipt issued) but then justly REJECTED at seal must NOT
    // be flagged as withheld: the enclave handled it (it is in manifest.rejected,
    // bound by manifest_hash), so flagging it would slash an honest sequencer.
    let mut s = setup();
    // owner 5 has no collateral → pre-trade margin check rejects this open order
    let bad = order(5, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 7);
    let oh = bad.order_hash::<Keccak256>();
    let r = s.accept_order(&bad, 1_000); // instant ACCEPTED ack → inclusion record
    assert!(r.verify());

    let sealed = s.seal_batch(&[bad], 1_000);
    // it was rejected, not ordered
    assert!(sealed.manifest.rejected.iter().any(|(h, _)| *h == oh));
    assert!(!sealed.manifest.ordered.contains(&oh));

    // even far past the timeout, a rejected-for-cause order is NOT a violation
    for _ in 0..3 {
        s.seal_batch(&[], 2_000);
    }
    assert!(
        !s.inclusion_violations(1).contains(&oh),
        "a justified rejection must not be mistaken for censorship"
    );
}
