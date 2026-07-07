//! End-to-end sequencer tests: signed receipts (§2), match→settle→manifest flow,
//! finality transitions (§3), and inclusion-violation detection (§2).

use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::OracleTranscript;
use perp_core::order::{Finality, Order, RejectReason, Side, TimeInForce};
use perp_core::Note;
use sequencer::{
    adl_tag, adl_tag_key, liquidation_tag, liquidation_tag_key, EnclaveIdentity, Sequencer,
};

fn enclave() -> EnclaveIdentity {
    EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32])
}

/// Trader `owner`'s spend key. Trader `n` funds/spends its notes with `[n; 32]`.
fn spend_key(owner: u64) -> [u8; 32] {
    [owner as u8; 32]
}

/// Trader `owner`'s public owner id, derived from its spend key (audit DP-003:
/// a note's `owner` MUST equal `owner_from_spend_key(&spend_key)`). Used wherever
/// the account is named: notes, deposits, positions, orders, and assertions.
fn owner_id(owner: u64) -> PubKey {
    owner_from_spend_key::<Keccak256>(&spend_key(owner))
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
        owner: owner_id(owner),
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
    let o = owner_id(owner);
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
            let o = owner_id(owner);
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
        s.state.position(&owner_id(1), 0).unwrap().size,
        SIZE_SCALE / 10
    );
    assert_eq!(s.state.position(&owner_id(1), 1).unwrap().size, -SIZE_SCALE);
    assert_eq!(
        s.state.position(&owner_id(2), 0).unwrap().size,
        -SIZE_SCALE / 10
    );
    assert_eq!(s.state.position(&owner_id(2), 1).unwrap().size, SIZE_SCALE);
    assert!(s.state.conservation_holds());

    // an ETH-only price move must not touch BTC positions
    s.set_oracle(1, oracle(2_400, 5_000)); // ETH −20%
    s.seal_batch(&[], 5_000);
    assert_eq!(
        s.state.position(&owner_id(1), 0).unwrap().size,
        SIZE_SCALE / 10,
        "BTC unaffected by ETH move"
    );
    assert_eq!(
        s.state.position(&owner_id(2), 0).unwrap().size,
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
    assert_eq!(s.state.position(&owner_id(2), 0).unwrap().size, SIZE_SCALE);
    assert_eq!(s.state.position(&owner_id(1), 0).unwrap().size, -SIZE_SCALE);
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
        .position(&owner_id(3), 0)
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
    assert_eq!(s.state.position(&owner_id(2), 0).unwrap().size, SIZE_SCALE);

    // price crashes to $84k → B (long) equity ~$4k < ~$4.2k maintenance.
    s.set_oracle(0, oracle(84_000, 5_000));
    let sealed = s.seal_batch(&[], 5_000);

    // B detects its own liquidation by recomputing its tag from its SECRET key
    // (derived from B's spend key [2u8;32]), not from its public owner id.
    let b_key = liquidation_tag_key(&[2u8; 32]);
    assert!(
        sealed
            .liquidation_tags
            .contains(&liquidation_tag(&b_key, 0, sealed.batch_id)),
        "long B liquidated (detectable by B's own secret tag)"
    );
    assert!(
        !sealed.liquidation_tags.contains(&liquidation_tag(
            &liquidation_tag_key(&[1u8; 32]),
            0,
            sealed.batch_id
        )),
        "short A healthy"
    );
    // Privacy: an observer who knows only B's PUBLIC owner id cannot find B —
    // neither the raw owner nor a tag keyed on the public owner id is present.
    assert!(
        !sealed.liquidation_tags.contains(&owner_id(2)),
        "the published batch exposes a tag, not the account"
    );
    assert!(
        !sealed
            .liquidation_tags
            .contains(&liquidation_tag(&owner_id(2), 0, sealed.batch_id)),
        "a tag keyed on the public owner id must NOT match — the tag is secret-keyed"
    );
    assert_eq!(
        s.state.position(&owner_id(2), 0).unwrap().size,
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
fn auto_deleverage_publishes_an_attributable_receipt() {
    // A (owner 1) short 1 BTC, B (owner 2) long 1 BTC at $100k, each funded $20k.
    // A hard gap down to $75k wrecks B (long): a $25k loss past its $20k collateral
    // is $5k of bad debt. With no insurance seeded, the cascade auto-deleverages it
    // onto the winning short A — and the sealed batch must carry an ADL receipt that
    // A can recognize as ITS OWN haircut, keyed on A's SECRET (audit Q2).
    let mut s = setup();
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );

    s.set_oracle(0, oracle(75_000, 5_000));
    let sealed = s.seal_batch(&[], 5_000);

    // A recomputes its own ADL tag from its secret spend key ([1u8;32]) and finds
    // its haircut + the amount clawed.
    let a_key = adl_tag_key(&[1u8; 32]);
    let a_tag = adl_tag(&a_key, 0, sealed.batch_id);
    let mine = sealed.adl_receipts.iter().find(|r| r.tag == a_tag);
    assert!(
        mine.is_some(),
        "A's ADL haircut is published as a tagged receipt"
    );
    assert!(
        mine.unwrap().clawed > 0,
        "the receipt carries the clawed amount"
    );

    // Privacy: an observer who knows only A's PUBLIC owner id cannot link the
    // receipt — a tag keyed on the public owner id is NOT present.
    assert!(
        !sealed
            .adl_receipts
            .iter()
            .any(|r| r.tag == adl_tag(&owner_id(1), 0, sealed.batch_id)),
        "a tag keyed on the public owner id must NOT match — the tag is secret-keyed"
    );
    // The liquidated B is not a winner and is not clawed.
    assert!(
        !sealed
            .adl_receipts
            .iter()
            .any(|r| r.tag == adl_tag(&adl_tag_key(&[2u8; 32]), 0, sealed.batch_id)),
        "the liquidated long is not auto-deleveraged"
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
    assert!(sealed.liquidation_tags.contains(&liquidation_tag(
        &liquidation_tag_key(&[2u8; 32]),
        0,
        sealed.batch_id
    )));
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
    let (a, b) = (owner_id(1), owner_id(2));

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

#[test]
fn marking_a_height_settled_finalizes_every_prior_pending_batch() {
    // A proof for batch N attests the state transition *through* batch N, and
    // mark_settled(N) prunes the rollback snapshots for batch N AND everything
    // before it — they become un-rollback-able (hard). §3 says a hard fill is
    // SETTLED (withdrawable). So finalizing a height must drag every earlier
    // still-pending batch to SETTLED too, not strand it at MATCHED.
    let mut s = setup();

    // batch 0: a crossing pair → MATCHED
    let t0 = order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2);
    let b0 = s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            t0,
        ],
        1_000,
    );
    let t0_hash = t0.order_hash::<Keccak256>();
    assert_eq!(s.finality_of(&t0_hash), Some(Finality::Matched));

    // batch 1: another crossing pair → MATCHED
    let t1 = order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 4);
    let b1 = s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 3),
            t1,
        ],
        2_000,
    );
    let t1_hash = t1.order_hash::<Keccak256>();
    assert_eq!(s.finality_of(&t1_hash), Some(Finality::Matched));

    // a single proof finalizes the chain THROUGH batch 1 (skipping a per-batch
    // mark_settled(0)). Batch 0 must not be left behind.
    assert_eq!(b0.batch_id, 0);
    assert_eq!(b1.batch_id, 1);
    s.mark_settled(b1.batch_id);

    assert_eq!(
        s.finality_of(&t1_hash),
        Some(Finality::Settled),
        "the proven height itself settles"
    );
    assert_eq!(
        s.finality_of(&t0_hash),
        Some(Finality::Settled),
        "an earlier batch made hard by the same proof must also settle, not strand at MATCHED"
    );
}

#[test]
fn maintenance_reaps_expired_makers_so_they_do_not_anchor_the_mark() {
    // A resting maker with a good-till-time bound must be reaped once the batch
    // clock passes its expiry, so it stops showing as best_ask / anchoring the
    // funding mark (§8). run_maintenance (called every seal_batch) does the reap.
    let mut s = setup();

    // owner 1 rests a lone sell with expiry=1_500 (no crossing bid → it rests).
    // The setup oracle is published at t=1_000, so seal at/after that or the
    // freshness gate (§8) would reject the order.
    let mut maker = order(1, Side::Sell, SIZE_SCALE / 10, 100_000 * PRICE_SCALE, 1);
    maker.expiry_ms = 1_500;
    let sealed = s.seal_batch(&[maker], 1_000);
    assert_eq!(
        sealed.manifest.ordered.len(),
        1,
        "maker rested into the book"
    );
    assert_eq!(
        s.book(0).unwrap().best_ask(),
        Some(100_000 * PRICE_SCALE),
        "expired-to-be maker is the best ask while still live"
    );

    // a later, empty batch whose clock is past the maker's expiry (refresh the
    // oracle so the batch itself isn't gated on staleness)
    s.set_oracle(0, oracle(100_000, 2_000));
    s.seal_batch(&[], 2_000);
    assert_eq!(
        s.book(0).unwrap().best_ask(),
        None,
        "the expired maker was reaped and no longer anchors best_ask / the mark"
    );
}

// audit DP-009: a reduce_only order may only SHRINK its owner's position, never open or
// grow it. Enforced at settlement — a reduce_only fill that would increase exposure is
// rejected (dropped), so the position never opens.
#[test]
fn reduce_only_order_cannot_open_a_position() {
    let mut s = setup();
    // trader 2 is flat; a reduce_only BUY would OPEN a long. trader 1 rests a Sell.
    let maker = order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1);
    let mut taker = order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2);
    taker.reduce_only = true;
    let taker_hash = taker.order_hash::<Keccak256>();
    let maker_hash = maker.order_hash::<Keccak256>();
    let sealed = s.seal_batch(&[maker, taker], 1_000);

    // trader 2 stays flat
    assert!(
        s.state
            .position(&owner_id(2), 0)
            .is_none_or(|p| p.size == 0),
        "a reduce_only order must not open a position",
    );
    // the reduce_only order is rejected as a reduce_only violation…
    assert!(
        sealed
            .manifest
            .rejected
            .iter()
            .any(|(h, r)| *h == taker_hash && *r == RejectReason::ReduceOnlyViolation),
        "the opening reduce_only order is rejected as a reduce_only violation",
    );
    // …the innocent counterparty is NOT tagged, and its resting liquidity is preserved
    // (adversarial-review follow-up: rejecting before matching must not consume the maker).
    assert!(
        !sealed
            .manifest
            .rejected
            .iter()
            .any(|(h, _)| *h == maker_hash),
        "the innocent counterparty is not tagged rejected",
    );
    assert_eq!(
        s.book(0).unwrap().best_ask(),
        Some(100_000 * PRICE_SCALE),
        "the counterparty's resting order survives, not destroyed",
    );
}

#[test]
fn reduce_only_order_may_shrink_a_position() {
    let mut s = setup();
    // batch 0: trader 2 opens a long (not reduce_only)
    let m0 = order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1);
    let t0 = order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2);
    s.seal_batch(&[m0, t0], 1_000);
    assert_eq!(
        s.state.position(&owner_id(2), 0).unwrap().size,
        SIZE_SCALE,
        "opened long"
    );
    // batch 1: trader 2 submits a reduce_only SELL that shrinks the long — allowed
    let m1 = order(1, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 3);
    let mut t1 = order(2, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 4);
    t1.reduce_only = true;
    let sealed = s.seal_batch(&[m1, t1], 2_000);
    assert_eq!(
        sealed.settlement_rejected,
        vec![],
        "a reducing reduce_only order settles"
    );
    assert!(
        s.state
            .position(&owner_id(2), 0)
            .is_none_or(|p| p.size == 0),
        "the long is closed by the reduce_only sell",
    );
}

#[test]
fn reduce_only_behind_an_earlier_same_batch_order_is_rejected() {
    // audit DP-009 review: a reduce_only order whose owner already has an earlier order this
    // batch is rejected at admission — its position could shift intra-batch (via that earlier
    // order's fill) and open at settlement, where the drop would consume an innocent maker.
    let mut s = setup();
    // trader 2 opens a long first
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    // batch 1: trader 2 submits a normal order and then a reduce_only order (same market)
    let first = order(2, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 3);
    let mut ro = order(2, Side::Sell, SIZE_SCALE / 2, 100_000 * PRICE_SCALE, 4);
    ro.reduce_only = true;
    let ro_hash = ro.order_hash::<Keccak256>();
    let sealed = s.seal_batch(&[first, ro], 2_000);
    assert!(
        sealed
            .manifest
            .rejected
            .iter()
            .any(|(h, r)| *h == ro_hash && *r == RejectReason::ReduceOnlyViolation),
        "the reduce_only order behind an earlier same-batch order is rejected up front",
    );
}

/// Slice 3a: `run_maintenance` must emit the exact `AccrueFunding`/`Liquidate` ops it
/// applies, in application order — the maintenance half of the batch's replayable
/// op-log. Replaying those ops onto the pre-maintenance state must reproduce the
/// maintenance state transition (funding accrual + liquidation + ADL cascade).
#[test]
fn run_maintenance_ops_replay_reproduces_state() {
    // ---- setup (adapted from `maintenance_liquidates_underwater_position`): a
    // sequencer whose state holds an OPEN long that is underwater at the current
    // oracle. A (owner 1) short 1 BTC, B (owner 2) long 1 BTC at $100k, each funded
    // $20k. A crash to $84k puts B (long) below maintenance margin.
    let mut seq = setup();
    seq.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    assert_eq!(seq.state.position(&owner_id(2), 0).unwrap().size, SIZE_SCALE);

    let now_ms = 5_000;
    seq.set_oracle(0, oracle(84_000, now_ms));

    // snapshot the pre-maintenance state so we can replay the emitted ops onto it
    let pre = seq.state.clone();

    // ---- act
    let outcome = seq.run_maintenance(now_ms);

    // ---- the ops must cover funding AND liquidation (else the gate proves nothing)
    assert!(
        outcome
            .ops
            .iter()
            .any(|o| matches!(o, BatchOp::AccrueFunding { .. })),
        "maintenance must emit AccrueFunding"
    );
    assert!(
        outcome
            .ops
            .iter()
            .any(|o| matches!(o, BatchOp::Liquidate { .. })),
        "the scenario must actually liquidate a position"
    );

    // ---- faithfulness: replaying the emitted ops onto the pre-state reproduces
    // exactly what run_maintenance did to the live state.
    let mut replay = pre;
    replay.apply_batch(&outcome.ops).expect("replay applies");
    // `apply_batch` is the guest's whole-batch primitive: it advances the per-batch
    // counter exactly once. `run_maintenance` is a SUB-step of a batch (its ops are the
    // tail of the full batch op-log the guest replays), so it legitimately leaves the
    // counter untouched. That counter is batch bookkeeping, not part of the maintenance
    // transition — assert the one expected delta, then align it so the state_root
    // comparison isolates the transition the ops actually encode (positions, funding,
    // insurance/vault balances, ...).
    assert_eq!(
        replay.next_batch_id,
        seq.state.next_batch_id + 1,
        "apply_batch advances the per-batch counter exactly once"
    );
    replay.next_batch_id = seq.state.next_batch_id;
    assert_eq!(
        replay.state_root(),
        seq.state.state_root(),
        "emitted maintenance ops must reproduce the maintenance state transition"
    );
}

/// Slice 3a MERGE GATE: a single sealed batch that carries a FILL, a FUNDING accrual
/// AND a LIQUIDATION retains a `(pre_state, ops, manifest)` witness that replays,
/// through `derive_roots` (the exact primitive the zkVM guest runs), to *exactly* the
/// sealed `new_state_root` and `manifest_hash`. This is the whole point of the slice:
/// the live sealer and the prover agree bit-for-bit. Because this is batch 1 (not 0),
/// it also exercises the per-batch `state.next_batch_id` bump — without it,
/// `derive_roots` would reject the witness (`manifest.batch_id != next_batch_id`).
#[test]
fn batch_witness_replays_to_sealed_roots_with_fill_funding_liquidation() {
    // ---- setup: traders 1 (short) & 2 (long) open 1 BTC at $100k in batch 0; traders
    // 3 & 4 are funded so their fresh orders settle a FILL in the liquidation batch.
    let mut seq = setup();
    fund(&mut seq, 3, 20_000, 0x33);
    fund(&mut seq, 4, 20_000, 0x44);
    seq.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    assert_eq!(seq.state.position(&owner_id(2), 0).unwrap().size, SIZE_SCALE);

    // price crashes to $84k → B (long, owner 2) is underwater and is liquidated this
    // batch, while 3 & 4 trade a fresh 0.1 BTC fill at the new mark.
    let now_ms = 5_000;
    seq.set_oracle(0, oracle(84_000, now_ms));
    let orders = [
        order(4, Side::Sell, SIZE_SCALE / 10, 84_000 * PRICE_SCALE, 3),
        order(3, Side::Buy, SIZE_SCALE / 10, 84_000 * PRICE_SCALE, 4),
    ];

    // ---- act
    let sealed = seq.seal_batch(&orders, now_ms);

    // ---- the retained witness
    let (pre_state, ops, manifest) = seq
        .batch_witness(sealed.batch_id)
        .expect("witness retained for a pending batch");

    // the op-log must cover all three op kinds (else the gate is hollow)
    assert!(
        ops.iter().any(|o| matches!(o, BatchOp::Fill { .. })),
        "batch had a fill"
    );
    assert!(
        ops.iter().any(|o| matches!(o, BatchOp::AccrueFunding { .. })),
        "funding accrued"
    );
    assert!(
        ops.iter().any(|o| matches!(o, BatchOp::Liquidate { .. })),
        "a position liquidated"
    );

    // ---- faithfulness: derive_roots over (pre_state, ops, manifest) reproduces
    // exactly what the sealer computed.
    let derived = perp_core::commitment::derive_roots(&mut pre_state.clone(), &ops, &manifest)
        .expect("derive_roots accepts the retained witness");
    assert_eq!(
        derived.new_state_root, sealed.new_state_root,
        "op-log must reproduce new_state_root"
    );
    assert_eq!(
        derived.manifest_hash, sealed.manifest_hash,
        "manifest hash must match"
    );
    assert_eq!(
        derived.prev_state_root, sealed.prev_state_root,
        "pre_state is the batch's prev_state"
    );
}

/// A batch with matching orders but NO maintenance liquidation still round-trips: the
/// fills-only op-log replays through `derive_roots` to the sealed `new_state_root`.
#[test]
fn batch_witness_round_trips_fills_only() {
    let mut seq = setup();
    let orders = [
        order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
        order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
    ];
    let sealed = seq.seal_batch(&orders, 1_000);
    let (pre_state, ops, manifest) = seq.batch_witness(sealed.batch_id).unwrap();
    assert!(
        ops.iter().any(|o| matches!(o, BatchOp::Fill { .. })),
        "batch had a fill"
    );
    let derived =
        perp_core::commitment::derive_roots(&mut pre_state.clone(), &ops, &manifest).unwrap();
    assert_eq!(derived.new_state_root, sealed.new_state_root);
}

/// AUDIT (Tier-3): the manifest reject reason must be honest. An order on an unknown
/// market is not a reduce-only violation — it must be tagged InvalidOrder.
#[test]
fn unknown_market_order_is_tagged_invalid_not_reduce_only() {
    let mut s = setup();
    let mut o = order(1, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 1);
    o.market_id = 99; // only market 0 is registered
    let oh = o.order_hash::<Keccak256>();
    let sealed = s.seal_batch(&[o], 1_000);
    assert!(
        sealed
            .manifest
            .rejected
            .iter()
            .any(|(h, r)| *h == oh && *r == RejectReason::InvalidOrder),
        "an unknown-market order must be tagged InvalidOrder, not ReduceOnlyViolation"
    );
}
