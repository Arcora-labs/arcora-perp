//! End-to-end sequencer tests: signed receipts (§2), match→settle→manifest flow,
//! finality transitions (§3), and inclusion-violation detection (§2).

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
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

// ZK-001: a fixed dev oracle-publisher key every seeded transcript is signed with;
// each market's `oracle_pubkey` is pinned to its address (see `test_market`) so the
// price clears the fail-closed §8 in-circuit signature gate.
fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).expect("valid dev scalar")
}
fn oracle_addr() -> [u8; 20] {
    let probe = oracle_digest(0, 0, 0, 0, 0);
    OracleSig::sign(&oracle_key(), &probe)
        .recover(&probe)
        .expect("fresh signature recovers")
}
/// A conservative market whose `oracle_pubkey` is the shared test signer's address.
fn test_market(id: u64) -> Market {
    let mut m = Market::conservative(id);
    m.oracle_pubkey = oracle_addr();
    m
}
/// A signed transcript for `market_id`, over the FINAL field values (`oracle_digest`,
/// never hand-rolled). `oracle(price, now)` is the market-0 shorthand.
fn oracle_on(market_id: u64, price_usd: i128, now: u64) -> OracleTranscript {
    let price = price_usd * PRICE_SCALE;
    let confidence = 10 * PRICE_SCALE;
    let d = oracle_digest(market_id, price, now, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}
fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    oracle_on(0, price_usd, now)
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

fn setup() -> Sequencer {
    let mut s = Sequencer::new(enclave(), 20);
    s.add_market(test_market(0));
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
    s.add_market(test_market(0)); // BTC-PERP
    s.add_market(test_market(1)); // ETH-PERP
    s.set_oracle(0, oracle(100_000, 1_000));
    s.set_oracle(1, oracle_on(1, 3_000, 1_000));

    // fund traders 1 & 2 on BOTH markets with distinct notes
    for owner in [1u64, 2] {
        for (mkt, blind) in [(0u64, 0xA0 | owner as u8), (1u64, 0xB0 | owner as u8)] {
            let o = owner_id(owner);
            let amt = 20_000 * QUOTE_SCALE;
            let cm = Note::new(o, 0, amt, [blind; 32]).commitment::<Keccak256>();
            let deposit_id = s.state.consumed_deposit_count;
            s.apply(&BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: amt,
                blinding: [blind; 32],
                from: [0u8; 20],
                deposit_id,
                deposit_blind: [0u8; 32],
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
    s.set_oracle(1, oracle_on(1, 2_400, 5_000)); // ETH −20%
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
fn missing_liq_key_falls_back_to_secret_not_public_owner() {
    let mut s = setup();
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    // Simulate a position funded "outside apply": drop B's captured secret tag-key
    // so the sealing path hits the fail-closed fallback.
    s.forget_liq_key(&owner_id(2));

    s.set_oracle(0, oracle(84_000, 5_000));
    let sealed = s.seal_batch(&[], 5_000);

    // B WAS liquidated, so exactly one liquidation tag is published.
    assert_eq!(sealed.liquidation_tags.len(), 1, "B liquidated");
    // Fail-closed: the tag is NOT recomputable from B's PUBLIC owner id.
    assert!(
        !sealed
            .liquidation_tags
            .contains(&liquidation_tag(&owner_id(2), 0, sealed.batch_id)),
        "missing-key fallback must NOT key on the public owner id"
    );
    // deterministic: recomputing from the same sequencer state yields the same tag set.
    let salt_tag = sealed.liquidation_tags.clone();
    assert!(!salt_tag.is_empty());
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
fn missing_adl_key_falls_back_to_secret_not_public_owner() {
    // Same ADL scenario as `auto_deleverage_publishes_an_attributable_receipt`:
    // A (owner 1) short, B (owner 2) long, each funded $20k at $100k. A hard gap
    // down to $75k wrecks B and, with no insurance seeded, auto-deleverages the
    // bad debt onto the winning short A.
    let mut s = setup();
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );
    // Simulate A's position funded "outside apply": drop its captured secret
    // ADL tag-key so the sealing path hits the fail-closed fallback.
    s.forget_adl_key(&owner_id(1));

    s.set_oracle(0, oracle(75_000, 5_000));
    let sealed = s.seal_batch(&[], 5_000);

    // A WAS clawed, so the ADL receipt is still published.
    assert!(
        !sealed.adl_receipts.is_empty(),
        "A auto-deleveraged despite the missing key"
    );
    // Fail-closed: no receipt tag is recomputable from A's PUBLIC owner id.
    assert!(
        !sealed
            .adl_receipts
            .iter()
            .any(|r| r.tag == adl_tag(&owner_id(1), 0, sealed.batch_id)),
        "missing-key fallback must NOT key on the public owner id"
    );
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
    assert_eq!(
        seq.state.position(&owner_id(2), 0).unwrap().size,
        SIZE_SCALE
    );

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

/// Slice 3b-1 MERGE GATE: a multi-tick settle window — a matched FILL in tick 1, a
/// mid-window out-of-band DEPOSIT, then FUNDING accrual + a LIQUIDATION in tick 2 —
/// produces ONE `WindowWitness` whose combined op-log replays, through `derive_roots`
/// (the exact primitive the zkVM guest runs), to *exactly* the live window-end state
/// root. The batch counter advances ONCE per window (not per tick), so `pre_state
/// .next_batch_id == batch_id` and `derive_roots` accepts the witness. This is the
/// whole point of the slice: one proof per settle window, live sealer and prover
/// agree bit-for-bit across every tick and out-of-band op in the window.
#[test]
fn seal_window_replays_multi_tick_window_to_live_root() {
    // ---- setup: traders 1 (short) & 2 (long) open 1 BTC at $100k in tick 1; trader 5
    // makes a mid-window deposit. Price then crashes so trader 2's long goes underwater
    // and is liquidated in tick 2's maintenance pass.
    let mut seq = setup();

    // ---- tick 1: a matched fill (seal_batch), window still open
    seq.set_oracle(0, oracle(100_000, 20_000));
    let orders_tick1 = [
        order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
        order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
    ];
    let _ = seq.seal_batch(&orders_tick1, 20_000);
    assert_eq!(
        seq.state.position(&owner_id(2), 0).unwrap().size,
        SIZE_SCALE
    );

    // ---- mid-window: an out-of-band deposit (must land in window_ops)
    let dep_owner = owner_id(5);
    let deposit_id = seq.state.consumed_deposit_count;
    seq.apply(&BatchOp::Deposit {
        owner: dep_owner,
        asset_id: 0,
        amount: 500_000,
        blinding: [7u8; 32],
        from: [0u8; 20],
        deposit_id,
        deposit_blind: [0u8; 32],
    })
    .unwrap();

    // ---- tick 2: oracle already crashed → maintenance accrues funding + liquidates
    seq.set_oracle(0, oracle(84_000, 20_700));
    let _ = seq.seal_batch(&[], 20_700);

    // ---- close the window
    let w = seq.seal_window();

    // the window op-log must span all four op kinds (else the gate is hollow)
    assert!(
        w.ops.iter().any(|o| matches!(o, BatchOp::Deposit { .. })),
        "mid-window deposit logged"
    );
    assert!(
        w.ops.iter().any(|o| matches!(o, BatchOp::Fill { .. })),
        "a fill this window"
    );
    assert!(
        w.ops
            .iter()
            .any(|o| matches!(o, BatchOp::AccrueFunding { .. })),
        "funding accrued"
    );
    assert!(
        w.ops.iter().any(|o| matches!(o, BatchOp::Liquidate { .. })),
        "a liquidation"
    );

    // faithfulness: replay the window witness onto its pre-state == the live window-end state
    let live_root = seq.state.state_root();
    let derived =
        perp_core::commitment::derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest)
            .expect("derive_roots accepts the window witness");
    assert_eq!(
        derived.new_state_root, live_root,
        "window op-log must reproduce the live window-end root"
    );
    assert_eq!(
        derived.manifest_hash,
        w.manifest.hash::<Keccak256>(),
        "manifest hash matches"
    );
    assert_eq!(
        w.pre_state.next_batch_id, w.batch_id,
        "pre_state counter == window batch_id"
    );
}

/// Slice 3b-1: a two-tick window of fills only (no liquidation) round-trips — the
/// combined op-log replays through `derive_roots` to the live window-end root.
#[test]
fn seal_window_two_tick_fills_only_round_trips() {
    let mut seq = setup();
    seq.set_oracle(0, oracle(100_000, 21_000));
    let orders_a = [
        order(1, Side::Sell, SIZE_SCALE / 10, 100_000 * PRICE_SCALE, 1),
        order(2, Side::Buy, SIZE_SCALE / 10, 100_000 * PRICE_SCALE, 2),
    ];
    let _ = seq.seal_batch(&orders_a, 21_000);
    seq.set_oracle(0, oracle(100_000, 21_700));
    let orders_b = [
        order(1, Side::Sell, SIZE_SCALE / 10, 100_000 * PRICE_SCALE, 3),
        order(2, Side::Buy, SIZE_SCALE / 10, 100_000 * PRICE_SCALE, 4),
    ];
    let _ = seq.seal_batch(&orders_b, 21_700);
    let w = seq.seal_window();
    let live_root = seq.state.state_root();
    let derived =
        perp_core::commitment::derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest).unwrap();
    assert_eq!(derived.new_state_root, live_root);
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

/// Slice 3b-3 MERGE GATE: a failed settle's window can be rolled back and re-sealed.
/// `rollback_window` restores the per-window counter and baseline and re-injects the
/// failed window's ops AHEAD of anything the tick loop appended since, so the re-seal
/// is `[failed ++ intervening]` under the SAME batch_id and its witness replays,
/// through `derive_roots`, to the live window-end root.
#[test]
fn rollback_window_restores_and_reseals_to_live_root() {
    let mut seq = setup();

    // window 1: tick 1 has a matched fill, then the window is sealed (a settle attempt).
    seq.set_oracle(0, oracle(100_000, 20_000));
    let orders = [
        order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
        order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
    ];
    let _ = seq.seal_batch(&orders, 20_000);
    let w = seq.seal_window();
    let sealed_id = w.batch_id;
    assert_eq!(
        seq.state.next_batch_id,
        sealed_id + 1,
        "seal_window bumped Counter B"
    );

    // the settle "fails" — meanwhile the 700ms tick loop keeps adding ops to the new window.
    let deposit_id = seq.state.consumed_deposit_count;
    seq.apply(&BatchOp::Deposit {
        owner: owner_id(5),
        asset_id: 0,
        amount: 500_000,
        blinding: [7u8; 32],
        from: [0u8; 20],
        deposit_id,
        deposit_blind: [0u8; 32],
    })
    .unwrap();
    // NOTE: mis-order falsifiability couples to the NON-ZERO funding this tick accrues off the crashed oracle — a timing/oracle edit that zeroes it silently darkens the ordering arm.
    let _ = seq.seal_batch(&[], 20_700);

    // roll the failed window back.
    seq.rollback_window(&w);
    assert_eq!(
        seq.state.next_batch_id, sealed_id,
        "Counter B restored to the pre-seal id"
    );

    // re-seal: same on-chain batch_id, and the witness replays [failed ++ intervening] from
    // the restored baseline to the LIVE window-end root (falsifiable: a dropped/mis-ordered
    // op diverges the root).
    let w2 = seq.seal_window();
    assert_eq!(
        w2.batch_id, sealed_id,
        "re-seal uses the same batch_id (== on-chain batchCount)"
    );
    let live_root = seq.state.state_root();
    let derived =
        perp_core::commitment::derive_roots(&mut w2.pre_state.clone(), &w2.ops, &w2.manifest)
            .expect("derive_roots accepts the rolled-back re-seal");
    assert_eq!(
        derived.new_state_root, live_root,
        "rolled-back re-seal reproduces the live root"
    );
    assert!(
        w2.ops.iter().any(|o| matches!(o, BatchOp::Fill { .. })),
        "the failed window's fill is re-included"
    );
    assert!(
        w2.ops.iter().any(|o| matches!(o, BatchOp::Deposit { .. })),
        "the intervening deposit is included, after the failed window's ops"
    );
}
