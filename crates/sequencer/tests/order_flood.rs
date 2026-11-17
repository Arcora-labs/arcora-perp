//! Audit 2026-11-16 GA-1 + SM-1 (admission) and SM-3, through the sequencer's
//! own loop (`seal_batch`).
//!
//! GA-1 + SM-1: the pre-trade check looked at each order alone. Nothing summed an
//! account's pending orders, and no account had an open-order cap, so 60 accounts
//! with 10 USDC each kept 22,081 buy orders resting, and every tick then did work
//! over all of them. Now an account keeps at most `PER_MARKET` orders open in one
//! market and `PER_ACCOUNT` across markets, and a new order is admitted only if the
//! account's collateral in the market covers the initial margin of every pending
//! order on the order's side together with the new one. A fill, a cancel, an
//! expiry or a rejection releases what the order held, and an IOC that does not
//! trade holds nothing after its batch.
//!
//! SM-3: 4,096 unfillable dust bids exhausted the funding-mark sweep's order
//! budget, so the mark fell back to the oracle index; the same dust queued behind
//! $50,000 of honest depth at the same price did it too, because the sweep summed a
//! whole price level before it looked at the notional. Now neither moves the mark:
//! it is the mark of the honest depth alone.

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Digest, Keccak256};
use perp_core::market::{Market, MarketId};
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{Order, RejectReason, Side, TimeInForce};
use perp_core::Note;
use sequencer::{
    EnclaveIdentity, OpenOrderLimit, SealedBatch, Sequencer,
    MAX_OPEN_ORDERS_PER_ACCOUNT as PER_ACCOUNT, MAX_OPEN_ORDERS_PER_MARKET as PER_MARKET,
};

/// 0.0001 BTC: $10 at the $100,000 index, the order minimum.
const TEN_DOLLARS: i128 = SIZE_SCALE / 10_000;
/// 0.01 BTC: $1,000 at the index.
const THOUSAND_DOLLARS: i128 = SIZE_SCALE / 100;
const INDEX_USD: i128 = 100_000;

fn enclave() -> EnclaveIdentity {
    EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32])
}

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

fn test_market(id: MarketId) -> Market {
    let mut m = Market::conservative(id);
    m.oracle_pubkey = oracle_addr();
    m
}

/// A transcript for `market` at the $100,000 index, published at `now`.
fn oracle(market: MarketId, now: u64) -> OracleTranscript {
    let price = INDEX_USD * PRICE_SCALE;
    let confidence = 10 * PRICE_SCALE;
    let d = oracle_digest(market, price, now, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

/// Markets `markets`, each at the $100,000 index at `now`.
fn setup(markets: &[MarketId], now: u64) -> Sequencer {
    let mut s = Sequencer::new(enclave(), 20);
    for &m in markets {
        s.add_market(test_market(m));
        s.set_oracle(m, oracle(m, now));
    }
    s
}

/// Deposit `amount_usd` for `owner` and bind it to its position in `market`.
fn fund(s: &mut Sequencer, owner: u64, market: MarketId, amount_usd: i128) {
    let o = owner_id(owner);
    let amount = amount_usd * QUOTE_SCALE;
    let deposit_id = s.state.consumed_deposit_count;
    let mut blinding = [0x5Au8; 32];
    blinding[..8].copy_from_slice(&deposit_id.to_le_bytes());
    let cm = Note::new(o, 0, amount, blinding).commitment::<Keccak256>();
    s.apply(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount,
        blinding,
        from: [0u8; 20],
        deposit_id,
        deposit_blind: [0u8; 32],
    })
    .unwrap();
    s.apply(&BatchOp::FundPosition {
        owner: o,
        market_id: market,
        note_commitment: cm,
        spend_key: [owner as u8; 32],
    })
    .unwrap();
}

/// Unbind all of `owner`'s collateral in `market` (its position is flat), so none
/// of its resting orders could fill any more.
fn unbind_all(s: &mut Sequencer, owner: u64, market: MarketId, now: u64) {
    let o = owner_id(owner);
    let amount = s.state.position(&o, market).unwrap().collateral;
    s.apply(&BatchOp::Unbind {
        owner: o,
        market_id: market,
        amount,
        blinding: [owner as u8 ^ 0xA5; 32],
        oracle: oracle(market, now),
        now_ms: now,
    })
    .unwrap();
}

/// A GTC order of `owner` in `market`.
fn order(
    owner: u64,
    market: MarketId,
    side: Side,
    size: i128,
    price_usd: i128,
    nonce: u64,
) -> Order {
    Order {
        owner: owner_id(owner),
        market_id: market,
        side,
        size,
        limit_price: price_usd * PRICE_SCALE,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: word_u64(nonce.wrapping_mul(31) ^ (owner << 40) ^ (market << 56)),
    }
}

fn ioc(o: Order) -> Order {
    Order {
        tif: TimeInForce::Ioc,
        ..o
    }
}

fn hash(o: &Order) -> Digest {
    o.order_hash::<Keccak256>()
}

/// Refresh every market's oracle at `now` and seal `orders`.
fn tick(s: &mut Sequencer, now: u64, orders: &[Order]) -> SealedBatch {
    let markets: Vec<MarketId> = s.state.markets.keys().copied().collect();
    for m in markets {
        s.set_oracle(m, oracle(m, now));
    }
    s.seal_batch(orders, now)
}

/// How many of `owner`'s orders rest on `market`'s book.
fn resting(s: &Sequencer, owner: u64, market: MarketId) -> usize {
    s.book(market)
        .unwrap()
        .resting_hashes_for(&owner_id(owner))
        .len()
}

/// The hashes `sealed` rejected for `reason`.
fn rejected_for(sealed: &SealedBatch, reason: RejectReason) -> Vec<Digest> {
    sealed
        .manifest
        .rejected
        .iter()
        .filter(|(_, r)| *r == reason)
        .map(|(h, _)| *h)
        .collect()
}

fn admitted(sealed: &SealedBatch, o: &Order) -> bool {
    sealed.manifest.ordered.contains(&hash(o))
}

// ---------------------------------------------------------------------------
// GA-1: open-order caps
// ---------------------------------------------------------------------------

/// One account floods one market with 100 well-margined bids in one batch: the
/// first `PER_MARKET` rest and the rest are refused, in this batch and the next.
/// An IOC is never refused for the cap and never rests. A fill, a cancel and an
/// expiry each free the slot the order held; another account is unaffected.
#[test]
fn audit_1116_ga1_one_account_cannot_rest_more_than_the_cap_in_one_market() {
    let mut t = 10_000u64;
    let mut s = setup(&[0], t);
    fund(&mut s, 1, 0, 1_000_000);
    fund(&mut s, 2, 0, 20_000);
    let mut flood: Vec<Order> = (0..PER_MARKET as u64 + 36)
        .map(|n| order(1, 0, Side::Buy, THOUSAND_DOLLARS, 99_000, n))
        .collect();
    // the second bid is good till t + 5 s
    flood[1].expiry_ms = t + 5_000;
    let sealed = tick(&mut s, t, &flood);
    assert_eq!(resting(&s, 1, 0), PER_MARKET);
    let refused = rejected_for(&sealed, RejectReason::InvalidOrder);
    assert_eq!(
        refused,
        flood[PER_MARKET..].iter().map(hash).collect::<Vec<_>>(),
        "the orders past the cap are refused, in arrival order"
    );

    // a later batch is refused too
    t += 700;
    let extra = order(1, 0, Side::Buy, THOUSAND_DOLLARS, 99_000, 1_000);
    let sealed = tick(&mut s, t, &[extra]);
    assert_eq!(
        rejected_for(&sealed, RejectReason::InvalidOrder),
        vec![hash(&extra)]
    );
    assert_eq!(resting(&s, 1, 0), PER_MARKET);

    // another account rests orders as before
    t += 700;
    let other = order(2, 0, Side::Buy, THOUSAND_DOLLARS, 98_000, 1);
    assert!(admitted(&tick(&mut s, t, &[other]), &other));

    // an IOC from the capped account is not refused for the cap; it trades
    // nothing here and does not rest
    t += 700;
    let take = ioc(order(1, 0, Side::Sell, THOUSAND_DOLLARS, 101_000, 1_001));
    let sealed = tick(&mut s, t, &[take]);
    assert!(admitted(&sealed, &take));
    assert_eq!(s.remaining_order_size(&hash(&take)), None);
    assert_eq!(resting(&s, 1, 0), PER_MARKET);

    // a fill frees a slot: owner 2 sells into owner 1's oldest bid
    t += 700;
    let hit = ioc(order(2, 0, Side::Sell, THOUSAND_DOLLARS, 99_000, 2));
    let sealed = tick(&mut s, t, &[hit]);
    assert!(sealed.settled_order_hashes.contains(&hash(&flood[0])));
    assert_eq!(resting(&s, 1, 0), PER_MARKET - 1);
    t += 700;
    let refill = order(1, 0, Side::Buy, THOUSAND_DOLLARS, 99_000, 1_002);
    let over = order(1, 0, Side::Buy, THOUSAND_DOLLARS, 99_000, 1_003);
    let sealed = tick(&mut s, t, &[refill, over]);
    assert!(admitted(&sealed, &refill));
    assert_eq!(
        rejected_for(&sealed, RejectReason::InvalidOrder),
        vec![hash(&over)]
    );

    // a cancel frees a slot
    assert!(s.cancel_order(&owner_id(1), &flood[2], true).is_some());
    t += 700;
    let after_cancel = order(1, 0, Side::Buy, THOUSAND_DOLLARS, 99_000, 1_004);
    assert!(admitted(&tick(&mut s, t, &[after_cancel]), &after_cancel));
    assert_eq!(resting(&s, 1, 0), PER_MARKET);

    // an expiry frees a slot, in the batch at which the order is void
    t = flood[1].expiry_ms;
    let after_expiry = order(1, 0, Side::Buy, THOUSAND_DOLLARS, 99_000, 1_005);
    let sealed = tick(&mut s, t, &[after_expiry]);
    assert!(admitted(&sealed, &after_expiry));
    assert_eq!(s.remaining_order_size(&hash(&flood[1])), None);
    assert_eq!(resting(&s, 1, 0), PER_MARKET);
}

/// The cap across markets: with `PER_MARKET` orders open in each of two markets an
/// account has `PER_ACCOUNT` open, and its first order in a third market is
/// refused until one of the others leaves the book.
#[test]
fn audit_1116_ga1_one_account_cannot_rest_more_than_the_cap_across_markets() {
    assert_eq!(PER_ACCOUNT, 2 * PER_MARKET, "fixture: two full markets");
    let mut t = 10_000u64;
    let mut s = setup(&[0, 1, 2], t);
    for m in [0, 1, 2] {
        fund(&mut s, 1, m, 1_000_000);
    }
    let mut first = None;
    for m in [0, 1] {
        let batch: Vec<Order> = (0..PER_MARKET as u64)
            .map(|n| order(1, m, Side::Buy, THOUSAND_DOLLARS, 99_000, n + 100 * m))
            .collect();
        let sealed = tick(&mut s, t, &batch);
        assert!(sealed.manifest.rejected.is_empty(), "market {m}");
        first.get_or_insert(batch[0]);
        t += 700;
    }
    let third = order(1, 2, Side::Buy, THOUSAND_DOLLARS, 99_000, 500);
    let sealed = tick(&mut s, t, &[third]);
    assert_eq!(
        rejected_for(&sealed, RejectReason::InvalidOrder),
        vec![hash(&third)]
    );
    assert_eq!(resting(&s, 1, 2), 0);

    assert!(s
        .cancel_order(&owner_id(1), &first.unwrap(), true)
        .is_some());
    t += 700;
    let retry = order(1, 2, Side::Buy, THOUSAND_DOLLARS, 99_000, 501);
    assert!(admitted(&tick(&mut s, t, &[retry]), &retry));
    assert_eq!(resting(&s, 1, 2), 1);
}

// ---------------------------------------------------------------------------
// SM-1: the collateral reserve for pending orders
// ---------------------------------------------------------------------------

/// With $10 of collateral an account margins $100 of notional at 10x: ten $10
/// bids. It posts 4,096 in one batch and then one per batch for 100 ticks; ten
/// rest, every other one is refused for margin. Before, every one of them rested.
#[test]
fn audit_1116_sm1_ten_usdc_cannot_keep_thousands_of_pending_orders() {
    let mut t = 10_000u64;
    let mut s = setup(&[0], t);
    fund(&mut s, 3, 0, 10);
    let flood: Vec<Order> = (0..4_096u64)
        .map(|n| order(3, 0, Side::Buy, TEN_DOLLARS, 99_000, n))
        .collect();
    let sealed = tick(&mut s, t, &flood);
    assert_eq!(resting(&s, 3, 0), 10);
    assert_eq!(
        rejected_for(&sealed, RejectReason::InsufficientMargin),
        flood[10..].iter().map(hash).collect::<Vec<_>>()
    );
    for n in 0..100u64 {
        t += 700;
        let more = order(3, 0, Side::Buy, TEN_DOLLARS, 99_000, 10_000 + n);
        let sealed = tick(&mut s, t, &[more]);
        assert_eq!(
            rejected_for(&sealed, RejectReason::InsufficientMargin),
            vec![hash(&more)],
            "tick {n}"
        );
    }
    assert_eq!(resting(&s, 3, 0), 10);

    // the reserve is per side: a $10 ask opens a short, which the same
    // collateral margins on its own
    t += 700;
    let ask = order(3, 0, Side::Sell, TEN_DOLLARS, 101_000, 20_000);
    assert!(admitted(&tick(&mut s, t, &[ask]), &ask));

    // a cancel releases what the order held
    assert!(s.cancel_order(&owner_id(3), &flood[0], true).is_some());
    t += 700;
    let after_cancel = order(3, 0, Side::Buy, TEN_DOLLARS, 99_000, 20_001);
    let over = order(3, 0, Side::Buy, TEN_DOLLARS, 99_000, 20_002);
    let sealed = tick(&mut s, t, &[after_cancel, over]);
    assert!(admitted(&sealed, &after_cancel));
    assert_eq!(
        rejected_for(&sealed, RejectReason::InsufficientMargin),
        vec![hash(&over)]
    );
}

/// An IOC is margined together with the account's pending orders on its side,
/// and once its batch has run it holds nothing: an IOC that does not trade never
/// stays pending.
#[test]
fn audit_1116_sm1_an_unmatched_ioc_never_stays_pending() {
    let mut t = 10_000u64;
    let mut s = setup(&[0], t);
    fund(&mut s, 3, 0, 10);
    // a $100 IOC bid with nothing to trade against
    let sweep = ioc(order(3, 0, Side::Buy, TEN_DOLLARS * 10, 101_000, 1));
    let sealed = tick(&mut s, t, &[sweep]);
    assert!(admitted(&sealed, &sweep) && sealed.applied_fills.is_empty());
    // the next batch: the IOC holds no margin, ten $10 bids fit
    t += 700;
    let bids: Vec<Order> = (0..10u64)
        .map(|n| order(3, 0, Side::Buy, TEN_DOLLARS, 99_000, 10 + n))
        .collect();
    let sealed = tick(&mut s, t, &bids);
    assert!(sealed.manifest.rejected.is_empty(), "{:?}", sealed.manifest);
    assert_eq!(resting(&s, 3, 0), 10);
    // with the bids pending, a $10 IOC bid that fits on its own is refused
    t += 700;
    let late = ioc(order(3, 0, Side::Buy, TEN_DOLLARS, 101_000, 30));
    let sealed = tick(&mut s, t, &[late]);
    assert_eq!(
        rejected_for(&sealed, RejectReason::InsufficientMargin),
        vec![hash(&late)]
    );
}

/// Filled orders move their margin into the position instead of holding it
/// twice: once the position they opened is closed, the account can post as much
/// again.
#[test]
fn audit_1116_sm1_a_fill_releases_the_reserve_into_the_position() {
    let mut t = 10_000u64;
    let mut s = setup(&[0], t);
    fund(&mut s, 3, 0, 20);
    fund(&mut s, 4, 0, 20_000);
    let bids: Vec<Order> = (0..20u64)
        .map(|n| order(3, 0, Side::Buy, TEN_DOLLARS, 99_900, n))
        .collect();
    let sealed = tick(&mut s, t, &bids);
    assert!(sealed.manifest.rejected.is_empty());
    // owner 4 sells into half of them: owner 3 is long $100 with $100 pending
    t += 700;
    let hit = ioc(order(4, 0, Side::Sell, TEN_DOLLARS * 10, 99_900, 1));
    tick(&mut s, t, &[hit]);
    assert_eq!(
        s.state.position(&owner_id(3), 0).unwrap().size,
        TEN_DOLLARS * 10
    );
    assert_eq!(resting(&s, 3, 0), 10);
    t += 700;
    let full = order(3, 0, Side::Buy, TEN_DOLLARS, 99_900, 100);
    let sealed = tick(&mut s, t, &[full]);
    assert_eq!(
        rejected_for(&sealed, RejectReason::InsufficientMargin),
        vec![hash(&full)],
        "the position and the pending bids use all of the collateral"
    );
    // owner 3 closes the long against owner 4's bid, above its own bids
    t += 700;
    let bid = order(4, 0, Side::Buy, TEN_DOLLARS * 10, 99_950, 2);
    let close = ioc(Order {
        reduce_only: true,
        ..order(3, 0, Side::Sell, TEN_DOLLARS * 10, 99_900, 101)
    });
    tick(&mut s, t, &[bid, close]);
    assert_eq!(
        s.state.position(&owner_id(3), 0).map_or(0, |p| p.size),
        0,
        "closed"
    );
    // ten more bids fit beside the ten still pending
    t += 700;
    let again: Vec<Order> = (0..10u64)
        .map(|n| order(3, 0, Side::Buy, TEN_DOLLARS, 99_000, 200 + n))
        .collect();
    let sealed = tick(&mut s, t, &again);
    assert!(sealed.manifest.rejected.is_empty(), "{:?}", sealed.manifest);
    assert_eq!(resting(&s, 3, 0), 20);
}

/// Intake (`check_open_order_limits`, then `accept_order`) counts the orders
/// accepted and waiting for their batch together with the resting ones: an IOC
/// waiting for its batch holds its margin until the batch has run, a cancel of an
/// order not yet sealed releases it, and the cap counts resting and waiting orders
/// alike, a cancel of a resting one freeing a slot.
#[test]
fn audit_1116_sm1_intake_counts_the_orders_waiting_for_their_batch() {
    let t = 10_000u64;
    let mut s = setup(&[0], t);
    fund(&mut s, 3, 0, 10);
    let sweep = ioc(order(3, 0, Side::Buy, TEN_DOLLARS * 10, 101_000, 1));
    assert_eq!(s.check_open_order_limits(&sweep, t), Ok(()));
    s.accept_order(&sweep, t);
    let bid = order(3, 0, Side::Buy, TEN_DOLLARS, 99_000, 2);
    assert_eq!(
        s.check_open_order_limits(&bid, t),
        Err(OpenOrderLimit::PendingMargin)
    );
    // the IOC's batch runs: it trades nothing and holds nothing
    tick(&mut s, t, &[sweep]);
    assert_eq!(s.check_open_order_limits(&bid, t), Ok(()));
    let bids: Vec<Order> = (0..10u64)
        .map(|n| order(3, 0, Side::Buy, TEN_DOLLARS, 99_000, 10 + n))
        .collect();
    for b in &bids {
        assert_eq!(s.check_open_order_limits(b, t), Ok(()));
        s.accept_order(b, t);
    }
    assert_eq!(
        s.check_open_order_limits(&bid, t),
        Err(OpenOrderLimit::PendingMargin)
    );
    assert!(s.cancel_order(&owner_id(3), &bids[0], false).is_some());
    assert_eq!(s.check_open_order_limits(&bid, t), Ok(()));

    // the cap: half resting, half waiting
    fund(&mut s, 1, 0, 1_000_000);
    let quotes: Vec<Order> = (0..PER_MARKET as u64)
        .map(|n| order(1, 0, Side::Buy, THOUSAND_DOLLARS, 98_000, n))
        .collect();
    let (resting_half, waiting_half) = quotes.split_at(PER_MARKET / 2);
    assert!(tick(&mut s, t, resting_half).manifest.rejected.is_empty());
    for q in waiting_half {
        assert_eq!(s.check_open_order_limits(q, t), Ok(()));
        s.accept_order(q, t);
    }
    let extra = order(1, 0, Side::Buy, THOUSAND_DOLLARS, 98_000, 1_000);
    assert_eq!(
        s.check_open_order_limits(&extra, t),
        Err(OpenOrderLimit::Market)
    );
    // an IOC is not refused for the cap
    let take = ioc(order(1, 0, Side::Sell, THOUSAND_DOLLARS, 101_000, 1_001));
    assert_eq!(s.check_open_order_limits(&take, t), Ok(()));
    assert!(s.cancel_order(&owner_id(1), &quotes[0], true).is_some());
    assert_eq!(s.check_open_order_limits(&extra, t), Ok(()));
}

// ---------------------------------------------------------------------------
// SM-3: dust cannot pin the funding mark
// ---------------------------------------------------------------------------

/// The first dust account; the wall uses `DUST_ACCOUNTS` accounts from here.
const FIRST_DUST: u64 = 100;
/// 64 accounts with 64 orders each: a 4,096-order wall that the per-account caps
/// admit.
const DUST_ACCOUNTS: u64 = 64;
const DUST_PER_ACCOUNT: u64 = 64;

/// Rest a 4,096-order wall of $10 bids at `price_usd`, from 64 accounts, each
/// margined when it is posted; then every dust account unbinds its collateral, so
/// no order of the wall could fill any more.
fn dust_wall(s: &mut Sequencer, mut t: u64, price_usd: i128) -> u64 {
    for a in 0..DUST_ACCOUNTS {
        let owner = FIRST_DUST + a;
        fund(s, owner, 0, 70);
        let batch: Vec<Order> = (0..DUST_PER_ACCOUNT)
            .map(|n| order(owner, 0, Side::Buy, TEN_DOLLARS, price_usd, n))
            .collect();
        let sealed = tick(s, t, &batch);
        assert!(sealed.manifest.rejected.is_empty(), "dust account {a}");
        t += 700;
    }
    for a in 0..DUST_ACCOUNTS {
        unbind_all(s, FIRST_DUST + a, 0, t);
        assert_eq!(resting(s, FIRST_DUST + a, 0), DUST_PER_ACCOUNT as usize);
    }
    t
}

/// The market-0 mark of the funding op in `sealed`.
fn accrue_mark(sealed: &SealedBatch) -> i128 {
    sealed
        .ops
        .iter()
        .find_map(|op| match op {
            BatchOp::AccrueFunding {
                market_id: 0, mark, ..
            } => Some(*mark),
            _ => None,
        })
        .expect("a market-0 funding op")
}

/// Owner 1 bids $10,000 at $100,000 and owner 2 asks $10,000 at $100,040: an impact
/// mid of $100,020, a $20 premium over the index.
fn honest_quotes(s: &mut Sequencer, t: u64) {
    fund(s, 1, 0, 20_000);
    fund(s, 2, 0, 20_000);
    let sealed = tick(
        s,
        t,
        &[
            order(1, 0, Side::Buy, SIZE_SCALE / 10, 100_000, 1),
            order(2, 0, Side::Sell, SIZE_SCALE / 10, 100_040, 2),
        ],
    );
    assert!(sealed.manifest.rejected.is_empty());
}

const HONEST_MID: i128 = 100_020 * PRICE_SCALE;

/// The original wall: 4,096 dust bids at $100,010, ahead of the honest bids at
/// $100,000. The impact bid is still owner 1's, and the mark carries the honest
/// premium instead of falling back to the index.
#[test]
fn audit_1116_sm3_a_dust_wall_ahead_of_honest_depth_does_not_pin_the_mark() {
    let mut t = 10_000u64;
    let mut s = setup(&[0], t);
    honest_quotes(&mut s, t);
    assert_eq!(s.impact_mid(0, t), Some(HONEST_MID));
    t += 700;
    t = dust_wall(&mut s, t, 100_010);
    assert_eq!(s.book(0).unwrap().best_bid(), Some(100_010 * PRICE_SCALE));
    assert_eq!(s.impact_mid(0, t), Some(HONEST_MID));
    // the window's samples are the honest premium, not zero
    let _ = s.seal_window();
    let sealed = tick(&mut s, t, &[]);
    assert_eq!(accrue_mark(&sealed), INDEX_USD * PRICE_SCALE);
    t += 700;
    let sealed = tick(&mut s, t, &[]);
    assert_eq!(
        accrue_mark(&sealed),
        INDEX_USD * PRICE_SCALE + 20 * PRICE_SCALE * 700 / 7_000
    );
}

/// The verified variant: owner 1's $50,000 bid at $100,000 first, then 4,096 dust
/// bids at the same price behind it. The sweep stops inside the level, at the
/// order that completes the impact notional.
#[test]
fn audit_1116_sm3_dust_behind_honest_depth_at_the_same_price_does_not_pin_the_mark() {
    let mut t = 10_000u64;
    let mut s = setup(&[0], t);
    fund(&mut s, 1, 0, 20_000);
    fund(&mut s, 2, 0, 20_000);
    let sealed = tick(
        &mut s,
        t,
        &[
            order(1, 0, Side::Buy, SIZE_SCALE / 2, 100_000, 1),
            order(2, 0, Side::Sell, SIZE_SCALE / 10, 100_040, 2),
        ],
    );
    assert!(sealed.manifest.rejected.is_empty());
    assert_eq!(s.impact_mid(0, t), Some(HONEST_MID));
    t += 700;
    t = dust_wall(&mut s, t, 100_000);
    assert_eq!(s.impact_mid(0, t), Some(HONEST_MID));
    let _ = s.seal_window();
    tick(&mut s, t, &[]);
    t += 700;
    let sealed = tick(&mut s, t, &[]);
    assert_eq!(
        accrue_mark(&sealed),
        INDEX_USD * PRICE_SCALE + 20 * PRICE_SCALE * 700 / 7_000
    );
}

/// Honest books price as before: several makers at several levels, every order
/// fillable and at least the order minimum. The impact prices are the averages
/// the per-level walk gives, computed here from the orders placed.
#[test]
fn audit_1116_sm3_honest_books_keep_their_mark() {
    let t = 10_000u64;
    let mut s = setup(&[0], t);
    for owner in 1..=6 {
        fund(&mut s, owner, 0, 50_000);
    }
    // (owner, side, size, price): $1,000 needs three bid levels and two ask levels
    let book: [(u64, Side, i128, i128); 9] = [
        (1, Side::Buy, TEN_DOLLARS * 30, 99_990),
        (2, Side::Buy, TEN_DOLLARS * 25, 99_990),
        (3, Side::Buy, TEN_DOLLARS * 20, 99_970),
        (1, Side::Buy, TEN_DOLLARS * 40, 99_950),
        (4, Side::Sell, TEN_DOLLARS * 45, 100_030),
        (5, Side::Sell, TEN_DOLLARS * 15, 100_030),
        (6, Side::Sell, TEN_DOLLARS * 70, 100_060),
        (5, Side::Sell, TEN_DOLLARS * 3, 100_090),
        (2, Side::Buy, TEN_DOLLARS, 99_900),
    ];
    let orders: Vec<Order> = book
        .iter()
        .enumerate()
        .map(|(n, (owner, side, size, price))| order(*owner, 0, *side, *size, *price, n as u64))
        .collect();
    let sealed = tick(&mut s, t, &orders);
    assert!(sealed.manifest.rejected.is_empty());
    let reference = |side: Side| -> i128 {
        let mut levels: Vec<(i128, i128)> = Vec::new();
        for (_, _, size, price) in book.iter().filter(|o| o.1 == side) {
            let p = price * PRICE_SCALE;
            match levels.iter_mut().find(|(lp, _)| *lp == p) {
                Some(level) => level.1 += size,
                None => levels.push((p, *size)),
            }
        }
        // best price first
        match side {
            Side::Buy => levels.sort_by_key(|level| -level.0),
            Side::Sell => levels.sort_by_key(|level| level.0),
        }
        let divisor = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
        let target = 1_000 * QUOTE_SCALE * divisor;
        let (mut left, mut base) = (target, 0i128);
        for (price, size) in levels {
            let value = size * price;
            if value >= left {
                return target * price / (base * price + left);
            }
            base += size;
            left -= value;
        }
        panic!("fixture: the side holds the impact notional");
    };
    let (bid, ask) = (reference(Side::Buy), reference(Side::Sell));
    assert_eq!(s.impact_mid(0, t), Some(bid / 2 + ask / 2));
}
