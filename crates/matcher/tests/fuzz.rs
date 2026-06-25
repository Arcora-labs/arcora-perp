//! Property fuzzer for the CLOB. Feeds long randomized order streams and asserts
//! the matching invariants on every run: no self-trades, no order overfills,
//! price-time monotonicity per taker, book non-negativity, no crossed book
//! (best_bid < best_ask), and determinism.
//! Deterministic xorshift PRNG so any failure reproduces from the printed seed.

use matcher::{MatchingEngine, SubmitStatus};
use perp_core::fixed::{PRICE_SCALE, SIZE_SCALE};
use perp_core::hash::word_u64;
use perp_core::order::{Order, Side, TimeInForce};
use std::collections::BTreeMap;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn rand_order(rng: &mut Rng, nonce: u64) -> Order {
    let owner = word_u64(rng.below(6)); // small owner set ⇒ self-trades happen
    let side = if rng.below(2) == 0 {
        Side::Buy
    } else {
        Side::Sell
    };
    let size = (1 + rng.below(20)) as i128 * (SIZE_SCALE / 10);
    // price near 100k, sometimes 0 (market)
    let price = if rng.below(5) == 0 {
        0
    } else {
        ((99_500 + rng.below(1000)) as i128) * PRICE_SCALE
    };
    let tif = match rng.below(4) {
        0 => TimeInForce::Ioc,
        1 => TimeInForce::Fok,
        2 => TimeInForce::PostOnly,
        _ => TimeInForce::Gtc,
    };
    Order {
        owner,
        market_id: 0,
        side,
        size,
        limit_price: price,
        tif,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: word_u64(nonce.wrapping_mul(2654435761)),
    }
}

fn run(seed: u64, n: usize) {
    let mut e = MatchingEngine::<perp_core::hash::Keccak256>::new();
    e.open_market(0);
    let mut rng = Rng(seed | 1);
    let orders: Vec<Order> = (0..n).map(|i| rand_order(&mut rng, i as u64)).collect();

    let result = e.process_stream(&orders, 0);

    // 1. every fill is positive-size, has a real price, and is NOT a self-trade.
    for m in &result.fills {
        assert!(m.size > 0, "seed={seed}: non-positive fill size");
        assert!(m.price > 0, "seed={seed}: non-positive fill price");
        assert_ne!(m.taker, m.maker, "seed={seed}: self-trade slipped through");
    }

    // 2. no taker order fills more than its size; per-taker fill prices are
    //    monotonic in the crossing direction (price-time priority).
    let mut filled: BTreeMap<[u8; 32], i128> = BTreeMap::new();
    let mut last_price: BTreeMap<[u8; 32], i128> = BTreeMap::new();
    // map order_hash → its side, to know the monotonic direction
    let side_of: BTreeMap<[u8; 32], Side> = orders
        .iter()
        .map(|o| (o.order_hash::<perp_core::hash::Keccak256>(), o.side))
        .collect();
    for m in &result.fills {
        *filled.entry(m.taker_order_hash).or_insert(0) += m.size;
        if let Some(prev) = last_price.get(&m.taker_order_hash) {
            match side_of.get(&m.taker_order_hash) {
                // a buy taker sweeps asks low→high: prices non-decreasing
                Some(Side::Buy) => {
                    assert!(m.price >= *prev, "seed={seed}: buy taker price went down")
                }
                // a sell taker sweeps bids high→low: prices non-increasing
                Some(Side::Sell) => {
                    assert!(m.price <= *prev, "seed={seed}: sell taker price went up")
                }
                None => {}
            }
        }
        last_price.insert(m.taker_order_hash, m.price);
    }
    for o in &orders {
        let h = o.order_hash::<perp_core::hash::Keccak256>();
        if let Some(f) = filled.get(&h) {
            assert!(
                *f <= o.size,
                "seed={seed}: order overfilled ({f} > {})",
                o.size
            );
        }
    }

    // 3. resting book sizes are non-negative and finite.
    let book = e.book(0).unwrap();
    assert!(book.resting_size(Side::Buy) >= 0);
    assert!(book.resting_size(Side::Sell) >= 0);

    // 3b. the resting book is NEVER crossed: the best bid must sit strictly below
    // the best ask. A crossed book means a marketable order was left resting instead
    // of matched — the core CLOB invariant. (Asserted at loadbot runtime; locked into
    // CI here so a regression fails `cargo test`, not just a manual stress run.)
    if let (Some(b), Some(a)) = (book.best_bid(), book.best_ask()) {
        assert!(
            b < a,
            "seed={seed}: resting book crossed (best_bid {b} >= best_ask {a})"
        );
    }

    // 4. accepted + rejected partition every order exactly once.
    let accepted_or_rejected = result
        .processed
        .iter()
        .filter(|p| !matches!(p.outcome.status, SubmitStatus::Rejected(_)))
        .count()
        + result.rejected.len();
    assert_eq!(
        accepted_or_rejected,
        orders.len(),
        "seed={seed}: order accounting"
    );
}

#[test]
fn fuzz_matcher_invariants() {
    for seed in 1..=300u64 {
        run(seed.wrapping_mul(0x9E3779B97F4A7C15), 60);
    }
}

#[test]
fn fuzz_matcher_deterministic() {
    let go = |seed: u64| {
        let mut e = MatchingEngine::<perp_core::hash::Keccak256>::new();
        e.open_market(0);
        let mut rng = Rng(seed | 1);
        let orders: Vec<Order> = (0..40).map(|i| rand_order(&mut rng, i)).collect();
        e.process_stream(&orders, 0).fills
    };
    for seed in 1..=50u64 {
        assert_eq!(
            go(seed),
            go(seed),
            "matching must be deterministic (seed={seed})"
        );
    }
}
