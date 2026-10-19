//! # matcher — deterministic continuous CLOB for dark-perp (Phase 1 hot path)
//!
//! Runs inside the matcher enclave (§1): it decrypts orders, maintains an
//! in-memory price-time-priority book per market, and emits matched fills that
//! `perp-core`'s settlement engine turns into state transitions. Like
//! `perp-core` it is `#![no_std]` + `alloc` with no clocks/RNG/IO, so the exact
//! same matching can later be re-executed inside a zkVM guest to discharge the
//! **Proof-v2** matching-determinism obligation (§4): committed-log price-time
//! priority, self-trade prevention, partial fills, expiry, and order types
//! (IOC / FOK / post-only / GTC).
//!
//! The matcher does **not** check margin or touch funds — that is settlement's
//! job (`perp-core::engine`). It only decides *who trades with whom, in what
//! order, at what price*, deterministically.

#![no_std]
#![cfg_attr(not(feature = "std"), forbid(unsafe_code))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod book;

pub use book::{Match, OrderBook, OrderRemoval, RestingQuote, SubmitOutcome, SubmitStatus};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use perp_core::hash::{Digest, Hasher, Keccak256};
use perp_core::market::MarketId;
use perp_core::order::{Order, RejectReason};

/// A multi-market matching engine. Assigns a monotonic sequence number to every
/// accepted order (the §2 receipt `seq_no`) and routes it to the right book.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct MatchingEngine<H: Hasher = Keccak256> {
    books: BTreeMap<MarketId, OrderBook<H>>,
    next_seq: u64,
}

impl<H: Hasher> Default for MatchingEngine<H> {
    fn default() -> Self {
        Self {
            books: BTreeMap::new(),
            next_seq: 0,
        }
    }
}

/// The record of one processed order, ready to fold into a batch manifest (§2).
#[derive(Clone, Debug)]
pub struct Processed {
    pub seq_no: u64,
    pub outcome: SubmitOutcome,
}

impl<H: Hasher> MatchingEngine<H> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a market's book. Idempotent.
    pub fn open_market(&mut self, market_id: MarketId) {
        self.books
            .entry(market_id)
            .or_insert_with(|| OrderBook::new(market_id));
    }

    pub fn book(&self, market_id: MarketId) -> Option<&OrderBook<H>> {
        self.books.get(&market_id)
    }

    /// Cancel every resting order belonging to `owner` across all markets (e.g.
    /// after liquidation). Returns the total number cancelled.
    pub fn cancel_owner_orders(&mut self, owner: &perp_core::note::PubKey) -> usize {
        self.books.values_mut().map(|b| b.cancel_owner(owner)).sum()
    }

    /// Cancel a single resting order by hash across all markets, returning its
    /// cancelled remaining size if it was resting. Used by the sequencer's SEC-022
    /// §6 dry-run to ban an offending maker that has been resting since an EARLIER
    /// batch (a drifted Gtc quote) — such an order is in no current stream, so
    /// dropping it from the order flow alone cannot remove it from the book.
    pub fn cancel_order(&mut self, order_hash: &Digest) -> Option<i128> {
        self.books.values_mut().find_map(|b| b.cancel(order_hash))
    }

    /// Reap expired resting makers across all markets at `now_ms` (good-till-time
    /// maintenance). Returns the total reaped. See [`OrderBook::reap_expired`].
    pub fn reap_expired(&mut self, now_ms: u64) -> usize {
        self.books
            .values_mut()
            .map(|b| b.reap_expired(now_ms))
            .sum()
    }

    pub fn remaining(&self, hash: &Digest) -> Option<i128> {
        self.books.values().find_map(|b| b.remaining(hash))
    }

    /// Keep in `hashes` only the orders that still rest on a book, in one pass
    /// over the books.
    pub fn retain_resting(&self, hashes: &mut BTreeSet<Digest>) {
        if hashes.is_empty() {
            return;
        }
        let resting: BTreeSet<Digest> = self
            .books
            .values()
            .flat_map(|b| b.resting_order_hashes())
            .collect();
        hashes.retain(|h| resting.contains(h));
    }

    pub fn reap_expired_with_events(&mut self, now_ms: u64) -> Vec<OrderRemoval> {
        self.books
            .values_mut()
            .flat_map(|b| b.reap_expired_with_events(now_ms))
            .collect()
    }

    pub fn cancel_owner_with_events(
        &mut self,
        owner: &perp_core::note::PubKey,
    ) -> Vec<OrderRemoval> {
        self.books
            .values_mut()
            .flat_map(|b| b.cancel_owner_with_events(owner))
            .collect()
    }

    /// The seq number that will be assigned to the next accepted order.
    pub fn peek_seq(&self) -> u64 {
        self.next_seq
    }

    /// Submit one order. Returns the assigned seq and the matching outcome.
    /// An order for an unknown market is rejected without consuming a seq.
    pub fn submit(&mut self, order: &Order, now_ms: u64) -> Processed {
        let Some(book) = self.books.get_mut(&order.market_id) else {
            return Processed {
                seq_no: u64::MAX,
                outcome: SubmitOutcome {
                    order_hash: order.order_hash::<H>(),
                    fills: Vec::new(),
                    removals: Vec::new(),
                    status: SubmitStatus::Rejected(RejectReason::MarketCloseOnly),
                },
            };
        };
        let seq = self.next_seq;
        self.next_seq += 1;
        let outcome = book.submit(order, seq, now_ms);
        Processed {
            seq_no: seq,
            outcome,
        }
    }

    /// Process a whole arrival-ordered stream, collecting fills and the
    /// manifest's `ordered` / `rejected` lists (§2).
    pub fn process_stream(&mut self, orders: &[Order], now_ms: u64) -> StreamResult {
        let mut result = StreamResult::default();
        for order in orders {
            let p = self.submit(order, now_ms);
            match p.outcome.status {
                SubmitStatus::Rejected(reason) => {
                    result.rejected.push((p.outcome.order_hash, reason));
                }
                _ => {
                    result.ordered.push(p.outcome.order_hash);
                }
            }
            result.fills.extend_from_slice(&p.outcome.fills);
            result.processed.push(p);
        }
        result
    }
}

/// Aggregated output of [`MatchingEngine::process_stream`].
#[derive(Clone, Debug, Default)]
pub struct StreamResult {
    pub fills: Vec<Match>,
    /// Order hashes accepted into the book / matched (manifest `ordered`).
    pub ordered: Vec<Digest>,
    /// Order hashes rejected, with reasons (manifest `rejected`).
    pub rejected: Vec<(Digest, RejectReason)>,
    pub processed: Vec<Processed>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use perp_core::fixed::{PRICE_SCALE, SIZE_SCALE};
    use perp_core::hash::word_u64;
    use perp_core::order::{Side, TimeInForce};

    fn order(
        owner: u64,
        side: Side,
        size: i128,
        price: i128,
        tif: TimeInForce,
        nonce: u64,
    ) -> Order {
        Order {
            owner: word_u64(owner),
            market_id: 0,
            side,
            size,
            limit_price: price,
            tif,
            reduce_only: false,
            nonce,
            expiry_ms: 0,
            ciphertext_commit: word_u64(nonce.wrapping_mul(7)),
        }
    }

    fn engine() -> MatchingEngine {
        let mut e = MatchingEngine::new();
        e.open_market(0);
        e
    }

    #[test]
    fn resting_then_cross_produces_fill() {
        let mut e = engine();
        // maker sells 1 @ 100k
        let r = e.submit(
            &order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        assert_eq!(r.outcome.status, SubmitStatus::Resting);
        // taker buys 1 @ 100k → full fill at maker price
        let t = e.submit(
            &order(
                2,
                Side::Buy,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                2,
            ),
            0,
        );
        assert_eq!(t.outcome.status, SubmitStatus::FilledFull);
        assert_eq!(t.outcome.fills.len(), 1);
        let f = t.outcome.fills[0];
        assert_eq!(f.size, SIZE_SCALE);
        assert_eq!(f.price, 100_000 * PRICE_SCALE);
        assert_eq!(f.maker, word_u64(1));
        assert_eq!(f.taker, word_u64(2));
    }

    #[test]
    fn price_time_priority() {
        let mut e = engine();
        // two asks at same price; first one in (seq) has priority
        e.submit(
            &order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        e.submit(
            &order(
                2,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                2,
            ),
            0,
        );
        // a better-priced ask should fill first regardless of time
        e.submit(
            &order(
                3,
                Side::Sell,
                SIZE_SCALE,
                99_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                3,
            ),
            0,
        );
        // taker buys 2 @ 100k → fills best price (99k, owner 3) then earliest 100k (owner 1)
        let t = e.submit(
            &order(
                9,
                Side::Buy,
                2 * SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                9,
            ),
            0,
        );
        assert_eq!(t.outcome.fills.len(), 2);
        assert_eq!(t.outcome.fills[0].maker, word_u64(3)); // best price first
        assert_eq!(t.outcome.fills[0].price, 99_000 * PRICE_SCALE);
        assert_eq!(t.outcome.fills[1].maker, word_u64(1)); // then earliest at 100k
    }

    #[test]
    fn partial_fill_rests_remainder() {
        let mut e = engine();
        e.submit(
            &order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        // buy 3 but only 1 available → 1 fills, 2 rest as a bid
        let t = e.submit(
            &order(
                2,
                Side::Buy,
                3 * SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                2,
            ),
            0,
        );
        assert_eq!(
            t.outcome.status,
            SubmitStatus::FilledResting {
                resting: 2 * SIZE_SCALE
            }
        );
        assert_eq!(e.book(0).unwrap().resting_size(Side::Buy), 2 * SIZE_SCALE);
    }

    #[test]
    fn ioc_cancels_remainder() {
        let mut e = engine();
        e.submit(
            &order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        let t = e.submit(
            &order(
                2,
                Side::Buy,
                3 * SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Ioc,
                2,
            ),
            0,
        );
        assert_eq!(
            t.outcome.status,
            SubmitStatus::FilledCancelled {
                cancelled: 2 * SIZE_SCALE
            }
        );
        assert_eq!(
            e.book(0).unwrap().resting_size(Side::Buy),
            0,
            "IOC never rests"
        );
    }

    #[test]
    fn fok_all_or_nothing() {
        let mut e = engine();
        e.submit(
            &order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        // FOK for 2 but only 1 available → rejected, book untouched
        let t = e.submit(
            &order(
                2,
                Side::Buy,
                2 * SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Fok,
                2,
            ),
            0,
        );
        assert_eq!(
            t.outcome.status,
            SubmitStatus::Rejected(RejectReason::FillOrKillUnfillable)
        );
        assert!(t.outcome.fills.is_empty());
        assert_eq!(
            e.book(0).unwrap().resting_size(Side::Sell),
            SIZE_SCALE,
            "maker still there"
        );
        // FOK for exactly 1 → fully fills
        let t2 = e.submit(
            &order(
                3,
                Side::Buy,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Fok,
                3,
            ),
            0,
        );
        assert_eq!(t2.outcome.status, SubmitStatus::FilledFull);
    }

    #[test]
    fn post_only_rejects_if_it_would_take() {
        let mut e = engine();
        e.submit(
            &order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        // post-only buy at 100k would cross → reject
        let t = e.submit(
            &order(
                2,
                Side::Buy,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::PostOnly,
                2,
            ),
            0,
        );
        assert_eq!(
            t.outcome.status,
            SubmitStatus::Rejected(RejectReason::PostOnlyWouldTake)
        );
        // post-only buy at 99k does not cross → rests
        let t2 = e.submit(
            &order(
                3,
                Side::Buy,
                SIZE_SCALE,
                99_000 * PRICE_SCALE,
                TimeInForce::PostOnly,
                3,
            ),
            0,
        );
        assert_eq!(t2.outcome.status, SubmitStatus::Resting);
        assert_eq!(e.book(0).unwrap().best_bid(), Some(99_000 * PRICE_SCALE));
    }

    #[test]
    fn self_trade_prevention_cancels_maker() {
        let mut e = engine();
        // owner 1 rests an ask
        e.submit(
            &order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        // owner 1 sends a crossing buy → STP cancels its own resting ask, no fill
        let t = e.submit(
            &order(
                1,
                Side::Buy,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Ioc,
                2,
            ),
            0,
        );
        assert!(t.outcome.fills.is_empty(), "no self-trade");
        assert_eq!(
            e.book(0).unwrap().resting_size(Side::Sell),
            0,
            "own maker cancelled"
        );
    }

    #[test]
    fn post_only_rejects_even_against_own_order() {
        // A post-only that would cross ONLY the taker's own resting order is still
        // rejected (conservative: "maker or nothing"), not silently rested by
        // self-trade-cancelling the owner's existing maker. Pins book.rs §2.
        let mut e = engine();
        // owner 1 rests an ask at 100k
        e.submit(
            &order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        // owner 1 sends a post-only buy at 100k — crosses only its own ask
        let t = e.submit(
            &order(
                1,
                Side::Buy,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::PostOnly,
                2,
            ),
            0,
        );
        assert_eq!(
            t.outcome.status,
            SubmitStatus::Rejected(RejectReason::PostOnlyWouldTake),
            "post-only rejected rather than STP-cancelling the owner's own maker"
        );
        // and the owner's original resting ask is untouched
        assert_eq!(
            e.book(0).unwrap().resting_size(Side::Sell),
            SIZE_SCALE,
            "own resting maker preserved"
        );
    }

    #[test]
    fn expired_order_rejected() {
        let mut e = engine();
        let mut o = order(
            1,
            Side::Buy,
            SIZE_SCALE,
            100_000 * PRICE_SCALE,
            TimeInForce::Gtc,
            1,
        );
        o.expiry_ms = 500;
        let t = e.submit(&o, 1000); // now past expiry
        assert_eq!(
            t.outcome.status,
            SubmitStatus::Rejected(RejectReason::Expired)
        );
    }

    #[test]
    fn expired_resting_maker_does_not_trade() {
        // A good-till-time maker rests at t=100 with expiry=500. A taker crosses it
        // at t=1000 — past the maker's expiry. The expired maker must NOT provide
        // liquidity (it should be void), so the taker finds nothing to fill.
        let mut e = engine();
        let mut maker = order(
            1,
            Side::Sell,
            SIZE_SCALE,
            100_000 * PRICE_SCALE,
            TimeInForce::Gtc,
            1,
        );
        maker.expiry_ms = 500;
        let r = e.submit(&maker, 100); // rests fine while still live
        assert_eq!(r.outcome.status, SubmitStatus::Resting);

        let taker = order(
            2,
            Side::Buy,
            SIZE_SCALE,
            100_000 * PRICE_SCALE,
            TimeInForce::Gtc,
            2,
        );
        let t = e.submit(&taker, 1000); // now past the maker's expiry
        assert!(
            t.outcome.fills.is_empty(),
            "an expired resting maker must not trade"
        );
        // the taker (still live) rests instead of hitting the stale maker
        assert_eq!(t.outcome.status, SubmitStatus::Resting);
    }

    #[test]
    fn fok_ignores_expired_resting_liquidity() {
        // FOK's all-or-nothing pre-check must not count expired makers as fillable
        // liquidity, or it would pass the check and then under-fill at matching.
        let mut e = engine();
        let mut maker = order(
            1,
            Side::Sell,
            SIZE_SCALE,
            100_000 * PRICE_SCALE,
            TimeInForce::Gtc,
            1,
        );
        maker.expiry_ms = 500;
        e.submit(&maker, 100);

        let mut taker = order(
            2,
            Side::Buy,
            SIZE_SCALE,
            100_000 * PRICE_SCALE,
            TimeInForce::Fok,
            2,
        );
        taker.expiry_ms = 0;
        let t = e.submit(&taker, 1000);
        assert_eq!(
            t.outcome.status,
            SubmitStatus::Rejected(RejectReason::FillOrKillUnfillable),
            "FOK must treat expired resting liquidity as unavailable"
        );
    }

    #[test]
    fn reap_expired_clears_stale_makers_from_the_book() {
        // An expired resting maker that no taker ever hits must still be removed so
        // it stops anchoring best_bid/best_ask (the funding mark, §8).
        let mut e = engine();
        let mut maker = order(
            1,
            Side::Sell,
            SIZE_SCALE,
            100_000 * PRICE_SCALE,
            TimeInForce::Gtc,
            1,
        );
        maker.expiry_ms = 500;
        e.submit(&maker, 100);
        assert_eq!(e.book(0).unwrap().best_ask(), Some(100_000 * PRICE_SCALE));

        // a live maker at a different price stays
        let live = order(
            2,
            Side::Sell,
            SIZE_SCALE,
            101_000 * PRICE_SCALE,
            TimeInForce::Gtc,
            2,
        );
        e.submit(&live, 100);

        let reaped = e.reap_expired(1000);
        assert_eq!(reaped, 1, "exactly the expired maker is reaped");
        assert_eq!(
            e.book(0).unwrap().best_ask(),
            Some(101_000 * PRICE_SCALE),
            "best ask is now the still-live maker, not the expired one"
        );
    }

    #[test]
    fn stream_collects_manifest_lists() {
        let mut e = engine();
        let orders = [
            order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            order(
                2,
                Side::Buy,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                2,
            ),
            {
                let mut o = order(
                    3,
                    Side::Buy,
                    SIZE_SCALE,
                    100_000 * PRICE_SCALE,
                    TimeInForce::Gtc,
                    3,
                );
                o.expiry_ms = 1; // expired
                o
            },
        ];
        let r = e.process_stream(&orders, 1000);
        assert_eq!(r.fills.len(), 1);
        assert_eq!(r.ordered.len(), 2);
        assert_eq!(r.rejected.len(), 1);
        assert_eq!(r.rejected[0].1, RejectReason::Expired);
    }

    #[test]
    fn market_buy_sweeps_multiple_levels() {
        let mut e = engine();
        e.submit(
            &order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        e.submit(
            &order(
                2,
                Side::Sell,
                SIZE_SCALE,
                101_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                2,
            ),
            0,
        );
        // market buy (limit 0) for 2 → sweeps 100k then 101k
        let t = e.submit(
            &order(9, Side::Buy, 2 * SIZE_SCALE, 0, TimeInForce::Ioc, 9),
            0,
        );
        assert_eq!(t.outcome.status, SubmitStatus::FilledFull);
        assert_eq!(t.outcome.fills[0].price, 100_000 * PRICE_SCALE);
        assert_eq!(t.outcome.fills[1].price, 101_000 * PRICE_SCALE);
    }

    #[test]
    fn sell_crosses_best_bid_first() {
        let mut e = engine();
        e.submit(
            &order(
                1,
                Side::Buy,
                SIZE_SCALE,
                99_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        e.submit(
            &order(
                2,
                Side::Buy,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                2,
            ),
            0,
        );
        // seller hits highest bid (100k, owner 2) first
        let t = e.submit(
            &order(
                9,
                Side::Sell,
                SIZE_SCALE,
                99_000 * PRICE_SCALE,
                TimeInForce::Ioc,
                9,
            ),
            0,
        );
        assert_eq!(t.outcome.fills.len(), 1);
        assert_eq!(t.outcome.fills[0].maker, word_u64(2));
        assert_eq!(t.outcome.fills[0].price, 100_000 * PRICE_SCALE);
    }

    #[test]
    fn fok_excludes_self_liquidity() {
        let mut e = engine();
        // the only ask is the taker's own resting order → FOK can't self-trade
        e.submit(
            &order(
                7,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            0,
        );
        let t = e.submit(
            &order(
                7,
                Side::Buy,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Fok,
                2,
            ),
            0,
        );
        assert_eq!(
            t.outcome.status,
            SubmitStatus::Rejected(RejectReason::FillOrKillUnfillable)
        );
        // and the resting maker is untouched (FOK rejected before matching)
        assert_eq!(e.book(0).unwrap().resting_size(Side::Sell), SIZE_SCALE);
    }

    #[test]
    fn deterministic_across_runs() {
        let orders = [
            order(
                1,
                Side::Sell,
                SIZE_SCALE,
                100_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                1,
            ),
            order(
                2,
                Side::Sell,
                SIZE_SCALE,
                101_000 * PRICE_SCALE,
                TimeInForce::Gtc,
                2,
            ),
            order(
                3,
                Side::Buy,
                2 * SIZE_SCALE,
                101_000 * PRICE_SCALE,
                TimeInForce::Ioc,
                3,
            ),
        ];
        let run = || {
            let mut e = engine();
            e.process_stream(&orders, 0).fills
        };
        assert_eq!(run(), run(), "matching must be deterministic");
    }
}

#[cfg(test)]
mod impact_price_tests {
    use super::*;
    use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
    use perp_core::hash::word_u64;
    use perp_core::order::{Side, TimeInForce};

    const THOUSAND: i128 = 1_000 * QUOTE_SCALE;

    /// The depth filter that accepts every live resting order.
    fn all(_: &RestingQuote) -> bool {
        true
    }

    fn rest(book: &mut OrderBook<Keccak256>, n: u64, side: Side, size: i128, price: i128) {
        rest_until(book, n, side, size, price, 0);
    }

    fn rest_until(
        book: &mut OrderBook<Keccak256>,
        n: u64,
        side: Side,
        size: i128,
        price: i128,
        expiry_ms: u64,
    ) {
        let order = Order {
            owner: word_u64(n),
            market_id: 0,
            side,
            size,
            limit_price: price,
            tif: TimeInForce::Gtc,
            reduce_only: false,
            nonce: n,
            expiry_ms,
            ciphertext_commit: word_u64(n.wrapping_mul(31)),
        };
        let out = book.submit(&order, n, 0);
        assert_eq!(out.status, SubmitStatus::Resting, "fixture order must rest");
    }

    #[test]
    fn one_deep_level_prices_at_that_level() {
        let mut book = OrderBook::<Keccak256>::new(0);
        rest(&mut book, 1, Side::Buy, SIZE_SCALE, 99_000 * PRICE_SCALE);
        rest(&mut book, 2, Side::Sell, SIZE_SCALE, 101_000 * PRICE_SCALE);
        assert_eq!(
            book.impact_price(Side::Buy, THOUSAND, 0, all),
            Some(99_000 * PRICE_SCALE)
        );
        assert_eq!(
            book.impact_price(Side::Sell, THOUSAND, 0, all),
            Some(101_000 * PRICE_SCALE)
        );
    }

    /// $400 at $100 and $600 at $50 buy 4 + 12 = 16 base units, an average of
    /// $62.50 — walked from the best price on each side.
    #[test]
    fn the_average_weighs_each_level_by_the_base_it_gives() {
        let mut bids = OrderBook::<Keccak256>::new(0);
        rest(&mut bids, 1, Side::Buy, 4 * SIZE_SCALE, 100 * PRICE_SCALE);
        rest(&mut bids, 2, Side::Buy, 100 * SIZE_SCALE, 50 * PRICE_SCALE);
        assert_eq!(
            bids.impact_price(Side::Buy, THOUSAND, 0, all),
            Some(625 * PRICE_SCALE / 10)
        );
        let mut asks = OrderBook::<Keccak256>::new(0);
        rest(&mut asks, 1, Side::Sell, 12 * SIZE_SCALE, 50 * PRICE_SCALE);
        rest(
            &mut asks,
            2,
            Side::Sell,
            100 * SIZE_SCALE,
            100 * PRICE_SCALE,
        );
        assert_eq!(
            asks.impact_price(Side::Sell, THOUSAND, 0, all),
            Some(625 * PRICE_SCALE / 10)
        );
    }

    #[test]
    fn a_side_without_the_notional_has_no_impact_price() {
        let mut book = OrderBook::<Keccak256>::new(0);
        // 9.99 units at $100 is $999 of bids: one dollar short.
        rest(
            &mut book,
            1,
            Side::Buy,
            999 * SIZE_SCALE / 100,
            100 * PRICE_SCALE,
        );
        assert_eq!(book.impact_price(Side::Buy, THOUSAND, 0, all), None);
        assert_eq!(book.impact_price(Side::Sell, THOUSAND, 0, all), None);
        // one more cent's worth of base reaches exactly $1,000
        rest(&mut book, 2, Side::Buy, SIZE_SCALE / 100, 100 * PRICE_SCALE);
        assert_eq!(
            book.impact_price(Side::Buy, THOUSAND, 0, all),
            Some(100 * PRICE_SCALE)
        );
        assert_eq!(book.impact_price(Side::Buy, 0, 0, all), None);
        assert_eq!(book.impact_price(Side::Buy, -THOUSAND, 0, all), None);
    }

    #[test]
    fn expired_makers_give_no_depth() {
        let mut book = OrderBook::<Keccak256>::new(0);
        rest_until(&mut book, 1, Side::Sell, SIZE_SCALE, 100 * PRICE_SCALE, 500);
        rest(
            &mut book,
            2,
            Side::Sell,
            SIZE_SCALE * 100,
            200 * PRICE_SCALE,
        );
        assert_eq!(
            book.impact_price(Side::Sell, 50 * QUOTE_SCALE, 499, all),
            Some(100 * PRICE_SCALE)
        );
        assert_eq!(
            book.impact_price(Side::Sell, 50 * QUOTE_SCALE, 500, all),
            Some(200 * PRICE_SCALE),
            "the expired $100 ask is skipped"
        );
    }

    /// Orders the filter refuses give no depth, whatever their price: the sweep
    /// moves on to the orders it accepts, and a side whose accepted orders hold
    /// less than the notional has no impact price.
    #[test]
    fn only_orders_the_filter_accepts_are_depth() {
        let mut book = OrderBook::<Keccak256>::new(0);
        rest(&mut book, 1, Side::Sell, SIZE_SCALE, 100 * PRICE_SCALE);
        rest(
            &mut book,
            2,
            Side::Sell,
            SIZE_SCALE * 100,
            200 * PRICE_SCALE,
        );
        assert_eq!(
            book.impact_price(Side::Sell, 50 * QUOTE_SCALE, 0, all),
            Some(100 * PRICE_SCALE)
        );
        let above_150 = |q: &RestingQuote| q.price > 150 * PRICE_SCALE;
        assert_eq!(
            book.impact_price(Side::Sell, 50 * QUOTE_SCALE, 0, above_150),
            Some(200 * PRICE_SCALE),
            "the refused $100 ask is skipped"
        );
        let none = |_: &RestingQuote| false;
        assert_eq!(
            book.impact_price(Side::Sell, 50 * QUOTE_SCALE, 0, none),
            None
        );
    }

    /// The filter sees each live order once, best price first and in arrival order
    /// within a level, with its maker, price, unfilled size and reduce-only flag.
    #[test]
    fn the_filter_sees_live_orders_in_sweep_order() {
        let mut book = OrderBook::<Keccak256>::new(0);
        rest(&mut book, 1, Side::Buy, SIZE_SCALE, 99 * PRICE_SCALE);
        rest(&mut book, 2, Side::Buy, SIZE_SCALE, 100 * PRICE_SCALE);
        rest(&mut book, 3, Side::Buy, SIZE_SCALE * 2, 100 * PRICE_SCALE);
        rest_until(&mut book, 4, Side::Buy, SIZE_SCALE, 101 * PRICE_SCALE, 10);
        let mut seen = Vec::new();
        let _ = book.impact_price(Side::Buy, THOUSAND, 10, |q| {
            seen.push(*q);
            true
        });
        let quote = |n: u64, size: i128, price: i128| RestingQuote {
            owner: word_u64(n),
            price: price * PRICE_SCALE,
            remaining: size,
            reduce_only: false,
        };
        assert_eq!(
            seen,
            [
                quote(2, SIZE_SCALE, 100),
                quote(3, SIZE_SCALE * 2, 100),
                quote(1, SIZE_SCALE, 99),
            ],
            "the expired $101 bid is never shown"
        );
    }

    #[test]
    fn retain_resting_keeps_only_orders_still_on_a_book() {
        let mut e = MatchingEngine::<Keccak256>::new();
        e.open_market(0);
        let order = |n: u64, side: Side| Order {
            owner: word_u64(n),
            market_id: 0,
            side,
            size: SIZE_SCALE,
            limit_price: 100 * PRICE_SCALE,
            tif: TimeInForce::Gtc,
            reduce_only: false,
            nonce: n,
            expiry_ms: 0,
            ciphertext_commit: word_u64(n.wrapping_mul(31)),
        };
        let filled = order(1, Side::Sell);
        let resting = order(2, Side::Sell);
        e.submit(&filled, 0);
        e.submit(&resting, 0);
        // a buy of one unit fills the older ask in full
        e.submit(&order(3, Side::Buy), 0);
        let mut hashes: BTreeSet<Digest> = [
            filled.order_hash::<Keccak256>(),
            resting.order_hash::<Keccak256>(),
            word_u64(99),
        ]
        .into_iter()
        .collect();
        e.retain_resting(&mut hashes);
        assert_eq!(
            hashes.into_iter().collect::<Vec<_>>(),
            [resting.order_hash::<Keccak256>()]
        );
    }

    #[test]
    fn extreme_prices_fail_closed_without_panicking() {
        let mut book = OrderBook::<Keccak256>::new(0);
        // the level notional overflows
        rest(&mut book, 1, Side::Sell, SIZE_SCALE, i128::MAX / 2);
        // the level size overflows
        rest(&mut book, 2, Side::Buy, i128::MAX / 2 + 1, 1);
        rest(&mut book, 3, Side::Buy, i128::MAX / 2 + 1, 1);
        assert_eq!(book.impact_price(Side::Sell, THOUSAND, 0, all), None);
        assert_eq!(book.impact_price(Side::Buy, THOUSAND, 0, all), None);
        // a tiny price with deep size is still a valid, finite average
        let mut deep = OrderBook::<Keccak256>::new(0);
        rest(&mut deep, 1, Side::Buy, i128::MAX / 4, 1);
        assert_eq!(deep.impact_price(Side::Buy, THOUSAND, 0, all), Some(1));
    }
}

#[cfg(test)]
mod execution_removal_tests {
    use super::*;
    use perp_core::order::{Order, Side, TimeInForce};
    fn order(n: u8) -> Order {
        Order {
            owner: [n; 32],
            market_id: 0,
            side: Side::Sell,
            size: 100,
            limit_price: 100,
            tif: TimeInForce::Gtc,
            reduce_only: false,
            nonce: n as u64,
            expiry_ms: 0,
            ciphertext_commit: [n; 32],
        }
    }
    #[test]
    fn expiry_and_liquidation_removals_retain_attribution() {
        let mut e = MatchingEngine::<Keccak256>::new();
        e.open_market(0);
        let mut expired = order(1);
        expired.expiry_ms = 50;
        e.submit(&expired, 1);
        let keeper = order(2);
        e.submit(&keeper, 1);
        let removed = e.reap_expired_with_events(50);
        assert_eq!(
            removed,
            [OrderRemoval {
                order_hash: expired.order_hash::<Keccak256>(),
                reason: "Expired"
            }]
        );
        assert!(e.remaining(&expired.order_hash::<Keccak256>()).is_none());
        let removed = e.cancel_owner_with_events(&keeper.owner);
        assert_eq!(
            removed,
            [OrderRemoval {
                order_hash: keeper.order_hash::<Keccak256>(),
                reason: "Liquidated"
            }]
        );
        assert!(e.remaining(&keeper.order_hash::<Keccak256>()).is_none());
    }
}
