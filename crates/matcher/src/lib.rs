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

pub use book::{
    ImpactWindow, Match, OrderBook, OrderRemoval, RestingQuote, SubmitOutcome, SubmitStatus,
    TradeCheck,
};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use perp_core::hash::{Digest, Hasher, Keccak256};
use perp_core::market::MarketId;
use perp_core::order::{Order, RejectReason, Side};

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

    /// Keep in `hashes` only the orders that still rest on a book, each looked
    /// up by its hash.
    pub fn retain_resting(&self, hashes: &mut BTreeSet<Digest>) {
        hashes.retain(|h| self.books.values().any(|b| b.rests(h)));
    }

    /// Cancel every order resting on `side` of market `market_id` that `select`
    /// picks, in one walk of that side, and return their hashes (see
    /// [`OrderBook::cancel_side_where`]).
    pub fn cancel_side_where<T>(
        &mut self,
        market_id: MarketId,
        side: Side,
        select: impl FnMut(&perp_core::note::PubKey, &Digest, bool) -> Option<T>,
    ) -> Vec<(Digest, T)> {
        self.books
            .get_mut(&market_id)
            .map(|b| b.cancel_side_where(side, select))
            .unwrap_or_default()
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

    /// Cancel every resting order of `owner` in `market_id` only, because a
    /// liquidation on the other side closed some or all of its position there
    /// (removal reason `ForcedClose`). Its orders in other markets stay.
    pub fn cancel_owner_forced_close_with_events(
        &mut self,
        owner: &perp_core::note::PubKey,
        market_id: MarketId,
    ) -> Vec<OrderRemoval> {
        self.books
            .get_mut(&market_id)
            .map(|b| b.cancel_owner_forced_close_with_events(owner))
            .unwrap_or_default()
    }

    /// The seq number that will be assigned to the next accepted order.
    pub fn peek_seq(&self) -> u64 {
        self.next_seq
    }

    /// Submit one order. Returns the assigned seq and the matching outcome.
    /// An order for an unknown market is rejected without consuming a seq.
    pub fn submit(&mut self, order: &Order, now_ms: u64) -> Processed {
        self.submit_journaled(order, now_ms, None, None)
    }

    /// [`Self::submit`], recording the changes to the order's book in `steps`
    /// and asking `check` about each trade, each if given.
    fn submit_journaled(
        &mut self,
        order: &Order,
        now_ms: u64,
        steps: Option<&mut Vec<book::Step>>,
        check: book::Check<'_>,
    ) -> Processed {
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
        let outcome = book.submit_with(order, seq, now_ms, steps, check);
        Processed {
            seq_no: seq,
            outcome,
        }
    }

    /// Process a whole arrival-ordered stream, collecting fills and the
    /// manifest's `ordered` / `rejected` lists (§2).
    pub fn process_stream(&mut self, orders: &[Order], now_ms: u64) -> StreamResult {
        self.process_stream_journaled(orders, now_ms, None, None)
    }

    /// [`Self::process_stream`], asking `check` about each trade before the
    /// book changes for it (audit 2026-11-16 SM-2). The sequencer's last
    /// matching pass settles each fill this way as it is matched, so a fill
    /// that would fail drops its maker or stops its taker before the other
    /// side loses any size to it (see [`TradeCheck`]).
    pub fn process_stream_checked(
        &mut self,
        orders: &[Order],
        now_ms: u64,
        check: &mut dyn FnMut(&Match) -> TradeCheck,
    ) -> StreamResult {
        self.process_stream_journaled(orders, now_ms, None, Some(check))
    }

    /// [`Self::process_stream`], returning with its result what it changed, for
    /// [`Self::undo`] to put back (audit 2026-11-16 SM-2). Recording costs a
    /// step per order the stream rests, takes off a level or trades against, so
    /// putting the books back costs what the stream changed, not a copy of them.
    pub fn process_stream_undoable(
        &mut self,
        orders: &[Order],
        now_ms: u64,
    ) -> (StreamResult, StreamUndo) {
        let mut undo = StreamUndo {
            next_seq: self.next_seq,
            steps: Vec::new(),
        };
        let result = self.process_stream_journaled(orders, now_ms, Some(&mut undo.steps), None);
        (result, undo)
    }

    /// Put the books and the sequence counter back to where they were before
    /// the [`Self::process_stream_undoable`] call that returned `undo`. Nothing
    /// else may have changed the books since.
    pub fn undo(&mut self, undo: StreamUndo) {
        for (market_id, step) in undo.steps.into_iter().rev() {
            self.books
                .get_mut(&market_id)
                .expect("an undone step's market has a book")
                .undo(step);
        }
        self.next_seq = undo.next_seq;
    }

    fn process_stream_journaled(
        &mut self,
        orders: &[Order],
        now_ms: u64,
        mut steps: Option<&mut Vec<(MarketId, book::Step)>>,
        mut check: book::Check<'_>,
    ) -> StreamResult {
        let mut result = StreamResult::default();
        let mut scratch = Vec::new();
        for order in orders {
            let p = match steps.as_deref_mut() {
                None => self.submit_journaled(order, now_ms, None, book::reborrow(&mut check)),
                Some(steps) => {
                    let p = self.submit_journaled(
                        order,
                        now_ms,
                        Some(&mut scratch),
                        book::reborrow(&mut check),
                    );
                    steps.extend(scratch.drain(..).map(|step| (order.market_id, step)));
                    p
                }
            };
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

/// What one [`MatchingEngine::process_stream_undoable`] call changed: the
/// sequence counter before it and each change to a book, oldest first.
#[derive(Debug)]
pub struct StreamUndo {
    next_seq: u64,
    steps: Vec<(MarketId, book::Step)>,
}

impl StreamUndo {
    /// The changes recorded: one per order rested, taken off a level or traded
    /// against, and per level removed.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the stream changed no book.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
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

    /// Every book's hash index matches its levels.
    fn assert_indexed(e: &MatchingEngine) {
        for book in e.books.values() {
            book.assert_indexed();
        }
    }

    /// The remainder of the order with `hash` as a walk of the books finds it.
    fn walked(e: &MatchingEngine, hash: &Digest) -> Option<i128> {
        e.books.values().find_map(|book| {
            book.resting_orders()
                .find(|(_, q, _)| q.order_hash == *hash)
                .map(|(_, q, _)| q.remaining)
        })
    }

    /// Audit 2026-11-16 GA-1 + SM-2: over pseudo-random streams in two markets
    /// (self-trades, expiries, fill-or-kill, post-only, market orders, partial
    /// fills) and cancellations, the hash index always matches the books and
    /// every lookup agrees with a walk of them; an undoable stream matches as a
    /// plain one does, and undoing it puts back exactly the books and the
    /// sequence counter it started from, so a rematch sees the batch-start book.
    #[test]
    fn audit_1116_sm2_undoing_a_stream_puts_back_the_books_it_started_from() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        for case in 0..300 {
            let mut e = engine();
            e.open_market(1);
            let mut nonce = 0u64;
            let mut seen: Vec<Digest> = Vec::new();
            for now in 0..8u64 {
                let orders: Vec<Order> = (0..next(14))
                    .map(|_| {
                        nonce += 1;
                        let side = if next(2) == 0 { Side::Buy } else { Side::Sell };
                        let price = match next(6) {
                            0 => 0,
                            n => (99_998 + n as i128) * PRICE_SCALE,
                        };
                        let tif = match next(5) {
                            0 => TimeInForce::Ioc,
                            1 => TimeInForce::Fok,
                            2 => TimeInForce::PostOnly,
                            _ => TimeInForce::Gtc,
                        };
                        let mut o = order(
                            next(5),
                            side,
                            (1 + next(5) as i128) * SIZE_SCALE / 10,
                            price,
                            tif,
                            nonce,
                        );
                        o.market_id = next(2);
                        if next(4) == 0 {
                            o.expiry_ms = now + 1 + next(3);
                        }
                        o
                    })
                    .collect();
                seen.extend(orders.iter().map(|o| o.order_hash::<Keccak256>()));

                let before = alloc::format!("{e:?}");
                let mut plain = e.clone();
                let expected = alloc::format!("{:?}", plain.process_stream(&orders, now));
                let (result, undo) = e.process_stream_undoable(&orders, now);
                assert_eq!(alloc::format!("{result:?}"), expected, "case {case}");
                assert_eq!(
                    alloc::format!("{e:?}"),
                    alloc::format!("{plain:?}"),
                    "case {case}"
                );
                assert_indexed(&e);
                e.undo(undo);
                assert_eq!(alloc::format!("{e:?}"), before, "case {case}: undo");
                assert_indexed(&e);
                e.process_stream(&orders, now);

                match next(4) {
                    0 if !seen.is_empty() => {
                        let hash = seen[next(seen.len() as u64) as usize];
                        let walked = walked(&e, &hash);
                        assert_eq!(e.cancel_order(&hash), walked, "case {case}");
                    }
                    1 => {
                        e.cancel_owner_orders(&word_u64(next(5)));
                    }
                    2 => {
                        let side = if next(2) == 0 { Side::Buy } else { Side::Sell };
                        let (market, owner) = (next(2), word_u64(next(5)));
                        let theirs = |e: &MatchingEngine| -> Vec<Digest> {
                            e.books[&market]
                                .resting_orders()
                                .filter(|(s, q, _)| {
                                    *s == side && q.owner == owner && !q.reduce_only
                                })
                                .map(|(_, q, _)| q.order_hash)
                                .collect()
                        };
                        let expected = theirs(&e);
                        let taken: Vec<Digest> = e
                            .cancel_side_where(market, side, |o, _, reduce_only| {
                                (*o == owner && !reduce_only).then_some(())
                            })
                            .into_iter()
                            .map(|(hash, ())| hash)
                            .collect();
                        assert_eq!(taken, expected);
                        assert!(theirs(&e).is_empty(), "case {case}");
                    }
                    _ => {
                        e.reap_expired(now);
                    }
                }
                assert_indexed(&e);
                for hash in &seen {
                    assert_eq!(e.remaining(hash), walked(&e, hash), "case {case}");
                }
                let mut resting: BTreeSet<Digest> = seen.iter().copied().collect();
                e.retain_resting(&mut resting);
                assert!(resting.iter().all(|h| walked(&e, h).is_some()));
                assert!(seen
                    .iter()
                    .all(|h| resting.contains(h) || walked(&e, h).is_none()));
            }
        }
    }

    /// Audit 2026-11-16 SM-2, round 1 review: the sequencer's last matching
    /// pass asks about each trade before the book changes for it, and a trade it
    /// refuses must cost no other order any size. Over pseudo-random streams in
    /// two markets, with a check that drops some makers and stops some takers:
    /// the fills are exactly the trades the check let through, in order; every
    /// order resting before the stream lost exactly what it traded, or left the
    /// book filled, dropped or removed; every order of the stream that rests
    /// holds its size less what it traded; a dropped maker and a stopped taker
    /// trade no more and do not rest; a fill-or-kill that is killed trades
    /// nothing. With a check that lets every trade through, a checked stream
    /// matches as a plain one does.
    #[test]
    fn audit_1116_sm2_a_checked_stream_takes_size_only_from_the_trades_it_allows() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        let (mut dropped_total, mut stopped_total, mut killed_total) = (0, 0, 0);
        for case in 0..300 {
            let mut e = engine();
            e.open_market(1);
            let mut nonce = 0u64;
            for now in 0..8u64 {
                let orders: Vec<Order> = (0..next(14))
                    .map(|_| {
                        nonce += 1;
                        let side = if next(2) == 0 { Side::Buy } else { Side::Sell };
                        let price = match next(6) {
                            0 => 0,
                            n => (99_998 + n as i128) * PRICE_SCALE,
                        };
                        let tif = match next(5) {
                            0 => TimeInForce::Ioc,
                            1 => TimeInForce::Fok,
                            2 => TimeInForce::PostOnly,
                            _ => TimeInForce::Gtc,
                        };
                        let mut o = order(
                            next(5),
                            side,
                            (1 + next(5) as i128) * SIZE_SCALE / 10,
                            price,
                            tif,
                            nonce,
                        );
                        o.market_id = next(2);
                        if next(4) == 0 {
                            o.expiry_ms = now + 1 + next(3);
                        }
                        o
                    })
                    .collect();

                let mut plain = e.clone();
                let expected = alloc::format!("{:?}", plain.process_stream(&orders, now));
                let mut allowing = e.clone();
                let allowed =
                    allowing.process_stream_checked(&orders, now, &mut |_| TradeCheck::TRADE);
                assert_eq!(alloc::format!("{allowed:?}"), expected, "case {case}");
                assert_eq!(
                    alloc::format!("{allowing:?}"),
                    alloc::format!("{plain:?}"),
                    "case {case}"
                );

                let before: BTreeMap<Digest, i128> = e
                    .books
                    .values()
                    .flat_map(|b| b.resting_orders())
                    .map(|(_, q, _)| (q.order_hash, q.remaining))
                    .collect();
                let salt = next(1 << 16) as u8;
                let mut asked: Vec<(Match, TradeCheck)> = Vec::new();
                let result = e.process_stream_checked(&orders, now, &mut |m| {
                    let verdict = TradeCheck {
                        drop_maker: (m.maker_order_hash[0] ^ salt).is_multiple_of(4),
                        stop_taker: (m.taker_order_hash[1] ^ salt).is_multiple_of(5),
                    };
                    asked.push((*m, verdict));
                    verdict
                });
                assert_indexed(&e);
                let traded: Vec<Match> = asked
                    .iter()
                    .filter(|(_, v)| *v == TradeCheck::TRADE)
                    .map(|(m, _)| *m)
                    .collect();
                assert_eq!(result.fills, traded, "case {case}");
                let dropped: BTreeSet<Digest> = asked
                    .iter()
                    .filter(|(_, v)| v.drop_maker)
                    .map(|(m, _)| m.maker_order_hash)
                    .collect();
                let stopped: BTreeSet<Digest> = asked
                    .iter()
                    .filter(|(_, v)| v.stop_taker)
                    .map(|(m, _)| m.taker_order_hash)
                    .collect();
                dropped_total += dropped.len();
                stopped_total += stopped.len();
                let removed: BTreeSet<Digest> = result
                    .processed
                    .iter()
                    .flat_map(|p| p.outcome.removals.iter().map(|r| r.order_hash))
                    .collect();
                let traded_by = |hash: &Digest| -> i128 {
                    result
                        .fills
                        .iter()
                        .filter(|m| m.maker_order_hash == *hash || m.taker_order_hash == *hash)
                        .map(|m| m.size)
                        .sum()
                };
                for (hash, remaining) in &before {
                    let traded = traded_by(hash);
                    match e.remaining(hash) {
                        Some(left) => {
                            assert_eq!(left, remaining - traded, "case {case}: a maker lost size")
                        }
                        None => assert!(
                            traded == *remaining
                                || dropped.contains(hash)
                                || removed.contains(hash),
                            "case {case}: a maker left the book unreported"
                        ),
                    }
                }
                for (o, p) in orders.iter().zip(&result.processed) {
                    let hash = p.outcome.order_hash;
                    if let Some(left) = e.remaining(&hash) {
                        assert!(
                            !stopped.contains(&hash),
                            "case {case}: a stopped taker rests"
                        );
                        if !before.contains_key(&hash) {
                            assert_eq!(left, o.size - traded_by(&hash), "case {case}");
                        }
                    }
                    if dropped.contains(&hash) || stopped.contains(&hash) {
                        let last = asked
                            .iter()
                            .rposition(|(m, v)| {
                                (v.drop_maker && m.maker_order_hash == hash)
                                    || (v.stop_taker && m.taker_order_hash == hash)
                            })
                            .unwrap();
                        assert!(
                            asked[last + 1..]
                                .iter()
                                .all(|(m, v)| *v != TradeCheck::TRADE
                                    || (m.maker_order_hash != hash && m.taker_order_hash != hash)),
                            "case {case}: an order traded after it was dropped or stopped"
                        );
                    }
                    if p.outcome.status
                        == SubmitStatus::Rejected(RejectReason::FillOrKillUnfillable)
                        && !p.outcome.fills.is_empty()
                    {
                        panic!("case {case}: a killed fill-or-kill traded");
                    }
                    if o.tif == TimeInForce::Fok
                        && p.outcome.status
                            == SubmitStatus::Rejected(RejectReason::FillOrKillUnfillable)
                    {
                        killed_total += 1;
                    }
                }
            }
        }
        assert!(
            dropped_total > 100 && stopped_total > 100 && killed_total > 10,
            "{dropped_total} dropped, {stopped_total} stopped, {killed_total} killed"
        );
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

    /// Rest a GTC order of owner `n` and return its hash.
    fn rest(
        book: &mut OrderBook<Keccak256>,
        n: u64,
        side: Side,
        size: i128,
        price: i128,
    ) -> Digest {
        rest_until(book, n, side, size, price, 0)
    }

    fn rest_until(
        book: &mut OrderBook<Keccak256>,
        n: u64,
        side: Side,
        size: i128,
        price: i128,
        expiry_ms: u64,
    ) -> Digest {
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
        out.order_hash
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
    /// within a level, with its hash, maker, price, unfilled size and reduce-only
    /// flag.
    #[test]
    fn the_filter_sees_live_orders_in_sweep_order() {
        let mut book = OrderBook::<Keccak256>::new(0);
        let hashes = [
            rest(&mut book, 1, Side::Buy, SIZE_SCALE, 99 * PRICE_SCALE),
            rest(&mut book, 2, Side::Buy, SIZE_SCALE, 100 * PRICE_SCALE),
            rest(&mut book, 3, Side::Buy, SIZE_SCALE * 2, 100 * PRICE_SCALE),
        ];
        rest_until(&mut book, 4, Side::Buy, SIZE_SCALE, 101 * PRICE_SCALE, 10);
        let mut seen = Vec::new();
        let _ = book.impact_price(Side::Buy, THOUSAND, 10, |q| {
            seen.push(*q);
            true
        });
        let quote = |n: u64, size: i128, price: i128| RestingQuote {
            order_hash: hashes[n as usize - 1],
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

    /// A window walks only the levels inside its price range (never showing the
    /// filter an order outside it). Inside it every live order is shown to the
    /// filter, however small, and the orders the filter refuses cost the walk
    /// nothing: no number of them ahead of the depth leaves a side without its
    /// impact price.
    #[test]
    fn a_window_bounds_the_levels_and_has_no_order_budget() {
        let mut book = OrderBook::<Keccak256>::new(0);
        // three asks of just under $50 at $90, $100 and $110, and a deep ask at $120
        for (n, price) in [(1, 90), (2, 100), (3, 110)] {
            rest(
                &mut book,
                n,
                Side::Sell,
                SIZE_SCALE / 2 * 100 / price,
                price * PRICE_SCALE,
            );
        }
        rest(
            &mut book,
            4,
            Side::Sell,
            100 * SIZE_SCALE,
            120 * PRICE_SCALE,
        );
        let window = |lo: i128, hi: i128| ImpactWindow {
            lo: lo * PRICE_SCALE,
            hi: hi * PRICE_SCALE,
        };
        let mut seen = Vec::new();
        let mut record = |q: &RestingQuote| {
            seen.push(q.price / PRICE_SCALE);
            true
        };
        // the $90 ask lies below the window and the $120 one above it: the $100 of
        // depth inside it is short of $140
        assert_eq!(
            book.impact_price_within(
                Side::Sell,
                140 * QUOTE_SCALE,
                0,
                window(95, 115),
                &mut record
            ),
            None
        );
        assert_eq!(seen, [100, 110]);
        // the same walk without the window reaches $140 at the $110 level
        assert!(book
            .impact_price_within(
                Side::Sell,
                140 * QUOTE_SCALE,
                0,
                ImpactWindow::UNBOUNDED,
                all
            )
            .is_some());
        // 10,000 one-unit asks at $95 that the filter refuses, ahead of the $100
        // ask: the walk passes all of them and prices $90 of depth at $100 and $110
        for n in 0..10_000 {
            rest(&mut book, 100 + n, Side::Sell, 1, 95 * PRICE_SCALE);
        }
        let mut shown = 0usize;
        assert_eq!(
            book.impact_price_within(Side::Sell, 90 * QUOTE_SCALE, 0, window(95, 115), |q| {
                shown += 1;
                q.remaining > 1
            }),
            book.impact_price_within(Side::Sell, 90 * QUOTE_SCALE, 0, window(96, 115), all)
        );
        assert_eq!(shown, 10_002);
        // and, counted, each one-unit ask is depth like any other
        let mut tiny = 0usize;
        assert!(book
            .impact_price_within(Side::Sell, 90 * QUOTE_SCALE, 0, window(95, 115), |q| {
                tiny += usize::from(q.remaining == 1);
                true
            })
            .is_some());
        assert_eq!(tiny, 10_000);
        // the bids side walks its window from the top down
        let mut bids = OrderBook::<Keccak256>::new(0);
        for (n, price) in [(5, 90), (6, 100), (7, 110)] {
            rest(&mut bids, n, Side::Buy, SIZE_SCALE, price * PRICE_SCALE);
        }
        let mut seen = Vec::new();
        let _ = bids.impact_price_within(Side::Buy, THOUSAND, 0, window(95, 105), |q| {
            seen.push(q.price / PRICE_SCALE);
            true
        });
        assert_eq!(seen, [100]);
        // an empty or inverted window has no depth
        assert_eq!(
            bids.impact_price_within(Side::Buy, 50 * QUOTE_SCALE, 0, window(105, 95), all),
            None
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
        // the order's notional overflows
        rest(&mut book, 1, Side::Sell, SIZE_SCALE, i128::MAX / 2);
        assert_eq!(book.impact_price(Side::Sell, THOUSAND, 0, all), None);
        // two bids whose sizes would overflow summed: the first alone holds the
        // notional, so the walk ends there with a valid, finite average
        rest(&mut book, 2, Side::Buy, i128::MAX / 2 + 1, 1);
        rest(&mut book, 3, Side::Buy, i128::MAX / 2 + 1, 1);
        assert_eq!(book.impact_price(Side::Buy, THOUSAND, 0, all), Some(1));
        // a tiny price with deep size is still a valid, finite average
        let mut deep = OrderBook::<Keccak256>::new(0);
        rest(&mut deep, 1, Side::Buy, i128::MAX / 4, 1);
        assert_eq!(deep.impact_price(Side::Buy, THOUSAND, 0, all), Some(1));
        // an overflowing order the filter refuses does not end the walk
        let mut asks = OrderBook::<Keccak256>::new(0);
        rest(&mut asks, 1, Side::Sell, i128::MAX / 2 + 1, 2);
        rest(
            &mut asks,
            2,
            Side::Sell,
            100 * SIZE_SCALE,
            100 * PRICE_SCALE,
        );
        assert_eq!(asks.impact_price(Side::Sell, THOUSAND, 0, all), None);
        assert_eq!(
            asks.impact_price(Side::Sell, THOUSAND, 0, |q| q.price > 2),
            Some(100 * PRICE_SCALE)
        );
    }

    /// Audit 2026-11-16 SM-3: the sweep checks the notional after each order it
    /// counts, not after a whole level. $50,000 of bids at $100 followed by 10,000
    /// more orders at the same price: the first order already holds the $1,000, so
    /// the filter sees it alone and never the orders queued behind it.
    #[test]
    fn audit_1116_sm3_the_sweep_stops_at_the_order_that_completes_the_notional() {
        let mut book = OrderBook::<Keccak256>::new(0);
        rest(&mut book, 1, Side::Buy, 500 * SIZE_SCALE, 100 * PRICE_SCALE);
        for n in 2..10_002 {
            rest(&mut book, n, Side::Buy, SIZE_SCALE / 100, 100 * PRICE_SCALE);
        }
        let mut shown = 0usize;
        let price = book.impact_price(Side::Buy, THOUSAND, 0, |_| {
            shown += 1;
            true
        });
        assert_eq!(price, Some(100 * PRICE_SCALE));
        assert_eq!(shown, 1, "the walk ends inside the level");
    }

    /// Audit 2026-11-16 GA-1: the gateway looks up each order a batch touched by its
    /// hash, and a ban or a cancellation removes one order by its hash. Neither
    /// may walk the book: 4,096 bids rest in one level and 4,096 asks across 64
    /// levels, and the order looked up rests last in its queue. Finding it,
    /// checking its owner and cancelling it each examine a handful of orders.
    #[test]
    fn audit_1116_ga1_an_order_is_found_by_its_hash_without_walking_the_book() {
        let mut book = OrderBook::<Keccak256>::new(0);
        let size = SIZE_SCALE / 100;
        for n in 1..=4_096 {
            rest(&mut book, n, Side::Buy, size, 99_000 * PRICE_SCALE);
        }
        for n in 4_097..=8_192 {
            let price = (101_000 + i128::from(n as u8 % 64)) * PRICE_SCALE;
            rest(&mut book, n, Side::Sell, size, price);
        }
        let last_bid = rest(&mut book, 8_193, Side::Buy, size, 99_000 * PRICE_SCALE);
        let last_ask = rest(&mut book, 8_194, Side::Sell, size, 101_063 * PRICE_SCALE);
        let examined = |lookup: &mut dyn FnMut()| {
            book::ORDERS_VISITED.with(|n| n.set(0));
            lookup();
            book::ORDERS_VISITED.with(core::cell::Cell::get)
        };
        for hash in [last_bid, last_ask] {
            let n = examined(&mut || assert_eq!(book.remaining(&hash), Some(size)));
            assert!(n <= 32, "remaining examined {n} orders");
        }
        let owner = word_u64(8_193);
        let n = examined(&mut || assert_eq!(book.remaining_for(&owner, &last_bid), Some(size)));
        assert!(n <= 32, "remaining_for examined {n} orders");
        let n = examined(&mut || assert!(book.remaining(&[0xAB; 32]).is_none()));
        assert!(n <= 32, "a miss examined {n} orders");
        let n = examined(&mut || assert_eq!(book.cancel(&last_bid), Some(size)));
        assert!(n <= 32, "cancel examined {n} orders");
        assert!(book.remaining(&last_bid).is_none());
    }

    /// Where every order counts, the per-order walk prices a side exactly as a walk
    /// that sums each level first: pseudo-random books of a few levels, compared
    /// with that reference.
    #[test]
    fn audit_1116_sm3_the_per_order_walk_prices_like_the_per_level_walk() {
        let mut seed = 0x5eed_u64;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        for case in 0..200 {
            let mut book = OrderBook::<Keccak256>::new(0);
            let mut levels: Vec<(i128, i128)> = Vec::new();
            for n in 0..(1 + next(30)) {
                let price = (95 + next(10) as i128) * PRICE_SCALE;
                let size = (1 + next(400) as i128) * SIZE_SCALE / 100;
                rest(&mut book, 1 + n, Side::Sell, size, price);
                match levels.iter_mut().find(|(p, _)| *p == price) {
                    Some(level) => level.1 += size,
                    None => levels.push((price, size)),
                }
            }
            levels.sort();
            let notional = (1 + next(2_000) as i128) * QUOTE_SCALE;
            let divisor = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
            let target = notional * divisor;
            let (mut left, mut base) = (target, 0i128);
            let mut reference = None;
            for (price, size) in levels {
                if size * price >= left {
                    reference = Some(target * price / (base * price + left));
                    break;
                }
                base += size;
                left -= size * price;
            }
            assert_eq!(
                book.impact_price(Side::Sell, notional, 0, all),
                reference,
                "case {case}"
            );
        }
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

    #[test]
    fn audit_1116_pc1_a_forced_close_cancels_the_owners_orders_in_that_market_only() {
        let mut e = MatchingEngine::<Keccak256>::new();
        e.open_market(0);
        e.open_market(1);
        let here = order(3);
        let mut elsewhere = order(3);
        elsewhere.market_id = 1;
        elsewhere.nonce = 30;
        let other_owner = order(4);
        for o in [&here, &elsewhere, &other_owner] {
            e.submit(o, 1);
        }
        let removed = e.cancel_owner_forced_close_with_events(&here.owner, 0);
        assert_eq!(
            removed,
            [OrderRemoval {
                order_hash: here.order_hash::<Keccak256>(),
                reason: "ForcedClose"
            }]
        );
        assert!(e.remaining(&here.order_hash::<Keccak256>()).is_none());
        assert_eq!(e.remaining(&elsewhere.order_hash::<Keccak256>()), Some(100));
        assert_eq!(
            e.remaining(&other_owner.order_hash::<Keccak256>()),
            Some(100)
        );
        assert!(e
            .cancel_owner_forced_close_with_events(&here.owner, 7)
            .is_empty());
    }
}
