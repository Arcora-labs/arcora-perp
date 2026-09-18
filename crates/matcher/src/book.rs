//! A single market's continuous limit order book with deterministic price-time
//! priority (§1 hot path, §4 Proof-v2 target).
//!
//! Determinism is the whole point: given the same ordered stream of submissions,
//! the book produces byte-identical fills on every machine and inside the zkVM
//! guest. Priority is **price, then arrival sequence** — never wall-clock, never
//! map iteration order. Bids are keyed high-to-low, asks low-to-high; within a
//! price level orders rest in a FIFO queue ordered by the monotonically
//! increasing `seq` the sequencer assigned at receipt (§2).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use perp_core::hash::Digest;
use perp_core::market::MarketId;
use perp_core::note::PubKey;
use perp_core::order::{Order, RejectReason, Side, TimeInForce};

/// A fill produced by the matcher: maps directly to a settlement `BatchOp::Fill`
/// once an oracle transcript is attached by the settlement layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match {
    pub market_id: MarketId,
    pub taker: PubKey,
    pub maker: PubKey,
    /// The aggressing side (taker's direction).
    pub taker_side: Side,
    pub size: i128,
    /// Execution price = the resting maker's price (price-time priority).
    pub price: i128,
    pub taker_order_hash: Digest,
    pub maker_order_hash: Digest,
    /// Whether each side's order is reduce-only — settlement rejects the fill if it would
    /// increase a reduce-only party's absolute exposure (audit DP-009).
    pub taker_reduce_only: bool,
    pub maker_reduce_only: bool,
}

/// What happened to a submitted order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitStatus {
    /// Fully filled on entry.
    FilledFull,
    /// Partially filled; the remainder rests on the book (GTC).
    FilledResting { resting: i128 },
    /// Partially filled; the remainder was cancelled (IOC).
    FilledCancelled { cancelled: i128 },
    /// Nothing filled; the whole order rests on the book (GTC / post-only).
    Resting,
    /// Nothing filled and nothing rested (IOC with no cross).
    CancelledNoFill,
    /// Rejected without touching the book.
    Rejected(RejectReason),
}

/// A non-fill removal. Native output metadata, not part of the serialized book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderRemoval {
    pub order_hash: Digest,
    pub reason: &'static str,
}

/// The result of submitting one order.
#[derive(Clone, Debug)]
pub struct SubmitOutcome {
    pub order_hash: Digest,
    pub fills: Vec<Match>,
    pub removals: Vec<OrderRemoval>,
    pub status: SubmitStatus,
}

/// A resting order on the book.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct Resting {
    order_hash: Digest,
    owner: PubKey,
    remaining: i128,
    price: i128,
    /// Arrival sequence (§2 receipt `seq_no`). The FIFO queue already encodes
    /// time priority for matching; `seq` is retained as explicit witness data
    /// for the Proof-v2 circuit, which must *prove* price-then-time priority
    /// rather than rely on container ordering. `reduce_only` is carried through
    /// to settlement, which enforces it against position state.
    #[allow(dead_code)]
    seq: u64,
    #[allow(dead_code)]
    reduce_only: bool,
    /// Good-till-time bound carried from the order (0 = no expiry). A resting maker
    /// whose expiry has passed relative to the batch clock is void and must not
    /// provide liquidity, so matching prunes it instead of trading against it.
    expiry_ms: u64,
}

/// Is this resting maker expired at the batch reference clock `now_ms`?
/// (`expiry_ms == 0` means good-till-cancelled — never expires.)
fn resting_expired(r: &Resting, now_ms: u64) -> bool {
    r.expiry_ms != 0 && now_ms >= r.expiry_ms
}

/// One market's order book.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct OrderBook<H: perp_core::hash::Hasher> {
    market_id: MarketId,
    /// price → FIFO queue (by seq). Bids and asks both keyed by raw price.
    bids: BTreeMap<i128, VecDeque<Resting>>,
    asks: BTreeMap<i128, VecDeque<Resting>>,
    _h: core::marker::PhantomData<H>,
}

impl<H: perp_core::hash::Hasher> OrderBook<H> {
    pub fn new(market_id: MarketId) -> Self {
        Self {
            market_id,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            _h: core::marker::PhantomData,
        }
    }

    pub fn market_id(&self) -> MarketId {
        self.market_id
    }

    /// Best bid (highest price) / best ask (lowest price), for inspection.
    pub fn best_bid(&self) -> Option<i128> {
        self.bids.keys().next_back().copied()
    }
    pub fn best_ask(&self) -> Option<i128> {
        self.asks.keys().next().copied()
    }

    /// Total resting size on a side (test/inspection helper).
    pub fn resting_size(&self, side: Side) -> i128 {
        let book = match side {
            Side::Buy => &self.bids,
            Side::Sell => &self.asks,
        };
        book.values()
            .flat_map(|q| q.iter())
            .map(|r| r.remaining)
            .sum()
    }

    /// Internal execution lookup. Public depth remains undisclosed.
    pub fn remaining(&self, hash: &Digest) -> Option<i128> {
        self.bids
            .values()
            .chain(self.asks.values())
            .flat_map(|q| q.iter())
            .find(|o| &o.order_hash == hash)
            .map(|o| o.remaining)
    }

    /// Owner-scoped remaining quantity, for cancellation eligibility. This is
    /// not public market depth and must only be exposed through authenticated views.
    pub fn remaining_for(&self, owner: &PubKey, order_hash: &Digest) -> Option<i128> {
        self.bids
            .values()
            .chain(self.asks.values())
            .flat_map(|queue| queue.iter())
            .find(|r| &r.owner == owner && &r.order_hash == order_hash)
            .map(|r| r.remaining)
    }

    /// Collect this owner's live hashes once when serving a whole order list.
    /// Avoid a full-book scan for every historical row in the authenticated view.
    pub fn resting_hashes_for(&self, owner: &PubKey) -> Vec<Digest> {
        self.bids
            .values()
            .chain(self.asks.values())
            .flat_map(|queue| queue.iter())
            .filter(|r| &r.owner == owner && r.remaining > 0)
            .map(|r| r.order_hash)
            .collect()
    }

    /// Does `price` cross a resting order on `opposite`? `limit == 0` means a
    /// market order (always crosses if liquidity exists).
    fn price_crosses(taker_side: Side, limit: i128, resting_price: i128) -> bool {
        match taker_side {
            Side::Buy => limit == 0 || resting_price <= limit,
            Side::Sell => limit == 0 || resting_price >= limit,
        }
    }

    /// Liquidity crossable by a taker on `taker_side` at `limit`, excluding the
    /// taker's own resting orders (those would be self-trade-prevented) and any
    /// resting maker expired at `now_ms` (those are void and won't trade). Used for
    /// the fill-or-kill all-or-nothing pre-check, so it must count exactly the
    /// liquidity the matching loop can actually consume — no expired maker, or FOK
    /// would pass the check and then under-fill.
    fn crossable_liquidity(
        &self,
        taker_side: Side,
        limit: i128,
        taker: &PubKey,
        now_ms: u64,
    ) -> i128 {
        let book = match taker_side {
            Side::Buy => &self.asks,
            Side::Sell => &self.bids,
        };
        let mut total: i128 = 0;
        // iterate best-first
        let iter: Vec<(&i128, &VecDeque<Resting>)> = match taker_side {
            Side::Buy => book.iter().collect(),
            Side::Sell => book.iter().rev().collect(),
        };
        for (price, q) in iter {
            if !Self::price_crosses(taker_side, limit, *price) {
                break;
            }
            for r in q {
                if &r.owner != taker && !resting_expired(r, now_ms) {
                    total = total.saturating_add(r.remaining);
                }
            }
        }
        total
    }

    /// Pop the best opposite price level key for a taker side.
    fn best_opposite_key(&self, taker_side: Side) -> Option<i128> {
        match taker_side {
            Side::Buy => self.asks.keys().next().copied(),
            Side::Sell => self.bids.keys().next_back().copied(),
        }
    }

    /// Submit an order to the book. `seq` is the sequencer-assigned arrival
    /// number (§2); `now_ms` is the batch reference clock for expiry.
    pub fn submit(&mut self, order: &Order, seq: u64, now_ms: u64) -> SubmitOutcome {
        debug_assert_eq!(order.market_id, self.market_id);
        let order_hash = order.order_hash::<H>();
        let mut out = SubmitOutcome {
            order_hash,
            fills: Vec::new(),
            removals: Vec::new(),
            status: SubmitStatus::Resting,
        };

        // 1. expiry
        if order.expiry_ms != 0 && now_ms >= order.expiry_ms {
            out.status = SubmitStatus::Rejected(RejectReason::Expired);
            return out;
        }
        if order.size <= 0 {
            out.status = SubmitStatus::Rejected(RejectReason::Cancelled);
            return out;
        }
        // A negative limit price is nonsensical — 0 means "market order" (no limit), and
        // any real limit is positive. Reject it up front instead of letting it rest as a
        // poison order that only produces a price<=0 fill the engine rejects at
        // settlement (which would also consume a counterparty for nothing) (audit Tier-3).
        if order.limit_price < 0 {
            out.status = SubmitStatus::Rejected(RejectReason::Cancelled);
            return out;
        }

        let side = order.side;
        let limit = order.limit_price;

        // 2. post-only must never take liquidity.
        //
        // Deliberately conservative: we reject if the order crosses the best
        // opposite price *even when that level holds only the taker's own resting
        // order*. The matching path would self-trade-prevent (cancel that maker)
        // rather than fill — so we could instead let the post-only rest. We choose
        // rejection: a post-only is a "maker, or nothing" instruction, and silently
        // cancelling the owner's existing resting order to honor a new post-only is
        // more surprising than a clean PostOnlyWouldTake. See the
        // `post_only_rejects_even_against_own_order` regression test.
        if order.tif == TimeInForce::PostOnly {
            if let Some(best) = self.best_opposite_key(side) {
                if Self::price_crosses(side, limit, best) {
                    out.status = SubmitStatus::Rejected(RejectReason::PostOnlyWouldTake);
                    return out;
                }
            }
            // market post-only is nonsensical (would always take) → reject
            if limit == 0 {
                out.status = SubmitStatus::Rejected(RejectReason::PostOnlyWouldTake);
                return out;
            }
            self.rest(order, order_hash, order.size, seq);
            out.status = SubmitStatus::Resting;
            return out;
        }

        // 3. fill-or-kill: all-or-nothing pre-check before mutating the book
        if order.tif == TimeInForce::Fok
            && self.crossable_liquidity(side, limit, &order.owner, now_ms) < order.size
        {
            out.status = SubmitStatus::Rejected(RejectReason::FillOrKillUnfillable);
            return out;
        }

        // 4. match against the opposite side, best price first
        let mut remaining = order.size;
        while remaining > 0 {
            let Some(level_price) = self.best_opposite_key(side) else {
                break;
            };
            if !Self::price_crosses(side, limit, level_price) {
                break;
            }
            let opposite = match side {
                Side::Buy => &mut self.asks,
                Side::Sell => &mut self.bids,
            };
            let queue = opposite.get_mut(&level_price).expect("level exists");
            // drop makers at the front that cannot trade: self-trade prevention
            // (own resting order is cancelled, not matched) and expired makers
            // (good-till-time elapsed → void liquidity). Both are removed from the
            // book; matching only ever consumes from the front, so a non-front
            // own/expired maker is handled once it reaches the front.
            while let Some(front) = queue.front() {
                if front.owner == order.owner || resting_expired(front, now_ms) {
                    let removed = queue.pop_front().expect("front exists");
                    out.removals.push(OrderRemoval {
                        order_hash: removed.order_hash,
                        reason: if resting_expired(&removed, now_ms) {
                            "Expired"
                        } else {
                            "SelfTradePrevented"
                        },
                    });
                } else {
                    break;
                }
            }
            let Some(front) = queue.front_mut() else {
                opposite.remove(&level_price);
                continue;
            };
            let trade = remaining.min(front.remaining);
            out.fills.push(Match {
                market_id: self.market_id,
                taker: order.owner,
                maker: front.owner,
                taker_side: side,
                size: trade,
                price: front.price,
                taker_order_hash: order_hash,
                maker_order_hash: front.order_hash,
                taker_reduce_only: order.reduce_only,
                maker_reduce_only: front.reduce_only,
            });
            remaining -= trade;
            front.remaining -= trade;
            if front.remaining == 0 {
                queue.pop_front();
            }
            if queue.is_empty() {
                opposite.remove(&level_price);
            }
        }

        // 5. handle the remainder by time-in-force
        let filled = order.size - remaining;
        out.status = match order.tif {
            TimeInForce::Fok => {
                debug_assert_eq!(remaining, 0, "FOK pre-check guarantees full fill");
                SubmitStatus::FilledFull
            }
            TimeInForce::Ioc => {
                if remaining == 0 {
                    SubmitStatus::FilledFull
                } else if filled > 0 {
                    SubmitStatus::FilledCancelled {
                        cancelled: remaining,
                    }
                } else {
                    SubmitStatus::CancelledNoFill
                }
            }
            TimeInForce::Gtc => {
                if remaining == 0 {
                    SubmitStatus::FilledFull
                } else if limit == 0 {
                    // a market GTC with leftover behaves like IOC (cannot rest
                    // without a price)
                    if filled > 0 {
                        SubmitStatus::FilledCancelled {
                            cancelled: remaining,
                        }
                    } else {
                        SubmitStatus::CancelledNoFill
                    }
                } else {
                    self.rest(order, order_hash, remaining, seq);
                    if filled > 0 {
                        SubmitStatus::FilledResting { resting: remaining }
                    } else {
                        SubmitStatus::Resting
                    }
                }
            }
            TimeInForce::PostOnly => unreachable!("handled above"),
        };
        out
    }

    /// Rest `remaining` of `order` at its limit price.
    fn rest(&mut self, order: &Order, order_hash: Digest, remaining: i128, seq: u64) {
        let book = match order.side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        };
        book.entry(order.limit_price)
            .or_default()
            .push_back(Resting {
                order_hash,
                owner: order.owner,
                remaining,
                price: order.limit_price,
                seq,
                reduce_only: order.reduce_only,
                expiry_ms: order.expiry_ms,
            });
    }

    /// Cancel every resting order belonging to `owner` (e.g. after the owner is
    /// liquidated). Returns the number of orders cancelled.
    pub fn cancel_owner(&mut self, owner: &PubKey) -> usize {
        self.cancel_owner_with_events(owner).len()
    }

    pub fn cancel_owner_with_events(&mut self, owner: &PubKey) -> Vec<OrderRemoval> {
        self.remove_where(|r| &r.owner == owner, "Liquidated")
    }

    /// Reap before using the book as a funding mark; retain attribution for clients.
    pub fn reap_expired(&mut self, now_ms: u64) -> usize {
        self.reap_expired_with_events(now_ms).len()
    }

    pub fn reap_expired_with_events(&mut self, now_ms: u64) -> Vec<OrderRemoval> {
        self.remove_where(|r| resting_expired(r, now_ms), "Expired")
    }

    fn remove_where(
        &mut self,
        remove: impl Fn(&Resting) -> bool,
        reason: &'static str,
    ) -> Vec<OrderRemoval> {
        let mut removed = Vec::new();
        for book in [&mut self.bids, &mut self.asks] {
            book.retain(|_, q| {
                q.retain(|r| {
                    if remove(r) {
                        removed.push(OrderRemoval {
                            order_hash: r.order_hash,
                            reason,
                        });
                        false
                    } else {
                        true
                    }
                });
                !q.is_empty()
            });
        }
        removed
    }

    /// Cancel a resting order by hash. Returns the cancelled remaining size.
    pub fn cancel(&mut self, order_hash: &Digest) -> Option<i128> {
        for book in [&mut self.bids, &mut self.asks] {
            let mut empty_key = None;
            let mut found = None;
            for (price, q) in book.iter_mut() {
                if let Some(pos) = q.iter().position(|r| &r.order_hash == order_hash) {
                    let r = q.remove(pos).unwrap();
                    found = Some(r.remaining);
                    if q.is_empty() {
                        empty_key = Some(*price);
                    }
                    break;
                }
            }
            if let Some(k) = empty_key {
                book.remove(&k);
            }
            if found.is_some() {
                return found;
            }
        }
        None
    }
}
