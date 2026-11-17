//! A single market's continuous limit order book with deterministic price-time
//! priority (§1 hot path, §4 Proof-v2 target).
//!
//! Determinism is the whole point: given the same ordered stream of submissions,
//! the book produces byte-identical fills on every machine and inside the zkVM
//! guest. Priority is **price, then arrival sequence** — never wall-clock, never
//! map iteration order. Bids are keyed high-to-low, asks low-to-high; within a
//! price level orders rest in a FIFO queue ordered by the monotonically
//! increasing `seq` the sequencer assigned at receipt (§2).

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
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

/// One resting order as [`OrderBook::impact_price`] shows it to its depth filter:
/// its hash, the maker, its price, its unfilled size and whether it is
/// reduce-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestingQuote {
    pub order_hash: Digest,
    pub owner: PubKey,
    pub price: i128,
    pub remaining: i128,
    pub reduce_only: bool,
}

/// The part of one side of a book that [`OrderBook::impact_price_within`] walks:
/// the price levels inside `lo..=hi`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImpactWindow {
    pub lo: i128,
    pub hi: i128,
}

impl ImpactWindow {
    /// Every level of the side.
    pub const UNBOUNDED: Self = Self {
        lo: i128::MIN,
        hi: i128::MAX,
    };
}

/// A resting order on the book.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Resting {
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
    reduce_only: bool,
    /// Good-till-time bound carried from the order (0 = no expiry). A resting maker
    /// whose expiry has passed relative to the batch clock is void and must not
    /// provide liquidity, so matching prunes it instead of trading against it.
    expiry_ms: u64,
    /// The order's place in its level's queue for the hash index (audit
    /// 2026-11-16 GA-1): given by the book when the order comes to rest, and
    /// increasing along every queue, so a lookup finds the order by binary
    /// search. Not persisted: a restore numbers the queues again.
    #[cfg_attr(feature = "serde", serde(skip))]
    slot: u64,
}

/// A side of the book, in the order the hash lookups have always met them:
/// bids before asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Half {
    Bids,
    Asks,
}

impl Half {
    /// The side `side`'s orders rest on.
    fn of(side: Side) -> Self {
        match side {
            Side::Buy => Half::Bids,
            Side::Sell => Half::Asks,
        }
    }

    /// The other side.
    fn opposite(self) -> Self {
        match self {
            Half::Bids => Half::Asks,
            Half::Asks => Half::Bids,
        }
    }
}

/// Where one resting order is: its key in the book's hash index. Ordered by the
/// hash, then as a walk of the book meets the orders (bids before asks, lower
/// price first, then queue order), so the first spot of a hash is the order the
/// linear lookups found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Spot {
    hash: Digest,
    half: Half,
    price: i128,
    slot: u64,
}

impl Spot {
    fn of(r: &Resting, half: Half, price: i128) -> Self {
        Self {
            hash: r.order_hash,
            half,
            price,
            slot: r.slot,
        }
    }
}

/// One change [`OrderBook::submit`] made to the book, as recorded for
/// [`crate::MatchingEngine::undo`] (audit 2026-11-16 SM-2). Undone newest
/// first, each puts back exactly what it changed.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Step {
    /// The order came to rest at the back of the level at `price`; `created`
    /// when that level did not exist before.
    Rested {
        half: Half,
        price: i128,
        created: bool,
    },
    /// `order` left the front of the level at `price`.
    Popped {
        half: Half,
        price: i128,
        order: Resting,
    },
    /// The order at the front of the level at `price` traded `size`.
    Traded { half: Half, price: i128, size: i128 },
    /// The (empty) level at `price` was removed.
    LevelDropped { half: Half, price: i128 },
}

/// Where [`OrderBook::submit`] records its changes, if anywhere.
struct Journal<'a>(Option<&'a mut Vec<Step>>);

impl Journal<'_> {
    fn note(&mut self, step: Step) {
        if let Some(steps) = self.0.as_mut() {
            steps.push(step);
        }
    }
}

#[cfg(test)]
std::thread_local! {
    /// Resting orders examined on this thread to find one order by its hash
    /// ([`OrderBook::remaining`], [`OrderBook::remaining_for`], [`OrderBook::cancel`]).
    pub(crate) static ORDERS_VISITED: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Count one resting order examined by a lookup (tests only).
#[cfg(test)]
fn visited() {
    ORDERS_VISITED.with(|n| n.set(n.get() + 1));
}

/// Is this resting maker expired at the batch reference clock `now_ms`?
/// (`expiry_ms == 0` means good-till-cancelled — never expires.)
fn resting_expired(r: &Resting, now_ms: u64) -> bool {
    r.expiry_ms != 0 && now_ms >= r.expiry_ms
}

/// One market's order book.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "", from = "BookState<H>"))]
pub struct OrderBook<H: perp_core::hash::Hasher> {
    market_id: MarketId,
    /// price → FIFO queue (by seq). Bids and asks both keyed by raw price.
    bids: BTreeMap<i128, VecDeque<Resting>>,
    asks: BTreeMap<i128, VecDeque<Resting>>,
    _h: core::marker::PhantomData<H>,
    /// Every resting order by its hash (audit 2026-11-16 GA-1): the gateway
    /// looks up each order a batch touched, and a ban or a cancellation removes
    /// one order, without walking the book. Not persisted: rebuilt on restore.
    #[cfg_attr(feature = "serde", serde(skip))]
    index: BTreeSet<Spot>,
    /// The slot the next order to rest takes. Not persisted.
    #[cfg_attr(feature = "serde", serde(skip))]
    next_slot: u64,
}

/// The persisted fields of an [`OrderBook`], as every snapshot has written them;
/// a restore numbers the queues and builds the hash index from them.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(bound = "")]
struct BookState<H> {
    market_id: MarketId,
    bids: BTreeMap<i128, VecDeque<Resting>>,
    asks: BTreeMap<i128, VecDeque<Resting>>,
    _h: core::marker::PhantomData<H>,
}

#[cfg(feature = "serde")]
impl<H: perp_core::hash::Hasher> From<BookState<H>> for OrderBook<H> {
    fn from(state: BookState<H>) -> Self {
        let mut book = Self {
            market_id: state.market_id,
            bids: state.bids,
            asks: state.asks,
            _h: state._h,
            index: BTreeSet::new(),
            next_slot: 0,
        };
        book.reindex();
        book
    }
}

impl<H: perp_core::hash::Hasher> OrderBook<H> {
    pub fn new(market_id: MarketId) -> Self {
        Self {
            market_id,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            _h: core::marker::PhantomData,
            index: BTreeSet::new(),
            next_slot: 0,
        }
    }

    /// Number every queue again, in order, and rebuild the hash index from the
    /// levels.
    #[cfg_attr(not(feature = "serde"), allow(dead_code))]
    fn reindex(&mut self) {
        let Self {
            bids,
            asks,
            index,
            next_slot,
            ..
        } = self;
        index.clear();
        let mut slot = 0u64;
        for (half, levels) in [(Half::Bids, bids), (Half::Asks, asks)] {
            for (price, queue) in levels.iter_mut() {
                for r in queue.iter_mut() {
                    r.slot = slot;
                    slot += 1;
                    index.insert(Spot::of(r, half, *price));
                }
            }
        }
        *next_slot = slot;
    }

    fn levels(&self, half: Half) -> &BTreeMap<i128, VecDeque<Resting>> {
        match half {
            Half::Bids => &self.bids,
            Half::Asks => &self.asks,
        }
    }

    fn levels_mut(&mut self, half: Half) -> &mut BTreeMap<i128, VecDeque<Resting>> {
        match half {
            Half::Bids => &mut self.bids,
            Half::Asks => &mut self.asks,
        }
    }

    /// Where the orders with `hash` rest, first the one a walk of the book
    /// meets first.
    fn spots(&self, hash: &Digest) -> impl Iterator<Item = &Spot> + '_ {
        let first = Spot {
            hash: *hash,
            half: Half::Bids,
            price: i128::MIN,
            slot: 0,
        };
        let last = Spot {
            hash: *hash,
            half: Half::Asks,
            price: i128::MAX,
            slot: u64::MAX,
        };
        self.index.range(first..=last)
    }

    /// The position of the order at `spot` in its level's queue.
    fn position(&self, spot: &Spot) -> Option<usize> {
        let queue = self.levels(spot.half).get(&spot.price)?;
        queue
            .binary_search_by_key(&spot.slot, |r| {
                #[cfg(test)]
                visited();
                r.slot
            })
            .ok()
    }

    /// The order at `spot`.
    fn at(&self, spot: &Spot) -> Option<&Resting> {
        let position = self.position(spot)?;
        self.levels(spot.half).get(&spot.price)?.get(position)
    }

    /// Whether an order with `hash` rests on this book.
    pub(crate) fn rests(&self, hash: &Digest) -> bool {
        self.spots(hash).next().is_some()
    }

    /// The hash index holds exactly the orders on the levels, every queue's
    /// slots increase and stay below the next one (tests only).
    #[cfg(test)]
    pub(crate) fn assert_indexed(&self) {
        let mut spots = BTreeSet::new();
        for half in [Half::Bids, Half::Asks] {
            for (price, queue) in self.levels(half) {
                for pair in queue.iter().collect::<Vec<_>>().windows(2) {
                    assert!(pair[0].slot < pair[1].slot, "a queue's slots must increase");
                }
                for r in queue {
                    assert!(r.slot < self.next_slot);
                    spots.insert(Spot::of(r, half, *price));
                }
            }
        }
        assert_eq!(spots, self.index, "the hash index must match the book");
    }

    /// Put back one change [`Self::submit`] recorded. Steps are undone newest
    /// first, so each finds the book as the change left it.
    pub(crate) fn undo(&mut self, step: Step) {
        match step {
            Step::Rested {
                half,
                price,
                created,
            } => {
                let levels = self.levels_mut(half);
                let queue = levels.get_mut(&price).expect("an undone order rests");
                let r = queue.pop_back().expect("an undone order rests last");
                if created {
                    levels.remove(&price);
                }
                self.index.remove(&Spot::of(&r, half, price));
                self.next_slot = r.slot;
            }
            Step::Popped { half, price, order } => {
                self.levels_mut(half)
                    .entry(price)
                    .or_default()
                    .push_front(order);
                self.index.insert(Spot::of(&order, half, price));
            }
            Step::Traded { half, price, size } => {
                let front = self
                    .levels_mut(half)
                    .get_mut(&price)
                    .and_then(VecDeque::front_mut)
                    .expect("an undone trade's maker is at the front");
                front.remaining += size;
            }
            Step::LevelDropped { half, price } => {
                self.levels_mut(half).entry(price).or_default();
            }
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

    /// The average price at which `notional` (quote-scaled, micro-USD) would fill
    /// against the resting `side` — the bids for [`Side::Buy`], the asks for
    /// [`Side::Sell`] — walking it best price first, as a taker sweeping that side
    /// would. Makers expired at `now_ms` are skipped, as matching skips them.
    ///
    /// Only the resting orders `counts` accepts are depth. It sees each live order
    /// at most once, in the order a sweeping taker would meet them (best price
    /// first, then arrival order within a level), so it may keep state across
    /// calls, such as a per-maker running total. It sees no order after the one
    /// that completes `notional`. The sequencer uses it to count only orders the
    /// engine could actually fill.
    ///
    /// `None` when `notional` is not positive, when the accepted orders on the
    /// side hold less than `notional` at positive prices, or on arithmetic overflow.
    /// It is an internal aggregate for the sequencer's funding mark, not a public
    /// depth view.
    ///
    /// Integer arithmetic only, exact up to one final division: the walk counts
    /// value in raw `size · price` units, so the order the remaining notional
    /// exhausts gives the fractional base it needs, and the result is the
    /// notional divided by the base consumed, in price scale, rounded down.
    pub fn impact_price(
        &self,
        side: Side,
        notional: i128,
        now_ms: u64,
        counts: impl FnMut(&RestingQuote) -> bool,
    ) -> Option<i128> {
        self.impact_price_within(side, notional, now_ms, ImpactWindow::UNBOUNDED, counts)
    }

    /// [`Self::impact_price`] over the part of the side inside `window`: only the
    /// price levels in `window.lo..=window.hi` are walked (best price first, as a
    /// sweeping taker meets them; the levels outside are never visited).
    ///
    /// The walk ends at the order that completes `notional`, inside its level
    /// (audit 2026-11-16 SM-3): orders queued behind it, at its price or worse,
    /// are never visited. It has no order budget: the orders `counts` refuses
    /// cost it nothing but the visit, so however many of them rest ahead of the
    /// depth, they never make a side without an impact price. Its work is the
    /// orders in the window ahead of that order.
    pub fn impact_price_within(
        &self,
        side: Side,
        notional: i128,
        now_ms: u64,
        window: ImpactWindow,
        counts: impl FnMut(&RestingQuote) -> bool,
    ) -> Option<i128> {
        if notional <= 0 || window.lo > window.hi {
            return None;
        }
        let prices = window.lo..=window.hi;
        match side {
            Side::Buy => {
                Self::sweep_average(self.bids.range(prices).rev(), notional, now_ms, counts)
            }
            Side::Sell => Self::sweep_average(self.asks.range(prices), notional, now_ms, counts),
        }
    }

    /// [`Self::impact_price`] over `levels`, given best price first.
    fn sweep_average<'a>(
        levels: impl Iterator<Item = (&'a i128, &'a VecDeque<Resting>)>,
        notional: i128,
        now_ms: u64,
        mut counts: impl FnMut(&RestingQuote) -> bool,
    ) -> Option<i128> {
        // `size · price` carries this much scale beyond QUOTE_SCALE (see
        // `perp_core::fixed::notional_quote`).
        const NOTIONAL_DIVISOR: i128 = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
        let target = notional.checked_mul(NOTIONAL_DIVISOR)?;
        let mut left = target;
        // base taken from the orders already counted, size-scaled
        let mut base: i128 = 0;
        for (&price, queue) in levels {
            if price <= 0 {
                return None;
            }
            for r in queue {
                if resting_expired(r, now_ms) || r.remaining <= 0 {
                    continue;
                }
                let quote = RestingQuote {
                    order_hash: r.order_hash,
                    owner: r.owner,
                    price: r.price,
                    remaining: r.remaining,
                    reduce_only: r.reduce_only,
                };
                if !counts(&quote) {
                    continue;
                }
                // an order the filter refuses fails nothing, even if its value
                // would overflow; a counted one fails the walk closed
                let value = r.remaining.checked_mul(price)?;
                if value >= left {
                    // This order gives `left / price` more base, so the average is
                    // target / (base + left / price) = target · price / (base · price + left).
                    // Checked per order rather than per level: a level's orders all
                    // share its price, so the result is the one a walk summing the
                    // whole level first gives, and the orders queued behind this one
                    // are never visited.
                    let denominator = base.checked_mul(price)?.checked_add(left)?;
                    return target.checked_mul(price)?.checked_div(denominator);
                }
                base = base.checked_add(r.remaining)?;
                left -= value;
            }
        }
        None
    }

    /// Internal execution lookup. Public depth remains undisclosed. Found
    /// through the hash index, not by walking the book.
    pub fn remaining(&self, hash: &Digest) -> Option<i128> {
        let spot = self.spots(hash).next()?;
        self.at(spot).map(|r| r.remaining)
    }

    /// Owner-scoped remaining quantity, for cancellation eligibility. This is
    /// not public market depth and must only be exposed through authenticated views.
    pub fn remaining_for(&self, owner: &PubKey, order_hash: &Digest) -> Option<i128> {
        self.spots(order_hash)
            .filter_map(|spot| self.at(spot))
            .find(|r| &r.owner == owner)
            .map(|r| r.remaining)
    }

    /// Every order resting on this book, bids then asks, with its side and its
    /// good-till-time (`0`: none), whether or not that has passed yet. Owner-scoped
    /// admission data for the sequencer's open-order limits, not a public depth
    /// view.
    pub fn resting_orders(&self) -> impl Iterator<Item = (Side, RestingQuote, u64)> + '_ {
        let bids = self.bids.values().flatten().map(|r| (Side::Buy, r));
        let asks = self.asks.values().flatten().map(|r| (Side::Sell, r));
        bids.chain(asks).map(|(side, r)| {
            (
                side,
                RestingQuote {
                    order_hash: r.order_hash,
                    owner: r.owner,
                    price: r.price,
                    remaining: r.remaining,
                    reduce_only: r.reduce_only,
                },
                r.expiry_ms,
            )
        })
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
        self.submit_journaled(order, seq, now_ms, Journal(None))
    }

    /// [`Self::submit`], recording each change it makes to the book in `steps`,
    /// for [`Self::undo`].
    pub(crate) fn submit_undoable(
        &mut self,
        order: &Order,
        seq: u64,
        now_ms: u64,
        steps: &mut Vec<Step>,
    ) -> SubmitOutcome {
        self.submit_journaled(order, seq, now_ms, Journal(Some(steps)))
    }

    fn submit_journaled(
        &mut self,
        order: &Order,
        seq: u64,
        now_ms: u64,
        mut journal: Journal<'_>,
    ) -> SubmitOutcome {
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
            self.rest(order, order_hash, order.size, seq, &mut journal);
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
            let half = Half::of(side).opposite();
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
                    self.index.remove(&Spot::of(&removed, half, level_price));
                    journal.note(Step::Popped {
                        half,
                        price: level_price,
                        order: removed,
                    });
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
                journal.note(Step::LevelDropped {
                    half,
                    price: level_price,
                });
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
            journal.note(Step::Traded {
                half,
                price: level_price,
                size: trade,
            });
            if front.remaining == 0 {
                let filled = queue.pop_front().expect("front exists");
                self.index.remove(&Spot::of(&filled, half, level_price));
                journal.note(Step::Popped {
                    half,
                    price: level_price,
                    order: filled,
                });
            }
            if queue.is_empty() {
                opposite.remove(&level_price);
                journal.note(Step::LevelDropped {
                    half,
                    price: level_price,
                });
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
                    self.rest(order, order_hash, remaining, seq, &mut journal);
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

    /// Rest `remaining` of `order` at its limit price, at the back of its level.
    fn rest(
        &mut self,
        order: &Order,
        order_hash: Digest,
        remaining: i128,
        seq: u64,
        journal: &mut Journal<'_>,
    ) {
        let half = Half::of(order.side);
        let price = order.limit_price;
        let slot = self.next_slot;
        self.next_slot += 1;
        let resting = Resting {
            order_hash,
            owner: order.owner,
            remaining,
            price,
            seq,
            reduce_only: order.reduce_only,
            expiry_ms: order.expiry_ms,
            slot,
        };
        let levels = self.levels_mut(half);
        let created = !levels.contains_key(&price);
        levels.entry(price).or_default().push_back(resting);
        self.index.insert(Spot::of(&resting, half, price));
        journal.note(Step::Rested {
            half,
            price,
            created,
        });
    }

    /// Cancel every resting order belonging to `owner` (e.g. after the owner is
    /// liquidated). Returns the number of orders cancelled.
    pub fn cancel_owner(&mut self, owner: &PubKey) -> usize {
        self.cancel_owner_with_events(owner).len()
    }

    pub fn cancel_owner_with_events(&mut self, owner: &PubKey) -> Vec<OrderRemoval> {
        self.remove_where(
            &[Half::Bids, Half::Asks],
            |r| &r.owner == owner,
            "Liquidated",
        )
    }

    /// Cancel every order of `owner` resting on `side` (its bids for
    /// [`Side::Buy`], its asks for [`Side::Sell`]) except its reduce-only ones,
    /// and return their hashes, lower price first and in queue order. The
    /// sequencer bans the side of a maker whose collateral failed a fill this way
    /// (audit 2026-11-16 SM-2); a reduce-only order adds no exposure, so it
    /// stays.
    pub fn cancel_owner_side(&mut self, owner: &PubKey, side: Side) -> Vec<Digest> {
        self.remove_where(
            &[Half::of(side)],
            |r| &r.owner == owner && !r.reduce_only,
            "Banned",
        )
        .into_iter()
        .map(|removal| removal.order_hash)
        .collect()
    }

    /// Cancel every resting order of `owner` in this book because another
    /// account's liquidation closed some or all of `owner`'s position here
    /// (audit 2026-11-16 PC-1): an order placed against the old position, a
    /// take-profit that was a close, could otherwise open a new one.
    pub fn cancel_owner_forced_close_with_events(&mut self, owner: &PubKey) -> Vec<OrderRemoval> {
        self.remove_where(
            &[Half::Bids, Half::Asks],
            |r| &r.owner == owner,
            "ForcedClose",
        )
    }

    /// Reap before using the book as a funding mark; retain attribution for clients.
    pub fn reap_expired(&mut self, now_ms: u64) -> usize {
        self.reap_expired_with_events(now_ms).len()
    }

    pub fn reap_expired_with_events(&mut self, now_ms: u64) -> Vec<OrderRemoval> {
        self.remove_where(
            &[Half::Bids, Half::Asks],
            |r| resting_expired(r, now_ms),
            "Expired",
        )
    }

    /// Remove every order on `halves` that `remove` selects, bids before asks,
    /// lower price first and in queue order, and drop the levels left empty.
    fn remove_where(
        &mut self,
        halves: &[Half],
        remove: impl Fn(&Resting) -> bool,
        reason: &'static str,
    ) -> Vec<OrderRemoval> {
        let mut removed = Vec::new();
        let Self {
            bids, asks, index, ..
        } = self;
        for &half in halves {
            let levels = match half {
                Half::Bids => &mut *bids,
                Half::Asks => &mut *asks,
            };
            levels.retain(|price, q| {
                q.retain(|r| {
                    if remove(r) {
                        index.remove(&Spot::of(r, half, *price));
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
    /// Found through the hash index; with two orders of one hash, the one a
    /// walk of the book meets first (bids before asks, lower price first).
    pub fn cancel(&mut self, order_hash: &Digest) -> Option<i128> {
        let spot = *self.spots(order_hash).next()?;
        let position = self.position(&spot)?;
        let levels = self.levels_mut(spot.half);
        let queue = levels.get_mut(&spot.price)?;
        let r = queue.remove(position)?;
        if queue.is_empty() {
            levels.remove(&spot.price);
        }
        self.index.remove(&spot);
        Some(r.remaining)
    }
}
