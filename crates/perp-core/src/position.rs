//! Perpetual positions and the margin / PnL / liquidation math (§5, §12).
//!
//! A position is plaintext *inside the enclave* (so it can be marked against the
//! oracle continuously and liquidated even while the user is offline, §5) but
//! shielded everywhere else. All risk math here is deterministic integer
//! arithmetic and is re-proven in ZK (Proof-v1: post-fill margin sufficiency,
//! liquidation threshold correctness).

use crate::fixed::{abs, apply_rate, notional_quote};
use crate::market::{Market, MarketId};
use crate::note::PubKey;

/// An open perpetual position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Position {
    pub owner: PubKey,
    pub market_id: MarketId,
    /// Signed size: `> 0` long, `< 0` short, size-scaled.
    pub size: i128,
    /// Volume-weighted average entry price, price-scaled.
    pub entry_price: i128,
    /// Posted collateral, quote-scaled (micro-USD).
    pub collateral: i128,
    /// Cumulative funding index (micro-USD per 1.0 base) captured at last update.
    pub funding_entry: i128,
}

/// A delta-hedging signal for one position/market (audit Q5). `inventory` is the
/// net signed base size held; `hedge_target` is its negation — the position a
/// delta-neutral keeper takes on an EXTERNAL venue to flatten directional risk;
/// `notional` is the quote-scaled exposure at mark. Venue-agnostic: the protocol
/// emits the "what to hedge", the keeper executes the hedge externally (the
/// protocol never custodies or routes it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HedgeSignal {
    pub inventory: i128,
    pub hedge_target: i128,
    pub notional: i128,
}

/// Outcome of a margin check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskError {
    /// Arithmetic would overflow — treated as a hard reject (never wrap).
    Overflow,
    /// Equity below the required margin for the attempted action.
    InsufficientMargin,
    /// Position is not actually liquidatable.
    NotLiquidatable,
}

impl Position {
    pub fn empty(owner: PubKey, market_id: MarketId) -> Self {
        Self {
            owner,
            market_id,
            size: 0,
            entry_price: 0,
            collateral: 0,
            funding_entry: 0,
        }
    }

    pub fn is_open(&self) -> bool {
        self.size != 0
    }

    /// Absolute notional at `mark`, quote-scaled.
    pub fn notional(&self, mark: i128) -> Option<i128> {
        notional_quote(abs(self.size), mark)
    }

    /// The delta-hedging signal for this position at `mark` (audit Q5): net
    /// inventory, the offsetting size to take on an external venue for
    /// delta-neutrality, and the notional exposure. The protocol emits this; the
    /// hedge itself is the market-maker's own external keeper operation.
    pub fn hedge_signal(&self, mark: i128) -> HedgeSignal {
        HedgeSignal {
            inventory: self.size,
            hedge_target: -self.size,
            notional: self.notional(mark).unwrap_or(0),
        }
    }

    /// Unrealized PnL at `mark`, quote-scaled. Long profits as price rises.
    pub fn unrealized_pnl(&self, mark: i128) -> Option<i128> {
        notional_quote(self.size, mark.checked_sub(self.entry_price)?)
    }

    /// Funding owed since `funding_entry` given the current global index.
    /// Positive = the position pays (debited from collateral).
    pub fn funding_owed(&self, funding_index_now: i128) -> Option<i128> {
        let delta = funding_index_now.checked_sub(self.funding_entry)?;
        // size is size-scaled; index is micro-USD per 1.0 base.
        self.size
            .checked_mul(delta)
            .map(|v| v / crate::fixed::SIZE_SCALE)
    }

    /// Equity = collateral + unrealized PnL − funding owed.
    pub fn equity(&self, mark: i128, funding_index_now: i128) -> Option<i128> {
        let pnl = self.unrealized_pnl(mark)?;
        let funding = self.funding_owed(funding_index_now)?;
        self.collateral.checked_add(pnl)?.checked_sub(funding)
    }

    /// Maintenance margin required at `mark`.
    pub fn maintenance_required(&self, market: &Market, mark: i128) -> Option<i128> {
        apply_rate(self.notional(mark)?, market.maintenance_margin_ratio)
    }

    /// Initial margin required at `mark` (to open / increase).
    pub fn initial_required(&self, market: &Market, mark: i128) -> Option<i128> {
        apply_rate(self.notional(mark)?, market.initial_margin_ratio)
    }

    /// Is the position liquidatable: equity < maintenance margin (§5).
    pub fn is_liquidatable(&self, market: &Market, mark: i128, funding_index_now: i128) -> bool {
        match (
            self.equity(mark, funding_index_now),
            self.maintenance_required(market, mark),
        ) {
            (Some(eq), Some(mm)) => eq < mm,
            // overflow ⇒ conservatively NOT auto-liquidate; close-only handles it
            _ => false,
        }
    }

    /// Does applying `delta_size` open new directional exposure — i.e. anything
    /// that is NOT a pure same-direction reduction or a clean close? This is true
    /// for opening from flat, growing a position, AND flipping direction (even to
    /// a *smaller* opposite position, which still opens a fresh opposite leg).
    /// Used for both the initial-margin gate and the close-only gate, so a flip
    /// can neither escape margin nor sneak past close-only.
    pub fn increases_exposure(&self, delta_size: i128) -> bool {
        if self.size == 0 {
            return true; // opening from flat
        }
        // Never wrap (crate rule): an overflowing add can only be an astronomically
        // large delta, which by definition opens exposure — treat it as increasing so it
        // stays subject to the initial-margin / close-only gates rather than panicking
        // (debug) or wrapping to a bogus "reduction" (release).
        let Some(new) = self.size.checked_add(delta_size) else {
            return true;
        };
        if new == 0 {
            return false; // exact close
        }
        let same_direction = (self.size > 0) == (new > 0);
        if same_direction {
            abs(new) > abs(self.size) // grew in the same direction
        } else {
            true // flipped direction → opened opposite exposure
        }
    }

    /// Pre-trade risk check (§12, Phase 3): if this order's full size filled at
    /// `mark`, would the resulting position still satisfy INITIAL margin?
    /// Reducing/closing orders always pass (they lower risk). Used by the
    /// sequencer to reject unmarginable orders *before* matching, so no fill can
    /// match-but-fail-to-settle.
    pub fn fits_initial_after(
        &self,
        market: &Market,
        delta_size: i128,
        mark: i128,
        funding_index_now: i128,
    ) -> bool {
        if !self.increases_exposure(delta_size) {
            return true;
        }
        let mut sim = *self;
        // simulate the fill at the conservative oracle mark
        if sim.apply_fill(delta_size, mark, funding_index_now).is_err() {
            return false;
        }
        sim.check_initial_margin(market, mark, funding_index_now)
            .is_ok()
    }

    /// Check the position satisfies INITIAL margin (post-open / post-increase).
    /// This is the Proof-v1 "post-fill margin sufficiency" obligation (§4).
    pub fn check_initial_margin(
        &self,
        market: &Market,
        mark: i128,
        funding_index_now: i128,
    ) -> Result<(), RiskError> {
        let eq = self
            .equity(mark, funding_index_now)
            .ok_or(RiskError::Overflow)?;
        let im = self
            .initial_required(market, mark)
            .ok_or(RiskError::Overflow)?;
        if eq < im {
            return Err(RiskError::InsufficientMargin);
        }
        Ok(())
    }

    /// Settle accrued funding into collateral, advancing `funding_entry` to the
    /// current index. Returns the funding amount paid (positive = debited). The
    /// engine routes this into the vault pool so total value is conserved.
    pub fn settle_funding(&mut self, funding_index_now: i128) -> Result<i128, RiskError> {
        let funding = self
            .funding_owed(funding_index_now)
            .ok_or(RiskError::Overflow)?;
        self.collateral = self
            .collateral
            .checked_sub(funding)
            .ok_or(RiskError::Overflow)?;
        self.funding_entry = funding_index_now;
        Ok(funding)
    }

    /// Apply a fill: change size by `delta_size` at `fill_price`, settling
    /// funding into collateral first. Updates the VWAP entry on increases and
    /// realizes PnL on decreases/flips. Returns `(realized_pnl, funding_paid)`,
    /// both quote-scaled, so the engine can route them through the vault pool.
    pub fn apply_fill(
        &mut self,
        delta_size: i128,
        fill_price: i128,
        funding_index_now: i128,
    ) -> Result<(i128, i128), RiskError> {
        let funding = self.settle_funding(funding_index_now)?;

        let new_size = self
            .size
            .checked_add(delta_size)
            .ok_or(RiskError::Overflow)?;
        let mut realized = 0i128;

        let increasing = self.size == 0 || (self.size > 0) == (delta_size > 0);
        if increasing {
            // VWAP: weight old and new by absolute size
            let old_abs = abs(self.size);
            let add_abs = abs(delta_size);
            let total = old_abs.checked_add(add_abs).ok_or(RiskError::Overflow)?;
            if total > 0 {
                let num = self
                    .entry_price
                    .checked_mul(old_abs)
                    .ok_or(RiskError::Overflow)?
                    .checked_add(fill_price.checked_mul(add_abs).ok_or(RiskError::Overflow)?)
                    .ok_or(RiskError::Overflow)?;
                self.entry_price = num / total;
            }
        } else {
            // reducing or flipping: realize PnL on the closed portion
            let closed = core::cmp::min(abs(delta_size), abs(self.size));
            let signed_closed = if self.size > 0 { closed } else { -closed };
            realized = notional_quote(signed_closed, fill_price - self.entry_price)
                .ok_or(RiskError::Overflow)?;
            self.collateral = self
                .collateral
                .checked_add(realized)
                .ok_or(RiskError::Overflow)?;
            if abs(delta_size) > abs(self.size) {
                // flipped through zero: new leg opens at fill price
                self.entry_price = fill_price;
            }
        }

        self.size = new_size;
        if self.size == 0 {
            self.entry_price = 0;
        }
        Ok((realized, funding))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
    use crate::hash::word_u64;

    fn pos(size: i128, entry: i128, coll: i128) -> Position {
        Position {
            owner: word_u64(1),
            market_id: 0,
            size,
            entry_price: entry,
            collateral: coll,
            funding_entry: 0,
        }
    }

    // AUDIT (Tier-3): increases_exposure must not overflow on the raw add. A near-max
    // position plus a positive delta overflows i128 — the old `self.size + delta_size`
    // panicked under debug overflow-checks; the checked version returns true (opening).
    #[test]
    fn increases_exposure_does_not_overflow_at_the_size_bound() {
        let p = pos(i128::MAX, 100_000 * PRICE_SCALE, 20_000 * QUOTE_SCALE);
        assert!(
            p.increases_exposure(1),
            "an overflowing delta is treated as increasing exposure, not a panic/wrap"
        );
        let short = pos(i128::MIN, 100_000 * PRICE_SCALE, 20_000 * QUOTE_SCALE);
        assert!(short.increases_exposure(-1), "symmetric on the short bound");
    }

    #[test]
    fn long_pnl_positive_when_price_rises() {
        // 1 BTC long from $100k, mark $110k → +$10k
        let p = pos(SIZE_SCALE, 100_000 * PRICE_SCALE, 20_000 * QUOTE_SCALE);
        assert_eq!(
            p.unrealized_pnl(110_000 * PRICE_SCALE),
            Some(10_000 * QUOTE_SCALE)
        );
    }

    #[test]
    fn short_pnl_positive_when_price_falls() {
        let p = pos(-SIZE_SCALE, 100_000 * PRICE_SCALE, 20_000 * QUOTE_SCALE);
        assert_eq!(
            p.unrealized_pnl(90_000 * PRICE_SCALE),
            Some(10_000 * QUOTE_SCALE)
        );
    }

    #[test]
    fn hedge_signal_reports_the_offsetting_external_position() {
        // An MM net short 2 BTC at mark $100k: the delta-neutral hedge is +2 BTC on
        // an external venue, on $200k of notional exposure (audit Q5).
        let p = pos(-2 * SIZE_SCALE, 100_000 * PRICE_SCALE, 50_000 * QUOTE_SCALE);
        let h = p.hedge_signal(100_000 * PRICE_SCALE);
        assert_eq!(
            h.inventory,
            -2 * SIZE_SCALE,
            "inventory is the signed size held"
        );
        assert_eq!(
            h.hedge_target,
            2 * SIZE_SCALE,
            "hedge the opposite for delta-neutrality"
        );
        assert_eq!(
            h.notional,
            200_000 * QUOTE_SCALE,
            "the notional exposure to hedge"
        );
        // a flat book needs no hedge
        let flat = pos(0, 100_000 * PRICE_SCALE, 0).hedge_signal(100_000 * PRICE_SCALE);
        assert_eq!(
            (flat.inventory, flat.hedge_target, flat.notional),
            (0, 0, 0)
        );
    }

    #[test]
    fn liquidatable_when_equity_below_maintenance() {
        let m = Market::conservative(0);
        // 1 BTC long from $100k, only $6k collateral (notional $100k, mm 5% = $5k).
        // price drops to $94k → pnl -$6k → equity $0 < $4.7k maintenance.
        let p = pos(SIZE_SCALE, 100_000 * PRICE_SCALE, 6_000 * QUOTE_SCALE);
        assert!(p.is_liquidatable(&m, 94_000 * PRICE_SCALE, 0));
        // healthy at $100k: equity $6k > $5k maintenance
        assert!(!p.is_liquidatable(&m, 100_000 * PRICE_SCALE, 0));
    }

    #[test]
    fn vwap_on_increase() {
        let mut p = pos(SIZE_SCALE, 100_000 * PRICE_SCALE, 50_000 * QUOTE_SCALE);
        // add 1 BTC at $120k → avg entry $110k
        p.apply_fill(SIZE_SCALE, 120_000 * PRICE_SCALE, 0).unwrap();
        assert_eq!(p.size, 2 * SIZE_SCALE);
        assert_eq!(p.entry_price, 110_000 * PRICE_SCALE);
    }

    #[test]
    fn realize_pnl_on_close() {
        let mut p = pos(SIZE_SCALE, 100_000 * PRICE_SCALE, 20_000 * QUOTE_SCALE);
        // close 1 BTC at $110k → realize +$10k into collateral
        let (realized, funding) = p.apply_fill(-SIZE_SCALE, 110_000 * PRICE_SCALE, 0).unwrap();
        assert_eq!(realized, 10_000 * QUOTE_SCALE);
        assert_eq!(funding, 0);
        assert_eq!(p.size, 0);
        assert_eq!(p.collateral, 30_000 * QUOTE_SCALE);
    }

    #[test]
    fn flip_to_smaller_opposite_still_requires_margin() {
        let m = Market::conservative(0);
        let mark = 100_000 * PRICE_SCALE;
        // long 2 BTC. delta -3 → flip to short 1 BTC: opens a fresh opposite leg.
        let long2 = pos(2 * SIZE_SCALE, mark, 30_000 * QUOTE_SCALE);
        assert!(
            long2.increases_exposure(-3 * SIZE_SCALE),
            "flip opens new exposure"
        );
        // a pure same-direction reduction does NOT
        assert!(!long2.increases_exposure(-SIZE_SCALE));
        // exact close does NOT
        assert!(!long2.increases_exposure(-2 * SIZE_SCALE));
        // the flip is margin-gated: with thin collateral it must fail pre-trade
        let thin = pos(2 * SIZE_SCALE, mark, 1_000 * QUOTE_SCALE);
        assert!(
            !thin.fits_initial_after(&m, -3 * SIZE_SCALE, mark, 0),
            "flip is margin-checked"
        );
    }

    #[test]
    fn pre_trade_blocks_overleverage_allows_reduce() {
        let m = Market::conservative(0);
        let mark = 100_000 * PRICE_SCALE;
        // empty position with $5k collateral can't open 1 BTC ($10k initial)…
        let mut empty = pos(0, 0, 5_000 * QUOTE_SCALE);
        assert!(!empty.fits_initial_after(&m, SIZE_SCALE, mark, 0));
        // …but can open 0.4 BTC ($4k initial).
        assert!(empty.fits_initial_after(&m, 2 * SIZE_SCALE / 5, mark, 0));

        // a long reducing its position always passes, even if underwater.
        empty.size = SIZE_SCALE;
        empty.entry_price = mark;
        empty.collateral = 1_000 * QUOTE_SCALE; // thin
        assert!(
            empty.fits_initial_after(&m, -SIZE_SCALE / 2, mark, 0),
            "reducing always allowed"
        );
    }

    #[test]
    fn funding_debits_long() {
        // long pays positive funding
        let p = pos(SIZE_SCALE, 100_000 * PRICE_SCALE, 20_000 * QUOTE_SCALE);
        // index moved +50 micro-USD-units... use 100 * QUOTE_SCALE per base = $100
        let idx = 100 * QUOTE_SCALE;
        assert_eq!(p.funding_owed(idx), Some(100 * QUOTE_SCALE));
    }
}
