//! Market definitions and the deterministic risk parameters (§12).
//!
//! Every risk threshold is explicit, bounded, and re-proven in ZK — no operator
//! discretion, no unbounded oracle trust. This struct is the "deterministic risk
//! core": margin ratios, leverage cap, liquidation incentive, and the oracle
//! sanity bounds that gate every price the engine accepts (§8).

use crate::fixed::RATE_SCALE;

/// Identifier of a perpetual market (e.g. 0 = BTC-PERP).
pub type MarketId = u64;

/// Static, governance-set risk parameters for one market.
///
/// All `*_ratio` and `*_bound` fields are [`RATE_SCALE`]-scaled fractions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Market {
    pub id: MarketId,
    /// Initial margin ratio: required equity / notional to OPEN or increase.
    /// e.g. 0.10 (= 10x max leverage) → `100_000`.
    pub initial_margin_ratio: i128,
    /// Maintenance margin ratio: equity / notional below which a position is
    /// liquidatable. Must be `< initial_margin_ratio`.
    pub maintenance_margin_ratio: i128,
    /// Liquidation penalty paid out of remaining collateral, as a fraction of
    /// notional. Funds the keeper + insurance fund (§6, §9).
    pub liquidation_fee_ratio: i128,
    /// Max staleness for an accepted oracle price, milliseconds (§8).
    pub max_oracle_staleness_ms: u64,
    /// Max oracle confidence interval as a fraction of price (§8).
    pub max_oracle_confidence_ratio: i128,
    /// Max |primary − backup_twap| / price tolerated before the price is rejected
    /// and the market enters close-only (§8).
    pub max_oracle_deviation_ratio: i128,
    /// Taker trading fee as a fraction of fill notional (§9). The taker pays it on
    /// every fill; `maker_rebate_ratio` of the notional is rebated to the maker (the
    /// market-maker incentive), and the remainder funds the insurance fund.
    pub taker_fee_ratio: i128,
    /// Maker rebate as a fraction of fill notional, paid to the resting maker out of
    /// the taker fee. Must be `<= taker_fee_ratio` so the insurance cut is never
    /// negative. This is what pays a market-maker to provide liquidity (§9, audit Q4).
    pub maker_rebate_ratio: i128,
    /// Protocol-treasury cut as a fraction of fill notional, taken out of the net
    /// trading fee (`taker_fee − maker_rebate`); the remainder funds the insurance
    /// fund. This is the operator's revenue. Must be `<= taker_fee_ratio −
    /// maker_rebate_ratio` so the insurance cut is never negative.
    pub treasury_fee_ratio: i128,
}

impl Market {
    /// A conservative BTC-PERP-style default for Phase 0 / mainnet-beta (§11):
    /// 10x max leverage, 5% maintenance, 1% liquidation fee, tight oracle bounds.
    pub fn conservative(id: MarketId) -> Self {
        Self {
            id,
            initial_margin_ratio: RATE_SCALE / 10,     // 10%
            maintenance_margin_ratio: RATE_SCALE / 20, // 5%
            liquidation_fee_ratio: RATE_SCALE / 100,   // 1%
            max_oracle_staleness_ms: 10_000,           // 10s
            max_oracle_confidence_ratio: RATE_SCALE / 100, // 1%
            max_oracle_deviation_ratio: RATE_SCALE / 50, // 2%
            taker_fee_ratio: 0,                        // fee-free by default
            maker_rebate_ratio: 0,
            treasury_fee_ratio: 0,
        }
    }

    /// Like [`Self::conservative`] but with a taker fee + maker rebate enabled —
    /// the market-maker incentive (§9, audit Q4). `taker_bps`/`maker_bps` are in
    /// basis points of notional; the maker rebate must not exceed the taker fee.
    pub fn with_fees(id: MarketId, taker_bps: i128, maker_bps: i128) -> Self {
        Self::with_fees_treasury(id, taker_bps, maker_bps, 0)
    }

    /// Like [`Self::with_fees`] but also routes `treasury_bps` of notional out of the
    /// net fee to the protocol treasury (operator revenue); the rest funds insurance.
    /// `treasury_bps <= taker_bps − maker_bps`.
    pub fn with_fees_treasury(
        id: MarketId,
        taker_bps: i128,
        maker_bps: i128,
        treasury_bps: i128,
    ) -> Self {
        let bps = RATE_SCALE / 10_000;
        Self {
            taker_fee_ratio: taker_bps * bps,
            maker_rebate_ratio: maker_bps * bps,
            treasury_fee_ratio: treasury_bps * bps,
            ..Self::conservative(id)
        }
    }

    /// Maximum leverage implied by the initial margin ratio, for display.
    pub fn max_leverage(&self) -> i128 {
        if self.initial_margin_ratio == 0 {
            0
        } else {
            RATE_SCALE / self.initial_margin_ratio
        }
    }

    /// Internal consistency check; governance must never set incoherent params.
    pub fn is_coherent(&self) -> bool {
        self.initial_margin_ratio > 0
            && self.maintenance_margin_ratio > 0
            && self.maintenance_margin_ratio < self.initial_margin_ratio
            && self.liquidation_fee_ratio >= 0
            && self.liquidation_fee_ratio < self.maintenance_margin_ratio
            && self.max_oracle_confidence_ratio > 0
            && self.max_oracle_deviation_ratio > 0
            && self.taker_fee_ratio >= 0
            // The taker fee, like the liquidation fee, must stay below the
            // maintenance buffer (audit Q4): otherwise a fee on a reducing fill —
            // which skips the initial-margin re-check — could push a still-open
            // position into fee-induced bad debt, and a same-size maker rebate could
            // fund an opening position's initial margin from the fee alone.
            && self.taker_fee_ratio < self.maintenance_margin_ratio
            && self.maker_rebate_ratio >= 0
            && self.maker_rebate_ratio <= self.taker_fee_ratio
            // the treasury cut comes out of the net fee, so insurance never goes negative
            && self.treasury_fee_ratio >= 0
            && self.treasury_fee_ratio <= self.taker_fee_ratio - self.maker_rebate_ratio
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_is_coherent() {
        assert!(Market::conservative(0).is_coherent());
    }

    #[test]
    fn max_leverage_is_10x() {
        assert_eq!(Market::conservative(0).max_leverage(), 10);
    }

    #[test]
    fn incoherent_rejected() {
        let mut m = Market::conservative(0);
        m.maintenance_margin_ratio = m.initial_margin_ratio; // not strictly less
        assert!(!m.is_coherent());
    }

    #[test]
    fn liquidation_fee_must_be_below_maintenance() {
        // a fee >= maintenance margin could consume more than the maintenance buffer
        // at the liquidation threshold — reject it.
        let mut m = Market::conservative(0);
        m.liquidation_fee_ratio = m.maintenance_margin_ratio;
        assert!(!m.is_coherent(), "fee == maintenance is incoherent");
        m.liquidation_fee_ratio = m.maintenance_margin_ratio + 1;
        assert!(!m.is_coherent(), "fee > maintenance is incoherent");
    }

    #[test]
    fn taker_fee_must_be_below_maintenance() {
        // A taker fee >= maintenance margin is two attacks at once (audit Q4):
        //  - on a REDUCING fill (no initial-margin re-check) the fee could consume
        //    more than the maintenance buffer and push a still-open position into
        //    fee-induced bad debt; and
        //  - a maker rebate that large (rebate <= fee) could satisfy a position's
        //    INITIAL margin from the fee alone — a maker opening with no real
        //    skin-in-the-game.
        // Bounding the fee below maintenance (like the liquidation fee) defuses both:
        // the fee can never zero out a maintenance-healthy position, and the rebate
        // is always strictly less than the initial margin it would need to cover.
        let mut m = Market::conservative(0);
        m.taker_fee_ratio = m.maintenance_margin_ratio;
        m.maker_rebate_ratio = 0;
        assert!(!m.is_coherent(), "taker fee == maintenance is incoherent");
        m.taker_fee_ratio = m.maintenance_margin_ratio + 1;
        assert!(!m.is_coherent(), "taker fee > maintenance is incoherent");
        // a realistic bps-scale fee stays coherent
        assert!(
            Market::with_fees(0, 10, 4).is_coherent(),
            "10/4 bps is fine"
        );
    }
}
