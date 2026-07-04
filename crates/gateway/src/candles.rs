//! REAL per-market price history. The chart's past bars were previously a
//! client-side synthetic walk; this store records the engine's own mark each
//! tick into per-timeframe OHLC ring buffers, so `/v1/markets/:id/candles`
//! serves the price history the engine actually marked, funded and liquidated
//! against. Feed-backed markets are additionally backfilled once at boot from
//! the exchange's historical candles (`oracle_feed::fetch_candles`), so the
//! chart is full from the first render; sim-walk markets accumulate their own
//! (equally real) engine history from boot.
//!
//! Deliberately NOT part of the sealed state snapshot: candle history is
//! derived display data, not protocol state — keeping it out avoids snapshot
//! schema churn, and a restart re-backfills feed markets anyway.

use std::collections::{BTreeMap, VecDeque};

/// Supported timeframes: (API name, bucket ms, Crypto.com timeframe name).
pub const TFS: &[(&str, u64, &str)] = &[
    ("1m", 60_000, "M1"),
    ("5m", 300_000, "M5"),
    ("15m", 900_000, "M15"),
    ("1h", 3_600_000, "H1"),
    ("4h", 14_400_000, "H4"),
    ("1d", 86_400_000, "D1"),
];

/// Bars retained per (market, timeframe) — enough to fill the chart's widest view.
pub const CAP: usize = 240;

/// One OHLC bar, price-scaled i128 like every engine price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candle {
    /// Bucket start, unix ms (aligned to the timeframe).
    pub start_ms: u64,
    pub open: i128,
    pub high: i128,
    pub low: i128,
    pub close: i128,
}

/// Per-market, per-timeframe OHLC rings.
#[derive(Default)]
pub struct CandleStore {
    rings: BTreeMap<u64, Vec<VecDeque<Candle>>>,
}

impl CandleStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn market_rings(&mut self, market: u64) -> &mut Vec<VecDeque<Candle>> {
        self.rings
            .entry(market)
            .or_insert_with(|| vec![VecDeque::new(); TFS.len()])
    }

    /// Fold one live mark observation into every timeframe's forming bar.
    pub fn record(&mut self, market: u64, now_ms: u64, px: i128) {
        if px <= 0 {
            return;
        }
        let rings = self.market_rings(market);
        for (i, (_, bucket_ms, _)) in TFS.iter().enumerate() {
            let start = now_ms - now_ms % bucket_ms;
            let ring = &mut rings[i];
            match ring.back_mut() {
                Some(last) if last.start_ms == start => {
                    last.close = px;
                    last.high = last.high.max(px);
                    last.low = last.low.min(px);
                }
                // an out-of-order stamp (clock skew) must not corrupt history
                Some(last) if last.start_ms > start => {}
                _ => {
                    ring.push_back(Candle {
                        start_ms: start,
                        open: px,
                        high: px,
                        low: px,
                        close: px,
                    });
                    if ring.len() > CAP {
                        ring.pop_front();
                    }
                }
            }
        }
    }

    /// Prepend exchange history (ascending) for one timeframe, keeping any bars
    /// the store already recorded live: only candles strictly OLDER than the
    /// oldest live bar are inserted, so a backfill never rewrites live truth.
    pub fn backfill(&mut self, market: u64, tf_idx: usize, history: &[Candle]) {
        let ring = &mut self.market_rings(market)[tf_idx];
        let oldest_live = ring.front().map(|c| c.start_ms);
        for c in history.iter().rev() {
            if oldest_live.is_none_or(|t| c.start_ms < t) && ring.len() < CAP {
                // history is ascending; iterate reversed and push_front to prepend
                if ring.front().is_none_or(|f| c.start_ms < f.start_ms) {
                    ring.push_front(*c);
                }
            }
        }
    }

    /// The most recent `limit` bars (ascending) for a market + timeframe name.
    pub fn get(&self, market: u64, tf: &str, limit: usize) -> Option<Vec<Candle>> {
        let tf_idx = TFS.iter().position(|(name, _, _)| *name == tf)?;
        let ring = self.rings.get(&market)?.get(tf_idx)?;
        let n = ring.len().min(limit);
        Some(ring.iter().skip(ring.len() - n).copied().collect())
    }
}

/// The index of a timeframe name, e.g. `"15m"` → 2.
pub fn tf_index(tf: &str) -> Option<usize> {
    TFS.iter().position(|(name, _, _)| *name == tf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: u64 = 60_000;

    #[test]
    fn record_folds_ohlc_and_rolls_buckets() {
        let mut s = CandleStore::new();
        // three ticks inside one 1m bucket: o=first, h=max, l=min, c=last
        s.record(0, 10 * M + 1_000, 100);
        s.record(0, 10 * M + 20_000, 130);
        s.record(0, 10 * M + 50_000, 90);
        // next bucket opens a new bar
        s.record(0, 11 * M + 5_000, 95);
        let cs = s.get(0, "1m", 10).unwrap();
        assert_eq!(cs.len(), 2);
        assert_eq!(
            (cs[0].open, cs[0].high, cs[0].low, cs[0].close),
            (100, 130, 90, 90)
        );
        assert_eq!(cs[0].start_ms, 10 * M);
        assert_eq!(cs[1].open, 95);
        // the same ticks also folded into the higher timeframes' single bar
        let h = s.get(0, "1h", 10).unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(
            (h[0].open, h[0].high, h[0].low, h[0].close),
            (100, 130, 90, 95)
        );
    }

    #[test]
    fn ring_is_capped_and_out_of_order_stamps_are_ignored() {
        let mut s = CandleStore::new();
        for i in 0..(CAP as u64 + 50) {
            s.record(0, i * M, 100 + i as i128);
        }
        let cs = s.get(0, "1m", usize::MAX).unwrap();
        assert_eq!(cs.len(), CAP, "ring holds at most CAP bars");
        // a stamp older than the forming bar must not corrupt history
        let last_before = *cs.last().unwrap();
        s.record(0, 3 * M, 1);
        let cs2 = s.get(0, "1m", usize::MAX).unwrap();
        assert_eq!(*cs2.last().unwrap(), last_before);
    }

    #[test]
    fn backfill_prepends_history_without_rewriting_live_bars() {
        let mut s = CandleStore::new();
        s.record(0, 100 * M, 500); // one live 1m bar at bucket 100
        let mk = |b: u64, px: i128| Candle {
            start_ms: b * M,
            open: px,
            high: px,
            low: px,
            close: px,
        };
        // history overlaps the live bar (bucket 100) — the live bar must win
        s.backfill(0, 0, &[mk(97, 480), mk(98, 485), mk(100, 999)]);
        let cs = s.get(0, "1m", 10).unwrap();
        assert_eq!(
            cs.iter().map(|c| c.start_ms / M).collect::<Vec<_>>(),
            vec![97, 98, 100]
        );
        assert_eq!(cs.last().unwrap().close, 500, "live bar not rewritten");
    }

    #[test]
    fn unknown_market_or_timeframe_is_none() {
        let mut s = CandleStore::new();
        s.record(0, M, 1);
        assert!(s.get(9, "1m", 10).is_none());
        assert!(s.get(0, "3m", 10).is_none());
        assert!(s.get(0, "1m", 10).is_some());
    }
}
