//! Order-book stress-test bot.
//!
//! Hammers the real price-time CLOB (`matcher::MatchingEngine`) with a large,
//! randomized order stream and reports throughput, fill ratio, rejection mix,
//! resting depth, and per-order latency percentiles — plus a hard check that the
//! book invariant (best_bid < best_ask) holds throughout and nothing panics.
//!
//! Usage: `cargo run -p loadbot --release -- [orders] [seed]`  (defaults 200000 42)

use matcher::{MatchingEngine, SubmitStatus};
use perp_core::fixed::{PRICE_SCALE, SIZE_SCALE};
use perp_core::hash::word_u64;
use perp_core::order::{Order, RejectReason, Side, TimeInForce};
use std::time::Instant;

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

fn main() {
    let mut args = std::env::args().skip(1);
    // clamp to >=1 so the latency percentile indexing can never underflow
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200_000).max(1);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(42);

    println!("\n=== dark-perp order-book stress test ===");
    println!("market BTC/USDC · {n} orders · seed {seed}\n");

    let mut e: MatchingEngine = MatchingEngine::new();
    e.open_market(0);
    let mut rng = Rng(seed | 1);

    // mid in price units (~$59,575), drifts slightly during the run
    let mut mid: i128 = 59_575 * PRICE_SCALE;
    const N_ACCT: u64 = 64;

    let mut fills = 0u64;
    let mut matched_size: i128 = 0;
    let mut rejects = [0u64; 10]; // indexed by RejectReason as u16
    let mut rested = 0u64;
    let mut peak_depth = 0i128;
    let mut lat: Vec<u64> = Vec::with_capacity(n);
    let mut bad_spread = 0u64;

    let wall = Instant::now();
    for i in 0..n {
        // random walk the mid a touch so the book churns
        mid += (rng.below(2001) as i128 - 1000) * (PRICE_SCALE / 10000);
        mid = mid.clamp(40_000 * PRICE_SCALE, 80_000 * PRICE_SCALE);

        let side = if rng.below(2) == 0 {
            Side::Buy
        } else {
            Side::Sell
        };
        let tif = match rng.below(10) {
            0 => TimeInForce::Fok,
            1 => TimeInForce::PostOnly,
            2 | 3 => TimeInForce::Ioc,
            _ => TimeInForce::Gtc,
        };
        // price within ±0.4% of mid; 1-in-12 is a market order
        let off = (rng.below(801) as i128 - 400) * (mid / 100_000);
        let limit_price = if rng.below(12) == 0 {
            0
        } else {
            (mid + off).max(PRICE_SCALE)
        };
        let size = (1 + rng.below(500)) as i128 * (SIZE_SCALE / 100); // 0.01–5.00

        let order = Order {
            owner: word_u64(rng.below(N_ACCT)),
            market_id: 0,
            side,
            size,
            limit_price,
            tif,
            reduce_only: false,
            nonce: i as u64,
            expiry_ms: 0,
            ciphertext_commit: word_u64((i as u64).wrapping_mul(0x9E37)),
        };

        let t0 = Instant::now();
        let out = e.submit(&order, 1_000).outcome;
        lat.push(t0.elapsed().as_nanos() as u64);

        fills += out.fills.len() as u64;
        for f in &out.fills {
            matched_size += f.size;
        }
        match out.status {
            SubmitStatus::Rejected(r) => rejects[r as usize] += 1,
            SubmitStatus::Resting | SubmitStatus::FilledResting { .. } => rested += 1,
            _ => {}
        }

        if let Some(book) = e.book(0) {
            // best_bid/best_ask are O(log n) — check the no-crossed-book invariant
            // every order; it must hold continuously.
            if let (Some(b), Some(a)) = (book.best_bid(), book.best_ask()) {
                if b >= a {
                    bad_spread += 1; // a resting book must never be crossed
                }
            }
            // resting_size walks the whole book (O(levels)), so sample peak depth
            // periodically rather than every order (keeps the measurement off the
            // hot path so the throughput number reflects the matcher, not the probe).
            if i % 512 == 0 {
                let depth = book.resting_size(Side::Buy) + book.resting_size(Side::Sell);
                if depth > peak_depth {
                    peak_depth = depth;
                }
            }
        }
    }
    let elapsed = wall.elapsed();

    lat.sort_unstable();
    let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)];
    let secs = elapsed.as_secs_f64();
    let book = e.book(0).unwrap();
    let f2 = |v: i128, s: i128| format!("{:.2}", v as f64 / s as f64);

    println!(
        "throughput     : {:.0} orders/sec  ({:.2?} total)",
        n as f64 / secs,
        elapsed
    );
    println!(
        "fills          : {fills} fills · {} BTC matched · {:.1}% of orders crossed",
        f2(matched_size, SIZE_SCALE),
        100.0 * (n as f64 - rested as f64 - rejects.iter().sum::<u64>() as f64).max(0.0) / n as f64
    );
    println!(
        "rejections     : post-only {} · FOK-unfillable {} · expired {} · other {}",
        rejects[RejectReason::PostOnlyWouldTake as usize],
        rejects[RejectReason::FillOrKillUnfillable as usize],
        rejects[RejectReason::Expired as usize],
        rejects.iter().sum::<u64>()
            - rejects[RejectReason::PostOnlyWouldTake as usize]
            - rejects[RejectReason::FillOrKillUnfillable as usize]
            - rejects[RejectReason::Expired as usize],
    );
    println!(
        "resting book   : {} bids / {} asks · best {} / {}",
        f2(book.resting_size(Side::Buy), SIZE_SCALE),
        f2(book.resting_size(Side::Sell), SIZE_SCALE),
        book.best_bid()
            .map(|p| f2(p, PRICE_SCALE))
            .unwrap_or_else(|| "—".into()),
        book.best_ask()
            .map(|p| f2(p, PRICE_SCALE))
            .unwrap_or_else(|| "—".into()),
    );
    println!(
        "peak depth     : {} BTC resting",
        f2(peak_depth, SIZE_SCALE)
    );
    println!(
        "per-order time : avg {}ns · p50 {}ns · p99 {}ns · max {}ns",
        lat.iter().sum::<u64>() / lat.len() as u64,
        pct(0.50),
        pct(0.99),
        lat[lat.len() - 1],
    );
    println!(
        "invariants     : best_bid < best_ask held {} · no panics ✓\n",
        if bad_spread == 0 {
            "✓"
        } else {
            "✗ VIOLATED"
        }
    );
    assert_eq!(
        bad_spread, 0,
        "the resting book was crossed — CLOB invariant violated"
    );
}
