//! A running dark-perp node: the live operating loop (§5, §8).
//!
//! Each tick it (1) refreshes the oracle from a ticker — fed through the SAME
//! `oracle-feed` adapter that converts real Crypto.com data, so deployment swaps
//! the simulated ticker for `oracle_feed::fetch_transcript`; (2) runs the
//! funding + liquidation maintenance pass; (3) seals a batch. It prints a status
//! line per tick so you can watch positions mark, fund, and liquidate as the price
//! moves — the continuous counterpart to the one-shot narrated `demo`.
//!
//! The loop itself lives in `lib.rs` (`Node`) so the lifecycle it shows is locked
//! into CI by `tests/lifecycle.rs`; this binary is just the printer.
//!
//!   cargo run -p node --release -- [ticks]   (default 12)

use node::{px, Node};

fn main() {
    let ticks: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);

    let mut node = Node::boot();

    println!("\n=== dark-perp node · live operating loop ===");
    println!("tick  price        batch  longPnL     insurance   event");
    println!("----  -----------  -----  ----------  ----------  -----------------");

    for _ in 0..ticks {
        let r = node.step();
        let pnl = r
            .long_pnl
            .map(|v| format!("${v}"))
            .unwrap_or_else(|| "—".into());
        let event = if r.liquidated {
            "LIQUIDATED long"
        } else if !r.long_open {
            "flat"
        } else {
            "marking"
        };
        println!(
            "{:>4}  {:>11}  {:>5}  {:>10}  {:>10}  {event}",
            r.tick,
            px(r.price),
            r.batch_id,
            pnl,
            format!("${}", r.insurance_fund),
        );
        assert!(
            r.conservation_holds,
            "conservation broke at tick {}",
            r.tick
        );
    }
    println!("\nconservation held every tick ✓\n");
}
