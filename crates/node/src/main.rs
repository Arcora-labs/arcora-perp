//! A running dark-perp node: the live operating loop (§5, §8).
//!
//! Each tick it (1) refreshes the oracle from a ticker — fed through the SAME
//! `oracle-feed` adapter that converts real Crypto.com data, so deployment swaps
//! the simulated ticker for `oracle_feed::fetch_transcript`; (2) runs the
//! funding + liquidation maintenance pass; (3) seals a batch. It prints a status
//! line per tick so you can watch positions mark, fund, and liquidate as the price
//! moves — the continuous counterpart to the one-shot narrated `demo`.
//!
//!   cargo run -p node --release -- [ticks]   (default 12)

use oracle_feed::transcript_from_ticker;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::order::{Order, Side, TimeInForce};
use perp_core::Note;
use sequencer::{EnclaveIdentity, Sequencer};

/// Format a PRICE_SCALE i128 as a 2-decimal ticker string (e.g. "59575.14").
fn px(scaled: i128) -> String {
    let whole = scaled / PRICE_SCALE;
    let frac = (scaled % PRICE_SCALE).abs() / (PRICE_SCALE / 100);
    format!("{whole}.{frac:02}")
}

fn fund(s: &mut Sequencer, owner: u64, usd: i128, blind: u8) {
    let o = word_u64(owner);
    let amount = usd * QUOTE_SCALE;
    let cm = Note::new(o, 0, amount, [blind; 32]).commitment::<Keccak256>();
    s.apply(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount,
        blinding: [blind; 32],
    })
    .unwrap();
    s.apply(&BatchOp::FundPosition {
        owner: o,
        market_id: 0,
        note_commitment: cm,
        spend_key: [owner as u8; 32],
    })
    .unwrap();
}

fn main() {
    let ticks: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);

    let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, [0xAB; 32]);
    let mut node = Sequencer::new(enclave, 24);
    node.add_market(Market::conservative(0));

    let mut price: i128 = 59_575 * PRICE_SCALE; // start near the real BTC index
    let mut now = 1_000u64;
    let seed_oracle = |n: &mut Sequencer, price: i128, now: u64| {
        let spread = price / 10_000; // ~1bp
        let t = transcript_from_ticker(&px(price), &px(price - spread), &px(price + spread), now)
            .expect("ticker → transcript");
        n.set_oracle(0, t);
    };
    seed_oracle(&mut node, price, now);

    // two traders take opposite sides of 1 BTC at the opening index
    fund(&mut node, 1, 6_200, 0x11); // long, thin margin → liquidates as price falls
    fund(&mut node, 2, 50_000, 0x22);
    let mk = |owner: u64, side: Side, nonce: u64| Order {
        owner: word_u64(owner),
        market_id: 0,
        side,
        size: SIZE_SCALE,
        limit_price: price,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: [nonce as u8; 32],
    };
    node.seal_batch(&[mk(1, Side::Buy, 1), mk(2, Side::Sell, 2)], now);

    println!("\n=== dark-perp node · live operating loop ===");
    println!("tick  price        batch  longPnL     insurance   event");
    println!("----  -----------  -----  ----------  ----------  -----------------");

    // a downward drift so the thin long eventually liquidates
    for tick in 0..ticks {
        now += 1_000;
        price -= price / 100; // −1%/tick
        seed_oracle(&mut node, price, now);

        let liquidated = node.run_maintenance(now);
        let sealed = node.seal_batch(&[], now);

        let pnl = node
            .state
            .position(&word_u64(1), 0)
            .filter(|p| p.is_open())
            .and_then(|p| p.unrealized_pnl(price))
            .map(|v| format!("${}", v / QUOTE_SCALE))
            .unwrap_or_else(|| "—".into());
        let event = if !liquidated.is_empty() {
            "LIQUIDATED long"
        } else if node.state.position(&word_u64(1), 0).map(|p| p.is_open()) != Some(true) {
            "flat"
        } else {
            "marking"
        };
        println!(
            "{:>4}  {:>11}  {:>5}  {:>10}  {:>10}  {event}",
            tick,
            px(price),
            sealed.batch_id,
            pnl,
            format!("${}", node.state.insurance_fund / QUOTE_SCALE),
        );
        assert!(
            node.state.conservation_holds(),
            "conservation broke at tick {tick}"
        );
    }
    println!("\nconservation held every tick ✓\n");
}
