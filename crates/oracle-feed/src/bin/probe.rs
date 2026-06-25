//! Live oracle probe: fetch each listed market's real Crypto.com ticker and print
//! the `OracleTranscript` the protocol would mark against.
//!
//!   cargo run -p oracle-feed --features http --bin probe
//!
//! Demonstrates the backend oracle connection end-to-end against the live exchange.
//! Falls through per-instrument: a feed/parse failure for one market is reported and
//! the rest still print, mirroring the frontend's graceful degradation.

use perp_core::fixed::PRICE_SCALE;
use perp_core::market::Market;

const MARKETS: &[(&str, &str)] = &[
    ("BTC/USDC", "BTCUSD-PERP"),
    ("ETH/USDC", "ETHUSD-PERP"),
    ("SOL/USDC", "SOLUSD-PERP"),
    ("HYPE/USDC", "HYPEUSD-PERP"),
];

fn main() {
    let now_ms = 0u64;
    let market = Market::conservative(0);
    println!("\n=== dark-perp live oracle probe (Crypto.com) ===\n");
    for (symbol, instrument) in MARKETS {
        match oracle_feed::fetch_transcript(instrument, now_ms) {
            Ok(mut t) => {
                t.publish_time_ms = now_ms;
                let gate = match t.validate(&market, now_ms) {
                    Ok(_) => "passes §8 gate",
                    Err(e) => {
                        eprintln!("{symbol:<10} gate rejected: {e:?}");
                        continue;
                    }
                };
                println!(
                    "{symbol:<10} price ${:<12} conf ${:<8} twap ${:<12} [{gate}]",
                    fmt(t.price),
                    fmt(t.confidence),
                    fmt(t.backup_twap),
                );
            }
            Err(e) => println!("{symbol:<10} feed unavailable: {e}"),
        }
    }
    println!();
}

fn fmt(scaled: i128) -> String {
    let whole = scaled / PRICE_SCALE;
    let frac = (scaled % PRICE_SCALE) / (PRICE_SCALE / 100);
    format!("{whole}.{:02}", frac.abs())
}
