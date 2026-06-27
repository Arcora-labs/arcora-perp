//! The dark-perp operating loop as a reusable, testable engine (§5, §8).
//!
//! `main.rs` is a thin printer over this; the lifecycle it demonstrates — a thin
//! long marks down, funds, and liquidates while collateral conservation holds at
//! every step — is exercised here so it can be **locked into CI** by
//! `tests/lifecycle.rs` instead of only being asserted at runtime when someone
//! happens to `cargo run` the binary.

use oracle_feed::transcript_from_ticker;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::order::{Order, Side, TimeInForce};
use perp_core::Note;
use sequencer::{EnclaveIdentity, Sequencer};

/// Opening index, matching the real BTC range the live oracle feeds.
pub const START_PRICE: i128 = 59_575 * PRICE_SCALE;
/// The thin long (owner 1) is funded just enough that a few −1% ticks wipe it.
pub const THIN_LONG_USD: i128 = 6_200;
/// The deep counterparty (owner 2) is funded so it never approaches maintenance.
pub const DEEP_SHORT_USD: i128 = 50_000;

/// Format a PRICE_SCALE i128 as a 2-decimal ticker string (e.g. "59575.14").
pub fn px(scaled: i128) -> String {
    let sign = if scaled < 0 { "-" } else { "" };
    let mag = scaled.abs();
    let whole = mag / PRICE_SCALE;
    let frac = (mag % PRICE_SCALE) / (PRICE_SCALE / 100);
    format!("{sign}{whole}.{frac:02}")
}

/// One tick's observable state — everything `main` prints and every property a
/// test wants to assert, with no I/O so it round-trips cleanly.
#[derive(Clone, Debug)]
pub struct TickReport {
    pub tick: u64,
    pub price: i128,
    pub batch_id: u64,
    /// Long's unrealized PnL in QUOTE_SCALE units, `None` once it is flat.
    pub long_pnl: Option<i128>,
    /// Insurance fund balance in QUOTE_SCALE units.
    pub insurance_fund: i128,
    /// True on the tick the long is force-closed.
    pub liquidated: bool,
    /// True while the long position is still open.
    pub long_open: bool,
    /// Collateral conservation after this tick — must always be true.
    pub conservation_holds: bool,
}

/// A booted node with two opposing 1 BTC positions already open at the index.
pub struct Node {
    seq: Sequencer,
    price: i128,
    now: u64,
    tick: u64,
}

impl Node {
    /// Boot the node: seed the oracle, fund both traders, and cross a 1 BTC
    /// long (thin) against a 1 BTC short (deep) at the opening index.
    pub fn boot() -> Self {
        let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, [0xAB; 32]);
        let mut seq = Sequencer::new(enclave, 24);
        seq.add_market(Market::conservative(0));

        let price = START_PRICE;
        let now = 1_000u64;
        seed_oracle(&mut seq, price, now);

        fund(&mut seq, 1, THIN_LONG_USD, 0x11);
        fund(&mut seq, 2, DEEP_SHORT_USD, 0x22);
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
        seq.seal_batch(&[mk(1, Side::Buy, 1), mk(2, Side::Sell, 2)], now);

        Node {
            seq,
            price,
            now,
            tick: 0,
        }
    }

    /// Advance one tick: drop the index −1%, refresh the oracle, run the
    /// funding+liquidation maintenance pass, seal a batch, and report.
    pub fn step(&mut self) -> TickReport {
        self.now += 1_000;
        self.price -= self.price / 100; // −1%/tick
        seed_oracle(&mut self.seq, self.price, self.now);

        let liquidated = !self.seq.run_maintenance(self.now).liquidated.is_empty();
        let sealed = self.seq.seal_batch(&[], self.now);

        let pos = self.seq.state.position(&word_u64(1), 0);
        let long_open = pos.map(|p| p.is_open()) == Some(true);
        let long_pnl = pos
            .filter(|p| p.is_open())
            .and_then(|p| p.unrealized_pnl(self.price))
            .map(|v| v / QUOTE_SCALE);

        let report = TickReport {
            tick: self.tick,
            price: self.price,
            batch_id: sealed.batch_id,
            long_pnl,
            insurance_fund: self.seq.state.insurance_fund / QUOTE_SCALE,
            liquidated,
            long_open,
            conservation_holds: self.seq.state.conservation_holds(),
        };
        self.tick += 1;
        report
    }
}

fn seed_oracle(n: &mut Sequencer, price: i128, now: u64) {
    let spread = price / 10_000; // ~1bp
    let t = transcript_from_ticker(&px(price), &px(price - spread), &px(price + spread), now)
        .expect("ticker → transcript");
    n.set_oracle(0, t);
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
