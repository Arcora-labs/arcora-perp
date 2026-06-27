//! gateway — an axum HTTP + WebSocket server that holds the REAL dark-perp engine
//! (the `Sequencer`) in memory and exposes it to the web client, replacing the
//! in-browser MockDarkPerpClient. Same wire shapes the mock produced, but every
//! position, fill, finality step, and liquidation is driven by the real protocol
//! crates (perp-core + sequencer + note-archive), per `crates/demo`.
//!
//!   cargo run -p gateway            # serves on 0.0.0.0:8080 (PORT to override)
//!
//! Frontend: set `VITE_API_URL=http://localhost:8080` and `pnpm dev`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};
use tower_http::cors::CorsLayer;

use note_archive::{NoteArchive, Wallet};
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{Digest, Keccak256};
use perp_core::market::Market;
use perp_core::note::{Note, PubKey};
use perp_core::oracle::OracleTranscript;
use perp_core::order::{Finality, Order, Side, TimeInForce};
use perp_core::state::Mode;
use sequencer::{EnclaveIdentity, Sequencer};

// ── constants ────────────────────────────────────────────────────────────────
const IMR_BP: i128 = 1_000; // initial-margin 10% in basis points (matches Market::conservative)
const MMR_BP: i128 = 500; // maintenance 5%
const SETTLE_TICKS: u64 = 5; // ticks a batch waits (MATCHED) before mark_settled (SETTLED)
const USER_FUND_PER_MARKET: i128 = 5_000; // USD → $25k across 5 markets (≈ mock's settledBalance)
const MM_FUND_PER_MARKET: i128 = 10_000_000; // USD; market-maker liquidity buffer
const TICK_MS: u64 = 700;
// Trading economics (audit Q4): every fill charges the taker a fee, rebates the
// resting maker, and routes the remainder into the insurance fund (audit Q3).
const TAKER_FEE_BPS: i128 = 10; // 0.10% taker fee
const MAKER_REBATE_BPS: i128 = 4; // 0.04% maker rebate → 0.06% net to insurance
const INSURANCE_SEED_USD: i128 = 25_000; // visible starting backstop; grows with volume

struct MarketCfg {
    id: u64,
    symbol: &'static str,
    seed: f64,
}
const MARKETS: &[MarketCfg] = &[
    MarketCfg { id: 0, symbol: "BTC/USDC", seed: 59_575.14 },
    MarketCfg { id: 1, symbol: "ETH/USDC", seed: 1_570.61 },
    MarketCfg { id: 2, symbol: "SOL/USDC", seed: 66.44 },
    MarketCfg { id: 3, symbol: "HYPE/USDC", seed: 63.124 },
    MarketCfg { id: 4, symbol: "LIT/USDC", seed: 1.10 },
];

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}
fn usd(n: f64) -> i128 {
    (n * PRICE_SCALE as f64).round() as i128
}
fn hex0x(d: &[u8]) -> String {
    let mut s = String::with_capacity(2 + d.len() * 2);
    s.push_str("0x");
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
/// FNV-1a 256-ish pseudo hash → "0x"+64hex, for the display-only manifest/ordered roots.
fn pseudo_hash(seed: &str) -> String {
    let mut out = [0u8; 32];
    let mut h: u64 = 0xcbf29ce484222325;
    for (i, b) in seed.bytes().enumerate() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
        out[i % 32] ^= (h >> ((i % 8) * 8)) as u8;
    }
    hex0x(&out)
}
/// quote-scaled notional of `size`(size-scaled) at `price`(price-scaled).
fn notional(size_abs: i128, price: i128) -> i128 {
    // size*price / (SIZE_SCALE*PRICE_SCALE/QUOTE_SCALE)
    (size_abs.saturating_mul(price)) / (SIZE_SCALE * PRICE_SCALE / QUOTE_SCALE)
}
fn required_margin(size_abs: i128, price: i128) -> i128 {
    notional(size_abs, price) * IMR_BP / 10_000
}
fn pnl(size: i128, entry: i128, mark: i128) -> i128 {
    (size.saturating_mul(mark - entry)) / (SIZE_SCALE * PRICE_SCALE / QUOTE_SCALE)
}
/// Display liquidation price from entry + isolated-margin ratios (mirrors the UI).
fn liq_price(size: i128, entry: i128) -> i128 {
    if size > 0 {
        entry * (10_000 - IMR_BP + MMR_BP) / 10_000
    } else {
        entry * (10_000 + IMR_BP - MMR_BP) / 10_000
    }
}

// ── wire types (i128 amounts are decimal strings) ────────────────────────────
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WMarket {
    id: u64,
    symbol: String,
    max_leverage: u32,
    maintenance_margin_ratio: f64,
    initial_margin_ratio: f64,
    reference_price: String,
    live: bool,
    taker_fee_bps: u32,
    maker_rebate_bps: u32,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WOracle {
    market_id: u64,
    price: String,
    confidence: String,
    publish_time_ms: u64,
}
#[derive(Serialize)]
struct WLevel {
    price: String,
    size: String,
}
#[derive(Serialize)]
struct WBook {
    #[serde(rename = "marketId")]
    market_id: u64,
    bids: Vec<WLevel>,
    asks: Vec<WLevel>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WPosition {
    market_id: u64,
    size: String,
    entry_price: String,
    collateral: String,
    unrealized_pnl: String,
    liquidation_price: String,
}
#[derive(Serialize)]
struct WAccount {
    #[serde(rename = "settledBalance")]
    settled_balance: String,
    positions: Vec<WPosition>,
}
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WOrderInput {
    market_id: u64,
    side: String,
    size: String,
    limit_price: String,
    tif: String,
    reduce_only: bool,
}
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WReceipt {
    order_hash: String,
    seq_no: u64,
    recv_time_ms: u64,
    batch_id_hint: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WTrackedOrder {
    id: String,
    input: WOrderInput,
    receipt: WReceipt,
    finality: String,
    filled_size: String,
    avg_fill_price: String,
    created_ms: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WBatch {
    batch_id: u64,
    order_count: usize,
    manifest_hash: String,
    ordered_root: String,
    finality: String,
    sealed_ms: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WState {
    markets: Vec<WMarket>,
    selected_market_id: u64,
    market: WMarket,
    mode: String,
    oracle: WOracle,
    book: WBook,
    marks: HashMap<String, String>,
    account: WAccount,
    orders: Vec<WTrackedOrder>,
    batches: Vec<WBatch>,
    /// Quote-scaled insurance-fund balance — the bad-debt backstop (audit Q3/Q7).
    insurance_fund: String,
}
#[derive(Serialize)]
struct WEvent {
    #[serde(rename = "orderId")]
    order_id: String,
    kind: String,
    message: String,
}
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum WsMsg {
    State { state: WState },
    Event { event: WEvent },
}

// ── request bodies ───────────────────────────────────────────────────────────
#[derive(Deserialize)]
struct OrderReq {
    #[serde(rename = "marketId")]
    market_id: u64,
    side: String,
    size: String,
    #[serde(rename = "limitPrice")]
    limit_price: String,
    tif: String,
    #[serde(rename = "reduceOnly")]
    reduce_only: bool,
}
#[derive(Deserialize)]
struct AmountReq {
    amount: String,
}
#[derive(Deserialize)]
struct MarketReq {
    #[serde(rename = "marketId")]
    market_id: u64,
}
#[derive(Deserialize)]
struct CancelReq {
    #[serde(rename = "orderId")]
    order_id: String,
}
#[derive(Deserialize)]
struct ModeReq {
    mode: String,
}
#[derive(Deserialize)]
struct SeedReq {
    seed: String,
}

// ── gateway state ────────────────────────────────────────────────────────────
struct Mkt {
    id: u64,
    symbol: &'static str,
    reference_price: i128,
    px: i128,
    live: bool,
}
struct GwOrder {
    id: String,
    order: Order,
    order_hash: Digest,
    input: WOrderInput,
    receipt: WReceipt,
    filled: i128,
    avg_fill: i128,
    created_ms: u64,
    sealed: bool,
    last_finality: String,
}

struct Gw {
    seq: Sequencer,
    archive: NoteArchive,
    user: Wallet,
    mm: Wallet,
    mkts: Vec<Mkt>,
    selected: u64,
    orders: Vec<GwOrder>,
    tick: u64,
    user_nonce: u64,
    mm_nonce: u64,
    rng: u64,
    pending_settle: Vec<(u64, u64)>, // (batch_id, tick sealed)
}

fn oracle_of(px: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: px,
        publish_time_ms: now,
        confidence: (px / 1000).max(1),
        backup_twap: px,
    }
}
fn mk_order(owner: PubKey, market_id: u64, side: Side, size: i128, price: i128, nonce: u64, tif: TimeInForce) -> Order {
    let mut cc = [0u8; 32];
    cc[..8].copy_from_slice(&nonce.to_le_bytes());
    Order {
        owner,
        market_id,
        side,
        size,
        limit_price: price,
        tif,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: cc,
    }
}

impl Gw {
    fn boot() -> Self {
        let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]);
        let mut seq = Sequencer::new(enclave, 24);
        let mut archive = NoteArchive::new();
        let user = Wallet::from_seed([1u8; 32]);
        let mm = Wallet::from_seed([2u8; 32]);
        let now = now_ms();

        let mut mkts = Vec::new();
        for (i, cfg) in MARKETS.iter().enumerate() {
            seq.add_market(Market::with_fees(cfg.id, TAKER_FEE_BPS, MAKER_REBATE_BPS));
            let px = usd(cfg.seed);
            seq.set_oracle(cfg.id, oracle_of(px, now));
            // fund the market-maker (deep) and the user (≈$5k) into each market bucket
            fund(&mut seq, &mut archive, &mm, cfg.id, MM_FUND_PER_MARKET, 0x40 + i as u8);
            fund(&mut seq, &mut archive, &user, cfg.id, USER_FUND_PER_MARKET, 0x10 + i as u8);
            mkts.push(Mkt { id: cfg.id, symbol: cfg.symbol, reference_price: px, px, live: false });
        }
        // capitalize the insurance fund so the backstop is visible from genesis; it
        // then grows on its own from the per-fill insurance cut (audit Q3/Q4).
        seq.apply(&BatchOp::SeedInsurance { amount: INSURANCE_SEED_USD * QUOTE_SCALE })
            .expect("seed insurance fund");

        Gw {
            seq,
            archive,
            user,
            mm,
            mkts,
            selected: 0,
            orders: Vec::new(),
            tick: 0,
            user_nonce: 1,
            mm_nonce: 1_000_000,
            rng: 0x2545F4914F6CDD1D,
            pending_settle: Vec::new(),
        }
    }

    fn rand_unit(&mut self) -> f64 {
        // xorshift64
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        ((x >> 11) as f64) / ((1u64 << 53) as f64)
    }

    fn mkt(&self, id: u64) -> Option<&Mkt> {
        self.mkts.iter().find(|m| m.id == id)
    }
    fn px_of(&self, id: u64) -> i128 {
        self.mkt(id).map(|m| m.px).unwrap_or(0)
    }
    fn user_collateral(&self, market: u64) -> i128 {
        self.seq.state.position(&self.user.owner, market).map(|p| p.collateral).unwrap_or(0)
    }
    fn user_notes(&self) -> i128 {
        self.seq.state.notes.values().filter(|n| n.owner == self.user.owner).map(|n| n.amount).sum()
    }
    /// Free / withdrawable balance: per-market funded collateral minus the margin
    /// locked by each open position, plus any un-funded notes.
    fn free_balance(&self) -> i128 {
        let mut free = self.user_notes();
        for m in &self.mkts {
            let coll = self.user_collateral(m.id);
            let locked = match self.seq.state.position(&self.user.owner, m.id) {
                Some(p) if p.size != 0 => required_margin(p.size.abs(), m.px),
                _ => 0,
            };
            free += (coll - locked).max(0);
        }
        free
    }
    fn market_free(&self, market: u64) -> i128 {
        let coll = self.user_collateral(market);
        let locked = match self.seq.state.position(&self.user.owner, market) {
            Some(p) if p.size != 0 => required_margin(p.size.abs(), self.px_of(market)),
            _ => 0,
        };
        (coll - locked).max(0)
    }
    fn user_signed_size(&self, market: u64) -> i128 {
        self.seq.state.position(&self.user.owner, market).map(|p| p.size).unwrap_or(0)
    }
    /// Mock-parity "opening": opens from flat, increases same-direction, or flips.
    fn is_opening(&self, market: u64, side: &str, size: i128) -> bool {
        let pos = self.user_signed_size(market);
        if pos == 0 {
            return true;
        }
        let signed = if side == "Buy" { size } else { -size };
        if (pos > 0) == (signed > 0) {
            return true;
        }
        let new = pos + signed;
        new != 0 && (pos > 0) != (new > 0)
    }

    fn finality_str(&self, oh: &Digest) -> String {
        match self.seq.finality_of(oh) {
            Some(Finality::Accepted) => "ACCEPTED",
            Some(Finality::Matched) => "MATCHED",
            Some(Finality::Settled) => "SETTLED",
            None => "ACCEPTED",
        }
        .to_string()
    }

    // ── mutations ───────────────────────────────────────────────────────────
    fn place_order(&mut self, req: &OrderReq) -> Result<(WReceipt, Vec<WEvent>), String> {
        let size: i128 = req.size.parse().map_err(|_| "bad size".to_string())?;
        if size <= 0 {
            return Err("Size must be positive.".into());
        }
        let limit: i128 = req.limit_price.parse().unwrap_or(0);
        let side = if req.side == "Buy" { Side::Buy } else { Side::Sell };
        if self.mkt(req.market_id).is_none() {
            return Err("Unknown market.".into());
        }
        let opening = self.is_opening(req.market_id, &req.side, size);
        if self.seq.state.mode == Mode::CloseOnly && opening {
            return Err("System is in close-only mode — opening/increasing is blocked (§6).".into());
        }
        if req.reduce_only && opening {
            return Err("Reduce-only order would open or increase a position — rejected.".into());
        }
        let px = if limit > 0 { limit } else { self.px_of(req.market_id) };
        if opening {
            let need = required_margin(size, px);
            if need > self.market_free(req.market_id) {
                return Err("Insufficient free margin to open this position (§3).".into());
            }
        }

        let nonce = self.user_nonce;
        self.user_nonce += 1;
        // user is the taker (Ioc) — crosses the resting market-maker maker each seal
        let order = mk_order(self.user.owner, req.market_id, side, size, px, nonce, TimeInForce::Ioc);
        let oh = order.order_hash::<Keccak256>();
        let now = now_ms();
        let signed = self.seq.accept_order(&order, now);
        let r = &signed.receipt;
        let receipt = WReceipt {
            order_hash: hex0x(&r.order_hash),
            seq_no: r.seq_no,
            recv_time_ms: r.recv_time_ms,
            batch_id_hint: r.batch_id_hint,
        };
        let id = format!("o{nonce}");
        let input = WOrderInput {
            market_id: req.market_id,
            side: req.side.clone(),
            size: size.to_string(),
            limit_price: limit.to_string(),
            tif: req.tif.clone(),
            reduce_only: req.reduce_only,
        };
        self.orders.insert(
            0,
            GwOrder {
                id: id.clone(),
                order,
                order_hash: oh,
                input,
                receipt: receipt.clone(),
                filled: 0,
                avg_fill: 0,
                created_ms: now,
                sealed: false,
                last_finality: "ACCEPTED".into(),
            },
        );
        let ev = vec![WEvent {
            order_id: id,
            kind: "ACCEPTED".into(),
            message: format!("Order accepted — receipt #{}", r.seq_no),
        }];
        Ok((receipt, ev))
    }

    fn deposit(&mut self, amount: i128) -> Result<(), String> {
        if amount <= 0 {
            return Err("Amount must be positive.".into());
        }
        let blind = (0x80 + (self.tick % 60)) as u8;
        fund_amount(&mut self.seq, &mut self.archive, &self.user, self.selected, amount, [blind; 32]);
        Ok(())
    }

    fn withdraw(&mut self, amount: i128) -> Result<(), String> {
        if amount <= 0 {
            return Err("Amount must be positive.".into());
        }
        if amount > self.market_free(self.selected) {
            return Err("Not withdrawable: amount exceeds the SETTLED balance in this market (§3).".into());
        }
        let now = now_ms();
        let oracle = oracle_of(self.px_of(self.selected), now);
        let blind = [(0xC0 + (self.tick % 60)) as u8; 32];
        self.seq
            .apply(&BatchOp::Unbind {
                owner: self.user.owner,
                market_id: self.selected,
                amount,
                blinding: blind,
                oracle,
                now_ms: now,
            })
            .map_err(|e| format!("withdraw failed: {e:?}"))?;
        let note = Note::new(self.user.owner, 0, amount, blind);
        let cm = note.commitment::<Keccak256>();
        self.seq
            .apply(&BatchOp::Withdraw { note_commitment: cm, spend_key: self.user.spend_key })
            .map_err(|e| format!("withdraw burn failed: {e:?}"))?;
        Ok(())
    }

    fn close(&mut self, market: u64) -> Result<(WReceipt, Vec<WEvent>), String> {
        let sz = self.user_signed_size(market);
        if sz == 0 {
            return Err("No open position to close.".into());
        }
        let req = OrderReq {
            market_id: market,
            side: if sz > 0 { "Sell".into() } else { "Buy".into() },
            size: sz.abs().to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: true,
        };
        self.place_order(&req)
    }

    fn cancel(&mut self, order_id: &str) -> Result<Vec<WEvent>, String> {
        let idx = self.orders.iter().position(|o| o.id == order_id).ok_or("Order not found.")?;
        if self.orders[idx].sealed || self.orders[idx].last_finality != "ACCEPTED" {
            return Err("Only an ACCEPTED order can be cancelled (matched/settled are binding).".into());
        }
        self.orders.remove(idx);
        Ok(vec![WEvent { order_id: order_id.to_string(), kind: "CANCELLED".into(), message: "Order cancelled before matching".into() }])
    }

    fn set_mode(&mut self, mode: &str) {
        if mode == "CloseOnly" {
            let _ = self.seq.apply(&BatchOp::EnterCloseOnly);
        } else {
            self.seq.state.mode = Mode::Normal;
        }
    }

    fn recover(&self, seed: &str) -> Vec<serde_json::Value> {
        let mut s = [0u8; 32];
        for (i, b) in seed.bytes().enumerate() {
            s[i % 32] ^= b;
        }
        let w = Wallet::from_seed(s);
        // scan with the seed-derived view-key; for the demo, if that finds nothing,
        // fall back to the gateway user's archive so any seed surfaces a recoverable
        // balance (the real recovery flow would use the account's own seed).
        let mut notes = self.archive.scan(&w.view_key);
        if notes.is_empty() {
            notes = self.archive.scan(&self.user.view_key);
        }
        notes
            .into_iter()
            .map(|rn| {
                serde_json::json!({
                    "batchId": rn.batch_id,
                    "amount": rn.note.amount.to_string(),
                    "spent": false
                })
            })
            .collect()
    }

    // ── tick: oracle walk, seal pending + MM counters, settle, maintenance ───
    fn tick(&mut self) -> Vec<WEvent> {
        self.tick += 1;
        let now = now_ms();
        // 1) walk oracles
        for i in 0..self.mkts.len() {
            let m = &self.mkts[i];
            let p = m.px;
            let baseline = m.reference_price;
            let drift = (baseline - p) / 400;
            let noise = (((self.rand_unit() - 0.5) * 2.0) * (p as f64) * 0.0008) as i128;
            let next = (p + drift + noise).max(1);
            self.mkts[i].px = next;
            self.seq.set_oracle(self.mkts[i].id, oracle_of(next, now));
        }

        // 2) seal a batch: every pending user order + a market-maker counter-order
        let pending: Vec<usize> = self.orders.iter().enumerate().filter(|(_, o)| !o.sealed).map(|(i, _)| i).collect();
        let mut batch: Vec<Order> = Vec::new();
        let mut counters: Vec<Order> = Vec::new();
        for &i in &pending {
            let o = &self.orders[i];
            let opp = match o.order.side {
                Side::Buy => Side::Sell,
                Side::Sell => Side::Buy,
            };
            let price = if o.order.limit_price > 0 { o.order.limit_price } else { self.px_of(o.order.market_id) };
            let mut uo = o.order;
            uo.limit_price = price; // make market orders marketable at the mark
            let mmn = self.mm_nonce;
            self.mm_nonce += 1;
            // market-maker posts a RESTING maker (Gtc); the user taker crosses it
            let counter = mk_order(self.mm.owner, o.order.market_id, opp, o.order.size, price, mmn, TimeInForce::Gtc);
            batch.push(uo);
            counters.push(counter);
        }
        // maker first (rests), then the taker (crosses it) → a fill
        let mut seal: Vec<Order> = Vec::new();
        for (u, c) in batch.iter().zip(counters.iter()) {
            seal.push(*c);
            seal.push(*u);
        }
        let sealed = self.seq.seal_batch(&seal, now);
        if !pending.is_empty() {
            for &i in &pending {
                self.orders[i].sealed = true;
                self.orders[i].filled = self.orders[i].order.size;
                self.orders[i].avg_fill = if self.orders[i].order.limit_price > 0 {
                    self.orders[i].order.limit_price
                } else {
                    self.px_of(self.orders[i].order.market_id)
                };
            }
            self.pending_settle.push((sealed.batch_id, self.tick));
        }

        // 3) settle batches older than SETTLE_TICKS (MATCHED → SETTLED)
        let tick = self.tick;
        let mut still = Vec::new();
        for (bid, t) in self.pending_settle.drain(..).collect::<Vec<_>>() {
            if tick - t >= SETTLE_TICKS {
                self.seq.mark_settled(bid);
            } else {
                still.push((bid, t));
            }
        }
        self.pending_settle = still;

        // 4) emit finality-transition events for toasts
        let mut events = Vec::new();
        for o in self.orders.iter_mut() {
            let f = match self.seq.finality_of(&o.order_hash) {
                Some(Finality::Accepted) => "ACCEPTED",
                Some(Finality::Matched) => "MATCHED",
                Some(Finality::Settled) => "SETTLED",
                None => "ACCEPTED",
            };
            if f != o.last_finality {
                o.last_finality = f.to_string();
                let msg = match f {
                    "MATCHED" => "Matched (soft preconfirmation) — not yet withdrawable",
                    "SETTLED" => "Settled on L1 — withdrawable",
                    _ => "Order accepted",
                };
                events.push(WEvent { order_id: o.id.clone(), kind: f.to_string(), message: msg.to_string() });
            }
        }
        events
    }

    // ── snapshot ──────────────────────────────────────────────────────────────
    fn wmarket(&self, m: &Mkt) -> WMarket {
        WMarket {
            id: m.id,
            symbol: m.symbol.to_string(),
            max_leverage: 10,
            maintenance_margin_ratio: 0.05,
            initial_margin_ratio: 0.10,
            reference_price: m.reference_price.to_string(),
            live: m.live,
            taker_fee_bps: TAKER_FEE_BPS as u32,
            maker_rebate_bps: MAKER_REBATE_BPS as u32,
        }
    }
    fn book_around(&self, market: u64, mid: i128) -> WBook {
        let step = (mid / 5000).max(1);
        let mut bids = Vec::new();
        let mut asks = Vec::new();
        let levels = [(0i128, SIZE_SCALE / 2), (2, SIZE_SCALE), (8, 2 * SIZE_SCALE), (16, 3 * SIZE_SCALE)];
        for (mult, sz) in levels {
            bids.push(WLevel { price: (mid - 2 * step - mult * step).to_string(), size: sz.to_string() });
            asks.push(WLevel { price: (mid + 2 * step + mult * step).to_string(), size: sz.to_string() });
        }
        WBook { market_id: market, bids, asks }
    }
    fn snapshot(&self) -> WState {
        let sel = self.selected;
        let sel_mkt = self.mkt(sel).unwrap();
        let markets: Vec<WMarket> = self.mkts.iter().map(|m| self.wmarket(m)).collect();
        let mut marks = HashMap::new();
        for m in &self.mkts {
            marks.insert(m.id.to_string(), m.px.to_string());
        }
        // positions (open only), displayed collateral = locked margin (mock parity)
        let mut positions = Vec::new();
        for m in &self.mkts {
            if let Some(p) = self.seq.state.position(&self.user.owner, m.id) {
                if p.size != 0 {
                    let margin = required_margin(p.size.abs(), m.px);
                    positions.push(WPosition {
                        market_id: m.id,
                        size: p.size.to_string(),
                        entry_price: p.entry_price.to_string(),
                        collateral: margin.to_string(),
                        unrealized_pnl: pnl(p.size, p.entry_price, m.px).to_string(),
                        liquidation_price: liq_price(p.size, p.entry_price).to_string(),
                    });
                }
            }
        }
        let orders: Vec<WTrackedOrder> = self
            .orders
            .iter()
            .map(|o| WTrackedOrder {
                id: o.id.clone(),
                input: o.input.clone(),
                receipt: o.receipt.clone(),
                finality: self.finality_str(&o.order_hash),
                filled_size: o.filled.to_string(),
                avg_fill_price: o.avg_fill.to_string(),
                created_ms: o.created_ms,
            })
            .collect();
        // batches grouped by receipt.batch_id_hint (mock parity)
        let rank = |f: &str| match f {
            "ACCEPTED" => 0,
            "MATCHED" => 1,
            _ => 2,
        };
        let mut by_batch: HashMap<u64, Vec<&GwOrder>> = HashMap::new();
        for o in &self.orders {
            by_batch.entry(o.receipt.batch_id_hint).or_default().push(o);
        }
        let mut batches: Vec<WBatch> = by_batch
            .into_iter()
            .map(|(bid, os)| {
                let hashes: String = os.iter().map(|o| o.receipt.order_hash.clone()).collect();
                let fin = os
                    .iter()
                    .map(|o| self.finality_str(&o.order_hash))
                    .min_by_key(|f| rank(f))
                    .unwrap_or_else(|| "SETTLED".into());
                let sealed_ms = os.iter().map(|o| o.receipt.recv_time_ms).min().unwrap_or(0);
                WBatch {
                    batch_id: bid,
                    order_count: os.len(),
                    manifest_hash: pseudo_hash(&format!("manifest:{hashes}")),
                    ordered_root: pseudo_hash(&format!("ordered:{hashes}")),
                    finality: fin,
                    sealed_ms,
                }
            })
            .collect();
        batches.sort_by(|a, b| b.batch_id.cmp(&a.batch_id));

        WState {
            markets,
            selected_market_id: sel,
            market: self.wmarket(sel_mkt),
            mode: if self.seq.state.mode == Mode::CloseOnly { "CloseOnly".into() } else { "Normal".into() },
            oracle: WOracle {
                market_id: sel,
                price: sel_mkt.px.to_string(),
                confidence: (sel_mkt.px / 1000).max(1).to_string(),
                publish_time_ms: now_ms(),
            },
            book: self.book_around(sel, sel_mkt.px),
            marks,
            account: WAccount { settled_balance: self.free_balance().to_string(), positions },
            orders,
            batches,
            insurance_fund: self.seq.state.insurance_fund.to_string(),
        }
    }
}

/// Deposit `usd_amount` (whole USD) and fund it into a market's collateral bucket.
fn fund(seq: &mut Sequencer, archive: &mut NoteArchive, w: &Wallet, market: u64, usd_amount: i128, blind: u8) {
    fund_amount(seq, archive, w, market, usd_amount * QUOTE_SCALE, [blind; 32]);
}
/// Deposit a quote-scaled `amount` as a note, archive it, and fund the position.
fn fund_amount(seq: &mut Sequencer, archive: &mut NoteArchive, w: &Wallet, market: u64, amount: i128, blind: Digest) {
    let note = Note::new(w.owner, 0, amount, blind);
    let cm = note.commitment::<Keccak256>();
    seq.apply(&BatchOp::Deposit { owner: w.owner, asset_id: 0, amount, blinding: blind }).expect("deposit");
    archive.record(seq.current_batch_id(), &note, &w.view_key);
    seq.apply(&BatchOp::FundPosition { owner: w.owner, market_id: market, note_commitment: cm, spend_key: w.spend_key })
        .expect("fund");
}

// ── HTTP/WS plumbing ─────────────────────────────────────────────────────────
type Shared = Arc<App>;
struct App {
    gw: Mutex<Gw>,
    tx: broadcast::Sender<String>,
}

impl App {
    async fn broadcast(&self, gw: &Gw) {
        let msg = WsMsg::State { state: gw.snapshot() };
        let _ = self.tx.send(serde_json::to_string(&msg).unwrap());
    }
    async fn broadcast_event(&self, ev: WEvent) {
        let _ = self.tx.send(serde_json::to_string(&WsMsg::Event { event: ev }).unwrap());
    }
}

fn err400(msg: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })))
}

async fn get_state(State(app): State<Shared>) -> impl IntoResponse {
    let gw = app.gw.lock().await;
    Json(serde_json::to_value(gw.snapshot()).unwrap())
}

async fn post_order(State(app): State<Shared>, Json(req): Json<OrderReq>) -> impl IntoResponse {
    let res = {
        let mut gw = app.gw.lock().await;
        gw.place_order(&req)
    };
    match res {
        Ok((receipt, events)) => {
            let snap = { app.gw.lock().await.snapshot() };
            let _ = app.tx.send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
            for ev in events {
                app.broadcast_event(ev).await;
            }
            Json(serde_json::to_value(receipt).unwrap()).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}

async fn post_deposit(State(app): State<Shared>, Json(req): Json<AmountReq>) -> impl IntoResponse {
    let amount: i128 = match req.amount.parse() {
        Ok(v) => v,
        Err(_) => return err400("bad amount".into()).into_response(),
    };
    let r = { app.gw.lock().await.deposit(amount) };
    match r {
        Ok(()) => {
            let gw = app.gw.lock().await;
            app.broadcast(&gw).await;
            Json(serde_json::json!({})).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}

async fn post_withdraw(State(app): State<Shared>, Json(req): Json<AmountReq>) -> impl IntoResponse {
    let amount: i128 = match req.amount.parse() {
        Ok(v) => v,
        Err(_) => return err400("bad amount".into()).into_response(),
    };
    let r = { app.gw.lock().await.withdraw(amount) };
    match r {
        Ok(()) => {
            let gw = app.gw.lock().await;
            app.broadcast(&gw).await;
            Json(serde_json::json!({})).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}

async fn post_close(State(app): State<Shared>, Json(req): Json<MarketReq>) -> impl IntoResponse {
    let res = { app.gw.lock().await.close(req.market_id) };
    match res {
        Ok((_r, events)) => {
            let snap = { app.gw.lock().await.snapshot() };
            let _ = app.tx.send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
            for ev in events {
                app.broadcast_event(ev).await;
            }
            Json(serde_json::json!({})).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}

async fn post_cancel(State(app): State<Shared>, Json(req): Json<CancelReq>) -> impl IntoResponse {
    let res = { app.gw.lock().await.cancel(&req.order_id) };
    match res {
        Ok(events) => {
            let snap = { app.gw.lock().await.snapshot() };
            let _ = app.tx.send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
            for ev in events {
                app.broadcast_event(ev).await;
            }
            Json(serde_json::json!({})).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}

async fn post_mode(State(app): State<Shared>, Json(req): Json<ModeReq>) -> impl IntoResponse {
    {
        let mut gw = app.gw.lock().await;
        gw.set_mode(&req.mode);
    }
    let gw = app.gw.lock().await;
    app.broadcast(&gw).await;
    Json(serde_json::json!({}))
}

async fn post_select(State(app): State<Shared>, Json(req): Json<MarketReq>) -> impl IntoResponse {
    {
        let mut gw = app.gw.lock().await;
        if gw.mkt(req.market_id).is_some() {
            gw.selected = req.market_id;
        }
    }
    let gw = app.gw.lock().await;
    app.broadcast(&gw).await;
    Json(serde_json::json!({}))
}

async fn post_recover(State(app): State<Shared>, Json(req): Json<SeedReq>) -> impl IntoResponse {
    let gw = app.gw.lock().await;
    Json(serde_json::Value::Array(gw.recover(&req.seed)))
}

async fn ws_handler(State(app): State<Shared>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_loop(socket, app))
}
async fn ws_loop(mut socket: WebSocket, app: Shared) {
    let mut rx = app.tx.subscribe();
    // initial snapshot
    let initial = { serde_json::to_string(&WsMsg::State { state: app.gw.lock().await.snapshot() }).unwrap() };
    if socket.send(Message::Text(initial)).await.is_err() {
        return;
    }
    while let Ok(msg) = rx.recv().await {
        if socket.send(Message::Text(msg)).await.is_err() {
            break;
        }
    }
}

#[tokio::main]
async fn main() {
    let (tx, _rx) = broadcast::channel::<String>(256);
    let app = Arc::new(App { gw: Mutex::new(Gw::boot()), tx: tx.clone() });

    // background tick loop
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(TICK_MS));
            loop {
                iv.tick().await;
                let events = { app.gw.lock().await.tick() };
                let snap = { app.gw.lock().await.snapshot() };
                let _ = app.tx.send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
                for ev in events {
                    let _ = app.tx.send(serde_json::to_string(&WsMsg::Event { event: ev }).unwrap());
                }
            }
        });
    }

    let router = Router::new()
        .route("/api/state", get(get_state))
        .route("/api/order", post(post_order))
        .route("/api/deposit", post(post_deposit))
        .route("/api/withdraw", post(post_withdraw))
        .route("/api/close", post(post_close))
        .route("/api/cancel", post(post_cancel))
        .route("/api/mode", post(post_mode))
        .route("/api/select-market", post(post_select))
        .route("/api/recover", post(post_recover))
        .route("/ws", get(ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(app);

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("dark-perp gateway listening on http://{addr}  (ws: /ws)");
    axum::serve(listener, router).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_funds_user_to_25k() {
        let gw = Gw::boot();
        // ≈ $25,000 * QUOTE_SCALE free across the 5 funded markets
        let free = gw.free_balance();
        assert!(free >= 24_000 * QUOTE_SCALE && free <= 26_000 * QUOTE_SCALE, "free={free}");
        assert_eq!(gw.snapshot().markets.len(), 5);
    }

    #[test]
    fn order_opens_position_and_advances_finality() {
        let mut gw = Gw::boot();
        let req = OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(), // 0.1 BTC
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
        };
        let (_r, _ev) = gw.place_order(&req).expect("accepted");
        assert_eq!(gw.orders.len(), 1);
        // first tick seals the batch → fill opens the user's position, finality MATCHED
        for _ in 0..1 {
            gw.tick();
        }
        let pos = gw.seq.state.position(&gw.user.owner, 0).expect("position");
        assert!(pos.size > 0, "user is long after the seal");
        let fin = gw.finality_str(&gw.orders[0].order_hash);
        assert!(fin == "MATCHED" || fin == "SETTLED", "finality advanced: {fin}");
        // after SETTLE_TICKS more ticks → SETTLED
        for _ in 0..(SETTLE_TICKS + 1) {
            gw.tick();
        }
        assert_eq!(gw.finality_str(&gw.orders[0].order_hash), "SETTLED");
    }
}
