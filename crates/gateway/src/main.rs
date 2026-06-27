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
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
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
use sequencer::{adl_tag, adl_tag_key, EnclaveIdentity, SealedBatch, Sequencer};

mod l1;
use l1::{L1Status, L1};

/// 0x-prefixed lowercase hex of a 32-byte digest (for L1 calldata + display).
fn hex32(d: &Digest) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

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
const L1_SETTLE_SECS: u64 = 30; // how often the L1 bridge advances the on-chain root
const L1_BOND_WEI: &str = "5000000000000000"; // 0.005 ETH sequencer bond posted once

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
/// 32 cryptographically secure random bytes (API keys + wallet seeds) from the OS
/// CSPRNG — never the demo's predictable xorshift walk.
fn csprng_bytes32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS CSPRNG");
    b
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
/// The market-maker's net inventory + delta-neutral hedge target per market (audit
/// Q5). The protocol emits this signal; an external keeper executes the hedge.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WHedge {
    market_id: u64,
    symbol: String,
    inventory: String,    // signed, size-scaled — the MM's net exposure
    hedge_target: String, // −inventory: the offset to take on an external venue
    notional: String,     // quote-scaled exposure at mark
}
/// The last on-chain L1 settlement the bridge published (audit/§3) — present only
/// when the gateway runs with the L1 bridge configured.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WL1 {
    settled_root: String,
    batch_count: u64,
    last_tx: String,
    bond_wei: String,
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
    /// Quote-scaled cumulative collateral the user has had auto-deleveraged — the
    /// transparency surface for socialized losses (audit Q2).
    user_adl_clawed: String,
    /// The market-maker's net inventory + hedge target per market with open MM
    /// exposure — the venue-agnostic delta-hedging signal (audit Q5).
    mm_hedge: Vec<WHedge>,
    /// The last on-chain L1 settlement, if the L1 bridge is active (else null).
    l1: Option<WL1>,
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

/// A registered external API account (multi-tenant `/v1`). Each is an independent
/// trader on the SAME shared engine/order book, keyed by a secret API key. Phase 0:
/// the gateway custodies the account's wallet (the real version moves spend keys
/// into the enclave); the API key authenticates the caller and the server acts for
/// them — the CEX-style API shape market-makers/bots expect.
struct Account {
    wallet: Wallet,
    orders: Vec<GwOrder>,
    nonce: u64,
    deposit_counter: u64,
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
    /// Cumulative collateral the USER has had clawed by auto-deleverage (audit Q2),
    /// recognized from the sealed batches' ADL receipts via the user's secret key.
    user_adl_clawed: i128,
    /// Registered external `/v1` API accounts, keyed by their secret API key.
    accounts: std::collections::BTreeMap<[u8; 32], Account>,
    /// Manifest hash of the most recently sealed batch — published to L1 as the
    /// settled batch's manifest when the L1 bridge is active.
    last_manifest: Digest,
    /// Last on-chain settlement the L1 bridge published (None until it settles once).
    l1_status: Option<L1Status>,
}

fn oracle_of(px: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: px,
        publish_time_ms: now,
        confidence: (px / 1000).max(1),
        backup_twap: px,
    }
}
fn parse_tif(s: &str) -> TimeInForce {
    match s {
        "Gtc" => TimeInForce::Gtc,
        "Fok" => TimeInForce::Fok,
        "PostOnly" => TimeInForce::PostOnly,
        _ => TimeInForce::Ioc,
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
            user_adl_clawed: 0,
            accounts: std::collections::BTreeMap::new(),
            last_manifest: [0u8; 32],
            l1_status: None,
        }
    }

    // ── multi-tenant `/v1` account operations ────────────────────────────────
    /// Register a fresh account: generate a custodied wallet + a secret API key.
    /// Returns `(api_key, owner)`. Both come from the OS CSPRNG (`csprng_bytes32`),
    /// NOT the demo's predictable xorshift walk — keys must be unguessable.
    ///
    /// NOTE (Phase 0 custody): the account's spend key is held in process memory in
    /// the clear, so a memory disclosure already exposes the real custody secret;
    /// hashing the API key for storage would be inconsistent with that. The durable
    /// fix is moving custody inside the enclave (the TEE milestone), not key hashing.
    fn register_account(&mut self) -> ([u8; 32], PubKey) {
        let seed = csprng_bytes32();
        let api_key = csprng_bytes32();
        let wallet = Wallet::from_seed(seed);
        let owner = wallet.owner;
        self.accounts.insert(
            api_key,
            Account {
                wallet,
                orders: Vec::new(),
                nonce: 1,
                deposit_counter: 0,
            },
        );
        (api_key, owner)
    }

    /// Per-owner free margin in a market (the multi-tenant analog of `market_free`).
    fn market_free_of(&self, owner: &PubKey, market: u64) -> i128 {
        let coll = self
            .seq
            .state
            .position(owner, market)
            .map(|p| p.collateral)
            .unwrap_or(0);
        let locked = match self.seq.state.position(owner, market) {
            Some(p) if p.size != 0 => required_margin(p.size.abs(), self.px_of(market)),
            _ => 0,
        };
        (coll - locked).max(0)
    }
    /// Does this order open/increase the owner's position (vs reduce/close)?
    fn is_opening_of(&self, owner: &PubKey, market: u64, side: &str, size: i128) -> bool {
        match self.seq.state.position(owner, market) {
            Some(p) if p.size != 0 => {
                let same = (p.size > 0) == (side == "Buy");
                same || size > p.size.abs()
            }
            _ => true,
        }
    }

    /// Deposit external collateral into an account's market bucket.
    fn account_deposit(&mut self, key: &[u8; 32], market: u64, amount: i128) -> Result<(), String> {
        if amount <= 0 {
            return Err("Amount must be positive.".into());
        }
        if self.mkt(market).is_none() {
            return Err("Unknown market.".into());
        }
        let (wallet, dc) = {
            let a = self.accounts.get(key).ok_or("Unknown account.")?;
            (a.wallet, a.deposit_counter)
        };
        let mut blind = [0xA0u8; 32];
        blind[..8].copy_from_slice(&dc.to_le_bytes());
        fund_amount(&mut self.seq, &mut self.archive, &wallet, market, amount, blind);
        self.accounts.get_mut(key).unwrap().deposit_counter += 1;
        Ok(())
    }

    /// Place an order for an account. Ioc/Fok are takers; Gtc/PostOnly rest in the
    /// matcher book (so an MM bot can quote). Returns the signed receipt.
    fn account_place_order(&mut self, key: &[u8; 32], req: &OrderReq) -> Result<WReceipt, String> {
        let size: i128 = req.size.parse().map_err(|_| "bad size".to_string())?;
        if size <= 0 {
            return Err("Size must be positive.".into());
        }
        if self.mkt(req.market_id).is_none() {
            return Err("Unknown market.".into());
        }
        let owner = self.accounts.get(key).ok_or("Unknown account.")?.wallet.owner;
        let limit: i128 = req.limit_price.parse().unwrap_or(0);
        let side = if req.side == "Buy" { Side::Buy } else { Side::Sell };
        let opening = self.is_opening_of(&owner, req.market_id, &req.side, size);
        if self.seq.state.mode == Mode::CloseOnly && opening {
            return Err("System is in close-only mode — opening/increasing is blocked (§6).".into());
        }
        if req.reduce_only && opening {
            return Err("Reduce-only order would open or increase a position — rejected.".into());
        }
        let px = if limit > 0 { limit } else { self.px_of(req.market_id) };
        if opening {
            let need = required_margin(size, px);
            if need > self.market_free_of(&owner, req.market_id) {
                return Err("Insufficient free margin to open this position (§3).".into());
            }
        }
        let tif = parse_tif(&req.tif);
        let acct = self.accounts.get_mut(key).unwrap();
        let nonce = acct.nonce;
        acct.nonce += 1;
        let order = mk_order(owner, req.market_id, side, size, px, nonce, tif);
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
        let input = WOrderInput {
            market_id: req.market_id,
            side: req.side.clone(),
            size: size.to_string(),
            limit_price: limit.to_string(),
            tif: req.tif.clone(),
            reduce_only: req.reduce_only,
        };
        let acct = self.accounts.get_mut(key).unwrap();
        acct.orders.insert(
            0,
            GwOrder {
                id: format!("o{nonce}"),
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
        Ok(receipt)
    }

    /// Cancel an account's still-ACCEPTED order.
    fn account_cancel(&mut self, key: &[u8; 32], order_id: &str) -> Result<(), String> {
        let acct = self.accounts.get_mut(key).ok_or("Unknown account.")?;
        let idx = acct
            .orders
            .iter()
            .position(|o| o.id == order_id)
            .ok_or("Order not found.")?;
        if acct.orders[idx].sealed || acct.orders[idx].last_finality != "ACCEPTED" {
            return Err("Only an ACCEPTED order can be cancelled (matched/settled are binding).".into());
        }
        // ACCEPTED orders have not been sealed into a batch yet (not in the matcher
        // book), so dropping them from tracking is enough — they are never submitted.
        acct.orders.remove(idx);
        Ok(())
    }

    // ── /v1 read views ───────────────────────────────────────────────────────
    fn free_balance_of(&self, owner: &PubKey) -> i128 {
        let mut free: i128 = self
            .seq
            .state
            .notes
            .values()
            .filter(|n| &n.owner == owner)
            .map(|n| n.amount)
            .sum();
        for m in &self.mkts {
            let coll = self.seq.state.position(owner, m.id).map(|p| p.collateral).unwrap_or(0);
            let locked = match self.seq.state.position(owner, m.id) {
                Some(p) if p.size != 0 => required_margin(p.size.abs(), m.px),
                _ => 0,
            };
            free += (coll - locked).max(0);
        }
        free
    }
    fn positions_json_of(&self, owner: &PubKey) -> Vec<serde_json::Value> {
        let mut v = Vec::new();
        for m in &self.mkts {
            if let Some(p) = self.seq.state.position(owner, m.id) {
                if p.size != 0 {
                    v.push(serde_json::json!({
                        "marketId": m.id,
                        "size": p.size.to_string(),
                        "entryPrice": p.entry_price.to_string(),
                        "collateral": required_margin(p.size.abs(), m.px).to_string(),
                        "unrealizedPnl": pnl(p.size, p.entry_price, m.px).to_string(),
                        "liquidationPrice": liq_price(p.size, p.entry_price).to_string(),
                    }));
                }
            }
        }
        v
    }
    fn v1_account(&self, key: &[u8; 32]) -> Option<serde_json::Value> {
        let a = self.accounts.get(key)?;
        let owner = a.wallet.owner;
        Some(serde_json::json!({
            "owner": hex0x(&owner),
            "settledBalance": self.free_balance_of(&owner).to_string(),
            "positions": self.positions_json_of(&owner),
            "nextNonce": a.nonce,
        }))
    }
    fn v1_orders_json(&self, key: &[u8; 32]) -> Option<serde_json::Value> {
        let a = self.accounts.get(key)?;
        let orders: Vec<_> = a
            .orders
            .iter()
            .map(|o| {
                serde_json::json!({
                    "orderId": o.id,
                    "marketId": o.order.market_id,
                    "side": o.input.side,
                    "size": o.input.size,
                    "limitPrice": o.input.limit_price,
                    "tif": o.input.tif,
                    "reduceOnly": o.input.reduce_only,
                    "orderHash": hex0x(&o.order_hash),
                    "finality": o.last_finality,
                    "filledSize": o.filled.to_string(),
                    "avgFillPrice": o.avg_fill.to_string(),
                    "createdMs": o.created_ms,
                })
            })
            .collect();
        Some(serde_json::json!({ "orders": orders }))
    }
    fn v1_positions_json(&self, key: &[u8; 32]) -> Option<serde_json::Value> {
        let a = self.accounts.get(key)?;
        Some(serde_json::json!({ "positions": self.positions_json_of(&a.wallet.owner) }))
    }
    fn v1_markets_json(&self) -> serde_json::Value {
        let ms: Vec<_> = self.mkts.iter().map(|m| serde_json::to_value(self.wmarket(m)).unwrap()).collect();
        serde_json::json!({ "markets": ms })
    }
    fn v1_orderbook_json(&self, market: u64) -> Option<serde_json::Value> {
        let m = self.mkt(market)?;
        Some(serde_json::to_value(self.book_around(market, m.px)).unwrap())
    }
    fn v1_oracle_json(&self, market: u64) -> Option<serde_json::Value> {
        let m = self.mkt(market)?;
        Some(serde_json::json!({
            "marketId": market,
            "price": m.px.to_string(),
            "confidence": (m.px / 1000).max(1).to_string(),
            "publishTimeMs": now_ms(),
        }))
    }
    fn v1_status_json(&self) -> serde_json::Value {
        serde_json::json!({
            "mode": if self.seq.state.mode == Mode::CloseOnly { "CloseOnly" } else { "Normal" },
            "insuranceFund": self.seq.state.insurance_fund.to_string(),
            "nextBatchId": self.seq.current_batch_id(),
            "accounts": self.accounts.len(),
        })
    }
    /// A public live-market snapshot for the `/v1/ws` stream (no per-account data).
    fn v1_public_json(&self) -> serde_json::Value {
        let markets: Vec<_> = self
            .mkts
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id,
                    "symbol": m.symbol,
                    "price": m.px.to_string(),
                    "book": serde_json::to_value(self.book_around(m.id, m.px)).unwrap(),
                })
            })
            .collect();
        serde_json::json!({ "type": "markets", "markets": markets, "tsMs": now_ms() })
    }

    /// The engine's live state root as 0x-hex — what the L1 bridge settles to.
    fn state_root_hex(&self) -> String {
        hex32(&self.seq.state.state_root())
    }
    /// The most recently sealed batch's manifest hash as 0x-hex.
    fn last_manifest_hex(&self) -> String {
        hex32(&self.last_manifest)
    }

    /// Sum the collateral the USER had auto-deleveraged in `sealed`, recognized by
    /// recomputing the user's own secret ADL tag per market (audit Q2). An observer
    /// without the user's spend key can't do this — privacy holds.
    fn user_adl_in(&self, sealed: &SealedBatch) -> i128 {
        let key = adl_tag_key(&self.user.spend_key);
        let mut clawed = 0i128;
        for m in &self.mkts {
            let tag = adl_tag(&key, m.id, sealed.batch_id);
            for r in &sealed.adl_receipts {
                if r.tag == tag {
                    clawed += r.clawed;
                }
            }
        }
        clawed
    }

    /// Demo: engineer a bad-debt liquidation whose shortfall outruns the insurance
    /// fund, so the auto-deleverage cascade claws the USER (a winner) — then return
    /// what the user lost. Shows Q2 transparency end-to-end: the socialized haircut
    /// is recorded as a receipt the user detects, not silent. Self-contained; the
    /// transient oracle spike is restored afterward.
    fn simulate_adl(&mut self) -> Result<i128, String> {
        let market = 0u64;
        let now = now_ms();
        let px = self.px_of(market);
        if px <= 0 {
            return Err("no market price".into());
        }
        // Per-call salt so repeated triggers never collide on a note commitment.
        let n = self.seq.current_batch_id();
        let bn = n as u8;
        // 1. Make the user a clear winner: ensure margin for a 1 BTC long, then open.
        let user = self.user;
        if self.market_free(market) < required_margin(SIZE_SCALE, px) {
            fund(&mut self.seq, &mut self.archive, &user, market, 30_000, 0x71u8.wrapping_add(bn));
        }
        // 2. An under-funded victim shorts the other side — bound to go bad-debt. A
        //    fresh victim per call (owner derived from the batch id) avoids reuse.
        let mut vseed = [0x9Au8; 32];
        vseed[..8].copy_from_slice(&n.to_le_bytes());
        let victim = Wallet::from_seed(vseed);
        let victim_margin_usd = required_margin(SIZE_SCALE, px) / QUOTE_SCALE + 1;
        fund(
            &mut self.seq,
            &mut self.archive,
            &victim,
            market,
            victim_margin_usd,
            0x9Au8.wrapping_add(bn),
        );
        let oracle = oracle_of(px, now);
        self.seq
            .apply(&BatchOp::Fill {
                taker: user.owner,
                maker: victim.owner,
                market_id: market,
                taker_side: Side::Buy,
                size: SIZE_SCALE,
                price: px,
                oracle,
                now_ms: now,
            })
            .map_err(|e| format!("fill failed: {e:?}"))?;
        // 3. Gap the oracle up so the victim's loss exceeds its margin AND the
        //    insurance fund, leaving a residual the cascade must claw from winners.
        //    Sized so the residual (~$2k) is well under the user's clawable margin,
        //    so it never trips the system into close-only.
        let residual_target = 2_000 * QUOTE_SCALE;
        let loss_quote = self.seq.state.insurance_fund.max(0)
            + residual_target
            + victim_margin_usd * QUOTE_SCALE;
        let gap_px = px + (loss_quote / QUOTE_SCALE) * PRICE_SCALE;
        self.seq.set_oracle(market, oracle_of(gap_px, now));
        let sealed = self.seq.seal_batch(&[], now);
        // 4. restore the oracle so the spike is transient; the haircut is permanent.
        self.seq.set_oracle(market, oracle_of(px, now));
        // 5. replenish the insurance fund to its baseline so the backstop is shown
        //    full again and the demo is repeatable (the draw-down happened within
        //    the cascade seal above; the user's haircut below is what persists).
        let target = INSURANCE_SEED_USD * QUOTE_SCALE;
        let now_ins = self.seq.state.insurance_fund;
        if now_ins < target {
            let _ = self.seq.apply(&BatchOp::SeedInsurance {
                amount: target - now_ins,
            });
        }
        let clawed = self.user_adl_in(&sealed);
        if clawed <= 0 {
            return Err("the cascade did not claw the user this run".into());
        }
        self.user_adl_clawed += clawed;
        Ok(clawed)
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

        // 2) seal a batch: pending demo-user orders + all registered accounts'
        //    pending orders. Ioc/Fok orders are takers and get a resting MM counter
        //    (guaranteed fill); Gtc/PostOnly orders rest in the matcher book so a
        //    market-maker bot can quote and be crossed by later takers.
        let pending: Vec<usize> =
            self.orders.iter().enumerate().filter(|(_, o)| !o.sealed).map(|(i, _)| i).collect();
        let mut seal: Vec<Order> = Vec::new();
        for &i in &pending {
            let o = &self.orders[i];
            let opp = match o.order.side {
                Side::Buy => Side::Sell,
                Side::Sell => Side::Buy,
            };
            let price = if o.order.limit_price > 0 { o.order.limit_price } else { self.px_of(o.order.market_id) };
            let mut uo = o.order;
            uo.limit_price = price;
            let mmn = self.mm_nonce;
            self.mm_nonce += 1;
            seal.push(mk_order(self.mm.owner, o.order.market_id, opp, o.order.size, price, mmn, TimeInForce::Gtc));
            seal.push(uo);
        }
        // registered /v1 accounts
        let account_keys: Vec<[u8; 32]> = self.accounts.keys().copied().collect();
        let mut account_refs: Vec<([u8; 32], usize)> = Vec::new();
        for k in &account_keys {
            let pend: Vec<usize> = self.accounts[k]
                .orders
                .iter()
                .enumerate()
                .filter(|(_, o)| !o.sealed)
                .map(|(i, _)| i)
                .collect();
            for i in pend {
                let mut uo = self.accounts[k].orders[i].order; // Order: Copy
                let price = if uo.limit_price > 0 { uo.limit_price } else { self.px_of(uo.market_id) };
                uo.limit_price = price;
                if matches!(uo.tif, TimeInForce::Ioc | TimeInForce::Fok) {
                    let opp = match uo.side {
                        Side::Buy => Side::Sell,
                        Side::Sell => Side::Buy,
                    };
                    let mmn = self.mm_nonce;
                    self.mm_nonce += 1;
                    seal.push(mk_order(self.mm.owner, uo.market_id, opp, uo.size, price, mmn, TimeInForce::Gtc));
                }
                seal.push(uo);
                account_refs.push((*k, i));
            }
        }
        let sealed = self.seq.seal_batch(&seal, now);
        self.last_manifest = sealed.manifest_hash;
        // recognize any auto-deleverage haircut that hit the user this batch (Q2)
        let adl_clawed = self.user_adl_in(&sealed);
        if adl_clawed > 0 {
            self.user_adl_clawed += adl_clawed;
        }
        let any_sealed = !pending.is_empty() || !account_refs.is_empty();
        for &i in &pending {
            self.orders[i].sealed = true;
            self.orders[i].filled = self.orders[i].order.size;
            self.orders[i].avg_fill = if self.orders[i].order.limit_price > 0 {
                self.orders[i].order.limit_price
            } else {
                self.px_of(self.orders[i].order.market_id)
            };
        }
        // account orders are submitted; their fill status is read from finality below
        for (k, i) in &account_refs {
            if let Some(a) = self.accounts.get_mut(k) {
                a.orders[*i].sealed = true;
            }
        }
        if any_sealed {
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
        // advance /v1 account orders' finality (no demo toast; surfaced via REST/WS)
        for acct in self.accounts.values_mut() {
            for o in acct.orders.iter_mut() {
                if o.last_finality == "SETTLED" {
                    continue;
                }
                let f = match self.seq.finality_of(&o.order_hash) {
                    Some(Finality::Matched) => "MATCHED",
                    Some(Finality::Settled) => "SETTLED",
                    _ => "ACCEPTED",
                };
                if f != o.last_finality {
                    o.last_finality = f.to_string();
                    if f != "ACCEPTED" {
                        o.filled = o.order.size;
                        o.avg_fill = o.order.limit_price;
                    }
                }
            }
        }
        if adl_clawed > 0 {
            events.push(WEvent {
                order_id: format!("adl-{}", sealed.batch_id),
                kind: "ADL".into(),
                message: format!(
                    "Auto-deleveraged: ${} of your winning position was clawed to cover a counterparty's bad debt (audit Q2).",
                    adl_clawed / QUOTE_SCALE
                ),
            });
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

        // the market-maker's per-market net inventory + delta-neutral hedge target
        // (audit Q5) — only markets where the MM actually carries exposure.
        let mm_hedge: Vec<WHedge> = self
            .mkts
            .iter()
            .filter_map(|m| {
                let p = self.seq.state.position(&self.mm.owner, m.id)?;
                if p.size == 0 {
                    return None;
                }
                let h = p.hedge_signal(m.px);
                Some(WHedge {
                    market_id: m.id,
                    symbol: m.symbol.to_string(),
                    inventory: h.inventory.to_string(),
                    hedge_target: h.hedge_target.to_string(),
                    notional: h.notional.to_string(),
                })
            })
            .collect();

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
            user_adl_clawed: self.user_adl_clawed.to_string(),
            mm_hedge,
            l1: self.l1_status.as_ref().map(|s| WL1 {
                settled_root: s.settled_root.clone(),
                batch_count: s.batch_count,
                last_tx: s.last_tx.clone(),
                bond_wei: s.bond_wei.clone(),
            }),
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

// ── multi-tenant external API (/v1) ──────────────────────────────────────────
#[derive(Deserialize)]
struct V1DepositReq {
    #[serde(rename = "marketId")]
    market_id: u64,
    amount: String,
}

/// Authenticate a `/v1` request: read `X-Api-Key` (0x + 64 hex) → 32-byte key.
fn api_key_from(headers: &HeaderMap) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
    let unauth = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid X-Api-Key" })),
        )
    };
    let h = headers.get("x-api-key").and_then(|v| v.to_str().ok()).ok_or_else(unauth)?;
    let h = h.strip_prefix("0x").unwrap_or(h);
    if h.len() != 64 {
        return Err(unauth());
    }
    let mut k = [0u8; 32];
    for (i, slot) in k.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|_| unauth())?;
    }
    Ok(k)
}

async fn post_v1_register(State(app): State<Shared>) -> impl IntoResponse {
    let (key, owner) = { app.gw.lock().await.register_account() };
    Json(serde_json::json!({ "apiKey": hex0x(&key), "owner": hex0x(&owner) }))
}
async fn get_v1_account(State(app): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    match app.gw.lock().await.v1_account(&key) {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "unknown account" }))).into_response(),
    }
}
async fn post_v1_deposit(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<V1DepositReq>,
) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let amount: i128 = match req.amount.parse() {
        Ok(v) => v,
        Err(_) => return err400("bad amount".into()).into_response(),
    };
    let r = { app.gw.lock().await.account_deposit(&key, req.market_id, amount) };
    match r {
        Ok(()) => Json(app.gw.lock().await.v1_account(&key).unwrap_or(serde_json::json!({}))).into_response(),
        Err(e) => err400(e).into_response(),
    }
}
async fn post_v1_order(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<OrderReq>,
) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let r = { app.gw.lock().await.account_place_order(&key, &req) };
    match r {
        Ok(receipt) => Json(serde_json::to_value(receipt).unwrap()).into_response(),
        Err(e) => err400(e).into_response(),
    }
}
async fn delete_v1_order(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(order_id): Path<String>,
) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let r = { app.gw.lock().await.account_cancel(&key, &order_id) };
    match r {
        Ok(()) => Json(serde_json::json!({ "orderId": order_id, "cancelled": true })).into_response(),
        Err(e) => err400(e).into_response(),
    }
}
async fn get_v1_orders(State(app): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    match app.gw.lock().await.v1_orders_json(&key) {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "unknown account" }))).into_response(),
    }
}
async fn get_v1_positions(State(app): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    match app.gw.lock().await.v1_positions_json(&key) {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "unknown account" }))).into_response(),
    }
}
async fn get_v1_markets(State(app): State<Shared>) -> impl IntoResponse {
    Json(app.gw.lock().await.v1_markets_json())
}
async fn get_v1_market(State(app): State<Shared>, Path(id): Path<u64>) -> impl IntoResponse {
    let gw = app.gw.lock().await;
    match gw.mkt(id) {
        Some(m) => Json(serde_json::to_value(gw.wmarket(m)).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "unknown market" }))).into_response(),
    }
}
async fn get_v1_orderbook(State(app): State<Shared>, Path(id): Path<u64>) -> impl IntoResponse {
    match app.gw.lock().await.v1_orderbook_json(id) {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "unknown market" }))).into_response(),
    }
}
async fn get_v1_oracle(State(app): State<Shared>, Path(id): Path<u64>) -> impl IntoResponse {
    match app.gw.lock().await.v1_oracle_json(id) {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "unknown market" }))).into_response(),
    }
}
async fn get_v1_status(State(app): State<Shared>) -> impl IntoResponse {
    Json(app.gw.lock().await.v1_status_json())
}
async fn ws_v1_handler(State(app): State<Shared>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_v1_loop(socket, app))
}
/// Public live-market WebSocket: pushes the market snapshot every tick. Per-account
/// authenticated channels (own fills/finality) are a documented follow-on.
async fn ws_v1_loop(mut socket: WebSocket, app: Shared) {
    let mut rx = app.tx.subscribe();
    let initial = { serde_json::to_string(&app.gw.lock().await.v1_public_json()).unwrap() };
    if socket.send(Message::Text(initial)).await.is_err() {
        return;
    }
    while rx.recv().await.is_ok() {
        let msg = { serde_json::to_string(&app.gw.lock().await.v1_public_json()).unwrap() };
        if socket.send(Message::Text(msg)).await.is_err() {
            break;
        }
    }
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

/// Demo trigger: run a bad-debt cascade that auto-deleverages the user, then push
/// the resulting ADL receipt + refreshed state (audit Q2).
async fn post_simulate_adl(State(app): State<Shared>) -> impl IntoResponse {
    let res = {
        let mut gw = app.gw.lock().await;
        gw.simulate_adl()
    };
    match res {
        Ok(clawed) => {
            let gw = app.gw.lock().await;
            app.broadcast(&gw).await;
            app.broadcast_event(WEvent {
                order_id: "adl-sim".into(),
                kind: "ADL".into(),
                message: format!(
                    "Auto-deleveraged: ${} of your winning position was clawed to cover a counterparty's bad debt (audit Q2).",
                    clawed / QUOTE_SCALE
                ),
            })
            .await;
            Json(serde_json::json!({ "clawed": (clawed / QUOTE_SCALE).to_string() })).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
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

    // optional L1 settlement bridge: post bond once, then advance the on-chain
    // root to mirror the engine root on a slow timer (Base Sepolia).
    if let Some(l1) = L1::from_env() {
        println!("[l1] bridge ON → settlement {} every {L1_SETTLE_SECS}s", l1.settlement);
        let app = app.clone();
        tokio::spawn(async move {
            {
                let l1b = l1.clone();
                match tokio::task::spawn_blocking(move || {
                    if l1b.sequencer_bond().unwrap_or(0) == 0 {
                        l1b.post_bond(L1_BOND_WEI)
                    } else {
                        Ok("already bonded".into())
                    }
                })
                .await
                {
                    Ok(Ok(tx)) => println!("[l1] bond: {tx}"),
                    Ok(Err(e)) => eprintln!("[l1] bond failed: {e}"),
                    Err(e) => eprintln!("[l1] bond join: {e}"),
                }
            }
            // start the first settle one period out, so it never races the bond's
            // confirmation (tokio's plain `interval` would fire immediately).
            let mut iv = tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::from_secs(L1_SETTLE_SECS),
                Duration::from_secs(L1_SETTLE_SECS),
            );
            loop {
                iv.tick().await;
                let (new_root, manifest) = {
                    let gw = app.gw.lock().await;
                    (gw.state_root_hex(), gw.last_manifest_hex())
                };
                let l1c = l1.clone();
                let res = tokio::task::spawn_blocking(move || {
                    let prev = l1c.current_root()?;
                    if prev.eq_ignore_ascii_case(&new_root) {
                        return Ok::<Option<L1Status>, String>(None);
                    }
                    let tx = l1c.settle(&prev, &manifest, &new_root)?;
                    Ok(Some(L1Status {
                        settled_root: new_root,
                        batch_count: l1c.batch_count().unwrap_or(0),
                        last_tx: tx,
                        bond_wei: l1c.sequencer_bond().unwrap_or(0).to_string(),
                    }))
                })
                .await;
                match res {
                    Ok(Ok(Some(status))) => {
                        println!(
                            "[l1] settled root {} batch {} tx {}",
                            status.settled_root, status.batch_count, status.last_tx
                        );
                        {
                            app.gw.lock().await.l1_status = Some(status);
                        }
                        let snap = { app.gw.lock().await.snapshot() };
                        let _ = app.tx.send(
                            serde_json::to_string(&WsMsg::State { state: snap }).unwrap(),
                        );
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(e)) => eprintln!("[l1] settle failed: {e}"),
                    Err(e) => eprintln!("[l1] settle join: {e}"),
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
        .route("/api/simulate-adl", post(post_simulate_adl))
        .route("/api/select-market", post(post_select))
        .route("/api/recover", post(post_recover))
        .route("/ws", get(ws_handler))
        // ── multi-tenant external API (/v1) ──
        .route("/v1/accounts", post(post_v1_register))
        .route("/v1/accounts/me", get(get_v1_account))
        .route("/v1/accounts/deposit", post(post_v1_deposit))
        .route("/v1/orders", post(post_v1_order).get(get_v1_orders))
        .route("/v1/orders/:order_id", delete(delete_v1_order))
        .route("/v1/positions", get(get_v1_positions))
        .route("/v1/markets", get(get_v1_markets))
        .route("/v1/markets/:id", get(get_v1_market))
        .route("/v1/markets/:id/orderbook", get(get_v1_orderbook))
        .route("/v1/markets/:id/oracle", get(get_v1_oracle))
        .route("/v1/system/status", get(get_v1_status))
        .route("/v1/ws", get(ws_v1_handler))
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

    #[test]
    fn v1_accounts_are_isolated_and_trade() {
        let mut gw = Gw::boot();
        let (a_key, a_owner) = gw.register_account();
        let (b_key, b_owner) = gw.register_account();
        assert_ne!(a_key, b_key, "distinct api keys");
        assert_ne!(a_owner, b_owner, "distinct owners");
        // A deposits $20k into market 0 and goes long 0.1 BTC
        gw.account_deposit(&a_key, 0, 20_000 * QUOTE_SCALE).expect("deposit");
        let req = OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
        };
        gw.account_place_order(&a_key, &req).expect("order");
        gw.tick();
        // A is long; B has nothing — full isolation over the shared engine
        let a_pos = gw.seq.state.position(&a_owner, 0).expect("A position");
        assert!(a_pos.size > 0, "A is long after the seal");
        assert!(gw.seq.state.position(&b_owner, 0).is_none(), "B has no position");
        let a_orders = gw.v1_orders_json(&a_key).unwrap();
        assert_eq!(a_orders["orders"].as_array().unwrap().len(), 1);
        let b_orders = gw.v1_orders_json(&b_key).unwrap();
        assert!(b_orders["orders"].as_array().unwrap().is_empty(), "B has no orders");
        // an unknown key has no view
        assert!(gw.v1_account(&[0xff; 32]).is_none());
    }
}
