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
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{ConnectInfo, Path, State},
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
use perp_core::hash::{Digest, Domain, Keccak256};
use perp_core::market::Market;
use perp_core::note::{Note, PubKey};
use perp_core::oracle::OracleTranscript;
use perp_core::order::{Finality, Order, Side, TimeInForce};
use perp_core::state::Mode;
use sequencer::{adl_tag, adl_tag_key, EnclaveIdentity, SealedBatch, Sequencer, WindowWitness};

mod candles;
mod enclave_epoch;
mod l1;
mod order_log;
mod prover_client;
mod rollback_journal;
mod snapshot;
mod withdrawals;
use l1::{L1Status, L1};
use withdrawals::{inclusion_leaf, merkle_proof, merkle_root, rejection_leaf, Withdrawal};

/// 0x-prefixed lowercase hex of a 32-byte digest (for L1 calldata + display).
fn hex32(d: &Digest) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// What to do with a sealed-but-settle-failed window, given the on-chain batchCount
/// re-read AFTER the failure. `seal_window` bumped the local per-window counter to
/// `sealed_batch_id + 1`, so `chain_batch_count == sealed_batch_id` means the tx never
/// landed (undo the seal), `== sealed_batch_id + 1` means it landed despite the cast
/// error (commit the bookkeeping), and anything else is unexpected (hold, let the
/// operator reconcile — a rollback there could strand the sequencer either way).
#[derive(Debug, PartialEq, Eq)]
enum RollAction {
    RollBack,
    RollForward,
    Hold,
}

fn settle_failure_action(sealed_batch_id: u64, chain_batch_count: u64) -> RollAction {
    if chain_batch_count == sealed_batch_id {
        RollAction::RollBack
    } else if chain_batch_count == sealed_batch_id + 1 {
        RollAction::RollForward
    } else {
        RollAction::Hold
    }
}

/// Fix round 2 (final-review TOCTOU): whether the boot-recovery chain read must
/// be CONFIRMED by a delayed second read before feeding the recovery decision.
///
/// The settle loop journals `prepared` (stage 2) strictly BEFORE the tx
/// broadcast, so `has_prepared == false` PROVES no tx was ever sent — the first
/// read is authoritative and RollBack is immediately safe. With `prepared`
/// present, a first read of `batch_count == j.batch_id` is ambiguous: the crash
/// may sit in the ~2-4 s window between the broadcast and its mining, and a
/// RollBack decided on that stale read rewinds Counter B and deletes the journal
/// (the only `prepared` copy) right before the tx lands — chain J+1 vs local J,
/// the unreconcilable wedge this recovery exists to kill. Any other first read
/// already disambiguates (landed → RollForward row, weirder → Hold), so no wait.
fn needs_confirm_delay(has_prepared: bool, first_bc: u64, j_batch: u64) -> bool {
    has_prepared && first_bc == j_batch
}

/// How long the boot-recovery block waits before the confirming re-read when
/// `needs_confirm_delay` fires — comfortably past Base Sepolia's ~2 s blocks and
/// the observed 2-4 s propagation window, cheap enough for a boot path.
const RECOVERY_CONFIRM_DELAY_SECS: u64 = 15;

/// Task 3 (crash recovery): what `apply_boot_recovery` decided about the journal
/// FILE. The function itself only mutates the `Gw` — it is pure of file I/O, so
/// the boot call site (and the tests, which have no journal file) own the delete.
#[derive(Debug, PartialEq, Eq)]
enum BootRecoveryOutcome {
    /// The journaled window is resolved (stale, never persisted, rolled back, or
    /// rolled forward) — the caller deletes the journal. `mutated` says whether
    /// the resolution CHANGED the `Gw` (RollBack / RollForward): those exist only
    /// in memory until a snapshot write, so the caller must persist the
    /// post-recovery snapshot BEFORE the delete (`finish_boot_recovery`) — a hard
    /// crash in the gap would otherwise restore the PRE-recovery snapshot with no
    /// journal left to re-resolve it. Non-mutating rows (Stale /
    /// SealNeverPersisted) resolve to the state already on disk, so they delete
    /// without a write.
    DeleteJournal { mutated: bool },
    /// HOLD: keep the journal for the operator / a later boot. The boot
    /// continuity check remains the final arbiter of whether startup proceeds.
    KeepJournal,
}

/// Task 3 (crash recovery): resolve a journaled in-flight window settle against
/// the restored snapshot and the chain, per the spec's boot-recovery table. The
/// pure decision is `rollback_journal::recovery_action`; this applies it to the
/// `Gw` (rollback: rewind Counter B + re-inject the drained withdrawals;
/// roll-forward: re-commit the bookkeeping from the journal's `prepared`).
/// Every HOLD prints a line containing "HOLDING" — the ops health alert greps
/// for that substring.
fn apply_boot_recovery(
    gw: &mut Gw,
    j: rollback_journal::RollbackJournal,
    chain_bc: u64,
    chain_root: &str,
    bond: u128,
) -> BootRecoveryOutcome {
    use rollback_journal::RecoveryAction;
    let b_snap = gw.seq.state.next_batch_id;
    // Root comparisons are case-insensitive (cast hex casing), like the boot
    // continuity check.
    let root_matches_prepared = j
        .prepared
        .as_ref()
        .is_some_and(|p| chain_root.eq_ignore_ascii_case(&hex32(&p.outcome.new_root)));
    let root_matches_settled = gw
        .l1_status
        .as_ref()
        .is_some_and(|st| chain_root.eq_ignore_ascii_case(&st.settled_root));
    match rollback_journal::recovery_action(
        j.batch_id,
        j.prepared.is_some(),
        b_snap,
        chain_bc,
        root_matches_prepared,
        root_matches_settled,
    ) {
        RecoveryAction::Stale => {
            println!(
                "[recovery] rollback journal for window {} is stale (its commit was already \
                 persisted) — resolved, nothing to do",
                j.batch_id
            );
            BootRecoveryOutcome::DeleteJournal { mutated: false }
        }
        RecoveryAction::SealNeverPersisted => {
            println!(
                "[recovery] rollback journal for window {}: pre-seal snapshot restored and the \
                 tx never landed — the seal effectively never happened; resolved, nothing to do",
                j.batch_id
            );
            BootRecoveryOutcome::DeleteJournal { mutated: false }
        }
        RecoveryAction::RollBack => {
            gw.seq.rollback_window(&j.witness);
            gw.rollback_window_withdrawals(j.ww);
            println!(
                "[recovery] rolled back window {} at boot (seal persisted, tx never landed) — \
                 the next settle re-seals it under the same batch id",
                j.batch_id
            );
            BootRecoveryOutcome::DeleteJournal { mutated: true }
        }
        RecoveryAction::RollForward => {
            // `recovery_action` returns RollForward only when `has_prepared`, so this
            // is unreachable — but a boot path must never panic: fall back to HOLD.
            let Some(prepared) = j.prepared else {
                eprintln!(
                    "[recovery] HOLDING: roll-forward decision without a prepared outcome for \
                     window {} — keeping the journal; operator must reconcile",
                    j.batch_id
                );
                return BootRecoveryOutcome::KeepJournal;
            };
            let ordered = j.witness.manifest.ordered.clone();
            let rejected: Vec<Digest> =
                j.witness.manifest.rejected.iter().map(|(h, _)| *h).collect();
            let status = L1Status {
                settled_root: hex32(&prepared.outcome.new_root),
                batch_count: j.batch_id + 1,
                last_tx: "(recovered at boot)".into(),
                bond: bond.to_string(),
                withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
            };
            gw.commit_window_settle(j.batch_id, ordered, rejected, prepared, status);
            println!(
                "[recovery] rolled forward window {} at boot (tx landed, commit lost) — \
                 bookkeeping re-committed from the journal",
                j.batch_id
            );
            BootRecoveryOutcome::DeleteJournal { mutated: true }
        }
        RecoveryAction::Hold => {
            eprintln!(
                "[recovery] HOLDING: rollback journal window {} matches no recovery row \
                 (snapshot Counter B {b_snap}, chain batchCount {chain_bc}, chain root \
                 {chain_root}) — keeping the journal; operator must reconcile (the continuity \
                 check decides whether boot proceeds)",
                j.batch_id
            );
            BootRecoveryOutcome::KeepJournal
        }
    }
}

/// Task 3 fix (review): synchronously persist the post-recovery snapshot — the
/// persistence block's exact three calls (`snapshot_plain` → `seal` →
/// `write_atomic`). At this point in boot the snapshot writer task is not spawned
/// yet, so the snapshot file still has exactly one writer (this call); there is
/// no `.tmp`-rename race to worry about.
fn persist_recovery(gw: &Gw, path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    let plain = gw.snapshot_plain();
    let sealed = snapshot::seal(&plain, seed);
    snapshot::write_atomic(path, &sealed).map_err(|e| format!("snapshot write: {e}"))
}

/// Task 3 fix (review): the post-`apply_boot_recovery` call-site glue, extracted
/// so the ordering is testable. A MUTATING resolution (RollBack / RollForward)
/// exists only in memory here, and the first periodic durability is ~SNAPSHOT_SECS
/// away (the writer task — spawned later — skips its first tick), so it must hit
/// disk BEFORE the journal (the only other copy of the rollback inputs) is
/// deleted. A hard crash in that gap would otherwise restore the PRE-recovery
/// snapshot with NO journal: the rollback case leaves Counter B at J+1 and the
/// settle desync guard skips settles forever (the exact wedge this recovery
/// exists to kill); the roll-forward case leaves a stale settled_root with
/// `prepared` gone, and the continuity check refuses to start. If the persist
/// FAILS, keep the journal — it is still the recovery source, and the next boot
/// re-resolves the same row idempotently (the on-disk snapshot is unchanged, so
/// the recovery table reads identically). Non-mutating resolutions (Stale /
/// SealNeverPersisted) delete without a write — they resolve to the state
/// already on disk (proven safe in the review's crash walk).
fn finish_boot_recovery(
    gw: &Gw,
    mutated: bool,
    state_path: &std::path::Path,
    journal_path: &std::path::Path,
    seed: &[u8; 32],
) {
    if mutated {
        if let Err(e) = persist_recovery(gw, state_path, seed) {
            eprintln!(
                "[recovery] HOLDING: window recovery applied in memory but the post-recovery \
                 snapshot could not be persisted ({e}) — keeping the rollback journal {} as \
                 the recovery source (the next boot re-resolves it); fix the snapshot path",
                journal_path.display()
            );
            return;
        }
    }
    rollback_journal::delete(journal_path);
}

// ── constants ────────────────────────────────────────────────────────────────
const IMR_BP: i128 = 1_000; // initial-margin 10% in basis points (matches Market::conservative)
const MMR_BP: i128 = 500; // maintenance 5%
const SETTLE_TICKS: u64 = 5; // ticks a batch waits (MATCHED) before mark_settled (SETTLED)
const USER_FUND_PER_MARKET: i128 = 5_000; // USD → $15k across 3 markets (≈ mock's settledBalance)
const MM_FUND_PER_MARKET: i128 = 6_000_000; // USD; the LP pool's seed (×3 markets = $18M)
const TICK_MS: u64 = 700;
// Trading economics (audit Q4): every fill charges the taker a fee, rebates the
// resting maker, and routes the remainder into the insurance fund (audit Q3).
const TAKER_FEE_BPS: i128 = 10; // 0.10% taker fee
const MAKER_REBATE_BPS: i128 = 0; // no maker rebate — the LP pool earns the house edge, not fees
const TREASURY_FEE_BPS: i128 = 8; // 0.08% → protocol treasury (operator revenue); 0.02% → insurance
const INSURANCE_SEED_USD: i128 = 25_000; // visible starting backstop; grows with volume
const L1_SETTLE_SECS: u64 = 30; // how often the L1 bridge advances the on-chain root
const V1_ORDER_RATE: u32 = 10; // max orders/sec per external account
const V1_REGISTER_RATE: u32 = 30; // max account registrations/min per IP
const SNAPSHOT_SECS: u64 = 30; // sealed state-snapshot cadence (DARKPERP_STATE)
/// Cap on retained per-account order history. SETTLED orders are terminal display data;
/// without a bound the Vec (and every snapshot) grows forever on a long-lived deployment.
const MAX_ACCOUNT_ORDER_HISTORY: usize = 500;

/// Evict up to `len - max` of the OLDEST terminal entries (front-first) so a Vec stays
/// bounded, never dropping a non-terminal (live/in-flight) entry. Generic over the
/// "is terminal" predicate so the eviction rule is unit-testable without heavy fixtures.
fn cap_history<T>(items: &mut Vec<T>, max: usize, is_terminal: impl Fn(&T) -> bool) {
    if items.len() <= max {
        return;
    }
    let mut excess = items.len() - max;
    items.retain(|it| {
        if excess > 0 && is_terminal(it) {
            excess -= 1;
            false
        } else {
            true
        }
    });
}

struct MarketCfg {
    id: u64,
    symbol: &'static str,
    seed: f64,
    /// Crypto.com instrument for a LIVE price feed (oracle-feed); `None` ⇒ sim walk.
    feed: Option<&'static str>,
}
const MARKETS: &[MarketCfg] = &[
    MarketCfg {
        id: 0,
        symbol: "BTC/USDC",
        seed: 59_575.14,
        feed: Some("BTC_USDT"),
    },
    MarketCfg {
        id: 1,
        symbol: "ETH/USDC",
        seed: 1_570.61,
        feed: Some("ETH_USDT"),
    },
    MarketCfg {
        id: 2,
        symbol: "SOL/USDC",
        seed: 66.44,
        feed: Some("SOL_USDT"),
    },
    // HYPE/USDC and LIT/USDC were removed 2026-07-05: they had no real oracle feed
    // (`feed: None` ⇒ sim walk only), so they don't belong on a testnet meant to mirror
    // real settlement. They'll be listed on mainnet once a genuine oracle source exists.
];

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
/// 32 cryptographically secure random bytes (API keys + wallet seeds) from the OS
/// CSPRNG — never the demo's predictable xorshift walk.
fn csprng_bytes32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS CSPRNG");
    b
}

/// A verified TEE attestation the gateway boots its enclave identity from.
#[derive(Clone)]
struct Attested {
    measurement: Digest,
    tcb: String,
    quote_version: u16,
}

/// Verify a real Azure TDX + vTPM attestation and derive the enclave measurement,
/// if `ATTESTATION_DIR` points at the captured artifacts (or a live VM's). Returns
/// `None` (→ stub enclave) when unset or verification fails. On a real confidential
/// VM, point `ATTESTATION_DIR` at the live quote; locally, at the captured fixtures
/// (`crates/attestation/tests/fixtures/azure`) with `ATTESTATION_NOW` at capture time.
fn attest_from_env() -> Option<Attested> {
    use dark_perp_attestation::vtpm::{azure_app_measurement, verify_azure_vtpm};
    use dark_perp_attestation::{verify_tdx_quote, Collateral};

    let dir = std::env::var("ATTESTATION_DIR").ok()?;
    let path = |f: &str| std::path::Path::new(&dir).join(f);
    let quote = std::fs::read(path("quote.bin")).ok()?;
    let collateral_json = std::fs::read(path("collateral.json")).ok()?;
    let hcl = std::fs::read(path("hcl_report.bin")).ok()?;
    let ak_msg = std::fs::read(path("ak_quote_msg.bin")).ok()?;
    let ak_sig = std::fs::read(path("ak_quote_sig.bin")).ok()?;
    let pcrs_txt = std::fs::read_to_string(path("pcrs.txt")).ok()?;

    // parse PCR lines "    N : 0x<64 hex>" into index→value, then take the quoted
    // measured-boot set (PCRs 0..=16, what the AK quote covers) in order.
    let mut by_idx: std::collections::BTreeMap<u32, [u8; 32]> = std::collections::BTreeMap::new();
    for line in pcrs_txt.lines() {
        let Some(pos) = line.find("0x") else { continue };
        // index token is "N" (single digit, " : ") or "N:" (double digit, "N:")
        let Some(idx) = line
            .split_whitespace()
            .next()
            .and_then(|t| t.trim_end_matches(':').parse::<u32>().ok())
        else {
            continue;
        };
        // Byte-safe nibble parse (same posture as `decode_hex`): a non-ASCII byte
        // in the PCR file yields a skipped line, not a mid-codepoint slice panic.
        let hex = line[pos + 2..].trim().as_bytes();
        if hex.len() < 64 {
            continue;
        }
        let mut a = [0u8; 32];
        let mut ok = true;
        for (i, slot) in a.iter_mut().enumerate() {
            match (hex_nibble(hex[i * 2]), hex_nibble(hex[i * 2 + 1])) {
                (Some(hi), Some(lo)) => *slot = hi << 4 | lo,
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            by_idx.insert(idx, a);
        }
    }
    let pcrs: Vec<[u8; 32]> = (0..17).filter_map(|i| by_idx.get(&i).copied()).collect();

    let now = std::env::var("ATTESTATION_NOW")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| now_ms() / 1000);
    let run = || -> Result<Attested, String> {
        let collateral =
            Collateral::from_json(&collateral_json).map_err(|e| format!("collateral: {e:?}"))?;
        let td =
            verify_tdx_quote(&quote, &collateral, now).map_err(|e| format!("tdx quote: {e:?}"))?;
        let report = verify_azure_vtpm(&td, &hcl, &ak_msg, &ak_sig, &pcrs)
            .map_err(|e| format!("vtpm chain: {e:?}"))?;
        Ok(Attested {
            measurement: azure_app_measurement(&td, &report).map_err(|e| format!("{e:?}"))?,
            tcb: format!("{:?}", td.tcb_status),
            quote_version: td.quote_version,
        })
    };
    match run() {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("[attest] ATTESTATION_DIR set but verification failed: {e}");
            None
        }
    }
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
/// The LP pool (the MM-as-counterparty) — public stats + the demo user's own stake.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WLp {
    tvl: String,
    nav_per_share: String,
    total_shares: String,
    my_shares: String,
    my_value: String,
}
/// The last on-chain L1 settlement the bridge published (audit/§3) — present only
/// when the gateway runs with the L1 bridge configured.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WL1 {
    settled_root: String,
    batch_count: u64,
    last_tx: String,
    /// Sequencer bond in USDC base units (USDC-denominated, audit Q1).
    bond_usdc: String,
    /// Cumulative withdrawals root last published to the vault (users claim against it).
    withdrawals_root: String,
}
/// The verified TEE attestation the enclave is bound to — present only when the
/// gateway boots with a real Azure TDX + vTPM attestation (else null = stub).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WAttestation {
    measurement: String,
    tcb: String,
    quote_version: u16,
}
#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WOrderInput {
    market_id: u64,
    side: String,
    size: String,
    limit_price: String,
    tif: String,
    reduce_only: bool,
}
#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WReceipt {
    order_hash: String,
    seq_no: u64,
    recv_time_ms: u64,
    batch_id_hint: u64,
    window_id: u64,
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
    window_id: Option<u64>,
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
    /// Quote-scaled protocol-treasury balance — the operator's accrued trading-fee
    /// revenue (§9); a 0.08% cut of every fill's notional.
    treasury: String,
    /// Quote-scaled cumulative collateral the user has had auto-deleveraged — the
    /// transparency surface for socialized losses (audit Q2).
    user_adl_clawed: String,
    /// The market-maker's net inventory + hedge target per market with open MM
    /// exposure — the venue-agnostic delta-hedging signal (audit Q5).
    mm_hedge: Vec<WHedge>,
    /// The last on-chain L1 settlement, if the L1 bridge is active (else null).
    l1: Option<WL1>,
    /// The verified TEE attestation the enclave is bound to (else null = stub).
    attestation: Option<WAttestation>,
    /// The LP pool (counterparty) — TVL, NAV/share, and the demo user's stake.
    lp: WLp,
}
#[derive(Serialize)]
struct WEvent {
    #[serde(rename = "orderId")]
    order_id: String,
    kind: String,
    message: String,
}
// A transient WS frame: constructed, serialized to a string, and dropped immediately
// (never stored in a collection). Boxing the large `State` variant would just add a
// heap allocation on the every-tick hot path for no memory benefit, so the size
// difference is deliberately allowed here.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum WsMsg {
    State { state: WState },
    Event { event: WEvent },
}

// ── request bodies ───────────────────────────────────────────────────────────
// The six plaintext trade-term fields are `#[serde(default)]` so a SEALED order
// can carry ONLY `{epochId, sealed}` on the wire (Task 11 contract) without the
// JSON extractor 422-ing before `account_place_order` ever runs. The sealed path
// overwrites them from the decrypted terms. The plaintext (dev/demo) path does NOT
// trust those serde defaults to be safe: it explicitly REQUIRES every core field
// (side/size/limitPrice/tif) via `require_core_order_fields` and parses side/tif
// STRICTLY, so a partial body like `{"size":"100"}` is rejected outright instead of
// silently defaulting into a wrong-direction market order.
#[derive(Deserialize, Default)]
struct OrderReq {
    #[serde(rename = "marketId", default)]
    market_id: u64,
    #[serde(default)]
    side: String,
    #[serde(default)]
    size: String,
    #[serde(rename = "limitPrice", default)]
    limit_price: String,
    #[serde(default)]
    tif: String,
    #[serde(rename = "reduceOnly", default)]
    reduce_only: bool,
    /// Caller-signed accounts: the order nonce the caller signed over (must
    /// strictly increase). For server-custody accounts the plaintext field is
    /// ignored — but a SEALED order's decrypted terms nonce IS enforced strictly
    /// increasing per account (replay protection; see `Account::last_sealed_nonce`).
    #[serde(default)]
    nonce: Option<u64>,
    /// Caller-signed accounts only: 65-byte secp256k1 signature (r‖s‖v) over the
    /// order hash, recovering to the account's registered signer.
    #[serde(default)]
    signature: Option<String>,
    /// Sealed order ingress (Task 10): the enclave order-epoch this order was
    /// encrypted to. Required whenever `sealed` is present; the enclave looks up
    /// the matching X25519 secret (current epoch OR the grace-window previous) to
    /// decrypt. Fetched by the client from `GET /v1/enclave/epoch`.
    #[serde(rename = "epochId", default)]
    epoch_id: Option<u64>,
    /// Sealed order ingress (Task 10): the 0x-hex `SealedBox` wire (X25519-sealed,
    /// XChaCha20-Poly1305) carrying the canonical order terms. When present the
    /// plaintext `side/size/limitPrice/tif/reduceOnly/marketId/nonce` fields above
    /// are IGNORED and the working order is derived from the decrypted payload; the
    /// caller `signature` (if any) still covers the order hash of the decrypted
    /// terms. In production posture an UNSEALED order is refused.
    #[serde(default)]
    sealed: Option<String>,
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
    /// Crypto.com instrument for a live feed (`None` ⇒ sim walk only).
    feed: Option<&'static str>,
    /// Local ms when the feed's own (exchange) timestamp last ADVANCED — the freshness
    /// clock the live oracle is stamped with. A frozen-but-200 feed (its timestamp
    /// stops) and a dead/hung feed both stop advancing this and go stale, while the
    /// exchange clock's absolute skew/lag never causes a false stall. Not serialized.
    px_ms: u64,
    /// Last exchange ticker timestamp seen, to detect the advance above.
    feed_ts: u64,
}
#[derive(Serialize, serde::Deserialize)]
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
#[derive(Serialize, serde::Deserialize)]
struct Account {
    wallet: Wallet,
    orders: Vec<GwOrder>,
    nonce: u64,
    deposit_counter: u64,
    /// Per-account order rate limit (a sliding 1s window).
    last_order_ms: u64,
    orders_this_sec: u32,
    /// The external EOA the account funds from. Bound once; an on-chain USDC
    /// `Deposit(from, amount)` is credited only when `from` matches this (so one
    /// account can't claim another's deposit). `None` until bound.
    deposit_address: Option<[u8; 20]>,
    /// Caller-signed mode: if set, every order MUST carry a secp256k1 signature over
    /// the order hash that recovers to this address (the caller's own key), so a
    /// leaked API key alone cannot place orders. `None` ⇒ Phase-0 server custody.
    signer: Option<[u8; 20]>,
    /// Strictly-increasing nonce of the last accepted caller-signed order (replay
    /// protection): a new signed order must carry a higher nonce than this.
    last_signed_nonce: u64,
    /// Strictly-increasing nonce of the last accepted SEALED order for a
    /// server-custody (`signer: None`) account (replay protection): the decrypted
    /// canonical terms carry a client-chosen `nonce`, and a new sealed order must
    /// carry a higher one — so re-POSTing a captured `{epochId, sealed}` body is
    /// rejected instead of duplicating the position. Rides the sealed snapshot
    /// (`serde(default)` keeps pre-upgrade snapshots loadable; fresh genesis on
    /// redeploy is fine).
    #[serde(default)]
    last_sealed_nonce: u64,
}

#[derive(Serialize, serde::Deserialize)]
struct Gw {
    seq: Sequencer,
    archive: NoteArchive,
    user: Wallet,
    mm: Wallet,
    /// Static market config (symbols/feeds are `&'static str`) — NOT persisted;
    /// `boot_restored` rebuilds it from `MARKETS` and overlays the persisted
    /// per-market dynamics (`reference_price`, `px`, `live`).
    #[serde(skip)]
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
    /// Authorized-but-unclaimed withdrawals (§3). The L1 bridge prunes the ones the
    /// vault already paid out and republishes the cumulative root every settle, so a
    /// user can claim USDC on Base Sepolia via `vault.claim(to, amount, nonce, proof)`.
    pending_withdrawals: Vec<Withdrawal>,
    /// Monotonic nonce making each withdrawal leaf unique.
    next_withdraw_nonce: u64,
    /// Claim data per withdrawal leaf: (published root, sibling path). The root lets a
    /// note carry the specific window (incremental) or cumulative (legacy) root it was
    /// published under — CollateralVault.claim(to, amount, nonce, root, proof) accepts any
    /// published root (DP-012).
    withdraw_proofs: std::collections::BTreeMap<[u8; 32], (Digest, Vec<[u8; 32]>)>,
    /// Slice 3b-2a: withdrawals created since the current window opened, in op-application
    /// order — the incremental per-window withdrawal set the circuit's `withdrawals_root`
    /// is derived from. Drained by the new (PROVER_URL) settle path. `serde(default)` is
    /// forward-additive struct hygiene (matches crate precedent); NOTE: postcard is
    /// positional (non-self-describing), so cross-version snapshot load still requires a
    /// state reset/migration — handled by the migration slice.
    #[serde(default)]
    window_withdrawals: Vec<Withdrawal>,
    /// Slice 3b-2a: the state root of the last on-chain settle (genesis at boot). The new
    /// settle path uses `seq.state.state_root() != last_settled_root` as its RPC-free
    /// "is there anything to settle?" signal. `serde(default)` is forward-additive struct
    /// hygiene (matches crate precedent); NOTE: postcard is positional, so cross-version
    /// snapshot load still requires a state reset/migration — handled by the migration slice.
    #[serde(default)]
    last_settled_root: Digest,
    /// On-chain deposit tx hashes already credited (idempotency / replay guard).
    processed_deposit_txs: std::collections::BTreeSet<String>,
    /// Manifest hash of the most recently sealed batch — published to L1 as the
    /// settled batch's manifest when the L1 bridge is active.
    last_manifest: Digest,
    /// Order hashes matched / validly-rejected since the last L1 settle, accumulated across
    /// engine batches. At settle they become this on-chain batch's ordered/rejected roots, so
    /// the sequencer can answer an inclusion challenge for a matched or validly-rejected order
    /// instead of being wrongfully slashed (audit DP-004).
    pending_ordered: Vec<Digest>,
    pending_rejected: Vec<Digest>,
    /// Per ON-CHAIN batch id → the (ordered, rejected) order hashes it committed, retained so a
    /// challenge for an order in that batch can be answered with a Merkle proof against its root.
    batch_orders: std::collections::BTreeMap<u64, (Vec<Digest>, Vec<Digest>)>,
    /// Last on-chain settlement the L1 bridge published (None until it settles once).
    l1_status: Option<L1Status>,
    /// The verified TEE attestation the enclave identity is bound to (None = stub).
    /// NOT persisted — every boot re-verifies the live quote (`attest_from_env`).
    #[serde(skip)]
    attestation: Option<Attested>,
    /// LP pool shares per depositor (keyed by the demo user's owner or an account's
    /// API key). The MM wallet IS the pool; LPs deposit USDC → mint shares of its
    /// mark-to-market equity, earn the house edge (trader losses), bear pool PnL.
    lp_shares: std::collections::BTreeMap<[u8; 32], u128>,
    /// Total LP shares outstanding. Seeded to the boot pool equity so the initial
    /// share price (equity / shares) is 1.0; the operator implicitly owns the seed.
    lp_total_shares: u128,
    /// Monotonic salt for LP deposit/withdraw note blindings.
    lp_counter: u64,
    /// Real-collateral / production posture. When true, self-service (unbacked)
    /// deposits are refused — collateral may only enter via a verified on-chain
    /// deposit (audit DP-001). Set from `production_mode()` in `main`; `false` in
    /// the demo/test build. NOT persisted — recomputed from the environment.
    #[serde(skip)]
    prod: bool,
    /// Task 5: honest finality reporting on the window-settle path. When the prover
    /// is configured (PROVER_URL), the tick loop must NOT simulate SETTLED after
    /// `SETTLE_TICKS` — orders stay MATCHED until their window's proof verifies on
    /// L1 (`commit_window_settle` → `mark_window_settled`). Set from `main()` right
    /// after `prod`; NOT persisted — recomputed from the environment every boot, so
    /// the snapshot wire format is untouched.
    #[serde(skip)]
    window_settle_mode: bool,
    /// Order-ingress X25519 epoch keys (Task 9). Seed-derived from `ENCLAVE_SEED`,
    /// published (signed) via `GET /v1/enclave/epoch`. NOT persisted — the epoch
    /// secret must never touch disk; `boot`/`boot_restored` re-derive it from the
    /// seed exactly as they re-derive the enclave signing identity.
    #[serde(skip)]
    epochs: enclave_epoch::EnclaveEpochs,
    /// Hash-chained, encrypted, append-only log of every ACCEPTED order (Task 12).
    /// Entries are sealed to the enclave's log X25519 PUBLIC key (seed-derived
    /// under `Domain::X25519LogKey`); the gateway never holds the log secret, so
    /// it can never read an entry back. Entries + head ARE persisted in the
    /// sealed snapshot; the recipient pubkey inside is `#[serde(skip)]`ped and
    /// re-derived from `ENCLAVE_SEED` on restore, like `epochs`.
    order_log: order_log::OrderLog,
}

/// Advisory lifetime of a published order-ingress epoch key (§5.1). Clients should
/// refetch `GET /v1/enclave/epoch` before `notAfterMs`; the previous epoch's secret
/// is retained one grace window past a rotation so in-flight orders still decrypt.
const ORDER_EPOCH_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// Derive the order-log recipient PUBLIC key from the enclave seed under the
/// dedicated `Domain::X25519LogKey` label. The secret half of the pair is
/// intentionally discarded right here: the gateway only ever SEALS log entries
/// (write-only log); the secret stays derivable from `ENCLAVE_SEED` and is to be
/// released only to an attested prover (future zk workstream — spec §9).
fn derive_log_pub(enclave_seed: &[u8; 32]) -> [u8; 32] {
    let (_secret_discarded, log_pub) =
        sealed_box::x25519_keypair_from_ikm(enclave_seed, &[Domain::X25519LogKey as u8]);
    log_pub
}

fn oracle_of(px: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: px,
        publish_time_ms: now,
        confidence: (px / 1000).max(1),
        backup_twap: px,
    }
}
/// The block the inclusion-challenge watcher should (re)start scanning from: rewind
/// 1.5× the challenge window behind `now_block` (min 64 blocks) so a restart that
/// straddles a challenge still scans it. 1× the window already covers every
/// still-answerable challenge (raised no more than `window` blocks ago); the extra
/// half-window is margin, and over-scanning is a harmless no-op (audit #8).
fn challenge_scan_start(now_block: u64, window_blocks: u64) -> u64 {
    now_block.saturating_sub(window_blocks.saturating_add(window_blocks / 2).max(64))
}

/// Strict `time-in-force` parse: exactly one of the four documented values.
/// Unlike a lenient `_ => Ioc` fallback, an empty or unrecognized value is an
/// ERROR — a malformed plaintext order must be REJECTED, not silently reinterpreted
/// under a defaulted policy (audit follow-up to the `#[serde(default)]` widening).
fn parse_tif_strict(s: &str) -> Result<TimeInForce, String> {
    match s {
        "Gtc" => Ok(TimeInForce::Gtc),
        "Ioc" => Ok(TimeInForce::Ioc),
        "Fok" => Ok(TimeInForce::Fok),
        "PostOnly" => Ok(TimeInForce::PostOnly),
        other => Err(format!(
            "unknown time-in-force `{other}` (expected Gtc, Ioc, Fok, or PostOnly)"
        )),
    }
}

/// Strict `side` parse: exactly `Buy` or `Sell`. Unlike the historical lenient
/// `if s == "Buy" { Buy } else { Sell }`, an empty or unrecognized value is an
/// ERROR, not a silent `Sell` — a malformed plaintext order must be rejected, not
/// re-interpreted as a (wrong-direction) trade.
fn parse_side_strict(s: &str) -> Result<Side, String> {
    match s {
        "Buy" => Ok(Side::Buy),
        "Sell" => Ok(Side::Sell),
        other => Err(format!(
            "unknown order side `{other}` (expected `Buy` or `Sell`)"
        )),
    }
}

/// Enforce that a PLAINTEXT order carries every core trade-term field. `OrderReq`'s
/// trade fields are `#[serde(default)]` so a SEALED order can be just
/// `{epochId, sealed}` on the wire (Task 11 contract) — but that default must never
/// leak into a plaintext order, where an absent field would otherwise become a real
/// order (side "" → Sell, limitPrice "" → market, tif "" → Ioc). Both plaintext
/// entry points call this before parsing, so a partial body is REJECTED, not
/// silently defaulted.
fn require_core_order_fields(req: &OrderReq) -> Result<(), String> {
    if req.side.is_empty()
        || req.size.is_empty()
        || req.limit_price.is_empty()
        || req.tif.is_empty()
    {
        return Err(
            "plaintext order is missing a required field (side, size, limitPrice, and tif must all be present)"
                .into(),
        );
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)] // a flat order constructor; a params struct would only add ceremony
fn mk_order(
    owner: PubKey,
    market_id: u64,
    side: Side,
    size: i128,
    price: i128,
    nonce: u64,
    tif: TimeInForce,
    reduce_only: bool,
) -> Order {
    // Bind the economically-meaningful trade terms into `ciphertext_commit`. Because
    // `Order::order_hash` hashes `ciphertext_commit`, this makes the order hash commit
    // to side/size/price/tif/market/nonce/reduce_only — so a caller-signed account's
    // signature (taken over the order hash) covers the ACTUAL trade: mutating any term
    // in the request invalidates the signature (review fix, was nonce-only before;
    // reduce_only added per audit — a leaked/relayed key must not flip a signed
    // reduce-only order into a position-opening one).
    use sha3::Digest as _;
    let side_b: u8 = match side {
        Side::Buy => 1,
        Side::Sell => 2,
    };
    let tif_b: u8 = match tif {
        TimeInForce::Gtc => 1,
        TimeInForce::Ioc => 2,
        TimeInForce::Fok => 3,
        TimeInForce::PostOnly => 4,
    };
    let mut hh = sha3::Keccak256::new();
    hh.update([side_b]);
    hh.update(size.to_le_bytes());
    hh.update(price.to_le_bytes());
    hh.update([tif_b]);
    hh.update(market_id.to_le_bytes());
    hh.update(nonce.to_le_bytes());
    hh.update([reduce_only as u8]);
    let cc: [u8; 32] = hh.finalize().into();
    Order {
        owner,
        market_id,
        side,
        size,
        limit_price: price,
        tif,
        reduce_only,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: cc,
    }
}

/// The economically-meaningful terms of an order, decoded from a client's sealed
/// payload (Task 10). This is the plaintext the enclave recovers after `unseal`.
struct OrderTerms {
    market_id: u64,
    side: Side,
    size: i128,
    limit_price: i128,
    tif: TimeInForce,
    reduce_only: bool,
    nonce: u64,
}

/// Wire length of a serialized `OrderTerms` (see [`deserialize_order_terms`]).
const ORDER_TERMS_LEN: usize = 51;

/// Serialize order terms to the canonical cross-language byte layout. The inverse
/// of [`deserialize_order_terms`]; see that function's doc comment for the exact,
/// authoritative layout the TS client (Task 11) must reproduce. On ingress the
/// enclave only DESERIALIZES (it opens what the client sealed); this direction is
/// exercised by the encrypted order log (Task 12) — which re-canonicalizes every
/// ACCEPTED order's terms before sealing them into a log entry — and by the
/// cross-language parity tests.
fn serialize_order_terms(t: &OrderTerms) -> [u8; ORDER_TERMS_LEN] {
    let mut b = [0u8; ORDER_TERMS_LEN];
    b[0..8].copy_from_slice(&t.market_id.to_le_bytes());
    b[8] = match t.side {
        Side::Buy => 1,
        Side::Sell => 2,
    };
    b[9..25].copy_from_slice(&t.size.to_le_bytes());
    b[25..41].copy_from_slice(&t.limit_price.to_le_bytes());
    b[41] = match t.tif {
        TimeInForce::Gtc => 1,
        TimeInForce::Ioc => 2,
        TimeInForce::Fok => 3,
        TimeInForce::PostOnly => 4,
    };
    b[42] = t.reduce_only as u8;
    b[43..51].copy_from_slice(&t.nonce.to_le_bytes());
    b
}

/// Deserialize the canonical sealed-order-terms byte layout (Task 10/11 contract).
///
/// A client seals EXACTLY these bytes to the enclave's current order-epoch X25519
/// key; the enclave decrypts them here (inside the gateway) before matching. The
/// TypeScript client (Task 11) MUST reproduce this layout byte-for-byte — copy the
/// table below verbatim.
///
/// All integers are little-endian. Total length is 51 bytes:
///
/// | offset | field       | type     | bytes | notes                                    |
/// |--------|-------------|----------|-------|------------------------------------------|
/// | 0      | marketId    | u64  LE  | 8     |                                          |
/// | 8      | side        | u8       | 1     | `1 = Buy`, `2 = Sell`                     |
/// | 9      | size        | i128 LE  | 16    | size-scaled, must be > 0                  |
/// | 25     | limitPrice  | i128 LE  | 16    | price-scaled, `0` = market order         |
/// | 41     | tif         | u8       | 1     | `1 = Gtc`, `2 = Ioc`, `3 = Fok`, `4 = PostOnly` |
/// | 42     | reduceOnly  | u8       | 1     | `0 = false`, `1 = true`                  |
/// | 43     | nonce       | u64  LE  | 8     |                                          |
///
/// The `side` and `tif` numeric mappings are IDENTICAL to the ones `mk_order`
/// folds into `ciphertext_commit` (Buy=1/Sell=2, Gtc=1/Ioc=2/Fok=3/PostOnly=4), so
/// the terms recovered here hash to the same order the caller signature (if any)
/// covers — no separate encoding is invented for the wire.
///
/// Returns `None` on a wrong length or an out-of-range side/tif/reduceOnly byte.
fn deserialize_order_terms(b: &[u8]) -> Option<OrderTerms> {
    if b.len() != ORDER_TERMS_LEN {
        return None;
    }
    let market_id = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let side = match b[8] {
        1 => Side::Buy,
        2 => Side::Sell,
        _ => return None,
    };
    let size = i128::from_le_bytes(b[9..25].try_into().ok()?);
    let limit_price = i128::from_le_bytes(b[25..41].try_into().ok()?);
    let tif = match b[41] {
        1 => TimeInForce::Gtc,
        2 => TimeInForce::Ioc,
        3 => TimeInForce::Fok,
        4 => TimeInForce::PostOnly,
        _ => return None,
    };
    let reduce_only = match b[42] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let nonce = u64::from_le_bytes(b[43..51].try_into().ok()?);
    Some(OrderTerms {
        market_id,
        side,
        size,
        limit_price,
        tif,
        reduce_only,
        nonce,
    })
}

/// Decode arbitrary-length hex (optionally `0x`-prefixed) into bytes. Used for the
/// variable-length sealed-order wire (`1 + 32 + 24 + ct`). `None` on odd length or
/// a non-hex nibble.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    // Operate on BYTES, not `&str` slices: `sealed` is attacker-controlled request
    // JSON, so a multi-byte UTF-8 codepoint could make the char length even while a
    // byte-offset slice landed mid-codepoint and PANICKED. Byte-based nibble decode
    // returns a clean `None` for any non-hex input (any byte >= 0x80 fails `hexval`).
    let h = s.strip_prefix("0x").unwrap_or(s).as_bytes();
    if !h.len().is_multiple_of(2) {
        return None;
    }
    let hexval = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    h.chunks(2)
        .map(|c| Some(hexval(c[0])? << 4 | hexval(c[1])?))
        .collect()
}

impl Gw {
    fn boot() -> Self {
        // Bind the enclave identity to a REAL verified TEE measurement when an
        // attestation is configured (Azure TDX + vTPM); else a stub for the demo.
        let attestation = attest_from_env();
        let measurement = attestation
            .as_ref()
            .map(|a| a.measurement)
            .unwrap_or([0xABu8; 32]);
        if let Some(a) = &attestation {
            println!(
                "[attest] enclave bound to verified measurement {} (TCB {})",
                hex0x(&a.measurement),
                a.tcb
            );
        }
        // main() validates the seed before boot in production; fall back to the (valid) demo
        // seed here so a stray/malformed ENCLAVE_SEED in a test env can never panic from_seed.
        let (enclave_seed, _) = enclave_seed_from_env().unwrap_or((DEMO_ENCLAVE_SEED, true));
        let enclave = EnclaveIdentity::from_seed(enclave_seed, 1, measurement);
        let mut seq = Sequencer::new(enclave, 24);
        let mut archive = NoteArchive::new();
        let user = Wallet::from_seed([1u8; 32]);
        let mm = Wallet::from_seed([2u8; 32]);
        let now = now_ms();

        // Pass 1 (registration): register EVERY market + its oracle before ANY funding.
        // add_market re-captures window_start_state and is sound only while window_ops is
        // empty; funding pushes ops into window_ops, so all add_market calls must complete
        // first (markets are boot config, not mid-window). See sequencer::add_market.
        let mut mkts = Vec::new();
        for cfg in MARKETS.iter() {
            seq.add_market(Market::with_fees_treasury(
                cfg.id,
                TAKER_FEE_BPS,
                MAKER_REBATE_BPS,
                TREASURY_FEE_BPS,
            ));
            let px = usd(cfg.seed);
            seq.set_oracle(cfg.id, oracle_of(px, now));
            mkts.push(Mkt {
                id: cfg.id,
                symbol: cfg.symbol,
                reference_price: px,
                px,
                live: false,
                feed: cfg.feed,
                px_ms: 0,
                feed_ts: 0,
            });
        }
        // Pass 2 (funding): all markets now exist, so fund each bucket.
        for (i, cfg) in MARKETS.iter().enumerate() {
            // fund the market-maker (deep) and the user (≈$5k) into each market bucket
            fund(
                &mut seq,
                &mut archive,
                &mm,
                cfg.id,
                MM_FUND_PER_MARKET,
                0x40 + i as u8,
            );
            fund(
                &mut seq,
                &mut archive,
                &user,
                cfg.id,
                USER_FUND_PER_MARKET,
                0x10 + i as u8,
            );
        }
        // give the demo user extra market-0 balance so the LP tab is demoable (LP
        // deposits debit this real balance — no free mint).
        fund(&mut seq, &mut archive, &user, 0, 2_000_000, 0x38);
        // capitalize the insurance fund so the backstop is visible from genesis; it
        // then grows on its own from the per-fill insurance cut (audit Q3/Q4).
        seq.apply(&BatchOp::SeedInsurance {
            amount: INSURANCE_SEED_USD * QUOTE_SCALE,
        })
        .expect("seed insurance fund");
        // Pass-2 funding + SeedInsurance mutated state and pushed ops into the open
        // window AFTER add_market last captured window_start_state. The L1 contract
        // is deployed with GENESIS_ROOT = the FULL boot state root (computed below),
        // so fold the boot ops into the genesis baseline: window 0 must open from
        // genesis, or its pre_state (post-Pass-1, pre-funding) != the on-chain
        // GENESIS_ROOT and the first settle reverts with BadPrevRoot.
        seq.seal_genesis_baseline();

        let genesis_root = seq.state.state_root();
        // Live-migration tooling: the runbook reads this line off a throwaway boot to
        // deploy the L1 contract with a matching GENESIS_ROOT (deterministic in the
        // boot config). Log-only — no behavior change.
        println!("[state] genesis engine root {}", hex32(&genesis_root));
        let mut gw = Gw {
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
            pending_withdrawals: Vec::new(),
            next_withdraw_nonce: 1,
            withdraw_proofs: std::collections::BTreeMap::new(),
            window_withdrawals: Vec::new(),
            last_settled_root: genesis_root,
            processed_deposit_txs: std::collections::BTreeSet::new(),
            last_manifest: [0u8; 32],
            pending_ordered: Vec::new(),
            pending_rejected: Vec::new(),
            batch_orders: std::collections::BTreeMap::new(),
            l1_status: None,
            attestation,
            lp_shares: std::collections::BTreeMap::new(),
            lp_total_shares: 0,
            lp_counter: 0,
            prod: false,
            window_settle_mode: false,
            // Derive the first order-ingress epoch from the SAME seed the enclave
            // signing identity derives from, so a reboot/re-pin keeps the key stable.
            epochs: enclave_epoch::EnclaveEpochs::derive(enclave_seed, 1, now, ORDER_EPOCH_TTL_MS),
            order_log: order_log::OrderLog::new(derive_log_pub(&enclave_seed)),
        };
        // seed total LP shares to the boot pool equity (the operator's stake), so the
        // initial NAV per share is 1.0 and LP deposits price in proportionally.
        gw.lp_total_shares = gw.pool_equity().max(0) as u128;
        gw
    }

    // ── sealed state snapshot (persistence across restarts) ─────────────────
    /// Serialize the persistable state: the `Gw` itself (serde skips the
    /// runtime-only fields) plus the per-market dynamics of the static market
    /// table (`(id, reference_price, px, live)` — symbols/feeds are `&'static`
    /// config rebuilt at restore).
    fn snapshot_plain(&self) -> Vec<u8> {
        let mkt_px: Vec<(u64, i128, i128, bool)> = self
            .mkts
            .iter()
            .map(|m| (m.id, m.reference_price, m.px, m.live))
            .collect();
        postcard::to_allocvec(&(self, mkt_px)).expect("snapshot encode")
    }

    /// Restore from snapshot plaintext, rebuilding the runtime-only parts exactly
    /// as `boot()` does: the live attestation, the enclave identity (from
    /// `ENCLAVE_SEED` — the snapshot never carries the signing secret), and the
    /// static market table with the persisted dynamics overlaid.
    fn boot_restored(plain: &[u8]) -> Result<Self, String> {
        let (mut gw, mkt_px): (Gw, Vec<(u64, i128, i128, bool)>) =
            postcard::from_bytes(plain).map_err(|e| format!("snapshot decode: {e}"))?;

        let attestation = attest_from_env();
        let measurement = attestation
            .as_ref()
            .map(|a| a.measurement)
            .unwrap_or([0xABu8; 32]);
        if let Some(a) = &attestation {
            println!(
                "[attest] enclave bound to verified measurement {} (TCB {})",
                hex0x(&a.measurement),
                a.tcb
            );
        }
        let (enclave_seed, _) = enclave_seed_from_env().unwrap_or((DEMO_ENCLAVE_SEED, true));
        gw.seq
            .set_enclave(EnclaveIdentity::from_seed(enclave_seed, 1, measurement));
        gw.attestation = attestation;
        // Re-derive the order-ingress epoch from ENCLAVE_SEED exactly as boot() does
        // (the snapshot serde-skips it — the epoch secret must never persist to disk).
        gw.epochs =
            enclave_epoch::EnclaveEpochs::derive(enclave_seed, 1, now_ms(), ORDER_EPOCH_TTL_MS);
        // Re-arm the order-log recipient pubkey (also serde-skipped) from the same
        // seed: the persisted entries + head restore as-is, but no key material —
        // public or secret — is ever read from the snapshot.
        gw.order_log.set_recipient(derive_log_pub(&enclave_seed));

        gw.mkts = MARKETS
            .iter()
            .map(|cfg| Mkt {
                id: cfg.id,
                symbol: cfg.symbol,
                reference_price: usd(cfg.seed),
                px: usd(cfg.seed),
                live: false,
                feed: cfg.feed,
                px_ms: 0,
                feed_ts: 0,
            })
            .collect();
        for (id, reference_price, px, live) in mkt_px {
            if let Some(m) = gw.mkts.iter_mut().find(|m| m.id == id) {
                m.reference_price = reference_price;
                m.px = px;
                m.live = live;
            }
        }
        Ok(gw)
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
    fn register_account(&mut self, signer: Option<[u8; 20]>) -> ([u8; 32], PubKey) {
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
                last_order_ms: 0,
                orders_this_sec: 0,
                deposit_address: None,
                signer,
                last_signed_nonce: 0,
                last_sealed_nonce: 0,
            },
        );
        (api_key, owner)
    }

    /// Bind the external EOA an account funds from (so its on-chain USDC deposits can
    /// be attributed). Requires a secp256k1 signature **recovering to `addr`** over a
    /// digest binding this account's owner — so only the controller of `addr` can bind
    /// it. This closes a front-run where an attacker binds a victim's public deposit
    /// EOA and steals the credit (review fix). An address binds to at most one account.
    fn account_set_deposit_address(
        &mut self,
        key: &[u8; 32],
        addr: [u8; 20],
        sig: &[u8; 65],
    ) -> Result<(), String> {
        let owner = self
            .accounts
            .get(key)
            .ok_or("Unknown account.")?
            .wallet
            .owner;
        // Accept the signature over ANY of the three deterministic shapes of the
        // bind digest (raw / EIP-191 over bytes / EIP-191 over hex string) so both
        // CLI signers and browser-wallet `personal_sign` work — see
        // `deposit_bind_prehash_candidates` for the WHY of each and the security
        // invariant (all shapes commit to the same (owner, addr), so this widens
        // signer ergonomics, never authorization).
        let digest = deposit_bind_digest(&owner, &addr);
        let proven = deposit_bind_prehash_candidates(&digest)
            .iter()
            .any(|prehash| recover_eth_address(prehash, sig) == Some(addr));
        if !proven {
            return Err(
                "deposit-address proof: signature must recover to the address being bound".into(),
            );
        }
        if self
            .accounts
            .iter()
            .any(|(k, a)| k != key && a.deposit_address == Some(addr))
        {
            return Err("that address is already bound to another account".into());
        }
        self.accounts.get_mut(key).unwrap().deposit_address = Some(addr);
        Ok(())
    }

    /// Credit a CONFIRMED on-chain USDC deposit to an account's market bucket. The
    /// caller (handler) has already read `(from, amount)` from the vault's `Deposit`
    /// log via the L1 bridge; here we enforce the binding (`from` == the account's
    /// bound address), dedup by tx hash, and fund the engine. USDC base units map 1:1
    /// to quote units (both 1e6), so `amount` credits directly.
    fn account_confirm_deposit(
        &mut self,
        key: &[u8; 32],
        from: [u8; 20],
        amount: u128,
        tx: &str,
        market: u64,
    ) -> Result<i128, String> {
        if self.mkt(market).is_none() {
            return Err("Unknown market.".into());
        }
        if self.processed_deposit_txs.contains(tx) {
            return Err("This deposit tx was already credited.".into());
        }
        let (wallet, bound) = {
            let a = self.accounts.get(key).ok_or("Unknown account.")?;
            (a.wallet, a.deposit_address)
        };
        match bound {
            Some(b) if b == from => {}
            Some(_) => {
                return Err(
                    "Deposit `from` does not match this account's bound deposit address.".into(),
                )
            }
            None => {
                return Err(
                    "Bind a deposit address first (POST /v1/accounts/deposit/address).".into(),
                )
            }
        }
        // checked u128 → i128 (a value above i128::MAX would sign-flip negative and
        // then panic inside the engine's non-positive-amount guard — review fix).
        let amt: i128 = amount
            .try_into()
            .map_err(|_| "deposit amount too large".to_string())?;
        if amt <= 0 {
            return Err("deposit amount must be positive".into());
        }
        let dc = self.accounts.get(key).unwrap().deposit_counter;
        let mut blind = [0xB0u8; 32];
        blind[..8].copy_from_slice(&dc.to_le_bytes());
        fund_amount(
            &mut self.seq,
            &mut self.archive,
            &wallet,
            market,
            amt,
            blind,
        );
        let a = self.accounts.get_mut(key).unwrap();
        a.deposit_counter += 1;
        self.processed_deposit_txs.insert(tx.to_string());
        Ok(amt)
    }

    /// Withdraw `amount` (quote units = USDC base units) from an account's market
    /// bucket to the L1 address `to`: debit the engine (Unbind + burn the note, so the
    /// off-chain balance really drops and can't be double-withdrawn) and record an
    /// authorized withdrawal leaf. On the next L1 settle the cumulative root is
    /// published and the user can `vault.claim` the USDC on Base Sepolia (§3).
    fn account_withdraw(
        &mut self,
        key: &[u8; 32],
        market: u64,
        amount: i128,
        to: [u8; 20],
    ) -> Result<Withdrawal, String> {
        if amount <= 0 {
            return Err("Amount must be positive.".into());
        }
        if self.mkt(market).is_none() {
            return Err("Unknown market.".into());
        }
        let wallet = self.accounts.get(key).ok_or("Unknown account.")?.wallet;
        if amount > self.market_free_of(&wallet.owner, market) {
            return Err(
                "Not withdrawable: amount exceeds the SETTLED balance in this market (§3).".into(),
            );
        }
        let nonce = self.next_withdraw_nonce;
        let now = now_ms();
        let oracle = oracle_of(self.px_of(market), now);
        let mut blind = [0xD0u8; 32];
        blind[..8].copy_from_slice(&nonce.to_le_bytes());
        self.seq
            .apply(&BatchOp::Unbind {
                owner: wallet.owner,
                market_id: market,
                amount,
                blinding: blind,
                oracle,
                now_ms: now,
            })
            .map_err(|e| format!("withdraw unbind failed: {e:?}"))?;
        let note = Note::new(wallet.owner, 0, amount, blind);
        let cm = note.commitment::<Keccak256>();
        self.seq
            .apply(&BatchOp::Withdraw {
                note_commitment: cm,
                spend_key: wallet.spend_key,
                // Real L1 withdrawal: bind the burned value to the same (to, nonce)
                // leaf pushed to `pending_withdrawals` below (enters withdrawals_root).
                to: Some(to),
                nonce,
            })
            .map_err(|e| format!("withdraw burn failed: {e:?}"))?;
        self.next_withdraw_nonce += 1;
        let w = Withdrawal {
            owner: wallet.owner,
            to,
            amount: amount as u128,
            nonce,
        };
        self.pending_withdrawals.push(w.clone());
        // Slice 3b-2a: also record it in the current window's incremental set (same order
        // the BatchOp::Withdraw was applied), so the new settle path's window withdrawal
        // tree byte-matches the circuit's withdrawals_root.
        self.window_withdrawals.push(w.clone());
        Ok(w)
    }

    /// Slice 3b-2a: begin a new-path window settle. Returns `None` if the engine root is
    /// unchanged since the last settle (nothing to prove). Errors WITHOUT mutating if the
    /// window's batch id would not match the on-chain `batchCount` (a desync a prior fault
    /// left behind — recovery is Slice 3b-3). Otherwise seals the window and takes its
    /// incremental withdrawal set.
    fn begin_window_settle(
        &mut self,
        chain_batch_count: u64,
    ) -> Result<Option<(WindowWitness, Vec<Withdrawal>)>, String> {
        if self.seq.state.state_root() == self.last_settled_root {
            return Ok(None); // no net state change since the last settle
        }
        // Pre-check the counter BEFORE sealing (which bumps it), so a desync leaves the
        // sequencer untouched instead of stranded ahead of the chain.
        let expected = self.seq.state.next_batch_id;
        if expected != chain_batch_count {
            return Err(format!(
                "batch_id desync: window {expected} vs chain {chain_batch_count} (recovery is 3b-3)"
            ));
        }
        let witness = self.seq.seal_window();
        let ww = core::mem::take(&mut self.window_withdrawals);
        Ok(Some((witness, ww)))
    }

    /// Slice 3b-2a: apply a completed new-path window settle to gateway state. Accumulates
    /// the window's per-note claim proofs (each window root is permanently claimable, so we
    /// EXTEND, never replace); advances `last_settled_root`; retains this batch's ordered/
    /// rejected hashes for DP-004 challenge answers (keyed by the on-chain batch id, which
    /// equals the window id); clears the now-redundant legacy pending accumulators; and
    /// records the published L1 status.
    fn commit_window_settle(
        &mut self,
        batch_id: u64,
        ordered: Vec<Digest>,
        rejected: Vec<Digest>,
        prepared: prover_client::PreparedSettle,
        l1_status: L1Status,
    ) {
        for (leaf, entry) in prepared.withdraw_proofs {
            self.withdraw_proofs.insert(leaf, entry);
        }
        self.last_settled_root = prepared.outcome.new_root;
        self.batch_orders.insert(batch_id, (ordered, rejected));
        // the window manifest is the source of truth for this batch's roots; the legacy
        // per-tick accumulators are unused by the new path — clear them so they can't grow.
        self.pending_ordered.clear();
        self.pending_rejected.clear();
        // Task 5: the verified proof just hardened every tick batch sealed into windows
        // ≤ batch_id — advance their orders MATCHED → SETTLED (and prune their rollback
        // snapshots). MUST run before the map prune below: the prune keeps a grace
        // window today, but honest finality must not depend on that grace.
        self.seq.mark_window_settled(batch_id);
        // Slice 3b-4 (Finding-1 fix): prune the tick->window map on WINDOW settle (Counter B),
        // not the ~10x-faster per-tick soft-finality, so /v1/batch/:id + WBatch.window_id survive
        // until their window settles + a grace (settled:true observable). batch_id just settled,
        // so the on-chain batchCount is now batch_id + 1.
        self.seq.prune_tick_window_settled(batch_id + 1);
        self.l1_status = Some(l1_status);
    }

    /// Slice 3b-2b: drop withdrawals the vault has already paid (claimed[leaf]) from both
    /// the listing (`pending_withdrawals`) and the served proofs (`withdraw_proofs`), so
    /// the new (per-window) settle path stays bounded and paid notes stop being listed —
    /// the same claimed-pruning the legacy cumulative path does at settle.
    fn prune_claimed_withdrawals(&mut self, claimed: &[[u8; 32]]) {
        if claimed.is_empty() {
            return;
        }
        let cset: std::collections::BTreeSet<[u8; 32]> = claimed.iter().copied().collect();
        self.pending_withdrawals.retain(|w| !cset.contains(&w.leaf()));
        for leaf in &cset {
            self.withdraw_proofs.remove(leaf);
        }
    }

    /// Slice 3b-3: re-inject a failed window's drained withdrawals AHEAD of any accumulated
    /// since, mirroring `Sequencer::rollback_window`'s op prepend, so the re-seal's withdrawal
    /// set is `[failed ++ intervening]` and no withdrawal is lost on a settle failure.
    fn rollback_window_withdrawals(&mut self, mut ww: Vec<Withdrawal>) {
        ww.append(&mut self.window_withdrawals);
        self.window_withdrawals = ww;
    }

    /// An account's withdrawals with the claim data: each carries its leaf and, once
    /// the cumulative root has been published on-chain, the Merkle `proof` to call
    /// `vault.claim(to, amount, nonce, proof)`. `claimable=false` means it is recorded
    /// but awaiting its first on-chain publish (the next settle).
    fn v1_withdrawals_json(&self, key: &[u8; 32]) -> Option<serde_json::Value> {
        let owner = self.accounts.get(key)?.wallet.owner;
        // the published cumulative root the served proofs verify against — the caller
        // passes it to CollateralVault.claim (which accepts any published root, audit DP-012).
        let current_root = self
            .l1_status
            .as_ref()
            .map(|s| s.withdrawals_root.clone())
            .unwrap_or_default();
        let items: Vec<_> = self
            .pending_withdrawals
            .iter()
            .filter(|w| w.owner == owner)
            .map(|w| {
                let leaf = w.leaf();
                let entry = self.withdraw_proofs.get(&leaf);
                serde_json::json!({
                    "to": hex0x(&w.to),
                    "amount": w.amount.to_string(),
                    "nonce": w.nonce,
                    "leaf": hex0x(&leaf),
                    // per-note published root (window root in the new path; the cumulative
                    // root in legacy); fall back to the last published root pre-publish.
                    "root": entry.map(|(r, _)| hex0x(r)).unwrap_or_else(|| current_root.clone()),
                    "claimable": entry.is_some(),
                    "proof": entry
                        .map(|(_, p)| p.iter().map(|n| hex0x(n)).collect::<Vec<_>>())
                        .unwrap_or_default(),
                })
            })
            .collect();
        Some(serde_json::json!({ "withdrawals": items }))
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
        if self.prod {
            // audit DP-001: self-service in-memory credit would let anyone mint unbacked
            // collateral and withdraw it against real vault funds. In production, collateral
            // enters only via a verified on-chain deposit.
            return Err(
                "Self-service deposit is disabled in production; fund via a verified \
                 on-chain deposit (POST /v1/accounts/deposit/onchain)."
                    .into(),
            );
        }
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
        fund_amount(
            &mut self.seq,
            &mut self.archive,
            &wallet,
            market,
            amount,
            blind,
        );
        self.accounts.get_mut(key).unwrap().deposit_counter += 1;
        Ok(())
    }

    /// Place an order for an account. Ioc/Fok are takers; Gtc/PostOnly rest in the
    /// matcher book (so an MM bot can quote). Returns the signed receipt.
    fn account_place_order(&mut self, key: &[u8; 32], req: &OrderReq) -> Result<WReceipt, String> {
        // The account's 32-byte owner pubkey — needed UP FRONT to build the sealed
        // order AAD (which binds the ciphertext to this epoch AND this owner), and
        // reused for the margin/opening checks below.
        let owner = self
            .accounts
            .get(key)
            .ok_or("Unknown account.")?
            .wallet
            .owner;

        // ── sealed order ingress: decrypt inside the enclave (Task 10) ────────
        // A client may send its order ENCRYPTED to the enclave's current order-epoch
        // X25519 key instead of in plaintext. When `sealed` is present we decrypt it
        // here — inside the gateway (the enclave) — and derive the working order from
        // the decrypted canonical terms; the plaintext `OrderReq` fields are IGNORED.
        // The AAD binds the ciphertext to (epoch_id ‖ owner), so an order sealed to a
        // different epoch or for a different account cannot be replayed here. In
        // production posture an UNSEALED order is refused outright; demo/dev keeps the
        // plaintext path for backward-compat. Exactly one `unseal` runs per order.
        let was_sealed = req.sealed.is_some();
        let decoded;
        let req: &OrderReq = if let Some(sealed_hex) = req.sealed.as_deref() {
            let epoch_id = req.epoch_id.ok_or("sealed order requires `epochId`")?;
            let secret = self
                .epochs
                .secret_for(epoch_id)
                .ok_or("sealed order: unknown or expired epoch")?;
            let raw = decode_hex(sealed_hex).ok_or("sealed order: bad 0x-hex wire")?;
            let sb = sealed_box::SealedBox::from_bytes(&raw)
                .ok_or("sealed order: malformed sealed box")?;
            let mut extra = Vec::with_capacity(8 + 32);
            extra.extend_from_slice(&epoch_id.to_le_bytes());
            extra.extend_from_slice(&owner);
            let aad = sealed_box::domain_aad(Domain::OrderEncryptAad as u8, &extra);
            let pt = sealed_box::unseal(secret, &sb, &aad)
                .ok_or("sealed order: decryption failed (tampered, wrong key, or wrong epoch)")?;
            let t =
                deserialize_order_terms(&pt).ok_or("sealed order: malformed order terms")?;
            // Re-materialize the decrypted terms as an `OrderReq` so the rest of the
            // flow (margin, opening/reduce-only, nonce, order-hash + caller-signature)
            // is IDENTICAL to the plaintext path. The caller `signature` (if any)
            // travels in the clear and still covers the order hash of these decrypted
            // terms; `epoch_id`/`sealed` are cleared so nothing re-reads them.
            decoded = OrderReq {
                market_id: t.market_id,
                side: match t.side {
                    Side::Buy => "Buy",
                    Side::Sell => "Sell",
                }
                .to_string(),
                size: t.size.to_string(),
                limit_price: t.limit_price.to_string(),
                tif: match t.tif {
                    TimeInForce::Gtc => "Gtc",
                    TimeInForce::Ioc => "Ioc",
                    TimeInForce::Fok => "Fok",
                    TimeInForce::PostOnly => "PostOnly",
                }
                .to_string(),
                reduce_only: t.reduce_only,
                nonce: Some(t.nonce),
                signature: req.signature.clone(),
                epoch_id: None,
                sealed: None,
            };
            &decoded
        } else {
            if self.prod {
                return Err("production requires sealed order ingress".into());
            }
            // Dev/demo plaintext ingress. The trade-term fields are `#[serde(default)]`
            // (so the sealed branch above can omit them); enforce their PRESENCE here
            // so a partial body like `{"size":"100"}` is REJECTED instead of silently
            // defaulting into a wrong-direction market order (side "" → Sell,
            // limitPrice "" → market, tif "" → Ioc). Strict side/tif parsing below
            // then rejects any present-but-unrecognized value too.
            require_core_order_fields(req)?;
            req
        };

        let size: i128 = req.size.parse().map_err(|_| "bad size".to_string())?;
        if size <= 0 {
            return Err("Size must be positive.".into());
        }
        if self.mkt(req.market_id).is_none() {
            return Err("Unknown market.".into());
        }
        let limit: i128 = req.limit_price.parse().unwrap_or(0);
        // Strict: an empty/unknown side is an error (the plaintext guard already
        // required presence; the sealed branch always supplies "Buy"/"Sell"). No
        // silent `else → Sell` default that could flip a malformed order's direction.
        let side = parse_side_strict(&req.side)?;
        let opening = self.is_opening_of(&owner, req.market_id, &req.side, size);
        if self.seq.state.mode == Mode::CloseOnly && opening {
            return Err(
                "System is in close-only mode — opening/increasing is blocked (§6).".into(),
            );
        }
        if req.reduce_only && opening {
            return Err("Reduce-only order would open or increase a position — rejected.".into());
        }
        let px = if limit > 0 {
            limit
        } else {
            self.px_of(req.market_id)
        };
        if opening {
            let need = required_margin(size, px);
            if need > self.market_free_of(&owner, req.market_id) {
                return Err("Insufficient free margin to open this position (§3).".into());
            }
        }
        let tif = parse_tif_strict(&req.tif)?;
        let now_rate = now_ms();
        let acct = self.accounts.get_mut(key).unwrap();
        // per-account sliding-1s rate limit
        if now_rate.saturating_sub(acct.last_order_ms) < 1000 {
            if acct.orders_this_sec >= V1_ORDER_RATE {
                return Err(format!(
                    "RATE_LIMIT: exceeded {V1_ORDER_RATE} orders/sec for this account"
                ));
            }
            acct.orders_this_sec += 1;
        } else {
            acct.last_order_ms = now_rate;
            acct.orders_this_sec = 1;
        }
        // nonce selection + (caller-signed accounts) signature verification over the
        // order hash. A caller-signed account requires the caller's own secp256k1
        // signature on every order, so a leaked API key alone cannot trade.
        let signer = acct.signer;
        let nonce = match signer {
            Some(_) => {
                // the signed order hash binds the price, so caller-signed orders must
                // carry a limit (the gateway-filled market price can't be pre-signed).
                if limit <= 0 {
                    return Err("caller-signed orders must specify a limit price (market price is not pre-signable)".into());
                }
                let n = match req.nonce {
                    Some(n) => n,
                    None => return Err("caller-signed account: `nonce` is required".into()),
                };
                if n <= acct.last_signed_nonce {
                    return Err("nonce must strictly increase (replay protection)".into());
                }
                n
            }
            // Server-custody account, SEALED ingress: the decrypted canonical terms
            // carry the client's nonce (the sealed branch always sets `req.nonce`).
            // Enforce strict monotonicity per account and USE it as the order nonce,
            // so a captured `{epochId, sealed}` body replayed verbatim decrypts to a
            // stale nonce and is rejected — no duplicated position (pre-merge FIX 1).
            None if was_sealed => {
                let n = req
                    .nonce
                    .expect("sealed branch always sets nonce from the decrypted terms");
                if n <= acct.last_sealed_nonce {
                    return Err(
                        "sealed order: nonce must strictly increase (replay protection)".into(),
                    );
                }
                n
            }
            None => acct.nonce,
        };
        // reduce_only is bound into the order hash (mk_order) so a caller signature
        // covers it — a leaked/relayed key can't flip it (audit DP-009 + follow-up).
        // Pass the RAW limit (0 = market): market orders must keep limit_price == 0
        // through to the seal so the matcher treats them as "cross at the mark" and the
        // seal-loop off-market check doesn't reject a market order whose accept-time
        // price has since drifted from the mark (audit review #5). `px` is only the
        // margin-check price above.
        let order = mk_order(
            owner,
            req.market_id,
            side,
            size,
            limit,
            nonce,
            tif,
            req.reduce_only,
        );
        let oh = order.order_hash::<Keccak256>();
        if let Some(expected) = signer {
            let sig_hex = match req.signature.as_deref() {
                Some(s) => s,
                None => return Err("caller-signed account: `signature` is required".into()),
            };
            let sig =
                parse_hex65(sig_hex).ok_or("bad signature (expected 65-byte 0x hex r‖s‖v)")?;
            let recovered =
                recover_eth_address(&oh, &sig).ok_or("signature did not recover a key")?;
            if recovered != expected {
                return Err("signature does not match the account's registered signer".into());
            }
            acct.last_signed_nonce = nonce;
        } else if was_sealed {
            // Commit the accepted sealed nonce (the strictly-increasing check above
            // passed) — a verbatim replay of this body is now permanently stale.
            acct.last_sealed_nonce = nonce;
            // Keep the auto-nonce ahead of client-chosen nonces so a later dev/demo
            // plaintext order can't mint a duplicate `o{nonce}` order id.
            acct.nonce = acct.nonce.max(nonce.saturating_add(1));
        } else {
            acct.nonce += 1;
        }
        let now = now_ms();
        let signed = self.seq.accept_order(&order, now);
        // ── hash-chained encrypted order log (Task 12) ───────────────────────
        // The order is ACCEPTED as of the receipt above — append it to the
        // append-only log: the SAME canonical 51-byte terms layout a sealed
        // client submits (re-serialized from the admitted working order, so the
        // plaintext and sealed ingress paths log identically), keyed by the
        // terms commitment `mk_order` already bound into the order. The entry is
        // sealed to the log pubkey (this gateway cannot read it back) and
        // chained into `order_log.head()`; OsRng is threaded in here — the
        // module itself never hardcodes an entropy source.
        let canonical = serialize_order_terms(&OrderTerms {
            market_id: req.market_id,
            side,
            size,
            limit_price: limit,
            tif,
            reduce_only: req.reduce_only,
            nonce,
        });
        self.order_log
            .append(&order.ciphertext_commit, &canonical, rand::rngs::OsRng);
        let r = &signed.receipt;
        let receipt = WReceipt {
            order_hash: hex0x(&r.order_hash),
            seq_no: r.seq_no,
            recv_time_ms: r.recv_time_ms,
            batch_id_hint: r.batch_id_hint,
            window_id: r.window_id,
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
            return Err(
                "Only an ACCEPTED order can be cancelled (matched/settled are binding).".into(),
            );
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
            let coll = self
                .seq
                .state
                .position(owner, m.id)
                .map(|p| p.collateral)
                .unwrap_or(0);
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
    /// Owner (hex) for an API key, for authenticating a /v1/ws connection.
    fn owner_hex_for(&self, key: &[u8; 32]) -> Option<String> {
        self.accounts.get(key).map(|a| hex0x(&a.wallet.owner))
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
        let ms: Vec<_> = self
            .mkts
            .iter()
            .map(|m| serde_json::to_value(self.wmarket(m)).unwrap())
            .collect();
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
            "treasury": self.seq.state.treasury.to_string(),
            "nextBatchId": self.seq.current_batch_id(),
            "openWindowId": self.seq.current_window_id(),
            "accounts": self.accounts.len(),
        })
    }
    /// Reconcile a per-tick Counter-A batch id to its on-chain window (Counter B) + settle state.
    fn v1_batch_json(&self, tick_batch: u64) -> serde_json::Value {
        let window = self.seq.window_for_tick(tick_batch);
        let batch_count = self.l1_status.as_ref().map(|s| s.batch_count).unwrap_or(0);
        // window M has settled on-chain once batchCount has advanced past it.
        let settled = window.is_some_and(|m| m < batch_count);
        serde_json::json!({
            "counterA": tick_batch,
            "windowId": window,
            "settled": settled,
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

    /// Build the answer to an inclusion challenge for `order_hash` (audit DP-004): find the
    /// settled on-chain batch that committed it and build the Merkle proof against that batch's
    /// ordered root (matched) or rejected root (validly rejected). Returns
    /// `(is_rejection, batch_id, proof)`; `None` if no retained batch holds the order (a genuine
    /// withhold the sequencer cannot — and should not — answer).
    fn build_challenge_answer(&self, order_hash: &Digest) -> Option<(bool, u64, Vec<[u8; 32]>)> {
        for (&batch_id, (ordered, rejected)) in &self.batch_orders {
            if let Some(i) = ordered.iter().position(|h| h == order_hash) {
                let leaves: Vec<[u8; 32]> = ordered
                    .iter()
                    .map(|h| inclusion_leaf(batch_id, h))
                    .collect();
                return Some((false, batch_id, merkle_proof(&leaves, i)));
            }
            if let Some(i) = rejected.iter().position(|h| h == order_hash) {
                let leaves: Vec<[u8; 32]> = rejected
                    .iter()
                    .map(|h| rejection_leaf(batch_id, h))
                    .collect();
                return Some((true, batch_id, merkle_proof(&leaves, i)));
            }
        }
        None
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
            fund(
                &mut self.seq,
                &mut self.archive,
                &user,
                market,
                30_000,
                0x71u8.wrapping_add(bn),
            );
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

    /// Apply a LIVE oracle price (fetched from the real feed) to a market: update the
    /// mark, flag it `live` (the UI shows "live oracle"), and set the engine oracle.
    // ── LP pool (the MM wallet IS the pool; LPs own shares of its equity) ──────
    /// The pool's mark-to-market equity: the MM's free notes + every open MM
    /// position's collateral + uPnL. LP shares are priced against this.
    fn pool_equity(&self) -> i128 {
        let owner = self.mm.owner;
        let mut eq: i128 = self
            .seq
            .state
            .notes
            .values()
            .filter(|n| n.owner == owner)
            .map(|n| n.amount)
            .sum();
        for m in &self.mkts {
            if let Some(p) = self.seq.state.position(&owner, m.id) {
                eq += p.collateral + pnl(p.size, p.entry_price, m.px);
            }
        }
        eq
    }

    /// NAV per share (quote units / share). 1.0 at boot; rises as the pool earns the
    /// house edge (traders lose net), falls if traders win net.
    fn lp_nav(&self) -> f64 {
        if self.lp_total_shares == 0 {
            return 1.0;
        }
        self.pool_equity().max(0) as f64 / self.lp_total_shares as f64
    }

    /// Move `value` of market-0 capital from `from` to `to` as a conserved transfer
    /// (debit one, credit the other) — the engine has no native transfer, so this is
    /// Unbind+Withdraw on `from` (external_out) then Deposit+Fund on `to` (external_in),
    /// net-zero externally. `from` must have `value` free in market 0.
    fn pool_transfer(&mut self, from: &Wallet, to: &Wallet, value: i128) -> Result<(), String> {
        if value > self.market_free_of(&from.owner, 0) {
            return Err("Insufficient market-0 free balance.".into());
        }
        let now = now_ms();
        let oracle = oracle_of(self.px_of(0), now);
        let c = self.lp_counter;
        self.lp_counter += 1;
        let mut db = [0xE0u8; 32];
        db[..8].copy_from_slice(&c.to_le_bytes());
        self.seq
            .apply(&BatchOp::Unbind {
                owner: from.owner,
                market_id: 0,
                amount: value,
                blinding: db,
                oracle,
                now_ms: now,
            })
            .map_err(|e| format!("lp debit unbind: {e:?}"))?;
        let dn = Note::new(from.owner, 0, value, db);
        self.seq
            .apply(&BatchOp::Withdraw {
                note_commitment: dn.commitment::<Keccak256>(),
                spend_key: from.spend_key,
                // Internal burn: value is re-funded internally (fund_amount below),
                // never becomes an L1 vault claim, so it must NOT enter withdrawals_root.
                to: None,
                nonce: 0,
            })
            .map_err(|e| format!("lp debit burn: {e:?}"))?;
        let mut cb = [0xE1u8; 32];
        cb[..8].copy_from_slice(&c.to_le_bytes());
        fund_amount(&mut self.seq, &mut self.archive, to, 0, value, cb);
        Ok(())
    }

    /// Deposit `amount` into the LP pool. The depositor's OWN market-0 balance is
    /// debited and bound as pool capital (no free mint — shares represent real
    /// provided capital), then shares are minted at the live NAV.
    fn lp_deposit(
        &mut self,
        share_key: [u8; 32],
        depositor: &Wallet,
        amount: i128,
    ) -> Result<u128, String> {
        if amount <= 0 {
            return Err("Amount must be positive.".into());
        }
        if amount > self.market_free_of(&depositor.owner, 0) {
            return Err(
                "Insufficient market-0 balance — fund it before providing liquidity.".into(),
            );
        }
        let eq = self.pool_equity().max(1) as u128;
        let shares = if self.lp_total_shares == 0 {
            amount as u128
        } else {
            (amount as u128).saturating_mul(self.lp_total_shares) / eq
        };
        let mm = self.mm;
        self.pool_transfer(depositor, &mm, amount)?;
        self.lp_total_shares += shares;
        *self.lp_shares.entry(share_key).or_insert(0) += shares;
        Ok(shares)
    }

    /// Withdraw `shares` from the LP pool: pay out shares × NAV from the pool's
    /// market-0 capital straight into the withdrawer's OWN market-0 balance.
    fn lp_withdraw(
        &mut self,
        share_key: &[u8; 32],
        withdrawer: &Wallet,
        shares: u128,
    ) -> Result<i128, String> {
        let have = self.lp_shares.get(share_key).copied().unwrap_or(0);
        if shares == 0 || shares > have {
            return Err("Insufficient LP shares.".into());
        }
        let eq = self.pool_equity().max(0) as u128;
        let value = (eq.saturating_mul(shares) / self.lp_total_shares.max(1)) as i128;
        if value > self.market_free_of(&self.mm.owner, 0) {
            return Err("Pool's market-0 free capital can't cover this right now (open positions tie up margin).".into());
        }
        let mm = self.mm;
        self.pool_transfer(&mm, withdrawer, value)?;
        self.lp_total_shares -= shares;
        if let Some(s) = self.lp_shares.get_mut(share_key) {
            *s -= shares;
        }
        Ok(value)
    }

    /// Pool stats for the UI: TVL (equity), NAV/share, total shares, and the caller's
    /// own shares + current value.
    fn lp_json(&self, who: &[u8; 32]) -> serde_json::Value {
        let eq = self.pool_equity();
        let my_shares = self.lp_shares.get(who).copied().unwrap_or(0);
        let my_value =
            (eq.max(0) as f64 * (my_shares as f64 / self.lp_total_shares.max(1) as f64)) as i128;
        serde_json::json!({
            "tvl": eq.to_string(),
            "navPerShare": format!("{:.6}", self.lp_nav()),
            "totalShares": self.lp_total_shares.to_string(),
            "myShares": my_shares.to_string(),
            "myValue": my_value.to_string(),
        })
    }

    fn apply_real_oracle(&mut self, market: u64, transcript: OracleTranscript) {
        let now = now_ms();
        if let Some(m) = self.mkts.iter_mut().find(|m| m.id == market) {
            // Advance the freshness clock ONLY when the exchange's own timestamp advances
            // (recorded in local time): a frozen-but-200 feed and a dead/hung feed both
            // stop advancing px_ms and go stale, while the exchange clock's absolute
            // skew/lag never false-stalls a healthy feed (audit review of #7).
            let exch_ts = transcript.publish_time_ms;
            if exch_ts != m.feed_ts {
                m.feed_ts = exch_ts;
                m.px_ms = now;
            }
            m.px = transcript.price;
            m.live = true;
            // Keep the real confidence/backup_twap band, but stamp freshness from px_ms
            // so tick() need not re-stamp (which would mask a frozen feed forever).
            let mut t = transcript;
            t.publish_time_ms = m.px_ms;
            self.seq.set_oracle(market, t);
        } else {
            self.seq.set_oracle(market, transcript);
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
        self.seq
            .state
            .position(&self.user.owner, market)
            .map(|p| p.collateral)
            .unwrap_or(0)
    }
    fn user_notes(&self) -> i128 {
        self.seq
            .state
            .notes
            .values()
            .filter(|n| n.owner == self.user.owner)
            .map(|n| n.amount)
            .sum()
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
        self.seq
            .state
            .position(&self.user.owner, market)
            .map(|p| p.size)
            .unwrap_or(0)
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
        // Legacy dev/demo plaintext ingress (this route is mounted only in the demo
        // build). It shares `OrderReq` — whose fields are `#[serde(default)]` for the
        // sealed wire — so it must enforce the SAME core-field presence as
        // `account_place_order`'s plaintext branch, or a partial body would silently
        // default into a real (wrong-direction) order. Tif is required for uniform
        // malformed-rejection even though this path always takes as Ioc below.
        require_core_order_fields(req)?;
        let size: i128 = req.size.parse().map_err(|_| "bad size".to_string())?;
        if size <= 0 {
            return Err("Size must be positive.".into());
        }
        let limit: i128 = req.limit_price.parse().unwrap_or(0);
        // Strict side parse: no silent `else → Sell` that could flip direction.
        let side = parse_side_strict(&req.side)?;
        if self.mkt(req.market_id).is_none() {
            return Err("Unknown market.".into());
        }
        let opening = self.is_opening(req.market_id, &req.side, size);
        if self.seq.state.mode == Mode::CloseOnly && opening {
            return Err(
                "System is in close-only mode — opening/increasing is blocked (§6).".into(),
            );
        }
        if req.reduce_only && opening {
            return Err("Reduce-only order would open or increase a position — rejected.".into());
        }
        let px = if limit > 0 {
            limit
        } else {
            self.px_of(req.market_id)
        };
        if opening {
            let need = required_margin(size, px);
            if need > self.market_free(req.market_id) {
                return Err("Insufficient free margin to open this position (§3).".into());
            }
        }

        let nonce = self.user_nonce;
        self.user_nonce += 1;
        // user is the taker (Ioc) — crosses the resting market-maker maker each seal.
        // Pass the RAW limit (0 = market) so the seal loop can tell a market order (fill
        // at the mark) from a caller-chosen limit and apply the off-market check to the
        // latter only (audit review #2/#5). `px` is only the margin-check price above.
        let order = mk_order(
            self.user.owner,
            req.market_id,
            side,
            size,
            limit,
            nonce,
            TimeInForce::Ioc,
            req.reduce_only,
        );
        let oh = order.order_hash::<Keccak256>();
        let now = now_ms();
        let signed = self.seq.accept_order(&order, now);
        let r = &signed.receipt;
        let receipt = WReceipt {
            order_hash: hex0x(&r.order_hash),
            seq_no: r.seq_no,
            recv_time_ms: r.recv_time_ms,
            batch_id_hint: r.batch_id_hint,
            window_id: r.window_id,
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
        fund_amount(
            &mut self.seq,
            &mut self.archive,
            &self.user,
            self.selected,
            amount,
            [blind; 32],
        );
        Ok(())
    }

    fn withdraw(&mut self, amount: i128) -> Result<(), String> {
        if amount <= 0 {
            return Err("Amount must be positive.".into());
        }
        if amount > self.market_free(self.selected) {
            return Err(
                "Not withdrawable: amount exceeds the SETTLED balance in this market (§3).".into(),
            );
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
            .apply(&BatchOp::Withdraw {
                note_commitment: cm,
                spend_key: self.user.spend_key,
                // Legacy demo withdraw: never pushed to pending_withdrawals, so it is
                // an internal burn and must NOT enter withdrawals_root.
                to: None,
                nonce: 0,
            })
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
            nonce: None,
            signature: None,
            ..Default::default()
        };
        self.place_order(&req)
    }

    fn cancel(&mut self, order_id: &str) -> Result<Vec<WEvent>, String> {
        let idx = self
            .orders
            .iter()
            .position(|o| o.id == order_id)
            .ok_or("Order not found.")?;
        if self.orders[idx].sealed || self.orders[idx].last_finality != "ACCEPTED" {
            return Err(
                "Only an ACCEPTED order can be cancelled (matched/settled are binding).".into(),
            );
        }
        self.orders.remove(idx);
        Ok(vec![WEvent {
            order_id: order_id.to_string(),
            kind: "CANCELLED".into(),
            message: "Order cancelled before matching".into(),
        }])
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
        // Derive the wallet and scan ONLY with its own view-key. Audit #3: we no longer
        // fall back to the gateway user's archive when the caller's view-key matches
        // nothing — that fallback returned the house account's note amounts to ANY caller
        // submitting a random seed (a confidentiality break). A non-matching seed now
        // correctly recovers nothing. (Follow-up: derive the view-key in the browser and
        // send only that, so the seed/spend-key never reach the server — needs frontend
        // keccak, which the UI does not yet ship.)
        let w = Wallet::from_seed(s);
        self.archive
            .scan(&w.view_x25519_secret())
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
    fn tick(&mut self) -> (Vec<WEvent>, Vec<String>) {
        self.tick += 1;
        let now = now_ms();
        // 1) oracle update. Markets with a LIVE feed keep the real transcript the
        //    oracle task last set (its publish time is the EXCHANGE's own timestamp,
        //    ≤ one fetch interval old). We deliberately do NOT re-stamp it fresh each
        //    tick — that would mask a frozen/dead feed forever; instead a stalled feed
        //    stops advancing the publish time and the §8 staleness gate trips (audit).
        //    Feed-less markets keep the simulated random walk.
        for i in 0..self.mkts.len() {
            if self.mkts[i].live {
                continue;
            }
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
        let pending: Vec<usize> = self
            .orders
            .iter()
            .enumerate()
            .filter(|(_, o)| !o.sealed)
            .map(|(i, _)| i)
            .collect();
        let mut seal: Vec<Order> = Vec::new();
        for &i in &pending {
            let uo = self.orders[i].order;
            let mark = self.px_of(uo.market_id);
            // Same off-market protection as the /v1 path: the house MM quotes at the mark,
            // and only counters a market order (limit 0 → matcher crosses at any price) or
            // a limit order whose price actually crosses the mark — so a demo taker can't
            // name an off-market price and mint an off-market entry against the house MM
            // (audit review #2). The taker order is pushed unchanged (hash-stable).
            let is_market = uo.limit_price == 0;
            let crosses = is_market
                || match uo.side {
                    Side::Buy => uo.limit_price >= mark,
                    Side::Sell => uo.limit_price <= mark,
                };
            if crosses {
                let opp = match uo.side {
                    Side::Buy => Side::Sell,
                    Side::Sell => Side::Buy,
                };
                let mmn = self.mm_nonce;
                self.mm_nonce += 1;
                seal.push(mk_order(
                    self.mm.owner,
                    uo.market_id,
                    opp,
                    uo.size,
                    mark,
                    mmn,
                    TimeInForce::Gtc,
                    false,
                ));
            }
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
                let uo = self.accounts[k].orders[i].order; // Order: Copy
                let mark = self.px_of(uo.market_id);
                // A market order carries limit_price == 0 (kept through admission); the
                // matcher treats it as crossing any price, so it fills at the MM's mark.
                // A limit order keeps the caller's own price for its crossing check. Either
                // way the taker order is pushed UNCHANGED so its seal-time order hash still
                // matches the one accept_order recorded at admission.
                let is_market = uo.limit_price == 0;
                if matches!(uo.tif, TimeInForce::Ioc | TimeInForce::Fok) {
                    // AUDIT (CRITICAL): the house MM quotes at the VALIDATED oracle mark,
                    // never at the taker's own limit, and only provides the counter-fill
                    // when a limit order's price actually crosses the mark (a market order
                    // always crosses). Otherwise a taker could name an off-market price (buy
                    // far below / sell far above the mark), mint an off-market entry against
                    // the fabricated MM, and drain the vault.
                    let crosses = is_market
                        || match uo.side {
                            Side::Buy => uo.limit_price >= mark,
                            Side::Sell => uo.limit_price <= mark,
                        };
                    if crosses {
                        let opp = match uo.side {
                            Side::Buy => Side::Sell,
                            Side::Sell => Side::Buy,
                        };
                        let mmn = self.mm_nonce;
                        self.mm_nonce += 1;
                        seal.push(mk_order(
                            self.mm.owner,
                            uo.market_id,
                            opp,
                            uo.size,
                            mark,
                            mmn,
                            TimeInForce::Gtc,
                            false,
                        ));
                    }
                }
                seal.push(uo);
                account_refs.push((*k, i));
            }
        }
        let sealed = self.seq.seal_batch(&seal, now);
        self.last_manifest = sealed.manifest_hash;
        // audit DP-004: accumulate this batch's matched + validly-rejected order hashes; at the
        // next L1 settle they become this on-chain batch's ordered/rejected roots, so the
        // sequencer can answer an inclusion challenge for either instead of being wrongfully slashed.
        self.pending_ordered
            .extend(sealed.manifest.ordered.iter().copied());
        self.pending_rejected
            .extend(sealed.manifest.rejected.iter().map(|(h, _)| *h));
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
        // Task 5: the SETTLE_TICKS queue is the LEGACY (demo/no-prover) finality
        // simulation. In window-settle mode SETTLED is earned by the real on-chain
        // settle (`commit_window_settle` → `mark_window_settled`), so neither feed
        // nor drain the queue — a tick-count simulation would report SETTLED while
        // the Groth16 proof is still proving (or wedged).
        if any_sealed && !self.window_settle_mode {
            self.pending_settle.push((sealed.batch_id, self.tick));
        }

        // 3) settle batches older than SETTLE_TICKS (MATCHED → SETTLED) — legacy only.
        if !self.window_settle_mode {
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
        }

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
                events.push(WEvent {
                    order_id: o.id.clone(),
                    kind: f.to_string(),
                    message: msg.to_string(),
                });
            }
        }
        // advance /v1 account orders' finality + collect per-account events for the
        // authenticated WS (own fills, order-finality transitions, ADL haircuts).
        let mut acct_events: Vec<String> = Vec::new();
        for acct in self.accounts.values_mut() {
            let owner_hex = hex0x(&acct.wallet.owner);
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
                        acct_events.push(
                            serde_json::json!({
                                "owner": owner_hex, "type": "fill", "orderId": o.id,
                                "marketId": o.order.market_id, "side": o.input.side,
                                "size": o.input.size, "price": o.order.limit_price.to_string(),
                            })
                            .to_string(),
                        );
                    }
                    acct_events.push(
                        serde_json::json!({
                            "owner": owner_hex, "type": "order", "orderId": o.id,
                            "finality": f, "marketId": o.order.market_id,
                        })
                        .to_string(),
                    );
                }
            }
            // per-account ADL: the account recognizes its own secret-keyed receipt
            let tag_key = adl_tag_key(&acct.wallet.spend_key);
            let mut clawed = 0i128;
            for m in &self.mkts {
                let tag = adl_tag(&tag_key, m.id, sealed.batch_id);
                for r in &sealed.adl_receipts {
                    if r.tag == tag {
                        clawed += r.clawed;
                    }
                }
            }
            if clawed > 0 {
                acct_events.push(
                    serde_json::json!({
                        "owner": owner_hex, "type": "adl", "clawed": (clawed / QUOTE_SCALE).to_string(),
                    })
                    .to_string(),
                );
            }
            // audit Tier-3: bound the retained order history so it (and every snapshot)
            // can't grow without limit. Runs AFTER the seal/finality passes above (which
            // reference orders by index), and only evicts SETTLED (terminal, display-only)
            // orders — live/pending orders and the account's replay nonce are untouched.
            cap_history(&mut acct.orders, MAX_ACCOUNT_ORDER_HISTORY, |o| {
                o.last_finality == "SETTLED"
            });
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
        (events, acct_events)
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
        let levels = [
            (0i128, SIZE_SCALE / 2),
            (2, SIZE_SCALE),
            (8, 2 * SIZE_SCALE),
            (16, 3 * SIZE_SCALE),
        ];
        for (mult, sz) in levels {
            bids.push(WLevel {
                price: (mid - 2 * step - mult * step).to_string(),
                size: sz.to_string(),
            });
            asks.push(WLevel {
                price: (mid + 2 * step + mult * step).to_string(),
                size: sz.to_string(),
            });
        }
        WBook {
            market_id: market,
            bids,
            asks,
        }
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
                    window_id: self.seq.window_for_tick(bid),
                    order_count: os.len(),
                    manifest_hash: pseudo_hash(&format!("manifest:{hashes}")),
                    ordered_root: pseudo_hash(&format!("ordered:{hashes}")),
                    finality: fin,
                    sealed_ms,
                }
            })
            .collect();
        batches.sort_by_key(|b| std::cmp::Reverse(b.batch_id));

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
            mode: if self.seq.state.mode == Mode::CloseOnly {
                "CloseOnly".into()
            } else {
                "Normal".into()
            },
            oracle: WOracle {
                market_id: sel,
                price: sel_mkt.px.to_string(),
                confidence: (sel_mkt.px / 1000).max(1).to_string(),
                publish_time_ms: now_ms(),
            },
            book: self.book_around(sel, sel_mkt.px),
            marks,
            account: WAccount {
                settled_balance: self.free_balance().to_string(),
                positions,
            },
            orders,
            batches,
            insurance_fund: self.seq.state.insurance_fund.to_string(),
            treasury: self.seq.state.treasury.to_string(),
            user_adl_clawed: self.user_adl_clawed.to_string(),
            mm_hedge,
            l1: self.l1_status.as_ref().map(|s| WL1 {
                settled_root: s.settled_root.clone(),
                batch_count: s.batch_count,
                last_tx: s.last_tx.clone(),
                bond_usdc: s.bond.clone(),
                withdrawals_root: s.withdrawals_root.clone(),
            }),
            attestation: self.attestation.as_ref().map(|a| WAttestation {
                measurement: hex0x(&a.measurement),
                tcb: a.tcb.clone(),
                quote_version: a.quote_version,
            }),
            lp: {
                let eq = self.pool_equity();
                let my_shares = self.lp_shares.get(&self.user.owner).copied().unwrap_or(0);
                let my_value = (eq.max(0) as f64
                    * (my_shares as f64 / self.lp_total_shares.max(1) as f64))
                    as i128;
                WLp {
                    tvl: eq.to_string(),
                    nav_per_share: format!("{:.6}", self.lp_nav()),
                    total_shares: self.lp_total_shares.to_string(),
                    my_shares: my_shares.to_string(),
                    my_value: my_value.to_string(),
                }
            },
        }
    }
}

/// Deposit `usd_amount` (whole USD) and fund it into a market's collateral bucket.
fn fund(
    seq: &mut Sequencer,
    archive: &mut NoteArchive,
    w: &Wallet,
    market: u64,
    usd_amount: i128,
    blind: u8,
) {
    fund_amount(
        seq,
        archive,
        w,
        market,
        usd_amount * QUOTE_SCALE,
        [blind; 32],
    );
}
/// Deposit a quote-scaled `amount` as a note, archive it, and fund the position.
fn fund_amount(
    seq: &mut Sequencer,
    archive: &mut NoteArchive,
    w: &Wallet,
    market: u64,
    amount: i128,
    blind: Digest,
) {
    let note = Note::new(w.owner, 0, amount, blind);
    let cm = note.commitment::<Keccak256>();
    seq.apply(&BatchOp::Deposit {
        owner: w.owner,
        asset_id: 0,
        amount,
        blinding: blind,
    })
    .expect("deposit");
    // Seal to the owner's X25519 viewing PUBLIC key (real note encryption); the
    // recorder needs no decryption capability. OsRng: fresh ephemeral + nonce.
    archive.record(
        seq.current_batch_id(),
        &note,
        &w.view_x25519_public(),
        rand::rngs::OsRng,
    );
    seq.apply(&BatchOp::FundPosition {
        owner: w.owner,
        market_id: market,
        note_commitment: cm,
        spend_key: w.spend_key,
    })
    .expect("fund");
}

// ── HTTP/WS plumbing ─────────────────────────────────────────────────────────
type Shared = Arc<App>;
struct App {
    gw: Mutex<Gw>,
    tx: broadcast::Sender<String>,
    /// Per-account event stream (own fills, order finality, ADL) — each JSON carries
    /// an `owner` field; the authenticated /v1/ws filters by it.
    events_tx: broadcast::Sender<String>,
    /// Per-IP registration counter (a sliding 60s window) to throttle account spam.
    reg_limit: Mutex<HashMap<IpAddr, (u64, u32)>>,
    /// The L1 bridge (Base Sepolia), if configured — used by the deposit-confirm
    /// handler to verify on-chain USDC deposits. `None` ⇒ pure in-memory mode.
    l1: Option<L1>,
    /// Slice 3b-2a: the settle path's prover client (None ⇒ legacy cumulative+mock path).
    prover: Option<std::sync::Arc<dyn prover_client::ProverClient>>,
    /// REAL per-market price history (the chart's past bars): the engine's own
    /// marks folded into per-timeframe OHLC rings each tick, plus a one-shot
    /// exchange backfill for feed-backed markets at boot. Display data — not
    /// part of the sealed snapshot (see `candles.rs`).
    candles: Mutex<candles::CandleStore>,
}

impl App {
    async fn broadcast(&self, gw: &Gw) {
        let msg = WsMsg::State {
            state: gw.snapshot(),
        };
        let _ = self.tx.send(serde_json::to_string(&msg).unwrap());
    }
    async fn broadcast_event(&self, ev: WEvent) {
        let _ = self
            .tx
            .send(serde_json::to_string(&WsMsg::Event { event: ev }).unwrap());
    }
}

fn err400(msg: String) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
}

// ── multi-tenant external API (/v1) ──────────────────────────────────────────
#[derive(Deserialize)]
struct V1DepositReq {
    #[serde(rename = "marketId")]
    market_id: u64,
    amount: String,
}
#[derive(Deserialize)]
struct DepositAddrReq {
    address: String,
    /// secp256k1 signature (65-byte r‖s‖v) proving the caller controls `address`.
    /// Accepted over any of three shapes of `deposit_bind_digest(owner, address)`:
    /// the raw digest, EIP-191 `personal_sign` over its 32 bytes, or EIP-191 over
    /// its "0x<64 hex>" string — see `deposit_bind_prehash_candidates`.
    signature: String,
}
#[derive(Deserialize)]
struct OnchainDepositReq {
    #[serde(rename = "txHash")]
    tx_hash: String,
    #[serde(rename = "marketId")]
    market_id: u64,
}
#[derive(Deserialize)]
struct WithdrawReq {
    #[serde(rename = "marketId")]
    market_id: u64,
    amount: String,
    to: String,
}

/// One hex nibble, byte-safe: `None` for anything outside `[0-9a-fA-F]` —
/// including every byte of a multi-byte UTF-8 codepoint (all >= 0x80).
pub(crate) fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Byte-safe fixed-length hex parse: `0x`-optional, exactly `N` bytes. Operates on
/// BYTES (same posture as `decode_hex`): these strings arrive in attacker-controlled
/// request JSON (api keys, deposit txHash/address, order signatures), so a
/// non-ASCII codepoint must yield a clean `None` — never the mid-codepoint `&str`
/// slice panic the old `&h[i*2..i*2+2]` loops had.
fn parse_hex_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    let h = s.strip_prefix("0x").unwrap_or(s).as_bytes();
    if h.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = hex_nibble(h[i * 2])? << 4 | hex_nibble(h[i * 2 + 1])?;
    }
    Some(out)
}

/// Parse a `0x`-optional 64-hex string into a 32-byte key.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    parse_hex_exact::<32>(s)
}

/// Parse a `0x`-optional 40-hex string into a 20-byte Ethereum address.
fn parse_addr20_hex(s: &str) -> Option<[u8; 20]> {
    parse_hex_exact::<20>(s)
}

/// Parse a `0x`-optional 130-hex string into a 65-byte secp256k1 signature (r‖s‖v).
fn parse_hex65(s: &str) -> Option<[u8; 65]> {
    parse_hex_exact::<65>(s)
}

/// Recover the 20-byte Ethereum address that signed `prehash` with `sig` (r‖s‖v),
/// exactly as the contract's `ecrecover` would — so a caller-signed order is
/// authenticated identically off-chain and on-chain.
fn recover_eth_address(prehash: &[u8; 32], sig: &[u8; 65]) -> Option<[u8; 20]> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let s = Signature::from_slice(&sig[..64]).ok()?;
    let v = sig[64];
    let recid_byte = if v >= 27 { v - 27 } else { v };
    let recid = RecoveryId::from_byte(recid_byte)?;
    let vk = VerifyingKey::recover_from_prehash(prehash, &s, recid).ok()?;
    let point = vk.to_encoded_point(false);
    let hash = RawKeccak::digest(&point.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&hash[12..]);
    Some(a)
}

/// The digest a deposit-address bind signature must cover: `keccak256("dark-perp:
/// bind-deposit:" ‖ owner ‖ addr)`. Binding the account owner stops the proof being
/// replayed to bind the same address to a different account.
fn deposit_bind_digest(owner: &PubKey, addr: &[u8; 20]) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let mut h = RawKeccak::new();
    h.update(b"dark-perp:bind-deposit:");
    h.update(owner);
    h.update(addr);
    h.finalize().into()
}

/// The three prehashes a deposit-address bind signature may cover, in the order
/// they are tried. SECURITY INVARIANT: every candidate is a deterministic
/// transform of the SAME `deposit_bind_digest(owner, addr)` — no attacker-chosen
/// message ever enters a preimage — so accepting any of them leaves the
/// authorization semantics unchanged: a valid signature still proves the signer
/// controls `addr` and consented to binding it to exactly this `owner`.
fn deposit_bind_prehash_candidates(digest: &[u8; 32]) -> [[u8; 32]; 3] {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    // (a) The raw digest itself. WHY: CLI signers (`cast wallet sign --no-hash`)
    //     sign the 32 digest bytes directly — the original form, kept byte-identical.
    let raw = *digest;
    // (b) EIP-191 `personal_sign` over the 32 raw digest bytes:
    //     keccak256("\x19Ethereum Signed Message:\n32" ‖ digest). WHY: browser
    //     wallets (MetaMask etc.) refuse to sign raw digests — `personal_sign`
    //     always prepends the EIP-191 prefix + decimal byte-length before hashing.
    //     This is what the wallet-connect frontend produces when it passes the
    //     32 digest bytes to `personal_sign`.
    let eip191_raw: [u8; 32] = {
        let mut h = RawKeccak::new();
        h.update(b"\x19Ethereum Signed Message:\n32");
        h.update(digest);
        h.finalize().into()
    };
    // (c) EIP-191 over the ASCII hex STRING of the digest:
    //     keccak256("\x19Ethereum Signed Message:\n66" ‖ "0x<64 lowercase hex>")
    //     (66 = len("0x") + 64 hex chars). WHY: some wallets treat a hex-string
    //     `personal_sign` argument as text and sign its UTF-8 bytes instead of
    //     decoding them to the 32 raw bytes.
    let eip191_hex: [u8; 32] = {
        let mut hex = [0u8; 66];
        hex[0] = b'0';
        hex[1] = b'x';
        const TAB: &[u8; 16] = b"0123456789abcdef";
        for (i, b) in digest.iter().enumerate() {
            hex[2 + i * 2] = TAB[(b >> 4) as usize];
            hex[3 + i * 2] = TAB[(b & 0x0f) as usize];
        }
        let mut h = RawKeccak::new();
        h.update(b"\x19Ethereum Signed Message:\n66");
        h.update(hex);
        h.finalize().into()
    };
    [raw, eip191_raw, eip191_hex]
}

/// Canonicalize a tx hash to `0x` + 64 **lowercase** hex, or `None` if malformed.
/// Ethereum tx hashes are not checksummed, so case-permuted spellings denote the SAME
/// tx — dedup must key on this canonical form (review fix), and the strict hex check
/// also stops flag-injection into the positional `cast receipt <tx>` argument.
fn canon_tx_hash(s: &str) -> Option<String> {
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", h.to_ascii_lowercase()))
}

/// Authenticate a `/v1` request: read `X-Api-Key` (0x + 64 hex) → 32-byte key.
fn api_key_from(headers: &HeaderMap) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_hex32)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid X-Api-Key" })),
        ))
}

/// The client IP to rate-limit on. The gateway serves plain HTTP behind a
/// same-host reverse proxy (Caddy), so the raw TCP peer is the proxy's loopback
/// address — keying the limiter on it collapses every client into one bucket.
/// Trust `X-Forwarded-For` / `X-Real-IP` ONLY when the direct peer is loopback
/// (the trusted proxy); on a direct connection the peer IS the client and those
/// headers are attacker-spoofable. With one trusted hop the proxy appends the real
/// client to XFF, so the LAST parseable entry is the client as the proxy saw it.
fn client_ip(peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if peer.ip().is_loopback() {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|xff| {
                xff.split(',')
                    .rev()
                    .find_map(|s| s.trim().parse::<IpAddr>().ok())
            })
        {
            return ip;
        }
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

async fn post_v1_register(
    State(app): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // throttle registrations per real client IP (sliding 60s window)
    {
        let now = now_ms() / 1000;
        let ip = client_ip(addr, &headers);
        let mut reg = app.reg_limit.lock().await;
        let e = reg.entry(ip).or_insert((now, 0));
        if now.saturating_sub(e.0) >= 60 {
            *e = (now, 0);
        }
        if e.1 >= V1_REGISTER_RATE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "RATE_LIMIT: too many registrations from this IP" })),
            )
                .into_response();
        }
        e.1 += 1;
    }
    // optional body `{ "signer": "0x<40 hex>" }` → caller-signed account (every order
    // must carry the caller's signature). A bad signer value is rejected.
    let signer = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("signer").and_then(|s| s.as_str()).map(String::from))
        {
            Some(s) => match parse_addr20_hex(&s) {
                Some(a) => Some(a),
                None => {
                    return err400("bad signer address (expected 0x + 40 hex)".into())
                        .into_response()
                }
            },
            None => None,
        }
    };
    let (key, owner) = { app.gw.lock().await.register_account(signer) };
    Json(serde_json::json!({
        "apiKey": hex0x(&key),
        "owner": hex0x(&owner),
        "callerSigned": signer.is_some(),
    }))
    .into_response()
}

/// Bind the external EOA an account funds from, so its on-chain USDC deposits can be
/// attributed to it (and not stolen by another account submitting the same tx).
async fn post_v1_deposit_address(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<DepositAddrReq>,
) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let addr = match parse_addr20_hex(&req.address) {
        Some(a) => a,
        None => return err400("bad address (expected 0x + 40 hex)".into()).into_response(),
    };
    let sig = match parse_hex65(&req.signature) {
        Some(s) => s,
        None => {
            return err400("bad signature (expected 65-byte 0x hex r‖s‖v)".into()).into_response()
        }
    };
    match app
        .gw
        .lock()
        .await
        .account_set_deposit_address(&key, addr, &sig)
    {
        Ok(()) => Json(serde_json::json!({ "depositAddress": hex0x(&addr) })).into_response(),
        Err(e) => err400(e).into_response(),
    }
}

/// Credit a real on-chain USDC deposit: verify the `vault.deposit` tx via the L1
/// bridge, enforce the `from`==bound-address binding + tx dedup, and fund the engine.
async fn post_v1_deposit_onchain(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<OnchainDepositReq>,
) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let l1 = match &app.l1 {
        Some(l) => l.clone(),
        None => {
            return err400("L1 bridge not configured — on-chain deposits unavailable".into())
                .into_response()
        }
    };
    // canonicalize the tx hash so case-permuted spellings of the same tx can't bypass
    // the dedup (they all resolve to one receipt on-chain) — review fix.
    let tx = match canon_tx_hash(&req.tx_hash) {
        Some(t) => t,
        None => return err400("bad txHash (expected 0x + 64 hex)".into()).into_response(),
    };
    let txc = tx.clone();
    let verified = tokio::task::spawn_blocking(move || l1.verify_deposit_tx(&txc)).await;
    let (from, amount) = match verified {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return err400(format!("deposit not verified: {e}")).into_response(),
        Err(e) => return err400(format!("verify task failed: {e}")).into_response(),
    };
    let r = {
        app.gw
            .lock()
            .await
            .account_confirm_deposit(&key, from, amount, &tx, req.market_id)
    };
    match r {
        Ok(amt) => {
            let acct = {
                app.gw
                    .lock()
                    .await
                    .v1_account(&key)
                    .unwrap_or(serde_json::json!({}))
            };
            Json(serde_json::json!({ "credited": amt.to_string(), "account": acct }))
                .into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}

/// Withdraw USDC: debit the engine and record an authorized withdrawal. The user
/// then claims on Base Sepolia via `vault.claim` once the next settle publishes the
/// cumulative root (GET /v1/accounts/withdrawals returns the proof).
async fn post_v1_withdraw(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<WithdrawReq>,
) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let amount: i128 = match req.amount.parse() {
        Ok(v) => v,
        Err(_) => return err400("bad amount".into()).into_response(),
    };
    let to = match parse_addr20_hex(&req.to) {
        Some(a) => a,
        None => return err400("bad `to` address (expected 0x + 40 hex)".into()).into_response(),
    };
    let r = {
        app.gw
            .lock()
            .await
            .account_withdraw(&key, req.market_id, amount, to)
    };
    match r {
        Ok(w) => Json(serde_json::json!({
            "to": hex0x(&w.to),
            "amount": w.amount.to_string(),
            "nonce": w.nonce,
            "leaf": hex0x(&w.leaf()),
            "status": "recorded — claimable on Base Sepolia after the next L1 settle; GET /v1/accounts/withdrawals for the Merkle proof",
        }))
        .into_response(),
        Err(e) => err400(e).into_response(),
    }
}

/// An account's withdrawals + claim data (Merkle proofs once published on-chain).
async fn get_v1_withdrawals(State(app): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let vault = app.l1.as_ref().and_then(|l| l.vault.clone());
    let gw = app.gw.lock().await;
    match gw.v1_withdrawals_json(&key) {
        Some(mut v) => {
            if let Some(vault) = vault {
                v["vault"] = serde_json::json!(vault);
            }
            Json(v).into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unknown account" })),
        )
            .into_response(),
    }
}

/// LP pool stats + the account's own stake (authenticated).
async fn get_v1_lp(State(app): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    Json(app.gw.lock().await.lp_json(&key)).into_response()
}
/// LP deposit for an account: stake USDC into the counterparty pool → mint shares.
async fn post_v1_lp_deposit(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<AmountReq>,
) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let amount: i128 = match req.amount.parse() {
        Ok(v) => v,
        Err(_) => return err400("bad amount".into()).into_response(),
    };
    let r = {
        let mut gw = app.gw.lock().await;
        match gw.accounts.get(&key).map(|a| a.wallet) {
            Some(w) => gw.lp_deposit(key, &w, amount),
            None => Err("unknown account".into()),
        }
    };
    match r {
        Ok(shares) => {
            Json(serde_json::json!({ "sharesMinted": shares.to_string() })).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}
/// LP withdraw for an account: burn `shares` for their current pool value.
async fn post_v1_lp_withdraw(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<LpWithdrawReq>,
) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let shares: u128 = match req.shares.parse() {
        Ok(v) => v,
        Err(_) => return err400("bad shares".into()).into_response(),
    };
    let r = {
        let mut gw = app.gw.lock().await;
        match gw.accounts.get(&key).map(|a| a.wallet) {
            Some(w) => gw.lp_withdraw(&key, &w, shares),
            None => Err("unknown account".into()),
        }
    };
    match r {
        Ok(value) => {
            Json(serde_json::json!({ "withdrawnValue": value.to_string() })).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}
async fn get_v1_account(State(app): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    match app.gw.lock().await.v1_account(&key) {
        Some(v) => Json(v).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unknown account" })),
        )
            .into_response(),
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
    let r = {
        app.gw
            .lock()
            .await
            .account_deposit(&key, req.market_id, amount)
    };
    match r {
        Ok(()) => Json(
            app.gw
                .lock()
                .await
                .v1_account(&key)
                .unwrap_or(serde_json::json!({})),
        )
        .into_response(),
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
        Err(e) if e.starts_with("RATE_LIMIT") => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
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
        Ok(()) => {
            Json(serde_json::json!({ "orderId": order_id, "cancelled": true })).into_response()
        }
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
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unknown account" })),
        )
            .into_response(),
    }
}
async fn get_v1_positions(State(app): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    match app.gw.lock().await.v1_positions_json(&key) {
        Some(v) => Json(v).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unknown account" })),
        )
            .into_response(),
    }
}
async fn get_v1_markets(State(app): State<Shared>) -> impl IntoResponse {
    Json(app.gw.lock().await.v1_markets_json())
}
async fn get_v1_market(State(app): State<Shared>, Path(id): Path<u64>) -> impl IntoResponse {
    let gw = app.gw.lock().await;
    match gw.mkt(id) {
        Some(m) => Json(serde_json::to_value(gw.wmarket(m)).unwrap()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown market" })),
        )
            .into_response(),
    }
}
async fn get_v1_orderbook(State(app): State<Shared>, Path(id): Path<u64>) -> impl IntoResponse {
    match app.gw.lock().await.v1_orderbook_json(id) {
        Some(v) => Json(v).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown market" })),
        )
            .into_response(),
    }
}
async fn get_v1_oracle(State(app): State<Shared>, Path(id): Path<u64>) -> impl IntoResponse {
    match app.gw.lock().await.v1_oracle_json(id) {
        Some(v) => Json(v).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown market" })),
        )
            .into_response(),
    }
}
/// `GET /v1/markets/:id/candles?tf=15m&limit=120` — the REAL price history the
/// engine marked against (see `candles.rs`): live-recorded OHLC bars, exchange-
/// backfilled at boot for feed markets. Prices are `1e8`-scaled decimal strings
/// like every other wire amount; `t` is the bucket start in unix ms.
async fn get_v1_candles(
    State(app): State<Shared>,
    Path(id): Path<u64>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let tf = q.get("tf").map(String::as_str).unwrap_or("15m");
    if candles::tf_index(tf).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("unknown timeframe (valid: {})",
                    candles::TFS.iter().map(|(n, _, _)| *n).collect::<Vec<_>>().join(", "))
            })),
        )
            .into_response();
    }
    if app.gw.lock().await.mkt(id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown market" })),
        )
            .into_response();
    }
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(120)
        .min(candles::CAP);
    let bars = app
        .candles
        .lock()
        .await
        .get(id, tf, limit)
        .unwrap_or_default();
    let out: Vec<serde_json::Value> = bars
        .iter()
        .map(|c| {
            serde_json::json!({
                "t": c.start_ms,
                "o": c.open.to_string(),
                "h": c.high.to_string(),
                "l": c.low.to_string(),
                "c": c.close.to_string(),
            })
        })
        .collect();
    Json(serde_json::json!({ "marketId": id, "tf": tf, "candles": out })).into_response()
}
async fn get_v1_status(State(app): State<Shared>) -> impl IntoResponse {
    Json(app.gw.lock().await.v1_status_json())
}
async fn get_v1_batch(State(app): State<Shared>, Path(id): Path<u64>) -> impl IntoResponse {
    Json(app.gw.lock().await.v1_batch_json(id))
}
/// Publish the enclave's current order-ingress X25519 epoch public key, SIGNED by
/// the enclave's secp256k1 identity and bound to the attested `measurement` (§5.1).
///
/// A client (Task 11) seals an order to `x25519Pub` after verifying `sig` recovers
/// to the enclave's pinned signer AND `measurement` equals the pinned attestation
/// measurement — proving the key belongs to the real attested enclave, not a MITM.
/// The signed digest layout is [`enclave_epoch::epoch_signing_digest`] (a
/// cross-component contract). `sig` is 65 bytes `r‖s‖v` (v in 27/28 convention).
async fn get_v1_enclave_epoch(State(app): State<Shared>) -> impl IntoResponse {
    let gw = app.gw.lock().await;
    let ek = gw.epochs.current();
    let measurement = gw.seq.enclave().measurement;
    let digest = enclave_epoch::epoch_signing_digest(ek.epoch_id, &ek.public, ek.not_after_ms);
    // Reuse the REAL enclave secp256k1 identity (the receipt signer) — no new key.
    let (r, s, v) = gw.seq.enclave().sign_prehash(&digest);
    let mut sig = [0u8; 65];
    sig[..32].copy_from_slice(&r);
    sig[32..64].copy_from_slice(&s);
    sig[64] = v;
    Json(serde_json::json!({
        "epochId": ek.epoch_id,
        "x25519Pub": hex0x(&ek.public),
        "notAfterMs": ek.not_after_ms,
        "measurement": hex0x(&measurement),
        "sig": hex0x(&sig),
    }))
}
/// Machine-readable OpenAPI 3.1 spec for the /v1 API, so bots/tools can codegen a
/// client. Hand-authored + compact; the prose reference is docs/API.md.
async fn get_v1_openapi() -> impl IntoResponse {
    let auth = serde_json::json!({ "security": [{ "ApiKey": [] }] });
    let ok = |desc: &str| serde_json::json!({ "200": { "description": desc } });
    let order_body = serde_json::json!({
        "required": true,
        "content": { "application/json": { "schema": { "type": "object",
            "description": "Two ingress forms. SEALED (production; the only form prod accepts): send ONLY { epochId, sealed } — the canonical 51-byte order terms encrypted to the enclave's order-epoch X25519 key from GET /v1/enclave/epoch; the plaintext fields are ignored. PLAINTEXT (dev/demo only): send marketId/side/size/limitPrice/tif/reduceOnly.",
            "properties": {
                "marketId": { "type": "integer", "description": "plaintext (dev) ingress; ignored when `sealed` is present" },
                "side": { "type": "string", "enum": ["Buy","Sell"], "description": "plaintext (dev) ingress" },
                "size": { "type": "string", "description": "size-scaled (*1e8) integer; plaintext (dev) ingress" },
                "limitPrice": { "type": "string", "description": "price-scaled (*1e8); 0 = market; plaintext (dev) ingress" },
                "tif": { "type": "string", "enum": ["Gtc","Ioc","Fok","PostOnly"], "description": "plaintext (dev) ingress" },
                "reduceOnly": { "type": "boolean", "description": "plaintext (dev) ingress" },
                "nonce": { "type": "integer", "description": "caller-signed accounts: strictly-increasing order nonce (sealed orders carry the nonce INSIDE the sealed terms; it must strictly increase per account)" },
                "signature": { "type": "string", "description": "caller-signed accounts: 65-byte secp256k1 sig over the order hash" },
                "epochId": { "type": "integer", "description": "sealed ingress: the enclave order-epoch the terms were sealed to (required with `sealed`)" },
                "sealed": { "type": "string", "description": "sealed ingress: 0x-hex sealed-box wire (0x01 ‖ epk32 ‖ nonce24 ‖ ct‖tag) over the canonical order terms, AAD = OrderEncryptAad ‖ epochId(u64 LE) ‖ owner" }
            } } } }
    });
    Json(serde_json::json!({
        "openapi": "3.1.0",
        "info": { "title": "dark-perp external API", "version": "1", "description": "Multi-tenant trading over the sequencer engine. Amounts are decimal strings of scaled integers (quote *1e6, size/price *1e8). See docs/API.md." },
        "components": { "securitySchemes": { "ApiKey": { "type": "apiKey", "in": "header", "name": "X-Api-Key" } } },
        "paths": {
            "/v1/accounts": { "post": { "summary": "Register an account (optional { signer } for caller-signed)", "responses": ok("apiKey + owner + callerSigned") } },
            "/v1/accounts/me": { "get": { "summary": "Own account (balance, positions, nextNonce)", "responses": ok("account"), "security": auth["security"] } },
            "/v1/accounts/deposit": { "post": { "summary": "Deposit collateral (demo/in-memory credit)", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["marketId","amount"], "properties": { "marketId": { "type": "integer" }, "amount": { "type": "string" } } } } } },
                "responses": ok("updated account") } },
            "/v1/accounts/deposit/address": { "post": { "summary": "Bind the external EOA you fund USDC from (ownership-proven)", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["address","signature"], "properties": { "address": { "type": "string" }, "signature": { "type": "string", "description": "secp256k1 sig recovering to address over the bind digest keccak256(\"dark-perp:bind-deposit:\"‖owner‖address) — raw, or EIP-191 personal_sign over its 32 bytes or its 0x-hex string" } } } } } },
                "responses": ok("bound address") } },
            "/v1/accounts/deposit/onchain": { "post": { "summary": "Credit a real on-chain USDC deposit by tx hash", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["txHash","marketId"], "properties": { "txHash": { "type": "string" }, "marketId": { "type": "integer" } } } } } },
                "responses": ok("credited + account") } },
            "/v1/accounts/withdraw": { "post": { "summary": "Withdraw USDC (record an authorized withdrawal)", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["marketId","amount","to"], "properties": { "marketId": { "type": "integer" }, "amount": { "type": "string" }, "to": { "type": "string" } } } } } },
                "responses": ok("recorded withdrawal + leaf") } },
            "/v1/accounts/withdrawals": { "get": { "summary": "Own withdrawals + claim proofs", "security": auth["security"], "responses": ok("vault + withdrawals[]") } },
            "/v1/orders": {
                "post": { "summary": "Place an order", "security": auth["security"], "requestBody": order_body, "responses": { "200": { "description": "signed receipt" }, "400": { "description": "rejected" }, "429": { "description": "rate limit (10/s)" } } },
                "get": { "summary": "Own orders + finality", "security": auth["security"], "responses": ok("orders") }
            },
            "/v1/orders/{orderId}": { "delete": { "summary": "Cancel an ACCEPTED order", "security": auth["security"], "parameters": [{ "name": "orderId", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": ok("cancelled") } },
            "/v1/positions": { "get": { "summary": "Own open positions", "security": auth["security"], "responses": ok("positions") } },
            "/v1/markets": { "get": { "summary": "All markets", "responses": ok("markets") } },
            "/v1/markets/{id}": { "get": { "summary": "One market", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }], "responses": ok("market") } },
            "/v1/markets/{id}/orderbook": { "get": { "summary": "Order book", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }], "responses": ok("book") } },
            "/v1/markets/{id}/candles": { "get": { "summary": "REAL price history (engine marks; exchange-backfilled for feed markets)", "parameters": [
                { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } },
                { "name": "tf", "in": "query", "schema": { "type": "string", "enum": ["1m","5m","15m","1h","4h","1d"], "default": "15m" } },
                { "name": "limit", "in": "query", "schema": { "type": "integer", "default": 120, "maximum": 240 } }
            ], "responses": ok("candles[] of { t, o, h, l, c } (1e8-scaled strings)") } },
            "/v1/markets/{id}/oracle": { "get": { "summary": "Oracle price", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }], "responses": ok("oracle") } },
            "/v1/enclave/epoch": { "get": { "summary": "Enclave order-ingress epoch key (X25519), signed by the enclave's secp256k1 identity — verify `sig` recovers to the pinned enclave signer before sealing orders to `x25519Pub`", "responses": ok("{ epochId, x25519Pub, notAfterMs, measurement, sig }") } },
            "/v1/system/status": { "get": { "summary": "System status", "responses": ok("status") } }
        }
    }))
}
async fn ws_v1_handler(State(app): State<Shared>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_v1_loop(socket, app))
}
/// `/v1/ws`: public live-market snapshots every tick, PLUS — after the client sends
/// `{"type":"auth","apiKey":"0x.."}` — that account's own events (fills, order
/// finality, ADL haircuts). Events are filtered to the authenticated owner; an
/// unauthenticated connection sees only public market data.
async fn ws_v1_loop(mut socket: WebSocket, app: Shared) {
    let mut ticks = app.tx.subscribe();
    let mut accts = app.events_tx.subscribe();
    let mut auth_owner: Option<String> = None;
    let initial = { serde_json::to_string(&app.gw.lock().await.v1_public_json()).unwrap() };
    if socket.send(Message::Text(initial)).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            client = socket.recv() => {
                match client {
                    Some(Ok(Message::Text(txt))) => {
                        let v: serde_json::Value = match serde_json::from_str(&txt) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        if v.get("type").and_then(|t| t.as_str()) == Some("auth") {
                            let key = v.get("apiKey").and_then(|a| a.as_str()).and_then(parse_hex32);
                            let owner = match key {
                                Some(k) => app.gw.lock().await.owner_hex_for(&k),
                                None => None,
                            };
                            let reply = match &owner {
                                Some(o) => serde_json::json!({ "type": "authOk", "owner": o }),
                                None => serde_json::json!({ "type": "error", "message": "unknown api key" }),
                            };
                            auth_owner = owner;
                            if socket.send(Message::Text(reply.to_string())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => break,
                }
            }
            tick = ticks.recv() => {
                if tick.is_err() { continue; }
                let msg = { serde_json::to_string(&app.gw.lock().await.v1_public_json()).unwrap() };
                if socket.send(Message::Text(msg)).await.is_err() { break; }
            }
            ev = accts.recv() => {
                let Ok(json) = ev else { continue; };
                if let Some(owner) = &auth_owner {
                    let is_mine = serde_json::from_str::<serde_json::Value>(&json)
                        .ok()
                        .and_then(|v| v.get("owner").and_then(|o| o.as_str()).map(|s| s == owner))
                        .unwrap_or(false);
                    if is_mine && socket.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
            }
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
            let _ = app
                .tx
                .send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
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

/// Demo-user LP deposit into the counterparty pool: mints shares of the pool equity.
async fn post_lp_deposit(
    State(app): State<Shared>,
    Json(req): Json<AmountReq>,
) -> impl IntoResponse {
    let amount: i128 = match req.amount.parse() {
        Ok(v) => v,
        Err(_) => return err400("bad amount".into()).into_response(),
    };
    let r = {
        let mut gw = app.gw.lock().await;
        let who = gw.user.owner;
        let w = gw.user;
        gw.lp_deposit(who, &w, amount)
    };
    match r {
        Ok(shares) => {
            let gw = app.gw.lock().await;
            app.broadcast(&gw).await;
            Json(serde_json::json!({ "sharesMinted": shares.to_string() })).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}

#[derive(Deserialize)]
struct LpWithdrawReq {
    shares: String,
}
/// Demo-user LP withdraw: burns `shares` for their current value out of the pool.
async fn post_lp_withdraw(
    State(app): State<Shared>,
    Json(req): Json<LpWithdrawReq>,
) -> impl IntoResponse {
    let shares: u128 = match req.shares.parse() {
        Ok(v) => v,
        Err(_) => return err400("bad shares".into()).into_response(),
    };
    let r = {
        let mut gw = app.gw.lock().await;
        let who = gw.user.owner;
        let w = gw.user;
        gw.lp_withdraw(&who, &w, shares)
    };
    match r {
        Ok(value) => {
            let gw = app.gw.lock().await;
            app.broadcast(&gw).await;
            Json(serde_json::json!({ "withdrawnValue": value.to_string() })).into_response()
        }
        Err(e) => err400(e).into_response(),
    }
}

async fn post_close(State(app): State<Shared>, Json(req): Json<MarketReq>) -> impl IntoResponse {
    let res = { app.gw.lock().await.close(req.market_id) };
    match res {
        Ok((_r, events)) => {
            let snap = { app.gw.lock().await.snapshot() };
            let _ = app
                .tx
                .send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
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
            let _ = app
                .tx
                .send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
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
            Json(serde_json::json!({ "clawed": (clawed / QUOTE_SCALE).to_string() }))
                .into_response()
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
    let initial = {
        serde_json::to_string(&WsMsg::State {
            state: app.gw.lock().await.snapshot(),
        })
        .unwrap()
    };
    if socket.send(Message::Text(initial)).await.is_err() {
        return;
    }
    while let Ok(msg) = rx.recv().await {
        if socket.send(Message::Text(msg)).await.is_err() {
            break;
        }
    }
}

/// Real-collateral / production posture. In this mode the gateway refuses
/// self-service (unbacked) deposits (audit DP-001) and does not mount the legacy
/// unauthenticated `/api/*` mutation routes (audit DP-010). Enabled whenever the L1
/// settlement bridge is configured (real USDC at stake) or forced via `DARKPERP_PROD=1`.
fn production_mode(l1_enabled: bool) -> bool {
    l1_enabled || std::env::var("DARKPERP_PROD").ok().as_deref() == Some("1")
}

/// Select the settle path's prover client from `PROVER_URL`.
/// unset/empty → legacy path (None); "mock" → in-process MockProverClient;
/// any URL → HttpProverClient (seal → POST /prove → real Groth16 proof).
fn prover_from_str(
    v: Option<&str>,
) -> Result<Option<std::sync::Arc<dyn prover_client::ProverClient>>, String> {
    match v {
        None | Some("") => Ok(None),
        Some("mock") => Ok(Some(std::sync::Arc::new(prover_client::MockProverClient))),
        Some(url) => Ok(Some(std::sync::Arc::new(prover_client::HttpProverClient::from_env(url)))),
    }
}

fn prover_from_env() -> Result<Option<std::sync::Arc<dyn prover_client::ProverClient>>, String> {
    prover_from_str(std::env::var("PROVER_URL").ok().as_deref())
}

/// Whether the gateway may boot given the attestation state. In production the enclave
/// identity must be bound to a verified TEE attestation — a missing/failed attestation
/// must fail closed rather than silently fall back to the stub measurement (audit DP-006).
/// The demo/dev build boots either way.
fn attestation_ok_for_mode(prod: bool, attested: bool) -> bool {
    attested || !prod
}

/// The enclave signing seed, and whether it is still the PUBLIC demo default. In
/// production the enclave key MUST be a secret (ENCLAVE_SEED, a 32-byte hex secp256k1
/// scalar): the demo default [7u8; 32] is a public constant, so anyone could reconstruct
/// it, forge an enclave-signed receipt for an unsequenced order, and slash the sequencer
/// bond via challengeInclusion + slashUnanswered (audit DP-006 follow-up).
/// The public demo signing seed — a well-known constant, so it must never seed a
/// production enclave identity regardless of HOW it is supplied.
const DEMO_ENCLAVE_SEED: [u8; 32] = [7u8; 32];

/// Resolve the enclave seed and whether it is the public demo default. `Err` distinguishes a
/// SET-but-malformed/invalid ENCLAVE_SEED (bad hex/length, or not a valid secp256k1 scalar)
/// from an UNSET one — so a mistyped secret is reported clearly instead of silently becoming
/// the demo constant (code-review follow-up). VALUE-based demo detection: the public constant
/// counts as "default" even when supplied via ENCLAVE_SEED (audit DP-006 review follow-up).
fn enclave_seed_from_env() -> Result<([u8; 32], bool), String> {
    match std::env::var("ENCLAVE_SEED") {
        Err(_) => Ok((DEMO_ENCLAVE_SEED, true)), // unset → the demo build's default
        Ok(s) => {
            let seed =
                parse_hex32(&s).ok_or("ENCLAVE_SEED is set but is not a 32-byte hex value")?;
            if !enclave_seed_is_valid(seed) {
                return Err("ENCLAVE_SEED is not a valid secp256k1 scalar \
                            (must be nonzero and below the curve order)"
                    .into());
            }
            Ok((seed, seed == DEMO_ENCLAVE_SEED))
        }
    }
}

/// Whether `seed` is a usable secp256k1 signing scalar (nonzero, below the curve order),
/// so a malformed ENCLAVE_SEED fails closed with a clear message instead of panicking deep
/// inside EnclaveIdentity::from_seed (audit DP-006 review follow-up).
fn enclave_seed_is_valid(seed: [u8; 32]) -> bool {
    k256::ecdsa::SigningKey::from_bytes((&seed).into()).is_ok()
}

/// Whether the gateway may boot given the enclave-seed provenance: production requires a
/// secret seed, not the public demo default (audit DP-006 follow-up).
fn enclave_seed_ok_for_mode(prod: bool, seed_is_secret: bool) -> bool {
    seed_is_secret || !prod
}

/// Whether the attested measurement satisfies the production pin policy. In production the
/// operator MUST pin the expected enclave measurement (ATTESTATION_EXPECTED_MEASUREMENT)
/// and the attested measurement MUST equal it — otherwise ANY valid TDX quote (a different
/// enclave's, or the in-repo test fixture's) would pass the mere presence check, so a
/// captured bundle can be replayed on a non-TEE box (audit DP-006 follow-up). Demo skips it.
fn measurement_matches_pin(prod: bool, attested: Option<[u8; 32]>, pin: Option<[u8; 32]>) -> bool {
    if !prod {
        return true;
    }
    match (attested, pin) {
        (Some(m), Some(p)) => m == p,
        // production requires BOTH a verified measurement AND an explicit pin
        _ => false,
    }
}

/// Assemble the HTTP router. In production mode the legacy, UNAUTHENTICATED `/api/*`
/// mutation routes are omitted (audit DP-010) — only the read-only demo state/websocket
/// and the API-key-authenticated `/v1` surface are exposed.
fn build_router(app: Shared, prod: bool) -> Router {
    let mut router = Router::new()
        .route("/api/state", get(get_state))
        .route("/ws", get(ws_handler));

    if !prod {
        // demo/dev build: the in-browser console drives these unauthenticated routes
        // against a single shared demo account. Omitted in production (audit DP-010).
        router = router
            .route("/api/order", post(post_order))
            .route("/api/deposit", post(post_deposit))
            .route("/api/withdraw", post(post_withdraw))
            .route("/api/lp/deposit", post(post_lp_deposit))
            .route("/api/lp/withdraw", post(post_lp_withdraw))
            .route("/api/close", post(post_close))
            .route("/api/cancel", post(post_cancel))
            .route("/api/mode", post(post_mode))
            .route("/api/simulate-adl", post(post_simulate_adl))
            .route("/api/select-market", post(post_select))
            .route("/api/recover", post(post_recover));
    }

    router
        // ── multi-tenant external API (/v1) ──
        .route("/v1/accounts", post(post_v1_register))
        .route("/v1/accounts/me", get(get_v1_account))
        .route("/v1/accounts/deposit", post(post_v1_deposit))
        .route(
            "/v1/accounts/deposit/address",
            post(post_v1_deposit_address),
        )
        .route(
            "/v1/accounts/deposit/onchain",
            post(post_v1_deposit_onchain),
        )
        .route("/v1/accounts/withdraw", post(post_v1_withdraw))
        .route("/v1/accounts/withdrawals", get(get_v1_withdrawals))
        .route("/v1/lp", get(get_v1_lp))
        .route("/v1/lp/deposit", post(post_v1_lp_deposit))
        .route("/v1/lp/withdraw", post(post_v1_lp_withdraw))
        .route("/v1/orders", post(post_v1_order).get(get_v1_orders))
        .route("/v1/orders/:order_id", delete(delete_v1_order))
        .route("/v1/positions", get(get_v1_positions))
        .route("/v1/markets", get(get_v1_markets))
        .route("/v1/markets/:id", get(get_v1_market))
        .route("/v1/markets/:id/orderbook", get(get_v1_orderbook))
        .route("/v1/markets/:id/candles", get(get_v1_candles))
        .route("/v1/markets/:id/oracle", get(get_v1_oracle))
        .route("/v1/system/status", get(get_v1_status))
        .route("/v1/batch/:id", get(get_v1_batch))
        .route("/v1/enclave/epoch", get(get_v1_enclave_epoch))
        .route("/v1/openapi.json", get(get_v1_openapi))
        .route("/v1/ws", get(ws_v1_handler))
        .layer(CorsLayer::permissive())
        .with_state(app)
}

#[tokio::main]
async fn main() {
    let (tx, _rx) = broadcast::channel::<String>(256);
    let (events_tx, _erx) = broadcast::channel::<String>(1024);
    let l1 = L1::from_env();
    let prover = match prover_from_env() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[prover] {e}");
            std::process::exit(1);
        }
    };
    if prover.is_some() {
        println!("[prover] window-settle path ON (PROVER_URL)");
    }
    let prod = production_mode(l1.is_some());
    if prod {
        println!(
            "[mode] production posture: self-service deposit + legacy /api mutation routes disabled"
        );
    }
    // audit DP-006 (+ review): resolve + validate the enclave seed BEFORE building the identity
    // in boot(), so a malformed/invalid ENCLAVE_SEED fails closed with a CLEAR message (not a
    // misleading "demo seed" one, and not a panic inside EnclaveIdentity::from_seed).
    let (enclave_seed, seed_is_default) = match enclave_seed_from_env() {
        Ok(x) => x,
        Err(e) => {
            eprintln!(
                "[enclave] REFUSING to start: {e}. Set ENCLAVE_SEED to a valid 32-byte hex \
                 secp256k1 scalar, or unset it for the demo build."
            );
            std::process::exit(1);
        }
    };
    if !enclave_seed_ok_for_mode(prod, !seed_is_default) {
        eprintln!(
            "[enclave] REFUSING to start in production with the public demo signing seed. \
             Set ENCLAVE_SEED to a secret 32-byte hex secp256k1 scalar, and set the settlement \
             contract's ENCLAVE_SIGNER to that key's address."
        );
        std::process::exit(1);
    }
    // Sealed state persistence: DARKPERP_STATE=<path> restores the engine across
    // restarts. A present-but-unopenable snapshot is fail-closed (never silently
    // wipe balances) — the operator deletes the file to consciously boot fresh.
    let state_path = std::env::var("DARKPERP_STATE")
        .ok()
        .map(std::path::PathBuf::from);
    // Task 3 (crash recovery): whether a sealed snapshot was actually restored —
    // a rollback journal is only meaningful against the state it was written
    // beside; on a fresh boot a leftover journal is deleted below, unapplied.
    let mut restored_from_snapshot = false;
    let mut gw = match &state_path {
        Some(p) if p.exists() => {
            let restored = std::fs::read(p)
                .map_err(|e| e.to_string())
                .and_then(|sealed| snapshot::open(&sealed, &enclave_seed))
                .and_then(|plain| Gw::boot_restored(&plain));
            match restored {
                Ok(gw) => {
                    println!("[state] restored sealed snapshot from {}", p.display());
                    restored_from_snapshot = true;
                    gw
                }
                Err(e) => {
                    eprintln!(
                        "[state] REFUSING to start: DARKPERP_STATE={} exists but cannot be \
                         restored ({e}). Restore the correct ENCLAVE_SEED/snapshot, or delete \
                         the file to consciously boot fresh.",
                        p.display()
                    );
                    std::process::exit(1);
                }
            }
        }
        _ => Gw::boot(),
    };
    gw.prod = prod;
    // Task 5: with a prover configured, the tick loop's SETTLE_TICKS simulation is OFF —
    // finality advances only when a window's proof verifies on L1. Set BEFORE the
    // boot-recovery block below, so a roll-forward re-commit already runs under the
    // honest-finality posture (its `commit_window_settle` marks the recovered window's
    // orders SETTLED either way — the flag gates only the tick-loop simulation).
    gw.window_settle_mode = prover.is_some();
    if gw.window_settle_mode {
        // Task 5 fix round 1 (report Concern 1, memory): the window path never
        // consumes the per-tick rollback snapshots, and with the SETTLE_TICKS
        // simulation off nothing prunes them until the window settles — a full
        // state clone per 700ms tick (~1100 per ~13-min proof, unbounded if
        // settles wedge). Skip retaining them entirely.
        gw.seq.set_retain_tick_snapshots(false);
        // Report Concern 3: a legacy-era snapshot restored into window mode can
        // carry stale queue entries the (now-gated) drain never consumes — drop
        // them once here.
        gw.pending_settle.clear();
    }
    // audit DP-006: in production the enclave identity must be bound to a verified TEE
    // attestation; refuse to serve traffic under the stub measurement.
    if !attestation_ok_for_mode(prod, gw.attestation.is_some()) {
        eprintln!(
            "[attest] REFUSING to start in production without a verified TEE attestation. \
             Set ATTESTATION_DIR to a valid quote/collateral/vTPM bundle, or drop the production \
             posture (no L1 bridge and DARKPERP_PROD unset) to run the demo build."
        );
        std::process::exit(1);
    }
    // audit DP-006 follow-up: pin the expected measurement so a different or replayed valid
    // quote (e.g. the in-repo test fixture) cannot pass the mere presence check.
    let expected_measurement = std::env::var("ATTESTATION_EXPECTED_MEASUREMENT")
        .ok()
        .and_then(|s| parse_hex32(&s));
    let attested_measurement = gw.attestation.as_ref().map(|a| a.measurement);
    if !measurement_matches_pin(prod, attested_measurement, expected_measurement) {
        eprintln!(
            "[attest] REFUSING to start: in production the attested measurement must equal a \
             pinned ATTESTATION_EXPECTED_MEASUREMENT (32-byte hex). A merely-valid quote is not \
             enough — pin the real enclave's measurement so a wrong/replayed quote is rejected."
        );
        std::process::exit(1);
    }
    // Task 3 (crash recovery): resolve any in-flight window settle the rollback
    // journal recorded. The settle loop journals every seal and NEVER deletes
    // (the journal is a WAL for the latest sealed window; resolving arms only
    // poke the snapshot writer) — BOOT is the only deleter, via the recovery
    // table. This runs BEFORE the continuity check below and leaves it untouched
    // as the final arbiter: a roll-forward re-commit advances
    // l1_status.settled_root so an interrupted-but-landed settle passes it, and
    // a rollback rewinds Counter B so the desync guard stops skipping settles.
    if let Some(sp) = &state_path {
        let jp = rollback_journal::journal_path(sp);
        if !restored_from_snapshot {
            // FRESH boot (no snapshot restored): a leftover journal references a
            // state that no longer exists (e.g. the operator wiped the snapshot
            // but not the sidecar) — meaningless; drop it so a later boot cannot
            // misapply it to unrelated state.
            if jp.exists() {
                eprintln!(
                    "[recovery] rollback journal {} found on a FRESH boot (no snapshot \
                     restored) — deleting the meaningless leftover",
                    jp.display()
                );
                rollback_journal::delete(&jp);
            }
        } else {
            match rollback_journal::read(&jp, &enclave_seed) {
                Ok(None) => {} // no journal — nothing was in flight
                Err(e) => {
                    // present but unreadable: never delete data the operator may
                    // need, never guess — HOLD and fall through.
                    eprintln!(
                        "[recovery] HOLDING: rollback journal {} exists but is unreadable \
                         ({e}) — keeping the file; operator must reconcile (the continuity \
                         check decides whether boot proceeds)",
                        jp.display()
                    );
                }
                Ok(Some(j)) => match &l1 {
                    None => {
                        // can't resolve the journal against a chain we can't read.
                        eprintln!(
                            "[recovery] HOLDING: rollback journal present (window {}) but no \
                             L1 bridge is configured — cannot resolve it against the chain; \
                             keeping the file",
                            j.batch_id
                        );
                    }
                    Some(l1c) => {
                        // chain reads exactly like the continuity check below
                        // (spawn_blocking — the L1 client is blocking).
                        let reads = {
                            let l1c = l1c.clone();
                            tokio::task::spawn_blocking(
                                move || -> Result<(u64, String, u128), String> {
                                    let bc = l1c.batch_count()?;
                                    let root = l1c.current_root()?;
                                    let bond = l1c.sequencer_bond().unwrap_or(0);
                                    Ok((bc, root, bond))
                                },
                            )
                            .await
                            .unwrap_or_else(|e| Err(e.to_string()))
                        };
                        // Fix round 2 (final-review TOCTOU): if the journal has a
                        // `prepared` outcome (a settle tx MAY have been broadcast)
                        // and the chain still reads the pre-settle batchCount, the
                        // crash may sit between the broadcast and its mining — a
                        // RollBack decided on this first read would delete the only
                        // `prepared` copy right before the tx lands. Wait out the
                        // propagation window and let a SECOND read decide; a failed
                        // re-read proves nothing and flows into the HOLD arm below,
                        // exactly like any other failed chain read.
                        let reads = match reads {
                            Ok((bc, _, bond))
                                if needs_confirm_delay(j.prepared.is_some(), bc, j.batch_id) =>
                            {
                                eprintln!(
                                    "[recovery] journal window {} has a prepared outcome and the \
                                     chain still reads batchCount {bc} — the settle tx may be \
                                     broadcast but not yet mined; waiting \
                                     {RECOVERY_CONFIRM_DELAY_SECS}s and re-reading the chain \
                                     before deciding",
                                    j.batch_id
                                );
                                tokio::time::sleep(Duration::from_secs(
                                    RECOVERY_CONFIRM_DELAY_SECS,
                                ))
                                .await;
                                let l1c = l1c.clone();
                                tokio::task::spawn_blocking(
                                    move || -> Result<(u64, String, u128), String> {
                                        let bc = l1c.batch_count()?;
                                        let root = l1c.current_root()?;
                                        Ok((bc, root, bond))
                                    },
                                )
                                .await
                                .unwrap_or_else(|e| Err(e.to_string()))
                                .map_err(|e| {
                                    format!(
                                        "confirming re-read after the {RECOVERY_CONFIRM_DELAY_SECS}s \
                                         in-flight-tx wait failed: {e}"
                                    )
                                })
                            }
                            other => other,
                        };
                        match reads {
                            Ok((chain_bc, chain_root, bond)) => {
                                match apply_boot_recovery(&mut gw, j, chain_bc, &chain_root, bond)
                                {
                                    // Task 3 fix: a MUTATED resolution is persisted
                                    // synchronously BEFORE the journal is deleted
                                    // (and a failed persist keeps the journal) —
                                    // see finish_boot_recovery.
                                    BootRecoveryOutcome::DeleteJournal { mutated } => {
                                        finish_boot_recovery(
                                            &gw,
                                            mutated,
                                            sp,
                                            &jp,
                                            &enclave_seed,
                                        );
                                    }
                                    BootRecoveryOutcome::KeepJournal => {}
                                }
                            }
                            Err(e) => {
                                // a failed read proves nothing — HOLD, never guess.
                                eprintln!(
                                    "[recovery] HOLDING: cannot read the chain to resolve the \
                                     rollback journal ({e}) — keeping the file; the continuity \
                                     check decides whether boot proceeds"
                                );
                            }
                        }
                    }
                },
            }
        }
    }
    // Restored-state ↔ L1 continuity: the snapshot's last settled root must equal
    // the on-chain currentStateRoot, or this snapshot is stale / from a different
    // deployment — settling from it would fork the withdrawal roots users hold.
    // Fail closed; the operator resolves (right snapshot, right chain, or fresh).
    if let (Some(l1c), Some(st)) = (&l1, gw.l1_status.as_ref()) {
        let chain_root = {
            let l1c = l1c.clone();
            tokio::task::spawn_blocking(move || l1c.current_root())
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
        };
        match chain_root {
            Ok(r) if r.eq_ignore_ascii_case(&st.settled_root) => {
                println!("[state] on-chain continuity OK (currentStateRoot {r})");
            }
            Ok(r) => {
                eprintln!(
                    "[state] REFUSING to start: restored snapshot last settled {} but the \
                     chain's currentStateRoot is {r} — the snapshot is stale or from a \
                     different deployment. Restore the latest snapshot or delete \
                     DARKPERP_STATE to consciously boot fresh.",
                    st.settled_root
                );
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!(
                    "[state] REFUSING to start: cannot verify on-chain continuity of the \
                     restored snapshot ({e})."
                );
                std::process::exit(1);
            }
        }
    }
    let app = Arc::new(App {
        gw: Mutex::new(gw),
        tx: tx.clone(),
        events_tx,
        reg_limit: Mutex::new(HashMap::new()),
        l1: l1.clone(),
        prover: prover.clone(),
        candles: Mutex::new(candles::CandleStore::new()),
    });

    // One-shot REAL history backfill for feed-backed markets (chart past bars):
    // exchange candles land under the live bars the tick loop records. Failures
    // degrade to shorter history, never block boot.
    {
        let app = app.clone();
        tokio::spawn(async move {
            let feeds: Vec<(u64, &'static str)> = MARKETS
                .iter()
                .filter_map(|m| m.feed.map(|f| (m.id, f)))
                .collect();
            for (id, inst) in feeds {
                for (tf_idx, (tf, _, cc_tf)) in candles::TFS.iter().enumerate() {
                    let fetched = tokio::task::spawn_blocking(move || {
                        oracle_feed::fetch_candles(inst, cc_tf, candles::CAP)
                    })
                    .await;
                    match fetched {
                        Ok(Ok(cs)) => {
                            let history: Vec<candles::Candle> = cs
                                .iter()
                                .map(|c| candles::Candle {
                                    start_ms: c.start_ms,
                                    open: c.open,
                                    high: c.high,
                                    low: c.low,
                                    close: c.close,
                                })
                                .collect();
                            app.candles.lock().await.backfill(id, tf_idx, &history);
                        }
                        Ok(Err(e)) => eprintln!("[candles] backfill {inst} {tf}: {e}"),
                        Err(e) => eprintln!("[candles] backfill join {inst} {tf}: {e}"),
                    }
                    // stay far under the public API's rate limits
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
            println!("[candles] exchange backfill complete");
        });
    }

    // Task 2 (crash recovery): the settle loop asks for an immediate snapshot right
    // after journaling a freshly sealed window (stage 1), so the on-disk pair
    // (post-seal snapshot + rollback journal) is consistent at seal time instead of
    // up to SNAPSHOT_SECS later. The snapshot FILE keeps exactly one writer — the
    // persistence block's `write` closure below (two writers would race the shared
    // `.tmp` rename and lose a snapshot); this Notify is only a wake-up. Created
    // unconditionally so the settle loop compiles and runs identically when
    // persistence is off (`notify_one` with no listener is a no-op).
    let snapshot_notify = Arc::new(tokio::sync::Notify::new());

    // Periodic sealed-snapshot writer + graceful-shutdown save (SIGTERM/ctrl-c).
    if let Some(path) = state_path.clone() {
        let write = {
            let app = app.clone();
            let path = path.clone();
            move || {
                let app = app.clone();
                let path = path.clone();
                async move {
                    let plain = { app.gw.lock().await.snapshot_plain() };
                    let sealed = snapshot::seal(&plain, &enclave_seed);
                    match snapshot::write_atomic(&path, &sealed) {
                        Ok(()) => true,
                        Err(e) => {
                            eprintln!("[state] snapshot write failed: {e}");
                            false
                        }
                    }
                }
            }
        };
        {
            let write = write.clone();
            let notify = snapshot_notify.clone();
            tokio::spawn(async move {
                let mut iv = tokio::time::interval(Duration::from_secs(SNAPSHOT_SECS));
                iv.tick().await; // skip the immediate first tick
                loop {
                    // Task 2: wake on the timer OR on demand (the settle loop's
                    // stage-1 journal write). Notify stores a permit if we're
                    // mid-write, so a wake-up is never lost — at worst it costs one
                    // extra snapshot.
                    tokio::select! {
                        _ = iv.tick() => {}
                        _ = notify.notified() => {}
                    }
                    write().await;
                }
            });
        }
        {
            let write = write.clone();
            let l1_ks = l1.clone();
            tokio::spawn(async move {
                let term = async {
                    #[cfg(unix)]
                    {
                        let mut sig = tokio::signal::unix::signal(
                            tokio::signal::unix::SignalKind::terminate(),
                        )
                        .expect("SIGTERM handler");
                        sig.recv().await;
                    }
                    #[cfg(not(unix))]
                    std::future::pending::<()>().await;
                };
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term => {}
                }
                let ok = write().await;
                // audit #6: process::exit skips Drop, so the KeystoreDir RAII guard never
                // fires on a graceful stop — remove the keystore temp dir (encrypted key +
                // 0600 password) explicitly here so it doesn't persist / accumulate.
                if let Some(l1) = &l1_ks {
                    l1.cleanup_keystore();
                }
                println!(
                    "[state] shutdown snapshot {} — exiting",
                    if ok { "saved" } else { "FAILED" }
                );
                std::process::exit(if ok { 0 } else { 1 });
            });
        }
        println!("[state] sealed persistence ON → {}", path.display());
    }

    // background tick loop
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(TICK_MS));
            loop {
                iv.tick().await;
                let (events, acct_events) = { app.gw.lock().await.tick() };
                // fold the fresh marks into the REAL candle history (chart past bars)
                {
                    let marks: Vec<(u64, i128)> = {
                        app.gw
                            .lock()
                            .await
                            .mkts
                            .iter()
                            .map(|m| (m.id, m.px))
                            .collect()
                    };
                    let now = now_ms();
                    let mut cs = app.candles.lock().await;
                    for (id, px) in marks {
                        cs.record(id, now, px);
                    }
                }
                let snap = { app.gw.lock().await.snapshot() };
                let _ = app
                    .tx
                    .send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
                for ev in events {
                    let _ = app
                        .tx
                        .send(serde_json::to_string(&WsMsg::Event { event: ev }).unwrap());
                }
                // fan out per-account events to the authenticated /v1/ws subscribers
                for ev in acct_events {
                    let _ = app.events_tx.send(ev);
                }
            }
        });
    }

    // live oracle: pull real prices for feed-backed markets from Crypto.com every 5s
    // and feed them into the engine (markets without a feed keep the sim walk).
    {
        let app = app.clone();
        tokio::spawn(async move {
            let feeds: Vec<(u64, &'static str)> = {
                let gw = app.gw.lock().await;
                gw.mkts
                    .iter()
                    .filter_map(|m| m.feed.map(|f| (m.id, f)))
                    .collect()
            };
            if feeds.is_empty() {
                return;
            }
            let mut iv = tokio::time::interval(Duration::from_secs(5));
            loop {
                iv.tick().await;
                for &(id, inst) in &feeds {
                    let now = now_ms();
                    match tokio::task::spawn_blocking(move || {
                        oracle_feed::fetch_transcript(inst, now)
                    })
                    .await
                    {
                        Ok(Ok(t)) => {
                            app.gw.lock().await.apply_real_oracle(id, t);
                        }
                        Ok(Err(e)) => eprintln!("[oracle] {inst} fetch failed: {e}"),
                        Err(e) => eprintln!("[oracle] {inst} join: {e}"),
                    }
                }
            }
        });
    }

    // optional L1 settlement bridge: top up the USDC bond, advance the on-chain root
    // to mirror the engine root, and publish the cumulative withdrawals root (so users
    // claim USDC) on a slow timer (Base Sepolia).
    if let Some(l1) = l1 {
        println!(
            "[l1] bridge ON → settlement {} every {L1_SETTLE_SECS}s",
            l1.settlement
        );
        // audit DP-004: answer inclusion challenges so an honest sequencer is not slashed for an
        // order it matched or validly rejected. Watch InclusionChallenged, build the Merkle proof
        // from the retained per-batch order hashes, and submit answerChallenge / answerByRejection.
        {
            let app = app.clone();
            let l1a = l1.clone();
            tokio::spawn(async move {
                // audit #8: DON'T start at the current block — that silently skips any
                // InclusionChallenged raised while we were restarting/down, letting an
                // honest sequencer be slashed for a challenge it could have answered. A
                // challenge is answerable only within `challengeWindowBlocks`, so rewind
                // past that window (see challenge_scan_start); over-scanning older /
                // already-answered challenges is a harmless no-op (challenge_open gates
                // the answer). The data to answer is in the persisted batch_orders.
                let mut from_block = {
                    let l1c = l1a.clone();
                    tokio::task::spawn_blocking(move || {
                        let now = l1c.block_number().unwrap_or(0);
                        let window = l1c.challenge_window_blocks().unwrap_or(300);
                        challenge_scan_start(now, window)
                    })
                    .await
                    .unwrap_or(0)
                };
                let mut iv = tokio::time::interval(Duration::from_secs(L1_SETTLE_SECS));
                loop {
                    iv.tick().await;
                    let l1c = l1a.clone();
                    let (hashes, next) =
                        match tokio::task::spawn_blocking(move || l1c.fetch_challenges(from_block))
                            .await
                        {
                            Ok(Ok(x)) => x,
                            Ok(Err(e)) => {
                                eprintln!("[l1] challenge scan failed: {e}");
                                continue;
                            }
                            Err(e) => {
                                eprintln!("[l1] challenge scan join: {e}");
                                continue;
                            }
                        };
                    from_block = next;
                    for oh in hashes {
                        // build the answer under the gw lock, then submit off-lock
                        let answer = {
                            let gw = app.gw.lock().await;
                            parse_hex32(&oh).and_then(|h| gw.build_challenge_answer(&h))
                        };
                        let Some((by_rejection, batch_id, proof)) = answer else {
                            continue; // not in any retained batch — a genuine withhold, unanswerable
                        };
                        let l1c = l1a.clone();
                        let oh2 = oh.clone();
                        let res = tokio::task::spawn_blocking(move || {
                            if l1c.challenge_open(&oh2)? {
                                l1c.answer_challenge(&oh2, batch_id, &proof, by_rejection)
                            } else {
                                Ok(String::new()) // already answered / slashed
                            }
                        })
                        .await;
                        match res {
                            Ok(Ok(tx)) if !tx.is_empty() => println!(
                                "[l1] answered inclusion challenge {oh} (batch {batch_id}, rejection={by_rejection}) tx {tx}"
                            ),
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => eprintln!("[l1] answer failed for {oh}: {e}"),
                            Err(e) => eprintln!("[l1] answer join: {e}"),
                        }
                    }
                }
            });
        }
        let app = app.clone();
        // Task 2 (crash recovery): journal in-flight window settles to the sealed
        // sidecar `<DARKPERP_STATE>.rollback` so Task-3 boot recovery can resolve a
        // restart mid-settle. Task 3 (WAL model): the loop NEVER deletes the journal
        // — it only overwrites it at the next stage-1. Every resolving arm instead
        // pokes the snapshot writer so the in-memory resolution persists promptly;
        // BOOT is the only deleter (deleting here would leave a crash inside the
        // resolution→snapshot window with a restored pre-resolution state and no
        // journal to reconcile it — the Task-2 residual wedge). No persistence path
        // (`None`) = no journal — the settle loop behaves exactly as before.
        let jpath = state_path.as_deref().map(rollback_journal::journal_path);
        let snapshot_notify = snapshot_notify.clone();
        tokio::spawn(async move {
            type SettleOut = (
                L1Status,
                Vec<[u8; 32]>,
                std::collections::BTreeMap<[u8; 32], (Digest, Vec<[u8; 32]>)>,
                u64, // on-chain batch id these ordered/rejected hashes were committed under
                Vec<[u8; 32]>, // ordered order hashes settled this batch (audit DP-004 retention)
                Vec<[u8; 32]>, // rejected order hashes settled this batch
            );
            // start the first settle one period out, so it never races the bond's
            // confirmation (tokio's plain `interval` would fire immediately).
            let mut iv = tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::from_secs(L1_SETTLE_SECS),
                Duration::from_secs(L1_SETTLE_SECS),
            );
            loop {
                iv.tick().await;
                if let Some(client) = app.prover.clone() {
                    // (A) top up the sequencer bond (as the legacy path does) + read the
                    // on-chain batch count (RPC, no lock). The bond top-up runs BEFORE the
                    // window is sealed, so an underbond settleBatch revert cannot strand the
                    // sequencer past the desync guard.
                    let l1c = l1.clone();
                    let bc = match tokio::task::spawn_blocking(move || -> Result<u64, String> {
                        match l1c.ensure_bond() {
                            Ok(Some(tx)) => println!("[l1] bond topped up: {tx}"),
                            Ok(None) => {}
                            Err(e) => eprintln!("[l1] bond top-up skipped: {e}"),
                        }
                        l1c.batch_count()
                    })
                    .await
                    {
                        Ok(Ok(bc)) => bc,
                        Ok(Err(e)) => {
                            eprintln!("[l1] batch_count: {e}");
                            continue;
                        }
                        Err(e) => {
                            eprintln!("[l1] batch_count join: {e}");
                            continue;
                        }
                    };
                    // (B) seal the window under the lock (or skip)
                    let begun = {
                        let mut gw = app.gw.lock().await;
                        match gw.begin_window_settle(bc) {
                            Ok(Some(x)) => {
                                let cand: Vec<[u8; 32]> =
                                    gw.pending_withdrawals.iter().map(|w| w.leaf()).collect();
                                Some((x, cand))
                            }
                            Ok(None) => None,
                            Err(e) => {
                                eprintln!("[l1] window settle skipped: {e}");
                                None
                            }
                        }
                    };
                    let Some(((witness, ww), prune_candidates)) = begun else { continue };
                    // capture the manifest's ordered/rejected for the DP-004 challenge store
                    let ordered = witness.manifest.ordered.clone();
                    let rejected: Vec<Digest> =
                        witness.manifest.rejected.iter().map(|(h, _)| *h).collect();
                    let batch_id = witness.batch_id;
                    // keep rollback copies for the failure path (a per-settle DefaultState
                    // clone — far rarer than the per-tick snapshot clone, so negligible).
                    let witness_rb = witness.clone();
                    let ww_rb = ww.clone();
                    // Task 2 stage 1: the seal just bumped Counter B in memory — persist
                    // the rollback inputs BEFORE anything can crash, then ask the single
                    // snapshot writer for an immediate snapshot so the on-disk pair
                    // (post-seal snapshot + journal) is consistent at seal time. The
                    // journal takes ownership of witness/ww (no extra DefaultState clone)
                    // and carries them into the prove closure below. Best-effort: a failed
                    // write only logs — the settle must behave exactly as the un-journaled
                    // path did. (A crash in the ~ms before the triggered snapshot lands
                    // restores a pre-seal snapshot → SEAL-NEVER-PERSISTED at boot — safe.)
                    let mut journal = rollback_journal::RollbackJournal {
                        batch_id,
                        witness,
                        ww,
                        prepared: None,
                    };
                    if let Some(jp) = &jpath {
                        match rollback_journal::write(jp, &journal, &enclave_seed) {
                            Ok(()) => snapshot_notify.notify_one(),
                            Err(e) => eprintln!(
                                "[recovery] stage-1 rollback journal write failed (settle continues unjournaled): {e}"
                            ),
                        }
                    }
                    // (C) prove + settle (lock-free). Distinguish a prove failure (no tx
                    // was ever broadcast -> unconditional rollback) from a settle failure
                    // (cast send broadcasts THEN waits for the receipt, so a 90s-kill/RPC
                    // error is AMBIGUOUS: the tx may have landed -> keep `prepared` so we
                    // can roll forward and commit the bookkeeping if batch_count advanced).
                    enum SettleAttempt {
                        Ok {
                            prepared: prover_client::PreparedSettle,
                            tx: String,
                            bond: u128,
                            claimed: Vec<[u8; 32]>,
                        },
                        ProveFailed(String),
                        SettleFailed {
                            err: String,
                            prepared: prover_client::PreparedSettle,
                        },
                    }
                    let l1c = l1.clone();
                    let jpath_bg = jpath.clone();
                    let res = tokio::task::spawn_blocking(move || -> SettleAttempt {
                        let prepared = match prover_client::prove_and_prepare(
                            client.as_ref(),
                            &journal.witness,
                            &journal.ww,
                        ) {
                            Ok(p) => p,
                            Err(e) => return SettleAttempt::ProveFailed(e),
                        };
                        // Task 2 stage 2: the prove came back — rewrite the journal with
                        // `prepared` BEFORE the tx can broadcast, so a crash between
                        // broadcast and commit leaves boot the exact new_root/claim
                        // proofs a roll-forward re-commits. Same best-effort posture as
                        // stage 1 (and no snapshot poke: nothing in-memory changed since).
                        if let Some(jp) = &jpath_bg {
                            journal.prepared = Some(prepared.clone());
                            if let Err(e) = rollback_journal::write(jp, &journal, &enclave_seed) {
                                eprintln!(
                                    "[recovery] stage-2 rollback journal write failed (settle continues): {e}"
                                );
                            }
                        }
                        match l1c.settle_proved(&prepared.outcome) {
                            Ok(tx) => {
                                let bond = l1c.sequencer_bond().unwrap_or(0);
                                let claimed: Vec<[u8; 32]> = prune_candidates
                                    .into_iter()
                                    .filter(|leaf| l1c.claimed(&hex32(leaf)).unwrap_or(false))
                                    .collect();
                                SettleAttempt::Ok { prepared, tx, bond, claimed }
                            }
                            Err(err) => SettleAttempt::SettleFailed { err, prepared },
                        }
                    })
                    .await;
                    match res {
                        Ok(SettleAttempt::Ok { prepared, tx, bond, claimed }) => {
                            let status = L1Status {
                                settled_root: hex32(&prepared.outcome.new_root),
                                batch_count: batch_id + 1,
                                last_tx: tx.clone(),
                                bond: bond.to_string(),
                                withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
                            };
                            println!(
                                "[l1] window settled root {} batch {} tx {} (withdrawals root {})",
                                status.settled_root, status.batch_count, tx, status.withdrawals_root
                            );
                            {
                                let mut gw = app.gw.lock().await;
                                gw.commit_window_settle(batch_id, ordered, rejected, prepared, status);
                                gw.prune_claimed_withdrawals(&claimed);
                            }
                            // Task 3 (WAL): the journal outlives the commit — boot's STALE
                            // row resolves it. Poke the single snapshot writer instead, so
                            // the committed l1_status/settled_root persists promptly and a
                            // crash inside the old ≤SNAPSHOT_SECS window no longer wedges
                            // the boot continuity check.
                            snapshot_notify.notify_one();
                            let snap = { app.gw.lock().await.snapshot() };
                            let _ = app.tx.send(
                                serde_json::to_string(&WsMsg::State { state: snap }).unwrap(),
                            );
                        }
                        Ok(SettleAttempt::ProveFailed(e)) => {
                            eprintln!("[l1] prove failed: {e} — rolling back (no tx was broadcast)");
                            {
                                let mut gw = app.gw.lock().await;
                                gw.seq.rollback_window(&witness_rb);
                                gw.rollback_window_withdrawals(ww_rb);
                            }
                            // Task 3 (WAL): keep the journal (boot's SEAL-NEVER-PERSISTED
                            // row resolves it once the rolled-back state persists); poke
                            // the writer so that happens promptly.
                            snapshot_notify.notify_one();
                        }
                        Ok(SettleAttempt::SettleFailed { err, prepared }) => {
                            // ambiguous: re-read batchCount (+ currentStateRoot to confirm WHICH
                            // window landed, + bond for a roll-forward status).
                            let l1c = l1.clone();
                            let recheck =
                                tokio::task::spawn_blocking(move || -> Result<(u64, String, u128), String> {
                                    let bc = l1c.batch_count()?;
                                    let root = l1c.current_root()?;
                                    let bond = l1c.sequencer_bond().unwrap_or(0);
                                    Ok((bc, root, bond))
                                })
                                .await;
                            match recheck {
                                Ok(Ok((now_bc, now_root, bond))) => match settle_failure_action(batch_id, now_bc) {
                                    RollAction::RollBack => {
                                        eprintln!("[l1] settle failed: {err} — tx did not land (batchCount still {batch_id}); rolled back");
                                        {
                                            let mut gw = app.gw.lock().await;
                                            gw.seq.rollback_window(&witness_rb);
                                            gw.rollback_window_withdrawals(ww_rb);
                                        }
                                        // Task 3 (WAL): keep the journal (boot's
                                        // SEAL-NEVER-PERSISTED row resolves it once the
                                        // rolled-back state persists); poke the writer.
                                        snapshot_notify.notify_one();
                                    }
                                    RollAction::RollForward => {
                                        // The tx landed (batchCount advanced), but confirm it
                                        // settled OUR window's root — not a re-sealed one from a
                                        // rare re-seal-then-old-tx-mines interleaving. Compare
                                        // case-insensitively (cast hex casing), like the boot guard.
                                        let our_root = hex32(&prepared.outcome.new_root);
                                        if !now_root.eq_ignore_ascii_case(&our_root) {
                                            // Task 2: HOLD keeps the journal — the operator (and
                                            // Task-3 boot recovery) still needs the rollback inputs.
                                            eprintln!("[l1] settle reported '{err}' and batchCount advanced to {now_bc}, but currentStateRoot {now_root} != our new_root {our_root} — a DIFFERENT window settled; HOLDING (no commit); operator must reconcile");
                                        } else {
                                            let status = L1Status {
                                                settled_root: hex32(&prepared.outcome.new_root),
                                                batch_count: batch_id + 1,
                                                last_tx: "(recovered: landed despite cast error)".to_string(),
                                                bond: bond.to_string(),
                                                withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
                                            };
                                            eprintln!("[l1] settle reported '{err}' but the tx LANDED (batchCount {batch_id}->{now_bc}); rolled forward + committed bookkeeping");
                                            {
                                                let mut gw = app.gw.lock().await;
                                                gw.commit_window_settle(batch_id, ordered, rejected, prepared, status);
                                            }
                                            // Task 3 (WAL): the journal outlives the commit —
                                            // boot's STALE row resolves it; poke the writer so
                                            // the commit persists promptly.
                                            snapshot_notify.notify_one();
                                            let snap = { app.gw.lock().await.snapshot() };
                                            let _ = app.tx.send(
                                                serde_json::to_string(&WsMsg::State { state: snap }).unwrap(),
                                            );
                                        }
                                    }
                                    RollAction::Hold => {
                                        // Task 2: HOLD keeps the journal (rollback inputs preserved
                                        // for the operator / Task-3 boot recovery).
                                        eprintln!("[l1] settle failed AND on-chain batchCount is {now_bc} for window {batch_id} — HOLDING (no rollback/commit); operator must reconcile");
                                    }
                                },
                                _ => {
                                    // Task 2: HOLD keeps the journal.
                                    eprintln!("[l1] settle failed ({err}) and the batchCount re-read failed — HOLDING (no rollback/commit); operator must reconcile");
                                }
                            }
                        }
                        Err(join) => {
                            // the settle task panicked — `prepared` is lost, so we cannot roll
                            // forward. Re-read batchCount and roll back ONLY if it confirms the
                            // tx did not land; otherwise hold.
                            let l1c = l1.clone();
                            let re = tokio::task::spawn_blocking(move || l1c.batch_count()).await;
                            match re {
                                Ok(Ok(now_bc)) if now_bc == batch_id => {
                                    eprintln!("[l1] settle task join error: {join} — tx did not land; rolled back");
                                    {
                                        let mut gw = app.gw.lock().await;
                                        gw.seq.rollback_window(&witness_rb);
                                        gw.rollback_window_withdrawals(ww_rb);
                                    }
                                    // Task 3 (WAL): keep the journal (boot's
                                    // SEAL-NEVER-PERSISTED row resolves it once the
                                    // rolled-back state persists); poke the writer.
                                    snapshot_notify.notify_one();
                                }
                                _ => {
                                    // Task 2: HOLD keeps the journal.
                                    eprintln!("[l1] settle task join error: {join} — cannot confirm the tx did not land (no prepared to roll forward); HOLDING; operator must reconcile");
                                }
                            }
                        }
                    }
                    continue; // new path handled this tick; skip the legacy body
                }
                let (new_root, manifest, withdrawals, ordered_h, rejected_h) = {
                    let gw = app.gw.lock().await;
                    (
                        gw.state_root_hex(),
                        gw.last_manifest_hex(),
                        gw.pending_withdrawals.clone(),
                        gw.pending_ordered.clone(),
                        gw.pending_rejected.clone(),
                    )
                };
                let l1c = l1.clone();
                let res =
                    tokio::task::spawn_blocking(move || -> Result<Option<SettleOut>, String> {
                        // keep the USDC bond above the 5%-of-TVL floor as deposits grow (Q1)
                        match l1c.ensure_bond() {
                            Ok(Some(tx)) => println!("[l1] bond topped up: {tx}"),
                            Ok(None) => {}
                            Err(e) => eprintln!("[l1] bond top-up skipped: {e}"),
                        }
                        let prev = l1c.current_root()?;
                        // prune withdrawals the vault already paid out, then build the
                        // CUMULATIVE root over every still-unclaimed leaf (vault invariant).
                        let mut surviving = Vec::new();
                        let mut claimed = Vec::new();
                        for w in withdrawals {
                            let leaf = w.leaf();
                            if l1c.claimed(&hex32(&leaf)).unwrap_or(false) {
                                claimed.push(leaf);
                            } else {
                                surviving.push(w);
                            }
                        }
                        let leaves: Vec<[u8; 32]> = surviving.iter().map(|w| w.leaf()).collect();
                        let wroot = merkle_root(&leaves);
                        let wroot_hex = hex32(&wroot);
                        if prev.eq_ignore_ascii_case(&new_root) {
                            return Ok(None); // engine root unchanged → nothing to settle
                        }
                        // audit DP-004: this settle becomes on-chain batch `batch_id` (the current
                        // count, which settleBatch consumes then increments). Build the ordered and
                        // rejected roots over THIS batch id, so a later `answerChallenge` /
                        // `answerByRejection` proof (built with the same id) verifies on-chain.
                        // audit (fail-closed): propagate a batch_count RPC error instead of
                        // defaulting to 0 — a transient failure that silently keyed the roots to
                        // batch 0 would make every challenge for this batch unanswerable and get an
                        // honest sequencer slashed. Aborting here just retries the settle next tick.
                        let batch_id = l1c.batch_count()?;
                        let ordered_leaves: Vec<[u8; 32]> = ordered_h
                            .iter()
                            .map(|h| inclusion_leaf(batch_id, h))
                            .collect();
                        let rejected_leaves: Vec<[u8; 32]> = rejected_h
                            .iter()
                            .map(|h| rejection_leaf(batch_id, h))
                            .collect();
                        let oroot_hex = hex32(&merkle_root(&ordered_leaves));
                        let rroot_hex = hex32(&merkle_root(&rejected_leaves));
                        let tx = l1c.settle(
                            &prev, &manifest, &new_root, &oroot_hex, &wroot_hex, &rroot_hex,
                        )?;
                        let mut proofs = std::collections::BTreeMap::new();
                        for (i, w) in surviving.iter().enumerate() {
                            // legacy: every note shares the one cumulative root published this settle.
                            proofs.insert(w.leaf(), (wroot, merkle_proof(&leaves, i)));
                        }
                        Ok(Some((
                            L1Status {
                                settled_root: new_root,
                                // settleBatch consumed `batch_id` then incremented, so the new
                                // on-chain count is known — no need to re-query (and never show 0).
                                batch_count: batch_id + 1,
                                last_tx: tx,
                                bond: l1c.sequencer_bond().unwrap_or(0).to_string(),
                                withdrawals_root: wroot_hex,
                            },
                            claimed,
                            proofs,
                            batch_id,
                            ordered_h,
                            rejected_h,
                        )))
                    })
                    .await;
                match res {
                    Ok(Ok(Some((status, claimed, proofs, batch_id, ordered_h, rejected_h)))) => {
                        println!(
                            "[l1] settled root {} batch {} tx {} (withdrawals root {})",
                            status.settled_root,
                            status.batch_count,
                            status.last_tx,
                            status.withdrawals_root
                        );
                        {
                            let mut gw = app.gw.lock().await;
                            if !claimed.is_empty() {
                                let cset: std::collections::BTreeSet<[u8; 32]> =
                                    claimed.into_iter().collect();
                                gw.pending_withdrawals.retain(|w| !cset.contains(&w.leaf()));
                            }
                            gw.withdraw_proofs = proofs;
                            gw.l1_status = Some(status);
                            // audit DP-004: retain the order hashes this on-chain batch committed so
                            // a challenge can be answered against its root, then drop exactly the
                            // ones just settled from the pending accumulators (any appended during
                            // the settle stay, at the back).
                            let (no, nr) = (ordered_h.len(), rejected_h.len());
                            gw.batch_orders.insert(batch_id, (ordered_h, rejected_h));
                            let po_len = gw.pending_ordered.len();
                            gw.pending_ordered.drain(0..no.min(po_len));
                            let pr_len = gw.pending_rejected.len();
                            gw.pending_rejected.drain(0..nr.min(pr_len));
                        }
                        let snap = { app.gw.lock().await.snapshot() };
                        let _ = app
                            .tx
                            .send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(e)) => eprintln!("[l1] settle failed: {e}"),
                    Err(e) => eprintln!("[l1] settle join: {e}"),
                }
            }
        });
    }

    let router = build_router(app, prod);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("dark-perp gateway listening on http://{addr}  (ws: /ws)");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `App` for router tests — no socket bound, pure in-memory (`l1: None`).
    fn test_app() -> Shared {
        let (tx, _rx) = broadcast::channel::<String>(16);
        let (events_tx, _erx) = broadcast::channel::<String>(16);
        Arc::new(App {
            gw: Mutex::new(Gw::boot()),
            tx,
            events_tx,
            reg_limit: Mutex::new(HashMap::new()),
            l1: None,
            prover: None,
            candles: Mutex::new(candles::CandleStore::new()),
        })
    }

    // ── ambiguous landed-tx recovery ─────────────────────────────────────────

    #[test]
    fn settle_failure_action_decides_by_batch_count() {
        use crate::RollAction;
        // chain still at the pre-seal count -> the tx did not land -> roll back.
        assert_eq!(crate::settle_failure_action(5, 5), RollAction::RollBack);
        // chain advanced by exactly one -> the tx landed despite the error -> roll forward.
        assert_eq!(crate::settle_failure_action(5, 6), RollAction::RollForward);
        // anything else is unexpected -> hold (no mutation).
        assert_eq!(crate::settle_failure_action(5, 7), RollAction::Hold);
        assert_eq!(crate::settle_failure_action(5, 4), RollAction::Hold);
        assert_eq!(crate::settle_failure_action(0, 0), RollAction::RollBack);
    }

    /// Fix round 2 (final-review TOCTOU): the boot-recovery confirm-delay fires
    /// ONLY in the ambiguous row — `prepared` journaled (so a settle tx may have
    /// been broadcast) AND the first chain read still shows the pre-settle
    /// batchCount (so the tx may be mined-but-not-yet-visible). `prepared`
    /// absent PROVES no broadcast ever happened (stage-2 journal write precedes
    /// the broadcast), and any other batchCount already disambiguates — no wait.
    #[test]
    fn needs_confirm_delay_only_for_ambiguous_prepared_row() {
        // ambiguous: prepared present + chain still at the journal's window id.
        assert!(crate::needs_confirm_delay(true, 5, 5));
        assert!(crate::needs_confirm_delay(true, 0, 0));
        // no prepared -> no tx was ever broadcast -> first read is authoritative.
        assert!(!crate::needs_confirm_delay(false, 5, 5));
        assert!(!crate::needs_confirm_delay(false, 0, 0));
        // chain already advanced (or is otherwise off) -> already disambiguated.
        assert!(!crate::needs_confirm_delay(true, 6, 5));
        assert!(!crate::needs_confirm_delay(true, 4, 5));
        assert!(!crate::needs_confirm_delay(false, 6, 5));
    }

    // ── off-chain receipt reconciliation (Slice 3b-4) ────────────────────────

    /// `GET /v1/batch/:id` reconciliation: a sealed tick (Counter A) maps to its
    /// on-chain window (Counter B); `settled` flips only once the chain's
    /// `batchCount` advances past that window; unknown ticks are null/unsettled.
    #[test]
    fn v1_batch_json_reconciles_tick_to_window() {
        let mut gw = Gw::boot();
        // seal a tick so the sequencer records a tick->window entry.
        let s = gw.seq.seal_batch(&[], now_ms());
        let window = gw.seq.window_for_tick(s.batch_id).unwrap();
        // no L1 status yet (batch_count defaults to 0) -> not settled.
        let v = gw.v1_batch_json(s.batch_id);
        assert_eq!(v["counterA"], s.batch_id);
        assert_eq!(v["windowId"], window);
        assert_eq!(v["settled"], false);
        // an unknown tick id -> windowId null, settled false.
        let u = gw.v1_batch_json(s.batch_id + 9999);
        assert!(u["windowId"].is_null());
        assert_eq!(u["settled"], false);
        // once the chain's batchCount advances PAST the window, it reads settled.
        gw.l1_status = Some(L1Status {
            batch_count: window + 1,
            ..Default::default()
        });
        let sv = gw.v1_batch_json(s.batch_id);
        assert_eq!(sv["windowId"], window);
        assert_eq!(sv["settled"], true);
        // batchCount == window (not yet past it) -> still unsettled.
        gw.l1_status = Some(L1Status {
            batch_count: window,
            ..Default::default()
        });
        assert_eq!(gw.v1_batch_json(s.batch_id)["settled"], false);
    }

    // ── sealed state persistence ─────────────────────────────────────────────

    /// The full restart round trip: mutate state (register, deposit, rest a
    /// maker order) → snapshot → seal → open → restore → the engine state is
    /// identical (state root, accounts, orders, LP pool, market dynamics), with
    /// the enclave identity rebuilt from the environment, never from disk.
    #[test]
    fn snapshot_restart_round_trip_preserves_state() {
        let seed = [42u8; 32];
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        // a far-from-market Gtc bid RESTS in the matcher book, so the round trip
        // must also carry the book (not just settled state)
        let receipt = gw
            .account_place_order(
                &key,
                &OrderReq {
                    market_id: 0,
                    side: "Buy".into(),
                    size: "1".into(),
                    limit_price: "1".into(),
                    tif: "Gtc".into(),
                    reduce_only: false,
                    nonce: None,
                    signature: None,
                    ..Default::default()
                },
            )
            .unwrap();
        gw.mkts[0].px += 1234; // market dynamics must survive too
        let root_before = gw.state_root_hex();
        let px_before = gw.mkts[0].px;
        let log_head_before = gw.order_log.head();
        assert_ne!(log_head_before, [0u8; 32], "the accepted order was logged");

        let sealed = snapshot::seal(&gw.snapshot_plain(), &seed);
        let plain = snapshot::open(&sealed, &seed).expect("authentic snapshot opens");
        let restored = Gw::boot_restored(&plain).expect("restore");

        assert_eq!(
            restored.state_root_hex(),
            root_before,
            "state root survives"
        );
        assert_eq!(restored.accounts.len(), gw.accounts.len());
        let acct = restored.accounts.get(&key).expect("account survives");
        assert_eq!(acct.orders.len(), 1, "order history survives");
        assert_eq!(
            acct.orders[0].receipt.order_hash, receipt.order_hash,
            "signed receipt survives"
        );
        assert_eq!(restored.lp_total_shares, gw.lp_total_shares);
        assert_eq!(restored.next_withdraw_nonce, gw.next_withdraw_nonce);
        assert_eq!(restored.mkts[0].px, px_before, "market px overlay survives");
        assert_eq!(
            restored.mkts[0].symbol, gw.mkts[0].symbol,
            "static market config rebuilt"
        );
        // The encrypted order log survives the restart intact: same entries, same
        // head, chain still verifies …
        assert_eq!(restored.order_log.len(), 1, "order-log entry survives");
        assert_eq!(restored.order_log.head(), log_head_before, "log head survives");
        assert_eq!(
            restored.order_log.recompute_head(),
            log_head_before,
            "restored chain re-folds to the same head"
        );
        // … and the recipient pubkey was NOT read from disk (it is serde-skipped):
        // boot_restored re-derived the SAME key boot() derived from ENCLAVE_SEED,
        // so the restored gateway keeps sealing to the identical log key.
        assert_eq!(
            restored.order_log.recipient(),
            gw.order_log.recipient(),
            "log pubkey re-derived from the seed, not persisted"
        );
    }

    /// Task 12: every ACCEPTED `/v1` order is appended to the hash-chained
    /// encrypted order log (sealed entry + advancing, recomputable head), and a
    /// REJECTED order is not.
    #[test]
    fn accepted_order_appends_to_encrypted_order_log() {
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        assert!(gw.order_log.is_empty(), "log starts empty");
        assert_eq!(gw.order_log.head(), [0u8; 32], "head starts at zero");

        // far-from-market Gtc bid: accepted, rests on the book
        let req = |market_id: u64| OrderReq {
            market_id,
            side: "Buy".into(),
            size: "1".into(),
            limit_price: "1".into(),
            tif: "Gtc".into(),
            reduce_only: false,
            nonce: None,
            signature: None,
            ..Default::default()
        };
        gw.account_place_order(&key, &req(0)).expect("order accepted");
        assert_eq!(gw.order_log.len(), 1, "accepted order appended");
        let head = gw.order_log.head();
        assert_ne!(head, [0u8; 32], "head advanced");
        assert_eq!(gw.order_log.recompute_head(), head, "chain verifies");

        // A rejected order (unknown market) must NOT touch the log.
        assert!(gw.account_place_order(&key, &req(999)).is_err());
        assert_eq!(gw.order_log.len(), 1, "rejected order not logged");
        assert_eq!(gw.order_log.head(), head, "head unchanged by a reject");

        // A second accept chains onto the first (the encryption property itself —
        // plaintext absent from the stored entry, opens only under the seed-derived
        // log secret — is proven by the order_log.rs module tests).
        gw.account_place_order(&key, &req(0)).expect("second order");
        assert_eq!(gw.order_log.len(), 2);
        assert_ne!(gw.order_log.head(), head, "each accept advances the chain");
        assert_eq!(gw.order_log.recompute_head(), gw.order_log.head());
    }

    /// `/v1/markets/:id/candles` serves the recorded engine history: real bars in,
    /// real bars out (ascending, scaled strings), 400 on a bogus timeframe, 404 on
    /// an unknown market.
    #[tokio::test]
    async fn candles_endpoint_serves_recorded_history() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        let app = test_app();
        {
            let mut cs = app.candles.lock().await;
            cs.record(0, 60_000, 100_000_000);
            cs.record(0, 90_000, 130_000_000);
            cs.record(0, 120_000, 90_000_000);
        }
        let router = build_router(app.clone(), false);
        let get = |uri: &str| Request::builder().uri(uri).body(Body::empty()).unwrap();

        let r = router
            .clone()
            .oneshot(get("/v1/markets/0/candles?tf=1m&limit=10"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let cs = v["candles"].as_array().unwrap();
        assert_eq!(cs.len(), 2, "two 1m buckets were recorded");
        assert_eq!(cs[0]["t"], 60_000, "ascending buckets");
        assert_eq!(cs[0]["o"], "100000000");
        assert_eq!(cs[0]["h"], "130000000");
        assert_eq!(cs[1]["o"], "90000000");

        let r = router
            .clone()
            .oneshot(get("/v1/markets/0/candles?tf=3m"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "unknown timeframe");
        let r = router.oneshot(get("/v1/markets/99/candles")).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "unknown market");
    }

    /// A snapshot sealed under one enclave seed must not open under another —
    /// the restore path is fail-closed on the wrong secret (no silent fresh boot).
    #[test]
    fn snapshot_wrong_enclave_seed_fails_closed() {
        let gw = Gw::boot();
        let sealed = snapshot::seal(&gw.snapshot_plain(), &[42u8; 32]);
        assert!(snapshot::open(&sealed, &[43u8; 32]).is_err());
    }

    // audit DP-001: in the production posture, the self-service (unbacked) deposit
    // faucet must be refused — collateral may only enter via a verified on-chain deposit.
    #[test]
    fn production_mode_refuses_self_service_deposit() {
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        // demo/dev build: the self-service faucet credit is allowed
        assert!(
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).is_ok(),
            "demo build allows the self-service deposit faucet",
        );
        // production posture: unbacked self-service credit is refused (audit DP-001)
        gw.prod = true;
        assert!(
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).is_err(),
            "production build must reject self-service (unbacked) deposits",
        );
    }

    // audit DP-010: the production router must not mount the legacy, unauthenticated
    // `/api/*` mutation routes, while the API-key-authenticated `/v1` surface stays up.
    #[tokio::test]
    async fn production_mode_drops_legacy_unauthenticated_api_mutations() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _; // for `oneshot`

        let post = |uri: &str| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::empty())
                .unwrap()
        };

        // demo build: the legacy /api/order mutation route IS mounted (not 404)
        let demo = build_router(test_app(), false);
        let r = demo.oneshot(post("/api/order")).await.unwrap();
        assert_ne!(
            r.status(),
            StatusCode::NOT_FOUND,
            "legacy /api/order is mounted in the demo build",
        );

        // production build: the legacy unauthenticated mutation route is NOT mounted (404)
        let prod = build_router(test_app(), true);
        let r = prod.oneshot(post("/api/order")).await.unwrap();
        assert_eq!(
            r.status(),
            StatusCode::NOT_FOUND,
            "legacy /api/order must be gone in the production build",
        );

        // …but the authenticated /v1 surface is still served in production (public GET → not 404)
        let prod2 = build_router(test_app(), true);
        let r = prod2
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/markets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            r.status(),
            StatusCode::NOT_FOUND,
            "/v1 surface stays mounted in the production build",
        );
    }

    // enabling the L1 settlement bridge (real USDC at stake) forces the production
    // posture regardless of DARKPERP_PROD (short-circuits before reading the env).
    #[test]
    fn l1_enabled_implies_production_mode() {
        assert!(
            production_mode(true),
            "L1-enabled deployments are always in the production posture",
        );
    }

    // audit DP-006: production must fail closed when the enclave has no verified
    // attestation, instead of silently serving traffic under the stub measurement.
    #[test]
    fn production_requires_verified_attestation() {
        // demo/dev build boots with or without attestation
        assert!(
            attestation_ok_for_mode(false, false),
            "demo build boots un-attested"
        );
        // production boots only when attestation is present…
        assert!(
            attestation_ok_for_mode(true, true),
            "production boots when attested"
        );
        // …and fails closed when it is missing/failed
        assert!(
            !attestation_ok_for_mode(true, false),
            "production must fail closed without a verified attestation",
        );
    }

    // audit DP-004 (answering): the proof build_challenge_answer produces must verify against the
    // same ordered/rejected root the settle loop publishes on-chain, for both an ordered and a
    // validly-rejected order; an unknown order yields no answer.
    #[test]
    fn build_challenge_answer_produces_a_verifying_proof() {
        let mut gw = Gw::boot();
        let (o1, o2, r1) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        gw.batch_orders.insert(7, (vec![o1, o2], vec![r1]));

        // an ORDERED order → inclusion answer whose proof verifies against the ordered root
        let (is_rej, bid, proof) = gw
            .build_challenge_answer(&o1)
            .expect("answer for ordered order");
        assert!(!is_rej);
        assert_eq!(bid, 7);
        let ordered_leaves: Vec<_> = [o1, o2].iter().map(|h| inclusion_leaf(7, h)).collect();
        assert!(withdrawals::verify(
            merkle_root(&ordered_leaves),
            inclusion_leaf(7, &o1),
            &proof
        ));

        // a REJECTED order → rejection answer whose proof verifies against the rejected root
        let (is_rej, bid, proof) = gw
            .build_challenge_answer(&r1)
            .expect("answer for rejected order");
        assert!(is_rej);
        assert_eq!(bid, 7);
        let rejected_leaves: Vec<_> = [r1].iter().map(|h| rejection_leaf(7, h)).collect();
        assert!(withdrawals::verify(
            merkle_root(&rejected_leaves),
            rejection_leaf(7, &r1),
            &proof
        ));

        // an order in no retained batch → no answer (a genuine withhold, correctly unanswerable)
        assert!(gw.build_challenge_answer(&[9u8; 32]).is_none());
    }

    // audit DP-006 follow-up: production must reject the public demo enclave seed (a
    // constant key lets anyone forge receipts and slash the sequencer bond).
    #[test]
    fn production_requires_a_secret_enclave_seed() {
        assert!(
            enclave_seed_ok_for_mode(false, false),
            "demo build boots with the default seed"
        );
        assert!(
            enclave_seed_ok_for_mode(true, true),
            "production boots with a secret seed"
        );
        assert!(
            !enclave_seed_ok_for_mode(true, false),
            "production must reject the public demo enclave seed",
        );
    }

    // audit DP-006 review follow-up: a malformed ENCLAVE_SEED must be rejected cleanly, and
    // the value-based demo-seed check flags the public constant even when supplied by value.
    #[test]
    fn enclave_seed_validation_and_demo_detection() {
        assert!(
            enclave_seed_is_valid([7u8; 32]),
            "the demo scalar is a valid secp256k1 key"
        );
        assert!(
            !enclave_seed_is_valid([0u8; 32]),
            "zero is not a valid scalar (no panic)"
        );
        assert!(
            !enclave_seed_is_valid([0xffu8; 32]),
            "a value >= the curve order is rejected"
        );
        // the public demo constant is detected as the default regardless of provenance
        assert_eq!(DEMO_ENCLAVE_SEED, [7u8; 32]);
    }

    // audit DP-006 follow-up: production must pin the expected enclave measurement, so a
    // different/replayed valid quote (e.g. the in-repo fixture) cannot pass.
    #[test]
    fn production_pins_the_expected_measurement() {
        let m = [0xAAu8; 32];
        assert!(
            measurement_matches_pin(false, Some(m), None),
            "demo needs no pin"
        );
        assert!(
            measurement_matches_pin(true, Some(m), Some(m)),
            "prod accepts the pinned measurement"
        );
        assert!(
            !measurement_matches_pin(true, Some(m), Some([0xBBu8; 32])),
            "prod rejects a measurement that does not match the pin (wrong/replayed enclave)",
        );
        assert!(
            !measurement_matches_pin(true, Some(m), None),
            "prod requires an explicit pin"
        );
        assert!(
            !measurement_matches_pin(true, None, Some(m)),
            "prod requires a verified measurement"
        );
    }

    #[test]
    fn boot_funds_user_to_15k() {
        let gw = Gw::boot();
        // ≈ $15,000 across the 3 markets + a $2,000,000 market-0 LP allowance.
        let free = gw.free_balance();
        assert!(
            (2_010_000 * QUOTE_SCALE..=2_020_000 * QUOTE_SCALE).contains(&free),
            "free={free}"
        );
        assert_eq!(gw.snapshot().markets.len(), 3);
    }

    #[test]
    fn mock_prover_client_matches_derive_roots() {
        use crate::prover_client::{MockProverClient, ProverClient};
        use perp_core::commitment::derive_roots;
        use perp_core::Keccak256;

        // A realistic non-empty window: boot registers markets + funds (those ops land
        // in window_ops), so the first seal_window yields a valid, non-trivial witness.
        let mut gw = Gw::boot();
        let witness = gw.seq.seal_window();

        let out = MockProverClient.prove(&witness).expect("mock prove");

        // Independently derive the same roots and assert byte-equality.
        let mut state = witness.pre_state.clone();
        let d = derive_roots(&mut state, &witness.ops, &witness.manifest).expect("derive");
        assert_eq!(out.prev_root, d.prev_state_root);
        assert_eq!(out.manifest_hash, d.manifest_hash);
        assert_eq!(out.new_root, d.new_state_root);
        assert_eq!(out.ordered_root, d.ordered_root);
        assert_eq!(out.withdrawals_root, d.withdrawals_root);
        assert_eq!(out.rejected_root, d.rejected_root);
        assert_eq!(out.commitment, d.commitment::<Keccak256>());
        // MockZkVerifier accepts proof == commitment.
        assert_eq!(out.proof, out.commitment.to_vec());
    }

    #[test]
    fn prover_from_str_selects_path() {
        assert!(prover_from_str(None).unwrap().is_none());
        assert!(prover_from_str(Some("")).unwrap().is_none());
        assert!(prover_from_str(Some("mock")).unwrap().is_some());
        assert!(prover_from_str(Some("http://prover.local:8091")).unwrap().is_some());
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
            nonce: None,
            signature: None,
            ..Default::default()
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
        assert!(
            fin == "MATCHED" || fin == "SETTLED",
            "finality advanced: {fin}"
        );
        // after SETTLE_TICKS more ticks → SETTLED
        for _ in 0..(SETTLE_TICKS + 1) {
            gw.tick();
        }
        assert_eq!(gw.finality_str(&gw.orders[0].order_hash), "SETTLED");
    }

    #[test]
    fn v1_accounts_are_isolated_and_trade() {
        let mut gw = Gw::boot();
        let (a_key, a_owner) = gw.register_account(None);
        let (b_key, b_owner) = gw.register_account(None);
        assert_ne!(a_key, b_key, "distinct api keys");
        assert_ne!(a_owner, b_owner, "distinct owners");
        // A deposits $20k into market 0 and goes long 0.1 BTC
        gw.account_deposit(&a_key, 0, 20_000 * QUOTE_SCALE)
            .expect("deposit");
        let req = OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            nonce: None,
            signature: None,
            ..Default::default()
        };
        gw.account_place_order(&a_key, &req).expect("order");
        gw.tick();
        // A is long; B has nothing — full isolation over the shared engine
        let a_pos = gw.seq.state.position(&a_owner, 0).expect("A position");
        assert!(a_pos.size > 0, "A is long after the seal");
        assert!(
            gw.seq.state.position(&b_owner, 0).is_none(),
            "B has no position"
        );
        let a_orders = gw.v1_orders_json(&a_key).unwrap();
        assert_eq!(a_orders["orders"].as_array().unwrap().len(), 1);
        let b_orders = gw.v1_orders_json(&b_key).unwrap();
        assert!(
            b_orders["orders"].as_array().unwrap().is_empty(),
            "B has no orders"
        );
        // an unknown key has no view
        assert!(gw.v1_account(&[0xff; 32]).is_none());
    }

    #[test]
    fn caller_signed_orders_require_a_valid_signature() {
        use k256::ecdsa::SigningKey;
        use sha3::{Digest as _, Keccak256 as RawKeccak};

        fn eth_addr(sk: &SigningKey) -> [u8; 20] {
            let point = sk.verifying_key().to_encoded_point(false);
            let hash = RawKeccak::digest(&point.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&hash[12..]);
            a
        }
        fn sign(sk: &SigningKey, oh: &Digest) -> String {
            let (sig, recid) = sk.sign_prehash_recoverable(oh).unwrap();
            let mut s = [0u8; 65];
            s[..64].copy_from_slice(&sig.to_bytes());
            s[64] = 27 + recid.to_byte();
            hex0x(&s)
        }
        fn req(
            market: u64,
            size: i128,
            limit: i128,
            nonce: Option<u64>,
            sig: Option<String>,
        ) -> OrderReq {
            OrderReq {
                market_id: market,
                side: "Buy".into(),
                size: size.to_string(),
                limit_price: limit.to_string(),
                tif: "Ioc".into(),
                reduce_only: false,
                nonce,
                signature: sig,
                ..Default::default()
            }
        }

        let mut gw = Gw::boot();
        let sk = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let (key, owner) = gw.register_account(Some(eth_addr(&sk)));
        gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();

        let market = 0u64;
        let limit = gw.px_of(market); // caller-signed orders are limit orders (price is signed)
        let size = SIZE_SCALE / 10;

        // the exact order the gateway will reconstruct, signed by the caller's key
        let order = mk_order(
            owner,
            market,
            Side::Buy,
            size,
            limit,
            1,
            TimeInForce::Ioc,
            false,
        );
        let oh = order.order_hash::<Keccak256>();
        assert!(
            gw.account_place_order(
                &key,
                &req(market, size, limit, Some(1), Some(sign(&sk, &oh)))
            )
            .is_ok(),
            "a valid caller signature is accepted",
        );

        // replay: reusing nonce 1 is rejected (strictly-increasing nonce)
        assert!(
            gw.account_place_order(
                &key,
                &req(market, size, limit, Some(1), Some(sign(&sk, &oh)))
            )
            .is_err(),
            "nonce replay rejected",
        );

        // a missing signature on a caller-signed account is rejected
        assert!(
            gw.account_place_order(&key, &req(market, size, limit, Some(2), None))
                .is_err(),
            "missing signature rejected",
        );

        // a signature from a DIFFERENT key (wrong signer) is rejected
        let wrong = SigningKey::from_bytes((&[10u8; 32]).into()).unwrap();
        let order2 = mk_order(
            owner,
            market,
            Side::Buy,
            size,
            limit,
            2,
            TimeInForce::Ioc,
            false,
        );
        let oh2 = order2.order_hash::<Keccak256>();
        assert!(
            gw.account_place_order(
                &key,
                &req(market, size, limit, Some(2), Some(sign(&wrong, &oh2)))
            )
            .is_err(),
            "wrong-key signature rejected",
        );

        // FIELD-BINDING (review fix): a signature is bound to the EXACT trade terms.
        // Sign a Buy of `size` @ limit (nonce 5), then submit size*2 with that same
        // signature — it must be rejected (the size is bound into the order hash)…
        let signed = mk_order(
            owner,
            market,
            Side::Buy,
            size,
            limit,
            5,
            TimeInForce::Ioc,
            false,
        );
        let sig5 = sign(&sk, &signed.order_hash::<Keccak256>());
        assert!(
            gw.account_place_order(
                &key,
                &req(market, size * 2, limit, Some(5), Some(sig5.clone()))
            )
            .is_err(),
            "a tampered size under a valid signature is rejected",
        );
        // …while the untampered order with that same signature IS accepted (proving
        // the rejection was the tamper, not a bad signature).
        assert!(
            gw.account_place_order(&key, &req(market, size, limit, Some(5), Some(sig5)))
                .is_ok(),
            "the untampered order with that signature is accepted",
        );

        // a server-custody account (no signer) still trades without a signature
        let (srv, _) = gw.register_account(None);
        gw.account_deposit(&srv, 0, 50_000 * QUOTE_SCALE).unwrap();
        assert!(
            gw.account_place_order(&srv, &req(market, size, 0, None, None))
                .is_ok(),
            "server-custody account unaffected",
        );
    }

    #[test]
    fn lp_deposit_debits_the_depositor_no_free_mint() {
        let mut gw = Gw::boot();
        let who = gw.user.owner;
        let w = gw.user;
        let free0 = gw.market_free_of(&who, 0);
        let pool0 = gw.pool_equity();

        // depositing more than the depositor's market-0 balance is rejected (no free mint)
        assert!(
            gw.lp_deposit(who, &w, free0 + 1).is_err(),
            "free-mint blocked"
        );

        // a valid deposit debits the depositor and grows the pool by the same amount
        let dep = 500_000 * QUOTE_SCALE;
        let shares = gw.lp_deposit(who, &w, dep).expect("deposit");
        assert!(shares > 0);
        assert_eq!(gw.market_free_of(&who, 0), free0 - dep, "depositor debited");
        assert!(
            (gw.pool_equity() - pool0 - dep).abs() < QUOTE_SCALE,
            "pool grew by the deposit"
        );

        // withdraw pays back into the depositor's balance (conserved, flat NAV)
        let val = gw.lp_withdraw(&who, &w, shares).expect("withdraw");
        assert!(
            (val - dep).abs() < QUOTE_SCALE,
            "withdraw ≈ deposit at flat NAV"
        );
        assert!(
            (gw.market_free_of(&who, 0) - free0).abs() < QUOTE_SCALE,
            "depositor made whole"
        );
    }

    #[test]
    fn deposit_address_bind_requires_ownership_proof() {
        use k256::ecdsa::SigningKey;
        use sha3::{Digest as _, Keccak256 as RawKeccak};
        fn eth_addr(sk: &SigningKey) -> [u8; 20] {
            let point = sk.verifying_key().to_encoded_point(false);
            let hash = RawKeccak::digest(&point.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&hash[12..]);
            a
        }
        fn sign(sk: &SigningKey, digest: &[u8; 32]) -> [u8; 65] {
            let (sig, recid) = sk.sign_prehash_recoverable(digest).unwrap();
            let mut s = [0u8; 65];
            s[..64].copy_from_slice(&sig.to_bytes());
            s[64] = 27 + recid.to_byte();
            s
        }

        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        let eoa = SigningKey::from_bytes((&[3u8; 32]).into()).unwrap();
        let addr = eth_addr(&eoa);

        // a proof signed by a DIFFERENT key (not the address being bound) is rejected
        let wrong = SigningKey::from_bytes((&[4u8; 32]).into()).unwrap();
        let bad = sign(&wrong, &deposit_bind_digest(&owner, &addr));
        assert!(
            gw.account_set_deposit_address(&key, addr, &bad).is_err(),
            "a proof not from the bound address is rejected",
        );

        // the address's own key proves control → bind succeeds
        let good = sign(&eoa, &deposit_bind_digest(&owner, &addr));
        assert!(
            gw.account_set_deposit_address(&key, addr, &good).is_ok(),
            "valid ownership proof accepted",
        );

        // exclusivity: another account can't bind the same address (even controlling it)
        let (key2, owner2) = gw.register_account(None);
        let good2 = sign(&eoa, &deposit_bind_digest(&owner2, &addr));
        assert!(
            gw.account_set_deposit_address(&key2, addr, &good2).is_err(),
            "an address already bound to another account is rejected",
        );
    }

    /// Browser wallets (MetaMask etc.) cannot sign a raw 32-byte digest —
    /// `personal_sign` always wraps the message with the EIP-191 prefix before
    /// hashing. The bind endpoint must therefore accept, besides the raw-digest
    /// form pinned above, the two `personal_sign` shapes a wallet can produce
    /// from the SAME `deposit_bind_digest`: over its 32 raw bytes, and over its
    /// ASCII "0x<64 lowercase hex>" string. A signature from any other key must
    /// stay rejected in every form.
    #[test]
    fn deposit_address_bind_accepts_eip191_personal_sign_forms() {
        use k256::ecdsa::SigningKey;
        use sha3::{Digest as _, Keccak256 as RawKeccak};
        fn eth_addr(sk: &SigningKey) -> [u8; 20] {
            let point = sk.verifying_key().to_encoded_point(false);
            let hash = RawKeccak::digest(&point.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&hash[12..]);
            a
        }
        fn sign(sk: &SigningKey, prehash: &[u8; 32]) -> [u8; 65] {
            let (sig, recid) = sk.sign_prehash_recoverable(prehash).unwrap();
            let mut s = [0u8; 65];
            s[..64].copy_from_slice(&sig.to_bytes());
            s[64] = 27 + recid.to_byte();
            s
        }
        /// What `personal_sign` actually hashes: EIP-191 prefix + decimal
        /// byte-length + the message bytes.
        fn eip191_prehash(msg: &[u8]) -> [u8; 32] {
            let mut h = RawKeccak::new();
            h.update(b"\x19Ethereum Signed Message:\n");
            h.update(msg.len().to_string().as_bytes());
            h.update(msg);
            h.finalize().into()
        }
        fn hex_string(digest: &[u8; 32]) -> String {
            let mut s = String::from("0x");
            for b in digest {
                s.push_str(&format!("{b:02x}"));
            }
            s
        }

        let mut gw = Gw::boot();

        // (2) EIP-191 over the 32 raw digest bytes — the frontend calls
        // `personal_sign` with the digest bytes, the wallet prefixes "\n32".
        let (key, owner) = gw.register_account(None);
        let eoa = SigningKey::from_bytes((&[5u8; 32]).into()).unwrap();
        let addr = eth_addr(&eoa);
        let digest = deposit_bind_digest(&owner, &addr);
        let sig = sign(&eoa, &eip191_prehash(&digest));
        assert!(
            gw.account_set_deposit_address(&key, addr, &sig).is_ok(),
            "EIP-191 personal_sign over the raw digest bytes accepted",
        );

        // (3) EIP-191 over the ASCII hex STRING of the digest — some wallets
        // sign the UTF-8 text "0x<64 hex>" (66 bytes) instead of the raw bytes.
        let (key2, owner2) = gw.register_account(None);
        let eoa2 = SigningKey::from_bytes((&[6u8; 32]).into()).unwrap();
        let addr2 = eth_addr(&eoa2);
        let digest2 = deposit_bind_digest(&owner2, &addr2);
        let hex_msg = hex_string(&digest2);
        assert_eq!(hex_msg.len(), 66, "sanity: 0x + 64 hex chars");
        let sig2 = sign(&eoa2, &eip191_prehash(hex_msg.as_bytes()));
        assert!(
            gw.account_set_deposit_address(&key2, addr2, &sig2).is_ok(),
            "EIP-191 personal_sign over the digest's hex string accepted",
        );

        // (4) a DIFFERENT key is rejected in ALL three forms — accepting the
        // extra digest shapes must not widen who can authorize a bind.
        let (key3, owner3) = gw.register_account(None);
        let eoa3 = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let addr3 = eth_addr(&eoa3);
        let wrong = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
        let digest3 = deposit_bind_digest(&owner3, &addr3);
        let forms: [[u8; 32]; 3] = [
            digest3,
            eip191_prehash(&digest3),
            eip191_prehash(hex_string(&digest3).as_bytes()),
        ];
        for (i, prehash) in forms.iter().enumerate() {
            let bad = sign(&wrong, prehash);
            assert!(
                gw.account_set_deposit_address(&key3, addr3, &bad).is_err(),
                "wrong-key signature rejected for digest form {i}",
            );
        }
    }

    /// AUDIT (CRITICAL — off-market fill-price vault drain): the gateway's house
    /// market-maker must quote at the validated oracle mark, never at the taker's
    /// own limit. A Buy Ioc whose limit sits far below the mark does not cross and
    /// must NOT open a position — otherwise a taker mints an off-market entry
    /// (buy 1 @ $1 while mark is ~$59.5k → equity ≈ +mark), closes it against the
    /// house at another off-market price, and withdraws the difference from the vault.
    #[test]
    fn ioc_taker_cannot_open_a_position_below_the_oracle_mark() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let mark = gw.px_of(0);
        assert!(
            mark > PRICE_SCALE,
            "sanity: BTC mark is far above 1 price-unit"
        );
        // Offer to BUY 0.1 BTC at a limit of 1 price-unit (~$1e-8) — wildly below the
        // ~$59.5k mark. No rational counterparty sells here; only the fabricated house
        // MM could, and at this price it must not.
        gw.account_place_order(
            &key,
            &OrderReq {
                market_id: 0,
                side: "Buy".into(),
                size: (SIZE_SCALE / 10).to_string(),
                limit_price: "1".into(),
                tif: "Ioc".into(),
                reduce_only: false,
                nonce: None,
                signature: None,
                ..Default::default()
            },
        )
        .expect("order admitted");
        gw.tick();
        let opened = gw.seq.state.position(&owner, 0).map_or(0, |p| p.size);
        assert_eq!(opened, 0, "off-market limit buy must NOT open a position");
    }

    /// AUDIT (#3): recovery must never surface another account's notes. Boot funds the
    /// demo user + MM into the archive; a caller submitting a random seed that derives a
    /// DIFFERENT view-key must recover NOTHING (the removed cross-account fallback used
    /// to return the house account's note amounts to any such caller).
    #[test]
    fn recover_does_not_leak_another_accounts_notes() {
        let gw = Gw::boot();
        let recovered = gw.recover("a-random-seed-that-matches-no-wallet-in-this-gateway");
        assert!(
            recovered.is_empty(),
            "a non-matching seed must recover nothing, got {} notes",
            recovered.len()
        );
    }

    /// AUDIT (#8): on boot the challenge watcher rewinds past the challenge window so
    /// a restart doesn't skip challenges raised while it was down (→ wrongful slash).
    #[test]
    fn challenge_scan_start_rewinds_past_the_window() {
        // rewinds 1.5x the window behind the current block
        assert_eq!(challenge_scan_start(10_000, 300), 10_000 - 450);
        // saturates at 0 near genesis rather than underflowing
        assert_eq!(challenge_scan_start(100, 300), 0);
        // a tiny/zero window still rewinds a 64-block floor (never starts at `now`,
        // which is the pre-fix bug that skipped in-flight challenges)
        assert_eq!(challenge_scan_start(10_000, 0), 10_000 - 64);
        assert_eq!(challenge_scan_start(10_000, 10), 10_000 - 64);
    }

    /// AUDIT (Tier-3): the order-history cap evicts the OLDEST terminal (SETTLED) entries
    /// first and NEVER a live/in-flight one, bounding growth without losing pending orders.
    #[test]
    fn cap_history_evicts_oldest_terminal_only() {
        // "S" = settled/terminal, "A" = live. Cap at 2.
        let mut v = vec!["S", "S", "S", "A", "A"];
        cap_history(&mut v, 2, |s| *s == "S");
        assert_eq!(v, vec!["A", "A"], "oldest settled evicted down to the cap");
        // live entries are never evicted, even if that leaves the Vec above the cap
        let mut v2 = vec!["S", "A", "A", "A"];
        cap_history(&mut v2, 2, |s| *s == "S");
        assert_eq!(
            v2,
            vec!["A", "A", "A"],
            "only the settled entry evicted; live kept"
        );
        // no-op when already within the cap
        let mut v3 = vec!["S", "A"];
        cap_history(&mut v3, 5, |s| *s == "S");
        assert_eq!(v3, vec!["S", "A"]);
    }

    /// AUDIT (rate-limit behind proxy): the register limiter must key on the real
    /// client IP, trusting forwarding headers only from a loopback proxy peer and
    /// ignoring them on a direct (spoofable) connection.
    #[test]
    fn client_ip_trusts_proxy_only_from_loopback() {
        let mk = |xff: Option<&str>, xri: Option<&str>| {
            let mut h = HeaderMap::new();
            if let Some(v) = xff {
                h.insert("x-forwarded-for", v.parse().unwrap());
            }
            if let Some(v) = xri {
                h.insert("x-real-ip", v.parse().unwrap());
            }
            h
        };
        let loop_peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let pub_peer: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();

        // behind the proxy: the LAST XFF entry (the client as the proxy saw it) wins,
        // even when the client prepends a spoofed value.
        assert_eq!(
            client_ip(loop_peer, &mk(Some("9.9.9.9, 1.2.3.4"), None)),
            ip("1.2.3.4"),
        );
        // X-Real-IP is the fallback when there's no XFF.
        assert_eq!(
            client_ip(loop_peer, &mk(None, Some("5.6.7.8"))),
            ip("5.6.7.8")
        );
        // a direct (non-loopback) peer: headers are attacker-controlled → ignore them.
        assert_eq!(
            client_ip(pub_peer, &mk(Some("1.2.3.4"), None)),
            ip("203.0.113.9")
        );
        // loopback peer with no forwarding headers → fall back to the peer itself.
        assert_eq!(client_ip(loop_peer, &mk(None, None)), ip("127.0.0.1"));
    }

    /// AUDIT (DP-009 follow-up): a caller-signed order's signature must bind
    /// `reduce_only`. A relay / leaked-key holder that flips a signed reduce-only
    /// order into a position-opening one (reduce_only true→false) must be rejected —
    /// the signature covers the flag.
    #[test]
    fn caller_signed_orders_bind_reduce_only() {
        use k256::ecdsa::SigningKey;
        use sha3::{Digest as _, Keccak256 as RawKeccak};

        fn eth_addr(sk: &SigningKey) -> [u8; 20] {
            let point = sk.verifying_key().to_encoded_point(false);
            let hash = RawKeccak::digest(&point.as_bytes()[1..]);
            let mut a = [0u8; 20];
            a.copy_from_slice(&hash[12..]);
            a
        }
        fn sign(sk: &SigningKey, oh: &Digest) -> String {
            let (sig, recid) = sk.sign_prehash_recoverable(oh).unwrap();
            let mut s = [0u8; 65];
            s[..64].copy_from_slice(&sig.to_bytes());
            s[64] = 27 + recid.to_byte();
            hex0x(&s)
        }

        let mut gw = Gw::boot();
        let sk = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
        let (key, owner) = gw.register_account(Some(eth_addr(&sk)));
        gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();
        let market = 0u64;
        let limit = gw.px_of(market);
        let size = SIZE_SCALE / 10;

        // The caller signs an order they intend as reduce_only = TRUE.
        let signed = mk_order(
            owner,
            market,
            Side::Buy,
            size,
            limit,
            1,
            TimeInForce::Ioc,
            true,
        );
        let sig = sign(&sk, &signed.order_hash::<Keccak256>());

        // A relay flips it to reduce_only = FALSE (an opening order) under the SAME
        // signature. This must be rejected — otherwise the flag is unbound and the
        // reduce-only safety guarantee the signer relied on is silently bypassed.
        let tampered = OrderReq {
            market_id: market,
            side: "Buy".into(),
            size: size.to_string(),
            limit_price: limit.to_string(),
            tif: "Ioc".into(),
            reduce_only: false,
            nonce: Some(1),
            signature: Some(sig),
            ..Default::default()
        };
        assert!(
            gw.account_place_order(&key, &tampered).is_err(),
            "flipping reduce_only under a valid signature must be rejected",
        );
    }

    /// AUDIT (review #5): a /v1 MARKET order must still fill when the mark moves between
    /// accept and seal. Market orders keep limit_price==0 to the seal, so the crossing
    /// check never rejects them — unlike the regressed version that stamped the
    /// accept-time price and dropped the order once the mark drifted away.
    #[test]
    fn market_order_fills_even_when_the_mark_moves_after_accept() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 200_000 * QUOTE_SCALE).unwrap();
        gw.account_place_order(
            &key,
            &OrderReq {
                market_id: 0,
                side: "Buy".into(),
                size: (SIZE_SCALE / 10).to_string(),
                limit_price: "0".into(), // market order
                tif: "Ioc".into(),
                reduce_only: false,
                nonce: None,
                signature: None,
                ..Default::default()
            },
        )
        .expect("order admitted");
        // The mark jumps sharply UP before the batch seals. A stamped-limit order whose
        // accept-time price is now below the mark would fail the buy crossing check; a
        // true market order must still fill at the (new) mark.
        gw.mkts[0].px += 10_000 * PRICE_SCALE;
        gw.tick();
        let pos = gw
            .seq
            .state
            .position(&owner, 0)
            .expect("market order filled");
        assert!(
            pos.size > 0,
            "market order fills despite the adverse mark move"
        );
    }

    /// The symmetric direction: a Sell Ioc whose limit sits far ABOVE the mark does
    /// not cross the house MM and must NOT open a short at that off-market price.
    #[test]
    fn ioc_taker_cannot_open_a_short_above_the_oracle_mark() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        // Fund enough that the (limit-priced) admission margin check passes — a
        // well-capitalized attacker reaches the seal loop, where the fix must still
        // deny the off-market counter-fill.
        gw.account_deposit(&key, 0, 200_000 * QUOTE_SCALE).unwrap();
        let mark = gw.px_of(0);
        // Offer to SELL 0.1 BTC at 2× the mark — favorable off-market short entry.
        gw.account_place_order(
            &key,
            &OrderReq {
                market_id: 0,
                side: "Sell".into(),
                size: (SIZE_SCALE / 10).to_string(),
                limit_price: (mark * 2).to_string(),
                tif: "Ioc".into(),
                reduce_only: false,
                nonce: None,
                signature: None,
                ..Default::default()
            },
        )
        .expect("order admitted");
        gw.tick();
        let opened = gw.seq.state.position(&owner, 0).map_or(0, |p| p.size);
        assert_eq!(opened, 0, "off-market limit sell must NOT open a position");
    }

    /// Regression guard: a market order (limit 0) still fills at the mark — the fix
    /// only blocks OFF-market fills, it must not break normal trading.
    #[test]
    fn market_order_still_fills_at_the_mark() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let mark = gw.px_of(0);
        gw.account_place_order(
            &key,
            &OrderReq {
                market_id: 0,
                side: "Buy".into(),
                size: (SIZE_SCALE / 10).to_string(),
                limit_price: "0".into(),
                tif: "Ioc".into(),
                reduce_only: false,
                nonce: None,
                signature: None,
                ..Default::default()
            },
        )
        .expect("order admitted");
        gw.tick();
        let pos = gw.seq.state.position(&owner, 0).expect("position opened");
        assert!(pos.size > 0, "market buy opens a long");
        // entry is at the mark, not some off-market price
        assert!(
            pos.entry_price >= mark - PRICE_SCALE && pos.entry_price <= mark + PRICE_SCALE,
            "entry {} is at the mark {mark}",
            pos.entry_price
        );
    }

    // ── sealed order ingress (Task 10) ───────────────────────────────────────

    /// Seal an order client-side EXACTLY as the TS client (Task 11) will:
    /// serialize the canonical terms, seal them to the enclave epoch key with
    /// AAD = domain_aad(OrderEncryptAad, epoch_id_le ‖ owner), and 0x-hex the wire.
    /// A fixed ephemeral secret/nonce keeps the vector deterministic (test-only).
    fn seal_order_wire(
        epoch_pub: &[u8; 32],
        epoch_id: u64,
        owner: &PubKey,
        terms: &OrderTerms,
    ) -> String {
        let pt = serialize_order_terms(terms);
        let mut extra = Vec::with_capacity(8 + 32);
        extra.extend_from_slice(&epoch_id.to_le_bytes());
        extra.extend_from_slice(owner);
        let aad = sealed_box::domain_aad(Domain::OrderEncryptAad as u8, &extra);
        let sb = sealed_box::seal_with_ephemeral(epoch_pub, &pt, &aad, &[7u8; 32], &[9u8; 24]);
        hex0x(&sb.to_bytes())
    }

    /// Task 11 wire-shape regression (found by the client's live e2e): a sealed
    /// order carries ONLY `{epochId, sealed}` in the JSON body — no plaintext
    /// trade-term fields. The `/v1/orders` extractor must PARSE that body (the
    /// six plaintext `OrderReq` fields are `#[serde(default)]`) and the full
    /// HTTP round trip must decrypt + accept the order. Before the fix this
    /// 422'd at the Json extractor, so every spec-conform sealed client broke.
    #[tokio::test]
    async fn sealed_only_wire_body_parses_and_places_the_order() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _; // for `oneshot`

        let app = test_app();
        let (key, wire, epoch_id) = {
            let mut gw = app.gw.lock().await;
            let (key, owner) = gw.register_account(None);
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).expect("deposit");
            let epoch_id = gw.epochs.current().epoch_id;
            let epoch_pub = gw.epochs.current().public;
            let wire = seal_order_wire(
                &epoch_pub,
                epoch_id,
                &owner,
                &OrderTerms {
                    market_id: 0,
                    side: Side::Buy,
                    size: SIZE_SCALE / 10,
                    limit_price: 0,
                    tif: TimeInForce::Ioc,
                    reduce_only: false,
                    nonce: 1,
                },
            );
            (key, wire, epoch_id)
        };

        let body = serde_json::json!({ "epochId": epoch_id, "sealed": wire }).to_string();
        let req = Request::builder()
            .method("POST")
            .uri("/v1/orders")
            .header("content-type", "application/json")
            .header("X-Api-Key", hex0x(&key))
            .body(Body::from(body))
            .unwrap();
        let res = build_router(app, false).oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "a sealed-only {{epochId, sealed}} body must round-trip through the HTTP layer",
        );
    }

    /// A client-SEALED order decrypts inside the enclave, opens the position the
    /// DECRYPTED terms describe (not the bogus plaintext fields), and leaves the
    /// public depth untouched.
    #[test]
    fn sealed_order_decrypts_and_opens_position() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).expect("deposit");

        // the client fetches the enclave's CURRENT epoch (GET /v1/enclave/epoch)
        let epoch_id = gw.epochs.current().epoch_id;
        let epoch_pub = gw.epochs.current().public;

        // seal a Buy 0.1 BTC market order to that epoch key
        let wire = seal_order_wire(
            &epoch_pub,
            epoch_id,
            &owner,
            &OrderTerms {
                market_id: 0,
                side: Side::Buy,
                size: SIZE_SCALE / 10,
                limit_price: 0,
                tif: TimeInForce::Ioc,
                reduce_only: false,
                nonce: 1,
            },
        );

        // the PLAINTEXT fields are deliberately the OPPOSITE trade (a Sell): if the
        // enclave used them instead of the sealed body it would open a SHORT.
        let req = OrderReq {
            market_id: 0,
            side: "Sell".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            epoch_id: Some(epoch_id),
            sealed: Some(wire),
            ..Default::default()
        };
        gw.account_place_order(&key, &req).expect("sealed order accepted");

        // depth is still served (public) — sealed ingress never touches the book
        let book = gw.v1_orderbook_json(0).expect("depth served");
        assert!(
            !book["bids"].as_array().unwrap().is_empty()
                && !book["asks"].as_array().unwrap().is_empty(),
            "public depth still populated after a sealed order",
        );

        let mark = gw.px_of(0);
        gw.tick();
        // the DECRYPTED Buy opened a LONG (proving the sealed body, not the Sell
        // plaintext, drove the trade), and it filled at the mark.
        let pos = gw
            .seq
            .state
            .position(&owner, 0)
            .expect("position opened from decrypted terms");
        assert!(
            pos.size > 0,
            "decrypted Buy opened a long, not the plaintext Sell short",
        );
        assert!(
            pos.entry_price >= mark - PRICE_SCALE && pos.entry_price <= mark + PRICE_SCALE,
            "entry {} is at the mark {mark}",
            pos.entry_price,
        );
    }

    /// The negative surface: an unknown/expired epoch, an AAD bound to a different
    /// epoch, and a tampered ciphertext all fail cleanly (Err → 400) — nothing
    /// opens.
    #[test]
    fn sealed_order_wrong_or_expired_epoch_is_rejected() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let epoch_id = gw.epochs.current().epoch_id;
        let epoch_pub = gw.epochs.current().public;
        let good = OrderTerms {
            market_id: 0,
            side: Side::Buy,
            size: SIZE_SCALE / 10,
            limit_price: 0,
            tif: TimeInForce::Ioc,
            reduce_only: false,
            nonce: 1,
        };

        // (a) an UNKNOWN epoch id: secret_for → None → clean rejection.
        let unknown = OrderReq {
            market_id: 0,
            epoch_id: Some(epoch_id + 9_999),
            sealed: Some(seal_order_wire(&epoch_pub, epoch_id, &owner, &good)),
            ..Default::default()
        };
        assert!(
            gw.account_place_order(&key, &unknown).is_err(),
            "an unknown/expired epoch must be rejected",
        );

        // (b) AAD/epoch binding: seal with AAD bound to epoch_id+1 but present it as
        // the (valid) current epoch. secret_for returns the RIGHT key, but the AAD
        // the enclave rebuilds (epoch_id ‖ owner) ≠ the sealed AAD (epoch_id+1 ‖
        // owner) → unseal fails. Proves the AAD binds the epoch.
        let aad_mismatch = OrderReq {
            market_id: 0,
            epoch_id: Some(epoch_id),
            sealed: Some(seal_order_wire(&epoch_pub, epoch_id + 1, &owner, &good)),
            ..Default::default()
        };
        assert!(
            gw.account_place_order(&key, &aad_mismatch).is_err(),
            "an order whose AAD is bound to a different epoch must fail to decrypt",
        );

        // (c) tamper: flip a ciphertext byte → Poly1305 tag fails → rejection.
        let mut raw = decode_hex(&seal_order_wire(&epoch_pub, epoch_id, &owner, &good)).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        let tampered = OrderReq {
            market_id: 0,
            epoch_id: Some(epoch_id),
            sealed: Some(hex0x(&raw)),
            ..Default::default()
        };
        assert!(
            gw.account_place_order(&key, &tampered).is_err(),
            "a tampered sealed order must be rejected",
        );

        // nothing opened a position through the whole negative surface (the
        // deposit leaves a zero-size collateral position; no rejected order fills).
        let opened = gw.seq.state.position(&owner, 0).map_or(0, |p| p.size);
        assert_eq!(opened, 0, "no rejected sealed order may open a position");
    }

    /// `decode_hex` must be BYTE-safe: any `&str` (including non-ASCII / multi-byte
    /// UTF-8) returns `Some`/`None`, never panics. Regression for the sealed-order
    /// dark-ingress path, where a client could otherwise send a multi-byte char that
    /// made the char length even while a byte-offset slice fell mid-codepoint →
    /// `str` slicing PANIC instead of a clean 400.
    #[test]
    fn decode_hex_rejects_non_ascii_without_panic() {
        // multi-byte codepoints that previously panicked (byte-len even, slice
        // boundary lands mid-codepoint) now return a clean `None`.
        assert_eq!(decode_hex("0xé0"), None, "mid-codepoint slice must not panic");
        assert_eq!(decode_hex("—"), None, "em dash (3 bytes) must reject cleanly");
        assert_eq!(decode_hex("é"), None); // single 2-byte char: even byte len, non-hex
        assert_eq!(decode_hex("0x00é"), None);
        // odd length still rejected; non-hex ASCII nibble still rejected.
        assert_eq!(decode_hex("0xabc"), None);
        assert_eq!(decode_hex("0xzz"), None);
        // valid hex still decodes, with and without the `0x` prefix.
        assert_eq!(decode_hex("0x01ff"), Some(vec![1, 255]));
        assert_eq!(decode_hex("01FF"), Some(vec![1, 255]));
        assert_eq!(decode_hex(""), Some(vec![]));
    }

    /// The fixed-length hex parsers share `decode_hex`'s byte-safety obligation:
    /// they parse attacker-controlled request JSON (api keys, deposit
    /// txHash/address, order signatures). A 2-byte UTF-8 char straddling an odd
    /// byte offset makes the BYTE length pass the length gate while the old
    /// `&h[i*2..i*2+2]` `&str` slice landed mid-codepoint and PANICKED; all must
    /// now return a clean `None`.
    #[test]
    fn fixed_len_hex_parsers_reject_non_ascii_without_panic() {
        // "aé…" puts é (2 bytes) at bytes 1..3, so the first nibble-pair slice
        // [0..2) would have split the codepoint in the old parsers.
        let bad64 = format!("aé{}", "a".repeat(61)); // 64 bytes
        assert_eq!(parse_hex32(&bad64), None);
        let bad40 = format!("aé{}", "a".repeat(37)); // 40 bytes
        assert_eq!(parse_addr20_hex(&bad40), None);
        let bad130 = format!("aé{}", "a".repeat(127)); // 130 bytes
        assert_eq!(parse_hex65(&bad130), None);
        // valid inputs still parse, with and without the 0x prefix.
        assert_eq!(parse_hex32(&format!("0x{}", "ab".repeat(32))), Some([0xab; 32]));
        assert_eq!(parse_addr20_hex(&"cd".repeat(20)), Some([0xcd; 20]));
        assert_eq!(parse_hex65(&format!("0x{}", "0F".repeat(65))), Some([0x0f; 65]));
        // wrong length still rejected.
        assert_eq!(parse_hex32("ab"), None);
    }

    /// End-to-end: a non-ASCII `sealed` field on the order-ingress path is a clean
    /// `Err` (bad 0x-hex wire) with NO position opened and NO panic.
    #[test]
    fn sealed_order_non_ascii_wire_is_cleanly_rejected() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let epoch_id = gw.epochs.current().epoch_id;
        let bad = OrderReq {
            market_id: 0,
            epoch_id: Some(epoch_id),
            sealed: Some("0x—é".into()), // multi-byte UTF-8 in the sealed hex wire
            ..Default::default()
        };
        assert!(
            gw.account_place_order(&key, &bad).is_err(),
            "a non-ASCII sealed wire must be rejected, not panic",
        );
        let opened = gw.seq.state.position(&owner, 0).map_or(0, |p| p.size);
        assert_eq!(opened, 0, "a rejected non-ASCII sealed order must open nothing");
    }

    /// Pre-merge FIX 1 (sealed-order replay): a captured `{epochId, sealed}` body
    /// re-POSTed VERBATIM must be rejected. The decrypted canonical terms carry the
    /// client's nonce; for a server-custody account the gateway now enforces it
    /// strictly increasing (`Account::last_sealed_nonce`) and uses it as the order
    /// nonce — so the replay decrypts to a stale nonce and never duplicates the
    /// position, even within one (currently unrotated) epoch.
    #[test]
    fn sealed_order_replay_of_same_body_is_rejected() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).expect("deposit");
        let epoch_id = gw.epochs.current().epoch_id;
        let epoch_pub = gw.epochs.current().public;
        let terms = |nonce: u64| OrderTerms {
            market_id: 0,
            side: Side::Buy,
            size: SIZE_SCALE / 10,
            limit_price: 0,
            tif: TimeInForce::Ioc,
            reduce_only: false,
            nonce,
        };
        let req = |wire: String| OrderReq {
            epoch_id: Some(epoch_id),
            sealed: Some(wire),
            ..Default::default()
        };

        let wire7 = seal_order_wire(&epoch_pub, epoch_id, &owner, &terms(7));
        gw.account_place_order(&key, &req(wire7.clone()))
            .expect("first sealed order accepted");
        assert_eq!(gw.accounts.get(&key).unwrap().orders.len(), 1);
        assert_eq!(gw.accounts.get(&key).unwrap().last_sealed_nonce, 7);

        // the SAME sealed body replayed → decrypts to nonce 7 again → stale → 400.
        let err = match gw.account_place_order(&key, &req(wire7)) {
            Ok(_) => panic!("a verbatim replay must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.contains("strictly increase"),
            "replay must fail the nonce monotonicity check, got: {err}",
        );
        assert_eq!(
            gw.accounts.get(&key).unwrap().orders.len(),
            1,
            "the replay must not record a second order",
        );

        // a LOWER fresh nonce is equally stale …
        let wire3 = seal_order_wire(&epoch_pub, epoch_id, &owner, &terms(3));
        assert!(
            gw.account_place_order(&key, &req(wire3)).is_err(),
            "a stale (lower) sealed nonce must be rejected",
        );
        // … while a HIGHER nonce is a legitimately new order and is accepted.
        let wire8 = seal_order_wire(&epoch_pub, epoch_id, &owner, &terms(8));
        gw.account_place_order(&key, &req(wire8))
            .expect("a strictly higher sealed nonce is accepted");
        assert_eq!(gw.accounts.get(&key).unwrap().orders.len(), 2);
        assert_eq!(gw.accounts.get(&key).unwrap().last_sealed_nonce, 8);
    }

    /// Production posture refuses an UNSEALED (plaintext) order — sealed ingress is
    /// mandatory in prod; demo/dev keeps plaintext for backward-compat.
    #[test]
    fn prod_posture_rejects_unsealed_plaintext_order() {
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        // enter production posture AFTER registering (self-service deposits, and now
        // plaintext orders, are refused in prod).
        gw.prod = true;
        let plaintext = OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            ..Default::default()
        };
        let err = match gw.account_place_order(&key, &plaintext) {
            Ok(_) => panic!("production must refuse an unsealed order"),
            Err(e) => e,
        };
        assert!(
            err.contains("production requires sealed order ingress"),
            "unexpected error: {err}",
        );
    }

    /// Regression for the `#[serde(default)]` widening (commit 76b94a5): that change
    /// let a partial plaintext body like `{"size":"100000000"}` PARSE and reach the
    /// dev/demo plaintext branch, where the missing fields silently defaulted into a
    /// real Sell / market-0 / Ioc order. The plaintext branch must now REJECT any
    /// order missing a core field, restoring pre-commit strictness.
    #[test]
    fn plaintext_order_missing_side_is_rejected() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        // valid size, everything else absent → serde defaults every other field to "".
        let partial = OrderReq {
            size: (SIZE_SCALE / 10).to_string(),
            ..Default::default()
        };
        assert!(
            gw.account_place_order(&key, &partial).is_err(),
            "a plaintext order with only `size` set must be rejected, not defaulted",
        );
        assert_eq!(
            gw.seq.state.position(&owner, 0).map_or(0, |p| p.size),
            0,
            "a rejected partial order must open nothing",
        );
    }

    /// Strict tif: an EMPTY tif (required-field guard) and an UNKNOWN tif (strict
    /// parse) are both rejected on the plaintext branch — no silent fallback to Ioc.
    #[test]
    fn plaintext_order_with_empty_or_unknown_tif_is_rejected() {
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let empty_tif = OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: String::new(),
            ..Default::default()
        };
        assert!(
            gw.account_place_order(&key, &empty_tif).is_err(),
            "an empty tif must be rejected, not defaulted to Ioc",
        );
        let unknown_tif = OrderReq {
            tif: "Whenever".into(),
            ..empty_tif
        };
        assert!(
            gw.account_place_order(&key, &unknown_tif).is_err(),
            "an unrecognized tif must be rejected, not silently defaulted to Ioc",
        );
    }

    /// Strict side: an UNKNOWN side value is rejected on the plaintext branch — no
    /// silent `else → Sell` that would flip a malformed order's direction.
    #[test]
    fn plaintext_order_with_unknown_side_is_rejected() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let bad_side = OrderReq {
            market_id: 0,
            side: "Longgg".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            ..Default::default()
        };
        assert!(
            gw.account_place_order(&key, &bad_side).is_err(),
            "an unrecognized side must be rejected, not silently defaulted to Sell",
        );
        assert_eq!(
            gw.seq.state.position(&owner, 0).map_or(0, |p| p.size),
            0,
            "a rejected unknown-side order must open nothing",
        );
    }

    /// The tightening must not regress the happy path: a COMPLETE plaintext order
    /// still places on the legacy demo `/api/order` (`place_order`) route, while a
    /// partial body on that SAME route is now rejected.
    #[test]
    fn complete_plaintext_order_still_succeeds_in_demo() {
        let mut gw = Gw::boot();
        let ok = OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            ..Default::default()
        };
        assert!(
            gw.place_order(&ok).is_ok(),
            "a complete plaintext order must still be accepted in demo mode",
        );
        let partial = OrderReq {
            size: (SIZE_SCALE / 10).to_string(),
            ..Default::default()
        };
        assert!(
            gw.place_order(&partial).is_err(),
            "a partial plaintext order must be rejected on the demo /api/order path too",
        );
    }

    /// The canonical order-terms layout round-trips and is exactly 51 bytes with the
    /// documented side/tif byte mapping — the Task 11 cross-language contract.
    #[test]
    fn order_terms_layout_is_stable_and_51_bytes() {
        let t = OrderTerms {
            market_id: 0x0102_0304_0506_0708,
            side: Side::Sell,
            size: 1_234_567,
            limit_price: -42,
            tif: TimeInForce::Fok,
            reduce_only: true,
            nonce: 0xAABB,
        };
        let b = serialize_order_terms(&t);
        assert_eq!(b.len(), ORDER_TERMS_LEN);
        assert_eq!(ORDER_TERMS_LEN, 51);
        assert_eq!(&b[0..8], &t.market_id.to_le_bytes(), "marketId u64 LE @0");
        assert_eq!(b[8], 2, "Sell encodes as 2");
        assert_eq!(&b[9..25], &t.size.to_le_bytes(), "size i128 LE @9");
        assert_eq!(&b[25..41], &t.limit_price.to_le_bytes(), "limitPrice i128 LE @25");
        assert_eq!(b[41], 3, "Fok encodes as 3");
        assert_eq!(b[42], 1, "reduceOnly true = 1");
        assert_eq!(&b[43..51], &t.nonce.to_le_bytes(), "nonce u64 LE @43");
        let d = deserialize_order_terms(&b).expect("round trip");
        assert_eq!(d.market_id, t.market_id);
        assert_eq!(d.side, t.side);
        assert_eq!(d.size, t.size);
        assert_eq!(d.limit_price, t.limit_price);
        assert_eq!(d.tif, t.tif);
        assert_eq!(d.reduce_only, t.reduce_only);
        assert_eq!(d.nonce, t.nonce);
        // wrong length and out-of-range discriminants are rejected
        assert!(deserialize_order_terms(&b[..50]).is_none());
        let mut bad = b;
        bad[8] = 0;
        assert!(deserialize_order_terms(&bad).is_none(), "side 0 is invalid");
    }

    // ── Slice 3b-2a: window withdrawal set + per-note (root, proof) ──────────

    #[test]
    fn account_withdraw_records_window_withdrawal() {
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        assert!(gw.window_withdrawals.is_empty());

        let to = [7u8; 20];
        let w = gw
            .account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, to)
            .expect("withdraw");

        assert_eq!(gw.window_withdrawals.len(), 1);
        assert_eq!(gw.window_withdrawals[0].to, to);
        assert_eq!(gw.window_withdrawals[0].nonce, w.nonce);
    }

    #[test]
    fn v1_withdrawals_json_serves_root_and_proof() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let w = gw
            .account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20])
            .unwrap();

        // seed a published (root, proof) for this leaf as the settle path would
        let leaf = w.leaf();
        let root = [0xAAu8; 32];
        gw.withdraw_proofs.insert(leaf, (root, vec![[0xBBu8; 32]]));
        let _ = owner;

        let json = gw.v1_withdrawals_json(&key).expect("json");
        let item = &json["withdrawals"][0];
        assert_eq!(item["claimable"], serde_json::json!(true));
        assert_eq!(item["root"], serde_json::json!(hex0x(&root)));
        assert_eq!(item["proof"], serde_json::json!([hex0x(&[0xBBu8; 32])]));
    }

    // ── Slice 3b-2b: Gw::prune_claimed_withdrawals ──────────────────────────

    #[test]
    fn prune_claimed_withdrawals_removes_only_claimed() {
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        let w1 = gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let w2 = gw.account_withdraw(&key, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        // seed proofs for both leaves as a settle would
        gw.withdraw_proofs.insert(w1.leaf(), ([0xAAu8; 32], vec![[0xBBu8; 32]]));
        gw.withdraw_proofs.insert(w2.leaf(), ([0xAAu8; 32], vec![[0xCCu8; 32]]));

        // claim w1 only
        gw.prune_claimed_withdrawals(&[w1.leaf()]);

        assert!(!gw.pending_withdrawals.iter().any(|w| w.leaf() == w1.leaf()));
        assert!(gw.pending_withdrawals.iter().any(|w| w.leaf() == w2.leaf()));
        assert!(!gw.withdraw_proofs.contains_key(&w1.leaf()));
        assert!(gw.withdraw_proofs.contains_key(&w2.leaf()));
    }

    // ── Slice 3b-3: Gw::rollback_window_withdrawals ─────────────────────────

    #[test]
    fn rollback_window_withdrawals_prepends() {
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        // one withdrawal accumulated since the (failed) seal drained the window's set
        let after = gw.account_withdraw(&key, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        // the failed window's withdrawals, captured before the seal
        let failed = vec![Withdrawal { owner: [1u8; 32], to: [7u8; 20], amount: 5_000, nonce: 1 }];

        gw.rollback_window_withdrawals(failed.clone());

        // the failed window's withdrawals are re-injected AHEAD of the accumulated one
        assert_eq!(gw.window_withdrawals.len(), 2);
        assert_eq!(gw.window_withdrawals[0].nonce, failed[0].nonce);
        assert_eq!(gw.window_withdrawals[0].to, [7u8; 20]);
        assert_eq!(gw.window_withdrawals[1].nonce, after.nonce);
    }

    // ── Slice 3b-2a: Gw::begin_window_settle ────────────────────────────────

    #[test]
    fn begin_window_settle_none_when_unchanged() {
        let mut gw = Gw::boot();
        // Force "no change since last settle": mark the current engine root as settled.
        gw.last_settled_root = gw.seq.state.state_root();
        let bc = gw.seq.state.next_batch_id;
        assert!(gw.begin_window_settle(bc).unwrap().is_none());
    }

    #[test]
    fn begin_window_settle_errors_on_desync_without_mutating() {
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20])
            .unwrap();
        let before_next = gw.seq.state.next_batch_id;
        let before_ww = gw.window_withdrawals.len();

        // chain count that does NOT match the window's next id → desync error, no mutation.
        // (`.err().expect(..)` instead of `.unwrap_err()`: WindowWitness has no Debug impl.)
        let err = gw
            .begin_window_settle(before_next + 99)
            .err()
            .expect("desync must error");
        assert!(err.contains("desync"));
        assert_eq!(gw.seq.state.next_batch_id, before_next); // not sealed
        assert_eq!(gw.window_withdrawals.len(), before_ww); // not drained
    }

    #[test]
    fn begin_window_settle_seals_and_takes_withdrawals() {
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20])
            .unwrap();
        let bc = gw.seq.state.next_batch_id;

        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        assert_eq!(witness.batch_id, bc);
        assert_eq!(ww.len(), 1); // the withdrawal was taken
        assert!(gw.window_withdrawals.is_empty()); // drained
        // the window op-log contains the real-exit withdraw op
        assert!(witness
            .ops
            .iter()
            .any(|op| matches!(op, BatchOp::Withdraw { to: Some(_), .. })));
    }

    // ── Task 2/3: settle-loop rollback-journal lifecycle (WAL model) ────────

    /// The settle loop's journal lifecycle against a REAL sealed window:
    /// stage 1 (seal → journal with `prepared: None`) → stage 2 (prove →
    /// rewrite at the same path with `prepared: Some`, cloning like the settle
    /// closure does so the original still reaches `settle_proved`) → the
    /// rollback arm (`rollback_window` + `rollback_window_withdrawals`) KEEPS
    /// the journal (Task 3 WAL: the loop never deletes — boot is the only
    /// deleter), a re-seal reproduces the window under the SAME batch id, and
    /// boot recovery's SEAL-NEVER-PERSISTED row is what finally deletes it.
    #[test]
    fn settle_loop_journal_lifecycle() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20])
            .unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("sealed");
        let ww_leaves: Vec<[u8; 32]> = ww.iter().map(|w| w.leaf()).collect();

        // unpredictable per-test scratch path (the rollback_journal test pattern),
        // derived from a fake DARKPERP_STATE exactly like the settle loop does.
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).expect("OS CSPRNG");
        let sfx: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let state = std::env::temp_dir().join(format!("darkperp-lifecycle-{sfx}.snap"));
        let jp = rollback_journal::journal_path(&state);
        let seed = [42u8; 32];

        // stage 1: journal the freshly sealed window, pre-prove.
        let mut journal = rollback_journal::RollbackJournal {
            batch_id: bc,
            witness,
            ww,
            prepared: None,
        };
        rollback_journal::write(&jp, &journal, &seed).expect("stage-1 write");
        let s1 = rollback_journal::read(&jp, &seed).expect("read").expect("present");
        assert_eq!(s1.batch_id, bc);
        assert!(s1.prepared.is_none(), "stage 1 journals pre-prove");

        // stage 2: rewrite the SAME path with the prove outcome — round-trips.
        let prepared =
            prove_and_prepare(&MockProverClient, &journal.witness, &journal.ww).expect("prove");
        journal.prepared = Some(prepared.clone());
        rollback_journal::write(&jp, &journal, &seed).expect("stage-2 write");
        let s2 = rollback_journal::read(&jp, &seed).expect("read").expect("present");
        assert_eq!(s2.batch_id, bc);
        let s2p = s2.prepared.expect("stage 2 carries the prove outcome");
        assert_eq!(s2p.outcome.new_root, prepared.outcome.new_root);
        assert_eq!(s2p.withdraw_proofs, prepared.withdraw_proofs);

        // the rollback arm: undo the seal + re-inject the withdrawals — and KEEP
        // the journal (Task 3 WAL: a resolving arm only pokes the snapshot writer;
        // deleting here would leave a crash-before-that-snapshot unreconcilable).
        gw.seq.rollback_window(&journal.witness);
        gw.rollback_window_withdrawals(journal.ww);
        assert!(jp.exists(), "the journal survives the rollback arm (WAL)");

        // BOOT is the deleter: with the rolled-back state persisted (Counter B
        // back at `bc`) and the tx never landed (chain batchCount == bc), the
        // recovery table reads SEAL-NEVER-PERSISTED → resolve, no mutation, and
        // the call site drops the file.
        let j = rollback_journal::read(&jp, &seed).expect("read").expect("present");
        let out = apply_boot_recovery(&mut gw, j, bc, "0x00", 0);
        // SEAL-NEVER-PERSISTED is a NON-mutating resolution: delete without a
        // pre-delete snapshot write (the state on disk is already the one it
        // resolves to).
        assert_eq!(out, BootRecoveryOutcome::DeleteJournal { mutated: false });
        rollback_journal::delete(&jp);
        assert!(!jp.exists(), "boot recovery resolved the journal");
        assert!(matches!(rollback_journal::read(&jp, &seed), Ok(None)));

        // a re-seal reproduces the window: same on-chain id, same withdrawal set.
        let (w2, ww2) = gw.begin_window_settle(bc).unwrap().expect("re-sealed");
        assert_eq!(w2.batch_id, bc, "re-seal keeps the on-chain window id");
        let leaves2: Vec<[u8; 32]> = ww2.iter().map(|w| w.leaf()).collect();
        assert_eq!(leaves2, ww_leaves, "the drained withdrawals were re-injected");
    }

    // ── Task 3: boot-time crash recovery (apply_boot_recovery) ──────────────

    /// The ROLLBACK row end-to-end across a simulated restart: seal a window,
    /// journal it, persist + restore the POST-seal snapshot (Counter B advanced,
    /// rollback clones lost with the process), then apply boot recovery with the
    /// chain still at the pre-seal count. Counter B rewinds to the journaled
    /// window and a fresh `begin_window_settle(bc)` re-seals the SAME ops (same
    /// batch id, same withdrawal leaves) — the wedge that killed the 0xEa11 stack.
    #[test]
    fn boot_recovery_rollback_restores_reseal() {
        let seed = [42u8; 32];
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20])
            .unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("sealed");
        let ww_leaves: Vec<[u8; 32]> = ww.iter().map(|w| w.leaf()).collect();
        let journal = rollback_journal::RollbackJournal {
            batch_id: bc,
            witness,
            ww,
            prepared: None,
        };

        // simulate the restart: the post-seal snapshot is what boot restores
        // (the `snapshot_restart_round_trip_preserves_state` pattern).
        let sealed = snapshot::seal(&gw.snapshot_plain(), &seed);
        let plain = snapshot::open(&sealed, &seed).expect("open");
        let mut restored = Gw::boot_restored(&plain).expect("restore");
        assert_eq!(
            restored.seq.state.next_batch_id,
            bc + 1,
            "the post-seal snapshot persisted the Counter B bump"
        );

        // a HOLD shape first (chain advanced BEYOND the window): journal kept,
        // and — the Hold contract — NO state mutation.
        let hold_j = rollback_journal::RollbackJournal {
            batch_id: bc,
            witness: journal.witness.clone(),
            ww: journal.ww.clone(),
            prepared: None,
        };
        assert_eq!(
            apply_boot_recovery(&mut restored, hold_j, bc + 2, "0x00", 0),
            BootRecoveryOutcome::KeepJournal
        );
        assert_eq!(restored.seq.state.next_batch_id, bc + 1, "HOLD never mutates");

        // the ROLLBACK row: seal persisted (B == bc+1), tx never landed (chain == bc).
        // A MUTATING resolution — the caller must persist before deleting.
        let out = apply_boot_recovery(&mut restored, journal, bc, "0x00", 0);
        assert_eq!(out, BootRecoveryOutcome::DeleteJournal { mutated: true });
        assert_eq!(
            restored.seq.state.next_batch_id,
            bc,
            "Counter B rewound to the journaled window"
        );

        // a fresh begin_window_settle(bc) re-seals the same window: the desync
        // guard passes and the drained withdrawals were re-injected.
        let (w2, ww2) = restored.begin_window_settle(bc).unwrap().expect("re-sealed");
        assert_eq!(w2.batch_id, bc, "re-seal keeps the on-chain window id");
        let leaves2: Vec<[u8; 32]> = ww2.iter().map(|w| w.leaf()).collect();
        assert_eq!(leaves2, ww_leaves, "same withdrawal leaves after recovery");
    }

    /// The ROLL-FORWARD row end-to-end across a simulated restart: the tx landed
    /// but the commit died with the process. Boot recovery re-commits from the
    /// journal's `prepared`: l1_status matches the chain, the claim proof is
    /// served, and `begin_window_settle(bc+1)` passes the desync guard. A second
    /// application of the same journal (the crash-after-commit shape) resolves
    /// STALE — delete again, but never double-apply.
    #[test]
    fn boot_recovery_roll_forward_commits() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let seed = [42u8; 32];
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20])
            .unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("sealed");
        let leaf0 = ww[0].leaf();
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prove");
        let new_root = prepared.outcome.new_root;
        let wroot = prepared.outcome.withdrawals_root;
        // two owned journal copies: one to roll forward, one to prove the STALE
        // row is a no-op on a second pass (recovery must be idempotent against a
        // journal whose delete raced a crash).
        let j1 = rollback_journal::RollbackJournal {
            batch_id: bc,
            witness: witness.clone(),
            ww: ww.clone(),
            prepared: Some(prepared.clone()),
        };
        let j2 = rollback_journal::RollbackJournal {
            batch_id: bc,
            witness,
            ww,
            prepared: Some(prepared),
        };

        // simulate the restart: post-seal snapshot restored, commit LOST.
        let sealed = snapshot::seal(&gw.snapshot_plain(), &seed);
        let plain = snapshot::open(&sealed, &seed).expect("open");
        let mut restored = Gw::boot_restored(&plain).expect("restore");
        assert!(restored.l1_status.is_none(), "the commit died with the crash");

        // the ROLL-FORWARD row: tx landed (chain == bc+1) and the chain root is
        // exactly our prepared new_root. Passed in MIXED case: root comparisons
        // must be case-insensitive like the continuity check (cast hex casing).
        let chain_root = hex32(&new_root);
        let out = apply_boot_recovery(
            &mut restored,
            j1,
            bc + 1,
            &chain_root.to_ascii_uppercase(),
            77,
        );
        // ROLL-FORWARD is a MUTATING resolution — persist before delete.
        assert_eq!(out, BootRecoveryOutcome::DeleteJournal { mutated: true });
        let st = restored.l1_status.clone().expect("bookkeeping re-committed");
        assert_eq!(st.settled_root, chain_root);
        assert_eq!(st.batch_count, bc + 1);
        assert_eq!(st.last_tx, "(recovered at boot)");
        assert_eq!(st.bond, "77");
        assert_eq!(st.withdrawals_root, hex32(&wroot));
        let (root, proof) = restored
            .withdraw_proofs
            .get(&leaf0)
            .expect("claim proof served after recovery");
        assert_eq!(*root, wroot);
        assert!(withdrawals::verify(*root, leaf0, proof));

        // STALE idempotence: the same journal against the now-persisted commit
        // resolves to delete WITHOUT re-applying anything. The proofs alone can't
        // prove that (re-inserting the same leaves is idempotent), so plant a
        // marker a second roll-forward would clobber back to "(recovered at boot)".
        restored.l1_status.as_mut().unwrap().last_tx = "(already committed)".into();
        let proofs_before = restored.withdraw_proofs.len();
        assert_eq!(
            apply_boot_recovery(&mut restored, j2, bc + 1, &chain_root, 77),
            BootRecoveryOutcome::DeleteJournal { mutated: false }
        );
        assert_eq!(
            restored.l1_status.clone().unwrap().last_tx,
            "(already committed)",
            "STALE never re-applies (a roll-forward would rewrite last_tx)"
        );
        assert_eq!(restored.withdraw_proofs.len(), proofs_before);

        // Counter B (bc+1) now matches the chain: the NEXT window passes the
        // desync guard and seals (new state so there is something to settle).
        restored
            .account_withdraw(&key, 0, 1_000 * QUOTE_SCALE, [9u8; 20])
            .unwrap();
        let (w2, _ww2) = restored
            .begin_window_settle(bc + 1)
            .unwrap()
            .expect("next window seals");
        assert_eq!(w2.batch_id, bc + 1);
    }

    /// Task 3 fix round 1: a MUTATING recovery resolution (RollBack / RollForward)
    /// must be durable on disk BEFORE the journal is deleted. At that point in
    /// boot the snapshot writer task is not spawned yet and its first tick is
    /// ~SNAPSHOT_SECS away, so crash-after-delete would otherwise restore the
    /// PRE-recovery snapshot with NO journal — the rollback case re-wedges the
    /// desync guard forever (the exact failure this plan exists to kill), the
    /// roll-forward case loses `prepared` (the only copy) and the continuity
    /// check refuses to start. `finish_boot_recovery` is the extracted call-site
    /// glue: persist (mutating rows only) THEN delete; a failed persist keeps
    /// the journal.
    #[test]
    fn boot_recovery_persists_before_journal_delete() {
        let seed = [42u8; 32];
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20])
            .unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("sealed");
        let journal = rollback_journal::RollbackJournal {
            batch_id: bc,
            witness: witness.clone(),
            ww: ww.clone(),
            prepared: None,
        };
        let journal2 = rollback_journal::RollbackJournal {
            batch_id: bc,
            witness,
            ww,
            prepared: None,
        };

        // the on-disk pair exactly as a crash leaves it: post-seal snapshot + journal
        // (unpredictable per-test scratch path — the rollback_journal test pattern).
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).expect("OS CSPRNG");
        let sfx: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let state = std::env::temp_dir().join(format!("darkperp-persist-first-{sfx}.snap"));
        let jp = rollback_journal::journal_path(&state);
        snapshot::write_atomic(&state, &snapshot::seal(&gw.snapshot_plain(), &seed))
            .expect("pre-crash snapshot write");
        rollback_journal::write(&jp, &journal, &seed).expect("journal write");

        // restart: boot restores the POST-seal snapshot (Counter B advanced).
        let plain = snapshot::open(&std::fs::read(&state).unwrap(), &seed).expect("open");
        let mut restored = Gw::boot_restored(&plain).expect("restore");
        assert_eq!(restored.seq.state.next_batch_id, bc + 1);

        // the ROLLBACK row — a MUTATING resolution.
        let j = rollback_journal::read(&jp, &seed).expect("read").expect("present");
        let out = apply_boot_recovery(&mut restored, j, bc, "0x00", 0);
        assert_eq!(out, BootRecoveryOutcome::DeleteJournal { mutated: true });

        // the call-site glue: persist the post-recovery snapshot, THEN delete.
        finish_boot_recovery(&restored, true, &state, &jp, &seed);
        // (a) the snapshot on disk now decodes to the ROLLED-BACK Counter B — a
        // hard crash right here re-resolves from the snapshot alone.
        let plain2 = snapshot::open(&std::fs::read(&state).unwrap(), &seed).expect("open post");
        let after = Gw::boot_restored(&plain2).expect("restore post");
        assert_eq!(
            after.seq.state.next_batch_id,
            bc,
            "the rolled-back Counter B was persisted before the journal delete"
        );
        // (b) only then is the journal deleted.
        assert!(!jp.exists(), "journal deleted after the snapshot hit disk");

        // failure branch: an unwritable snapshot path (missing parent dir) keeps
        // the journal — it is still the only recovery source; the next boot
        // re-resolves the same row idempotently.
        rollback_journal::write(&jp, &journal2, &seed).expect("journal re-write");
        let bad_state = std::env::temp_dir()
            .join(format!("darkperp-no-such-dir-{sfx}"))
            .join("state.snap");
        finish_boot_recovery(&after, true, &bad_state, &jp, &seed);
        assert!(jp.exists(), "failed persist keeps the journal");

        // non-mutating resolutions stay delete-without-write: the same unwritable
        // snapshot path does not block the delete (nothing changed to persist).
        finish_boot_recovery(&after, false, &bad_state, &jp, &seed);
        assert!(!jp.exists(), "non-mutating rows delete without a snapshot write");

        std::fs::remove_file(&state).ok();
    }

    #[test]
    fn seal_witness_is_well_formed_and_addressed() {
        use crate::prover_client::seal_witness;
        use prover::SealedWitness;

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, _ww) = gw.begin_window_settle(bc).unwrap().expect("some");

        let root = [0x5Eu8; 32];
        let measurement = [0xABu8; 32];
        let hexed = seal_witness(&witness, &root, &measurement).expect("seal");
        assert!(hexed.starts_with("0x"));

        // it must postcard-decode back into a SealedWitness addressed to the right
        // measurement, with the content-derived nonce and the full plaintext length.
        let raw = decode_hex(&hexed).expect("hex");
        let sealed: SealedWitness = postcard::from_bytes(&raw).expect("decode sealed");
        assert_eq!(sealed.measurement(), measurement);
        let plaintext =
            postcard::to_allocvec(&(&witness.pre_state, &witness.ops, &witness.manifest)).unwrap();
        // P3 Slice A: the nonce is the secret-keyed seal_nonce(root, plaintext)
        // (content-derived, so a rollback+re-seal under the same batch_id never reuses
        // a keystream; keyed with the seal root, so the clear nonce is not a
        // plaintext-confirmation oracle).
        let expect_nonce = crate::prover_client::seal_nonce(&root, &plaintext);
        assert_eq!(sealed.nonce(), expect_nonce);
        assert_eq!(sealed.ciphertext_len(), plaintext.len());
    }

    #[test]
    fn parse_prove_resp_decodes_all_fields() {
        use crate::prover_client::parse_prove_resp;
        let r32 = |b: u8| format!("0x{}", crate::hex32(&[b; 32]).trim_start_matches("0x"));
        let json = format!(
            r#"{{"prev_root":"{}","manifest_hash":"{}","new_root":"{}","ordered_root":"{}","withdrawals_root":"{}","rejected_root":"{}","commitment":"{}","proof":"0xdeadbeef"}}"#,
            r32(1), r32(2), r32(3), r32(4), r32(5), r32(6), r32(7)
        );
        let out = parse_prove_resp(&json).expect("parse");
        assert_eq!(out.prev_root, [1u8; 32]);
        assert_eq!(out.manifest_hash, [2u8; 32]);
        assert_eq!(out.new_root, [3u8; 32]);
        assert_eq!(out.ordered_root, [4u8; 32]);
        assert_eq!(out.withdrawals_root, [5u8; 32]);
        assert_eq!(out.rejected_root, [6u8; 32]);
        assert_eq!(out.commitment, [7u8; 32]);
        assert_eq!(out.proof, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_prove_resp_rejects_malformed() {
        use crate::prover_client::parse_prove_resp;
        // not JSON
        assert!(parse_prove_resp("not json").is_err());
        // missing a field (no commitment/proof)
        assert!(parse_prove_resp(r#"{"prev_root":"0x00"}"#).is_err());
        // a root that isn't 32 bytes
        let bad = r#"{"prev_root":"0x1234","manifest_hash":"0x00","new_root":"0x00","ordered_root":"0x00","withdrawals_root":"0x00","rejected_root":"0x00","commitment":"0x00","proof":"0x00"}"#;
        assert!(parse_prove_resp(bad).is_err());
    }

    // ── Slice 3b-2a: prove_and_prepare + Gw::commit_window_settle ───────────

    #[test]
    fn prove_and_prepare_withdrawal_tree_byte_matches_circuit() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        // THREE real-exit withdrawals in the window → a non-trivial withdrawals tree
        // that also pins op-ORDER (a 2-leaf sorted-pair tree is permutation-invariant,
        // so two leaves alone couldn't tell "same set" from "same order")
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        gw.account_withdraw(&key, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        gw.account_withdraw(&key, 0, 2_000 * QUOTE_SCALE, [9u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;

        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        assert_eq!(ww.len(), 3);

        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prepare");

        // the byte-match invariant: the gateway tree root == the circuit's derived root
        let leaves: Vec<[u8; 32]> = ww.iter().map(|w| w.leaf()).collect();
        assert_eq!(merkle_root(&leaves), prepared.outcome.withdrawals_root);
        assert!(prepared.outcome.withdrawals_root != [0u8; 32]); // non-empty

        // each served proof verifies against that root the way the vault does
        for (i, w) in ww.iter().enumerate() {
            let (root, proof) = prepared.withdraw_proofs.get(&w.leaf()).expect("proof");
            assert_eq!(*root, prepared.outcome.withdrawals_root);
            assert!(withdrawals::verify(*root, w.leaf(), proof));
            assert_eq!(*proof, merkle_proof(&leaves, i));
        }
    }

    #[test]
    fn commit_window_settle_accumulates_and_advances() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;

        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        let ordered = witness.manifest.ordered.clone();
        let rejected: Vec<_> = witness.manifest.rejected.iter().map(|(h, _)| *h).collect();
        let batch_id = witness.batch_id;
        let leaf0 = ww[0].leaf();
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).unwrap();
        let new_root = prepared.outcome.new_root;

        let status = L1Status {
            settled_root: hex32(&new_root),
            batch_count: batch_id + 1,
            last_tx: "0xtx".into(),
            bond: "0".into(),
            withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
        };
        gw.commit_window_settle(batch_id, ordered, rejected, prepared, status);

        assert_eq!(gw.last_settled_root, new_root);
        assert!(gw.withdraw_proofs.contains_key(&leaf0));
        assert!(gw.batch_orders.contains_key(&batch_id));
        assert!(gw.pending_ordered.is_empty());
        assert!(gw.l1_status.is_some());
    }

    // Task 5: with the prover configured, SETTLED must be EARNED by the on-chain window
    // settle — the legacy SETTLE_TICKS simulation must not fire, and the commit is what
    // advances finality (honest reporting; the TestnetNotice says SETTLED lags a proof).
    #[test]
    fn window_mode_defers_settled_until_commit() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let mut gw = Gw::boot();
        gw.window_settle_mode = true;
        // mirror main()'s pairing: window mode also turns off per-tick rollback-
        // snapshot retention (Task 5 fix round 1) — the commit path below must
        // harden finality with no snapshots present.
        gw.seq.set_retain_tick_snapshots(false);
        let req = OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            nonce: None,
            signature: None,
            ..Default::default()
        };
        let (_r, _ev) = gw.place_order(&req).expect("accepted");
        // run well past the legacy horizon: finality must STAY matched — no simulation.
        for _ in 0..(SETTLE_TICKS * 3) {
            gw.tick();
        }
        assert_eq!(gw.finality_str(&gw.orders[0].order_hash), "MATCHED");
        assert!(
            gw.pending_settle.is_empty(),
            "window mode must not accumulate the legacy settle queue"
        );

        // the real settle: begin → prove → commit (the commit_window_settle shape).
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        let ordered = witness.manifest.ordered.clone();
        let rejected: Vec<_> = witness.manifest.rejected.iter().map(|(h, _)| *h).collect();
        let batch_id = witness.batch_id;
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).unwrap();
        let status = L1Status {
            settled_root: hex32(&prepared.outcome.new_root),
            batch_count: batch_id + 1,
            last_tx: "0xtx".into(),
            bond: "0".into(),
            withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
        };
        gw.commit_window_settle(batch_id, ordered, rejected, prepared, status);
        assert_eq!(gw.finality_str(&gw.orders[0].order_hash), "SETTLED");
    }

    // Task 5: without a prover (flag defaults false) the demo-era tick simulation is
    // byte-identical — batches still advance MATCHED → SETTLED after SETTLE_TICKS.
    #[test]
    fn legacy_mode_settles_after_ticks_unchanged() {
        let mut gw = Gw::boot();
        assert!(!gw.window_settle_mode, "legacy path is the default");
        let req = OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            nonce: None,
            signature: None,
            ..Default::default()
        };
        let (_r, _ev) = gw.place_order(&req).expect("accepted");
        gw.tick(); // seals the fill → MATCHED
        assert_eq!(gw.finality_str(&gw.orders[0].order_hash), "MATCHED");
        for _ in 0..(SETTLE_TICKS + 1) {
            gw.tick();
        }
        assert_eq!(gw.finality_str(&gw.orders[0].order_hash), "SETTLED");
    }

    #[test]
    fn prove_and_prepare_rejects_wroot_mismatch() {
        use crate::prover_client::{
            prove_and_prepare, MockProverClient, ProveOutcome, ProverClient, ProverClientError,
        };
        use perp_core::commitment::DerivedRoots;
        use perp_core::Keccak256;
        use sequencer::WindowWitness;

        // corrupts withdrawals_root AND recomputes commitment over the tampered roots, so
        // the commitment cross-check PASSES and the failure lands on the withdrawal-tree
        // byte-match branch.
        struct WrootTamper;
        impl ProverClient for WrootTamper {
            fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
                let mut out = MockProverClient.prove(w)?;
                out.withdrawals_root = [0xFFu8; 32];
                out.commitment = DerivedRoots {
                    prev_state_root: out.prev_root,
                    manifest_hash: out.manifest_hash,
                    new_state_root: out.new_root,
                    ordered_root: out.ordered_root,
                    withdrawals_root: out.withdrawals_root,
                    rejected_root: out.rejected_root,
                }
                .commitment::<Keccak256>();
                Ok(out)
            }
        }

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        assert!(!ww.is_empty());

        // (PreparedSettle is not Debug, so no unwrap_err here)
        let Err(err) = prove_and_prepare(&WrootTamper, &witness, &ww) else {
            panic!("tampered withdrawals_root must be a hard error");
        };
        assert!(err.contains("withdrawals root mismatch"), "got: {err}");
    }

    #[test]
    fn prove_and_prepare_rejects_commitment_mismatch() {
        use crate::prover_client::{
            prove_and_prepare, MockProverClient, ProveOutcome, ProverClient, ProverClientError,
        };
        use sequencer::WindowWitness;

        // corrupts only the commitment (roots stay consistent with the gateway tree) → the
        // commitment cross-check branch fires first.
        struct CommitTamper;
        impl ProverClient for CommitTamper {
            fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
                let mut out = MockProverClient.prove(w)?;
                out.commitment = [0xFFu8; 32];
                Ok(out)
            }
        }

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");

        // (PreparedSettle is not Debug, so no unwrap_err here)
        let Err(err) = prove_and_prepare(&CommitTamper, &witness, &ww) else {
            panic!("tampered commitment must be a hard error");
        };
        assert!(err.contains("commitment mismatch"), "got: {err}");
    }

    #[test]
    fn commit_window_settle_extends_proofs_across_windows() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();

        // ── window 1: withdrawal → begin → prove → commit ────────────────────
        gw.account_withdraw(&key, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc1 = gw.seq.state.next_batch_id;
        let (witness1, ww1) = gw.begin_window_settle(bc1).unwrap().expect("some");
        let ordered1 = witness1.manifest.ordered.clone();
        let rejected1: Vec<_> = witness1.manifest.rejected.iter().map(|(h, _)| *h).collect();
        let batch_id1 = witness1.batch_id;
        let leaf_w1 = ww1[0].leaf();
        let prepared1 = prove_and_prepare(&MockProverClient, &witness1, &ww1).unwrap();
        let status1 = L1Status {
            settled_root: hex32(&prepared1.outcome.new_root),
            batch_count: batch_id1 + 1,
            last_tx: "0xtx1".into(),
            bond: "0".into(),
            withdrawals_root: hex32(&prepared1.outcome.withdrawals_root),
        };
        gw.commit_window_settle(batch_id1, ordered1, rejected1, prepared1, status1);
        assert!(gw.withdraw_proofs.contains_key(&leaf_w1));

        // ── window 2: another withdrawal (root changes) → begin → commit ─────
        gw.account_withdraw(&key, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        let bc2 = gw.seq.state.next_batch_id;
        let (witness2, ww2) = gw.begin_window_settle(bc2).unwrap().expect("some");
        let ordered2 = witness2.manifest.ordered.clone();
        let rejected2: Vec<_> = witness2.manifest.rejected.iter().map(|(h, _)| *h).collect();
        let batch_id2 = witness2.batch_id;
        assert_eq!(batch_id2, batch_id1 + 1); // windows advance
        let leaf_w2 = ww2[0].leaf();
        let prepared2 = prove_and_prepare(&MockProverClient, &witness2, &ww2).unwrap();
        let new_root2 = prepared2.outcome.new_root;
        let status2 = L1Status {
            settled_root: hex32(&new_root2),
            batch_count: batch_id2 + 1,
            last_tx: "0xtx2".into(),
            bond: "0".into(),
            withdrawals_root: hex32(&prepared2.outcome.withdrawals_root),
        };
        gw.commit_window_settle(batch_id2, ordered2, rejected2, prepared2, status2);

        // EXTEND semantics: window 1's claim proof SURVIVES window 2's commit
        assert!(
            gw.withdraw_proofs.contains_key(&leaf_w1),
            "window-1 withdraw proof must survive a window-2 commit (extend, not replace)"
        );
        assert!(gw.withdraw_proofs.contains_key(&leaf_w2));
        assert!(gw.batch_orders.contains_key(&batch_id1));
        assert!(gw.batch_orders.contains_key(&batch_id2));
        assert_eq!(gw.last_settled_root, new_root2);
    }
}
