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
    extract::{ConnectInfo, Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
// SEC-020 mutual-attestation handshake — quote/verify backends + the pure
// transcript math (ephemeral DH + session secret/token) shared with the
// prover-service. `StaticSecret` is the attestation crate's re-export of the
// ephemeral x25519 secret type (no direct x25519-dalek dependency here).
use dark_perp_attestation::{
    derive_session, dh_shared, ephemeral_keypair, validate_session_expiry, Attestor as _,
    AzureTdxAttestor, NvidiaCcAttestor, StaticSecret, Zeroizing, DEV_INSECURE_SESSION_TOKEN,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};

use note_archive::{NoteArchive, Wallet};
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{Digest, Domain, Keccak256};
use perp_core::market::Market;
use perp_core::note::{Note, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{Finality, Order, Side, TimeInForce};
use perp_core::state::Mode;
use sequencer::{adl_tag, adl_tag_key, EnclaveIdentity, SealedBatch, Sequencer, WindowWitness};

mod account_recovery;
mod bootstrap;
mod candles;
mod challenge_scan;
mod clock_admission;
mod clock_client;
mod clock_wait;
#[cfg(test)]
mod continuation_settlement_tests;
mod credential_session;
mod deposit_ingestion;
mod deposit_rpc;
mod enclave_epoch;
mod execution;
#[cfg(test)]
mod funds_lifecycle_tests;
mod l1;
mod listen_config;
mod ops_alerts;
#[cfg(test)]
mod oracle_intake_tests;
mod order_log;
mod prover_client;
mod recovery_checkpoint;
mod rollback_journal;
mod service_policy;
#[cfg(test)]
mod service_policy_integration_tests;
mod service_shutdown;
#[cfg(test)]
mod service_shutdown_tests;
mod settle_health;
mod snapshot;
mod trading_gate;
mod wind_down;
mod withdrawals;
use l1::{L1Status, L1};
// SEC-025-B: `merkle_root` left the production import set with the legacy settle body
// (the window path derives roots inside prover_client); tests still assert with it.
#[cfg(test)]
use withdrawals::merkle_root;
use withdrawals::{inclusion_leaf, merkle_proof, owner_commit, rejection_leaf, Withdrawal};

/// 0x-prefixed lowercase hex of a 32-byte digest (for L1 calldata + display).
fn hex32(d: &Digest) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// SEC-025-C: does the gateway's last settled root match the chain's currentStateRoot?
/// Split from the boot wiring so it is testable without an RPC. Case-insensitive
/// because `current_root()` returns whatever the node formats.
fn continuity_ok(last_settled_root: &Digest, chain_root: &str) -> bool {
    hex32(last_settled_root).eq_ignore_ascii_case(chain_root)
}

/// SEC-025-C follow-up (deposit-posture check): verdict of comparing the gateway's
/// consumed-deposit accumulator against the vault's on-chain deposit chain at boot.
/// Split from the boot wiring so it is testable without an RPC (like `continuity_ok`).
#[derive(Debug, PartialEq, Eq)]
enum DepositPosture {
    Ok,
    /// The gateway has consumed MORE deposits than the vault ever received. A correct
    /// gateway can only ever credit deposits the vault actually holds, so this has no
    /// false positives — it is exactly the unbacked-deposit signature (a demo-derived
    /// genesis, or a demo snapshot booted under production posture). The converse does
    /// NOT hold: this detects unbacked deposit LEAVES, not unbacked mints in general —
    /// it is complete today because every unbacked credit emits a `Deposit` batch op
    /// and folds a leaf: `fund` → `fund_amount`, and (SEC-024) the demo insurance
    /// seed, which now enters as its own Deposit → `FundInsurance` pair. The old
    /// `SeedInsurance` mint — which inflated `insurance_fund` with NO deposit leaf,
    /// the one credit this check could not see — is a deterministically-rejected stub.
    UnbackedCount,
    /// The counts are consistent, but the vault's recorded prefix tip at the gateway's
    /// consumed count differs from the gateway's fold — the consumed leaves are not the
    /// vault's leaves (sentinel/fabricated deposits with a coincidental count).
    TipMismatch,
}

/// The pure half of the boot-time deposit-posture check. `vault_tip_at_gw_count` is
/// `vault.depositTipAt(gw_count)` as `cast` formats it (`bytes32(0)` — never written —
/// for the honest-genesis `gw_count == 0`); the tip comparison reuses `continuity_ok`
/// so hex-case tolerance stays in one place. `gw_count < vault_count` is legitimate:
/// deposits the vault holds but the gateway has not yet confirmed.
fn deposit_posture(
    gw_count: u64,
    gw_tip: &Digest,
    vault_count: u64,
    vault_tip_at_gw_count: &str,
) -> DepositPosture {
    if gw_count > vault_count {
        return DepositPosture::UnbackedCount;
    }
    if !continuity_ok(gw_tip, vault_tip_at_gw_count) {
        return DepositPosture::TipMismatch;
    }
    DepositPosture::Ok
}

/// A send error is ambiguous: an unchanged counter cannot prove a previously
/// broadcast transaction will never land. Only a matching advanced counter may
/// roll forward (the caller must also confirm the prepared root); otherwise HOLD.
#[derive(Debug, PartialEq, Eq)]
enum RollAction {
    RollForward,
    Hold,
}

fn settle_failure_action(sealed_batch_id: u64, chain_batch_count: u64) -> RollAction {
    if Some(chain_batch_count) == sealed_batch_id.checked_add(1) {
        RollAction::RollForward
    } else {
        RollAction::Hold
    }
}

/// SEC-025-D: how long a settle path may wait for its gate observation to become
/// conclusive before carrying `Inconclusive` into the commit. The observation block
/// sits `GATE_OPEN_CONFIRMATIONS` behind head, so right after a settle's receipt it
/// predates the settle by construction and the classifier reads "lagging" — the
/// chain needs ~12 more Base blocks (~24 s) before the observation can decide.
/// This deadline is that, with generous slack for a slow or load-balanced RPC.
/// Only paid while the gate is Closed (launch), never in steady state.
const GATE_OBSERVE_WAIT_SECS: u64 = 120;

/// Poll cadence inside that wait — a few Base blocks per probe. Each probe is four
/// `cast` subprocesses, so probing faster than the chain moves only burns RPC.
const GATE_OBSERVE_POLL_SECS: u64 = 5;

/// SEC-025-D: ONE block-pinned three-way gate observation. Reads `batchCount`,
/// `currentStateRoot` and `closeOnly` at a SINGLE canonical hash at height
/// `GATE_OPEN_CONFIRMATIONS` behind the current head. Configured witness agreement
/// and canonical rechecks are enforced by the L1 reader. All three at one block, or
/// the finalSettle exclusion does not hold; the depth means a reorg shallower than the confirmation policy
/// cannot unwind what an OPEN was decided on. Any failed read is `Inconclusive`,
/// NEVER `StaysClosed`: the opening check runs once per commit and a commit is not
/// repeatable, so resolving an errored read against opening could burn a launch's
/// only opportunity — an idle book opens no further windows, and 025-A's bootstrap
/// endpoint is one-shot and cannot manufacture one.
fn observe_gate_once(
    l1: &L1,
    sealed_batch_id: u64,
    our_new_root: Digest,
) -> trading_gate::GateObservation {
    let read = || -> Result<trading_gate::GateObservation, String> {
        let (_block, count, root, close_only) = l1.gate_observation()?;
        Ok(trading_gate::classify(
            count,
            sealed_batch_id,
            root,
            our_new_root,
            close_only,
        ))
    };
    read().unwrap_or_else(|e| {
        eprintln!("[gate] pinned observation read failed ({e}) — inconclusive, not resolved");
        trading_gate::GateObservation::Inconclusive
    })
}

/// SEC-025-D: the settle paths' gate observation — `observe_gate_once`, retried
/// while it reads `Inconclusive`, up to a wall-clock deadline. The wait is what
/// makes a quiet launch able to open at all: the commit right after a receipt
/// always starts lagging (the observation block trails head by the confirmation
/// depth), and a deployment whose only window was the capitalization settle never
/// seals another — without the wait every observation it will ever get is
/// `Inconclusive` and the gate never opens. Bounded: past the deadline the last
/// `Inconclusive` is returned, which leaves the gate UNRESOLVED rather than
/// resolved against opening.
///
/// "For a later window" is NOT a guarantee: `begin_window_settle` returns `None` on an
/// unchanged root with no manifest content, and SEC-025-A's bootstrap endpoint is
/// one-shot, so a quiet deployment may seal nothing further on its own. The recovery is
/// that ANY deposit moves the state root and therefore manufactures a window — an
/// operator whose observation was burnt by a long outage should credit one rather than
/// wait. Recorded here because the code offers no other way back.
///
/// Blocking (subprocess reads + sleeps) — call from `spawn_blocking` or boot, never on
/// the async runtime.
fn observe_gate(
    l1: &L1,
    sealed_batch_id: u64,
    our_new_root: Digest,
) -> trading_gate::GateObservation {
    let deadline = std::time::Instant::now() + Duration::from_secs(GATE_OBSERVE_WAIT_SECS);
    loop {
        let obs = observe_gate_once(l1, sealed_batch_id, our_new_root);
        if obs != trading_gate::GateObservation::Inconclusive
            || std::time::Instant::now() >= deadline
        {
            return obs;
        }
        std::thread::sleep(Duration::from_secs(GATE_OBSERVE_POLL_SECS));
    }
}

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
    /// HOLD: keep the journal and refuse startup until a later boot can resolve it.
    KeepJournal,
}

/// Task 3 (crash recovery): resolve a journaled in-flight window settle against
/// the restored snapshot and the chain, per the spec's boot-recovery table. The
/// pure decision is `rollback_journal::recovery_action`; this applies it to the
/// `Gw` (rollback: rewind Counter B + re-inject the drained withdrawals;
/// roll-forward: re-commit the bookkeeping from the journal's `prepared`).
/// Every HOLD prints a line containing "HOLDING" — the ops health alert greps
/// for that substring.
///
/// SEC-025-D: `gate_observation` is the block-pinned three-way gate read the CALLER
/// took (this function stays pure of chain I/O so its tests can drive the table
/// directly); it reaches `commit_window_settle` only through the RollForward arm —
/// the third place a settle can be committed, and so the third place a wind-down
/// `finalSettle` could be mistaken for ours. Callers that cannot or need not
/// observe (tests, a gate already open, a non-roll-forward shape) pass
/// `Inconclusive`, which can never open the gate and never latches it either.
fn apply_boot_recovery(
    gw: &mut Gw,
    j: rollback_journal::RollbackJournal,
    chain_bc: u64,
    chain_root: &str,
    bond: u128,
    gate_observation: trading_gate::GateObservation,
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
            let rejected: Vec<Digest> = j
                .witness
                .manifest
                .rejected
                .iter()
                .map(|(h, _)| *h)
                .collect();
            let status = L1Status {
                settled_root: hex32(&prepared.outcome.new_root),
                batch_count: j.batch_id + 1,
                last_tx: "(recovered at boot)".into(),
                bond: bond.to_string(),
                withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
            };
            gw.commit_window_settle(
                j.batch_id,
                ordered,
                rejected,
                prepared,
                status,
                gate_observation,
            );
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
                 {chain_root}) — keeping the journal; operator must reconcile (startup is refused until this journal resolves)",
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
) -> bool {
    if mutated {
        if let Err(e) = persist_recovery(gw, state_path, seed) {
            eprintln!(
                "[recovery] HOLDING: window recovery applied in memory but the post-recovery \
                 snapshot could not be persisted ({e}) — keeping the rollback journal {} as \
                 the recovery source (the next boot re-resolves it); fix the snapshot path",
                journal_path.display()
            );
            return false;
        }
    }
    rollback_journal::delete(journal_path);
    !journal_path.try_exists().unwrap_or(true)
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
/// How long an acknowledged snapshot waits before giving up. A wedge here means the
/// writer cannot make progress — most likely a caller holding `App.gw` across the await —
/// and an `Err` that a caller can refuse on is strictly better than an unbounded hang
/// that takes the whole gateway with it.
const SNAPSHOT_ACK_TIMEOUT_SECS: u64 = 30;
/// Soft cap on retained per-account order history. A SETTLED partial fill can still
/// have a live remainder: only sealed orders absent from the book may be evicted.
/// Live orders take priority over the history cap so their cancellation stays reachable.
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

// ── SEC-020 Task 4: mutual-attestation handshake (gateway side) ──────────────

/// GET `url` via a curl subprocess (the repo's HTTP transport pattern — see
/// `prover_client::http_post` / `L1::cast`) and parse the JSON body. Boot-time
/// only; short timeouts so a dead peer fails the handshake fast (fail-closed),
/// never wedges startup.
fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let out = std::process::Command::new("curl")
        .args([
            "-s",
            "-S",
            "--fail",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            url,
        ])
        .output()
        .map_err(|e| format!("curl spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("json: {e}"))
}

/// A pinned expected-measurement env var (32-byte hex): required for the
/// attestation handshake unless `DEV_INSECURE` — unset/malformed refuses the
/// handshake (fail-closed), never a default.
///
/// PHASE 2: these pins must be APP-level identities (see the C1 note at the
/// prover-service's gateway-verify call site): `GATEWAY_EXPECTED_MEASUREMENT` =
/// this CVM's `azure_app_measurement` (MRTD‖pcr_digest, `vtpm.rs`), and
/// `PROVER_EXPECTED_MEASUREMENT` = the GB10 prover's CC measurement.
fn expected_measurement_env(var: &str) -> Result<Digest, String> {
    let s = std::env::var(var).map_err(|_| {
        format!("{var} unset — required for the attestation handshake unless DEV_INSECURE")
    })?;
    parse_hex32(&s).ok_or_else(|| format!("{var} is not 32-byte hex"))
}

/// SEC-020 Phase-2 (C3): the gateway's side of the ephemeral-DH mutual-
/// attestation handshake, run once at settle-path init. No query nonce —
/// freshness is the single-use ephemeral keypair each side binds into its OWN
/// attested evidence. Fetches the prover's `/attest` `{bundle, eph_pub,
/// not_after}`, verifies the bundle over the prover's advertised `eph_pub`
/// against the pinned `PROVER_EXPECTED_MEASUREMENT` via the NVIDIA CC backend,
/// folds the x25519 ECDH shared point into the session secret, and mints the
/// token under the PROVER's advertised `not_after` (the prover owns expiry, C5).
///
/// Fail-closed by construction: ANY `Err` at ANY step (env pin unset,
/// unreachable peer, malformed response, failed verify) aborts the WHOLE
/// handshake — the caller leaves the token unset and proving stays closed. A
/// token is never minted from a partial transcript. Phase-1 pivot INTACT: on
/// today's CC-off GB10 the `NvidiaCcAttestor::verify` below is
/// `Err(CcNotEnabled)`, so in production this ALWAYS refuses — independently of
/// whether the Azure-side verify (the prover's half) would have passed.
///
/// Returns the `/prove` session token, the raw `session_secret` (the attested
/// seal key rests on it — never logged or served; threaded only into the
/// `HttpProverClient`), and the prover's `not_after`. On any `Err` the caller
/// gets none of them, so nothing is ever built from a partial handshake.
fn prover_handshake(
    prover_url: &str,
    gw_sk: &StaticSecret,
    gw_pub: &[u8; 32],
) -> Result<(String, [u8; 32], u64), String> {
    let gw_expected = expected_measurement_env("GATEWAY_EXPECTED_MEASUREMENT")?;
    let pv_expected = expected_measurement_env("PROVER_EXPECTED_MEASUREMENT")?;
    let url = format!("{}/attest", prover_url.trim_end_matches('/'));
    let resp = http_get_json(&url)?;
    let bundle = resp
        .get("bundle")
        .and_then(|v| v.as_str())
        .and_then(decode_hex)
        .ok_or("no hex `bundle` in the prover /attest response")?;
    // The prover's own per-boot ephemeral DH pubkey + session expiry ride its
    // /attest response: `eph_pub` is the challenge its evidence must bind, and
    // the gateway mints its token under the PROVER's `not_after` (the value the
    // /prove gate will compare — the prover owns expiry).
    let pv_pub = resp
        .get("eph_pub")
        .and_then(|v| v.as_str())
        .and_then(parse_hex32)
        .ok_or("no 32-byte `eph_pub` in the prover /attest response")?;
    let not_after = resp
        .get("not_after")
        .and_then(|v| v.as_u64())
        .ok_or("no `not_after` in the prover /attest response")?;
    // Phase-1 fail-closed pivot: CC is off on today's GB10, so this verify is
    // `Err(CcNotEnabled)` and the handshake refuses HERE — token unset, proving
    // closed — regardless of anything else in the transcript. The challenge is
    // the PROVER's own advertised `eph_pub`: a passing verify proves the peer's
    // evidence binds the DH key we are about to derive the secret from.
    let pv_meas = NvidiaCcAttestor::detect()
        .verify(&bundle, &pv_expected, &pv_pub)
        .map_err(|e| format!("prover quote verify: {e:?}"))?;
    // Shared transcript orientation (both sides identical): gateway fields
    // first, prover second. `pv_meas` is verify-enforced == `pv_expected`;
    // `gw_expected` stands in for our own measurement (the prover's Azure-side
    // verify enforces the same pin on its half). The ECDH `shared` requires OUR
    // ephemeral PRIVATE key, so the secret is not derivable from the public
    // /attest transcript (C3).
    let shared =
        Zeroizing::new(dh_shared(gw_sk, &pv_pub).map_err(|e| format!("prover DH: {e:?}"))?);
    validate_session_expiry(not_after, now_ms())
        .map_err(|e| format!("prover session expiry: {e:?}"))?;
    let (secret, token) =
        derive_session(&shared, &gw_expected, &pv_meas, gw_pub, &pv_pub, not_after);
    Ok((token, secret, not_after))
}

/// `GET /attest` — this gateway's attestation evidence bundle + per-boot
/// ephemeral DH pubkey, for the prover's side of the SEC-020 mutual-attestation
/// handshake. No `?nonce=` query (C2/C3): freshness IS the single-use `eph_pub`
/// this boot bound into its own evidence — a replayed `{bundle, eph_pub}` is
/// useless without the matching ephemeral PRIVATE key. `quote()` binds `gw_pub`
/// as the challenge on a live CVM (tee-capture AK-extraData); the static local
/// fixture ignores it, which is why the real-binary handshake is window-deferred.
/// NO `not_after` here — the PROVER owns session expiry (C5). No quote source ⇒
/// 503 — never a fabricated bundle.
async fn get_attest(
    State(app): State<Shared>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let unavailable = |msg: String| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": msg })),
        )
    };
    let Some(att) = app.attestor.as_ref() else {
        return Err(unavailable(
            "attestation not ready: no ATTESTATION_DIR quote/collateral bundle".into(),
        ));
    };
    match att.quote(&app.gw_pub) {
        Ok(bundle) => Ok(Json(serde_json::json!({
            "bundle": hex0x(&bundle),
            "eph_pub": hex32(&app.gw_pub),
        }))),
        Err(e) => Err(unavailable(format!("attestation not ready: {e:?}"))),
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
    unavailable: bool,
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
    receipt: serde_json::Value,
    finality: String,
    cancellable: bool,
    filled_size: Option<String>,
    avg_fill_price: Option<String>,
    execution: serde_json::Value,
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
    /// Admission is independent of the settlement failure circuit breaker.
    clock_admission: Option<clock_admission::Status>,
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
    /// FIN-001 settle-loop health for operators/monitors: "HEALTHY"|"DEGRADED"|"HELD".
    settlement_health: String,
    /// A01 finalized-prefix/durability health, without permit/account secrets.
    deposit_ingestion: serde_json::Value,
    /// Consecutive settle failures behind `settlement_health` (0 when healthy).
    settlement_consecutive_failures: u32,
    /// Most recent settle error while unhealthy (omitted when none).
    #[serde(skip_serializing_if = "Option::is_none")]
    settlement_last_error: Option<String>,
    /// Wall-clock ms the settle loop entered HELD (omitted unless currently HELD).
    #[serde(skip_serializing_if = "Option::is_none")]
    settlement_held_since_ms: Option<u64>,
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
    /// Local receipt time of the last accepted source observation, for telemetry
    /// only. The signed exchange timestamp remains the freshness authority.
    /// Duplicate, old, invalid and future observations never refresh this field.
    px_ms: u64,
    /// Last exchange ticker timestamp seen, to detect the advance above.
    feed_ts: u64,
}
#[derive(Serialize, serde::Deserialize)]
struct GwOrder {
    /// Persisted in the versioned snapshot trailer, not the legacy Gw prefix.
    #[serde(skip)]
    execution: Option<execution::Execution>,
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
    /// The external EOA the account funds from. An on-chain USDC `Deposit(from, amount)`
    /// is credited only when `from` matches this (so one account can't claim another's
    /// deposit). `None` until bound. NOT immutable: it may be REBOUND, but SEC-021b
    /// requires the currently bound address to sign the change — the API key alone is
    /// not sufficient, because proving control of the new address is free for whoever
    /// chose it.
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
    /// rejected instead of duplicating the position. Rides the sealed snapshot.
    /// NOTE (SEC-021, tested): `serde(default)` does NOT keep pre-upgrade postcard
    /// snapshots loadable — postcard is positional, so a shorter old encoding fails
    /// to decode (see `pre_upgrade_account_encoding_behaviour_is_pinned`); fresh
    /// genesis on redeploy is fine.
    #[serde(default)]
    last_sealed_nonce: u64,
    /// SEC-021: strictly-increasing nonce of the last SUCCESSFULLY COMPLETED signed
    /// withdrawal (account or LP). Deliberately SEPARATE from `last_signed_nonce`
    /// (orders): orders are high-frequency, and a shared counter would let an order
    /// stream racing past nonce N invalidate an already-signed withdrawal in flight.
    /// Committed only after the whole withdrawal succeeds, so a validly signed request
    /// that then fails on insufficient balance stays retryable rather than burning its
    /// nonce. Both withdrawal flows share this one counter — their digests are
    /// domain-separated, so cross-replay is impossible without a second counter.
    /// `serde(default)` is forward-additive struct hygiene; NOTE postcard is positional,
    /// so a cross-version snapshot load still requires a state reset (see the migration
    /// note in the deploy runbook).
    #[serde(default)]
    last_withdraw_nonce: u64,
    /// SEC-021b: how many times this account's deposit-address binding has been moved.
    /// Mixed into `rebind_auth_digest` and incremented on every accepted rebind, so a
    /// rebind authorization is single-use. Without it a signature over (owner, A, B)
    /// would stay valid any time the bound address is A — letting a leaked API key plus
    /// a captured old signature force the binding back to B after the user rotated away
    /// from it. Counts rebinds only; the first-time bind does not increment it.
    #[serde(default)]
    rebind_counter: u64,
    /// A07 credential-rotation generation; trailer-persisted, not positional.
    #[serde(skip)]
    recovery_nonce: u64,
    /// Runtime-only synchronization; no positional or trailer schema change.
    #[serde(skip)]
    credential_control: Arc<credential_session::Control>,
    /// SEC-019 (Task 7b): gateway-issued deposit authorizations awaiting their on-chain
    /// landing, keyed by `ownerCommit = keccak(owner ‖ deposit_blind)`. The value is the
    /// SECRET per-deposit `deposit_blind` (a fresh 32-byte CSPRNG value); `owner` is this
    /// account's `wallet.owner`. On the matching `Deposit` event the gateway looks the
    /// blind up by the on-chain `ownerCommit`, recomputes `keccak(owner ‖ blind)`, and
    /// credits only on a match (the misattribution guard). The blind is NEVER served
    /// publicly (only `ownerCommit` + `sig` leave the gateway) but IS persisted — it must
    /// be reproducible at credit time, and it rides the existing sealed snapshot.
    /// NOTE (SEC-021, tested): `serde(default)` does NOT make this loadable from a
    /// pre-upgrade snapshot — postcard is positional (see
    /// `pre_upgrade_account_encoding_behaviour_is_pinned`); a state reset is required.
    #[serde(default)]
    deposit_authorizations: std::collections::BTreeMap<[u8; 32], [u8; 32]>,
}

/// The output of `Gw::validated_deposit` — everything the funding op needs, produced
/// by the guards WITHOUT mutating anything (SEC-025-A Task 3). Existing so the
/// insurance-bootstrap path can run the same validation as a user deposit and then
/// route the value differently, instead of duplicating the security checks.
#[cfg(test)]
struct ValidatedDeposit {
    wallet: Wallet,
    amt: i128,
    note_blind: [u8; 32],
    deposit_blind: [u8; 32],
}

/// serde `default` for `Gw::settle_health` on the restore (postcard) path. Settlement
/// health is ephemeral runtime state — a restored `Gw` starts a fresh `from_env` breaker
/// just as a cold `boot()` does. `SettleHealth` isn't (de)serializable, so the field is
/// `#[serde(skip)]` and this supplies its value (also reused by `boot()` to stay DRY).
fn default_settle_health() -> crate::settle_health::SettleHealth {
    crate::settle_health::SettleHealth::from_env(std::time::Duration::from_secs(L1_SETTLE_SECS))
}

// Public receipt material only. Runtime-only and bounded: repeated polling must
// not perform one ECDSA operation per historical order while holding App.gw.
type ReceiptCache =
    std::sync::Mutex<std::collections::BTreeMap<(Digest, u64, [u8; 20]), serde_json::Value>>;
const MAX_RECEIPT_CACHE: usize = 4096;

#[derive(Serialize, serde::Deserialize)]
struct Gw {
    /// Runtime-only alert episode state; never changes the frozen snapshot encoding.
    #[serde(skip)]
    ops_alerts: ops_alerts::OpsAlerts,
    /// Persisted in the v9 envelope prefix, outside the frozen positional Gw layout.
    /// Freezes ordinary ops after SettleAll or on ambiguous legacy CloseOnly.
    /// It never proves phase-1 completion; only a canonical L1 read does that.
    #[serde(skip)]
    wind_down_started: bool,

    // A01 extension is versioned outside the frozen v5 positional Gw encoding.
    #[serde(skip)]
    deposits: deposit_ingestion::DepositState,
    seq: Sequencer,
    #[serde(skip)]
    receipt_cache: ReceiptCache,
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
    /// settle path's RPC-free "is there anything to settle?" signal is
    /// `seq.state.state_root() != last_settled_root` OR the open window carries manifest
    /// content (`window_has_pending_manifest` — SEC-025-B break 4: a resting or rejected
    /// order lands in the manifest without moving the engine root, and must still settle
    /// so inclusion/rejection challenges stay answerable); see `begin_window_settle`.
    /// `serde(default)` is forward-additive struct
    /// hygiene (matches crate precedent); NOTE: postcard is positional, so cross-version
    /// snapshot load still requires a state reset/migration — handled by the migration slice.
    #[serde(default)]
    last_settled_root: Digest,
    /// SEC-025-A: the operator insurance bootstrap state machine. Persisted, because a
    /// crash between the two legs must not lose the `(cm, spend_key)` the second leg
    /// needs, and because `Complete` is what 025-D's launch gate reads.
    #[serde(default = "bootstrap_not_started")]
    bootstrap: bootstrap::Bootstrap,
    /// SEC-025-D: the launch gate. `Closed` on a production genesis until a proven,
    /// block-pinned `settleBatch` shows the deployment capitalized — see `trading_gate`.
    #[serde(default = "trading_gate_closed")]
    trading_gate: trading_gate::TradingGate,
    /// SEC-025-D test-only: `(mode_is_normal, insurance_fund, deposit_count)` the
    /// test commit fixture puts on its `ProveOutcome` INSTEAD of deriving them from
    /// live state. The divergence is the point: the gate must judge the PROVEN
    /// post-state terms, and only terms that differ from `seq.state` can catch a
    /// transition that consults the live state (see
    /// `commit_window_settle_for_test_with`). `serde(skip)` — never persisted, so
    /// the snapshot wire format is identical with and without `cfg(test)`.
    #[cfg(test)]
    #[serde(skip)]
    test_post_state: Option<(bool, i128, u64)>,
    /// On-chain deposit tx hashes already credited (idempotency / replay guard).
    processed_deposit_txs: std::collections::BTreeSet<String>,
    /// Manifest hash of the most recently sealed batch. SEC-025-B: no longer read —
    /// the deleted legacy settle body was its only consumer (the window path publishes
    /// the sealed witness's own manifest hash) — but it stays: postcard snapshots are
    /// positional, so dropping the field would break every existing snapshot.
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
    /// FIN-001 settle-loop health (bounded-retry → HELD circuit breaker). Runtime-only:
    /// settlement failures are ephemeral, so a reboot/restore starts fresh (`from_env`),
    /// exactly like `attestation` — hence `#[serde(skip)]` + a from_env default.
    #[serde(skip, default = "default_settle_health")]
    settle_health: crate::settle_health::SettleHealth,
    /// Wall-clock ms when the settle loop last entered HELD (None unless currently HELD).
    /// Runtime-only, resets on reboot in lockstep with `settle_health`.
    #[serde(skip)]
    settlement_held_since_ms: Option<u64>,
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
    /// SEC-021: the deployment this gateway's withdrawal-authorization signatures are
    /// bound to (L1 chain id + vault address). Mixed into every withdrawal/rebind digest
    /// so a snapshot restored or copied onto a DIFFERENT deployment cannot accept a
    /// signature minted for this one — the signed nonce is not the withdrawal-leaf nonce
    /// (that is the gateway-global `next_withdraw_nonce`), so one authorization could
    /// otherwise become different claim leaves on two deployments. NOT persisted —
    /// like `oracle_signer`, serde skips it and the REAL identity is installed by the
    /// boot wiring: `main()` writes both from `GatewaySigner` (the same env source the
    /// on-chain deposit digest is bound to) right beside `prod`, and the digest paths
    /// (`account_withdraw`, `account_lp_withdraw`, the SEC-021b rebind in
    /// `account_set_deposit_address`) read them at runtime — that write + those reads
    /// are what keep these fields live code (no `dead_code` marker needed; the serde
    /// `default` reference is NOT what silences the lint — a `#[serde(skip)]` field
    /// with no `default` is equally silent). The `default` fn
    /// (`dev_fallback_chain_id`/`dev_fallback_vault`) is load-bearing for the RESTORE
    /// path only: a deserialized `Gw` holds the same dev fallback a fresh `boot()`
    /// does until the `main()` write lands, so no deserialize path can invent a third
    /// identity. A prod boot whose vault is still the zero fallback is refused
    /// (`vault_binding_ok_for_mode`).
    #[serde(skip, default = "dev_fallback_chain_id")]
    chain_id: u64,
    #[serde(skip, default = "dev_fallback_vault")]
    vault: [u8; 20],
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
    /// ZK-001: the operator's oracle-publisher signing key (from `ORACLE_SIGNER_KEY`,
    /// else the documented oracle-feed dev key). Every `Market.oracle_pubkey` is pinned
    /// to this signer's address at boot, so every synthetic/live transcript the gateway
    /// produces recovers to it and clears the fail-closed §8 signature gate. A secp256k1
    /// secret must NEVER touch the sealed snapshot, so this is runtime-only — re-derived
    /// from the environment on boot/restore exactly like the enclave identity and
    /// `epochs` (`#[serde(skip)]` + a from_env default). Since the derivation is
    /// deterministic, a restored gateway re-derives the SAME address the persisted
    /// markets were pinned to.
    #[serde(skip, default = "boot_oracle_signer")]
    oracle_signer: k256::ecdsa::SigningKey,
}

/// The oracle-publisher signer every market's `oracle_pubkey` is pinned to (ZK-001).
/// Mirrors `default_settle_health`: a restored `Gw` re-derives it from the same env
/// the original boot used, so the persisted `Market.oracle_pubkey` still matches. A
/// SET-but-malformed `ORACLE_SIGNER_KEY` fails closed (exit) rather than silently
/// signing with the dev key — `main()` validates it up front, so this only fires on
/// a genuinely broken restore environment.
fn boot_oracle_signer() -> k256::ecdsa::SigningKey {
    oracle_feed::signer_from_env().unwrap_or_else(|e| {
        eprintln!("[fatal] oracle publisher signer: {e}");
        std::process::exit(1);
    })
}

/// Serde-restore defaults for the SEC-021 deployment binding (`Gw.chain_id`/`Gw.vault`):
/// a deserialized `Gw` gets the SAME dev fallback `boot()` and `GatewaySigner::from_env`
/// use (single source: `DEV_FALLBACK_CHAIN_ID`/`DEV_FALLBACK_VAULT`), and `main()` then
/// overwrites both from `GatewaySigner` — mirrors `boot_oracle_signer`'s
/// "runtime-only, re-derived on restore" pattern.
fn dev_fallback_chain_id() -> u64 {
    DEV_FALLBACK_CHAIN_ID
}
fn dev_fallback_vault() -> [u8; 20] {
    DEV_FALLBACK_VAULT
}

fn bootstrap_not_started() -> bootstrap::Bootstrap {
    bootstrap::Bootstrap::NotStarted
}

fn trading_gate_closed() -> trading_gate::TradingGate {
    trading_gate::TradingGate::Closed
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

/// Build a synthetic (non-live) oracle transcript for `market_id` and SIGN it with
/// the operator's oracle key (ZK-001). Every market's `oracle_pubkey` is pinned to
/// this signer's address at boot, so the simulated price clears the fail-closed §8
/// in-circuit signature gate exactly as a live one does. The digest is produced by
/// CALLING [`perp_core::oracle::oracle_digest`] over the FINAL field values (never
/// hand-rolled), so the guest's re-hash is byte-identical.
fn oracle_of(
    px: i128,
    now: u64,
    market_id: u64,
    signer: &k256::ecdsa::SigningKey,
) -> OracleTranscript {
    let price = px;
    let publish_time_ms = now;
    let confidence = (px / 1000).max(1);
    let backup_twap = px;
    let digest = oracle_digest(market_id, price, publish_time_ms, confidence, backup_twap);
    OracleTranscript {
        price,
        publish_time_ms,
        confidence,
        backup_twap,
        signature: OracleSig::sign(signer, &digest),
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

/// SEC-025-C: what a boot mints at genesis. **Passed into `Gw::boot_with`, never read
/// from `Gw::prod`** — `prod` is assigned two lines after `boot()` returns in `main()`,
/// so it cannot guard the funding that happens inside.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisMode {
    /// Registers markets AND funds MM / demo user / LP demo, and seeds insurance.
    /// Those are UNBACKED mints with sentinel L1 fields, so a chain built on this
    /// genesis can never satisfy `_requireDepositPrefix`. Demo and no-L1 dev only.
    Demo,
    /// Markets only. `consumed_deposit_tip` and `consumed_deposit_count` stay at their
    /// `State::new` values, which is exactly the pair a fresh vault's `depositTipAt(0)`
    /// returns — so the first settle's deposit-prefix pin passes.
    Production,
}

impl Gw {
    /// Demo-genesis boot — the historical entry point, kept so its ~80 test call
    /// sites stay untouched (exactly one caller was ever non-test: `main`, which
    /// now derives a `GenesisMode` and calls `boot_with` directly). Compiled out
    /// of the non-test binary entirely — `cfg(test)`, not `allow(dead_code)` — so
    /// a future non-test caller is a COMPILE ERROR rather than a silent
    /// reintroduction of demo funding (eight unbacked deposits) into production,
    /// which is the exact bug class SEC-025-C exists to kill.
    #[cfg(test)]
    fn boot() -> Self {
        Self::boot_with(GenesisMode::Demo)
    }

    fn boot_with(mode: GenesisMode) -> Self {
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

        // ZK-001: the single oracle-publisher key every market trusts. Its address is
        // logged (by `signer_from_env`) so the operator can pin it on-chain, and is set
        // as each `Market.oracle_pubkey` below — without this, even correctly-signed
        // transcripts fail `WrongOraclePublisher`.
        let oracle_signer = boot_oracle_signer();
        let oracle_addr = oracle_feed::signer_address(&oracle_signer);

        // Pass 1 (registration): register EVERY market + its oracle before ANY funding.
        // add_market re-captures window_start_state and is sound only while window_ops is
        // empty; funding pushes ops into window_ops, so all add_market calls must complete
        // first (markets are boot config, not mid-window). See sequencer::add_market.
        let mut mkts = Vec::new();
        for cfg in MARKETS.iter() {
            let mut market = Market::with_fees_treasury(
                cfg.id,
                TAKER_FEE_BPS,
                MAKER_REBATE_BPS,
                TREASURY_FEE_BPS,
            );
            // Pin the market's trusted oracle publisher to the operator's signer (ZK-001).
            market.oracle_pubkey = oracle_addr;
            seq.add_market(market);
            let px = usd(cfg.seed);
            seq.set_oracle(cfg.id, oracle_of(px, now, cfg.id, &oracle_signer));
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
        // Pass 2 (funding): all markets now exist, so fund each bucket. DEMO ONLY
        // (SEC-025-C): every credit below is an UNBACKED mint with sentinel L1 fields,
        // each folding a sentinel leaf into `consumed_deposit_tip`. A production
        // genesis must mint NOTHING — a chain built on these eight fabricated deposits
        // submits `newDepositCount = 8+` against a fresh vault whose `depositCount` is
        // 0, and `_requireDepositPrefix` reverts BEFORE the proof is even verified.
        if mode == GenesisMode::Demo {
            // Infallible-by-construction (SEC-026): genesis boot mints into an EMPTY tree,
            // and every blind below (0x40+i / 0x10+i / 0x38 / 0x39) is a distinct constant
            // used exactly once — no historical duplicate is possible, so `.expect` is honest.
            for (i, cfg) in MARKETS.iter().enumerate() {
                // fund the market-maker (deep) and the user (≈$5k) into each market bucket
                // `prod: false` — this whole block runs only under `GenesisMode::Demo`,
                // never in production (SEC-025-C).
                fund(
                    &mut seq,
                    &mut archive,
                    &mm,
                    cfg.id,
                    MM_FUND_PER_MARKET,
                    0x40 + i as u8,
                    false,
                )
                .expect("boot MM funding: fresh distinct blinds on an empty genesis tree");
                fund(
                    &mut seq,
                    &mut archive,
                    &user,
                    cfg.id,
                    USER_FUND_PER_MARKET,
                    0x10 + i as u8,
                    false,
                )
                .expect("boot user funding: fresh distinct blinds on an empty genesis tree");
            }
            // give the demo user extra market-0 balance so the LP tab is demoable (LP
            // deposits debit this real balance — no free mint).
            fund(&mut seq, &mut archive, &user, 0, 2_000_000, 0x38, false)
                .expect("boot LP-demo funding: fresh distinct blind on an empty genesis tree");
            // capitalize the insurance fund so the backstop is visible from genesis; it
            // then grows on its own from the per-fill insurance cut (audit Q3/Q4).
            // SEC-024: insurance is a TRANSFER now, never a mint — a sentinel-leaf
            // deposit (so it counts in `consumed_deposit_count` like every credit
            // above) consumed by `FundInsurance`. There is no unspent boot note to
            // reuse (`fund` consumes what it deposits), so this is its own pair,
            // under the free blind 0x39 and a throwaway owner (seed [3; 32]).
            seed_insurance_unbacked(
                &mut seq,
                [3u8; 32],
                INSURANCE_SEED_USD * QUOTE_SCALE,
                [0x39u8; 32],
                false,
            )
            .expect("boot insurance seed: fresh distinct blind + owner on an empty genesis tree");
        }
        // Pass-2 funding + the insurance transfer mutated state and pushed ops into the open
        // window AFTER add_market last captured window_start_state. The L1 contract
        // is deployed with GENESIS_ROOT = the FULL boot state root (computed below),
        // so fold the boot ops into the genesis baseline: window 0 must open from
        // genesis, or its pre_state (post-Pass-1, pre-funding) != the on-chain
        // GENESIS_ROOT and the first settle reverts with BadPrevRoot. Runs in BOTH
        // genesis modes: with no Pass-2 ops (Production) it simply folds nothing.
        seq.seal_genesis_baseline();

        let genesis_root = seq.state.state_root();
        // Live-migration tooling: the runbook reads this line off a throwaway boot to
        // deploy the L1 contract with a matching GENESIS_ROOT (deterministic in the
        // boot config). Log-only — no behavior change.
        println!("[state] genesis engine root {}", hex32(&genesis_root));
        let mut gw = Gw {
            ops_alerts: Default::default(),
            wind_down_started: false,
            deposits: Default::default(),
            seq,
            receipt_cache: ReceiptCache::default(),
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
            bootstrap: bootstrap::Bootstrap::NotStarted,
            // SEC-025-D: a demo genesis trades from boot (funded accounts, no L1 to
            // observe, so no settle could ever open a closed gate); production starts
            // Closed and stays so until the launch check (Task 4) opens it.
            trading_gate: if mode == GenesisMode::Demo {
                trading_gate::TradingGate::Open
            } else {
                trading_gate::TradingGate::Closed
            },
            #[cfg(test)]
            test_post_state: None,
            processed_deposit_txs: std::collections::BTreeSet::new(),
            last_manifest: [0u8; 32],
            pending_ordered: Vec::new(),
            pending_rejected: Vec::new(),
            batch_orders: std::collections::BTreeMap::new(),
            l1_status: None,
            settle_health: default_settle_health(),
            settlement_held_since_ms: None,
            attestation,
            lp_shares: std::collections::BTreeMap::new(),
            lp_total_shares: 0,
            lp_counter: 0,
            prod: false,
            // SEC-021: overwritten in `main()` from GatewaySigner. The shared consts
            // ARE GatewaySigner::from_env's unset-var fallbacks, so the demo build and
            // unit tests get a coherent (if non-unique) deployment identity by
            // construction.
            chain_id: DEV_FALLBACK_CHAIN_ID,
            vault: DEV_FALLBACK_VAULT,
            window_settle_mode: false,
            // Derive the first order-ingress epoch from the SAME seed the enclave
            // signing identity derives from, so a reboot/re-pin keeps the key stable.
            epochs: enclave_epoch::EnclaveEpochs::derive(enclave_seed, 1, now, ORDER_EPOCH_TTL_MS),
            order_log: order_log::OrderLog::new(derive_log_pub(&enclave_seed)),
            oracle_signer,
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
        let mut bytes = wind_down::SNAPSHOT_V9.to_vec();
        bytes.push(u8::from(self.wind_down_started));
        bytes.extend_from_slice(account_recovery::SNAPSHOT_V8);
        bytes.extend_from_slice(deposit_ingestion::SNAPSHOT_V6);
        bytes.extend(
            postcard::to_allocvec(&(self, mkt_px, &self.deposits)).expect("snapshot encode"),
        );
        execution::append_snapshot(self, &mut bytes);
        account_recovery::append(self, &mut bytes);
        bytes
    }

    /// Restore from snapshot plaintext, rebuilding the runtime-only parts exactly
    /// as `boot()` does: the live attestation, the enclave identity (from
    /// `ENCLAVE_SEED` — the snapshot never carries the signing secret), and the
    /// static market table with the persisted dynamics overlaid.
    fn boot_restored(plain: &[u8]) -> Result<Self, String> {
        if plain.len() > snapshot::MAX_PLAIN_BYTES {
            return Err(
                "snapshot exceeds 64 MiB payload limit; preserve file for offline reconciliation"
                    .into(),
            );
        }
        let (plain, wind_down_started) = wind_down::snapshot_payload(plain)?;
        let (plain, version7, version8) =
            if let Some(payload) = plain.strip_prefix(account_recovery::SNAPSHOT_V8) {
                (payload, true, true)
            } else if let Some(payload) = plain.strip_prefix(execution::SNAPSHOT_V7) {
                (payload, true, false)
            } else {
                (plain, false, false)
            };
        if version7 && !plain.starts_with(deposit_ingestion::SNAPSHOT_V6) {
            return Err("v7 snapshot missing A01 payload".into());
        }
        type MarketDynamics = Vec<(u64, i128, i128, bool)>;
        let (mut gw, mkt_px): (Gw, MarketDynamics) = if let Some(payload) =
            plain.strip_prefix(deposit_ingestion::SNAPSHOT_V6)
        {
            let ((mut gw, prices, deposits), rest): (
                (Gw, MarketDynamics, deposit_ingestion::DepositState),
                _,
            ) = postcard::take_from_bytes(payload)
                .map_err(|e| format!("v6 snapshot decode: {e}"))?;
            gw.deposits = deposits;
            if version7 {
                if rest.is_empty() {
                    return Err("v7 snapshot missing execution extension".into());
                }
                let recovery = if version8 {
                    let recovery = execution::restore_snapshot_prefix(&mut gw, rest)?;
                    if !recovery.starts_with(account_recovery::EXT) {
                        return Err("v8 snapshot missing recovery extension".into());
                    }
                    recovery
                } else {
                    execution::restore_snapshot(&mut gw, rest)?;
                    &[][..]
                };
                account_recovery::restore(&mut gw, recovery)?;
            } else {
                if !rest.is_empty() {
                    return Err("trailing v6 snapshot bytes".into());
                }
                execution::restore_snapshot(&mut gw, &[])?;
                account_recovery::restore(&mut gw, &[])?;
            }
            (gw, prices)
        } else {
            // Frozen DPSNAP5 positional layout: preserve all fields, including
            // every secret blind. Missing routing remains explicitly unresolved.
            let (mut legacy, rest): ((Gw, MarketDynamics), _) =
                postcard::take_from_bytes(plain).map_err(|e| format!("v5 snapshot decode: {e}"))?;
            if !rest.is_empty() {
                return Err("trailing v5 snapshot bytes".into());
            }
            legacy.0.deposits.legacy_prefix = Some((
                legacy.0.seq.state.consumed_deposit_count,
                legacy.0.seq.state.consumed_deposit_tip,
            ));
            execution::restore_snapshot(&mut legacy.0, &[])?;
            account_recovery::restore(&mut legacy.0, &[])?;
            legacy
        };
        // Old snapshots cannot distinguish a circuit breaker from SettleAll.
        // Conservatively freeze ordinary ingress in legacy CloseOnly; the pinned
        // admin/withdraw routes can still select the correct L1 phase.
        gw.wind_down_started = wind_down_started.unwrap_or(gw.seq.state.mode == Mode::CloseOnly);
        if gw.wind_down_started && gw.seq.state.mode != Mode::CloseOnly {
            return Err("wind-down snapshot latch requires CloseOnly".into());
        }
        gw.validate_deposit_state()?;

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

        // SEC-021: chain_id/vault are serde-skipped with a `default` fn (the
        // oracle_signer pattern), so deserialization ALREADY re-applied the shared dev
        // fallback — no manual re-apply here, and any future deserialize path gets the
        // same identity for free. main() then overwrites both from GatewaySigner.

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
                last_withdraw_nonce: 0,
                rebind_counter: 0,
                recovery_nonce: 0,
                credential_control: Arc::default(),
                deposit_authorizations: std::collections::BTreeMap::new(),
            },
        );
        (api_key, owner)
    }

    /// Bind the external EOA an account funds from (so its on-chain USDC deposits can
    /// be attributed). Requires a secp256k1 signature **recovering to `addr`** over a
    /// digest binding this account's owner — so only the controller of `addr` can bind
    /// it. This closes a front-run where an attacker binds a victim's public deposit
    /// EOA and steals the credit (review fix). An address binds to at most one account.
    /// SEC-021b: a REBIND must additionally carry `current_sig` — the CURRENTLY bound
    /// address's signature over `rebind_auth_digest` — see the body for the WHY.
    ///
    /// NO RECOVERY PATH (accepted product decision, to be DOCUMENTED not engineered
    /// around — Task 9: docs/API.md, docs/SECURITY.md, alpha release notes): if the
    /// key for the currently bound address is lost, the binding is permanently
    /// frozen — there is no unbind, override, or admin escape hatch — and once
    /// withdrawals are pinned to the bound address (Task 5), the account's funds
    /// become unwithdrawable. Keep the bound key safe.
    fn account_set_deposit_address(
        &mut self,
        key: &[u8; 32],
        addr: [u8; 20],
        sig: &[u8; 65],
        current_sig: Option<&[u8; 65]>,
    ) -> Result<(), String> {
        let (owner, bound, rebinds) = {
            let a = self.accounts.get(key).ok_or("Unknown account.")?;
            (a.wallet.owner, a.deposit_address, a.rebind_counter)
        };
        // Proof of control over the address being bound (unchanged). Accept the
        // signature over ANY of the three deterministic shapes of the bind digest
        // (raw / EIP-191 over bytes / EIP-191 over hex string) so both CLI signers
        // and browser-wallet `personal_sign` work — see `eip191_prehash_candidates`
        // for the WHY of each and the security invariant (all shapes commit to the
        // same (owner, addr), so this widens signer ergonomics, never authorization).
        let digest = deposit_bind_digest(&owner, &addr);
        let proven = eip191_prehash_candidates(&digest)
            .iter()
            .any(|prehash| recover_eth_address(prehash, sig) == Some(addr));
        if !proven {
            return Err(
                "deposit-address proof: signature must recover to the address being bound".into(),
            );
        }
        // SEC-021b: a REBIND must additionally be authorized by the address currently
        // bound. Proving control of the NEW address is free for an attacker (it is
        // their own address), so without this a leaked API key alone could redirect
        // the binding and drain every future withdrawal to it.
        if let Some(old) = bound {
            if old == addr {
                return Ok(()); // idempotent re-bind of the same address: no-op
            }
            if !self.accounts[key].deposit_authorizations.is_empty() {
                return Err("Confirm all outstanding deposit authorizations before rebinding; issued L1 permits do not expire.".into());
            }
            let cur = current_sig.ok_or(
                "rebinding requires `currentSignature` from the account's current deposit address",
            )?;
            let rebind_digest =
                rebind_auth_digest(self.chain_id, &self.vault, &owner, rebinds, &old, &addr);
            let authorized = eip191_prehash_candidates(&rebind_digest)
                .iter()
                .any(|prehash| recover_eth_address(prehash, cur) == Some(old));
            if !authorized {
                return Err(
                    "rebind not authorized: `currentSignature` must recover to the current deposit address"
                        .into(),
                );
            }
        }
        if self
            .accounts
            .iter()
            .any(|(k, a)| k != key && a.deposit_address == Some(addr))
        {
            return Err("that address is already bound to another account".into());
        }
        // Check exhaustion before changing either the binding or its generation.
        // A wrapped counter would make an old rebind authorization valid again.
        let next_rebinds = if bound.is_some() {
            rebinds.checked_add(1).ok_or("rebind nonce exhausted")?
        } else {
            rebinds
        };
        let a = self.accounts.get_mut(key).unwrap();
        a.deposit_address = Some(addr);
        // Only a REBIND increments; a first bind has no old authorization to burn.
        a.rebind_counter = next_rebinds;
        Ok(())
    }

    /// SEC-019 (Task 7b): authorize a deposit of `amount` from L1 address `from` for
    /// this account. Generates a FRESH 32-byte CSPRNG `deposit_blind`, computes
    /// `ownerCommit = keccak(owner ‖ deposit_blind)`, records `(ownerCommit → blind)` in
    /// the account's authorization set (so the eventual `Deposit` event is creditable by
    /// construction — no uncreditable leaf can head-of-line-block the queue, spec §1b),
    /// and returns `ownerCommit`. The caller signs `keccak256(chainid ‖ vault ‖ from ‖
    /// ownerCommit ‖ amount)` with the gateway key and hands the user `(ownerCommit, sig)`
    /// to submit as `deposit(amount, ownerCommit, sig)` on L1. The blind is per-deposit,
    /// high-entropy, secret, and reproducible (stored) — the four §5 requirements.
    fn account_authorize_deposit(
        &mut self,
        key: &[u8; 32],
        from: [u8; 20],
        amount: u128,
    ) -> Result<[u8; 32], String> {
        self.refuse_if_wind_down_started()?;
        // `from` must be the account's bound deposit address, mirroring the credit-side
        // binding — a signature is only ever issued for the payer the account owns.
        let (owner, bound) = {
            let a = self.accounts.get(key).ok_or("Unknown account.")?;
            (a.wallet.owner, a.deposit_address)
        };
        match bound {
            Some(b) if b == from => {}
            Some(_) => {
                return Err("`from` does not match this account's bound deposit address.".into())
            }
            None => {
                return Err(
                    "Bind a deposit address first (POST /v1/accounts/deposit/address).".into(),
                )
            }
        }
        if amount == 0 {
            return Err("deposit amount must be positive".into());
        }
        if amount > i128::MAX as u128 {
            return Err("deposit amount too large".into());
        }
        // Fresh CSPRNG blind per authorization (never derived from public data — a
        // public-derived blind would let an observer brute-force keccak(owner ‖ blind)
        // against the on-chain commit and de-anonymize the payer↔owner link, spec §5).
        let deposit_blind = csprng_bytes32();
        let commit = owner_commit(&owner, &deposit_blind);
        self.accounts
            .get_mut(key)
            .unwrap()
            .deposit_authorizations
            .insert(commit, deposit_blind);
        Ok(commit)
    }

    /// The validation half of crediting a confirmed L1 deposit: every guard, NO
    /// mutation (SEC-025-A Task 3). Split out of `account_confirm_deposit` so the
    /// insurance-bootstrap path reaches the SAME guards — tx-hash dedup, the payer
    /// binding, the SEC-019 misattribution guard, the checked u128→i128, the
    /// in-order id gate, and the note-blind derivation — around a different funding
    /// op, instead of duplicating them (duplicated security bookkeeping is how one
    /// copy drifts). Pure by contract: calling it twice succeeds twice, because
    /// nothing here consumes the authorization or advances a counter.
    #[allow(clippy::too_many_arguments)] // the L1 `Deposit` event's fields, threaded flat; a struct adds only ceremony
    #[cfg(test)]
    fn validated_deposit(
        &self,
        key: &[u8; 32],
        from: [u8; 20],
        owner_commit_onchain: [u8; 32],
        amount: u128,
        deposit_id: u64,
        tx: &str,
        market: u64,
    ) -> Result<ValidatedDeposit, String> {
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
        // SEC-019 misattribution guard (FAIL-CLOSED): the on-chain `ownerCommit` is
        // authoritative. Look up the SECRET blind we authorized for it and REJECT — do
        // NOT credit — unless `keccak(owner ‖ blind)` reproduces the on-chain commit. An
        // ABSENT record (a deposit whose commit we never authorized) or a stored blind
        // that fails to reproduce the commit is refused: crediting it would let a real L1
        // deposit be attributed to an owner the payer did not commit to (or fold a leaf
        // the vault chain does not contain).
        let deposit_blind = *self
            .accounts
            .get(key)
            .unwrap()
            .deposit_authorizations
            .get(&owner_commit_onchain)
            .ok_or("no gateway authorization for this ownerCommit — deposit refused")?;
        if owner_commit(&wallet.owner, &deposit_blind) != owner_commit_onchain {
            return Err(
                "stored deposit_blind does not reproduce the on-chain ownerCommit — deposit refused"
                    .into(),
            );
        }
        // checked u128 → i128 (a value above i128::MAX would sign-flip negative and
        // then panic inside the engine's non-positive-amount guard — review fix).
        let amt: i128 = amount
            .try_into()
            .map_err(|_| "deposit amount too large".to_string())?;
        if amt <= 0 {
            return Err("deposit amount must be positive".into());
        }
        // Host-boundary in-order guard (fail-closed): `op_deposit` only credits when
        // `deposit_id == consumed_deposit_count`. Confirm the id is next-in-line HERE so
        // an out-of-order confirm returns a clean error (and does not consume the
        // authorization). The host must feed deposits in ascending L1 `id` (spec §5).
        if deposit_id != self.seq.state.consumed_deposit_count {
            return Err(format!(
                "deposit id {deposit_id} is not next-in-line (expected {}); confirm deposits in L1 order",
                self.seq.state.consumed_deposit_count
            ));
        }
        let dc = self.accounts.get(key).unwrap().deposit_counter;
        let mut note_blind = [0xB0u8; 32];
        note_blind[..8].copy_from_slice(&dc.to_le_bytes());
        Ok(ValidatedDeposit {
            wallet,
            amt,
            note_blind,
            deposit_blind,
        })
    }

    /// The success-bookkeeping half (SEC-025-A Task 3): bump `deposit_counter`,
    /// consume the one-shot authorization, mark the tx processed. Runs ONLY after
    /// the funding op succeeded — on any Err the caller must skip it, so a failed
    /// confirm stays retriable (nothing consumed, nothing marked).
    #[cfg(test)]
    fn commit_deposit_bookkeeping(
        &mut self,
        key: &[u8; 32],
        owner_commit_onchain: &[u8; 32],
        tx: &str,
    ) {
        let a = self.accounts.get_mut(key).unwrap();
        a.deposit_counter += 1;
        // One-shot: consume the authorization so a second event for the same ownerCommit
        // can't double-credit (the tx-hash dedup already guards replays; this is defense
        // in depth and keeps the SECRET blind from lingering past its single use).
        a.deposit_authorizations.remove(owner_commit_onchain);
        self.processed_deposit_txs.insert(tx.to_string());
    }

    /// Credit a CONFIRMED on-chain USDC deposit to an account's market bucket. The
    /// caller (handler) has already read `(from, ownerCommit, amount, id)` from the
    /// vault's SEC-019 `Deposit` log via the L1 bridge; here we enforce the binding
    /// (`from` == the account's bound address), the SEC-019 misattribution guard (the
    /// stored blind for `ownerCommit` must reproduce the on-chain commit), dedup by tx
    /// hash, and fund the engine with the REAL L1-leaf fields so the resulting
    /// `consumed_deposit_tip` fold matches the vault's `depositChainTip` for this
    /// `(from, ownerCommit, amount, id)`. USDC base units map 1:1 to quote units.
    /// The guards live in `validated_deposit` and the success mutations in
    /// `commit_deposit_bookkeeping` (both shared with the insurance bootstrap,
    /// SEC-025-A); this composes them around the user-deposit funding op.
    #[allow(clippy::too_many_arguments)] // the L1 `Deposit` event's fields, threaded flat; a struct adds only ceremony
    #[cfg(test)]
    fn account_confirm_deposit(
        &mut self,
        key: &[u8; 32],
        from: [u8; 20],
        owner_commit_onchain: [u8; 32],
        amount: u128,
        deposit_id: u64,
        tx: &str,
        market: u64,
    ) -> Result<i128, String> {
        let v = self.validated_deposit(
            key,
            from,
            owner_commit_onchain,
            amount,
            deposit_id,
            tx,
            market,
        )?;
        // Fund with the REAL L1-leaf fields: the payer `from`, the L1 `id`, and the
        // authorized `deposit_blind` — so `consumed_deposit_tip` folds the SAME leaf the
        // vault chained on-chain (`deposit_leaf(from, keccak(owner‖blind), amount, id)`).
        //
        // FALLIBLE (SEC-026 review F2): the note blind (`0xB0 ‖ deposit_counter`,
        // monotonic per account, bumped only on success) makes a historical duplicate
        // unreachable today, but an engine refusal here must be a clean Err, never a
        // panic under the account lock. On Err NOTHING below runs (the authorization is
        // NOT consumed, `deposit_counter` is NOT bumped, the tx is NOT marked
        // processed) — but `fund_amount` is TWO-PHASE and its arms leave DIFFERENT
        // engine state, so the operator contract is per-arm:
        //
        //  - `CreditRefused` (phase 1, `op_deposit`): the engine mutated nothing, so
        //    `consumed_deposit_count` did NOT advance — the in-order stream IS stalled
        //    at this id and the SAME confirm may be retried. (A DuplicateCommitment
        //    retry needs a fresh note blind; the note blind is independent of the L1
        //    leaf's `deposit_blind`, so the same L1 deposit stays creditable — an
        //    operator/cutover decision, not automated here.)
        //
        //  - `FundPositionFailed` (phase 2, after the credit landed): the deposit WAS
        //    credited and `consumed_deposit_count` DID advance — the stream is NOT
        //    stalled, and retrying this confirm is refused as not next-in-line. The
        //    value sits as an unspent note owned by this account (recoverable). And
        //    because `deposit_counter` was not bumped, this account's NEXT same-amount
        //    confirm re-derives the same `0xB0` blind against the still-live note and
        //    hits a permanent DuplicateCommitment — which THEN stalls the stream. This
        //    arm needs operator intervention, not a blind retry. (Reachable only via a
        //    gateway/state market-table divergence or collateral near `i128::MAX`;
        //    `consume_note` cannot fail here — SEC-026: a fresh cm implies a fresh
        //    nullifier.)
        fund_amount(
            &mut self.seq,
            &mut self.archive,
            &v.wallet,
            market,
            v.amt,
            v.note_blind,
            from,
            deposit_id,
            v.deposit_blind,
        )
        .map_err(|e| match e {
            FundAmountError::CreditRefused(msg) => format!(
                "L1 deposit id {deposit_id} (tx {tx}) could NOT be credited: {msg}. \
                 OPERATOR: the SEC-019 in-order deposit stream is STALLED at id \
                 {deposit_id} — `op_deposit` requires deposit_id == consumed_deposit_count, \
                 so every later on-chain deposit confirm will fail (DepositOutOfOrder) \
                 until this deposit is credited. The authorization was not consumed and \
                 the tx was not marked processed; the confirm may be retried."
            ),
            FundAmountError::FundPositionFailed(msg) => format!(
                "L1 deposit id {deposit_id} (tx {tx}) WAS credited but binding it as \
                 collateral failed: {msg}. OPERATOR: the deposit stream is NOT stalled — \
                 the credit advanced consumed_deposit_count to {}, so retrying this \
                 confirm will be refused as not next-in-line. The value is recoverable \
                 (an unspent note owned by this account). The authorization was not \
                 consumed, the tx was not marked processed, and deposit_counter was not \
                 bumped — so this account's NEXT same-amount deposit would re-derive the \
                 same note blind and hit a permanent DuplicateCommitment, stalling the \
                 stream for real. Operator intervention required; do NOT blind-retry.",
                deposit_id + 1
            ),
        })?;
        self.commit_deposit_bookkeeping(key, &owner_commit_onchain, tx);
        Ok(v.amt)
    }

    /// Drive the bootstrap. Ordering is load-bearing:
    /// one-shot → resume (second leg alone) → payer binding → checked u128→i128 →
    /// floor → validate → apply both legs → record → bookkeeping. The property that
    /// matters is not which guard runs first but that EVERY guard precedes the first
    /// `seq.apply`: no guard failure can consume a deposit id or mint a note, so a
    /// refused call spends nothing — in particular, a below-floor amount cannot spend
    /// the one-shot. (The resume arm is the one deliberate exception to "guards then
    /// apply": it spends a note the guards already vetted when the record was written,
    /// and consumes nothing from THIS request.)
    #[allow(clippy::too_many_arguments)] // the L1 `Deposit` event's fields, threaded flat; a struct adds only ceremony
    #[cfg(test)]
    fn bootstrap_insurance(
        &mut self,
        key: &[u8; 32],
        expected_payer: [u8; 20],
        from: [u8; 20],
        owner_commit_onchain: [u8; 32],
        amount_u128: u128,
        deposit_id: u64,
        tx: &str,
        market: u64,
    ) -> Result<(), String> {
        // One-shot keyed on REACHING THE FLOOR, not on having been called. Counting calls
        // deadlocks across time: A completes under floor F1, a later D build raises it to
        // F2, D refuses to open and a spent one-shot refuses to top up.
        //
        // KNOWN TENSION, named rather than hidden: because this reads the CURRENT fund, a
        // fund later drained below the floor by bad debt also reopens the endpoint. That is
        // a recapitalization path, which 025-D lists as a required follow-up — but it was a
        // declared non-goal here, and it is admin+payer gated rather than free. Do not
        // "tidy" this into a plain `== Complete` check without re-reading 025-D §3; that
        // reintroduces the temporal deadlock.
        if self.bootstrap == bootstrap::Bootstrap::Complete
            && self.seq.state.insurance_fund >= bootstrap::MIN_BOOTSTRAP_INSURANCE
        {
            return Err(
                "insurance bootstrap already completed and the fund meets the minimum".into(),
            );
        }
        // SEC-025-A Task 5: resume a half-finished bootstrap — the SECOND leg alone.
        // `DepositApplied` is written only on the `TransferFailed` arm below, from the
        // values the engine was actually fed, so the note it names really was minted
        // and is live. A pair-retry cannot work (the first `Deposit` already advanced
        // `consumed_deposit_count`, so it would fail `DepositOutOfOrder` before ever
        // reaching `FundInsurance`); and none of the request-derived guards below
        // apply, because this arm consumes NOTHING from the current request — it
        // spends the recorded note, whose payer and amount the guards vetted when the
        // record was written. On failure the record is untouched (engine failure
        // atomicity), so the resume stays retriable.
        if let bootstrap::Bootstrap::DepositApplied {
            note_commitment,
            spend_key,
            ..
        } = self.bootstrap
        {
            self.seq
                .apply(&BatchOp::FundInsurance {
                    note_commitment,
                    spend_key,
                })
                .map_err(|e| {
                    format!(
                        "insurance transfer resume failed (the recorded note stays live, \
                         resume again): {e:?}"
                    )
                })?;
            self.bootstrap = bootstrap::Bootstrap::InsuranceApplied {
                window_id: self.seq.state.next_batch_id,
            };
            return Ok(());
        }
        // The only non-forgeable discriminator: the on-chain payer, taken from the parsed
        // receipt rather than the request body. Without it an admin key could route ANY
        // user's deposit into the fund, because the engine validates the spend with
        // `expected_owner = None` and the gateway custodies every account's spend key.
        if from != expected_payer {
            return Err("deposit payer is not the configured INSURANCE_OPERATOR_ADDRESS".into());
        }
        let amount = i128::try_from(amount_u128)
            .map_err(|_| "deposit amount does not fit i128".to_string())?;
        if !bootstrap::amount_meets_floor(amount) {
            return Err(format!(
                "bootstrap amount {amount} is below the minimum {} — refusing so the \
                 one-shot is not spent on an amount that would leave the launch gate closed",
                bootstrap::MIN_BOOTSTRAP_INSURANCE
            ));
        }
        let v = self.validated_deposit(
            key,
            from,
            owner_commit_onchain,
            amount_u128,
            deposit_id,
            tx,
            market,
        )?;
        fund_insurance_backed(
            &mut self.seq,
            &v.wallet,
            v.amt,
            v.note_blind,
            from,
            deposit_id,
            v.deposit_blind,
        )
        .map_err(|e| match e {
            // Leg 1 refused: NOTHING was applied (SEC-026 failure atomicity), so the
            // record must not move. In particular a pre-existing `DepositApplied` from
            // an earlier attempt still describes the note that WAS minted — overwriting
            // it here would swap in THIS attempt's deposit_id while the live note came
            // from the old one.
            FundInsuranceError::DepositRefused(msg) => msg,
            // Leg 2 failed AFTER the note was minted: record what a resume of the
            // second leg alone needs, from the values the engine was actually fed —
            // the variant carries them so there is exactly one derivation and no
            // recompute here that could drift from it.
            FundInsuranceError::TransferFailed {
                msg,
                note_commitment,
                spend_key,
            } => {
                self.bootstrap = bootstrap::Bootstrap::DepositApplied {
                    note_commitment,
                    spend_key,
                    deposit_id,
                };
                // The DEPOSIT succeeded on this arm, so its two irreversible consequences
                // must be booked even though the transfer did not. Skipping them is a
                // landmine, not a tidy rollback:
                //
                // `deposit_counter` feeds the note blind (`0xB0 ‖ counter`). The mint
                // consumed this blind, and SEC-026 uniqueness is HISTORICAL, so leaving the
                // counter would make this account's next SAME-AMOUNT deposit re-derive the
                // same commitment and fail `DuplicateCommitment`. `op_deposit` mints before
                // any counter bump, so that failure does NOT advance
                // `consumed_deposit_count` — which stalls the SEC-019 in-order deposit
                // stream for EVERY account, not just this one. And the operator cannot dodge
                // it by retrying with a different amount: the amount comes from the on-chain
                // `Deposit` event, never from the request body.
                //
                // The tx is marked because it really was credited; a later confirm of it
                // would otherwise fail as not-next-in-line and read like a different bug.
                //
                // The AUTHORIZATION is deliberately left in place. Removing it is what makes
                // a second leaf for the same `ownerCommit` permanently uncreditable
                // (SEC-028), and nothing here needs it gone.
                let a = self.accounts.get_mut(key).unwrap();
                a.deposit_counter += 1;
                self.processed_deposit_txs.insert(tx.to_string());
                msg
            }
        })?;
        self.bootstrap = bootstrap::Bootstrap::InsuranceApplied {
            window_id: self.seq.state.next_batch_id,
        };
        self.commit_deposit_bookkeeping(key, &owner_commit_onchain, tx);
        Ok(())
    }

    /// SEC-021: the address whose secp256k1 signature authorizes this account's
    /// withdrawals. A caller-signed account's registered `signer` wins — it is the
    /// explicit opt-in. Otherwise the bound `deposit_address`: the account already
    /// proved it can sign with that key when it bound it, so requiring it again on
    /// the money path costs the user nothing new and leaves no account authorized by
    /// the bearer API key alone. Neither ⇒ no withdrawal is possible.
    fn authorizing_address(&self, key: &[u8; 32]) -> Result<[u8; 20], String> {
        let a = self.accounts.get(key).ok_or("Unknown account.")?;
        a.signer.or(a.deposit_address).ok_or_else(|| {
            "no authorizing address: bind a deposit address (POST /v1/accounts/deposit/address) \
             or register a caller-signed account before withdrawing"
                .to_string()
        })
    }

    /// Withdraw `amount` (quote units = USDC base units) from an account's market
    /// bucket to the L1 address `to`: debit the engine (Unbind + burn the note, so the
    /// off-chain balance really drops and can't be double-withdrawn) and record an
    /// authorized withdrawal leaf. On the next L1 settle the cumulative root is
    /// published and the user can `vault.claim` the USDC on Base Sepolia (§3).
    /// SEC-021: EVERY withdrawal must carry a secp256k1 signature over
    /// `withdraw_auth_digest` recovering to the account's authorizing address
    /// (`authorizing_address`) — the API key alone must never move funds. All
    /// checks run BEFORE the first `seq.apply` (fail-closed: a rejection mutates
    /// nothing and burns no nonce).
    #[cfg(test)]
    fn account_withdraw(
        &mut self,
        key: &[u8; 32],
        market: u64,
        amount: i128,
        to: [u8; 20],
        auth_nonce: u64,
        sig: &[u8; 65],
    ) -> Result<Withdrawal, String> {
        self.account_withdraw_observed(key, market, amount, to, (auth_nonce, sig), None)
    }

    fn account_withdraw_observed(
        &mut self,
        key: &[u8; 32],
        market: u64,
        amount: i128,
        to: [u8; 20],
        auth: (u64, &[u8; 65]),
        wind_down: Option<&wind_down::Observation>,
    ) -> Result<Withdrawal, String> {
        let (auth_nonce, sig) = auth;
        // Validate BEFORE any unbind, note burn, or nonce mutation. A local
        // CloseOnly circuit breaker alone never authorizes phase-2 operations.
        if self.seq.state.mode == Mode::CloseOnly {
            wind_down
                .ok_or("wind-down requires a fresh L1 phase-1 observation")?
                .check_exit(self)?;
        }
        self.deposits.check_ready()?;
        if amount <= 0 {
            return Err("Amount must be positive.".into());
        }
        if self.mkt(market).is_none() {
            return Err("Unknown market.".into());
        }
        let (wallet, signer, bound, last_nonce) = {
            let a = self.accounts.get(key).ok_or("Unknown account.")?;
            (a.wallet, a.signer, a.deposit_address, a.last_withdraw_nonce)
        };
        // SEC-021: server-custody accounts may only withdraw to the address they
        // bound. The signature already binds `to`, but the rebind path is exactly
        // where this design's first version failed (SEC-021b), so the destination
        // carries a second, independent constraint. Caller-signed accounts are the
        // explicit advanced mode and keep a free destination — they consented to it
        // cryptographically (deposit from a hot wallet, withdraw to a cold one).
        if signer.is_none() {
            match bound {
                Some(b) if b == to => {}
                Some(_) => {
                    return Err(
                        "Withdrawal `to` must equal this account's bound deposit address.".into(),
                    )
                }
                None => {
                    return Err(
                        "Bind a deposit address first (POST /v1/accounts/deposit/address).".into(),
                    )
                }
            }
        }
        // Replay protection: strictly increasing, CHECKED here but COMMITTED only
        // after the withdrawal fully succeeds (see the end of this function).
        if auth_nonce <= last_nonce {
            return Err("withdrawal nonce must strictly increase (replay protection)".into());
        }
        let expected = self.authorizing_address(key)?;
        let digest = withdraw_auth_digest(
            self.chain_id,
            &self.vault,
            &wallet.owner,
            market,
            amount,
            &to,
            auth_nonce,
        );
        let authorized = eip191_prehash_candidates(&digest)
            .iter()
            .any(|prehash| recover_eth_address(prehash, sig) == Some(expected));
        if !authorized {
            return Err(
                "withdrawal signature does not recover to this account's authorizing address"
                    .into(),
            );
        }
        if amount > self.market_free_of(&wallet.owner, market) {
            return Err(
                "Not withdrawable: amount exceeds the SETTLED balance in this market (§3).".into(),
            );
        }
        let nonce = self.next_withdraw_nonce;
        let mut blind = [0xD0u8; 32];
        blind[..8].copy_from_slice(&nonce.to_le_bytes());
        let wind_down = self.seq.state.mode == Mode::CloseOnly;
        if wind_down {
            self.seq
                .apply(&BatchOp::WindDownUnbind {
                    owner: wallet.owner,
                    market_id: market,
                    amount,
                    blinding: blind,
                })
                .map_err(|e| format!("wind-down unbind failed: {e:?}"))?;
        } else {
            let now = now_ms();
            let oracle = oracle_of(self.px_of(market), now, market, &self.oracle_signer);
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
        }
        let note = Note::new(wallet.owner, 0, amount, blind);
        let cm = note.commitment::<Keccak256>();
        let withdraw_op = if wind_down {
            BatchOp::WindDownWithdraw {
                note_commitment: cm,
                spend_key: wallet.spend_key,
                to: Some(to),
                nonce,
            }
        } else {
            BatchOp::Withdraw {
                note_commitment: cm,
                spend_key: wallet.spend_key,
                to: Some(to),
                nonce,
            }
        };
        self.seq
            .apply(&withdraw_op)
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
        // SEC-021: commit the authorization nonce ONLY now — the withdrawal is fully
        // applied. Committing at verification time would burn the nonce on a request
        // that then failed the balance check, and the user's retry of the unchanged
        // signed request would be rejected as a replay.
        self.accounts.get_mut(key).unwrap().last_withdraw_nonce = auth_nonce;
        Ok(w)
    }

    /// Slice 3b-2a: begin a new-path window settle. Returns `None` if the engine root is
    /// unchanged since the last settle AND the open window carries no manifest content
    /// (nothing to prove). Errors WITHOUT mutating if the window's batch id would not
    /// match the on-chain `batchCount` (a desync a prior fault left behind — recovery is
    /// Slice 3b-3). Otherwise seals the window and takes its incremental withdrawal set.
    fn begin_window_settle(
        &mut self,
        chain_batch_count: u64,
    ) -> Result<Option<(WindowWitness, Vec<Withdrawal>)>, String> {
        self.deposits.check_ready()?;
        // SEC-025-B break 4: a window can carry consensus-relevant manifest content with
        // an UNCHANGED engine root — a resting unfilled order is in `ordered` but moves no
        // state. Settling is what populates the challenge-answer store, and both on-chain
        // answer paths require a settled batch, so a root-only predicate leaves an honest
        // sequencer unable to answer a ripe challenge. Still returns None when the window
        // is empty in both senses, so idle ticks burn no proofs.
        // SettleAll still needs a phase-1 proof when a circuit breaker has
        // already flattened all positions and its state root is unchanged.
        let pending_wind_down = self.seq.window_has_pending_settle_all();
        if self.seq.state.state_root() == self.last_settled_root
            && !self.seq.window_has_pending_manifest()
            && !pending_wind_down
        {
            return Ok(None);
        }
        // Pre-check the counter BEFORE sealing (which bumps it), so a desync leaves the
        // sequencer untouched instead of stranded ahead of the chain.
        let expected = self.seq.state.next_batch_id;
        if expected != chain_batch_count {
            return Err(format!(
                "batch_id desync: window {expected} vs chain {chain_batch_count} (recovery is 3b-3)"
            ));
        }
        expected
            .checked_add(1)
            .ok_or("window batch counter exhausted")?;
        let witness = self.seq.seal_window();
        let ww = core::mem::take(&mut self.window_withdrawals);
        Ok(Some((witness, ww)))
    }

    /// Slice 3b-2a: apply a completed new-path window settle to gateway state. Accumulates
    /// the window's per-note claim proofs (each window root is permanently claimable, so we
    /// EXTEND, never replace); advances `last_settled_root`; retains this batch's ordered/
    /// rejected hashes for DP-004 challenge answers (keyed by the on-chain batch id, which
    /// equals the window id); clears the now-redundant legacy pending accumulators; and
    /// records the published L1 status. SEC-025-D: also the ONE place the launch gate
    /// can open — every path that commits a settle passes the block-pinned observation
    /// it took, and the gate opens only on `OpensGate` over a capitalized PROVEN
    /// post-state (the `ProveOutcome` terms, not the live `seq.state`, which has
    /// advanced past the proven window by the time a proof returns).
    fn commit_window_settle(
        &mut self,
        batch_id: u64,
        ordered: Vec<Digest>,
        rejected: Vec<Digest>,
        prepared: prover_client::PreparedSettle,
        l1_status: L1Status,
        observation: trading_gate::GateObservation,
    ) {
        for (leaf, entry) in prepared.withdraw_proofs {
            self.withdraw_proofs.insert(leaf, entry);
        }
        self.last_settled_root = prepared.outcome.new_root;
        // SEC-025-D: open ONCE, and only on a proven, block-pinned normal settle over a
        // capitalized post-state. Never re-closes — see `trading_gate`'s module doc for
        // why a launch gate must not double as a circuit breaker.
        if self.trading_gate == trading_gate::TradingGate::Closed
            && observation == trading_gate::GateObservation::OpensGate
            && trading_gate::predicate_met(
                prepared.outcome.post_mode_is_normal,
                prepared.outcome.post_insurance_fund,
                prepared.outcome.new_deposit_count,
                trading_gate::MIN_BOOTSTRAP_DEPOSITS,
            )
        {
            self.trading_gate = trading_gate::TradingGate::Open;
            println!(
                "[gate] trading gate OPEN (window {batch_id}): pinned observation confirmed \
                 our settleBatch on a capitalized post-state"
            );
        }
        // SEC-025-A: the bootstrap completes only when the window carrying the SECOND leg
        // commits. Keyed on the id rather than on a predicate, because this function
        // receives no witness and no post-state — the replay built during proving is
        // discarded, with one scalar surviving it.
        if let bootstrap::Bootstrap::InsuranceApplied { window_id } = self.bootstrap {
            // Both conditions matter. The id proves the SECOND leg's window is what
            // committed; the floor proves the capitalization is actually adequate, which is
            // what 025-D's launch gate goes on to require. Completing on the id alone would
            // let a deployment whose floor later rose sit permanently uncapitalizable.
            if window_id == batch_id
                && self.seq.state.insurance_fund >= bootstrap::MIN_BOOTSTRAP_INSURANCE
            {
                self.bootstrap = bootstrap::Bootstrap::Complete;
            }
        }
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

    /// One shared production transition for prove-failure health and HELD alerts.
    fn settle_breaker_failed(&mut self, error: String) -> (settle_health::NextAction, bool) {
        let (action, just_held) = self.settle_health.on_failure(error);
        if just_held {
            self.settlement_held_since_ms = Some(now_ms());
            self.ops_alerts
                .activate(ops_alerts::AlertKind::SettlementHeld);
        }
        (action, just_held)
    }

    /// FIN-001: clear the settlement circuit-breaker after a genuine settlement
    /// success — i.e. ANY path that reaches on-chain finality (the clean settle,
    /// or the ambiguous-but-landed roll-forward). Resets the failure streak/health
    /// and drops the HELD timestamp. Returns whether we were HELD, so the caller
    /// can emit the one-shot recovery log. Kept as a single shared method so the
    /// two success sites in the settle loop cannot drift apart again.
    fn settle_breaker_recovered(&mut self) -> bool {
        let was_held = matches!(
            self.settle_health.health(),
            crate::settle_health::Health::Held
        );
        self.settle_health.on_success();
        self.settlement_held_since_ms = None;
        self.ops_alerts
            .recover(ops_alerts::AlertKind::SettlementHeld);
        was_held
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
        self.pending_withdrawals
            .retain(|w| !cset.contains(&w.leaf()));
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
        self.refuse_if_wind_down_started()?;
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
        // SEC-026: the 0xA0-prefixed blind embeds the per-account monotonic
        // `deposit_counter` (bumped only on success, persisted with the snapshot), so a
        // historical duplicate is unreachable by construction — but this is a
        // user-reachable route, so an engine refusal surfaces as a clean Err, not a panic.
        fund_amount_unbacked(
            &mut self.seq,
            &mut self.archive,
            &wallet,
            market,
            amount,
            blind,
            self.prod,
        )?;
        self.accounts.get_mut(key).unwrap().deposit_counter += 1;
        Ok(())
    }

    /// Place an order for an account. Ioc/Fok are takers; Gtc/PostOnly rest in the
    /// matcher book (so an MM bot can quote). Returns the signed receipt.
    /// SEC-025-D: refuse while the launch gate is closed.
    ///
    /// DISTINCT from the close-only refusal on purpose. Close-only blocks only *opening*
    /// and means a wind-down is under way; this blocks ALL ingress and means the
    /// deployment has not launched. They stack on the same handler, and an operator who
    /// reads one message while the other is the real cause diagnoses the wrong system.
    fn refuse_if_gate_closed(&self) -> Result<(), String> {
        self.refuse_if_wind_down_started()?;
        self.deposits.check_ready()?;
        if self.trading_gate == trading_gate::TradingGate::Closed {
            return Err(
                "Trading has not been opened on this deployment yet — the launch gate is \
                 closed until a proven settle shows the insurance fund capitalized (§025-D). \
                 This is NOT close-only: no wind-down is in progress."
                    .into(),
            );
        }
        Ok(())
    }

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
            let t = deserialize_order_terms(&pt).ok_or("sealed order: malformed order terms")?;
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
        // Before the close-only check and before any mutation: a closed gate refuses
        // every order, opening or not.
        self.refuse_if_gate_closed()?;
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
                execution: Some(execution::Execution::new(order.size)),
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

    /// Cancel the caller's pending order or live maker remainder, not prior fills.
    /// The handler and tick loop hold the SAME Gw mutex. Keep lookup, matcher
    /// cancellation, manifest recording and ingress removal inside that lock.
    fn account_cancel(&mut self, key: &[u8; 32], order_id: &str) -> Result<i128, String> {
        self.refuse_if_wind_down_started()?;
        let acct = self.accounts.get_mut(key).ok_or("Unknown account.")?;
        let order = acct
            .orders
            .iter_mut()
            .find(|o| o.id == order_id)
            .ok_or("Order not found.")?;
        let cancelled = execution::cancel(&mut self.seq, &acct.wallet.owner, order)?;
        if !self.pending_rejected.contains(&order.order_hash) {
            self.pending_rejected.push(order.order_hash);
        }
        Ok(cancelled)
    }

    /// Reproduce the original acceptance signature over the PRESERVED receipt
    /// fields, never via `accept_order`/`issue_receipt` (those refresh timestamps).
    /// k256 uses deterministic signing; the snapshot and enclave identity share
    /// ENCLAVE_SEED, so an ordinary authenticated restore reproduces the same
    /// key and byte-identical signature. No persisted postcard fields change.
    /// Only trusted, stored receipt metadata reaches this helper, not user JSON.
    fn receipt_json(&self, stored: &WReceipt) -> serde_json::Value {
        let Some(order_hash) = parse_hex32(&stored.order_hash) else {
            return serde_json::Value::Null; // do not sign corrupt stored metadata
        };
        let receipt = perp_core::order::Receipt {
            order_hash,
            seq_no: stored.seq_no,
            recv_time_ms: stored.recv_time_ms,
            batch_id_hint: stored.batch_id_hint,
            window_id: stored.window_id, // deliberately unsigned, as in the L1 ABI
        };
        let digest = receipt.signing_digest::<Keccak256>();
        let signer = self.seq.enclave().eth_address();
        let cache_key = (digest, stored.window_id, signer);
        if let Ok(cache) = self.receipt_cache.lock() {
            if let Some(wire) = cache.get(&cache_key) {
                return wire.clone();
            }
        }
        let (r, s, v) = self.seq.enclave().sign_prehash(&digest);
        let mut signature = [0u8; 65];
        signature[..32].copy_from_slice(&r);
        signature[32..64].copy_from_slice(&s);
        signature[64] = v;
        let mut wire = serde_json::to_value(stored).expect("receipt fields serialize");
        wire["signature"] = serde_json::json!(hex0x(&signature));
        wire["enclaveSigner"] = serde_json::json!(hex0x(&signer));
        if let Ok(mut cache) = self.receipt_cache.lock() {
            if cache.len() >= MAX_RECEIPT_CACHE {
                cache.clear();
            }
            cache.insert(cache_key, wire.clone());
        }
        wire
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
            // SEC-021: everything the client needs to build a withdrawal signature —
            // which address must sign, which nonce is next, and the deployment the
            // digest is bound to (never hardcode these client-side: a client built
            // against the wrong deployment would sign digests that silently fail).
            "depositAddress": a.deposit_address.map(|d| hex0x(&d)),
            "callerSigned": a.signer.is_some(),
            // Saturating: `u64::MAX` means "no acceptable nonce remains" (the
            // account is already permanently un-withdrawable at that point), so
            // saturate rather than panic (debug) / wrap to a never-valid 0 (release).
            "nextWithdrawNonce": a.last_withdraw_nonce.saturating_add(1),
            "rebindCounter": a.rebind_counter,
            "recoveryNonce": a.recovery_nonce,
            "chainId": self.chain_id,
            "vault": hex0x(&self.vault),
        }))
    }
    /// One scan per market, not one full-book scan per historical order row.
    fn live_order_hashes(&self, owner: &PubKey) -> std::collections::BTreeSet<Digest> {
        self.mkts
            .iter()
            .filter_map(|m| self.seq.book(m.id))
            .flat_map(|book| book.resting_hashes_for(owner))
            .collect()
    }

    fn v1_orders_json(&self, key: &[u8; 32]) -> Option<serde_json::Value> {
        let a = self.accounts.get(key)?;
        let live = self.live_order_hashes(&a.wallet.owner);
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
                    "cancellable": live.contains(&o.order_hash) || (!o.sealed && self.seq.cancellable_size(&a.wallet.owner, &o.order, false).is_some()),
                    "filledSize": o.execution.as_ref().filter(|e| e.known).map(|e| e.filled.to_string()),
                    "avgFillPrice": o.execution.as_ref().filter(|e| e.known).map(|e| e.average().to_string()),
                    "execution": execution::wire(o, &self.seq),
                    "createdMs": o.created_ms,
                    // SEC-025-E1 decision (c): serve the stored ACCEPTANCE RECEIPT.
                    // The gateway already holds it (populated when the order was
                    // accepted); the alternatives — a client-side receipt cache or
                    // an optional field — degrade the UI for every order not placed
                    // in the current page session, for no saving beyond these lines.
                    // Serialized via WReceipt so the camelCase field names stay
                    // byte-identical to the /api/state + placeOrder-response shape.
                    // `unwrap_or(Null)` not `unwrap`: WReceipt's flat String/int
                    // fields cannot fail serialization today, but a panic is never
                    // the right default on a serving path — the frontend already
                    // synthesizes a stub for an absent/null receipt.
                    "receipt": self.receipt_json(&o.receipt),
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
            "publishTimeMs": if m.live { m.feed_ts } else { m.px_ms },
            "receivedTimeMs": m.px_ms,
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
            "chainId": self.chain_id,
            "vault": hex0x(&self.vault),
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

    /// The engine's live state root as 0x-hex. SEC-025-B: only tests read this now —
    /// the legacy settle body that fed it (and `last_manifest_hex`) to `L1::settle` is
    /// deleted; the window path derives every settled root from the sealed witness.
    #[cfg(test)]
    fn state_root_hex(&self) -> String {
        hex32(&self.seq.state.state_root())
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
        // SEC-025-D: its own guard. This path applies `BatchOp::Fill` DIRECTLY, and until
        // now was refused in production only because an unrelated unconditional `fund(..)`
        // happened to reach `refuse_unbacked_mint` first. Refusal that depends on another
        // call's position is one refactor away from disappearing.
        self.refuse_if_gate_closed()?;
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
        // SEC-026: the `0x71 + batch_id-as-u8` salt wraps every 256 batches, so a
        // historical duplicate is possible in a very long demo session — surfaced as
        // a clean Err (the demo is retryable next batch), never a panic.
        let user = self.user;
        if self.market_free(market) < required_margin(SIZE_SCALE, px) {
            fund(
                &mut self.seq,
                &mut self.archive,
                &user,
                market,
                30_000,
                0x71u8.wrapping_add(bn),
                self.prod,
            )
            .map_err(|e| format!("adl demo: user margin fund failed: {e}"))?;
        }
        // 2. An under-funded victim shorts the other side — bound to go bad-debt. A
        //    fresh victim per call (owner derived from the batch id) avoids reuse.
        let mut vseed = [0x9Au8; 32];
        vseed[..8].copy_from_slice(&n.to_le_bytes());
        let victim = Wallet::from_seed(vseed);
        let victim_margin_usd = required_margin(SIZE_SCALE, px) / QUOTE_SCALE + 1;
        // The victim OWNER is fresh per call (derived from the full 64-bit batch id),
        // so its commitment cannot be a historical duplicate even when the u8 salt
        // wraps — but propagate anyway rather than assert an engine invariant here.
        fund(
            &mut self.seq,
            &mut self.archive,
            &victim,
            market,
            victim_margin_usd,
            0x9Au8.wrapping_add(bn),
            self.prod,
        )
        .map_err(|e| format!("adl demo: victim fund failed: {e}"))?;
        let oracle = oracle_of(px, now, market, &self.oracle_signer);
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
        self.seq
            .set_oracle(market, oracle_of(gap_px, now, market, &self.oracle_signer));
        let sealed = self.seq.seal_batch(&[], now);
        // 4. restore the oracle so the spike is transient; the haircut is permanent.
        self.seq
            .set_oracle(market, oracle_of(px, now, market, &self.oracle_signer));
        // 5. replenish the insurance fund to its baseline so the backstop is shown
        //    full again and the demo is repeatable (the draw-down happened within
        //    the cascade seal above; the user's haircut below is what persists).
        //    SEC-024: replenish by TRANSFER — an unbacked demo deposit (prod-refused,
        //    like every fund above) moved into the fund with `FundInsurance`; the old
        //    `SeedInsurance` mint is a rejected stub. A fresh owner per call (derived
        //    from the full 64-bit batch id, like the victim above) keeps the note
        //    commitment historically unique even when the u8 salts wrap. Errors
        //    PROPAGATE: the old `let _ =` would have silently skipped the one refill
        //    this demo exists to show.
        let target = INSURANCE_SEED_USD * QUOTE_SCALE;
        let now_ins = self.seq.state.insurance_fund;
        if now_ins < target {
            let mut iseed = [0x1Cu8; 32];
            iseed[..8].copy_from_slice(&n.to_le_bytes());
            let mut iblind = [0x1Du8; 32];
            iblind[..8].copy_from_slice(&n.to_le_bytes());
            seed_insurance_unbacked(&mut self.seq, iseed, target - now_ins, iblind, self.prod)
                .map_err(|e| format!("adl demo: insurance refill: {e}"))?;
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
        self.refuse_if_wind_down_started()?;
        // SEC-025-C: the credit leg below is an unbacked mint, refused in production
        // by `fund_amount_unbacked`. But the debit leg (Unbind+Withdraw) is applied
        // FIRST, so relying on the mint-site refusal alone would return `Err` with
        // `from`'s value already burned. Pre-flight the SAME guard before mutating
        // anything: a production refusal must mutate NOTHING. The mint-site check
        // remains the backstop for every other caller.
        refuse_unbacked_mint(self.prod)?;
        if value > self.market_free_of(&from.owner, 0) {
            return Err("Insufficient market-0 free balance.".into());
        }
        let now = now_ms();
        let oracle = oracle_of(self.px_of(0), now, 0, &self.oracle_signer);
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
        // SEC-026: the 0xE1-prefixed blind embeds the monotonic persisted `lp_counter`
        // (bumped above, never reused), so a historical duplicate is unreachable by
        // construction — but the LP routes are user-reachable, so propagate cleanly.
        // NOTE: the debit (Unbind+Withdraw) has already been applied at this point; the
        // engine refusing the credit would leave the value burned, which is why the
        // blind's by-construction uniqueness matters and why we still never panic here.
        fund_amount_unbacked(
            &mut self.seq,
            &mut self.archive,
            to,
            0,
            value,
            cb,
            self.prod,
        )
        .map_err(|e| format!("lp credit fund: {e}"))?;
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

    /// SEC-021: the authorized, account-scoped LP withdrawal — the entry point `/v1`
    /// uses. `lp_withdraw` itself stays an unauthenticated engine primitive because
    /// the legacy demo handler calls it with the demo wallet's owner, which is not a
    /// registered account; putting the check there would break that path, and
    /// skipping the check for non-account keys would hollow it out.
    ///
    /// The withdrawer wallet is DERIVED from the account rather than accepted as a
    /// parameter, so a caller cannot pair one account's share key with another
    /// account's wallet.
    fn account_lp_withdraw(
        &mut self,
        key: &[u8; 32],
        shares: u128,
        auth_nonce: u64,
        sig: &[u8; 65],
    ) -> Result<i128, String> {
        self.deposits.check_ready()?;
        let (wallet, last_nonce) = {
            let a = self.accounts.get(key).ok_or("unknown account")?;
            (a.wallet, a.last_withdraw_nonce)
        };
        if auth_nonce <= last_nonce {
            return Err("withdrawal nonce must strictly increase (replay protection)".into());
        }
        let expected = self.authorizing_address(key)?;
        let digest = lp_withdraw_auth_digest(
            self.chain_id,
            &self.vault,
            &wallet.owner,
            shares,
            auth_nonce,
        );
        let authorized = eip191_prehash_candidates(&digest)
            .iter()
            .any(|prehash| recover_eth_address(prehash, sig) == Some(expected));
        if !authorized {
            return Err(
                "LP withdrawal signature does not recover to this account's authorizing address"
                    .into(),
            );
        }
        let value = self.lp_withdraw(key, &wallet, shares)?;
        // Commit only after success, for the same reason as `account_withdraw`.
        self.accounts.get_mut(key).unwrap().last_withdraw_nonce = auth_nonce;
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

    /// Validate source signature, source age and market bounds before touching
    /// either the displayed mark or the sequencer. Receipt time is telemetry,
    /// never permission to re-stamp an old exchange observation as fresh.
    fn apply_real_oracle(&mut self, market: u64, transcript: OracleTranscript) -> bool {
        self.apply_real_oracle_at(market, transcript, now_ms())
    }

    fn apply_real_oracle_at(
        &mut self,
        market: u64,
        transcript: OracleTranscript,
        received_ms: u64,
    ) -> bool {
        let Some(policy) = self.seq.state.markets.get(&market) else {
            return false;
        };
        if transcript.publish_time_ms == 0
            || transcript.confidence < 0
            || transcript.validate(policy, received_ms).is_err()
        {
            return false;
        }
        let Some(m) = self.mkts.iter_mut().find(|m| m.id == market) else {
            return false;
        };
        if m.live && transcript.publish_time_ms <= m.feed_ts {
            return false;
        }
        m.feed_ts = transcript.publish_time_ms;
        m.px_ms = received_ms;
        m.px = transcript.price;
        m.live = true;
        self.seq.set_oracle(market, transcript);
        true
    }

    /// Called when main activates production posture, including restored state.
    /// Demo seeds and persisted marks cannot authorize trading before a newly
    /// validated feed observation. This changes runtime admission, not snapshots
    /// or the reviewed guest's public-input/consensus format.
    fn require_fresh_production_oracles(&mut self) {
        if !self.prod {
            return;
        }
        for m in &mut self.mkts {
            m.live = false;
            m.px_ms = 0;
            m.feed_ts = 0;
            self.seq.set_oracle(
                m.id,
                OracleTranscript {
                    price: 0,
                    publish_time_ms: 0,
                    confidence: 0,
                    backup_twap: 0,
                    signature: OracleSig {
                        r: [0; 32],
                        s: [0; 32],
                        v: 0,
                    },
                },
            );
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
        // Before the close-only check and before any mutation: a closed gate refuses
        // every order, opening or not.
        self.refuse_if_gate_closed()?;
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
                execution: Some(execution::Execution::new(order.size)),
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
        self.refuse_if_wind_down_started()?;
        if amount <= 0 {
            return Err("Amount must be positive.".into());
        }
        // SEC-026 (review F1): the old `0x80 + tick % 60` blind repeats every 60 ticks,
        // so the same amount deposited 60 ticks apart reconstructed an identical note
        // commitment — accepted before (the note left the live map when immediately
        // spent by FundPosition), a historical DuplicateCommitment now. Derive the
        // blind from the tree's LEAF COUNT instead: every successful mint appends a
        // leaf, so the count strictly increases per deposit, never repeats within the
        // state's history, and is persisted with the state (snapshot restores included).
        let mut blind = [0x80u8; 32];
        blind[..8].copy_from_slice(&self.seq.state.tree.len().to_le_bytes());
        fund_amount_unbacked(
            &mut self.seq,
            &mut self.archive,
            &self.user,
            self.selected,
            amount,
            blind,
            self.prod,
        )
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
        let oracle = oracle_of(
            self.px_of(self.selected),
            now,
            self.selected,
            &self.oracle_signer,
        );
        // SEC-026: same repeat hazard as the demo deposit — `op_unbind` MINTS a note,
        // so the old `0xC0 + tick % 60` blind made withdrawing the same amount 60 ticks
        // apart a historical DuplicateCommitment. Same fix: the tree leaf count never
        // repeats (the Unbind itself appends a leaf), so the blind is session-unique.
        let mut blind = [0xC0u8; 32];
        blind[..8].copy_from_slice(&self.seq.state.tree.len().to_le_bytes());
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
        self.refuse_if_wind_down_started()?;
        let o = self
            .orders
            .iter_mut()
            .find(|o| o.id == order_id)
            .ok_or("Order not found.")?;
        execution::cancel(&mut self.seq, &self.user.owner, o)?;
        if !self.pending_rejected.contains(&o.order_hash) {
            self.pending_rejected.push(o.order_hash);
        }
        Ok(vec![WEvent {
            order_id: order_id.to_string(),
            kind: "CANCELLED".into(),
            message: "Unfilled remainder cancelled; prior fills are unchanged".into(),
        }])
    }

    fn set_mode(&mut self, mode: &str) {
        if self.wind_down_started {
            return;
        }
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
                let cm = rn.note.commitment::<Keccak256>();
                serde_json::json!({
                    "batchId": rn.batch_id,
                    "amount": rn.note.amount.to_string(),
                    // A06 can replace a haircut note without its spend key. The
                    // append-only archive therefore retains the old ciphertext;
                    // liveness comes from the authoritative root-bound unspent map,
                    // not from pretending every archived record is still live.
                    "spent": !self.seq.state.notes.contains_key(&cm)
                })
            })
            .collect()
    }

    // ── tick: oracle walk, seal pending + MM counters, settle, maintenance ───
    fn tick(&mut self) -> (Vec<WEvent>, Vec<String>) {
        if self.wind_down_started || self.deposits.check_ready().is_err() {
            return (vec![], vec![]);
        }
        self.tick += 1;
        let now = now_ms();
        // 1) oracle update. Markets with a LIVE feed keep the real transcript the
        //    oracle task last set (its publish time is the EXCHANGE's own timestamp,
        //    ≤ one fetch interval old). We deliberately do NOT re-stamp it fresh each
        //    tick — that would mask a frozen/dead feed forever; instead a stalled feed
        //    stops advancing the publish time and the §8 staleness gate trips (audit).
        //    Feed-less markets keep the simulated random walk.
        for i in 0..self.mkts.len() {
            if self.prod || self.mkts[i].live {
                continue; // No simulated fallback on an unavailable production feed.
            }
            let m = &self.mkts[i];
            let p = m.px;
            let baseline = m.reference_price;
            let drift = (baseline - p) / 400;
            let noise = (((self.rand_unit() - 0.5) * 2.0) * (p as f64) * 0.0008) as i128;
            let next = (p + drift + noise).max(1);
            self.mkts[i].px = next;
            self.mkts[i].px_ms = now;
            let id = self.mkts[i].id;
            let oracle = oracle_of(next, now, id, &self.oracle_signer);
            self.seq.set_oracle(id, oracle);
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
            // SEC-025-D: gated DIRECTLY. This injector pushes straight into the seal
            // vector without touching `accept_order` and carries no `prod` gate of its
            // own — a gate placed only in the order handlers would leave it live, stopped
            // merely because no taker got through.
            if crosses && self.trading_gate == trading_gate::TradingGate::Open {
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
                    // SEC-025-D: the /v1-account injector, gated on the SAME terms as the
                    // demo arm above. There are TWO injectors and the first pass gated only
                    // one — not exploitable today, since the one-way latch means no order
                    // can be staged while Closed, but that is exactly the positional
                    // reliance this branch refuses one screen earlier for `simulate_adl`.
                    if crosses && self.trading_gate == trading_gate::TradingGate::Open {
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
        // Update all orders, including makers submitted in older ticks/windows.
        // Applied-fill attribution is independent of the monotone finality axis.
        let mut acct_events: Vec<String> = Vec::new();
        for (i, o) in self.orders.iter_mut().enumerate() {
            let fresh = pending.contains(&i);
            let _ = execution::update(o, &self.seq, &sealed, fresh);
            if fresh {
                o.sealed = true;
            }
        }
        for (key, acct) in &mut self.accounts {
            for (i, o) in acct.orders.iter_mut().enumerate() {
                let fresh = account_refs.contains(&(*key, i));
                for mut event in execution::update(o, &self.seq, &sealed, fresh) {
                    event["owner"] = serde_json::json!(hex0x(&acct.wallet.owner));
                    acct_events.push(event.to_string());
                }
                if fresh {
                    o.sealed = true;
                }
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
            for (bid, t) in std::mem::take(&mut self.pending_settle) {
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
        for acct in self.accounts.values_mut() {
            let owner_hex = hex0x(&acct.wallet.owner);
            for o in acct.orders.iter_mut() {
                // Execution was updated above for every row. This separate
                // receipt axis may retain an earlier SETTLED fact indefinitely.
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
            // A04: SETTLED is a finality axis, not proof of full execution. Never
            // evict the only API row for a still-live partial maker. Gather its live
            // hashes once (only when pruning is needed), not once per history row.
            if acct.orders.len() > MAX_ACCOUNT_ORDER_HISTORY {
                let live: std::collections::BTreeSet<Digest> = self
                    .mkts
                    .iter()
                    .filter_map(|m| self.seq.book(m.id))
                    .flat_map(|book| book.resting_hashes_for(&acct.wallet.owner))
                    .collect();
                cap_history(&mut acct.orders, MAX_ACCOUNT_ORDER_HISTORY, |o| {
                    o.sealed
                        && o.last_finality == "SETTLED"
                        && !live.contains(&o.order_hash)
                        && o.execution
                            .as_ref()
                            .is_some_and(execution::Execution::terminal)
                });
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
        if self.prod {
            return WBook {
                market_id: market,
                unavailable: true,
                bids: Vec::new(),
                asks: Vec::new(),
            };
        }
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
            unavailable: false,
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
        // PUBLIC feed invariant (LIQ-001): the public /api/state + /ws snapshot exposes
        // ONLY the shared demo `user` account, NEVER a real /v1 tenant. This loop reads
        // `self.user.owner` alone; do not extend it to iterate real accounts. `/v1`
        // per-owner data is served only on the authenticated, owner-filtered `/v1/ws`.
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
        let live = self.live_order_hashes(&self.user.owner);
        let orders: Vec<WTrackedOrder> = self
            .orders
            .iter()
            .map(|o| WTrackedOrder {
                id: o.id.clone(),
                input: o.input.clone(),
                receipt: self.receipt_json(&o.receipt),
                finality: self.finality_str(&o.order_hash),
                cancellable: live.contains(&o.order_hash)
                    || (!o.sealed
                        && self
                            .seq
                            .cancellable_size(&self.user.owner, &o.order, false)
                            .is_some()),
                filled_size: o
                    .execution
                    .as_ref()
                    .filter(|e| e.known)
                    .map(|e| e.filled.to_string()),
                avg_fill_price: o
                    .execution
                    .as_ref()
                    .filter(|e| e.known)
                    .map(|e| e.average().to_string()),
                execution: execution::wire(o, &self.seq),
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
        // mm_hedge exposes the market-maker's net inventory + hedge target — useful
        // in dev, but front-runnable, so never on the public prod feed (LIQ-001).
        let mm_hedge: Vec<WHedge> = if self.prod {
            Vec::new()
        } else {
            self.mkts
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
                .collect()
        };

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
                publish_time_ms: if sel_mkt.live {
                    sel_mkt.feed_ts
                } else {
                    sel_mkt.px_ms
                },
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
            clock_admission: None,
            settlement_health: self.settle_health.health().as_str().to_string(),
            deposit_ingestion: serde_json::json!({
                "state": if self.deposits.halt.is_some() { "halted" } else if self.deposits.check_ready().is_err() { "paused" } else { "ready" },
                "consumedCount": self.seq.state.consumed_deposit_count,
                "consumedTip": hex0x(&self.seq.state.consumed_deposit_tip),
                "anchor": self.deposits.anchor,
                "halt": self.deposits.halt,
                "lastError": self.deposits.last_error,
                "unresolvedPermits": self.accounts.values().flat_map(|a| a.deposit_authorizations.keys()).filter(|c| !self.deposits.routes.contains_key(*c)).count(),
            }),
            settlement_consecutive_failures: self.settle_health.consecutive_failures(),
            settlement_last_error: self.settle_health.last_error().map(|s| s.to_string()),
            settlement_held_since_ms: self.settlement_held_since_ms,
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
/// Fallible (SEC-026): the caller's `blind` byte must never have been used with the
/// same `(owner, amount)` before, or the mint is refused as a historical duplicate.
fn fund(
    seq: &mut Sequencer,
    archive: &mut NoteArchive,
    w: &Wallet,
    market: u64,
    usd_amount: i128,
    blind: u8,
    prod: bool,
) -> Result<(), String> {
    fund_amount_unbacked(
        seq,
        archive,
        w,
        market,
        usd_amount * QUOTE_SCALE,
        [blind; 32],
        prod,
    )
}

/// SEC-025-C: THE production refusal for unbacked minting — the single guard every
/// unbacked-credit path funnels through: `fund_amount_unbacked` at the mint itself,
/// and `pool_transfer` as a pre-flight BEFORE its debit leg (its Unbind+Withdraw is
/// applied first, so a mint-site refusal alone would return `Err` with the debited
/// value already burned). Refused HERE rather than at the router, because
/// route-mounting protects one caller and is invisible to the next one added: that
/// is exactly how `/v1/lp` and `simulate_adl` came to be reachable while
/// self-service was correctly closed (audit DP-001).
fn refuse_unbacked_mint(prod: bool) -> Result<(), String> {
    if prod {
        return Err(
            "unbacked funding is refused in production: collateral must enter through a \
             verified L1 deposit (CollateralVault.deposit → account_confirm_deposit)"
                .to_string(),
        );
    }
    Ok(())
}

/// SEC-019 (Task 7b): an UNBACKED credit — a `Deposit` op with SENTINEL L1-leaf fields
/// (`from=[0;20]`, `deposit_blind=[0;32]`, `deposit_id` = the live consumed count so the
/// strict in-order gate passes). Used ONLY by the demo/LP/self-service seed paths that
/// fabricate collateral without a real L1 deposit event; those fold a `consumed_deposit_tip`
/// the on-chain vault chain will NOT match, so a single one breaks every subsequent
/// settle at `_requireDepositPrefix` — before the proof is even verified. REFUSED in
/// production (SEC-025-C, `refuse_unbacked_mint`). The REAL L1-credit path
/// (`account_confirm_deposit`) calls `fund_amount` with the payer's real `from`, the
/// deposit's L1 `id`, and the authorized `deposit_blind`, so its fold DOES match the vault.
fn fund_amount_unbacked(
    seq: &mut Sequencer,
    archive: &mut NoteArchive,
    w: &Wallet,
    market: u64,
    amount: i128,
    blind: Digest,
    prod: bool,
) -> Result<(), String> {
    refuse_unbacked_mint(prod)?;
    let deposit_id = seq.state.consumed_deposit_count;
    fund_amount(
        seq, archive, w, market, amount, blind, [0u8; 20], deposit_id, [0u8; 32],
    )
    // Callers of the unbacked helper (demo/LP/self-service) don't have the
    // in-order deposit-stream contract, so the flat message suffices — the arm
    // distinction only matters to `account_confirm_deposit` (SEC-026 review).
    .map_err(|e| e.to_string())
}

/// SEC-024: capitalize the insurance fund with an UNBACKED demo credit — a
/// sentinel-leaf `Deposit` (minted to a throwaway owner derived from
/// `owner_seed`) consumed in the same breath by `FundInsurance`. Insurance is a
/// TRANSFER now, never a mint: the pair folds a deposit leaf into
/// `consumed_deposit_tip` exactly like `fund_amount_unbacked`, so the boot-time
/// deposit-posture check sees it, and it is REFUSED in production by the same
/// SEC-025-C guard. The note is never archived — it is consumed immediately and
/// no wallet ever needs to decrypt it. the UNBACKED insurance-seeding funnel (demo
/// boot + `simulate_adl` refill); the `unbacked_funding_has_exactly_the_known_
/// call_sites` scan pins its single raw `Deposit` construction.
fn seed_insurance_unbacked(
    seq: &mut Sequencer,
    owner_seed: [u8; 32],
    amount: i128,
    blind: Digest,
    prod: bool,
) -> Result<(), String> {
    refuse_unbacked_mint(prod)?;
    let w = Wallet::from_seed(owner_seed);
    let cm = Note::new(w.owner, 0, amount, blind).commitment::<Keccak256>();
    seq.apply(&BatchOp::Deposit {
        owner: w.owner,
        asset_id: 0,
        amount,
        blinding: blind,
        from: [0u8; 20],
        deposit_id: seq.state.consumed_deposit_count,
        deposit_blind: [0u8; 32],
    })
    .map_err(|e| format!("insurance deposit refused by the engine: {e:?}"))?;
    // Infallible-by-construction in practice (the note was minted just above for
    // this exact key), but surfaced honestly: a failure here leaves the value as
    // an unspent note owned by the throwaway key — recoverable, not insurance.
    seq.apply(&BatchOp::FundInsurance {
        note_commitment: cm,
        spend_key: w.spend_key,
    })
    .map_err(|e| format!("insurance transfer failed AFTER the note was minted: {e:?}"))
}

/// SEC-025-A: the BACKED sibling of `seed_insurance_unbacked`, and the first production
/// caller of `BatchOp::FundInsurance`.
///
/// Three SENTINEL fields differ from the demo funnel — the three it fabricates. (`owner`
/// and `blinding` differ too: a registered account's wallet rather than a throwaway seed,
/// and `0xB0 ‖ deposit_counter` rather than a free constant. "Exactly three" is true only
/// of the sentinels.) `from` is the real L1 payer, `deposit_blind` is the authorization blind the
/// gateway actually issued, and `deposit_id` is the chain-assigned id. So this path folds
/// the SAME leaf the vault chained on-chain, and `_requireDepositPrefix` will match.
///
/// No `refuse_unbacked_mint` here: that guard stops value being asserted without backing.
/// But this function VERIFIES no backing itself — the backing is its caller's contract
/// (the funnel scan pins it: "callers must pass a REAL verified L1 leaf", which the
/// bootstrap driver satisfies via `validated_deposit`), unlike `seed_insurance_unbacked`,
/// which carries its guard inside. Calling the guard here would be cargo-culting a check
/// whose premise this function cannot even evaluate.
///
/// Deliberately no `archive.record`: the note is consumed in the same breath and no wallet
/// ever needs to decrypt it — same reasoning as the demo funnel.
#[cfg(test)]
fn fund_insurance_backed(
    seq: &mut Sequencer,
    wallet: &Wallet,
    amount: i128,
    note_blind: [u8; 32],
    from: [u8; 20],
    deposit_id: u64,
    deposit_blind: [u8; 32],
) -> Result<(), FundInsuranceError> {
    let cm = Note::new(wallet.owner, 0, amount, note_blind).commitment::<Keccak256>();
    seq.apply(&BatchOp::Deposit {
        owner: wallet.owner,
        asset_id: 0,
        amount,
        blinding: note_blind,
        from,
        deposit_id,
        deposit_blind,
    })
    .map_err(|e| {
        FundInsuranceError::DepositRefused(format!(
            "operator deposit leg failed (nothing applied): {e:?}"
        ))
    })?;
    seq.apply(&BatchOp::FundInsurance {
        note_commitment: cm,
        spend_key: wallet.spend_key,
    })
    .map_err(|e| FundInsuranceError::TransferFailed {
        msg: format!(
            "insurance transfer failed AFTER the operator note was minted: {e:?}. \
             OPERATOR: no value is lost — the deposit IS credited and the note is a live \
             unspent note owned by this account. Resume the SECOND LEG ALONE by calling \
             the bootstrap endpoint again; the persisted record carries the note's \
             identity. A pair-retry cannot work — the deposit already advanced \
             consumed_deposit_count, so it would fail DepositOutOfOrder. The caller has \
             ALREADY booked this leg's two irreversible consequences (deposit_counter \
             bumped so the next same-amount deposit cannot collide on a historical \
             commitment, and the tx marked credited), so do NOT hand-repair them; the \
             deposit stream is NOT stalled."
        ),
        note_commitment: cm,
        spend_key: wallet.spend_key,
    })?;
    Ok(())
}

/// Which leg of the TWO-LEG `fund_insurance_backed` failed. Same shape and reason as
/// `FundAmountError`: the arms leave the engine in DIFFERENT states, and the bootstrap
/// driver persists a record whose truth depends on WHICH leg failed — a `String` cannot
/// be matched on, and matching on message text would couple the record to prose.
#[cfg(test)]
enum FundInsuranceError {
    /// Leg 1 (`op_deposit`) refused the credit — all-or-nothing, the engine state is
    /// byte-for-byte unchanged (SEC-026 failure atomicity). NO note was minted, so the
    /// driver must NOT record `Bootstrap::DepositApplied` on this arm.
    DepositRefused(String),
    /// Leg 2 (`FundInsurance`) failed AFTER the operator note was minted: the value is
    /// a live unspent note and only the SECOND leg may be resumed. Carries the minted
    /// note's commitment and spend key — the SAME values leg 2 was applied with — so
    /// the driver's `Bootstrap::DepositApplied` record is written from the one
    /// derivation that fed the engine, never a recompute that could drift from it.
    TransferFailed {
        msg: String,
        note_commitment: [u8; 32],
        spend_key: [u8; 32],
    },
}

/// Which phase of the TWO-PHASE `fund_amount` failed. The arms leave the engine
/// in DIFFERENT states, so a caller with an operator-facing contract
/// (`account_confirm_deposit`) must not describe both with one message: a
/// `CreditRefused` mutated nothing, while a `FundPositionFailed` comes AFTER the
/// deposit credit landed (`consumed_deposit_count` advanced, note minted).
enum FundAmountError {
    /// Phase 1 (`op_deposit`) refused the credit — all-or-nothing, the engine
    /// state is byte-for-byte unchanged (SEC-026 failure atomicity), so the
    /// same op may be re-applied.
    CreditRefused(String),
    /// Phase 2 (`op_fund_position`) failed AFTER the note was minted and the
    /// deposit credited: `consumed_deposit_count` HAS advanced, and the value
    /// sits as an unspent note owned by the wallet (recoverable, not
    /// collateral). Re-applying the whole two-phase op is NOT possible.
    FundPositionFailed(String),
}

impl std::fmt::Display for FundAmountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreditRefused(m) | Self::FundPositionFailed(m) => f.write_str(m),
        }
    }
}

/// Deposit a quote-scaled `amount` as a note, archive it, and fund the position. The
/// note is committed under its own `note_blind`; the L1-leaf fields (`from`, `deposit_id`,
/// `deposit_blind`) are folded into `consumed_deposit_tip` so a REAL deposit reproduces
/// the vault's on-chain `depositChainTip` for `(from, ownerCommit, amount, id)`.
///
/// FALLIBLE (SEC-026): commitment uniqueness is now HISTORICAL — a
/// `(owner, asset, amount, note_blind)` tuple whose commitment was EVER minted
/// before (even if long since spent) is refused by the engine with
/// `DuplicateCommitment`. Callers must either construct a blind that provably
/// never repeats within the state's history, or surface the `Err` cleanly —
/// never `.expect()` this on a path a user or the world tick can reach.
///
/// BLIND-DERIVATION WARNING: the demo paths derive their blinds from the tree's
/// LEAF COUNT (`0x80`/`0xC0` ‖ `tree.len()`). That satisfies never-repeats, but
/// it is DEMO-ONLY because the leaf count is PUBLIC: `blinding` is the note's
/// hiding factor, and a blind derived from a readable tree index lets anyone
/// reading the tree brute-force the note's amount with a single candidate per
/// leaf. Harmless for the demo (those routes are omitted in production) — never
/// copy it onto a `/v1` money path; use a secret or per-account-counter blind
/// there (`0xA0`/`0xB0` ‖ `deposit_counter`, `0xE1` ‖ `lp_counter`).
#[allow(clippy::too_many_arguments)] // a flat funding spec; a params struct adds only ceremony
fn fund_amount(
    seq: &mut Sequencer,
    archive: &mut NoteArchive,
    w: &Wallet,
    market: u64,
    amount: i128,
    note_blind: Digest,
    from: [u8; 20],
    deposit_id: u64,
    deposit_blind: Digest,
) -> Result<(), FundAmountError> {
    let note = Note::new(w.owner, 0, amount, note_blind);
    let cm = note.commitment::<Keccak256>();
    seq.apply(&BatchOp::Deposit {
        owner: w.owner,
        asset_id: 0,
        amount,
        blinding: note_blind,
        from,
        deposit_id,
        deposit_blind,
    })
    .map_err(|e| {
        FundAmountError::CreditRefused(format!(
            "deposit credit refused by the engine: {e:?} (a DuplicateCommitment means this \
             exact (owner, amount, note_blind) note was minted before — SEC-026 historical \
             uniqueness — and crediting requires a FRESH note blind; the note blind is \
             independent of any L1 deposit_blind, so the same L1 leaf remains creditable)"
        ))
    })?;
    // Seal to the owner's X25519 viewing PUBLIC key (real note encryption); the
    // recorder needs no decryption capability. OsRng: fresh ephemeral + nonce.
    archive.record(
        seq.current_batch_id(),
        &note,
        &w.view_x25519_public(),
        rand::rngs::OsRng,
    );
    // Infallible-by-construction in practice (the note `cm` was minted just above for
    // `w.owner` and is spent with `w.spend_key`; callers pass a registered market), but
    // surfaced as an `Err` rather than a panic: if it ever fails, the deposited value
    // sits as an unspent note owned by `w` — recoverable, and worth an honest message.
    seq.apply(&BatchOp::FundPosition {
        owner: w.owner,
        market_id: market,
        note_commitment: cm,
        spend_key: w.spend_key,
    })
    .map_err(|e| {
        FundAmountError::FundPositionFailed(format!(
            "fund-position failed AFTER the note was minted: {e:?} — the deposited value \
             now sits as an unspent note for this owner (not lost, not yet collateral)"
        ))
    })
}

// ── HTTP/WS plumbing ─────────────────────────────────────────────────────────
type Shared = Arc<App>;

/// Acknowledgement after a complete sealed snapshot write, rename, and directory sync.
type SnapshotAck = tokio::sync::oneshot::Sender<bool>;

/// Wait for a durable snapshot. The deadline includes queue backpressure AND the
/// writer's acknowledgement. Never call while holding `App.gw`.
/// A timeout is an unknown write outcome, never permission to release a signature.
async fn snapshot_now(req: &Option<tokio::sync::mpsc::Sender<SnapshotAck>>) -> Result<(), String> {
    let Some(tx) = req else {
        return Err("state persistence is not configured — cannot guarantee durability".into());
    };
    let request = async {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        tx.send(ack_tx)
            .await
            .map_err(|_| "snapshot writer is gone".to_string())?;
        match ack_rx.await {
            Ok(true) => Ok(()),
            Ok(false) => Err("snapshot write failed".to_string()),
            Err(_) => Err("snapshot writer dropped the request".to_string()),
        }
    };
    tokio::time::timeout(Duration::from_secs(SNAPSHOT_ACK_TIMEOUT_SECS), request)
        .await
        .map_err(|_| format!("snapshot request timed out after {SNAPSHOT_ACK_TIMEOUT_SECS}s (queue or writer stalled)"))?
}

/// Stop state mutations before the final capture and keep them stopped through
/// process exit. The returned guard is deliberately retained by the signal task;
/// releasing it after a successful save would permit an acknowledged API mutation
/// or a new seal to slip into the save-to-exit gap.
async fn final_snapshot<'a>(
    app: &'a Shared,
    path: &std::path::Path,
    seed: [u8; 32],
    serial: Arc<Mutex<()>>,
) -> (tokio::sync::MutexGuard<'a, Gw>, bool) {
    let serial = serial.lock_owned().await;
    let frozen = app.gw.lock().await;
    let plain = frozen.snapshot_plain();
    let path = path.to_owned();
    let saved = tokio::task::spawn_blocking(move || {
        // Cancellation must not release serialization while the filesystem worker
        // continues using the shared atomic-write temporary path.
        let _serial = serial;
        let sealed = snapshot::seal(&plain, &seed);
        snapshot::write_atomic(&path, &sealed)
    })
    .await;
    let ok = matches!(saved, Ok(Ok(())));
    if ok {
        frozen
            .ops_alerts
            .recover(ops_alerts::AlertKind::PersistenceFailed);
    } else {
        frozen
            .ops_alerts
            .activate(ops_alerts::AlertKind::PersistenceFailed);
        eprintln!("[state] final snapshot failed: {saved:?}");
    }
    (frozen, ok)
}

/// All runtime snapshot callers share `serial`. Acquire it BEFORE capturing state,
/// otherwise an older capture could overwrite a newer acknowledged snapshot.
/// Move the owned guard into the blocking worker: cancelling the async caller must
/// not unlock it while an uncancellable filesystem operation is still running.
async fn write_snapshot(
    app: &Shared,
    path: &std::path::Path,
    seed: [u8; 32],
    serial: Arc<Mutex<()>>,
) -> bool {
    let guard = serial.lock_owned().await;
    let (plain, alerts) = {
        let gw = app.gw.lock().await;
        (gw.snapshot_plain(), gw.ops_alerts.clone())
    };
    let path = path.to_path_buf();
    let writer_alerts = alerts.clone();
    match tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let sealed = snapshot::seal(&plain, &seed);
        let result = snapshot::write_atomic(&path, &sealed);
        // Publish the episode transition before releasing the same serialization
        // guard as the write. A delayed successful caller must not clear an alert
        // emitted by a later failed writer.
        if result.is_ok() {
            writer_alerts.recover(ops_alerts::AlertKind::PersistenceFailed);
        } else {
            writer_alerts.activate(ops_alerts::AlertKind::PersistenceFailed);
        }
        result
    })
    .await
    {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            eprintln!("[state] snapshot write failed: {e}");
            false
        }
        Err(e) => {
            alerts.activate(ops_alerts::AlertKind::PersistenceFailed);
            eprintln!("[state] snapshot worker failed: {e}");
            false
        }
    }
}

struct App {
    clock_admission: Arc<clock_admission::ClockAdmission>,
    deposit_source: Option<Arc<dyn deposit_rpc::DepositSource>>,
    deposit_serial: Mutex<()>,
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
    /// SEC-025-A: acknowledged-snapshot requests, served by the single periodic writer.
    /// `None` when persistence is off. Read by the two `snapshot_now` durability
    /// barriers (Task 5): the bootstrap endpoint's post-success barrier and the settle
    /// loop's pre-submit barrier for the window carrying the bootstrap's second leg.
    /// See `snapshot_now` for the fail-closed and lock contracts.
    snapshot_req: Option<tokio::sync::mpsc::Sender<SnapshotAck>>,
    /// SEC-019 (Task 7b): the gateway deposit-authorization signer. Its ADDRESS is what
    /// the deployed `CollateralVault.gatewaySigner` must equal; `POST /v1/accounts/
    /// deposit/authorize` signs `keccak256(chainid ‖ vault ‖ from ‖ ownerCommit ‖ amount)`
    /// with it so a user may enter a deposit (a liveness gate on entry, not a mint key).
    gateway_signer: GatewaySigner,
    /// Slice 3b-2a: the settle path's prover client (None ⇒ legacy cumulative+mock path).
    prover: Option<std::sync::Arc<dyn prover_client::ProverClient>>,
    /// REAL per-market price history (the chart's past bars): the engine's own
    /// marks folded into per-timeframe OHLC rings each tick, plus a one-shot
    /// exchange backfill for feed-backed markets at boot. Display data — not
    /// part of the sealed snapshot (see `candles.rs`).
    candles: Mutex<candles::CandleStore>,
    /// SEC-020 Task 4: the Azure TDX attestor whose self-quote `GET /attest`
    /// serves (pinned collateral + the §5c `ATTESTATION_DIR` capture). `None`
    /// (no bundle configured) ⇒ /attest answers 503 — never a fabricated quote.
    attestor: Option<AzureTdxAttestor>,
    /// SEC-020 Phase-2 (C3): this gateway's per-boot ephemeral x25519 DH
    /// SECRET. It never leaves the process and is never logged/served — it
    /// exists so the session secret requires a private key, not just the public
    /// /attest transcript. The boot handshake consumes it before the App is
    /// built, and the 401 re-handshake (C4) REUSES it via a clone captured in
    /// the re-handshake closure at boot (so the gateway re-derives against the
    /// same `/attest`-advertised `gw_pub` a rebooted prover uses). The closure
    /// captures its own clone before the App exists, so this FIELD still has no
    /// in-App reader — hence `#[allow(dead_code)]` (retained so the private
    /// half of the `/attest`-served `gw_pub` lives exactly as long as the
    /// process advertising it).
    #[allow(dead_code)]
    gw_eph_secret: StaticSecret,
    /// SEC-020 Phase-2 (C3): the matching PUBLIC half — served in `/attest`
    /// (and bound as the self-quote challenge on a live CVM) so the prover
    /// derives the shared transcript. Freshness = this single-use key; no
    /// fetcher-supplied nonce exists anymore.
    gw_pub: [u8; 32],
    /// SEC-020 Task 4/5: the session token minted by the settle-path-init mutual-
    /// attestation handshake with the prover. `None` ⇒ the handshake refused or
    /// failed (fail-closed) and no proof request may be authorized. Task 5 injects
    /// the live copy into the `HttpProverClient` (which sends it as
    /// `Authorization: Bearer` on `/prove`); this field is retained for boot
    /// observability — hence still `#[allow(dead_code)]` (no in-App reader).
    #[allow(dead_code)]
    prover_session_token: Option<String>,
    /// FIN-001 Task 4: an operator-set one-shot flag. `POST /v1/admin/settlement/resume`
    /// (gated by `FIN_ADMIN_KEY`) sets it; the settle loop `swap`s it to `false` at the top of
    /// each tick and, when it was set, resets its backoff deadline to now so a fixed prover is
    /// retried immediately instead of waiting out the HELD backoff. Setting it NEVER fakes
    /// health — health clears only when a real settle succeeds.
    force_settle: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl App {
    fn snapshot(&self, gw: &Gw) -> WState {
        let mut state = gw.snapshot();
        state.clock_admission = Some(self.clock_admission.status());
        state
    }
    async fn broadcast(&self, gw: &Gw) {
        let msg = WsMsg::State {
            state: self.snapshot(gw),
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
    /// its "0x<64 hex>" string — see `eip191_prehash_candidates`.
    signature: String,
    /// SEC-021b: REBIND ONLY. When the account already has a bound address, this
    /// must additionally carry that CURRENT address's signature over
    /// `rebind_auth_digest(chain_id, vault, owner, rebind_counter, old_addr, new_addr)`
    /// — see that function's doc for the exact 133-byte preimage. `rebind_counter`
    /// is the account's rebind generation: 0 at account creation, untouched by the
    /// first-time bind and by REJECTED attempts, +1 on every ACCEPTED rebind. Read
    /// the current value as `rebindCounter` from `GET /v1/accounts/me` (`v1_account`).
    /// Absent/ignored on a first-time bind. Without this signature, a leaked API key
    /// alone could redirect the binding — and therefore every future withdrawal — to
    /// an attacker's address.
    #[serde(rename = "currentSignature", default)]
    current_signature: Option<String>,
}
#[derive(Deserialize)]
struct RecoveryReq {
    owner: String,
    nonce: u64,
    signature: String,
}
#[derive(Deserialize)]
struct OnchainDepositReq {
    #[serde(rename = "txHash")]
    tx_hash: String,
    #[serde(rename = "marketId")]
    market_id: u64,
}
/// SEC-019 (Task 7b): request to authorize a deposit — the gateway generates the blind,
/// records `(ownerCommit → blind)`, and returns `(ownerCommit, sig)` for the user to
/// submit as `deposit(amount, ownerCommit, sig)` on L1.
#[derive(Deserialize)]
struct DepositAuthorizeReq {
    #[serde(rename = "marketId")]
    market_id: u64,
    purpose: deposit_ingestion::Purpose,
    /// The L1 address the deposit will be sent `from` (must equal the account's bound
    /// deposit address). Also the `msg.sender` the on-chain digest binds.
    from: String,
    /// USDC base units to be deposited — bound into the signed digest (a sig for one
    /// amount cannot authorize another).
    amount: String,
}
#[derive(Deserialize)]
struct WithdrawReq {
    #[serde(rename = "marketId")]
    market_id: u64,
    amount: String,
    to: String,
    /// SEC-021: strictly-increasing withdrawal-authorization nonce (replay
    /// protection). Required for every account.
    #[serde(default)]
    nonce: Option<u64>,
    /// SEC-021: 65-byte secp256k1 signature (r‖s‖v) over `withdraw_auth_digest`,
    /// recovering to the account's authorizing address (registered `signer`, else
    /// the bound deposit address). Required for every account; accepted over any of
    /// the three shapes in `eip191_prehash_candidates`.
    #[serde(default)]
    signature: Option<String>,
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

/// Recover the 20-byte Ethereum address that signed `prehash` with `sig` (r‖s‖v).
/// NOTE: this is deliberately more permissive than the Solidity side on `v` — it
/// accepts 0..3 as well as 27..30, whereas `CollateralVault`/`DarkPerpSettlement`
/// accept only 27/28. That is safe for gateway-local authorization (these signatures
/// never reach a contract), but it is NOT byte-identical to on-chain `ecrecover`.
/// High-`s` (malleable) signatures are rejected inside k256's recovery primitive
/// (`recover_from_prehash` ends by re-verifying, and secp256k1's `verify_prehashed`
/// refuses a high-`s` signature).
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

/// SEC-021: the dev/demo fallback deployment identity — Base Sepolia's chain id and an
/// all-zero vault address. Single source of truth for the THREE consumers that must
/// agree: `GatewaySigner::from_env`'s unset-var fallbacks, `Gw::boot`'s initial fields,
/// and the serde-restore defaults (`dev_fallback_chain_id`/`dev_fallback_vault`) — so a
/// fresh boot, a restored snapshot, and the signer-derived identity can never silently
/// diverge. Production never runs on these: `vault_binding_ok_for_mode` refuses a prod
/// boot whose vault is still the zero fallback.
const DEV_FALLBACK_CHAIN_ID: u64 = 84532;
const DEV_FALLBACK_VAULT: [u8; 20] = [0u8; 20];

/// SEC-021 (final-review M-e): the parse decision for `L1_CHAIN_ID` — UNSET takes the
/// dev fallback; SET-but-unparseable fails closed, mirroring `GATEWAY_SIGNER_KEY` in
/// `from_env` below. Decimal only: the hex form (`0x14a34`) previously fell through the
/// silent `.ok()` fallback and became 84532, which is exactly the silent-divergence this
/// refuses. Takes the raw `Option<String>` (not the env directly) so the decision is
/// unit-testable without process-global env mutation.
fn parse_l1_chain_id(raw: Option<String>) -> Result<u64, String> {
    match raw {
        Some(s) => s.trim().parse::<u64>().map_err(|_| {
            format!(
                "L1_CHAIN_ID is set but is not a decimal u64 chain id (got {s:?}; \
                 hex like 0x14a34 is not accepted — use 84532)"
            )
        }),
        None => Ok(DEV_FALLBACK_CHAIN_ID),
    }
}

/// SEC-021 (final-review M-e): the parse decision for `L1_VAULT` — same convention as
/// `parse_l1_chain_id`. A SET-but-malformed vault previously became the zero address
/// silently, and `vault_binding_ok_for_mode`'s refusal then claimed "`L1_VAULT` must be
/// set" to an operator whose var WAS set, just malformed. Now that state errs here with
/// the actual problem named.
fn parse_l1_vault(raw: Option<String>) -> Result<[u8; 20], String> {
    match raw {
        Some(s) => parse_addr20_hex(&s).ok_or_else(|| {
            format!("L1_VAULT is set but is not a 20-byte 0x hex address (got {s:?})")
        }),
        None => Ok(DEV_FALLBACK_VAULT),
    }
}

/// SEC-019 (Task 7b) demo/test default for the gateway deposit-authorization key. NEVER
/// use it on a real deployment — the deployed `CollateralVault.gatewaySigner` must be the
/// ADDRESS of a SECRET production key set via `GATEWAY_SIGNER_KEY`. This fixed scalar only
/// exists so the demo build + unit tests have a working signer (Anvil account #0's key).
const DEMO_GATEWAY_SIGNER_KEY: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];

/// SEC-019 (Task 7b): the gateway's deposit-authorization signer. Holds the secret
/// `gatewaySigner` key whose ADDRESS the deployed `CollateralVault` pins, plus the chain
/// id + vault address needed to reproduce the contract's digest BYTE-IDENTICALLY. It signs
/// `keccak256(abi.encodePacked(chainid, vault, from, ownerCommit, amount))` so a user may
/// ENTER a deposit; the signature only gates entry (every deposit still performs a real
/// `transferFrom` and settlement still pins `depositsRoot`), so it is a liveness gate, NOT
/// a mint authority (spec §1b). A compromised signer can authorize deposits but cannot
/// conjure collateral.
struct GatewaySigner {
    key: k256::ecdsa::SigningKey,
    chain_id: u64,
    vault: [u8; 20],
}

impl GatewaySigner {
    /// Build from a raw 32-byte secp256k1 scalar + the chain id and vault address the
    /// contract's digest is bound to. Errors if the scalar is not a valid signing key.
    fn from_parts(key: [u8; 32], chain_id: u64, vault: [u8; 20]) -> Result<Self, String> {
        let key = k256::ecdsa::SigningKey::from_slice(&key)
            .map_err(|e| format!("GATEWAY_SIGNER_KEY is not a valid secp256k1 scalar: {e}"))?;
        Ok(Self {
            key,
            chain_id,
            vault,
        })
    }

    /// Load from env: `GATEWAY_SIGNER_KEY` (32-byte hex scalar), `L1_CHAIN_ID`, `L1_VAULT`.
    /// Falls back to the demo key / a dev chain id (Base Sepolia) / a zero vault when a var
    /// is unset — fine for the demo build and unit tests (live-key provisioning + the real
    /// vault/chain wiring are the deferred deploy phase). All three vars share one
    /// convention: a SET-but-malformed value fails closed (the caller exits) rather than
    /// silently taking its fallback — the key because silently signing with the demo key
    /// would be a catastrophe, and the deployment identity (final-review M-e) because a
    /// typo'd `L1_CHAIN_ID`/`L1_VAULT` would otherwise silently bind every SEC-021 digest
    /// to the dev identity, and `vault_binding_ok_for_mode`'s "`L1_VAULT` must be set"
    /// refusal would gaslight an operator whose var IS set, just malformed.
    fn from_env() -> Result<Self, String> {
        let key = match std::env::var("GATEWAY_SIGNER_KEY") {
            Ok(s) => {
                parse_hex32(&s).ok_or("GATEWAY_SIGNER_KEY is set but is not a 32-byte hex value")?
            }
            Err(_) => DEMO_GATEWAY_SIGNER_KEY,
        };
        let chain_id = parse_l1_chain_id(std::env::var("L1_CHAIN_ID").ok())?;
        let vault = parse_l1_vault(std::env::var("L1_VAULT").ok())?;
        Self::from_parts(key, chain_id, vault)
    }

    /// The 20-byte Ethereum address of this signer — the value the deployed
    /// `CollateralVault.gatewaySigner` must equal for the on-chain gate to accept our sigs.
    fn address(&self) -> [u8; 20] {
        use sha3::{Digest as _, Keccak256 as RawKeccak};
        let point = self.key.verifying_key().to_encoded_point(false);
        let hash = RawKeccak::digest(&point.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&hash[12..]);
        a
    }

    /// The digest the contract recomputes and `ecrecover`s in `deposit(...)`:
    /// `keccak256(abi.encodePacked(uint256 chainid, address vault, address from,
    /// bytes32 ownerCommit, uint256 amount))`. Byte-identical to
    /// `CollateralVault.deposit`'s digest (chainid + amount as 32-byte BE words, vault +
    /// from as their 20 address bytes, ownerCommit as its 32 bytes) — verified by the KAT
    /// in `gateway_signature_round_trips_and_matches_solidity_digest`.
    fn digest(&self, from: &[u8; 20], owner_commit: &[u8; 32], amount: u128) -> [u8; 32] {
        use sha3::{Digest as _, Keccak256 as RawKeccak};
        let mut chain = [0u8; 32];
        chain[24..].copy_from_slice(&self.chain_id.to_be_bytes()); // uint256, low 8 bytes
        let mut amt = [0u8; 32];
        amt[16..].copy_from_slice(&amount.to_be_bytes()); // uint256, low 16 bytes (< 2^128)
        let mut h = RawKeccak::new();
        h.update(chain);
        h.update(self.vault);
        h.update(from);
        h.update(owner_commit);
        h.update(amt);
        h.finalize().into()
    }

    /// Sign the deposit-authorization digest, returning a 65-byte `r‖s‖v` signature that
    /// the contract's `ecrecover` accepts: low-`s` (k256 normalizes S) and `v ∈ {27, 28}`
    /// — mirroring `recover_eth_address`'s conventions, inverted. The user submits this as
    /// `deposit(amount, ownerCommit, sig)` on L1.
    fn sign(
        &self,
        from: &[u8; 20],
        owner_commit: &[u8; 32],
        amount: u128,
    ) -> Result<[u8; 65], String> {
        let digest = self.digest(from, owner_commit, amount);
        let (sig, recid) = self
            .key
            .sign_prehash_recoverable(&digest)
            .map_err(|e| format!("gateway sign failed: {e}"))?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + recid.to_byte();
        Ok(out)
    }
}

/// The digest a deposit-address bind signature must cover: `keccak256("dark-perp:
/// bind-deposit:" ‖ owner ‖ addr)`. Binding the account owner stops the proof being
/// replayed to bind the same address to a different account.
///
/// Byte layout (fixed-width fields, no length prefixes, no separators):
/// ```text
/// offset  len  field
///      0   23  "dark-perp:bind-deposit:"  (ASCII, no trailing space)
///     23   32  owner
///     55   20  addr                       (total preimage: 75 bytes)
/// ```
/// Layout frozen by `auth_digests_match_known_answer_vectors`.
fn deposit_bind_digest(owner: &PubKey, addr: &[u8; 20]) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let mut h = RawKeccak::new();
    h.update(b"dark-perp:bind-deposit:");
    h.update(owner);
    h.update(addr);
    h.finalize().into()
}

/// SEC-021: the digest a withdrawal authorization signature must cover.
/// `keccak256("dark-perp:withdraw:" ‖ chain_id ‖ vault ‖ owner ‖ market_id ‖ amount ‖ to ‖ nonce)`
///
/// Every field is fixed-width big-endian (no length prefixes, no separators), so the
/// concatenation is unambiguous by construction — there is no variable-length field
/// that could collide under a different field split:
/// ```text
/// offset  len  field
///      0   19  "dark-perp:withdraw:"  (ASCII, no trailing space)
///     19    8  chain_id   u64 BE
///     27   20  vault
///     47   32  owner
///     79    8  market_id  u64 BE
///     87   16  amount     i128 BE (two's complement)
///    103   20  to
///    123    8  nonce      u64 BE   (total preimage: 131 bytes)
/// ```
/// NOTE for the TypeScript mirror (Task 8): `chain_id` here is EIGHT bytes (u64 BE),
/// NOT the 32-byte word `GatewaySigner::digest` (in this same file) uses for the
/// on-chain deposit digest (Solidity `abi.encodePacked(uint256)`). These digests are
/// verified gateway-side only, so they owe Solidity's ABI nothing — do not conflate
/// the two encodings. Layout frozen by `auth_digests_match_known_answer_vectors`.
///
/// `owner` stops a signature being replayed onto a second account registered to the
/// same address; `chain_id`+`vault` stop it being replayed onto another deployment
/// restored from a copied snapshot.
fn withdraw_auth_digest(
    chain_id: u64,
    vault: &[u8; 20],
    owner: &PubKey,
    market_id: u64,
    amount: i128,
    to: &[u8; 20],
    nonce: u64,
) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let mut h = RawKeccak::new();
    h.update(b"dark-perp:withdraw:");
    h.update(chain_id.to_be_bytes());
    h.update(vault);
    h.update(owner);
    h.update(market_id.to_be_bytes());
    h.update(amount.to_be_bytes());
    h.update(to);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// SEC-021: the digest an LP-withdrawal authorization signature must cover.
/// `keccak256("dark-perp:lp-withdraw:" ‖ chain_id ‖ vault ‖ owner ‖ shares ‖ nonce)`
/// There is no `to`: LP value lands in the account's OWN internal balance, never on L1.
/// The distinct prefix makes a `withdraw` signature unusable here and vice versa.
///
/// Byte layout (all fields fixed-width big-endian, no length prefixes, no separators;
/// `chain_id` is 8 bytes, NOT `GatewaySigner::digest`'s 32-byte Solidity word — see
/// `withdraw_auth_digest`):
/// ```text
/// offset  len  field
///      0   22  "dark-perp:lp-withdraw:"  (ASCII, no trailing space)
///     22    8  chain_id  u64 BE
///     30   20  vault
///     50   32  owner
///     82   16  shares    u128 BE
///     98    8  nonce     u64 BE   (total preimage: 106 bytes)
/// ```
/// Layout frozen by `auth_digests_match_known_answer_vectors`.
fn lp_withdraw_auth_digest(
    chain_id: u64,
    vault: &[u8; 20],
    owner: &PubKey,
    shares: u128,
    nonce: u64,
) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let mut h = RawKeccak::new();
    h.update(b"dark-perp:lp-withdraw:");
    h.update(chain_id.to_be_bytes());
    h.update(vault);
    h.update(owner);
    h.update(shares.to_be_bytes());
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// SEC-021b: the digest the CURRENTLY BOUND address must sign to authorize moving an
/// account's deposit-address binding to `new_addr`.
/// `keccak256("dark-perp:rebind-deposit:" ‖ chain_id ‖ vault ‖ owner ‖ rebind_counter ‖ old ‖ new)`
///
/// Byte layout (all fields fixed-width big-endian, no length prefixes, no separators;
/// `chain_id` is 8 bytes, NOT `GatewaySigner::digest`'s 32-byte Solidity word — see
/// `withdraw_auth_digest`):
/// ```text
/// offset  len  field
///      0   25  "dark-perp:rebind-deposit:"  (ASCII, no trailing space)
///     25    8  chain_id        u64 BE
///     33   20  vault
///     53   32  owner
///     85    8  rebind_counter  u64 BE
///     93   20  old_addr
///    113   20  new_addr        (total preimage: 133 bytes)
/// ```
/// Layout frozen by `auth_digests_match_known_answer_vectors`.
///
/// Binding BOTH addresses (in this order) stops a signature authorizing old→new being
/// reused to authorize old→someone-else, or replayed in reverse. `rebind_counter` —
/// the account's rebind generation, incremented on every ACCEPTED rebind
/// (`Account.rebind_counter`, enforced by `account_set_deposit_address`) — closes
/// the CYCLE replay the address pair alone cannot: without it, a signature over
/// `(chain, vault, owner, A, B)` stays valid ANY time the bound address is `A` again.
/// Bind A → rotate A→B → later rotate B→A, and the ORIGINAL A→B signature replays,
/// forcing the binding back to B. That failure is worst exactly when rebinding matters
/// most — rotating away from a COMPROMISED address, whose old rotation signatures the
/// attacker may hold. With the counter, every accepted rebind bumps the generation, so
/// each signature authorizes at most one specific rotation and then dies.
fn rebind_auth_digest(
    chain_id: u64,
    vault: &[u8; 20],
    owner: &PubKey,
    rebind_counter: u64,
    old_addr: &[u8; 20],
    new_addr: &[u8; 20],
) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let mut h = RawKeccak::new();
    h.update(b"dark-perp:rebind-deposit:");
    h.update(chain_id.to_be_bytes());
    h.update(vault);
    h.update(owner);
    h.update(rebind_counter.to_be_bytes());
    h.update(old_addr);
    h.update(new_addr);
    h.finalize().into()
}

/// The three prehashes a gateway-local authorization signature may cover, in the
/// order they are tried. SECURITY INVARIANT: every candidate is a deterministic
/// transform of the SAME caller-independent digest — no attacker-chosen message
/// ever enters a preimage — so accepting any of them leaves the authorization
/// semantics unchanged: a valid signature still proves the signer consented to
/// exactly the fields that digest binds. Shared by the deposit-address bind
/// (`deposit_bind_digest`) and by withdrawal authorization (`withdraw_auth_digest`,
/// `lp_withdraw_auth_digest`, `rebind_auth_digest`).
fn eip191_prehash_candidates(digest: &[u8; 32]) -> [[u8; 32]; 3] {
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
/// FIN-001 Task 4: the settlement-resume authorization decision.
/// `Disabled` ⇒ no operator key configured (endpoint off, fail-closed 503);
/// `Unauthorized` ⇒ key configured but the presented `X-Admin-Key` is absent or wrong (401);
/// `Ok` ⇒ exact match (200 + force flag). This is a DEDICATED operator gate — it deliberately
/// does NOT reuse `api_key_from`/`X-Api-Key` (that authenticates a registered USER, which would
/// let any user force settlement).
#[derive(Debug, PartialEq, Eq)]
enum AdminAuthz {
    Ok,
    Unauthorized,
    Disabled,
}

/// Constant-time compare of the presented `X-Admin-Key` against the configured `FIN_ADMIN_KEY`.
/// `configured` = env value (None ⇒ endpoint disabled); `presented` = header value.
/// The fold is length-independent and never early-returns on the first mismatching byte, so it
/// leaks neither the key length nor a matching-prefix length through timing.
fn admin_resume_authz(configured: Option<&str>, presented: Option<&str>) -> AdminAuthz {
    let Some(cfg) = configured.filter(|c| !c.is_empty()) else {
        return AdminAuthz::Disabled;
    };
    let Some(got) = presented else {
        return AdminAuthz::Unauthorized;
    };
    let (a, b) = (cfg.as_bytes(), got.as_bytes());
    // Seed the accumulator with the length difference so a shorter/longer presentation can
    // never fold to zero, then OR every positional byte-xor (padding the short side with 0).
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= x ^ y;
    }
    if diff == 0 {
        AdminAuthz::Ok
    } else {
        AdminAuthz::Unauthorized
    }
}

/// Called under Gw's lock so an admin retry cannot race a recovery hold.
fn request_settlement_retry(
    gw: &Gw,
    force: &std::sync::atomic::AtomicBool,
) -> Result<String, &'static str> {
    if gw.settle_health.recovery_required() {
        return Err("settlement outcome is unresolved; reconcile the pending transaction and restart before retrying");
    }
    force.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(gw.settle_health.health().as_str().to_string())
}

async fn hold_settlement_for_recovery(app: &Shared, error: String) {
    let mut gw = app.gw.lock().await;
    gw.settle_health.hold_for_recovery(error);
    gw.settlement_held_since_ms.get_or_insert_with(now_ms);
    gw.ops_alerts
        .activate(ops_alerts::AlertKind::SettlementHeld);
    app.force_settle
        .store(false, std::sync::atomic::Ordering::SeqCst);
}

/// FIN-001 Task 4: `POST /v1/admin/settlement/resume` — an OPERATOR (not user) action that,
/// once the prover is fixed, forces an immediate settle attempt instead of waiting out the
/// HELD backoff. It is gated by the dedicated `FIN_ADMIN_KEY` (0x+64hex) via the `X-Admin-Key`
/// header, compared constant-time. Fail-closed: no key configured ⇒ 503 (disabled, no action);
/// missing/wrong key ⇒ 401 (no action). On an exact match it sets the shared `force_settle`
/// flag ONLY — it must NOT call `on_success` or flip health; the 200 body just REPORTS the
/// current settlement health so the operator sees the real state (which clears only when a
/// real settle succeeds).
async fn post_v1_admin_resume(State(app): State<Shared>, headers: HeaderMap) -> impl IntoResponse {
    let configured = std::env::var("FIN_ADMIN_KEY").ok();
    let presented = headers.get("x-admin-key").and_then(|v| v.to_str().ok());
    match admin_resume_authz(configured.as_deref(), presented) {
        AdminAuthz::Disabled => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "settlement resume disabled — set FIN_ADMIN_KEY" })),
        )
            .into_response(),
        AdminAuthz::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid X-Admin-Key" })),
        )
            .into_response(),
        AdminAuthz::Ok => {
            let result = {
                let gw = app.gw.lock().await;
                request_settlement_retry(&gw, &app.force_settle)
            };
            match result {
                Ok(health) => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "status": "settlement retry forced on next tick",
                        "settlement_health": health
                    })),
                )
                    .into_response(),
                Err(error) => (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"error": error, "settlement_health": "HELD"})),
                )
                    .into_response(),
            }
        }
    }
}

/// A06: explicitly start the one-shot counterparty-free wind-down. This endpoint
/// never fabricates the L1 condition: it requires a successful block-pinned read
/// showing the deployed settlement is already in close-only. The SettleAll op is
/// persisted before 200; the ordinary settle loop then proves it and routes phase 1
/// to `finalSettle` by the proof-derived wind-down phase.
async fn post_v1_admin_wind_down(
    State(app): State<Shared>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let configured = std::env::var("FIN_ADMIN_KEY").ok();
    let presented = headers.get("x-admin-key").and_then(|v| v.to_str().ok());
    match admin_resume_authz(configured.as_deref(), presented) {
        AdminAuthz::Disabled => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error":"wind-down disabled — set FIN_ADMIN_KEY"})),
            )
                .into_response()
        }
        AdminAuthz::Unauthorized => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error":"missing or invalid X-Admin-Key"})),
            )
                .into_response()
        }
        AdminAuthz::Ok => {}
    }
    if app.snapshot_req.is_none() || app.prover.is_none() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"wind-down requires durable snapshots and the proof settlement path"}))).into_response();
    }
    let Some(l1) = app.l1.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error":"L1 bridge is not configured"})),
        )
            .into_response();
    };
    let observed = tokio::task::spawn_blocking(move || wind_down::Observation::read(&l1)).await;
    let observation = match observed {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error":format!("cannot verify L1 close-only: {e}")})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error":format!("L1 close-only reader failed: {e}")})),
            )
                .into_response()
        }
    };
    let block = observation.block;
    {
        let mut gw = app.gw.lock().await;
        if let Err(error) = observation.check_start(&gw) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error":error,"observedBlock":block})),
            )
                .into_response();
        }
        // SettleAll may haircut an unspent note and deterministically reissue the
        // reduced claim. Simulate first, while nothing is mutated, so every such
        // replacement can be encrypted into the owner's recovery archive. If an
        // owner is not registered locally, refuse rather than create an unreachable
        // private claim; A07 supplies the broader account-recovery story.
        let before: std::collections::HashSet<[u8; 32]> =
            gw.seq.state.notes.keys().copied().collect();
        let mut preview = gw.seq.state.clone();
        if let Err(e) = preview.apply_batch(&[BatchOp::SettleAll]) {
            return err400(format!("SettleAll refused: {e:?}")).into_response();
        }
        let replacements: Vec<Note> = preview
            .notes
            .iter()
            .filter(|(cm, _)| !before.contains(*cm))
            .map(|(_, note)| *note)
            .collect();
        let mut archive_targets = Vec::with_capacity(replacements.len());
        for note in &replacements {
            let Some(account) = gw.accounts.values().find(|a| a.wallet.owner == note.owner) else {
                return (StatusCode::CONFLICT, Json(serde_json::json!({"error":"wind-down would reissue a haircut note for an owner not recoverable by this gateway"}))).into_response();
            };
            archive_targets.push((*note, account.wallet.view_x25519_public()));
        }
        let window = gw.seq.current_window_id();
        if let Err(e) = gw.seq.apply(&BatchOp::SettleAll) {
            return err400(format!("SettleAll refused: {e:?}")).into_response();
        }
        gw.wind_down_started = true;
        for (note, view) in archive_targets {
            gw.archive.record(window, &note, &view, rand::rngs::OsRng);
        }
    }
    if let Err(e) = snapshot_now(&app.snapshot_req).await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error":e,"durability":"unknown"})),
        )
            .into_response();
    }
    app.force_settle
        .store(true, std::sync::atomic::Ordering::SeqCst);
    (StatusCode::ACCEPTED, Json(serde_json::json!({"status":"wind-down phase 1 queued for proof/finalSettle","observedBlock":block}))).into_response()
}

/// A01: optional operator receipt/acceleration endpoint. Payer and purpose are
/// fixed by the durable permit, never inferred from this confirm request.
async fn post_v1_admin_insurance_bootstrap(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let configured = std::env::var("FIN_ADMIN_KEY").ok();
    let presented = headers.get("x-admin-key").and_then(|v| v.to_str().ok());
    match admin_resume_authz(configured.as_deref(), presented) {
        AdminAuthz::Disabled => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                serde_json::json!({ "error": "insurance bootstrap disabled — set FIN_ADMIN_KEY" }),
            ),
        )
            .into_response(),
        AdminAuthz::Unauthorized => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing or invalid X-Admin-Key" })),
            )
                .into_response()
        }
        AdminAuthz::Ok => {}
    }
    let Some(operator) = std::env::var("INSURANCE_OPERATOR_ADDRESS")
        .ok()
        .as_deref()
        .and_then(parse_addr20_hex)
    else {
        return err400(
            "INSURANCE_OPERATOR_ADDRESS is not configured (expected 0x + 40 hex)".into(),
        )
        .into_response();
    };
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    if app
        .gw
        .lock()
        .await
        .accounts
        .get(&key)
        .and_then(|a| a.deposit_address)
        != Some(operator)
    {
        return err400("account is not bound to INSURANCE_OPERATOR_ADDRESS".into()).into_response();
    }
    let Some(tx) = body.get("txHash").and_then(|v| v.as_str()) else {
        return err400("missing txHash".into()).into_response();
    };
    let Some(market) = body.get("marketId").and_then(|v| v.as_u64()) else {
        return err400("missing marketId".into()).into_response();
    };
    deposit_ingestion::confirm(
        &app,
        &headers,
        tx,
        market,
        deposit_ingestion::Purpose::InsuranceBootstrap,
    )
    .await
}

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
    let (key, owner, chain_id, vault) = {
        let mut gw = app.gw.lock().await;
        let (key, owner) = gw.register_account(signer);
        (key, owner, gw.chain_id, gw.vault)
    };
    account_recovery::recovery_response(
        StatusCode::OK,
        serde_json::json!({
            "apiKey": hex0x(&key), "owner": hex0x(&owner),
            "callerSigned": signer.is_some(), "recoveryNonce": 0,
            "chainId": chain_id, "vault": hex0x(&vault),
        }),
    )
}

async fn get_v1_recovery(
    State(app): State<Shared>,
    Path(owner): Path<String>,
) -> impl IntoResponse {
    let Some(owner) = parse_hex32(&owner) else {
        return err400("bad owner (expected 32-byte 0x hex)".into()).into_response();
    };
    match app.gw.lock().await.recovery_view(&owner) {
        Some(v) => account_recovery::recovery_response(StatusCode::OK, v),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"unknown or unrecoverable account"})),
        )
            .into_response(),
    }
}
async fn post_v1_recovery(
    State(app): State<Shared>,
    Json(req): Json<RecoveryReq>,
) -> impl IntoResponse {
    account_recovery::post(app, req).await
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
    let current_sig = match req.current_signature.as_deref() {
        Some(s) => match parse_hex65(s) {
            Some(v) => Some(v),
            None => {
                return err400("bad `currentSignature` (expected 65-byte 0x hex r‖s‖v)".into())
                    .into_response()
            }
        },
        None => None,
    };
    match app
        .gw
        .lock()
        .await
        .account_set_deposit_address(&key, addr, &sig, current_sig.as_ref())
    {
        Ok(()) => Json(serde_json::json!({ "depositAddress": hex0x(&addr) })).into_response(),
        Err(e) => err400(e).into_response(),
    }
}

/// Optional owned receipt from the shared finalized ingester. This endpoint
/// cannot choose routing, bypass L1 ordering, or consume a deposit a second time.
async fn post_v1_deposit_onchain(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<OnchainDepositReq>,
) -> impl IntoResponse {
    deposit_ingestion::confirm(
        &app,
        &headers,
        &req.tx_hash,
        req.market_id,
        deposit_ingestion::Purpose::Collateral,
    )
    .await
}

/// SEC-019 (Task 7b): authorize an L1 deposit. Records a fresh per-deposit blind under
/// `ownerCommit = keccak(owner ‖ blind)` and returns `{ ownerCommit, sig }` where `sig`
/// is the gateway's ECDSA signature over `keccak256(chainid ‖ vault ‖ from ‖ ownerCommit
/// ‖ amount)`. The user submits `deposit(amount, ownerCommit, sig)` on L1; without this
/// signature the vault refuses the deposit (so every on-chain leaf is creditable by
/// construction — spec §1b). The SECRET blind is never returned, only `ownerCommit`.
async fn post_v1_deposit_authorize(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<DepositAuthorizeReq>,
) -> impl IntoResponse {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let from = match parse_addr20_hex(&req.from) {
        Some(a) => a,
        None => return err400("bad `from` address (expected 0x + 40 hex)".into()).into_response(),
    };
    let amount: u128 = match req.amount.parse() {
        Ok(v) => v,
        Err(_) => {
            return err400("bad amount (expected a u128 of USDC base units)".into()).into_response()
        }
    };
    if let Err(e) = deposit_ingestion::authorize_purpose(&headers, req.purpose, from) {
        return err400(e).into_response();
    }
    if app.snapshot_req.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "state persistence is not configured; deposit authorization unavailable"
            })),
        )
            .into_response();
    }
    // Release the account lock before requesting durability. No signature may be
    // constructed or returned until the writer acknowledges the stored blind.
    let commit = {
        match app.gw.lock().await.authorize_routed_deposit(
            &key,
            from,
            amount,
            req.market_id,
            req.purpose,
        ) {
            Ok(c) => c,
            Err(e) => return err400(e).into_response(),
        }
    };
    if let Err(e) = snapshot_now(&app.snapshot_req).await {
        // No signature was released, so this specific permit cannot have reached
        // L1. Remove it to avoid exhausting capacity after repeated disk failures.
        let mut gw = app.gw.lock().await;
        gw.deposits.routes.remove(&commit);
        if let Some(a) = gw.accounts.get_mut(&key) {
            a.deposit_authorizations.remove(&commit);
        }
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("deposit authorization not issued: {e}")
            })),
        )
            .into_response();
    }
    match app.gateway_signer.sign(&from, &commit, amount) {
        Ok(sig) => Json(serde_json::json!({
            "ownerCommit": hex0x(&commit),
            "sig": hex0x(&sig),
            "marketId": req.market_id,
            "purpose": req.purpose,
        }))
        .into_response(),
        Err(e) => err400(format!("gateway sign failed: {e}")).into_response(),
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
    // SEC-021: every withdrawal must carry its authorization nonce + signature —
    // the engine method verifies them; the handler only refuses absent/unparseable
    // fields early with a clear message.
    let nonce = match req.nonce {
        Some(n) => n,
        None => return err400("`nonce` is required".into()).into_response(),
    };
    let sig = match req.signature.as_deref().and_then(parse_hex65) {
        Some(s) => s,
        None => {
            return err400("`signature` is required (65-byte 0x hex r‖s‖v)".into()).into_response()
        }
    };
    // Avoid RPC work for ordinary withdrawals; recheck the mode under the
    // mutation lock below so a concurrent circuit breaker fails closed.
    let needs_wind_down = {
        let gw = app.gw.lock().await;
        if !gw.accounts.contains_key(&key) {
            return err400("Unknown account.".into()).into_response();
        }
        gw.seq.state.mode == Mode::CloseOnly
    };
    let observation = if needs_wind_down {
        let Some(l1) = app.l1.clone() else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error":"wind-down requires L1 phase-1 verification"})),
            )
                .into_response();
        };
        match tokio::task::spawn_blocking(move || wind_down::Observation::read(&l1)).await {
            Ok(Ok(value)) => Some(value),
            _ => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"error":"cannot verify L1 wind-down phase"})),
                )
                    .into_response()
            }
        }
    } else {
        None
    };
    let r = {
        app.gw.lock().await.account_withdraw_observed(
            &key,
            req.market_id,
            amount,
            to,
            (nonce, &sig),
            observation.as_ref(),
        )
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
    // SEC-021: every LP withdrawal must carry its authorization nonce + signature —
    // the engine method verifies them; the handler only refuses absent/unparseable
    // fields early with a clear message.
    let nonce = match req.nonce {
        Some(n) => n,
        None => return err400("`nonce` is required".into()).into_response(),
    };
    let sig = match req.signature.as_deref().and_then(parse_hex65) {
        Some(s) => s,
        None => {
            return err400("`signature` is required (65-byte 0x hex r‖s‖v)".into()).into_response()
        }
    };
    let r = {
        app.gw
            .lock()
            .await
            .account_lp_withdraw(&key, shares, nonce, &sig)
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
    let r = {
        let mut gw = app.gw.lock().await;
        gw.account_place_order(&key, &req)
            .map(|receipt| gw.receipt_json(&receipt))
    };
    match r {
        Ok(receipt) => Json(receipt).into_response(),
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
    let r = {
        let mut gw = app.gw.lock().await;
        // Refuse BEFORE mutation when a production deployment cannot durably
        // acknowledge cancellation. Otherwise a restart could revive the quote.
        if gw.prod && app.snapshot_req.is_none() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "Cancellation unavailable: state persistence is not configured." })),
            )
                .into_response();
        }
        gw.account_cancel(&key, &order_id)
    };
    match r {
        Ok(cancelled) => {
            // The state lock is released before waiting for the snapshot writer.
            // A timeout is an UNKNOWN durable outcome, never successful cancellation.
            if app.snapshot_req.is_some() {
                if let Err(e) = snapshot_now(&app.snapshot_req).await {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(serde_json::json!({
                            "error": format!("Cancellation durability unconfirmed: {e}. The in-memory remainder was removed, but a CANCELLED row alone does not confirm durable cancellation. Retry cancellation before replacing it."),
                            "orderId": order_id,
                            "durability": "unknown",
                        })),
                    )
                .into_response();
                }
            }
            if let Some(owner) = app.gw.lock().await.owner_hex_for(&key) {
                let _ = app.events_tx.send(
                    serde_json::json!({
                        "owner": owner, "type": "execution", "orderId": order_id,
                        "status": "CANCELLED"
                    })
                    .to_string(),
                );
            }
            Json(serde_json::json!({
                "orderId": order_id,
                "cancelled": true,
                "cancelledSize": cancelled.to_string(),
            }))
            .into_response()
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
    let mut status = app.gw.lock().await.v1_status_json();
    status["clockAdmission"] = serde_json::to_value(app.clock_admission.status()).unwrap();
    Json(status)
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
///
/// Takes the production posture because the document must match the MOUNTED
/// surface: `/v1/lp*` is not mounted in production (SEC-025-C Task 3), so the
/// production document must OMIT those three paths rather than advertise routes
/// that 404. Split from the axum handler so the gating is testable without an
/// HTTP stack (`openapi_advertises_lp_only_in_demo`).
fn v1_openapi_json(prod: bool) -> serde_json::Value {
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
    let mut spec = serde_json::json!({
        "openapi": "3.1.0",
        "info": { "title": "dark-perp external API", "version": "1", "description": "Multi-tenant trading over the sequencer engine. Amounts are decimal strings of scaled integers (quote *1e6, size/price *1e8). See docs/API.md." },
        "components": { "securitySchemes": { "ApiKey": { "type": "apiKey", "in": "header", "name": "X-Api-Key" } } },
        "paths": {
            "/v1/accounts": { "post": { "summary": "Register an account (optional { signer } for caller-signed)", "responses": ok("apiKey + owner + callerSigned") } },
            "/v1/accounts/me": { "get": { "summary": "Own account (balance, positions, nextNonce; SEC-021 withdrawal-auth state: depositAddress, callerSigned, nextWithdrawNonce, rebindCounter, chainId, vault — read these from here, never hardcode)", "responses": ok("account"), "security": auth["security"] } },
            "/v1/accounts/deposit": { "post": { "summary": "Deposit collateral (demo/in-memory credit)", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["marketId","amount"], "properties": { "marketId": { "type": "integer" }, "amount": { "type": "string" } } } } } },
                "responses": ok("updated account") } },
            "/v1/accounts/deposit/address": { "post": { "summary": "Bind the external EOA you fund USDC from (ownership-proven; a REBIND additionally requires currentSignature)", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["address","signature"], "properties": { "address": { "type": "string" }, "signature": { "type": "string", "description": "secp256k1 sig recovering to address over the bind digest keccak256(\"dark-perp:bind-deposit:\"‖owner‖address) — raw, or EIP-191 personal_sign over its 32 bytes or its 0x-hex string" },
                    "currentSignature": { "type": "string", "description": "REBIND ONLY (SEC-021b): the CURRENTLY bound address's sig over the rebind digest keccak256(\"dark-perp:rebind-deposit:\"‖chainId(u64 BE)‖vault‖owner‖rebindCounter(u64 BE)‖oldAddr‖newAddr) — rebindCounter from GET /v1/accounts/me; same three accepted shapes as `signature`. Absent/ignored on a first-time bind; without it a rebind is refused. There is NO operator or timelock override: losing the bound key permanently freezes the binding" } } } } } },
                "responses": ok("bound address") } },
            "/v1/accounts/deposit/authorize": { "post": { "summary": "Authorize an L1 deposit (SEC-019): get ownerCommit + gateway sig for deposit(amount, ownerCommit, sig)", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["from","amount","marketId","purpose"], "properties": { "marketId": { "type": "integer", "minimum": 0 }, "purpose": { "type": "string", "enum": ["collateral","insuranceBootstrap"], "description": "Immutable routing; insurance also requires admin authorization and the bound operator payer" }, "from": { "type": "string", "description": "the L1 address the deposit is sent from (your bound deposit address)" }, "amount": { "type": "string", "description": "USDC base units to deposit" } } } } } },
                "responses": ok("ownerCommit + sig") } },
            "/v1/accounts/deposit/onchain": { "post": { "summary": "Optional finalized ingestion accelerator and durable receipt; cannot change routing", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["txHash","marketId"], "properties": { "txHash": { "type": "string" }, "marketId": { "type": "integer" } } } } } },
                "responses": { "200": { "description": "Owned durable credit receipt" }, "202": { "description": "pendingFinalizedIngestion; do not send funds again" }, "409": { "description": "Routing mismatch or legacy receipt" }, "503": { "description": "Ingestion unavailable or durability unknown" } } } },
            "/v1/accounts/withdraw": { "post": { "summary": "Withdraw USDC (record an authorized withdrawal; SEC-021: every withdrawal is wallet-signed — the API key alone can never move funds)", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["marketId","amount","to","nonce","signature"], "properties": { "marketId": { "type": "integer" }, "amount": { "type": "string" }, "to": { "type": "string", "description": "destination L1 address. Server-custody accounts (no registered signer) MUST set this to their bound deposit address; caller-signed accounts may use any address" },
                    "nonce": { "type": "integer", "description": "strictly-increasing withdrawal auth nonce, shared with /v1/lp/withdraw — use nextWithdrawNonce from GET /v1/accounts/me; committed only when the withdrawal succeeds (a rejected request does not burn it)" },
                    "signature": { "type": "string", "description": "65-byte secp256k1 sig (r‖s‖v) over the withdraw auth digest keccak256(\"dark-perp:withdraw:\"‖chainId(u64 BE)‖vault(20)‖owner(32)‖marketId(u64 BE)‖amount(i128 BE)‖to(20)‖nonce(u64 BE)), recovering to the registered signer (caller-signed) or else the bound deposit address. Accepted over any of THREE shapes: the raw 32-byte digest, EIP-191 personal_sign over those 32 bytes, or EIP-191 over their lowercase 0x-hex string — so both CLI signers and browser-wallet personal_sign work. chainId/vault/owner: read them from GET /v1/accounts/me" } } } } } },
                "responses": ok("recorded withdrawal + leaf") } },
            "/v1/accounts/withdrawals": { "get": { "summary": "Own withdrawals + claim proofs (NOTE: this endpoint's `vault` echoes the raw L1_VAULT env string, possibly EIP-55 mixed-case; for building signing digests use the normalized lowercase `vault` from GET /v1/accounts/me — those are the exact bytes hashed)", "security": auth["security"], "responses": ok("vault + withdrawals[]") } },
            "/v1/orders": {
                "post": { "summary": "Place an order", "security": auth["security"], "requestBody": order_body, "responses": { "200": { "description": "signed receipt" }, "400": { "description": "rejected" }, "429": { "description": "rate limit (10/s)" } } },
                "get": { "summary": "Own orders, signed receipt finality, and native cumulative execution (unknown legacy history is null)", "security": auth["security"], "responses": ok("orders") }
            },
            "/v1/orders/{orderId}": { "delete": { "summary": "Cancel a pending order or live maker remainder. Prior fills are unchanged, including settled partial fills. Retains the original receipt and execution history; retries are idempotent. Production success requires a durable snapshot; cancellation is recorded in the open window manifest", "security": auth["security"], "parameters": [{ "name": "orderId", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "cancelled" }, "400": { "description": "refused: unknown order or no cancellable remainder" }, "503": { "description": "persistence unavailable or durable cancellation outcome unknown" } } } },
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
    });
    let mut route = spec["paths"]["/v1/accounts/deposit/authorize"].clone();
    route["post"]["summary"] =
        serde_json::json!("Explicitly adopt a legacy permit; routing is immutable");
    let schema = &mut route["post"]["requestBody"]["content"]["application/json"]["schema"];
    schema["required"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("ownerCommit"));
    schema["properties"]["ownerCommit"] = serde_json::json!({"type":"string"});
    route["post"]["responses"] = ok("ownerCommit + routing + durability; no new signature");
    spec["paths"]["/v1/accounts/deposit/route"] = route;
    if !prod {
        // demo/dev only — mirrors the `build_router` gating (SEC-025-C Task 3):
        // the LP pool credits through an unbacked mint, so production neither
        // mounts nor documents it. INSERTED when demo (rather than removed when
        // prod) so forgetting this block under-advertises the demo surface
        // instead of over-advertising the production one.
        let paths = spec["paths"]
            .as_object_mut()
            .expect("the openapi spec always has a paths object");
        paths.insert("/v1/lp".to_string(), serde_json::json!(
            { "get": { "summary": "LP pool stats + own stake", "security": auth["security"], "responses": ok("{ tvl, navPerShare, totalShares, myShares, myValue }") } }
        ));
        paths.insert("/v1/lp/deposit".to_string(), serde_json::json!(
            { "post": { "summary": "Stake USDC into the counterparty pool (mint LP shares)", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["amount"], "properties": { "amount": { "type": "string", "description": "USDC base units (1e6-scaled string) staked from the account's market-0 balance" } } } } } },
                "responses": ok("{ sharesMinted }") } }
        ));
        paths.insert("/v1/lp/withdraw".to_string(), serde_json::json!(
            { "post": { "summary": "Burn LP shares for their pool value (SEC-021: wallet-signed like /v1/accounts/withdraw; pays into the account's OWN market-0 balance — no `to`)", "security": auth["security"],
                "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["shares","nonce","signature"], "properties": { "shares": { "type": "string" },
                    "nonce": { "type": "integer", "description": "strictly-increasing withdrawal auth nonce, shared with /v1/accounts/withdraw — use nextWithdrawNonce from GET /v1/accounts/me" },
                    "signature": { "type": "string", "description": "65-byte secp256k1 sig (r‖s‖v) over the LP withdraw auth digest keccak256(\"dark-perp:lp-withdraw:\"‖chainId(u64 BE)‖vault(20)‖owner(32)‖shares(u128 BE)‖nonce(u64 BE)), recovering to the registered signer (caller-signed) or else the bound deposit address — same three accepted shapes as /v1/accounts/withdraw" } } } } } },
                "responses": ok("{ withdrawnValue }") } }
        ));
    }
    spec
}

/// `/v1/openapi.json`: the spec for THIS deployment's mounted surface — reads the
/// production posture off the shared state like the neighbouring handlers do.
async fn get_v1_openapi(State(app): State<Shared>) -> impl IntoResponse {
    let prod = app.gw.lock().await.prod;
    Json(v1_openapi_json(prod))
}
async fn ws_v1_handler(
    State(app): State<Shared>,
    Extension(policy): Extension<Arc<service_policy::ServicePolicy>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let permit = match policy.admit(&headers) {
        Ok(permit) => permit,
        Err(code) => return code.into_response(),
    };
    policy.configure(ws).on_upgrade(move |socket| async move {
        let _permit = permit;
        let stop = policy.shutdown.clone();
        tokio::select! {
            biased;
            _ = stop.cancelled() => {},
            _ = ws_v1_loop(socket, app, policy) => {},
        }
    })
}
/// `/v1/ws`: public live-market snapshots every tick, PLUS — after the client sends
/// `{"type":"auth","apiKey":"0x.."}` — that account's own events (fills, order
/// finality, ADL haircuts). Events are filtered to the authenticated owner; an
/// unauthenticated connection sees only public market data.
async fn ws_v1_loop(socket: WebSocket, app: Shared, policy: Arc<service_policy::ServicePolicy>) {
    credential_session::serve(socket, app, policy).await;
}

async fn get_state(State(app): State<Shared>) -> impl IntoResponse {
    let gw = app.gw.lock().await;
    Json(serde_json::to_value(app.snapshot(&gw)).unwrap())
}

async fn post_order(State(app): State<Shared>, Json(req): Json<OrderReq>) -> impl IntoResponse {
    let res = {
        let mut gw = app.gw.lock().await;
        gw.place_order(&req)
    };
    match res {
        Ok((receipt, events)) => {
            let snap = { app.snapshot(&*app.gw.lock().await) };
            let _ = app
                .tx
                .send(serde_json::to_string(&WsMsg::State { state: snap }).unwrap());
            for ev in events {
                app.broadcast_event(ev).await;
            }
            let receipt = app.gw.lock().await.receipt_json(&receipt);
            Json(receipt).into_response()
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
    /// SEC-021: required on `/v1/lp/withdraw`. Ignored by the legacy demo handler,
    /// which is omitted in production (audit DP-010).
    #[serde(default)]
    nonce: Option<u64>,
    #[serde(default)]
    signature: Option<String>,
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
            let snap = { app.snapshot(&*app.gw.lock().await) };
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
            let snap = { app.snapshot(&*app.gw.lock().await) };
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

async fn ws_handler(
    State(app): State<Shared>,
    Extension(policy): Extension<Arc<service_policy::ServicePolicy>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let permit = match policy.admit(&headers) {
        Ok(permit) => permit,
        Err(code) => return code.into_response(),
    };
    policy.configure(ws).on_upgrade(move |socket| async move {
        let _permit = permit;
        let stop = policy.shutdown.clone();
        tokio::select! {
            biased;
            _ = stop.cancelled() => {},
            _ = ws_loop(socket, app, policy) => {},
        }
    })
}
async fn ws_loop(mut socket: WebSocket, app: Shared, policy: Arc<service_policy::ServicePolicy>) {
    let mut rx = app.tx.subscribe();
    let mut budget = policy.message_budget();
    let initial = {
        serde_json::to_string(&WsMsg::State {
            state: app.snapshot(&*app.gw.lock().await),
        })
        .unwrap()
    };
    if !policy.send(&mut socket, Message::Text(initial)).await {
        return;
    }
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) if !budget.take() => break,
                    Some(Ok(_)) => {},
                }
            }
            message = rx.recv() => {
                let Ok(message) = message else { break; };
                if !policy.send(&mut socket, Message::Text(message)).await { break; }
            }
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

/// SEC-025-B: TRUE production, as opposed to `production_mode`, which is also true for
/// any L1-configured testnet (`l1_enabled || DARKPERP_PROD`). The prover-less settle
/// refusal keys on THIS, so a testnet can still settle on-chain with `PROVER_URL=mock`
/// while a real deployment cannot boot without a real prover.
fn strict_production() -> bool {
    std::env::var("DARKPERP_PROD").ok().as_deref() == Some("1")
}

/// Select the settle path's prover client from `PROVER_URL`.
/// unset/empty → legacy path (None); "mock" → in-process MockProverClient;
/// any URL → HttpProverClient (seal → POST /prove → real Groth16 proof).
/// The HTTP client's seal root is resolved FAIL-CLOSED (SEC-020): an unset
/// PROVER_SEAL_ROOT (without a non-prod DEV_INSECURE=1) is an `Err` that
/// refuses to boot the window-settle path, never a silent public default.
fn prover_from_str(
    v: Option<&str>,
    prod: bool,
) -> Result<Option<std::sync::Arc<dyn prover_client::ProverClient>>, String> {
    match v {
        None | Some("") => Ok(None),
        Some("mock") => Ok(Some(std::sync::Arc::new(prover_client::MockProverClient))),
        Some(url) => Ok(Some(std::sync::Arc::new(
            prover_client::HttpProverClient::from_env(url, prod)?,
        ))),
    }
}

/// SEC-025-B §6: `prover_from_str`, plus the strict-production refusal. Split from the
/// env read so it is testable without mutating process environment.
///
/// `prod` and `strict_prod` are DIFFERENT and both are needed: `prod` is
/// `production_mode` (true for any L1-configured deployment) and is what
/// `HttpProverClient::from_env` uses for its own fail-closed seal-root resolution;
/// `strict_prod` is `DARKPERP_PROD=1` alone and is what gates this refusal. Collapsing
/// them would refuse mock on every testnet: settlement only runs when L1 is configured,
/// and L1 implies `production_mode`, so no configuration could settle on-chain without
/// a real prover.
fn prover_from_str_strict(
    v: Option<&str>,
    prod: bool,
    strict_prod: bool,
) -> Result<Option<std::sync::Arc<dyn prover_client::ProverClient>>, String> {
    if strict_prod && matches!(v, None | Some("") | Some("mock")) {
        return Err(
            "DARKPERP_PROD=1 requires a real prover: set PROVER_URL to the prover-service \
             endpoint. A prover-less settle path cannot produce a proof the on-chain \
             verifier accepts."
                .to_string(),
        );
    }
    prover_from_str(v, prod)
}

/// SEC-025-B Task-4 carry-in: whether the tick loop's SETTLE_TICKS finality SIMULATION
/// must be OFF (i.e. `window_settle_mode`). With a prover, SETTLED is earned by the
/// on-chain window settle. With L1 configured but NO prover, Task 4 deleted the legacy
/// settle body, so nothing can land on-chain at all — simulating SETTLED would be false
/// finality over real collateral, so the simulation is off there too and orders honestly
/// stay MATCHED (main() warns loudly at boot). Only the pure demo (no L1, no prover)
/// keeps the simulation.
fn honest_finality_required(prover_configured: bool, l1_enabled: bool) -> bool {
    prover_configured || l1_enabled
}

/// SEC-020 Task 5: like `prover_from_str` for the None/"mock" cases, but for a real
/// HTTP prover it ALSO injects the boot-minted `session_token` (sent as
/// `Authorization: Bearer` on every `/prove`), the boot `session_secret` +
/// `not_after`, and a re-handshake closure used to refresh ALL THREE on a 401 (C4:
/// a rebooted / rotated prover mints a NEW secret — refreshing only the token would
/// leave the gateway sealing under the stale one while the bearer gate passed).
/// `session_token = None` ⇒ the client sends no bearer and the prover 401s
/// (fail-closed).
fn prover_from_env_attested(
    prod: bool,
    session_token: Option<String>,
    session_secret: Option<[u8; 32]>,
    session_not_after: u64,
    dev_insecure: bool,
    gw_eph_secret: StaticSecret,
    gw_pub: [u8; 32],
) -> Result<Option<std::sync::Arc<dyn prover_client::ProverClient>>, String> {
    match std::env::var("PROVER_URL").ok().as_deref() {
        Some(url) if !url.is_empty() && url != "mock" => {
            let url_owned = url.to_string();
            // SEC-020 C4: the 401 re-handshake REUSES the gateway's BOOT
            // ephemeral keypair. `GET /attest` serves the boot `gw_pub` for the
            // whole process lifetime (no mid-run re-advertise), so a rebooted
            // prover derives its new secret from ECDH(pv_sk_new, gw_pub_boot) —
            // only re-deriving with the SAME boot key (against the prover's
            // newly fetched `pv_pub`) makes both sides converge on the identical
            // secret + token; a fresh gateway keypair would diverge and wedge
            // the retry. The closure re-fetches the prover's current `eph_pub` +
            // `not_after` and yields the full `(token, secret, not_after)`
            // triple so the client refreshes its session as one unit.
            // `dev_insecure` short-circuits to the fixed dev token (never a real
            // quote; the secret is unused on the dev seal path); prod exits
            // before reaching here.
            let rehandshake: prover_client::ReHandshake = Box::new(move || {
                if dev_insecure {
                    return Ok((DEV_INSECURE_SESSION_TOKEN.to_string(), [0u8; 32], u64::MAX));
                }
                prover_handshake(&url_owned, &gw_eph_secret, &gw_pub)
            });
            let client = prover_client::HttpProverClient::from_env(url, prod)?
                .with_session_token(session_token)
                .with_session_secret(session_secret, session_not_after)
                .with_rehandshake(rehandshake);
            Ok(Some(std::sync::Arc::new(client)))
        }
        // None / "" ⇒ no client; "mock" ⇒ in-process MockProverClient — but under
        // DARKPERP_PROD=1 (strict production, NOT mere `production_mode`) all three
        // are refused outright: a prover-less settle path cannot produce a proof
        // the on-chain verifier accepts (SEC-025-B §6).
        other => prover_from_str_strict(other, prod, strict_production()),
    }
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

/// Whether the gateway may boot given the oracle-signer provenance: production requires a
/// SECRET oracle-publisher key, not the public `oracle_feed::DEV_ORACLE_SIGNER_KEY`
/// (well-known Anvil account #1, a PUBLISHED scalar). Booting prod on the dev default pins
/// every `Market.oracle_pubkey` to a PUBLIC address — anyone could then sign fabricated
/// oracle transcripts that recover to it and clear the fail-closed §8 signature gate,
/// re-opening the exact prover-price-fabrication hole ZK-001 closes. Mirrors
/// `enclave_seed_ok_for_mode` (ZK-001 follow-up); the demo/dev build boots either way.
fn oracle_signer_ok_for_mode(prod: bool, is_default: bool) -> bool {
    !is_default || !prod
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

/// SEC-021 (Task-2 review Finding 3): whether the gateway may boot given its deployment
/// vault binding. In production posture the vault address must be real — `L1_VAULT` set
/// and non-zero. `production_mode()` is `l1_enabled || DARKPERP_PROD=1`, so a prod-posture
/// gateway CAN run without an L1 bridge; if `L1_VAULT` is then unset (or explicitly zero),
/// `GatewaySigner::from_env` falls back to `DEV_FALLBACK_VAULT` and every SEC-021
/// withdrawal/rebind digest binds to `(84532, 0x00…00)` — byte-identical to the unit-test
/// identity and to every other such deployment, making the cross-deployment replay
/// protection vacuous. Mirrors `oracle_signer_ok_for_mode`; the demo/dev build boots
/// either way.
fn vault_binding_ok_for_mode(prod: bool, vault: [u8; 20]) -> bool {
    !prod || vault != [0u8; 20]
}

/// Assemble the HTTP router. In production mode the legacy, UNAUTHENTICATED `/api/*`
/// mutation routes are omitted (audit DP-010) — only the read-only demo state/websocket
/// and the API-key-authenticated `/v1` surface are exposed.
#[cfg(test)]
fn build_router(app: Shared, prod: bool) -> Router {
    let policy =
        Arc::new(service_policy::ServicePolicy::from_env(prod).expect("gateway service policy"));
    build_router_with_policy(app, prod, policy)
}

fn build_router_with_policy(
    app: Shared,
    prod: bool,
    policy: Arc<service_policy::ServicePolicy>,
) -> Router {
    let mut router = Router::new()
        .route("/api/state", get(get_state))
        // SEC-020 Task 4: this host's quote for the peer's handshake half —
        // read-only, unauthenticated by design (a quote is public evidence).
        .route("/attest", get(get_attest))
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

    if !prod {
        // SEC-025-C: the LP pool credits through an UNBACKED mint (`pool_transfer` →
        // `fund_amount_unbacked`), which folds a sentinel leaf the vault chain cannot
        // match — one call breaks every later settle at `_requireDepositPrefix`. Task 2
        // refuses it at the call site; not mounting it in production keeps it off the
        // surface too. Removing this block does NOT re-enable LP in production.
        router = router
            .route("/v1/lp", get(get_v1_lp))
            .route("/v1/lp/deposit", post(post_v1_lp_deposit))
            .route("/v1/lp/withdraw", post(post_v1_lp_withdraw));
    }

    router
        // ── multi-tenant external API (/v1) ──
        .route("/v1/accounts", post(post_v1_register))
        .route("/v1/accounts/me", get(get_v1_account))
        .route("/v1/accounts/recovery/:owner", get(get_v1_recovery))
        .route("/v1/accounts/recovery", post(post_v1_recovery))
        .route("/v1/accounts/deposit", post(post_v1_deposit))
        .route(
            "/v1/accounts/deposit/address",
            post(post_v1_deposit_address),
        )
        .route(
            "/v1/accounts/deposit/authorize",
            post(post_v1_deposit_authorize),
        )
        .route(
            "/v1/accounts/deposit/route",
            post(deposit_ingestion::route_legacy),
        )
        .route(
            "/v1/accounts/deposit/onchain",
            post(post_v1_deposit_onchain),
        )
        .route("/v1/accounts/withdraw", post(post_v1_withdraw))
        .route("/v1/accounts/withdrawals", get(get_v1_withdrawals))
        .route("/v1/orders", post(post_v1_order).get(get_v1_orders))
        .route("/v1/orders/:order_id", delete(delete_v1_order))
        .route("/v1/positions", get(get_v1_positions))
        .route("/v1/markets", get(get_v1_markets))
        .route("/v1/markets/:id", get(get_v1_market))
        .route("/v1/markets/:id/orderbook", get(get_v1_orderbook))
        .route("/v1/markets/:id/candles", get(get_v1_candles))
        .route("/v1/markets/:id/oracle", get(get_v1_oracle))
        .route("/v1/system/status", get(get_v1_status))
        .route("/v1/admin/settlement/resume", post(post_v1_admin_resume))
        .route("/v1/admin/wind-down", post(post_v1_admin_wind_down))
        .route(
            "/v1/admin/insurance/bootstrap",
            post(post_v1_admin_insurance_bootstrap),
        )
        .route("/v1/batch/:id", get(get_v1_batch))
        .route("/v1/enclave/epoch", get(get_v1_enclave_epoch))
        .route("/v1/openapi.json", get(get_v1_openapi))
        .route("/v1/ws", get(ws_v1_handler))
        .layer(policy.cors())
        .layer(axum::middleware::from_fn_with_state(
            policy.clone(),
            service_policy::enforce_origin,
        ))
        .layer(Extension(policy))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            clock_admission::http_gate,
        ))
        .with_state(app)
}

/// Seal and persist stage 1 under the same Gw guard used by snapshot capture.
/// A writer can observe either the pre-seal state or a sealed state whose rollback
/// record is already durable, never the gap between them. On failure the seal is
/// undone before the caller releases the guard. The previous resolution must be
/// snapshotted before calling this helper and replacing the previous journal.
fn begin_journaled_window_settle(
    gw: &mut Gw,
    chain_batch_count: u64,
    path: Option<&std::path::Path>,
    seed: &[u8; 32],
) -> Result<Option<rollback_journal::RollbackJournal>, String> {
    let Some((witness, ww)) = gw.begin_window_settle(chain_batch_count)? else {
        return Ok(None);
    };
    let journal = rollback_journal::RollbackJournal {
        batch_id: witness.batch_id,
        witness,
        ww,
        prepared: None,
    };
    if let Err(error) = after_settle_journal(path, &journal, seed, || ()) {
        gw.seq.rollback_window(&journal.witness);
        gw.rollback_window_withdrawals(journal.ww);
        return Err(format!("stage-1 rollback journal is not durable: {error}"));
    }
    Ok(Some(journal))
}

/// A configured journal is a durability barrier before proving/broadcasting.
/// Do not invoke the continuation after any write or fsync failure. `None`
/// preserves the explicitly unjournaled dev path; it is not durable evidence.
fn after_settle_journal<T>(
    path: Option<&std::path::Path>,
    journal: &rollback_journal::RollbackJournal,
    seed: &[u8; 32],
    next: impl FnOnce() -> T,
) -> Result<T, String> {
    if let Some(path) = path {
        rollback_journal::write(path, journal, seed)?;
    }
    Ok(next())
}

#[tokio::main]
async fn main() {
    let addr = listen_config::parse(
        std::env::var("GATEWAY_BIND_ADDRESS").ok().as_deref(),
        std::env::var("PORT").ok().as_deref(),
    )
    .unwrap_or_else(|error| {
        eprintln!("[listener] REFUSING to start: {error}");
        std::process::exit(1);
    });
    let (tx, _rx) = broadcast::channel::<String>(256);
    let (events_tx, _erx) = broadcast::channel::<String>(1024);
    let l1 = L1::from_env();
    // SEC-020: the prover client's seal root is resolved against the production
    // posture, so compute `prod` BEFORE building the client — a prod boot with an
    // unset PROVER_SEAL_ROOT (or a DEV_INSECURE escape) must refuse to start.
    let prod = production_mode(l1.is_some());
    let service_policy = Arc::new(
        service_policy::ServicePolicy::from_env(prod).unwrap_or_else(|error| {
            eprintln!("[listener] REFUSING to start: {error}");
            if let Some(l1c) = &l1 {
                l1c.cleanup_keystore();
            }
            std::process::exit(1);
        }),
    );
    let l1 = l1.map(|chain| chain.with_clock_shutdown(service_policy.shutdown.clone()));
    let clock_settle_period = if let Some(chain) = l1.as_ref().filter(|c| c.clock_enabled()) {
        let chain = chain.clone();
        match tokio::task::spawn_blocking(move || chain.clock_seal_period()).await {
            Ok(Ok(period)) => period,
            _ => {
                eprintln!("[clock] REFUSING startup: cannot verify timing policy and seal cadence");
                std::process::exit(1);
            }
        }
    } else {
        Duration::from_secs(L1_SETTLE_SECS)
    };
    // SEC-020 Task 4: the DEV_INSECURE escape is refused outright in production
    // (Task-1 posture). `resolve_seal_root` only refuses it when the seal root
    // is ALSO unset; the handshake escape must be prod-forbidden unconditionally.
    let dev_insecure = std::env::var("DEV_INSECURE").as_deref() == Ok("1");
    if prod && dev_insecure {
        eprintln!("[attest] REFUSING to start: DEV_INSECURE is forbidden in production");
        std::process::exit(1);
    }
    // ── SEC-020 Task 4/5: mutual-attestation handshake at settle-path init ──
    // Fail-closed structure: ANY `Err` from ANY attestation step aborts the
    // handshake with the token unset — a token is never minted from a partial or
    // failed handshake. The minted token is injected into the HttpProverClient
    // (Task 5, below) so it rides every /prove as `Authorization: Bearer`; a `None`
    // token ⇒ the client sends no bearer and the prover 401s (fail-closed). The
    // handshake runs BEFORE the client is built because the client needs the token.
    // SEC-020 Phase-2 (C3): the per-boot ephemeral x25519 keypair — the
    // freshness for BOTH directions of the handshake. The public half rides our
    // /attest (and is the challenge a live self-quote binds); the SECRET half is
    // what makes the session secret underivable from the public transcript. It
    // is never logged or served.
    let ikm = Zeroizing::new(csprng_bytes32());
    let (gw_eph_secret, gw_pub) = ephemeral_keypair(&ikm);
    // Erase the owned random seed after key construction.
    drop(ikm);
    // SEC-020 Task 6: capture the raw `session_secret` alongside the token — the
    // attested seal key rests on it (never logged/served). `None` on both the dev
    // and refused-prod paths ⇒ the gateway seals with the DEV_INSECURE
    // SoftwareSealProvider; the attested seal is Phase-2-active.
    let (prover_session_token, prover_session_secret, prover_session_not_after): (
        Option<String>,
        Option<[u8; 32]>,
        u64,
    ) = match std::env::var("PROVER_URL").ok().as_deref() {
        // Only a real HTTP prover has an /attest to shake hands with ("mock" is
        // in-process and the legacy path has no prover at all).
        Some(url) if !url.is_empty() && url != "mock" => {
            if dev_insecure {
                // Non-prod only (prod exits above): skip BOTH verifications and
                // use the FIXED dev token — never derived from real quotes. No real
                // session secret ⇒ the dev SoftwareSealProvider seal path (and no
                // real expiry — the dev token never rotates).
                eprintln!(
                    "WARN gateway: INSECURE: attestation handshake skipped — never production"
                );
                (Some(DEV_INSECURE_SESSION_TOKEN.to_string()), None, u64::MAX)
            } else {
                match prover_handshake(url, &gw_eph_secret, &gw_pub) {
                    // `not_after` (the prover-owned expiry) is bound into the
                    // token AND threaded into the client alongside the secret,
                    // so a C4 re-handshake refreshes a complete session.
                    Ok((t, secret, not_after)) => {
                        println!(
                            "[attest] prover handshake OK — session token minted \
                             (not_after {not_after} ms)"
                        );
                        (Some(t), Some(secret), not_after)
                    }
                    Err(e) => {
                        // Expected on today's hardware (GB10 CC off ⇒ the NVIDIA
                        // verify is CcNotEnabled): no token/secret, proving stays closed.
                        eprintln!(
                            "[attest] prover handshake REFUSED ({e}) — no session token; \
                             proving stays closed once /prove is gated (SEC-020 fail-closed)"
                        );
                        (None, None, 0)
                    }
                }
            }
        }
        _ => (None, None, 0),
    };
    // Build the settle path's prover client, injecting the SEC-020 session token +
    // secret + the 401 re-handshake (HTTP prover only). The seal root is resolved
    // fail-closed inside `from_env`, so a prod boot with an unset PROVER_SEAL_ROOT
    // still refuses.
    let prover = match prover_from_env_attested(
        prod,
        prover_session_token.clone(),
        prover_session_secret,
        prover_session_not_after,
        dev_insecure,
        // C4: the re-handshake must reuse the BOOT keypair — /attest keeps
        // advertising the boot `gw_pub`, so a rebooted prover derives against
        // it; only the same key re-derives the same secret (clone: the App
        // below takes ownership of the original).
        gw_eph_secret.clone(),
        gw_pub,
    ) {
        Ok(p) => p,
        Err(e) => {
            // SEC-025-B §6: a refusal to start, not a warning that proceeds — this is
            // where a DARKPERP_PROD=1 boot without a real PROVER_URL dies.
            eprintln!("[prover] REFUSING to start: {e}");
            std::process::exit(1);
        }
    };
    let prover: Option<Arc<dyn prover_client::ProverClient>> = match (prover, &l1) {
        (Some(inner), Some(chain)) if chain.clock_enabled() => {
            Some(Arc::new(clock_client::ClockProverClient {
                inner,
                l1: chain.clone(),
            }))
        }
        (p, _) => p,
    };
    if prod && !prover.as_ref().is_some_and(|p| p.clock_enabled()) {
        eprintln!("[clock] REFUSING production without CLOCK_BOUND_VERIFIER and L1_CHAIN_ID; explicit legacy mode is development-only");
        std::process::exit(1);
    }
    if prover.is_some() {
        println!("[prover] window-settle path ON (PROVER_URL)");
    } else if l1.is_some() {
        // SEC-025-B Task-4 carry-in: Task 4 deleted the legacy settle body, so an
        // L1-configured gateway without a prover settles NOTHING — and it used to be
        // silent about it (the legacy body's per-tick "[l1] settle failed" log went
        // with it). Under the §6 rule this configuration is only reachable WITHOUT
        // DARKPERP_PROD=1 (strict production refuses it above), i.e. a testnet or
        // local chain — so warn loudly rather than refuse, and run under the honest
        // finality posture (`window_settle_mode` below): orders stay MATCHED instead
        // of the SETTLE_TICKS simulation reporting a SETTLED that never happened.
        eprintln!(
            "[l1] WARNING: L1 settlement is configured but no prover is (PROVER_URL unset) — \
             the gateway CANNOT settle on-chain: the root never advances and withdrawals \
             never become claimable. The SETTLE_TICKS finality simulation is DISABLED, so \
             orders stay MATCHED. Set PROVER_URL to the prover-service endpoint \
             (or PROVER_URL=mock on a testnet/local chain)."
        );
    }
    // The attestor whose self-quote `GET /attest` serves: pinned collateral +
    // the same §5c ATTESTATION_DIR capture `attest_from_env` verifies. Absent
    // or unparsable ⇒ None ⇒ /attest answers 503 (fail-closed, loudly).
    let attestor = std::env::var("ATTESTATION_DIR").ok().and_then(|dir| {
        let p = std::path::Path::new(&dir).join("collateral.json");
        match std::fs::read(&p)
            .map_err(|e| e.to_string())
            .and_then(|b| AzureTdxAttestor::from_collateral_json(&b).map_err(|e| format!("{e:?}")))
        {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("[attest] /attest quote source unavailable ({e}) — will answer 503");
                None
            }
        }
    });
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
    // ZK-001 follow-up: production requires a SECRET oracle-publisher key. Resolve it up
    // front (mirrors enclave_seed_from_env), so a SET-but-malformed ORACLE_SIGNER_KEY fails
    // closed HERE with a clear message, and — critically — an UNSET key in production is
    // refused BEFORE boot pins every Market.oracle_pubkey to the public dev address. Without
    // this, a prod gateway booted without ORACLE_SIGNER_KEY would trust a well-known scalar,
    // letting anyone sign fabricated oracle transcripts that clear the §8 gate (re-opening
    // the price-fabrication hole ZK-001 closes). Explicitly setting the known public
    // key is also refused; presence in an environment variable is not secrecy.
    let oracle_signer_is_default = match oracle_feed::signer_from_env_checked() {
        Ok((signer, is_default)) => is_default || oracle_feed::is_known_dev_signer(&signer),
        Err(e) => {
            eprintln!(
                "[oracle] REFUSING to start: {e}. Set ORACLE_SIGNER_KEY to a valid 32-byte hex \
                 secp256k1 scalar, or unset it for the demo build."
            );
            std::process::exit(1);
        }
    };
    if !oracle_signer_ok_for_mode(prod, oracle_signer_is_default) {
        eprintln!(
            "[oracle] REFUSING to start: ORACLE_SIGNER_KEY must be set in production — refusing \
             to boot with the public dev oracle key. Every Market.oracle_pubkey would be pinned \
             to a well-known address, letting anyone sign fabricated oracle transcripts that \
             clear the §8 signature gate. Set ORACLE_SIGNER_KEY to a secret 32-byte hex \
             secp256k1 scalar and pin its address as each Market.oracle_pubkey."
        );
        std::process::exit(1);
    }
    if oracle_signer_is_default {
        // non-prod only (prod exits above): the public dev oracle key is fine for the demo
        // build / tests, but must never sign on a real deployment (mirrors the enclave-seed
        // posture and the DEV_INSECURE WARN).
        eprintln!(
            "WARN gateway: oracle publisher signer is the PUBLIC dev default (ORACLE_SIGNER_KEY \
             unset) — demo/test only, never production"
        );
    }
    // SEC-019 (Task 7b): load the deposit-authorization signer. A SET-but-malformed
    // GATEWAY_SIGNER_KEY fails closed with a clear message (never silently signs with
    // the demo key); unset falls back to the demo key for the demo build. Loaded BEFORE
    // the state restore below (SEC-021 review Finding 8): `from_env` reads only the
    // environment, and hoisting it lets the SEC-021 deployment binding be applied
    // beside `gw.prod` — so no code between restore and wiring can ever observe the
    // restore-default chain_id/vault instead of the environment's.
    let gateway_signer = match GatewaySigner::from_env() {
        Ok(gs) => {
            println!(
                "[sec-019] gateway deposit-authorization signer address {} (must equal the \
                 deployed CollateralVault.gatewaySigner)",
                hex0x(&gs.address())
            );
            gs
        }
        Err(e) => {
            eprintln!("[sec-019] REFUSING to start: {e}");
            std::process::exit(1);
        }
    };
    // SEC-021 (review Finding 3): in production the deployment binding must be real.
    if !vault_binding_ok_for_mode(prod, gateway_signer.vault) {
        eprintln!(
            "[sec-021] REFUSING to start: in production L1_VAULT must be set to the deployed \
             CollateralVault address (non-zero). Without it, every withdrawal/rebind \
             authorization digest binds to the dev fallback identity (chain 84532 / zero \
             vault) — byte-identical to every other such deployment and to the unit-test \
             identity — so the cross-deployment replay protection is vacuous. Set L1_VAULT, \
             or drop the production posture (no L1 bridge and DARKPERP_PROD unset) to run \
             the demo build."
        );
        std::process::exit(1);
    }
    // Sealed state persistence: DARKPERP_STATE=<path> restores the engine across
    // restarts. Required restore/pinned checkpoint modes never interpret a
    // missing backup as permission to start a new genesis.
    let state_path = std::env::var_os("DARKPERP_STATE").map(std::path::PathBuf::from);
    let startup_snapshot = snapshot::RestorePolicy::from_env()
        .and_then(|policy| policy.read_for_boot(state_path.as_deref()))
        .unwrap_or_else(|error| {
            eprintln!("[state] REFUSING to start: {error}");
            std::process::exit(1);
        });
    let startup_journal = recovery_checkpoint::JournalPolicy::from_env()
        .and_then(|policy| policy.read_for_boot(state_path.as_deref()))
        .unwrap_or_else(|error| {
            eprintln!("[recovery] REFUSING to start: {error}");
            std::process::exit(1);
        });
    let mut unresolved_startup_journal = startup_journal.is_some();
    // Task 3 (crash recovery): whether a sealed snapshot was actually restored —
    // a rollback journal is only meaningful against the state it was written
    // beside; a journal without its snapshot now refuses startup for reconciliation.
    if prover.as_ref().is_some_and(|p| p.clock_enabled()) && state_path.is_none() {
        eprintln!("[clock] REFUSING to start without DARKPERP_STATE durability");
        std::process::exit(1);
    }
    let mut restored_from_snapshot = false;
    // SEC-025-C: the genesis mode is computed BEFORE boot and passed as a parameter —
    // `gw.prod` is assigned two lines after boot returns, so a field read inside
    // `boot()` could never guard the demo funding. Keyed on `production_mode`
    // (L1-configured OR DARKPERP_PROD): any L1-configured deployment gets a
    // markets-only genesis whose (tip, count) = (0, 0) matches a fresh vault.
    let genesis_mode = if prod {
        GenesisMode::Production
    } else {
        GenesisMode::Demo
    };
    let mut gw = match (&state_path, startup_snapshot) {
        (Some(p), Some(sealed)) => {
            let restored =
                snapshot::open(&sealed, &enclave_seed).and_then(|plain| Gw::boot_restored(&plain));
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
        (_, None) => Gw::boot_with(genesis_mode),
        (None, Some(_)) => unreachable!("startup snapshot requires a configured path"),
    };
    gw.prod = prod;
    gw.require_fresh_production_oracles();
    // SEC-021: bind withdrawal authorization to this deployment — the same env source
    // the deposit-authorization signer uses, so both digest families agree on chain id
    // + vault by construction. Set HERE, beside `prod` (review Finding 8): the signer
    // is loaded before `gw` exists, so a future pre-`App` reader sees the environment's
    // identity, never the restore default.
    gw.chain_id = gateway_signer.chain_id;
    gw.vault = gateway_signer.vault;
    // Task 5: with a prover configured, the tick loop's SETTLE_TICKS simulation is OFF —
    // finality advances only when a window's proof verifies on L1. Set BEFORE the
    // boot-recovery block below, so a roll-forward re-commit already runs under the
    // honest-finality posture (its `commit_window_settle` marks the recovered window's
    // orders SETTLED either way — the flag gates only the tick-loop simulation).
    // SEC-025-B Task-4 carry-in: ALSO off when L1 is configured with NO prover — the
    // legacy settle body is deleted, so nothing lands on-chain and the simulation would
    // be false finality (see `honest_finality_required` + the boot warning above; pinned
    // by `l1_without_a_prover_must_not_simulate_settled`).
    gw.window_settle_mode = honest_finality_required(prover.is_some(), l1.is_some());
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
    // as the final arbiter: a roll-forward re-commit (`commit_window_settle`)
    // advances `last_settled_root` — the value the continuity check compares —
    // so an interrupted-but-landed settle passes it, and a rollback rewinds
    // Counter B so the desync guard stops skipping settles.
    if let Some(sp) = &state_path {
        let jp = rollback_journal::journal_path(sp);
        if !restored_from_snapshot {
            if unresolved_startup_journal {
                eprintln!("[recovery] HOLDING: rollback journal {} exists without a restored snapshot; preserve both files and reconcile before restart", jp.display());
            }
        } else {
            match startup_journal
                .as_deref()
                .map(|bytes| rollback_journal::open(bytes, &enclave_seed))
                .transpose()
            {
                Ok(None) => {} // no journal — nothing was in flight
                Err(e) => {
                    // present but unreadable: never delete data the operator may
                    // need, never guess — HOLD and fall through.
                    eprintln!(
                        "[recovery] HOLDING: rollback journal {} exists but is unreadable \
                         ({e}) — keeping the file; operator must reconcile (startup is refused until this journal resolves)",
                        jp.display()
                    );
                }
                Ok(Some(mut j)) => match &l1 {
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
                        // Counter/root/bond are read at one finalized canonical block hash.
                        // No finite delay proves an unmined prepared transaction absent.
                        let mut reads = {
                            let l1c = l1c.clone();
                            tokio::task::spawn_blocking(move || l1c.settlement_observation())
                                .await
                                .unwrap_or_else(|e| Err(e.to_string()))
                        };
                        // Resume only the exact immutable, durably prepared clock
                        // window. Finality lag or a reorg keeps the WAL and refuses
                        // startup; it never turns into a legacy rollback/re-seal.
                        if let (Ok((bc, root, _)), Some(client)) = (&reads, &prover) {
                            if client.clock_enabled()
                                && j.prepared.is_some()
                                && *bc == j.batch_id
                                && Some(gw.seq.state.next_batch_id) == j.batch_id.checked_add(1)
                                && root
                                    .eq_ignore_ascii_case(&hex32(&j.witness.pre_state.state_root()))
                            {
                                let (chain, client, mut saved, path) =
                                    (l1c.clone(), client.clone(), j.clone(), jp.clone());
                                match tokio::task::spawn_blocking(move || {
                                    let observation = clock_client::resume_exact(&chain, client.as_ref(), &mut saved, &path, &enclave_seed)?;
                                    Ok::<_,String>((saved, observation))
                                }).await {
                                    Ok(Ok((saved, observation))) => { j = saved; reads = Ok(observation); }
                                    _ => eprintln!("[clock] exact-journal recovery unresolved; preserve WAL and retry after canonical finality"),
                                }
                            }
                        }
                        match reads {
                            Ok((chain_bc, chain_root, bond)) => {
                                // SEC-025-D: the boot roll-forward COMMITS a settle, so it
                                // must carry the same block-pinned observation as the live
                                // settle paths — it must not shortcut the finalSettle
                                // distinction to `StaysClosed`, and a failed read proves
                                // nothing (`Inconclusive`). Observed only when this journal
                                // actually presents the roll-forward shape (the same
                                // conjunction `recovery_action`'s RollForward row requires)
                                // and the gate is still Closed. The pre-filter carries no
                                // safety weight — the observation re-derives all three
                                // terms at one pinned block regardless — and erring on
                                // skipping can only leave the gate UNRESOLVED, never open
                                // it on a wind-down.
                                let gate_observation = match (&gw.trading_gate, &j.prepared) {
                                    (trading_gate::TradingGate::Closed, Some(p))
                                        if Some(gw.seq.state.next_batch_id)
                                            == j.batch_id.checked_add(1)
                                            && Some(chain_bc) == j.batch_id.checked_add(1)
                                            && chain_root.eq_ignore_ascii_case(&hex32(
                                                &p.outcome.new_root,
                                            )) =>
                                    {
                                        let l1o = l1c.clone();
                                        let (bid, our_root) = (j.batch_id, p.outcome.new_root);
                                        tokio::task::spawn_blocking(move || {
                                            observe_gate(&l1o, bid, our_root)
                                        })
                                        .await
                                        .unwrap_or(trading_gate::GateObservation::Inconclusive)
                                    }
                                    _ => trading_gate::GateObservation::Inconclusive,
                                };
                                match apply_boot_recovery(
                                    &mut gw,
                                    j,
                                    chain_bc,
                                    &chain_root,
                                    bond,
                                    gate_observation,
                                ) {
                                    // Task 3 fix: a MUTATED resolution is persisted
                                    // synchronously BEFORE the journal is deleted
                                    // (and a failed persist keeps the journal) —
                                    // see finish_boot_recovery.
                                    BootRecoveryOutcome::DeleteJournal { mutated } => {
                                        unresolved_startup_journal = !finish_boot_recovery(
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
                                     rollback journal ({e}) — keeping the file; startup is refused until this journal resolves"
                                );
                            }
                        }
                    }
                },
            }
        }
    }
    // A matching old settled root alone does not resolve an in-flight journal.
    // Never start another settlement loop that could overwrite this recovery record.
    if let Some(sp) = &state_path {
        let jp = rollback_journal::journal_path(sp);
        if unresolved_startup_journal || jp.try_exists().unwrap_or(true) {
            eprintln!("[recovery] REFUSING to start: unresolved rollback journal {}; reconcile the pending transaction and restart", jp.display());
            if let Some(l1c) = &l1 {
                l1c.cleanup_keystore();
            }
            std::process::exit(1);
        }
    }
    // State ↔ L1 continuity, on EVERY L1-configured boot (SEC-025-C): the gateway's
    // last settled root must equal the on-chain currentStateRoot, or this state is
    // stale / from a different deployment — settling from it would fork the
    // withdrawal roots users hold. Gating this on `l1_status` being Some left every
    // pre-first-settle snapshot unchecked: `l1_status` stays None until the first
    // commit_window_settle, yet the gateway persists (and restores the deposit
    // accumulator) throughout — and since `prod` is not persisted, a DEMO snapshot
    // carrying unbacked deposits could be restored under production posture.
    // `last_settled_root` (genesis until a settle lands) is compared rather than
    // `state_root()`, because a legitimate pre-settle snapshot may hold real pending
    // deposits and correctly differ from the chain. Fail closed; the operator
    // resolves (right snapshot, right chain, or fresh).
    if let Some(l1c) = &l1 {
        let chain_root = {
            let l1c = l1c.clone();
            tokio::task::spawn_blocking(move || l1c.current_root())
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
        };
        match chain_root {
            Ok(r) if continuity_ok(&gw.last_settled_root, &r) => {
                println!("[state] on-chain continuity OK (currentStateRoot {r})");
            }
            Ok(r) => {
                eprintln!(
                    "[state] REFUSING to start: the gateway's last settled root is {} but the \
                     chain's currentStateRoot is {r} — this state is stale, from a different \
                     deployment, or a DEMO snapshot booted under production posture (prod is \
                     not persisted, so a demo snapshot's unbacked balances would otherwise \
                     re-break settlement). Restore the snapshot matching this chain, point \
                     the gateway at the deployment this state belongs to, or deploy fresh \
                     contracts and delete DARKPERP_STATE to consciously start over.",
                    hex32(&gw.last_settled_root)
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
        // Deposit posture, beside the continuity check (SEC-025-C follow-up): root
        // EQUALITY above is not a posture detector — a deployment whose contract
        // GENESIS_ROOT was itself derived from a DEMO boot matches its own demo
        // snapshot and would boot with fabricated unbacked deposits intact. That
        // strands real USDC: `account_confirm_deposit` refuses every real deposit
        // (id 0 is not next-in-line), `settleBatch` reverts at `_requireDepositPrefix`,
        // and `finalSettle` reverts on the same pin — the wind-down escape hatch is
        // bricked. So ALSO require, on every L1-configured boot, that the vault can
        // back what the gateway has consumed. Fail closed on every arm, including
        // "vault not configured": that Errs inside the accessors and lands here as
        // an RPC-shaped refusal, never a silent skip.
        let gw_count = gw.seq.state.consumed_deposit_count;
        let vault_reads = {
            let l1c = l1c.clone();
            tokio::task::spawn_blocking(move || l1c.vault_deposit_observation(gw_count))
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
        };
        let gw_tip = hex32(&gw.seq.state.consumed_deposit_tip);
        match vault_reads {
            Ok((vault_count, vault_tip)) => {
                match deposit_posture(
                    gw_count,
                    &gw.seq.state.consumed_deposit_tip,
                    vault_count,
                    &vault_tip,
                ) {
                    DepositPosture::Ok => {
                        println!(
                            "[state] deposit posture OK (consumed {gw_count} of {vault_count} \
                             vault deposits, tip {gw_tip})"
                        );
                    }
                    DepositPosture::UnbackedCount => {
                        eprintln!(
                            "[state] REFUSING to start: the gateway has consumed {gw_count} \
                             deposits (tip {gw_tip}) but the vault has only ever received \
                             {vault_count} — the gateway credited deposits the vault never \
                             received. If this gateway was previously healthy: a stale read \
                             from a load-balanced RPC backend produces this exact signature, \
                             so restart and let the check re-read before concluding the state \
                             is unbacked. If it persists, this is almost always a demo-derived \
                             genesis or a demo snapshot booted under production posture; left \
                             running it strands real USDC (every real deposit is refused as \
                             out-of-order, and both settleBatch and finalSettle revert at the \
                             deposit-prefix pin). The remedy for a genuinely unbacked state is \
                             fresh contracts at an honest genesis plus a snapshot wipe (delete \
                             DARKPERP_STATE) — a restart alone cannot repair it."
                        );
                        std::process::exit(1);
                    }
                    DepositPosture::TipMismatch => {
                        eprintln!(
                            "[state] REFUSING to start: the gateway's consumed-deposit tip at \
                             count {gw_count} is {gw_tip} but the vault's recorded prefix tip \
                             depositTipAt({gw_count}) is {vault_tip} — the leaves the gateway \
                             consumed are not the vault's leaves, even though the counts \
                             coincide. This signature is almost always a demo-derived genesis \
                             or a demo snapshot booted under production posture (sentinel \
                             deposits credited off-chain); left running it strands real USDC \
                             (settleBatch and finalSettle both revert at the deposit-prefix \
                             pin). The remedy is fresh contracts at an honest genesis plus a \
                             snapshot wipe (delete DARKPERP_STATE) — not a restart."
                        );
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[state] REFUSING to start: cannot verify the deposit posture against \
                     the vault ({e}). If this says L1_VAULT is not set: an L1-configured \
                     gateway without a vault is itself a misconfiguration — configure \
                     L1_VAULT rather than expecting the check to be skipped."
                );
                std::process::exit(1);
            }
        }
    }
    gw.ops_alerts = ops_alerts::OpsAlerts::from_env().unwrap_or_else(|error| {
        eprintln!("[alerts] REFUSING to start: {error}");
        std::process::exit(1);
    });
    if gw.deposits.halt.is_some() {
        gw.ops_alerts.activate(ops_alerts::AlertKind::DepositHalted);
    }
    let (snapshot_req_tx, mut snapshot_req_rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    let snapshot_req = state_path.as_ref().map(|_| snapshot_req_tx);
    let deposit_source = l1.as_ref().map(|l| {
        gw.deposits.required = true;
        Arc::new(deposit_rpc::VaultSource::new(l.clone())) as Arc<dyn deposit_rpc::DepositSource>
    });
    if l1.as_ref().is_some_and(|chain| chain.clock_enabled())
        && gw.window_withdrawals.is_empty()
        && gw.seq.state.state_root() == gw.last_settled_root
    {
        gw.seq.discard_idle_funding_window();
    }
    let app = Arc::new(App {
        clock_admission: clock_admission::ClockAdmission::new(
            prover.as_ref().is_some_and(|p| p.clock_enabled()),
        ),
        deposit_source,
        deposit_serial: Mutex::new(()),
        gw: Mutex::new(gw),
        tx: tx.clone(),
        events_tx,
        reg_limit: Mutex::new(HashMap::new()),
        l1: l1.clone(),
        snapshot_req,
        gateway_signer,
        prover: prover.clone(),
        candles: Mutex::new(candles::CandleStore::new()),
        attestor,
        gw_eph_secret,
        gw_pub,
        prover_session_token,
        force_settle: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });

    let signals = service_shutdown::Signals::new().expect("shutdown signal handlers");
    let mut background = Vec::new();
    let cleanup_l1 = l1.clone();

    if app.deposit_source.is_some() {
        let app = app.clone();
        let stop = service_policy.shutdown.clone();
        background.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                if !stop.next_tick(&mut interval).await {
                    break;
                }
                if let Err(e) = deposit_ingestion::ingest_once(&app).await {
                    eprintln!("[deposit-ingester] paused: {e}");
                }
            }
        }));
    }

    // One-shot REAL history backfill for feed-backed markets (chart past bars):
    // exchange candles land under the live bars the tick loop records. Failures
    // degrade to shorter history, never block boot.
    {
        let app = app.clone();
        let stop = service_policy.shutdown.clone();
        background.push(tokio::spawn(async move {
            let feeds: Vec<(u64, &'static str)> = MARKETS
                .iter()
                .filter_map(|m| m.feed.map(|f| (m.id, f)))
                .collect();
            for (id, inst) in feeds {
                for (tf_idx, (tf, _, cc_tf)) in candles::TFS.iter().enumerate() {
                    if stop.started() {
                        return;
                    }
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
        }));
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

    // Keep the writer alive until accepted HTTP and background work have
    // finished every durability ACK. Only then stop it and capture final state.
    let snapshot_serial = Arc::new(Mutex::new(()));
    let snapshot_stop = Arc::new(service_shutdown::Shutdown::default());
    let snapshot_writer = if let Some(path) = state_path.clone() {
        let app = app.clone();
        let serial = snapshot_serial.clone();
        let stop = snapshot_stop.clone();
        let notify = snapshot_notify.clone();
        println!("[state] sealed persistence ON → {}", path.display());
        Some(tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(SNAPSHOT_SECS));
            iv.tick().await;
            loop {
                let mut ack: Option<SnapshotAck> = None;
                tokio::select! {
                    biased;
                    _ = stop.cancelled() => break,
                    Some(a) = snapshot_req_rx.recv() => { ack = Some(a); }
                    _ = notify.notified() => {}
                    _ = iv.tick() => {}
                }
                let ok = write_snapshot(&app, &path, enclave_seed, serial.clone()).await;
                if let Some(ack) = ack {
                    let _ = ack.send(ok);
                }
            }
        }))
    } else {
        None
    };

    // background tick loop
    {
        let app = app.clone();
        let stop = service_policy.shutdown.clone();
        background.push(tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(TICK_MS));
            loop {
                if !stop.next_tick(&mut iv).await {
                    break;
                }
                let (events, acct_events) = {
                    let Ok(_admission) = app.clock_admission.enter() else {
                        // The paused gate stops financial ticks, not read-only status.
                        // Existing WebSocket clients must see the pause/recovery hold.
                        app.broadcast(&*app.gw.lock().await).await;
                        continue;
                    };
                    app.gw.lock().await.tick()
                };
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
                let snap = { app.snapshot(&*app.gw.lock().await) };
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
        }));
    }

    // live oracle: pull real prices for feed-backed markets from Crypto.com every 5s
    // and feed them into the engine (markets without a feed keep the sim walk).
    {
        let app = app.clone();
        let stop = service_policy.shutdown.clone();
        background.push(tokio::spawn(async move {
            let (feeds, oracle_signer): (Vec<(u64, &'static str)>, k256::ecdsa::SigningKey) = {
                let gw = app.gw.lock().await;
                let feeds = gw
                    .mkts
                    .iter()
                    .filter_map(|m| m.feed.map(|f| (m.id, f)))
                    .collect();
                // The operator's oracle-publisher key: fetched transcripts are signed
                // with it (ZK-001) so they recover to each market's pinned `oracle_pubkey`.
                (feeds, gw.oracle_signer.clone())
            };
            if feeds.is_empty() {
                return;
            }
            let mut iv = tokio::time::interval(Duration::from_secs(5));
            loop {
                if !stop.next_tick(&mut iv).await {
                    break;
                }
                for &(id, inst) in &feeds {
                    if stop.started() {
                        break;
                    }
                    let now = now_ms();
                    let signer = oracle_signer.clone();
                    match tokio::task::spawn_blocking(move || {
                        oracle_feed::fetch_transcript(inst, now, id, &signer)
                    })
                    .await
                    {
                        Ok(Ok(t)) => {
                            if !app.gw.lock().await.apply_real_oracle(id, t) {
                                eprintln!("[oracle] {inst} observation rejected: source time, signature or market bounds; previous observation is not refreshed");
                            }
                        }
                        Ok(Err(e)) => eprintln!("[oracle] {inst} fetch failed: {e}"),
                        Err(e) => eprintln!("[oracle] {inst} join: {e}"),
                    }
                }
            }
        }));
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
            let stop = service_policy.shutdown.clone();
            background.push(tokio::spawn(async move {
                // audit #8: DON'T start at the current block — that silently skips any
                // InclusionChallenged raised while we were restarting/down, letting an
                // honest sequencer be slashed for a challenge it could have answered. A
                // challenge is answerable only within `challengeWindowBlocks`, so rewind
                // past that window (see challenge_scan_start); over-scanning older /
                // already-answered challenges is a harmless no-op (challenge_answerable gates
                // the answer). The data to answer is in the persisted batch_orders.
                let mut from_block = challenge_scan::Cursor::default();
                let mut iv = tokio::time::interval(Duration::from_secs(L1_SETTLE_SECS));
                loop {
                    if !stop.next_tick(&mut iv).await { break; }
                    let start_l1 = l1a.clone();
                    let fetch_l1 = l1a.clone();
                    let check_l1 = l1a.clone();
                    let result = challenge_scan::advance(
                        &mut from_block,
                        || async move {
                            tokio::task::spawn_blocking(move || {
                                let (now, window) = start_l1.challenge_scan_start_observation()?;
                                Ok(challenge_scan_start(now, window))
                            }).await.map_err(|_| "challenge startup join failed".to_string())?
                        },
                        |height, hash| {
                            let check_l1 = check_l1.clone();
                            async move {
                                tokio::task::spawn_blocking(move || check_l1.challenge_scan_anchor_matches(height, hash))
                                    .await.map_err(|_| "challenge anchor join failed".to_string())?
                            }
                        },
                        |from| async move {
                            tokio::task::spawn_blocking(move || fetch_l1.fetch_challenges(from))
                                .await.map_err(|_| "challenge scan join failed".to_string())?
                        },
                        |oh| {
                            let app = app.clone();
                            let l1c = l1a.clone();
                            async move {
                                let eligibility_l1 = l1c.clone();
                                let eligibility_hash = oh.clone();
                                let answerable = tokio::task::spawn_blocking(move || eligibility_l1.challenge_answerable(&eligibility_hash))
                                    .await.map_err(|_| "challenge eligibility join failed".to_string())??;
                                if !answerable { return Ok(()); }
                                // Build the answer under the gw lock, then submit off-lock.
                                let answer = {
                                    let gw = app.gw.lock().await;
                                    parse_hex32(&oh).and_then(|h| gw.build_challenge_answer(&h))
                                };
                                let Some((by_rejection, batch_id, proof)) = answer else {
                                    // A batch may settle after the challenge opened. Keep
                                    // this hash pending while discovery continues independently.
                                    return Err("challenge awaiting retained batch".to_string());
                                };
                                tokio::task::spawn_blocking(move || {
                                    if l1c.challenge_answerable(&oh)? {
                                        let tx = l1c.answer_challenge(&oh, batch_id, &proof, by_rejection)?;
                                        println!("[l1] answered inclusion challenge {oh} (batch {batch_id}, rejection={by_rejection}) tx {tx}");
                                    }
                                    Ok(())
                                }).await.map_err(|_| "challenge answer join failed".to_string())?
                            }
                        },
                    ).await;
                    if let Err(e) = result {
                        eprintln!("[l1] challenge scan or pending answer will retry: {e}");
                    }
                }
            }));
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
        // (`None`) has no journal; production refuses settlement without snapshot ACKs.
        let jpath = state_path.as_deref().map(rollback_journal::journal_path);
        let snapshot_notify = snapshot_notify.clone();
        let stop = service_policy.shutdown.clone();
        background.push(tokio::spawn(async move {
            // start the first settle one period out, so it never races the bond's
            // confirmation (tokio's plain `interval` would fire immediately).
            let mut iv = tokio::time::interval_at(
                tokio::time::Instant::now() + clock_settle_period,
                clock_settle_period,
            );
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // FIN-001: gate settle attempts on a backoff deadline. The base cadence is
            // the L1_SETTLE_SECS interval above; after a prove failure the SettleHealth
            // machine dictates the next delay (exponential → HELD cap). `next_attempt`
            // starts open (now) so the first tick attempts normally.
            let mut next_attempt = tokio::time::Instant::now();
            loop {
                if !stop.next_tick(&mut iv).await { break; }
                // FIN-001 Task 4: an operator forced a resume (POST /v1/admin/settlement/resume) —
                // collapse the backoff deadline to now so this tick attempts a settle immediately
                // instead of waiting out the HELD backoff. `swap` consumes the one-shot flag.
                if app
                    .force_settle
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    next_attempt = tokio::time::Instant::now();
                }
                if tokio::time::Instant::now() < next_attempt {
                    continue;
                }
                if let Some(client) = app.prover.clone() {
                    let mut admission = match app.clock_admission.pause(&stop).await {
                        Ok(p) => p, Err(_) => break,
                    };
                    // (A) top up the sequencer bond (as the legacy path does) + read the
                    // on-chain batch count (RPC, no lock). The bond top-up runs BEFORE the
                    // window is sealed, so an underbond settleBatch revert cannot strand the
                    // sequencer past the desync guard.
                    let l1c = l1.clone();
                    let bc = match tokio::task::spawn_blocking(move || -> Result<u64, String> {
                        if let Some(tx) = l1c.ensure_bond()? {
                            println!("[l1] bond topped up: {tx}");
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
                    // Persist the previous resolution before replacing its journal.
                    // This also covers a previous rollback or a committed window whose
                    // asynchronous save has not completed yet.
                    if prod || jpath.is_some() {
                        if let Err(error) = snapshot_now(&app.snapshot_req).await {
                            eprintln!("[recovery] prior window state is not durable: {error}; keeping the journal and skipping seal");
                            continue;
                        }
                    }
                    // Stage 1 and seal share Gw's lock with every snapshot capture.
                    let begun = {
                        let mut gw = app.gw.lock().await;
                        if client.clock_enabled()
                            && gw.window_withdrawals.is_empty()
                            && gw.seq.state.state_root() == gw.last_settled_root
                        { gw.seq.discard_idle_funding_window(); }
                        match begin_journaled_window_settle(
                            &mut gw,
                            bc,
                            jpath.as_deref(),
                            &enclave_seed,
                        ) {
                            Ok(Some(journal)) => {
                                let cand: Vec<[u8; 32]> =
                                    gw.pending_withdrawals.iter().map(|w| w.leaf()).collect();
                                let gate_was_closed =
                                    gw.trading_gate == trading_gate::TradingGate::Closed;
                                Some((journal, cand, gate_was_closed))
                            }
                            Ok(None) => None,
                            Err(error) => {
                                eprintln!("[l1] window settle skipped: {error}");
                                None
                            }
                        }
                    };
                    let Some((mut journal, prune_candidates, gate_was_closed)) = begun else {
                        continue;
                    };
                    if let Some(p) = admission.as_mut() { p.arm(); }
                    let ordered = journal.witness.manifest.ordered.clone();
                    let rejected: Vec<Digest> = journal
                        .witness
                        .manifest
                        .rejected
                        .iter()
                        .map(|(h, _)| *h)
                        .collect();
                    let batch_id = journal.batch_id;
                    let witness_rb = journal.witness.clone();
                    let ww_rb = journal.ww.clone();
                    // Every configured window must persist its post-seal Counter B
                    // before a transaction may be broadcast, including manifest-only
                    // windows and windows with no deposits. Release Gw before waiting.
                    if prod || jpath.is_some() {
                        if let Err(error) = snapshot_now(&app.snapshot_req).await {
                            eprintln!("[l1] window {batch_id}: post-seal snapshot is not durable ({error}); rolling back before proving");
                            {
                                let mut gw = app.gw.lock().await;
                                gw.seq.rollback_window(&witness_rb);
                                gw.rollback_window_withdrawals(ww_rb);
                            }
                            snapshot_notify.notify_one();
                            continue;
                        }
                    }
                    if client.clock_enabled() {
                        let intent = prover_client::prepare_unproved(&journal.witness, &journal.ww);
                        let durable = intent.and_then(|p| {
                            journal.prepared = Some(p);
                            rollback_journal::write(jpath.as_deref().ok_or("clock registration requires journal")?, &journal, &enclave_seed)
                        });
                        if let Err(error) = durable {
                            hold_settlement_for_recovery(&app, format!("clock intent not durable: {error}")).await;
                            break;
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
                            /// SEC-025-D: the block-pinned gate observation taken AFTER
                            /// the receipt (Inconclusive when the gate is already open
                            /// and no read was needed).
                            observation: trading_gate::GateObservation,
                        },
                        ProveFailed(String),
                        ClockFailed(String),
                        SettleFailed {
                            err: String,
                            prepared: prover_client::PreparedSettle,
                        },
                    }
                    let l1c = l1.clone();
                    let jpath_bg = jpath.clone();
                    let deposit_guard_app = app.clone();
                    let clock_mode = client.clock_enabled();
                    let res = tokio::task::spawn_blocking(move || -> SettleAttempt {
                        let prepared = match prover_client::prove_and_prepare(
                            client.as_ref(),
                            &journal.witness,
                            &journal.ww,
                        ) {
                            Ok(p) => p,
                            Err(e) => return if clock_mode { SettleAttempt::ClockFailed(e) } else { SettleAttempt::ProveFailed(e) },
                        };
                        // Persist the prepared outcome before the broadcast continuation.
                        if jpath_bg.is_some() {
                            journal.prepared = Some(prepared.clone());
                        }
                        after_settle_journal(jpath_bg.as_deref(), &journal, &enclave_seed, || {
                            // A01: do not broadcast after an observed RPC/reorg/durability
                            // pause that arrived while the proof was being prepared.
                            if let Err(e) =
                                deposit_guard_app.gw.blocking_lock().deposits.check_ready()
                            {
                                return if clock_mode { SettleAttempt::ClockFailed(e) } else { SettleAttempt::ProveFailed(e) };
                            }
                            match l1c.settle_proved(&prepared.outcome) {
                                Ok(tx) => {
                                    // A receipt may already exist; failed post-send
                                    // corroboration must take the journal recovery path,
                                    // never invent a bond or partially prune claims.
                                    let bond = match l1c.sequencer_bond() {
                                        Ok(bond) => bond,
                                        Err(err) => return SettleAttempt::SettleFailed { err, prepared },
                                    };
                                    let claimed = match l1c.claimed_many(&prune_candidates) {
                                        Ok(claimed) => claimed,
                                        Err(err) => return SettleAttempt::SettleFailed { err, prepared },
                                    };
                                    // SEC-025-D: the launch observation, AFTER the receipt —
                                    // an observation taken before broadcast could never see
                                    // our settle and would waste the whole wait. Skipped once
                                    // the gate is open: the transition only consults it while
                                    // Closed, and the read costs pinned RPC rounds plus a
                                    // bounded wait (`GATE_OBSERVE_WAIT_SECS`).
                                    let observation = if gate_was_closed {
                                        observe_gate(&l1c, batch_id, prepared.outcome.new_root)
                                    } else {
                                        trading_gate::GateObservation::Inconclusive
                                    };
                                    SettleAttempt::Ok {
                                        prepared,
                                        tx,
                                        bond,
                                        claimed,
                                        observation,
                                    }
                                }
                                Err(err) => SettleAttempt::SettleFailed { err, prepared },
                            }
                        })
                        .unwrap_or_else(|error| {
                            let error = format!("stage-2 rollback journal is not durable: {error}");
                            if clock_mode { SettleAttempt::ClockFailed(error) } else { SettleAttempt::ProveFailed(error) }
                        })
                    })
                    .await;
                    match res {
                        Ok(SettleAttempt::Ok {
                            prepared,
                            tx,
                            bond,
                            claimed,
                            observation,
                        }) => {
                            let status = L1Status {
                                settled_root: hex32(&prepared.outcome.new_root),
                                batch_count: batch_id + 1,
                                last_tx: tx.clone(),
                                bond: bond.to_string(),
                                withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
                            };
                            println!(
                                "[l1] window settled root {} batch {} tx {} (withdrawals root {})",
                                status.settled_root,
                                status.batch_count,
                                tx,
                                status.withdrawals_root
                            );
                            {
                                let mut gw = app.gw.lock().await;
                                gw.commit_window_settle(
                                    batch_id,
                                    ordered,
                                    rejected,
                                    prepared,
                                    status,
                                    observation,
                                );
                                gw.prune_claimed_withdrawals(&claimed);
                                // FIN-001: this window settled — clear any failure/HELD state
                                // and (below) resume the normal settle cadence.
                                let was_held = gw.settle_breaker_recovered();
                                if was_held {
                                    println!("[l1] settlement recovered → HEALTHY");
                                }
                            }
                            if let Some(p) = admission.as_mut() {
                                if let Err(error) = snapshot_now(&app.snapshot_req).await {
                                    hold_settlement_for_recovery(&app, format!("clock commit snapshot not durable: {error}")).await;
                                    break;
                                }
                                p.resolved();
                            }
                            next_attempt = tokio::time::Instant::now();
                            // Task 3 (WAL): the journal outlives the commit — boot's STALE
                            // row resolves it. Poke the single snapshot writer instead, so
                            // the committed l1_status/settled_root persists promptly and a
                            // crash inside the old ≤SNAPSHOT_SECS window no longer wedges
                            // the boot continuity check.
                            snapshot_notify.notify_one();
                            let snap = { app.snapshot(&*app.gw.lock().await) };
                            let _ = app.tx.send(
                                serde_json::to_string(&WsMsg::State { state: snap }).unwrap(),
                            );
                        }
                        Ok(SettleAttempt::ClockFailed(e)) => {
                            // A registration may already be mined or pending. Never
                            // merge this immutable window with newer ops on a retry.
                            hold_settlement_for_recovery(&app, format!("clock-bound window unresolved: {e}; retain journal and restart to resume exact witness")).await;
                            break;
                        }
                        Ok(SettleAttempt::ProveFailed(e)) => {
                            eprintln!(
                                "[l1] prove failed: {e} — rolling back (no tx was broadcast)"
                            );
                            // FIN-001: keep the existing rollback, and under the same lock
                            // feed the failure to the circuit breaker so the next attempt is
                            // backed off (exponential → HELD cap). Capture the decision to act
                            // on off-lock.
                            let (action, just_held, n, last) = {
                                let mut gw = app.gw.lock().await;
                                gw.seq.rollback_window(&witness_rb);
                                gw.rollback_window_withdrawals(ww_rb);
                                let (action, just_held) = gw.settle_breaker_failed(e);
                                (
                                    action,
                                    just_held,
                                    gw.settle_health.consecutive_failures(),
                                    gw.settle_health.last_error().unwrap_or("").to_string(),
                                )
                            };
                            next_attempt = tokio::time::Instant::now() + action.delay();
                            // Emit the greppable HELD alert exactly once per episode (the
                            // machine only reports `just_held` on the crossing failure).
                            if just_held {
                                let msg = crate::settle_health::held_alert_message(n, &last);
                                eprintln!("{msg}");
                            }
                            // Task 3 (WAL): keep the journal (boot's SEAL-NEVER-PERSISTED
                            // row resolves it once the rolled-back state persists); poke
                            // the writer so that happens promptly.
                            snapshot_notify.notify_one();
                        }
                        Ok(SettleAttempt::SettleFailed { err, prepared }) => {
                            // All recovery terms name one finalized block hash.
                            let l1c = l1.clone();
                            let recheck =
                                tokio::task::spawn_blocking(move || l1c.settlement_observation())
                                    .await;
                            match recheck {
                                Ok(Ok((now_bc, now_root, bond))) => {
                                    match settle_failure_action(batch_id, now_bc) {
                                        RollAction::RollForward => {
                                            // The tx landed (batchCount advanced), but confirm it
                                            // settled OUR window's root — not a re-sealed one from a
                                            // rare re-seal-then-old-tx-mines interleaving. Compare
                                            // case-insensitively (cast hex casing), like the boot guard.
                                            let our_root = hex32(&prepared.outcome.new_root);
                                            if !now_root.eq_ignore_ascii_case(&our_root) {
                                                // Task 2: HOLD keeps the journal — the operator (and
                                                // Task-3 boot recovery) still needs the rollback inputs.
                                                eprintln!("[l1] settle reported '{err}' and batchCount advanced to {now_bc}, but currentStateRoot {now_root} != our new_root {our_root} — HOLDING; settlement loop stopped until restart reconciliation");
                                                hold_settlement_for_recovery(&app, format!("settlement root mismatch after ambiguous send: {err}; reconcile journal and restart")).await;
                                                break;
                                            } else {
                                                // SEC-025-D: this roll-forward COMMITS, and it is
                                                // exactly where a wind-down finalSettle could be
                                                // mistaken for our settle (batchCount and root are
                                                // the two values it advances identically) — so it
                                                // performs the SAME block-pinned three-way read as
                                                // the clean path, never a shortcut to StaysClosed.
                                                // A failed spawn proves nothing → Inconclusive.
                                                let observation = if gate_was_closed {
                                                    let l1o = l1.clone();
                                                    let our_root = prepared.outcome.new_root;
                                                    tokio::task::spawn_blocking(move || {
                                                        observe_gate(&l1o, batch_id, our_root)
                                                    })
                                                    .await
                                                    .unwrap_or(
                                                        trading_gate::GateObservation::Inconclusive,
                                                    )
                                                } else {
                                                    trading_gate::GateObservation::Inconclusive
                                                };
                                                let status = L1Status {
                                                    settled_root: hex32(&prepared.outcome.new_root),
                                                    batch_count: batch_id + 1,
                                                    last_tx:
                                                        "(recovered: landed despite cast error)"
                                                            .to_string(),
                                                    bond: bond.to_string(),
                                                    withdrawals_root: hex32(
                                                        &prepared.outcome.withdrawals_root,
                                                    ),
                                                };
                                                eprintln!("[l1] settle reported '{err}' but the tx LANDED (batchCount {batch_id}->{now_bc}); rolled forward + committed bookkeeping");
                                                {
                                                    let mut gw = app.gw.lock().await;
                                                    gw.commit_window_settle(
                                                        batch_id,
                                                        ordered,
                                                        rejected,
                                                        prepared,
                                                        status,
                                                        observation,
                                                    );
                                                    // FIN-001: this ambiguous-but-landed settle
                                                    // reached finality — clear any failure/HELD
                                                    // state, exactly like the clean Ok path (else
                                                    // the breaker reports HELD forever after a
                                                    // recovery via this path).
                                                    let was_held = gw.settle_breaker_recovered();
                                                    if was_held {
                                                        println!(
                                                            "[l1] settlement recovered → HEALTHY"
                                                        );
                                                    }
                                                }
                                                // a landed settlement is a success — resume the
                                                // normal settle cadence (mirror the clean Ok arm).
                                                if let Some(p) = admission.as_mut() {
                                                    if let Err(error) = snapshot_now(&app.snapshot_req).await {
                                                        hold_settlement_for_recovery(&app, format!("clock recovered snapshot not durable: {error}")).await;
                                                        break;
                                                    }
                                                    p.resolved();
                                                }
                                                next_attempt = tokio::time::Instant::now();
                                                // Task 3 (WAL): the journal outlives the commit —
                                                // boot's STALE row resolves it; poke the writer so
                                                // the commit persists promptly.
                                                snapshot_notify.notify_one();
                                                let snap = { app.snapshot(&*app.gw.lock().await) };
                                                let _ = app.tx.send(
                                                    serde_json::to_string(&WsMsg::State {
                                                        state: snap,
                                                    })
                                                    .unwrap(),
                                                );
                                            }
                                        }
                                        RollAction::Hold => {
                                            // Task 2: HOLD keeps the journal (rollback inputs preserved
                                            // for the operator / Task-3 boot recovery).
                                            eprintln!("[l1] settle failed AND finalized batchCount is {now_bc} for window {batch_id} — HOLDING; transaction may still land; settlement loop stopped until restart reconciliation");
                                            hold_settlement_for_recovery(&app, format!("unresolved settlement send: {err}; finalized batchCount {now_bc}; reconcile journal and restart")).await;
                                            break;
                                        }
                                    }
                                }
                                _ => {
                                    // Task 2: HOLD keeps the journal.
                                    eprintln!("[l1] settle failed ({err}) and the pinned observation failed — HOLDING; settlement loop stopped until restart reconciliation");
                                    hold_settlement_for_recovery(&app, format!("unresolved settlement send and failed pinned observation: {err}; reconcile journal and restart")).await;
                                    break;
                                }
                            }
                        }
                        Err(join) => {
                            // The worker may have broadcast before panicking. Neither a
                            // failed read nor an unchanged counter proves that impossible.
                            eprintln!("[l1] settle task join error: {join} — HOLDING; preserving journal and stopping settlement until restart reconciliation");
                            hold_settlement_for_recovery(&app, format!("settlement worker failed after possible broadcast: {join}; reconcile journal and restart")).await;
                            break;
                        }
                    }
                }
                // SEC-025-B: the legacy `L1::settle` body that lived here is deleted. It
                // synthesized its commitment via a six-root `publicCommitment` and sent a
                // seven-parameter `settleBatch` — both arities are stale since SEC-019, so
                // it could not produce a resolvable call. `PROVER_URL=mock` covers the
                // prover-free role through the window path above with the correct ABI;
                // with no prover configured the loop settles nothing.
            }
        }));
    }

    let router = build_router_with_policy(app.clone(), prod, service_policy.clone());
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    let addr = listener.local_addr().expect("bound listener address");
    println!("dark-perp gateway listening on http://{addr}  (ws: /ws)");
    let stop = service_policy.shutdown.clone();
    let served = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        signals.wait().await;
        stop.begin();
        println!("[shutdown] admission closed; draining accepted HTTP, sockets and workers");
    })
    .await;
    // Also stop background work if the listener fails independently of a signal.
    service_policy.shutdown.begin();
    let mut clean = served.is_ok();
    if let Err(error) = served {
        eprintln!("[shutdown] server failed: {error}");
    }
    service_policy.wait_for_sockets().await;
    for worker in background {
        if let Err(error) = worker.await {
            clean = false;
            eprintln!("[shutdown] background worker failed: {error}");
        }
    }
    snapshot_stop.begin();
    if let Some(writer) = snapshot_writer {
        if let Err(error) = writer.await {
            clean = false;
            eprintln!("[shutdown] snapshot writer failed: {error}");
        }
    }
    // No handler or worker can now mutate state. Retain the freeze through exit
    // anyway, so future shutdown changes cannot reopen a save-to-exit gap.
    let frozen = if let Some(path) = state_path.as_ref() {
        let capture = final_snapshot(&app, path, enclave_seed, snapshot_serial).await;
        clean &= capture.1;
        println!(
            "[state] shutdown snapshot {}",
            if capture.1 { "saved" } else { "FAILED" }
        );
        Some(capture)
    } else {
        None
    };
    if let Some(l1) = cleanup_l1 {
        l1.cleanup_keystore();
    }
    println!(
        "[shutdown] drain complete — exiting {}",
        if clean { 0 } else { 1 }
    );
    let _frozen = frozen;
    std::process::exit(if clean { 0 } else { 1 });
}

#[cfg(test)]
#[path = "s1_recovery_ws_tests.rs"]
mod s1_recovery_ws_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only deposit fixtures (SEC-025-A Task 3). The register/bind/authorize
    /// preamble was already repeated inline across the deposit tests; the split of
    /// `account_confirm_deposit` into validate + bookkeeping halves needs it again,
    /// so it becomes a named helper instead of a fourth copy.
    impl Gw {
        /// Register a fresh account and bind its `deposit_address` to a fixed
        /// 20-byte payer, returning the API key. The binding skips the SEC-021b
        /// signature ceremony on purpose — these tests exercise the deposit
        /// guards, not the bind path.
        fn account_register_for_test(&mut self) -> [u8; 32] {
            let (key, _owner) = self.register_account(None);
            self.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42u8; 20]);
            key
        }

        /// Authorize a deposit of `amount` for the account's bound payer and
        /// return the tuple a confirm needs: `(from, owner_commit, amount,
        /// deposit_id)`, where `deposit_id` is the live next-in-line id
        /// (`seq.state.consumed_deposit_count`) so the in-order gate passes.
        fn authorize_for_test(
            &mut self,
            key: &[u8; 32],
            amount: u128,
        ) -> ([u8; 20], [u8; 32], u128, u64) {
            let from = self.accounts[key]
                .deposit_address
                .expect("account_register_for_test binds a deposit address");
            let commit = self
                .account_authorize_deposit(key, from, amount)
                .expect("authorization must succeed for a bound payer");
            (from, commit, amount, self.seq.state.consumed_deposit_count)
        }

        /// SEC-025-A Task 4 fixture: drive the REAL `bootstrap_insurance` (a
        /// parallel test-only path would pin nothing). Binds the account's deposit
        /// address to `from` and authorizes the deposit for it FIRST, so of the
        /// driver's guards only the `expected_payer` binding (and the floor) can
        /// refuse — each caller varies exactly one of the two. Uses the
        /// chain-assigned next-in-line id and a unique tx string per call, so
        /// neither the in-order gate nor the dedup guard can mask the guard under
        /// test.
        fn bootstrap_insurance_for_test(
            &mut self,
            key: &[u8; 32],
            expected_payer: [u8; 20],
            from: [u8; 20],
            amount: i128,
        ) -> Result<(), String> {
            self.bootstrap_insurance_capturing(key, expected_payer, from, amount)
                .0
        }

        /// As above, but hands back the request tuple it synthesised so a caller can
        /// REPLAY it. That matters for the resume path: production resumes by re-sending
        /// the SAME request, and a fixture that mints a fresh authorization, a fresh
        /// in-order `deposit_id` and a fresh tx hash every call makes the resume look like
        /// a valid brand-new first leg — which is how the resume's placement ahead of the
        /// request-derived guards went unpinned (review I-2).
        fn bootstrap_insurance_capturing(
            &mut self,
            key: &[u8; 32],
            expected_payer: [u8; 20],
            from: [u8; 20],
            amount: i128,
        ) -> (Result<(), String>, [u8; 32], u128, u64, String) {
            self.accounts.get_mut(key).unwrap().deposit_address = Some(from);
            let amount_u128 = u128::try_from(amount).expect("test amounts are non-negative");
            let commit = self
                .account_authorize_deposit(key, from, amount_u128)
                .expect("authorization must succeed for the just-bound payer");
            let deposit_id = self.seq.state.consumed_deposit_count;
            let tx = hex0x(&csprng_bytes32());
            let r = self.bootstrap_insurance(
                key,
                expected_payer,
                from,
                commit,
                amount_u128,
                deposit_id,
                &tx,
                0,
            );
            (r, commit, amount_u128, deposit_id, tx)
        }

        /// SEC-025-A Task 5 fixture: drive the REAL `commit_window_settle` (a
        /// parallel test-only transition path would pin nothing) with a minimal
        /// `PreparedSettle` and empty manifests. The completion transition reads
        /// only `batch_id` and gateway state, so the roots' exact values are
        /// irrelevant to what its tests pin. The bootstrap tests that use this
        /// wrapper never examine the gate (their demo boots are already Open), so
        /// it fixes the observation to the clean-settle shape.
        fn commit_window_settle_for_test(&mut self, batch_id: u64) {
            self.commit_window_settle_for_test_with(
                batch_id,
                trading_gate::GateObservation::OpensGate,
            );
        }

        /// SEC-025-D Task 4: as above, with the caller choosing the observation,
        /// and the post-state TERMS taken from `test_post_state` when set (live
        /// state otherwise, as before). The override exists so the PREPARED terms
        /// can DIVERGE from live state: `boot_production_for_test` leaves the live
        /// state a genuinely empty production genesis while the prepared terms
        /// read capitalized, so a transition that consulted `seq.state` instead of
        /// the proven post-state fails the opening tests — live state at commit
        /// time has advanced past the proven window and is exactly what the gate
        /// must NOT trust.
        fn commit_window_settle_for_test_with(
            &mut self,
            batch_id: u64,
            observation: trading_gate::GateObservation,
        ) {
            let root = self.seq.state.state_root();
            let (post_mode_is_normal, post_insurance_fund, new_deposit_count) =
                self.test_post_state.unwrap_or((
                    self.seq.state.mode == Mode::Normal,
                    self.seq.state.insurance_fund,
                    self.seq.state.consumed_deposit_count,
                ));
            let prepared = prover_client::PreparedSettle {
                outcome: prover_client::ProveOutcome {
                    prev_root: self.last_settled_root,
                    manifest_hash: [0u8; 32],
                    new_root: root,
                    ordered_root: [0u8; 32],
                    withdrawals_root: [0u8; 32],
                    rejected_root: [0u8; 32],
                    deposits_root: [0u8; 32],
                    wind_down_phase: 0,
                    new_deposit_count,
                    post_mode_is_normal,
                    post_insurance_fund,
                    commitment: [0u8; 32],
                    proof: Vec::new(),
                },
                withdraw_proofs: std::collections::BTreeMap::new(),
            };
            let status = L1Status {
                settled_root: hex32(&root),
                batch_count: batch_id + 1,
                last_tx: "(test)".into(),
                bond: "0".into(),
                withdrawals_root: hex32(&[0u8; 32]),
            };
            self.commit_window_settle(
                batch_id,
                Vec::new(),
                Vec::new(),
                prepared,
                status,
                observation,
            );
        }

        /// SEC-025-D Task 4: pin the post-state terms the next test commit's
        /// outcome carries — `(mode_is_normal, insurance_fund, deposit_count)` —
        /// independently of live state. Sticky until set again.
        fn set_prepared_post_state_for_test(
            &mut self,
            mode_normal: bool,
            insurance: i128,
            deposits: u64,
        ) {
            self.test_post_state = Some((mode_normal, insurance, deposits));
        }

        /// SEC-025-D Task 4: a production-genesis gateway — gate Closed, nothing
        /// minted — whose PREPARED post-state terms default to capitalized while
        /// the LIVE state stays empty (see `commit_window_settle_for_test_with`
        /// for why the divergence is the point). The default lets the tests that
        /// are NOT about the predicate isolate the observation term; the
        /// predicate-half tests override the terms explicitly.
        fn boot_production_for_test() -> Self {
            let mut gw = Self::boot_with(GenesisMode::Production);
            gw.set_prepared_post_state_for_test(true, bootstrap::MIN_BOOTSTRAP_INSURANCE, 1);
            gw
        }
    }

    fn gate_test_order() -> OrderReq {
        OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            nonce: None,
            signature: None,
            ..Default::default()
        }
    }

    /// SEC-025-D: every ingress path refuses while the gate is closed — asserted per
    /// path, because three of the four do NOT go through the HTTP order handler and a
    /// gate placed only there would leave them live.
    #[test]
    fn every_ingress_path_refuses_while_the_gate_is_closed() {
        let mut gw = Gw::boot_production_for_test();
        assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
        let key = gw.account_register_for_test();
        let req = gate_test_order();

        // `WReceipt`/`WEvent` are not `Debug`, so `expect_err` will not compile here.
        let e1 = match gw.account_place_order(&key, &req) {
            Ok(_) => panic!("/v1/orders must refuse while the gate is closed"),
            Err(e) => e,
        };
        assert!(e1.contains("launch gate"), "wrong refusal: {e1}");
        let e2 = match gw.place_order(&req) {
            Ok(_) => panic!("the legacy path must refuse too"),
            Err(e) => e,
        };
        assert!(e2.contains("launch gate"), "wrong refusal: {e2}");
        let e3 = gw
            .simulate_adl()
            .expect_err("simulate_adl must refuse on its OWN guard");
        assert!(e3.contains("launch gate"), "wrong refusal: {e3}");

        // The refusal must be distinguishable from close-only, which is a different
        // condition with a different remedy.
        assert!(
            !e1.contains("close-only mode"),
            "must not read as a wind-down"
        );
    }

    /// The house-MM injector pushes straight into the seal vector without touching
    /// `accept_order`. Asserted DIRECTLY rather than via "no taker exists", because the
    /// latter passes even if the injector is completely ungated.
    #[test]
    fn the_house_mm_injector_stages_no_counter_order_while_the_gate_is_closed() {
        let mut gw = Gw::boot();
        gw.trading_gate = trading_gate::TradingGate::Open;
        let req = gate_test_order();
        gw.place_order(&req)
            .expect("demo order accepted while open");
        gw.tick();
        let opened = gw
            .seq
            .state
            .position(&gw.mm.owner, 0)
            .map(|p| p.is_open())
            .unwrap_or(false);
        assert!(
            opened,
            "fixture precondition: with the gate OPEN the injector must actually fill \
             the MM — otherwise the closed case below proves nothing"
        );

        let mut gw2 = Gw::boot();
        gw2.trading_gate = trading_gate::TradingGate::Open;
        gw2.place_order(&req).expect("accepted");
        gw2.trading_gate = trading_gate::TradingGate::Closed;
        gw2.tick();
        let opened2 = gw2
            .seq
            .state
            .position(&gw2.mm.owner, 0)
            .map(|p| p.is_open())
            .unwrap_or(false);
        assert!(
            !opened2,
            "a closed gate must stop the injector itself, not merely starve it of takers"
        );
    }

    /// `tick()` has TWO injectors — the demo-order arm and the /v1-account arm. The first
    /// enforcement pass gated only the demo one and every test stayed green, so this
    /// covers the other explicitly rather than trusting that "the injector" is singular.
    #[test]
    fn the_v1_account_injector_stages_no_counter_order_while_the_gate_is_closed() {
        let mut gw = Gw::boot();
        gw.trading_gate = trading_gate::TradingGate::Open;
        let key = gw.account_register_for_test();
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let req = gate_test_order();
        gw.account_place_order(&key, &req)
            .expect("accepted while open");
        gw.tick();
        assert!(
            gw.seq
                .state
                .position(&gw.mm.owner, 0)
                .map(|p| p.is_open())
                .unwrap_or(false),
            "fixture precondition: the /v1 injector must actually fill the MM while OPEN"
        );

        let mut gw2 = Gw::boot();
        gw2.trading_gate = trading_gate::TradingGate::Open;
        let key2 = gw2.account_register_for_test();
        gw2.account_deposit(&key2, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw2.account_place_order(&key2, &req).expect("accepted");
        gw2.trading_gate = trading_gate::TradingGate::Closed;
        gw2.tick();
        assert!(
            !gw2.seq
                .state
                .position(&gw2.mm.owner, 0)
                .map(|p| p.is_open())
                .unwrap_or(false),
            "a closed gate must stop the /v1 injector too"
        );
    }

    /// SEC-025-A Task 3: the deposit guards and their success bookkeeping must be
    /// separable, because the insurance-bootstrap path (Task 4) reuses the guards
    /// around a DIFFERENT funding op. The validation half must be pure (safe to
    /// call twice), and only the bookkeeping half may consume the one-shot state.
    #[test]
    fn validated_deposit_checks_without_mutating_and_bookkeeping_is_separable() {
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();
        let (from, commit, amount, id) = gw.authorize_for_test(&key, 5_000_000);

        // The validation half must be pure: calling it twice must succeed twice, because
        // nothing it does can consume the authorization or advance a counter.
        let before = gw.accounts.get(&key).unwrap().deposit_counter;
        let v1 = gw
            .validated_deposit(&key, from, commit, amount, id, "0xtx", 0)
            .expect("first validate");
        let v2 = gw
            .validated_deposit(&key, from, commit, amount, id, "0xtx", 0)
            .expect("second validate must also succeed — validation must not mutate");
        assert_eq!(v1.note_blind, v2.note_blind);
        assert_eq!(gw.accounts.get(&key).unwrap().deposit_counter, before);
        assert!(gw
            .accounts
            .get(&key)
            .unwrap()
            .deposit_authorizations
            .contains_key(&commit));
        assert!(!gw.processed_deposit_txs.contains("0xtx"));

        // The bookkeeping half, applied once, must consume all three.
        gw.commit_deposit_bookkeeping(&key, &commit, "0xtx");
        assert_eq!(gw.accounts.get(&key).unwrap().deposit_counter, before + 1);
        assert!(!gw
            .accounts
            .get(&key)
            .unwrap()
            .deposit_authorizations
            .contains_key(&commit));
        assert!(gw.processed_deposit_txs.contains("0xtx"));

        // And the guards must now refuse a replay of the same tx.
        assert!(gw
            .validated_deposit(&key, from, commit, amount, id, "0xtx", 0)
            .is_err());
    }

    #[test]
    fn the_tx_dedup_guard_refuses_a_replayed_hash_on_its_own() {
        // ISOLATES tx dedup. The sibling test above ends by replaying the SAME tx with the
        // SAME ownerCommit — but `commit_deposit_bookkeeping` removes the authorization too,
        // so that assertion is satisfied by the AUTHORIZATION guard and survives deleting
        // the dedup check entirely (mutation-verified). Here a FRESH authorization exists,
        // so every other guard passes and only dedup can refuse.
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();

        let (from, commit_a, amount, id) = gw.authorize_for_test(&key, 5_000_000);
        gw.validated_deposit(&key, from, commit_a, amount, id, "0xreplayed", 0)
            .expect("first deposit validates");
        gw.commit_deposit_bookkeeping(&key, &commit_a, "0xreplayed");

        // A second, DIFFERENT authorization — its blind is present and reproduces its own
        // commit, so the SEC-019 guard is satisfied.
        let (_, commit_b, _, _) = gw.authorize_for_test(&key, 5_000_000);
        assert_ne!(commit_a, commit_b, "authorize must mint a fresh blind");

        // `ValidatedDeposit` is not `Debug`, so `expect_err` will not compile here.
        let err = match gw.validated_deposit(&key, from, commit_b, amount, id, "0xreplayed", 0) {
            Ok(_) => panic!("an already-credited tx hash must be refused"),
            Err(e) => e,
        };
        assert!(
            err.contains("already credited"),
            "must fail on tx dedup, not on some other guard: {err}"
        );
    }

    #[test]
    fn the_bootstrap_driver_refuses_a_non_operator_payer() {
        // THE central security property of this piece — and note what it does NOT claim.
        // This is an ENDPOINT property, not a protocol invariant: `FundInsurance` carries no
        // payer and the guest validates with `expected_owner = None`, so a compromised
        // sequencer can spend any custodied note directly. This test pins the endpoint.
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();
        let operator = [0xAAu8; 20];
        let attacker = [0xBBu8; 20];
        let amount = bootstrap::MIN_BOOTSTRAP_INSURANCE;
        let ins_before = gw.seq.state.insurance_fund;
        let count_before = gw.seq.state.consumed_deposit_count;

        // A deposit whose on-chain payer is NOT the configured operator must be refused even
        // though both credentials are valid — the admin key and the account key are present,
        // and only the payer differs.
        let err = gw
            .bootstrap_insurance_for_test(&key, operator, attacker, amount)
            .expect_err("a non-operator payer must be refused");
        assert!(
            err.contains("INSURANCE_OPERATOR_ADDRESS"),
            "the refusal must name the binding that failed: {err}"
        );
        // Refused before ANY mutation: no note minted, no deposit consumed.
        assert_eq!(gw.seq.state.insurance_fund, ins_before);
        assert_eq!(gw.seq.state.consumed_deposit_count, count_before);
        assert_eq!(gw.bootstrap, bootstrap::Bootstrap::NotStarted);

        // The same call with the operator as payer succeeds, proving the refusal above was
        // the payer binding and not some unrelated precondition.
        gw.bootstrap_insurance_for_test(&key, operator, operator, amount)
            .expect("the configured operator's own deposit must be accepted");
        assert_eq!(gw.seq.state.insurance_fund, ins_before + amount);
    }

    #[test]
    fn a_below_floor_bootstrap_is_refused_before_either_leg_applies() {
        // Without this, the one-shot is spent on dust, 025-D's launch gate stays closed,
        // and NEITHER piece has a retry path — an unlaunchable deployment.
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();
        let operator = [0xAAu8; 20];
        let before_insurance = gw.seq.state.insurance_fund;
        let before_count = gw.seq.state.consumed_deposit_count;

        // `expected_payer == from`, so the payer binding is satisfied and the amount
        // is the only thing the refusal can be about.
        let err = gw
            .bootstrap_insurance_for_test(
                &key,
                operator,
                operator,
                bootstrap::MIN_BOOTSTRAP_INSURANCE - 1,
            )
            .expect_err("a below-floor amount must be refused");
        assert!(
            err.contains("below the minimum"),
            "must fail on the floor check, not the one-shot (whose message also \
             says \"minimum\"): {err}"
        );

        // "Before either leg" is the load-bearing part: no deposit may have been consumed.
        assert_eq!(gw.seq.state.insurance_fund, before_insurance);
        assert_eq!(gw.seq.state.consumed_deposit_count, before_count);
        assert_eq!(gw.bootstrap, bootstrap::Bootstrap::NotStarted);
    }

    #[test]
    fn a_successful_bootstrap_raises_insurance_without_raising_external_in_twice() {
        // The SEC-024 property, re-pinned at this new call site: the Deposit leg raises
        // `external_in` exactly once; the FundInsurance leg is a TRANSFER and must not
        // touch it at all.
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();
        let operator = [0xAAu8; 20];
        let ext_before = gw.seq.state.external_in;
        let ins_before = gw.seq.state.insurance_fund;
        let amount = bootstrap::MIN_BOOTSTRAP_INSURANCE;

        gw.bootstrap_insurance_for_test(&key, operator, operator, amount)
            .expect("bootstrap");

        assert_eq!(gw.seq.state.external_in, ext_before + amount);
        assert_eq!(gw.seq.state.insurance_fund, ins_before + amount);
        assert!(matches!(
            gw.bootstrap,
            bootstrap::Bootstrap::InsuranceApplied { .. }
        ));
    }

    #[test]
    fn the_one_shot_reopens_only_when_the_fund_falls_below_the_floor() {
        // Pins the one-shot's exact key — `Complete` AND a fund still meeting the
        // floor — and the deliberate reopen when bad debt later drains the fund (the
        // KNOWN TENSION named in `bootstrap_insurance`: an admin+payer-gated
        // recapitalization path, not a bug). An ENDPOINT property only, like
        // everything here.
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();
        let operator = [0xAAu8; 20];
        let amount = bootstrap::MIN_BOOTSTRAP_INSURANCE;
        gw.bootstrap_insurance_for_test(&key, operator, operator, amount)
            .expect("first bootstrap");
        // The InsuranceApplied → Complete transition lands at settle commit (a later
        // task); force the record so the refusal that reads it is reachable.
        gw.bootstrap = bootstrap::Bootstrap::Complete;

        let err = gw
            .bootstrap_insurance_for_test(&key, operator, operator, amount)
            .expect_err("Complete over a floor-meeting fund must refuse a second spend");
        assert!(
            err.contains("already completed"),
            "the refusal must be the one-shot, not some other guard: {err}"
        );

        // Simulate bad debt draining the fund below the floor — conservation-neutrally
        // (insurance → treasury is an internal transfer), because the engine asserts
        // `conservation_holds` after every subsequent op.
        let drain = gw.seq.state.insurance_fund - (bootstrap::MIN_BOOTSTRAP_INSURANCE - 1);
        gw.seq.state.insurance_fund -= drain;
        gw.seq.state.treasury += drain;

        gw.bootstrap_insurance_for_test(&key, operator, operator, amount)
            .expect("a drained fund must reopen the gated recapitalization path");
        assert!(gw.seq.state.insurance_fund >= bootstrap::MIN_BOOTSTRAP_INSURANCE);
    }

    #[test]
    fn a_second_leg_failure_records_deposit_applied_with_the_minted_notes_identity() {
        // Task-4 review I-1, the true half: `Bootstrap::DepositApplied` is written ONLY
        // when the operator note really was minted, and from the values the engine was
        // fed. Leg 2 (`FundInsurance`) is forced to fail by an insurance fund one
        // `amount` short of i128 overflow — `op_fund_insurance` checked_adds BEFORE any
        // mutation, so the leg-1 note stays live. The inflation is conservation-neutral
        // (insurance ↔ treasury is an internal transfer), as in the reopen test above.
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();
        let operator = [0xAAu8; 20];
        let amount = bootstrap::MIN_BOOTSTRAP_INSURANCE;
        let bump = (i128::MAX - amount + 1) - gw.seq.state.insurance_fund;
        gw.seq.state.insurance_fund += bump;
        gw.seq.state.treasury -= bump;

        // The note identity the record must carry, derived INDEPENDENTLY here (the
        // account wallet's keys and the 0xB0 ‖ deposit_counter blind): a record written
        // from anything but the real mint fails these comparisons.
        let (owner, spend_key) = {
            let w = gw.accounts.get(&key).unwrap().wallet;
            (w.owner, w.spend_key)
        };
        let dc = gw.accounts.get(&key).unwrap().deposit_counter;
        let mut note_blind = [0xB0u8; 32];
        note_blind[..8].copy_from_slice(&dc.to_le_bytes());
        let cm = Note::new(owner, 0, amount, note_blind).commitment::<Keccak256>();
        let deposit_id = gw.seq.state.consumed_deposit_count;

        let err = gw
            .bootstrap_insurance_for_test(&key, operator, operator, amount)
            .expect_err("an overflowing insurance fund must fail the second leg");
        assert!(
            err.contains("AFTER the operator note was minted"),
            "must fail on leg 2, not leg 1: {err}"
        );
        // The note really is live — the record below asserts a fact, not a hope.
        assert!(gw.seq.state.notes.contains_key(&cm));
        assert_eq!(
            gw.bootstrap,
            bootstrap::Bootstrap::DepositApplied {
                note_commitment: cm,
                spend_key,
                deposit_id,
            },
            "the record must carry the minted note's identity and the consumed id"
        );
    }

    #[test]
    fn a_first_leg_refusal_leaves_the_bootstrap_record_untouched() {
        // Task-4 review I-1, the false half: when leg 1 refuses, NOTHING was applied
        // (SEC-026 failure atomicity), so the record must not move — writing it would
        // persist a note that was never minted, and a pre-existing `DepositApplied`
        // would have THIS attempt's deposit_id swapped in while the live note came from
        // the old one. Leg 1 is forced to fail by pre-minting the exact commitment the
        // bootstrap would mint (same owner/amount and the 0xB0 ‖ deposit_counter
        // blind), so `mint_note` refuses with DuplicateCommitment (SEC-026 historical
        // uniqueness) while every gateway-level guard still passes.
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();
        let operator = [0xAAu8; 20];
        let amount = bootstrap::MIN_BOOTSTRAP_INSURANCE;
        let owner = gw.accounts.get(&key).unwrap().wallet.owner;
        let dc = gw.accounts.get(&key).unwrap().deposit_counter;
        let mut note_blind = [0xB0u8; 32];
        note_blind[..8].copy_from_slice(&dc.to_le_bytes());
        gw.seq
            .apply(&BatchOp::Deposit {
                owner,
                asset_id: 0,
                amount,
                blinding: note_blind,
                from: [0x11u8; 20],
                deposit_id: gw.seq.state.consumed_deposit_count,
                deposit_blind: [0u8; 32],
            })
            .expect("pre-minting the colliding note must succeed");

        // From NotStarted, a leg-1 refusal must leave it NotStarted.
        let err = gw
            .bootstrap_insurance_for_test(&key, operator, operator, amount)
            .expect_err("the duplicate commitment must refuse leg 1");
        assert!(
            err.contains("nothing applied"),
            "must fail on leg 1, not leg 2: {err}"
        );
        assert_eq!(gw.bootstrap, bootstrap::Bootstrap::NotStarted);

        // And from a pre-existing `DepositApplied` (an earlier attempt whose note IS
        // live): the record must survive byte-identical — above all its deposit_id.
        let sentinel = bootstrap::Bootstrap::DepositApplied {
            note_commitment: [7u8; 32],
            spend_key: [9u8; 32],
            deposit_id: 3,
        };
        gw.bootstrap = sentinel.clone();
        gw.bootstrap_insurance_for_test(&key, operator, operator, amount)
            .expect_err("still a duplicate — leg 1 refuses again");
        assert_eq!(
            gw.bootstrap, sentinel,
            "a leg-1 refusal must not overwrite an earlier attempt's record"
        );
    }

    #[test]
    fn completion_requires_the_window_carrying_the_second_leg() {
        // The defect this whole four-state design exists to prevent: if the DEPOSIT's window
        // commits while FundInsurance has not applied, completion must NOT be recorded.
        let mut gw = Gw::boot();
        gw.bootstrap = bootstrap::Bootstrap::DepositApplied {
            note_commitment: [1u8; 32],
            spend_key: [2u8; 32],
            deposit_id: 0,
        };
        gw.commit_window_settle_for_test(0);
        assert_eq!(
            gw.bootstrap,
            bootstrap::Bootstrap::DepositApplied {
                note_commitment: [1u8; 32],
                spend_key: [2u8; 32],
                deposit_id: 0
            },
            "a deposit-only window must never complete the bootstrap"
        );

        // And a DIFFERENT window committing must not complete it either.
        gw.bootstrap = bootstrap::Bootstrap::InsuranceApplied { window_id: 7 };
        gw.commit_window_settle_for_test(6);
        assert_eq!(
            gw.bootstrap,
            bootstrap::Bootstrap::InsuranceApplied { window_id: 7 }
        );

        // Only the matching window completes it.
        gw.commit_window_settle_for_test(7);
        assert_eq!(gw.bootstrap, bootstrap::Bootstrap::Complete);
    }

    #[test]
    fn a_fund_above_the_floor_alone_does_not_complete_the_bootstrap() {
        // `insurance_fund` moves for reasons that are not a bootstrap — the per-fill cut
        // and liquidation penalties both credit it. The RECORD must not follow.
        //
        // The earlier version of this test only added to an `i128` and asserted a
        // different field was unchanged, which the language guarantees; it executed no
        // production code and could not fail under any mutation. This version drives the
        // REAL commit path with a fund far above the floor, so it dies if completion is
        // ever keyed on the balance instead of on the second leg's window id.
        let mut gw = Gw::boot();
        gw.bootstrap = bootstrap::Bootstrap::NotStarted;
        gw.seq.state.insurance_fund += bootstrap::MIN_BOOTSTRAP_INSURANCE * 10;
        gw.commit_window_settle_for_test(0);
        assert_eq!(
            gw.bootstrap,
            bootstrap::Bootstrap::NotStarted,
            "a fund above the floor must not complete a bootstrap that never happened"
        );
    }

    #[test]
    fn completion_requires_the_floor_not_just_the_window_id() {
        // The transition's second conjunct. 025-D's launch gate reads the SAME floor,
        // so completing on the id alone would hand it a `Complete` record over a fund
        // that bad debt drained below adequacy between apply and settle.
        let mut gw = Gw::boot();
        gw.bootstrap = bootstrap::Bootstrap::InsuranceApplied { window_id: 3 };
        // Drain conservation-neutrally (insurance → treasury is an internal transfer),
        // as the reopen test above does.
        let drain = gw.seq.state.insurance_fund - (bootstrap::MIN_BOOTSTRAP_INSURANCE - 1);
        gw.seq.state.insurance_fund -= drain;
        gw.seq.state.treasury += drain;

        gw.commit_window_settle_for_test(3);
        assert_eq!(
            gw.bootstrap,
            bootstrap::Bootstrap::InsuranceApplied { window_id: 3 },
            "a below-floor fund must not complete, even on the matching window"
        );
    }

    #[test]
    fn a_resume_from_deposit_applied_applies_only_the_second_leg() {
        // Task 5's resume path: from `DepositApplied` the driver must apply
        // `FundInsurance` ALONE — never a second `Deposit` (which would fail
        // DepositOutOfOrder anyway: the first leg already advanced
        // `consumed_deposit_count`). Reach `DepositApplied` the only way production
        // can — a REAL leg-2 failure (fund one `amount` short of i128 overflow, as in
        // the record-writing test above), so the recorded note is genuinely live.
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();
        let operator = [0xAAu8; 20];
        let amount = bootstrap::MIN_BOOTSTRAP_INSURANCE;
        let bump = (i128::MAX - amount + 1) - gw.seq.state.insurance_fund;
        gw.seq.state.insurance_fund += bump;
        gw.seq.state.treasury -= bump;
        let (r, commit, amount_u128, deposit_id, tx) =
            gw.bootstrap_insurance_capturing(&key, operator, operator, amount);
        r.expect_err("an overflowing insurance fund must fail the second leg");
        let bootstrap::Bootstrap::DepositApplied {
            note_commitment, ..
        } = gw.bootstrap
        else {
            panic!("a leg-2 failure must record DepositApplied");
        };
        // Un-inflate (conservation-neutrally) so the resume's transfer can succeed.
        gw.seq.state.insurance_fund -= bump;
        gw.seq.state.treasury += bump;
        assert!(
            gw.seq.state.notes.contains_key(&note_commitment),
            "the recorded note must be live before the resume"
        );

        let count_before = gw.seq.state.consumed_deposit_count;
        let ext_before = gw.seq.state.external_in;
        let ins_before = gw.seq.state.insurance_fund;
        let expected_window = gw.seq.state.next_batch_id;
        // REPLAY the original request, which is what production re-sends. A fresh
        // authorization/id/tx here would make this a valid brand-new first leg and would
        // pass even if the resume arm sat BEHIND the request-derived guards — where it
        // would be unreachable in production, because this deposit_id is already consumed.
        gw.bootstrap_insurance(
            &key,
            operator,
            operator,
            commit,
            amount_u128,
            deposit_id,
            &tx,
            0,
        )
        .expect("a resume from DepositApplied must apply the second leg alone");

        // The load-bearing assertion: no second `Deposit` — the id counter (and the
        // deposit-stream accounting) must not move on a resume.
        assert_eq!(
            gw.seq.state.consumed_deposit_count, count_before,
            "a resume must not consume a deposit id"
        );
        assert_eq!(
            gw.seq.state.external_in, ext_before,
            "a resume must not re-credit external value"
        );
        // The second leg really applied: the note was spent into the fund …
        assert_eq!(gw.seq.state.insurance_fund, ins_before + amount);
        assert!(
            !gw.seq.state.notes.contains_key(&note_commitment),
            "the resume must spend the recorded note"
        );
        // … and the record now waits on the window the resume applied into.
        assert_eq!(
            gw.bootstrap,
            bootstrap::Bootstrap::InsuranceApplied {
                window_id: expected_window
            }
        );
    }

    /// SEC-025-B break-4 fixtures. The manifest-only tests need an order that is
    /// genuinely ACCEPTED and RESTS (it lands in `ordered` with no fill and no
    /// rejection). The distinction matters: a REJECTED order also lands in the
    /// window manifest, so a broken fixture would still satisfy
    /// `window_has_pending_manifest()` while silently testing the wrong path — and
    /// an order that accidentally FILLS would move the engine root and stop
    /// exercising break 4 at all. The tests' precondition asserts pin both.
    mod tests_support {
        use super::*;

        /// A booted gateway whose market-0 oracle is re-signed at a small
        /// deterministic publish time (500 ms), so a batch sealed at `now_ms =
        /// 1_000` clears the freshness gate (`publish_time ∈ [now − staleness,
        /// now]`). Boot pins the transcript at the REAL wall clock — the future of
        /// `1_000` — which `validate` rejects as Stale, and a stale oracle turns
        /// the resting order into a REJECTED one (`OracleUnavailable`), defeating
        /// the fixture.
        pub fn gw_with_market() -> Gw {
            let mut gw = Gw::boot();
            let px = gw.seq.oracle(0).expect("boot pins a market-0 oracle").price;
            let t = oracle_of(px, 500, 0, &gw.oracle_signer);
            gw.seq.set_oracle(0, t);
            gw
        }

        /// A Gtc buy at HALF the oracle mark from the boot-funded demo user
        /// (wallet seed `[1u8; 32]`, exactly boot's `user`): it clears the
        /// pre-trade margin gate (boot funds ≫ the initial margin on 0.1 base) but
        /// crosses nothing in an empty book, so it RESTS — its hash enters the
        /// window manifest while engine state (and thus the state root) is
        /// untouched: the book is matcher state, not `State`.
        pub fn resting_order(nonce: u64) -> Order {
            let user = Wallet::from_seed([1u8; 32]);
            let px = usd(MARKETS[0].seed);
            mk_order(
                user.owner,
                0,
                Side::Buy,
                SIZE_SCALE / 10,
                px / 2,
                nonce,
                TimeInForce::Gtc,
                false,
            )
        }

        /// `resting_order`'s evil twin for the `window_rejected` arm: the same Gtc
        /// buy at half the mark, but sized so its initial margin exceeds the demo
        /// user's boot funds by orders of magnitude — the pre-trade gate REJECTS it
        /// (`InsufficientMargin`) before matching, so it fills nothing, rests
        /// nowhere, and moves no state. A margin rejection is used (over the
        /// equally reachable stale-oracle one) precisely because it is
        /// distinguishable: under `gw_with_market`'s freshly re-signed oracle an
        /// `OracleUnavailable` rejection can only mean the fixture regressed, so
        /// the dependent test asserts the REASON, not just that a rejection exists.
        pub fn oversized_order(nonce: u64) -> Order {
            let user = Wallet::from_seed([1u8; 32]);
            let px = usd(MARKETS[0].seed);
            mk_order(
                user.owner,
                0,
                Side::Buy,
                SIZE_SCALE * 1_000_000,
                px / 2,
                nonce,
                TimeInForce::Gtc,
                false,
            )
        }
    }

    // ── SEC-025-C: a production genesis mints nothing ────────────────────────

    /// SEC-025-C: a production genesis must mint nothing. Boot fabricated seven
    /// unbacked deposits (MM + user per market across 3 markets, plus an LP-demo
    /// grant), each folding a sentinel leaf into `consumed_deposit_tip`. Every settle
    /// then submitted `newDepositCount = 7+` against a vault whose `depositCount` is 0,
    /// and `_requireDepositPrefix` reverted BEFORE the proof was verified.
    #[test]
    fn production_genesis_mints_nothing() {
        let gw = Gw::boot_with(GenesisMode::Production);
        let s = &gw.seq.state;
        assert_eq!(s.consumed_deposit_count, 0, "no deposits at genesis");
        assert_eq!(s.consumed_deposit_tip, [0u8; 32], "untouched deposit chain");
        assert_eq!(s.insurance_fund, 0, "no seeded insurance");
        assert_eq!(s.external_in, 0, "no external value asserted");
        assert!(s.notes.is_empty(), "no notes");
        assert!(s.positions.is_empty(), "no positions");
        assert_eq!(s.markets.len(), MARKETS.len(), "markets ARE registered");
    }

    /// The pair a fresh vault expects. `CollateralVault.sol:59` states that
    /// `depositTipAt[0]` is never written and the mapping default `bytes32(0)` IS the
    /// genesis tip, so this is the exact tuple `_requireDepositPrefix(0, 0)` accepts.
    #[test]
    fn production_genesis_matches_a_fresh_vault_prefix() {
        let gw = Gw::boot_with(GenesisMode::Production);
        assert_eq!(
            (
                gw.seq.state.consumed_deposit_tip,
                gw.seq.state.consumed_deposit_count
            ),
            ([0u8; 32], 0u64),
        );
    }

    /// The demo path is untouched — explicitly demo-scoped, not a global expectation.
    #[test]
    fn demo_genesis_is_still_funded() {
        let gw = Gw::boot();
        let s = &gw.seq.state;
        // + 2, not + 1, since SEC-024: the insurance seed is no longer a mint — it
        // enters as its own boot `Deposit` (blind 0x39) consumed by `FundInsurance`,
        // so it counts in `consumed_deposit_count` like every other demo credit.
        assert_eq!(
            s.consumed_deposit_count,
            (MARKETS.len() as u64) * 2 + 2,
            "MM + user per market, plus the LP-demo grant and the insurance-seed deposit"
        );
        assert!(s.insurance_fund > 0, "demo seeds insurance");
        assert!(
            !s.notes.is_empty() || !s.positions.is_empty(),
            "demo has value"
        );
    }

    /// The window must open from genesis with nothing staged, or the first settle's
    /// witness pre-state would not be the deployed GENESIS_ROOT. Probes BOTH window
    /// accumulators: the ordered/rejected manifest AND the op-log — boot funding
    /// stages `Deposit` ops in `window_ops`, never the manifest, so the manifest
    /// probe alone could not see ops staged after `seal_genesis_baseline`.
    #[test]
    fn production_genesis_leaves_no_staged_ops() {
        let gw = Gw::boot_with(GenesisMode::Production);
        assert!(
            !gw.seq.window_has_pending_manifest(),
            "no manifest content at genesis"
        );
        assert!(
            !gw.seq.window_has_staged_ops(),
            "no window ops staged at genesis"
        );
    }

    // ── SEC-025-C Task 2: unbacked minting is refused at every call site ─────

    /// SEC-025-C: unbacked minting must be refused in production AT THE CALL SITE,
    /// not merely unrouted. `/v1/lp/*` was mounted in production and `simulate_adl`
    /// sits behind route-mounting alone — both reach `fund_amount_unbacked` and would
    /// re-corrupt `consumed_deposit_tip` after a clean genesis.
    #[test]
    fn unbacked_funding_is_refused_in_production() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let before_root = gw.seq.state.state_root();
        let before_ops = gw.seq.window_op_count();
        let before_archive = gw.archive.len();
        let w = Wallet::from_seed([9u8; 32]);

        let err = fund_amount_unbacked(
            &mut gw.seq,
            &mut gw.archive,
            &w,
            0,
            1_000 * QUOTE_SCALE,
            [0x99u8; 32],
            /* prod */ true,
        )
        .expect_err("production must refuse an unbacked mint");
        assert!(err.contains("production"), "error names the reason: {err}");

        // `state_root()` alone is NOT sufficient here: this fn takes &mut Sequencer
        // and &mut NoteArchive, and state_root() commits only perp_core::State — a
        // buggy rejected call could mutate the sequencer's op log or the archive
        // invisibly.
        assert_eq!(
            gw.seq.state.state_root(),
            before_root,
            "engine state untouched"
        );
        assert_eq!(gw.seq.window_op_count(), before_ops, "no op staged");
        assert_eq!(gw.archive.len(), before_archive, "no archive record");
    }

    /// SEC-024: the insurance-seeding funnel is an unbacked credit too, and
    /// `simulate_adl`'s refill reaches it with the live `prod` flag — so its
    /// refusal must hold AT THE CALL SITE like every other unbacked path.
    #[test]
    fn unbacked_insurance_seeding_is_refused_in_production() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let before_root = gw.seq.state.state_root();
        let before_ops = gw.seq.window_op_count();

        let err = seed_insurance_unbacked(
            &mut gw.seq,
            [0x1Cu8; 32],
            1_000 * QUOTE_SCALE,
            [0x1Du8; 32],
            /* prod */ true,
        )
        .expect_err("production must refuse an unbacked insurance seed");
        assert!(err.contains("production"), "error names the reason: {err}");

        assert_eq!(
            gw.seq.state.state_root(),
            before_root,
            "engine state untouched"
        );
        assert_eq!(gw.seq.window_op_count(), before_ops, "no op staged");
        assert_eq!(gw.seq.state.insurance_fund, 0, "no insurance minted");
    }

    /// A production LP transfer is the live corruption path today (`/v1/lp/*` is
    /// mounted in production, outside the demo-only route block).
    ///
    /// FIXTURE NOTE: this boots the FUNDED demo genesis and then flips `prod`. On a
    /// bare production genesis `from` has no market-0 balance, so the transfer would
    /// be refused by the BALANCE check and this test would keep passing with the
    /// SEC-025-C guard deleted — a fixture that tests nothing. Funded, the guard is
    /// the only thing standing between this call and a mint (pinned by the
    /// precondition assert), which is exactly what the Step-5 mutation check needs.
    #[test]
    fn a_production_lp_transfer_is_refused() {
        let mut gw = Gw::boot();
        gw.prod = true;
        let user = gw.user;
        let mm = gw.mm;
        let value = 100 * QUOTE_SCALE;
        assert!(
            value <= gw.market_free_of(&user.owner, 0),
            "precondition: the transfer must clear the balance gate, or the refusal \
             below could come from the wrong check"
        );
        let before_root = gw.seq.state.state_root();
        let before_ops = gw.seq.window_op_count();
        let before_count = gw.seq.state.consumed_deposit_count;

        let res = gw.pool_transfer(&user, &mm, value);

        assert!(res.is_err(), "LP transfer must be refused in production");
        assert_eq!(
            gw.seq.state.consumed_deposit_count, before_count,
            "the deposit accumulator must not move"
        );
        // The debit leg (Unbind+Withdraw) runs BEFORE the credit in pool_transfer:
        // a refusal firing only at the mint would return Err with `from`'s value
        // already burned. The production refusal must mutate NOTHING.
        assert_eq!(
            gw.seq.state.state_root(),
            before_root,
            "the refusal must precede the debit leg — no value burned"
        );
        assert_eq!(gw.seq.window_op_count(), before_ops, "no ops staged");
    }

    /// simulate_adl reaches `fund` at runtime and was protected only by
    /// `/api/simulate-adl` sitting inside the router's demo-only block — route-only
    /// enforcement, which SEC-025-C replaces with a refusal at the mint itself.
    #[test]
    fn a_production_simulate_adl_is_refused() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = true;
        // OPEN the launch gate first. SEC-025-D added its own refusal at the top of
        // `simulate_adl`, and with the gate closed IT answers — which would leave this
        // test green while proving nothing about the SEC-025-C guard it exists to pin.
        // Opening the gate makes 025-C's guard the only thing that can refuse here, so
        // the two guards stay independently pinned instead of one masking the other.
        gw.trading_gate = trading_gate::TradingGate::Open;
        let before_root = gw.seq.state.state_root();
        let before_count = gw.seq.state.consumed_deposit_count;
        let err = gw.simulate_adl().expect_err("refused in production");
        assert!(
            err.contains("production"),
            "refused by the SEC-025-C guard, not an incidental demo failure: {err}"
        );
        assert_eq!(gw.seq.state.consumed_deposit_count, before_count);
        assert_eq!(
            gw.seq.state.state_root(),
            before_root,
            "the first mutation in the demo flow is a fund call, so a refusal \
             must leave the engine untouched"
        );
    }

    /// The legacy demo deposit is protected today only by its route not being
    /// mounted. After this task the method itself refuses, so an internal caller
    /// cannot reach it.
    #[test]
    fn legacy_deposit_is_refused_in_production() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = true;
        let before = gw.seq.state.consumed_deposit_count;
        let err = gw
            .deposit(1_000 * QUOTE_SCALE)
            .expect_err("the method must refuse, not merely be unrouted");
        assert!(err.contains("production"), "error names the reason: {err}");
        assert_eq!(gw.seq.state.consumed_deposit_count, before);
    }

    /// DP-001 regression — self-service was already correctly closed at the METHOD;
    /// keep it closed. The account is registered BEFORE flipping `prod` and the
    /// parameters are valid, so the only possible refusal is the production one
    /// (pinned by message) — not "unknown account" or a bad-amount error.
    #[test]
    fn self_service_deposit_is_still_refused_in_production() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let (key, _owner) = gw.register_account(None);
        gw.prod = true;
        let before = gw.seq.state.consumed_deposit_count;
        let err = gw
            .account_deposit(&key, 0, 1_000 * QUOTE_SCALE)
            .expect_err("DP-001: self-service deposit refuses in production");
        assert!(err.contains("production"), "error names the reason: {err}");
        assert_eq!(gw.seq.state.consumed_deposit_count, before);
    }

    // ── SEC-025-C Task 5: the fifth blocker, proven end to end ───────────────

    /// SEC-025-C: the row that actually proves the fifth blocker is closed. From a
    /// PRODUCTION boot, seal a window and prepare the settle tuple; the tuple that
    /// would go on-chain must be the zero prefix a fresh vault accepts. Asserting
    /// the genesis constants alone (`production_genesis_matches_a_fresh_vault_prefix`)
    /// proves two constants — it would not catch a sentinel op left staged in the
    /// window, a wrong witness pre-state reaching the prover, or the demo funding
    /// block regressing to run in both modes. Scope, stated honestly: the batch is
    /// sealed via `gw.seq.seal_batch` directly (not `Gw::tick`, so the house-MM
    /// counter-order injection is bypassed), and the proof step is
    /// `MockProverClient` — a local re-derivation of the roots, not the real
    /// prover. What IS end-to-end here is the settle-tuple pipeline: production
    /// boot → sealed window → `begin_window_settle` → `prove_and_prepare` → the
    /// nine-parameter `settleBatch` tuple.
    ///
    /// The contract side is already covered — `contracts/test/DarkPerpSettlement.t.sol`
    /// lands a zero-prefix settle — but nothing connected it to the boot mode, which
    /// is the half that was broken.
    #[test]
    fn a_production_genesis_window_submits_the_zero_prefix() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = true; // mirrors main(): `gw.prod = prod` right after boot returns
        let genesis_root = gw.seq.state.state_root();

        // PRECONDITION, verified rather than assumed: a BARE production genesis has
        // no state change and no manifest content, so `begin_window_settle` correctly
        // returns `None` (025-B's predicate — idle ticks burn no proofs). The fixture
        // below therefore gives the window real content first.
        assert!(
            gw.begin_window_settle(0)
                .expect("window 0 vs a fresh chain's batchCount 0")
                .is_none(),
            "a bare production genesis window must have nothing to prove — Some here \
             means boot staged content and the markets-only genesis regressed"
        );

        // FIXTURE: the cheapest REAL first-window content that touches no deposit
        // machinery — an order from an unfunded account, rejected pre-trade
        // (InsufficientMargin). An ACCEPTED order needs margin, and on a production
        // genesis margin can only come from a real L1 deposit, which would advance
        // the very accumulator this test pins at zero. A rejected-only window is a
        // genuinely reachable first window (any order sent before depositing) and
        // must settle (SEC-025-B break 4 / whole-branch review item 5).
        //
        // Deterministic oracle, mirroring `tests_support::gw_with_market`: re-sign
        // market 0 at 500 ms so a batch sealed at 1_000 ms clears the freshness
        // gate — otherwise this rejection could silently become OracleUnavailable.
        let px = gw.seq.oracle(0).expect("boot pins a market-0 oracle").price;
        let t = oracle_of(px, 500, 0, &gw.oracle_signer);
        gw.seq.set_oracle(0, t);
        let trader = Wallet::from_seed([9u8; 32]);
        let sealed = gw.seq.seal_batch(
            &[mk_order(
                trader.owner,
                0,
                Side::Buy,
                SIZE_SCALE / 10,
                px / 2,
                1,
                TimeInForce::Gtc,
                false,
            )],
            1_000,
        );

        // Fixture-suspicion guards: exactly the constructed rejection, nothing
        // accepted, and no state moved — otherwise the zero-prefix assertions below
        // could pass while the window exercises a different path entirely.
        assert!(
            sealed.manifest.ordered.is_empty(),
            "fixture precondition: an unfunded account's order must not be accepted: {:?}",
            sealed.manifest.ordered
        );
        assert_eq!(
            sealed.manifest.rejected.len(),
            1,
            "fixture precondition: exactly the one constructed rejection"
        );
        assert_eq!(
            sealed.manifest.rejected[0].1,
            perp_core::order::RejectReason::InsufficientMargin,
            "fixture precondition: the margin rejection we constructed — any other \
             reason (e.g. OracleUnavailable) means the fixture regressed"
        );
        assert_eq!(
            gw.seq.state.state_root(),
            genesis_root,
            "fixture precondition: a rejected order moves no state — the deposit \
             accumulator must reach the prover untouched by the fixture itself"
        );

        let (witness, ww) = gw
            .begin_window_settle(0)
            .expect("window 0 vs a fresh chain's batchCount 0")
            .expect("a window carrying a rejected order is settleable (break 4)");

        // The witness pre-state is what the proof opens from: anything but the boot
        // state root is the BadPrevRoot revert the live migration hit.
        assert_eq!(witness.batch_id, 0, "the first window is window 0");
        assert_eq!(
            witness.pre_state.state_root(),
            genesis_root,
            "witness pre-state must be the deployed GENESIS_ROOT"
        );

        let prepared =
            prover_client::prove_and_prepare(&prover_client::MockProverClient, &witness, &ww)
                .expect("local derivation agrees with the mock prover");

        // The tuple that reaches `settleBatch`. `_requireDepositPrefix`
        // (DarkPerpSettlement.sol:301-307) pins (newDepositCount, depositsRoot) to
        // the vault's `depositTipAt` BEFORE the proof is verified; a fresh vault has
        // depositCount 0 and `depositTipAt(0)` is the never-written mapping default.
        assert_eq!(
            prepared.outcome.prev_root, genesis_root,
            "prevRoot must be the deployed GENESIS_ROOT"
        );
        assert_eq!(
            prepared.outcome.deposits_root, [0u8; 32],
            "depositsRoot must be the vault's genesis tip"
        );
        assert_eq!(
            prepared.outcome.new_deposit_count, 0,
            "newDepositCount must be 0 — _requireDepositPrefix reads depositTipAt(0)"
        );
    }

    /// SEC-025-C's invariant, checked by enumeration rather than by imagining an
    /// attack — the method that made SEC-024's core the one design in this
    /// workstream to survive review intact. `fund_amount_unbacked` is the ONLY
    /// constructor of sentinel-leaf deposits in the gateway and
    /// `refuse_unbacked_mint` guards it (plus the `pool_transfer` pre-flight), so
    /// guarding the wrapper is sufficient — but a NEW unbacked caller must break
    /// something. This test is that something: it scans every gateway source file
    /// (not just main.rs), so a call site added in a sibling module is caught too.
    /// The scan covers top-level production modules; nested A01 modules are test-only; the needles
    /// are `concat!`-split so this test does not count itself.
    ///
    /// Whole-branch review item 2: the wrapper is not the only way in, so the two
    /// levels BELOW it are pinned too. Calling `fund_amount` directly with the
    /// sentinel tuple (`from=[0;20]`, `deposit_id = consumed_deposit_count`,
    /// `deposit_blind=[0;32]` — exactly what the unbacked wrapper passes) bypasses
    /// `refuse_unbacked_mint` entirely; and so does applying the raw `Deposit`
    /// engine op through `seq.apply` directly.
    #[test]
    fn unbacked_funding_has_exactly_the_known_call_sites() {
        let unbacked_needle = concat!("fund_amount_unbacked", "(");
        let fund_needle = concat!("fund_amount", "(");
        let deposit_op_needle = concat!("BatchOp::", "Deposit");
        let backed_needle = concat!("fund_insurance_backed", "(");
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&src_dir).expect("gateway src dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                sources.push(std::fs::read_to_string(&path).expect("readable gateway source"));
            }
        }
        assert!(
            sources.len() >= 2,
            "the scan must actually cover the gateway sources (found {} files)",
            sources.len()
        );
        let count =
            |needle: &str| -> usize { sources.iter().map(|s| s.matches(needle).count()).sum() };
        // SEC-025-A: pin the BACKED insurance funnel's callers too. The deposit-op count
        // below does NOT cover this — a new caller of `fund_insurance_backed` that passes
        // a fabricated sentinel leaf constructs no deposit op of its own and would sail
        // through. `fund_amount`'s callers are pinned for exactly that reason; this closes
        // the same gap on the sibling funnel, whose whole safety argument is that its
        // CALLER supplies a real verified L1 leaf.
        //
        // (Deliberately phrased without the op's literal name: this scan counts occurrences
        // across its own source file, so naming it here would inflate the very count it
        // describes — which is how this edit first failed.)
        let nb = count(backed_needle);
        assert_eq!(
            nb, 2,
            "expected exactly 2 occurrences of `{backed_needle}` across the gateway \
             sources: the definition (`fn fund_insurance_backed`) and its ONE production \
             call site, the operator bootstrap driver `Gw::bootstrap_insurance`; found \
             {nb}. This funnel folds a REAL L1 leaf and its backing is supplied by the \
             CALLER, not verified inside — so a new call site must prove it passes the \
             payer, id and blind that the vault actually chained, or it fabricates \
             collateral exactly as `SeedInsurance` did before SEC-024."
        );
        let n = count(unbacked_needle);
        assert_eq!(
            n, 7,
            "expected exactly 7 occurrences of `{unbacked_needle}` across the \
             gateway sources: the definition (`fn fund_amount_unbacked`), 4 \
             production call sites — `fund` (the boot/demo funnel), `pool_transfer` \
             (the LP credit leg), `deposit` (legacy demo), `account_deposit` \
             (self-service) — and 2 test call sites \
             (`unbacked_funding_is_refused_in_production`, \
             `confirm_deposit_duplicate_commitment_is_clean_err_and_retriable`); \
             found {n}. A new unbacked-funding call site MUST thread the production \
             flag through `refuse_unbacked_mint` (SEC-025-C) and get a refusal test \
             like `unbacked_funding_is_refused_in_production` — only then update this \
             count and its breakdown."
        );
        // Review item 2, pin 1: the chokepoint one level down. A direct
        // `fund_amount` call handed the sentinel tuple mints unbacked collateral
        // without ever reaching `refuse_unbacked_mint`, so every caller is pinned.
        let fund_calls = count(fund_needle);
        assert_eq!(
            fund_calls, 3,
            "expected exactly 3 occurrences of `{fund_needle}` across the gateway \
             sources (all in main.rs): the definition (`fn` + name) and 2 callers — \
             `account_confirm_deposit` (the REAL L1-credit path, passing the \
             verified vault leaf) and `fund_amount_unbacked` (the guarded sentinel \
             wrapper); found {fund_calls}. A direct caller can mint UNBACKED \
             collateral by passing the sentinel tuple (from=[0;20], deposit_id = \
             consumed_deposit_count, deposit_blind=[0;32]) without ever reaching \
             `refuse_unbacked_mint` — so a legitimately added caller MUST either \
             route through `fund_amount_unbacked` (which carries the guard) or pass \
             a REAL verified L1 leaf like `account_confirm_deposit` does, and only \
             then update this count and its breakdown."
        );
        // Review item 2, pin 2: the bottom level. Applying the raw `Deposit`
        // engine op through `seq.apply` mints collateral below BOTH the guard and
        // `fund_amount`'s note/archive bookkeeping.
        assert_eq!(
            include_str!("deposit_ingestion.rs")
                .matches(deposit_op_needle)
                .count(),
            1,
            "one prefix-verified atomic intake constructor"
        );
        let deposit_ops = count(deposit_op_needle);
        assert_eq!(
            deposit_ops, 8,
            "expected exactly 8 occurrences of `{deposit_op_needle}` across the \
             gateway sources: 4 in main.rs — the `seq.apply(..)` constructions \
             inside `fund_amount` (the only position-credit minter), \
             `seed_insurance_unbacked` (SEC-024: the UNBACKED insurance funnel, \
             itself behind `refuse_unbacked_mint`), and `fund_insurance_backed` \
             (SEC-025-A: the BACKED insurance funnel — its callers thread the \
             REAL verified L1 leaf from `validated_deposit`, so the unbacked \
             guard's premise does not apply), plus 1 `cfg(test)` fixture in \
             `a_first_leg_refusal_leaves_the_bootstrap_record_untouched` that \
             pre-mints a colliding note to force leg 1's DuplicateCommitment — \
             and 3 in prover_client.rs, all \
             `cfg(test)` `matches!`/filter PATTERNS that inspect ops without \
             constructing one; plus A01 atomic intake (all windows now require post-seal persistence, so the deposit-only pattern was removed); found {deposit_ops}. Applying this op anywhere \
             else mints collateral below BOTH `refuse_unbacked_mint` and the \
             funnels' bookkeeping, so a new construction site is almost \
             certainly wrong; a legitimate credit path MUST route through \
             `fund_amount` (backed), `fund_amount_unbacked` (guarded), \
             `seed_insurance_unbacked` (guarded, insurance only), or \
             `fund_insurance_backed` (backed, insurance only — callers must \
             pass a REAL verified L1 leaf), and a legitimate new PATTERN use \
             (e.g. a test inspecting ops) just updates this count and its breakdown."
        );
    }

    // Hash-pinning now has executable real-cast/loopback coverage in
    // l1::witness_tests, including this module's gate classifier call path.
    // The old textual argv occurrence count is obsolete: no cast-call argv
    // builder remains in these typed observation paths.

    /// Whole-branch review item 5: the OpenAPI document must describe the MOUNTED
    /// surface. Task 3 removed `/v1/lp*` from the production router, so an
    /// unconditional spec would advertise three paths that 404 in production.
    /// Asserts on the parsed `paths` object (not a substring of the whole
    /// document) in BOTH modes, so the discriminator is proven to discriminate:
    /// un-gating the entries (advertising LP unconditionally) fails the
    /// production half, and dropping them outright fails the demo half.
    #[test]
    fn openapi_advertises_lp_only_in_demo() {
        const LP_PATHS: [&str; 3] = ["/v1/lp", "/v1/lp/deposit", "/v1/lp/withdraw"];
        let prod_spec = v1_openapi_json(true);
        let demo_spec = v1_openapi_json(false);
        let prod_paths = prod_spec["paths"]
            .as_object()
            .expect("production spec has a paths object");
        let demo_paths = demo_spec["paths"]
            .as_object()
            .expect("demo spec has a paths object");
        for p in LP_PATHS {
            assert!(
                !prod_paths.contains_key(p),
                "production openapi must NOT advertise {p} — the production router \
                 does not mount it (SEC-025-C Task 3), so documenting it advertises \
                 a 404"
            );
            assert!(
                demo_paths.contains_key(p),
                "demo openapi must keep advertising {p} — the demo router mounts it"
            );
        }
        // Fixture-suspicion guards: an empty (or LP-only) paths object would pass
        // the loop above while documenting nothing. Both documents must carry the
        // ungated surface, and the LP gating must be their ONLY difference.
        assert!(
            prod_paths.contains_key("/v1/orders"),
            "production spec still documents the ungated /v1 surface"
        );
        assert_eq!(
            demo_paths.len(),
            prod_paths.len() + LP_PATHS.len(),
            "the demo and production documents differ by EXACTLY the three LP paths"
        );
    }

    // Live ingress must preserve the source's exact signed transcript. The same
    // source timestamp, signature and bounds are then checked inside the guest;
    // successful receipt cannot turn stale input into a fresh publisher statement.
    #[test]
    fn gateway_oracle_path_produces_a_validatable_signed_transcript() {
        let mut gw = Gw::boot();
        let market_id = 0u64;
        let now = now_ms();
        // Build the transcript exactly as the live feed does: signed by the gateway's
        // OWN oracle signer over the exchange timestamp (the fetch path, offline).
        let signer = gw.oracle_signer.clone();
        let fetched = oracle_feed::transcript_from_ticker(
            "59585.6", "59586.7", "59586.8", now, market_id, &signer,
        )
        .expect("ticker → signed transcript");
        // Drive the live path: validate without re-stamping or re-signing.
        gw.apply_real_oracle(market_id, fetched);
        // The stored transcript is byte-identical and validates against the pin.
        assert_eq!(gw.seq.oracle(market_id).copied(), Some(fetched));
        let stored = *gw.seq.oracle(market_id).expect("oracle stored for market");
        let market = *gw
            .seq
            .state
            .markets
            .get(&market_id)
            .expect("market registered");
        assert_eq!(
            market.oracle_pubkey,
            oracle_feed::signer_address(&signer),
            "boot must pin the market's oracle_pubkey to the gateway's oracle signer"
        );
        assert_eq!(
            stored.validate(&market, stored.publish_time_ms),
            Ok(stored.price),
            "a live-path transcript must preserve the source signature under the market pin"
        );
    }

    // ── SEC-026 gateway follow-ups (review F1): the demo paths must survive
    //    HISTORICAL commitment uniqueness ─────────────────────────────────────

    /// Review F1 regression: under the old blind scheme (`0x80 + tick % 60`) the demo
    /// account depositing the SAME amount 60 ticks apart reconstructed an identical
    /// note commitment — accepted before SEC-026 (the note had already been spent out
    /// of the live map by the immediate FundPosition), a panic (`.expect("deposit")`)
    /// after. The blind is now derived from the tree's leaf count, so both deposits
    /// must simply succeed — no panic, no rejection.
    #[test]
    fn demo_deposit_same_amount_sixty_ticks_apart_succeeds() {
        let mut gw = Gw::boot();
        let amount = 1_000 * QUOTE_SCALE;
        let free_before = gw.market_free(gw.selected);
        gw.deposit(amount).expect("first demo deposit");
        // exactly the repeat distance that collided under `tick % 60`
        gw.tick += 60;
        gw.deposit(amount)
            .expect("second demo deposit of the same amount 60 ticks later (SEC-026 F1)");
        // and a same-tick repeat (blind must be unique per MINT, not per tick)
        gw.deposit(amount)
            .expect("third demo deposit within the same tick (SEC-026 F1)");
        assert_eq!(
            gw.market_free(gw.selected),
            free_before + 3 * amount,
            "all three identical-amount demo deposits must be credited"
        );
    }

    /// The demo withdraw path mints too (`op_unbind`), and its old blind
    /// (`0xC0 + tick % 60`) had the same 60-tick repeat — the second withdrawal of the
    /// same amount was a historical DuplicateCommitment (a clean Err, but a broken
    /// demo). Same fix, same guarantee: both must succeed.
    #[test]
    fn demo_withdraw_same_amount_sixty_ticks_apart_succeeds() {
        let mut gw = Gw::boot();
        let amount = 100 * QUOTE_SCALE; // well under the boot-funded free balance
        gw.withdraw(amount).expect("first demo withdraw");
        gw.tick += 60;
        gw.withdraw(amount)
            .expect("second demo withdraw of the same amount 60 ticks later (SEC-026)");
    }

    /// Review F2 regression: `account_confirm_deposit` driven into a historical
    /// `DuplicateCommitment` — the arm the design calls "worse than a panic" because
    /// it stalls the SEC-019 in-order deposit stream. Pre-mint the EXACT note the
    /// confirm path will derive (same owner, asset 0, same amount, and the same
    /// `0xB0 ‖ deposit_counter` blind), then confirm at the next-in-line id: the
    /// engine must refuse in phase 1 (`op_deposit`) with a clean operator-facing
    /// `Err` — never a panic under the account lock — whose text names the stall
    /// correctly for the CREDIT-REFUSAL arm, and the three retriability invariants
    /// must hold (counter unbumped, authorization intact, tx not marked processed).
    #[test]
    fn confirm_deposit_duplicate_commitment_is_clean_err_and_retriable() {
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        let from = [0x42u8; 20];
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(from);
        let amount = 5_000_000u128;
        let wallet = gw.accounts[&key].wallet;
        // The colliding blind: exactly what the confirm path derives from the
        // account's live `deposit_counter`.
        let dc = gw.accounts[&key].deposit_counter;
        let mut note_blind = [0xB0u8; 32];
        note_blind[..8].copy_from_slice(&dc.to_le_bytes());
        fund_amount_unbacked(
            &mut gw.seq,
            &mut gw.archive,
            &wallet,
            0,
            amount as i128,
            note_blind,
            /* prod */ false,
        )
        .expect("pre-minting the colliding note must succeed");
        // Authorize, then confirm at the live next-in-line id so the in-order guard
        // passes and the duplicate refusal (not DepositOutOfOrder) is what fires.
        let commit = gw.account_authorize_deposit(&key, from, amount).unwrap();
        let dc_before = gw.accounts[&key].deposit_counter;
        let id = gw.seq.state.consumed_deposit_count;
        let count_before = id;
        let err = gw
            .account_confirm_deposit(&key, from, commit, amount, id, "0xf2dup", 0)
            .expect_err("a historical duplicate must be a clean Err, not a panic (SEC-026 F2)");
        // Phase 1 actually refused as a duplicate (the parenthetical in the message
        // always mentions DuplicateCommitment, so pin the ENGINE's rendering)…
        assert!(
            err.contains("refused by the engine: DuplicateCommitment"),
            "the engine must refuse phase 1 as a historical duplicate: {err}"
        );
        // …and the operator text carries the CREDIT-REFUSAL contract: the stream is
        // stalled at this id and the same confirm may be retried. (The other arm's
        // "WAS credited / NOT stalled" text would be FALSE here.)
        assert!(
            err.contains("STALLED at id") && err.contains("may be retried"),
            "the operator text must name the stall + retriability of the credit-refusal arm: {err}"
        );
        assert!(
            !err.contains("NOT stalled"),
            "the fund-position arm's text must not leak onto the credit-refusal arm: {err}"
        );
        // The three retriability invariants — nothing after the failed fund ran.
        assert_eq!(
            gw.accounts[&key].deposit_counter, dc_before,
            "deposit_counter must be unchanged on refusal"
        );
        assert!(
            gw.accounts[&key]
                .deposit_authorizations
                .contains_key(&commit),
            "the authorization must still be present (not consumed) — retriable"
        );
        assert!(
            !gw.processed_deposit_txs.contains("0xf2dup"),
            "the tx must not be marked processed — retriable"
        );
        // And the engine really is byte-consistent with "stalled": no credit landed.
        assert_eq!(
            gw.seq.state.consumed_deposit_count, count_before,
            "phase-1 refusal must not advance consumed_deposit_count"
        );
    }

    /// A minimal `App` for router tests — no socket bound, pure in-memory (`l1: None`).
    pub(crate) fn test_app() -> Shared {
        let (tx, _rx) = broadcast::channel::<String>(16);
        let (events_tx, _erx) = broadcast::channel::<String>(16);
        // A fixed-IKM ephemeral keypair — deterministic, fine for router tests
        // (no handshake runs; /attest 503s on `attestor: None` anyway).
        let (gw_eph_secret, gw_pub) = ephemeral_keypair(&[0u8; 32]);
        Arc::new(App {
            clock_admission: clock_admission::ClockAdmission::new(false),
            deposit_source: None,
            deposit_serial: Mutex::new(()),
            gw: Mutex::new(Gw::boot()),
            tx,
            events_tx,
            reg_limit: Mutex::new(HashMap::new()),
            l1: None,
            snapshot_req: None,
            gateway_signer: GatewaySigner::from_env().expect("demo gateway signer"),
            prover: None,
            candles: Mutex::new(candles::CandleStore::new()),
            attestor: None,
            gw_eph_secret,
            gw_pub,
            prover_session_token: None,
            force_settle: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    // ── SEC-019 (Task 7b): real L1-bound deposit crediting + gateway auth signing ──

    /// The gateway's deposit-authorization signature recovers to the gateway address
    /// under the SAME verifier the contract mirrors, and its digest is BYTE-IDENTICAL to
    /// Solidity's `keccak256(abi.encodePacked(chainid, vault, from, ownerCommit, amount))`
    /// (KAT from `cast keccak $(cast abi-encode --packed ...)`). If this drifts, the
    /// deployed vault's `ecrecover` would reject every gateway-issued deposit signature.
    #[test]
    fn gateway_signature_round_trips_and_matches_solidity_digest() {
        let vault = [0x11u8; 20];
        let from = [0x22u8; 20];
        let oc = [0x33u8; 32];
        let gs = GatewaySigner::from_parts(DEMO_GATEWAY_SIGNER_KEY, 84532, vault).unwrap();
        // digest byte-parity with Solidity abi.encodePacked (chainid=84532, amount=1000).
        let expected =
            parse_hex32("0x616596ebb8fceaa76501abebf569187adcbc045cda51a9e3023a217d9e8c440b")
                .unwrap();
        assert_eq!(
            gs.digest(&from, &oc, 1000),
            expected,
            "gateway digest must match Solidity abi.encodePacked"
        );
        // sign → recover round-trip: the gateway's sig recovers to its OWN address.
        let sig = gs.sign(&from, &oc, 1000).unwrap();
        assert_eq!(
            recover_eth_address(&gs.digest(&from, &oc, 1000), &sig),
            Some(gs.address()),
            "gateway signature must recover to the gateway address"
        );
        // contract accepts only low-s + v ∈ {27,28}.
        assert!(sig[64] == 27 || sig[64] == 28, "v must be 27 or 28");
        // a sig for (from, oc, amount) must NOT verify for a different amount.
        assert_ne!(
            recover_eth_address(&gs.digest(&from, &oc, 999), &sig),
            Some(gs.address()),
            "the signature is bound to the amount"
        );
    }

    /// A deposit whose stored blind reproduces the on-chain `ownerCommit` is credited,
    /// and the post-credit `consumed_deposit_tip` equals the vault-matching fold
    /// `deposit_chain_fold(prev, deposit_leaf(from, ownerCommit, amount, id))` — the
    /// whole point of SEC-019: the gateway's fold reproduces the vault's `depositChainTip`.
    #[test]
    fn confirm_deposit_matching_blind_advances_tip_to_vault_fold() {
        use crate::withdrawals::{deposit_chain_fold, deposit_leaf};
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        let from = [0x42u8; 20];
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(from);
        let amount = 5_000_000u128;
        // authorize → gateway stores the blind and returns ownerCommit.
        let commit = gw.account_authorize_deposit(&key, from, amount).unwrap();
        // snapshot the pre-credit chain; the real event's id is the live consumed count.
        let prev_tip = gw.seq.state.consumed_deposit_tip;
        let id = gw.seq.state.consumed_deposit_count;
        let ext_in_before = gw.seq.state.external_in;
        let credited = gw
            .account_confirm_deposit(&key, from, commit, amount, id, "0xdeadbeef", 0)
            .expect("matching blind must credit");
        assert_eq!(credited, amount as i128);
        assert_eq!(
            gw.seq.state.consumed_deposit_count,
            id + 1,
            "count bumps by one"
        );
        assert_eq!(
            gw.seq.state.external_in,
            ext_in_before + amount as i128,
            "external_in grows by the deposit"
        );
        let expected_tip = deposit_chain_fold(&prev_tip, &deposit_leaf(&from, &commit, amount, id));
        assert_eq!(
            gw.seq.state.consumed_deposit_tip, expected_tip,
            "post-credit tip must equal the vault-matching fold of (from, ownerCommit, amount, id)"
        );
        // the one-shot authorization is consumed after crediting.
        assert!(
            !gw.accounts[&key]
                .deposit_authorizations
                .contains_key(&commit),
            "authorization is consumed after a successful credit"
        );
    }

    /// FAIL-CLOSED misattribution guard: a deposit with NO authorization record, or with
    /// a stored blind that does not reproduce the on-chain `ownerCommit`, is REFUSED — no
    /// credit, no state advance. This is the security guard, not an error to smooth over.
    #[test]
    fn confirm_deposit_absent_or_mismatched_blind_is_refused() {
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        let from = [0x42u8; 20];
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(from);
        let amount = 5_000_000u128;
        let id = gw.seq.state.consumed_deposit_count;
        let tip_before = gw.seq.state.consumed_deposit_tip;
        let count_before = gw.seq.state.consumed_deposit_count;
        let ext_before = gw.seq.state.external_in;

        // (1) ABSENT record: an ownerCommit we never authorized is refused.
        let never_authorized = [0x99u8; 32];
        let r = gw.account_confirm_deposit(&key, from, never_authorized, amount, id, "0xtx1", 0);
        assert!(r.is_err(), "absent authorization must be refused");

        // (2) MISMATCHED record: a stored blind that does NOT reproduce the commit key.
        // keccak(owner ‖ wrong_blind) != bogus_commit, so the recompute guard rejects.
        let bogus_commit = [0x77u8; 32];
        gw.accounts
            .get_mut(&key)
            .unwrap()
            .deposit_authorizations
            .insert(bogus_commit, [0x01u8; 32]); // blind that won't reproduce bogus_commit
        let r2 = gw.account_confirm_deposit(&key, from, bogus_commit, amount, id, "0xtx2", 0);
        assert!(
            r2.is_err(),
            "a blind that fails to reproduce the commit must be refused"
        );

        // (3) OUT-OF-ORDER id: a validly-authorized deposit whose id is not next-in-line
        // is refused CLEANLY (no panic under the lock) — the host must confirm in L1 order.
        let commit = gw.account_authorize_deposit(&key, from, amount).unwrap();
        let r3 = gw.account_confirm_deposit(&key, from, commit, amount, id + 99, "0xtx3", 0);
        assert!(r3.is_err(), "an out-of-order deposit id must be refused");

        // NEITHER refusal advanced the chain, external_in, or the tx dedup set.
        assert_eq!(
            gw.seq.state.consumed_deposit_tip, tip_before,
            "tip unchanged"
        );
        assert_eq!(
            gw.seq.state.consumed_deposit_count, count_before,
            "count unchanged"
        );
        assert_eq!(
            gw.seq.state.external_in, ext_before,
            "external_in unchanged"
        );
        assert!(!gw.processed_deposit_txs.contains("0xtx1"));
        assert!(!gw.processed_deposit_txs.contains("0xtx2"));
    }

    // ── ambiguous landed-tx recovery ─────────────────────────────────────────

    #[test]
    fn settle_failure_action_decides_by_batch_count() {
        use crate::RollAction;
        // The old transaction can land later even if repeated reads are unchanged.
        assert_eq!(crate::settle_failure_action(5, 5), RollAction::Hold);
        // chain advanced by exactly one -> the tx landed despite the error -> roll forward.
        assert_eq!(crate::settle_failure_action(5, 6), RollAction::RollForward);
        // anything else is unexpected -> hold (no mutation).
        assert_eq!(crate::settle_failure_action(5, 7), RollAction::Hold);
        assert_eq!(crate::settle_failure_action(5, 4), RollAction::Hold);
        assert_eq!(crate::settle_failure_action(0, 0), RollAction::Hold);
        assert_eq!(
            crate::settle_failure_action(u64::MAX, u64::MAX),
            RollAction::Hold
        );
        assert_eq!(crate::settle_failure_action(u64::MAX, 0), RollAction::Hold);
    }

    /// SEC-025-C: the pure comparator refuses a root mismatch (and its sibling
    /// `continuity_comparison_ignores_hex_case` pins the format tolerance). Scope,
    /// stated honestly: this exercises ONLY `continuity_ok` — it touches neither
    /// `l1_status` nor the boot guard. The actual SEC-025-C change — WIDENING the
    /// guard so continuity is checked on every L1-configured boot (a pre-first-settle
    /// snapshot has `l1_status == None`, and `prod` is not persisted, so a DEMO
    /// snapshot with unbacked deposits could be restored under production posture)
    /// — is verified by reading the `if let Some(l1c) = &l1` continuity block in
    /// `main()`, and is NOT covered by an in-process test: `main()` is untestable
    /// in a bin crate.
    #[test]
    fn continuity_comparator_rejects_a_mismatch() {
        // genesis root vs a chain that has advanced past it
        assert!(
            !continuity_ok(
                &[0x11u8; 32],
                "0x2222222222222222222222222222222222222222222222222222222222222222"
            ),
            "a mismatch must be refused even with no prior settle"
        );
        assert!(
            continuity_ok(&[0x11u8; 32], &hex32(&[0x11u8; 32])),
            "a match starts"
        );
    }

    /// Hex comparison must not be case-sensitive — `current_root()` returns whatever
    /// the RPC formats, and the existing check used `eq_ignore_ascii_case`.
    #[test]
    fn continuity_comparison_ignores_hex_case() {
        let root = [0xABu8; 32];
        assert!(continuity_ok(&root, &hex32(&root).to_uppercase()));
    }

    // ── deposit-posture check (SEC-025-C follow-up) ──────────────────────────
    //
    // Scope, stated honestly: these exercise ONLY the pure `deposit_posture`
    // predicate. The boot wiring — the vault reads and the exit(1) arms inside
    // `main()`'s `if let Some(l1c) = &l1` block, including the requirement that
    // an L1-configured-but-vault-less gateway refuses rather than skips — is
    // verified by reading that block, NOT by an in-process test: `main()` is
    // untestable in a bin crate (same caveat as the continuity tests above).

    /// A count the vault can back, with the matching prefix tip, boots. Equality is
    /// the boundary: mutating the count predicate's `>` to `>=` (i.e. the spec's
    /// `<=` to `<`) must kill this test.
    #[test]
    fn deposit_posture_accepts_a_backed_count_and_matching_tip() {
        let tip = [0x5Au8; 32];
        assert_eq!(
            deposit_posture(3, &tip, 3, &hex32(&tip)),
            DepositPosture::Ok
        );
        // tip comparison goes through `continuity_ok`, so it is hex-case tolerant.
        assert_eq!(
            deposit_posture(3, &tip, 3, &hex32(&tip).to_uppercase()),
            DepositPosture::Ok
        );
    }

    /// The unbacked signature: the gateway consumed MORE deposits than the vault ever
    /// received — the live demo-genesis shape (7 fabricated deposits vs a fresh vault).
    /// Must be refused as `UnbackedCount` specifically (the count check, not a
    /// coincidental tip mismatch, is what names the failure for the operator).
    #[test]
    fn deposit_posture_refuses_an_unbacked_count() {
        let demo_tip = [0xAAu8; 32]; // 7 sentinel leaves folded off-chain
        assert_eq!(
            deposit_posture(7, &demo_tip, 0, &hex32(&[0u8; 32])),
            DepositPosture::UnbackedCount,
            "count above the vault's is exactly the unbacked-deposit condition"
        );
    }

    /// Equal counts do NOT imply honesty: if the fold at that prefix differs, the
    /// consumed leaves are not the vault's leaves. The tip check catches it.
    #[test]
    fn deposit_posture_refuses_a_tip_mismatch_at_an_equal_count() {
        let gw_tip = [0xAAu8; 32];
        let vault_tip = [0xBBu8; 32];
        assert_eq!(
            deposit_posture(4, &gw_tip, 4, &hex32(&vault_tip)),
            DepositPosture::TipMismatch
        );
    }

    /// The honest genesis: a fresh gateway `(0, [0;32])` against a fresh vault's
    /// `(0, bytes32(0))` — `depositTipAt[0]` is never written, the mapping default IS
    /// the genesis tip — must boot.
    #[test]
    fn deposit_posture_accepts_the_honest_genesis() {
        assert_eq!(
            deposit_posture(0, &[0u8; 32], 0, &hex32(&[0u8; 32])),
            DepositPosture::Ok
        );
    }

    /// A gateway BEHIND the vault is legitimate — deposits landed on-chain that the
    /// gateway has not yet confirmed — provided the tip at its consumed prefix
    /// matches. Kills the mutation that inverts the count comparison (`<=` → `>=`).
    #[test]
    fn deposit_posture_accepts_a_gateway_behind_the_vault() {
        let tip_at_2 = [0x11u8; 32];
        assert_eq!(
            deposit_posture(2, &tip_at_2, 5, &hex32(&tip_at_2)),
            DepositPosture::Ok
        );
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

    // ── FIN-001 settlement health on the status snapshot ─────────────────────

    /// The status snapshot surfaces the settle loop's circuit-breaker health so
    /// operators/monitors can see HEALTHY → DEGRADED → HELD, the failure streak,
    /// the last error, and when it entered HELD.
    #[test]
    fn snapshot_exposes_settlement_health() {
        let mut gw = Gw::boot();
        // healthy by default
        let s = gw.snapshot();
        assert_eq!(s.settlement_health, "HEALTHY");
        assert_eq!(s.settlement_consecutive_failures, 0);
        assert_eq!(s.settlement_last_error, None);
        assert_eq!(s.settlement_held_since_ms, None);
        // drive to HELD (default threshold 3)
        gw.settle_health.on_failure("e1".into());
        gw.settle_health.on_failure("e2".into());
        let (_, just_held) = gw.settle_health.on_failure("e3".into());
        if just_held {
            gw.settlement_held_since_ms = Some(1_700_000_000_000);
        }
        let s2 = gw.snapshot();
        assert_eq!(s2.settlement_health, "HELD");
        assert_eq!(s2.settlement_consecutive_failures, 3);
        assert_eq!(s2.settlement_last_error.as_deref(), Some("e3"));
        assert_eq!(s2.settlement_held_since_ms, Some(1_700_000_000_000));
    }

    /// FIN-001 (final-review): the shared breaker-recovery helper both success
    /// paths call clears the HELD state and reports `was_held` for the one-shot
    /// recovery log — so the ambiguous-but-landed roll-forward path recovers the
    /// circuit breaker exactly like the clean Ok path (no HELD-forever surface).
    #[test]
    fn settle_breaker_recovered_clears_held_state() {
        let mut gw = Gw::boot();
        gw.settle_health.on_failure("e1".into());
        gw.settle_health.on_failure("e2".into());
        gw.settle_health.on_failure("e3".into()); // default threshold 3 ⇒ HELD
        gw.settlement_held_since_ms = Some(1_700_000_000_000);
        assert_eq!(gw.settle_health.health().as_str(), "HELD");

        // recovery from HELD clears every failure/HELD surface and reports was_held
        assert!(gw.settle_breaker_recovered());
        assert_eq!(gw.settle_health.health().as_str(), "HEALTHY");
        assert_eq!(gw.settle_health.consecutive_failures(), 0);
        assert_eq!(gw.settlement_held_since_ms, None);

        // idempotent: already healthy ⇒ not "was held", state stays clear
        assert!(!gw.settle_breaker_recovered());
        assert_eq!(gw.settle_health.health().as_str(), "HEALTHY");
        assert_eq!(gw.settlement_held_since_ms, None);
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
                               // SEC-021 (review Finding 7): scribble on the runtime-only deployment binding
                               // BEFORE snapshotting — restore must NOT carry it (serde-skip) and must
                               // re-apply the shared dev fallback via the `default` fns, exactly as a fresh
                               // boot() would (main() then overwrites both from GatewaySigner).
        gw.chain_id = 31_337;
        gw.vault = [0xEEu8; 20];
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
        assert_eq!(
            restored.order_log.head(),
            log_head_before,
            "log head survives"
        );
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
        // SEC-021 (review Finding 7): the deployment binding is runtime-only — the
        // scribbled values above must NOT survive the round trip; the restore re-applies
        // the shared dev fallback (dev_fallback_chain_id/dev_fallback_vault).
        assert_eq!(
            restored.chain_id, DEV_FALLBACK_CHAIN_ID,
            "chain_id not persisted; restore re-applies the dev fallback"
        );
        assert_eq!(
            restored.vault, DEV_FALLBACK_VAULT,
            "vault not persisted; restore re-applies the dev fallback"
        );
    }

    #[test]
    fn the_bootstrap_record_survives_a_snapshot_round_trip() {
        let mut gw = Gw::boot();
        gw.bootstrap = bootstrap::Bootstrap::InsuranceApplied { window_id: 42 };
        let plain = gw.snapshot_plain();
        let restored = Gw::boot_restored(&plain).expect("restore");
        // The launch gate 025-D will read this, so losing it across a restart would
        // silently reopen the question the record exists to answer.
        assert_eq!(
            restored.bootstrap,
            bootstrap::Bootstrap::InsuranceApplied { window_id: 42 }
        );
    }

    #[test]
    fn the_trading_gate_survives_a_snapshot_round_trip() {
        let mut gw = Gw::boot();
        gw.trading_gate = trading_gate::TradingGate::Closed;
        let plain = gw.snapshot_plain();
        let restored = Gw::boot_restored(&plain).expect("restore");
        assert_eq!(restored.trading_gate, trading_gate::TradingGate::Closed);
        // The Open leg is what makes this test able to die: `Closed` is ALSO the
        // deserialization default (`trading_gate_closed`), so the leg above passes even
        // if the field is serde-skipped and never persisted at all. Losing the field
        // across a restart would silently re-CLOSE an opened deployment — and a closed
        // ingress gate blocks reduce-only exits, the exact trap the one-way latch
        // exists to avoid.
        gw.trading_gate = trading_gate::TradingGate::Open;
        let restored = Gw::boot_restored(&gw.snapshot_plain()).expect("restore");
        assert_eq!(restored.trading_gate, trading_gate::TradingGate::Open);
    }

    #[test]
    fn a_wind_down_shaped_commit_does_not_open_the_gate() {
        // The finalSettle defence, at the transition rather than in the classifier: the
        // count and root match exactly, and only the observation distinguishes it.
        let mut gw = Gw::boot_production_for_test();
        assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
        gw.commit_window_settle_for_test_with(0, trading_gate::GateObservation::StaysClosed);
        assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
    }

    #[test]
    fn an_inconclusive_observation_leaves_the_gate_unresolved_rather_than_closed() {
        // The liveness half. The commit is not repeatable, so resolving a failed or lagging
        // read AGAINST opening would burn the only opportunity — and 025-A's bootstrap
        // endpoint is one-shot and cannot manufacture another window.
        let mut gw = Gw::boot_production_for_test();
        gw.commit_window_settle_for_test_with(0, trading_gate::GateObservation::Inconclusive);
        assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
        // …and a later conclusive observation still opens it.
        gw.commit_window_settle_for_test_with(1, trading_gate::GateObservation::OpensGate);
        assert_eq!(gw.trading_gate, trading_gate::TradingGate::Open);
    }

    #[test]
    fn an_undercapitalized_deployment_does_not_open_on_a_clean_settle() {
        // The predicate half: a perfect on-chain observation is not enough.
        let mut gw = Gw::boot_production_for_test();
        gw.set_prepared_post_state_for_test(true, 1, 1); // one base unit of insurance
        gw.commit_window_settle_for_test_with(0, trading_gate::GateObservation::OpensGate);
        assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
    }

    #[test]
    fn the_gate_does_not_re_close_when_the_fund_is_later_drained() {
        // Deliberate: this is a LAUNCH gate. Re-closing a blunt ingress gate would block
        // reduce-only exits, trapping users exactly when they most need to leave.
        let mut gw = Gw::boot_production_for_test();
        gw.commit_window_settle_for_test_with(0, trading_gate::GateObservation::OpensGate);
        assert_eq!(gw.trading_gate, trading_gate::TradingGate::Open);
        gw.set_prepared_post_state_for_test(true, 0, 1);
        gw.commit_window_settle_for_test_with(1, trading_gate::GateObservation::OpensGate);
        assert_eq!(gw.trading_gate, trading_gate::TradingGate::Open);
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
        gw.account_place_order(&key, &req(0))
            .expect("order accepted");
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

    #[tokio::test]
    async fn snapshot_now_reports_the_writers_verdict_and_refuses_when_unconfigured() {
        // Each error case asserts on a DISTINGUISHING substring, not just is_err():
        // these strings become operator-facing text, and collapsing two cases into
        // one message would otherwise go unnoticed.

        // Persistence off ⇒ there is no writer, so a caller must NOT be told the state
        // is durable. This is the case that matters: the bootstrap barrier runs before
        // an irreversible L1 deposit.
        let err = snapshot_now(&None).await.unwrap_err();
        assert!(err.contains("not configured"), "got: {err}");

        // A writer that succeeds.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        tokio::spawn(async move {
            while let Some(ack) = rx.recv().await {
                let _ = ack.send(true);
            }
        });
        assert!(snapshot_now(&Some(tx)).await.is_ok());

        // A writer that FAILS must surface as Err, not as a silent success — the whole
        // point of the ack is that the caller learns the write did not land.
        let (tx2, mut rx2) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        tokio::spawn(async move {
            while let Some(ack) = rx2.recv().await {
                let _ = ack.send(false);
            }
        });
        let err = snapshot_now(&Some(tx2)).await.unwrap_err();
        assert!(err.contains("write failed"), "got: {err}");

        // A dead writer (receiver dropped) must also be an Err, never a hang.
        let (tx3, rx3) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        drop(rx3);
        let err = snapshot_now(&Some(tx3)).await.unwrap_err();
        assert!(err.contains("writer is gone"), "got: {err}");

        // A writer that TAKES the request and then dies mid-write must also be an Err.
        // Distinct from the dropped-receiver case above: there `send()` fails and we never
        // reach the ack at all, so this is the only case that exercises the ack's own
        // failure arm — the one a mutation to `Ok(())` otherwise walks straight through.
        let (tx4, mut rx4) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        tokio::spawn(async move {
            while let Some(ack) = rx4.recv().await {
                drop(ack);
            }
        });
        let err = snapshot_now(&Some(tx4)).await.unwrap_err();
        assert!(err.contains("dropped the request"), "got: {err}");
    }

    #[tokio::test(start_paused = true)]
    async fn snapshot_now_times_out_instead_of_hanging_when_the_writer_never_replies() {
        // A wedged writer — most likely a caller holding `App.gw` across the await, the
        // deadlock the doc comment forbids — must surface as an `Err` the caller can
        // refuse on, never an unbounded hang that takes the gateway with it. Paused
        // time: the runtime auto-advances the virtual clock when every task is idle,
        // so this exercises the full SNAPSHOT_ACK_TIMEOUT_SECS without sleeping.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        let wedged = tokio::spawn(async move {
            // Take the request, then hold the ack forever: never reply, never drop.
            let held = rx.recv().await;
            std::future::pending::<()>().await;
            drop(held);
        });
        let err = snapshot_now(&Some(tx)).await.unwrap_err();
        assert!(err.contains("timed out"), "got: {err}");
        wedged.abort();
    }

    // FIN-001 Task 4: the operator-gated settlement-resume auth matrix, exercised as
    // a pure function (no env, no I/O) — the primary, deterministic evidence.
    #[test]
    fn admin_key_check_is_fail_closed_and_constant_shape() {
        let k = "0x".to_string() + &"aa".repeat(32);
        let wrong = "0x".to_string() + &"bb".repeat(32);
        // unset config ⇒ endpoint disabled (fail-closed), regardless of what's presented
        assert_eq!(admin_resume_authz(None, None), AdminAuthz::Disabled);
        assert_eq!(admin_resume_authz(None, Some(&k)), AdminAuthz::Disabled);
        // configured but no header presented ⇒ unauthorized
        assert_eq!(admin_resume_authz(Some(&k), None), AdminAuthz::Unauthorized);
        // wrong presented ⇒ unauthorized
        assert_eq!(
            admin_resume_authz(Some(&k), Some(&wrong)),
            AdminAuthz::Unauthorized
        );
        // a length-only prefix must NOT authorize (the fold folds the length too)
        assert_eq!(
            admin_resume_authz(Some(&k), Some("0xaa")),
            AdminAuthz::Unauthorized
        );
        // exact match ⇒ ok
        assert_eq!(admin_resume_authz(Some(&k), Some(&k)), AdminAuthz::Ok);
    }

    #[test]
    fn empty_configured_admin_key_is_disabled_not_authorizing() {
        // blank configured key ⇒ disabled, even with a blank presented header
        assert_eq!(admin_resume_authz(Some(""), Some("")), AdminAuthz::Disabled);
        assert_eq!(admin_resume_authz(Some(""), None), AdminAuthz::Disabled);
        // a real key still works and still rejects a blank/wrong header
        let k = "0x".to_string() + &"aa".repeat(32);
        assert_eq!(admin_resume_authz(Some(&k), Some(&k)), AdminAuthz::Ok);
        assert_eq!(
            admin_resume_authz(Some(&k), Some("")),
            AdminAuthz::Unauthorized
        );
    }

    // FIN-001 Task 4: the async handler flips the shared force flag ONLY on an exact
    // FIN_ADMIN_KEY match; wrong/absent key ⇒ 401 (no action); key unset ⇒ 503.
    // Serialize with wind-down route tests: FIN_ADMIN_KEY is process-global.
    #[tokio::test]
    async fn resume_sets_force_flag_when_authorized() {
        let _env = wind_down::ADMIN_ENV_LOCK.lock().await;
        use axum::http::HeaderMap;
        use std::sync::atomic::Ordering;

        let app = test_app();
        let key = "0x".to_string() + &"aa".repeat(32);
        std::env::set_var("FIN_ADMIN_KEY", &key);
        app.force_settle.store(false, Ordering::SeqCst);

        // exact admin key ⇒ 200 + force flag set (health is only REPORTED, not flipped)
        let mut ok_headers = HeaderMap::new();
        ok_headers.insert("x-admin-key", key.parse().unwrap());
        let resp = post_v1_admin_resume(State(app.clone()), ok_headers)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            app.force_settle.load(Ordering::SeqCst),
            "force flag set on 200"
        );

        // wrong key ⇒ 401, flag NOT set
        app.force_settle.store(false, Ordering::SeqCst);
        let mut bad_headers = HeaderMap::new();
        bad_headers.insert(
            "x-admin-key",
            ("0x".to_string() + &"bb".repeat(32)).parse().unwrap(),
        );
        let resp = post_v1_admin_resume(State(app.clone()), bad_headers)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !app.force_settle.load(Ordering::SeqCst),
            "wrong key must not force"
        );

        // missing header ⇒ 401
        let resp = post_v1_admin_resume(State(app.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!app.force_settle.load(Ordering::SeqCst));

        // FIN_ADMIN_KEY unset ⇒ 503 (disabled), even with a header present
        std::env::remove_var("FIN_ADMIN_KEY");
        let mut hdr = HeaderMap::new();
        hdr.insert("x-admin-key", key.parse().unwrap());
        let resp = post_v1_admin_resume(State(app.clone()), hdr)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            !app.force_settle.load(Ordering::SeqCst),
            "disabled must not force"
        );
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

    // SEC-021 (final-review M-c): the whole server-custody defence composes with one
    // load-bearing invariant — an UNBOUND account can hold no funds in production. The
    // FIRST bind is deliberately free for a bare API key (only the NEW address signs,
    // SEC-021b covers only rebinds), and that is harmless griefing exactly because
    // neither crediting path will fund the account first: the self-service credit is
    // prod-disabled (DP-001) and the on-chain credit requires a binding. Nothing else
    // pins that composition, so pin it here: both paths must refuse an unbound
    // account, each on its stated ground, and no balance may appear.
    #[test]
    fn prod_unbound_account_cannot_be_credited_by_either_path() {
        let mut gw = Gw::boot();
        gw.prod = true;
        let (key, owner) = gw.register_account(None); // no signer, never bound

        // Path 1: the self-service credit is prod-disabled outright (DP-001).
        let err = gw
            .account_deposit(&key, 0, 20_000 * QUOTE_SCALE)
            .expect_err("prod self-service deposit must be refused");
        assert!(
            err.contains("disabled in production"),
            "unexpected error: {err}"
        );

        // Path 2: the on-chain credit requires a binding. Everything ELSE about this
        // confirm is valid — a stored authorization whose blind reproduces the
        // on-chain ownerCommit, a positive amount, the next-in-line deposit id — so
        // the ONLY check refusing it is the missing binding (drop that check and this
        // credit lands, failing the test).
        let blind = [0x11u8; 32];
        let commit = owner_commit(&owner, &blind);
        gw.accounts
            .get_mut(&key)
            .unwrap()
            .deposit_authorizations
            .insert(commit, blind);
        let next_id = gw.seq.state.consumed_deposit_count;
        let err = gw
            .account_confirm_deposit(&key, [0x22u8; 20], commit, 1_000, next_id, "0xtx", 0)
            .expect_err("an unbound account must not be creditable from a real deposit");
        assert!(
            err.contains("Bind a deposit address first"),
            "unexpected error: {err}"
        );
        // The invariant itself: the unbound account still holds nothing.
        assert_eq!(
            gw.market_free_of(&owner, 0),
            0,
            "an unbound account must hold no funds in production"
        );
    }

    // audit LIQ-001b: the public /api/state + /ws snapshot must never expose the
    // market-maker's inventory in production — mm_hedge is dev-only detail.
    #[test]
    fn prod_snapshot_omits_mm_hedge() {
        let mut gw = Gw::boot();
        // Open a real MM position via the same live-order path the demo boot uses:
        // the demo user's Ioc order crosses at the mark, and the seal loop counters
        // it with an opposite MM order (see `tick`), so mm_hedge WOULD be populated
        // when not in prod.
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
        gw.place_order(&req).expect("accepted");
        gw.tick();
        assert!(
            gw.seq
                .state
                .position(&gw.mm.owner, 0)
                .is_some_and(|p| p.size != 0),
            "MM opened a countering position after the seal",
        );

        gw.prod = true;
        let snap = gw.snapshot();
        assert!(
            snap.mm_hedge.is_empty(),
            "prod public snapshot must not expose MM inventory",
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

    /// Build a router in the given mode, issue one bare (unauthenticated,
    /// empty-body) request at `path`, and return the response status. The
    /// method matches the mounted route (`/v1/lp` is GET; the LP mutations are
    /// POST) so a mounted route answers with its real handler-surface status —
    /// a wrong-method request would return 405 and still satisfy the not-404
    /// discriminator, but would not verify what a mounted route actually says.
    async fn router_status_for(prod: bool, path: &str) -> StatusCode {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _; // for `oneshot`

        let method = if path == "/v1/lp" { "GET" } else { "POST" };
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        build_router(test_app(), prod)
            .oneshot(req)
            .await
            .unwrap()
            .status()
    }

    /// SEC-025-C: the LP pool credits via an unbacked mint (`pool_transfer` →
    /// `fund_amount_unbacked`), so it cannot exist in production without breaking
    /// settlement. Task 2 refuses it at the call site; this keeps it off the surface
    /// entirely. **Must fail at the parent commit** — these routes are mounted today.
    #[tokio::test]
    async fn lp_routes_are_absent_in_production() {
        for path in ["/v1/lp", "/v1/lp/deposit", "/v1/lp/withdraw"] {
            let status = router_status_for(/* prod */ true, path).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{path} must not be mounted in production"
            );
        }
    }

    /// …and still present in demo, so this is a posture change, not a deletion.
    /// Beyond the not-404 discriminator, pin the statuses a mounted route
    /// actually returns to a bare request: `/v1/lp` hits `api_key_from` → 401;
    /// the POST routes die in the `Json` extractor first (no content-type on an
    /// empty body → 415) — the extractor runs before the handler's auth check.
    #[tokio::test]
    async fn lp_routes_are_present_in_demo() {
        for (path, expect) in [
            ("/v1/lp", StatusCode::UNAUTHORIZED),
            ("/v1/lp/deposit", StatusCode::UNSUPPORTED_MEDIA_TYPE),
            ("/v1/lp/withdraw", StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ] {
            let status = router_status_for(/* prod */ false, path).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "{path} must remain mounted in demo"
            );
            assert_eq!(status, expect, "{path} mounted-route status in demo");
        }
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

    // ZK-001 follow-up: production must reject the public dev oracle signer key (the
    // well-known Anvil account #1). Booting prod on it pins every Market.oracle_pubkey to a
    // PUBLIC address, so anyone could sign fabricated oracle transcripts that clear the §8
    // signature gate — re-opening the price-fabrication hole ZK-001 closes.
    #[test]
    fn production_requires_a_secret_oracle_signer() {
        assert!(
            !oracle_signer_ok_for_mode(true, true),
            "production must reject the public dev oracle key"
        );
        assert!(
            oracle_signer_ok_for_mode(true, false),
            "production boots with a secret oracle key"
        );
        assert!(
            oracle_signer_ok_for_mode(false, true),
            "demo build boots with the dev oracle default"
        );
        assert!(
            oracle_signer_ok_for_mode(false, false),
            "demo build boots with a real oracle key too"
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

    // SEC-021 (Task-2 review Finding 3): production must refuse the zero-vault dev
    // fallback — a prod-posture gateway with no L1 bridge and no L1_VAULT would bind
    // every withdrawal/rebind digest to (84532, 0x00…00), byte-identical to the
    // unit-test identity and to every other such deployment, so the cross-deployment
    // replay protection would be vacuous.
    #[test]
    fn production_requires_a_real_vault_binding() {
        assert!(
            !vault_binding_ok_for_mode(true, [0u8; 20]),
            "production must reject the zero-vault fallback (L1_VAULT unset or zero)"
        );
        assert!(
            vault_binding_ok_for_mode(true, [0x22u8; 20]),
            "production boots with a real vault address"
        );
        assert!(
            vault_binding_ok_for_mode(false, [0u8; 20]),
            "demo build boots on the zero-vault fallback"
        );
        assert!(
            vault_binding_ok_for_mode(false, [0x22u8; 20]),
            "demo build boots with a real vault too"
        );
        // the gate's zero test IS the shared fallback const — if the fallback ever
        // changes, this keeps the gate honest.
        assert_eq!(DEV_FALLBACK_VAULT, [0u8; 20]);
    }

    // SEC-021 (final-review M-e): the deployment-identity env vars follow the same
    // convention as GATEWAY_SIGNER_KEY — UNSET ⇒ dev fallback, SET-but-malformed ⇒
    // fail closed. Before this, L1_CHAIN_ID=0x14a34 silently became 84532 and a
    // malformed L1_VAULT silently became the zero address, which the prod boot gate
    // then reported as "L1_VAULT must be set" (it WAS set — just malformed).
    #[test]
    fn deployment_identity_env_vars_fall_back_only_when_unset() {
        // unset ⇒ the documented dev fallback (unchanged behavior)
        assert_eq!(parse_l1_chain_id(None), Ok(DEV_FALLBACK_CHAIN_ID));
        assert_eq!(parse_l1_vault(None), Ok(DEV_FALLBACK_VAULT));
        // set + well-formed ⇒ parsed (the trim is preserved)
        assert_eq!(parse_l1_chain_id(Some("8453".into())), Ok(8453));
        assert_eq!(parse_l1_chain_id(Some(" 84532 ".into())), Ok(84532));
        let addr = "0x00000000000000000000000000000000000000aa";
        assert_eq!(
            parse_l1_vault(Some(addr.into())),
            Ok(parse_addr20_hex(addr).unwrap())
        );
        // set + malformed ⇒ Err naming the var, NEVER the silent fallback. The hex
        // chain-id form is the documented foot-gun (Base Sepolia's 84532 = 0x14a34).
        for bad in ["0x14a34", "", "84532n", "eighty"] {
            let err = parse_l1_chain_id(Some(bad.into()))
                .expect_err("a set-but-malformed L1_CHAIN_ID must fail closed");
            assert!(err.contains("L1_CHAIN_ID"), "unexpected error: {err}");
        }
        for bad in [
            "not-an-address",
            "0x1234",
            "",
            "0xgg000000000000000000000000000000000000gg",
        ] {
            let err = parse_l1_vault(Some(bad.into()))
                .expect_err("a set-but-malformed L1_VAULT must fail closed");
            assert!(err.contains("L1_VAULT"), "unexpected error: {err}");
        }
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

        // Independently derive the same roots and assert byte-equality (SEC-025-B:
        // the mock returns the RAW remote shape, so its itemised roots are Options).
        let mut state = witness.pre_state.clone();
        let d = derive_roots(&mut state, &witness.ops, &witness.manifest).expect("derive");
        assert_eq!(out.roots.prev_root, Some(d.prev_state_root));
        assert_eq!(out.roots.manifest_hash, Some(d.manifest_hash));
        assert_eq!(out.roots.new_root, Some(d.new_state_root));
        assert_eq!(out.roots.ordered_root, Some(d.ordered_root));
        assert_eq!(out.roots.withdrawals_root, Some(d.withdrawals_root));
        assert_eq!(out.roots.rejected_root, Some(d.rejected_root));
        assert_eq!(out.roots.deposits_root, Some(d.deposits_root));
        assert_eq!(out.commitment, d.commitment::<Keccak256>());
        // MockZkVerifier accepts proof == commitment.
        assert_eq!(out.proof, out.commitment.to_vec());
    }

    #[test]
    fn prover_from_str_selects_path() {
        assert!(prover_from_str(None, false).unwrap().is_none());
        assert!(prover_from_str(Some(""), false).unwrap().is_none());
        assert!(prover_from_str(Some("mock"), false).unwrap().is_some());
        // SEC-020 fail-closed: an HTTP prover needs an explicit seal root — with
        // PROVER_SEAL_ROOT unset (and no DEV_INSECURE) it must refuse, never
        // default to the old repo-public [0x5E; 32] constant. No other test
        // touches these env vars, so this test owns them without racing.
        std::env::remove_var("PROVER_SEAL_ROOT");
        std::env::remove_var("DEV_INSECURE");
        assert!(
            prover_from_str(Some("http://prover.local:8091"), false).is_err(),
            "unset seal root must refuse the HTTP prover path (fail-closed)"
        );
        std::env::set_var("PROVER_SEAL_ROOT", "11".repeat(32));
        assert!(prover_from_str(Some("http://prover.local:8091"), false)
            .unwrap()
            .is_some());
        assert!(
            prover_from_str(Some("http://prover.local:8091"), true)
                .unwrap()
                .is_some(),
            "an explicit seal root serves prod too"
        );
        std::env::remove_var("PROVER_SEAL_ROOT");
    }

    /// SEC-025-B §6: DARKPERP_PROD=1 must refuse a prover-less settle path — but an
    /// L1-configured TESTNET must still be able to run with mock. `production_mode` is
    /// `l1_enabled || DARKPERP_PROD`, so keying this on `prod` would leave no
    /// configuration that settles on-chain without a real prover.
    #[test]
    fn strict_prod_refuses_a_proverless_settle_path() {
        for v in [None, Some(""), Some("mock")] {
            // Not `expect_err`: that needs `T: Debug` and `Arc<dyn ProverClient>` has
            // no Debug impl (the brief's fixture as written did not compile).
            let err =
                match prover_from_str_strict(v, /* prod */ true, /* strict_prod */ true) {
                    Err(e) => e,
                    Ok(_) => panic!("strict production must refuse a prover-less path (v={v:?})"),
                };
            assert!(
                err.contains("PROVER_URL"),
                "the error must name the variable an operator has to set, got: {err}"
            );
        }
    }

    /// The case the first draft of this design would have broken: an L1-configured
    /// testnet is `production_mode` (because `l1_enabled` implies it) but is NOT strict
    /// production, and must still be able to settle on-chain with the mock prover.
    #[test]
    fn a_testnet_may_still_use_the_mock_prover() {
        let c = prover_from_str_strict(
            Some("mock"),
            /* prod */ true,
            /* strict_prod */ false,
        )
        .expect("mock is allowed outside strict production, even when prod-mode is on");
        assert!(
            c.is_some(),
            "mock must yield a client, not the legacy None path"
        );
    }

    /// The legacy None path is gone (Task 4 deleted L1::settle), so an unset PROVER_URL
    /// outside strict production must still produce no client — the caller treats that
    /// as "do not run the settle loop", not as "settle through a deleted path".
    #[test]
    fn unset_prover_url_outside_strict_prod_yields_no_client() {
        let c = prover_from_str_strict(None, false, false).expect("allowed");
        assert!(c.is_none());
    }

    /// Task-4 carry-in (SEC-025-B): with L1 configured but NO prover, the legacy settle
    /// body is deleted, so nothing can ever land on-chain — the tick loop's SETTLE_TICKS
    /// simulation would report SETTLED over real collateral that never settled (false
    /// finality). The simulation must be off for ANY L1-configured boot; only the pure
    /// demo (no L1, no prover) keeps it. The tick-loop mechanism this flag gates is
    /// exercised by `window_mode_defers_settled_until_commit` /
    /// `legacy_mode_settles_after_ticks_unchanged`; this pins the boot-wiring decision.
    #[test]
    fn l1_without_a_prover_must_not_simulate_settled() {
        assert!(
            honest_finality_required(/* prover */ false, /* l1 */ true),
            "L1 with no prover cannot settle — simulating SETTLED would be false finality"
        );
        assert!(honest_finality_required(true, true));
        assert!(honest_finality_required(true, false));
        assert!(
            !honest_finality_required(false, false),
            "the pure demo (no L1, no prover) keeps the legacy tick simulation"
        );
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

    /// SEC-025-E1 Task 3: order ids are `format!("o{nonce}")` — PER-ACCOUNT,
    /// not globally unique — so a cancel MUST resolve the id inside the
    /// caller's own list and nowhere else. The legacy demo `POST /api/cancel`
    /// resolves ids against the SHARED DEMO WALLET's list (`Gw::cancel` over
    /// `self.orders`), which is why the browser mis-cancelling a stranger's
    /// same-named order was live until Task 3 re-routed it to
    /// `DELETE /v1/orders/:id`. This pins the /v1 path's resolution scope.
    #[test]
    fn account_cancel_cannot_reach_another_accounts_order() {
        let mut gw = Gw::boot();
        let (a_key, _a_owner) = gw.register_account(None);
        let (b_key, _b_owner) = gw.register_account(None);
        gw.account_deposit(&a_key, 0, 20_000 * QUOTE_SCALE)
            .expect("A deposit");
        gw.account_deposit(&b_key, 0, 20_000 * QUOTE_SCALE)
            .expect("B deposit");
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
        // No tick between place and cancel: both orders stay ACCEPTED/unsealed.
        gw.account_place_order(&a_key, &req).expect("A order");
        gw.account_place_order(&b_key, &req).expect("B order");
        let ids = |gw: &Gw, key: &[u8; 32]| -> Vec<String> {
            gw.v1_orders_json(key).unwrap()["orders"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["orderId"].as_str().unwrap().to_string())
                .collect()
        };
        // THE DISCRIMINATING PRECONDITION: each account's first order takes
        // the registration-initial nonce 1, so BOTH lists hold an order with
        // the SAME id "o1". Without this collision the test proves nothing
        // about targeting — a wrong-list resolver would merely 404 and fail
        // for the wrong reason.
        assert_eq!(ids(&gw, &a_key), ["o1"], "A holds its own o1");
        assert_eq!(ids(&gw, &b_key), ["o1"], "B holds its own, same-named o1");
        // A's cancel removes A's order ONLY.
        gw.account_cancel(&a_key, "o1")
            .expect("A cancels its own o1");
        assert_eq!(ids(&gw, &a_key), ["o1"], "receipt history is retained");
        assert_eq!(
            gw.v1_orders_json(&a_key).unwrap()["orders"][0]["execution"]["status"],
            "CANCELLED"
        );
        assert_eq!(
            ids(&gw, &b_key),
            ["o1"],
            "B's same-named order must be untouched by A's cancel"
        );
        // And an id ABSENT from the caller's list errors even though another
        // account still holds one by that name — resolution never crosses.
        let err = gw
            .account_cancel(&a_key, "o2")
            .expect_err("A never held o2");
        assert_eq!(err, "Order not found.");
        assert_eq!(
            ids(&gw, &b_key),
            ["o1"],
            "the failed cancel mutated no other account's list"
        );
    }

    /// SEC-025-E1 decision (c): `GET /v1/orders` serves each order's ACCEPTANCE
    /// RECEIPT — the exact one `account_place_order` returned — so a browser can
    /// render receipts for orders placed in ANY session, not just those whose
    /// receipt it still holds from its own placeOrder response.
    ///
    /// TWO orders, deliberately: orders are stored newest-first (`insert(0, …)`),
    /// so a handler that served `a.orders[0].receipt` for EVERY order — a
    /// realistic mis-index — passes a single-order assert. Each served order
    /// must carry ITS OWN receipt, and the second order's non-zero `seqNo`
    /// closes the hole where a zeroed fabrication matched the first order's
    /// genuine `seqNo == 0`.
    #[test]
    fn v1_orders_carry_the_acceptance_receipt() {
        let mut gw = Gw::boot();
        let (key, _owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE)
            .expect("deposit");
        let req = |size: i128| OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: size.to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            nonce: None,
            signature: None,
            ..Default::default()
        };
        let first = gw
            .account_place_order(&key, &req(SIZE_SCALE / 10))
            .expect("order 1");
        let second = gw
            .account_place_order(&key, &req(SIZE_SCALE / 20))
            .expect("order 2");
        // Fixture guard: the two receipts must be distinguishable in the fields
        // asserted below, or the per-order pairing proves nothing.
        assert_ne!(first.order_hash, second.order_hash, "distinct order hashes");
        assert_ne!(first.seq_no, second.seq_no, "distinct seqNos");
        assert!(
            second.seq_no > 0,
            "second acceptance has a non-zero seqNo (a zeroed fabrication cannot match it)"
        );
        let v = gw.v1_orders_json(&key).unwrap();
        let orders = v["orders"].as_array().unwrap();
        assert_eq!(orders.len(), 2);
        // Newest-first storage: orders[0] is the SECOND order placed. Each served
        // receipt must be the STORED acceptance receipt for THAT order, field by
        // field (camelCase per WReceipt's serde rename) — not a default, not a
        // reconstruction, and not the newest order's receipt repeated.
        for (o, want) in [(&orders[0], &second), (&orders[1], &first)] {
            let r = &o["receipt"];
            assert_eq!(r["orderHash"], serde_json::json!(want.order_hash));
            assert_eq!(r["seqNo"], serde_json::json!(want.seq_no));
            assert_eq!(r["recvTimeMs"], serde_json::json!(want.recv_time_ms));
            assert_eq!(r["batchIdHint"], serde_json::json!(want.batch_id_hint));
            assert_eq!(r["windowId"], serde_json::json!(want.window_id));
            // internal consistency: the receipt names the same order as the flat field
            assert_eq!(o["orderHash"], r["orderHash"]);
        }
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
            gw.account_set_deposit_address(&key, addr, &bad, None)
                .is_err(),
            "a proof not from the bound address is rejected",
        );

        // the address's own key proves control → bind succeeds
        let good = sign(&eoa, &deposit_bind_digest(&owner, &addr));
        assert!(
            gw.account_set_deposit_address(&key, addr, &good, None)
                .is_ok(),
            "valid ownership proof accepted",
        );

        // exclusivity: another account can't bind the same address (even controlling it)
        let (key2, owner2) = gw.register_account(None);
        let good2 = sign(&eoa, &deposit_bind_digest(&owner2, &addr));
        assert!(
            gw.account_set_deposit_address(&key2, addr, &good2, None)
                .is_err(),
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
            gw.account_set_deposit_address(&key, addr, &sig, None)
                .is_ok(),
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
            gw.account_set_deposit_address(&key2, addr2, &sig2, None)
                .is_ok(),
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
                gw.account_set_deposit_address(&key3, addr3, &bad, None)
                    .is_err(),
                "wrong-key signature rejected for digest form {i}",
            );
        }
    }

    /// Shared by the SEC-021b rebind tests below: sign a 32-byte digest directly
    /// (the raw-digest shape (a) of `eip191_prehash_candidates`).
    fn sign_digest(sk: &k256::ecdsa::SigningKey, digest: &[u8; 32]) -> [u8; 65] {
        let (sig, recid) = sk.sign_prehash_recoverable(digest).unwrap();
        let mut s = [0u8; 65];
        s[..64].copy_from_slice(&sig.to_bytes());
        s[64] = 27 + recid.to_byte();
        s
    }
    /// The Ethereum address of a secp256k1 key (keccak of the uncompressed point).
    fn eth_addr(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
        use sha3::{Digest as _, Keccak256 as RawKeccak};
        let point = sk.verifying_key().to_encoded_point(false);
        let hash = RawKeccak::digest(&point.as_bytes()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&hash[12..]);
        a
    }

    /// SEC-021 fixture: credit an account through the same dev-mode path the
    /// pre-existing withdrawal tests use (`account_deposit`, the DP-001-guarded
    /// self-service credit — enabled because tests boot non-prod).
    fn fund_test_account(gw: &mut Gw, key: &[u8; 32], amount: i128) {
        gw.account_deposit(key, 0, amount).unwrap();
    }

    /// SEC-021 fixture for tests whose SUBJECT is not withdrawal authorization:
    /// register a CALLER-SIGNED account (its registered signer authorizes its
    /// withdrawals and the destination stays free, so each test keeps its original
    /// `to` values and assertions) and return the key material to sign with.
    fn register_withdrawer(gw: &mut Gw) -> ([u8; 32], k256::ecdsa::SigningKey) {
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x51u8; 32]).unwrap();
        let (key, _owner) = gw.register_account(Some(eth_addr(&sk)));
        (key, sk)
    }

    /// SEC-021 fixture: a withdrawal through the REAL authorization path — computes
    /// `withdraw_auth_digest` for the account's next strictly-increasing auth nonce
    /// and signs it with `sk`. No exemption anywhere: `account_withdraw` runs its
    /// full destination/nonce/signature/balance checks on every call.
    fn signed_withdraw(
        gw: &mut Gw,
        key: &[u8; 32],
        sk: &k256::ecdsa::SigningKey,
        market: u64,
        amount: i128,
        to: [u8; 20],
    ) -> Result<Withdrawal, String> {
        let (owner, nonce) = {
            let a = gw.accounts.get(key).unwrap();
            (a.wallet.owner, a.last_withdraw_nonce + 1)
        };
        let sig = sign_digest(
            sk,
            &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, market, amount, &to, nonce),
        );
        gw.account_withdraw(key, market, amount, to, nonce, &sig)
    }

    /// SEC-021b: an attacker holding ONLY the API key must not be able to move the
    /// account's deposit-address binding to an address they control. Before the fix,
    /// account_set_deposit_address proved control only of the NEW address and
    /// overwrote an existing binding unconditionally — so a leaked key plus the
    /// attacker's own signature was enough to redirect every future withdrawal.
    #[test]
    fn leaked_api_key_alone_cannot_rebind_deposit_address() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let victim_sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let victim_eoa = eth_addr(&victim_sk);
        let attacker_sk = SigningKey::from_slice(&[0xA5u8; 32]).unwrap();
        let attacker_eoa = eth_addr(&attacker_sk);

        let (key, owner) = gw.register_account(None);

        // Victim binds their own address — one signature, unchanged flow.
        let bind_sig = sign_digest(&victim_sk, &deposit_bind_digest(&owner, &victim_eoa));
        gw.account_set_deposit_address(&key, victim_eoa, &bind_sig, None)
            .expect("first bind succeeds");

        // Attacker has the API key and their own key. They can sign for their OWN
        // address trivially — that was the whole bypass.
        let attacker_bind_sig =
            sign_digest(&attacker_sk, &deposit_bind_digest(&owner, &attacker_eoa));
        let err = gw
            .account_set_deposit_address(&key, attacker_eoa, &attacker_bind_sig, None)
            .expect_err("rebind without the current address's signature must be refused");
        assert!(
            err.contains("rebinding requires"),
            "expected the MISSING-`currentSignature` rejection (not the bad-signature one): {err}"
        );

        // Binding is untouched.
        assert_eq!(
            gw.accounts.get(&key).unwrap().deposit_address,
            Some(victim_eoa)
        );

        // A rebind signed by the CURRENT address is allowed (legitimate rotation).
        let rotate_sig = sign_digest(
            &victim_sk,
            &rebind_auth_digest(
                gw.chain_id,
                &gw.vault,
                &owner,
                0,
                &victim_eoa,
                &attacker_eoa,
            ),
        );
        gw.account_set_deposit_address(&key, attacker_eoa, &attacker_bind_sig, Some(&rotate_sig))
            .expect("rebind authorized by the current address succeeds");
        assert_eq!(
            gw.accounts.get(&key).unwrap().deposit_address,
            Some(attacker_eoa)
        );
        assert_eq!(
            gw.accounts.get(&key).unwrap().rebind_counter,
            1,
            "rebind burns the authorization"
        );
    }

    /// SEC-021b: a rebind authorization is SINGLE-USE. Without the counter in the digest,
    /// a signature over (owner, A, B) stays valid any time the bound address is A — so a
    /// user who rotates A->B and later back to A hands anyone holding the old signature
    /// (plus a leaked API key) the power to force the binding back to B. That is worst
    /// exactly when it matters most: rotating away from a compromised address.
    #[test]
    fn a_rebind_authorization_cannot_be_replayed_after_returning_to_the_old_address() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let a_sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let b_sk = SigningKey::from_slice(&[0xB5u8; 32]).unwrap();
        let a = eth_addr(&a_sk);
        let b = eth_addr(&b_sk);
        let (key, owner) = gw.register_account(None);
        let bind_a = sign_digest(&a_sk, &deposit_bind_digest(&owner, &a));
        let bind_b = sign_digest(&b_sk, &deposit_bind_digest(&owner, &b));
        gw.account_set_deposit_address(&key, a, &bind_a, None)
            .unwrap();

        // Rotate A -> B (counter 0), then B -> A (counter 1).
        let a_to_b = sign_digest(
            &a_sk,
            &rebind_auth_digest(gw.chain_id, &gw.vault, &owner, 0, &a, &b),
        );
        gw.account_set_deposit_address(&key, b, &bind_b, Some(&a_to_b))
            .unwrap();
        let b_to_a = sign_digest(
            &b_sk,
            &rebind_auth_digest(gw.chain_id, &gw.vault, &owner, 1, &b, &a),
        );
        gw.account_set_deposit_address(&key, a, &bind_a, Some(&b_to_a))
            .unwrap();
        assert_eq!(gw.accounts.get(&key).unwrap().deposit_address, Some(a));
        assert_eq!(gw.accounts.get(&key).unwrap().rebind_counter, 2);

        // The account is bound to A again — replay the ORIGINAL A->B authorization.
        let err = gw
            .account_set_deposit_address(&key, b, &bind_b, Some(&a_to_b))
            .expect_err("a spent rebind authorization must not work a second time");
        assert!(
            err.contains("rebind not authorized"),
            "unexpected error: {err}"
        );
        assert_eq!(
            gw.accounts.get(&key).unwrap().deposit_address,
            Some(a),
            "binding unchanged"
        );
        // A REJECTED rebind must not advance the generation. If it did, an attacker
        // holding only the API key could spam garbage `currentSignature`s to burn
        // the generation and silently invalidate a legitimate rotation signature
        // the user already holds — a rotation DoS, worst exactly when the user is
        // rotating away from a compromised address.
        assert_eq!(
            gw.accounts.get(&key).unwrap().rebind_counter,
            2,
            "a rejected rebind must not burn the generation"
        );
    }

    /// SEC-021b: re-binding the SAME already-bound address is an idempotent no-op —
    /// it succeeds without a `currentSignature`, leaves the binding unchanged, and
    /// must NOT advance `rebind_counter` (only an ACCEPTED move to a DIFFERENT
    /// address burns a generation).
    #[test]
    fn rebinding_the_same_address_is_a_no_op_and_burns_no_generation() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let a = eth_addr(&sk);
        let (key, owner) = gw.register_account(None);
        let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &a));
        gw.account_set_deposit_address(&key, a, &bind, None)
            .expect("first bind succeeds");

        gw.account_set_deposit_address(&key, a, &bind, None)
            .expect("re-binding the already-bound address is an idempotent Ok");
        let acct = gw.accounts.get(&key).unwrap();
        assert_eq!(acct.deposit_address, Some(a), "binding unchanged");
        assert_eq!(
            acct.rebind_counter, 0,
            "an idempotent same-address re-bind must not burn a generation"
        );
    }

    /// SEC-021b ordering pin: the proof-of-control check runs BEFORE the idempotent
    /// same-address short-circuit. Hoisted above the proof, that short-circuit would
    /// hand an API-key-only attacker an oracle: call with a GUESSED address and a
    /// garbage signature — an `Ok` confirms the guess is the bound address, without
    /// controlling it or holding any signature at all.
    #[test]
    fn same_address_short_circuit_still_requires_the_control_proof() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let a = eth_addr(&sk);
        let (key, owner) = gw.register_account(None);
        let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &a));
        gw.account_set_deposit_address(&key, a, &bind, None)
            .expect("first bind succeeds");

        // Same (currently bound) address, garbage signature: the proof must be
        // checked first, so this is an Err — never an idempotent Ok.
        let garbage = [0u8; 65];
        assert!(
            gw.account_set_deposit_address(&key, a, &garbage, None)
                .is_err(),
            "a garbage signature must fail even when `addr` equals the bound address"
        );
        assert_eq!(
            gw.accounts.get(&key).unwrap().rebind_counter,
            0,
            "the rejected probe must not burn a generation either"
        );
    }

    /// SEC-021b: every field of the rebind digest is public (owner, chain_id, vault,
    /// rebind_counter, both addresses), so an attacker CAN compute the exact digest
    /// the current address would sign. Authorization must therefore hinge on WHO
    /// signed: the correct digest signed by the attacker's OWN key is rejected.
    #[test]
    fn a_correct_rebind_digest_signed_by_the_wrong_key_is_rejected() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let victim_sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let victim_eoa = eth_addr(&victim_sk);
        let attacker_sk = SigningKey::from_slice(&[0xA5u8; 32]).unwrap();
        let attacker_eoa = eth_addr(&attacker_sk);
        let (key, owner) = gw.register_account(None);
        let bind = sign_digest(&victim_sk, &deposit_bind_digest(&owner, &victim_eoa));
        gw.account_set_deposit_address(&key, victim_eoa, &bind, None)
            .expect("first bind succeeds");

        // The attacker computes the CORRECT current rebind digest — everything in
        // it is public — but can only sign it with their own key.
        let attacker_bind = sign_digest(&attacker_sk, &deposit_bind_digest(&owner, &attacker_eoa));
        let forged = sign_digest(
            &attacker_sk,
            &rebind_auth_digest(
                gw.chain_id,
                &gw.vault,
                &owner,
                0,
                &victim_eoa,
                &attacker_eoa,
            ),
        );
        let err = gw
            .account_set_deposit_address(&key, attacker_eoa, &attacker_bind, Some(&forged))
            .expect_err("a `currentSignature` from the wrong key must be rejected");
        assert!(
            err.contains("rebind not authorized"),
            "unexpected error: {err}"
        );
        let acct = gw.accounts.get(&key).unwrap();
        assert_eq!(acct.deposit_address, Some(victim_eoa), "binding unchanged");
        assert_eq!(
            acct.rebind_counter, 0,
            "the rejected forgery must not burn a generation"
        );
    }

    /// SEC-021: the client needs the binding state to build a withdrawal signature.
    /// It persists only `{apiKey, owner}`, so after a reload `/v1/accounts/me` is its
    /// only source for which key must sign (`callerSigned` / `depositAddress`), the
    /// next auth nonce, the rebind generation, and the deployment (`chainId`, `vault`)
    /// every digest is bound to.
    #[test]
    fn v1_account_exposes_withdrawal_authorization_state() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        // A distinctive vault: `DEV_FALLBACK_VAULT` is the all-zero address, so
        // asserting against the boot default could not tell the real field from a
        // hardcoded zero. Every digest below reads `gw.vault`, so this stays coherent.
        gw.vault = [0x77u8; 20];
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let eoa = eth_addr(&sk);
        let (key, owner) = gw.register_account(None);

        let v = gw.v1_account(&key).unwrap();
        assert_eq!(v["depositAddress"], serde_json::Value::Null);
        assert_eq!(v["callerSigned"], false);
        assert_eq!(v["nextWithdrawNonce"], 1);
        assert_eq!(v["rebindCounter"], 0);
        // The client cannot build a valid digest without these.
        assert_eq!(v["chainId"], gw.chain_id);
        assert_eq!(v["vault"], hex0x(&gw.vault));

        let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
        gw.account_set_deposit_address(&key, eoa, &bind, None)
            .unwrap();
        let v = gw.v1_account(&key).unwrap();
        assert_eq!(v["depositAddress"], hex0x(&eoa));
        assert_eq!(v["rebindCounter"], 0, "a first-time bind is not a rebind");
        // Binding an address does NOT make the account caller-signed: `signer`
        // (None here) — not `deposit_address` — decides, and that precedence is
        // exactly what the client keys off to pick which key must sign.
        assert_eq!(v["callerSigned"], false);

        // One REAL authorized withdrawal: the served nonce must track
        // `last_withdraw_nonce` (the withdrawal-auth counter) — not any other
        // per-account counter, which all still read 0 here.
        fund_test_account(&mut gw, &key, 10_000);
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000, eoa).expect("authorized withdrawal");
        let v = gw.v1_account(&key).unwrap();
        assert_eq!(
            v["nextWithdrawNonce"], 2,
            "the served nonce advances with the withdrawal-auth counter"
        );

        // An ACCEPTED rebind (authorized by the currently bound address) must be
        // surfaced as the incremented generation — the client signs the NEXT
        // rebind digest over this value.
        let b_sk = SigningKey::from_slice(&[0xB7u8; 32]).unwrap();
        let b = eth_addr(&b_sk);
        let bind_b = sign_digest(&b_sk, &deposit_bind_digest(&owner, &b));
        let rotate = sign_digest(
            &sk,
            &rebind_auth_digest(gw.chain_id, &gw.vault, &owner, 0, &eoa, &b),
        );
        gw.account_set_deposit_address(&key, b, &bind_b, Some(&rotate))
            .expect("rebind authorized by the current address");
        let v = gw.v1_account(&key).unwrap();
        assert_eq!(v["depositAddress"], hex0x(&b));
        assert_eq!(
            v["rebindCounter"], 1,
            "an accepted rebind burns a generation"
        );

        // A caller-signed account reports callerSigned=true, so the client knows the
        // registered signer — not the bound deposit address — must sign withdrawals.
        let (key2, _owner2) = gw.register_account(Some(eth_addr(&sk)));
        let v2 = gw.v1_account(&key2).unwrap();
        assert_eq!(v2["callerSigned"], true);
    }

    /// SEC-021: the regression test for the reported finding. A caller-signed account
    /// exists precisely so a leaked API key cannot act — but the withdrawal path never
    /// read `acct.signer`, so the key alone could drain funds to any address.
    #[test]
    fn caller_signed_account_cannot_withdraw_without_a_signature() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (key, _owner) = gw.register_account(Some(eth_addr(&sk)));
        fund_test_account(&mut gw, &key, 10_000);
        let root_before = gw.seq.state.state_root();

        let err = gw
            .account_withdraw(&key, 0, 5_000, [0x66u8; 20], 1, &[0u8; 65])
            .expect_err("unsigned withdrawal must be refused");
        assert!(err.contains("signature"), "unexpected error: {err}");

        assert_eq!(gw.seq.state.state_root(), root_before, "no state mutation");
        assert_eq!(
            gw.accounts.get(&key).unwrap().last_withdraw_nonce,
            0,
            "a rejected withdrawal must not burn its nonce"
        );
    }

    /// SEC-021: server-custody accounts are authorized by the EOA they already proved
    /// they can sign with at bind time, and may only withdraw to that address.
    #[test]
    fn server_custody_withdrawal_requires_bound_address_signature_and_destination() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let eoa = eth_addr(&sk);
        let (key, owner) = gw.register_account(None);
        let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
        gw.account_set_deposit_address(&key, eoa, &bind, None)
            .unwrap();
        fund_test_account(&mut gw, &key, 10_000);

        // Wrong destination, even with a valid signature over that destination.
        let elsewhere = [0x66u8; 20];
        let sig_elsewhere = sign_digest(
            &sk,
            &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &elsewhere, 1),
        );
        let err = gw
            .account_withdraw(&key, 0, 5_000, elsewhere, 1, &sig_elsewhere)
            .expect_err("server-custody withdrawal to a non-bound address must be refused");
        assert!(
            err.contains("bound deposit address"),
            "unexpected error: {err}"
        );

        // Correct destination + signature.
        let sig = sign_digest(
            &sk,
            &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &eoa, 1),
        );
        let w = gw
            .account_withdraw(&key, 0, 5_000, eoa, 1, &sig)
            .expect("accepted");
        assert_eq!(w.to, eoa);
        assert_eq!(gw.accounts.get(&key).unwrap().last_withdraw_nonce, 1);

        // Replay of the same signed request.
        let err = gw
            .account_withdraw(&key, 0, 5_000, eoa, 1, &sig)
            .expect_err("replay must be refused");
        assert!(err.contains("nonce"), "unexpected error: {err}");
    }

    /// SEC-021: a validly signed withdrawal that fails on insufficient balance must NOT
    /// burn its nonce — otherwise the user's retry of the unchanged signed request would
    /// be rejected as a replay, stranding them.
    #[test]
    fn failed_withdrawal_does_not_burn_its_nonce() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let eoa = eth_addr(&sk);
        let (key, owner) = gw.register_account(None);
        let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
        gw.account_set_deposit_address(&key, eoa, &bind, None)
            .unwrap();
        fund_test_account(&mut gw, &key, 1_000);

        let sig = sign_digest(
            &sk,
            &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &eoa, 1),
        );
        let err = gw
            .account_withdraw(&key, 0, 5_000, eoa, 1, &sig)
            .expect_err("over-balance withdrawal fails");
        assert!(err.contains("Not withdrawable"), "unexpected error: {err}");
        assert_eq!(
            gw.accounts.get(&key).unwrap().last_withdraw_nonce,
            0,
            "nonce must survive a post-verification failure"
        );

        // Fund and retry the SAME signed request — it must now succeed.
        fund_test_account(&mut gw, &key, 10_000);
        gw.account_withdraw(&key, 0, 5_000, eoa, 1, &sig)
            .expect("the unchanged signed request is still valid on retry");
    }

    /// SEC-021: a caller-signed account's registered `signer` takes precedence — a
    /// signature from the bound deposit address must NOT authorize its withdrawals,
    /// or registering a signer would silently widen authorization instead of
    /// narrowing it.
    #[test]
    fn registered_signer_takes_precedence_over_bound_address() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let signer_sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let eoa_sk = SigningKey::from_slice(&[0xE0u8; 32]).unwrap();
        let eoa = eth_addr(&eoa_sk);
        let (key, owner) = gw.register_account(Some(eth_addr(&signer_sk)));
        let bind = sign_digest(&eoa_sk, &deposit_bind_digest(&owner, &eoa));
        gw.account_set_deposit_address(&key, eoa, &bind, None)
            .unwrap();
        fund_test_account(&mut gw, &key, 10_000);

        let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &eoa, 1);
        // The bound address signs — must be refused, the account registered a signer.
        let err = gw
            .account_withdraw(&key, 0, 5_000, eoa, 1, &sign_digest(&eoa_sk, &digest))
            .expect_err("bound-address signature must not authorize a caller-signed account");
        assert!(err.contains("signature"), "unexpected error: {err}");
        // The registered signer signs — accepted, and `to` is free for caller-signed.
        gw.account_withdraw(&key, 0, 5_000, eoa, 1, &sign_digest(&signer_sk, &digest))
            .expect("registered signer authorizes");
    }

    /// SEC-021: `owner` in the digest stops a signature being replayed onto a SECOND
    /// account registered to the same signer address.
    #[test]
    fn withdrawal_signature_does_not_replay_across_accounts() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let addr = eth_addr(&sk);
        let (key_a, owner_a) = gw.register_account(Some(addr));
        let (key_b, owner_b) = gw.register_account(Some(addr));
        assert_ne!(owner_a, owner_b);
        fund_test_account(&mut gw, &key_a, 10_000);
        fund_test_account(&mut gw, &key_b, 10_000);

        let to = [0x66u8; 20];
        let sig_a = sign_digest(
            &sk,
            &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner_a, 0, 5_000, &to, 1),
        );
        let err = gw
            .account_withdraw(&key_b, 0, 5_000, to, 1, &sig_a)
            .expect_err("account A's signature must not authorize account B");
        assert!(err.contains("signature"), "unexpected error: {err}");
    }

    /// SEC-021: the signature covers every money-moving field — tampering with any of
    /// them after signing must invalidate it.
    #[test]
    fn tampering_with_a_signed_withdrawal_invalidates_it() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (key, owner) = gw.register_account(Some(eth_addr(&sk)));
        fund_test_account(&mut gw, &key, 100_000);

        let to = [0x66u8; 20];
        let sig = sign_digest(
            &sk,
            &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &to, 1),
        );
        // Amount tampered.
        assert!(gw.account_withdraw(&key, 0, 9_000, to, 1, &sig).is_err());
        // Destination tampered.
        assert!(gw
            .account_withdraw(&key, 0, 5_000, [0x77u8; 20], 1, &sig)
            .is_err());
        // Nonce tampered.
        assert!(gw.account_withdraw(&key, 0, 5_000, to, 2, &sig).is_err());
        // Nothing was applied by any of the three.
        assert_eq!(gw.accounts.get(&key).unwrap().last_withdraw_nonce, 0);
        // The untampered request still works.
        gw.account_withdraw(&key, 0, 5_000, to, 1, &sig)
            .expect("untampered request is valid");
    }

    /// SEC-021: all three EIP-191 prehash shapes authorize a withdrawal, so both CLI
    /// signers and browser wallets work. Mirrors the deposit-bind shape test above.
    #[test]
    fn withdrawal_accepts_all_three_prehash_shapes() {
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let addr = eth_addr(&sk);
        let to = [0x66u8; 20];

        for shape in 0..3 {
            let mut gw = Gw::boot();
            let (key, owner) = gw.register_account(Some(addr));
            fund_test_account(&mut gw, &key, 10_000);
            let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &to, 1);
            let prehash = eip191_prehash_candidates(&digest)[shape];
            let sig = sign_digest(&sk, &prehash);
            gw.account_withdraw(&key, 0, 5_000, to, 1, &sig)
                .unwrap_or_else(|e| panic!("prehash shape {shape} must be accepted: {e}"));
        }
    }

    /// SEC-021: cross-flow and cross-deployment replay are both closed by the digest.
    #[test]
    fn withdrawal_signature_does_not_replay_across_deployments() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let eoa = eth_addr(&sk);
        let (key, owner) = gw.register_account(None);
        let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
        gw.account_set_deposit_address(&key, eoa, &bind, None)
            .unwrap();
        fund_test_account(&mut gw, &key, 10_000);

        // Signed for a DIFFERENT chain id.
        let foreign = sign_digest(
            &sk,
            &withdraw_auth_digest(gw.chain_id + 1, &gw.vault, &owner, 0, 5_000, &eoa, 1),
        );
        let err = gw
            .account_withdraw(&key, 0, 5_000, eoa, 1, &foreign)
            .expect_err("a signature for another deployment must be refused");
        assert!(err.contains("signature"), "unexpected error: {err}");
    }

    /// SEC-021: the /v1 LP withdrawal is authorized like any other withdrawal, and a
    /// withdrawal signature cannot be carried across into it.
    #[test]
    fn account_lp_withdraw_requires_its_own_signature() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let eoa = eth_addr(&sk);
        let (key, owner) = gw.register_account(None);
        let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
        gw.account_set_deposit_address(&key, eoa, &bind, None)
            .unwrap();
        fund_test_account(&mut gw, &key, 10_000);
        let wallet = gw.accounts.get(&key).unwrap().wallet;
        let shares = gw.lp_deposit(key, &wallet, 5_000).expect("stake");

        // A signature over the ACCOUNT-withdrawal digest must not authorize an LP
        // withdrawal — the two digests are domain-separated.
        let wrong = sign_digest(
            &sk,
            &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, shares as i128, &eoa, 1),
        );
        let err = gw
            .account_lp_withdraw(&key, shares, 1, &wrong)
            .expect_err("cross-flow signature must be refused");
        assert!(err.contains("signature"), "unexpected error: {err}");

        let sig = sign_digest(
            &sk,
            &lp_withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, shares, 1),
        );
        gw.account_lp_withdraw(&key, shares, 1, &sig)
            .expect("accepted");
        assert_eq!(gw.accounts.get(&key).unwrap().last_withdraw_nonce, 1);
    }

    /// SEC-021: the legacy demo LP handler calls the raw primitive with a key that is
    /// not a registered account. That path must keep working — authorization lives in
    /// the wrapper, not in `lp_withdraw`.
    #[test]
    fn legacy_lp_withdraw_primitive_still_works_for_the_demo_wallet() {
        let mut gw = Gw::boot();
        let who = gw.user.owner;
        let w = gw.user;
        let shares = gw.lp_deposit(who, &w, 1_000).expect("stake");
        gw.lp_withdraw(&who, &w, shares)
            .expect("legacy primitive is unauthenticated by contract");
    }

    /// SEC-021: a validly signed LP withdrawal that then fails inside the delegated
    /// primitive (here: more shares than held) must NOT burn its nonce — the nonce
    /// commits only after `lp_withdraw` succeeds, so the same nonce is still usable
    /// and a later replay of a SPENT nonce is still refused. Mirrors
    /// `failed_withdrawal_does_not_burn_its_nonce` for the LP flow.
    #[test]
    fn rejected_lp_withdrawal_does_not_burn_its_nonce() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let eoa = eth_addr(&sk);
        let (key, owner) = gw.register_account(None);
        let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
        gw.account_set_deposit_address(&key, eoa, &bind, None)
            .unwrap();
        fund_test_account(&mut gw, &key, 10_000);
        let wallet = gw.accounts.get(&key).unwrap().wallet;
        let shares = gw.lp_deposit(key, &wallet, 5_000).expect("stake");

        // Validly signed, but for more shares than the account holds.
        let over = sign_digest(
            &sk,
            &lp_withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, shares + 1, 1),
        );
        let err = gw
            .account_lp_withdraw(&key, shares + 1, 1, &over)
            .expect_err("over-shares LP withdrawal fails");
        assert!(
            err.contains("Insufficient LP shares"),
            "unexpected error: {err}"
        );
        assert_eq!(
            gw.accounts.get(&key).unwrap().last_withdraw_nonce,
            0,
            "nonce must survive a post-verification failure"
        );
        assert_eq!(
            gw.lp_shares.get(&key).copied().unwrap_or(0),
            shares,
            "no shares burned by the rejection"
        );

        // Nonce 1 is still spendable — proof the rejection committed nothing.
        let sig = sign_digest(
            &sk,
            &lp_withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, shares, 1),
        );
        gw.account_lp_withdraw(&key, shares, 1, &sig)
            .expect("the un-burned nonce is still valid");
        assert_eq!(gw.accounts.get(&key).unwrap().last_withdraw_nonce, 1);

        // A SPENT nonce is refused (replay protection).
        let err = gw
            .account_lp_withdraw(&key, shares, 1, &sig)
            .expect_err("replay must be refused");
        assert!(err.contains("nonce"), "unexpected error: {err}");
    }

    /// SEC-021 (final-review M-b — the spec's "server-custody, no bound address and
    /// no signer ⇒ rejected" row): `authorizing_address`'s no-address arm is
    /// unreachable through `account_withdraw` (its `to` match errors first), so pin
    /// it through the one caller that CAN reach it — `account_lp_withdraw`. An
    /// account with neither a registered signer nor a bound deposit address, holding
    /// real LP shares, must be refused on the missing authorizing address with
    /// nothing mutated and no nonce advance. The request is otherwise fully valid
    /// (fresh nonce, a real signature over the correct digest), so the refusal can
    /// only come from the fail-closed arm itself.
    #[test]
    fn lp_withdraw_with_no_signer_and_no_bound_address_is_refused() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None); // server-custody, never bound
        fund_test_account(&mut gw, &key, 10_000);
        let wallet = gw.accounts.get(&key).unwrap().wallet;
        let shares = gw.lp_deposit(key, &wallet, 5_000).expect("stake");

        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let sig = sign_digest(
            &sk,
            &lp_withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, shares, 1),
        );
        let err = gw
            .account_lp_withdraw(&key, shares, 1, &sig)
            .expect_err("no signer and no bound address ⇒ rejected");
        assert!(
            err.contains("no authorizing address"),
            "unexpected error: {err}"
        );
        // Nothing mutated: the shares are intact and the nonce did not advance.
        assert_eq!(
            gw.lp_shares.get(&key).copied().unwrap_or(0),
            shares,
            "a refused LP withdrawal must not burn shares"
        );
        assert_eq!(
            gw.accounts.get(&key).unwrap().last_withdraw_nonce,
            0,
            "a refused LP withdrawal must not advance the nonce"
        );
    }

    #[test]
    fn withdraw_auth_digest_binds_every_field() {
        let owner: PubKey = [7u8; 32];
        let to = [0x11u8; 20];
        let vault = [0x22u8; 20];
        let base = withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &to, 1);

        // Every field must change the digest.
        assert_ne!(
            base,
            withdraw_auth_digest(1, &vault, &owner, 0, 1_000, &to, 1)
        );
        assert_ne!(
            base,
            withdraw_auth_digest(84532, &[0x33u8; 20], &owner, 0, 1_000, &to, 1)
        );
        assert_ne!(
            base,
            withdraw_auth_digest(84532, &vault, &[8u8; 32], 0, 1_000, &to, 1)
        );
        assert_ne!(
            base,
            withdraw_auth_digest(84532, &vault, &owner, 1, 1_000, &to, 1)
        );
        assert_ne!(
            base,
            withdraw_auth_digest(84532, &vault, &owner, 0, 1_001, &to, 1)
        );
        assert_ne!(
            base,
            withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &[0x44u8; 20], 1)
        );
        assert_ne!(
            base,
            withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &to, 2)
        );

        // Deterministic.
        assert_eq!(
            base,
            withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &to, 1)
        );
    }

    #[test]
    fn withdrawal_digests_are_domain_separated_from_each_other_and_from_bind() {
        let owner: PubKey = [7u8; 32];
        let addr = [0x11u8; 20];
        let vault = [0x22u8; 20];
        let w = withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &addr, 1);
        let lp = lp_withdraw_auth_digest(84532, &vault, &owner, 1_000, 1);
        let rb = rebind_auth_digest(84532, &vault, &owner, 0, &addr, &[0x33u8; 20]);
        let bind = deposit_bind_digest(&owner, &addr);
        assert_ne!(w, lp);
        assert_ne!(w, rb);
        assert_ne!(lp, rb);
        assert_ne!(w, bind);
        assert_ne!(lp, bind);
        assert_ne!(rb, bind);
    }

    #[test]
    fn rebind_auth_digest_binds_both_addresses_in_order() {
        let owner: PubKey = [7u8; 32];
        let a = [0xAAu8; 20];
        let b = [0xBBu8; 20];
        let vault = [0x22u8; 20];
        // Swapping old/new must NOT produce the same digest — otherwise a signature
        // authorizing A->B would also authorize B->A.
        assert_ne!(
            rebind_auth_digest(84532, &vault, &owner, 0, &a, &b),
            rebind_auth_digest(84532, &vault, &owner, 0, &b, &a)
        );
        // Finding 1: a different rebind_counter must change the digest — the counter
        // is what makes an old rotation signature unreplayable after the binding
        // cycles back to the same address pair.
        assert_ne!(
            rebind_auth_digest(84532, &vault, &owner, 0, &a, &b),
            rebind_auth_digest(84532, &vault, &owner, 1, &a, &b)
        );
    }

    /// SEC-021 (Task-2 review Finding 2): known-answer tests freezing the exact BYTE
    /// LAYOUT of every authorization digest. The sensitivity tests above compare the
    /// implementation against itself, so they still pass under a prefix typo, a swap of
    /// two same-width fields (`market_id`↔`nonce`, `vault`↔`to`, `old_addr`↔`new_addr`),
    /// or a little-endian encoding. Task 8 mirrors `withdraw_auth_digest` byte-for-byte
    /// in TypeScript, so the layout is a cross-component CONTRACT — a wrong layout is a
    /// silent security bug. These vectors were computed ONCE from this implementation
    /// and hard-coded (never recomputed at test time from the function under test);
    /// any later change to a prefix, field order, width, or endianness fails loudly.
    #[test]
    fn auth_digests_match_known_answer_vectors() {
        let owner: PubKey = [7u8; 32];
        let to = [0x11u8; 20];
        let vault = [0x22u8; 20];
        assert_eq!(
            hex0x(&withdraw_auth_digest(
                84532, &vault, &owner, 0, 1_000, &to, 1
            )),
            "0x297d6fcc305700b679a59a06cb0d990a70157fcc314f93f69ed36bb1eec6ff97",
            "withdraw_auth_digest layout drifted"
        );
        // amount = -1 pins the i128 two's-complement big-endian encoding (16 bytes of
        // 0xFF) — nothing else in the suite covers a negative amount.
        assert_eq!(
            hex0x(&withdraw_auth_digest(84532, &vault, &owner, 0, -1, &to, 1)),
            "0xe9285454ef17c530a4a32577d234bbace2d0fc1177f7a9a677a88f63474f695e",
            "withdraw_auth_digest negative-amount (i128 two's-complement BE) drifted"
        );
        assert_eq!(
            hex0x(&lp_withdraw_auth_digest(84532, &vault, &owner, 1_000, 1)),
            "0x6499ac5025078970b4d4aea3031d0704d6a0398c8a748c299dbad105b0c00914",
            "lp_withdraw_auth_digest layout drifted"
        );
        // Frozen baseline: the pre-SEC-021 bind digest must never move either.
        assert_eq!(
            hex0x(&deposit_bind_digest(&owner, &to)),
            "0x2ba386f057ba44415aab7b46643ed103af568763a1f9c31afd7ce639a07f983f",
            "deposit_bind_digest layout drifted"
        );
        // rebind_counter = 1 (not 0), so a big-endian↔little-endian flip of the counter
        // bytes changes the digest and is caught here. Vector computed AFTER Finding 1
        // inserted the counter between `owner` and `old_addr`.
        assert_eq!(
            hex0x(&rebind_auth_digest(
                84532,
                &vault,
                &owner,
                1,
                &to,
                &[0x33u8; 20]
            )),
            "0x5443439bdaff6c0664d421740e45477386aa256329eb9dbf68c3564676ff917e",
            "rebind_auth_digest layout drifted"
        );
    }

    /// SEC-021: adding `last_withdraw_nonce` must not silently corrupt snapshot
    /// loading. postcard is POSITIONAL, so `#[serde(default)]` does not necessarily
    /// make an older (shorter) encoding loadable. This test pins the actual behaviour
    /// so the deploy runbook states the truth instead of a guess.
    #[test]
    fn account_snapshot_round_trips_with_withdraw_nonce() {
        let mut a = Account {
            wallet: Wallet::from_seed([3u8; 32]),
            orders: vec![],
            nonce: 0,
            deposit_counter: 0,
            last_order_ms: 0,
            orders_this_sec: 0,
            deposit_address: Some([0x11u8; 20]),
            signer: None,
            last_signed_nonce: 0,
            last_sealed_nonce: 0,
            deposit_authorizations: Default::default(),
            last_withdraw_nonce: 42,
            rebind_counter: 3,
            recovery_nonce: 0,
            credential_control: Arc::default(),
        };
        a.nonce = 7;
        let bytes = postcard::to_allocvec(&a).expect("serialize");
        let back: Account = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(back.last_withdraw_nonce, 42);
        assert_eq!(back.rebind_counter, 3);
        assert_eq!(back.nonce, 7);
        assert_eq!(back.deposit_address, Some([0x11u8; 20]));
    }

    /// SEC-021 migration fact: can a PRE-upgrade Account encoding still load?
    /// postcard is positional and non-self-describing, so a trailing field with
    /// `#[serde(default)]` is NOT guaranteed to be optional on the wire. This test
    /// RECORDS the real behaviour — whichever way it goes, the deploy runbook must
    /// match it.
    #[test]
    fn pre_upgrade_account_encoding_behaviour_is_pinned() {
        #[derive(serde::Serialize)]
        struct OldAccount {
            wallet: Wallet,
            orders: Vec<GwOrder>,
            nonce: u64,
            deposit_counter: u64,
            last_order_ms: u64,
            orders_this_sec: u32,
            deposit_address: Option<[u8; 20]>,
            signer: Option<[u8; 20]>,
            last_signed_nonce: u64,
            last_sealed_nonce: u64,
            deposit_authorizations: std::collections::BTreeMap<[u8; 32], [u8; 32]>,
        }
        let old = OldAccount {
            wallet: Wallet::from_seed([3u8; 32]),
            orders: vec![],
            nonce: 7,
            deposit_counter: 0,
            last_order_ms: 0,
            orders_this_sec: 0,
            deposit_address: Some([0x11u8; 20]),
            signer: None,
            last_signed_nonce: 0,
            last_sealed_nonce: 0,
            deposit_authorizations: Default::default(),
        };
        let bytes = postcard::to_allocvec(&old).expect("serialize old");
        let decoded: Result<Account, _> = postcard::from_bytes(&bytes);
        // ANSWER (pinned 2026-07-25): with THIS fixture (empty `deposit_authorizations`)
        // the decode fails with Err(DeserializeUnexpectedEnd). Mechanism: the new fields
        // are NOT trailing — `last_withdraw_nonce` and `rebind_counter` sit mid-struct,
        // BEFORE `deposit_authorizations` — so `last_withdraw_nonce` swallows the map's
        // length byte and `rebind_counter` then hits end-of-input. This is NOT a
        // universal guarantee of an error: with a NON-EMPTY map whose key bytes happen
        // to align, an old encoding can decode SUCCESSFULLY into corrupt state (the
        // nonce absorbs the map's length byte and the authorizations are silently
        // dropped) — strictly worse than erroring, and exactly the case where a state
        // wipe matters most. Either way, pre-upgrade snapshots do not load CORRECTLY,
        // so the deploy runbook's state wipe is REQUIRED in BOTH outcomes. Do not "fix"
        // a failure of this assert by changing a field; see the assert message for what
        // a flip actually means.
        assert!(
            decoded.is_err(),
            "pre-upgrade Account encoding DECODED — on a SHORTER pre-upgrade encoding a \
             successful decode is a silent mis-parse, NOT compatibility: \
             `last_withdraw_nonce` swallows the `deposit_authorizations` length byte and \
             the authorizations are silently dropped into corrupt state (strictly worse \
             than erroring). The deploy runbook's state wipe is STILL REQUIRED; anyone \
             changing the runbook must FIRST verify, field-by-field, that every \
             pre-upgrade field decodes into the same field post-upgrade"
        );
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
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE)
                .expect("deposit");
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
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE)
            .expect("deposit");

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
        gw.account_place_order(&key, &req)
            .expect("sealed order accepted");

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
        assert_eq!(
            decode_hex("0xé0"),
            None,
            "mid-codepoint slice must not panic"
        );
        assert_eq!(
            decode_hex("—"),
            None,
            "em dash (3 bytes) must reject cleanly"
        );
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
        assert_eq!(
            parse_hex32(&format!("0x{}", "ab".repeat(32))),
            Some([0xab; 32])
        );
        assert_eq!(parse_addr20_hex(&"cd".repeat(20)), Some([0xcd; 20]));
        assert_eq!(
            parse_hex65(&format!("0x{}", "0F".repeat(65))),
            Some([0x0f; 65])
        );
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
        assert_eq!(
            opened, 0,
            "a rejected non-ASCII sealed order must open nothing"
        );
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
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE)
            .expect("deposit");
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
        assert_eq!(
            &b[25..41],
            &t.limit_price.to_le_bytes(),
            "limitPrice i128 LE @25"
        );
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
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        assert!(gw.window_withdrawals.is_empty());

        let to = [7u8; 20];
        let w = signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, to).expect("withdraw");

        assert_eq!(gw.window_withdrawals.len(), 1);
        assert_eq!(gw.window_withdrawals[0].to, to);
        assert_eq!(gw.window_withdrawals[0].nonce, w.nonce);
    }

    #[test]
    fn v1_withdrawals_json_serves_root_and_proof() {
        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let w = signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();

        // seed a published (root, proof) for this leaf as the settle path would
        let leaf = w.leaf();
        let root = [0xAAu8; 32];
        gw.withdraw_proofs.insert(leaf, (root, vec![[0xBBu8; 32]]));

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
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        let w1 = signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let w2 = signed_withdraw(&mut gw, &key, &sk, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        // seed proofs for both leaves as a settle would
        gw.withdraw_proofs
            .insert(w1.leaf(), ([0xAAu8; 32], vec![[0xBBu8; 32]]));
        gw.withdraw_proofs
            .insert(w2.leaf(), ([0xAAu8; 32], vec![[0xCCu8; 32]]));

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
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        // one withdrawal accumulated since the (failed) seal drained the window's set
        let after = signed_withdraw(&mut gw, &key, &sk, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        // the failed window's withdrawals, captured before the seal
        let failed = vec![Withdrawal {
            owner: [1u8; 32],
            to: [7u8; 20],
            amount: 5_000,
            nonce: 1,
        }];

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

    /// SEC-025-B break 4: a window holding an accepted-but-unfilled order's hash must
    /// settle even though the engine root did not move. Otherwise its hashes never reach
    /// the challenge-answer store and an honest sequencer cannot answer a ripe inclusion
    /// challenge — a wrongful-slash path reachable by any user resting an order into an
    /// otherwise quiet window.
    #[test]
    fn a_manifest_only_window_still_settles() {
        let mut gw = tests_support::gw_with_market();
        let root_before = gw.seq.state.state_root();

        // A far-from-the-book limit that rests without crossing: no fill, no state change.
        let sealed = gw.seq.seal_batch(&[tests_support::resting_order(1)], 1_000);

        // Fixture-suspicion guards: the order must be ACCEPTED into `ordered`, not
        // rejected — a REJECTED order also reaches the window manifest, so without
        // these two asserts a broken fixture (e.g. a stale oracle) would pass the
        // preconditions below while exercising the wrong path.
        assert!(
            sealed.manifest.rejected.is_empty(),
            "fixture precondition: the resting order must be ACCEPTED, not rejected: {:?}",
            sealed.manifest.rejected
        );
        assert_eq!(
            sealed.manifest.ordered.len(),
            1,
            "fixture precondition: the resting order must be in this tick's `ordered`"
        );

        assert_eq!(
            gw.seq.state.state_root(),
            root_before,
            "fixture precondition: a resting unfilled order must NOT move the engine root, \
             or this test is not exercising break 4"
        );
        assert!(
            gw.seq.window_has_pending_manifest(),
            "fixture precondition: the order must be in the window manifest"
        );

        let out = gw
            .begin_window_settle(gw.seq.state.next_batch_id)
            .expect("no desync");
        assert!(
            out.is_some(),
            "a window carrying manifest content must settle even with an unchanged root"
        );
    }

    /// Whole-branch review item 5 — the `window_rejected` arm of the predicate. A
    /// window whose ONLY manifest content is a REJECTED order (nothing accepted, no
    /// state change) must also settle: `answerByRejection` requires the answering
    /// batch to be genuinely settled (`DarkPerpSettlement.sol:554`,
    /// `settledAtBlock != 0`), so a predicate checking `window_ordered` alone would
    /// leave an honest sequencer unable to answer a rejection challenge — the same
    /// wrongful-slash vector as break 4's accepted-order case, reachable via a
    /// stale-oracle rejection, a margin rejection, or SEC-022's band-ban. Without
    /// this test, mutating `window_has_pending_manifest` to drop the
    /// `window_rejected` arm left the suite green.
    #[test]
    fn a_rejected_only_window_still_settles() {
        let mut gw = tests_support::gw_with_market();
        let root_before = gw.seq.state.state_root();

        // A margin-unpayable order: rejected pre-trade, so it never touches the book.
        let sealed = gw
            .seq
            .seal_batch(&[tests_support::oversized_order(1)], 1_000);

        // Fixture-suspicion guards — `a_manifest_only_window_still_settles` with the
        // arms swapped: nothing may be ACCEPTED (an accepted order would satisfy the
        // predicate via the other, already-tested arm), and the one rejection must be
        // the rejection we CONSTRUCTED. `gw_with_market` re-signs the oracle at 500ms
        // exactly so an accidental stale-oracle rejection cannot masquerade as this
        // margin rejection — hence the reason is asserted, not just the count.
        assert!(
            sealed.manifest.ordered.is_empty(),
            "fixture precondition: nothing may be accepted, or this test exercises \
             the window_ordered arm instead: {:?}",
            sealed.manifest.ordered
        );
        assert_eq!(
            sealed.manifest.rejected.len(),
            1,
            "fixture precondition: exactly the one constructed rejection"
        );
        assert_eq!(
            sealed.manifest.rejected[0].1,
            perp_core::order::RejectReason::InsufficientMargin,
            "fixture precondition: the rejection must be the margin rejection we \
             constructed — any other reason (e.g. OracleUnavailable) means the \
             fixture regressed and the test passes for an unrelated rejection"
        );
        assert_eq!(
            gw.seq.state.state_root(),
            root_before,
            "fixture precondition: a pre-trade-rejected order must NOT move the \
             engine root, or the root half of the predicate carries the test"
        );
        assert!(
            gw.seq.window_has_pending_manifest(),
            "fixture precondition: the rejected hash must be in the window manifest"
        );

        let out = gw
            .begin_window_settle(gw.seq.state.next_batch_id)
            .expect("no desync");
        assert!(
            out.is_some(),
            "a window whose only manifest content is a rejected order must settle — \
             answerByRejection is only reachable against a settled batch"
        );
    }

    /// The predicate must not turn idle ticks into proofs: a window empty in BOTH senses
    /// still returns None.
    #[test]
    fn a_truly_empty_window_still_returns_none() {
        let mut gw = tests_support::gw_with_market();
        assert!(!gw.seq.window_has_pending_manifest());
        let out = gw
            .begin_window_settle(gw.seq.state.next_batch_id)
            .expect("no desync");
        assert!(
            out.is_none(),
            "no state change and no manifest content ⇒ nothing to prove"
        );
    }

    #[test]
    fn begin_window_settle_errors_on_desync_without_mutating() {
        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
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
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
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

    fn settle_journal_guard_fixture() -> rollback_journal::RollbackJournal {
        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("sealed");
        rollback_journal::RollbackJournal {
            batch_id: bc,
            witness,
            ww,
            prepared: None,
        }
    }

    fn settle_journal_guard_scratch() -> std::path::PathBuf {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("darkperp-journal-guard-{name}"));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn journal_ambiguous_hold_surfaces_health_and_refuses_admin_retry() {
        let app = test_app();
        app.force_settle
            .store(true, std::sync::atomic::Ordering::SeqCst);
        hold_settlement_for_recovery(&app, "ambiguous send; reconcile journal and restart".into())
            .await;
        let gw = app.gw.lock().await;
        assert_eq!(gw.settle_health.health(), settle_health::Health::Held);
        assert!(gw.settlement_held_since_ms.is_some());
        assert!(gw.snapshot().settlement_health == "HELD");
        assert!(request_settlement_retry(&gw, &app.force_settle)
            .unwrap_err()
            .contains("reconcile"));
        assert!(!app.force_settle.load(std::sync::atomic::Ordering::SeqCst));
        assert!(gw
            .settle_health
            .last_error()
            .unwrap()
            .contains("ambiguous send"));
    }

    #[test]
    fn journal_window_counter_exhaustion_refuses_before_any_mutation() {
        let mut gw = Gw::boot();
        gw.seq.state.next_batch_id = u64::MAX;
        let before = gw.snapshot_plain();
        let error = match begin_journaled_window_settle(&mut gw, u64::MAX, None, &[42; 32]) {
            Err(error) => error,
            Ok(_) => panic!("an exhausted window must not seal"),
        };
        assert!(error.contains("counter exhausted"));
        assert_eq!(gw.snapshot_plain(), before);
    }

    #[test]
    fn journal_stage1_failure_rolls_back_before_snapshot_can_capture() {
        let dir = settle_journal_guard_scratch();
        let path = dir.join("missing").join("state.rollback");
        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7; 20]).unwrap();
        let root = gw.seq.state.state_root();
        let bid = gw.seq.state.next_batch_id;
        let leaves: Vec<_> = gw.window_withdrawals.iter().map(|w| w.leaf()).collect();
        assert!(begin_journaled_window_settle(&mut gw, bid, Some(&path), &[42; 32]).is_err());
        assert_eq!(gw.seq.state.next_batch_id, bid);
        assert_eq!(gw.seq.state.state_root(), root);
        assert_eq!(
            gw.window_withdrawals
                .iter()
                .map(|w| w.leaf())
                .collect::<Vec<_>>(),
            leaves
        );
        let restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert_eq!(restored.seq.state.next_batch_id, bid);
        assert_eq!(restored.seq.state.state_root(), root);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn journal_seal_and_snapshot_capture_share_the_state_lock() {
        let dir = settle_journal_guard_scratch();
        let path = dir.join("state.rollback");
        let seed = [42; 32];
        let app = test_app();
        let mut state = app.gw.lock().await;
        let (key, _) = state.register_account(None);
        state
            .account_deposit(&key, 0, 20_000 * QUOTE_SCALE)
            .unwrap();
        let bid = state.seq.state.next_batch_id;
        let (entered, receiver) = tokio::sync::oneshot::channel();
        let reader_app = app.clone();
        let reader_path = path.clone();
        let reader = tokio::spawn(async move {
            entered.send(()).unwrap();
            let state = reader_app.gw.lock().await;
            let journal = rollback_journal::read(&reader_path, &seed)
                .unwrap()
                .expect("sealed snapshot always has journal");
            assert_eq!(state.seq.state.next_batch_id, journal.batch_id + 1);
            state.snapshot_plain()
        });
        receiver.await.unwrap();
        assert!(
            !reader.is_finished(),
            "snapshot waits for seal+journal guard"
        );
        let journal = begin_journaled_window_settle(&mut state, bid, Some(&path), &seed)
            .unwrap()
            .unwrap();
        assert!(!reader.is_finished());
        drop(state);
        let captured = reader.await.unwrap();
        let mut restored = Gw::boot_restored(&captured).unwrap();
        assert_eq!(
            apply_boot_recovery(
                &mut restored,
                journal,
                bid,
                "0x00",
                0,
                trading_gate::GateObservation::Inconclusive
            ),
            BootRecoveryOutcome::DeleteJournal { mutated: true }
        );
        assert_eq!(restored.seq.state.next_batch_id, bid);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn journal_late_transaction_keeps_original_until_matching_landed_root() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};
        let dir = settle_journal_guard_scratch();
        let path = dir.join("state.rollback");
        let seed = [42; 32];
        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7; 20]).unwrap();
        let pre_seal = gw.snapshot_plain();
        let bid = gw.seq.state.next_batch_id;
        let mut journal = begin_journaled_window_settle(&mut gw, bid, Some(&path), &seed)
            .unwrap()
            .unwrap();
        let prepared = prove_and_prepare(&MockProverClient, &journal.witness, &journal.ww).unwrap();
        let root = hex32(&prepared.outcome.new_root);
        let proofs = prepared.withdraw_proofs.clone();
        journal.prepared = Some(prepared);
        rollback_journal::write(&path, &journal, &seed).unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        let post_seal = gw.snapshot_plain();
        // Repeated old observations are still ambiguous; neither a pre-seal nor a
        // post-seal restored snapshot may authorize resealing/deleting prepared data.
        for snap in [&pre_seal, &post_seal] {
            let mut restored = Gw::boot_restored(snap).unwrap();
            let before = restored.snapshot_plain();
            for _ in 0..3 {
                let pending = rollback_journal::read(&path, &seed).unwrap().unwrap();
                assert_eq!(
                    apply_boot_recovery(
                        &mut restored,
                        pending,
                        bid,
                        "0x00",
                        0,
                        trading_gate::GateObservation::Inconclusive
                    ),
                    BootRecoveryOutcome::KeepJournal
                );
                assert_eq!(restored.snapshot_plain(), before);
                assert_eq!(std::fs::read(&path).unwrap(), on_disk);
            }
        }
        // The OLD transaction finally lands: the same retained prepared window
        // remains recoverable, with exactly its original withdrawal proofs.
        let mut restored = Gw::boot_restored(&post_seal).unwrap();
        let pending = rollback_journal::read(&path, &seed).unwrap().unwrap();
        assert_eq!(
            apply_boot_recovery(
                &mut restored,
                pending,
                bid + 1,
                &root,
                77,
                trading_gate::GateObservation::Inconclusive
            ),
            BootRecoveryOutcome::DeleteJournal { mutated: true }
        );
        assert_eq!(restored.withdraw_proofs, proofs);
        assert_eq!(restored.l1_status.as_ref().unwrap().settled_root, root);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn journal_shutdown_snapshot_holds_mutations_until_exit_guard_drops() {
        let dir = settle_journal_guard_scratch();
        let path = dir.join("state");
        let app = test_app();
        let seed = [42; 32];
        let serial = Arc::new(Mutex::new(()));
        let (frozen, saved) = final_snapshot(&app, &path, seed, serial.clone()).await;
        assert!(saved);
        assert!(
            app.gw.try_lock().is_err(),
            "no mutation in snapshot-to-exit gap"
        );
        let back = snapshot::open(&std::fs::read(&path).unwrap(), &seed).unwrap();
        assert_eq!(back, frozen.snapshot_plain());
        drop(frozen);
        assert!(app.gw.try_lock().is_ok());
        // Failure also freezes mutations until the failure exit, so no success is
        // falsely acknowledged in the failed-save-to-exit gap.
        let (frozen, saved) = final_snapshot(&app, &path.join("invalid"), seed, serial).await;
        assert!(!saved);
        assert!(app.gw.try_lock().is_err());
        drop(frozen);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn settle_journal_guard_stage1_fs_failure_never_reaches_prove_callback() {
        let dir = settle_journal_guard_scratch();
        let not_directory = dir.join("parent-is-file");
        std::fs::write(&not_directory, b"sentinel").unwrap();
        let path = not_directory.join("state.rollback");
        let journal = settle_journal_guard_fixture();
        let mut reached = false;
        let result = after_settle_journal(Some(&path), &journal, &[42; 32], || reached = true);
        assert_eq!(std::fs::read(&not_directory).unwrap(), b"sentinel");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            !reached,
            "stage-1 write failure must not reach the proving continuation"
        );
        assert!(result.is_err(), "failed filesystem write must propagate");
    }

    #[cfg(unix)]
    #[test]
    fn settle_journal_guard_stage2_fs_failure_keeps_original_and_never_broadcasts() {
        let dir = settle_journal_guard_scratch();
        let short = dir.join("original.rollback");
        let mut journal = settle_journal_guard_fixture();
        let seed = [42; 32];
        rollback_journal::write(&short, &journal, &seed).unwrap();
        // POSIX filesystem failure independent of uid/permissions: the target
        // name fits NAME_MAX, but write_atomic's exclusive sibling suffix does
        // not. Move an actual valid stage-1 journal there first.
        let path = dir.join("j".repeat(240));
        std::fs::rename(&short, &path).unwrap();
        let original = std::fs::read(&path).unwrap();
        journal.prepared = Some(
            prover_client::prove_and_prepare(
                &prover_client::MockProverClient,
                &journal.witness,
                &journal.ww,
            )
            .unwrap(),
        );
        let mut broadcast = false;
        let result = after_settle_journal(Some(&path), &journal, &seed, || broadcast = true);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "old journal retained byte-exact"
        );
        let retained = rollback_journal::read(&path, &seed).unwrap().unwrap();
        assert!(
            retained.prepared.is_none(),
            "stage-1 recovery record remains readable"
        );
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "no leaked temporary file"
        );
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            !broadcast,
            "stage-2 write failure must not reach the broadcast continuation"
        );
        assert!(result.is_err(), "failed filesystem write must propagate");
    }

    #[test]
    fn settle_journal_guard_success_persists_each_stage_before_callback() {
        let dir = settle_journal_guard_scratch();
        let path = dir.join("state.rollback");
        let seed = [42; 32];
        let mut journal = settle_journal_guard_fixture();
        let mut callbacks = 0;
        after_settle_journal(Some(&path), &journal, &seed, || {
            let persisted = rollback_journal::read(&path, &seed).unwrap().unwrap();
            assert!(persisted.prepared.is_none());
            assert_eq!(persisted.batch_id, journal.batch_id);
            callbacks += 1;
        })
        .unwrap();
        let prepared = prover_client::prove_and_prepare(
            &prover_client::MockProverClient,
            &journal.witness,
            &journal.ww,
        )
        .unwrap();
        let expected_root = prepared.outcome.new_root;
        journal.prepared = Some(prepared);
        after_settle_journal(Some(&path), &journal, &seed, || {
            let persisted = rollback_journal::read(&path, &seed).unwrap().unwrap();
            assert_eq!(persisted.prepared.unwrap().outcome.new_root, expected_root);
            callbacks += 1;
        })
        .unwrap();
        assert_eq!(callbacks, 2);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn settle_journal_guard_unconfigured_dev_path_keeps_existing_behavior() {
        let journal = settle_journal_guard_fixture();
        assert_eq!(
            after_settle_journal(None, &journal, &[42; 32], || 42).unwrap(),
            42
        );
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
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
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
        let s1 = rollback_journal::read(&jp, &seed)
            .expect("read")
            .expect("present");
        assert_eq!(s1.batch_id, bc);
        assert!(s1.prepared.is_none(), "stage 1 journals pre-prove");

        // stage 2: rewrite the SAME path with the prove outcome — round-trips.
        let prepared =
            prove_and_prepare(&MockProverClient, &journal.witness, &journal.ww).expect("prove");
        journal.prepared = Some(prepared.clone());
        rollback_journal::write(&jp, &journal, &seed).expect("stage-2 write");
        let s2 = rollback_journal::read(&jp, &seed)
            .expect("read")
            .expect("present");
        assert_eq!(s2.batch_id, bc);
        let s2p = s2.prepared.expect("stage 2 carries the prove outcome");
        assert_eq!(s2p.outcome.new_root, prepared.outcome.new_root);
        assert_eq!(s2p.withdraw_proofs, prepared.withdraw_proofs);

        // This fixture now models positive evidence that no broadcast occurred.
        // An unchanged chain counter alone must retain stage-2 as ambiguous.
        journal.prepared = None;
        rollback_journal::write(&jp, &journal, &seed).expect("known pre-broadcast stage");

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
        let j = rollback_journal::read(&jp, &seed)
            .expect("read")
            .expect("present");
        let out = apply_boot_recovery(
            &mut gw,
            j,
            bc,
            "0x00",
            0,
            trading_gate::GateObservation::Inconclusive,
        );
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
        assert_eq!(
            leaves2, ww_leaves,
            "the drained withdrawals were re-injected"
        );
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
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
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
            apply_boot_recovery(
                &mut restored,
                hold_j,
                bc + 2,
                "0x00",
                0,
                trading_gate::GateObservation::Inconclusive,
            ),
            BootRecoveryOutcome::KeepJournal
        );
        assert_eq!(
            restored.seq.state.next_batch_id,
            bc + 1,
            "HOLD never mutates"
        );

        // the ROLLBACK row: seal persisted (B == bc+1), tx never landed (chain == bc).
        // A MUTATING resolution — the caller must persist before deleting.
        let out = apply_boot_recovery(
            &mut restored,
            journal,
            bc,
            "0x00",
            0,
            trading_gate::GateObservation::Inconclusive,
        );
        assert_eq!(out, BootRecoveryOutcome::DeleteJournal { mutated: true });
        assert_eq!(
            restored.seq.state.next_batch_id, bc,
            "Counter B rewound to the journaled window"
        );

        // a fresh begin_window_settle(bc) re-seals the same window: the desync
        // guard passes and the drained withdrawals were re-injected.
        let (w2, ww2) = restored
            .begin_window_settle(bc)
            .unwrap()
            .expect("re-sealed");
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
    /// SEC-025-D §8.4/§8.5: the boot roll-forward arm threads a gate observation into
    /// `commit_window_settle`, and until this test nothing distinguished "threaded
    /// through" from "ignored" — every other boot-recovery test passes `Inconclusive`,
    /// so hardcoding that value inside the arm left the whole suite green.
    ///
    /// Both directions matter here and neither is covered by the settle-loop tests: this
    /// is the arm a governance `finalSettle` can reach after a crash, AND the arm a
    /// genuine settle reaches when the process died before committing.
    #[test]
    fn the_boot_roll_forward_arm_carries_the_gate_observation_both_ways() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        // A bare production genesis seals NOTHING — `begin_window_settle` returns `None`
        // on an unchanged root, which is the circularity this piece documents. So build a
        // window the way the sibling roll-forward test does (a real deposit moves the
        // root) and force the gate Closed; the arm's plumbing is what is under test here,
        // not the genesis mode.
        let build = || {
            let mut gw = Gw::boot();
            gw.trading_gate = trading_gate::TradingGate::Closed;
            gw.set_prepared_post_state_for_test(true, bootstrap::MIN_BOOTSTRAP_INSURANCE, 1);
            let (key, _sk) = register_withdrawer(&mut gw);
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
            let bc = gw.seq.state.next_batch_id;
            let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("sealed");
            let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prove");
            let root = hex32(&prepared.outcome.new_root);
            let j = rollback_journal::RollbackJournal {
                batch_id: bc,
                witness,
                ww,
                prepared: Some(prepared),
            };
            (gw, j, bc, root)
        };

        // A wind-down-shaped commit must NOT open the gate on this arm.
        let (mut gw, j, bc, root) = build();
        assert_eq!(gw.trading_gate, trading_gate::TradingGate::Closed);
        apply_boot_recovery(
            &mut gw,
            j,
            bc + 1,
            &root,
            77,
            trading_gate::GateObservation::StaysClosed,
        );
        assert_eq!(
            gw.trading_gate,
            trading_gate::TradingGate::Closed,
            "a StaysClosed observation must not open the gate at boot"
        );

        // …and a genuine one MUST, or a settle that landed before the crash can never
        // launch the deployment — there is no guarantee of another window.
        let (mut gw2, j2, bc2, root2) = build();
        apply_boot_recovery(
            &mut gw2,
            j2,
            bc2 + 1,
            &root2,
            77,
            trading_gate::GateObservation::OpensGate,
        );
        assert_eq!(
            gw2.trading_gate,
            trading_gate::TradingGate::Open,
            "an OpensGate observation at boot must open the gate"
        );
    }

    #[test]
    fn boot_recovery_roll_forward_commits() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let seed = [42u8; 32];
        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
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
        assert!(
            restored.l1_status.is_none(),
            "the commit died with the crash"
        );

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
            trading_gate::GateObservation::Inconclusive,
        );
        // ROLL-FORWARD is a MUTATING resolution — persist before delete.
        assert_eq!(out, BootRecoveryOutcome::DeleteJournal { mutated: true });
        let st = restored
            .l1_status
            .clone()
            .expect("bookkeeping re-committed");
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
            apply_boot_recovery(
                &mut restored,
                j2,
                bc + 1,
                &chain_root,
                77,
                trading_gate::GateObservation::Inconclusive,
            ),
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
        signed_withdraw(&mut restored, &key, &sk, 0, 1_000 * QUOTE_SCALE, [9u8; 20]).unwrap();
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
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
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
        let j = rollback_journal::read(&jp, &seed)
            .expect("read")
            .expect("present");
        let out = apply_boot_recovery(
            &mut restored,
            j,
            bc,
            "0x00",
            0,
            trading_gate::GateObservation::Inconclusive,
        );
        assert_eq!(out, BootRecoveryOutcome::DeleteJournal { mutated: true });

        // the call-site glue: persist the post-recovery snapshot, THEN delete.
        assert!(finish_boot_recovery(&restored, true, &state, &jp, &seed));
        // (a) the snapshot on disk now decodes to the ROLLED-BACK Counter B — a
        // hard crash right here re-resolves from the snapshot alone.
        let plain2 = snapshot::open(&std::fs::read(&state).unwrap(), &seed).expect("open post");
        let after = Gw::boot_restored(&plain2).expect("restore post");
        assert_eq!(
            after.seq.state.next_batch_id, bc,
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
        assert!(!finish_boot_recovery(&after, true, &bad_state, &jp, &seed));
        assert!(jp.exists(), "failed persist keeps the journal");

        // non-mutating resolutions stay delete-without-write: the same unwritable
        // snapshot path does not block the delete (nothing changed to persist).
        assert!(finish_boot_recovery(&after, false, &bad_state, &jp, &seed));
        assert!(
            !jp.exists(),
            "non-mutating rows delete without a snapshot write"
        );

        std::fs::remove_file(&state).ok();
    }

    #[test]
    fn seal_witness_is_well_formed_and_addressed() {
        use crate::prover_client::seal_witness;
        use prover::SealedWitness;

        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, _ww) = gw.begin_window_settle(bc).unwrap().expect("some");

        let root = [0x5Eu8; 32];
        let measurement = [0xABu8; 32];
        // DEV_INSECURE seal path (session_secret = None ⇒ SoftwareSealProvider).
        let hexed = seal_witness(&witness, &root, &measurement, None).expect("seal");
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
            r#"{{"prev_root":"{}","manifest_hash":"{}","new_root":"{}","ordered_root":"{}","withdrawals_root":"{}","rejected_root":"{}","deposits_root":"{}","commitment":"{}","proof":"0xdeadbeef"}}"#,
            r32(1),
            r32(2),
            r32(3),
            r32(4),
            r32(5),
            r32(6),
            r32(8),
            r32(7)
        );
        let out = parse_prove_resp(&json).expect("parse");
        // SEC-025-B: the raw remote shape — itemised roots are Options (diagnostic only).
        assert_eq!(out.roots.prev_root, Some([1u8; 32]));
        assert_eq!(out.roots.manifest_hash, Some([2u8; 32]));
        assert_eq!(out.roots.new_root, Some([3u8; 32]));
        assert_eq!(out.roots.ordered_root, Some([4u8; 32]));
        assert_eq!(out.roots.withdrawals_root, Some([5u8; 32]));
        assert_eq!(out.roots.rejected_root, Some([6u8; 32]));
        assert_eq!(out.roots.deposits_root, Some([8u8; 32]));
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
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        // THREE real-exit withdrawals in the window → a non-trivial withdrawals tree
        // that also pins op-ORDER (a 2-leaf sorted-pair tree is permutation-invariant,
        // so two leaves alone couldn't tell "same set" from "same order")
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 2_000 * QUOTE_SCALE, [9u8; 20]).unwrap();
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
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
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
        gw.commit_window_settle(
            batch_id,
            ordered,
            rejected,
            prepared,
            status,
            trading_gate::GateObservation::OpensGate,
        );

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
        gw.commit_window_settle(
            batch_id,
            ordered,
            rejected,
            prepared,
            status,
            trading_gate::GateObservation::OpensGate,
        );
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
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        // SEC-025-B: the withdrawals_root now comes from the gateway's OWN replay, so a
        // prover can no longer steer it — the wroot byte-match branch guards a
        // gateway-INTERNAL invariant instead: the drained window withdrawal set (`ww`)
        // must reproduce the withdrawals the witness ops derive. Drive it with an
        // honest prover and a `ww` that drifted (a dropped withdrawal).
        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, mut ww) = gw.begin_window_settle(bc).unwrap().expect("some");
        assert!(!ww.is_empty());
        ww.pop(); // the drift: a withdrawal the ops derived is missing from the set

        let err = prove_and_prepare(&MockProverClient, &witness, &ww)
            .expect_err("a drifted withdrawal set must be a hard error");
        assert!(err.contains("withdrawals root mismatch"), "got: {err}");
    }

    #[test]
    fn prove_and_prepare_rejects_commitment_mismatch() {
        use crate::prover_client::{
            prove_and_prepare, MockProverClient, ProverClient, ProverClientError, RemoteProveResp,
        };
        use sequencer::WindowWitness;

        // corrupts only the commitment (itemised roots stay honest) → SEC-025-B: the
        // prover's commitment no longer equals the gateway's OWN derivation → refused.
        struct CommitTamper;
        impl ProverClient for CommitTamper {
            fn prove(&self, w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
                let mut out = MockProverClient.prove(w)?;
                out.commitment = [0xFFu8; 32];
                Ok(out)
            }
        }

        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("some");

        let err = prove_and_prepare(&CommitTamper, &witness, &ww)
            .expect_err("tampered commitment must be a hard error");
        assert!(err.contains("commitment mismatch"), "got: {err}");
    }

    #[test]
    fn commit_window_settle_extends_proofs_across_windows() {
        use crate::prover_client::{prove_and_prepare, MockProverClient};

        let mut gw = Gw::boot();
        let (key, sk) = register_withdrawer(&mut gw);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();

        // ── window 1: withdrawal → begin → prove → commit ────────────────────
        signed_withdraw(&mut gw, &key, &sk, 0, 5_000 * QUOTE_SCALE, [7u8; 20]).unwrap();
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
        gw.commit_window_settle(
            batch_id1,
            ordered1,
            rejected1,
            prepared1,
            status1,
            trading_gate::GateObservation::OpensGate,
        );
        assert!(gw.withdraw_proofs.contains_key(&leaf_w1));

        // ── window 2: another withdrawal (root changes) → begin → commit ─────
        signed_withdraw(&mut gw, &key, &sk, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
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
        gw.commit_window_settle(
            batch_id2,
            ordered2,
            rejected2,
            prepared2,
            status2,
            trading_gate::GateObservation::OpensGate,
        );

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
    include!("audit_remediation_tests.rs");
    include!("execution_regression_tests.rs");
    include!("audit_cancellation_tests.rs");
}
