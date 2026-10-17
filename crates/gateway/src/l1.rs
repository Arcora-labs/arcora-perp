//! Optional L1 settlement bridge (Base Sepolia / Phase 0).
//!
//! When configured, the gateway periodically advances the on-chain
//! `DarkPerpSettlement.currentStateRoot` to mirror the engine's live state root, and
//! publishes a **real cumulative withdrawals root** so users can claim **USDC** from
//! the `CollateralVault` on L1. It also confirms on-chain USDC deposits and tops up
//! the USDC sequencer bond as TVL grows.
//!
//! SEC-025-B: every settle goes through `settle_proved` — the nine-parameter
//! `settleBatch` carrying the seven roots + `newDepositCount` the gateway derived from
//! its own window-witness replay, plus the prover's proof (== the commitment bytes for
//! MockProverClient, which the testnet `MockZkVerifier` accepts; see docs/PROVING.md).
//! The legacy path that read the on-chain root as `prev` and synthesized its
//! commitment via `publicCommitment` is deleted — both its arities went stale at
//! SEC-019, so it could not produce a resolvable call.
//!
//! Transport: shells out to `cast` (Foundry) — pragmatic for a testnet demo and
//! reuses the same signer path as deploy. A production bridge would use a native
//! signer (alloy) instead of a subprocess + key in argv.

use perp_core::Digest;
use std::process::Command;

mod clock_binding;
mod nonce_fence;
mod observation;
pub(crate) use clock_binding::AnchorAge;
use clock_binding::ClockConfig;
pub(crate) use nonce_fence::{fence_path, Ceiling, NonceFence};
use observation::{abi_address, abi_bool, abi_u128, abi_u64, address_word, CanonicalRead};
pub(crate) use observation::{OpenChallenge, OpenSetRead};

impl L1 {
    /// Resolved public configuration only: no RPC, key, URL or registration read.
    pub(crate) fn public_clock_identity(&self) -> Option<(u64, [u8; 20])> {
        self.clock
            .as_ref()
            .map(|clock| (clock.chain_id, clock.verifier))
    }
}

/// keccak256("Deposit(address,bytes32,uint256,uint64,bytes32)") — the vault's deposit
/// log topic0 for the SEC-019 event `Deposit(address indexed from, bytes32 indexed
/// ownerCommit, uint256 amount, uint64 id, bytes32 newTip)`. Recomputed for the new
/// signature (the old `Deposit(address,uint256)` topic `0xe1fffcc4…` now matches nothing):
/// a STALE topic0 means the log matcher never fires and EVERY deposit silently fails to
/// credit, so this is load-bearing. The `deposit_topic0_matches_event_signature` test
/// recomputes it from the signature string and guards against drift.
pub(super) const DEPOSIT_TOPIC0: &str =
    "0xdf3f00354434921901d8a49f26c4b0e4a907d497e57f2e9478e9ba4ea43eb0f9";

/// `DarkPerpSettlement.ABI_VERSION()` this gateway speaks. Boot refuses any other.
pub(crate) const ABI_VERSION: u64 = 3;
/// Seconds per block on the settlement chain (Base makes one block every 2 s). The
/// settlement counts its liveness window in blocks; permit lifetimes are seconds.
pub(crate) const L1_BLOCK_SECS: u64 = 2;
/// `BOND_BPS` in the settlement: the bond covers this share of TVL, in basis points.
const BOND_BPS: u128 = 500;
/// Stake refunds owed to the sequencer are swept to the answer key once they
/// reach one default challenge stake (0.01 ETH), so they pay for answer gas.
const STAKE_SWEEP_MIN_WEI: u128 = 10_000_000_000_000_000;

/// Per-RPC timeout handed to every `cast` invocation (bounds each JSON-RPC call).
const CAST_RPC_TIMEOUT_SECS: u64 = 15;
/// Hard wall-clock bound on a whole `cast` subprocess. `send()` holds the nonce lock
/// across the entire call (which waits for the receipt), so a wedged RPC or a receipt
/// wait that never returns would otherwise freeze settlement AND inclusion-challenge
/// answering indefinitely (risking a bond slash). On timeout the child is killed and
/// the call fails, so `send()` re-seeds the nonce from chain and the loop retries.
const CAST_WALL_TIMEOUT_SECS: u64 = 90;

/// L1 bridge configuration, read from env. `None` ⇒ L1 mode off (pure in-memory).
#[derive(Clone)]
pub struct L1 {
    clock: Option<ClockConfig>,
    pub rpc: String,
    /// Optional independent read endpoint. Used by authoritative state readers, never
    /// for transaction submission or signing. A configured witness must agree;
    /// unavailability cannot silently downgrade the observation to one provider.
    rpc_witness: Option<String>,
    /// Chain identity established before key setup. Witness agreement on a
    /// different chain is still a refusal, even if both endpoints switch together.
    witness_chain: Option<u64>,
    pub settlement: String,
    /// Path to the V3 keystore encrypting the sequencer key, and to its (0600) password
    /// file. `cast` signs via `--keystore`/`--password-file`, so the raw key never enters a
    /// process argv (audit DP-013). A native in-process signer is the eventual full fix.
    keystore_path: String,
    password_file: String,
    /// RAII guard: removes the keystore temp dir when the LAST `L1` clone drops, so the
    /// on-disk key material does not persist / accumulate across restarts (DP-013 review).
    _keystore: std::sync::Arc<KeystoreDir>,
    /// USDC token (collateral asset) — needed for the bond top-up + deposit checks.
    pub usdc: Option<String>,
    /// CollateralVault — needed to read `claimed(leaf)` and match deposit logs.
    pub vault: Option<String>,
    /// Locally-tracked next transaction nonce, shared across clones. Base Sepolia's
    /// public RPC lags its `pending` nonce, so relying on cast's default nonce source
    /// makes back-to-back sends collide ("nonce too low" / "replacement underpriced"),
    /// which stalled settlement the moment a deposit made the bond non-zero. We seed
    /// from the confirmed chain nonce once, pass `--nonce` explicitly, and increment
    /// per confirmed send; the mutex is held across each send so all L1 transactions
    /// (settle loop + challenge-answer loop) serialize and never race. A failed send
    /// resets it to re-seed from chain on the next attempt.
    nonce: std::sync::Arc<std::sync::Mutex<Option<u64>>>,
    /// Optional separate key for challenge answers (`L1_ANSWER_KEYSTORE`), with its
    /// own nonce lane so answers never queue behind a register, settle or bond send.
    /// `None` falls back to the sequencer lane.
    answer: Option<AnswerLane>,
    /// Bond top-up target and the operator's slash acknowledgement (shared by clones).
    bond_policy: std::sync::Arc<BondPolicy>,
    /// Freshness of the open-challenge read. The settle loop refuses to seal while
    /// the watcher cannot see the open set.
    challenge_discovery: crate::challenge_scan::Discovery,
    /// The sequencer address, derived once from the keystore.
    sequencer_addr: std::sync::Arc<std::sync::OnceLock<String>>,
    /// Durable record of the highest sequencer-key nonce ever broadcast, set once
    /// the state path is known and shared by every clone. Unset (tests, or no
    /// persistence) records nothing, and recovery then treats the fence as unknown.
    nonce_fence: std::sync::Arc<std::sync::OnceLock<NonceFence>>,
    /// Set when answers may have routed stakes to the sequencer's `pendingEth`.
    /// The settle loop sweeps them before admission pauses, so the claim never
    /// sits on the sequencer lane while a window waits to register.
    stake_sweep: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// A second signing key and its nonce tracker. The key file is the operator's;
/// the gateway never writes or removes it.
#[derive(Clone)]
struct AnswerLane {
    keystore_path: String,
    password_file: String,
    address: String,
    nonce: std::sync::Arc<std::sync::Mutex<Option<u64>>>,
}

/// One signer as `send_on` sees it.
struct Lane<'a> {
    keystore_path: &'a str,
    password_file: &'a str,
    address: Option<&'a str>,
    nonce: &'a std::sync::Mutex<Option<u64>>,
}

/// Bond policy (design: post capacity toward a TVL target; stop topping up after a
/// slash until an operator acknowledges it).
#[derive(Default)]
pub(crate) struct BondPolicy {
    /// `ceil(L1_BOND_TARGET_TVL * BOND_BPS / 10_000)`: the bond that covers the
    /// configured TVL target.
    target_tvl_bond: u128,
    /// The highest `slashCount()` an operator has acknowledged.
    acknowledged_slashes: std::sync::atomic::AtomicU64,
    /// Set while one top-up is being sent.
    in_flight: std::sync::atomic::AtomicBool,
}

impl BondPolicy {
    /// Record an operator's acknowledgement of `requested` slashes. Only the
    /// exact `observed` count is accepted: a stale count would leave a newer slash
    /// unseen, and a future one would pre-acknowledge slashes that have not
    /// happened. The acknowledged count never goes down.
    fn acknowledge(&self, observed: u64, requested: u64) -> Result<u64, String> {
        if observed != requested {
            return Err(format!(
                "slashCount() is {observed}; acknowledge that exact value"
            ));
        }
        self.acknowledged_slashes
            .fetch_max(observed, std::sync::atomic::Ordering::SeqCst);
        Ok(observed)
    }
}

fn read_slash_count(r: &CanonicalRead<'_>, s: &str) -> Result<u64, String> {
    abi_u64(r.word(s, "slashCount()", None)?, "slashCount")
}

/// Bond needed to cover `target_tvl` at `BOND_BPS`, rounded up.
pub(crate) fn tvl_target_bond(target_tvl: u128) -> Option<u128> {
    Some(target_tvl.checked_mul(BOND_BPS)?.checked_add(9_999)? / 10_000)
}

/// What `ensure_bond` decided from one observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BondPlan {
    Covered { target: u128 },
    TopUp { amount: u128, target: u128 },
    Paused { slash_count: u64, acknowledged: u64 },
}

/// Target `max(2 * requiredBond, bond for the TVL target)`. Any slash newer than
/// the acknowledged count pauses top-ups, so a systematic answering fault cannot
/// drain the operator one capped fine at a time.
pub(crate) fn bond_plan(
    required: u128,
    bond: u128,
    slash_count: u64,
    acknowledged: u64,
    target_tvl_bond: u128,
) -> BondPlan {
    if slash_count > acknowledged {
        return BondPlan::Paused {
            slash_count,
            acknowledged,
        };
    }
    let target = required.saturating_mul(2).max(target_tvl_bond);
    if bond >= target {
        BondPlan::Covered { target }
    } else {
        BondPlan::TopUp {
            amount: target - bond,
            target,
        }
    }
}

/// The result of one `ensure_bond` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BondOutcome {
    Covered {
        bond: u128,
        target: u128,
        capacity: u128,
    },
    ToppedUp {
        tx: String,
        amount: u128,
        target: u128,
    },
    PausedAfterSlash {
        slash_count: u64,
        acknowledged: u64,
    },
    /// Another top-up is still being sent.
    InFlight,
}

struct InFlight<'a>(&'a std::sync::atomic::AtomicBool);
impl<'a> InFlight<'a> {
    fn take(flag: &'a std::sync::atomic::AtomicBool) -> Option<Self> {
        (!flag.swap(true, std::sync::atomic::Ordering::SeqCst)).then_some(Self(flag))
    }
}
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One entry of a batched `answerChallenges` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChallengeAnswer {
    pub order_hash: Digest,
    pub by_rejection: bool,
    pub proof: Vec<Digest>,
}

/// L1 terms the boot handshake checks before any other read relies on them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BootPosture {
    pub abi_version: u64,
    pub verifier: [u8; 20],
    pub proof_version: u64,
    pub vault: [u8; 20],
    pub vault_settlement: [u8; 20],
    pub anchor_timeout_ms: Option<u64>,
    pub liveness_timeout_blocks: u64,
    pub consumed_deposit_count: u64,
    pub current_root: Digest,
    /// `enclaveSigner()`: the only key whose challenge authorization the
    /// settlement accepts.
    pub enclave_signer: [u8; 20],
    /// `sequencer()`: the only key that may register phase-0 anchors and settle.
    pub sequencer: [u8; 20],
}

/// What this gateway is configured for and holds locally.
#[derive(Clone, Debug)]
pub(crate) struct BootExpectation {
    pub settlement: [u8; 20],
    pub vault: Option<[u8; 20]>,
    pub clock_verifier: Option<[u8; 20]>,
    /// The address of this gateway's enclave key, which signs every receipt's
    /// `l1Challenge` authorization.
    pub enclave_signer: [u8; 20],
    /// The address of the sequencer keystore this gateway sends from.
    pub sequencer: [u8; 20],
    pub min_anchor_timeout_ms: u64,
    pub last_settled_root: Digest,
    pub live_root: Digest,
    pub local_consumed: u64,
    /// `DEPOSIT_PERMIT_TTL_SECS`.
    pub permit_ttl_secs: u64,
}

/// The smallest `anchorTimeoutMs` that cannot cancel an anchor whose honest proof
/// is still on its way: register finality, proving, settle finality, plus margin.
pub(crate) fn min_anchor_timeout_ms(prover_timeout_secs: u64) -> u64 {
    crate::clock_wait::FINALITY_BUDGET
        .as_secs()
        .saturating_mul(2)
        .saturating_add(prover_timeout_secs)
        .saturating_add(300)
        .saturating_mul(1000)
}

/// Refuse to run against a settlement this binary does not speak, keys other
/// than the settlement's enclave signer and sequencer, an unclocked or foreign
/// verifier, an unpaired vault, a too-short anchor timeout, or a consumed-deposit
/// count that disagrees with the settled root.
pub(crate) fn check_boot_posture(p: &BootPosture, e: &BootExpectation) -> Result<(), String> {
    if p.abi_version != ABI_VERSION {
        return Err(format!(
            "settlement ABI_VERSION is {}, this gateway speaks {ABI_VERSION}",
            p.abi_version
        ));
    }
    // Nothing else on L1 checks the enclave key: with another seed every
    // receipt's l1Challenge would be refused (BadReceiptSignature) while trading,
    // deposits and settlement all kept working.
    if p.enclave_signer != e.enclave_signer {
        return Err(format!(
            "the settlement's enclaveSigner() is {} but ENCLAVE_SEED signs as {}; no inclusion challenge could be opened with this gateway's receipts",
            crate::hex0x(&p.enclave_signer),
            crate::hex0x(&e.enclave_signer)
        ));
    }
    if p.sequencer != e.sequencer {
        return Err(format!(
            "the settlement's sequencer() is {} but the sequencer keystore is {}",
            crate::hex0x(&p.sequencer),
            crate::hex0x(&e.sequencer)
        ));
    }
    if p.proof_version != 2 {
        return Err(format!(
            "settlement verifier proofVersion is {}, expected the clock-bound version 2",
            p.proof_version
        ));
    }
    match e.clock_verifier {
        None => {
            return Err("the settlement verifier is clock-bound; set CLOCK_BOUND_VERIFIER".into())
        }
        Some(v) if v != p.verifier => {
            return Err("CLOCK_BOUND_VERIFIER is not the settlement's verifier()".into())
        }
        Some(_) => {}
    }
    match e.vault {
        None => return Err("L1_VAULT is not set".into()),
        Some(v) if v != p.vault => return Err("L1_VAULT is not the settlement's vault()".into()),
        Some(_) if p.vault_settlement != e.settlement => {
            return Err("the vault is not paired with this settlement".into())
        }
        Some(_) => {}
    }
    match p.anchor_timeout_ms {
        Some(t) if t >= e.min_anchor_timeout_ms => {}
        Some(t) => {
            return Err(format!(
                "clock anchorTimeoutMs {t} is below the {} ms an honest proof may take",
                e.min_anchor_timeout_ms
            ))
        }
        None => return Err("clock anchorTimeoutMs was not read".into()),
    }
    // A permit must expire well inside the liveness window: at most an eighth of
    // it, so a permit issued just before a stall cannot outlive the stall by much.
    let liveness_secs = u128::from(p.liveness_timeout_blocks) * u128::from(L1_BLOCK_SECS);
    if u128::from(e.permit_ttl_secs) * 8 > liveness_secs {
        return Err(format!(
            "DEPOSIT_PERMIT_TTL_SECS {} exceeds an eighth of the settlement's {liveness_secs} s liveness window",
            e.permit_ttl_secs
        ));
    }
    // The continuity check reports a root mismatch on its own. With matching
    // roots, the settled state binds exactly consumedDepositCount deposits; a
    // live state with unsettled credits can only have consumed more.
    if e.last_settled_root == p.current_root {
        let ok = if e.live_root == e.last_settled_root {
            e.local_consumed == p.consumed_deposit_count
        } else {
            e.local_consumed >= p.consumed_deposit_count
        };
        if !ok {
            return Err(format!(
                "local consumed deposit count {} disagrees with L1 consumedDepositCount {}",
                e.local_consumed, p.consumed_deposit_count
            ));
        }
    }
    Ok(())
}

/// Immutable settlement parameters, logged at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SettlementParams {
    pub liveness_timeout_blocks: u64,
    pub challenge_grace_blocks: u64,
    pub progress_batches: u64,
    pub slash_payout_cap: u128,
    pub challenge_bond: u128,
    pub inclusion_deadline_secs: u64,
}

/// Deposit-gate terms at one block, for permit issuance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DepositGateObservation {
    pub block: u64,
    pub close_only: bool,
    pub accepting_deposits: bool,
    pub deposit_capacity: u128,
    pub consumed_deposit_count: u64,
    pub last_progress_block: u64,
    pub liveness_timeout_blocks: u64,
}
impl DepositGateObservation {
    /// Seconds left before anyone may trigger close-only for lack of progress.
    pub(crate) fn remaining_liveness_secs(&self) -> u64 {
        let idle = self.block.saturating_sub(self.last_progress_block);
        self.liveness_timeout_blocks
            .saturating_sub(idle)
            .saturating_mul(L1_BLOCK_SECS)
    }
}

/// Liveness terms at one block, for the keepalive and its alert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LivenessObservation {
    pub head: u64,
    pub last_progress_block: u64,
    pub liveness_timeout_blocks: u64,
    pub close_only: bool,
}
impl LivenessObservation {
    /// Blocks since the settlement last progressed.
    pub(crate) fn idle_blocks(&self) -> u64 {
        self.head.saturating_sub(self.last_progress_block)
    }
    /// An idle gateway settles an empty keepalive batch once a quarter of the
    /// liveness window has passed without progress.
    pub(crate) fn keepalive_due(&self) -> bool {
        !self.close_only && self.idle_blocks() >= self.liveness_timeout_blocks / 4
    }
    /// Blocks until the keepalive is due (0 once it is).
    pub(crate) fn blocks_until_keepalive(&self) -> u64 {
        (self.liveness_timeout_blocks / 4).saturating_sub(self.idle_blocks())
    }
    /// Half of the liveness window has passed without progress.
    pub(crate) fn liveness_low(&self) -> bool {
        !self.close_only && self.idle_blocks() >= self.liveness_timeout_blocks / 2
    }
}

/// Settlement terms at the finalized block that ingestion and the account views
/// depend on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SettlementFinality {
    pub block: u64,
    pub close_only: bool,
    pub consumed_deposit_count: u64,
}

/// What the bridge last published — surfaced to the UI so on-chain settlement is visible.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct L1Status {
    pub settled_root: String,
    pub batch_count: u64,
    pub last_tx: String,
    /// Sequencer bond, in USDC base units (the bond is USDC-denominated, audit Q1).
    pub bond: String,
    /// Cumulative withdrawals root last published to the vault (0x0 if none pending).
    pub withdrawals_root: String,
}

/// Reject aliases of the same endpoint host before a two-provider policy can be
/// enabled. Distinct hosts are a configuration guard, not proof of independent
/// operators (DNS, proxies and shared upstreams still require operator review).
fn witness_endpoint(primary: &str, witness: Option<String>) -> Result<Option<String>, String> {
    fn identity(value: &str) -> Result<String, String> {
        let uri: axum::http::Uri = value.parse().map_err(|_| "invalid RPC endpoint URL")?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) {
            return Err("RPC endpoint must use HTTP(S)".into());
        }
        let authority = uri.authority().ok_or("RPC endpoint requires a host")?;
        let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
        let host_port = authority.as_str().rsplit('@').next().unwrap_or_default();
        let port_suffix = &host_port[authority.host().len()..];
        if host.is_empty()
            || value.contains('#')
            || (!port_suffix.is_empty()
                && port_suffix
                    .strip_prefix(':')
                    .and_then(|p| p.parse::<u16>().ok())
                    .is_none())
        {
            return Err("invalid RPC endpoint host or port".into());
        }
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
            let ip = match ip {
                std::net::IpAddr::V6(v) => {
                    v.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip)
                }
                _ => ip,
            };
            return Ok(if ip.is_loopback() {
                "loopback".into()
            } else {
                ip.to_string()
            });
        }
        if host == "localhost" || host.ends_with(".localhost") {
            return Ok("loopback".into());
        }
        // Ambiguous shortened, octal or hexadecimal IPv4 strings must not pass
        // as a second DNS host and then normalize back to the same address in cast.
        if host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || host.split('.').any(|part| part.starts_with("0x"))
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || host
                .split('.')
                .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
        {
            return Err("invalid or ambiguous RPC endpoint host".into());
        }
        Ok(host)
    }
    if let Some(ref value) = witness {
        if identity(primary)? == identity(value)? {
            return Err("L1_RPC_WITNESS must use a distinct endpoint host".into());
        }
    }
    Ok(witness)
}

fn decimal_u128(value: &str) -> Option<u128> {
    (!value.is_empty() && value.len() <= 39 && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

/// `L1_BOND_TARGET_TVL` (USDC base units, default 0 = no TVL target) and
/// `L1_BOND_ACKED_SLASH_COUNT` (default 0). Malformed values refuse to start.
pub(crate) fn bond_policy_from_values(
    target_tvl: Option<&str>,
    acked: Option<&str>,
) -> Result<BondPolicy, String> {
    let target_tvl = match target_tvl {
        None => 0,
        Some(v) => decimal_u128(v).ok_or("L1_BOND_TARGET_TVL must be a decimal USDC amount")?,
    };
    let target_tvl_bond = tvl_target_bond(target_tvl).ok_or("L1_BOND_TARGET_TVL is too large")?;
    let acknowledged = match acked {
        None => 0,
        Some(v) => decimal_u128(v)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or("L1_BOND_ACKED_SLASH_COUNT must be a decimal count")?,
    };
    Ok(BondPolicy {
        target_tvl_bond,
        acknowledged_slashes: acknowledged.into(),
        in_flight: false.into(),
    })
}

/// Both answer-key paths or neither. The password file must not be readable by
/// group or others.
fn answer_paths_from_values(
    keystore: Option<&str>,
    password: Option<&str>,
) -> Result<Option<(String, String)>, String> {
    match (
        keystore.filter(|s| !s.is_empty()),
        password.filter(|s| !s.is_empty()),
    ) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            Err("L1_ANSWER_KEYSTORE and L1_ANSWER_PASSWORD_FILE must be set together".into())
        }
        (Some(k), Some(p)) => {
            if !std::path::Path::new(k).is_file() {
                return Err("L1_ANSWER_KEYSTORE is not a readable file".into());
            }
            let meta = std::fs::metadata(p)
                .map_err(|_| "L1_ANSWER_PASSWORD_FILE is not a readable file")?;
            if !meta.is_file() {
                return Err("L1_ANSWER_PASSWORD_FILE is not a readable file".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(
                        "L1_ANSWER_PASSWORD_FILE must not be readable by group or others".into(),
                    );
                }
            }
            Ok(Some((k.to_string(), p.to_string())))
        }
    }
}

fn witness_chain_override(declared: Option<&str>) -> Result<u64, String> {
    declared
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            "L1_RPC_WITNESS with L1_ALLOW_MOCK_PROOF requires an explicit nonzero L1_CHAIN_ID"
                .into()
        })
}

/// The read methods a settlement observation may send. `eth_getTransactionCount`
/// is the sequencer nonce that the boot dead-intent check compares with the nonce
/// fence. Nothing here signs or mutates.
fn settlement_read_method(method: &str) -> bool {
    matches!(
        method,
        "eth_chainId"
            | "eth_getBlockByNumber"
            | "eth_call"
            | "eth_getCode"
            | "eth_getLogs"
            | "eth_getTransactionCount"
    )
}

/// A restricted adapter for the optional witness policy. Neither endpoint receives
/// keys or mutation calls. Do not propagate cast stderr or provider JSON errors:
/// those can echo credential-bearing URL paths, userinfo, queries or response data.
struct SettlementReader<'a> {
    l1: &'a L1,
    endpoint: &'a str,
    role: &'static str,
}
impl crate::deposit_rpc::Rpc for SettlementReader<'_> {
    fn call(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        if !settlement_read_method(method) {
            return Err("settlement observation: unsupported read method".into());
        }
        let mut args = vec![
            "rpc".to_string(),
            "--rpc-url".into(),
            self.endpoint.into(),
            method.into(),
        ];
        args.extend(params.iter().map(|v| v.to_string()));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = self
            .l1
            .cast(&refs)
            .map_err(|_| format!("settlement observation: {} {method} failed", self.role))?;
        serde_json::from_str(&out)
            .map_err(|_| format!("settlement observation: {} invalid RPC response", self.role))
    }
}

/// Separate transport from parsing so local fault fixtures exercise the exact
/// observation routine used by live error reconciliation and boot recovery.
fn settlement_observation_from(
    rpc: &impl crate::deposit_rpc::Rpc,
    witness: Option<&dyn crate::deposit_rpc::Rpc>,
    expected_chain: Option<u64>,
    settlement: &str,
) -> Result<(u64, String, u128), String> {
    let read = CanonicalRead::new(rpc, witness, expected_chain)?;
    let batch = abi_u64(read.word(settlement, "batchCount()", None)?, "batchCount")?;
    let root = read.word(settlement, "currentStateRoot()", None)?;
    let bond = abi_u128(
        read.word(settlement, "sequencerBond()", None)?,
        "sequencerBond",
    )?;
    read.finish()?;
    Ok((batch, crate::hex32(&root), bond))
}

impl L1 {
    #[cfg(test)]
    pub(crate) fn test_reader(rpc: String) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "a01-readonly-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        Self {
            clock: None,
            rpc,
            rpc_witness: None,
            witness_chain: None,
            settlement: String::new(),
            keystore_path: String::new(),
            password_file: String::new(),
            _keystore: std::sync::Arc::new(KeystoreDir(dir)),
            usdc: None,
            vault: None,
            nonce: std::sync::Arc::new(std::sync::Mutex::new(None)),
            answer: None,
            bond_policy: Default::default(),
            challenge_discovery: Default::default(),
            sequencer_addr: Default::default(),
            nonce_fence: Default::default(),
            stake_sweep: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// Configure from env. Requires `L1_SETTLEMENT` + `L1_SEQUENCER_KEY`; RPC defaults
    /// to Base Sepolia. `L1_USDC` + `L1_VAULT` enable the USDC bond, deposit
    /// confirmation, and withdrawal-claim pruning. `L1_RPC_WITNESS` optionally
    /// requires a second endpoint for authoritative finalized state observations.
    pub fn from_env() -> Option<L1> {
        let settlement = std::env::var("L1_SETTLEMENT").ok()?;
        let key = std::env::var("L1_SEQUENCER_KEY").ok()?;
        let allow_unsafe = std::env::var("L1_ALLOW_MOCK_PROOF").ok().as_deref() == Some("1");
        let rpc = std::env::var("L1_RPC").unwrap_or_else(|_| "https://sepolia.base.org".into());
        let configured_witness = match std::env::var("L1_RPC_WITNESS") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                eprintln!("[l1] REFUSING to start: invalid L1_RPC_WITNESS encoding");
                std::process::exit(1);
            }
        };
        let rpc_witness = match witness_endpoint(&rpc, configured_witness) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("[l1] REFUSING to start: {e}");
                std::process::exit(1);
            }
        };
        // audit DP-007 (+ code-review): this bridge submits mock-shaped proofs (proof ==
        // publicCommitment), which only MockZkVerifier accepts, so it must run ONLY on an
        // allowlisted testnet. Skip the RPC query entirely when explicitly overridden (its
        // answer is unused). L1_CHAIN_ID is OPTIONAL: if set it must MATCH the RPC's real chain
        // (extra assurance against a proxied endpoint); if unset the guard is just the allowlist
        // on the RPC's actual chain — so upgrading without the new var no longer crashes boot.
        // The chain check runs BEFORE creating any on-disk key material, so a refusal leaks no
        // keystore, and the query retries so a transient RPC blip doesn't crash startup.
        let witness_chain = if !allow_unsafe {
            let actual = query_chain_id_retry(&rpc);
            let declared = std::env::var("L1_CHAIN_ID")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(actual);
            if !l1_chain_ok(declared, actual, false) {
                eprintln!(
                    "[l1] REFUSING to start the settlement bridge: the RPC serves chain {actual} \
                     (declared L1_CHAIN_ID={declared}), not an allowlisted testnet this \
                     MockZkVerifier-shaped bridge may run on. Point L1_RPC at a testnet (and match \
                     L1_CHAIN_ID if set), or set L1_ALLOW_MOCK_PROOF=1 to override — UNSAFE, never \
                     on a real-value chain."
                );
                std::process::exit(1);
            }
            rpc_witness.as_ref().map(|_| actual)
        } else if rpc_witness.is_some() {
            match witness_chain_override(std::env::var("L1_CHAIN_ID").ok().as_deref()) {
                Ok(chain) => Some(chain),
                Err(e) => {
                    eprintln!("[l1] REFUSING to start: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            None
        };
        let clock = ClockConfig::from_env().unwrap_or_else(|error| {
            eprintln!("[clock] REFUSING to start: {error}");
            std::process::exit(1);
        });
        // An empty value (as in deploy/env/gateway.env.example) means unset.
        let bond_policy = bond_policy_from_values(
            std::env::var("L1_BOND_TARGET_TVL")
                .ok()
                .filter(|v| !v.is_empty())
                .as_deref(),
            std::env::var("L1_BOND_ACKED_SLASH_COUNT")
                .ok()
                .filter(|v| !v.is_empty())
                .as_deref(),
        )
        .unwrap_or_else(|error| {
            eprintln!("[l1] REFUSING to start: {error}");
            std::process::exit(1);
        });
        let answer_paths = answer_paths_from_values(
            std::env::var("L1_ANSWER_KEYSTORE").ok().as_deref(),
            std::env::var("L1_ANSWER_PASSWORD_FILE").ok().as_deref(),
        )
        .unwrap_or_else(|error| {
            eprintln!("[l1] REFUSING to start: {error}");
            std::process::exit(1);
        });
        // audit DP-013: encrypt the key into a keystore, so it never enters a cast argv.
        let (keystore_path, password_file, dir) = match create_keystore(&key) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[l1] REFUSING to start: could not create the sequencer keystore: {e}");
                std::process::exit(1);
            }
        };
        let mut l1 = L1 {
            clock,
            rpc,
            rpc_witness,
            witness_chain,
            settlement,
            keystore_path,
            password_file,
            _keystore: std::sync::Arc::new(KeystoreDir(dir)),
            usdc: std::env::var("L1_USDC").ok(),
            vault: std::env::var("L1_VAULT").ok(),
            nonce: std::sync::Arc::new(std::sync::Mutex::new(None)),
            answer: None,
            bond_policy: std::sync::Arc::new(bond_policy),
            challenge_discovery: Default::default(),
            sequencer_addr: Default::default(),
            nonce_fence: Default::default(),
            // Stakes may have accrued before this start.
            stake_sweep: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        match answer_paths {
            Some((keystore_path, password_file)) => {
                match l1.answer_lane_from(keystore_path, password_file) {
                    Ok(lane) => {
                        println!("[l1] challenge answers use their own key {}", lane.address);
                        l1.answer = Some(lane);
                    }
                    Err(e) => {
                        eprintln!("[l1] REFUSING to start: {e}");
                        l1.cleanup_keystore();
                        std::process::exit(1);
                    }
                }
            }
            None => eprintln!(
                "[l1] WARN: L1_ANSWER_KEYSTORE is not set; challenge answers share the \
                 sequencer key and nonce lane with register, settle and bond sends"
            ),
        }
        Some(l1)
    }

    /// Validate the operator's answer keystore: its address must differ from the
    /// sequencer's, or the two nonce trackers would race on one account.
    fn answer_lane_from(
        &self,
        keystore_path: String,
        password_file: String,
    ) -> Result<AnswerLane, String> {
        let address = self
            .cast(&[
                "wallet",
                "address",
                "--keystore",
                &keystore_path,
                "--password-file",
                &password_file,
            ])
            .map_err(|_| "L1_ANSWER_KEYSTORE does not open with L1_ANSWER_PASSWORD_FILE")?;
        let parsed = crate::parse_addr20_hex(address.trim())
            .ok_or("L1_ANSWER_KEYSTORE did not yield an address")?;
        let sequencer = self.sequencer_address()?;
        if crate::parse_addr20_hex(&sequencer) == Some(parsed) {
            return Err(
                "L1_ANSWER_KEYSTORE must hold a different key than L1_SEQUENCER_KEY".into(),
            );
        }
        Ok(AnswerLane {
            keystore_path,
            password_file,
            address: crate::hex0x(&parsed),
            nonce: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Read-only JSON-RPC, with the same subprocess and network deadlines as the bridge.
    /// No signing key, transaction send, or receipt-based credit shortcut is exposed.
    pub(crate) fn read_rpc(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        let primary = SettlementReader {
            l1: self,
            endpoint: &self.rpc,
            role: "primary",
        };
        let witness = self.rpc_witness.as_ref().map(|endpoint| SettlementReader {
            l1: self,
            endpoint,
            role: "witness",
        });
        observation::deposit_read(
            &primary,
            witness.as_ref().map(|r| r as &dyn crate::deposit_rpc::Rpc),
            self.witness_chain,
            method,
            params.to_vec(),
        )
    }

    /// The confirmed transaction count of `addr` = its next unused nonce.
    fn chain_nonce(&self, addr: &str) -> Result<u64, String> {
        let out = self.cast(&["nonce", addr, "--rpc-url", &self.rpc])?;
        out.split_whitespace()
            .next()
            .unwrap_or("")
            .parse::<u64>()
            .map_err(|e| format!("nonce parse: {e}"))
    }

    fn cast(&self, args: &[&str]) -> Result<String, String> {
        use std::io::Read;
        // Spawn with piped output and a hard wall-clock deadline: a black-hole RPC must
        // not hang forever holding the nonce lock (see CAST_WALL_TIMEOUT_SECS). ETH_RPC_
        // TIMEOUT additionally bounds each individual JSON-RPC call.
        let mut child = Command::new("cast")
            .args(args)
            .env("ETH_RPC_TIMEOUT", CAST_RPC_TIMEOUT_SECS.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("cast spawn failed (is Foundry installed?): {e}"))?;
        // Drain stdout/stderr on their OWN threads: a large child output (e.g. a
        // `cast logs --json` over many events) can exceed the ~64KB OS pipe buffer, and
        // if we only polled try_wait() without reading, the child would block on write()
        // and never exit — a deadlock until the kill deadline. Concurrent readers keep
        // the pipes drained so the child can always make progress and exit.
        let mut stdout_pipe = child.stdout.take().ok_or("cast: no stdout pipe")?;
        let mut stderr_pipe = child.stderr.take().ok_or("cast: no stderr pipe")?;
        let out_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout_pipe.read_to_end(&mut buf);
            buf
        });
        let err_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut buf);
            buf
        });
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(CAST_WALL_TIMEOUT_SECS);
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        // killing closes the pipes, so the readers unblock and finish
                        let _ = out_reader.join();
                        let _ = err_reader.join();
                        return Err(format!(
                            "cast timed out after {CAST_WALL_TIMEOUT_SECS}s (RPC wedged)"
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(format!("cast wait failed: {e}")),
            }
        };
        let stdout = out_reader.join().unwrap_or_default();
        let stderr = err_reader.join().unwrap_or_default();
        if !status.success() {
            return Err(String::from_utf8_lossy(&stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&stdout).trim().to_string())
    }

    /// `cast send <target> <sig> [args..]` signed by the sequencer key, returning the tx hash.
    ///
    /// Holds the shared nonce lock across the whole send (which waits for the receipt),
    /// so every L1 transaction serializes and gets an explicit, monotonic `--nonce` —
    /// immune to the public RPC's lagging `pending` nonce (see the `nonce` field). A
    /// failed send resets the tracker so the next attempt re-seeds from the chain.
    fn send(&self, target: &str, sig: &str, args: &[&str]) -> Result<String, String> {
        // No gas limit ⇒ cast estimates as before, so every pre-existing call site
        // produces a byte-identical argv.
        self.send_opts(target, sig, args, None)
    }

    /// `send` with an optional explicit `--gas-limit`, which makes cast SKIP
    /// `eth_estimateGas`. Needed when a tx's success depends on an earlier same-sender
    /// tx that a load-balanced read backend may not have seen yet (see `ensure_bond`):
    /// execution is nonce-ordered and correct, only the estimate races.
    fn send_opts(
        &self,
        target: &str,
        sig: &str,
        args: &[&str],
        gas_limit: Option<&str>,
    ) -> Result<String, String> {
        self.send_on(self.sequencer_lane(), target, sig, args, gas_limit)
    }

    fn sequencer_lane(&self) -> Lane<'_> {
        Lane {
            keystore_path: &self.keystore_path,
            password_file: &self.password_file,
            address: None,
            nonce: &self.nonce,
        }
    }

    /// The answer key's lane when configured, else the sequencer's.
    fn answer_lane(&self) -> Lane<'_> {
        match &self.answer {
            Some(a) => Lane {
                keystore_path: &a.keystore_path,
                password_file: &a.password_file,
                address: Some(&a.address),
                nonce: &a.nonce,
            },
            None => self.sequencer_lane(),
        }
    }

    fn send_on(
        &self,
        lane: Lane<'_>,
        target: &str,
        sig: &str,
        args: &[&str],
        gas_limit: Option<&str>,
    ) -> Result<String, String> {
        let mut guard = lane.nonce.lock().map_err(|_| "nonce lock poisoned")?;
        let n = match *guard {
            Some(n) => n,
            None => match lane.address {
                Some(addr) => self.chain_nonce(addr)?,
                None => self.chain_nonce(&self.sequencer_address()?)?,
            },
        };
        // A sequencer-key nonce is made durable before the transaction can exist,
        // so recovery can tell when no transaction of ours is still pending.
        if lane.address.is_none() {
            if let Some(fence) = self.nonce_fence.get() {
                fence.cover(n)?;
            }
        }
        let a = send_args(
            target,
            sig,
            args,
            &n.to_string(),
            lane.keystore_path,
            lane.password_file,
            &self.rpc,
            gas_limit,
        );
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        match self.cast(&a) {
            Ok(out) => {
                *guard = Some(n + 1);
                Ok(tx_hash(&out))
            }
            Err(e) => {
                *guard = None; // re-seed from chain next time
                Err(e)
            }
        }
    }

    /// Install the durable nonce fence. Once per process, before the first send.
    pub(crate) fn set_nonce_fence(&self, fence: NonceFence) -> Result<(), String> {
        self.nonce_fence
            .set(fence)
            .map_err(|_| "the nonce fence is already installed".to_string())
    }

    /// What the fence knows; `Unknown` when none is installed.
    pub(crate) fn nonce_ceiling(&self) -> Ceiling {
        self.nonce_fence
            .get()
            .map_or(Ceiling::Unknown, NonceFence::ceiling)
    }

    /// After the journal found at boot is resolved, start recording a fence that
    /// was missing next to it (see `NonceFence::start_fresh_if_unknown`).
    pub(crate) fn restart_unknown_nonce_fence(&self) -> Result<(), String> {
        match self.nonce_fence.get() {
            Some(fence) => fence.start_fresh_if_unknown(),
            None => Ok(()),
        }
    }

    /// Explicitly remove the keystore temp dir (encrypted key + 0600 password file) NOW.
    /// The RAII `Drop` on `KeystoreDir` only fires when the last `L1` clone drops on a
    /// NORMAL return, but the gateway exits via `std::process::exit` from its signal
    /// handler — which skips destructors — so the shutdown path must call this or the key
    /// material persists in $TMPDIR and accumulates one dir per restart (audit #6 /
    /// DP-013 review).
    pub fn cleanup_keystore(&self) {
        let _ = std::fs::remove_dir_all(&self._keystore.0);
    }

    /// Observe related values in one finalized EIP-1898 snapshot. A configured
    /// witness is mandatory for every read and both canonical hashes are rechecked
    /// before any result escapes. Callback errors return no partial observation.
    fn observe<T>(
        &self,
        f: impl FnOnce(&CanonicalRead<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        self.observe_at(observation::AnchorPolicy::Finalized, f)
    }

    fn observe_at<T>(
        &self,
        policy: observation::AnchorPolicy,
        f: impl FnOnce(&CanonicalRead<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let primary = SettlementReader {
            l1: self,
            endpoint: &self.rpc,
            role: "primary",
        };
        let witness = self.rpc_witness.as_ref().map(|endpoint| SettlementReader {
            l1: self,
            endpoint,
            role: "witness",
        });
        let read = CanonicalRead::with_policy(
            &primary,
            witness.as_ref().map(|r| r as &dyn crate::deposit_rpc::Rpc),
            self.witness_chain,
            policy,
        )?;
        let result = f(&read)?;
        read.finish()?;
        Ok(result)
    }

    /// The finalized state root, also used to verify snapshot continuity at boot.
    pub fn current_root(&self) -> Result<String, String> {
        self.observe(|r| {
            r.word(&self.settlement, "currentStateRoot()", None)
                .map(|w| crate::hex32(&w))
        })
    }
    pub fn sequencer_bond(&self) -> Result<u128, String> {
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            abi_u128(
                r.word(&self.settlement, "sequencerBond()", None)?,
                "sequencerBond",
            )
        })
    }
    pub fn batch_count(&self) -> Result<u64, String> {
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            abi_u64(
                r.word(&self.settlement, "batchCount()", None)?,
                "batchCount",
            )
        })
    }
    pub fn settlement_observation(&self) -> Result<(u64, String, u128), String> {
        let primary = SettlementReader {
            l1: self,
            endpoint: &self.rpc,
            role: "primary",
        };
        let witness = self.rpc_witness.as_ref().map(|endpoint| SettlementReader {
            l1: self,
            endpoint,
            role: "witness",
        });
        settlement_observation_from(
            &primary,
            witness.as_ref().map(|r| r as &dyn crate::deposit_rpc::Rpc),
            self.witness_chain,
            &self.settlement,
        )
    }

    /// Gate-opening terms share a canonical hash at the existing confirmation
    /// depth. Both providers must have that depth; no finalized/latest fallback.
    pub fn gate_observation(&self) -> Result<(u64, u64, Digest, bool), String> {
        self.observe_at(
            observation::AnchorPolicy::Confirmed(crate::trading_gate::GATE_OPEN_CONFIRMATIONS),
            |r| {
                Ok((
                    r.height(),
                    abi_u64(
                        r.word(&self.settlement, "batchCount()", None)?,
                        "batchCount",
                    )?,
                    r.word(&self.settlement, "currentStateRoot()", None)?,
                    abi_bool(r.word(&self.settlement, "closeOnly()", None)?, "closeOnly")?,
                ))
            },
        )
    }

    /// All terminal terms belong to one hash-pinned observation, corroborated by
    /// the configured witness and rechecked before the gateway can mutate state.
    pub(crate) fn wind_down_observation(&self) -> Result<crate::wind_down::Observation, String> {
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            Ok(crate::wind_down::Observation {
                block: r.height(),
                close_only: abi_bool(r.word(&self.settlement, "closeOnly()", None)?, "closeOnly")?,
                settled: abi_bool(
                    r.word(&self.settlement, "windDownSettled()", None)?,
                    "windDownSettled",
                )?,
                batch_count: abi_u64(
                    r.word(&self.settlement, "batchCount()", None)?,
                    "batchCount",
                )?,
                root: r.word(&self.settlement, "currentStateRoot()", None)?,
            })
        })
    }

    /// The settled L1 state the close-only rebase returns to, at the finalized
    /// block: close-only is final there, and so are the root and counts.
    pub(crate) fn close_only_settled_observation(
        &self,
    ) -> Result<crate::wind_down::SettledL1, String> {
        self.observe(|r| {
            Ok(crate::wind_down::SettledL1 {
                block: r.height(),
                close_only: abi_bool(r.word(&self.settlement, "closeOnly()", None)?, "closeOnly")?,
                settled: abi_bool(
                    r.word(&self.settlement, "windDownSettled()", None)?,
                    "windDownSettled",
                )?,
                batch_count: abi_u64(
                    r.word(&self.settlement, "batchCount()", None)?,
                    "batchCount",
                )?,
                root: r.word(&self.settlement, "currentStateRoot()", None)?,
                consumed_deposit_count: abi_u64(
                    r.word(&self.settlement, "consumedDepositCount()", None)?,
                    "consumedDepositCount",
                )?,
            })
        })
    }

    #[cfg(test)]
    pub fn close_only_observation(&self) -> Result<(u64, bool), String> {
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            Ok((
                r.height(),
                abi_bool(r.word(&self.settlement, "closeOnly()", None)?, "closeOnly")?,
            ))
        })
    }

    /// The sequencer key's address (the `cast wallet` derivation; no key is printed).
    fn sequencer_address(&self) -> Result<String, String> {
        if let Some(addr) = self.sequencer_addr.get() {
            return Ok(addr.clone());
        }
        let out = self.cast(&[
            "wallet",
            "address",
            "--keystore",
            &self.keystore_path,
            "--password-file",
            &self.password_file,
        ])?;
        let addr = crate::parse_addr20_hex(out.trim())
            .map(|a| crate::hex0x(&a))
            .ok_or("sequencer keystore did not yield an address")?;
        Ok(self.sequencer_addr.get_or_init(|| addr).clone())
    }

    /// The chain the primary RPC serves; must equal the witness chain when one is set.
    fn rpc_chain_id(&self) -> Result<u64, String> {
        use crate::deposit_rpc::Rpc as _;
        let primary = SettlementReader {
            l1: self,
            endpoint: &self.rpc,
            role: "primary",
        };
        let chain = observation::quantity(&primary.call("eth_chainId", vec![])?)?;
        if self.witness_chain.is_some_and(|w| w != chain) {
            return Err("settlement observation: RPC chain disagrees with startup domain".into());
        }
        Ok(chain)
    }

    /// Whether `token` is the testnet MockUSDC faucet (`name() == "Mock USD Coin"`)
    /// on an allowlisted testnet. Any read failure counts as "no".
    fn mintable_mock_token(&self, token: &str) -> bool {
        let mut expected = observation::u64_word(32).to_vec();
        expected.extend(observation::u64_word(13));
        let mut text = [0u8; 32];
        text[..13].copy_from_slice(b"Mock USD Coin");
        expected.extend(text);
        let is_mock = self
            .observe_at(observation::AnchorPolicy::Latest, |r| {
                r.call_bytes(token, "name()", &[])
            })
            .is_ok_and(|name| name == expected);
        is_mock
            && self
                .rpc_chain_id()
                .is_ok_and(|c| l1_chain_allowed(c, false))
    }

    /// Keep the USDC sequencer bond at `max(2 * requiredBond, bond for
    /// L1_BOND_TARGET_TVL)`, so deposit capacity exists before the first deposit.
    /// Mints only MockUSDC on an allowlisted testnet; otherwise the top-up comes
    /// from the sequencer's own balance. Top-ups stop after any slash newer than the
    /// acknowledged count. One top-up runs at a time.
    pub fn ensure_bond(&self) -> Result<BondOutcome, String> {
        let usdc = self.usdc.clone().ok_or("L1_USDC not set")?;
        let Some(_in_flight) = InFlight::take(&self.bond_policy.in_flight) else {
            return Ok(BondOutcome::InFlight);
        };
        let terms = self.observe_at(observation::AnchorPolicy::Latest, |r| {
            read_bond_terms(r, &self.settlement)
        })?;
        let (required, bond, slash_count, capacity) = (
            terms.required,
            terms.bond,
            terms.slash_count,
            terms.capacity,
        );
        let acknowledged = self
            .bond_policy
            .acknowledged_slashes
            .load(std::sync::atomic::Ordering::SeqCst);
        let (amount, target) = match bond_plan(
            required,
            bond,
            slash_count,
            acknowledged,
            self.bond_policy.target_tvl_bond,
        ) {
            BondPlan::Covered { target } => {
                return Ok(BondOutcome::Covered {
                    bond,
                    target,
                    capacity,
                })
            }
            BondPlan::Paused {
                slash_count,
                acknowledged,
            } => {
                return Ok(BondOutcome::PausedAfterSlash {
                    slash_count,
                    acknowledged,
                })
            }
            BondPlan::TopUp { amount, target } => (amount, target),
        };
        let seq = self.sequencer_address()?;
        let seq_word =
            address_word(&crate::parse_addr20_hex(&seq).ok_or("invalid sequencer address")?);
        let settlement_word = address_word(
            &crate::parse_addr20_hex(&self.settlement).ok_or("invalid settlement address")?,
        );
        // Token amounts are uint256; anything above u128 (an unlimited allowance)
        // covers every top-up, so it saturates instead of failing the read.
        let saturating = |w: Digest| abi_u128(w, "token amount").unwrap_or(u128::MAX);
        let (balance, allowance) = self.observe_at(observation::AnchorPolicy::Latest, |r| {
            Ok((
                saturating(r.word(&usdc, "balanceOf(address)", Some(seq_word))?),
                saturating(
                    r.words_args(
                        &usdc,
                        "allowance(address,address)",
                        &[seq_word, settlement_word],
                        1,
                    )?[0],
                ),
            ))
        })?;
        if balance < amount {
            if !self.mintable_mock_token(&usdc) {
                return Err(format!(
                    "bond shortfall: sequencer USDC balance {balance} is below the {amount} \
                     top-up toward a {target} bond; fund the sequencer"
                ));
            }
            let mint = (amount - balance).to_string();
            self.send(&usdc, "mint(address,uint256)", &[&seq, &mint])?;
        }
        let amount_arg = amount.to_string();
        if allowance < amount {
            self.send(
                &usdc,
                "approve(address,uint256)",
                &[&self.settlement, &amount_arg],
            )?;
        }
        // Explicit gas limit: drpc load-balances reads across backends, so postBond's
        // eth_estimateGas can hit a node that hasn't seen the just-mined approve and
        // revert "InsufficientAllowance" — even though same-sender nonce order makes
        // EXECUTION correct (observed live; the current bond was posted manually).
        // Skipping estimation puts the tx straight in the pool, where it executes
        // after approve. postBond = transferFrom + storage ≈ 120k worst case; 300k is
        // comfortable headroom and unused gas is refunded.
        let tx = self.send_opts(
            &self.settlement.clone(),
            "postBond(uint256)",
            &[&amount_arg],
            Some("300000"),
        )?;
        Ok(BondOutcome::ToppedUp { tx, amount, target })
    }

    /// Resume bond top-ups after slashes. The operator names the exact current
    /// `slashCount()`, so acknowledging can never cover a slash not yet seen.
    pub(crate) fn acknowledge_slashes(&self, slash_count: u64) -> Result<u64, String> {
        let observed = self.observe_at(observation::AnchorPolicy::Latest, |r| {
            read_slash_count(r, &self.settlement)
        })?;
        self.bond_policy.acknowledge(observed, slash_count)
    }

    /// The highest `slashCount()` acknowledged so far.
    #[cfg(test)]
    pub(crate) fn acknowledged_slash_count(&self) -> u64 {
        self.bond_policy
            .acknowledged_slashes
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Settlement immutables the gateway's timing depends on.
    pub(crate) fn settlement_params(&self) -> Result<SettlementParams, String> {
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            read_settlement_params(r, &self.settlement)
        })
    }

    /// The boot handshake terms, at one finalized block.
    pub(crate) fn boot_posture(&self) -> Result<BootPosture, String> {
        let clock = self.clock.as_ref().map(|c| crate::hex0x(&c.verifier));
        self.observe(|r| read_boot_posture(r, &self.settlement, clock.as_deref()))
    }

    /// The expectation the boot handshake compares against. Reads the sequencer
    /// keystore's address (a local `cast` call), so call it off the async runtime.
    pub(crate) fn boot_expectation(
        &self,
        enclave_signer: [u8; 20],
        last_settled_root: Digest,
        live_root: Digest,
        local_consumed: u64,
        permit_ttl_secs: u64,
    ) -> Result<BootExpectation, String> {
        Ok(BootExpectation {
            settlement: crate::parse_addr20_hex(&self.settlement)
                .ok_or("invalid L1_SETTLEMENT address")?,
            vault: match &self.vault {
                Some(v) => Some(crate::parse_addr20_hex(v).ok_or("invalid L1_VAULT address")?),
                None => None,
            },
            clock_verifier: self.clock.as_ref().map(|c| c.verifier),
            enclave_signer,
            sequencer: crate::parse_addr20_hex(&self.sequencer_address()?)
                .ok_or("invalid sequencer address")?,
            min_anchor_timeout_ms: min_anchor_timeout_ms(
                crate::prover_client::prover_timeout_secs(),
            ),
            last_settled_root,
            live_root,
            local_consumed,
            permit_ttl_secs,
        })
    }

    /// Deposit-gate terms for permit issuance, at the latest block.
    pub(crate) fn deposit_gate_observation(&self) -> Result<DepositGateObservation, String> {
        let s = &self.settlement;
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            Ok(DepositGateObservation {
                block: r.height(),
                close_only: abi_bool(r.word(s, "closeOnly()", None)?, "closeOnly")?,
                accepting_deposits: abi_bool(
                    r.word(s, "acceptingDeposits()", None)?,
                    "acceptingDeposits",
                )?,
                deposit_capacity: abi_u128(
                    r.word(s, "depositCapacity()", None)?,
                    "depositCapacity",
                )?,
                consumed_deposit_count: abi_u64(
                    r.word(s, "consumedDepositCount()", None)?,
                    "consumedDepositCount",
                )?,
                last_progress_block: abi_u64(
                    r.word(s, "lastProgressBlock()", None)?,
                    "lastProgressBlock",
                )?,
                liveness_timeout_blocks: abi_u64(
                    r.word(s, "livenessTimeoutBlocks()", None)?,
                    "livenessTimeoutBlocks",
                )?,
            })
        })
    }

    /// `closeOnly()` and `consumedDepositCount()` at the finalized block.
    pub(crate) fn settlement_finality(&self) -> Result<SettlementFinality, String> {
        let s = &self.settlement;
        self.observe(|r| {
            Ok(SettlementFinality {
                block: r.height(),
                close_only: abi_bool(r.word(s, "closeOnly()", None)?, "closeOnly")?,
                consumed_deposit_count: abi_u64(
                    r.word(s, "consumedDepositCount()", None)?,
                    "consumedDepositCount",
                )?,
            })
        })
    }

    /// Whether the finalized block shows the settlement in close-only.
    pub(crate) fn close_only_finalized(&self) -> Result<bool, String> {
        self.settlement_finality().map(|f| f.close_only)
    }

    /// `consumedDepositCount()` at the finalized block.
    #[allow(dead_code)] // consumed by the close-only rebase
    pub(crate) fn consumed_deposit_count(&self) -> Result<u64, String> {
        self.observe(|r| {
            abi_u64(
                r.word(&self.settlement, "consumedDepositCount()", None)?,
                "consumedDepositCount",
            )
        })
    }

    /// Liveness terms for the keepalive, at the latest block.
    pub(crate) fn liveness_observation(&self) -> Result<LivenessObservation, String> {
        let s = &self.settlement;
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            Ok(LivenessObservation {
                head: r.height(),
                last_progress_block: abi_u64(
                    r.word(s, "lastProgressBlock()", None)?,
                    "lastProgressBlock",
                )?,
                liveness_timeout_blocks: abi_u64(
                    r.word(s, "livenessTimeoutBlocks()", None)?,
                    "livenessTimeoutBlocks",
                )?,
                close_only: abi_bool(r.word(s, "closeOnly()", None)?, "closeOnly")?,
            })
        })
    }

    /// All candidate claims share one finalized canonical snapshot. Any malformed
    /// bool, disagreement, transport error or final reorg rejects the whole set;
    /// callers retain every candidate on error instead of pruning a partial result.
    pub fn claimed_many(&self, leaves: &[Digest]) -> Result<Vec<Digest>, String> {
        let vault = self.vault.as_ref().ok_or("L1_VAULT not set")?;
        self.observe(|r| {
            let mut claimed = Vec::new();
            for leaf in leaves {
                if abi_bool(r.word(vault, "claimed(bytes32)", Some(*leaf))?, "claimed")? {
                    claimed.push(*leaf);
                }
            }
            Ok(claimed)
        })
    }

    /// Boot deposit posture: count and the consumed prefix tip MUST come from the
    /// same finalized block, with a canonical recheck after both ABI words.
    pub fn vault_deposit_observation(&self, consumed_count: u64) -> Result<(u64, String), String> {
        let vault = self.vault.as_ref().ok_or("L1_VAULT not set")?;
        self.observe(|r| {
            Ok((
                abi_u64(r.word(vault, "depositCount()", None)?, "depositCount")?,
                crate::hex32(&r.word(
                    vault,
                    "depositTipAt(uint64)",
                    Some(observation::u64_word(consumed_count)),
                )?),
            ))
        })
    }

    /// Slice 3b-2a / SEC-025-B: submit the gateway-derived roots + the proof through the
    /// nine-parameter `settleBatch` — no `publicCommitment` synthesis. Every value in
    /// `out` except `proof` was derived by the gateway's own witness replay (Task 3);
    /// `out.proof` is the ZK proof (== the commitment bytes for MockProverClient, which
    /// the on-chain MockZkVerifier accepts).
    pub fn settle_proved(
        &self,
        out: &crate::prover_client::ProveOutcome,
    ) -> Result<String, String> {
        let mut checked = out.clone();
        checked.proof = self.clock_proof_for_send(out)?;
        let args = settle_proved_args(&checked);
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let sig = settle_sig_for_phase(out.wind_down_phase)?;
        let batch = if self.clock_enabled() {
            Some(self.batch_count()?)
        } else {
            None
        };
        if self.clock_stopping() {
            return Err("clock settlement cancelled before broadcast; retain journal".into());
        }
        let sent = self.send(&self.settlement.clone(), sig, &refs);
        if let Some(batch) = batch {
            self.wait_clock_settled(batch, out)?;
            return Ok(
                sent.unwrap_or_else(|_| "(clock settlement confirmed after ambiguous send)".into())
            );
        }
        sent
    }

    // ── inclusion-challenge answering ────────────────────────────────────────────

    /// The shared freshness of the open-challenge read.
    pub(crate) fn challenge_discovery(&self) -> &crate::challenge_scan::Discovery {
        &self.challenge_discovery
    }

    /// `openChallengeCount()` at the latest block.
    #[allow(dead_code)] // consumed by the operator alerts
    pub(crate) fn open_challenge_count(&self) -> Result<u64, String> {
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            abi_u64(
                r.word(&self.settlement, "openChallengeCount()", None)?,
                "openChallengeCount",
            )
        })
    }

    /// The whole open-challenge set at one latest block, with a configured witness
    /// agreeing on every word. Stored details are read for at most `max_details`
    /// hashes that are not in `known` (they cannot change while open).
    pub(crate) fn open_challenge_set(
        &self,
        known: &std::collections::BTreeSet<Digest>,
        max_details: usize,
    ) -> Result<OpenSetRead, String> {
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            r.open_challenges(&self.settlement, known, max_details)
        })
    }

    /// Answer open challenges proven by one settled batch with a single
    /// `answerChallenges` call from the answer lane. Entries closed meanwhile are
    /// skipped on-chain; one invalid proof reverts the whole call.
    pub(crate) fn answer_challenges(
        &self,
        batch_id: u64,
        answers: &[ChallengeAnswer],
    ) -> Result<String, String> {
        if answers.is_empty() {
            return Err("no challenge answers to send".into());
        }
        let args = answer_challenges_args(batch_id, answers);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.send_on(
            self.answer_lane(),
            &self.settlement.clone(),
            ANSWER_CHALLENGES_SIG,
            &refs,
            None,
        )
    }

    /// Ask the settle loop to sweep stake refunds (after answers were sent).
    pub(crate) fn request_stake_sweep(&self) {
        self.stake_sweep
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// `sweep_stake_refunds` once per request. Called by the settle loop
    /// before admission pauses, when no window is sealed: the claim is sent from
    /// the sequencer key, so it must not queue a register behind it. A failed
    /// sweep stays requested.
    pub(crate) fn sweep_requested_stake_refunds(&self) -> Result<Option<String>, String> {
        if !take_request(&self.stake_sweep) {
            return Ok(None);
        }
        let swept = self.sweep_stake_refunds();
        if swept.is_err() {
            self.request_stake_sweep();
        }
        swept
    }

    /// Stakes that answers routed to the sequencer accrue in `pendingEth`. With a
    /// separate answer key configured, move them there once they reach
    /// `STAKE_SWEEP_MIN_WEI`, so they fund answer gas. Returns the claim tx.
    fn sweep_stake_refunds(&self) -> Result<Option<String>, String> {
        let Some(answer) = &self.answer else {
            return Ok(None);
        };
        let seq = self.sequencer_address()?;
        let seq_word =
            address_word(&crate::parse_addr20_hex(&seq).ok_or("invalid sequencer address")?);
        let pending = self.observe_at(observation::AnchorPolicy::Latest, |r| {
            abi_u128(
                r.word(&self.settlement, "pendingEth(address)", Some(seq_word))?,
                "pendingEth",
            )
        })?;
        if pending < STAKE_SWEEP_MIN_WEI {
            return Ok(None);
        }
        self.send(
            &self.settlement.clone(),
            CLAIM_ETH_TO_SIG,
            &[&answer.address],
        )
        .map(Some)
    }
}

/// Clear a one-shot request flag, reporting whether it was set.
fn take_request(flag: &std::sync::atomic::AtomicBool) -> bool {
    flag.swap(false, std::sync::atomic::Ordering::SeqCst)
}

/// `DarkPerpSettlement.answerChallenges(uint256,bytes32[],bool[],bytes32[][])`.
pub(crate) const ANSWER_CHALLENGES_SIG: &str =
    "answerChallenges(uint256,bytes32[],bool[],bytes32[][])";
/// `DarkPerpSettlement.claimEthTo(address)`: pay the caller's `pendingEth` to `to`.
pub(crate) const CLAIM_ETH_TO_SIG: &str = "claimEthTo(address)";

/// The `answerChallenges` argument vector in Solidity order, as cast array literals.
pub(crate) fn answer_challenges_args(batch_id: u64, answers: &[ChallengeAnswer]) -> Vec<String> {
    let list = |items: Vec<String>| format!("[{}]", items.join(","));
    vec![
        batch_id.to_string(),
        list(answers.iter().map(|a| hex0x32(&a.order_hash)).collect()),
        list(answers.iter().map(|a| a.by_rejection.to_string()).collect()),
        list(
            answers
                .iter()
                .map(|a| list(a.proof.iter().map(hex0x32).collect()))
                .collect(),
        ),
    ]
}

/// Bond terms `ensure_bond` decides from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BondTerms {
    pub required: u128,
    pub bond: u128,
    pub slash_count: u64,
    pub capacity: u128,
}

fn read_bond_terms(r: &CanonicalRead<'_>, s: &str) -> Result<BondTerms, String> {
    Ok(BondTerms {
        required: abi_u128(r.word(s, "requiredBond()", None)?, "requiredBond")?,
        bond: abi_u128(r.word(s, "sequencerBond()", None)?, "sequencerBond")?,
        slash_count: abi_u64(r.word(s, "slashCount()", None)?, "slashCount")?,
        capacity: abi_u128(r.word(s, "depositCapacity()", None)?, "depositCapacity")?,
    })
}

fn read_settlement_params(r: &CanonicalRead<'_>, s: &str) -> Result<SettlementParams, String> {
    Ok(SettlementParams {
        liveness_timeout_blocks: abi_u64(
            r.word(s, "livenessTimeoutBlocks()", None)?,
            "livenessTimeoutBlocks",
        )?,
        challenge_grace_blocks: abi_u64(
            r.word(s, "challengeGraceBlocks()", None)?,
            "challengeGraceBlocks",
        )?,
        progress_batches: abi_u64(r.word(s, "progressBatches()", None)?, "progressBatches")?,
        slash_payout_cap: abi_u128(r.word(s, "slashPayoutCap()", None)?, "slashPayoutCap")?,
        challenge_bond: abi_u128(r.word(s, "challengeBond()", None)?, "challengeBond")?,
        inclusion_deadline_secs: abi_u64(
            r.word(s, "inclusionDeadlineSecs()", None)?,
            "inclusionDeadlineSecs",
        )?,
    })
}

/// The boot handshake terms from one snapshot. `ABI_VERSION` is read first: a
/// settlement that does not speak this ABI fails with that reason rather than
/// on whichever later getter it lacks.
fn read_boot_posture(
    r: &CanonicalRead<'_>,
    s: &str,
    clock: Option<&str>,
) -> Result<BootPosture, String> {
    let abi_version = abi_u64(
        r.word(s, "ABI_VERSION()", None).map_err(|_| {
            "cannot read ABI_VERSION(); the settlement predates this gateway or the RPC failed"
                .to_string()
        })?,
        "ABI_VERSION",
    )?;
    if abi_version != ABI_VERSION {
        return Err(format!(
            "settlement ABI_VERSION is {abi_version}, this gateway speaks {ABI_VERSION}"
        ));
    }
    let verifier = abi_address(r.word(s, "verifier()", None)?, "verifier")?;
    let proof_version = abi_u64(
        r.word(&crate::hex0x(&verifier), "proofVersion()", None)?,
        "proofVersion",
    )?;
    let vault = abi_address(r.word(s, "vault()", None)?, "vault")?;
    let vault_settlement = if vault == [0; 20] {
        [0; 20]
    } else {
        abi_address(
            r.word(&crate::hex0x(&vault), "settlement()", None)?,
            "vault settlement",
        )?
    };
    let anchor_timeout_ms = match clock {
        Some(v) => Some(abi_u64(
            r.word(v, "anchorTimeoutMs()", None)?,
            "anchorTimeoutMs",
        )?),
        None => None,
    };
    Ok(BootPosture {
        abi_version,
        verifier,
        proof_version,
        vault,
        vault_settlement,
        anchor_timeout_ms,
        liveness_timeout_blocks: abi_u64(
            r.word(s, "livenessTimeoutBlocks()", None)?,
            "livenessTimeoutBlocks",
        )?,
        consumed_deposit_count: abi_u64(
            r.word(s, "consumedDepositCount()", None)?,
            "consumedDepositCount",
        )?,
        current_root: r.word(s, "currentStateRoot()", None)?,
        enclave_signer: abi_address(r.word(s, "enclaveSigner()", None)?, "enclaveSigner")?,
        sequencer: abi_address(r.word(s, "sequencer()", None)?, "sequencer")?,
    })
}

/// The nine-parameter settleBatch signature. Six roots, then SEC-019's depositsRoot and
/// newDepositCount, then the proof. Must byte-match
/// `contracts/src/DarkPerpSettlement.sol:311-321`; the gateway previously sent the
/// seven-parameter form, which does not even resolve to this selector.
pub(crate) const SETTLE_BATCH_SIG: &str =
    "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)";
pub(crate) const FINAL_SETTLE_SIG: &str =
    "finalSettle(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)";
pub(crate) const FINAL_EXIT_SIG: &str =
    "finalExit(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)";

pub(crate) fn settle_sig_for_phase(phase: u8) -> Result<&'static str, String> {
    match phase {
        0 => Ok(SETTLE_BATCH_SIG),
        1 => Ok(FINAL_SETTLE_SIG),
        2 => Ok(FINAL_EXIT_SIG),
        _ => Err("invalid wind-down phase in proven outcome".into()),
    }
}

/// The `settleBatch` argument vector, in exactly Solidity's declared order. Pure (no
/// subprocess, no `&self`) so the order is unit-testable against a fixed vector.
/// `newDepositCount` is rendered as a decimal uint64 (cast parses it per the sig).
pub(crate) fn settle_proved_args(out: &crate::prover_client::ProveOutcome) -> Vec<String> {
    let mut proof_hex = String::with_capacity(2 + out.proof.len() * 2);
    proof_hex.push_str("0x");
    for byte in &out.proof {
        proof_hex.push_str(&format!("{byte:02x}"));
    }
    vec![
        crate::hex32(&out.prev_root),
        crate::hex32(&out.manifest_hash),
        crate::hex32(&out.new_root),
        crate::hex32(&out.ordered_root),
        crate::hex32(&out.withdrawals_root),
        crate::hex32(&out.rejected_root),
        crate::hex32(&out.deposits_root),
        out.new_deposit_count.to_string(),
        proof_hex,
    ]
}

/// Build the full `cast send` argv. Pure (no subprocess, no `&self`) so the flag
/// layout is unit-testable — in particular that ONLY a gas-limited send carries
/// `--gas-limit`, and that it lands before `--rpc-url`.
///
/// audit DP-013: authenticate via the encrypted keystore + password FILE, never the
/// raw key in argv. Both are file paths — the key never appears in /proc/<pid>/cmdline.
#[allow(clippy::too_many_arguments)] // a flat argv spec; bundling into a struct adds nothing
fn send_args(
    target: &str,
    sig: &str,
    args: &[&str],
    nonce: &str,
    keystore: &str,
    password_file: &str,
    rpc: &str,
    gas_limit: Option<&str>,
) -> Vec<String> {
    let mut a: Vec<String> = vec!["send".into(), target.into(), sig.into()];
    a.extend(args.iter().map(|s| (*s).into()));
    a.extend([
        "--nonce".into(),
        nonce.into(),
        "--keystore".into(),
        keystore.into(),
        "--password-file".into(),
        password_file.into(),
    ]);
    // An explicit gas limit makes cast skip eth_estimateGas entirely (see send_opts).
    if let Some(g) = gas_limit {
        a.extend(["--gas-limit".into(), g.into()]);
    }
    a.extend(["--rpc-url".into(), rpc.into(), "--json".into()]);
    a
}

/// A 32-byte value as `0x`+64 hex, for cast calldata.
fn hex0x32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Chain ids this bridge may settle against. It submits mock-shaped proofs
/// (`proof == publicCommitment`), which only `MockZkVerifier` accepts, so running
/// it against a real-value chain is catastrophic (audit DP-007). Testnets are
/// allowlisted; anything else requires an explicit unsafe override.
///
/// KEEP IN SYNC with `DeployGuard.isTestnet` (contracts/script/DeployGuard.sol) — Solidity
/// can't call this, so the two allowlists are maintained by hand and must not drift.
pub fn l1_chain_allowed(chain_id: u64, allow_unsafe: bool) -> bool {
    if allow_unsafe {
        return true;
    }
    matches!(
        chain_id,
        84532        // Base Sepolia
        | 11155111   // Sepolia
        | 421614     // Arbitrum Sepolia
        | 11155420   // OP Sepolia
        | 80002      // Polygon Amoy
        | 31337      // anvil / hardhat
        | 1337 // ganache
    )
}

/// Whether the bridge may run against the RPC's chain: the operator-declared `L1_CHAIN_ID`
/// must EQUAL the chain the RPC actually serves AND be an allowlisted testnet. Trusting the
/// declared id alone let an operator point `L1_RPC` at mainnet while declaring a testnet and
/// still submit mock-shaped proofs (audit DP-007 follow-up). `allow_unsafe` overrides.
pub fn l1_chain_ok(declared: u64, actual: u64, allow_unsafe: bool) -> bool {
    if allow_unsafe {
        return true;
    }
    // `actual == 0` means the RPC chain id was unresolved (unreachable / parse fail) — fail
    // closed. Otherwise require the declared id to match ground truth AND be allowlisted.
    actual != 0 && declared == actual && l1_chain_allowed(actual, false)
}

/// Encrypt `key_hex` (a 32-byte secp256k1 scalar) into a fresh V3 keystore plus a 0600
/// password file, so `cast` can sign via `--keystore`/`--password-file` and the raw key
/// never enters any process argv (audit DP-013). Returns (keystore_path, password_file).
/// RAII guard that removes the keystore temp dir on drop (audit DP-013 review — otherwise
/// the encrypted key + password persist in $TMPDIR and accumulate one dir per restart).
struct KeystoreDir(std::path::PathBuf);
impl Drop for KeystoreDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The chain id the RPC serves — a free function (no keystore) so it can be checked BEFORE
/// any on-disk key material is created, and so a refusal leaks nothing (DP-007/DP-013 review).
fn query_chain_id(rpc: &str) -> Result<u64, String> {
    let out = Command::new("cast")
        .args(["chain-id", "--rpc-url", rpc])
        .env("ETH_RPC_TIMEOUT", "15") // bound the startup stall on a black-hole RPC
        .output()
        .map_err(|e| format!("cast spawn failed (is Foundry installed?): {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .parse::<u64>()
        .map_err(|e| format!("chain-id parse: {e}"))
}

/// `query_chain_id` with a few retries, so a TRANSIENT RPC blip at startup does not crash the
/// whole gateway (code-review follow-up). Returns 0 if the chain stays unresolved — which the
/// caller treats as fail-closed. Runs before the async server binds, so a brief block is fine.
fn query_chain_id_retry(rpc: &str) -> u64 {
    for attempt in 0..3 {
        match query_chain_id(rpc) {
            Ok(id) => return id,
            Err(e) => {
                eprintln!("[l1] chain-id query attempt {} failed: {e}", attempt + 1);
                if attempt < 2 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        }
    }
    0
}

fn create_keystore(key_hex: &str) -> Result<(String, String, std::path::PathBuf), String> {
    use std::io::Write as _;
    let raw = key_hex.strip_prefix("0x").unwrap_or(key_hex).trim();
    if raw.len() != 64 {
        return Err("L1_SEQUENCER_KEY must be a 32-byte hex secp256k1 scalar".into());
    }
    // Byte-safe nibble parse (same posture as main.rs `decode_hex`): a non-ASCII
    // byte in the env var errors cleanly instead of a mid-codepoint slice panic.
    let raw = raw.as_bytes();
    let mut pk = [0u8; 32];
    for (i, slot) in pk.iter_mut().enumerate() {
        *slot = match (
            crate::hex_nibble(raw[i * 2]),
            crate::hex_nibble(raw[i * 2 + 1]),
        ) {
            (Some(hi), Some(lo)) => hi << 4 | lo,
            _ => return Err("bad key hex".into()),
        };
    }
    // a random keystore password (kept only in memory + a 0600 file, never in argv)
    let mut pw = [0u8; 32];
    getrandom::getrandom(&mut pw).map_err(|e| format!("rng: {e}"))?;
    let password: String = pw.iter().map(|b| format!("{b:02x}")).collect();

    // An UNPREDICTABLE, owner-only (0700), atomically-created directory: a random name (not
    // the pid) plus a non-recursive create that FAILS if the path already exists, so an
    // attacker cannot pre-plant a symlink or a readable dir at a guessable path.
    let mut rnd = [0u8; 16];
    getrandom::getrandom(&mut rnd).map_err(|e| format!("rng: {e}"))?;
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("darkperp-keystore-{suffix}"));
    {
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            b.mode(0o700);
        }
        b.create(&dir).map_err(|e| format!("keystore dir: {e}"))?;
    }

    // encrypt_key writes the file to `dir/<name>` but RETURNS the uuid, so build the path
    // from the fixed name we chose, not the return value.
    let ksname = "sequencer";
    eth_keystore::encrypt_key(&dir, &mut rand::rngs::OsRng, pk, &password, Some(ksname))
        .map_err(|e| format!("encrypt keystore: {e}"))?;
    let keystore_path = dir.join(ksname);

    // Password file: create_new + 0600 in one step, so it is never briefly world-readable
    // and cannot follow an attacker-planted symlink (create_new fails if the path exists).
    let pw_path = dir.join("password");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&pw_path)
        .map_err(|e| format!("password file: {e}"))?;
    f.write_all(password.as_bytes())
        .map_err(|e| format!("password write: {e}"))?;

    // The keystore file lives inside the 0700 dir (already unreadable by other users);
    // tighten it to 0600 as defense in depth.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&keystore_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((
        keystore_path.to_string_lossy().into_owned(),
        pw_path.to_string_lossy().into_owned(),
        dir,
    ))
}

/// Pull `transactionHash` out of `cast send --json` output (falls back to raw).
fn tx_hash(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| {
            v.get("transactionHash")
                .and_then(|h| h.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| json.lines().next().unwrap_or("").to_string())
}

/// Parse a 32-byte-padded hex topic into the low 20 bytes (an address).
/// Byte-safe: RPC log topics are external data, so a non-ASCII byte returns a
/// clean `None` (never a mid-codepoint `&str` slice panic).
#[cfg(test)]
fn parse_addr20(s: &str) -> Option<[u8; 20]> {
    let h = s.strip_prefix("0x").unwrap_or(s).as_bytes();
    if h.len() < 40 {
        return None;
    }
    let start = h.len() - 40;
    let mut a = [0u8; 20];
    for (i, slot) in a.iter_mut().enumerate() {
        *slot =
            crate::hex_nibble(h[start + i * 2])? << 4 | crate::hex_nibble(h[start + i * 2 + 1])?;
    }
    Some(a)
}

/// Parse a 32-byte hex word (an event topic or a `bytes32` field) into `[u8; 32]`.
/// Byte-safe (external RPC data): a non-ASCII byte returns a clean `None`. Accepts a
/// leading `0x` and requires exactly 64 hex nibbles.
fn parse_bytes32(s: &str) -> Option<[u8; 32]> {
    let h = s.strip_prefix("0x").unwrap_or(s).trim().as_bytes();
    if h.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = crate::hex_nibble(h[i * 2])? << 4 | crate::hex_nibble(h[i * 2 + 1])?;
    }
    Some(out)
}

/// Slice the `n`-th 32-byte (64-nibble) ABI word out of a log `data` hex string.
/// `data` is `0x`-optional and holds the non-indexed event fields packed as full
/// 32-byte words. Returns the word's 64-hex substring, or `None` if `data` is too short.
#[cfg(test)]
fn data_word(data: &str, n: usize) -> Option<&str> {
    let h = data.strip_prefix("0x").unwrap_or(data);
    let start = n * 64;
    let end = start + 64;
    h.get(start..end)
}

/// Parse the SEC-019 `Deposit(address indexed from, bytes32 indexed ownerCommit,
/// uint256 amount, uint64 id, bytes32 newTip)` log out of a `cast receipt --json`
/// body, returning `(from, owner_commit, amount, id)`. Pure (no subprocess) so the
/// parse is unit-testable against a canned receipt fixture. `vault` is the lowercased
/// vault address the log must originate from — a `Deposit` log from any other contract
/// is ignored.
#[cfg(test)]
fn parse_deposit_receipt(
    json: &str,
    vault: &str,
) -> Result<([u8; 20], [u8; 32], u128, u64), String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("receipt json: {e}"))?;
    let logs = v
        .get("logs")
        .and_then(|l| l.as_array())
        .ok_or("no logs in receipt")?;
    for log in logs {
        let addr = log
            .get("address")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_lowercase();
        let topics = log.get("topics").and_then(|t| t.as_array());
        let (Some(topics), true) = (topics, addr == vault) else {
            continue;
        };
        let t0 = topics.first().and_then(|t| t.as_str()).unwrap_or("");
        // topic0 = event sig, topic1 = indexed `from`, topic2 = indexed `ownerCommit`.
        if !t0.eq_ignore_ascii_case(DEPOSIT_TOPIC0) || topics.len() < 3 {
            continue;
        }
        // from = indexed topic1 (low 20 bytes); owner_commit = indexed topic2 (full 32).
        let from = parse_addr20(topics[1].as_str().unwrap_or("")).ok_or("bad from topic")?;
        let owner_commit =
            parse_bytes32(topics[2].as_str().unwrap_or("")).ok_or("bad ownerCommit topic")?;
        // data = amount(uint256) ‖ id(uint64, right-aligned in a word) ‖ newTip(bytes32).
        let data = log.get("data").and_then(|d| d.as_str()).unwrap_or("");
        let amount = parse_u256_low128(data_word(data, 0).ok_or("deposit data too short: amount")?)
            .ok_or("bad amount data")?;
        let id_word = parse_u256_low128(data_word(data, 1).ok_or("deposit data too short: id")?)
            .ok_or("bad id data")?;
        let id: u64 = id_word.try_into().map_err(|_| "deposit id overflows u64")?;
        return Ok((from, owner_commit, amount, id));
    }
    Err("no Deposit log from the vault in this tx".into())
}

/// Parse a uint256 hex word into u128 (USDC amounts fit comfortably); rejects overflow.
/// Byte-safe: operates on bytes (RPC data is external), so a non-ASCII byte returns a
/// clean `None` instead of a mid-codepoint `&str` slice panic.
#[cfg(test)]
fn parse_u256_low128(s: &str) -> Option<u128> {
    let h = s.strip_prefix("0x").unwrap_or(s).trim().as_bytes();
    if h.is_empty() {
        return None;
    }
    // Right-align into a 64-nibble window (matching the old zero-pad/truncate):
    // everything above the low 32 nibbles must be '0' (no overflow of a real
    // USDC amount), and the low 32 nibbles parse as the u128.
    let window = if h.len() > 64 { &h[h.len() - 64..] } else { h };
    let (high, low) = if window.len() > 32 {
        window.split_at(window.len() - 32)
    } else {
        (&[][..], window)
    };
    if high.iter().any(|&b| b != b'0') {
        return None;
    }
    let mut v: u128 = 0;
    for &b in low {
        v = v << 4 | u128::from(crate::hex_nibble(b)?);
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    struct RecoveryRpc {
        replies: std::sync::Mutex<std::collections::VecDeque<Result<serde_json::Value, String>>>,
        calls: std::sync::Mutex<Vec<(String, Vec<serde_json::Value>)>>,
    }
    impl crate::deposit_rpc::Rpc for RecoveryRpc {
        fn call(
            &self,
            method: &str,
            params: Vec<serde_json::Value>,
        ) -> Result<serde_json::Value, String> {
            self.calls.lock().unwrap().push((method.into(), params));
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra recovery read")
        }
    }
    fn recovery_rpc() -> RecoveryRpc {
        use serde_json::json;
        let block = json!({"number": "0x10", "hash": crate::hex32(&[9; 32])});
        let mut batch = [0; 32];
        batch[31] = 6;
        let mut bond = [0; 32];
        bond[31] = 77;
        RecoveryRpc {
            replies: std::sync::Mutex::new(
                vec![
                    Ok(block.clone()),
                    Ok(json!(crate::hex32(&batch))),
                    Ok(json!(crate::hex32(&[3; 32]))),
                    Ok(json!(crate::hex32(&bond))),
                    Ok(block),
                ]
                .into(),
            ),
            calls: std::sync::Mutex::new(vec![]),
        }
    }
    #[test]
    fn journal_recovery_observation_pins_every_term_to_one_finalized_hash() {
        use serde_json::json;
        use sha3::{Digest as _, Keccak256};
        let rpc = recovery_rpc();
        assert_eq!(
            super::settlement_observation_from(&rpc, None, None, "0xvault").unwrap(),
            (6, crate::hex32(&[3; 32]), 77)
        );
        let calls = rpc.calls.lock().unwrap();
        assert_eq!(calls.len(), 5);
        assert_eq!(
            calls[0],
            (
                "eth_getBlockByNumber".into(),
                vec![json!("finalized"), json!(false)]
            )
        );
        for (i, signature) in ["batchCount()", "currentStateRoot()", "sequencerBond()"]
            .iter()
            .enumerate()
        {
            assert_eq!(calls[i + 1].0, "eth_call");
            assert_eq!(
                calls[i + 1].1[0],
                json!({"to": "0xvault", "data": crate::hex0x(&Keccak256::digest(signature.as_bytes())[..4])})
            );
            assert_eq!(
                calls[i + 1].1[1],
                json!({"blockHash": crate::hex32(&[9;32]), "requireCanonical": true})
            );
        }
        assert_eq!(
            calls[4],
            (
                "eth_getBlockByNumber".into(),
                vec![json!("0x10"), json!(false)]
            )
        );
    }
    #[test]
    fn journal_recovery_observation_refuses_failure_at_every_read() {
        for i in 0..5 {
            let rpc = recovery_rpc();
            rpc.replies.lock().unwrap()[i] = Err(format!("injected failure {i}"));
            assert!(
                super::settlement_observation_from(&rpc, None, None, "0xvault")
                    .unwrap_err()
                    .contains("injected failure")
            );
            assert_eq!(rpc.calls.lock().unwrap().len(), i + 1);
        }
    }
    #[test]
    fn journal_recovery_observation_refuses_malformed_overflow_and_forked_data() {
        use serde_json::json;
        let mut overflow_count = [0; 32];
        overflow_count[23] = 1;
        let mut overflow_bond = [0; 32];
        overflow_bond[15] = 1;
        for (i, bad) in [
            (0, json!(null)),
            (
                0,
                json!({"number":"0x10000000000000000", "hash":crate::hex32(&[9;32])}),
            ),
            (1, json!(crate::hex32(&overflow_count))),
            (2, json!("0xdead")),
            (3, json!(crate::hex32(&overflow_bond))),
            (4, json!({"number":"0x10", "hash":crate::hex32(&[8;32])})),
            (4, json!({"number":"0x11", "hash":crate::hex32(&[9;32])})),
        ] {
            let rpc = recovery_rpc();
            rpc.replies.lock().unwrap()[i] = Ok(bad);
            assert!(
                super::settlement_observation_from(&rpc, None, None, "0xvault").is_err(),
                "invalid reply {i} accepted"
            );
        }
    }

    use super::*;

    // SEC-019 Task 7b: DEPOSIT_TOPIC0 MUST equal keccak256 of the new event signature.
    // A stale topic0 silently stops every deposit from crediting (the log matcher never
    // fires), so this guard recomputes the hash from the signature string with the same
    // keccak the rest of the stack uses and pins the constant to it.
    #[test]
    fn deposit_topic0_matches_event_signature() {
        use sha3::{Digest as _, Keccak256};
        let h = Keccak256::digest(b"Deposit(address,bytes32,uint256,uint64,bytes32)");
        let mut expected = String::from("0x");
        for b in h {
            expected.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            DEPOSIT_TOPIC0, expected,
            "DEPOSIT_TOPIC0 must be keccak256(\"Deposit(address,bytes32,uint256,uint64,bytes32)\")"
        );
        // and it must NOT be the stale old-signature topic that matches nothing now.
        assert_ne!(
            DEPOSIT_TOPIC0, "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c",
            "must not be the stale Deposit(address,uint256) topic"
        );
    }

    // SEC-019 Task 7b: the receipt parser extracts (from, ownerCommit, amount, id) from
    // the new indexed-from / indexed-ownerCommit event, reading amount+id out of `data`.
    #[test]
    fn verify_deposit_tx_extracts_from_ownercommit_amount_id() {
        let vault = "0x00000000000000000000000000000000000000aa";
        // data = amount(5_000_000) ‖ id(3) ‖ newTip, each a full 32-byte ABI word.
        let amount_word = "00000000000000000000000000000000000000000000000000000000004c4b40";
        let id_word = "0000000000000000000000000000000000000000000000000000000000000003";
        let tip_word = "3333333333333333333333333333333333333333333333333333333333333333";
        let data = format!("0x{amount_word}{id_word}{tip_word}");
        // A receipt with an unrelated log first (wrong address), then the real Deposit log.
        let json = format!(
            r#"{{"logs":[
                {{"address":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                  "topics":["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
                  "data":"0x"}},
                {{"address":"{vault}",
                  "topics":[
                    "{DEPOSIT_TOPIC0}",
                    "0x0000000000000000000000001111111111111111111111111111111111111111",
                    "0x2222222222222222222222222222222222222222222222222222222222222222"
                  ],
                  "data":"{data}"}}
            ]}}"#
        );
        let (from, owner_commit, amount, id) =
            parse_deposit_receipt(&json, vault).expect("parses the Deposit log");
        assert_eq!(from, [0x11u8; 20], "from = indexed topic1 low 20 bytes");
        assert_eq!(owner_commit, [0x22u8; 32], "ownerCommit = indexed topic2");
        assert_eq!(amount, 5_000_000u128, "amount = data word 0");
        assert_eq!(id, 3u64, "id = data word 1");
        // A wrong vault address ⇒ no matching log ⇒ error (deposit from another contract).
        assert!(
            parse_deposit_receipt(&json, "0x00000000000000000000000000000000000000bb").is_err()
        );
    }

    // audit DP-007: the mock-proof bridge may only settle against testnets; real-value
    // chains are refused unless the operator explicitly opts into the unsound verifier.
    #[test]
    fn mock_proof_bridge_allows_testnets_and_refuses_real_chains() {
        // testnets the bridge may run against
        assert!(l1_chain_allowed(84532, false), "Base Sepolia allowed");
        assert!(l1_chain_allowed(11155111, false), "Sepolia allowed");
        assert!(l1_chain_allowed(31337, false), "anvil allowed");
        // real-value chains are refused (a mock proof there would drain the vault)
        assert!(!l1_chain_allowed(1, false), "Ethereum mainnet refused");
        assert!(!l1_chain_allowed(8453, false), "Base mainnet refused");
        assert!(!l1_chain_allowed(0, false), "unset/unknown chain refused");
        // an explicit unsafe override lifts the guard (the operator's informed choice)
        assert!(l1_chain_allowed(1, true), "override allows any chain");
    }

    // audit DP-007 follow-up: the declared L1_CHAIN_ID must match the chain the RPC
    // actually serves — declaring a testnet while pointing the RPC at mainnet is the bypass.
    #[test]
    fn bridge_cross_checks_declared_chain_against_the_rpc() {
        assert!(
            l1_chain_ok(84532, 84532, false),
            "declared == RPC testnet is allowed"
        );
        assert!(
            !l1_chain_ok(84532, 8453, false),
            "declared testnet but RPC is Base mainnet is refused"
        );
        assert!(
            !l1_chain_ok(8453, 8453, false),
            "a matched mainnet is still refused"
        );
        assert!(
            !l1_chain_ok(84532, 0, false),
            "an unresolved RPC chain fails closed"
        );
        assert!(l1_chain_ok(8453, 8453, true), "override allows any chain");
    }

    // audit DP-013: the sequencer key is encrypted into a keystore that cast reads via file
    // paths, so no `cast` command carries the raw key in argv (L1 no longer even stores it).
    // Verify the keystore actually round-trips the key (so cast can sign with it).
    #[test]
    fn keystore_roundtrips_the_sequencer_key() {
        let key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let (ks, pw, _dir) = create_keystore(key).expect("keystore created");
        let password = std::fs::read_to_string(&pw).expect("password file");
        let decrypted = eth_keystore::decrypt_key(&ks, password.trim()).expect("keystore decrypts");
        let mut expected = [0u8; 32];
        for (i, s) in expected.iter_mut().enumerate() {
            *s = u8::from_str_radix(&key[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(
            decrypted.as_slice(),
            &expected[..],
            "keystore round-trips the sequencer key"
        );
        let _ = std::fs::remove_dir_all(std::path::Path::new(&ks).parent().unwrap());
    }

    // Settle-crash-recovery spec, Design 2: drpc load-balances reads across backends,
    // so postBond's `eth_estimateGas` can hit a node that hasn't seen the just-mined
    // approve → "InsufficientAllowance" — even though same-sender nonce order makes
    // execution correct. The fix skips estimation with an explicit `--gas-limit` on
    // postBond ONLY; every other send keeps estimating with a byte-identical argv.
    #[test]
    fn post_bond_send_has_an_explicit_gas_limit_and_plain_sends_are_unchanged() {
        // postBond-shaped call: --gas-limit 300000 present, placed before --rpc-url.
        let bond = send_args(
            "0xSETTLEMENT",
            "postBond(uint256)",
            &["12345"],
            "7",
            "/tmp/ks",
            "/tmp/pw",
            "http://rpc.example",
            Some("300000"),
        );
        let gl = bond
            .iter()
            .position(|a| a == "--gas-limit")
            .expect("postBond argv carries --gas-limit");
        assert_eq!(bond[gl + 1], "300000", "gas limit value follows the flag");
        let rpc = bond
            .iter()
            .position(|a| a == "--rpc-url")
            .expect("argv carries --rpc-url");
        assert!(gl < rpc, "--gas-limit must precede --rpc-url");

        // A plain send: NO --gas-limit anywhere, and the flag layout is exactly what
        // every pre-existing call site produced (nonce → keystore → password-file →
        // rpc-url → json), so refactoring `send` changed no other transaction.
        let plain = send_args(
            "0xUSDC",
            "mint(address,uint256)",
            &["0xSEQ", "12345"],
            "7",
            "/tmp/ks",
            "/tmp/pw",
            "http://rpc.example",
            None,
        );
        assert_eq!(
            plain,
            [
                "send",
                "0xUSDC",
                "mint(address,uint256)",
                "0xSEQ",
                "12345",
                "--nonce",
                "7",
                "--keystore",
                "/tmp/ks",
                "--password-file",
                "/tmp/pw",
                "--rpc-url",
                "http://rpc.example",
                "--json",
            ]
        );
    }

    /// SEC-025-B: the encoded signature must match Solidity's nine-parameter
    /// settleBatch (contracts/src/DarkPerpSettlement.sol:311-321). Honest scope: this
    /// asserts a Rust constant equals a Rust literal, BOTH written from the same
    /// reading of the Solidity — so it guards ONLY against someone editing
    /// `SETTLE_BATCH_SIG` in isolation. It would NOT have caught SEC-019's arity
    /// change either: a Solidity-side change leaves both sides here stale together.
    /// What DOES catch a Solidity arity change is a Solidity-side selector assertion
    /// against the compiled contract — see
    /// `contracts/test/DarkPerpSettlement.t.sol::test_settleBatch_selector_matches_nine_param_signature`,
    /// which recomputes this exact string's selector and compares it to
    /// `DarkPerpSettlement.settleBatch.selector`.
    #[test]
    fn a06_proven_phase_routes_only_to_its_l1_entrypoint() {
        assert_eq!(settle_sig_for_phase(0).unwrap(), SETTLE_BATCH_SIG);
        assert_eq!(settle_sig_for_phase(1).unwrap(), FINAL_SETTLE_SIG);
        assert_eq!(settle_sig_for_phase(2).unwrap(), FINAL_EXIT_SIG);
        assert!(settle_sig_for_phase(3).is_err());
    }

    #[test]
    fn settle_batch_signature_matches_solidity() {
        assert_eq!(
            SETTLE_BATCH_SIG,
            "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)"
        );
    }

    /// The argument vector must be in Solidity's declared order: six roots, then
    /// depositsRoot, then newDepositCount, then proof. Every argument gets a distinct
    /// byte pattern and EVERY position is asserted (the brief's fixture left positions
    /// 1–4 unasserted, so a transposition among manifestHash/newRoot/orderedRoot/
    /// withdrawalsRoot would have passed — exactly the class of fixture this branch
    /// exists to distrust).
    #[test]
    fn settle_proved_argument_order_matches_solidity() {
        let out = crate::prover_client::ProveOutcome {
            prev_root: [0x11; 32],
            manifest_hash: [0x22; 32],
            new_root: [0x33; 32],
            ordered_root: [0x44; 32],
            withdrawals_root: [0x55; 32],
            rejected_root: [0x66; 32],
            deposits_root: [0x77; 32],
            wind_down_phase: 0,
            new_deposit_count: 42,
            // SEC-025-D: gate terms — consumed by `commit_window_settle`'s opening
            // check, never by the settleBatch calldata this test pins.
            post_mode_is_normal: true,
            post_insurance_fund: 0,
            commitment: [0x88; 32],
            proof: vec![0xab, 0xcd],
        };
        let args = settle_proved_args(&out);
        assert_eq!(args.len(), 9);
        // bytes32 args are cast-shaped: 0x + 64 nibbles.
        assert!(
            args[0].starts_with("0x") && args[0].len() == 66,
            "prevRoot is 0x+64 hex"
        );
        assert!(args[0].ends_with("1111"), "prevRoot is 1st");
        assert!(args[1].ends_with("2222"), "manifestHash is 2nd");
        assert!(args[2].ends_with("3333"), "newRoot is 3rd");
        assert!(args[3].ends_with("4444"), "orderedRoot is 4th");
        assert!(args[4].ends_with("5555"), "withdrawalsRoot is 5th");
        assert!(args[5].ends_with("6666"), "rejectedRoot is 6th");
        assert!(args[6].ends_with("7777"), "depositsRoot is 7th");
        assert_eq!(args[7], "42", "newDepositCount is 8th, decimal uint64");
        assert_eq!(args[8], "0xabcd", "proof is 9th");
    }

    fn selector(sig: &str) -> String {
        use sha3::{Digest as _, Keccak256};
        crate::hex0x(&Keccak256::digest(sig.as_bytes())[..4])
    }

    /// Every settlement entrypoint and getter this crate names, against the
    /// selectors the Solidity suite pins for the deployed ABI.
    #[test]
    fn settlement_signatures_match_the_contract_selectors() {
        for (sig, expected) in [
            (ANSWER_CHALLENGES_SIG, "0x81913954"),
            (CLAIM_ETH_TO_SIG, "0xc1f631b9"),
            ("ABI_VERSION()", "0xf6b45cfd"),
            ("consumedDepositCount()", "0xbefd565d"),
            ("depositCapacity()", "0xf35ce643"),
            ("acceptingDeposits()", "0xdf334093"),
            ("openChallengeCount()", "0x6f443c06"),
            ("openChallenges(uint256,uint256)", "0x555fa4f8"),
            ("challengeGraceBlocks()", "0x48fda272"),
            ("progressBatches()", "0xe17a6484"),
            ("slashPayoutCap()", "0xf2a452c3"),
            ("slashCount()", "0x4d21497f"),
            ("challenges(bytes32)", "0xc1e69b66"),
            (
                "challengeAuthDigest(bytes32,uint64,uint64,uint64,address)",
                "0x441859ad",
            ),
            (SETTLE_BATCH_SIG, "0xf92fc4d4"),
            (FINAL_SETTLE_SIG, "0xd74f1bd3"),
            (FINAL_EXIT_SIG, "0x98f16b08"),
        ] {
            assert_eq!(selector(sig), expected, "{sig}");
        }
    }

    /// Discovery reads the open set, not logs; the event changed shape (staker and
    /// open batch count instead of a deadline), so any log consumer must use this.
    #[test]
    fn inclusion_challenged_topic_is_the_new_event_shape() {
        use sha3::{Digest as _, Keccak256};
        assert_eq!(
            crate::hex0x(&Keccak256::digest(
                b"InclusionChallenged(bytes32,address,address,uint256)"
            )),
            "0x16a25995582a5d2e093efeec773455d64ba9532b4523ad1036ccf5ed3c9add0d"
        );
    }

    #[test]
    fn answer_lane_has_its_own_key_and_nonce_and_falls_back_to_the_sequencer() {
        let mut l1 = L1::test_reader("http://127.0.0.1:9".into());
        l1.keystore_path = "/seq/ks".into();
        l1.password_file = "/seq/pw".into();
        let lane = l1.answer_lane();
        assert_eq!(
            (lane.keystore_path, lane.password_file),
            ("/seq/ks", "/seq/pw")
        );
        assert!(lane.address.is_none());
        assert!(std::ptr::eq(lane.nonce, &*l1.nonce));
        l1.answer = Some(AnswerLane {
            keystore_path: "/ans/ks".into(),
            password_file: "/ans/pw".into(),
            address: crate::hex0x(&[0x44; 20]),
            nonce: std::sync::Arc::new(std::sync::Mutex::new(Some(9))),
        });
        *l1.nonce.lock().unwrap() = Some(5);
        let lane = l1.answer_lane();
        assert_eq!(
            (lane.keystore_path, lane.password_file),
            ("/ans/ks", "/ans/pw")
        );
        assert_eq!(lane.address, Some(crate::hex0x(&[0x44; 20]).as_str()));
        assert!(!std::ptr::eq(lane.nonce, &*l1.nonce));
        assert_eq!(*lane.nonce.lock().unwrap(), Some(9));
        // Register, settle and bond sends stay on the sequencer lane.
        let seq = l1.sequencer_lane();
        assert_eq!(seq.keystore_path, "/seq/ks");
        assert_eq!(*seq.nonce.lock().unwrap(), Some(5));
    }

    #[test]
    fn answer_challenges_arguments_are_parallel_cast_arrays() {
        let answers = [
            ChallengeAnswer {
                order_hash: [0x11; 32],
                by_rejection: false,
                proof: vec![[0x21; 32], [0x22; 32]],
            },
            ChallengeAnswer {
                order_hash: [0x12; 32],
                by_rejection: true,
                proof: vec![],
            },
        ];
        let args = answer_challenges_args(9, &answers);
        let (a, b, p1, p2) = (
            hex0x32(&[0x11; 32]),
            hex0x32(&[0x12; 32]),
            hex0x32(&[0x21; 32]),
            hex0x32(&[0x22; 32]),
        );
        assert_eq!(
            args,
            vec![
                "9".to_string(),
                format!("[{a},{b}]"),
                "[false,true]".to_string(),
                format!("[[{p1},{p2}],[]]"),
            ]
        );
    }

    #[test]
    fn bond_plan_targets_capacity_and_pauses_after_unacknowledged_slashes() {
        // No TVL yet: the TVL target still posts capacity (no early return at 0).
        assert_eq!(
            bond_plan(0, 0, 0, 0, 50_000_000_000),
            BondPlan::TopUp {
                amount: 50_000_000_000,
                target: 50_000_000_000
            }
        );
        // Twice requiredBond once that exceeds the TVL target.
        assert_eq!(
            bond_plan(40, 70, 0, 0, 50),
            BondPlan::TopUp {
                amount: 10,
                target: 80
            }
        );
        assert_eq!(
            bond_plan(40, 80, 0, 0, 50),
            BondPlan::Covered { target: 80 }
        );
        assert_eq!(bond_plan(0, 0, 0, 0, 0), BondPlan::Covered { target: 0 });
        // A newer slash pauses even when the bond is short; an acknowledged one does not.
        assert_eq!(
            bond_plan(40, 0, 2, 1, 50),
            BondPlan::Paused {
                slash_count: 2,
                acknowledged: 1
            }
        );
        assert_eq!(
            bond_plan(40, 0, 2, 2, 50),
            BondPlan::TopUp {
                amount: 80,
                target: 80
            }
        );
        assert_eq!(
            bond_plan(u128::MAX, 0, 0, 0, 0),
            BondPlan::TopUp {
                amount: u128::MAX,
                target: u128::MAX
            }
        );
    }

    #[test]
    fn tvl_target_bond_rounds_up_and_policy_env_is_strict() {
        assert_eq!(tvl_target_bond(1_000_000_000_000), Some(50_000_000_000));
        assert_eq!(tvl_target_bond(1), Some(1));
        assert_eq!(tvl_target_bond(20), Some(1));
        assert_eq!(tvl_target_bond(21), Some(2));
        assert_eq!(tvl_target_bond(0), Some(0));
        assert_eq!(tvl_target_bond(u128::MAX), None);
        let p = bond_policy_from_values(Some("1000000000000"), Some("3")).unwrap();
        assert_eq!(p.target_tvl_bond, 50_000_000_000);
        assert_eq!(
            p.acknowledged_slashes
                .load(std::sync::atomic::Ordering::SeqCst),
            3
        );
        let p = bond_policy_from_values(None, None).unwrap();
        assert_eq!(p.target_tvl_bond, 0);
        for (tvl, acked) in [
            (Some(""), None),
            (Some("1e12"), None),
            (Some("-1"), None),
            (Some(" 1"), None),
            (Some("340282366920938463463374607431768211455"), None),
            (None, Some("x")),
            (None, Some("18446744073709551616")),
        ] {
            assert!(
                bond_policy_from_values(tvl, acked).is_err(),
                "{tvl:?} {acked:?}"
            );
        }
    }

    #[test]
    fn a_slash_acknowledgement_must_name_the_exact_observed_count() {
        use std::sync::atomic::Ordering::SeqCst;
        let policy = BondPolicy {
            target_tvl_bond: 50,
            ..Default::default()
        };
        // Two slashes happened; top-ups are paused.
        let paused = |p: &BondPolicy| {
            matches!(
                bond_plan(
                    40,
                    0,
                    2,
                    p.acknowledged_slashes.load(SeqCst),
                    p.target_tvl_bond
                ),
                BondPlan::Paused { .. }
            )
        };
        assert!(paused(&policy));
        // A stale count would leave the second slash unseen; a future one would
        // cover a slash that has not happened yet. Neither changes anything.
        for requested in [0, 1, 3, u64::MAX] {
            let error = policy.acknowledge(2, requested).unwrap_err();
            assert!(error.contains("slashCount() is 2"), "{error}");
            assert_eq!(policy.acknowledged_slashes.load(SeqCst), 0);
            assert!(paused(&policy));
        }
        assert_eq!(policy.acknowledge(2, 2), Ok(2));
        assert_eq!(policy.acknowledged_slashes.load(SeqCst), 2);
        assert!(!paused(&policy), "top-ups resume");
        // The acknowledged count never goes down.
        assert_eq!(policy.acknowledge(1, 1), Ok(1));
        assert_eq!(policy.acknowledged_slashes.load(SeqCst), 2);
        // A later slash pauses again until it is acknowledged in turn.
        assert!(matches!(
            bond_plan(40, 0, 3, policy.acknowledged_slashes.load(SeqCst), 50),
            BondPlan::Paused {
                slash_count: 3,
                acknowledged: 2
            }
        ));
    }

    #[test]
    fn bond_top_up_runs_one_at_a_time() {
        let flag = std::sync::atomic::AtomicBool::new(false);
        let first = InFlight::take(&flag).expect("first top-up");
        assert!(InFlight::take(&flag).is_none(), "second waits");
        drop(first);
        assert!(InFlight::take(&flag).is_some(), "released on drop");
    }

    #[test]
    fn stake_sweeps_run_once_per_request_and_a_failure_stays_requested() {
        use std::sync::atomic::Ordering::SeqCst;
        // Without an answer key there is nothing to sweep and nothing is read.
        let mut l1 = L1::test_reader("http://127.0.0.1:9".into());
        assert_eq!(l1.sweep_requested_stake_refunds(), Ok(None));
        assert!(
            !l1.stake_sweep.load(SeqCst),
            "the start-up request was taken"
        );
        l1.clone().request_stake_sweep();
        assert!(l1.stake_sweep.load(SeqCst), "requests are shared by clones");
        // A sweep that cannot complete is asked for again on the next tick.
        l1.answer = Some(AnswerLane {
            keystore_path: String::new(),
            password_file: String::new(),
            address: crate::hex0x(&[0x66; 20]),
            nonce: Default::default(),
        });
        assert!(l1.sweep_requested_stake_refunds().is_err());
        assert!(l1.stake_sweep.load(SeqCst));
        assert!(take_request(&l1.stake_sweep));
        assert_eq!(
            l1.sweep_requested_stake_refunds(),
            Ok(None),
            "not requested"
        );
    }

    #[test]
    fn answer_key_paths_are_paired_and_the_password_file_private() {
        assert_eq!(answer_paths_from_values(None, None).unwrap(), None);
        assert_eq!(answer_paths_from_values(Some(""), Some("")).unwrap(), None);
        let dir = std::env::temp_dir().join(format!("answer-key-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let ks = dir.join("ks");
        let pw = dir.join("pw");
        std::fs::write(&ks, "{}").unwrap();
        std::fs::write(&pw, "secret").unwrap();
        let (ks_s, pw_s) = (ks.to_str().unwrap(), pw.to_str().unwrap());
        assert!(answer_paths_from_values(Some(ks_s), None).is_err());
        assert!(answer_paths_from_values(None, Some(pw_s)).is_err());
        assert!(answer_paths_from_values(Some("/nonexistent/ks"), Some(pw_s)).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o644)).unwrap();
            let error = answer_paths_from_values(Some(ks_s), Some(pw_s)).unwrap_err();
            assert!(error.contains("group or others"));
            std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            answer_paths_from_values(Some(ks_s), Some(pw_s)).unwrap(),
            Some((ks_s.to_string(), pw_s.to_string()))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn posture() -> BootPosture {
        BootPosture {
            abi_version: ABI_VERSION,
            verifier: [0x11; 20],
            proof_version: 2,
            vault: [0x22; 20],
            vault_settlement: [0xaa; 20],
            anchor_timeout_ms: Some(3_600_000),
            liveness_timeout_blocks: 43_200,
            consumed_deposit_count: 5,
            current_root: [3; 32],
            enclave_signer: [0x55; 20],
            sequencer: [0x44; 20],
        }
    }
    fn expectation() -> BootExpectation {
        BootExpectation {
            settlement: [0xaa; 20],
            vault: Some([0x22; 20]),
            clock_verifier: Some([0x11; 20]),
            enclave_signer: [0x55; 20],
            sequencer: [0x44; 20],
            min_anchor_timeout_ms: min_anchor_timeout_ms(900),
            last_settled_root: [3; 32],
            live_root: [3; 32],
            local_consumed: 5,
            permit_ttl_secs: 1800,
        }
    }

    #[test]
    fn boot_handshake_accepts_the_launch_stack_and_refuses_each_mismatch() {
        // (2 * 1200 + 900 + 300) s: the launch anchor timeout exactly.
        assert_eq!(min_anchor_timeout_ms(900), 3_600_000);
        check_boot_posture(&posture(), &expectation()).unwrap();
        let p = posture();
        let e = expectation();
        let cases: Vec<(BootPosture, BootExpectation, &str)> = vec![
            (
                BootPosture {
                    abi_version: 2,
                    ..p.clone()
                },
                e.clone(),
                "ABI_VERSION",
            ),
            // An enclave seed the settlement was not deployed with: every receipt's
            // challenge authorization would be refused on L1.
            (
                p.clone(),
                BootExpectation {
                    enclave_signer: [0x56; 20],
                    ..e.clone()
                },
                "enclaveSigner()",
            ),
            (
                BootPosture {
                    enclave_signer: [0x57; 20],
                    ..p.clone()
                },
                e.clone(),
                "ENCLAVE_SEED",
            ),
            (
                p.clone(),
                BootExpectation {
                    sequencer: [0x45; 20],
                    ..e.clone()
                },
                "sequencer()",
            ),
            (
                BootPosture {
                    proof_version: 1,
                    ..p.clone()
                },
                e.clone(),
                "proofVersion",
            ),
            (
                p.clone(),
                BootExpectation {
                    clock_verifier: None,
                    ..e.clone()
                },
                "CLOCK_BOUND_VERIFIER",
            ),
            (
                p.clone(),
                BootExpectation {
                    clock_verifier: Some([0x12; 20]),
                    ..e.clone()
                },
                "verifier()",
            ),
            (
                p.clone(),
                BootExpectation {
                    vault: None,
                    ..e.clone()
                },
                "L1_VAULT",
            ),
            (
                p.clone(),
                BootExpectation {
                    vault: Some([0x23; 20]),
                    ..e.clone()
                },
                "vault()",
            ),
            (
                BootPosture {
                    vault_settlement: [0xab; 20],
                    ..p.clone()
                },
                e.clone(),
                "paired",
            ),
            (
                BootPosture {
                    anchor_timeout_ms: Some(3_599_999),
                    ..p.clone()
                },
                e.clone(),
                "anchorTimeoutMs",
            ),
            (
                BootPosture {
                    anchor_timeout_ms: None,
                    ..p.clone()
                },
                e.clone(),
                "anchorTimeoutMs",
            ),
            (
                p.clone(),
                BootExpectation {
                    local_consumed: 6,
                    ..e.clone()
                },
                "consumed",
            ),
            // 24 h of 2 s blocks allows a permit of at most 3 h.
            (
                p.clone(),
                BootExpectation {
                    permit_ttl_secs: 10_801,
                    ..e.clone()
                },
                "DEPOSIT_PERMIT_TTL_SECS",
            ),
            (
                BootPosture {
                    liveness_timeout_blocks: 7_199,
                    ..p.clone()
                },
                e.clone(),
                "DEPOSIT_PERMIT_TTL_SECS",
            ),
            (
                p.clone(),
                BootExpectation {
                    local_consumed: 4,
                    live_root: [4; 32],
                    ..e.clone()
                },
                "consumed",
            ),
        ];
        for (p, e, reason) in cases {
            let error = check_boot_posture(&p, &e).unwrap_err();
            assert!(error.contains(reason), "{reason}: {error}");
        }
        // The limit itself is allowed: 10,800 s of a 86,400 s window, and the
        // launch TTL at the 7,200-block floor.
        check_boot_posture(
            &posture(),
            &BootExpectation {
                permit_ttl_secs: 10_800,
                ..expectation()
            },
        )
        .unwrap();
        check_boot_posture(
            &BootPosture {
                liveness_timeout_blocks: 7_200,
                ..posture()
            },
            &expectation(),
        )
        .unwrap();
        // Unsettled live credits may only add to the settled count.
        check_boot_posture(
            &posture(),
            &BootExpectation {
                local_consumed: 6,
                live_root: [4; 32],
                ..expectation()
            },
        )
        .unwrap();
        // A root mismatch is left to the continuity check.
        check_boot_posture(
            &posture(),
            &BootExpectation {
                local_consumed: 0,
                last_settled_root: [9; 32],
                ..expectation()
            },
        )
        .unwrap();
    }

    /// Byte-safety regression (pre-merge hygiene): non-ASCII input to the L1 hex
    /// parsers must fail CLEANLY. A 2-byte UTF-8 char at an odd byte offset used to
    /// make the old `&str`-slice loops panic mid-codepoint; the keystore key comes
    /// from an env var and the topic/amount parsers eat external RPC data.
    #[test]
    fn l1_hex_parsers_reject_non_ascii_without_panic() {
        // 64 BYTES with é straddling the first nibble-pair slice boundary.
        let bad_key = format!("aé{}", "a".repeat(61));
        assert!(
            create_keystore(&bad_key).is_err(),
            "bad key hex must be a clean Err"
        );
        // 40-byte topic tail with the same straddle → clean None.
        let bad_topic = format!("aé{}", "a".repeat(37));
        assert_eq!(parse_addr20(&bad_topic), None);
        // amount word: non-ASCII in the low 32 nibbles → clean None.
        let bad_amount = format!("{}aé{}", "0".repeat(33), "0".repeat(29));
        assert_eq!(parse_u256_low128(&bad_amount), None);
        // sane inputs still parse.
        assert_eq!(
            parse_addr20(&format!("0x{}{}", "00".repeat(12), "ab".repeat(20))),
            Some([0xab; 20]),
        );
        assert_eq!(
            parse_u256_low128("0x0de0b6b3a7640000"),
            Some(1_000_000_000_000_000_000)
        );
    }
}

#[cfg(test)]
mod witness_tests;

#[cfg(test)]
mod state_read_tests;
