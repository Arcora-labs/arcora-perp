//! Hash-pinned reads and one authorized registration before proving. No
//! "latest" fallback after an anchor is submitted: finality lag means HOLD.
use super::*;
use crate::deposit_rpc::Rpc;
use perp_core::clock::{ClockContext, TimeBounds};

#[derive(Clone)]
pub(crate) struct ClockConfig {
    pub verifier: [u8; 20],
    pub chain_id: u64,
    pub stop: Option<std::sync::Arc<crate::service_shutdown::Shutdown>>,
    /// The route's program vkey once read; shared by every clone.
    pub program_vkey: std::sync::Arc<std::sync::OnceLock<Digest>>,
    /// The verifier's `clockSkewMs` once read; it is constructor-set, so the
    /// first successful read holds for every clone.
    pub clock_skew_ms: std::sync::Arc<std::sync::OnceLock<u64>>,
}

/// `cell`'s value, or the result of `read`, kept only when it succeeds.
fn cached_once<T: Copy>(
    cell: &std::sync::OnceLock<T>,
    read: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    if let Some(v) = cell.get() {
        return Ok(*v);
    }
    let v = read()?;
    Ok(*cell.get_or_init(|| v))
}
impl ClockConfig {
    pub(crate) fn from_values(
        verifier: Option<&str>,
        chain: Option<&str>,
    ) -> Result<Option<Self>, String> {
        let Some(value) = verifier else {
            return Ok(None);
        };
        let verifier = crate::parse_addr20_hex(value)
            .filter(|a| *a != [0; 20])
            .ok_or("invalid CLOCK_BOUND_VERIFIER")?;
        let chain_id = chain
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .ok_or("clock binding requires a nonzero L1_CHAIN_ID")?;
        Ok(Some(Self {
            verifier,
            chain_id,
            stop: None,
            program_vkey: Default::default(),
            clock_skew_ms: Default::default(),
        }))
    }
    pub(crate) fn from_env() -> Result<Option<Self>, String> {
        let v = match std::env::var("CLOCK_BOUND_VERIFIER") {
            Ok(v) => Some(v),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("invalid CLOCK_BOUND_VERIFIER encoding".into()),
        };
        Self::from_values(v.as_deref(), std::env::var("L1_CHAIN_ID").ok().as_deref())
    }
}
/// `ClockBoundVerifier.cancel(uint64 batchId, uint8 phase, bytes32 expectedReceipt)`.
pub(crate) const CANCEL_ANCHOR_SIG: &str = "cancel(uint64,uint8,bytes32)";
/// Terminal outcomes of waiting for a clock-bound settle whose anchor is gone.
pub(crate) const ANCHOR_CANCELLED: &str =
    "clock anchor was cancelled on L1; its bound proof can never settle";
pub(crate) const ANCHOR_REPLACED: &str =
    "another clock anchor is finalized for this batch and phase; the bound proof can never settle";
/// `RegisterMode::ExistingOnly` found no anchor for the window at the latest block.
pub(crate) const ANCHOR_NOT_REGISTERED: &str = "clock anchor no longer registered; reclassify";
/// The `register` entry point of the clock verifier.
const REGISTER_SIG: &str = "register(uint64,bytes32,bytes32,uint64,uint64,uint64,uint8)";
/// The most a registration is held back from the verifier's skew bound, for the
/// time until it is mined. A tenth of a shorter skew.
const REGISTER_SKEW_MARGIN_MS: u64 = 2_000;
/// A zero-value transfer: the plain-transfer gas, so cast runs no estimate.
const BURN_GAS_LIMIT: &str = "21000";

/// What became of the anchor a proof is bound to, at one block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnchorFate {
    /// The anchor with this receipt is still registered.
    Live,
    /// `cancel` removed it; `cancelledReceipt(receipt)` is set for good.
    Cancelled,
    /// A different receipt is registered for the same batch and phase.
    Replaced,
    /// No anchor is registered and this receipt was not cancelled.
    Absent,
}

/// The receipt inside a clock-tagged proof (`PROOF_MAGIC ‖ receipt ‖ inner`).
pub(crate) fn proof_receipt(proof: &[u8]) -> Option<Digest> {
    proof
        .strip_prefix(perp_core::clock::PROOF_MAGIC)
        .and_then(|body| body.get(..32))
        .and_then(|r| r.try_into().ok())
}

/// The wind-down phase the settlement is in, as `ClockBoundVerifier.phase()` sees it.
fn settlement_phase(r: &CanonicalRead<'_>, settlement: &str) -> Result<u8, String> {
    Ok(
        if !abi_bool(r.word(settlement, "closeOnly()", None)?, "closeOnly")? {
            0
        } else if abi_bool(
            r.word(settlement, "windDownSettled()", None)?,
            "windDownSettled",
        )? {
            2
        } else {
            1
        },
    )
}

/// Read the fate of `receipt`'s anchor for (batch, phase) from one snapshot.
pub(super) fn read_anchor_fate(
    r: &CanonicalRead<'_>,
    verifier: &str,
    batch: u64,
    phase: u8,
    receipt: &Digest,
) -> Result<AnchorFate, String> {
    if abi_bool(
        r.word(verifier, "cancelledReceipt(bytes32)", Some(*receipt))?,
        "cancelledReceipt",
    )? {
        return Ok(AnchorFate::Cancelled);
    }
    let words = r.words_args(
        verifier,
        "anchor(uint64,uint8)",
        &[
            observation::u64_word(batch),
            observation::u64_word(phase as u64),
        ],
        8,
    )?;
    if !abi_bool(words[7], "anchor exists")? {
        return Ok(AnchorFate::Absent);
    }
    Ok(if words[2] == *receipt {
        AnchorFate::Live
    } else {
        AnchorFate::Replaced
    })
}

/// How long the anchor of the settlement's current batch and phase has existed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AnchorAge {
    pub batch: u64,
    pub phase: u8,
    pub age_ms: u64,
    pub timeout_ms: u64,
}
impl AnchorAge {
    /// Older than `anchorTimeoutMs`: an honest proof bound to it should have
    /// settled by now, and its registrant role may cancel it.
    pub(crate) fn stale(&self) -> bool {
        self.age_ms > self.timeout_ms
    }
}

/// The age of the anchor registered for the canonical batch and phase, against
/// the header-bound block time. `None` when no anchor is registered.
pub(super) fn read_anchor_age(
    r: &CanonicalRead<'_>,
    settlement: &str,
    verifier: &str,
) -> Result<Option<AnchorAge>, String> {
    let batch = abi_u64(r.word(settlement, "batchCount()", None)?, "batchCount")?;
    let phase = settlement_phase(r, settlement)?;
    let words = r.words_args(
        verifier,
        "anchor(uint64,uint8)",
        &[
            observation::u64_word(batch),
            observation::u64_word(phase as u64),
        ],
        8,
    )?;
    if !abi_bool(words[7], "anchor exists")? {
        return Ok(None);
    }
    let anchored_at = abi_u64(words[6], "anchoredAtMs")?;
    let timeout_ms = abi_u64(
        r.word(verifier, "anchorTimeoutMs()", None)?,
        "anchorTimeoutMs",
    )?;
    let now_ms = r
        .timestamp()?
        .checked_mul(1000)
        .ok_or("block time overflow")?;
    Ok(Some(AnchorAge {
        batch,
        phase,
        age_ms: now_ms.saturating_sub(anchored_at),
        timeout_ms,
    }))
}

/// Every precondition `cancel` checks, at one latest block: the binding, the
/// caller's role, the canonical batch and phase, the exact receipt, and the
/// timeout against the header-bound block time.
#[allow(clippy::too_many_arguments)]
pub(super) fn check_cancel(
    r: &CanonicalRead<'_>,
    settlement: &str,
    verifier: &[u8; 20],
    caller: &[u8; 20],
    batch: u64,
    phase: u8,
    receipt: &Digest,
) -> Result<(), String> {
    let v = crate::hex0x(verifier);
    let target = crate::parse_addr20_hex(settlement).ok_or("invalid settlement address")?;
    if address(r.word(settlement, "verifier()", None)?)? != *verifier
        || address(r.word(&v, "settlement()", None)?)? != target
    {
        return Err("clock verifier/settlement mismatch".into());
    }
    let role = if phase == 0 {
        "sequencer()"
    } else {
        "governance()"
    };
    if address(r.word(settlement, role, None)?)? != *caller {
        return Err(format!(
            "this key is not the settlement {role} that may cancel phase {phase}"
        ));
    }
    if abi_u64(r.word(settlement, "batchCount()", None)?, "batchCount")? != batch {
        return Err("anchor batch is not the canonical batch".into());
    }
    if settlement_phase(r, settlement)? != phase {
        return Err("anchor phase is not the settlement's phase".into());
    }
    let words = r.words_args(
        &v,
        "anchor(uint64,uint8)",
        &[
            observation::u64_word(batch),
            observation::u64_word(phase as u64),
        ],
        8,
    )?;
    if !abi_bool(words[7], "anchor exists")? || words[2] != *receipt {
        return Err("no registered anchor carries this receipt".into());
    }
    let anchored_at = abi_u64(words[6], "anchoredAtMs")?;
    let timeout = abi_u64(r.word(&v, "anchorTimeoutMs()", None)?, "anchorTimeoutMs")?;
    let now_ms = r
        .timestamp()?
        .checked_mul(1000)
        .ok_or("block time overflow")?;
    if (now_ms as u128) < anchored_at as u128 + timeout as u128 {
        return Err("anchor timeout has not passed at the latest block".into());
    }
    Ok(())
}

/// The clock verifier and the settlement name each other.
fn check_binding(
    r: &CanonicalRead<'_>,
    settlement: &str,
    verifier: &[u8; 20],
) -> Result<(), String> {
    let target = crate::parse_addr20_hex(settlement).ok_or("invalid settlement address")?;
    if address(r.word(settlement, "verifier()", None)?)? != *verifier
        || address(r.word(&crate::hex0x(verifier), "settlement()", None)?)? != target
    {
        return Err("clock verifier/settlement mismatch".into());
    }
    Ok(())
}

/// The dead-intent evidence for a journaled clock intent, all at one block: the
/// settlement's batch, root and close-only flag, the intent's anchor slot, the
/// sequencer's nonce and whether it is past `ceiling`, the header-bound block
/// time and the verifier's `clockSkewMs`. `quiet` is left unset; see
/// [`dead_intent_evidence_from`].
pub(super) fn read_dead_intent_evidence(
    r: &CanonicalRead<'_>,
    settlement: &str,
    verifier: &[u8; 20],
    sequencer: &[u8; 20],
    intent: &crate::rollback_journal::ClockIntent,
    ceiling: super::Ceiling,
) -> Result<crate::rollback_journal::DeadIntentEvidence, String> {
    use crate::rollback_journal::{AnchorSlot, DeadIntentEvidence};
    check_binding(r, settlement, verifier)?;
    let v = crate::hex0x(verifier);
    let batch_count = abi_u64(r.word(settlement, "batchCount()", None)?, "batchCount")?;
    let state_root = r.word(settlement, "currentStateRoot()", None)?;
    let close_only = abi_bool(r.word(settlement, "closeOnly()", None)?, "closeOnly")?;
    let cancelled = match intent.receipt {
        Some(receipt) => abi_bool(
            r.word(&v, "cancelledReceipt(bytes32)", Some(receipt))?,
            "cancelledReceipt",
        )?,
        None => false,
    };
    let slot = if cancelled {
        AnchorSlot::Cancelled
    } else {
        let words = r.words_args(
            &v,
            "anchor(uint64,uint8)",
            &[
                observation::u64_word(intent.batch),
                observation::u64_word(intent.phase as u64),
            ],
            8,
        )?;
        let ours = match intent.receipt {
            Some(receipt) => words[2] == receipt,
            None => words[0] == intent.prev_root && words[1] == intent.base,
        };
        if !abi_bool(words[7], "anchor exists")? {
            AnchorSlot::Empty
        } else if ours {
            AnchorSlot::Matching
        } else {
            AnchorSlot::Different
        }
    };
    let nonce = r.nonce(sequencer)?;
    let clock_skew_ms = read_clock_skew(r, verifier)?;
    Ok(DeadIntentEvidence {
        block: r.height(),
        batch_count,
        state_root,
        close_only,
        slot,
        nonce,
        fence_passed: ceiling.passed_by(nonce),
        quiet: false,
        block_time_ms: r.timestamp().ok().and_then(|s| s.checked_mul(1000)),
        clock_skew_ms,
    })
}

/// Whether no sequencer-key transaction is visible as pending: on every
/// endpoint, the sequencer's latest and pending nonces equal `finalized`. A
/// failed or malformed read is not quiet.
pub(super) fn nonces_quiet(endpoints: &[&dyn Rpc], sequencer: &[u8; 20], finalized: u64) -> bool {
    let account = serde_json::json!(crate::hex0x(sequencer));
    endpoints.iter().all(|rpc| {
        ["latest", "pending"].into_iter().all(|tag| {
            rpc.call(
                "eth_getTransactionCount",
                vec![account.clone(), serde_json::json!(tag)],
            )
            .and_then(|v| observation::quantity(&v))
            .is_ok_and(|n| n == finalized)
        })
    })
}

/// The dead-intent evidence on `primary`, with `witness` agreeing when it is
/// configured: one finalized read ([`read_dead_intent_evidence`]), then, right
/// after it, the quiet-nonce read on every endpoint ([`nonces_quiet`]).
#[allow(clippy::too_many_arguments)] // the endpoints and the intent's whole identity
pub(super) fn dead_intent_evidence_from(
    primary: &dyn Rpc,
    witness: Option<&dyn Rpc>,
    expected_chain: Option<u64>,
    settlement: &str,
    verifier: &[u8; 20],
    sequencer: &[u8; 20],
    intent: &crate::rollback_journal::ClockIntent,
    ceiling: super::Ceiling,
) -> Result<crate::rollback_journal::DeadIntentEvidence, String> {
    let r = CanonicalRead::with_policy(
        primary,
        witness,
        expected_chain,
        observation::AnchorPolicy::Finalized,
    )?;
    let mut evidence =
        read_dead_intent_evidence(&r, settlement, verifier, sequencer, intent, ceiling)?;
    r.finish()?;
    let endpoints: Vec<&dyn Rpc> = std::iter::once(primary).chain(witness).collect();
    evidence.quiet = nonces_quiet(&endpoints, sequencer, evidence.nonce);
    Ok(evidence)
}

/// The verifier's `clockSkewMs` (constructor-set).
fn read_clock_skew(r: &CanonicalRead<'_>, verifier: &[u8; 20]) -> Result<u64, String> {
    abi_u64(
        r.word(&crate::hex0x(verifier), "clockSkewMs()", None)?,
        "clockSkewMs",
    )
}

/// A timed window registers only while `lastMs + clockSkewMs` is not behind the
/// block time it is mined at. The gateway refuses to send once its own clock,
/// plus a margin for the time until the registration is mined, is past that
/// bound, so the refusal comes before a nonce is recorded. A local clock ahead
/// of the chain's can refuse a registration the chain would still accept.
pub(super) fn check_register_skew(last_ms: u64, skew_ms: u64, now_ms: u64) -> Result<(), String> {
    let margin = (skew_ms / 10).min(REGISTER_SKEW_MARGIN_MS);
    if now_ms as u128 + margin as u128 > last_ms as u128 + skew_ms as u128 {
        return Err("timed window is past its registration skew; nothing sent".into());
    }
    Ok(())
}

/// What a registration does once the window's anchor at the latest block is
/// known: return an existing anchor for the caller to validate, or send the
/// registration with `send` and return `None`. `ExistingOnly` never sends, and
/// a timed window is never sent past its registration skew; `clock_skew_ms` is
/// read only for a timed window that would be sent. An error from `send` means
/// nothing was broadcast; a broadcast whose outcome is unknown returns `Ok`.
pub(super) fn register_or_reuse(
    mode: crate::clock_client::RegisterMode,
    existing: Option<ClockContext>,
    bounds: &TimeBounds,
    now_ms: u64,
    clock_skew_ms: impl FnOnce() -> Result<u64, String>,
    send: impl FnOnce() -> Result<(), String>,
) -> Result<Option<ClockContext>, String> {
    if let Some(c) = existing {
        return Ok(Some(c));
    }
    if mode == crate::clock_client::RegisterMode::ExistingOnly {
        return Err(ANCHOR_NOT_REGISTERED.into());
    }
    if bounds.count > 0 {
        check_register_skew(bounds.last_ms, clock_skew_ms()?, now_ms)?;
    }
    send()?;
    Ok(None)
}

/// A recovery settle is broadcast only while its anchor is live at the latest
/// block; anything else asks the caller to classify the window again.
pub(super) fn latest_fate_permits_settle(fate: AnchorFate) -> Result<(), String> {
    match fate {
        AnchorFate::Live => Ok(()),
        AnchorFate::Cancelled => {
            Err("clock anchor cancelled at the latest block; nothing sent; reclassify".into())
        }
        AnchorFate::Replaced => Err(
            "another clock anchor holds this batch at the latest block; nothing sent; reclassify"
                .into(),
        ),
        AnchorFate::Absent => Err(
            "clock anchor no longer registered at the latest block; nothing sent; reclassify"
                .into(),
        ),
    }
}

/// A nonce burn may use `expected` only while it is the sequencer's latest
/// nonce, and the lane's next nonce when the lane knows one.
pub(super) fn check_burn(expected: u64, latest: u64, lane_next: Option<u64>) -> Result<(), String> {
    if latest != expected {
        return Err(format!(
            "the sequencer's latest nonce is {latest}, not {expected}; nothing sent"
        ));
    }
    if let Some(next) = lane_next.filter(|n| *n != expected) {
        return Err(format!(
            "the sequencer lane's next nonce is {next}, not {expected}; nothing sent"
        ));
    }
    Ok(())
}

/// `cast send` for a nonce burn: a zero-value transfer from the sequencer key to
/// itself at `nonce`, with no calldata and the plain-transfer gas limit.
pub(super) fn burn_send_args(
    address: &str,
    nonce: u64,
    keystore: &str,
    password_file: &str,
    rpc: &str,
) -> Vec<String> {
    [
        "send",
        address,
        "--value",
        "0",
        "--gas-limit",
        BURN_GAS_LIMIT,
        "--nonce",
        &nonce.to_string(),
        "--keystore",
        keystore,
        "--password-file",
        password_file,
        "--rpc-url",
        rpc,
        "--json",
    ]
    .map(String::from)
    .into()
}

/// A nonce burn under the caller's lane lock, in order: the checks, the fence
/// record, then the send. `lane_next` follows the send as in `send_on`.
pub(super) fn burn_on(
    expected: u64,
    lane_next: &mut Option<u64>,
    latest: impl FnOnce() -> Result<u64, String>,
    fence: Option<&NonceFence>,
    send: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    check_burn(expected, latest()?, *lane_next)?;
    if let Some(fence) = fence {
        fence.cover(expected)?;
    }
    match send() {
        Ok(tx) => {
            *lane_next = Some(expected + 1);
            Ok(tx)
        }
        Err(e) => {
            *lane_next = None;
            Err(e)
        }
    }
}

/// The registration state that does not depend on the window: the binding is
/// checked, then the settlement's batch count and wind-down phase are returned,
/// all at one block. `RegisterPreconditions::admit` compares a sealed window
/// against them.
pub(super) fn read_register_state(
    r: &CanonicalRead<'_>,
    settlement: &str,
    verifier: &[u8; 20],
) -> Result<(u64, u8), String> {
    check_binding(r, settlement, verifier)?;
    let phase = settlement_phase(r, settlement)?;
    let count = abi_u64(r.word(settlement, "batchCount()", None)?, "batchCount")?;
    Ok((count, phase))
}

/// The program vkey the clock route verifies: `innerVerifier()` is the SP1
/// adapter, or an oracle wrapper whose own `innerVerifier()` is.
pub(super) fn read_program_vkey(
    r: &CanonicalRead<'_>,
    verifier: &[u8; 20],
) -> Result<Digest, String> {
    let inner = address(r.word(&crate::hex0x(verifier), "innerVerifier()", None)?)?;
    let inner_hex = crate::hex0x(&inner);
    let adapter = match r.call_bytes(&inner_hex, "innerVerifier()", &[]) {
        Ok(bytes) if bytes.len() == 32 => {
            let word: Digest = bytes[..]
                .try_into()
                .map_err(|_| "invalid inner verifier word")?;
            crate::hex0x(&address(word)?)
        }
        _ => inner_hex,
    };
    r.word(&adapter, "programVKey()", None)
}

fn address(word: Digest) -> Result<[u8; 20], String> {
    if word[..12] != [0; 12] {
        return Err("invalid clock address word".into());
    }
    word[12..]
        .try_into()
        .map_err(|_| "invalid clock address".into())
}
impl L1 {
    /// A read-only test bridge with a configured clock verifier.
    #[cfg(test)]
    pub(crate) fn test_clocked_reader(rpc: String, verifier: [u8; 20], chain_id: u64) -> Self {
        let mut l1 = Self::test_reader(rpc);
        l1.clock = Some(ClockConfig {
            verifier,
            chain_id,
            stop: None,
            program_vkey: Default::default(),
            clock_skew_ms: Default::default(),
        });
        l1
    }
    pub(crate) fn with_clock_shutdown(
        mut self,
        stop: std::sync::Arc<crate::service_shutdown::Shutdown>,
    ) -> Self {
        if let Some(c) = self.clock.as_mut() {
            c.stop = Some(stop);
        }
        self
    }
    pub(crate) fn clock_stopping(&self) -> bool {
        self.clock_stop()
            .is_some_and(crate::service_shutdown::Shutdown::started)
    }
    fn clock_stop(&self) -> Option<&crate::service_shutdown::Shutdown> {
        self.clock.as_ref().and_then(|c| c.stop.as_deref())
    }
    pub(crate) fn clock_seal_period(&self) -> Result<std::time::Duration, String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        let verifier = crate::hex0x(&cfg.verifier);
        let (window, skew) = self.observe_at(observation::AnchorPolicy::Latest, |r| {
            if address(r.word(&self.settlement, "verifier()", None)?)? != cfg.verifier {
                return Err("clock verifier mismatch".into());
            }
            Ok((
                abi_u64(r.word(&verifier, "maxWindowMs()", None)?, "maxWindowMs")?,
                abi_u64(r.word(&verifier, "clockSkewMs()", None)?, "clockSkewMs")?,
            ))
        })?;
        let millis = (window / 4).min(skew / 4).min(crate::L1_SETTLE_SECS * 1000);
        if millis < 100 {
            return Err("clock timing policy is too narrow for gateway cadence".into());
        }
        Ok(std::time::Duration::from_millis(millis))
    }
    /// `anchorTimeoutMs()` of the configured clock verifier.
    #[allow(dead_code)] // consumed by the stale-anchor alert
    pub(crate) fn anchor_timeout_ms(&self) -> Result<u64, String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        let v = crate::hex0x(&cfg.verifier);
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            abi_u64(r.word(&v, "anchorTimeoutMs()", None)?, "anchorTimeoutMs")
        })
    }
    /// The age of the current batch's anchor at the latest block, for the
    /// stale-anchor alert. `None` without a registered anchor.
    pub(crate) fn anchor_age(&self) -> Result<Option<AnchorAge>, String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        let v = crate::hex0x(&cfg.verifier);
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            read_anchor_age(r, &self.settlement, &v)
        })
    }
    /// `cancelledReceipt(receipt)` at the finalized block.
    #[allow(dead_code)] // consumed by the dead-intent classifier
    pub(crate) fn cancelled_receipt(&self, receipt: &Digest) -> Result<bool, String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        let v = crate::hex0x(&cfg.verifier);
        self.observe(|r| {
            abi_bool(
                r.word(&v, "cancelledReceipt(bytes32)", Some(*receipt))?,
                "cancelledReceipt",
            )
        })
    }
    /// The finalized fate of the anchor `receipt` names for (batch, phase).
    pub(crate) fn anchor_fate(
        &self,
        batch: u64,
        phase: u8,
        receipt: &Digest,
    ) -> Result<AnchorFate, String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        let v = crate::hex0x(&cfg.verifier);
        self.observe(|r| read_anchor_fate(r, &v, batch, phase, receipt))
    }
    /// Every precondition of `cancel` at the latest block, for this gateway's key.
    pub(crate) fn check_cancel_anchor(
        &self,
        batch_id: u64,
        phase: u8,
        receipt: Digest,
    ) -> Result<(), String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        if phase > 2 {
            return Err("invalid wind-down phase".into());
        }
        let caller = crate::parse_addr20_hex(&self.sequencer_address()?)
            .ok_or("invalid sequencer address")?;
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            check_cancel(
                r,
                &self.settlement,
                &cfg.verifier,
                &caller,
                batch_id,
                phase,
                &receipt,
            )
        })
    }
    /// The dead-intent evidence for `intent` at the finalized block, with the
    /// nonce fence at `ceiling` and the quiet-nonce read on `L1_RPC` and, when it
    /// is set, `L1_RPC_WITNESS`.
    pub(crate) fn dead_intent_evidence(
        &self,
        intent: &crate::rollback_journal::ClockIntent,
        ceiling: super::Ceiling,
    ) -> Result<crate::rollback_journal::DeadIntentEvidence, String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        let sequencer = crate::parse_addr20_hex(&self.sequencer_address()?)
            .ok_or("invalid sequencer address")?;
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
        let evidence = dead_intent_evidence_from(
            &primary,
            witness.as_ref().map(|r| r as &dyn Rpc),
            self.witness_chain,
            &self.settlement,
            &cfg.verifier,
            &sequencer,
            intent,
            ceiling,
        )?;
        let _ = cfg.clock_skew_ms.set(evidence.clock_skew_ms);
        Ok(evidence)
    }
    /// The settlement's batch count and wind-down phase at the latest block, with
    /// the clock binding checked at the same block. Until it is cached, the
    /// verifier's `clockSkewMs` is read with them, so that a timed registration
    /// after the seal needs no further read.
    pub(crate) fn clock_register_state(&self) -> Result<(u64, u8), String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        let skew_cached = cfg.clock_skew_ms.get().is_some();
        let (count, phase, skew) = self.observe_at(observation::AnchorPolicy::Latest, |r| {
            let (count, phase) = read_register_state(r, &self.settlement, &cfg.verifier)?;
            let skew = if skew_cached {
                None
            } else {
                Some(read_clock_skew(r, &cfg.verifier)?)
            };
            Ok((count, phase, skew))
        })?;
        if let Some(skew) = skew {
            let _ = cfg.clock_skew_ms.set(skew);
        }
        Ok((count, phase))
    }
    /// The verifier's `clockSkewMs`. It is constructor-set, so the first
    /// successful read is kept for every clone of this bridge.
    pub(crate) fn clock_skew_ms(&self) -> Result<u64, String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        cached_once(&cfg.clock_skew_ms, || {
            self.observe_at(observation::AnchorPolicy::Latest, |r| {
                read_clock_skew(r, &cfg.verifier)
            })
        })
    }
    /// The terms of `triggerCloseOnly` at the latest block: the settlement's last
    /// progress and liveness timeout, and the landing block of the oldest
    /// deposit no settled batch consumed. While a clock window is recovering,
    /// they tell how long the settlement can wait for it.
    pub(crate) fn close_only_budget(
        &self,
    ) -> Result<crate::clock_recovery::CloseOnlyBudget, String> {
        let s = &self.settlement;
        let vault = self.vault.as_ref().ok_or("L1_VAULT not set")?;
        self.observe_at(observation::AnchorPolicy::Latest, |r| {
            let consumed = abi_u64(
                r.word(s, "consumedDepositCount()", None)?,
                "consumedDepositCount",
            )?;
            let deposits = abi_u64(r.word(vault, "depositCount()", None)?, "depositCount")?;
            let oldest_unconsumed_deposit_block = if deposits > consumed {
                Some(abi_u64(
                    r.word(
                        vault,
                        "depositBlock(uint64)",
                        Some(observation::u64_word(consumed)),
                    )?,
                    "depositBlock",
                )?)
            } else {
                None
            };
            Ok(crate::clock_recovery::CloseOnlyBudget {
                head: r.height(),
                last_progress_block: abi_u64(
                    r.word(s, "lastProgressBlock()", None)?,
                    "lastProgressBlock",
                )?,
                liveness_timeout_blocks: abi_u64(
                    r.word(s, "livenessTimeoutBlocks()", None)?,
                    "livenessTimeoutBlocks",
                )?,
                oldest_unconsumed_deposit_block,
                close_only: abi_bool(r.word(s, "closeOnly()", None)?, "closeOnly")?,
            })
        })
    }
    /// Immediately before a recovery settle: the anchor `receipt` names for
    /// (batch, phase) must still be registered, and the receipt not cancelled, at
    /// the latest block. Anything else, a failed read included, sends nothing.
    pub(crate) fn clock_anchor_live_at_latest(
        &self,
        batch: u64,
        phase: u8,
        receipt: &Digest,
    ) -> Result<(), String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        let v = crate::hex0x(&cfg.verifier);
        let fate = self
            .observe_at(observation::AnchorPolicy::Latest, |r| {
                read_anchor_fate(r, &v, batch, phase, receipt)
            })
            .map_err(|e| {
                format!("the latest anchor read failed ({e}); nothing sent; reclassify")
            })?;
        latest_fate_permits_settle(fate)
    }
    /// Use the sequencer's unused nonce `expected` with a zero-value transfer to
    /// itself, so that a nonce recorded for a send that was never broadcast is
    /// used. It runs under the sequencer lane's nonce lock and sends nothing
    /// unless the latest nonce, and the lane's next nonce when it is known, are
    /// `expected`. The fence records `expected` before the broadcast, like every
    /// sequencer-key send. With its explicit gas limit cast runs no estimate. It
    /// touches no contract.
    pub(crate) fn burn_sequencer_nonce(&self, expected: u64) -> Result<String, String> {
        let lane = self.sequencer_lane();
        let mut lane_next = lane.nonce.lock().map_err(|_| "nonce lock poisoned")?;
        let address = self.sequencer_address()?;
        burn_on(
            expected,
            &mut lane_next,
            || self.account_nonce(&address, "latest"),
            self.nonce_fence.get(),
            || {
                if self.clock_stopping() {
                    return Err("nonce burn stopped before broadcast".into());
                }
                let args = burn_send_args(
                    &address,
                    expected,
                    lane.keystore_path,
                    lane.password_file,
                    &self.rpc,
                );
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                self.cast(&refs).map(|out| tx_hash(&out))
            },
        )
    }
    /// The program vkey of the clock verifier route's SP1 adapter. The route is
    /// immutable (the clock verifier's `innerVerifier`, an oracle wrapper's
    /// `innerVerifier` and the adapter's `programVKey` are all constructor-set),
    /// so the first successful read is kept for every clone of this bridge.
    pub(crate) fn clock_program_vkey(&self) -> Result<Digest, String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        cached_once(&cfg.program_vkey, || {
            self.observe_at(observation::AnchorPolicy::Latest, |r| {
                read_program_vkey(r, &cfg.verifier)
            })
        })
    }
    /// Cancel a dead anchor after `anchorTimeoutMs`, as its registrant role (the
    /// sequencer for phase 0, governance for phases 1 and 2). Every precondition
    /// is checked first, so a cancel that would revert is never broadcast. A lost
    /// receipt is ambiguous; confirm with `cancelled_receipt`.
    pub(crate) fn cancel_anchor(
        &self,
        batch_id: u64,
        phase: u8,
        receipt: Digest,
    ) -> Result<String, String> {
        let cfg = self.clock.as_ref().ok_or("clock mode not configured")?;
        self.check_cancel_anchor(batch_id, phase, receipt)?;
        if self.clock_stopping() {
            return Err("clock cancel stopped before broadcast".into());
        }
        let (batch, phase_arg) = (batch_id.to_string(), phase.to_string());
        self.send(
            &crate::hex0x(&cfg.verifier),
            CANCEL_ANCHOR_SIG,
            &[&batch, &phase_arg, &crate::hex32(&receipt)],
        )
    }
    /// Wait until our settle is finalized. Terminal (an error, never a timeout)
    /// once the proof's anchor is cancelled or replaced at the finalized block,
    /// because that proof can then never verify.
    pub(crate) fn wait_clock_settled(
        &self,
        batch: u64,
        out: &crate::prover_client::ProveOutcome,
    ) -> Result<(u64, String, u128), String> {
        let next = batch.checked_add(1).ok_or("clock batch overflow")?;
        let receipt = proof_receipt(&out.proof);
        crate::clock_wait::wait_for(
            crate::clock_wait::FINALITY_BUDGET,
            crate::clock_wait::POLL_INTERVAL,
            self.clock_stop(),
            || {
                let observed = match self.settlement_observation() {
                    Ok(o) => o,
                    Err(_) => return Ok(None),
                };
                if observed.0 == next
                    && observed
                        .1
                        .eq_ignore_ascii_case(&crate::hex32(&out.new_root))
                {
                    return Ok(Some(observed));
                }
                if observed.0 < batch
                    || (observed.0 == batch
                        && observed
                            .1
                            .eq_ignore_ascii_case(&crate::hex32(&out.prev_root)))
                {
                    if let (true, Some(receipt)) = (observed.0 == batch, receipt) {
                        match self.anchor_fate(batch, out.wind_down_phase, &receipt) {
                            Ok(AnchorFate::Cancelled) => return Err(ANCHOR_CANCELLED.into()),
                            Ok(AnchorFate::Replaced) => return Err(ANCHOR_REPLACED.into()),
                            // A failed read or a still-live anchor keeps waiting.
                            _ => {}
                        }
                    }
                    return Ok(None);
                }
                Err("clock settlement diverged from the immutable journal; retain intent".into())
            },
        )
    }
    /// The configuration is immutable for this L1 instance. No late env fallback.
    pub(crate) fn clock_enabled(&self) -> bool {
        self.clock.is_some()
    }
    fn clock_read(
        &self,
        batch: u64,
        phase: u8,
        policy: observation::AnchorPolicy,
    ) -> Result<Option<ClockContext>, String> {
        let cfg = self
            .clock
            .as_ref()
            .ok_or("clock binding is not configured")?;
        let v = crate::hex0x(&cfg.verifier);
        let target =
            crate::parse_addr20_hex(&self.settlement).ok_or("invalid settlement address")?;
        let primary = SettlementReader {
            l1: self,
            endpoint: &self.rpc,
            role: "primary",
        };
        if observation::quantity(&primary.call("eth_chainId", vec![])?)? != cfg.chain_id {
            return Err("clock chain mismatch".into());
        }
        self.observe_at(policy, |r| {
            if address(r.word(&self.settlement, "verifier()", None)?)? != cfg.verifier
                || address(r.word(&v, "settlement()", None)?)? != target
                || abi_u64(r.word(&v, "proofVersion()", None)?, "proofVersion")? != 2
            {
                return Err("clock verifier/settlement/version mismatch".into());
            }
            if abi_u64(
                r.word(&self.settlement, "batchCount()", None)?,
                "batchCount",
            )? != batch
            {
                return Err("clock batch is not the canonical batch".into());
            }
            let actual_phase = settlement_phase(r, &self.settlement)?;
            if phase != actual_phase {
                return Err("clock wind-down phase mismatch".into());
            }
            let words = r.words_args(
                &v,
                "anchor(uint64,uint8)",
                &[
                    observation::u64_word(batch),
                    observation::u64_word(phase as u64),
                ],
                8,
            )?;
            if !abi_bool(words[7], "anchor exists")? {
                return Ok(None);
            }
            if words[0] != r.word(&self.settlement, "currentStateRoot()", None)? {
                return Err("clock previous root mismatch".into());
            }
            let c = ClockContext {
                chain_id: cfg.chain_id,
                verifier: cfg.verifier,
                settlement: target,
                batch_id: batch,
                previous_root: words[0],
                base_commitment: words[1],
                phase,
                first_ms: abi_u64(words[3], "firstMs")?,
                last_ms: abi_u64(words[4], "lastMs")?,
                timed_ops: abi_u64(words[5], "timedOps")?,
                anchored_at_ms: abi_u64(words[6], "anchoredAtMs")?,
                max_window_ms: abi_u64(r.word(&v, "maxWindowMs()", None)?, "maxWindowMs")?,
                clock_skew_ms: abi_u64(r.word(&v, "clockSkewMs()", None)?, "clockSkewMs")?,
            };
            if words[2] != c.receipt() {
                return Err("clock receipt mismatch".into());
            }
            Ok(Some(c))
        })
    }
    /// Register the window's clock bounds, or reuse the anchor that already
    /// carries them, then wait until the anchor is finalized. `ExistingOnly`
    /// never sends, and neither does a timed window past its registration skew
    /// (see [`register_or_reuse`]).
    pub(crate) fn register_clock_with(
        &self,
        w: &sequencer::WindowWitness,
        mode: crate::clock_client::RegisterMode,
    ) -> Result<ClockContext, String> {
        if self.clock_stopping() {
            return Err("clock registration cancelled; retain journal".into());
        }
        let mut post = w.pre_state.clone();
        let roots = perp_core::commitment::derive_roots(&mut post, &w.ops, &w.manifest)
            .map_err(|e| format!("clock replay: {e:?}"))?;
        let b = TimeBounds::derive(&w.ops).map_err(|e| format!("clock bounds: {e:?}"))?;
        let existing = self.clock_read(
            w.batch_id,
            roots.wind_down_phase,
            observation::AnchorPolicy::Latest,
        )?;
        let send = || {
            let cfg = self
                .clock
                .as_ref()
                .ok_or("clock binding is not configured")?;
            let values = [
                w.batch_id.to_string(),
                crate::hex32(&roots.prev_state_root),
                crate::hex32(&roots.commitment::<perp_core::hash::Keccak256>()),
                b.first_ms.to_string(),
                b.last_ms.to_string(),
                b.count.to_string(),
                roots.wind_down_phase.to_string(),
            ];
            let args: Vec<&str> = values.iter().map(String::as_str).collect();
            // Errors are ambiguous: caller retains the pre-registration WAL intent.
            // A lost receipt is ambiguous. Do not submit changed data or roll back;
            // observe finalized state until this SAME registration resolves.
            if self.clock_stopping() {
                return Err("clock registration cancelled before broadcast; retain journal".into());
            }
            let _send_result = self.send(&crate::hex0x(&cfg.verifier), REGISTER_SIG, &args);
            Ok(())
        };
        let reused = register_or_reuse(
            mode,
            existing,
            &b,
            crate::now_ms(),
            || self.clock_skew_ms(),
            send,
        )?;
        if let Some(c) = reused {
            c.validate(w.batch_id, &roots, &w.ops)
                .map_err(|_| "existing clock registration differs")?;
        }
        crate::clock_wait::wait_for(
            crate::clock_wait::FINALITY_BUDGET,
            crate::clock_wait::POLL_INTERVAL,
            self.clock_stop(),
            || {
                // Failed or lagging reads never authorize a proof. No latest fallback.
                let c = match self.clock_read(
                    w.batch_id,
                    roots.wind_down_phase,
                    observation::AnchorPolicy::Finalized,
                ) {
                    Ok(Some(c)) => c,
                    Ok(None) | Err(_) => return Ok(None),
                };
                c.validate(w.batch_id, &roots, &w.ops)
                    .map_err(|_| "finalized clock context differs")?;
                Ok(Some(c))
            },
        )
    }
    /// Recheck the exact receipt before broadcast; strip only the internal envelope.
    pub(crate) fn clock_proof_for_send(
        &self,
        out: &crate::prover_client::ProveOutcome,
    ) -> Result<Vec<u8>, String> {
        let tagged = out.proof.strip_prefix(perp_core::clock::PROOF_MAGIC);
        match (&self.clock, tagged) {
            (None, None) if !out.proof.is_empty() => Ok(out.proof.clone()),
            (Some(_), Some(body)) if body.len() > 32 => {
                let batch = self.batch_count()?;
                let c = self
                    .clock_read(
                        batch,
                        out.wind_down_phase,
                        observation::AnchorPolicy::Finalized,
                    )?
                    .ok_or("finalized clock record missing")?;
                if c.receipt().as_slice() != &body[..32]
                    || c.base_commitment != out.commitment
                    || c.previous_root != out.prev_root
                {
                    return Err("clock receipt changed before broadcast".into());
                }
                Ok(body[32..].to_vec())
            }
            _ => Err("clock proof version/configuration mismatch or empty proof".into()),
        }
    }
}

#[cfg(test)]
mod configuration_tests {
    use super::*;
    #[test]
    fn clock_config_is_explicit_and_never_truthy() {
        assert!(ClockConfig::from_values(None, None).unwrap().is_none());
        let v = crate::hex0x(&[1; 20]);
        assert!(ClockConfig::from_values(Some(&v), Some("84532"))
            .unwrap()
            .is_some());
        for chain in [
            None,
            Some(""),
            Some("0"),
            Some("-1"),
            Some(" 84532"),
            Some("84532 "),
            Some("18446744073709551616"),
        ] {
            assert!(ClockConfig::from_values(Some(&v), chain).is_err());
        }
        for addr in [
            "",
            "0x00",
            "mock",
            "0x0000000000000000000000000000000000000000",
        ] {
            assert!(ClockConfig::from_values(Some(addr), Some("84532")).is_err());
        }
    }
    #[test]
    fn clock_sender_rejects_tagged_proof_when_binding_disabled() {
        let (w, ww) = crate::prover_client::tests_support::sample_window();
        let mut p = crate::prover_client::prepare_unproved(&w, &ww).unwrap();
        let l1 = L1::test_reader("http://127.0.0.1:9".into());
        assert!(l1.clock_proof_for_send(&p.outcome).is_err());
        p.outcome.proof = perp_core::clock::PROOF_MAGIC.to_vec();
        p.outcome.proof.extend([1; 64]);
        assert!(l1.clock_proof_for_send(&p.outcome).is_err());
        p.outcome.proof = vec![1; 32];
        assert_eq!(l1.clock_proof_for_send(&p.outcome).unwrap(), vec![1; 32]);
    }
    #[test]
    fn clock_sender_refuses_untagged_or_truncated_v2_proof_without_rpc() {
        let (w, ww) = crate::prover_client::tests_support::sample_window();
        let mut p = crate::prover_client::prepare_unproved(&w, &ww).unwrap();
        let mut l1 = L1::test_reader("http://127.0.0.1:9".into());
        l1.clock = Some(ClockConfig {
            verifier: [1; 20],
            chain_id: 84532,
            stop: None,
            program_vkey: Default::default(),
            clock_skew_ms: Default::default(),
        });
        p.outcome.proof = vec![1; 32];
        assert!(l1.clock_proof_for_send(&p.outcome).is_err());
        p.outcome.proof = perp_core::clock::PROOF_MAGIC.to_vec();
        p.outcome.proof.extend([1; 32]);
        assert!(l1.clock_proof_for_send(&p.outcome).is_err());
    }
}

#[cfg(test)]
#[path = "clock_rpc_tests.rs"]
mod rpc_tests;

#[cfg(test)]
#[path = "anchor_cancel_tests.rs"]
mod anchor_cancel_tests;

#[cfg(test)]
#[path = "dead_intent_tests.rs"]
mod dead_intent_tests;

#[cfg(test)]
#[path = "send_guard_tests.rs"]
mod send_guard_tests;
