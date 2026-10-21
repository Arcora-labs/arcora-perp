//! The settle loop's recovery of a clock-bound window that did not settle.
//!
//! Once a window's clock intent is journaled, a failed registration, proof or
//! settle no longer stops the settle loop. The window stays sealed and clock
//! admission stays closed, and each poll runs one [`run_step`]: it reads the
//! durable journal again, reads the settlement at one finalized block and
//! carries out what [`decide`] makes of it:
//!
//! - a settle of the window that landed is committed (or, when its commit is
//!   already in memory, only made durable);
//! - a window whose own anchor is registered is settled again from the exact
//!   journal, with a backoff;
//! - a window that can never settle returns to the open window (an untimed
//!   window, or a phase-0 window in close-only) or is voided (a timed phase-0
//!   window, `Gw::live_void_window`);
//! - a window that is not decided yet waits for the chain clock or the nonce
//!   fence. On the fence alone, a sequencer nonce that was recorded for a send
//!   that never reached the chain is used by a bounded burn.
//!
//! Only a state that contradicts the journal, a deterministic error and
//! repeated voids stop the loop.
use crate::clock_admission::Paused;
use crate::l1::{Ceiling, L1Status, L1};
use crate::live_void::{LiveVoidError, LiveVoidOutcome, VoidReport};
use crate::ops_alerts::AlertKind;
use crate::prover_client::{PreparedSettle, ProverClient};
use crate::rollback_journal::{
    classify_dead_intent, dead_intent_action, AnchorSlot, Classified, ClockIntent, DeadBasis,
    DeadIntent, DeadIntentAction, DeadIntentEvidence, OpenedJournal, RollbackJournal,
};
use crate::trading_gate::GateObservation;
use crate::{hex32, rollback_journal, snapshot_now, Digest, Shared};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Nonce burns one pending recovery may attempt, sent or refused.
pub(crate) const MAX_NONCE_BURNS: u8 = 3;
/// Consecutive steps with quiet nonces before a burn.
const QUIET_STEPS_BEFORE_BURN: u8 = 2;
/// Failed settles against a matching anchor before the proof is made again and
/// the operator is alerted.
const RETRY_FAILURES_BEFORE_REPROVE: u32 = 3;

/// A clock window the settle loop is recovering. Runtime only: after a restart
/// boot classifies the journal itself.
pub(crate) struct PendingRecovery {
    pub batch_id: u64,
    pub phase: u8,
    pub since: Instant,
    /// What failed: the registration, proof or settle error.
    pub cause: String,
    /// Withdrawal leaves to check for claims once the window settles.
    pub prune_candidates: Vec<[u8; 32]>,
    /// The trading gate was closed when the window was sealed.
    pub gate_was_closed: bool,
    /// The window's own nonce fence: the recorded ceiling when the window failed,
    /// raised to the recorded ceiling after each settle attempt. While a recovery
    /// is pending only this loop sends a registration or settle for the window,
    /// so later sequencer-key sends made for other reasons cannot hold it back.
    pub ceiling: Ceiling,
    /// Consecutive steps whose nonces were quiet.
    pub quiet_steps: u8,
    /// Nonce burns attempted for the window, sent or refused before a send.
    pub burns: u8,
    pub retry_failures: u32,
    /// The proof was dropped and made again once.
    pub reproved: bool,
    /// Steps taken.
    pub steps: u32,
    /// What the last step waited for or failed with, in full, for the log.
    pub last: String,
    /// The same as the recovery status names it: a wait reason or a settle error
    /// class, never an error message.
    pub last_class: &'static str,
    /// What only the operator can do about the last step's outcome, if anything.
    pub operator_action: Option<&'static str>,
    /// Wall-clock milliseconds when the recovery began.
    pub since_ms: u64,
    /// The window's last timed operation (`lastMs`); `None` for an untimed window
    /// or one whose time bounds do not derive.
    pub last_ms: Option<u64>,
    /// The last successful finalized read and close-only budget read.
    pub last_evidence: Option<DeadIntentEvidence>,
    pub last_budget: Option<CloseOnlyBudget>,
    /// A void applied in memory whose snapshot or journal delete has not
    /// completed: its report, basis and finalized block. The next step finishes
    /// it without deciding again.
    voided: Option<(VoidReport, DeadBasis, u64)>,
}

impl PendingRecovery {
    pub(crate) fn new(
        batch_id: u64,
        phase: u8,
        cause: String,
        prune_candidates: Vec<[u8; 32]>,
        gate_was_closed: bool,
        ceiling: Ceiling,
    ) -> Self {
        Self {
            batch_id,
            phase,
            since: Instant::now(),
            cause,
            prune_candidates,
            gate_was_closed,
            ceiling,
            quiet_steps: 0,
            burns: 0,
            retry_failures: 0,
            reproved: false,
            steps: 0,
            last: String::new(),
            last_class: "the window failed after its clock intent was journaled",
            operator_action: None,
            since_ms: crate::now_ms(),
            last_ms: None,
            last_evidence: None,
            last_budget: None,
            voided: None,
        }
    }

    /// The window's last timed operation, from its operations.
    pub(crate) fn with_ops(mut self, ops: &[perp_core::engine::BatchOp]) -> Self {
        self.last_ms = perp_core::clock::TimeBounds::derive(ops)
            .ok()
            .filter(|b| b.count > 0)
            .map(|b| b.last_ms);
        self
    }

    /// The recovery as `/api/state` shows it.
    pub(crate) fn status(&self) -> RecoveryStatus {
        let e = self.last_evidence.as_ref();
        RecoveryStatus {
            batch_id: self.batch_id,
            phase: self.phase,
            since_ms: self.since_ms,
            steps: self.steps,
            last: self.last_class,
            basis: if self.last_ms.is_some() {
                "chainClock"
            } else {
                "fence"
            },
            fence: e.map(|e| FenceStatus {
                block: e.block,
                ceiling: match self.ceiling {
                    Ceiling::Nonce(n) => CeilingView::Nonce(n),
                    Ceiling::None => CeilingView::Other("none"),
                    Ceiling::Unknown => CeilingView::Other("unknown"),
                },
                finalized_nonce: e.nonce,
                latest_nonce: e.seen_nonces.map(|(latest, _)| latest),
                pending_nonce: e.seen_nonces.map(|(_, pending)| pending),
                quiet: e.quiet,
                passed: self.ceiling.passed_by(e.nonce),
            }),
            chain_clock: self.last_ms.map(|last_ms| ChainClockStatus {
                block_time_ms: e.and_then(|e| e.block_time_ms),
                last_ms,
                skew_ms: e.map(|e| e.clock_skew_ms),
            }),
            burns: self.burns,
            retry_failures: self.retry_failures,
            close_only_budget: self.last_budget.map(|b| BudgetStatus {
                stalled_blocks_left: b.stalled_blocks_left(),
                starved_blocks_left: b.starved_blocks_left(),
            }),
            operator_action: self.operator_action,
        }
    }
}

/// A pending recovery as `/api/state` shows it (`clockRecovery`). Reasons are
/// fixed text; it never carries an error message.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryStatus {
    pub batch_id: u64,
    pub phase: u8,
    pub since_ms: u64,
    pub steps: u32,
    /// The last wait reason or settle error class.
    pub last: &'static str,
    /// What can show that the window is dead: `chainClock` for a window with
    /// timed operations (the quiet nonce fence can too), `fence` otherwise.
    pub basis: &'static str,
    /// The nonce fence at the last finalized read.
    pub fence: Option<FenceStatus>,
    /// For a window with timed operations: the finalized block time against its
    /// last operation time plus `clockSkewMs`.
    pub chain_clock: Option<ChainClockStatus>,
    pub burns: u8,
    pub retry_failures: u32,
    pub close_only_budget: Option<BudgetStatus>,
    pub operator_action: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FenceStatus {
    /// The finalized block of the read.
    pub block: u64,
    /// The window's nonce ceiling: a nonce, `none` (no send recorded) or `unknown`.
    pub ceiling: CeilingView,
    pub finalized_nonce: u64,
    /// The highest latest and pending nonces over the configured endpoints; null
    /// when a read failed. A pending nonce above the finalized one is a pending
    /// sequencer-key transaction; quiet nonces below the ceiling are a recorded
    /// nonce that no transaction used.
    pub latest_nonce: Option<u64>,
    pub pending_nonce: Option<u64>,
    pub quiet: bool,
    /// The finalized nonce is past the ceiling.
    pub passed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub(crate) enum CeilingView {
    Nonce(u64),
    Other(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChainClockStatus {
    pub block_time_ms: Option<u64>,
    pub last_ms: u64,
    pub skew_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetStatus {
    pub stalled_blocks_left: u64,
    pub starved_blocks_left: Option<u64>,
}

/// What the operator can do, by the reason a recovery raised
/// `ClockRecoveryBlocked` (`RecoveryStatus::operator_action`).
mod operator {
    pub(super) const REPLACED: &str = "cancel the other anchor once it is older than \
        anchorTimeoutMs (POST /v1/admin/settlement/cancel-anchor)";
    pub(super) const RETRY_FAILING: &str = "the settle keeps failing against our anchor: fix \
        the prover or RPC, or cancel the anchor once it is older than anchorTimeoutMs, after \
        which the window is voided (timed) or returned to the open window (untimed)";
    pub(super) const DEPOSIT_HALT: &str = "clear the deposit halt, or cancel the anchor once \
        it is older than anchorTimeoutMs";
    pub(super) const BURNS_USED: &str = "the nonce burns are used up: let the pending \
        sequencer-key transaction be mined, or mine any transaction from the sequencer key";
    pub(super) const BUDGET: &str = "less than half of the close-only budget is left: \
        resolve the window before anyone can trigger close-only";
    pub(super) const PENDING_LONG: &str = "the recovery has been pending for many polls: see \
        the [recovery] lines in the gateway log";
    pub(super) const VOID_BREAKER: &str = "repeated live voids: find the delay between a \
        window's last operation and its registration in the gateway log (clock, RPC, disk), \
        then restart";
    pub(super) const STOPPED: &str = "the settle loop stopped and settlement is held: \
        reconcile the window from the gateway log, then restart";
}

/// How long until anyone may put the settlement in close-only
/// (`triggerCloseOnly`), at the latest block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CloseOnlyBudget {
    pub head: u64,
    pub last_progress_block: u64,
    pub liveness_timeout_blocks: u64,
    /// The landing block of the oldest deposit no settled batch consumed.
    pub oldest_unconsumed_deposit_block: Option<u64>,
    pub close_only: bool,
}

impl CloseOnlyBudget {
    fn left_after(&self, since: u64) -> u64 {
        self.liveness_timeout_blocks
            .saturating_add(1)
            .saturating_sub(self.head.saturating_sub(since))
    }
    /// Blocks until close-only may be triggered for lack of progress.
    pub(crate) fn stalled_blocks_left(&self) -> u64 {
        self.left_after(self.last_progress_block)
    }
    /// Blocks until it may be triggered for the oldest unconsumed deposit.
    pub(crate) fn starved_blocks_left(&self) -> Option<u64> {
        self.oldest_unconsumed_deposit_block
            .map(|block| self.left_after(block))
    }
    /// Less than half of the budget is left.
    pub(crate) fn half_spent(&self) -> bool {
        let left = self
            .starved_blocks_left()
            .map_or(self.stalled_blocks_left(), |s| {
                s.min(self.stalled_blocks_left())
            });
        !self.close_only && left.saturating_mul(2) < self.liveness_timeout_blocks
    }
    /// `LivenessLow`'s rule: half the liveness window passed without progress.
    pub(crate) fn liveness_low(&self) -> bool {
        !self.close_only
            && self.head.saturating_sub(self.last_progress_block)
                >= self.liveness_timeout_blocks / 2
    }
}

/// The chain side of a recovery step. [`L1Recovery`] is the production one; the
/// trait lets the loop logic run against a fake chain.
pub(crate) trait RecoveryChain: Send + Sync {
    /// The dead-intent evidence at one finalized block, then the quiet read.
    fn evidence(&self, i: &ClockIntent, ceiling: Ceiling) -> Result<DeadIntentEvidence, String>;
    /// Use an unused sequencer nonce (`L1::burn_sequencer_nonce`).
    fn burn_nonce(&self, expected: u64) -> Result<String, String>;
    /// Settle the exact journal against its existing anchor
    /// (`clock_client::resume_exact_with` in recovery mode).
    fn resume(
        &self,
        j: &mut RollbackJournal,
        path: &Path,
        seed: &[u8; 32],
        reprove: bool,
    ) -> Result<(u64, String, u128), String>;
    /// After a settle landed: the bond, the claimed withdrawal leaves and the
    /// trading-gate observation the commit needs.
    fn corroborate(
        &self,
        batch: u64,
        p: &PreparedSettle,
        prune: &[[u8; 32]],
        gate_closed: bool,
    ) -> Result<(u128, Vec<[u8; 32]>, GateObservation), String>;
    fn close_only_budget(&self) -> Result<CloseOnlyBudget, String>;
    /// The challenge watcher's gate in front of every settle.
    fn settle_permitted(&self) -> Result<(), String>;
    /// The recorded nonce ceiling, every sequencer-key send included.
    fn nonce_ceiling(&self) -> Ceiling;
    /// Stop the process without persisting anything (a void's post-check failed).
    fn fail_stop(&self) -> !;
}

/// The production chain: the L1 bridge and a clock client that never registers.
pub(crate) struct L1Recovery {
    pub l1: L1,
    pub client: Arc<dyn ProverClient>,
}

impl RecoveryChain for L1Recovery {
    fn evidence(&self, i: &ClockIntent, ceiling: Ceiling) -> Result<DeadIntentEvidence, String> {
        self.l1.dead_intent_evidence(i, ceiling)
    }
    fn burn_nonce(&self, expected: u64) -> Result<String, String> {
        self.l1.burn_sequencer_nonce(expected)
    }
    fn resume(
        &self,
        j: &mut RollbackJournal,
        path: &Path,
        seed: &[u8; 32],
        reprove: bool,
    ) -> Result<(u64, String, u128), String> {
        crate::clock_client::resume_exact_with(
            &self.l1,
            self.client.as_ref(),
            j,
            None,
            path,
            seed,
            crate::clock_client::ResumeMode::Recovery { reprove },
        )
    }
    fn corroborate(
        &self,
        batch: u64,
        p: &PreparedSettle,
        prune: &[[u8; 32]],
        gate_closed: bool,
    ) -> Result<(u128, Vec<[u8; 32]>, GateObservation), String> {
        let bond = self.l1.sequencer_bond()?;
        let claimed = self.l1.claimed_many(prune)?;
        let observation = if gate_closed {
            crate::observe_gate(&self.l1, batch, p.outcome.new_root)
        } else {
            GateObservation::Inconclusive
        };
        Ok((bond, claimed, observation))
    }
    fn close_only_budget(&self) -> Result<CloseOnlyBudget, String> {
        self.l1.close_only_budget()
    }
    fn settle_permitted(&self) -> Result<(), String> {
        self.l1.challenge_discovery().settle_permitted(
            Instant::now(),
            Duration::from_secs(3 * crate::L1_SETTLE_SECS),
        )
    }
    fn nonce_ceiling(&self) -> Ceiling {
        self.l1.nonce_ceiling()
    }
    fn fail_stop(&self) -> ! {
        self.l1.cleanup_keystore();
        std::process::exit(1)
    }
}

/// Why a step waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitReason {
    /// The finalized read failed.
    ReadFailed,
    /// Another anchor holds the batch and phase.
    Replaced,
    /// A timed window whose `lastMs + clockSkewMs` the finalized block time has
    /// not passed yet.
    ChainClock,
    /// The finalized nonce has not passed the window's ceiling.
    NonceFence,
    /// A sequencer-key transaction is pending.
    NotQuiet,
    /// The finalized batch count is below the window's batch: the read's
    /// finalized head is behind the settles this gateway already committed.
    FinalizedBehind,
}

impl WaitReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ReadFailed => "settlement read failed",
            Self::Replaced => "another anchor holds this batch; cancel it after anchorTimeoutMs",
            Self::ChainClock => "awaiting the chain clock",
            Self::NonceFence => "awaiting the nonce fence",
            Self::NotQuiet => "sequencer nonces not quiet",
            Self::FinalizedBehind => "the finalized batch count is behind the window",
        }
    }
}

/// What one step does with a pending window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Our settle landed and its commit is already in memory: persist only.
    Stale,
    /// Our settle landed: commit it.
    RollForward,
    ReturnToOpenWindow {
        close_only: bool,
    },
    LiveVoid(DeadIntent, DeadBasis),
    /// Our anchor is registered: settle the exact journal again.
    Retry,
    /// Use this unused sequencer nonce.
    Burn(u64),
    Wait(WaitReason),
    Stop(String),
}

/// Decide what to do with the pending window `j` (its intent `i`) from the
/// evidence at one finalized block. `committed_root` is the gateway's last
/// settled root. Rows in order:
///
/// 1. A failed read waits.
/// 2. Our root at the next batch, already committed in memory, is only
///    persisted.
/// 3. Our root at the next batch is committed.
/// 4. Another root at the next batch stops.
/// 5. At the window's batch, a root other than its pre-state root stops.
/// 6. A phase-0 window in close-only returns to the open window.
/// 7. Our registered anchor is settled again, without the fence.
/// 8. Another anchor waits for the operator's cancel.
/// 9. A contradiction stops.
/// 10. A dead untimed window returns to the open window.
/// 11. A dead timed phase-0 window is voided.
/// 12. A dead timed wind-down window stops (unreachable).
/// 13. An undecided window on the fence basis burns an unused nonce: no chain
///     clock applies, the finalized nonce is at most the window's recorded
///     ceiling, the nonces were quiet on this and the previous step, and fewer
///     than [`MAX_NONCE_BURNS`] were attempted.
/// 14. Otherwise it waits.
/// 15. A batch count below the window's waits: a finalized head that lags (a
///     load-balanced or failed-over RPC) shows nothing new.
/// 16. A batch count beyond the next batch stops.
pub(crate) fn decide(
    j: &RollbackJournal,
    i: &ClockIntent,
    committed_root: Digest,
    e: Result<&DeadIntentEvidence, ()>,
    p: &PendingRecovery,
) -> Decision {
    let Ok(e) = e else {
        return Decision::Wait(WaitReason::ReadFailed);
    };
    let Some(prepared) = j.prepared.as_ref() else {
        return Decision::Stop("the rollback journal holds no prepared clock intent".into());
    };
    let new_root = prepared.outcome.new_root;
    if Some(e.batch_count) == j.batch_id.checked_add(1) {
        return if e.state_root != new_root {
            Decision::Stop(format!(
                "batch {} settled with another state root at finalized block {}",
                j.batch_id, e.block
            ))
        } else if committed_root == new_root {
            Decision::Stale
        } else {
            Decision::RollForward
        };
    }
    if e.batch_count < j.batch_id {
        return Decision::Wait(WaitReason::FinalizedBehind);
    }
    if e.batch_count != j.batch_id {
        return Decision::Stop(format!(
            "the finalized batch count is {}, beyond window {} and the next",
            e.batch_count, j.batch_id
        ));
    }
    if e.state_root != j.witness.pre_state.state_root() {
        return Decision::Stop(format!(
            "at finalized block {} the settled state root is not window {}'s pre-state root",
            e.block, j.batch_id
        ));
    }
    match classify_dead_intent(i, e) {
        Classified::Dead(DeadIntent::CloseOnlyPhaseZero, _) => {
            Decision::ReturnToOpenWindow { close_only: true }
        }
        Classified::Dead(DeadIntent::Replaced, _) => Decision::Wait(WaitReason::Replaced),
        Classified::Dead(dead, basis) => match dead_intent_action(dead, i.phase, i.timed) {
            DeadIntentAction::ReturnToOpenWindow => {
                Decision::ReturnToOpenWindow { close_only: false }
            }
            DeadIntentAction::LiveVoid => Decision::LiveVoid(dead, basis),
            DeadIntentAction::Hold(why) => Decision::Stop(why.into()),
        },
        Classified::Inconsistent(why) => Decision::Stop(why.into()),
        Classified::MaySettle if e.slot == AnchorSlot::Matching => Decision::Retry,
        Classified::MaySettle => {
            let chain_clock = i.last_ms.is_some() && e.block_time_ms.is_some();
            let below_ceiling = matches!(p.ceiling, Ceiling::Nonce(c) if e.nonce <= c);
            if !chain_clock
                && below_ceiling
                && e.quiet
                && p.quiet_steps >= QUIET_STEPS_BEFORE_BURN
                && p.burns < MAX_NONCE_BURNS
            {
                Decision::Burn(e.nonce)
            } else if chain_clock {
                Decision::Wait(WaitReason::ChainClock)
            } else if !e.quiet {
                Decision::Wait(WaitReason::NotQuiet)
            } else {
                Decision::Wait(WaitReason::NonceFence)
            }
        }
    }
}

/// How a failed recovery settle is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryError {
    /// The local journal or configuration can never settle: stop.
    Deterministic,
    /// The chain moved since the classification; nothing was sent: classify again
    /// on the next step.
    Reclassify,
    /// A prove, send or wait failure: retry with a backoff.
    Transient,
}

/// Classify a recovery settle error. A cast send cannot reliably tell a reverted
/// estimate from a transport error, so send failures are told apart by how many
/// there were, not by their text.
pub(crate) fn classify_retry_error(e: &str) -> RetryError {
    const DETERMINISTIC: [&str; 6] = [
        "journal does not match its immutable witness",
        "clock resume requires durable intent",
        "clock resume requires version 2",
        "candidate-bound journal",
        "intent encode",
        "journal encode",
    ];
    if DETERMINISTIC.iter().any(|d| e.contains(d)) {
        RetryError::Deterministic
    } else if e.contains("; reclassify") || e.contains("clock resume batch/root changed") {
        RetryError::Reclassify
    } else {
        RetryError::Transient
    }
}

/// What a step left the loop to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The window is resolved and durable, and admission reopened. `close_only`:
    /// it returned because the settlement is in close-only.
    Resolved { close_only: bool },
    /// Poll again after this delay; admission stays closed.
    Wait(Duration),
    /// The loop stops; settlement is held for the operator.
    Stop,
}

/// Why the journal could not be read again.
enum Reread {
    Wait(String),
    Stop(String),
}

/// The durable journal of window `batch_id`. An I/O error may pass; a missing,
/// unauthenticated, undecodable or foreign journal cannot be decided.
fn reread(path: &Path, seed: &[u8; 32], batch_id: u64) -> Result<RollbackJournal, Reread> {
    let sealed = match crate::snapshot::read_file(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Reread::Stop("the rollback journal is gone".into()))
        }
        Err(e) => {
            return Err(Reread::Wait(format!(
                "the rollback journal read failed: {e}"
            )))
        }
    };
    match rollback_journal::open_versioned(&sealed, seed) {
        Ok(OpenedJournal::Legacy(j)) if j.batch_id == batch_id => Ok(j),
        Ok(OpenedJournal::Legacy(j)) => Err(Reread::Stop(format!(
            "the rollback journal is window {}'s",
            j.batch_id
        ))),
        Ok(OpenedJournal::Candidate { .. }) => Err(Reread::Stop(
            "a candidate-bound journal is not resumed by this loop".into(),
        )),
        Err(e) => Err(Reread::Stop(format!(
            "the rollback journal does not open: {e}"
        ))),
    }
}

/// Whether the journal holds a proof bound to an anchor.
fn has_durable_proof(j: &RollbackJournal) -> bool {
    j.prepared.as_ref().is_some_and(|p| {
        p.outcome.proof.starts_with(perp_core::clock::PROOF_MAGIC)
            && p.outcome.proof.len() > perp_core::clock::PROOF_MAGIC.len() + 32
    })
}

/// Make the resolution durable, then delete the journal and check it is gone.
async fn persist_and_delete(app: &Shared, jpath: &Path) -> Result<(), String> {
    snapshot_now(&app.snapshot_req).await?;
    rollback_journal::delete(jpath);
    match jpath.try_exists() {
        Ok(false) => Ok(()),
        Ok(true) => Err("the rollback journal is still present after its delete".into()),
        Err(e) => Err(format!(
            "the rollback journal delete cannot be checked: {e}"
        )),
    }
}

/// Raise `ClockRecoveryBlocked`: the recovery needs the operator, or time is
/// running out. It clears when the recovery resolves. `action` becomes the
/// status's operator action, unless `weak` and the step already named one.
fn blocked(gw: &crate::Gw, rec: &mut PendingRecovery, why: &str, action: &'static str) {
    blocked_as(gw, rec, why, action, false)
}

fn blocked_as(
    gw: &crate::Gw,
    rec: &mut PendingRecovery,
    why: &str,
    action: &'static str,
    weak: bool,
) {
    eprintln!(
        "[recovery] window {}: operator action needed: {why}",
        rec.batch_id
    );
    gw.ops_alerts.activate(AlertKind::ClockRecoveryBlocked);
    if weak {
        rec.operator_action.get_or_insert(action);
    } else {
        rec.operator_action = Some(action);
    }
}

/// Wait with the settle backoff: the failure counts toward HELD, whose line names
/// the window and no error text. `class` names the reason in the status.
async fn wait(app: &Shared, rec: &mut PendingRecovery, class: &'static str, why: String) -> Step {
    let batch_id = rec.batch_id;
    eprintln!(
        "[recovery] window {batch_id}: waiting ({} polls, {} s): {why}",
        rec.steps,
        rec.since.elapsed().as_secs()
    );
    rec.last = why.clone();
    rec.last_class = class;
    let mut gw = app.gw.lock().await;
    let (action, just_held) =
        gw.settle_breaker_failed(format!("clock window {batch_id} unresolved: {why}"));
    if just_held {
        eprintln!(
            "{}",
            crate::settle_health::held_recovery_alert_message(batch_id, rec.steps)
        );
    }
    if rec.steps >= gw.settle_health.threshold() {
        blocked_as(
            &gw,
            rec,
            &format!("the recovery has been pending for {} polls", rec.steps),
            operator::PENDING_LONG,
            true,
        );
    }
    Step::Wait(action.delay())
}

/// Classify again on the next poll, without a backoff: the chain moved.
fn reclassify(rec: &mut PendingRecovery, class: &'static str, why: String) -> Step {
    eprintln!("[recovery] window {}: {why}", rec.batch_id);
    rec.last = why;
    rec.last_class = class;
    Step::Wait(Duration::ZERO)
}

async fn stop(app: &Shared, rec: &mut PendingRecovery, class: &'static str, why: String) -> Step {
    eprintln!(
        "[recovery] HOLDING: window {} (it failed with: {}): {why}; the settle loop stops \
         until a restart",
        rec.batch_id, rec.cause
    );
    rec.last = why.clone();
    rec.last_class = class;
    rec.operator_action.get_or_insert(operator::STOPPED);
    crate::hold_settlement_for_recovery(
        app,
        format!("clock window {} unresolved: {why}", rec.batch_id),
    )
    .await;
    Step::Stop
}

/// The window is resolved without settling: the replacement starts at the base
/// delay, the recovery alert clears, and admission reopens.
async fn resolved(app: &Shared, admission: &mut Option<Paused>, close_only: bool) -> Step {
    {
        let mut gw = app.gw.lock().await;
        gw.settle_health.reset_backoff();
        gw.ops_alerts.recover(AlertKind::ClockRecoveryBlocked);
    }
    if let Some(p) = admission.as_mut() {
        p.resolved();
    }
    Step::Resolved { close_only }
}

/// Feed the close-only budget into the alerts while the window is pending.
async fn note_budget(
    app: &Shared,
    rec: &mut PendingRecovery,
    budget: &Result<CloseOnlyBudget, String>,
) {
    let Ok(b) = budget else {
        return;
    };
    rec.last_budget = Some(*b);
    let gw = app.gw.lock().await;
    if b.liveness_low() {
        gw.ops_alerts.activate(AlertKind::LivenessLow);
    } else {
        gw.ops_alerts.recover(AlertKind::LivenessLow);
    }
    if b.half_spent() {
        blocked_as(
            &gw,
            rec,
            &format!(
                "less than half of the close-only budget is left ({} blocks without \
                 progress, {:?} for the oldest unconsumed deposit)",
                b.stalled_blocks_left(),
                b.starved_blocks_left()
            ),
            operator::BUDGET,
            true,
        );
    }
}

/// How the recovery status names a step's outcome, besides the wait reasons
/// (`RecoveryStatus::last`).
mod class {
    pub(super) const JOURNAL_READ: &str = "the rollback journal read failed";
    pub(super) const CONTRADICTION: &str = "the chain or the journal contradicts the window";
    pub(super) const BURNED: &str = "an unused sequencer nonce was burned";
    pub(super) const BURN_FAILED: &str = "the nonce burn failed";
    pub(super) const SETTLE_HELD: &str = "the challenge watcher holds the settle";
    pub(super) const DEPOSIT_HALT: &str = "a deposit halt blocks the retry";
    pub(super) const DEPOSIT_READINESS: &str = "deposit readiness is not confirmed";
    pub(super) const RETRY_TRANSIENT: &str = "the settle failed (transient)";
    pub(super) const RETRY_RECLASSIFY: &str = "the chain moved since the decision (reclassify)";
    pub(super) const RETRY_DETERMINISTIC: &str = "the settle failed (deterministic)";
    pub(super) const RETRY_WORKER: &str = "the settle worker failed";
    pub(super) const NOT_CORROBORATED: &str = "the landed settle is not corroborated yet";
    pub(super) const NOT_DURABLE: &str = "the resolution is not durable yet";
    pub(super) const VOID_REFUSED: &str = "the live void was refused";
    pub(super) const VOID_BREAKER: &str = "the void breaker tripped";
}

/// Publish a pending recovery's status on `/api/state`, before its first step.
pub(crate) async fn publish(app: &Shared, rec: &PendingRecovery) {
    app.gw.lock().await.clock_recovery = Some(rec.status());
}

/// One recovery step for the pending window `rec`, with clock admission paused
/// (`admission`) and armed by the seal. See the module documentation. The
/// recovery's status on `/api/state` follows each step, and is cleared once the
/// window is resolved.
pub(crate) async fn run_step(
    app: &Shared,
    chain: &Arc<dyn RecoveryChain>,
    rec: &mut PendingRecovery,
    jpath: &Path,
    seed: &[u8; 32],
    admission: &mut Option<Paused>,
) -> Step {
    rec.operator_action = None;
    let step = step(app, chain, rec, jpath, seed, admission).await;
    app.gw.lock().await.clock_recovery = match step {
        Step::Resolved { .. } => None,
        Step::Wait(_) | Step::Stop => Some(rec.status()),
    };
    step
}

async fn step(
    app: &Shared,
    chain: &Arc<dyn RecoveryChain>,
    rec: &mut PendingRecovery,
    jpath: &Path,
    seed: &[u8; 32],
    admission: &mut Option<Paused>,
) -> Step {
    rec.steps = rec.steps.saturating_add(1);
    // A void applied in memory whose snapshot or journal delete failed. It was
    // decided dead when it was applied, and that is final: finish it without
    // reading or deciding again, so nothing the chain showed since (close-only,
    // a failed read) can skip its notice, its events or the breaker.
    if rec.voided.is_some() {
        return finish_void(app, rec, jpath, admission).await;
    }
    let j = match reread(jpath, seed, rec.batch_id) {
        Ok(j) => j,
        Err(Reread::Wait(why)) => return wait(app, rec, class::JOURNAL_READ, why).await,
        Err(Reread::Stop(why)) => return stop(app, rec, class::CONTRADICTION, why).await,
    };
    let Some(intent) = ClockIntent::of(&j).filter(|i| i.phase == rec.phase) else {
        return stop(
            app,
            rec,
            class::CONTRADICTION,
            format!(
                "the rollback journal holds no phase-{} clock intent",
                rec.phase
            ),
        )
        .await;
    };
    rec.last_ms = intent.last_ms;
    // Held from the read until the decision is carried out: no anchor cancel can
    // be sent in between. One sent before the read and not final yet is caught by
    // the latest-block check in front of a settle.
    let mut in_flight = app.settle_in_flight.lock().await;
    let (evidence, budget) = {
        let (c, ceiling) = (chain.clone(), rec.ceiling);
        tokio::task::spawn_blocking(move || (c.evidence(&intent, ceiling), c.close_only_budget()))
            .await
            .unwrap_or_else(|e| (Err(e.to_string()), Err(e.to_string())))
    };
    rec.quiet_steps = match &evidence {
        Ok(e) if e.quiet => rec.quiet_steps.saturating_add(1),
        _ => 0,
    };
    if let Ok(e) = &evidence {
        rec.last_evidence = Some(*e);
    }
    note_budget(app, rec, &budget).await;
    let committed = app.gw.lock().await.last_settled_root;
    let decision = decide(
        &j,
        &intent,
        committed,
        evidence.as_ref().map_err(|_| ()),
        rec,
    );
    let block = evidence.as_ref().map_or(0, |e| e.block);
    match decision {
        Decision::Wait(reason) => {
            drop(in_flight);
            let why = match (&evidence, reason) {
                (Err(e), _) => format!("{}: {e}", reason.as_str()),
                (Ok(e), WaitReason::ChainClock) => format!(
                    "{} (finalized block {block} at {} ms; the window's last operation \
                     {} ms plus clockSkewMs {} ms)",
                    reason.as_str(),
                    e.block_time_ms.unwrap_or_default(),
                    intent.last_ms.unwrap_or_default(),
                    e.clock_skew_ms
                ),
                (Ok(e), WaitReason::FinalizedBehind) => format!(
                    "{} (finalized batch count {} at block {block}, window {})",
                    reason.as_str(),
                    e.batch_count,
                    rec.batch_id
                ),
                (Ok(e), WaitReason::NonceFence | WaitReason::NotQuiet) => format!(
                    "{} (finalized nonce {} at block {block}, window ceiling {:?}, {} burns)",
                    reason.as_str(),
                    e.nonce,
                    rec.ceiling,
                    rec.burns
                ),
                (Ok(_), _) => reason.as_str().into(),
            };
            {
                let gw = app.gw.lock().await;
                if reason == WaitReason::Replaced {
                    blocked(&gw, rec, reason.as_str(), operator::REPLACED);
                }
                if matches!(reason, WaitReason::NonceFence | WaitReason::NotQuiet)
                    && rec.burns >= MAX_NONCE_BURNS
                {
                    blocked(
                        &gw,
                        rec,
                        "the nonce burns are used up and the fence has not passed",
                        operator::BURNS_USED,
                    );
                }
            }
            wait(app, rec, reason.as_str(), why).await
        }
        Decision::Burn(nonce) => {
            rec.burns = rec.burns.saturating_add(1);
            let c = chain.clone();
            let burned = match tokio::task::spawn_blocking(move || c.burn_nonce(nonce)).await {
                Ok(Ok(tx)) => {
                    println!(
                        "[recovery] window {}: burned unused sequencer nonce {nonce} ({tx})",
                        rec.batch_id
                    );
                    Ok(tx)
                }
                Ok(Err(e)) => Err(e),
                Err(e) => Err(e.to_string()),
            };
            drop(in_flight);
            // Either way the next step classifies the window again.
            match burned {
                Ok(tx) => {
                    rec.last = format!("burned unused sequencer nonce {nonce} ({tx})");
                    rec.last_class = class::BURNED;
                    Step::Wait(Duration::ZERO)
                }
                Err(e) => reclassify(
                    rec,
                    class::BURN_FAILED,
                    format!("the nonce burn at {nonce} failed: {e}"),
                ),
            }
        }
        Decision::Retry => {
            if let Err(e) = chain.settle_permitted() {
                drop(in_flight);
                return wait(
                    app,
                    rec,
                    class::SETTLE_HELD,
                    format!("window settle held: {e}"),
                )
                .await;
            }
            if let Err((class, why)) = deposit_gate(app, rec).await {
                drop(in_flight);
                return wait(app, rec, class, why).await;
            }
            *in_flight = Some((j.batch_id, intent.phase));
            let reprove = rec.retry_failures >= RETRY_FAILURES_BEFORE_REPROVE
                && !rec.reproved
                && has_durable_proof(&j);
            rec.reproved |= reprove;
            let (c, path, seed) = (chain.clone(), jpath.to_path_buf(), *seed);
            let attempt = tokio::task::spawn_blocking(move || {
                let mut j = j;
                let result = c.resume(&mut j, &path, &seed, reprove);
                (j, result)
            })
            .await;
            *in_flight = None;
            drop(in_flight);
            rec.ceiling = chain.nonce_ceiling();
            match attempt {
                Err(join) => {
                    stop(
                        app,
                        rec,
                        class::RETRY_WORKER,
                        format!("the recovery settle worker failed after a possible broadcast: {join}"),
                    )
                    .await
                }
                Ok((j, Ok((bc, root, _))))
                    if Some(bc) == j.batch_id.checked_add(1)
                        && j.prepared.as_ref().is_some_and(|p| {
                            root.eq_ignore_ascii_case(&hex32(&p.outcome.new_root))
                        }) =>
                {
                    commit_landed(app, chain, rec, j, "(recovered: settled in loop)", admission)
                        .await
                }
                Ok((_, Ok((bc, _, _)))) => reclassify(
                    rec,
                    class::RETRY_RECLASSIFY,
                    format!("the recovery settle returned at finalized batch count {bc}; classify again"),
                ),
                Ok((_, Err(e))) => match classify_retry_error(&e) {
                    RetryError::Deterministic => {
                        stop(app, rec, class::RETRY_DETERMINISTIC, e).await
                    }
                    RetryError::Reclassify => reclassify(rec, class::RETRY_RECLASSIFY, e),
                    RetryError::Transient => {
                        rec.retry_failures = rec.retry_failures.saturating_add(1);
                        if rec.retry_failures == RETRY_FAILURES_BEFORE_REPROVE {
                            let gw = app.gw.lock().await;
                            blocked(
                                &gw,
                                rec,
                                "the settle keeps failing against a matching anchor; cancel-anchor \
                                 after anchorTimeoutMs voids (timed) or returns (untimed) the window",
                                operator::RETRY_FAILING,
                            );
                        } else if rec.retry_failures > RETRY_FAILURES_BEFORE_REPROVE {
                            rec.operator_action = Some(operator::RETRY_FAILING);
                        }
                        wait(
                            app,
                            rec,
                            class::RETRY_TRANSIENT,
                            format!("the recovery settle failed: {e}"),
                        )
                        .await
                    }
                },
            }
        }
        Decision::RollForward => {
            drop(in_flight);
            commit_landed(app, chain, rec, j, "(recovered: landed in loop)", admission).await
        }
        Decision::Stale => {
            drop(in_flight);
            if let Err(e) = persist_and_delete(app, jpath).await {
                return wait(
                    app,
                    rec,
                    class::NOT_DURABLE,
                    format!("the committed window is not durable yet: {e}"),
                )
                .await;
            }
            println!(
                "[recovery] window {}: its commit is durable; journal deleted",
                rec.batch_id
            );
            app.gw
                .lock()
                .await
                .ops_alerts
                .recover(AlertKind::ClockRecoveryBlocked);
            if let Some(p) = admission.as_mut() {
                p.resolved();
            }
            Step::Resolved { close_only: false }
        }
        Decision::ReturnToOpenWindow { close_only } => {
            drop(in_flight);
            {
                let mut gw = app.gw.lock().await;
                // A step whose snapshot or delete failed already returned the
                // window; only the seal is undone, and only once.
                if Some(gw.seq.state.next_batch_id) == j.batch_id.checked_add(1) {
                    gw.seq.rollback_window(&j.witness);
                    gw.rollback_window_withdrawals(j.ww.clone());
                }
                if close_only {
                    gw.deposits.l1_close_only = true;
                }
            }
            if let Err(e) = persist_and_delete(app, jpath).await {
                return wait(
                    app,
                    rec,
                    class::NOT_DURABLE,
                    format!("the returned window is not durable yet: {e}"),
                )
                .await;
            }
            println!(
                "[recovery] window {}: the clock intent can never settle{}; nothing on L1 is \
                 undone and its operations are returned to the open window",
                rec.batch_id,
                if close_only { " (close-only)" } else { "" }
            );
            resolved(app, admission, close_only).await
        }
        Decision::LiveVoid(cause, basis) => {
            drop(in_flight);
            let applied = {
                let mut gw = app.gw.lock().await;
                match gw.live_void_window(&j, cause) {
                    Ok(LiveVoidOutcome::Applied(report)) => {
                        gw.note_void_headroom(j.batch_id);
                        Ok(Some(report))
                    }
                    Ok(LiveVoidOutcome::AlreadyVoided) => Ok(None),
                    Err(LiveVoidError::Refused(e)) => Err(e),
                    Err(LiveVoidError::PostCheck(e)) => {
                        // Memory holds a void that must never be persisted: the
                        // snapshot writer needs this lock, so nothing reaches disk.
                        eprintln!(
                            "[recovery] HOLDING: live void post-check failed: {e}; stopping \
                             without persisting it"
                        );
                        chain.fail_stop();
                    }
                }
            };
            match applied {
                Ok(Some(report)) => rec.voided = Some((report, basis, block)),
                Ok(None) => {}
                Err(e) => {
                    return stop(
                        app,
                        rec,
                        class::VOID_REFUSED,
                        format!("live void refused: {e}"),
                    )
                    .await
                }
            }
            finish_void(app, rec, jpath, admission).await
        }
        Decision::Stop(why) => {
            drop(in_flight);
            stop(app, rec, class::CONTRADICTION, why).await
        }
    }
}

/// Make a live void durable, delete its journal, and only then tell users of it
/// and count it toward the void breaker. A snapshot or delete that fails keeps
/// the recovery pending, with the report in `rec.voided`; the next step comes
/// straight back here.
async fn finish_void(
    app: &Shared,
    rec: &mut PendingRecovery,
    jpath: &Path,
    admission: &mut Option<Paused>,
) -> Step {
    if let Err(e) = persist_and_delete(app, jpath).await {
        return wait(
            app,
            rec,
            class::NOT_DURABLE,
            format!("the voided window is not durable yet: {e}"),
        )
        .await;
    }
    // Durable and the journal gone: only now do users hear of it.
    let notice = rec.voided.take().map(|(report, basis, block)| {
        println!(
            "[recovery] VOIDED window {} ({}, basis {basis:?}) at finalized block {block}: {}",
            report.batch_id,
            report.cause_name(),
            report.summary()
        );
        for event in report.account_events() {
            let _ = app.events_tx.send(event);
        }
        report.notice(crate::now_ms())
    });
    if notice.is_none() {
        println!(
            "[recovery] window {}: the snapshot already holds its void; journal deleted",
            rec.batch_id
        );
    }
    {
        let mut gw = app.gw.lock().await;
        if notice.is_some() {
            gw.last_void = notice;
        }
        gw.ops_alerts.activate(AlertKind::WindowVoided);
        if let Some(why) = gw.void_breaker.record(Instant::now()) {
            blocked(
                &gw,
                rec,
                &format!("repeated live voids: {why}"),
                operator::VOID_BREAKER,
            );
            drop(gw);
            return stop(
                app,
                rec,
                class::VOID_BREAKER,
                format!("repeated live voids: {why}; admission stays closed until a restart"),
            )
            .await;
        }
    }
    resolved(app, admission, false).await
}

/// The deposit barrier in front of a recovery settle. While admission is closed
/// ingestion cannot clear it, so its readiness is read once here. A halt blocks
/// the settle until the operator clears it. An error names its status class.
async fn deposit_gate(
    app: &Shared,
    rec: &mut PendingRecovery,
) -> Result<(), (&'static str, String)> {
    if app.gw.lock().await.deposits.check_ready().is_ok() {
        return Ok(());
    }
    let refreshed = crate::deposit_ingestion::refresh_readiness(app).await;
    let gw = app.gw.lock().await;
    if gw.deposits.halt.is_some() {
        let why = "a deposit halt blocks the retry: clear it, or cancel the anchor after \
                   anchorTimeoutMs";
        blocked(&gw, rec, why, operator::DEPOSIT_HALT);
        return Err((class::DEPOSIT_HALT, why.into()));
    }
    refreshed.map_err(|why| (class::DEPOSIT_READINESS, why))
}

/// Our settle of `j` landed: corroborate and commit it, and make the commit
/// durable. A commit whose snapshot fails stays pending; the next step finds it
/// in memory and only persists it.
async fn commit_landed(
    app: &Shared,
    chain: &Arc<dyn RecoveryChain>,
    rec: &mut PendingRecovery,
    j: RollbackJournal,
    last_tx: &str,
    admission: &mut Option<Paused>,
) -> Step {
    let Some(prepared) = j.prepared.clone() else {
        return stop(
            app,
            rec,
            class::CONTRADICTION,
            "the rollback journal holds no prepared outcome".into(),
        )
        .await;
    };
    let corroborated = {
        let (c, batch, p, prune, closed) = (
            chain.clone(),
            j.batch_id,
            prepared.clone(),
            rec.prune_candidates.clone(),
            rec.gate_was_closed,
        );
        tokio::task::spawn_blocking(move || c.corroborate(batch, &p, &prune, closed))
            .await
            .unwrap_or_else(|e| Err(e.to_string()))
    };
    let (bond, claimed, observation) = match corroborated {
        Ok(v) => v,
        Err(e) => {
            return wait(
                app,
                rec,
                class::NOT_CORROBORATED,
                format!("the landed settle is not corroborated yet: {e}"),
            )
            .await
        }
    };
    let status = L1Status {
        settled_root: hex32(&prepared.outcome.new_root),
        batch_count: j.batch_id + 1,
        last_tx: last_tx.into(),
        bond: bond.to_string(),
        withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
    };
    let committed = crate::commit_and_resolve(
        app,
        &j.witness,
        prepared,
        status,
        observation,
        &claimed,
        admission,
    )
    .await;
    if let Err(e) = committed {
        return wait(
            app,
            rec,
            class::NOT_DURABLE,
            format!("the committed window is not durable yet: {e}"),
        )
        .await;
    }
    println!(
        "[recovery] window {}: settled at batch {}; recovery resolved",
        rec.batch_id,
        j.batch_id + 1
    );
    app.gw
        .lock()
        .await
        .ops_alerts
        .recover(AlertKind::ClockRecoveryBlocked);
    Step::Resolved { close_only: false }
}

#[cfg(test)]
#[path = "clock_recovery_tests.rs"]
mod tests;
