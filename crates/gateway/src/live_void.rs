//! Live void of a dead phase-0 window.
//!
//! A sealed phase-0 window whose clock intent can never settle on L1 (its anchor
//! was cancelled, or none exists and none can be created) still holds everything
//! it did off-chain. [`Gw::live_void_window`] discards it, without a restart and
//! without undoing anything on L1, where nothing of it ever landed:
//!
//! - the engine, the window baseline and the window counter return to the
//!   window's pre-state, and the window's ticks are discarded
//!   (`Sequencer::void_window`), so no later settle hardens their fills;
//! - the order records undo the voided fills, and each voided order ends as
//!   cancelled with the reason `WindowVoided`;
//! - every voided order hash is published as `Cancelled` in the open window, so
//!   the replacement window, which settles under the same batch id, answers
//!   their receipts;
//! - each voided deposit is restored as landed and uncredited, with its permit
//!   route and blind, and the deposit cursor is rewound to the block of the last
//!   deposit the pre-state consumed, so ingestion credits it again (with new
//!   notes and commitments);
//! - the note-archive records of the voided deposits' notes are dropped;
//! - an insurance bootstrap the window applied returns to `NotStarted`;
//! - the window's withdrawal leaves stop being pending. No nonce moves back: the
//!   leaf counter and every account's authorization nonce stay ahead, so a
//!   voided withdrawal is requested again with a new signature.
//!
//! Every input is already durable: the rollback journal holds the window's
//! witness and withdrawals, and the post-seal snapshot holds the credits, routes,
//! ticks and order records. Nothing new is persisted. The caller holds the one
//! Gw lock throughout, makes the result durable with one snapshot and deletes the
//! journal only then. Called again on a state that already holds the void (the
//! snapshot was written, the journal delete was not), it recognizes the void and
//! changes nothing.
//!
//! Automatic voids that repeat stop at the [`VoidBreaker`].

use super::*;
use crate::rollback_journal::{DeadIntent, RollbackJournal};
use perp_core::order::RejectReason;
use std::collections::BTreeSet;

/// What [`Gw::live_void_window`] did.
#[derive(Debug)]
pub(crate) enum LiveVoidOutcome {
    /// The window was voided now.
    Applied(VoidReport),
    /// The state already holds this window's void; nothing changed.
    AlreadyVoided,
}

/// What one live void undid.
#[derive(Debug)]
pub(crate) struct VoidReport {
    pub batch_id: u64,
    pub cause: DeadIntent,
    /// Order hashes published as cancelled.
    pub orders: usize,
    /// Fills the voided window applied.
    pub fills_reverted: usize,
    /// The voided withdrawals; none of their leaves is pending any more.
    pub withdrawals: Vec<Withdrawal>,
    /// The ids of the deposits restored for re-ingestion, in order.
    pub deposits: Vec<u64>,
    /// The same ids by the owner of the account each is credited to.
    pub depositors: std::collections::BTreeMap<PubKey, Vec<u64>>,
    /// An insurance bootstrap the window applied returned to `NotStarted`.
    pub bootstrap_restored: bool,
    /// Note-archive records dropped.
    pub archive_dropped: usize,
    /// The window's operation times are not monotonic, so its time bounds do
    /// not derive and it could never have registered.
    pub underivable: bool,
    /// One `execution` event per account order record the void changed, tagged
    /// with its owner like the tick's events. The caller sends them once the
    /// void is durable.
    pub order_events: Vec<String>,
}

/// Two automatic voids without a settled timed window between them, or three
/// within an hour, trip the breaker.
const VOID_BREAKER_CONSECUTIVE: u32 = 2;
const VOID_BREAKER_IN_WINDOW: usize = 3;
const VOID_BREAKER_WINDOW: std::time::Duration = std::time::Duration::from_secs(3600);

/// Stops automatic live voids once they repeat. A systematic delay between a
/// window's last operation and its registration (a slow RPC, a slow disk) would
/// otherwise void every timed window while the exchange looks alive. A void
/// counts once it is durable, a void at boot included. Runtime only: the restart
/// after a trip is the operator's acknowledgment and starts it afresh.
#[derive(Debug, Default)]
pub(crate) struct VoidBreaker {
    /// When the voids of the last hour were made durable.
    recent: std::collections::VecDeque<std::time::Instant>,
    /// Voids since the last settled timed window.
    consecutive: u32,
}

impl VoidBreaker {
    /// Count a durable automatic void made at `now`. Returns why the breaker
    /// tripped, if it did.
    pub(crate) fn record(&mut self, now: std::time::Instant) -> Option<String> {
        self.consecutive = self.consecutive.saturating_add(1);
        self.recent.push_back(now);
        while self
            .recent
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) > VOID_BREAKER_WINDOW)
        {
            self.recent.pop_front();
        }
        if self.consecutive >= VOID_BREAKER_CONSECUTIVE {
            Some(format!(
                "{} live voids without a settled timed window between them",
                self.consecutive
            ))
        } else if self.recent.len() >= VOID_BREAKER_IN_WINDOW {
            Some(format!("{} live voids within an hour", self.recent.len()))
        } else {
            None
        }
    }

    /// A window with timed operations settled: the voids before it are no longer
    /// consecutive.
    pub(crate) fn timed_window_settled(&mut self) {
        self.consecutive = 0;
    }
}

/// The last live void since the gateway started: `/api/state` shows it as
/// `settlementVoid`, and each owner's withdrawals view lists its voided
/// withdrawals. Runtime only, so a restart forgets it.
#[derive(Clone, Debug)]
pub(crate) struct VoidNotice {
    pub batch_id: u64,
    /// `Cancelled`, `EmptyAfterFence` or `UnderivableTimeBounds`.
    pub cause: &'static str,
    pub at_ms: u64,
    pub orders: usize,
    pub fills: usize,
    pub withdrawals: Vec<Withdrawal>,
    pub deposits: usize,
}

impl VoidNotice {
    /// `/api/state` `settlementVoid`: counts only, no account data.
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "batchId": self.batch_id,
            "cause": self.cause,
            "atMs": self.at_ms,
            "orders": self.orders,
            "fills": self.fills,
            "withdrawals": self.withdrawals.len(),
            "deposits": self.deposits,
        })
    }

    /// `owner`'s voided withdrawals, for its withdrawals view.
    pub(crate) fn withdrawals_of(&self, owner: &PubKey) -> Vec<serde_json::Value> {
        self.withdrawals
            .iter()
            .filter(|w| w.owner == *owner)
            .map(|w| {
                serde_json::json!({
                    "to": hex0x(&w.to),
                    "amount": w.amount.to_string(),
                    "nonce": w.nonce,
                    "leaf": hex0x(&w.leaf()),
                    "batchId": self.batch_id,
                })
            })
            .collect()
    }
}

impl VoidReport {
    /// The cause as the notice and the log name it.
    pub(crate) fn cause_name(&self) -> &'static str {
        match self.cause {
            _ if self.underivable => "UnderivableTimeBounds",
            DeadIntent::Cancelled => "Cancelled",
            DeadIntent::EmptyAfterFence => "EmptyAfterFence",
            DeadIntent::CloseOnlyPhaseZero => "CloseOnlyPhaseZero",
            DeadIntent::Replaced => "Replaced",
        }
    }

    /// The runtime notice of this void, made at `at_ms`.
    pub(crate) fn notice(&self, at_ms: u64) -> VoidNotice {
        VoidNotice {
            batch_id: self.batch_id,
            cause: self.cause_name(),
            at_ms,
            orders: self.orders,
            fills: self.fills_reverted,
            withdrawals: self.withdrawals.clone(),
            deposits: self.deposits.len(),
        }
    }

    /// The per-account events of this void, each tagged with its owner: one
    /// `execution` event per changed order record, one `withdrawalVoided` per
    /// withdrawal and one `depositRestored` per depositor. Sent once the void is
    /// durable.
    pub(crate) fn account_events(&self) -> Vec<String> {
        let withdrawals = self.withdrawals.iter().map(|w| {
            serde_json::json!({
                "type": "withdrawalVoided",
                "owner": hex0x(&w.owner),
                "leaf": hex0x(&w.leaf()),
                "amount": w.amount.to_string(),
                "nonce": w.nonce,
                "batchId": self.batch_id,
            })
            .to_string()
        });
        let deposits = self.depositors.iter().map(|(owner, ids)| {
            serde_json::json!({
                "type": "depositRestored",
                "owner": hex0x(owner),
                "depositIds": ids,
                "batchId": self.batch_id,
            })
            .to_string()
        });
        self.order_events
            .iter()
            .cloned()
            .chain(withdrawals)
            .chain(deposits)
            .collect()
    }

    /// What the void undid, for the recovery log line.
    pub(crate) fn summary(&self) -> String {
        let mut line = format!(
            "{} orders cancelled, {} fills undone, {} withdrawals removed, {} deposits restored \
             for re-ingestion, bootstrap {}, {} archive records dropped",
            self.orders,
            self.fills_reverted,
            self.withdrawals.len(),
            self.deposits.len(),
            if self.bootstrap_restored {
                "restored"
            } else {
                "unchanged"
            },
            self.archive_dropped,
        );
        if self.underivable {
            line.push_str("; operation times are not monotonic: check the gateway clock (NTP)");
        }
        line
    }
}

/// Why [`Gw::live_void_window`] did not void the window.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LiveVoidError {
    /// A check before the void failed. Nothing changed; keep the journal.
    Refused(String),
    /// A check after the void failed. The in-memory state has changed and must
    /// never become durable: stop without persisting it. The journal and the
    /// snapshot taken before the void are still on disk.
    PostCheck(String),
}

impl std::fmt::Display for LiveVoidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "live void refused, nothing changed: {why}"),
            Self::PostCheck(why) => write!(f, "live void post-check failed: {why}"),
        }
    }
}

/// One deposit of the voided window, read from its journaled operations.
struct VoidedDeposit {
    id: u64,
    owner: PubKey,
    from: [u8; 20],
    amount: i128,
    /// The permit blind and the `ownerCommit` it opens for `owner`.
    blind: [u8; 32],
    commit: [u8; 32],
    /// The commitment of the note the deposit minted.
    note: Digest,
}

fn voided_deposits(j: &RollbackJournal) -> Vec<VoidedDeposit> {
    j.witness
        .ops
        .iter()
        .filter_map(|op| match op {
            BatchOp::Deposit {
                owner,
                asset_id,
                amount,
                blinding,
                from,
                deposit_id,
                deposit_blind,
            } => Some(VoidedDeposit {
                id: *deposit_id,
                owner: *owner,
                from: *from,
                amount: *amount,
                blind: *deposit_blind,
                commit: owner_commit(owner, deposit_blind),
                note: Note::new(*owner, *asset_id, *amount, *blinding).commitment::<Keccak256>(),
            }),
            _ => None,
        })
        .collect()
}

/// Which state the journaled window is in.
enum Shape {
    /// Sealed and unresolved: the void can be applied.
    Sealed,
    /// The state already holds the void.
    AlreadyVoided,
}

impl Gw {
    /// Void the sealed phase-0 window `j`, whose clock intent can never settle
    /// (`cause` is `Cancelled` or `EmptyAfterFence`), and everything it did. See
    /// the module documentation.
    ///
    /// Every check runs first; on [`LiveVoidError::Refused`] nothing changed. The
    /// void itself cannot fail. The state is checked again afterwards; a failure
    /// there ([`LiveVoidError::PostCheck`]) leaves a changed state the caller
    /// must never persist. A state that already holds the void returns
    /// [`LiveVoidOutcome::AlreadyVoided`] and is not changed.
    pub(crate) fn live_void_window(
        &mut self,
        j: &RollbackJournal,
        cause: DeadIntent,
    ) -> Result<LiveVoidOutcome, LiveVoidError> {
        if !matches!(cause, DeadIntent::Cancelled | DeadIntent::EmptyAfterFence) {
            return Err(LiveVoidError::Refused(format!(
                "a {cause:?} intent is not voided: only one whose anchor was cancelled or can \
                 never exist"
            )));
        }
        let deposits = voided_deposits(j);
        match self
            .live_void_shape(j, &deposits)
            .map_err(LiveVoidError::Refused)?
        {
            Shape::AlreadyVoided => return Ok(LiveVoidOutcome::AlreadyVoided),
            Shape::Sealed => {}
        }
        self.live_void_checks(j, &deposits)
            .map_err(LiveVoidError::Refused)?;
        let (report, hashes) = self.apply_live_void(j, cause, &deposits)?;
        self.live_void_post_checks(j, &hashes)
            .map_err(LiveVoidError::PostCheck)?;
        Ok(LiveVoidOutcome::Applied(report))
    }

    /// Whether the state already holds the void of window `j`: the void's
    /// snapshot was made durable and its journal was not deleted yet. Changes
    /// nothing.
    pub(crate) fn holds_live_void(&self, j: &RollbackJournal) -> bool {
        matches!(
            self.live_void_shape(j, &voided_deposits(j)),
            Ok(Shape::AlreadyVoided)
        )
    }

    /// The journal and the state it must be voided in.
    fn live_void_shape(
        &self,
        j: &RollbackJournal,
        deposits: &[VoidedDeposit],
    ) -> Result<Shape, String> {
        let prepared = j
            .prepared
            .as_ref()
            .ok_or("the journal holds no prepared clock intent")?;
        if prepared.outcome.wind_down_phase != 0 {
            return Err(format!(
                "window {} is a wind-down phase-{} window; only a phase-0 window is voided",
                j.batch_id, prepared.outcome.wind_down_phase
            ));
        }
        if j.witness.batch_id != j.batch_id || j.witness.pre_state.next_batch_id != j.batch_id {
            return Err(format!(
                "the journal's witness does not open window {}",
                j.batch_id
            ));
        }
        if self.wind_down_started {
            return Err("the wind-down has started".into());
        }
        let counter = self.seq.state.next_batch_id;
        if Some(counter) == j.batch_id.checked_add(1) {
            if self.seq.open_window_has_ops()
                || self.seq.window_has_pending_manifest()
                || !self.window_withdrawals.is_empty()
            {
                return Err(format!(
                    "the open window after sealed window {} is not empty",
                    j.batch_id
                ));
            }
            Ok(Shape::Sealed)
        } else if counter == j.batch_id {
            self.already_voided(j, deposits)
                .map_err(|why| {
                    format!(
                        "window {} is not sealed and the state does not hold its void: {why}",
                        j.batch_id
                    )
                })
                .map(|()| Shape::AlreadyVoided)
        } else {
            Err(format!(
                "the window counter is {counter}: window {} is neither sealed nor voided",
                j.batch_id
            ))
        }
    }

    /// The checks before a void of the sealed window `j`.
    fn live_void_checks(
        &self,
        j: &RollbackJournal,
        deposits: &[VoidedDeposit],
    ) -> Result<(), String> {
        let pre = &j.witness.pre_state;
        if self.last_settled_root != pre.state_root() {
            return Err(format!(
                "the last settled root is not window {}'s pre-state root",
                j.batch_id
            ));
        }
        // The deposits: exactly the ids after the pre-state's consumed count, each
        // credited from the payer and amount its operation names, under the permit
        // its blind opens for the credited account. None is refunded or recorded as
        // uncredited, and none is credited beyond them.
        let consumed = pre.consumed_deposit_count;
        let end = consumed
            .checked_add(deposits.len() as u64)
            .ok_or("deposit count overflow")?;
        if !deposits.iter().map(|d| d.id).eq(consumed..end) {
            return Err(format!(
                "the window's deposits are not deposits {consumed}..{end} in order"
            ));
        }
        if self.seq.state.consumed_deposit_count != end
            || self.deposits.credits.range(end..).next().is_some()
        {
            return Err(format!(
                "the credited deposits do not end at deposit {end}, where the window ends"
            ));
        }
        if self.deposits.refunds.range(consumed..end).next().is_some()
            || self
                .deposits
                .uncredited
                .range(consumed..end)
                .next()
                .is_some()
        {
            return Err(
                "a deposit of the window is also recorded as refunded or uncredited".into(),
            );
        }
        for d in deposits {
            let credit = self
                .deposits
                .credits
                .get(&d.id)
                .ok_or_else(|| format!("deposit {} of the window has no credit", d.id))?;
            let account = self
                .accounts
                .get(&credit.route.key)
                .ok_or_else(|| format!("deposit {}'s account is missing", d.id))?;
            if account.wallet.owner != d.owner
                || credit.event.from != d.from
                || i128::try_from(credit.event.amount).ok() != Some(d.amount)
                || credit.event.commit != d.commit
            {
                return Err(format!(
                    "deposit {}'s credit does not match the window's operation and permit blind",
                    d.id
                ));
            }
            if self.deposits.routes.contains_key(&d.commit)
                || account.deposit_authorizations.contains_key(&d.commit)
            {
                return Err(format!("deposit {}'s permit is still held", d.id));
            }
            if pre.tree.contains_leaf(&d.note) {
                return Err(format!(
                    "deposit {}'s note is in the window's pre-state",
                    d.id
                ));
            }
        }
        // The credits below the window reach the pre-state's deposit prefix.
        if self.deposits.domain.is_some() {
            let (prefix, prefix_tip) = self.deposits.legacy_prefix.unwrap_or((0, [0; 32]));
            let tip = if consumed == prefix {
                Some(prefix_tip)
            } else {
                consumed
                    .checked_sub(1)
                    .and_then(|id| self.deposits.credits.get(&id))
                    .map(|c| c.event.tip)
            };
            if consumed < prefix || tip != Some(pre.consumed_deposit_tip) {
                return Err("the deposit ledger does not reach the window's deposit prefix".into());
            }
        }
        if let bootstrap::Bootstrap::DepositApplied { deposit_id, .. } = self.bootstrap {
            if deposit_id >= consumed {
                return Err(
                    "a legacy insurance bootstrap deposit of the window cannot be restored".into(),
                );
            }
        }
        self.seq
            .void_preconditions(&j.witness)
            .map_err(|e| e.to_string())?;
        self.validate_deposit_state()
            .map_err(|e| format!("the deposit ledger does not validate before the void: {e}"))
    }

    /// The void itself, after every check passed. Returns the report and the
    /// order hashes published as cancelled. The checks rule out every error
    /// below; none panics, since a panic would release the Gw lock over a
    /// partly voided state.
    fn apply_live_void(
        &mut self,
        j: &RollbackJournal,
        cause: DeadIntent,
        deposits: &[VoidedDeposit],
    ) -> Result<(VoidReport, Vec<Digest>), LiveVoidError> {
        // The sequencer checks before it changes anything.
        let voided = self
            .seq
            .void_window(&j.witness)
            .map_err(|e| LiveVoidError::Refused(e.to_string()))?;
        let order_events = self.void_order_records(&voided.hashes, &voided.ticks);
        self.seq
            .reject_in_window(&voided.hashes, RejectReason::Cancelled);

        // Each deposit is landed and uncredited again, with its permit route and
        // blind, until ingestion credits it again.
        let mut voided_txs = BTreeSet::new();
        for d in deposits {
            let lost =
                || LiveVoidError::PostCheck(format!("deposit {} could not be restored", d.id));
            let credit = self.deposits.credits.remove(&d.id).ok_or_else(lost)?;
            self.accounts
                .get_mut(&credit.route.key)
                .ok_or_else(lost)?
                .deposit_authorizations
                .insert(d.commit, d.blind);
            self.deposits.routes.insert(d.commit, credit.route.clone());
            voided_txs.insert(credit.event.tx);
            self.deposits.uncredited.insert(d.id, credit);
        }
        let kept_txs: BTreeSet<[u8; 32]> = self
            .deposits
            .credits
            .values()
            .chain(self.deposits.refunds.values())
            .map(|c| c.event.tx)
            .collect();
        for tx in voided_txs.difference(&kept_txs) {
            self.processed_deposit_txs.remove(&hex0x(tx));
        }
        // The window's first deposit is in a later block than the last one the
        // pre-state consumed (a deposit block is credited whole), so reading on
        // from that block finds it again. At the legacy prefix there is no such
        // block, and the read starts from the chain's beginning.
        let consumed = j.witness.pre_state.consumed_deposit_count;
        self.deposits.anchor = consumed
            .checked_sub(1)
            .and_then(|id| self.deposits.credits.get(&id))
            .map(|c| c.event.block.clone());
        self.deposits.uncredited_scan = None;
        self.deposits.uncredited_scan_done = false;
        self.deposits.dirty = true;

        let notes: BTreeSet<Digest> = deposits.iter().map(|d| d.note).collect();
        let archive_dropped = self.archive.retain(|r| !notes.contains(&r.commitment));

        let bootstrap_restored = matches!(
            self.bootstrap,
            bootstrap::Bootstrap::InsuranceApplied { window_id } if window_id >= j.batch_id
        );
        if bootstrap_restored {
            self.bootstrap = bootstrap::Bootstrap::NotStarted;
        }

        let mut withdrawals = j.ww.clone();
        withdrawals.append(&mut self.window_withdrawals);
        let leaves: BTreeSet<[u8; 32]> = withdrawals.iter().map(Withdrawal::leaf).collect();
        self.pending_withdrawals
            .retain(|w| !leaves.contains(&w.leaf()));

        let fills_reverted = j
            .witness
            .ops
            .iter()
            .filter(|op| matches!(op, BatchOp::Fill { .. }))
            .count();
        let report = VoidReport {
            batch_id: j.batch_id,
            cause,
            orders: voided.hashes.len(),
            fills_reverted,
            withdrawals,
            deposits: deposits.iter().map(|d| d.id).collect(),
            depositors: deposits.iter().fold(Default::default(), |mut by, d| {
                by.entry(d.owner).or_insert_with(Vec::new).push(d.id);
                by
            }),
            bootstrap_restored,
            archive_dropped,
            underivable: perp_core::clock::TimeBounds::derive(&j.witness.ops).is_err(),
            order_events,
        };
        Ok((report, voided.hashes))
    }

    /// Undo the fills of the discarded `ticks` in the order records of `hashes`,
    /// in the gateway's list and in each account's, and end each as cancelled
    /// with the reason `WindowVoided` (`execution::void`). Call it right after
    /// the sequencer discarded the ticks and before any view refreshes finality:
    /// the discarded ticks are no longer pending, and a refresh would read their
    /// fills as settled. Returns one `execution` event per account record it
    /// changed, tagged with its owner like the tick's events.
    pub(crate) fn void_order_records(
        &mut self,
        hashes: &[Digest],
        ticks: &BTreeSet<u64>,
    ) -> Vec<String> {
        let hashes: BTreeSet<Digest> = hashes.iter().copied().collect();
        for o in self
            .orders
            .iter_mut()
            .filter(|o| hashes.contains(&o.order_hash))
        {
            let _ = execution::void(o, &self.seq, ticks);
        }
        let mut events = Vec::new();
        for account in self.accounts.values_mut() {
            let owner = hex0x(&account.wallet.owner);
            for o in account
                .orders
                .iter_mut()
                .filter(|o| hashes.contains(&o.order_hash))
            {
                if let Some(mut event) = execution::void(o, &self.seq, ticks) {
                    event["owner"] = serde_json::json!(owner);
                    events.push(event.to_string());
                }
            }
        }
        events
    }

    /// The state a void must reach. Only a bug fails this: every check before
    /// the void guards it.
    fn live_void_post_checks(&self, j: &RollbackJournal, hashes: &[Digest]) -> Result<(), String> {
        let pre = &j.witness.pre_state;
        let pre_root = pre.state_root();
        if self.seq.state.state_root() != pre_root || self.last_settled_root != pre_root {
            return Err("the state root is not the window's pre-state root".into());
        }
        if self.seq.state.consumed_deposit_count != pre.consumed_deposit_count {
            return Err("the consumed deposit count is not the window's pre-state count".into());
        }
        if self.seq.current_window_id() != j.batch_id {
            return Err(format!("the open window is not window {}", j.batch_id));
        }
        if self.seq.open_window_has_ops() {
            return Err("the open window holds operations".into());
        }
        let rejected = self.seq.window_rejected();
        if rejected.len() != hashes.len()
            || rejected
                .iter()
                .zip(hashes)
                .any(|((h, reason), voided)| h != voided || *reason != RejectReason::Cancelled)
        {
            return Err(
                "the open window does not reject exactly the voided orders as cancelled".into(),
            );
        }
        self.validate_deposit_state()
    }

    /// Whether the state already holds the void of window `j`: the void's
    /// snapshot was made durable and the journal was not deleted yet.
    fn already_voided(
        &self,
        j: &RollbackJournal,
        deposits: &[VoidedDeposit],
    ) -> Result<(), String> {
        let pre = &j.witness.pre_state;
        let pre_root = pre.state_root();
        if self.seq.window_baseline().state_root() != pre_root
            || self.seq.state.state_root() != pre_root
            || self.last_settled_root != pre_root
        {
            return Err("the state is not the window's pre-state".into());
        }
        if self.seq.open_window_has_ops() || !self.window_withdrawals.is_empty() {
            return Err("the open window holds operations".into());
        }
        let rejected = self.seq.window_rejected();
        let published = |h: &Digest| rejected.contains(&(*h, RejectReason::Cancelled));
        if !j.witness.manifest.ordered.iter().all(published)
            || !j
                .witness
                .manifest
                .rejected
                .iter()
                .all(|(h, _)| published(h))
        {
            return Err("an order of the window is not published as cancelled".into());
        }
        if self.seq.state.consumed_deposit_count != pre.consumed_deposit_count {
            return Err("the consumed deposit count is not the window's pre-state count".into());
        }
        for d in deposits {
            let restored = self
                .deposits
                .uncredited
                .get(&d.id)
                .is_some_and(|row| row.event.commit == d.commit)
                && self.deposits.routes.get(&d.commit).is_some_and(|route| {
                    self.accounts
                        .get(&route.key)
                        .is_some_and(|a| a.deposit_authorizations.get(&d.commit) == Some(&d.blind))
                });
            if !restored {
                return Err(format!("deposit {} is not restored with its permit", d.id));
            }
        }
        if matches!(
            self.bootstrap,
            bootstrap::Bootstrap::InsuranceApplied { window_id } if window_id >= j.batch_id
        ) {
            return Err("the window's insurance bootstrap is still applied".into());
        }
        let leaves: BTreeSet<[u8; 32]> = j.ww.iter().map(Withdrawal::leaf).collect();
        if self
            .pending_withdrawals
            .iter()
            .any(|w| leaves.contains(&w.leaf()))
        {
            return Err("a withdrawal of the window is still pending".into());
        }
        let notes: BTreeSet<Digest> = deposits.iter().map(|d| d.note).collect();
        if self
            .archive
            .notes()
            .iter()
            .any(|r| notes.contains(&r.commitment))
        {
            return Err("a note of the window is still archived".into());
        }
        Ok(())
    }

    /// After a live void, before admission reopens: whether crediting every
    /// outstanding permit, the restored deposits included, would take the state
    /// beyond an admission bound. Returns the bound, logs it and raises
    /// `DepositBlockedAtCap` if so; the void stands either way.
    ///
    /// Usually there is room: the voided window held the same deposits. But a
    /// window can also remove position entries and unspent notes (a full exit
    /// removes an entry), which the restored state holds again, and the cap
    /// keeps room for one more exit of each. Then ingestion holds the restored
    /// page until exits free room, as for any deposit beyond a bound, and the
    /// deposit is refundable after close-only.
    pub(crate) fn note_void_headroom(&self, batch_id: u64) -> Option<&'static str> {
        let size =
            crate::admission::HistorySize::of(&self.seq.state).plus(self.outstanding_permit_size());
        let cap = &self.admission_cap;
        let bound = if size.history > cap.max_history {
            "provable-history"
        } else if size.positions > cap.max_positions {
            "position-entry"
        } else if size.notes > cap.max_notes {
            "unspent-note"
        } else {
            return None;
        };
        eprintln!(
            "[recovery] window {batch_id}: re-ingest of the restored deposits would exceed the \
             {bound} bound; ingestion holds them until exits free room"
        );
        self.ops_alerts
            .activate(ops_alerts::AlertKind::DepositBlockedAtCap);
        Some(bound)
    }
}

#[cfg(test)]
#[path = "live_void_tests.rs"]
pub(crate) mod tests;
