//! Pipelined, fee-bumped challenge answers on the answer key's own nonce lane.
//!
//! Up to `Policy::max_in_flight` `answerChallenges` transactions are broadcast
//! without waiting for receipts, each at an explicit nonce and explicit EIP-1559
//! fees. A transaction that has not mined after `bump_after` is replaced at the
//! SAME nonce with both fees raised by at least 12.5% (and never below the current
//! estimate), at most `max_bumps` times and never above `max_fee_cap`. Past those
//! caps the same transaction is only rebroadcast, which keeps it alive if a node
//! evicted it and is a no-op otherwise.
//!
//! A slot is released only by the chain: once the account's mined nonce passes
//! it, one transaction at that nonce mined (ours, which succeeded or reverted, or
//! one this process did not send). Receipts only classify the release. Answers
//! are idempotent on-chain (`answerChallenges` skips hashes that are no longer
//! open), so resending after a revert, a replacement or a restart is safe; a
//! revert releases its slot and its hashes are planned again, so nothing wedges
//! the lane.
//!
//! No nonce is ever skipped unless the chain holds a transaction there. A fee
//! refusal at a fresh nonce (a full pool, a tip under the node's minimum) is
//! retried at the same nonce with higher fees; a nonce is treated as occupied only
//! when the node says a replacement is underpriced and the pending nonce confirms
//! something is there. A stuck nonce this process did not fill (inherited at
//! start, or occupied) is taken over by queued answers, or, when answers of ours
//! wait behind it, replaced by a no-op transfer under the same bump caps, so it
//! cannot hold the lane. A no-op that fails for a reason other than its fees
//! (the account's balance, the RPC, the keystore) counts toward the round's
//! `max_failures` but not toward the bump caps, so the nonce is never given up:
//! each such failure in a row adds one `bump_after` to the wait before the next
//! attempt there, up to `MAX_NOOP_BACKOFF` intervals, and a broadcast there that
//! is accepted or refused for its fees clears the wait.
//!
//! A payload the estimate refuses is halved depth-first (the left half next), so
//! one refused entry among n is isolated after about log2(n) refused attempts,
//! and the payload's remaining pieces move behind the other queued answers.
//! Every attempt is one broadcast call and none starts after the round budget,
//! so one round makes at most `round_budget` over the RPC's time per call of
//! them; pieces a round does not reach wait for the next. A single refused answer
//! is not sent again for `refused_ttl`, and is isolated again if it is still
//! planned after that. Refusals never stop a round, so one batch cannot starve
//! the next. Only failures that are not the payload's fault count toward
//! `max_failures`.
//!
//! An "already known" reply names no transaction hash, so no receipt can be read
//! for it. When the chain moves past a nonce where these very answers were known
//! to be pending and no readable receipt says otherwise, they count as answered
//! and are not resent while a stale open-set read still lists them.
//!
//! Nothing is persisted. A fresh pipeline reads the mined and pending nonces from
//! the chain; transactions between them were sent before the restart and occupy
//! slots until they mine.
//!
//! Rounds are bounded by `round_budget`: no replacement or fresh broadcast starts
//! after it. Nothing here feeds the settle gate: the open-set read alone decides
//! whether the settle loop may seal, and hashes no settled batch can prove are
//! never planned, so they never occupy the lane.
use crate::l1::ChallengeAnswer;
use perp_core::hash::Digest;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// EIP-1559 fees of one transaction, in wei.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fees {
    pub max_fee: u128,
    pub priority: u128,
}

/// Pipelining and fee-bumping limits.
#[derive(Clone, Debug)]
pub(crate) struct Policy {
    /// Answer transactions broadcast but not yet mined, inherited ones included.
    pub max_in_flight: usize,
    /// A transaction not mined this long after its last broadcast is replaced.
    pub bump_after: Duration,
    /// Replacements per nonce; past this the transaction is only rebroadcast.
    pub max_bumps: u32,
    /// No answer transaction offers a higher max fee per gas.
    pub max_fee_cap: u128,
    /// Floor for the priority fee when the node suggests less.
    pub min_priority: u128,
    /// Pause between chain polls inside a round.
    pub poll_every: Duration,
    /// A round returns after this long even with work left.
    pub round_budget: Duration,
    /// Hashes in a transaction that mined successfully are not sent again for
    /// this long, so an open-set read taken before the mining does not resend them.
    pub recent_ttl: Duration,
    /// A single answer whose estimate reverted is not sent again for this long,
    /// so later rounds do not repeat the halving that isolated it.
    pub refused_ttl: Duration,
    /// Failed broadcasts per round that are not the payload's fault (an RPC or
    /// account error) before the round stops. Payload refusals do not count.
    pub max_failures: usize,
}

/// One wei-per-gas unit in gwei.
const GWEI: u128 = 1_000_000_000;

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_in_flight: 4,
            // Ten Base blocks.
            bump_after: Duration::from_secs(20),
            max_bumps: 6,
            max_fee_cap: 10 * GWEI,
            min_priority: GWEI / 1000,
            poll_every: Duration::from_secs(crate::l1::L1_BLOCK_SECS),
            // Below the watcher's 30 s tick, so the next round starts on time.
            round_budget: Duration::from_secs(25),
            recent_ttl: Duration::from_secs(120),
            // Two watcher ticks: a refusal from a node lagging behind settlement
            // clears soon, a persistent one costs one halving per minute.
            refused_ttl: Duration::from_secs(60),
            max_failures: 16,
        }
    }
}

/// Inherited transactions tracked after a restart, at most.
const MAX_INHERITED: u64 = 64;

/// Attempts at a nonce whose no-ops keep failing for a reason other than their
/// fees are at most this many `bump_after` intervals apart.
const MAX_NOOP_BACKOFF: u32 = 8;

/// One answer transaction as the lane asks the chain to broadcast it.
pub(crate) struct AnswerTx<'a> {
    pub nonce: u64,
    pub fees: Fees,
    pub batch: u64,
    pub answers: &'a [ChallengeAnswer],
}

/// The answer account as the pipeline sees it. Implemented over `cast` in `l1`.
pub(crate) trait AnswerChain {
    /// Transactions of the answer account mined so far (its `latest` nonce).
    fn mined_nonce(&self) -> Result<u64, String>;
    /// Its next nonce counting the mempool (`pending`).
    fn pending_nonce(&self) -> Result<u64, String>;
    /// The node's current fee suggestion, before the policy's floor and cap.
    fn fee_estimate(&self) -> Result<Fees, String>;
    /// Sign and broadcast without waiting for the receipt; the transaction hash.
    fn broadcast(&self, tx: &AnswerTx<'_>) -> Result<String, String>;
    /// Sign and broadcast a no-op (a zero-value transfer to the answer account
    /// itself) at `nonce`, without waiting for the receipt; the transaction hash.
    fn cancel(&self, nonce: u64, fees: Fees) -> Result<String, String>;
    /// `Some(true)` mined and succeeded, `Some(false)` mined and reverted, `None`
    /// no receipt (still pending, or replaced by another transaction).
    fn receipt(&self, tx_hash: &str) -> Result<Option<bool>, String>;
}

/// Time as a round sees it, so tests can run rounds without waiting.
pub(crate) trait Clock {
    fn now(&self) -> Instant;
    fn sleep(&self, d: Duration);
}

/// The wall clock.
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// What one round did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RoundReport {
    /// New transactions broadcast at fresh nonces.
    pub submitted: usize,
    /// Replacements broadcast at an in-flight nonce with higher fees.
    pub bumped: usize,
    /// Our transactions that mined and succeeded.
    pub mined: usize,
    /// Entries in those transactions (hashes closed meanwhile are skipped on-chain).
    pub answered: usize,
    /// Our transactions that mined and reverted; their hashes are planned again.
    pub reverted: usize,
    /// Nonces consumed by a transaction this process did not send (one sent before
    /// a restart, or a replacement from elsewhere), or whose receipt was unreadable.
    pub replaced: usize,
    /// No-op transfers broadcast to free a stuck nonce this process did not fill,
    /// so the answers behind it can mine.
    pub cancelled: usize,
    /// In-flight transactions at their bump limit or fee cap, plus queued answers
    /// whose fresh nonce the node keeps refusing at the fee cap.
    pub at_fee_cap: usize,
    /// The lowest in-flight nonce, when no answer of ours is pending there and it
    /// has been held longer than `bump_after`: every answer above it waits.
    pub blocked_at: Option<u64>,
    /// Transactions still in flight when the round returned.
    pub in_flight: usize,
    /// Planned answers left for a later round.
    pub deferred: usize,
    /// The first error this round; else, when a no-op this lane needs keeps
    /// failing, its last error and when it is tried again.
    pub first_error: Option<String>,
}

/// The transactions at one nonce.
struct Slot {
    /// The answers this process last broadcast (or is known to have pending) at
    /// this nonce. `None` for a nonce it did not fill: a transaction inherited at
    /// start, one found occupying the nonce, or a no-op transfer replacing those.
    payload: Option<(u64, Vec<ChallengeAnswer>)>,
    /// Fees of the latest broadcast attempt at this nonce.
    fees: Option<Fees>,
    /// Every hash this process broadcast at this nonce.
    hashes: Vec<String>,
    /// A broadcast of `payload` here was answered "already known": that
    /// transaction is pending under a hash this process never learned.
    unhashed: bool,
    /// Replacements accepted, or refused for their fees.
    bumps: u32,
    /// No-op broadcasts here that failed in a row for a reason other than their
    /// fees, and the last such error. Each one lengthens the wait before the next
    /// attempt; a broadcast here that is accepted or refused for its fees clears it.
    failed_noops: Option<(u32, String)>,
    /// The latest broadcast attempt (or the start, for an inherited slot).
    since: Instant,
    /// When the slot was first tracked.
    opened: Instant,
}

impl Slot {
    fn inherited(now: Instant) -> Self {
        Self {
            payload: None,
            fees: None,
            hashes: Vec::new(),
            unhashed: false,
            bumps: 0,
            failed_noops: None,
            since: now,
            opened: now,
        }
    }
}

/// Answers waiting for a fresh nonce, one entry per planned payload, in plan
/// order. A refused piece is halved in place with its left half next, and its
/// entry moves behind the others: halving is depth-first within a payload, and
/// one payload's refusals never hold back the next.
#[derive(Default)]
struct Queue(VecDeque<Entry>);

/// One planned payload: its batch and the pieces still to send, the next last.
/// Never empty while queued.
struct Entry {
    batch: u64,
    pieces: Vec<Vec<ChallengeAnswer>>,
}

impl Queue {
    /// The next piece to send.
    fn front(&self) -> Option<(u64, &[ChallengeAnswer])> {
        let entry = self.0.front()?;
        let piece = entry.pieces.last()?;
        Some((entry.batch, piece.as_slice()))
    }

    /// Remove the next piece (it was sent).
    fn take_front(&mut self) -> Option<(u64, Vec<ChallengeAnswer>)> {
        let entry = self.0.front_mut()?;
        let batch = entry.batch;
        let piece = entry.pieces.pop();
        if entry.pieces.is_empty() {
            self.0.pop_front();
        }
        piece.map(|piece| (batch, piece))
    }

    /// Halve the next piece in place, left half next, and move its entry behind
    /// the others. A single answer cannot be halved: it is removed and returned.
    fn halve_front(&mut self) -> Option<ChallengeAnswer> {
        let mut entry = self.0.pop_front()?;
        let mut left = entry.pieces.pop().unwrap_or_default();
        let single = if left.len() > 1 {
            let right = left.split_off(left.len() / 2);
            entry.pieces.push(right);
            entry.pieces.push(left);
            None
        } else {
            left.pop()
        };
        if !entry.pieces.is_empty() {
            self.0.push_back(entry);
        }
        single
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Answers still queued.
    fn answers(&self) -> usize {
        self.0
            .iter()
            .flat_map(|entry| &entry.pieces)
            .map(Vec::len)
            .sum()
    }
}

/// The answer lane's in-memory state. Only derived data: a restart rebuilds it
/// from the chain.
pub(crate) struct Pipeline {
    policy: Policy,
    /// The next fresh nonce; `None` until read from the chain.
    next_nonce: Option<u64>,
    slots: BTreeMap<u64, Slot>,
    recent: HashMap<Digest, Instant>,
    /// Single answers whose estimate reverted, and when.
    refused: HashMap<Digest, Instant>,
    /// Fees the node last refused as too low at the fresh nonce; the next attempt
    /// there offers more. Cleared once a fresh nonce is filled.
    fresh_floor: Option<Fees>,
}

impl Pipeline {
    pub(crate) fn new(policy: Policy) -> Self {
        Self {
            policy,
            next_nonce: None,
            slots: BTreeMap::new(),
            recent: HashMap::new(),
            refused: HashMap::new(),
            fresh_floor: None,
        }
    }

    /// Transactions in flight.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        self.slots.len()
    }

    /// Reconcile in-flight transactions with the chain, replace stuck ones and
    /// broadcast `sends` (minus answers already in flight) while slots are free,
    /// polling until nothing is left or the round budget is spent.
    pub(crate) fn round(
        &mut self,
        chain: &dyn AnswerChain,
        clock: &dyn Clock,
        sends: Vec<(u64, Vec<ChallengeAnswer>)>,
    ) -> RoundReport {
        let mut report = RoundReport::default();
        let start = clock.now();
        let deadline = start + self.policy.round_budget;
        let (recent_ttl, refused_ttl) = (self.policy.recent_ttl, self.policy.refused_ttl);
        self.recent
            .retain(|_, at| start.saturating_duration_since(*at) < recent_ttl);
        self.refused
            .retain(|_, at| start.saturating_duration_since(*at) < refused_ttl);
        // Admitted after the first reconcile, so answers whose transaction just
        // reverted or was replaced are planned again in this round.
        let mut sends = Some(sends);
        let mut queue = Queue::default();
        let mut failures = 0;
        loop {
            let stop = self
                .reconcile(chain, clock.now(), &mut report)
                .and_then(|()| {
                    if let Some(sends) = sends.take() {
                        queue = self.admit(sends);
                    }
                    self.work(
                        chain,
                        clock,
                        deadline,
                        &mut queue,
                        &mut report,
                        &mut failures,
                    )
                });
            if let Err(stop) = stop {
                report.first_error.get_or_insert(stop);
                break;
            }
            if queue.is_empty() && self.slots.is_empty() {
                break;
            }
            if clock.now() + self.policy.poll_every > deadline {
                break;
            }
            clock.sleep(self.policy.poll_every);
        }
        let now = clock.now();
        report.in_flight = self.slots.len();
        report.deferred = queue.answers()
            + sends
                .iter()
                .flatten()
                .map(|(_, answers)| answers.len())
                .sum::<usize>();
        let fresh_at_cap = !queue.is_empty()
            && self
                .fresh_floor
                .is_some_and(|f| replacement_fees(f, None, self.policy.max_fee_cap).is_none());
        report.at_fee_cap = self
            .slots
            .values()
            .filter(|slot| self.exhausted(slot))
            .count()
            + usize::from(fresh_at_cap);
        report.blocked_at = self
            .slots
            .iter()
            .next()
            .filter(|(_, slot)| {
                slot.payload.is_none()
                    && now.saturating_duration_since(slot.opened) >= self.policy.bump_after
            })
            .map(|(nonce, _)| *nonce);
        if report.first_error.is_none() {
            report.first_error = self.slots.iter().find_map(|(nonce, slot)| {
                let (count, error) = slot.failed_noops.as_ref()?;
                let next = slot
                    .since
                    .checked_add(self.retry_after(slot))
                    .map_or(Duration::MAX, |at| at.saturating_duration_since(now));
                Some(format!(
                    "the no-op at nonce {nonce} failed {count} time(s) in a row, next attempt \
                     in {} s: {error}",
                    next.as_secs()
                ))
            });
        }
        report
    }

    /// Planned answers minus those already in flight, recently mined or recently
    /// refused.
    fn admit(&self, sends: Vec<(u64, Vec<ChallengeAnswer>)>) -> Queue {
        let in_flight: HashSet<Digest> = self
            .slots
            .values()
            .filter_map(|slot| slot.payload.as_ref())
            .flat_map(|(_, answers)| answers.iter().map(|a| a.order_hash))
            .collect();
        Queue(
            sends
                .into_iter()
                .filter_map(|(batch, answers)| {
                    let answers: Vec<ChallengeAnswer> = answers
                        .into_iter()
                        .filter(|a| {
                            !in_flight.contains(&a.order_hash)
                                && !self.recent.contains_key(&a.order_hash)
                                && !self.refused.contains_key(&a.order_hash)
                        })
                        .collect();
                    (!answers.is_empty()).then(|| Entry {
                        batch,
                        pieces: vec![answers],
                    })
                })
                .collect(),
        )
    }

    /// How long after its latest attempt a slot is stuck: `bump_after`, plus one
    /// interval per no-op that failed there in a row, up to `MAX_NOOP_BACKOFF`.
    fn retry_after(&self, slot: &Slot) -> Duration {
        let failed = slot.failed_noops.as_ref().map_or(0, |(count, _)| *count);
        self.policy
            .bump_after
            .saturating_mul(failed.saturating_add(1).min(MAX_NOOP_BACKOFF))
    }

    /// A slot that can no longer be replaced: only rebroadcast, or, when nothing
    /// was ever accepted there, left to mine on its own.
    fn exhausted(&self, slot: &Slot) -> bool {
        slot.bumps >= self.policy.max_bumps
            || slot
                .fees
                .is_some_and(|fees| replacement_fees(fees, None, self.policy.max_fee_cap).is_none())
    }

    /// Move the fresh nonce. A fee refused at one nonce says nothing about the
    /// next, so the floor it set is dropped when the nonce changes.
    fn move_fresh(&mut self, next: Option<u64>) {
        if self.next_nonce != next {
            self.fresh_floor = None;
        }
        self.next_nonce = next;
    }

    /// Fees for the next broadcast at the fresh nonce: the estimate, or more than
    /// the node last refused there.
    fn fresh_fees(&self, estimate: Fees) -> Fees {
        let fees = initial_fees(estimate, &self.policy);
        match self.fresh_floor {
            Some(refused) => {
                replacement_fees(refused, Some(fees), self.policy.max_fee_cap).unwrap_or(refused)
            }
            None => fees,
        }
    }

    /// Read the mined nonce (and, once, the pending nonce) and release every slot
    /// the chain has moved past.
    fn reconcile(
        &mut self,
        chain: &dyn AnswerChain,
        now: Instant,
        report: &mut RoundReport,
    ) -> Result<(), String> {
        let mined = chain.mined_nonce()?;
        if self.next_nonce.is_none() {
            let pending = chain.pending_nonce()?.max(mined);
            // Transactions sent before a restart (or by anything else using the
            // key): they hold slots until they mine.
            for nonce in mined..pending.min(mined.saturating_add(MAX_INHERITED)) {
                self.slots
                    .entry(nonce)
                    .or_insert_with(|| Slot::inherited(now));
            }
            self.move_fresh(Some(pending));
        }
        self.release_below(chain, mined, now, report);
        let floor = self
            .slots
            .keys()
            .next_back()
            .map_or(mined, |n| n.saturating_add(1))
            .max(mined);
        let next = self.next_nonce.map_or(floor, |next| next.max(floor));
        self.move_fresh(Some(next));
        Ok(())
    }

    /// Track `payload` as ours at the fresh `nonce`, and move past it.
    fn fill(
        &mut self,
        nonce: u64,
        payload: (u64, Vec<ChallengeAnswer>),
        fees: Fees,
        hash: Option<String>,
        now: Instant,
    ) {
        self.slots.insert(
            nonce,
            Slot {
                payload: Some(payload),
                fees: Some(fees),
                unhashed: hash.is_none(),
                hashes: hash.into_iter().collect(),
                bumps: 0,
                failed_noops: None,
                since: now,
                opened: now,
            },
        );
        self.next_nonce = Some(nonce + 1);
        self.fresh_floor = None;
    }

    /// Replace stuck transactions, then fill free slots from `queue` until the
    /// deadline. No broadcast starts after the deadline. An error ends the round.
    fn work(
        &mut self,
        chain: &dyn AnswerChain,
        clock: &dyn Clock,
        deadline: Instant,
        queue: &mut Queue,
        report: &mut RoundReport,
        failures: &mut usize,
    ) -> Result<(), String> {
        let now = clock.now();
        let mut estimate: Option<Option<Fees>> = None;
        let stuck: Vec<u64> = self
            .slots
            .iter()
            .filter(|(_, slot)| now.saturating_duration_since(slot.since) >= self.retry_after(slot))
            .map(|(nonce, _)| *nonce)
            .collect();
        // Lowest nonce first: it holds back every answer above it.
        for nonce in stuck {
            if clock.now() > deadline {
                break;
            }
            let fees = *estimate.get_or_insert_with(|| chain.fee_estimate().ok());
            if self.replace(chain, nonce, now, fees, queue, report)? {
                *failures += 1;
                if *failures >= self.policy.max_failures {
                    return Err(format!("{failures} answer broadcasts failed this round"));
                }
            }
        }

        while self.slots.len() < self.policy.max_in_flight && clock.now() < deadline {
            let Some((batch, answers)) = queue.front() else {
                break;
            };
            let Some(estimate) = *estimate.get_or_insert_with(|| chain.fee_estimate().ok()) else {
                return Err("the fee estimate is unavailable".into());
            };
            let fees = self.fresh_fees(estimate);
            let Some(nonce) = self.next_nonce else {
                break;
            };
            let sent = chain.broadcast(&AnswerTx {
                nonce,
                fees,
                batch,
                answers,
            });
            let error = match sent {
                Ok(hash) => {
                    if let Some(payload) = queue.take_front() {
                        self.fill(nonce, payload, fees, Some(hash), now);
                    }
                    report.submitted += 1;
                    continue;
                }
                Err(error) => error,
            };
            let kind = classify(&error);
            if kind != SendError::Known {
                report.first_error.get_or_insert(error.clone());
            }
            let mut pause = false;
            match kind {
                // This very transaction is already pending (a broadcast whose
                // reply was lost): the nonce holds our answers.
                SendError::Known => {
                    if let Some(payload) = queue.take_front() {
                        self.fill(nonce, payload, fees, None, now);
                    }
                    report.submitted += 1;
                    continue;
                }
                SendError::Wedged => return Err(error),
                // Something mined at this nonce: read the chain again.
                SendError::NonceTooLow => {
                    *failures += 1;
                    self.move_fresh(None);
                    pause = true;
                }
                SendError::Occupied | SendError::Underpriced => {
                    *failures += 1;
                    let occupied = kind == SendError::Occupied
                        && chain.pending_nonce().is_ok_and(|pending| pending > nonce);
                    if occupied {
                        // Another transaction, paying at least as much, is pending
                        // at this nonce: it holds a slot until it mines, and is
                        // replaced if it gets stuck. The answers take the next nonce.
                        self.slots.insert(
                            nonce,
                            Slot {
                                fees: Some(fees),
                                ..Slot::inherited(now)
                            },
                        );
                        self.move_fresh(Some(nonce + 1));
                    } else {
                        // Nothing was added (a full pool, a tip under the node's
                        // minimum, or nothing actually pending there): retry this
                        // same nonce at the next poll with higher fees.
                        self.fresh_floor = Some(fees);
                        pause = true;
                    }
                }
                // The estimate reverted: the nonce is unused and the payload is
                // refused. Halve it depth-first, its entry behind the other queued
                // answers, so one bad entry cannot hold back the rest of its batch
                // or any later batch; a single refused answer is skipped for
                // `refused_ttl`.
                SendError::Refused => {
                    if let Some(single) = queue.halve_front() {
                        self.refused.insert(single.order_hash, now);
                    }
                }
                // Not the payload's fault as far as we can tell: counted, and
                // halved as the serial path does (a single answer waits for the
                // next round).
                SendError::Failed => {
                    *failures += 1;
                    queue.halve_front();
                }
            }
            if *failures >= self.policy.max_failures {
                return Err(format!("{failures} answer broadcasts failed this round"));
            }
            if pause {
                break;
            }
        }
        Ok(())
    }

    /// Release every slot below the mined nonce: one transaction at that nonce
    /// mined. Receipts of our hashes say which.
    fn release_below(
        &mut self,
        chain: &dyn AnswerChain,
        mined: u64,
        now: Instant,
        report: &mut RoundReport,
    ) {
        let done: Vec<u64> = self.slots.range(..mined).map(|(nonce, _)| *nonce).collect();
        for nonce in done {
            let Some(slot) = self.slots.remove(&nonce) else {
                continue;
            };
            // Without a readable receipt, a transaction of these very answers
            // known to be pending here under an unlearned hash took the nonce.
            let outcome = slot
                .hashes
                .iter()
                .rev()
                .find_map(|hash| chain.receipt(hash).ok().flatten())
                .or(slot.unhashed.then_some(true));
            match (outcome, slot.payload) {
                (Some(true), Some((_, answers))) => {
                    report.mined += 1;
                    report.answered += answers.len();
                    for a in answers {
                        self.recent.insert(a.order_hash, now);
                    }
                }
                (Some(true), None) => report.mined += 1,
                (Some(false), _) => report.reverted += 1,
                (None, _) => report.replaced += 1,
            }
        }
    }

    /// Replace (or, past the caps, rebroadcast) the stuck transaction at `nonce`.
    /// A nonce this process did not fill is taken over by queued answers, or, when
    /// answers of ours wait behind it, by a no-op transfer. `Ok(true)` when a
    /// no-op failed for a reason other than its fees: that counts toward the
    /// round's failures and lengthens the wait before the next attempt here, but
    /// uses none of the slot's replacements. Errors only for a wedged RPC.
    fn replace(
        &mut self,
        chain: &dyn AnswerChain,
        nonce: u64,
        now: Instant,
        estimate: Option<Fees>,
        queue: &mut Queue,
        report: &mut RoundReport,
    ) -> Result<bool, String> {
        let ours_behind = self
            .slots
            .range(nonce.saturating_add(1)..)
            .any(|(_, slot)| slot.payload.is_some());
        let policy = &self.policy;
        let Some(slot) = self.slots.get_mut(&nonce) else {
            return Ok(false);
        };
        let replacement = if slot.bumps >= policy.max_bumps {
            None
        } else {
            match slot.fees {
                Some(old) => replacement_fees(old, estimate, policy.max_fee_cap),
                None => estimate.map(|e| initial_fees(e, policy)),
            }
        };
        // Our own answers; else queued answers taking over a nonce this process
        // did not fill; else, when answers of ours wait behind it, a no-op (`None`).
        // A queued piece stays queued until a broadcast takes it over.
        let (content, taken) = match &slot.payload {
            Some(payload) => (Some(payload.clone()), false),
            None => match queue.front() {
                Some((batch, answers)) => (Some((batch, answers.to_vec())), true),
                None if ours_behind => (None, false),
                // It holds back nothing of ours: let it mine on its own.
                None => {
                    slot.since = now;
                    return Ok(false);
                }
            },
        };
        let (fees, bump) = match (replacement, slot.fees) {
            (Some(fees), _) => (fees, true),
            // At the caps: rebroadcast what this process last sent here, unchanged.
            (None, Some(fees)) if !taken && (slot.payload.is_some() || !slot.hashes.is_empty()) => {
                (fees, false)
            }
            (None, _) => {
                slot.since = now;
                return Ok(false);
            }
        };
        let sent = match &content {
            Some((batch, answers)) => chain.broadcast(&AnswerTx {
                nonce,
                fees,
                batch: *batch,
                answers,
            }),
            None => chain.cancel(nonce, fees),
        };
        slot.since = now;
        let error = match sent {
            Ok(hash) => {
                if !slot.hashes.contains(&hash) {
                    slot.hashes.push(hash);
                }
                None
            }
            Err(error) => Some(error),
        };
        match error.as_deref().map(classify) {
            // Broadcast, or this very transaction is already pending.
            None | Some(SendError::Known) => {
                // A new transaction of ours known to be pending under a hash the
                // reply did not name.
                if error.is_some() && content.is_some() && (bump || taken) {
                    slot.unhashed = true;
                }
                slot.failed_noops = None;
                if bump {
                    slot.fees = Some(fees);
                    slot.bumps += 1;
                    report.bumped += 1;
                    if content.is_none() {
                        report.cancelled += 1;
                    }
                }
                if taken {
                    queue.take_front();
                    slot.payload = content;
                }
                Ok(false)
            }
            Some(kind) => {
                let error = error.unwrap_or_default();
                match kind {
                    SendError::Wedged => {
                        report.first_error.get_or_insert(error.clone());
                        Err(error)
                    }
                    // Mined meanwhile: the next poll releases the slot.
                    SendError::NonceTooLow => Ok(false),
                    // The pending transaction pays more than we knew, or the node
                    // wants more: start the next attempt from these fees. A fee
                    // refusal also ends a run of failed no-ops here, so neither
                    // their longer wait nor their last error carries over.
                    SendError::Occupied | SendError::Underpriced => {
                        if bump {
                            slot.fees = Some(fees);
                            slot.bumps += 1;
                        }
                        slot.failed_noops = None;
                        Ok(false)
                    }
                    // The pending transaction stays; retry after the next interval.
                    // A failed no-op counts toward the round's failures and waits
                    // one interval longer each time in a row, but uses none of the
                    // slot's replacements: once the cause clears, it is tried again.
                    SendError::Refused | SendError::Failed | SendError::Known => {
                        report.first_error.get_or_insert(error.clone());
                        if content.is_none() {
                            let count = slot.failed_noops.as_ref().map_or(0, |(count, _)| *count);
                            slot.failed_noops = Some((count.saturating_add(1), error));
                            return Ok(true);
                        }
                        Ok(false)
                    }
                }
            }
        }
    }
}

/// How a broadcast failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendError {
    /// The RPC hung; stop the round.
    Wedged,
    /// The nonce is already mined.
    NonceTooLow,
    /// This very transaction is already in the pool.
    Known,
    /// A different transaction paying at least as much is pending at the nonce.
    Occupied,
    /// The fees are too low for the node (full pool, minimum tip, base fee);
    /// nothing was added.
    Underpriced,
    /// The estimate reverted: the payload itself is refused.
    Refused,
    /// Any other error (account, RPC or unknown).
    Failed,
}

fn classify(error: &str) -> SendError {
    let e = error.to_ascii_lowercase();
    let any = |needles: &[&str]| needles.iter().any(|n| e.contains(n));
    // Only where a word starts: "unknown transaction type" is not "known
    // transaction", and taking it as one would adopt a nonce nothing holds.
    let any_word = |needles: &[&str]| needles.iter().any(|n| at_word_start(&e, n));
    if any(&["timed out"]) {
        SendError::Wedged
    } else if any(&[
        "nonce too low",
        "nonce has already been used",
        "nonce_expired",
    ]) {
        SendError::NonceTooLow
    } else if any_word(&["already known", "already imported", "known transaction"]) {
        SendError::Known
    } else if any(&[
        "replacement transaction underpriced",
        "replacement fee too low",
        "could not replace",
    ]) {
        SendError::Occupied
    } else if any(&[
        "underpriced",
        "txpool is full",
        "pool is full",
        "below minimum",
        "less than block base fee",
        "fee too low",
    ]) {
        SendError::Underpriced
    } else if any(&["revert"]) {
        SendError::Refused
    } else {
        SendError::Failed
    }
}

/// Whether `needle` occurs in `haystack` where a word starts (not right after a
/// letter or digit).
fn at_word_start(haystack: &str, needle: &str) -> bool {
    haystack.match_indices(needle).any(|(at, _)| {
        haystack[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric())
    })
}

/// `v` raised by at least 12.5% (and by at least 1 wei).
pub(crate) fn bumped(v: u128) -> u128 {
    v.saturating_add(v.div_ceil(8).max(1))
}

/// Fees for a first broadcast: the estimate with the priority floor, under the cap.
pub(crate) fn initial_fees(estimate: Fees, policy: &Policy) -> Fees {
    let priority = estimate.priority.max(policy.min_priority);
    let max_fee = estimate.max_fee.max(priority).min(policy.max_fee_cap);
    Fees {
        max_fee,
        priority: priority.min(max_fee),
    }
}

/// Fees replacing `old` at its nonce: both at least 12.5% higher and no lower
/// than the current estimate. `None` when the cap leaves no valid replacement.
pub(crate) fn replacement_fees(old: Fees, estimate: Option<Fees>, cap: u128) -> Option<Fees> {
    let floor = Fees {
        max_fee: bumped(old.max_fee),
        priority: bumped(old.priority),
    };
    let wanted = estimate.unwrap_or(floor);
    let priority = floor.priority.max(wanted.priority);
    let max_fee = floor.max_fee.max(wanted.max_fee).max(priority).min(cap);
    (max_fee >= floor.max_fee && max_fee >= floor.priority).then_some(Fees {
        max_fee,
        priority: priority.min(max_fee),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn h(n: u8) -> Digest {
        [n; 32]
    }
    fn answer(n: u8) -> ChallengeAnswer {
        ChallengeAnswer {
            order_hash: h(n),
            by_rejection: false,
            proof: vec![],
        }
    }
    /// One single-answer transaction per hash, batch = hash.
    fn sends(hashes: &[u8]) -> Vec<(u64, Vec<ChallengeAnswer>)> {
        hashes
            .iter()
            .map(|n| (*n as u64, vec![answer(*n)]))
            .collect()
    }

    struct TestClock {
        now: Cell<Instant>,
        start: Instant,
    }
    impl TestClock {
        fn new() -> Self {
            let start = Instant::now();
            Self {
                now: Cell::new(start),
                start,
            }
        }
        fn advance(&self, d: Duration) {
            self.now.set(self.now.get() + d);
        }
        fn elapsed(&self) -> Duration {
            self.now.get() - self.start
        }
    }
    impl Clock for TestClock {
        fn now(&self) -> Instant {
            self.now.get()
        }
        fn sleep(&self, d: Duration) {
            self.advance(d);
        }
    }

    #[derive(Clone)]
    struct PoolTx {
        hash: String,
        fees: Fees,
        hashes: Vec<Digest>,
    }

    /// A mempool and chain for one account. Replacement needs both fees 10%
    /// higher (geth's rule; the lane bumps by 12.5%). Mining takes pending
    /// transactions in nonce order while their max fee covers the base fee.
    #[derive(Default)]
    struct State {
        mined: u64,
        base_fee: u128,
        estimate: Option<Fees>,
        pool: BTreeMap<u64, PoolTx>,
        receipts: HashMap<String, bool>,
        /// Every accepted broadcast: (nonce, fees, batch, hashes).
        accepted: Vec<(u64, Fees, u64, Vec<Digest>)>,
        broadcasts: usize,
        /// Estimation refuses any transaction holding one of these.
        refuse: HashSet<Digest>,
        /// A mined transaction holding one of these reverts.
        revert: HashSet<Digest>,
        /// Errors returned by the next broadcasts, in order.
        fail_next: VecDeque<String>,
        reads_fail: bool,
        /// Mine on every `mined_nonce` read (a block between polls).
        auto_mine: bool,
        counter: u64,
        /// Hashes in transactions that mined and succeeded.
        answered: HashSet<Digest>,
        /// Every no-op broadcast fails with this error.
        cancel_fails: Option<String>,
        /// No-op broadcasts attempted, failed ones included.
        cancels: usize,
    }
    struct FakeChain(RefCell<State>);
    impl FakeChain {
        fn new() -> Self {
            Self(RefCell::new(State {
                base_fee: 50,
                estimate: Some(Fees {
                    max_fee: 100,
                    priority: 10,
                }),
                ..State::default()
            }))
        }
        fn s(&self) -> std::cell::RefMut<'_, State> {
            self.0.borrow_mut()
        }
        fn mine(&self) {
            self.mine_at_most(usize::MAX);
        }
        fn mine_at_most(&self, limit: usize) {
            let mut s = self.s();
            for _ in 0..limit {
                let mined = s.mined;
                let Some(tx) = s.pool.get(&mined).cloned() else {
                    break;
                };
                if tx.fees.max_fee < s.base_fee {
                    break;
                }
                let ok = !tx.hashes.iter().any(|x| s.revert.contains(x));
                if ok {
                    s.answered.extend(tx.hashes.iter().copied());
                }
                s.receipts.insert(tx.hash, ok);
                s.pool.remove(&mined);
                s.mined += 1;
            }
        }
        /// A transaction this process did not send takes the next nonce.
        fn mine_external(&self) {
            let mut s = self.s();
            let mined = s.mined;
            s.pool.remove(&mined);
            s.mined += 1;
        }
        /// A transaction sent before a restart, pending at `nonce`.
        fn preload(&self, nonce: u64, fees: Fees) {
            self.s().pool.insert(
                nonce,
                PoolTx {
                    hash: format!("0xold{nonce}"),
                    fees,
                    hashes: vec![],
                },
            );
        }
        fn accepted_nonces(&self) -> Vec<u64> {
            self.s().accepted.iter().map(|a| a.0).collect()
        }
        /// Nonces of accepted no-op transfers.
        fn cancelled_nonces(&self) -> Vec<u64> {
            let s = self.s();
            s.accepted
                .iter()
                .filter(|a| a.2 == CANCEL)
                .map(|a| a.0)
                .collect()
        }
        /// The pool's admission rules for one signed transaction.
        fn submit(
            &self,
            nonce: u64,
            fees: Fees,
            batch: u64,
            hashes: Vec<Digest>,
        ) -> Result<String, String> {
            let mut s = self.s();
            s.broadcasts += 1;
            if let Some(e) = s.fail_next.pop_front() {
                return Err(e);
            }
            if hashes.iter().any(|x| s.refuse.contains(x)) {
                return Err("execution reverted: NotIncluded()".into());
            }
            if nonce < s.mined {
                return Err("nonce too low".into());
            }
            if let Some(old) = s.pool.get(&nonce) {
                if old.fees == fees && old.hashes == hashes {
                    return Err("transaction already imported".into());
                }
                if fees.max_fee * 10 < old.fees.max_fee * 11
                    || fees.priority * 10 < old.fees.priority * 11
                {
                    return Err("replacement transaction underpriced".into());
                }
            }
            s.counter += 1;
            let hash = format!("0x{nonce:x}-{}", s.counter);
            s.pool.insert(
                nonce,
                PoolTx {
                    hash: hash.clone(),
                    fees,
                    hashes: hashes.clone(),
                },
            );
            s.accepted.push((nonce, fees, batch, hashes));
            Ok(hash)
        }
    }
    /// The batch an accepted no-op transfer is recorded under.
    const CANCEL: u64 = u64::MAX;
    impl AnswerChain for FakeChain {
        fn mined_nonce(&self) -> Result<u64, String> {
            if self.s().reads_fail {
                return Err("connection refused".into());
            }
            if self.s().auto_mine {
                self.mine();
            }
            Ok(self.s().mined)
        }
        fn pending_nonce(&self) -> Result<u64, String> {
            let s = self.s();
            Ok(s.pool.keys().next_back().map_or(s.mined, |n| n + 1))
        }
        fn fee_estimate(&self) -> Result<Fees, String> {
            self.s()
                .estimate
                .ok_or_else(|| "fee read failed".to_string())
        }
        fn broadcast(&self, tx: &AnswerTx<'_>) -> Result<String, String> {
            self.submit(
                tx.nonce,
                tx.fees,
                tx.batch,
                tx.answers.iter().map(|a| a.order_hash).collect(),
            )
        }
        fn cancel(&self, nonce: u64, fees: Fees) -> Result<String, String> {
            let fails = {
                let mut s = self.s();
                s.cancels += 1;
                s.cancel_fails.clone()
            };
            if let Some(error) = fails {
                self.s().broadcasts += 1;
                return Err(error);
            }
            self.submit(nonce, fees, CANCEL, vec![])
        }
        fn receipt(&self, tx_hash: &str) -> Result<Option<bool>, String> {
            Ok(self.s().receipts.get(tx_hash).copied())
        }
    }

    /// `FakeChain` behind a slow RPC: every call takes `cost` of round time.
    struct SlowChain<'a> {
        chain: &'a FakeChain,
        clock: &'a TestClock,
        cost: Duration,
    }
    impl AnswerChain for SlowChain<'_> {
        fn mined_nonce(&self) -> Result<u64, String> {
            self.clock.advance(self.cost);
            self.chain.mined_nonce()
        }
        fn pending_nonce(&self) -> Result<u64, String> {
            self.clock.advance(self.cost);
            self.chain.pending_nonce()
        }
        fn fee_estimate(&self) -> Result<Fees, String> {
            self.clock.advance(self.cost);
            self.chain.fee_estimate()
        }
        fn broadcast(&self, tx: &AnswerTx<'_>) -> Result<String, String> {
            self.clock.advance(self.cost);
            self.chain.broadcast(tx)
        }
        fn cancel(&self, nonce: u64, fees: Fees) -> Result<String, String> {
            self.clock.advance(self.cost);
            self.chain.cancel(nonce, fees)
        }
        fn receipt(&self, tx_hash: &str) -> Result<Option<bool>, String> {
            self.clock.advance(self.cost);
            self.chain.receipt(tx_hash)
        }
    }

    /// The fake chain's fee estimate, which `calm()` offers unchanged.
    const ESTIMATE: Fees = Fees {
        max_fee: 100,
        priority: 10,
    };

    /// Bumps never happen unless a test asks for them.
    fn calm() -> Policy {
        Policy {
            bump_after: Duration::from_secs(3600),
            round_budget: Duration::from_secs(6),
            poll_every: Duration::from_secs(2),
            min_priority: 1,
            max_fee_cap: 1_000,
            ..Policy::default()
        }
    }

    #[test]
    fn at_most_four_answer_transactions_are_in_flight() {
        let chain = FakeChain::new();
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        let report = lane.round(&chain, &clock, sends(&[1, 2, 3, 4, 5, 6]));
        assert_eq!(chain.accepted_nonces(), vec![0, 1, 2, 3]);
        assert_eq!(
            (report.submitted, report.in_flight, report.deferred),
            (4, 4, 2)
        );
        assert!(
            clock.elapsed() <= Duration::from_secs(6),
            "a round is bounded"
        );
        // The next read still lists every hash: in-flight ones are not resent and
        // the full lane takes nothing new.
        let report = lane.round(&chain, &clock, sends(&[1, 2, 3, 4, 5, 6]));
        assert_eq!(chain.accepted_nonces().len(), 4);
        assert_eq!((report.submitted, report.deferred), (0, 2));
        // Two mine; their slots go to the deferred answers at fresh nonces.
        chain.mine_at_most(2);
        let report = lane.round(&chain, &clock, sends(&[3, 4, 5, 6]));
        assert_eq!(report.mined, 2);
        assert_eq!(chain.accepted_nonces(), vec![0, 1, 2, 3, 4, 5]);
        let batches: Vec<u64> = chain.s().accepted[4..].iter().map(|a| a.2).collect();
        assert_eq!(batches, vec![5, 6]);
        assert_eq!(lane.in_flight(), 4);
    }

    #[test]
    fn mined_and_reverted_transactions_release_their_slots() {
        let chain = FakeChain::new();
        chain.s().revert.insert(h(2));
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        lane.round(&chain, &clock, sends(&[1, 2, 3, 4]));
        assert_eq!(lane.in_flight(), 4);
        chain.mine();
        // A read taken before the mining still lists every hash. The successful
        // ones are not resent; the reverted one is planned again at a new nonce.
        let report = lane.round(&chain, &clock, sends(&[1, 2, 3, 4]));
        assert_eq!((report.mined, report.answered, report.reverted), (3, 3, 1));
        assert_eq!(report.submitted, 1);
        let s = chain.s();
        let last = s.accepted.last().unwrap();
        assert_eq!((last.0, &last.3), (4, &vec![h(2)]));
        assert_eq!(s.accepted.len(), 5);
    }

    #[test]
    fn a_stuck_answer_is_replaced_at_the_same_nonce_until_the_caps() {
        let chain = FakeChain::new();
        chain.s().base_fee = 10_000; // nothing mines
        let clock = TestClock::new();
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            max_bumps: 3,
            round_budget: Duration::from_secs(100),
            ..calm()
        };
        let mut lane = Pipeline::new(policy);
        let report = lane.round(&chain, &clock, sends(&[1]));
        let accepted = chain.s().accepted.clone();
        assert!(accepted.iter().all(|a| a.0 == 0), "always nonce 0");
        let fees: Vec<Fees> = accepted.iter().map(|a| a.1).collect();
        assert_eq!(
            fees,
            vec![
                Fees {
                    max_fee: 100,
                    priority: 10
                },
                Fees {
                    max_fee: 113,
                    priority: 12
                },
                Fees {
                    max_fee: 128,
                    priority: 14
                },
                Fees {
                    max_fee: 144,
                    priority: 16
                },
            ]
        );
        for pair in fees.windows(2) {
            assert!(pair[1].max_fee * 8 >= pair[0].max_fee * 9);
            assert!(pair[1].priority * 8 >= pair[0].priority * 9);
        }
        assert_eq!((report.submitted, report.bumped), (1, 3));
        assert_eq!(report.at_fee_cap, 1, "the bump limit is reached");
        assert!(
            chain.s().broadcasts > 4,
            "past the limit the same transaction is only rebroadcast"
        );
        // The last replacement mines; the slot is released by its receipt.
        chain.s().base_fee = 140;
        chain.mine();
        let report = lane.round(&chain, &clock, vec![]);
        assert_eq!((report.mined, report.answered, report.in_flight), (1, 1, 0));

        // The fee cap stops bumping below the 12.5% step, and a rising estimate
        // is followed.
        let chain = FakeChain::new();
        chain.s().base_fee = 10_000;
        let clock = TestClock::new();
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            max_bumps: 100,
            max_fee_cap: 300,
            round_budget: Duration::from_secs(100),
            ..calm()
        };
        let mut lane = Pipeline::new(policy);
        chain.s().estimate = Some(Fees {
            max_fee: 100,
            priority: 10,
        });
        lane.round(&chain, &clock, sends(&[1]));
        chain.s().estimate = Some(Fees {
            max_fee: 250,
            priority: 20,
        });
        let report = lane.round(&chain, &clock, vec![]);
        let fees: Vec<Fees> = chain.s().accepted.iter().map(|a| a.1).collect();
        assert_eq!(
            fees[fees.len() - 2..],
            [
                Fees {
                    max_fee: 250,
                    priority: 24
                },
                Fees {
                    max_fee: 282,
                    priority: 27
                },
            ],
            "the estimate is followed, the priority still bumped by an eighth"
        );
        assert!(fees.iter().all(|f| f.max_fee <= 300), "{fees:?}");
        assert_eq!(report.at_fee_cap, 1, "318 would exceed the cap of 300");
    }

    #[test]
    fn replacement_fees_bump_both_fees_by_an_eighth_within_the_cap() {
        let old = Fees {
            max_fee: 1_000,
            priority: 100,
        };
        assert_eq!(
            replacement_fees(old, None, 10_000),
            Some(Fees {
                max_fee: 1_125,
                priority: 113
            })
        );
        // A higher estimate wins on either fee.
        assert_eq!(
            replacement_fees(
                old,
                Some(Fees {
                    max_fee: 2_000,
                    priority: 50
                }),
                10_000
            ),
            Some(Fees {
                max_fee: 2_000,
                priority: 113
            })
        );
        // Clamped to the cap while that still beats the old fee by 12.5%.
        assert_eq!(
            replacement_fees(
                old,
                Some(Fees {
                    max_fee: 5_000,
                    priority: 50
                }),
                1_200
            ),
            Some(Fees {
                max_fee: 1_200,
                priority: 113
            })
        );
        assert_eq!(replacement_fees(old, None, 1_124), None);
        // The priority fee never exceeds the max fee.
        assert_eq!(
            replacement_fees(
                Fees {
                    max_fee: 100,
                    priority: 100
                },
                Some(Fees {
                    max_fee: 100,
                    priority: 1_000
                }),
                10_000
            ),
            Some(Fees {
                max_fee: 1_000,
                priority: 1_000
            })
        );
        assert_eq!(bumped(0), 1);
        assert_eq!(bumped(7), 8);
        assert_eq!(bumped(8), 9);
        assert_eq!(bumped(9), 11);
        let policy = Policy {
            min_priority: 5,
            max_fee_cap: 80,
            ..Policy::default()
        };
        assert_eq!(
            initial_fees(
                Fees {
                    max_fee: 100,
                    priority: 1
                },
                &policy
            ),
            Fees {
                max_fee: 80,
                priority: 5
            }
        );
        assert_eq!(
            initial_fees(
                Fees {
                    max_fee: 2,
                    priority: 1
                },
                &policy
            ),
            Fees {
                max_fee: 5,
                priority: 5
            }
        );
    }

    #[test]
    fn a_restart_reads_the_chain_nonce_and_inherits_pending_transactions() {
        let chain = FakeChain::new();
        chain.s().mined = 7;
        let ok = Fees {
            max_fee: 100,
            priority: 10,
        };
        chain.preload(7, ok);
        chain.preload(8, ok);
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        let report = lane.round(&chain, &clock, sends(&[1, 2, 3, 4]));
        assert_eq!(chain.accepted_nonces(), vec![9, 10], "two inherited slots");
        assert_eq!((report.in_flight, report.deferred), (4, 2));
        chain.mine();
        let report = lane.round(&chain, &clock, sends(&[3, 4]));
        assert_eq!((report.replaced, report.mined), (2, 2));
        assert_eq!(chain.accepted_nonces(), vec![9, 10, 11, 12]);

        // A stuck inherited transaction is replaced by queued answers at its nonce.
        let chain = FakeChain::new();
        chain.s().mined = 3;
        chain.preload(
            3,
            Fees {
                max_fee: 20,
                priority: 1,
            },
        );
        let clock = TestClock::new();
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            max_in_flight: 1,
            round_budget: Duration::from_secs(30),
            ..calm()
        };
        let mut lane = Pipeline::new(policy);
        let report = lane.round(&chain, &clock, sends(&[5]));
        assert_eq!(chain.accepted_nonces(), vec![3]);
        assert_eq!(chain.s().accepted[0].3, vec![h(5)]);
        assert_eq!(
            (report.bumped, report.in_flight, report.deferred),
            (1, 1, 0)
        );
        chain.mine();
        let report = lane.round(&chain, &clock, vec![]);
        assert_eq!((report.mined, report.answered), (1, 1));
    }

    #[test]
    fn a_nonce_consumed_elsewhere_is_released_and_its_answers_retried() {
        let chain = FakeChain::new();
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        lane.round(&chain, &clock, sends(&[1]));
        chain.mine_external();
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!((report.replaced, report.submitted), (1, 1));
        assert_eq!(chain.accepted_nonces(), vec![0, 1]);
    }

    #[test]
    fn broadcast_errors_reseed_skip_occupied_nonces_isolate_refusals_or_stop() {
        // "nonce too low" at a fresh nonce: re-read the chain, then continue.
        let chain = FakeChain::new();
        chain.s().fail_next.push_back("nonce too low".into());
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!((report.submitted, chain.s().broadcasts), (1, 2));
        assert!(report.first_error.unwrap().contains("nonce too low"));
        // The mined nonce jumps past ours (another sender used the key).
        chain.mine();
        chain.s().mined = 5; // other transactions used the key meanwhile
        let report = lane.round(&chain, &clock, sends(&[2]));
        assert_eq!(report.submitted, 1);
        assert_eq!(chain.accepted_nonces(), vec![0, 5]);

        // Another transaction really pending at the next nonce (and paying more)
        // occupies a slot; the answer goes to the nonce after it, and every nonce
        // mines.
        let chain = FakeChain::new();
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        lane.round(&chain, &clock, sends(&[1]));
        chain.preload(
            1,
            Fees {
                max_fee: 1_000,
                priority: 100,
            },
        );
        let report = lane.round(&chain, &clock, sends(&[2]));
        assert_eq!(chain.accepted_nonces(), vec![0, 2]);
        assert_eq!(report.in_flight, 3);
        chain.mine();
        let report = lane.round(&chain, &clock, sends(&[2]));
        assert_eq!(chain.s().mined, 3, "no gap: every nonce mined");
        assert_eq!(
            (
                report.mined,
                report.answered,
                report.replaced,
                report.in_flight
            ),
            (2, 2, 1, 0)
        );

        // One refused entry is isolated by halving; the others go out.
        let chain = FakeChain::new();
        chain.s().refuse.insert(h(5));
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        let batch = vec![(9, (1..=8).map(answer).collect::<Vec<_>>())];
        let report = lane.round(&chain, &clock, batch);
        let sent: usize = chain.s().accepted.iter().map(|a| a.3.len()).sum();
        assert_eq!(sent, 7);
        assert!(!chain.s().accepted.iter().any(|a| a.3.contains(&h(5))));
        assert!(report.first_error.unwrap().contains("NotIncluded"));

        // A wedged RPC stops the round at once and keeps the answers queued.
        let chain = FakeChain::new();
        chain
            .s()
            .fail_next
            .push_back("cast timed out after 90s (RPC wedged)".into());
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        let report = lane.round(&chain, &clock, sends(&[1, 2]));
        assert_eq!(chain.s().broadcasts, 1);
        assert_eq!(report.deferred, 2);
        assert!(report.first_error.unwrap().contains("timed out"));
        assert_eq!(clock.elapsed(), Duration::ZERO);

        // A failed nonce read sends nothing.
        let chain = FakeChain::new();
        chain.s().reads_fail = true;
        let mut lane = Pipeline::new(calm());
        let report = lane.round(&chain, &TestClock::new(), sends(&[1]));
        assert_eq!((chain.s().broadcasts, report.deferred), (0, 1));
        assert!(report.first_error.is_some());
    }

    #[test]
    fn a_fee_refusal_at_a_fresh_nonce_retries_that_nonce_and_never_leaves_a_gap() {
        // Nothing is added to the pool for any of these, so skipping the nonce
        // would leave a gap no later transaction can mine past.
        for refusal in [
            "server returned an error response: error code -32000: transaction underpriced",
            "txpool is full",
            "gas price below minimum: gas tip cap 1, minimum needed 2",
            "max fee per gas less than block base fee",
            // Claimed occupied, but nothing is pending there (the pending nonce
            // says so).
            "replacement transaction underpriced",
        ] {
            let chain = FakeChain::new();
            chain.s().fail_next.push_back(refusal.into());
            let clock = TestClock::new();
            let mut lane = Pipeline::new(calm());
            let report = lane.round(&chain, &clock, sends(&[1]));
            assert_eq!(chain.accepted_nonces(), vec![0], "{refusal}: {report:?}");
            let fees = chain.s().accepted[0].1;
            assert!(
                fees.max_fee > 100 && fees.priority > 10,
                "{refusal}: retried with higher fees, got {fees:?}"
            );
            assert_eq!(report.in_flight, 1, "{refusal}");
            chain.mine();
            let report = lane.round(&chain, &clock, sends(&[1]));
            assert_eq!(
                (report.mined, report.answered, report.in_flight),
                (1, 1, 0),
                "{refusal}"
            );
        }

        // The reviewer's scenario: one transient refusal, then normal blocks.
        let chain = FakeChain::new();
        chain.s().fail_next.push_back(
            "server returned an error response: error code -32000: transaction underpriced".into(),
        );
        let clock = TestClock::new();
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            round_budget: Duration::from_secs(25),
            ..calm()
        };
        let mut lane = Pipeline::new(policy);
        let mut answered = lane.round(&chain, &clock, sends(&[1])).answered;
        for _ in 0..3 {
            chain.mine();
            clock.advance(Duration::from_secs(30));
            answered += lane.round(&chain, &clock, sends(&[1])).answered;
        }
        assert_eq!((chain.s().mined, answered), (1, 1));
        assert!(chain.accepted_nonces().iter().all(|n| *n == 0));
    }

    #[test]
    fn stuck_nonces_this_process_did_not_send_never_wedge_answers_behind_them() {
        // After a restart during a fee spike: two inherited transactions below the
        // base fee, the default four slots, and the planned answers at 9 and 10.
        let chain = FakeChain::new();
        chain.s().mined = 7;
        let low = Fees {
            max_fee: 20,
            priority: 1,
        };
        chain.preload(7, low);
        chain.preload(8, low);
        let clock = TestClock::new();
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            round_budget: Duration::from_secs(25),
            ..calm()
        };
        let mut lane = Pipeline::new(policy);
        let report = lane.round(&chain, &clock, sends(&[1, 2]));
        let mut answered = report.answered;
        assert_eq!(chain.accepted_nonces()[..2], [9, 10]);
        // Nothing is queued to take the stuck nonces over, so no-ops replace them
        // within the bump interval; the round names the blocking nonce.
        assert_eq!(chain.cancelled_nonces(), vec![7, 8]);
        assert_eq!(
            (report.cancelled, report.blocked_at, report.in_flight),
            (2, Some(7), 4),
            "{report:?}"
        );
        for _ in 0..5 {
            chain.mine();
            clock.advance(Duration::from_secs(30));
            // The open set stops listing the hashes once they are answered.
            let plan = if answered < 2 { sends(&[1, 2]) } else { vec![] };
            answered += lane.round(&chain, &clock, plan).answered;
        }
        assert_eq!(chain.s().mined, 11, "nonces 7 and 8 were filled");
        assert_eq!(answered, 2, "both answers mined");
        assert_eq!(lane.in_flight(), 0);

        // A stuck nonce that holds back nothing of ours is left to mine on its own.
        let chain = FakeChain::new();
        chain.s().mined = 7;
        chain.preload(7, low);
        let clock = TestClock::new();
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            round_budget: Duration::from_secs(25),
            ..calm()
        };
        let mut lane = Pipeline::new(policy);
        let report = lane.round(&chain, &clock, vec![]);
        assert_eq!(chain.s().broadcasts, 0);
        assert_eq!((report.blocked_at, report.in_flight), (Some(7), 1));

        // At the bump limit a no-op is only rebroadcast, and counts at the cap.
        let chain = FakeChain::new();
        chain.s().mined = 7;
        chain.s().base_fee = 10_000;
        chain.preload(7, low);
        let clock = TestClock::new();
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            max_bumps: 2,
            round_budget: Duration::from_secs(100),
            ..calm()
        };
        let mut lane = Pipeline::new(policy);
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(chain.cancelled_nonces(), vec![7, 7]);
        assert_eq!(chain.accepted_nonces(), vec![8, 7, 8, 7, 8]);
        assert_eq!((report.cancelled, report.at_fee_cap), (2, 2), "{report:?}");

        // The same with a nonce taken by an "already known" reply after a lost
        // broadcast: the answers it carries are ours and keep being bumped.
        let chain = FakeChain::new();
        chain.s().base_fee = 10_000;
        chain
            .s()
            .fail_next
            .push_back("cast timed out after 90s (RPC wedged)".into());
        let clock = TestClock::new();
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            round_budget: Duration::from_secs(25),
            ..calm()
        };
        let mut lane = Pipeline::new(policy);
        lane.round(&chain, &clock, sends(&[1]));
        // The timed-out send did reach the pool.
        chain.s().pool.insert(
            0,
            PoolTx {
                hash: "0xlost".into(),
                fees: Fees {
                    max_fee: 100,
                    priority: 10,
                },
                hashes: vec![h(1)],
            },
        );
        clock.advance(Duration::from_secs(30));
        lane.round(&chain, &clock, sends(&[1]));
        // The base fee settles above what the lost transaction pays: it mines only
        // once replaced with higher fees.
        chain.s().base_fee = 120;
        let mut answered = 0;
        for _ in 0..5 {
            chain.mine();
            clock.advance(Duration::from_secs(30));
            let plan = if answered < 1 { sends(&[1]) } else { vec![] };
            answered += lane.round(&chain, &clock, plan).answered;
        }
        assert!(chain.s().pool.is_empty(), "nothing left stuck");
        assert_eq!(chain.s().mined, 1);
        assert!(chain.accepted_nonces().iter().all(|n| *n == 0), "no gap");
        assert_eq!(answered, 1);
        assert_eq!(lane.in_flight(), 0);
    }

    #[test]
    fn refusals_in_an_earlier_batch_never_starve_answers_in_later_batches() {
        for bad in [9u8, 8, 12, 40] {
            let chain = FakeChain::new();
            for n in 1..=bad {
                chain.s().refuse.insert(h(n));
            }
            let clock = TestClock::new();
            let mut lane = Pipeline::new(calm());
            let plan = vec![
                (1, (1..=bad).map(answer).collect::<Vec<_>>()),
                (2, vec![answer(50)]),
            ];
            let report = lane.round(&chain, &clock, plan.clone());
            assert!(
                chain.s().accepted.iter().any(|a| a.3.contains(&h(50))),
                "bad={bad}: {report:?}"
            );
            assert!(report.first_error.unwrap().contains("NotIncluded"));
            // Isolated refusals are not bisected again by the next rounds.
            let before = chain.s().broadcasts;
            lane.round(&chain, &clock, plan);
            assert_eq!(chain.s().broadcasts, before, "bad={bad}");
        }

        // Many batches, each with one refused entry, all reach the chain.
        let chain = FakeChain::new();
        let clock = TestClock::new();
        let mut lane = Pipeline::new(Policy {
            max_in_flight: 64,
            ..calm()
        });
        let mut plan = Vec::new();
        for batch in 0..30u8 {
            let bad = 100 + batch;
            chain.s().refuse.insert(h(bad));
            plan.push((u64::from(batch), vec![answer(bad), answer(batch + 1)]));
        }
        lane.round(&chain, &clock, plan);
        let sent: HashSet<Digest> = chain
            .s()
            .accepted
            .iter()
            .flat_map(|a| a.3.clone())
            .collect();
        assert!((1..=30).all(|n| sent.contains(&h(n))), "{sent:?}");

        // Failures that are not the payload's fault still stop the round.
        let chain = FakeChain::new();
        for _ in 0..40 {
            chain
                .s()
                .fail_next
                .push_back("insufficient funds for gas * price + value".into());
        }
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        let report = lane.round(&chain, &clock, sends(&(1..=30).collect::<Vec<_>>()));
        assert_eq!(chain.s().broadcasts, calm().max_failures);
        assert!(report.first_error.unwrap().contains("insufficient funds"));
    }

    #[test]
    fn a_refused_payload_moves_behind_the_batches_planned_after_it() {
        // Batch 1 is refused entry by entry; batches 2 and 3 are clean. Every chain
        // call takes a second, so the round has room for a few broadcasts only.
        let chain = FakeChain::new();
        for n in 1..=64u8 {
            chain.s().refuse.insert(h(n));
        }
        let clock = TestClock::new();
        let slow = SlowChain {
            chain: &chain,
            clock: &clock,
            cost: Duration::from_secs(1),
        };
        let mut lane = Pipeline::new(Policy {
            round_budget: Duration::from_secs(10),
            ..calm()
        });
        let plan = vec![
            (1, (1..=64).map(answer).collect::<Vec<_>>()),
            (2, vec![answer(100)]),
            (3, vec![answer(101)]),
        ];
        let report = lane.round(&slow, &clock, plan);
        // The first refusal moves batch 1 behind the others: batches 2 and 3 take
        // the next two attempts and the first two nonces, and its halves follow.
        let accepted: Vec<(u64, u64)> = chain.s().accepted.iter().map(|a| (a.0, a.2)).collect();
        assert_eq!(accepted, vec![(0, 2), (1, 3)], "{report:?}");
        assert!(report.deferred > 0, "batch 1 is still being halved");
        assert!(report.first_error.unwrap().contains("NotIncluded"));
    }

    #[test]
    fn broadcast_errors_are_classified_by_what_they_say_about_the_nonce() {
        use SendError::*;
        for (error, kind) in [
            ("cast timed out after 90s (RPC wedged)", Wedged),
            ("nonce too low: next nonce 5, tx nonce 4", NonceTooLow),
            ("already known", Known),
            ("transaction already imported", Known),
            ("known transaction: 0xabc", Known),
            ("replacement transaction underpriced", Occupied),
            ("replacement fee too low", Occupied),
            ("could not replace existing tx", Occupied),
            ("transaction underpriced", Underpriced),
            ("txpool is full", Underpriced),
            ("gas price below minimum: gas tip cap 0", Underpriced),
            ("max fee per gas less than block base fee", Underpriced),
            ("execution reverted: NotIncluded()", Refused),
            (
                "server returned an error response: error code 3: execution reverted",
                Refused,
            ),
            ("insufficient funds for gas * price + value", Failed),
            ("error sending request: connection refused", Failed),
            // A needle inside a longer word says nothing: this transaction was
            // never added, so nothing of ours holds the nonce.
            ("Known transaction: 0xabc", Known),
            ("error code -32000: known transaction", Known),
            ("unknown transaction type", Failed),
            (
                "server returned an error response: error code -32602: unknown transaction type 0x7e",
                Failed,
            ),
        ] {
            assert_eq!(classify(error), kind, "{error}");
        }
    }

    #[test]
    fn unanswerable_hashes_never_reach_the_lane_and_a_full_lane_round_stays_bounded() {
        use crate::challenge_scan::Watcher;
        let mut orders = BTreeMap::new();
        orders.insert(0u64, (vec![h(1), h(2)], vec![]));
        let mut watcher = Watcher::default();
        let detail = |n: u8| crate::l1::OpenChallenge {
            order_hash: h(n),
            beneficiary: [0x33; 20],
            batch_id_hint: 0,
            opened_block: 10,
            open_batch_count: 0,
            stake: 1,
        };
        // Hash 9 is in no settled batch although batch 0 settled after it opened.
        watcher.observe(crate::l1::OpenSetRead {
            head: 20,
            batch_count: 1,
            hashes: vec![h(1), h(9), h(2)],
            details: vec![detail(9)],
        });
        let plan = watcher.plan(&orders);
        assert_eq!(plan.unanswerable, vec![h(9)]);

        // The lane is full of transactions that never mine.
        let chain = FakeChain::new();
        chain.s().base_fee = 10_000;
        let clock = TestClock::new();
        let policy = Policy {
            max_in_flight: 1,
            round_budget: Duration::from_secs(20),
            ..calm()
        };
        let mut lane = Pipeline::new(policy);
        let report = lane.round(&chain, &clock, plan.sends);
        assert!(clock.elapsed() <= Duration::from_secs(20), "bounded round");
        assert_eq!(report.in_flight, 1);
        assert!(chain.s().accepted.iter().all(|a| !a.3.contains(&h(9))));
    }

    #[test]
    fn interleaved_refusals_in_one_chunk_never_starve_its_good_answers_under_a_slow_chain() {
        // One 100-entry chunk with every second entry refused: clean payloads
        // exist only as single answers. Every chain call takes half a second and
        // a block mines between polls.
        let chain = FakeChain::new();
        chain.s().auto_mine = true;
        for n in (2..=100u8).step_by(2) {
            chain.s().refuse.insert(h(n));
        }
        let clock = TestClock::new();
        let slow = SlowChain {
            chain: &chain,
            clock: &clock,
            cost: Duration::from_millis(500),
        };
        let mut lane = Pipeline::new(Policy {
            min_priority: 1,
            max_fee_cap: 1_000,
            ..Policy::default()
        });
        // Twenty minutes of 30 s watcher ticks; the open set drops answered hashes.
        for _ in 0..40 {
            let tick = clock.now();
            let open: Vec<ChallengeAnswer> = (1..=100u8)
                .filter(|n| !chain.s().answered.contains(&h(*n)))
                .map(answer)
                .collect();
            let report = lane.round(&slow, &clock, vec![(1, open)]);
            assert!(clock.now() - tick <= Duration::from_secs(30), "{report:?}");
            clock.now.set(tick + Duration::from_secs(30));
        }
        let good = (1..=99u8).step_by(2);
        let answered = good
            .clone()
            .filter(|n| chain.s().answered.contains(&h(*n)))
            .count();
        assert_eq!(answered, 50, "every good answer in the chunk mined");
        assert!((2..=100u8)
            .step_by(2)
            .all(|n| !chain.s().answered.contains(&h(n))));
    }

    #[test]
    fn a_slow_chain_never_stretches_a_round_past_its_budget() {
        // Every payload is refused, so no slot ever fills: only the deadline ends
        // the fill loop.
        let chain = FakeChain::new();
        for n in 1..=200u8 {
            chain.s().refuse.insert(h(n));
        }
        let clock = TestClock::new();
        let cost = Duration::from_secs(1);
        let slow = SlowChain {
            chain: &chain,
            clock: &clock,
            cost,
        };
        let budget = Duration::from_secs(25);
        let mut lane = Pipeline::new(Policy {
            round_budget: budget,
            ..calm()
        });
        let report = lane.round(&slow, &clock, sends(&(1..=200).collect::<Vec<_>>()));
        assert!(clock.elapsed() <= budget + cost, "{:?}", clock.elapsed());
        assert!(report.deferred > 0, "{report:?}");

        // Eight stuck answers, each replacement a slow broadcast: the round stops
        // replacing at its deadline, lowest nonce first.
        let chain = FakeChain::new();
        chain.s().base_fee = 10_000; // nothing mines
        let clock = TestClock::new();
        let budget = Duration::from_secs(10);
        let mut lane = Pipeline::new(Policy {
            max_in_flight: 8,
            bump_after: Duration::from_secs(20),
            round_budget: budget,
            ..calm()
        });
        lane.round(&chain, &clock, sends(&[1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(lane.in_flight(), 8);
        clock.advance(Duration::from_secs(20));
        let cost = Duration::from_secs(2);
        let slow = SlowChain {
            chain: &chain,
            clock: &clock,
            cost,
        };
        let start = clock.now();
        let report = lane.round(&slow, &clock, vec![]);
        assert!(
            clock.now() - start <= budget + 2 * cost,
            "{:?}",
            clock.now() - start
        );
        assert!((1..8).contains(&report.bumped), "{report:?}");
        let replaced: Vec<u64> = chain.s().accepted[8..].iter().map(|a| a.0).collect();
        assert_eq!(replaced, (0..report.bumped as u64).collect::<Vec<_>>());
    }

    #[test]
    fn an_already_known_answer_that_mines_counts_as_answered_and_is_not_resent() {
        // A broadcast times out but reaches the pool; the next attempt at that
        // nonce is told the very transaction is already known.
        let chain = FakeChain::new();
        chain
            .s()
            .fail_next
            .push_back("cast timed out after 90s (RPC wedged)".into());
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        lane.round(&chain, &clock, sends(&[1]));
        chain.s().pool.insert(
            0,
            PoolTx {
                hash: "0xlost".into(),
                fees: ESTIMATE,
                hashes: vec![h(1)],
            },
        );
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!((report.submitted, report.in_flight), (1, 1), "{report:?}");
        assert!(report.first_error.is_none(), "{report:?}");
        chain.mine();
        assert!(chain.s().answered.contains(&h(1)));
        // A read taken before the mining still lists the hash.
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(
            (
                report.mined,
                report.answered,
                report.replaced,
                report.submitted
            ),
            (1, 1, 0, 0),
            "{report:?}"
        );
        assert!(chain.accepted_nonces().is_empty(), "nothing resent");
        assert_eq!(lane.in_flight(), 0);

        // The same when the known transaction mines after a replacement was sent
        // with a readable hash: the replacement has no receipt, the answers are in.
        let chain = FakeChain::new();
        chain.s().base_fee = 10_000;
        chain
            .s()
            .fail_next
            .push_back("cast timed out after 90s (RPC wedged)".into());
        let clock = TestClock::new();
        let mut lane = Pipeline::new(Policy {
            bump_after: Duration::from_secs(20),
            round_budget: Duration::from_secs(25),
            ..calm()
        });
        lane.round(&chain, &clock, sends(&[1]));
        chain.s().pool.insert(
            0,
            PoolTx {
                hash: "0xlost".into(),
                fees: ESTIMATE,
                hashes: vec![h(1)],
            },
        );
        clock.advance(Duration::from_secs(30));
        lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(chain.accepted_nonces(), vec![0], "bumped once");
        // The lost transaction mines before the replacement reaches a block.
        {
            let mut s = chain.s();
            s.pool.remove(&0);
            s.receipts.insert("0xlost".into(), true);
            s.answered.insert(h(1));
            s.mined = 1;
        }
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(
            (report.mined, report.answered, report.replaced),
            (1, 1, 0),
            "{report:?}"
        );
        assert_eq!(chain.accepted_nonces(), vec![0], "nothing resent");
    }

    #[test]
    fn a_replacement_told_already_known_counts_as_answered_once_its_nonce_mines() {
        // One pass per round, so each attempt is staged by hand.
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            round_budget: Duration::from_secs(1),
            ..calm()
        };
        let wedged = "cast timed out after 90s (RPC wedged)";

        // A bump times out but reaches the pool. The next bump at that nonce, at
        // the same fees, is told the very transaction is already known.
        let chain = FakeChain::new();
        chain.s().base_fee = 10_000; // nothing mines
        let clock = TestClock::new();
        let mut lane = Pipeline::new(policy.clone());
        lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(chain.accepted_nonces(), vec![0]);
        chain.s().fail_next.push_back(wedged.into());
        clock.advance(Duration::from_secs(20));
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert!(
            report.first_error.is_some_and(|e| e.contains("timed out")),
            "the bump timed out"
        );
        chain.s().pool.insert(
            0,
            PoolTx {
                hash: "0xlostbump".into(),
                fees: Fees {
                    max_fee: 113,
                    priority: 12,
                },
                hashes: vec![h(1)],
            },
        );
        clock.advance(Duration::from_secs(20));
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(report.bumped, 1, "{report:?}");
        assert!(report.first_error.is_none(), "{report:?}");
        // The lost bump mines; the one hash this process learned has no receipt.
        chain.s().base_fee = 110;
        chain.mine();
        assert!(chain.s().answered.contains(&h(1)));
        // A read taken before the mining still lists the hash.
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(
            (
                report.mined,
                report.answered,
                report.replaced,
                report.submitted
            ),
            (1, 1, 0, 0),
            "{report:?}"
        );
        assert_eq!(chain.accepted_nonces(), vec![0], "nothing resent");
        assert_eq!(lane.in_flight(), 0);

        // The same for queued answers taking over a stuck nonce this process did
        // not fill: the takeover times out but reaches the pool, and the next
        // takeover is told it is already known.
        let chain = FakeChain::new();
        chain.s().mined = 7;
        chain.s().base_fee = 10_000;
        chain.preload(
            7,
            Fees {
                max_fee: 20,
                priority: 1,
            },
        );
        let clock = TestClock::new();
        let mut lane = Pipeline::new(Policy {
            max_in_flight: 1,
            ..policy.clone()
        });
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!((report.in_flight, report.deferred), (1, 1), "{report:?}");
        chain.s().fail_next.push_back(wedged.into());
        clock.advance(Duration::from_secs(20));
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert!(
            report.first_error.is_some_and(|e| e.contains("timed out")),
            "the takeover timed out"
        );
        chain.s().pool.insert(
            7,
            PoolTx {
                hash: "0xlosttakeover".into(),
                fees: ESTIMATE,
                hashes: vec![h(1)],
            },
        );
        clock.advance(Duration::from_secs(20));
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!((report.bumped, report.deferred), (1, 0), "{report:?}");
        chain.s().base_fee = 50;
        chain.mine();
        assert!(chain.s().answered.contains(&h(1)));
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(
            (
                report.mined,
                report.answered,
                report.replaced,
                report.submitted
            ),
            (1, 1, 0, 0),
            "{report:?}"
        );
        assert!(chain.accepted_nonces().is_empty(), "nothing resent");
        assert_eq!(lane.in_flight(), 0);

        // A rebroadcast at the caps told "already known" learns nothing new: what
        // is pending there is the transaction whose hash this process holds. When
        // a transaction from elsewhere takes the nonce, the answers are sent again.
        let chain = FakeChain::new();
        chain.s().base_fee = 10_000;
        let clock = TestClock::new();
        let mut lane = Pipeline::new(Policy {
            max_bumps: 0,
            ..policy
        });
        lane.round(&chain, &clock, sends(&[1]));
        let before = chain.s().broadcasts;
        clock.advance(Duration::from_secs(20));
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(
            (chain.s().broadcasts - before, report.bumped),
            (1, 0),
            "rebroadcast unchanged: {report:?}"
        );
        assert!(report.first_error.is_none(), "{report:?}");
        chain.mine_external();
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(
            (
                report.mined,
                report.answered,
                report.replaced,
                report.submitted
            ),
            (0, 0, 1, 1),
            "{report:?}"
        );
        assert_eq!(chain.accepted_nonces(), vec![0, 1]);
    }

    #[test]
    fn a_failing_no_op_waits_longer_each_time_and_counts_toward_the_round_failures() {
        // A stuck inherited transaction at 7, our answer behind it at 8, and every
        // no-op broadcast fails with an error that is not about fees. One pass per
        // round, a round every 10 s.
        let chain = FakeChain::new();
        chain.s().mined = 7;
        chain.s().base_fee = 10_000; // nothing mines
        chain.s().cancel_fails = Some("insufficient funds for gas * price + value".into());
        chain.preload(
            7,
            Fees {
                max_fee: 20,
                priority: 1,
            },
        );
        let clock = TestClock::new();
        let mut lane = Pipeline::new(Policy {
            bump_after: Duration::from_secs(20),
            max_bumps: 3,
            round_budget: Duration::from_secs(1),
            ..calm()
        });
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!((report.submitted, report.in_flight), (1, 2), "{report:?}");
        let mut attempts = Vec::new();
        let mut run_until = |secs: u64, attempts: &mut Vec<u64>| {
            while clock.elapsed() < Duration::from_secs(secs) {
                clock.advance(Duration::from_secs(10));
                let before = chain.s().cancels;
                lane.round(&chain, &clock, vec![]);
                if chain.s().cancels > before {
                    attempts.push(clock.elapsed().as_secs());
                }
            }
        };
        run_until(1_000, &mut attempts);
        // Each failure in a row adds one 20 s interval to the wait, up to eight,
        // well past the bump limit of three.
        assert_eq!(attempts, vec![20, 60, 120, 200, 300, 420, 560, 720, 880]);
        assert!(chain.cancelled_nonces().is_empty());
        // The cause clears: the next attempt is accepted and the wait is back to
        // one interval, so the no-op is bumped as any replacement is.
        chain.s().cancel_fails = None;
        attempts.clear();
        run_until(1_100, &mut attempts);
        assert_eq!(attempts, vec![1_040, 1_060, 1_080, 1_100]);
        assert_eq!(chain.cancelled_nonces(), vec![7, 7, 7]);
        let report = lane.round(&chain, &clock, vec![]);
        assert_eq!(report.at_fee_cap, 2, "both nonces at the bump limit now");

        // Each failed no-op is a failure of its round: two stuck nonces and a
        // limit of one stop the round after the first attempt.
        let chain = FakeChain::new();
        chain.s().mined = 7;
        chain.s().base_fee = 10_000;
        chain.s().cancel_fails = Some("insufficient funds for gas * price + value".into());
        let low = Fees {
            max_fee: 20,
            priority: 1,
        };
        chain.preload(7, low);
        chain.preload(8, low);
        let clock = TestClock::new();
        let mut lane = Pipeline::new(Policy {
            bump_after: Duration::from_secs(20),
            round_budget: Duration::from_secs(25),
            max_failures: 1,
            ..calm()
        });
        let report = lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(chain.s().cancels, 1, "{report:?}");
        assert_eq!(
            chain.accepted_nonces(),
            vec![9],
            "the answer was not bumped"
        );
    }

    #[test]
    fn failing_no_ops_back_off_and_free_the_nonce_once_the_cause_clears() {
        // A stuck inherited transaction at 7 below the base fee, our answer behind
        // it at 8, and every no-op broadcast fails for a reason that is not about
        // its fees, for longer than the bump limit would allow.
        let chain = FakeChain::new();
        chain.s().mined = 7;
        chain.s().base_fee = 10_000; // nothing mines
        chain.s().cancel_fails = Some("insufficient funds for gas * price + value".into());
        chain.preload(
            7,
            Fees {
                max_fee: 20,
                priority: 1,
            },
        );
        let clock = TestClock::new();
        let policy = Policy {
            bump_after: Duration::from_secs(20),
            round_budget: Duration::from_secs(25),
            ..calm()
        };
        let max_bumps = policy.max_bumps as usize;
        let mut lane = Pipeline::new(policy);
        let mut answered = lane.round(&chain, &clock, sends(&[1])).answered;
        let rounds = 30;
        let mut report = RoundReport::default();
        for _ in 0..rounds {
            clock.advance(Duration::from_secs(30));
            report = lane.round(&chain, &clock, vec![]);
            // Every round says why the answers still wait, attempt or not.
            assert!(
                report
                    .first_error
                    .as_deref()
                    .is_some_and(|e| e.contains("insufficient funds")),
                "{report:?}"
            );
            assert_eq!(
                (report.blocked_at, report.in_flight),
                (Some(7), 2),
                "{report:?}"
            );
        }
        // Only our own answer at 8 is at its bump limit: failed no-ops use none
        // of the replacements at 7.
        assert_eq!(report.at_fee_cap, 1, "{report:?}");
        let failed = chain.s().cancels;
        assert!(
            failed > max_bumps,
            "the nonce is never given up: {failed} no-op attempts"
        );
        assert!(
            failed * 2 <= rounds,
            "each failure lengthens the wait: {failed} no-op attempts in {rounds} rounds"
        );
        assert!(chain.cancelled_nonces().is_empty());

        // The cause clears and the base fee falls, though not to what the
        // transaction at 7 pays: only a no-op frees the answer behind it.
        chain.s().cancel_fails = None;
        chain.s().base_fee = 50;
        for _ in 0..20 {
            chain.mine();
            clock.advance(Duration::from_secs(30));
            let plan = if answered < 1 { sends(&[1]) } else { vec![] };
            answered += lane.round(&chain, &clock, plan).answered;
        }
        let cancelled = chain.cancelled_nonces();
        assert!(
            !cancelled.is_empty() && cancelled.iter().all(|n| *n == 7),
            "{cancelled:?}"
        );
        assert_eq!(chain.s().mined, 9, "nonces 7 and 8 were filled");
        assert_eq!(answered, 1, "the answer mined");
        assert_eq!(lane.in_flight(), 0);
    }

    #[test]
    fn a_no_op_refused_for_its_fees_ends_the_run_of_failures_before_it() {
        // A stuck inherited transaction at 7, our answer behind it at 8, and the
        // no-op at 7 fails at 20 and 60 s for a reason that is not about its fees.
        // From 100 s the node refuses it for its fees instead. A round every 10 s.
        for refusal in [
            "replacement transaction underpriced",
            "transaction underpriced",
        ] {
            let chain = FakeChain::new();
            chain.s().mined = 7;
            chain.s().base_fee = 10_000; // nothing mines
            chain.s().cancel_fails = Some("insufficient funds for gas * price + value".into());
            chain.preload(
                7,
                Fees {
                    max_fee: 20,
                    priority: 1,
                },
            );
            let clock = TestClock::new();
            let mut lane = Pipeline::new(Policy {
                bump_after: Duration::from_secs(20),
                round_budget: Duration::from_secs(1),
                ..calm()
            });
            lane.round(&chain, &clock, sends(&[1]));
            let (mut attempts, mut errors) = (Vec::new(), Vec::new());
            while clock.elapsed() < Duration::from_secs(160) {
                clock.advance(Duration::from_secs(10));
                let at = clock.elapsed().as_secs();
                if at == 100 {
                    chain.s().cancel_fails = Some(refusal.into());
                }
                let before = chain.s().cancels;
                let report = lane.round(&chain, &clock, vec![]);
                if chain.s().cancels > before {
                    attempts.push(at);
                }
                errors.push((at, report.first_error));
            }
            // The fee refusal at 120 s ends the run of failures: the next attempt
            // is one interval later, and no round names the earlier failures.
            assert_eq!(attempts, vec![20, 60, 120, 140, 160], "{refusal}");
            for (at, error) in errors {
                if (20..120).contains(&at) {
                    assert!(
                        error
                            .as_deref()
                            .is_some_and(|e| e.contains("insufficient funds")),
                        "{refusal} at {at} s: {error:?}"
                    );
                } else {
                    assert_eq!(error, None, "{refusal} at {at} s");
                }
            }
        }
    }

    #[test]
    fn a_fee_refused_at_one_nonce_never_raises_the_first_offer_at_the_next() {
        // One attempt per round.
        let policy = Policy {
            round_budget: Duration::from_secs(1),
            ..calm()
        };
        let clock = TestClock::new();

        // Refused for its fees at 0; then "nonce too low" (the read node lags), and
        // the chain reread puts the answer at 1.
        let chain = FakeChain::new();
        chain.s().fail_next.extend([
            "transaction underpriced".to_string(),
            "nonce too low".to_string(),
        ]);
        let mut lane = Pipeline::new(policy.clone());
        lane.round(&chain, &clock, sends(&[1]));
        lane.round(&chain, &clock, sends(&[1]));
        chain.mine_external();
        lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(chain.s().accepted, vec![(1, ESTIMATE, 1, vec![h(1)])]);

        // Refused for its fees at 0; then another transaction paying more is
        // pending there, so the answer goes to 1.
        let chain = FakeChain::new();
        chain
            .s()
            .fail_next
            .push_back("transaction underpriced".into());
        let mut lane = Pipeline::new(policy.clone());
        lane.round(&chain, &clock, sends(&[1]));
        chain.preload(
            0,
            Fees {
                max_fee: 1_000,
                priority: 100,
            },
        );
        lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(chain.s().accepted, vec![(1, ESTIMATE, 1, vec![h(1)])]);

        // Refused for its fees at 0; then a transaction from elsewhere mines there.
        let chain = FakeChain::new();
        chain
            .s()
            .fail_next
            .push_back("transaction underpriced".into());
        let mut lane = Pipeline::new(policy);
        lane.round(&chain, &clock, sends(&[1]));
        chain.mine_external();
        lane.round(&chain, &clock, sends(&[1]));
        assert_eq!(chain.s().accepted, vec![(1, ESTIMATE, 1, vec![h(1)])]);
    }

    #[test]
    fn an_unrecognised_broadcast_error_never_skips_a_nonce() {
        let chain = FakeChain::new();
        chain
            .s()
            .fail_next
            .push_back("insufficient funds for gas * price + value".into());
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        let report = lane.round(&chain, &clock, sends(&[1, 2]));
        assert!(report
            .first_error
            .is_some_and(|e| e.contains("insufficient funds")));
        // Nothing was added at 0, so the next answer takes 0.
        assert_eq!(chain.accepted_nonces(), vec![0]);
        assert_eq!(chain.s().accepted[0].3, vec![h(2)]);
        // The failed answer goes out in a later round, at the next nonce.
        lane.round(&chain, &clock, sends(&[1, 2]));
        assert_eq!(chain.accepted_nonces(), vec![0, 1]);
        chain.mine();
        assert_eq!(chain.s().mined, 2, "no gap: every nonce mined");
        assert!(chain.s().pool.is_empty());
    }
}
