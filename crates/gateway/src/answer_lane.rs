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
//! Nothing is persisted. A fresh pipeline reads the mined and pending nonces from
//! the chain; transactions between them were sent before the restart and occupy
//! slots until they mine. When one of them is stuck, queued answers replace it at
//! its nonce.
//!
//! Rounds are bounded by `round_budget`, and nothing here feeds the settle gate:
//! the open-set read alone decides whether the settle loop may seal, and hashes no
//! settled batch can prove are never planned, so they never occupy the lane.
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
    /// Refused or failed broadcasts per round before the round stops.
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
            max_failures: 16,
        }
    }
}

/// Inherited transactions tracked after a restart, at most.
const MAX_INHERITED: u64 = 64;

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
    /// In-flight transactions at their bump limit or fee cap.
    pub at_fee_cap: usize,
    /// Transactions still in flight when the round returned.
    pub in_flight: usize,
    /// Planned answers left for a later round.
    pub deferred: usize,
    pub first_error: Option<String>,
}

/// The transactions at one nonce.
struct Slot {
    /// `None` for a transaction this process did not send (inherited at start).
    payload: Option<(u64, Vec<ChallengeAnswer>)>,
    /// Fees of the latest broadcast attempt at this nonce.
    fees: Option<Fees>,
    /// Every hash this process broadcast at this nonce.
    hashes: Vec<String>,
    bumps: u32,
    /// The latest broadcast attempt (or the start, for an inherited slot).
    since: Instant,
}

impl Slot {
    fn inherited(now: Instant) -> Self {
        Self {
            payload: None,
            fees: None,
            hashes: Vec::new(),
            bumps: 0,
            since: now,
        }
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
}

impl Pipeline {
    pub(crate) fn new(policy: Policy) -> Self {
        Self {
            policy,
            next_nonce: None,
            slots: BTreeMap::new(),
            recent: HashMap::new(),
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
        let ttl = self.policy.recent_ttl;
        self.recent
            .retain(|_, at| start.saturating_duration_since(*at) < ttl);
        // Admitted after the first reconcile, so answers whose transaction just
        // reverted or was replaced are planned again in this round.
        let mut sends = Some(sends);
        let mut queue = VecDeque::new();
        let mut failures = 0;
        loop {
            let now = clock.now();
            let stop = self.reconcile(chain, now, &mut report).and_then(|()| {
                if let Some(sends) = sends.take() {
                    queue = self.admit(sends);
                }
                self.work(chain, now, &mut queue, &mut report, &mut failures)
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
        report.in_flight = self.slots.len();
        report.deferred = queue
            .iter()
            .chain(sends.iter().flatten())
            .map(|(_, answers)| answers.len())
            .sum();
        report.at_fee_cap = self
            .slots
            .values()
            .filter(|slot| self.exhausted(slot))
            .count();
        report
    }

    /// Planned answers minus those already in flight or recently mined.
    fn admit(
        &self,
        sends: Vec<(u64, Vec<ChallengeAnswer>)>,
    ) -> VecDeque<(u64, Vec<ChallengeAnswer>)> {
        let in_flight: HashSet<Digest> = self
            .slots
            .values()
            .filter_map(|slot| slot.payload.as_ref())
            .flat_map(|(_, answers)| answers.iter().map(|a| a.order_hash))
            .collect();
        sends
            .into_iter()
            .filter_map(|(batch, answers)| {
                let answers: Vec<ChallengeAnswer> = answers
                    .into_iter()
                    .filter(|a| {
                        !in_flight.contains(&a.order_hash)
                            && !self.recent.contains_key(&a.order_hash)
                    })
                    .collect();
                (!answers.is_empty()).then_some((batch, answers))
            })
            .collect()
    }

    /// A slot that can no longer be replaced: only rebroadcast.
    fn exhausted(&self, slot: &Slot) -> bool {
        slot.payload.is_some()
            && slot.fees.is_some_and(|fees| {
                slot.bumps >= self.policy.max_bumps
                    || replacement_fees(fees, None, self.policy.max_fee_cap).is_none()
            })
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
            self.next_nonce = Some(pending);
        }
        self.release_below(chain, mined, now, report);
        let floor = self
            .slots
            .keys()
            .next_back()
            .map_or(mined, |n| n.saturating_add(1))
            .max(mined);
        let next = self.next_nonce.get_or_insert(floor);
        *next = (*next).max(floor);
        Ok(())
    }

    /// Replace stuck transactions, then fill free slots from `queue`. An error
    /// ends the round.
    fn work(
        &mut self,
        chain: &dyn AnswerChain,
        now: Instant,
        queue: &mut VecDeque<(u64, Vec<ChallengeAnswer>)>,
        report: &mut RoundReport,
        failures: &mut usize,
    ) -> Result<(), String> {
        let mut estimate: Option<Option<Fees>> = None;
        let stuck: Vec<u64> = self
            .slots
            .iter()
            .filter(|(_, slot)| now.saturating_duration_since(slot.since) >= self.policy.bump_after)
            .map(|(nonce, _)| *nonce)
            .collect();
        for nonce in stuck {
            let fees = *estimate.get_or_insert_with(|| chain.fee_estimate().ok());
            self.replace(chain, nonce, now, fees, queue, report)?;
        }

        while self.slots.len() < self.policy.max_in_flight {
            let Some((batch, answers)) = queue.pop_front() else {
                break;
            };
            let Some(estimate) = *estimate.get_or_insert_with(|| chain.fee_estimate().ok()) else {
                queue.push_front((batch, answers));
                return Err("the fee estimate is unavailable".into());
            };
            let fees = initial_fees(estimate, &self.policy);
            let Some(nonce) = self.next_nonce else {
                queue.push_front((batch, answers));
                break;
            };
            let sent = chain.broadcast(&AnswerTx {
                nonce,
                fees,
                batch,
                answers: &answers,
            });
            match sent {
                Ok(hash) => {
                    self.slots.insert(
                        nonce,
                        Slot {
                            payload: Some((batch, answers)),
                            fees: Some(fees),
                            hashes: vec![hash],
                            bumps: 0,
                            since: now,
                        },
                    );
                    self.next_nonce = Some(nonce + 1);
                    report.submitted += 1;
                }
                Err(error) => {
                    *failures += 1;
                    let kind = classify(&error);
                    report.first_error.get_or_insert(error.clone());
                    match kind {
                        SendError::Wedged => {
                            queue.push_front((batch, answers));
                            return Err(error);
                        }
                        // Something mined at this nonce: read the chain again.
                        SendError::NonceTooLow => {
                            queue.push_front((batch, answers));
                            self.next_nonce = None;
                            break;
                        }
                        // Something is already pending at this nonce.
                        SendError::Occupied => {
                            self.slots.insert(nonce, Slot::inherited(now));
                            self.next_nonce = Some(nonce + 1);
                            queue.push_front((batch, answers));
                        }
                        // Estimation refused the payload; the nonce is unused. Halve
                        // so one bad entry cannot hold back the others; a single
                        // refused entry waits for the next plan.
                        SendError::Refused => {
                            if answers.len() > 1 {
                                let mut left = answers;
                                let right = left.split_off(left.len() / 2);
                                queue.push_front((batch, right));
                                queue.push_front((batch, left));
                            }
                        }
                    }
                    if *failures >= self.policy.max_failures {
                        return Err(format!("{failures} answer broadcasts failed this round"));
                    }
                }
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
            let outcome = slot
                .hashes
                .iter()
                .rev()
                .find_map(|hash| chain.receipt(hash).ok().flatten());
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
    /// An inherited one is replaced by queued answers. Errors only for a wedged RPC.
    fn replace(
        &mut self,
        chain: &dyn AnswerChain,
        nonce: u64,
        now: Instant,
        estimate: Option<Fees>,
        queue: &mut VecDeque<(u64, Vec<ChallengeAnswer>)>,
        report: &mut RoundReport,
    ) -> Result<(), String> {
        let policy = &self.policy;
        let Some(slot) = self.slots.get_mut(&nonce) else {
            return Ok(());
        };
        let replacement = if slot.bumps >= policy.max_bumps {
            None
        } else {
            match slot.fees {
                Some(old) => replacement_fees(old, estimate, policy.max_fee_cap),
                None => estimate.map(|e| initial_fees(e, policy)),
            }
        };
        // Our own payload, or queued answers taking over an inherited nonce.
        let (payload, taken) = match &slot.payload {
            Some(payload) => (payload.clone(), false),
            None => {
                let Some(next) = queue.pop_front() else {
                    return Ok(());
                };
                (next, true)
            }
        };
        let (fees, bump) = match (replacement, slot.fees) {
            (Some(fees), _) => (fees, true),
            // At the caps: rebroadcast our transaction unchanged.
            (None, Some(fees)) if !taken => (fees, false),
            (None, _) => {
                if taken {
                    queue.push_front(payload);
                }
                slot.since = now;
                return Ok(());
            }
        };
        let sent = chain.broadcast(&AnswerTx {
            nonce,
            fees,
            batch: payload.0,
            answers: &payload.1,
        });
        slot.since = now;
        match sent {
            Ok(hash) => {
                if !slot.hashes.contains(&hash) {
                    slot.hashes.push(hash);
                }
                if bump {
                    slot.fees = Some(fees);
                    slot.bumps += 1;
                    report.bumped += 1;
                }
                if taken {
                    slot.payload = Some(payload);
                }
                Ok(())
            }
            Err(error) => {
                if taken {
                    queue.push_front(payload);
                }
                match classify(&error) {
                    SendError::Wedged => {
                        report.first_error.get_or_insert(error.clone());
                        Err(error)
                    }
                    // Mined meanwhile: the next poll releases the slot.
                    SendError::NonceTooLow => Ok(()),
                    // The pending transaction pays more than we knew (or is this
                    // very one): start the next attempt from these fees.
                    SendError::Occupied => {
                        if bump {
                            slot.fees = Some(fees);
                            slot.bumps += 1;
                        }
                        Ok(())
                    }
                    // The pending transaction stays; retry after the next interval.
                    SendError::Refused => {
                        report.first_error.get_or_insert(error);
                        Ok(())
                    }
                }
            }
        }
    }
}

/// How a broadcast failed.
#[derive(Debug, PartialEq, Eq)]
enum SendError {
    /// The RPC hung; stop the round.
    Wedged,
    /// The nonce is already mined.
    NonceTooLow,
    /// A transaction is already pending at the nonce (identical, or paying more).
    Occupied,
    /// The payload was refused (estimation reverted) or another error.
    Refused,
}

fn classify(error: &str) -> SendError {
    let e = error.to_ascii_lowercase();
    if e.contains("timed out") {
        SendError::Wedged
    } else if e.contains("nonce too low")
        || e.contains("nonce has already been used")
        || e.contains("nonce_expired")
    {
        SendError::NonceTooLow
    } else if e.contains("underpriced")
        || e.contains("already known")
        || e.contains("already imported")
        || e.contains("known transaction")
    {
        SendError::Occupied
    } else {
        SendError::Refused
    }
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
    }
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
            let mut s = self.s();
            s.broadcasts += 1;
            if let Some(e) = s.fail_next.pop_front() {
                return Err(e);
            }
            let hashes: Vec<Digest> = tx.answers.iter().map(|a| a.order_hash).collect();
            if hashes.iter().any(|x| s.refuse.contains(x)) {
                return Err("execution reverted: NotIncluded()".into());
            }
            if tx.nonce < s.mined {
                return Err("nonce too low".into());
            }
            if let Some(old) = s.pool.get(&tx.nonce) {
                if old.fees == tx.fees && old.hashes == hashes {
                    return Err("transaction already imported".into());
                }
                if tx.fees.max_fee * 10 < old.fees.max_fee * 11
                    || tx.fees.priority * 10 < old.fees.priority * 11
                {
                    return Err("replacement transaction underpriced".into());
                }
            }
            s.counter += 1;
            let hash = format!("0x{:x}-{}", tx.nonce, s.counter);
            s.pool.insert(
                tx.nonce,
                PoolTx {
                    hash: hash.clone(),
                    fees: tx.fees,
                    hashes: hashes.clone(),
                },
            );
            s.accepted.push((tx.nonce, tx.fees, tx.batch, hashes));
            Ok(hash)
        }
        fn receipt(&self, tx_hash: &str) -> Result<Option<bool>, String> {
            Ok(self.s().receipts.get(tx_hash).copied())
        }
    }

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

        // Something already pending at the next nonce occupies a slot.
        let chain = FakeChain::new();
        let clock = TestClock::new();
        let mut lane = Pipeline::new(calm());
        lane.round(&chain, &clock, sends(&[1]));
        chain
            .s()
            .fail_next
            .push_back("replacement transaction underpriced".into());
        let report = lane.round(&chain, &clock, sends(&[2]));
        assert_eq!(chain.accepted_nonces(), vec![0, 2]);
        assert_eq!(report.in_flight, 3);

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
    fn unanswerable_hashes_and_a_full_lane_never_hold_settlement() {
        use crate::challenge_scan::{Discovery, Watcher};
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
        let discovery = Discovery::default();
        let t0 = Instant::now();
        discovery.record_ok(t0);

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
        assert!(discovery
            .settle_permitted(t0, Duration::from_secs(90))
            .is_ok());
    }
}
