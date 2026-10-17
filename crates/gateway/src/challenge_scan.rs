//! Inclusion-challenge watcher. The settlement keeps its open challenges in an
//! enumerable set, so every tick reads the whole set at one canonical block and
//! answers what the locally retained settled batches can prove. Nothing depends
//! on event logs, a scan cursor or the deploy block, and a restart loses nothing.
//!
//! The settle loop refuses to seal while this tick's read failed (or no read is
//! fresh), so the gateway never makes progress while blind to challenges. An
//! open hash that no settled batch can prove does not hold settlement; it raises
//! an operator alert instead.
use crate::l1::{ChallengeAnswer, OpenChallenge, OpenSetRead};
use perp_core::hash::Digest;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// At most this many answers per `answerChallenges` transaction.
pub(crate) const ANSWER_CHUNK: usize = 100;
/// Keep every argument cast receives well below the 128 KiB single-argument
/// limit of Linux `execve`.
pub(crate) const MAX_ANSWER_ARG_BYTES: usize = 96 * 1024;
/// Stored details read per tick for hashes not seen before. Answering never
/// waits for details; they only classify hashes nobody can answer.
pub(crate) const MAX_NEW_DETAILS: usize = 64;
/// Consecutive failed reads before the discovery alert fires.
pub(crate) const DISCOVERY_ALERT_AFTER: u32 = 3;

/// Freshness of the open-set read, shared by the watcher and the settle loop.
#[derive(Clone, Default)]
pub(crate) struct Discovery(Arc<Mutex<DiscoveryState>>);

#[derive(Default)]
struct DiscoveryState {
    last_ok: Option<Instant>,
    last_failed: bool,
    consecutive_failures: u32,
}

impl Discovery {
    pub(crate) fn record_ok(&self, now: Instant) {
        let mut s = self.0.lock().unwrap_or_else(|p| p.into_inner());
        s.last_ok = Some(now);
        s.last_failed = false;
        s.consecutive_failures = 0;
    }
    /// Returns the number of consecutive failures, this one included.
    pub(crate) fn record_failure(&self) -> u32 {
        let mut s = self.0.lock().unwrap_or_else(|p| p.into_inner());
        s.last_failed = true;
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        s.consecutive_failures
    }
    /// Sealing needs a successful latest read no older than `max_age`.
    pub(crate) fn settle_permitted(&self, now: Instant, max_age: Duration) -> Result<(), String> {
        let s = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if s.last_failed {
            return Err("the latest open-challenge read failed".into());
        }
        match s.last_ok {
            Some(t) if now.saturating_duration_since(t) <= max_age => Ok(()),
            Some(_) => Err("the open-challenge read is stale".into()),
            None => Err("the open challenges have not been read yet".into()),
        }
    }
}

/// Where the answer for an order hash lives: the earliest settled batch whose
/// ordered list (then its rejected list) holds it, and the first position there.
/// This is the same choice `Gw::build_challenge_answer` makes.
#[derive(Default)]
pub(crate) struct AnswerIndex {
    by_hash: HashMap<Digest, (u64, bool, usize)>,
    indexed: BTreeSet<u64>,
}

impl AnswerIndex {
    /// Index every retained batch not indexed yet.
    pub(crate) fn extend(&mut self, batch_orders: &BTreeMap<u64, (Vec<Digest>, Vec<Digest>)>) {
        for (&batch, (ordered, rejected)) in batch_orders {
            if !self.indexed.insert(batch) {
                continue;
            }
            let entries = ordered
                .iter()
                .enumerate()
                .map(|(i, h)| (h, false, i))
                .chain(rejected.iter().enumerate().map(|(i, h)| (h, true, i)));
            for (hash, by_rejection, index) in entries {
                let key = (batch, by_rejection, index);
                self.by_hash
                    .entry(*hash)
                    .and_modify(|current| {
                        if key < *current {
                            *current = key;
                        }
                    })
                    .or_insert(key);
            }
        }
    }
    pub(crate) fn locate(&self, hash: &Digest) -> Option<(u64, bool, usize)> {
        self.by_hash.get(hash).copied()
    }
}

/// One tick's work.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct AnswerPlan {
    /// Answer transactions, each for one batch, in ascending batch order.
    pub sends: Vec<(u64, Vec<ChallengeAnswer>)>,
    /// Open hashes that no settled batch holds, although a batch at or after the
    /// one that had to include them is already settled locally.
    pub unanswerable: Vec<Digest>,
    /// Open hashes whose including batch has not settled yet (or whose stored
    /// details have not been read yet).
    pub awaiting: usize,
}

/// Watcher state kept across ticks. Only derived data: a restart rebuilds it.
#[derive(Default)]
pub(crate) struct Watcher {
    index: AnswerIndex,
    details: BTreeMap<Digest, OpenChallenge>,
    open: Vec<Digest>,
}

impl Watcher {
    /// Hashes whose stored details are already known.
    pub(crate) fn known(&self) -> BTreeSet<Digest> {
        self.details.keys().copied().collect()
    }

    /// Fold one open-set read in. Details of hashes that left the set are dropped.
    pub(crate) fn observe(&mut self, read: OpenSetRead) {
        let open: BTreeSet<Digest> = read.hashes.iter().copied().collect();
        self.details.retain(|h, _| open.contains(h));
        for c in read.details {
            if open.contains(&c.order_hash) {
                self.details.insert(c.order_hash, c);
            }
        }
        self.open = read.hashes;
    }

    /// Plan the answers for the current open set from the retained batches.
    pub(crate) fn plan(
        &mut self,
        batch_orders: &BTreeMap<u64, (Vec<Digest>, Vec<Digest>)>,
    ) -> AnswerPlan {
        self.index.extend(batch_orders);
        let mut by_batch: BTreeMap<u64, Vec<(Digest, bool, usize)>> = BTreeMap::new();
        let mut plan = AnswerPlan::default();
        for hash in &self.open {
            if let Some((batch, by_rejection, index)) = self.index.locate(hash) {
                by_batch
                    .entry(batch)
                    .or_default()
                    .push((*hash, by_rejection, index));
                continue;
            }
            let settled_past = self
                .details
                .get(hash)
                .is_some_and(|c| batch_orders.range(c.open_batch_count..).next().is_some());
            if settled_past {
                plan.unanswerable.push(*hash);
            } else {
                plan.awaiting += 1;
            }
        }
        for (batch, entries) in by_batch {
            let Some((ordered, rejected)) = batch_orders.get(&batch) else {
                continue;
            };
            let ordered_leaves: Vec<Digest> = ordered
                .iter()
                .map(|h| crate::withdrawals::inclusion_leaf(batch, h))
                .collect();
            let rejected_leaves: Vec<Digest> = rejected
                .iter()
                .map(|h| crate::withdrawals::rejection_leaf(batch, h))
                .collect();
            let answers: Vec<ChallengeAnswer> = entries
                .into_iter()
                .map(|(order_hash, by_rejection, index)| ChallengeAnswer {
                    order_hash,
                    by_rejection,
                    proof: crate::withdrawals::merkle_proof(
                        if by_rejection {
                            &rejected_leaves
                        } else {
                            &ordered_leaves
                        },
                        index,
                    ),
                })
                .collect();
            for chunk in chunk_answers(answers) {
                plan.sends.push((batch, chunk));
            }
        }
        plan
    }
}

/// Split answers into transactions of at most `ANSWER_CHUNK` entries whose proof
/// argument stays under `MAX_ANSWER_ARG_BYTES`.
pub(crate) fn chunk_answers(answers: Vec<ChallengeAnswer>) -> Vec<Vec<ChallengeAnswer>> {
    let mut chunks = Vec::new();
    let mut current: Vec<ChallengeAnswer> = Vec::new();
    let mut bytes = 0usize;
    for answer in answers {
        // One "0x"+64 hex word plus a separator per proof element, plus brackets.
        let size = answer.proof.len() * 67 + 3;
        if !current.is_empty()
            && (current.len() == ANSWER_CHUNK || bytes + size > MAX_ANSWER_ARG_BYTES)
        {
            chunks.push(std::mem::take(&mut current));
            bytes = 0;
        }
        bytes += size;
        current.push(answer);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Send planned answers. A failed multi-entry send is retried as two halves, so
/// one entry the chain refuses cannot hold back the others. Stops early once a
/// send times out (the RPC is wedged; the next tick retries). Returns the
/// number of answers that landed and the first error.
pub(crate) fn send_answers(
    sends: Vec<(u64, Vec<ChallengeAnswer>)>,
    mut send: impl FnMut(u64, &[ChallengeAnswer]) -> Result<String, String>,
) -> (usize, Option<String>) {
    let mut answered = 0;
    let mut first_error = None;
    let mut work: Vec<(u64, Vec<ChallengeAnswer>)> = sends.into_iter().rev().collect();
    while let Some((batch, answers)) = work.pop() {
        match send(batch, &answers) {
            Ok(_) => answered += answers.len(),
            Err(error) => {
                let wedged = error.contains("timed out");
                first_error.get_or_insert(error);
                if wedged {
                    break;
                }
                if answers.len() > 1 {
                    let mut left = answers;
                    let right = left.split_off(left.len() / 2);
                    work.push((batch, right));
                    work.push((batch, left));
                }
            }
        }
    }
    (answered, first_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Digest {
        [n; 32]
    }
    fn challenge(n: u8, open_batch_count: u64) -> OpenChallenge {
        OpenChallenge {
            order_hash: h(n),
            beneficiary: [0x33; 20],
            batch_id_hint: 0,
            opened_block: 10,
            open_batch_count,
            stake: 10_000_000_000_000_000,
        }
    }
    fn read(hashes: &[u8], details: Vec<OpenChallenge>) -> OpenSetRead {
        OpenSetRead {
            head: 20,
            batch_count: 3,
            hashes: hashes.iter().map(|n| h(*n)).collect(),
            details,
        }
    }

    #[test]
    fn discovery_gates_settlement_on_a_fresh_successful_read() {
        let d = Discovery::default();
        let t0 = Instant::now();
        let age = Duration::from_secs(90);
        assert!(d.settle_permitted(t0, age).is_err(), "no read yet");
        d.record_ok(t0);
        assert!(d
            .settle_permitted(t0 + Duration::from_secs(60), age)
            .is_ok());
        assert!(
            d.settle_permitted(t0 + Duration::from_secs(91), age)
                .is_err(),
            "stale"
        );
        assert_eq!(d.record_failure(), 1);
        assert!(d.settle_permitted(t0, age).is_err(), "this tick failed");
        assert_eq!(d.record_failure(), 2);
        d.record_ok(t0);
        assert!(d.settle_permitted(t0, age).is_ok());
        assert_eq!(d.record_failure(), 1, "a success resets the streak");
    }

    #[test]
    fn index_matches_build_challenge_answer_earliest_batch_choice() {
        // Hash 1 is ordered in batch 2 and rejected in batch 1; hash 2 is rejected
        // and ordered in the same batch; hash 3 repeats inside one list.
        let mut orders = BTreeMap::new();
        orders.insert(2, (vec![h(1), h(3), h(3)], vec![]));
        orders.insert(1, (vec![h(2)], vec![h(1), h(2)]));
        let mut index = AnswerIndex::default();
        index.extend(&orders);
        assert_eq!(index.locate(&h(1)), Some((1, true, 0)));
        assert_eq!(index.locate(&h(2)), Some((1, false, 0)));
        assert_eq!(index.locate(&h(3)), Some((2, false, 1)));
        assert_eq!(index.locate(&h(4)), None);
        // A later, lower batch still wins once indexed.
        orders.insert(0, (vec![h(3)], vec![]));
        index.extend(&orders);
        assert_eq!(index.locate(&h(3)), Some((0, false, 0)));
    }

    #[test]
    fn plan_groups_by_batch_with_verifying_proofs() {
        let mut orders = BTreeMap::new();
        orders.insert(4, (vec![h(1), h(2), h(3)], vec![h(4)]));
        orders.insert(5, (vec![h(5)], vec![]));
        let mut w = Watcher::default();
        w.observe(read(&[3, 4, 5, 1], vec![]));
        let plan = w.plan(&orders);
        assert!(plan.unanswerable.is_empty());
        assert_eq!(plan.awaiting, 0);
        assert_eq!(plan.sends.len(), 2);
        let (batch, answers) = &plan.sends[0];
        assert_eq!(*batch, 4);
        assert_eq!(
            answers
                .iter()
                .map(|a| (a.order_hash, a.by_rejection))
                .collect::<Vec<_>>(),
            vec![(h(3), false), (h(4), true), (h(1), false)]
        );
        let ordered_root = perp_core::merkle::merkle_root(
            &[h(1), h(2), h(3)]
                .iter()
                .map(|x| crate::withdrawals::inclusion_leaf(4, x))
                .collect::<Vec<_>>(),
        );
        let rejected_root =
            perp_core::merkle::merkle_root(&[crate::withdrawals::rejection_leaf(4, &h(4))]);
        for a in answers {
            let (root, leaf) = if a.by_rejection {
                (
                    rejected_root,
                    crate::withdrawals::rejection_leaf(4, &a.order_hash),
                )
            } else {
                (
                    ordered_root,
                    crate::withdrawals::inclusion_leaf(4, &a.order_hash),
                )
            };
            assert!(perp_core::merkle::verify(root, leaf, &a.proof));
        }
        assert_eq!(plan.sends[1].0, 5);
    }

    #[test]
    fn plan_flags_unanswerable_only_after_its_batch_settled_locally() {
        let mut orders = BTreeMap::new();
        orders.insert(0, (vec![h(1)], vec![]));
        let mut w = Watcher::default();
        // Hash 9 opened before batch 0 settled; batch 0 does not hold it.
        // Hash 8 opened at batch count 1; batch 1 is not settled yet.
        // Hash 7 has no stored details yet.
        w.observe(read(&[9, 8, 7], vec![challenge(9, 0), challenge(8, 1)]));
        let plan = w.plan(&orders);
        assert!(plan.sends.is_empty());
        assert_eq!(plan.unanswerable, vec![h(9)]);
        assert_eq!(plan.awaiting, 2);
        // Batch 1 settles without hash 8, so it is unanswerable too.
        orders.insert(1, (vec![h(2)], vec![]));
        let plan = w.plan(&orders);
        assert_eq!(plan.unanswerable, vec![h(9), h(8)]);
        // A hash that left the open set is forgotten with its details.
        w.observe(read(&[8], vec![]));
        assert_eq!(w.known(), BTreeSet::from([h(8)]));
        assert_eq!(w.plan(&orders).unanswerable, vec![h(8)]);
    }

    #[test]
    fn chunks_respect_entry_and_argument_limits() {
        let answer = |n: usize, depth: usize| ChallengeAnswer {
            order_hash: [n as u8; 32],
            by_rejection: false,
            proof: vec![[0; 32]; depth],
        };
        let chunks = chunk_answers((0..250).map(|n| answer(n, 1)).collect());
        assert_eq!(
            chunks.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![100, 100, 50]
        );
        // Deep proofs split before the argument limit.
        let chunks = chunk_answers((0..100).map(|n| answer(n, 30)).collect());
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            let args = crate::l1::answer_challenges_args(1, chunk);
            assert!(args.iter().all(|a| a.len() <= MAX_ANSWER_ARG_BYTES + 1024));
        }
        assert_eq!(chunks.iter().map(Vec::len).sum::<usize>(), 100);
    }

    #[test]
    fn a_refused_entry_is_isolated_by_halving_and_a_timeout_stops_the_tick() {
        let answer = |n: u8| ChallengeAnswer {
            order_hash: [n; 32],
            by_rejection: false,
            proof: vec![],
        };
        let sends = vec![
            (1, (0..8).map(answer).collect::<Vec<_>>()),
            (2, vec![answer(9)]),
        ];
        let mut calls = 0;
        let (answered, error) = send_answers(sends.clone(), |_, answers| {
            calls += 1;
            if answers.iter().any(|a| a.order_hash == [5; 32]) {
                Err("execution reverted: NotIncluded".into())
            } else {
                Ok("0xtx".into())
            }
        });
        assert_eq!(answered, 8, "all but the refused entry land");
        assert!(error.unwrap().contains("NotIncluded"));
        assert!(calls > 2);
        let mut calls = 0;
        let (answered, error) = send_answers(sends, |_, _| {
            calls += 1;
            Err("cast timed out after 90s (RPC wedged)".into())
        });
        assert_eq!((answered, calls), (0, 1));
        assert!(error.is_some());
    }
}
