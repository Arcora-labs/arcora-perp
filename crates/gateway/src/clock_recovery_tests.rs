//! The settle loop's recovery of a clock window: the pure decision ([`decide`])
//! and whole steps ([`run_step`]) against a fake chain, with a real gateway, a
//! journal on disk and an acknowledging snapshot writer.
use super::*;
use crate::deposit_ingestion::tests::{chained_blocks, fresh, permit, settle_open_window};
use crate::deposit_ingestion::Purpose;
use crate::live_void::tests::{ingest, published, seal, voidable, Voidable};
use crate::service_shutdown::Shutdown;
use crate::settle_health::{Health, SettleHealth};
use crate::{Gw, Withdrawal};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Mutex as StdMutex;

const SKEW_MS: u64 = 30_000;
const RECEIPT: Digest = [0x5a; 32];

/// The settlement as the fake chain answers it.
struct ChainState {
    batch_count: u64,
    root: Digest,
    slot: AnchorSlot,
    close_only: bool,
    /// The sequencer's finalized nonce.
    nonce: u64,
    /// A sequencer-key transaction is pending: the nonces are not quiet.
    pending: bool,
    block_time_ms: Option<u64>,
    /// Evidence reads that fail before one succeeds.
    failing_reads: u32,
    /// The recorded nonce ceiling, every sequencer-key send included.
    global_ceiling: Ceiling,
    /// What each settle attempt does: `Ok` lands it, `Err` fails with the text.
    resumes: VecDeque<Result<(), String>>,
    /// A burn sends nothing.
    burn_fails: bool,
    budget: CloseOnlyBudget,
    settle_held: Option<String>,
    // What the step did.
    ceilings: Vec<Ceiling>,
    burned: Vec<u64>,
    reproves: Vec<bool>,
    corroborated: u32,
}

/// Where a call blocks until the test releases it.
struct Hook {
    at: &'static str,
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

struct FakeChain {
    s: StdMutex<ChainState>,
    hook: StdMutex<Option<Hook>>,
}

impl FakeChain {
    fn hook(&self, at: &str) {
        let hook = {
            let mut slot = self.hook.lock().unwrap();
            match slot.as_ref() {
                Some(h) if h.at == at => slot.take(),
                _ => None,
            }
        };
        if let Some(h) = hook {
            h.entered.send(()).unwrap();
            h.release.recv().unwrap();
        }
    }
    fn with<T>(&self, f: impl FnOnce(&mut ChainState) -> T) -> T {
        f(&mut self.s.lock().unwrap())
    }
}

impl RecoveryChain for FakeChain {
    fn evidence(&self, i: &ClockIntent, ceiling: Ceiling) -> Result<DeadIntentEvidence, String> {
        self.hook("evidence");
        let mut s = self.s.lock().unwrap();
        s.ceilings.push(ceiling);
        assert!(i.batch <= s.batch_count + 1, "the intent of another window");
        if s.failing_reads > 0 {
            s.failing_reads -= 1;
            return Err("finalized block read timed out".into());
        }
        Ok(DeadIntentEvidence {
            block: 100,
            batch_count: s.batch_count,
            state_root: s.root,
            close_only: s.close_only,
            slot: s.slot,
            nonce: s.nonce,
            fence_passed: ceiling.passed_by(s.nonce),
            quiet: !s.pending,
            seen_nonces: Some((s.nonce, s.nonce + u64::from(s.pending))),
            block_time_ms: s.block_time_ms,
            clock_skew_ms: SKEW_MS,
        })
    }
    fn burn_nonce(&self, expected: u64) -> Result<String, String> {
        let mut s = self.s.lock().unwrap();
        s.burned.push(expected);
        if s.burn_fails || s.nonce != expected {
            return Err(format!(
                "the sequencer's latest nonce is {}, not {expected}; nothing sent",
                s.nonce
            ));
        }
        // Mined and final at once.
        s.nonce += 1;
        Ok("0xburn".into())
    }
    fn resume(
        &self,
        j: &mut RollbackJournal,
        path: &Path,
        seed: &[u8; 32],
        reprove: bool,
    ) -> Result<(u64, String, u128), String> {
        self.hook("resume");
        let next = {
            let mut s = self.s.lock().unwrap();
            s.reproves.push(reprove);
            s.resumes
                .pop_front()
                .unwrap_or_else(|| Err("no settle attempt was scripted".into()))
        };
        next?;
        let mut prepared = crate::prover_client::prove_and_prepare(
            &crate::prover_client::MockProverClient,
            &j.witness,
            &j.ww,
        )?;
        prepared.outcome.proof = bound_proof();
        let new_root = prepared.outcome.new_root;
        j.prepared = Some(prepared);
        rollback_journal::write(path, j, seed)?;
        let mut s = self.s.lock().unwrap();
        s.batch_count = j.batch_id + 1;
        s.root = new_root;
        Ok((s.batch_count, hex32(&s.root), 7))
    }
    fn corroborate(
        &self,
        _: u64,
        _: &PreparedSettle,
        _: &[[u8; 32]],
        _: bool,
    ) -> Result<(u128, Vec<[u8; 32]>, GateObservation), String> {
        self.s.lock().unwrap().corroborated += 1;
        Ok((7, Vec::new(), GateObservation::Inconclusive))
    }
    fn close_only_budget(&self) -> Result<CloseOnlyBudget, String> {
        Ok(self.s.lock().unwrap().budget)
    }
    fn settle_permitted(&self) -> Result<(), String> {
        self.s
            .lock()
            .unwrap()
            .settle_held
            .clone()
            .map_or(Ok(()), Err)
    }
    fn nonce_ceiling(&self) -> Ceiling {
        self.s.lock().unwrap().global_ceiling
    }
    fn fail_stop(&self) -> ! {
        panic!("a live void post-check failed")
    }
}

/// A clock proof bound to the anchor `RECEIPT` names.
fn bound_proof() -> Vec<u8> {
    let mut proof = perp_core::clock::PROOF_MAGIC.to_vec();
    proof.extend(RECEIPT);
    proof.extend([7; 32]);
    proof
}

/// `j` with a durable proof bound to its anchor, as after a proof was journaled.
fn proved(mut j: RollbackJournal) -> RollbackJournal {
    j.prepared.as_mut().unwrap().outcome.proof = bound_proof();
    j
}

fn healthy_budget() -> CloseOnlyBudget {
    CloseOnlyBudget {
        head: 1_000,
        last_progress_block: 990,
        liveness_timeout_blocks: 1_000,
        oldest_unconsumed_deposit_block: None,
        close_only: false,
    }
}

/// The chain at the window's batch and pre-state root with no anchor in the
/// slot: the finalized block time is at the window's registration bound and the
/// nonce at the window's ceiling (5), so neither basis holds yet.
fn chain_at(j: &RollbackJournal) -> ChainState {
    let last_ms = ClockIntent::of(j).and_then(|i| i.last_ms).unwrap_or(1_000);
    ChainState {
        batch_count: j.batch_id,
        root: j.witness.pre_state.state_root(),
        slot: AnchorSlot::Empty,
        close_only: false,
        nonce: 5,
        pending: false,
        block_time_ms: Some(last_ms + SKEW_MS),
        failing_reads: 0,
        global_ceiling: Ceiling::Nonce(5),
        resumes: VecDeque::new(),
        burn_fails: false,
        budget: healthy_budget(),
        settle_held: None,
        ceilings: Vec::new(),
        burned: Vec::new(),
        reproves: Vec::new(),
        corroborated: 0,
    }
}

/// The finalized block time just past the window's registration bound.
fn past_skew(j: &RollbackJournal) -> Option<u64> {
    Some(ClockIntent::of(j).unwrap().last_ms.unwrap() + SKEW_MS + 1)
}

struct Harness {
    app: Shared,
    fake: Arc<FakeChain>,
    chain: Arc<dyn RecoveryChain>,
    journal: RollbackJournal,
    jpath: PathBuf,
    state: PathBuf,
    dir: PathBuf,
    seed: [u8; 32],
    fail_snapshots: Arc<AtomicBool>,
    /// One entry per snapshot written: whether the journal was still on disk.
    writes: Arc<StdMutex<Vec<bool>>>,
    stop: Shutdown,
    writer: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.writer.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn scratch_dir() -> PathBuf {
    let mut rnd = [0u8; 8];
    getrandom::getrandom(&mut rnd).unwrap();
    let sfx: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("darkperp-clock-recovery-{sfx}"));
    std::fs::create_dir_all(dir.join("journal")).unwrap();
    dir
}

/// A gateway whose sealed window `journal` failed after its intent was
/// journaled: the journal is on disk, admission is closed and sticky, and
/// snapshots are acknowledged once written.
fn harness(gw: Gw, journal: RollbackJournal, state: ChainState) -> Harness {
    harness_with(gw, journal, state, None)
}

/// [`harness`] with a deposit source for ingestion.
fn harness_with(
    mut gw: Gw,
    journal: RollbackJournal,
    state: ChainState,
    source: Option<Arc<dyn crate::deposit_rpc::DepositSource>>,
) -> Harness {
    gw.settle_health = SettleHealth::new(3, Duration::from_secs(30), Duration::from_secs(300));
    let dir = scratch_dir();
    let state_path = dir.join("state.snap");
    // In its own directory, so that a test can make its delete fail alone.
    let jpath = dir.join("journal").join("state.snap.rollback");
    let seed = [0x61; 32];
    rollback_journal::write(&jpath, &journal, &seed).unwrap();
    let mut app = crate::tests::test_app();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::SnapshotAck>(4);
    {
        let a = Arc::get_mut(&mut app).unwrap();
        a.clock_admission = crate::clock_admission::ClockAdmission::new(true);
        a.snapshot_req = Some(tx);
        a.gw = tokio::sync::Mutex::new(gw);
        a.l1 = Some(L1::test_clocked_reader(
            "http://127.0.0.1:9".into(),
            [0x11; 20],
            84532,
        ));
        a.deposit_source = source;
    }
    let fail_snapshots = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(StdMutex::new(Vec::new()));
    let writer = {
        let (app, fail, writes, state, jpath) = (
            app.clone(),
            fail_snapshots.clone(),
            writes.clone(),
            state_path.clone(),
            jpath.clone(),
        );
        tokio::spawn(async move {
            while let Some(ack) = rx.recv().await {
                if fail.load(Ordering::SeqCst) {
                    let _ = ack.send(false);
                    continue;
                }
                let plain = app.gw.lock().await.snapshot_plain();
                crate::snapshot::write_atomic(&state, &crate::snapshot::seal(&plain, &seed))
                    .unwrap();
                writes.lock().unwrap().push(jpath.exists());
                let _ = ack.send(true);
            }
        })
    };
    let fake = Arc::new(FakeChain {
        s: StdMutex::new(state),
        hook: StdMutex::new(None),
    });
    Harness {
        app,
        chain: fake.clone(),
        fake,
        journal,
        jpath,
        state: state_path,
        dir,
        seed,
        fail_snapshots,
        writes,
        stop: Shutdown::default(),
        writer,
    }
}

impl Harness {
    /// The recovery the loop starts when the window's attempt failed, with the
    /// window's ceiling at 5.
    fn pending(&self) -> PendingRecovery {
        PendingRecovery::new(
            self.journal.batch_id,
            0,
            "clock preparation: refused before broadcast".into(),
            Vec::new(),
            false,
            Ceiling::Nonce(5),
        )
    }
    /// Close admission and leave it sticky, as the sealed window does.
    async fn seal_hold(&self) {
        let mut paused = self.app.clock_admission.pause(&self.stop).await.unwrap();
        paused.as_mut().unwrap().arm();
    }
    async fn step(&self, rec: &mut PendingRecovery) -> Step {
        let mut admission = self.app.clock_admission.pause(&self.stop).await.unwrap();
        run_step(
            &self.app,
            &self.chain,
            rec,
            &self.jpath,
            &self.seed,
            &mut admission,
        )
        .await
    }
    /// One step in its own task, stopped where the fake chain's `at` call
    /// blocks until the returned sender releases it.
    async fn step_held_at(
        &self,
        at: &'static str,
        mut rec: PendingRecovery,
    ) -> (
        mpsc::Sender<()>,
        tokio::task::JoinHandle<(PendingRecovery, Step)>,
    ) {
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        *self.fake.hook.lock().unwrap() = Some(Hook {
            at,
            entered: entered_tx,
            release: release_rx,
        });
        let (app, chain, jpath, seed) = (
            self.app.clone(),
            self.chain.clone(),
            self.jpath.clone(),
            self.seed,
        );
        let task = tokio::spawn(async move {
            let stop = Shutdown::default();
            let mut admission = app.clock_admission.pause(&stop).await.unwrap();
            let step = run_step(&app, &chain, &mut rec, &jpath, &seed, &mut admission).await;
            (rec, step)
        });
        tokio::task::spawn_blocking(move || entered.recv().unwrap())
            .await
            .unwrap();
        (release, task)
    }
    fn admission_open(&self) -> bool {
        self.app.clock_admission.enter().is_ok()
    }
    fn alert(&self, gw: &Gw, kind: AlertKind) -> bool {
        let _ = self;
        gw.ops_alerts.active().contains(&kind)
    }
    /// The state the snapshot writer last made durable.
    fn durable(&self) -> Gw {
        let plain =
            crate::snapshot::open(&std::fs::read(&self.state).unwrap(), &self.seed).unwrap();
        Gw::boot_restored(&plain).unwrap()
    }
}

/// A settled window, then a sealed window that only credits a deposit: it holds
/// no timed operation.
fn untimed() -> (Gw, RollbackJournal) {
    let mut gw = fresh();
    let (_, settled) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
    let (_, later) = permit(&mut gw, 7_000_000, Purpose::Collateral, 0);
    let chain = chained_blocks(&gw, &[&[settled], &[later]]);
    assert_eq!(ingest(&mut gw, &chain), 1);
    settle_open_window(&mut gw);
    assert_eq!(ingest(&mut gw, &chain), 1);
    let j = seal(&mut gw);
    let i = ClockIntent::of(&j).unwrap();
    assert!(!i.timed && i.last_ms.is_none());
    (gw, j)
}

fn ops_bytes(ops: &[perp_core::engine::BatchOp]) -> Vec<u8> {
    postcard::to_allocvec(ops).unwrap()
}

fn evidence_for(j: &RollbackJournal, slot: AnchorSlot) -> DeadIntentEvidence {
    DeadIntentEvidence {
        block: 100,
        batch_count: j.batch_id,
        state_root: j.witness.pre_state.state_root(),
        close_only: false,
        slot,
        nonce: 5,
        fence_passed: false,
        quiet: true,
        seen_nonces: Some((5, 5)),
        block_time_ms: ClockIntent::of(j).unwrap().last_ms.map(|l| l + SKEW_MS),
        clock_skew_ms: SKEW_MS,
    }
}

/// Every row of the decision, in order, for a timed and an untimed window.
#[test]
fn decision_matrix() {
    let Voidable { journal, .. } = voidable(false);
    let (j, timed) = (&journal, ClockIntent::of(&journal).unwrap());
    let new_root = j.prepared.as_ref().unwrap().outcome.new_root;
    let pre_root = j.witness.pre_state.state_root();
    let p = PendingRecovery::new(
        j.batch_id,
        0,
        String::new(),
        Vec::new(),
        false,
        Ceiling::Nonce(5),
    );
    let decide_at = |i: &ClockIntent, committed, e: DeadIntentEvidence, p: &PendingRecovery| {
        decide(j, i, committed, Ok(&e), p)
    };
    let e = evidence_for(j, AnchorSlot::Matching);
    // 1. A failed read waits.
    assert_eq!(
        decide(j, &timed, pre_root, Err(()), &p),
        Decision::Wait(WaitReason::ReadFailed)
    );
    // 2.-4. The next batch: our root committed in memory, our root, another root,
    // with or without a durable proof.
    for journal in [j.clone(), proved(j.clone())] {
        let landed = DeadIntentEvidence {
            batch_count: j.batch_id + 1,
            state_root: new_root,
            ..e
        };
        let i = ClockIntent::of(&journal).unwrap();
        assert_eq!(
            decide(&journal, &i, new_root, Ok(&landed), &p),
            Decision::Stale
        );
        assert_eq!(
            decide(&journal, &i, pre_root, Ok(&landed), &p),
            Decision::RollForward
        );
        let other = DeadIntentEvidence {
            state_root: [0xee; 32],
            ..landed
        };
        assert!(matches!(
            decide(&journal, &i, pre_root, Ok(&other), &p),
            Decision::Stop(why) if why.contains("another state root")
        ));
    }
    // 5. At the window's batch with another root.
    assert!(matches!(
        decide_at(&timed, pre_root, DeadIntentEvidence { state_root: [0xee; 32], ..e }, &p),
        Decision::Stop(why) if why.contains("pre-state root")
    ));
    // 6. A phase-0 window in close-only returns, whatever the slot holds.
    for slot in [
        AnchorSlot::Matching,
        AnchorSlot::Empty,
        AnchorSlot::Different,
    ] {
        assert_eq!(
            decide_at(
                &timed,
                pre_root,
                DeadIntentEvidence {
                    close_only: true,
                    slot,
                    ..e
                },
                &p
            ),
            Decision::ReturnToOpenWindow { close_only: true }
        );
    }
    // 7. Our anchor is registered: settle again, without the fence.
    assert_eq!(decide_at(&timed, pre_root, e, &p), Decision::Retry);
    // 8. Another anchor: wait for the operator's cancel.
    assert_eq!(
        decide_at(
            &timed,
            pre_root,
            DeadIntentEvidence {
                slot: AnchorSlot::Different,
                ..e
            },
            &p
        ),
        Decision::Wait(WaitReason::Replaced)
    );
    // 9. An empty slot for a journaled receipt contradicts the journal.
    let journaled = ClockIntent::of(&proved(j.clone())).unwrap();
    assert!(matches!(
        decide_at(&journaled, pre_root, DeadIntentEvidence { slot: AnchorSlot::Empty, ..e }, &p),
        Decision::Stop(why) if why.contains("journaled receipt")
    ));
    // 10.-12. Dead: untimed returns, timed phase 0 is voided, a timed wind-down
    // window stops.
    let past = DeadIntentEvidence {
        slot: AnchorSlot::Empty,
        block_time_ms: timed.last_ms.map(|l| l + SKEW_MS + 1),
        ..e
    };
    assert_eq!(
        decide_at(&timed, pre_root, past, &p),
        Decision::LiveVoid(DeadIntent::EmptyAfterFence, DeadBasis::ChainClock)
    );
    assert_eq!(
        decide_at(
            &journaled,
            pre_root,
            DeadIntentEvidence {
                slot: AnchorSlot::Cancelled,
                ..past
            },
            &p
        ),
        Decision::LiveVoid(DeadIntent::Cancelled, DeadBasis::ChainClock)
    );
    let untimed = ClockIntent {
        timed: false,
        last_ms: None,
        ..timed
    };
    let fenced = DeadIntentEvidence {
        slot: AnchorSlot::Empty,
        nonce: 6,
        fence_passed: true,
        ..e
    };
    assert_eq!(
        decide_at(&untimed, pre_root, fenced, &p),
        Decision::ReturnToOpenWindow { close_only: false }
    );
    let underivable = ClockIntent {
        last_ms: None,
        underivable: true,
        ..timed
    };
    assert_eq!(
        decide_at(&underivable, pre_root, fenced, &p),
        Decision::LiveVoid(DeadIntent::EmptyAfterFence, DeadBasis::Fence)
    );
    assert!(matches!(
        decide_at(&ClockIntent { phase: 1, ..timed }, pre_root, past, &p),
        Decision::Stop(why) if why.contains("wind-down")
    ));
    // 13. The burn: no chain clock, the nonce at or below the window ceiling,
    // quiet on this and the previous step, burns left.
    let empty = DeadIntentEvidence {
        slot: AnchorSlot::Empty,
        ..e
    };
    let quiet = |steps, burns, ceiling| PendingRecovery {
        quiet_steps: steps,
        burns,
        ceiling,
        ..PendingRecovery::new(j.batch_id, 0, String::new(), Vec::new(), false, ceiling)
    };
    let eligible = quiet(2, 0, Ceiling::Nonce(5));
    for i in [untimed, underivable] {
        assert_eq!(decide_at(&i, pre_root, empty, &eligible), Decision::Burn(5));
        assert_eq!(
            decide_at(&i, pre_root, empty, &quiet(1, 0, Ceiling::Nonce(5))),
            Decision::Wait(WaitReason::NonceFence)
        );
        assert_eq!(
            decide_at(
                &i,
                pre_root,
                empty,
                &quiet(2, MAX_NONCE_BURNS, Ceiling::Nonce(5))
            ),
            Decision::Wait(WaitReason::NonceFence)
        );
        assert_eq!(
            decide_at(&i, pre_root, empty, &quiet(2, 0, Ceiling::Unknown)),
            Decision::Wait(WaitReason::NonceFence)
        );
        assert_eq!(
            decide_at(
                &i,
                pre_root,
                DeadIntentEvidence {
                    quiet: false,
                    ..empty
                },
                &eligible
            ),
            Decision::Wait(WaitReason::NotQuiet)
        );
        // Passed but not quiet: no burn, since the nonce is above the ceiling.
        assert_eq!(
            decide_at(
                &i,
                pre_root,
                DeadIntentEvidence {
                    nonce: 6,
                    fence_passed: true,
                    quiet: false,
                    ..empty
                },
                &eligible
            ),
            Decision::Wait(WaitReason::NotQuiet)
        );
    }
    // A timed window waits for the chain clock instead, unless its block has no
    // header-bound time.
    assert_eq!(
        decide_at(&timed, pre_root, empty, &eligible),
        Decision::Wait(WaitReason::ChainClock)
    );
    assert_eq!(
        decide_at(
            &timed,
            pre_root,
            DeadIntentEvidence {
                block_time_ms: None,
                ..empty
            },
            &eligible
        ),
        Decision::Burn(5)
    );
    // 15. A finalized head behind the window waits, whatever else it shows.
    for (bc, state_root) in [(j.batch_id - 1, pre_root), (j.batch_id - 1, [0xee; 32])] {
        assert_eq!(
            decide_at(
                &timed,
                pre_root,
                DeadIntentEvidence {
                    batch_count: bc,
                    state_root,
                    ..past
                },
                &p
            ),
            Decision::Wait(WaitReason::FinalizedBehind)
        );
    }
    // 16. Beyond the next batch.
    assert!(matches!(
        decide_at(
            &timed,
            pre_root,
            DeadIntentEvidence {
                batch_count: j.batch_id + 2,
                ..e
            },
            &p
        ),
        Decision::Stop(why) if why.contains("beyond window")
    ));
    // A journal without a prepared intent cannot be decided.
    let stage1 = RollbackJournal {
        prepared: None,
        ..j.clone()
    };
    assert!(matches!(
        decide(&stage1, &timed, pre_root, Ok(&e), &p),
        Decision::Stop(_)
    ));
}

/// The main case: the window's registration was refused before broadcast (its
/// estimate reverted past the skew), so its recorded nonce stays unused and the
/// fence never passes. The chain clock voids it without a restart. While it
/// waits `/api/state` shows the recovery; once the void is durable the owners
/// hear of it and the views show it.
#[tokio::test]
async fn a_never_broadcast_register_is_voided_by_the_chain_clock_without_restart() {
    let Voidable {
        gw,
        journal,
        chain,
        maker,
        taker,
        operator,
        withdrawal,
        w,
        consumed,
        ..
    } = voidable(false);
    let owner_of = |key: &[u8; 32]| crate::hex0x(&gw.accounts[key].wallet.owner);
    let (maker_owner, taker_owner, operator_owner) =
        (owner_of(&maker.key), owner_of(&taker), owner_of(&operator));
    let h = harness(gw, journal.clone(), chain_at(&journal));
    let window = journal.batch_id;
    let last_ms = ClockIntent::of(&journal).unwrap().last_ms.unwrap();
    h.seal_hold().await;
    let mut rec = h.pending();
    let mut events = h.app.events_tx.subscribe();
    // At the registration bound the chain clock has not passed: wait, closed.
    assert!(matches!(h.step(&mut rec).await, Step::Wait(_)));
    assert!(!h.admission_open());
    assert!(h.jpath.exists());
    assert_eq!(h.app.gw.lock().await.seq.state.next_batch_id, window + 1);
    {
        let gw = h.app.gw.lock().await;
        let state = serde_json::to_value(h.app.snapshot(&gw)).unwrap();
        assert!(state.get("settlementVoid").is_none());
        let r = &state["clockRecovery"];
        assert_eq!(r["batchId"], window);
        assert_eq!(r["phase"], 0);
        assert_eq!(r["steps"], 1);
        assert_eq!(r["last"], "awaiting the chain clock");
        assert_eq!(r["basis"], "chainClock");
        assert_eq!(
            r["chainClock"],
            serde_json::json!({
                "blockTimeMs": last_ms + SKEW_MS, "lastMs": last_ms, "skewMs": SKEW_MS,
            })
        );
        assert_eq!(
            r["fence"],
            serde_json::json!({
                "block": 100, "ceiling": 5, "finalizedNonce": 5, "latestNonce": 5,
                "pendingNonce": 5, "quiet": true, "passed": false,
            })
        );
        assert_eq!(
            r["closeOnlyBudget"],
            serde_json::json!({ "stalledBlocksLeft": 991, "starvedBlocksLeft": null })
        );
        assert_eq!(
            (r["burns"].clone(), r["retryFailures"].clone()),
            (0.into(), 0.into())
        );
        assert!(r["operatorAction"].is_null(), "waiting needs nobody");
        assert!(r["sinceMs"].as_u64().unwrap() <= crate::now_ms());
    }
    assert!(events.try_recv().is_err(), "nothing is voided yet");
    // Past it: voided, durable before the journal is deleted, and admission reopens.
    h.fake.with(|s| s.block_time_ms = past_skew(&journal));
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert!(h.admission_open());
    assert!(!h.jpath.exists());
    assert!(*h.writes.lock().unwrap().last().unwrap());
    // Each owner hears of what it lost: its order records, its withdrawal and
    // its deposits, which are credited again.
    let events: Vec<serde_json::Value> = std::iter::from_fn(|| events.try_recv().ok())
        .map(|e| serde_json::from_str(&e).unwrap())
        .collect();
    let of = |kind: &str| -> Vec<&serde_json::Value> {
        events.iter().filter(|e| e["type"] == kind).collect()
    };
    let executions = of("execution");
    assert_eq!(executions.len(), 2);
    for e in &executions {
        assert_eq!(e["execution"]["status"], "CANCELLED", "{e}");
        assert_eq!(e["execution"]["reason"], "WindowVoided", "{e}");
    }
    let mut order_owners: Vec<&str> = executions
        .iter()
        .map(|e| e["owner"].as_str().unwrap())
        .collect();
    order_owners.sort_unstable();
    let mut expected = vec![maker_owner.as_str(), taker_owner.as_str()];
    expected.sort_unstable();
    assert_eq!(order_owners, expected);
    assert_eq!(
        of("withdrawalVoided"),
        vec![&serde_json::json!({
            "type": "withdrawalVoided",
            "owner": crate::hex0x(&withdrawal.owner),
            "leaf": crate::hex0x(&withdrawal.leaf()),
            "amount": withdrawal.amount.to_string(),
            "nonce": withdrawal.nonce,
            "batchId": window,
        })]
    );
    let mut restored: Vec<(String, serde_json::Value)> = of("depositRestored")
        .iter()
        .map(|e| {
            assert_eq!(e["batchId"], window);
            (
                e["owner"].as_str().unwrap().to_string(),
                e["depositIds"].clone(),
            )
        })
        .collect();
    restored.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected = vec![
        (maker_owner, serde_json::json!([consumed])),
        (taker_owner, serde_json::json!([consumed + 1])),
        (operator_owner, serde_json::json!([consumed + 2])),
    ];
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(restored, expected);
    assert_eq!(events.len(), 2 + 1 + 3);
    {
        let gw = h.app.gw.lock().await;
        let state = serde_json::to_value(h.app.snapshot(&gw)).unwrap();
        assert!(state.get("clockRecovery").is_none(), "resolved");
        let notice = &state["settlementVoid"];
        assert_eq!(notice["batchId"], window);
        assert_eq!(notice["cause"], "EmptyAfterFence");
        assert_eq!(notice["orders"], published(&journal).len());
        assert_eq!(
            (
                notice["fills"].clone(),
                notice["withdrawals"].clone(),
                notice["deposits"].clone()
            ),
            (1.into(), 1.into(), 3.into())
        );
        assert!(notice["atMs"].as_u64().unwrap() <= crate::now_ms());
        // The withdrawer's view lists the voided withdrawal; nobody else's does.
        let view = gw.v1_withdrawals_json(&w.key).unwrap();
        assert_eq!(view["withdrawals"], serde_json::json!([]));
        assert_eq!(
            view["voided"],
            serde_json::json!([{
                "to": crate::hex0x(&withdrawal.to),
                "amount": withdrawal.amount.to_string(),
                "nonce": withdrawal.nonce,
                "leaf": crate::hex0x(&withdrawal.leaf()),
                "batchId": window,
            }])
        );
        assert_eq!(
            gw.v1_withdrawals_json(&maker.key).unwrap()["voided"],
            serde_json::json!([])
        );
    }
    let durable = h.durable();
    assert_eq!(durable.seq.state.next_batch_id, window);
    assert_eq!(
        durable.seq.state.state_root(),
        journal.witness.pre_state.state_root()
    );
    assert!(h
        .fake
        .with(|s| s.ceilings.iter().all(|c| *c == Ceiling::Nonce(5))));
    // The loop continues: the deposits are credited again and the next seal is
    // window j, publishing the voided orders as cancelled.
    let mut gw = h.app.gw.lock().await;
    assert!(h.alert(&gw, AlertKind::WindowVoided));
    assert_eq!(gw.settle_health.consecutive_failures(), 0);
    gw.deposits.dirty = false;
    assert_eq!(ingest(&mut gw, &chain), 3);
    let replacement = seal(&mut gw);
    assert_eq!(replacement.batch_id, window);
    for hash in published(&journal) {
        assert!(replacement
            .witness
            .manifest
            .rejected
            .contains(&(hash, perp_core::order::RejectReason::Cancelled)));
    }
}

/// A registration mined after the skew reverts on chain and uses its nonce: the
/// chain clock decides, and so does the fence where the block has no
/// header-bound time.
#[tokio::test]
async fn a_register_mined_after_the_skew_is_voided_without_restart() {
    for header_time in [true, false] {
        let Voidable { gw, journal, .. } = voidable(false);
        let mut state = chain_at(&journal);
        state.nonce = 6;
        state.block_time_ms = if header_time {
            past_skew(&journal)
        } else {
            None
        };
        let h = harness(gw, journal.clone(), state);
        h.seal_hold().await;
        let mut rec = h.pending();
        let basis = if header_time {
            DeadBasis::ChainClock
        } else {
            DeadBasis::Fence
        };
        let e = h
            .chain
            .evidence(&ClockIntent::of(&journal).unwrap(), Ceiling::Nonce(5))
            .unwrap();
        assert_eq!(
            decide(
                &journal,
                &ClockIntent::of(&journal).unwrap(),
                [0; 32],
                Ok(&e),
                &rec
            ),
            Decision::LiveVoid(DeadIntent::EmptyAfterFence, basis)
        );
        assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
        assert!(!h.jpath.exists());
        assert_eq!(
            h.app.gw.lock().await.seq.state.next_batch_id,
            journal.batch_id
        );
    }
}

/// An untimed window whose recorded nonce was never used: after two quiet steps
/// the nonce is burned, the fence passes, and the window returns to the open
/// window. Burns are capped, and the operator is alerted once they are used up.
#[tokio::test]
async fn an_untimed_dead_window_with_an_unused_nonce_burns_it_and_returns() {
    let (gw, journal) = untimed();
    let h = harness(gw, journal.clone(), chain_at(&journal));
    h.seal_hold().await;
    let mut rec = h.pending();
    assert!(matches!(h.step(&mut rec).await, Step::Wait(d) if d > Duration::ZERO));
    assert_eq!(rec.quiet_steps, 1);
    assert_eq!(h.step(&mut rec).await, Step::Wait(Duration::ZERO));
    assert_eq!(h.fake.with(|s| s.burned.clone()), vec![5]);
    assert_eq!(rec.burns, 1);
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    {
        let gw = h.app.gw.lock().await;
        assert_eq!(gw.seq.state.next_batch_id, journal.batch_id);
        assert!(gw.seq.open_window_has_ops());
    }
    assert!(!h.jpath.exists());
    assert!(h.admission_open());

    // Burns that never take effect stop at the cap.
    let (gw, journal) = untimed();
    let mut state = chain_at(&journal);
    state.burn_fails = true;
    let h = harness(gw, journal, state);
    h.seal_hold().await;
    let mut rec = h.pending();
    for _ in 0..6 {
        assert!(matches!(h.step(&mut rec).await, Step::Wait(_)));
    }
    assert_eq!(
        h.fake.with(|s| s.burned.len()),
        usize::from(MAX_NONCE_BURNS)
    );
    assert!(h.alert(&*h.app.gw.lock().await, AlertKind::ClockRecoveryBlocked));
    assert!(!h.admission_open());
    assert!(h.jpath.exists());
}

/// Sequencer-key sends made after the window failed (a challenge answer, a bond
/// top-up) raise the recorded ceiling but not the window's.
#[tokio::test]
async fn unrelated_sequencer_sends_do_not_delay_the_window_fence() {
    let (gw, journal) = untimed();
    let mut state = chain_at(&journal);
    state.global_ceiling = Ceiling::Nonce(9);
    state.nonce = 6;
    let h = harness(gw, journal, state);
    h.seal_hold().await;
    let mut rec = h.pending();
    assert!(
        !Ceiling::Nonce(9).passed_by(6),
        "the recorded fence has not passed"
    );
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert_eq!(h.fake.with(|s| s.ceilings.clone()), vec![Ceiling::Nonce(5)]);
}

/// A matching anchor is settled again even without the fence. A failed attempt
/// backs off without stopping the loop; the next one commits and the settlement
/// is healthy again.
#[tokio::test]
async fn a_prove_failure_with_a_matching_anchor_retries_in_loop() {
    let Voidable { gw, journal, .. } = voidable(false);
    let journal = proved(journal);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Matching;
    state.resumes = VecDeque::from([Err("prove: timed out".to_string()), Ok(())]);
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    assert_eq!(h.step(&mut rec).await, Step::Wait(Duration::from_secs(30)));
    assert_eq!(rec.retry_failures, 1);
    assert_eq!(
        h.app.gw.lock().await.settle_health.health(),
        Health::Degraded
    );
    assert!(!h.admission_open());
    // The second attempt holds the in-flight lock while it settles.
    let (release, task) = h.step_held_at("resume", rec).await;
    assert!(h.app.settle_in_flight.try_lock().is_err());
    release.send(()).unwrap();
    let (rec, step) = task.await.unwrap();
    assert_eq!(step, Step::Resolved { close_only: false });
    assert_eq!(*h.app.settle_in_flight.lock().await, None);
    let gw = h.app.gw.lock().await;
    let new_root = rollback_journal::read(&h.jpath, &h.seed)
        .unwrap()
        .unwrap()
        .prepared
        .unwrap()
        .outcome
        .new_root;
    assert_eq!(gw.last_settled_root, new_root);
    assert_eq!(
        gw.l1_status.as_ref().unwrap().batch_count,
        journal.batch_id + 1
    );
    assert_eq!(gw.settle_health.health(), Health::Healthy);
    assert_eq!(h.fake.with(|s| s.reproves.clone()), vec![false, false]);
    assert_eq!(rec.ceiling, Ceiling::Nonce(5));
    drop(gw);
    assert!(h.admission_open());
}

/// The admin cancel request answered while a step holds the in-flight lock.
async fn cancel(app: &Shared, batch: u64) -> (axum::http::StatusCode, String) {
    use tower::ServiceExt as _;
    let body = serde_json::json!({"batchId": batch, "phase": 0, "receipt": hex32(&RECEIPT)});
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/admin/settlement/cancel-anchor")
        .header("content-type", "application/json")
        .header("x-admin-key", "0x".to_string() + &"bb".repeat(32))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = crate::build_router(app.clone(), false)
        .oneshot(req)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// No cancel is sent between a step's read and its attempt: the endpoint is
/// refused while the step holds the lock. A cancel that reached the latest block
/// first makes the attempt send nothing and classify again; the next step reads
/// the cancelled receipt and voids the timed window.
#[tokio::test]
async fn a_cancel_between_decision_and_attempt_sends_no_settle() {
    let _env = crate::wind_down::ADMIN_ENV_LOCK.lock().await;
    let previous = std::env::var_os("FIN_ADMIN_KEY");
    std::env::set_var("FIN_ADMIN_KEY", "0x".to_string() + &"bb".repeat(32));
    let Voidable { gw, journal, .. } = voidable(false);
    let journal = proved(journal);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Matching;
    state.resumes = VecDeque::from([Err(
        "clock anchor cancelled at the latest block; nothing sent; reclassify".to_string(),
    )]);
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let (release, task) = h.step_held_at("evidence", h.pending()).await;
    let (status, text) = cancel(&h.app, journal.batch_id).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{text}");
    assert!(text.contains("working on this window; retry"), "{text}");
    release.send(()).unwrap();
    let (mut rec, step) = task.await.unwrap();
    assert_eq!(step, Step::Wait(Duration::ZERO));
    assert_eq!(rec.retry_failures, 0);
    assert_eq!(
        h.app.gw.lock().await.settle_health.consecutive_failures(),
        0
    );
    assert!(h.jpath.exists());
    // The cancel is final: dead on the chain clock, the timed window is voided.
    h.fake.with(|s| {
        s.slot = AnchorSlot::Cancelled;
        s.block_time_ms = past_skew(&journal);
    });
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert!(!h.jpath.exists());
    match previous {
        Some(v) => std::env::set_var("FIN_ADMIN_KEY", v),
        None => std::env::remove_var("FIN_ADMIN_KEY"),
    }
}

/// The settle of a proved window failed with a cancelled anchor (an operator
/// cancel): the recovery reads the cancelled receipt on the chain clock and voids
/// the timed window.
#[tokio::test]
async fn a_cancelled_receipt_after_an_operator_cancel_voids_the_timed_window() {
    let Voidable { gw, journal, .. } = voidable(false);
    let journal = proved(journal);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Cancelled;
    state.block_time_ms = past_skew(&journal);
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = PendingRecovery {
        cause: "clock anchor cancelled".into(),
        ..h.pending()
    };
    let i = ClockIntent::of(&journal).unwrap();
    assert_eq!(i.receipt, Some(RECEIPT));
    let e = h.chain.evidence(&i, Ceiling::Nonce(5)).unwrap();
    assert_eq!(
        decide(&journal, &i, [0; 32], Ok(&e), &rec),
        Decision::LiveVoid(DeadIntent::Cancelled, DeadBasis::ChainClock)
    );
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert_eq!(
        h.app.gw.lock().await.seq.state.next_batch_id,
        journal.batch_id
    );
}

/// A finalized head behind the window (a load-balanced or failed-over RPC that
/// lags) waits instead of stopping the loop and holding settlement; once it
/// catches up the window is decided.
#[tokio::test]
async fn a_finalized_head_behind_the_window_waits() {
    let Voidable { gw, journal, .. } = voidable(false);
    let mut state = chain_at(&journal);
    state.batch_count = journal.batch_id - 1;
    state.block_time_ms = past_skew(&journal);
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    assert!(matches!(h.step(&mut rec).await, Step::Wait(d) if d > Duration::ZERO));
    assert_eq!(rec.last_class, WaitReason::FinalizedBehind.as_str());
    assert!(rec.last.contains("finalized batch count"), "{}", rec.last);
    assert!(h.jpath.exists());
    assert!(!h.admission_open());
    {
        let gw = h.app.gw.lock().await;
        assert!(!gw.settle_health.recovery_required(), "not held");
        assert_eq!(gw.seq.state.next_batch_id, journal.batch_id + 1);
    }
    h.fake.with(|s| s.batch_count = journal.batch_id);
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert!(!h.jpath.exists());
}

/// A dead untimed window returns to the open window in the loop.
#[tokio::test]
async fn an_untimed_dead_intent_returns_to_the_open_window_in_loop() {
    let (gw, journal) = untimed();
    let mut state = chain_at(&journal);
    state.nonce = 6;
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let ww: Vec<_> = journal.ww.iter().map(Withdrawal::leaf).collect();
    let mut rec = h.pending();
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert!(!h.jpath.exists());
    assert!(*h.writes.lock().unwrap().last().unwrap());
    assert_eq!(h.durable().seq.state.next_batch_id, journal.batch_id);
    let mut gw = h.app.gw.lock().await;
    assert!(!gw.deposits.l1_close_only);
    let (again, ww2) = gw
        .begin_window_settle(journal.batch_id)
        .unwrap()
        .expect("re-sealed");
    assert_eq!(ops_bytes(&again.ops), ops_bytes(&journal.witness.ops));
    assert_eq!(ww2.iter().map(Withdrawal::leaf).collect::<Vec<_>>(), ww);
}

/// A phase-0 window in close-only returns to the open window and latches
/// close-only, so the loop seals only the wind-down's windows from then on.
#[tokio::test]
async fn a_phase_zero_window_in_close_only_returns_and_latches_close_only() {
    let Voidable { gw, journal, .. } = voidable(false);
    let mut state = chain_at(&journal);
    state.close_only = true;
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: true });
    let gw = h.app.gw.lock().await;
    assert!(gw.deposits.l1_close_only);
    assert_eq!(gw.seq.state.next_batch_id, journal.batch_id);
    assert!(gw.seq.open_window_has_ops());
}

/// Another anchor holds the batch: the loop waits and alerts the operator, and
/// once that anchor's cancel is final the window is decided.
#[tokio::test]
async fn a_replaced_anchor_waits_and_resolves_after_the_cancel() {
    let Voidable { gw, journal, .. } = voidable(false);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Different;
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    assert!(matches!(h.step(&mut rec).await, Step::Wait(d) if d > Duration::ZERO));
    assert!(rec.last.contains("another anchor holds this batch"));
    assert!(h.alert(&*h.app.gw.lock().await, AlertKind::ClockRecoveryBlocked));
    assert!(!h.admission_open());
    h.fake.with(|s| {
        s.slot = AnchorSlot::Empty;
        s.block_time_ms = past_skew(&journal);
    });
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert!(!h.alert(&*h.app.gw.lock().await, AlertKind::ClockRecoveryBlocked));
}

/// A settle that landed is committed in the loop, from a journal with or
/// without a durable proof.
#[tokio::test]
async fn a_landed_settle_rolls_forward_in_loop() {
    for with_proof in [false, true] {
        let Voidable { gw, journal, .. } = voidable(false);
        let journal = if with_proof { proved(journal) } else { journal };
        let new_root = journal.prepared.as_ref().unwrap().outcome.new_root;
        let mut state = chain_at(&journal);
        state.batch_count = journal.batch_id + 1;
        state.root = new_root;
        let h = harness(gw, journal.clone(), state);
        h.seal_hold().await;
        let mut rec = h.pending();
        assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
        let gw = h.app.gw.lock().await;
        assert_eq!(gw.last_settled_root, new_root);
        assert_eq!(
            gw.l1_status.as_ref().unwrap().batch_count,
            journal.batch_id + 1
        );
        assert_eq!(h.fake.with(|s| s.corroborated), 1);
        assert_eq!(h.fake.with(|s| s.reproves.len()), 0, "nothing is sent");
        drop(gw);
        assert!(h.admission_open());
        assert!(h.durable().last_settled_root == new_root);
    }
}

/// A void whose snapshot or journal delete fails keeps the recovery pending,
/// admission closed and the loop running; the next step finds the void already
/// applied and completes it. Nobody hears of the void before it is durable and
/// its journal is gone, and then exactly once.
#[tokio::test]
async fn a_failed_void_snapshot_or_journal_delete_waits_and_completes_on_the_next_step() {
    let Voidable { gw, journal, .. } = voidable(false);
    let mut state = chain_at(&journal);
    state.block_time_ms = past_skew(&journal);
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    let mut events = h.app.events_tx.subscribe();
    h.fail_snapshots.store(true, Ordering::SeqCst);
    assert!(matches!(h.step(&mut rec).await, Step::Wait(d) if d > Duration::ZERO));
    assert!(h.jpath.exists());
    assert!(!h.admission_open());
    assert!(
        rec.voided.is_some(),
        "the report waits for the void to be durable"
    );
    assert_eq!(
        h.app.gw.lock().await.seq.state.next_batch_id,
        journal.batch_id
    );
    assert!(
        events.try_recv().is_err(),
        "no event before the void is durable"
    );
    {
        let gw = h.app.gw.lock().await;
        assert!(gw.last_void.is_none());
        let status = gw.clock_recovery.as_ref().expect("still pending");
        assert_eq!(status.last, "the resolution is not durable yet");
    }
    let voided = h.app.gw.lock().await.snapshot_plain();
    h.fail_snapshots.store(false, Ordering::SeqCst);
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert_eq!(h.app.gw.lock().await.snapshot_plain(), voided);
    assert!(rec.voided.is_none());
    assert!(!h.jpath.exists());
    assert!(h.admission_open());
    let sent = std::iter::from_fn(|| events.try_recv().ok()).count();
    assert_eq!(
        sent,
        2 + 1 + 3,
        "the order, withdrawal and deposit events, once"
    );
    {
        let gw = h.app.gw.lock().await;
        assert_eq!(gw.last_void.as_ref().unwrap().batch_id, journal.batch_id);
        assert!(gw.clock_recovery.is_none());
    }

    // The delete fails: the void is durable and the journal stays until it goes.
    let Voidable { gw, journal, .. } = voidable(false);
    let mut state = chain_at(&journal);
    state.block_time_ms = past_skew(&journal);
    let h = harness(gw, journal, state);
    h.seal_hold().await;
    let mut rec = h.pending();
    let journal_dir = h.jpath.parent().unwrap().to_path_buf();
    let set_mode = |mode| {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&journal_dir, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    let mut events = h.app.events_tx.subscribe();
    set_mode(0o555);
    let step = h.step(&mut rec).await;
    set_mode(0o755);
    assert!(matches!(step, Step::Wait(_)), "{step:?}");
    assert!(h.jpath.exists());
    assert!(!h.admission_open());
    assert_eq!(h.durable().seq.state.next_batch_id, h.journal.batch_id);
    assert!(
        events.try_recv().is_err(),
        "no event while the journal is still there"
    );
    assert!(h.app.gw.lock().await.last_void.is_none());
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert!(!h.jpath.exists());
    assert_eq!(
        std::iter::from_fn(|| events.try_recv().ok()).count(),
        2 + 1 + 3
    );
}

/// A void applied in memory whose snapshot failed is finished by the next step
/// without reading the chain or deciding again. Close-only on L1 meanwhile
/// would decide a phase-0 window as returned to the open window; the void
/// already decided it, and its notice, events, `window_voided` and breaker
/// count all follow.
#[tokio::test]
async fn an_applied_void_is_finished_on_the_next_step_without_deciding_again() {
    let Voidable { gw, journal, .. } = voidable(false);
    let mut state = chain_at(&journal);
    state.block_time_ms = past_skew(&journal);
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    let mut events = h.app.events_tx.subscribe();
    h.fail_snapshots.store(true, Ordering::SeqCst);
    assert!(matches!(h.step(&mut rec).await, Step::Wait(_)));
    assert!(rec.voided.is_some());
    let reads = h.fake.with(|s| s.ceilings.len());
    h.fake.with(|s| s.close_only = true);
    let voided = h.app.gw.lock().await.snapshot_plain();
    h.fail_snapshots.store(false, Ordering::SeqCst);
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert_eq!(h.fake.with(|s| s.ceilings.len()), reads, "nothing was read");
    assert!(rec.voided.is_none());
    assert!(!h.jpath.exists());
    assert!(h.admission_open());
    assert_eq!(
        std::iter::from_fn(|| events.try_recv().ok()).count(),
        2 + 1 + 3,
        "the order, withdrawal and deposit events"
    );
    assert_eq!(h.durable().snapshot_plain(), voided);
    let mut gw = h.app.gw.lock().await;
    assert_eq!(gw.snapshot_plain(), voided);
    assert_eq!(gw.last_void.as_ref().unwrap().batch_id, journal.batch_id);
    assert!(h.alert(&gw, AlertKind::WindowVoided));
    assert!(gw.clock_recovery.is_none());
    // The void counted toward the breaker: one more trips it.
    assert!(gw.void_breaker.record(Instant::now()).is_some());
}

/// A return to the open window whose snapshot failed is not applied again by
/// the next step: the window's operations are in the open window once.
#[tokio::test]
async fn a_return_to_the_open_window_is_never_applied_twice() {
    let (gw, journal) = untimed();
    let mut state = chain_at(&journal);
    state.nonce = 6;
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    h.fail_snapshots.store(true, Ordering::SeqCst);
    assert!(matches!(h.step(&mut rec).await, Step::Wait(_)));
    let returned = h.app.gw.lock().await.snapshot_plain();
    assert_eq!(
        h.app.gw.lock().await.seq.state.next_batch_id,
        journal.batch_id
    );
    h.fail_snapshots.store(false, Ordering::SeqCst);
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    let mut gw = h.app.gw.lock().await;
    assert_eq!(gw.snapshot_plain(), returned, "nothing was applied again");
    let (again, _) = gw.begin_window_settle(journal.batch_id).unwrap().unwrap();
    assert_eq!(ops_bytes(&again.ops), ops_bytes(&journal.witness.ops));
}

/// A settle in the loop committed, but its snapshot failed: the next step reads
/// our settle at the next batch with the commit in memory and only persists it.
#[tokio::test]
async fn a_commit_snapshot_failure_after_a_retry_resolves_as_stale_without_recommitting() {
    let Voidable { gw, journal, .. } = voidable(false);
    let journal = proved(journal);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Matching;
    state.resumes = VecDeque::from([Ok(())]);
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    h.fail_snapshots.store(true, Ordering::SeqCst);
    assert!(matches!(h.step(&mut rec).await, Step::Wait(_)));
    let new_root = journal.prepared.as_ref().unwrap().outcome.new_root;
    let committed = {
        let gw = h.app.gw.lock().await;
        assert_eq!(gw.last_settled_root, new_root);
        gw.snapshot_plain()
    };
    assert!(!h.admission_open());
    h.fail_snapshots.store(false, Ordering::SeqCst);
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert_eq!(h.app.gw.lock().await.snapshot_plain(), committed);
    assert_eq!(h.fake.with(|s| (s.corroborated, s.reproves.len())), (1, 1));
    assert!(!h.jpath.exists());
    assert!(h.admission_open());
}

/// Settle errors are classed: a local, deterministic one stops the loop; a
/// chain that moved classifies again at once; others back off, and after three
/// the proof is made once more and the operator is alerted.
#[tokio::test]
async fn retry_errors_are_classified() {
    for (e, class) in [
        (
            "journal does not match its immutable witness",
            RetryError::Deterministic,
        ),
        (
            "clock resume requires durable intent",
            RetryError::Deterministic,
        ),
        (
            "candidate-bound journal: exact v2 resume is unsupported",
            RetryError::Deterministic,
        ),
        ("intent encode", RetryError::Deterministic),
        (
            "clock preparation: Http(\"clock anchor no longer registered; reclassify\")",
            RetryError::Reclassify,
        ),
        (
            "clock anchor cancelled at the latest block; nothing sent; reclassify",
            RetryError::Reclassify,
        ),
        ("clock resume batch/root changed", RetryError::Reclassify),
        ("prove: timed out", RetryError::Transient),
        ("settle: cast send exited 1", RetryError::Transient),
        ("journal write: disk full", RetryError::Transient),
    ] {
        assert_eq!(classify_retry_error(e), class, "{e}");
    }
    // Three failed settles: the fourth drops the proof and proves it again.
    let Voidable { gw, journal, .. } = voidable(false);
    let journal = proved(journal);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Matching;
    state.resumes = VecDeque::from([
        Err("settle: cast send exited 1".to_string()),
        Err("settle: cast send exited 1".to_string()),
        Err("settle: cast send exited 1".to_string()),
        Ok(()),
    ]);
    let h = harness(gw, journal, state);
    h.seal_hold().await;
    let mut rec = h.pending();
    for n in 1..=3 {
        assert!(matches!(h.step(&mut rec).await, Step::Wait(_)));
        assert_eq!(rec.retry_failures, n);
        assert_eq!(
            h.alert(&*h.app.gw.lock().await, AlertKind::ClockRecoveryBlocked),
            n == 3
        );
    }
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert_eq!(
        h.fake.with(|s| s.reproves.clone()),
        vec![false, false, false, true]
    );
    assert!(rec.reproved);
    // A deterministic error holds the settlement and stops the loop.
    let Voidable { gw, journal, .. } = voidable(false);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Matching;
    state.resumes = VecDeque::from([Err(
        "journal does not match its immutable witness".to_string()
    )]);
    let h = harness(gw, journal, state);
    h.seal_hold().await;
    let mut rec = h.pending();
    assert_eq!(h.step(&mut rec).await, Step::Stop);
    assert!(h.app.gw.lock().await.settle_health.recovery_required());
    assert!(h.jpath.exists());
    assert!(!h.admission_open());
}

/// A deposit source whose finalized page always starts at the cursor and would
/// credit one deposit.
struct OnePage {
    reads: std::sync::atomic::AtomicUsize,
}
impl crate::deposit_rpc::DepositSource for OnePage {
    fn fetch(
        &self,
        cursor: crate::deposit_rpc::Cursor,
    ) -> Result<crate::deposit_rpc::Page, crate::deposit_rpc::Error> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let end = crate::deposit_rpc::Block {
            number: 60,
            hash: [0x60; 32],
            timestamp: None,
        };
        Ok(crate::deposit_rpc::Page {
            events: vec![crate::deposit_rpc::Event {
                id: cursor.count,
                from: [0x42; 20],
                commit: [0x43; 32],
                amount: 1_000_000,
                tip: [0x44; 32],
                tx: [0x45; 32],
                tx_index: 0,
                log_index: 0,
                block: end.clone(),
            }],
            start: cursor,
            end,
        })
    }
}

/// While admission is closed ingestion cannot clear the deposit barrier, so a
/// retry reads the finalized prefix once, and applies nothing.
#[tokio::test]
async fn the_retry_refreshes_deposit_readiness_without_applying_a_page() {
    let Voidable {
        mut gw, journal, ..
    } = voidable(false);
    gw.deposits.required = true;
    gw.deposits.ready = false;
    let journal = proved(journal);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Matching;
    state.resumes = VecDeque::from([Ok(())]);
    let source = Arc::new(OnePage { reads: 0.into() });
    let h = harness_with(gw, journal, state, Some(source.clone()));
    let before = {
        let gw = h.app.gw.lock().await;
        (
            gw.seq.state.consumed_deposit_count,
            gw.deposits.credits.len(),
            gw.deposits.anchor.clone(),
        )
    };
    h.seal_hold().await;
    let mut rec = h.pending();
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert_eq!(source.reads.load(Ordering::SeqCst), 1);
    let gw = h.app.gw.lock().await;
    assert!(gw.deposits.ready);
    assert_eq!(
        (
            gw.seq.state.consumed_deposit_count,
            gw.deposits.credits.len(),
            gw.deposits.anchor.clone()
        ),
        before,
        "the page was not applied"
    );
}

/// A deposit halt blocks the retry: the step waits with the halt as its reason
/// and the operator is alerted; nothing is sent.
#[tokio::test]
async fn a_deposit_halt_blocks_the_retry_with_its_reason() {
    let Voidable {
        mut gw, journal, ..
    } = voidable(false);
    gw.deposits.halt = Some("finalized deposit reorg".into());
    let journal = proved(journal);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Matching;
    state.resumes = VecDeque::from([Ok(())]);
    let h = harness(gw, journal, state);
    h.seal_hold().await;
    let mut rec = h.pending();
    assert!(matches!(h.step(&mut rec).await, Step::Wait(_)));
    assert!(
        rec.last.contains("a deposit halt blocks the retry"),
        "{}",
        rec.last
    );
    assert!(h.alert(&*h.app.gw.lock().await, AlertKind::ClockRecoveryBlocked));
    assert!(h.fake.with(|s| s.reproves.is_empty()), "nothing was sent");
    assert!(!h.admission_open());
}

/// Two voids without a settled timed window between them trip the breaker: the
/// void is durable and the journal deleted, but admission stays closed, the
/// loop stops, and the next start is a normal boot.
#[tokio::test]
async fn the_void_breaker_keeps_admission_closed_after_two_consecutive_voids() {
    let Voidable {
        mut gw, journal, ..
    } = voidable(false);
    // An earlier void, at boot or in the loop.
    assert_eq!(gw.void_breaker.record(Instant::now()), None);
    let mut state = chain_at(&journal);
    state.block_time_ms = past_skew(&journal);
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    assert_eq!(h.step(&mut rec).await, Step::Stop);
    {
        let gw = h.app.gw.lock().await;
        assert!(h.alert(&gw, AlertKind::ClockRecoveryBlocked));
        assert!(h.alert(&gw, AlertKind::WindowVoided));
        assert!(gw.settle_health.recovery_required());
    }
    assert!(!h.admission_open());
    assert!(!h.jpath.exists());
    let restarted = h.durable();
    assert_eq!(restarted.seq.state.next_batch_id, journal.batch_id);
    restarted.validate_deposit_state().unwrap();
}

/// A settled window that credited two accounts, then a sealed window in which a
/// resting order is filled twice, the second fill stamped ten seconds before
/// the first: the window's time bounds do not derive.
fn underivable() -> (Gw, RollbackJournal) {
    use crate::live_void::tests::{open_trading, submit};
    let mut gw = fresh();
    open_trading(&mut gw);
    let collateral = (50_000 * perp_core::fixed::QUOTE_SCALE) as u128;
    let (maker, cm) = permit(&mut gw, collateral, Purpose::Collateral, 0);
    let (taker, ct) = permit(&mut gw, collateral, Purpose::Collateral, 0);
    let chain = chained_blocks(&gw, &[&[cm, ct]]);
    assert_eq!(ingest(&mut gw, &chain), 2);
    settle_open_window(&mut gw);
    let tick_at = |gw: &mut Gw, t: u64| {
        for (id, px) in gw.mkts.iter().map(|m| (m.id, m.px)).collect::<Vec<_>>() {
            gw.seq
                .set_oracle(id, crate::oracle_of(px, t, id, &gw.oracle_signer));
        }
        gw.tick_checked(crate::PriceUse {
            archive: None,
            now_ms: t,
        })
        .unwrap();
    };
    let size = perp_core::fixed::SIZE_SCALE;
    let t0 = crate::now_ms();
    let px = gw.px_of(0);
    submit(&mut gw, &maker, "Sell", size / 10, px, "Gtc");
    tick_at(&mut gw, t0);
    submit(&mut gw, &taker, "Buy", size / 40, 0, "Ioc");
    tick_at(&mut gw, t0);
    submit(&mut gw, &taker, "Buy", size / 40, 0, "Ioc");
    tick_at(&mut gw, t0 - 10_000);
    let j = seal(&mut gw);
    (gw, j)
}

/// A window whose operation times step backwards can never register: it is
/// voided on the fence basis, and the void names the cause.
#[tokio::test]
async fn an_underivable_window_voids_with_its_cause() {
    let (gw, journal) = underivable();
    let i = ClockIntent::of(&journal).unwrap();
    assert!(i.timed && i.underivable && i.last_ms.is_none(), "{i:?}");
    let rec = PendingRecovery::new(
        journal.batch_id,
        0,
        String::new(),
        Vec::new(),
        false,
        Ceiling::Nonce(5),
    );
    // No chain-clock basis, whatever the block time: only the fence decides.
    let unfenced = DeadIntentEvidence {
        block_time_ms: Some(u64::MAX),
        ..evidence_for(&journal, AnchorSlot::Empty)
    };
    assert_eq!(
        decide(&journal, &i, [0; 32], Ok(&unfenced), &rec),
        Decision::Wait(WaitReason::NonceFence)
    );
    let fenced = DeadIntentEvidence {
        nonce: 6,
        fence_passed: true,
        ..unfenced
    };
    assert_eq!(
        decide(&journal, &i, [0; 32], Ok(&fenced), &rec),
        Decision::LiveVoid(DeadIntent::EmptyAfterFence, DeadBasis::Fence)
    );
    let mut state = chain_at(&journal);
    state.nonce = 6;
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = h.pending();
    // The report is kept until the void is durable; read it while it is not.
    h.fail_snapshots.store(true, Ordering::SeqCst);
    assert!(matches!(h.step(&mut rec).await, Step::Wait(_)));
    let (report, basis, _) = rec.voided.as_ref().expect("the void was applied");
    assert_eq!(*basis, DeadBasis::Fence);
    assert!(report.underivable);
    assert!(
        report
            .summary()
            .contains("operation times are not monotonic: check the gateway clock (NTP)"),
        "{}",
        report.summary()
    );
    h.fail_snapshots.store(false, Ordering::SeqCst);
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    assert_eq!(
        h.app.gw.lock().await.seq.state.next_batch_id,
        journal.batch_id
    );
}

/// The recovery's alerts and backoff: `ClockRecoveryBlocked` is raised and
/// cleared, the HELD line names the window without error text, the backoff
/// restarts on resolution while `SettlementHeld` stays until the replacement
/// settles, and `LivenessLow` follows the step's budget read. `/api/state`
/// names the reason and the operator action, without error text either.
#[tokio::test]
async fn recovery_alerts_and_backoff() {
    let Voidable {
        gw, journal, chain, ..
    } = voidable(false);
    let mut state = chain_at(&journal);
    state.slot = AnchorSlot::Different;
    state.budget = CloseOnlyBudget {
        last_progress_block: 400,
        ..healthy_budget()
    };
    let h = harness(gw, journal.clone(), state);
    h.seal_hold().await;
    let mut rec = PendingRecovery {
        cause: "prove: upstream https://user:secret@rpc.example failed".into(),
        ..h.pending()
    };
    let mut delays = Vec::new();
    for _ in 0..3 {
        match h.step(&mut rec).await {
            Step::Wait(d) => delays.push(d.as_secs()),
            other => panic!("expected a wait, got {other:?}"),
        }
    }
    assert_eq!(delays, vec![30, 60, 300]);
    {
        let gw = h.app.gw.lock().await;
        assert!(h.alert(&gw, AlertKind::ClockRecoveryBlocked));
        assert!(h.alert(&gw, AlertKind::SettlementHeld));
        assert!(
            h.alert(&gw, AlertKind::LivenessLow),
            "half the window without progress"
        );
    }
    let held = crate::settle_health::held_recovery_alert_message(rec.batch_id, rec.steps);
    assert!(
        !held.contains("secret") && !held.contains("upstream"),
        "{held}"
    );
    {
        let gw = h.app.gw.lock().await;
        let status = serde_json::to_value(h.app.snapshot(&gw)).unwrap()["clockRecovery"].clone();
        assert_eq!(status["batchId"], journal.batch_id);
        assert_eq!(status["steps"], 3);
        assert_eq!(status["last"], WaitReason::Replaced.as_str());
        // The other anchor's cancel is the operator's; it outranks the budget.
        assert_eq!(status["operatorAction"], operator::REPLACED);
        assert_eq!(
            status["closeOnlyBudget"],
            serde_json::json!({ "stalledBlocksLeft": 401, "starvedBlocksLeft": null })
        );
        assert_eq!(status["fence"]["quiet"], true);
        assert_eq!(status["fence"]["passed"], false);
        let text = status.to_string();
        assert!(
            !text.contains("secret") && !text.contains("upstream"),
            "{text}"
        );
    }
    // The budget recovers, and the cancel of the other anchor is final.
    h.fake.with(|s| {
        s.budget = healthy_budget();
        s.slot = AnchorSlot::Empty;
        s.block_time_ms = past_skew(&journal);
    });
    assert_eq!(h.step(&mut rec).await, Step::Resolved { close_only: false });
    {
        let gw = h.app.gw.lock().await;
        assert!(
            gw.clock_recovery.is_none(),
            "the status clears on resolution"
        );
        assert!(!h.alert(&gw, AlertKind::ClockRecoveryBlocked));
        assert!(!h.alert(&gw, AlertKind::LivenessLow));
        assert!(
            h.alert(&gw, AlertKind::SettlementHeld),
            "until the replacement settles"
        );
        assert!(h.alert(&gw, AlertKind::WindowVoided));
        assert_eq!(gw.settle_health.consecutive_failures(), 0);
    }
    // The replacement settles: both alerts recover.
    let replacement = {
        let mut gw = h.app.gw.lock().await;
        gw.deposits.dirty = false;
        assert_eq!(ingest(&mut gw, &chain), 3);
        seal(&mut gw)
    };
    let prepared = crate::prover_client::prove_and_prepare(
        &crate::prover_client::MockProverClient,
        &replacement.witness,
        &replacement.ww,
    )
    .unwrap();
    crate::commit_and_resolve(
        &h.app,
        &replacement.witness,
        prepared,
        L1Status::default(),
        GateObservation::Inconclusive,
        &[],
        &mut None,
    )
    .await
    .unwrap();
    let gw = h.app.gw.lock().await;
    assert!(!h.alert(&gw, AlertKind::SettlementHeld));
    assert!(!h.alert(&gw, AlertKind::WindowVoided));
    assert_eq!(gw.settle_health.health(), Health::Healthy);
}

/// The settle loop hands a failed clock window to the recovery with the
/// window's phase, the last time of its operations and the window's nonce
/// ceiling, and `/api/state` shows it before the first step. A settle that
/// failed after its send goes to the recovery only in clock mode, while the
/// finalized batch count is still the window's or could not be read.
#[tokio::test]
async fn the_settle_loop_starts_a_recovery_with_the_window_identity() {
    let Voidable { gw, journal, .. } = voidable(false);
    let h = harness(gw, journal.clone(), chain_at(&journal));
    let window = journal.batch_id;
    let last_ms = ClockIntent::of(&journal).unwrap().last_ms.unwrap();
    for phase in [0, 2] {
        let (rec, delay) = crate::start_clock_recovery(
            &h.app,
            window,
            &journal.witness,
            phase,
            "clock preparation: refused before broadcast".into(),
            vec![[3; 32]],
            true,
            Ceiling::Nonce(7),
        )
        .await;
        assert_eq!(
            (rec.batch_id, rec.phase, rec.last_ms, rec.ceiling),
            (window, phase, Some(last_ms), Ceiling::Nonce(7))
        );
        assert_eq!(rec.prune_candidates, vec![[3; 32]]);
        assert!(rec.gate_was_closed);
        assert!(
            delay > Duration::ZERO,
            "the failure counts toward the backoff"
        );
        let gw = h.app.gw.lock().await;
        let status = serde_json::to_value(h.app.snapshot(&gw)).unwrap()["clockRecovery"].clone();
        assert_eq!(status["batchId"], window);
        assert_eq!(status["phase"], phase);
        assert_eq!(status["steps"], 0);
        assert_eq!(status["basis"], "chainClock");
        assert_eq!(status["chainClock"]["lastMs"], last_ms);
    }
    // An untimed window has no last operation time: the fence decides it.
    let (gw, untimed) = untimed();
    let h = harness(gw, untimed.clone(), chain_at(&untimed));
    let (rec, _) = crate::start_clock_recovery(
        &h.app,
        untimed.batch_id,
        &untimed.witness,
        0,
        "settle: timed out".into(),
        Vec::new(),
        false,
        Ceiling::Nonce(5),
    )
    .await;
    assert_eq!(rec.last_ms, None);
    let status = h.app.gw.lock().await.clock_recovery.clone().unwrap();
    assert_eq!((status.basis, status.chain_clock), ("fence", None));
    // Which failed settles the recovery takes.
    for (clock_mode, now_bc, recovers) in [
        (true, Some(window), true),
        (true, None, true),
        (true, Some(window + 1), false),
        (true, Some(window + 2), false),
        (true, Some(window - 1), false),
        (false, Some(window), false),
        (false, None, false),
    ] {
        assert_eq!(
            crate::settle_failure_recovers(clock_mode, window, now_bc),
            recovers,
            "{clock_mode} {now_bc:?}"
        );
    }
}

/// The settle loop's turn while a window is pending: a wait keeps the recovery
/// and sets the next attempt; a resolution clears it, latches close-only when
/// the window returned for it, persists promptly and attempts at once; a stop
/// ends the loop, and so does a recovery without its bridge, which holds
/// settlement.
#[tokio::test]
async fn the_settle_loop_turn_follows_each_recovery_step() {
    use std::ops::ControlFlow;
    let notify = tokio::sync::Notify::new();
    let Voidable { gw, journal, .. } = voidable(false);
    let h = harness(gw, journal.clone(), chain_at(&journal));
    h.seal_hold().await;
    let mut pending = Some(h.pending());
    let mut next = tokio::time::Instant::now();
    let mut close_only_seen = false;
    let before = tokio::time::Instant::now();
    // At the registration bound: a wait.
    assert_eq!(
        crate::settle_loop_recovery_step(
            &h.app,
            &h.stop,
            Some(&h.chain),
            Some(h.jpath.as_path()),
            &h.seed,
            &mut pending,
            &mut next,
            &mut close_only_seen,
            &notify,
        )
        .await,
        ControlFlow::Continue(())
    );
    assert!(pending.is_some());
    assert!(next > before + Duration::from_secs(1));
    assert!(!close_only_seen);
    // Close-only on L1: the window returns and the loop latches close-only.
    h.fake.with(|s| s.close_only = true);
    assert_eq!(
        crate::settle_loop_recovery_step(
            &h.app,
            &h.stop,
            Some(&h.chain),
            Some(h.jpath.as_path()),
            &h.seed,
            &mut pending,
            &mut next,
            &mut close_only_seen,
            &notify,
        )
        .await,
        ControlFlow::Continue(())
    );
    assert!(pending.is_none());
    assert!(close_only_seen);
    assert!(
        next <= tokio::time::Instant::now(),
        "the next tick attempts at once"
    );
    tokio::time::timeout(Duration::from_secs(5), notify.notified())
        .await
        .expect("the snapshot writer was poked");
    assert!(!h.jpath.exists());
    // Nothing pending: nothing to do.
    assert_eq!(
        crate::settle_loop_recovery_step(
            &h.app,
            &h.stop,
            Some(&h.chain),
            Some(h.jpath.as_path()),
            &h.seed,
            &mut pending,
            &mut next,
            &mut close_only_seen,
            &notify,
        )
        .await,
        ControlFlow::Continue(())
    );

    // A contradiction stops the loop.
    let Voidable { gw, journal, .. } = voidable(false);
    let mut state = chain_at(&journal);
    state.batch_count = journal.batch_id + 2;
    let h = harness(gw, journal, state);
    h.seal_hold().await;
    let mut pending = Some(h.pending());
    let mut close_only_seen = false;
    assert_eq!(
        crate::settle_loop_recovery_step(
            &h.app,
            &h.stop,
            Some(&h.chain),
            Some(h.jpath.as_path()),
            &h.seed,
            &mut pending,
            &mut next,
            &mut close_only_seen,
            &notify,
        )
        .await,
        ControlFlow::Break(())
    );
    assert!(pending.is_some());
    assert!(h.app.gw.lock().await.settle_health.recovery_required());
    // Without its bridge the recovery cannot run: settlement is held.
    let Voidable { gw, journal, .. } = voidable(false);
    let h = harness(gw, journal.clone(), chain_at(&journal));
    h.seal_hold().await;
    let mut pending = Some(h.pending());
    assert_eq!(
        crate::settle_loop_recovery_step(
            &h.app,
            &h.stop,
            None,
            Some(h.jpath.as_path()),
            &h.seed,
            &mut pending,
            &mut next,
            &mut close_only_seen,
            &notify,
        )
        .await,
        ControlFlow::Break(())
    );
    let gw = h.app.gw.lock().await;
    assert!(gw.settle_health.recovery_required());
    assert!(h.alert(&gw, AlertKind::SettlementHeld));
    assert!(h.jpath.exists());
}
