//! Synthetic fixtures only: a locally built ABI container (FAKE signature words,
//! never DON-authentic), an operator-pinned policy, owned temp dirs. No real
//! feed IDs, credentials, or network.
use super::*;
use chainlink_oracle::policy::MarketFeed;
use chainlink_streams_client::{parse_response, FeedId, Network, Request};
use perp_core::order::Side;

const NOW: u64 = 100_000;
const AGE_MS: u64 = 10_000;

fn feed(n: u8) -> [u8; 32] {
    let mut id = [n; 32];
    id[0] = 0;
    id[1] = 3;
    id
}
fn policy() -> Policy {
    Policy {
        chain_id: 84532,
        network: 0,
        verifier_proxy: [3; 20],
        oracle_wrapper: [4; 20],
        markets: vec![MarketFeed {
            market_id: 0,
            base_symbol: "BTC".into(),
            base_usd_feed: feed(0x11),
            base_decimals: 8,
            usdc_usd_feed: feed(0x22),
            usdc_decimals: 8,
            max_report_age_ms: AGE_MS,
            max_pair_skew_ms: 1_000,
        }],
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
fn word(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}
/// The same canonical ABI container shape the streams-client tests use: context
/// offsets at words 3..7, one fake r/s pair, v=0. Never a DON signature.
fn full_report(id: [u8; 32], price: u64, observed: u64) -> Vec<u8> {
    let mut full = vec![0u8; 672];
    for (i, n) in [(3, 224), (4, 544), (5, 608), (7, 288), (17, 1), (19, 1)] {
        full[i * 32..(i + 1) * 32].copy_from_slice(&word(n));
    }
    full[256..288].copy_from_slice(&id);
    for (i, n) in [
        (1, observed),
        (2, observed),
        (5, observed + 60),
        (6, price),
        (7, price),
        (8, price),
    ] {
        full[256 + i * 32..256 + (i + 1) * 32].copy_from_slice(&word(n));
    }
    full[576..608].fill(0x11);
    full[640..672].fill(0x22);
    full
}
fn report_from_full(full: Vec<u8>, observed: u64, received: u64) -> UnverifiedReport {
    let id: [u8; 32] = full[256..288].try_into().unwrap();
    let v = serde_json::json!({"report":{"feedID":format!("0x{}",hex(&id)),
        "validFromTimestamp":observed,"observationsTimestamp":observed,
        "fullReport":format!("0x{}",hex(&full))}});
    let req = Request::new(
        Network::Testnet,
        FeedId::parse_v3(&format!("0x{}", hex(&id))).unwrap(),
        AGE_MS,
    )
    .unwrap();
    parse_response(&serde_json::to_vec(&v).unwrap(), &req, received).unwrap()
}
fn report(id: [u8; 32], price: u64, observed: u64, received: u64) -> UnverifiedReport {
    report_from_full(full_report(id, price, observed), observed, received)
}
fn base_report(observed: u64, received: u64) -> UnverifiedReport {
    base_report_price(observed, 6_000_000_000_000, received)
}
fn base_report_price(observed: u64, price: u64, received: u64) -> UnverifiedReport {
    report(feed(0x11), price, observed, received)
}
fn quote_report(observed: u64, received: u64) -> UnverifiedReport {
    report(feed(0x22), 100_000_000, observed, received)
}
fn transcript_of(n: Normalized) -> perp_core::oracle::OracleTranscript {
    n.with_signature(perp_core::oracle::OracleSig {
        r: [0; 32],
        s: [0; 32],
        v: 0,
    })
}
fn fill(market: u64, now_ms: u64, oracle: perp_core::oracle::OracleTranscript) -> BatchOp {
    BatchOp::Fill {
        taker: [1; 32],
        maker: [2; 32],
        market_id: market,
        taker_side: Side::Buy,
        size: 1,
        price: 100,
        oracle,
        now_ms,
    }
}
struct Temp(std::path::PathBuf);
impl Temp {
    fn new(tag: &str) -> Self {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("arcora-binding-{tag}-{suffix}"));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn binding(tag: &str) -> (Temp, ArchiveBinding) {
    let t = Temp::new(tag);
    let b = ArchiveBinding::create_in(&t.0, policy()).unwrap();
    (t, b)
}

/// The production contract: store durable → downstream admission → install
/// ONLY on acceptance. Tests model a successful admission.
fn admit_installed(
    b: &mut ArchiveBinding,
    market: u64,
    base: UnverifiedReport,
    quote: UnverifiedReport,
    now: u64,
) -> Normalized {
    let pending = b.admit(market, base, quote, now).unwrap();
    b.install(pending).unwrap();
    pending.transcript
}

#[test]
fn admit_persists_the_exact_record_before_returning() {
    let (_t, mut b) = binding("admit");
    let n = admit_installed(
        &mut b,
        0,
        base_report(100, NOW),
        quote_report(100, NOW),
        NOW,
    );
    assert_eq!(n.price, 6_000_000_000_000);
    assert_eq!(n.publish_time_ms, NOW);
    // The durable barrier: the record is loadable immediately, from disk, with
    // the original bytes and receipt times — no "latest file" indirection.
    let id = b.admissions[0].id;
    let loaded = b.archive.load(id, &policy(), 0).unwrap();
    assert_eq!(loaded.base().received_ms(), NOW);
    assert!(loaded.for_operation(NOW).is_ok());
}

#[test]
fn bind_binds_the_actual_op_stream_in_order_with_repeated_use() {
    let (_t, mut b) = binding("order");
    let a = admit_installed(
        &mut b,
        0,
        base_report(100, NOW),
        quote_report(100, NOW),
        NOW,
    );
    let later = NOW + 5_000;
    let bpair = admit_installed(
        &mut b,
        0,
        base_report(101, later),
        quote_report(101, later),
        later,
    );
    let ops = [
        fill(0, NOW, transcript_of(a)),
        fill(0, later, transcript_of(bpair)),
        BatchOp::AccrueFunding {
            market_id: 0,
            mark: bpair.price,
            oracle: transcript_of(bpair),
            now_ms: later,
        },
        fill(0, NOW, transcript_of(a)), // repeated use of the older record
    ];
    let env = b.bind_ops(&ops).unwrap();
    assert_eq!(env.policy_binding, policy_binding(&policy()).unwrap());
    assert_eq!(env.refs.len(), 4, "one ref per oracle-bearing op, in order");
    assert_eq!(env.refs[0].archive_id, b.admissions[0].id);
    assert_eq!(env.refs[1].archive_id, b.admissions[1].id);
    assert_eq!(env.refs[2].archive_id, b.admissions[1].id);
    assert_eq!(env.refs[3].archive_id, b.admissions[0].id);
    assert_eq!(env.refs[0].now_ms, NOW);
    // Recovery-side verification of the same stream must accept it.
    assert!(b.verify(&ops, &env).is_ok());
}

/// Review focus: a window can contain BOTH an earlier and a later transcript
/// for the same market. Binding is keyed by exact (market, transcript)
/// identity and derived in op order — never a latest-pair-per-market map —
/// and repeated use of the same valid archive ID is legitimate.
#[test]
fn bind_handles_multiple_observations_per_market_in_op_order_with_repeated_use() {
    let (_t, mut b) = binding("multi-obs");
    // Two observations of the same market, distinguishable prices.
    let early = admit_installed(
        &mut b,
        0,
        base_report_price(100, 6_000_000_000_000, NOW),
        quote_report(100, NOW),
        NOW,
    );
    let mid = NOW + 4_000;
    let late = admit_installed(
        &mut b,
        0,
        base_report_price(101, 6_200_000_000_000, mid),
        quote_report(101, mid),
        mid,
    );
    let early_id = b.admissions[0].id;
    let late_id = b.admissions[1].id;
    assert_ne!(
        early_id, late_id,
        "different reports hash to different records"
    );

    // Op times are deliberately NOT monotonic and the op types vary; the same
    // archive ID appears several times (repeated use is not invalid).
    let liquidate = |now_ms: u64, oracle: perp_core::oracle::OracleTranscript| BatchOp::Liquidate {
        owner: [3; 32],
        market_id: 0,
        oracle,
        now_ms,
    };
    let ops = [
        fill(0, NOW, transcript_of(early)),   // 0: early
        fill(0, mid, transcript_of(late)),    // 1: late
        liquidate(NOW, transcript_of(early)), // 2: early again, EARLIER timestamp after later op
        fill(0, mid, transcript_of(late)),    // 3: late again (duplicate usage)
        BatchOp::AccrueFunding {
            market_id: 0,
            mark: late.price,
            oracle: transcript_of(late),
            now_ms: mid,
        }, // 4: late
        fill(0, NOW, transcript_of(early)),   // 5: early
    ];
    let env = b.bind_ops(&ops).expect("all ops trace to exact records");
    let ids: Vec<_> = env.refs.iter().map(|r| r.archive_id).collect();
    assert_eq!(
        ids,
        vec![early_id, late_id, early_id, late_id, late_id, early_id],
        "refs must follow the ACTUAL op stream (identity per op), not recency"
    );
    assert_eq!(
        env.refs.iter().map(|r| r.now_ms).collect::<Vec<_>>(),
        vec![NOW, mid, NOW, mid, mid, NOW],
        "each ref carries its own op's exact timestamp"
    );
    assert!(b.verify(&ops, &env).is_ok());

    // An unarchived transcript injected mid-stream fails the whole seal, even
    // though every other op still traces to exact records.
    let mut bad = ops.clone();
    bad[2] = fill(
        0,
        NOW,
        transcript_of(Normalized {
            price: early.price + 1,
            ..early
        }),
    );
    assert_eq!(b.bind_ops(&bad).unwrap_err(), BindError::Mismatch);
}

#[test]
fn bind_fails_closed_for_unarchived_or_substituted_transcripts() {
    let (_t, mut b) = binding("closed");
    let a = admit_installed(
        &mut b,
        0,
        base_report(100, NOW),
        quote_report(100, NOW),
        NOW,
    );
    // A transcript from any real archived admission binds by exact value.
    let later = admit_installed(
        &mut b,
        0,
        base_report_price(100, 6_100_000_000_000, NOW),
        quote_report(100, NOW),
        NOW,
    );
    assert!(b.bind_ops(&[fill(0, NOW, transcript_of(later))]).is_ok());
    // Identity binding is clock-independent: an op timestamped BEFORE the
    // admission still binds, because the match is the exact transcript value,
    // not recency (the op can only carry a transcript some admission produced).
    assert!(b.bind_ops(&[fill(0, NOW - 1, transcript_of(a))]).is_ok());
    // A transcript NO archived record reproduces (one-off price) refuses…
    let ghost = transcript_of(Normalized {
        price: a.price + 1,
        ..a
    });
    assert_eq!(
        b.bind_ops(&[fill(0, NOW, ghost)]).unwrap_err(),
        BindError::Mismatch
    );
    // …and a market with NO admission at all reports NoAdmission.
    let (_t2, b2) = binding("closed-empty");
    assert_eq!(
        b2.bind_ops(&[fill(0, NOW, transcript_of(a))]).unwrap_err(),
        BindError::NoAdmission
    );
    // Non-oracle ops bind nothing.
    assert!(b
        .bind_ops(&[BatchOp::EnterCloseOnly])
        .unwrap()
        .refs
        .is_empty());
}

#[test]
fn verify_fails_closed_on_missing_corrupt_or_mismatched_records() {
    // Record path is content-addressed: <archive root>/<id hex>.json.
    fn record_path(t: &Temp, id: ArchiveId) -> std::path::PathBuf {
        t.0.join("store").join(format!("{}.json", id.hex()))
    }
    // Fresh bound fixture: one archived admission, one op using its transcript.
    let fresh = |tag: &str| {
        let (t, mut b) = binding(tag);
        let n = admit_installed(
            &mut b,
            0,
            base_report(100, NOW),
            quote_report(100, NOW),
            NOW,
        );
        let ops = [fill(0, NOW, transcript_of(n))];
        let env = b.bind_ops(&ops).unwrap();
        (t, b, ops, env, n)
    };

    // Missing record (operator deleted it): recovery must HOLD.
    let (t, b, ops, env, _) = fresh("missing");
    std::fs::remove_file(record_path(&t, env.refs[0].archive_id)).unwrap();
    assert_eq!(b.verify(&ops, &env), Err(BindError::Archive));

    // Corrupt record preserved-not-repaired: still HOLD, bytes untouched.
    let (t, b, ops, env, _) = fresh("corrupt");
    let path = record_path(&t, env.refs[0].archive_id);
    std::fs::write(&path, b"corrupt").unwrap();
    assert_eq!(b.verify(&ops, &env), Err(BindError::Archive));
    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");

    // Policy-binding mismatch refuses before any record read.
    let (_t, b, ops, env, _) = fresh("policy");
    let mut wrong_policy = env.clone();
    wrong_policy.policy_binding = [9; 32];
    assert_eq!(b.verify(&ops, &wrong_policy), Err(BindError::Policy));

    // Op identity (market/now_ms) must equal the ref's.
    let (_t, b, ops, env, _) = fresh("op-time");
    let mut wrong_time = env.clone();
    wrong_time.refs[0].now_ms = NOW + 1;
    assert_eq!(b.verify(&ops, &wrong_time), Err(BindError::Mismatch));

    // Ref/op count disagreement (dropped or extra ref) refuses.
    let (_t, b, ops, env, _) = fresh("count");
    let mut short = env.clone();
    short.refs.clear();
    assert_eq!(b.verify(&ops, &short), Err(BindError::Mismatch));

    // A transcript the record cannot reproduce (different op price).
    let (_t, b, _ops, env, n) = fresh("value");
    let mismatched = [fill(
        0,
        NOW,
        transcript_of(Normalized {
            price: n.price + 1,
            ..n
        }),
    )];
    assert_eq!(b.verify(&mismatched, &env), Err(BindError::Mismatch));
    // And the positive control: the exact stream verifies.
    let (_t, b, ops, env, _) = fresh("ok");
    assert!(b.verify(&ops, &env).is_ok());
}

/// The full candidate durability chain with a REAL sealed window and the REAL
/// sealed-journal write/read path: archive → admission transcript → op →
/// bind at seal time → v6 authenticated journal → recovery verify.
#[test]
fn candidate_journal_round_trips_through_the_real_sealed_journal_path() {
    use crate::rollback_journal;
    use crate::Gw;
    use perp_core::fixed::QUOTE_SCALE;

    let (_t, mut b) = binding("journal");
    let normalized = admit_installed(
        &mut b,
        0,
        base_report(100, NOW),
        quote_report(100, NOW),
        NOW,
    );

    // A real sealed window (deposit), with one archived-price-bearing Fill op
    // appended so the journaled op stream carries an oracle transcript.
    let mut gw = Gw::boot();
    let (key, _owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
    let bc = gw.seq.state.next_batch_id;
    let (mut witness, ww) = gw.begin_window_settle(bc).unwrap().expect("window sealed");
    witness.ops.push(fill(0, NOW, transcript_of(normalized)));

    let envelope = b.bind_ops(&witness.ops).expect("ops bind to exact records");
    assert_eq!(envelope.refs.len(), 1);
    let journal = rollback_journal::RollbackJournal {
        batch_id: witness.batch_id,
        witness,
        ww,
        prepared: None,
    };
    let seed = [42u8; 32];
    let path = std::env::temp_dir().join(format!(
        "arcora-binding-journal-{}-{}",
        std::process::id(),
        envelope.refs[0].archive_id.hex()
    ));
    rollback_journal::write_versioned(&path, &journal, Some(&envelope), &seed)
        .expect("candidate journal write");

    // Recovery: the sealed v6 journal opens to the same witness + envelope and
    // every referenced record verifies against the exact op stream.
    let sealed = std::fs::read(&path).unwrap();
    let reopened = rollback_journal::open_versioned(&sealed, &seed).expect("v6 open");
    let rollback_journal::OpenedJournal::Candidate {
        journal: back,
        envelope: back_env,
    } = reopened
    else {
        panic!("v6 journal must open as Candidate");
    };
    assert_eq!(back.witness.batch_id, journal.batch_id);
    b.verify(&back.witness.ops, &back_env)
        .expect("recovery binding verifies");

    // The legacy v5-only decoder must refuse the v6 magic as a versioned
    // mismatch (never a silent postcard misparse), and the wrong seed fails closed.
    let err = match rollback_journal::open(&sealed, &seed) {
        Err(e) => e,
        Ok(_) => panic!("legacy open must refuse a v6 journal"),
    };
    assert!(err.contains("magic"), "unexpected error: {err}");
    assert!(rollback_journal::open_versioned(&sealed, &[43u8; 32]).is_err());

    // A legacy v5 journal stays byte-identical and opens as Legacy.
    let legacy_path = path.with_extension("legacy");
    rollback_journal::write(&legacy_path, &journal, &seed).expect("legacy write");
    let legacy_sealed = std::fs::read(&legacy_path).unwrap();
    assert_ne!(legacy_sealed, sealed, "v6 must not equal the v5 encoding");
    assert!(matches!(
        rollback_journal::open_versioned(&legacy_sealed, &seed).unwrap(),
        rollback_journal::OpenedJournal::Legacy(_)
    ));
    // And the v6 envelope REFUSES to verify against legacy bytes implicitly:
    // open_versioned reports Legacy, so a candidate-required boot can HOLD.
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&legacy_path).ok();
}

/// Review gate: the archive-required guard must run BEFORE any prover client
/// invocation (prove_and_prepare performs the clock-registration chain
/// mutation for clock clients). A counting prover proves no call happened when
/// a record goes missing or an op no longer matches its envelope.
#[test]
fn archive_guard_blocks_prover_invocation_on_missing_or_mismatched_records() {
    use crate::prover_client::{
        MockProverClient, ProverClient, ProverClientError, RemoteProveResp,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct CountingProver(Arc<AtomicUsize>);
    impl ProverClient for CountingProver {
        fn prove(
            &self,
            w: &sequencer::WindowWitness,
        ) -> Result<RemoteProveResp, ProverClientError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            MockProverClient.prove(w)
        }
    }

    /// The exact pre-prove sequence of the settle loop: guard first, prove only
    /// if the sealed window's archive binding still verifies against disk.
    fn guard_then_prove(
        prover: &CountingProver,
        binding: &ArchiveBinding,
        journal: &crate::rollback_journal::RollbackJournal,
        envelope: &crate::rollback_journal::ArchiveEnvelope,
    ) -> Result<(), String> {
        crate::ensure_archive_binding_current(Some(binding), journal, Some(envelope))?;
        crate::prover_client::prove_and_prepare(prover, &journal.witness, &journal.ww)?;
        Ok(())
    }

    let (t, mut b) = binding("guard");
    // Negative fixtures carry an oracle-bearing op but are never replayed (the
    // guard must reject them before any prove); the positive control proves a
    // REAL sealed window, which replays cleanly.
    let now = crate::now_ms();
    let observed = now / 1000 - 1;
    let normalized = admit_installed(
        &mut b,
        0,
        base_report(observed, now),
        quote_report(observed, now),
        now,
    );
    let mut gw = crate::Gw::boot();
    let (key, _owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 20_000 * perp_core::fixed::QUOTE_SCALE)
        .unwrap();
    let bc = gw.seq.state.next_batch_id;
    let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("window sealed");

    // Oracle-bearing journal: the real sealed witness plus one archived Fill.
    // (Appended after sealing, so it cannot be proven — that is exactly why the
    // negatives must be stopped by the guard, not by a replay error.)
    let mut ops = witness.ops.clone();
    ops.push(fill(0, now, transcript_of(normalized)));
    let envelope = b.bind_ops(&ops).unwrap();
    let op_journal = crate::rollback_journal::RollbackJournal {
        batch_id: witness.batch_id,
        witness: sequencer::WindowWitness {
            ops,
            ..witness.clone()
        },
        ww: ww.clone(),
        prepared: None,
    };
    let record =
        t.0.join("store")
            .join(format!("{}.json", envelope.refs[0].archive_id.hex()));

    // Intact archive: the guard passes and the prover IS invoked (control case)
    // — a REAL sealed window with its (empty-ref) envelope, proven for real.
    let control_env = b
        .bind_ops(&witness.ops)
        .expect("deposit-only window binds with an empty ref list");
    let control_journal = crate::rollback_journal::RollbackJournal {
        batch_id: witness.batch_id,
        witness,
        ww,
        prepared: None,
    };
    let prover = CountingProver(Arc::new(AtomicUsize::new(0)));
    guard_then_prove(&prover, &b, &control_journal, &control_env).expect("intact binding proves");
    assert_eq!(
        prover.0.load(Ordering::SeqCst),
        1,
        "the counting prover must run exactly once when the binding verifies"
    );

    // Missing record: guard fails, prover untouched.
    std::fs::remove_file(&record).unwrap();
    let prover = CountingProver(Arc::new(AtomicUsize::new(0)));
    let err = guard_then_prove(&prover, &b, &op_journal, &envelope)
        .expect_err("a missing record must stop the attempt");
    assert!(err.contains("archive binding"), "unexpected error: {err}");
    assert_eq!(
        prover.0.load(Ordering::SeqCst),
        0,
        "no prover invocation is permitted with a missing archive record"
    );

    // Corrupt record (preserved, not repaired): same fail-closed posture.
    std::fs::write(&record, b"corrupt").unwrap();
    let prover = CountingProver(Arc::new(AtomicUsize::new(0)));
    assert!(guard_then_prove(&prover, &b, &op_journal, &envelope).is_err());
    assert_eq!(prover.0.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(&record).unwrap(), b"corrupt");

    // Op/envelope mismatch (a price-bearing op substituted after sealing):
    // the envelope's referenced record cannot reproduce the journaled op.
    let mut tampered_ops = op_journal.witness.ops.clone();
    tampered_ops.push(fill(
        0,
        now,
        transcript_of(Normalized {
            price: normalized.price + 1,
            ..normalized
        }),
    ));
    let tampered = crate::rollback_journal::RollbackJournal {
        witness: sequencer::WindowWitness {
            ops: tampered_ops,
            ..op_journal.witness.clone()
        },
        ..op_journal.clone()
    };
    let prover = CountingProver(Arc::new(AtomicUsize::new(0)));
    let err = guard_then_prove(&prover, &b, &tampered, &envelope)
        .expect_err("a mismatched op stream must stop the attempt");
    assert!(err.contains("archive binding"), "unexpected error: {err}");
    assert_eq!(
        prover.0.load(Ordering::SeqCst),
        0,
        "no prover invocation is permitted with a mismatched op stream"
    );
}

/// Review gate: the v2 exact-resume path must reject candidate-bound journals
/// (resume_exact re-submits via prove_and_prepare → settle_proved; that stays
/// v2-only until real v3 submission is wired), and an unverifiable candidate
/// journal must never demote to "legacy" at recovery — it stays Candidate and
/// the caller HOLDs.
#[test]
fn candidate_bound_journal_is_rejected_by_v2_resume_and_never_falls_back_to_legacy() {
    use crate::rollback_journal;
    let (t, mut b) = binding("resume");
    let normalized = admit_installed(
        &mut b,
        0,
        base_report(100, NOW),
        quote_report(100, NOW),
        NOW,
    );
    let mut gw = crate::Gw::boot();
    let (key, _owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 20_000 * perp_core::fixed::QUOTE_SCALE)
        .unwrap();
    let bc = gw.seq.state.next_batch_id;
    let (mut witness, ww) = gw.begin_window_settle(bc).unwrap().expect("window sealed");
    witness.ops.push(fill(0, NOW, transcript_of(normalized)));
    let envelope = b.bind_ops(&witness.ops).unwrap();
    let journal = rollback_journal::RollbackJournal {
        batch_id: witness.batch_id,
        witness,
        ww,
        prepared: None, // the unproved stage-1 shape
    };
    let seed = [42u8; 32];
    let path = t.0.join("candidate.rollback");
    rollback_journal::write_versioned(&path, &journal, Some(&envelope), &seed).unwrap();
    let sealed = std::fs::read(&path).unwrap();

    // 1) The v2 resume gate refuses the candidate envelope — before any L1 or
    //    prover involvement (this predicate is resume_exact's first check).
    let err = clock_client_resume_gate(Some(&envelope)).expect_err("v2 resume must reject");
    assert!(err.contains("v3"), "unexpected error: {err}");
    assert!(
        clock_client_resume_gate(None).is_ok(),
        "legacy resume stays allowed"
    );

    // 2) Even with its record deleted (archive references missing) or its op
    //    stream tampered, the sealed journal still opens as CANDIDATE — never
    //    demoted to Legacy — and verification fails, so recovery HOLDs instead
    //    of falling back to the unbound path.
    std::fs::remove_dir_all(t.0.join("store")).unwrap();
    let opened = rollback_journal::open_versioned(&sealed, &seed).expect("v6 opens");
    let rollback_journal::OpenedJournal::Candidate {
        journal: reopened,
        envelope: reopened_env,
    } = opened
    else {
        panic!("a candidate journal must never read back as Legacy");
    };
    assert_eq!(reopened.batch_id, journal.batch_id);
    assert!(
        b.verify(&reopened.witness.ops, &reopened_env).is_err(),
        "with the archive gone the binding must refuse (HOLD), not fall back"
    );
}

/// Indirection so the test names the gate the boot block and resume_exact both
/// call, without needing an L1 handle.
fn clock_client_resume_gate(
    envelope: Option<&crate::rollback_journal::ArchiveEnvelope>,
) -> Result<(), String> {
    crate::clock_client::ensure_resume_supported(envelope)
}

/// Recovery boundary review: candidate mode is a runtime gate (env + in-memory
/// binding) that serde skips everywhere. The sealed `.chainlink` marker makes
/// the requirement durable: state that ever ran candidate MUST refuse to boot
/// as legacy, and the decision runs BEFORE apply_boot_recovery (incl. its
/// Stale/SealNeverPersisted journal deletions). This is the pure decision
/// matrix; main() performs the IO directly ahead of the recovery block.
#[test]
fn mode_gate_matrix_covers_disabled_missing_mismatched_and_unreadable() {
    use super::{mode_gate, ModeGate};
    let pb = [7u8; 32];
    let other = [9u8; 32];

    // Never candidate, nothing configured: the reviewed legacy path, unchanged.
    assert_eq!(mode_gate(Ok(None), None), ModeGate::Legacy);
    // First candidate boot: persist the marker before any window settles.
    assert_eq!(
        mode_gate(Ok(None), Some(pb)),
        ModeGate::CandidateWriteMarker
    );
    // Candidate reboot with the same policy: continue.
    assert_eq!(
        mode_gate(Ok(Some(pb)), Some(pb)),
        ModeGate::CandidateContinue
    );

    // DISABLED CONFIGURATION with candidate-persisted state: refuse — this is
    // the open-unsealed-window restart hazard (see next test).
    let refuse = mode_gate(Ok(Some(pb)), None);
    assert!(
        matches!(&refuse, ModeGate::Refuse(r) if r.contains("not configured")),
        "expected a not-configured refusal, got {refuse:?}"
    );
    // Mismatched policy on a marked state: refuse.
    let refuse = mode_gate(Ok(Some(pb)), Some(other));
    assert!(
        matches!(&refuse, ModeGate::Refuse(r) if r.contains("does not match")),
        "expected a policy-mismatch refusal, got {refuse:?}"
    );
    // A marker that EXISTS but cannot be read is never treated as absent.
    let refuse = mode_gate(Err("mode marker open: wrong seed".into()), None);
    assert!(
        matches!(&refuse, ModeGate::Refuse(r) if r.contains("unreadable")),
        "expected an unreadable-marker refusal, got {refuse:?}"
    );
    let refuse = mode_gate(Err("tampered".into()), Some(pb));
    assert!(matches!(&refuse, ModeGate::Refuse(r) if r.contains("unreadable")));
}

/// The exact restart hazard the marker exists for: a candidate-mode gateway
/// persisted state MID-WINDOW (restored snapshot, ops admitted from archived
/// reports, window not yet sealed — so there is NO rollback journal for any
/// journal-level guard to catch) and reboots with the env flag omitted. Only
/// the durable marker stands between that state and a silent legacy boot that
/// would keep settling unbound windows. It must refuse.
#[test]
fn candidate_state_with_open_unsealed_window_refuses_legacy_boot() {
    use super::{marker_path, mode_gate, read_marker, write_marker, ModeGate};
    let t = Temp::new("marker-gate");
    let state = t.0.join("state.snapshot");
    let seed = [42u8; 32];
    let pb = policy_binding(&policy()).unwrap();

    // Candidate mode ran and persisted its marker; the window was never sealed,
    // so no `.rollback` journal exists.
    write_marker(&marker_path(&state), pb, &seed).expect("marker write");
    assert!(matches!(
        mode_gate(read_marker(&marker_path(&state), &seed), None),
        ModeGate::Refuse(_)
    ));

    // With the flag restored (same policy), the same state boots and continues.
    assert_eq!(
        mode_gate(read_marker(&marker_path(&state), &seed), Some(pb)),
        ModeGate::CandidateContinue
    );

    // A legacy state (no marker) with the flag omitted boots unchanged, and a
    // first candidate boot on it knows it must persist the marker first.
    let legacy = Temp::new("marker-legacy");
    let legacy_state = legacy.0.join("state.snapshot");
    assert_eq!(
        mode_gate(read_marker(&marker_path(&legacy_state), &seed), None),
        ModeGate::Legacy
    );
    assert_eq!(
        mode_gate(read_marker(&marker_path(&legacy_state), &seed), Some(pb)),
        ModeGate::CandidateWriteMarker
    );
}

/// Marker IO discipline: sealed round trip, absent-vs-unreadable distinction,
/// version/magic confusion, wrong seed, and trailing bytes inside the
/// authenticated plaintext all behave fail-closed.
#[test]
fn mode_marker_round_trip_and_fail_closed_postures() {
    use super::{marker_path, read_marker, write_marker};
    use crate::snapshot;
    let t = Temp::new("marker-io");
    let state = t.0.join("state.snapshot");
    let seed = [42u8; 32];
    let pb = [3u8; 32];
    let mp = marker_path(&state);

    // Absent is the only "no marker" answer.
    assert_eq!(read_marker(&mp, &seed), Ok(None));
    write_marker(&mp, pb, &seed).expect("marker write");
    assert_eq!(read_marker(&mp, &seed), Ok(Some(pb)));

    // Wrong seed: the marker EXISTS but is unreadable → Err, never Ok(None).
    assert!(read_marker(&mp, &[43u8; 32]).is_err());
    // Tampered ciphertext → Err.
    let mut bytes = std::fs::read(&mp).unwrap();
    bytes[10] ^= 1;
    std::fs::write(&mp, &bytes).unwrap();
    assert!(read_marker(&mp, &seed).is_err());

    // Version confusion: a valid marker payload sealed under a FUTURE/unknown
    // magic is a mismatch, not an absent marker.
    let payload =
        postcard::to_allocvec(&super::CandidateModeMarkerV1 { policy_binding: pb }).unwrap();
    let mut plain = b"DPCAM9\0\0".to_vec();
    plain.extend_from_slice(&payload);
    std::fs::write(&mp, snapshot::seal(&plain, &seed)).unwrap();
    assert!(read_marker(&mp, &seed).is_err());

    // Trailing bytes inside the authenticated plaintext are refused
    // (postcard take_from_bytes + empty-remainder, same decoder rule as the
    // rollback journal).
    let mut plain = b"DPCAM1\0\0".to_vec();
    plain.extend_from_slice(
        &postcard::to_allocvec(&super::CandidateModeMarkerV1 { policy_binding: pb }).unwrap(),
    );
    plain.extend_from_slice([0xaa].as_slice());
    std::fs::write(&mp, snapshot::seal(&plain, &seed)).unwrap();
    assert!(read_marker(&mp, &seed).is_err());
}

/// Review blocker: an admission REJECTED downstream must never enter the
/// binding index — it cannot become the selectable record for its identity,
/// and it cannot shadow the accepted one.
#[test]
fn rejected_admission_is_never_installed_and_cannot_replace_or_shadow() {
    let (_t, mut b) = binding("rejected");
    // Accepted admission for identity A.
    let a = admit_installed(
        &mut b,
        0,
        base_report(100, NOW),
        quote_report(100, NOW),
        NOW,
    );
    // A later pair with a DIFFERENT transcript (identity B): stored, but the
    // gateway rejects it downstream — install is never called.
    let rejected = b
        .admit(
            0,
            base_report_price(100, 6_500_000_000_000, NOW),
            quote_report(100, NOW),
            NOW,
        )
        .unwrap();
    assert_eq!(
        b.admissions.len(),
        1,
        "rejected admission must not enter the index"
    );
    // The rejected transcript is unbindable even though its record is on disk…
    assert_eq!(
        b.bind_ops(&[fill(0, NOW, transcript_of(rejected.transcript))])
            .unwrap_err(),
        BindError::Mismatch
    );
    // …and the accepted identity still binds to its ORIGINAL ID.
    let env = b.bind_ops(&[fill(0, NOW, transcript_of(a))]).unwrap();
    assert_eq!(env.refs[0].archive_id, b.admissions[0].id);
}

/// Review blocker: two DIFFERENT original full-report records can normalize
/// identically. The FIRST ACCEPTED admission is the canonical ID for the
/// identity; a later equal-normalized record is stored but NEVER replaces the
/// selection, and missing the exact ID must Err even though the sibling exists.
#[test]
fn same_normalized_different_full_reports_keep_original_id_and_missing_exact_id_fails() {
    let (t, mut b) = binding("siblings");
    // Same body (same normalization) but different original full-report bytes:
    // vary a byte inside the (deliberately fake) signature region, which is
    // part of the archived record's identity but not of the price normalization.
    let mut first_full = full_report(feed(0x11), 6_000_000_000_000, 100);
    first_full[600] = 0x11;
    let first = report_from_full(first_full, 100, NOW);
    let mut second_full = full_report(feed(0x11), 6_000_000_000_000, 100);
    second_full[600] = 0x22;
    let second = report_from_full(second_full, 100, NOW);
    let quote = quote_report(100, NOW);

    let p1 = b.admit(0, first, quote.clone(), NOW).unwrap();
    b.install(p1).unwrap();
    let p2 = b.admit(0, second, quote, NOW).unwrap();
    b.install(p2).unwrap();
    assert_eq!(
        p1.transcript, p2.transcript,
        "same body normalizes identically"
    );
    assert_ne!(
        p1.id, p2.id,
        "different original full reports hash differently"
    );

    // Both admissions installed, but the identity resolves to the ORIGINAL ID.
    let env = b
        .bind_ops(&[fill(0, NOW, transcript_of(p1.transcript))])
        .unwrap();
    assert_eq!(
        env.refs[0].archive_id, p1.id,
        "the first accepted record is canonical"
    );

    // Delete the SELECTED record: seal must fail even though the equal-
    // normalized sibling exists. No substitution, no fallback.
    std::fs::remove_file(t.0.join("store").join(format!("{}.json", p1.id.hex()))).unwrap();
    assert_eq!(
        b.bind_ops(&[fill(0, NOW, transcript_of(p1.transcript))])
            .unwrap_err(),
        BindError::Archive,
        "a missing exact ID must fail the seal even with an equal-normalized sibling"
    );
    // Recovery verification agrees: HOLD, never the sibling.
    assert_eq!(
        b.verify(&[fill(0, NOW, transcript_of(p1.transcript))], &env),
        Err(BindError::Archive)
    );
}

/// Review blocker: capacity REFUSES rather than silently evicting — an evicted
/// identity could strand the ops of an unsealed window.
#[test]
fn capacity_refuses_instead_of_silently_evicting() {
    let t = Temp::new("capacity");
    let mut b = ArchiveBinding::create_in(&t.0, policy())
        .unwrap()
        .with_capacity(2);
    assert!(!b.is_full());
    let p1 = b
        .admit(0, base_report(100, NOW), quote_report(100, NOW), NOW)
        .unwrap();
    b.install(p1).unwrap();
    let p2 = b
        .admit(
            0,
            base_report_price(100, 6_100_000_000_000, NOW),
            quote_report(100, NOW),
            NOW,
        )
        .unwrap();
    b.install(p2).unwrap();
    assert!(b.is_full());
    // Third DISTINCT identity: install refuses; nothing is evicted.
    let p3 = b
        .admit(
            0,
            base_report_price(100, 6_200_000_000_000, NOW),
            quote_report(100, NOW),
            NOW,
        )
        .unwrap();
    assert_eq!(b.install(p3), Err(BindError::Capacity));
    assert_eq!(b.admissions.len(), 2, "no silent eviction");
    // The two retained identities still bind exactly; the refused one does not.
    assert!(b
        .bind_ops(&[fill(0, NOW, transcript_of(p1.transcript))])
        .is_ok());
    assert!(b
        .bind_ops(&[fill(0, NOW, transcript_of(p2.transcript))])
        .is_ok());
    assert_eq!(
        b.bind_ops(&[fill(0, NOW, transcript_of(p3.transcript))])
            .unwrap_err(),
        BindError::Mismatch
    );
}

/// Candidate reachability: the startup check requires the pinned policy to
/// cover EVERY configured market (pure helper), so default feed-backed market
/// sets are servable in candidate mode — the legacy intake is suppressed, not
/// the configuration refused.
#[test]
fn policy_coverage_is_the_candidate_startup_requirement() {
    assert_eq!(super::uncovered_market(&policy(), &[0]), None);
    assert_eq!(super::uncovered_market(&policy(), &[0, 1]), Some(1));
    assert_eq!(super::uncovered_market(&policy(), &[]), None);
}

/// Consolidated review: until v3 routing is wired, candidate mode has NO
/// supported submission route. The gate must refuse BEFORE any prover
/// construction / register_clock / broadcast — including zero-oracle batches —
/// while legacy mode proceeds unchanged. A counting prover proves no call
/// happens on the refused path.
#[test]
fn candidate_submission_refused_before_any_prover_call_incl_zero_oracle() {
    use crate::prover_client::{
        MockProverClient, ProverClient, ProverClientError, RemoteProveResp,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Counting(Arc<AtomicUsize>);
    impl ProverClient for Counting {
        fn prove(
            &self,
            w: &sequencer::WindowWitness,
        ) -> Result<RemoteProveResp, ProverClientError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            MockProverClient.prove(w)
        }
    }
    fn submit(
        prover: &Counting,
        envelope: Option<&crate::rollback_journal::ArchiveEnvelope>,
    ) -> Result<(), String> {
        crate::ensure_submission_supported(envelope)?;
        crate::prover_client::prove_and_prepare(prover, &real_deposit_window().0, &Vec::new())?;
        Ok(())
    }
    let (_t, mut b) = binding("submit-gate");
    let n = admit_installed(
        &mut b,
        0,
        base_report(100, NOW),
        quote_report(100, NOW),
        NOW,
    );
    let (witness, _ww) = real_deposit_window();
    let mut ops = witness.ops.clone();
    ops.push(fill(0, NOW, transcript_of(n)));
    let envelope = b.bind_ops(&ops).unwrap();
    // Candidate envelope (oracle-bearing): refused, prover untouched.
    let prover = Counting(Arc::new(AtomicUsize::new(0)));
    let err = submit(&prover, Some(&envelope)).expect_err("candidate submission must refuse");
    assert!(
        err.contains("no supported submission route"),
        "unexpected: {err}"
    );
    assert_eq!(prover.0.load(Ordering::SeqCst), 0);
    // Zero-oracle candidate batch (empty refs): STILL refused — no v3 route.
    let empty_env = crate::rollback_journal::ArchiveEnvelope {
        policy_binding: envelope.policy_binding,
        refs: Vec::new(),
    };
    let prover = Counting(Arc::new(AtomicUsize::new(0)));
    assert!(submit(&prover, Some(&empty_env)).is_err());
    assert_eq!(
        prover.0.load(Ordering::SeqCst),
        0,
        "zero-oracle candidate batch must not submit either"
    );
    // Legacy control: no envelope → the prover IS invoked.
    let prover = Counting(Arc::new(AtomicUsize::new(0)));
    submit(&prover, None).expect("legacy submission proceeds");
    assert_eq!(prover.0.load(Ordering::SeqCst), 1);
}

/// A REAL sealed window (deposit) via the real Gw, shared by the submission
/// tests; replayable, so the counting prover's success path is genuine.
fn real_deposit_window() -> (
    sequencer::WindowWitness,
    Vec<crate::withdrawals::Withdrawal>,
) {
    let mut gw = crate::Gw::boot();
    let (key, _owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 20_000 * perp_core::fixed::QUOTE_SCALE)
        .unwrap();
    let bc = gw.seq.state.next_batch_id;
    gw.begin_window_settle(bc).unwrap().expect("window sealed")
}

/// Consolidated review: partial candidate configuration must FAIL, never
/// silently disable; the policy file must be bounded, regular, non-symlink
/// public data.
#[test]
fn partial_candidate_config_fails_and_policy_file_is_hardened() {
    use super::ArchiveBinding;
    let t = Temp::new("config");
    let dir = t.0.join("store");
    // A candidate binding is needed up front to obtain a valid archive dir.
    let (_tb, b0) = binding("config-seed");
    let _ = &b0;
    let archive_dir = {
        // create a fresh operator-style dir via the streams-client API
        chainlink_streams_client::report_archive::ReportArchive::create(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    };
    let policy_path = t.0.join("policy.json");
    std::fs::write(&policy_path, serde_json::to_vec(&policy()).unwrap()).unwrap();
    let pp = policy_path.to_string_lossy().into_owned();

    // Full candidate config: accepted.
    assert!(ArchiveBinding::configured(
        Some("candidate".into()),
        Some(archive_dir.clone()),
        Some(pp.clone())
    )
    .unwrap()
    .is_some());
    // DIR or POLICY without MODE: ERROR, not silent disable.
    assert!(matches!(
        ArchiveBinding::configured(None, Some(archive_dir.clone()), None),
        Err(BindError::Config)
    ));
    assert!(matches!(
        ArchiveBinding::configured(None, None, Some(pp.clone())),
        Err(BindError::Config)
    ));
    assert!(matches!(
        ArchiveBinding::configured(None, Some(archive_dir.clone()), Some(pp.clone())),
        Err(BindError::Config)
    ));
    // Explicitly disabled must be clean.
    assert!(matches!(
        ArchiveBinding::configured(Some("disabled".into()), Some(archive_dir.clone()), None),
        Err(BindError::Config)
    ));
    assert!(
        ArchiveBinding::configured(Some("disabled".into()), None, None)
            .unwrap()
            .is_none()
    );
    // Unknown mode refuses.
    assert!(matches!(
        ArchiveBinding::configured(Some("enabled".into()), None, None),
        Err(BindError::Config)
    ));

    // Policy file hardening: symlink, directory, empty, and oversized refuse.
    let link = t.0.join("policy-link.json");
    std::os::unix::fs::symlink(&policy_path, &link).unwrap();
    assert!(matches!(
        ArchiveBinding::configured(
            Some("candidate".into()),
            Some(archive_dir.clone()),
            Some(link.to_string_lossy().into_owned())
        ),
        Err(BindError::Config)
    ));
    assert!(matches!(
        ArchiveBinding::configured(
            Some("candidate".into()),
            Some(archive_dir.clone()),
            Some(t.0.to_string_lossy().into_owned())
        ),
        Err(BindError::Config)
    ));
    let empty = t.0.join("empty.json");
    std::fs::write(&empty, b"").unwrap();
    assert!(matches!(
        ArchiveBinding::configured(
            Some("candidate".into()),
            Some(archive_dir.clone()),
            Some(empty.to_string_lossy().into_owned())
        ),
        Err(BindError::Config)
    ));
    let fat = t.0.join("fat.json");
    std::fs::write(&fat, vec![b' '; 64 * 1024 + 1]).unwrap();
    assert!(matches!(
        ArchiveBinding::configured(
            Some("candidate".into()),
            Some(archive_dir.clone()),
            Some(fat.to_string_lossy().into_owned())
        ),
        Err(BindError::Config)
    ));
}

/// THE full gateway success path, end to end, with REAL signatures and a REAL
/// engine fill (no zero-sig fixture): production-style fresh oracles → archived
/// pair admitted through the real `apply_validated_real_oracle_at` → real order
/// fills at the archived mark → real window seal → encrypted v6 journal →
/// exact read/recovery → real replay prove.
#[test]
fn real_admission_to_sealed_window_to_v6_journal_to_recovery_proves_end_to_end() {
    use crate::prover_client::{MockProverClient, ProverClient as _};
    use crate::{Gw, OrderReq};
    use perp_core::fixed::{QUOTE_SCALE, SIZE_SCALE};
    use perp_core::oracle::OracleSig;

    // Candidate mode (like the startup check) requires the pinned policy to
    // cover EVERY configured market — real windows carry maintenance oracle ops
    // for all of them.
    let mut gw = Gw::boot();
    let market_ids: Vec<u64> = gw.mkts.iter().map(|m| m.id).collect();
    let t = Temp::new("e2e");
    let mut full = policy();
    for id in market_ids.iter().skip(1).copied() {
        let mut m = full.markets[0].clone();
        m.market_id = id;
        m.base_usd_feed = feed(0x11 + id as u8);
        m.usdc_usd_feed = feed(0x22 + id as u8);
        full.markets.push(m);
    }
    full.markets.sort_by_key(|m| m.market_id);
    let mut b = ArchiveBinding::create_in(&t.0, full).unwrap();
    let (key, _owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 200_000 * QUOTE_SCALE).unwrap();
    // Production-style posture without the prod ingress gate (so the order
    // path stays reachable in the test): the demo-seeded mark must not
    // authorize trading — the ONLY subsequent price is the archived admission.
    // (In the real gateway `require_fresh_production_oracles` does this under
    // prod; here we reset market 0 directly.)
    gw.seq.set_oracle(
        0,
        perp_core::oracle::OracleTranscript {
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
    if let Some(m) = gw.mkts.iter_mut().find(|m| m.id == 0) {
        m.live = false;
        m.feed_ts = 0;
        m.px_ms = 0;
    }

    // REAL admissions for every market: archive first, then the gateway-signed
    // transcript through the real validated path (the signature recovers to the
    // market's pinned oracle_pubkey).
    let now = crate::now_ms();
    let observed = now / 1000;
    let mut transcripts = std::collections::HashMap::new();
    for &id in &market_ids {
        let base = report(feed(0x11 + id as u8), 6_000_000_000_000, observed, now);
        let quote = report(feed(0x22 + id as u8), 100_000_000, observed, now);
        let pending = b.admit(id, base, quote, now).unwrap();
        let transcript = pending.transcript.with_signature(OracleSig::sign(
            &gw.oracle_signer,
            &crate::oracle_digest(
                id,
                pending.transcript.price,
                pending.transcript.publish_time_ms,
                pending.transcript.confidence,
                pending.transcript.backup_twap,
            ),
        ));
        assert!(
            gw.apply_validated_real_oracle_at(id, transcript, now),
            "real archived admission must be accepted by the gateway"
        );
        b.install(pending).unwrap();
        transcripts.insert(id, pending.transcript);
    }

    // REAL fill: a market order crosses the house MM at the archived mark, so
    // the sealed window's Fill op carries EXACTLY the archived transcript.
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

    // Real window seal + archive binding + encrypted v6 journal, exactly as the
    // settle loop does it.
    let bc = gw.seq.state.next_batch_id;
    let (journal, envelope) = crate::begin_journaled_window_settle(
        &mut gw,
        bc,
        Some(&t.0.join("state.rollback")),
        &[42u8; 32],
        Some(&b),
    )
    .unwrap()
    .expect("candidate window sealed and journaled");
    let envelope = envelope.expect("candidate mode always binds an envelope");
    // At least the real fill; windows may also carry funding-maintenance ops.
    assert!(
        !envelope.refs.is_empty(),
        "every oracle-bearing op is bound"
    );
    assert!(
        envelope
            .refs
            .iter()
            .all(|r| transcripts.contains_key(&r.market_id)),
        "every bound op traces to an archived admission"
    );

    // Encrypted v6 journal: exact read, version dispatch, recovery verify.
    let sealed = std::fs::read(t.0.join("state.rollback")).unwrap();
    let reopened =
        crate::rollback_journal::open_versioned(&sealed, &[42u8; 32]).expect("v6 journal opens");
    let crate::rollback_journal::OpenedJournal::Candidate {
        journal: back,
        envelope: back_env,
    } = reopened
    else {
        panic!("must reopen as Candidate, never Legacy")
    };
    assert_eq!(back.witness.batch_id, journal.batch_id);
    assert!(
        back_env.policy_binding == envelope.policy_binding && back_env.refs == envelope.refs,
        "envelope survives the sealed round trip"
    );
    b.verify(&back.witness.ops, &back_env)
        .expect("recovery binding verifies");
    // The restored witness carries REAL oracle ops with REAL signatures: the
    // fill's transcript is exactly the archived market-0 admission.
    let m0 = transcripts[&0];
    assert!(back.witness.ops.iter().any(|op| matches!(
        op,
        BatchOp::Fill { oracle, .. } if oracle.price == m0.price
            && oracle.publish_time_ms == m0.publish_time_ms
            && oracle.signature != (OracleSig { r: [0; 32], s: [0; 32], v: 0 })
    )));

    // Real replay: the restored v6 witness proves to the SAME commitment a
    // fresh prove of the original produces — the full success path.
    let replay = MockProverClient
        .prove(&back.witness)
        .expect("replay proves");
    let fresh = MockProverClient
        .prove(&journal.witness)
        .expect("fresh proves");
    assert_eq!(replay.commitment, fresh.commitment);
}
