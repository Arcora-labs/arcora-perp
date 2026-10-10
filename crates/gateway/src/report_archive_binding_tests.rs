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
fn report(id: [u8; 32], price: u64, observed: u64, received: u64) -> UnverifiedReport {
    let v = serde_json::json!({"report":{"feedID":format!("0x{}",hex(&id)),
        "validFromTimestamp":observed,"observationsTimestamp":observed,
        "fullReport":format!("0x{}",hex(&full_report(id,price,observed)))}});
    let req = Request::new(
        Network::Testnet,
        FeedId::parse_v3(&format!("0x{}", hex(&id))).unwrap(),
        AGE_MS,
    )
    .unwrap();
    parse_response(&serde_json::to_vec(&v).unwrap(), &req, received).unwrap()
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

#[test]
fn admit_persists_the_exact_record_before_returning() {
    let (_t, mut b) = binding("admit");
    let n = b
        .admit(0, base_report(100, NOW), quote_report(100, NOW), NOW)
        .unwrap();
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
    let a = b
        .admit(0, base_report(100, NOW), quote_report(100, NOW), NOW)
        .unwrap();
    let later = NOW + 5_000;
    let bpair = b
        .admit(0, base_report(101, later), quote_report(101, later), later)
        .unwrap();
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

#[test]
fn bind_fails_closed_for_unarchived_or_substituted_transcripts() {
    let (_t, mut b) = binding("closed");
    let a = b
        .admit(0, base_report(100, NOW), quote_report(100, NOW), NOW)
        .unwrap();
    // A transcript from any real archived admission binds by exact value.
    let later = b
        .admit(
            0,
            base_report_price(100, 6_100_000_000_000, NOW),
            quote_report(100, NOW),
            NOW,
        )
        .unwrap();
    assert!(b.bind_ops(&[fill(0, NOW, transcript_of(later))]).is_ok());
    // A transcript NO archived record reproduces (one-off price) refuses.
    let ghost = transcript_of(Normalized {
        price: a.price + 1,
        ..a
    });
    assert_eq!(
        b.bind_ops(&[fill(0, NOW, ghost)]).unwrap_err(),
        BindError::Mismatch
    );
    // An op at a time BEFORE every admission: no candidate at all.
    assert_eq!(
        b.bind_ops(&[fill(0, NOW - 1, transcript_of(a))])
            .unwrap_err(),
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
        let n = b
            .admit(0, base_report(100, NOW), quote_report(100, NOW), NOW)
            .unwrap();
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
    let normalized = b
        .admit(0, base_report(100, NOW), quote_report(100, NOW), NOW)
        .unwrap();

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
