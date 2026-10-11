//! Candidate host lifecycle using owned synthetic reports/wallets only.
//! No DON verification, cryptographic SP1 proof or submission is performed.
use super::*;
use chainlink_oracle::{
    binding::{CandidateWitness, PairEvidence},
    policy::{MarketFeed, Policy},
};
use chainlink_streams_client::{
    parse_response, report_archive::ArchiveId, FeedId, Network, Request,
};
use report_archive_binding::{used_oracle, ArchiveBinding};
use std::path::PathBuf;

const NOW: u64 = 2_000_000;
const AGE: u64 = 2_000;
const SEED: [u8; 32] = [0x39; 32];

struct Fixture {
    dir: PathBuf,
    gw: Gw,
    binding: ArchiveBinding,
    key: [u8; 32],
    owner: PubKey,
    signer: k256::ecdsa::SigningKey,
    to: [u8; 20],
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn feed(byte: u8) -> [u8; 32] {
    let mut out = [byte; 32];
    out[0] = 0;
    out[1] = 3;
    out
}
fn word(n: u64) -> [u8; 32] {
    let mut out = [0; 32];
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}
fn report(
    id: [u8; 32],
    price: u64,
    observed: u64,
    received: u64,
    salt: u8,
) -> chainlink_streams_client::UnverifiedReport {
    let mut full = vec![0; 672];
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
    // Fake container signature words, never a DON authenticity claim.
    full[576..608].fill(salt);
    full[640..672].fill(0x22);
    let json = serde_json::json!({"report":{"feedID":hex32(&id), "validFromTimestamp":observed,
        "observationsTimestamp":observed,"fullReport":hex0x(&full)}});
    let request = Request::new(
        Network::Testnet,
        FeedId::parse_v3(&hex32(&id)).unwrap(),
        10_000,
    )
    .unwrap();
    parse_response(&serde_json::to_vec(&json).unwrap(), &request, received).unwrap()
}
fn binding_at(
    path: &std::path::Path,
    policy: Policy,
) -> Result<ArchiveBinding, report_archive_binding::BindError> {
    std::fs::create_dir(path).unwrap();
    ArchiveBinding::create_in(path, policy)
}
impl Fixture {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "arcora-price-{tag}-{}-{}",
            std::process::id(),
            hex0x(&csprng_bytes32())
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut gw = Gw::boot();
        let policy = Policy {
            chain_id: 84532,
            network: 0,
            verifier_proxy: [3; 20],
            oracle_wrapper: [4; 20],
            markets: gw
                .mkts
                .iter()
                .map(|m| MarketFeed {
                    market_id: m.id,
                    base_symbol: m.symbol.split('/').next().unwrap().into(),
                    base_usd_feed: feed(0x11 + m.id as u8),
                    base_decimals: 8,
                    usdc_usd_feed: feed(0x61 + m.id as u8),
                    usdc_decimals: 8,
                    max_report_age_ms: AGE,
                    max_pair_skew_ms: 1000,
                })
                .collect(),
        };
        let binding = binding_at(&dir.join("archive"), policy).unwrap();
        let signer = k256::ecdsa::SigningKey::from_slice(&[0x52; 32]).unwrap();
        let to = oracle_feed::signer_address(&signer);
        let (key, owner) = gw.register_account(None);
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(to);
        gw.account_deposit(&key, 0, 8_000 * QUOTE_SCALE).unwrap();
        // Make the original replay pre-state include setup only, like production
        // deployment baseline. All later oracle-bearing operations are real paths.
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        gw.window_settle_mode = true;
        gw.candidate_archive_required = true;
        let mut fixture = Self {
            dir,
            gw,
            binding,
            key,
            owner,
            signer,
            to,
        };
        fixture.admit_all(NOW, 60_000);
        fixture
    }
    fn admit(&mut self, market: u64, at: u64, usd: u64, salt: u8) {
        let observed = at / 1000;
        let base = report(
            feed(0x11 + market as u8),
            usd * 100_000_000,
            observed,
            at,
            salt,
        );
        let quote = report(feed(0x61 + market as u8), 100_000_000, observed, at, salt);
        let gw = &mut self.gw;
        assert!(self
            .binding
            .admit_with(market, base, quote, at, |normalized| {
                let signature = OracleSig::sign(
                    &gw.oracle_signer,
                    &oracle_digest(
                        market,
                        normalized.price,
                        normalized.publish_time_ms,
                        normalized.confidence,
                        normalized.backup_twap,
                    ),
                );
                gw.apply_validated_real_oracle_at(market, normalized.with_signature(signature), at)
            })
            .unwrap());
    }
    fn admit_all(&mut self, at: u64, usd: u64) {
        let ids: Vec<_> = self.gw.mkts.iter().map(|m| m.id).collect();
        for id in ids {
            self.admit(id, at, usd, 0x11);
        }
    }
    fn order(
        &mut self,
        side: &str,
        size: i128,
        reduce_only: bool,
        at: u64,
    ) -> Result<WReceipt, String> {
        self.gw.account_place_order_checked(
            &self.key,
            &OrderReq {
                market_id: 0,
                side: side.into(),
                size: size.to_string(),
                limit_price: "0".into(),
                tif: "Ioc".into(),
                reduce_only,
                ..Default::default()
            },
            PriceUse {
                archive: Some(&self.binding),
                now_ms: at,
            },
        )
    }
    fn tick(&mut self, at: u64) -> Result<(Vec<WEvent>, Vec<String>), String> {
        self.gw.tick_checked(PriceUse {
            archive: Some(&self.binding),
            now_ms: at,
        })
    }
    fn withdrawal_sig(&self, amount: i128, nonce: u64) -> [u8; 65] {
        let digest = withdraw_auth_digest(
            self.gw.chain_id,
            &self.gw.vault,
            &self.owner,
            0,
            amount,
            &self.to,
            nonce,
        );
        let (s, r) = self.signer.sign_prehash_recoverable(&digest).unwrap();
        let mut sig = [0; 65];
        sig[..64].copy_from_slice(&s.to_bytes());
        sig[64] = 27 + r.to_byte();
        sig
    }
    fn withdraw(&mut self, amount: i128, at: u64) -> Result<Withdrawal, String> {
        let sig = self.withdrawal_sig(amount, 1);
        self.gw.account_withdraw_checked(
            &self.key,
            0,
            amount,
            self.to,
            (1, &sig),
            WithdrawalContext {
                wind_down: None,
                price: PriceUse {
                    archive: Some(&self.binding),
                    now_ms: at,
                },
            },
        )
    }
    fn selected(&self, market: u64, at: u64) -> ArchiveId {
        let oracle = *self.gw.seq.oracle(market).unwrap();
        let env = self
            .binding
            .bind_ops(&[BatchOp::AccrueFunding {
                market_id: market,
                mark: oracle.price,
                oracle,
                now_ms: at,
            }])
            .unwrap();
        env.refs[0].archive_id
    }
    fn fingerprint(&self) -> (Vec<u8>, Vec<u8>) {
        fingerprint(&self.gw)
    }
}

fn fingerprint(gw: &Gw) -> (Vec<u8>, Vec<u8>) {
    // Covers financial state, rate/order/withdrawal nonces, history and replay
    // op stream + matcher including resting liquidity and matching sequence.
    (gw.snapshot_plain(), postcard::to_allocvec(&gw.seq).unwrap())
}

fn candidate(
    w: &sequencer::WindowWitness,
    b: &ArchiveBinding,
    archive: &std::path::Path,
) -> CandidateWitness {
    let envelope = b.bind_ops(&w.ops).unwrap();
    b.verify(&w.ops, &envelope).unwrap();
    let store =
        chainlink_streams_client::report_archive::ReportArchive::open_existing(archive).unwrap();
    let evidence: Vec<PairEvidence> = envelope
        .refs
        .iter()
        .map(|r| {
            store
                .load(r.archive_id, b.policy(), r.market_id)
                .unwrap()
                .for_operation(r.now_ms)
                .unwrap()
                .1
        })
        .collect();
    let roots =
        perp_core::commitment::derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest).unwrap();
    let times = perp_core::clock::TimeBounds::derive(&w.ops).unwrap();
    let clock = perp_core::clock::ClockContext {
        chain_id: b.policy().chain_id,
        verifier: [5; 20],
        settlement: [6; 20],
        batch_id: w.batch_id,
        previous_root: roots.prev_state_root,
        base_commitment: roots.commitment::<Keccak256>(),
        phase: roots.wind_down_phase,
        first_ms: times.first_ms,
        last_ms: times.last_ms,
        timed_ops: times.count,
        anchored_at_ms: times.last_ms,
        max_window_ms: 10_000,
        clock_skew_ms: 2_000,
    };
    CandidateWitness {
        clock: (
            w.pre_state.clone(),
            w.ops.clone(),
            w.manifest.clone(),
            clock,
        ),
        policy: b.policy().clone(),
        evidence,
    }
}

fn run_lifecycle() -> (Fixture, sequencer::WindowWitness, CandidateWitness) {
    let mut f = Fixture::new("normal");
    f.order("Buy", SIZE_SCALE, false, NOW).unwrap();
    f.tick(NOW).unwrap();
    assert_eq!(
        f.gw.seq.state.position(&f.owner, 0).unwrap().size,
        SIZE_SCALE
    );
    f.admit_all(NOW + 1_000, 60_010);
    f.order("Sell", SIZE_SCALE, true, NOW + 1_000).unwrap();
    f.tick(NOW + 1_000).unwrap();
    assert_eq!(
        f.gw.seq.state.position(&f.owner, 0).unwrap().size,
        0,
        "real reduce-only fill closes position"
    );
    let original = *f.gw.seq.oracle(0).unwrap();
    let withdrawal = f.withdraw(1_000 * QUOTE_SCALE, NOW + 1_100).unwrap();
    assert_eq!(withdrawal.amount, 1_000 * QUOTE_SCALE as u128);
    let path = f.dir.join("state.rollback");
    let batch = f.gw.seq.current_window_id();
    let (journal, envelope) =
        begin_journaled_window_settle(&mut f.gw, batch, Some(&path), &SEED, Some(&f.binding))
            .unwrap()
            .unwrap();
    let envelope = envelope.unwrap();
    f.binding.verify(&journal.witness.ops, &envelope).unwrap();
    assert!(journal
        .witness
        .ops
        .iter()
        .any(|o| matches!(o, BatchOp::Fill { .. })));
    assert!(journal
        .witness
        .ops
        .iter()
        .any(|o| matches!(o, BatchOp::AccrueFunding { .. })));
    assert!(journal
        .witness
        .ops
        .iter()
        .any(|o| matches!(o,BatchOp::Unbind {oracle,now_ms,..}
        if oracle==&original && *now_ms==NOW+1_100)));
    assert!(journal
        .witness
        .ops
        .iter()
        .any(|o| matches!(o, BatchOp::Withdraw { .. })));
    assert!(
        ensure_submission_supported(Some(&envelope)).is_err(),
        "candidate still has no submission route"
    );
    let input = candidate(&journal.witness, &f.binding, &f.dir.join("archive/store"));
    let mut bytes = chainlink_oracle::binding::WIRE_MAGIC.to_vec();
    bytes.extend(postcard::to_allocvec(&input).unwrap());
    let native = chainlink_oracle::binding::run_encoded(&bytes).unwrap();
    assert_eq!(
        native,
        chainlink_oracle::binding::run(input.clone()).unwrap()
    );
    // Native v3 evidence execution above is distinct from SP1 CPU/proof.
    let opened = rollback_journal::open_versioned(&std::fs::read(&path).unwrap(), &SEED).unwrap();
    let rollback_journal::OpenedJournal::Candidate {
        journal: back,
        envelope: back_envelope,
    } = opened
    else {
        panic!("v6 required")
    };
    assert_eq!(back_envelope.refs, envelope.refs);
    assert_eq!(
        postcard::to_allocvec(&back.witness.ops).unwrap(),
        postcard::to_allocvec(&journal.witness.ops).unwrap()
    );
    let snapshot = snapshot_plain_with_archive(&f.gw, Some(&f.binding)).unwrap();
    // Config needs a policy file; reopen with the same explicit pinned policy.
    let policy_path = f.dir.join("policy.json");
    std::fs::write(
        &policy_path,
        serde_json::to_vec(f.binding.policy()).unwrap(),
    )
    .unwrap();
    let restored = ArchiveBinding::configured(
        Some("candidate".into()),
        Some(f.dir.join("archive/store").to_string_lossy().into()),
        Some(policy_path.to_string_lossy().into()),
    );
    let mut restored = restored.unwrap().unwrap();
    assert!(matches!(
        report_archive_binding::mode_gate(Ok(Some(restored.policy_binding())), None),
        report_archive_binding::ModeGate::Refuse(_)
    ));
    assert!(report_archive_binding::restore_snapshot_plain(&snapshot, None).is_err());
    let state =
        report_archive_binding::restore_snapshot_plain(&snapshot, Some(&mut restored)).unwrap();
    let mut recovered = Gw::boot_restored(&state).unwrap();
    assert!(
        !recovered.candidate_archive_required,
        "runtime config is not persisted in the reviewed wire"
    );
    recovered.candidate_archive_required = true; // same startup runtime configuration
    assert!(snapshot_plain_with_archive(&recovered, None).is_err());
    assert!(recovered
        .require_candidate_price(
            0,
            PriceUse {
                archive: None,
                now_ms: NOW + 1_100
            }
        )
        .is_err());
    recovered
        .require_candidate_price(
            0,
            PriceUse {
                archive: Some(&restored),
                now_ms: NOW + 1_100,
            },
        )
        .unwrap();
    restored
        .recover_journal(&back.witness.ops, &back_envelope)
        .unwrap();
    restored.verify(&back.witness.ops, &back_envelope).unwrap();
    assert_eq!(
        postcard::to_allocvec(&candidate(
            &back.witness,
            &restored,
            &f.dir.join("archive/store")
        ))
        .unwrap(),
        postcard::to_allocvec(&input).unwrap()
    );
    assert!(recovered
        .account_place_order(&f.key, &OrderReq::default())
        .is_err());
    (f, journal.witness, input)
}

#[test]
fn archived_open_funding_close_signed_withdraw_and_restart_replay_v3() {
    let _ = run_lifecycle();
}

fn run_liquidation() -> (Fixture, CandidateWitness) {
    let mut f = Fixture::new("liquidate");
    f.order("Buy", SIZE_SCALE, false, NOW).unwrap();
    f.tick(NOW).unwrap();
    f.admit_all(NOW + 1_000, 53_000);
    f.tick(NOW + 1_000).unwrap();
    assert_eq!(
        f.gw.seq.state.position(&f.owner, 0).unwrap().size,
        0,
        "real maintenance liquidated position"
    );
    let path = f.dir.join("liquidation.rollback");
    let batch = f.gw.seq.current_window_id();
    let (journal, env) =
        begin_journaled_window_settle(&mut f.gw, batch, Some(&path), &SEED, Some(&f.binding))
            .unwrap()
            .unwrap();
    assert!(journal
        .witness
        .ops
        .iter()
        .any(|o| matches!(o,BatchOp::Liquidate {owner,..} if owner==&f.owner)));
    f.binding
        .verify(&journal.witness.ops, &env.unwrap())
        .unwrap();
    let input = candidate(&journal.witness, &f.binding, &f.dir.join("archive/store"));
    chainlink_oracle::binding::run(input.clone()).unwrap();
    (f, input)
}

#[test]
fn archived_liquidation_succeeds_with_valid_position_and_preserves_evidence() {
    let _ = run_liquidation();
}

#[test]
fn report_failures_refuse_orders_ticks_and_withdrawals_before_financial_mutation() {
    for cause in [
        "missing-admission",
        "missing-selected",
        "corrupt-selected",
        "wrong-transcript",
        "wrong-policy",
        "stale",
        "future",
    ] {
        let mut f = Fixture::new(cause);
        // A resting maker and a pending taker make book mutation observable.
        let maker = mk_order(
            f.gw.mm.owner,
            0,
            Side::Sell,
            SIZE_SCALE,
            60_000 * PRICE_SCALE,
            17,
            TimeInForce::Gtc,
            false,
        );
        f.gw.seq.seal_batch(&[maker], NOW);
        f.order("Buy", SIZE_SCALE / 10, false, NOW).unwrap();
        let mut at = NOW + 100;
        match cause {
            "missing-admission" => {
                let p = f.binding.policy().clone();
                f.binding = binding_at(&f.dir.join("empty"), p).unwrap();
            }
            "missing-selected" => {
                let id = f.selected(0, NOW);
                std::fs::remove_file(
                    f.dir
                        .join("archive/store")
                        .join(format!("{}.json", id.hex())),
                )
                .unwrap();
                // Equal-normalized sibling exists, but was never selected.
                let store = chainlink_streams_client::report_archive::ReportArchive::open_existing(
                    &f.dir.join("archive/store"),
                )
                .unwrap();
                let pair = chainlink_streams_client::report_pair::PreparedPair::new(
                    f.binding.policy(),
                    0,
                    report(feed(0x11), 6_000_000_000_000, NOW / 1000, NOW, 0x31),
                    report(feed(0x61), 100_000_000, NOW / 1000, NOW, 0x31),
                    NOW,
                )
                .unwrap();
                assert_ne!(store.store(&pair).unwrap().id, id);
            }
            "corrupt-selected" => {
                let id = f.selected(0, NOW);
                std::fs::write(
                    f.dir
                        .join("archive/store")
                        .join(format!("{}.json", id.hex())),
                    b"{}",
                )
                .unwrap();
            }
            "wrong-transcript" => {
                let oracle = oracle_of(61_000 * PRICE_SCALE, NOW, 0, &f.gw.oracle_signer);
                f.gw.seq.set_oracle(0, oracle);
                let m = f.gw.mkts.iter_mut().find(|m| m.id == 0).unwrap();
                m.px = oracle.price;
            }
            "wrong-policy" => {
                let mut p = f.binding.policy().clone();
                p.oracle_wrapper = [8; 20];
                f.binding = binding_at(&f.dir.join("wrong-policy"), p).unwrap();
            }
            "stale" => at = NOW + AGE + 1,
            "future" => at = NOW - 1,
            _ => unreachable!(),
        }
        let before = f.fingerprint();
        assert!(
            f.order("Buy", SIZE_SCALE / 10, false, at).is_err(),
            "order {cause}"
        );
        assert_eq!(f.fingerprint(), before, "order {cause}");
        assert!(f.tick(at).is_err(), "tick {cause}");
        assert_eq!(f.fingerprint(), before, "tick {cause}");
        assert!(f.withdraw(QUOTE_SCALE, at).is_err(), "withdraw {cause}");
        assert_eq!(f.fingerprint(), before, "withdraw {cause}");
    }
}

#[test]
fn stale_policy_at_seal_rolls_back_without_journal_even_if_engine_age_passes() {
    let mut f = Fixture::new("seal-age");
    let oracle = *f.gw.seq.oracle(0).unwrap();
    let at = NOW + AGE + 1;
    assert!(oracle
        .validate(f.gw.seq.state.markets.get(&0).unwrap(), at)
        .is_ok());
    // Emulate a prior unguarded operation. The defense-in-depth seal check
    // catches it before publishing a journal, preserving the exact open stream.
    f.gw.seq
        .apply(&BatchOp::Unbind {
            owner: f.owner,
            market_id: 0,
            amount: QUOTE_SCALE,
            blinding: [0x88; 32],
            oracle,
            now_ms: at,
        })
        .unwrap();
    let before = f.fingerprint();
    let batch = f.gw.seq.current_window_id();
    let path = f.dir.join("stale.rollback");
    assert!(
        begin_journaled_window_settle(&mut f.gw, batch, Some(&path), &SEED, Some(&f.binding))
            .is_err()
    );
    assert!(!path.exists());
    assert_eq!(f.fingerprint(), before);
}

#[test]
fn candidate_refuses_synthetic_demo_prices_and_unguarded_entrypoints() {
    let mut f = Fixture::new("demo");
    let before = f.fingerprint();
    assert!(f.gw.simulate_adl().is_err());
    assert_eq!(f.fingerprint(), before);
    let user = f.gw.user;
    let mm = f.gw.mm;
    assert!(f.gw.pool_transfer(&user, &mm, QUOTE_SCALE).is_err());
    assert_eq!(f.fingerprint(), before);
    assert!(f.gw.withdraw(QUOTE_SCALE).is_err());
    assert_eq!(f.fingerprint(), before);
    assert!(f.gw.place_order(&OrderReq::default()).is_err());
    assert_eq!(f.fingerprint(), before);
    assert!(f
        .gw
        .account_place_order(
            &f.key,
            &OrderReq {
                market_id: 0,
                side: "Buy".into(),
                size: SIZE_SCALE.to_string(),
                limit_price: "0".into(),
                tif: "Ioc".into(),
                ..Default::default()
            }
        )
        .is_err());
    assert_eq!(f.fingerprint(), before);
    f.gw.tick();
    assert_eq!(f.fingerprint(), before);
}

#[test]
fn terminal_wind_down_withdrawal_does_not_require_a_price_or_archive() {
    let mut f = Fixture::new("wind-down");
    f.gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
    f.gw.seq.apply(&BatchOp::SettleAll).unwrap();
    f.gw.wind_down_started = true;
    let witness = f.gw.seq.seal_window();
    f.gw.last_settled_root = f.gw.seq.state.state_root();
    let observation = wind_down::Observation {
        block: 42,
        close_only: true,
        settled: true,
        batch_count: f.gw.seq.current_window_id(),
        root: f.gw.last_settled_root,
    };
    let sig = f.withdrawal_sig(QUOTE_SCALE, 1);
    f.gw.account_withdraw_checked(
        &f.key,
        0,
        QUOTE_SCALE,
        f.to,
        (1, &sig),
        WithdrawalContext {
            wind_down: Some(&observation),
            price: PriceUse {
                archive: None,
                now_ms: NOW + 100_000,
            },
        },
    )
    .unwrap();
    let next = f.gw.seq.seal_window();
    assert!(next.ops.iter().all(|op| used_oracle(op).is_none()));
    assert!(witness
        .ops
        .iter()
        .any(|op| matches!(op, BatchOp::SettleAll)));
}

#[tokio::test]
async fn runtime_order_withdraw_routes_require_archive_before_financial_mutation() {
    use axum::body::Body;
    use tower::ServiceExt as _;
    let mut f = Fixture::new("route");
    f.admit_all(now_ms(), 60_000);
    let amount = 100 * QUOTE_SCALE;
    let first_sig = f.withdrawal_sig(amount, 1);
    let second_sig = f.withdrawal_sig(amount, 2);
    let app = tests::test_app();
    let empty = binding_at(&f.dir.join("route-empty"), f.binding.policy().clone()).unwrap();
    let app = std::sync::Arc::new(App {
        archive: Some(std::sync::Mutex::new(empty)),
        ..std::sync::Arc::try_unwrap(app).ok().unwrap()
    });
    std::mem::swap(&mut *app.gw.lock().await, &mut f.gw);
    let before = fingerprint(&app.gw.lock().await);
    let req = || {
        axum::http::Request::builder().method("POST").uri("/v1/orders")
        .header("Content-Type","application/json").header("X-Api-Key",hex0x(&f.key))
        .body(Body::from(serde_json::json!({"marketId":0,"side":"Buy","size":SIZE_SCALE.to_string(),"limitPrice":"0","tif":"Ioc"}).to_string())).unwrap()
    };
    let withdraw_req = |nonce: u64, sig: &[u8; 65]| {
        axum::http::Request::builder()
            .method("POST")
            .uri("/v1/accounts/withdraw")
            .header("Content-Type", "application/json")
            .header("X-Api-Key", hex0x(&f.key))
            .body(Body::from(serde_json::json!({"marketId":0,"amount":amount.to_string(),"to":hex0x(&f.to),"nonce":nonce,"signature":hex0x(sig)}).to_string()))
            .unwrap()
    };
    assert_eq!(
        build_router(app.clone(), true)
            .oneshot(req())
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        build_router(app.clone(), true)
            .oneshot(withdraw_req(1, &first_sig))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(fingerprint(&app.gw.lock().await), before);
    std::mem::swap(
        &mut *app.archive.as_ref().unwrap().lock().unwrap(),
        &mut f.binding,
    );
    assert_eq!(
        build_router(app.clone(), true)
            .oneshot(req())
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        build_router(app.clone(), true)
            .oneshot(withdraw_req(1, &first_sig))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let before = fingerprint(&app.gw.lock().await);
    let app2 = app.clone();
    let _ = std::thread::spawn(move || {
        let _g = app2.archive.as_ref().unwrap().lock().unwrap();
        panic!("poison fixture");
    })
    .join();
    assert_eq!(
        build_router(app.clone(), true)
            .oneshot(req())
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        build_router(app.clone(), true)
            .oneshot(withdraw_req(2, &second_sig))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(fingerprint(&app.gw.lock().await), before);
}

#[test]
fn candidate_seal_and_checkpoint_cannot_downgrade_when_archive_context_is_missing() {
    let mut f = Fixture::new("missing-context");
    f.order("Buy", SIZE_SCALE, false, NOW).unwrap();
    f.tick(NOW).unwrap();
    let before = fingerprint(&f.gw);
    let batch = f.gw.seq.current_batch_id();
    let journal_path = f.dir.join("no-downgrade.rollback");
    assert!(
        begin_journaled_window_settle(&mut f.gw, batch, Some(&journal_path), &SEED, None).is_err()
    );
    assert!(snapshot_plain_with_archive(&f.gw, None).is_err());
    assert_eq!(fingerprint(&f.gw), before);
    assert!(!journal_path.exists());
}

/// Export the exact successful gateway v3 lifecycle for separate pinned-ELF CPU
/// replay. Outputs are public synthetic; destination must be new and explicit.
#[test]
#[ignore = "explicit export of owned synthetic lifecycle to a fresh directory"]
fn export_candidate_price_lifecycle_for_cpu() {
    let dest = std::env::var_os("ARCORA_CHAINLINK_PRICE_LIFECYCLE_EXPORT")
        .expect("explicit fresh destination");
    let path = PathBuf::from(dest);
    std::fs::create_dir(&path).unwrap();
    use sha2::Digest as _;
    let (_fixture, _w, normal) = run_lifecycle();
    let (_liquidation, liquidated) = run_liquidation();
    let mut missing = normal.clone();
    missing.evidence.clear();
    let mut wrong = normal.clone();
    wrong.evidence[0].market_id += 1;
    let mut stale = normal.clone();
    // Change only the quote source time: native evidence validation must reject
    // before replay/public commitment, independently of publisher signatures.
    stale.evidence[0].quote.0[32..64].copy_from_slice(&word((NOW - AGE - 1000) / 1000));
    stale.evidence[0].quote.0[64..96].copy_from_slice(&word((NOW - AGE - 1000) / 1000));
    let cases = [
        ("normal-lifecycle", normal, None),
        ("liquidation", liquidated, None),
        (
            "missing-lifecycle-evidence",
            missing,
            Some(chainlink_oracle::Error::Evidence),
        ),
        (
            "wrong-lifecycle-market",
            wrong,
            Some(chainlink_oracle::Error::Evidence),
        ),
        (
            "stale-lifecycle-quote",
            stale,
            Some(chainlink_oracle::Error::Time),
        ),
    ];
    let mut rows = Vec::new();
    for (name, input, error) in cases {
        let mut bytes = chainlink_oracle::binding::WIRE_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(&input).unwrap());
        let native = chainlink_oracle::binding::run_encoded(&bytes);
        let public = if let Some(error) = error {
            assert_eq!(native, Err(error), "negative lifecycle {name}");
            Vec::new()
        } else {
            native.unwrap().commitment.to_vec()
        };
        let witness_file = format!("{name}.witness.bin");
        std::fs::write(path.join(&witness_file), &bytes).unwrap();
        std::fs::write(path.join(format!("{name}.native-public.bin")), &public).unwrap();
        rows.push(serde_json::json!({
            "name":name,"witness_file":witness_file,
            "witness_sha256":hex0x(&sha2::Sha256::digest(&bytes))[2..].to_string(),
            "witness_bytes":bytes.len(),"outcome":if error.is_some(){"REJECT"}else{"PASS"},
            "native_error":error.map(|e|format!("{e:?}")),
            "expected_commitment":hex0x(&public)[2..].to_string(),
            "op_count":input.clock.1.len(),"evidence_count":input.evidence.len()
        }));
    }
    std::fs::write(
        path.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "synthetic":true,"real_don_verified":false,"proof_generated":false,
            "candidate_submission":"HOLD","cases":rows
        }))
        .unwrap(),
    )
    .unwrap();
}
