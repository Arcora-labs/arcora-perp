//! Gateway lifecycle guards. CloseOnly is a circuit breaker, not proof that
//! finalSettle ran. Read the terminal L1 flag and its root/count at one block;
//! compare under the gateway lock so an in-flight seal cannot use a stale read.
use super::*;

pub(super) const SNAPSHOT_V9: &[u8] = b"\xffDP-WIND-DOWN-v9\0";

pub(super) fn snapshot_payload(plain: &[u8]) -> Result<(&[u8], Option<bool>), String> {
    let Some(payload) = plain.strip_prefix(SNAPSHOT_V9) else {
        return Ok((plain, None));
    };
    let (flag, rest) = payload
        .split_first()
        .ok_or("missing wind-down snapshot flag")?;
    if *flag > 1 || !rest.starts_with(account_recovery::SNAPSHOT_V8) {
        return Err("invalid wind-down snapshot prefix".into());
    }
    Ok((rest, Some(*flag == 1)))
}

impl Gw {
    pub(super) fn refuse_if_wind_down_started(&self) -> Result<(), String> {
        if self.wind_down_started {
            return Err("wind-down has started; only emergency withdrawals are available".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Observation {
    pub block: u64,
    pub close_only: bool,
    pub settled: bool,
    pub batch_count: u64,
    pub root: Digest,
}

impl Observation {
    pub fn read(l1: &L1) -> Result<Self, String> {
        l1.wind_down_observation()
    }

    fn matches_settled_gateway(&self, gw: &Gw) -> bool {
        self.batch_count == gw.seq.current_window_id() && self.root == gw.last_settled_root
    }

    pub fn check_start(&self, gw: &Gw) -> Result<(), String> {
        if !self.close_only {
            return Err("L1 settlement is not in close-only".into());
        }
        if self.settled {
            return Err("wind-down phase 1 already settled on L1".into());
        }
        if gw.seq.open_window_has_ops() || gw.seq.window_has_pending_manifest() {
            return Err("seal the current ordinary window before starting wind-down".into());
        }
        if !self.matches_settled_gateway(gw) || gw.seq.state.state_root() != self.root {
            return Err("wind-down requires the local settled root and window to match L1; settlement may be in flight".into());
        }
        Ok(())
    }

    pub fn check_exit(&self, gw: &Gw) -> Result<(), String> {
        if !self.close_only || !self.settled {
            return Err("wind-down phase 1 must settle on L1 before withdrawing".into());
        }
        if !self.matches_settled_gateway(gw) {
            return Err(
                "wind-down withdrawal requires the local settled root and window to match L1"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) static ADMIN_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    use tower::ServiceExt as _;

    type RpcState = Arc<std::sync::Mutex<Observation>>;

    fn selector(sig: &str) -> String {
        hex0x(&RawKeccak::digest(sig.as_bytes())[..4])
    }

    async fn rpc(
        State(state): State<RpcState>,
        Json(req): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let o = *state.lock().unwrap();
        let result = match req["method"].as_str().unwrap() {
            "eth_getBlockByNumber" => {
                return Json(
                    serde_json::json!({"jsonrpc":"2.0","id":req["id"],"result":{"number":format!("0x{:x}",o.block),"hash":hex32(&[0x42;32])}}),
                )
            }
            "eth_chainId" => "0x14a34".into(),
            "eth_getCode" => "0x01".into(),
            "eth_getTransactionCount" => "0x0".into(),
            "eth_call" => {
                assert_eq!(
                    req["params"][1],
                    serde_json::json!({"blockHash":hex32(&[0x42;32]),"requireCanonical":true}),
                    "every read pinned"
                );
                let data = req["params"][0]["input"]
                    .as_str()
                    .or_else(|| req["params"][0]["data"].as_str())
                    .unwrap();
                if data == selector("closeOnly()") {
                    format!("0x{:064x}", u8::from(o.close_only))
                } else if data == selector("windDownSettled()") {
                    format!("0x{:064x}", u8::from(o.settled))
                } else if data == selector("batchCount()") {
                    format!("0x{:064x}", o.batch_count)
                } else if data == selector("currentStateRoot()") {
                    hex32(&o.root)
                } else {
                    panic!("unexpected read {data}")
                }
            }
            method => panic!("unexpected RPC method {method}"),
        };
        Json(serde_json::json!({"jsonrpc":"2.0","id":req["id"],"result":result}))
    }

    fn admin_request() -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/wind-down")
            .header("x-admin-key", "local-wind-down-test")
            .body(axum::body::Body::empty())
            .unwrap()
    }

    async fn request(app: &Shared, expected: StatusCode) {
        let response = build_router(app.clone(), false)
            .oneshot(admin_request())
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(status, expected, "{}", String::from_utf8_lossy(&body));
    }

    #[tokio::test]
    async fn close_only_phase_one_restart_and_phase_two_are_distinct() {
        let _env = ADMIN_ENV_LOCK.lock().await;
        let previous = std::env::var_os("FIN_ADMIN_KEY");
        std::env::set_var("FIN_ADMIN_KEY", "local-wind-down-test");
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x51; 32]).unwrap();
        let public = sk.verifying_key().to_encoded_point(false);
        let address: [u8; 20] = RawKeccak::digest(&public.as_bytes()[1..])[12..]
            .try_into()
            .unwrap();
        let (key, owner) = gw.register_account(Some(address));
        gw.account_deposit(&key, 0, 100 * QUOTE_SCALE).unwrap();
        // Model a SETTLED circuit breaker, before SettleAll. Core liquidation's
        // real trigger is separately covered by lifecycle::true_insolvency_*.
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        let initial = Observation {
            block: 100,
            close_only: true,
            settled: false,
            batch_count: gw.seq.current_window_id(),
            root: gw.last_settled_root,
        };
        let rpc_state = Arc::new(std::sync::Mutex::new(initial));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let rpc_app = Router::new()
            .route("/", post(rpc))
            .with_state(rpc_state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, rpc_app).await.unwrap();
        });
        let mut app = crate::tests::test_app();
        let inner = Arc::get_mut(&mut app).unwrap();
        inner.gw = Mutex::new(gw);
        inner.prover = Some(Arc::new(prover_client::MockProverClient));
        let mut l1 = L1::test_reader(format!("http://{addr}"));
        l1.settlement = format!("0x{}", "11".repeat(20));
        inner.l1 = Some(l1);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
        inner.snapshot_req = Some(tx);
        let writer_app = app.clone();
        let persisted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = persisted.clone();
        let writer = tokio::spawn(async move {
            while let Some(ack) = rx.recv().await {
                *capture.lock().unwrap() = writer_app.gw.lock().await.snapshot_plain();
                ack.send(true).unwrap();
            }
        });
        // The pre-phase-1 refusal must leave root, ops and auth nonce intact.
        {
            let mut gw = app.gw.lock().await;
            let before = gw.snapshot_plain();
            assert!(gw
                .account_withdraw_observed(
                    &key,
                    0,
                    QUOTE_SCALE,
                    address,
                    (1, &[0; 65]),
                    Some(&initial)
                )
                .unwrap_err()
                .contains("must settle"));
            assert_eq!(gw.snapshot_plain(), before);
        }
        request(&app, StatusCode::ACCEPTED).await;
        assert!(!persisted.lock().unwrap().is_empty());
        {
            let mut gw = app.gw.lock().await;
            let before = gw.snapshot_plain();
            gw.tick();
            assert!(gw.account_deposit(&key, 0, QUOTE_SCALE).is_err());
            assert!(gw.refuse_if_gate_closed().is_err());
            assert_eq!(
                gw.snapshot_plain(),
                before,
                "no ordinary ops after SettleAll"
            );
        }
        // Queued SettleAll survives restart and cannot be duplicated.
        let restored = Gw::boot_restored(&persisted.lock().unwrap()).unwrap();
        *app.gw.lock().await = restored;
        assert!(app.gw.lock().await.wind_down_started);
        request(&app, StatusCode::CONFLICT).await;
        let (witness, withdrawals) = app
            .gw
            .lock()
            .await
            .begin_window_settle(initial.batch_count)
            .unwrap()
            .unwrap();
        assert!(matches!(witness.ops.as_slice(), [BatchOp::SettleAll]));
        // While a sealed phase-1 proof is in flight, the open window is empty.
        // The counter/root guard still prevents a second phase-1, after restart too.
        let in_flight = app.gw.lock().await.snapshot_plain();
        *app.gw.lock().await = Gw::boot_restored(&in_flight).unwrap();
        request(&app, StatusCode::CONFLICT).await;
        {
            let mut gw = app.gw.lock().await;
            gw.seq.rollback_window(&witness);
            gw.rollback_window_withdrawals(withdrawals);
            let before = gw.snapshot_plain();
            gw.tick();
            assert_eq!(gw.snapshot_plain(), before);
        }
        let (witness, withdrawals) = app
            .gw
            .lock()
            .await
            .begin_window_settle(initial.batch_count)
            .unwrap()
            .unwrap();
        let prepared = prover_client::prove_and_prepare(
            &prover_client::MockProverClient,
            &witness,
            &withdrawals,
        )
        .unwrap();
        assert_eq!(prepared.outcome.wind_down_phase, 1);
        let settled = Observation {
            settled: true,
            batch_count: witness.batch_id + 1,
            root: prepared.outcome.new_root,
            ..initial
        };
        *rpc_state.lock().unwrap() = settled;
        app.gw.lock().await.commit_window_settle(
            witness.batch_id,
            witness.manifest.ordered,
            witness
                .manifest
                .rejected
                .into_iter()
                .map(|(hash, _)| hash)
                .collect(),
            prepared,
            L1Status::default(),
            trading_gate::GateObservation::StaysClosed,
        );
        let completed = app.gw.lock().await.snapshot_plain();
        *app.gw.lock().await = Gw::boot_restored(&completed).unwrap();
        request(&app, StatusCode::CONFLICT).await;
        // Actual HTTP withdrawal, fresh pinned L1 phase observation, real signature.
        let digest = {
            let gw = app.gw.lock().await;
            withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, QUOTE_SCALE, &address, 1)
        };
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut wire = [0; 65];
        wire[..64].copy_from_slice(&sig.to_bytes());
        wire[64] = recid.to_byte() + 27;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/accounts/withdraw")
            .header("x-api-key", hex0x(&key))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"marketId":0,"amount":QUOTE_SCALE.to_string(),
                "to":hex0x(&address),"nonce":1,"signature":hex0x(&wire)})
                .to_string(),
            ))
            .unwrap();
        let response = build_router(app.clone(), false).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // A phase-2 retry must remain phase-2 across restart and rollback;
        // neither the maintenance tick nor the retry may append ordinary ops.
        {
            let mut gw = app.gw.lock().await;
            *gw = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
            let before = gw.snapshot_plain();
            gw.tick();
            assert_eq!(gw.snapshot_plain(), before);
            let (failed, ww) = gw
                .begin_window_settle(settled.batch_count)
                .unwrap()
                .unwrap();
            gw.seq.rollback_window(&failed);
            gw.rollback_window_withdrawals(ww);
            *gw = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
            gw.tick();
        }
        let (exit, ww) = app
            .gw
            .lock()
            .await
            .begin_window_settle(settled.batch_count)
            .unwrap()
            .unwrap();
        let phase2 =
            prover_client::prove_and_prepare(&prover_client::MockProverClient, &exit, &ww).unwrap();
        assert_eq!(phase2.outcome.wind_down_phase, 2);
        assert_eq!(ww.len(), 1);
        writer.abort();
        server.abort();
        match previous {
            Some(v) => std::env::set_var("FIN_ADMIN_KEY", v),
            None => std::env::remove_var("FIN_ADMIN_KEY"),
        }
    }

    #[tokio::test]
    async fn unknown_account_is_rejected_before_l1_reads() {
        let app = crate::tests::test_app();
        app.gw.lock().await.seq.state.mode = Mode::CloseOnly;
        // No L1 configured: if the request reaches the RPC preflight it returns
        // 503 instead. Unknown credentials must not trigger external work.
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/accounts/withdraw")
            .header("x-api-key", hex0x(&[0; 32]))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"marketId":0,"amount":"1",
                "to":hex0x(&[0; 20]),"nonce":1,"signature":hex0x(&[0; 65])})
                .to_string(),
            ))
            .unwrap();
        let response = build_router(app, false).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Unknown account"));
    }

    #[test]
    fn snapshot_migrates_legacy_close_only_and_validates_the_terminal_latch() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let normal = gw.snapshot_plain();
        let mut invalid = normal.clone();
        invalid[SNAPSHOT_V9.len()] = 1;
        assert!(
            Gw::boot_restored(&invalid).is_err(),
            "normal state cannot carry a terminal latch"
        );
        invalid[SNAPSHOT_V9.len()] = 2;
        assert!(Gw::boot_restored(&invalid).is_err());
        assert!(Gw::boot_restored(SNAPSHOT_V9).is_err());
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        let current = gw.snapshot_plain();
        assert!(
            !Gw::boot_restored(&current).unwrap().wind_down_started,
            "v9 distinguishes pre-phase-1 CloseOnly from the terminal latch"
        );
        let (old_v8, _) = snapshot_payload(&current).unwrap();
        let restored = Gw::boot_restored(old_v8).unwrap();
        assert!(
            restored.wind_down_started,
            "ambiguous old CloseOnly freezes ordinary ops"
        );
        assert_eq!(restored.seq.state.state_root(), gw.seq.state.state_root());
        let observation = Observation {
            block: 100,
            close_only: true,
            settled: false,
            batch_count: restored.seq.current_window_id(),
            root: restored.last_settled_root,
        };
        assert!(
            observation.check_start(&restored).is_ok(),
            "migration does not prevent first phase-1"
        );
    }

    #[test]
    fn root_neutral_settle_all_is_sealed_after_restart() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        let root = gw.seq.state.state_root();
        gw.last_settled_root = root;
        let batch = gw.seq.current_window_id();
        assert!(!gw.seq.window_has_pending_manifest());
        gw.seq.apply(&BatchOp::SettleAll).unwrap();
        gw.wind_down_started = true;
        assert_eq!(
            gw.seq.state.state_root(),
            root,
            "fixture must be root-neutral"
        );
        let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        let (witness, withdrawals) = restored
            .begin_window_settle(batch)
            .unwrap()
            .expect("root-neutral terminal operation must not be skipped");
        assert!(matches!(witness.ops.as_slice(), [BatchOp::SettleAll]));
        let prepared = prover_client::prove_and_prepare(
            &prover_client::MockProverClient,
            &witness,
            &withdrawals,
        )
        .unwrap();
        assert_eq!(prepared.outcome.wind_down_phase, 1);
        assert_eq!(witness.pre_state.state_root(), root);
        // Sealing itself advances the batch counter, which is part of the root.
        assert_eq!(prepared.outcome.new_root, restored.seq.state.state_root());
    }

    #[test]
    fn legacy_ordinary_noop_stays_idle_across_migration_and_restart() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        let bytes = gw.snapshot_plain();
        let (v8, _) = snapshot_payload(&bytes).unwrap();
        let mut restored = Gw::boot_restored(v8).unwrap();
        assert!(
            restored.wind_down_started,
            "legacy ambiguity freezes ingress only"
        );
        for _ in 0..2 {
            let before = restored.snapshot_plain();
            assert!(restored
                .begin_window_settle(restored.seq.current_window_id())
                .unwrap()
                .is_none());
            assert_eq!(
                restored.snapshot_plain(),
                before,
                "idle window must not seal"
            );
            restored = Gw::boot_restored(&before).unwrap();
        }
    }

    #[test]
    fn ordinary_idle_funding_does_not_force_a_proof() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.last_settled_root = gw.seq.state.state_root();
        gw.tick();
        assert!(gw.seq.open_window_has_ops(), "fixture must stage funding");
        assert!(!gw.seq.window_has_pending_settle_all());
        assert_eq!(gw.seq.state.state_root(), gw.last_settled_root);
        let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert!(restored
            .begin_window_settle(restored.seq.current_window_id())
            .unwrap()
            .is_none());
    }

    #[test]
    fn legacy_root_neutral_phase_one_survives_failed_proof_retry() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        gw.seq.apply(&BatchOp::SettleAll).unwrap();
        let bytes = gw.snapshot_plain();
        let (v8, _) = snapshot_payload(&bytes).unwrap();
        let mut restored = Gw::boot_restored(v8).unwrap();
        let batch = restored.seq.current_window_id();
        for _ in 0..2 {
            restored.tick();
            let (witness, ww) = restored.begin_window_settle(batch).unwrap().unwrap();
            assert!(matches!(witness.ops.as_slice(), [BatchOp::SettleAll]));
            assert_eq!(
                prover_client::prove_and_prepare(&prover_client::MockProverClient, &witness, &ww)
                    .unwrap()
                    .outcome
                    .wind_down_phase,
                1
            );
            restored.seq.rollback_window(&witness);
            restored.rollback_window_withdrawals(ww);
            restored = Gw::boot_restored(&restored.snapshot_plain()).unwrap();
        }
    }

    #[test]
    fn legacy_mixed_phase_window_remains_rejected() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        gw.seq.apply(&BatchOp::SettleAll).unwrap();
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        let bytes = gw.snapshot_plain();
        let (v8, _) = snapshot_payload(&bytes).unwrap();
        let mut restored = Gw::boot_restored(v8).unwrap();
        let (witness, ww) = restored
            .begin_window_settle(restored.seq.current_window_id())
            .unwrap()
            .unwrap();
        assert!(
            prover_client::prove_and_prepare(&prover_client::MockProverClient, &witness, &ww)
                .is_err(),
            "intent detection must not bypass phase grammar"
        );
    }

    #[test]
    fn exit_rejects_missing_or_stale_phase_observation_without_mutation() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        let o = Observation {
            block: 100,
            close_only: true,
            settled: true,
            batch_count: gw.seq.current_window_id(),
            root: gw.last_settled_root,
        };
        for observation in [
            None,
            Some(Observation {
                settled: false,
                ..o
            }),
            Some(Observation {
                close_only: false,
                ..o
            }),
            Some(Observation {
                root: [0x55; 32],
                ..o
            }),
            Some(Observation {
                batch_count: o.batch_count + 1,
                ..o
            }),
        ] {
            let before = gw.snapshot_plain();
            assert!(gw
                .account_withdraw_observed(
                    &[0; 32],
                    0,
                    1,
                    [0; 20],
                    (1, &[0; 65]),
                    observation.as_ref()
                )
                .is_err());
            assert_eq!(gw.snapshot_plain(), before);
        }
    }
}
