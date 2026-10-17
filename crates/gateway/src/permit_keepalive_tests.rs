// Deposit permits with deadlines, the settlement gate on issuance, the L1
// challenge authorization in receipts, the liveness keepalive and the L1 health
// alerts. In-process only: no RPC, no chain, no funds.
mod permit_keepalive {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    fn terms() -> l1::DepositGateObservation {
        l1::DepositGateObservation {
            block: 1_000,
            close_only: false,
            accepting_deposits: true,
            deposit_capacity: 2_000_000_019,
            consumed_deposit_count: 3,
            last_progress_block: 1_000,
            liveness_timeout_blocks: 43_200,
        }
    }

    #[test]
    fn permit_gate_refuses_close_only_capacity_and_low_liveness_only_when_failing() {
        let ttl = 1_800;
        permit_gate(&terms(), 2_000_000_019, false, ttl).unwrap();
        assert_eq!(
            permit_gate(
                &l1::DepositGateObservation {
                    close_only: true,
                    accepting_deposits: false,
                    ..terms()
                },
                1,
                false,
                ttl
            ),
            Err(PermitGateRefusal::CloseOnly)
        );
        assert_eq!(
            permit_gate(
                &l1::DepositGateObservation {
                    accepting_deposits: false,
                    ..terms()
                },
                1,
                false,
                ttl
            ),
            Err(PermitGateRefusal::NotAccepting)
        );
        assert_eq!(
            permit_gate(&terms(), 2_000_000_020, false, ttl),
            Err(PermitGateRefusal::OverCapacity {
                capacity: 2_000_000_019
            })
        );
        // 1,800 blocks (3,600 s = two permit lifetimes) left: still issued.
        let edge = l1::DepositGateObservation {
            block: 1_000 + 43_200 - 1_800,
            ..terms()
        };
        assert_eq!(edge.remaining_liveness_secs(), 3_600);
        permit_gate(&edge, 1, true, ttl).unwrap();
        let low = l1::DepositGateObservation {
            block: edge.block + 1,
            ..terms()
        };
        assert_eq!(
            permit_gate(&low, 1, true, ttl),
            Err(PermitGateRefusal::LivenessLow {
                remaining_secs: 3_598
            })
        );
        // A healthy settle loop is not refused for low liveness alone.
        permit_gate(&low, 1, false, ttl).unwrap();
        // Past the window: nothing remains, and the count saturates.
        let expired = l1::DepositGateObservation {
            block: 1_000 + 50_000,
            ..terms()
        };
        assert_eq!(expired.remaining_liveness_secs(), 0);
    }

    #[tokio::test]
    async fn permit_refusals_are_409_with_capacity_or_503() {
        let body = |r: axum::response::Response| async move {
            let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };
        let r = permit_refusal_response(PermitGateRefusal::OverCapacity { capacity: 77 });
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(body(r).await["capacity"], "77");
        let r = permit_refusal_response(PermitGateRefusal::CloseOnly);
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert!(body(r).await["error"]
            .as_str()
            .unwrap()
            .contains("close-only"));
        let r = permit_refusal_response(PermitGateRefusal::LivenessLow { remaining_secs: 5 });
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn permit_ttl_parse_is_positive_decimal_with_a_default() {
        assert_eq!(parse_deposit_permit_ttl(None), Ok(1_800));
        assert_eq!(parse_deposit_permit_ttl(Some("")), Ok(1_800));
        assert_eq!(parse_deposit_permit_ttl(Some("600")), Ok(600));
        for bad in ["0", "-1", " 60", "60s", "0x10", "18446744073709551616"] {
            assert!(parse_deposit_permit_ttl(Some(bad)).is_err(), "{bad}");
        }
    }

    async fn json_body(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap()
    }
    fn permit_request(key: &[u8; 32], reuse: Option<&str>) -> Request<Body> {
        let mut body = serde_json::json!({"from": hex0x(&[0x42; 20]), "amount": "5000000",
            "marketId": 0, "purpose": "collateral"});
        if let Some(reuse) = reuse {
            body["reuseOwnerCommit"] = serde_json::json!(reuse);
        }
        Request::builder()
            .method("POST")
            .uri("/v1/accounts/deposit/authorize")
            .header("content-type", "application/json")
            .header("x-api-key", hex0x(key))
            .body(Body::from(body.to_string()))
            .unwrap()
    }
    fn acking_app() -> (Shared, tokio::task::JoinHandle<()>) {
        let mut app = test_app();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let writer = tokio::spawn(async move {
            while let Some(ack) = rx.recv().await {
                let _ = ack.send(true);
            }
        });
        (app, writer)
    }

    /// The response carries the stored deadline, the signature covers it, a retry
    /// re-issues the same permit while a minute is left, and a fresh permit after.
    #[tokio::test]
    async fn permit_deadline_is_signed_persisted_and_reused_only_with_time_left() {
        let (app, writer) = acking_app();
        let key = {
            let mut gw = app.gw.lock().await;
            let (key, _) = gw.register_account(None);
            gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
            key
        };
        let router = build_router(app.clone(), true);
        let before = now_ms() / 1000;
        let first = json_body(
            router
                .clone()
                .oneshot(permit_request(&key, None))
                .await
                .unwrap(),
        )
        .await;
        let until = first["validUntil"].as_u64().unwrap();
        assert!((before + DEFAULT_DEPOSIT_PERMIT_TTL_SECS
            ..=now_ms() / 1000 + DEFAULT_DEPOSIT_PERMIT_TTL_SECS)
            .contains(&until));
        let commit = parse_hex32(first["ownerCommit"].as_str().unwrap()).unwrap();
        let sig = parse_hex65(first["sig"].as_str().unwrap()).unwrap();
        assert_eq!(
            recover_eth_address(
                &app.gateway_signer
                    .digest(&[0x42; 20], &commit, 5_000_000, until),
                &sig
            ),
            Some(app.gateway_signer.address())
        );
        assert_eq!(
            app.gw.lock().await.deposits.routes[&commit].valid_until,
            until
        );
        let commit_hex = hex0x(&commit);
        let again = json_body(
            router
                .clone()
                .oneshot(permit_request(&key, Some(&commit_hex)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(again["ownerCommit"], first["ownerCommit"]);
        assert_eq!(again["validUntil"], first["validUntil"]);
        assert_eq!(again["sig"], first["sig"]);
        // Under a minute left: a fresh permit with its own deadline.
        app.gw
            .lock()
            .await
            .deposits
            .routes
            .get_mut(&commit)
            .unwrap()
            .valid_until = now_ms() / 1000 + 30;
        let fresh = json_body(
            router
                .oneshot(permit_request(&key, Some(&commit_hex)))
                .await
                .unwrap(),
        )
        .await;
        assert_ne!(fresh["ownerCommit"], first["ownerCommit"]);
        assert!(fresh["validUntil"].as_u64().unwrap() >= until);
        writer.abort();
    }

    #[tokio::test]
    async fn permits_are_refused_while_ingestion_is_halted_or_close_only_is_seen() {
        let (app, writer) = acking_app();
        let key = {
            let mut gw = app.gw.lock().await;
            let (key, _) = gw.register_account(None);
            gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
            gw.deposits.halt = Some("fixture halt".into());
            key
        };
        let router = build_router(app.clone(), true);
        let r = router
            .clone()
            .oneshot(permit_request(&key, None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(json_body(r).await.get("sig").is_none());
        {
            let mut gw = app.gw.lock().await;
            assert!(gw
                .ops_alerts
                .active()
                .contains(&ops_alerts::AlertKind::DepositHalted));
            assert!(gw.accounts[&key].deposit_authorizations.is_empty());
            gw.deposits.halt = None;
            gw.deposits.l1_close_only = true;
        }
        let r = router.oneshot(permit_request(&key, None)).await.unwrap();
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert!(app.gw.lock().await.accounts[&key]
            .deposit_authorizations
            .is_empty());
        writer.abort();
    }

    #[test]
    fn rebind_waits_for_permits_to_land_or_expire() {
        use k256::ecdsa::SigningKey;
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        let old_key = SigningKey::from_slice(&[0x31; 32]).unwrap();
        let new_key = SigningKey::from_slice(&[0x32; 32]).unwrap();
        let (old, new) = (eth_address(&old_key), eth_address(&new_key));
        let sign = |k: &SigningKey, d: &[u8; 32]| {
            let (sig, recid) = k.sign_prehash_recoverable(d).unwrap();
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(&sig.to_bytes());
            out[64] = 27 + recid.to_byte();
            out
        };
        let bind = deposit_bind_digest(gw.chain_id, &gw.vault, &owner, &old);
        gw.account_set_deposit_address(&key, old, &sign(&old_key, &bind), None)
            .unwrap();
        gw.authorize_routed_deposit(
            &key,
            old,
            5_000_000,
            0,
            deposit_ingestion::Purpose::Collateral,
            10,
        )
        .unwrap();
        let bind_new = deposit_bind_digest(gw.chain_id, &gw.vault, &owner, &new);
        let rebind = rebind_auth_digest(gw.chain_id, &gw.vault, &owner, 0, &old, &new);
        let error = gw
            .account_set_deposit_address(
                &key,
                new,
                &sign(&new_key, &bind_new),
                Some(&sign(&old_key, &rebind)),
            )
            .unwrap_err();
        assert!(error.contains("landed or expired"), "{error}");
    }

    #[test]
    fn receipt_carries_an_l1_challenge_authorization_for_the_bound_beneficiary() {
        let mut gw = Gw::boot();
        gw.chain_id = 84_532;
        let stored = WReceipt {
            order_hash: hex0x(&[0x0c; 32]),
            seq_no: 7,
            recv_time_ms: 123_456,
            batch_id_hint: 3,
            window_id: 4,
        };
        let beneficiary = [0x33; 20];
        // No settlement configured: no kit, whatever the beneficiary.
        assert!(gw.receipt_json(&stored, Some(beneficiary))["l1Challenge"].is_null());
        gw.l1_settlement = Some([0x22; 20]);
        assert!(gw.receipt_json(&stored, None)["l1Challenge"].is_null());
        let wire = gw.receipt_json(&stored, Some(beneficiary));
        let kit = &wire["l1Challenge"];
        assert_eq!(kit["chainId"], 84_532);
        assert_eq!(kit["settlement"], hex0x(&[0x22; 20]));
        assert_eq!(kit["beneficiary"], hex0x(&beneficiary));
        let auth = challenge_auth::ChallengeAuth {
            chain_id: 84_532,
            settlement: [0x22; 20],
            order_hash: [0x0c; 32],
            seq_no: 7,
            recv_time_ms: 123_456,
            batch_id_hint: 3,
            beneficiary,
        };
        let sig = parse_hex65(kit["signature"].as_str().unwrap()).unwrap();
        assert!(sig[64] == 27 || sig[64] == 28);
        assert_eq!(
            recover_eth_address(&auth.digest(), &sig),
            Some(gw.seq.enclave().eth_address())
        );
        // The receipt signature itself is unchanged by the kit.
        assert_eq!(
            wire["signature"],
            gw.receipt_json(&stored, None)["signature"]
        );
        // The cache keeps beneficiaries apart.
        let other = gw.receipt_json(&stored, Some([0x34; 20]));
        assert_eq!(other["l1Challenge"]["beneficiary"], hex0x(&[0x34; 20]));
        assert_ne!(other["l1Challenge"]["signature"], kit["signature"]);
        assert_eq!(gw.receipt_json(&stored, Some(beneficiary)), wire);
    }

    #[tokio::test]
    async fn order_accept_response_carries_the_kit_for_the_bound_address() {
        let app = test_app();
        let key = {
            let mut gw = app.gw.lock().await;
            gw.l1_settlement = Some([0x22; 20]);
            let (key, _) = gw.register_account(None);
            gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
            key
        };
        let req = Request::builder().method("POST").uri("/v1/orders")
            .header("x-api-key", hex0x(&key)).header("content-type", "application/json")
            .body(Body::from(serde_json::json!({"marketId":0,"side":"Buy","size":"1","limitPrice":"1","tif":"Gtc","reduceOnly":false}).to_string())).unwrap();
        let receipt = json_body(build_router(app.clone(), false).oneshot(req).await.unwrap()).await;
        assert_eq!(receipt["l1Challenge"]["beneficiary"], hex0x(&[0x42; 20]));
        let req = Request::builder()
            .uri("/v1/orders")
            .header("x-api-key", hex0x(&key))
            .body(Body::empty())
            .unwrap();
        let listed = json_body(build_router(app, false).oneshot(req).await.unwrap()).await;
        assert_eq!(listed["orders"][0]["receipt"], receipt);
    }

    /// An idle window is skipped, unless a keepalive is due: then it seals empty,
    /// registers untimed, replays to the same state with only the batch counter
    /// advanced, and its commit records the unchanged consumed deposit count.
    #[test]
    fn keepalive_seals_an_empty_untimed_window_only_when_idle() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.last_settled_root = gw.seq.state.state_root();
        assert!(gw.window_is_idle());
        assert!(!gw.seq.window_has_staged_ops());
        let bc = gw.seq.state.next_batch_id;
        assert!(gw.begin_window_settle_mode(bc, false).unwrap().is_none());
        assert!(gw.begin_window_settle_mode(bc + 1, true).is_err(), "desync");
        assert_eq!(gw.seq.state.next_batch_id, bc);
        let (witness, ww) = gw.begin_window_settle_mode(bc, true).unwrap().unwrap();
        assert!(ww.is_empty() && witness.ops.is_empty());
        assert_eq!(witness.batch_id, bc);
        assert_eq!(gw.seq.state.next_batch_id, bc + 1);
        let bounds = perp_core::clock::TimeBounds::derive(&witness.ops).unwrap();
        assert_eq!((bounds.first_ms, bounds.last_ms, bounds.count), (0, 0, 0));
        let prepared = prover_client::prepare_unproved(&witness, &ww).unwrap();
        assert_eq!(prepared.outcome.prev_root, gw.last_settled_root);
        assert_eq!(prepared.outcome.new_root, gw.seq.state.state_root());
        assert_eq!(prepared.outcome.wind_down_phase, 0);
        assert_eq!(
            prepared.outcome.new_deposit_count,
            gw.seq.state.consumed_deposit_count
        );
        let status = L1Status {
            settled_root: hex32(&prepared.outcome.new_root),
            batch_count: bc + 1,
            last_tx: "0xkeepalive".into(),
            bond: "0".into(),
            withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
        };
        let consumed = prepared.outcome.new_deposit_count;
        gw.commit_window_settle(
            bc,
            vec![],
            vec![],
            prepared,
            status,
            trading_gate::GateObservation::Inconclusive,
        );
        assert_eq!(gw.deposits.settled_count, Some(consumed));
        assert!(gw.window_is_idle());
        assert_eq!(gw.last_settled_root, gw.seq.state.state_root());
    }

    #[test]
    fn keepalive_waits_a_quarter_window_and_liveness_low_fires_at_half() {
        let obs = |head: u64, close_only: bool| l1::LivenessObservation {
            head,
            last_progress_block: 1_000,
            liveness_timeout_blocks: 43_200,
            close_only,
        };
        assert!(!obs(1_000 + 10_799, false).keepalive_due());
        assert_eq!(obs(1_000 + 10_799, false).blocks_until_keepalive(), 1);
        assert!(obs(1_000 + 10_800, false).keepalive_due());
        assert_eq!(obs(1_000 + 10_800, false).blocks_until_keepalive(), 0);
        assert!(!obs(1_000 + 21_599, false).liveness_low());
        assert!(obs(1_000 + 21_600, false).liveness_low());
        // Close-only ends the liveness clock: no keepalive, no alert.
        assert!(!obs(1_000 + 40_000, true).keepalive_due());
        assert!(!obs(1_000 + 40_000, true).liveness_low());
        // A head behind the recorded progress (lagging RPC) is not idle.
        assert_eq!(obs(900, false).idle_blocks(), 0);
    }

    #[test]
    fn l1_health_drives_alerts_close_only_latch_and_settled_count() {
        let mut gw = Gw::boot();
        let live = |head: u64| {
            Ok(l1::LivenessObservation {
                head,
                last_progress_block: 0,
                liveness_timeout_blocks: 100,
                close_only: false,
            })
        };
        let age = |age_ms: u64| {
            Some(Ok(Some(l1::AnchorAge {
                batch: 3,
                phase: 0,
                age_ms,
                timeout_ms: 1_000,
            })))
        };
        let fin = |close_only: bool, consumed: u64| {
            Ok(l1::SettlementFinality {
                block: 9,
                close_only,
                consumed_deposit_count: consumed,
            })
        };
        let active = |gw: &Gw| gw.ops_alerts.active();
        gw.apply_l1_health(live(49), age(1_000), fin(false, 2));
        assert!(active(&gw).is_empty());
        assert_eq!(gw.deposits.settled_count, Some(2));
        assert!(!gw.deposits.l1_close_only);
        gw.apply_l1_health(live(50), age(1_001), fin(false, 1));
        assert_eq!(
            active(&gw),
            vec![
                ops_alerts::AlertKind::StaleAnchor,
                ops_alerts::AlertKind::LivenessLow
            ]
        );
        assert_eq!(gw.deposits.settled_count, Some(2), "never decreases");
        // Failed reads keep the last state.
        gw.apply_l1_health(
            Err("rpc".into()),
            Some(Err("rpc".into())),
            Err("rpc".into()),
        );
        assert_eq!(active(&gw).len(), 2);
        let state = serde_json::to_value(gw.snapshot()).unwrap();
        assert_eq!(
            state["opsAlerts"],
            serde_json::json!(["stale_anchor", "liveness_low"])
        );
        assert_eq!(state["mode"], "Normal");
        assert_eq!(gw.v1_status_json()["mode"], "Normal");
        // Progress and a settled anchor recover both; finalized close-only latches.
        gw.apply_l1_health(live(10), Some(Ok(None)), fin(true, 4));
        assert!(active(&gw).is_empty());
        assert!(gw.deposits.l1_close_only && gw.l1_close_only_observed());
        // The public surfaces report close-only before any wind-down starts.
        assert_eq!(gw.seq.state.mode, Mode::Normal);
        assert_eq!(serde_json::to_value(gw.snapshot()).unwrap()["mode"], "CloseOnly");
        assert_eq!(gw.v1_status_json()["mode"], "CloseOnly");
        assert_eq!(gw.deposits.settled_count, Some(4));
        gw.apply_l1_health(live(10), None, fin(false, 4));
        assert!(gw.deposits.l1_close_only, "close-only is irreversible");
    }
}
