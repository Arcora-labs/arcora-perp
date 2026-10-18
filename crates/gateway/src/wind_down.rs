//! Gateway lifecycle guards. CloseOnly is a circuit breaker, not proof that
//! finalSettle ran. Read the terminal L1 flag and its root/count at one block;
//! compare under the gateway lock so an in-flight seal cannot use a stale read.
use super::*;

impl Gw {
    pub(super) fn refuse_if_wind_down_started(&self) -> Result<(), String> {
        if self.wind_down_started {
            return Err("wind-down has started; only emergency withdrawals are available".into());
        }
        Ok(())
    }

    /// Record the phase-1 reserve leaf `SettleAll` produced: in the open window's
    /// withdrawal set (which the window's withdrawals root must match) and in the
    /// pending list the claim views read. The engine committed it under the nonce
    /// one past its last, so the withdrawal counter moves past it too.
    pub(super) fn record_reserve_sink(&mut self, leaf: Withdrawal) {
        self.next_withdraw_nonce = self.next_withdraw_nonce.max(leaf.nonce.saturating_add(1));
        self.pending_withdrawals.push(leaf.clone());
        self.window_withdrawals.push(leaf);
    }

    /// The reserve leaves this gateway holds (at most one per deployment), with
    /// their claim data once the phase-1 root is published on L1.
    pub(super) fn reserve_sink_json(&self) -> Vec<serde_json::Value> {
        self.pending_withdrawals
            .iter()
            .filter(|w| w.owner == RESERVE_SINK_OWNER)
            .map(|w| {
                let mut bundle = reserve_sink_bundle(w);
                let published = self.withdraw_proofs.get(&w.leaf());
                bundle["claimable"] = serde_json::json!(published.is_some());
                if let Some((root, proof)) = published {
                    bundle["root"] = serde_json::json!(hex0x(root));
                    bundle["proof"] =
                        serde_json::json!(proof.iter().map(|n| hex0x(n)).collect::<Vec<_>>());
                }
                bundle
            })
            .collect()
    }

    /// The public wind-down read-out: whether it started, the recipient the genesis
    /// bound, the reserve leaf, and each market's last committed signed price (the
    /// price `SettleAll` settles open positions at) with its publish time.
    pub(super) fn wind_down_status_json(&self) -> serde_json::Value {
        let markets: Vec<_> = self
            .seq
            .state
            .funding
            .iter()
            .map(|(id, f)| {
                serde_json::json!({
                    "marketId": id,
                    "lastPrice": f.last_price.to_string(),
                    "lastPriceMs": f.last_price_ms,
                })
            })
            .collect();
        serde_json::json!({
            "started": self.wind_down_started,
            "engineCloseOnly": self.seq.state.mode == Mode::CloseOnly,
            "recipient": hex0x(&self.seq.state.wind_down_recipient),
            "reserveSink": self.reserve_sink_json(),
            "markets": markets,
        })
    }
}

/// The off-chain owner tag of the phase-1 reserve leaf. It is not an account (no
/// account's owner is this constant) and is not part of the leaf, which is the
/// ordinary `(to, amount, nonce)` withdrawal leaf; it only keeps the leaf out of
/// every account's withdrawal list.
pub(crate) const RESERVE_SINK_OWNER: [u8; 32] = *b"dp.wind-down.reserve-sink.leaf..";

/// The reserve leaf among a `SettleAll`'s batch outputs: none, or exactly one with
/// a positive amount. Anything else is an engine invariant violation and refuses
/// the wind-down before anything is mutated.
pub(crate) fn reserve_sink_leaf(
    outputs: &[perp_core::engine::WithdrawalOut],
) -> Result<Option<Withdrawal>, String> {
    match outputs {
        [] => Ok(None),
        [out] => {
            let amount = u128::try_from(out.amount)
                .ok()
                .filter(|a| *a > 0)
                .ok_or("SettleAll produced a reserve leaf with a non-positive amount")?;
            Ok(Some(Withdrawal {
                owner: RESERVE_SINK_OWNER,
                to: out.to,
                amount,
                nonce: out.nonce,
            }))
        }
        _ => Err("SettleAll produced more than one withdrawal".into()),
    }
}

/// The claim bundle of a reserve leaf before the phase-1 root is published: the
/// phase-1 withdrawal tree holds only this leaf, so its root is the leaf itself and
/// `CollateralVault.claim(to, amount, nonce, [])` takes an empty proof.
pub(crate) fn reserve_sink_bundle(w: &Withdrawal) -> serde_json::Value {
    let leaf = w.leaf();
    serde_json::json!({
        "to": hex0x(&w.to),
        "amount": w.amount.to_string(),
        "nonce": w.nonce,
        "leaf": hex0x(&leaf),
        "root": hex0x(&leaf),
        "proof": Vec::<String>::new(),
    })
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

/// The settled L1 state, read at one finalized block, that the close-only rebase
/// returns the gateway to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SettledL1 {
    pub block: u64,
    pub close_only: bool,
    pub settled: bool,
    pub batch_count: u64,
    pub root: Digest,
    pub consumed_deposit_count: u64,
}

impl Gw {
    /// Whether starting the wind-down needs the close-only rebase first: L1 is in
    /// close-only before phase 1 settled, this gateway has not started the
    /// wind-down, and it holds state beyond the settled state.
    pub(super) fn close_only_rebase_applies(&self, close_only: bool, settled: bool) -> bool {
        close_only
            && !settled
            && !self.wind_down_started
            && (self.seq.open_window_has_ops()
                || self.seq.window_has_pending_manifest()
                || !self.window_withdrawals.is_empty()
                || self.seq.state.state_root() != self.last_settled_root)
    }

    /// The close-only rebase. After close-only no ordinary window can settle, so
    /// the open window is discarded and the gateway returns to the L1-settled
    /// state: the engine state, the deposit ledger (credits with an id at or above
    /// `consumedDepositCount` become refund records; the vault refunds them) and
    /// the withdrawals requested in the discarded window. Permits that have not
    /// landed are dropped with their blinds, since the vault refuses every deposit
    /// in close-only. Every precondition is checked before anything changes; the
    /// result must equal L1's root and counts. Returns the discarded window's order
    /// hashes, which the wind-down publishes as rejected (`MarketCloseOnly`).
    ///
    /// A window sealed but not settled must be resolved first (boot recovery
    /// returns a dead phase-0 window to the open window).
    pub(super) fn rebase_to_settled(&mut self, l1: &SettledL1) -> Result<Vec<Digest>, String> {
        if !l1.close_only || l1.settled {
            return Err(
                "the close-only rebase needs L1 in close-only before wind-down phase 1 settled"
                    .into(),
            );
        }
        if self.wind_down_started {
            return Err("the wind-down has already started".into());
        }
        if self.seq.current_window_id() != l1.batch_count {
            return Err(format!(
                "window {} is sealed but not settled on L1 (batchCount {}); restart so recovery can resolve it",
                self.seq.current_window_id().saturating_sub(1),
                l1.batch_count
            ));
        }
        let baseline = self.seq.window_baseline();
        let consumed = l1.consumed_deposit_count;
        if self.last_settled_root != l1.root
            || baseline.state_root() != l1.root
            || baseline.consumed_deposit_count != consumed
        {
            return Err("the local settled state is not the finalized L1 settled state".into());
        }
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
            if consumed < prefix || tip != Some(baseline.consumed_deposit_tip) {
                return Err("the deposit ledger does not reach the settled deposit prefix".into());
            }
        }
        let window = self.seq.current_window_id();
        let voided = self.seq.void_open_window();
        let dropped = self.deposits.credits.split_off(&consumed);
        if !dropped.is_empty() {
            // The ingestion anchor may point past the consumed prefix; refetch from
            // the start of the chain, which close-only stops at its first page.
            self.deposits.anchor = None;
        }
        self.deposits.refunds.extend(dropped);
        for (commit, route) in core::mem::take(&mut self.deposits.routes) {
            if let Some(account) = self.accounts.get_mut(&route.key) {
                account.deposit_authorizations.remove(&commit);
            }
        }
        let voided_withdrawals: std::collections::BTreeSet<[u8; 32]> =
            core::mem::take(&mut self.window_withdrawals)
                .iter()
                .map(Withdrawal::leaf)
                .collect();
        self.pending_withdrawals
            .retain(|w| !voided_withdrawals.contains(&w.leaf()));
        self.bootstrap =
            match core::mem::replace(&mut self.bootstrap, bootstrap::Bootstrap::NotStarted) {
                bootstrap::Bootstrap::InsuranceApplied { window_id } if window_id >= window => {
                    bootstrap::Bootstrap::NotStarted
                }
                bootstrap::Bootstrap::DepositApplied { deposit_id, .. }
                    if deposit_id >= consumed =>
                {
                    bootstrap::Bootstrap::NotStarted
                }
                other => other,
            };
        self.deposits.l1_close_only = true;
        self.note_settled_deposit_count(consumed);
        if self.seq.state.state_root() != l1.root
            || self.seq.state.consumed_deposit_count != consumed
            || self.seq.current_window_id() != l1.batch_count
        {
            return Err("the close-only rebase did not reach the L1 settled state".into());
        }
        self.validate_deposit_state()?;
        Ok(voided)
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

    /// L1 state for the rebase test: the wind-down observation plus the
    /// consumed deposit count the finalized rebase read needs.
    type RebaseRpcState = Arc<std::sync::Mutex<(Observation, u64, Vec<String>)>>;

    async fn rebase_rpc(
        State(state): State<RebaseRpcState>,
        Json(req): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let (o, consumed) = {
            let mut s = state.lock().unwrap();
            if req["method"] == "eth_getBlockByNumber" {
                let tag = req["params"][0].as_str().unwrap_or_default().to_string();
                s.2.push(tag);
            }
            (s.0, s.1)
        };
        let result = match req["method"].as_str().unwrap() {
            "eth_getBlockByNumber" => {
                return Json(
                    serde_json::json!({"jsonrpc":"2.0","id":req["id"],"result":{"number":format!("0x{:x}",o.block),"hash":hex32(&[0x42;32])}}),
                )
            }
            "eth_chainId" => "0x14a34".into(),
            "eth_call" => {
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
                } else if data == selector("consumedDepositCount()") {
                    format!("0x{consumed:064x}")
                } else {
                    panic!("unexpected read {data}")
                }
            }
            method => panic!("unexpected RPC method {method}"),
        };
        Json(serde_json::json!({"jsonrpc":"2.0","id":req["id"],"result":result}))
    }

    /// After close-only, a gateway holding an unsettled open window starts the
    /// wind-down only through the close-only rebase: the window is discarded back
    /// to the finalized settled state, SettleAll is queued, and the discarded
    /// orders are published as rejected (`MarketCloseOnly`) in the phase-1 window.
    #[tokio::test]
    async fn wind_down_after_close_only_rebases_an_unsettled_window() {
        let _env = ADMIN_ENV_LOCK.lock().await;
        let previous = std::env::var_os("FIN_ADMIN_KEY");
        std::env::set_var("FIN_ADMIN_KEY", "local-wind-down-test");
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let (key, _) = gw.register_account(None);
        gw.account_deposit(&key, 0, 100 * QUOTE_SCALE).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        let settled_root = gw.last_settled_root;
        let consumed = gw.seq.state.consumed_deposit_count;
        // Unsettled work after the last settle: a credit and a rejected order.
        gw.account_deposit(&key, 0, 5 * QUOTE_SCALE).unwrap();
        let stray = [0x5c; 32];
        gw.seq
            .reject_in_window(&[stray], perp_core::order::RejectReason::Expired);
        let window = gw.seq.current_window_id();
        let initial = Observation {
            block: 100,
            close_only: true,
            settled: false,
            batch_count: window,
            root: settled_root,
        };
        assert!(initial.check_start(&gw).is_err());
        let rpc_state: RebaseRpcState =
            Arc::new(std::sync::Mutex::new((initial, consumed, Vec::new())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let rpc_app = Router::new()
            .route("/", post(rebase_rpc))
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
        // A finalized state that differs from the local settled state refuses.
        rpc_state.lock().unwrap().1 = consumed + 1;
        request(&app, StatusCode::CONFLICT).await;
        assert!(!app.gw.lock().await.wind_down_started);
        rpc_state.lock().unwrap().1 = consumed;
        request(&app, StatusCode::ACCEPTED).await;
        assert!(
            rpc_state.lock().unwrap().2.iter().any(|t| t == "finalized"),
            "the rebase reads the finalized settled state"
        );
        let restored = Gw::boot_restored(&persisted.lock().unwrap()).unwrap();
        let mut gw = app.gw.lock().await;
        assert!(gw.wind_down_started && restored.wind_down_started);
        assert!(gw.deposits.l1_close_only);
        assert_eq!(gw.seq.state.consumed_deposit_count, consumed);
        let (witness, ww) = gw.begin_window_settle(window).unwrap().unwrap();
        assert_eq!(witness.pre_state.state_root(), settled_root);
        assert!(matches!(witness.ops.as_slice(), [BatchOp::SettleAll]));
        assert_eq!(
            witness.manifest.rejected,
            vec![(stray, perp_core::order::RejectReason::MarketCloseOnly)]
        );
        let phase1 =
            prover_client::prove_and_prepare(&prover_client::MockProverClient, &witness, &ww)
                .unwrap();
        assert_eq!(phase1.outcome.wind_down_phase, 1);
        assert_eq!(phase1.outcome.new_deposit_count, consumed);
        drop(gw);
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

    async fn request_json(app: &Shared, expected: StatusCode) -> serde_json::Value {
        let response = build_router(app.clone(), false)
            .oneshot(admin_request())
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(status, expected, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }

    /// Phase 1 pays the reserves left after every deficit to the recipient the
    /// genesis bound, as the window's only withdrawal leaf: the window's withdrawals
    /// root is that leaf, it survives a restart, and once phase 1 settles it is
    /// claimable with an empty proof. No account lists it.
    #[tokio::test]
    async fn phase_one_pays_the_reserves_to_the_bound_recipient_as_one_leaf() {
        let _env = ADMIN_ENV_LOCK.lock().await;
        let previous = std::env::var_os("FIN_ADMIN_KEY");
        std::env::set_var("FIN_ADMIN_KEY", "local-wind-down-test");
        let recipient = [0xC0; 20];
        // The demo genesis seeds the insurance fund, so there is a reserve to pay.
        let mut gw = Gw::boot_genesis(GenesisMode::Demo, recipient);
        let (key, _) = gw.register_account(None);
        let reserves =
            gw.seq.state.vault_pool + gw.seq.state.insurance_fund + gw.seq.state.treasury;
        assert!(reserves > 0);
        let last = gw.seq.state.last_withdrawal_nonce;
        gw.next_withdraw_nonce = 7;
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

        let body = request_json(&app, StatusCode::ACCEPTED).await;
        let sink = Withdrawal {
            owner: RESERVE_SINK_OWNER,
            to: recipient,
            amount: reserves as u128,
            nonce: last + 1,
        };
        let leaf = hex0x(&sink.leaf());
        assert_eq!(
            body["reserveSink"],
            serde_json::json!({
                "to": hex0x(&recipient),
                "amount": reserves.to_string(),
                "nonce": last + 1,
                "leaf": leaf,
                "root": leaf,
                "proof": [],
            })
        );
        {
            let gw = app.gw.lock().await;
            assert_eq!(gw.seq.state.last_withdrawal_nonce, last + 1);
            assert_eq!(
                gw.seq.state.vault_pool + gw.seq.state.insurance_fund + gw.seq.state.treasury,
                0,
                "the reserves left the engine"
            );
            assert_eq!(gw.window_withdrawals.len(), 1);
            assert_eq!(gw.window_withdrawals[0].leaf(), sink.leaf());
            assert_eq!(gw.next_withdraw_nonce, 7, "the counter was already ahead");
            assert!(gw.v1_withdrawals_json(&key).unwrap()["withdrawals"]
                .as_array()
                .unwrap()
                .is_empty());
            let status = gw.v1_status_json();
            assert_eq!(status["windDown"]["recipient"], hex0x(&recipient));
            assert_eq!(status["windDown"]["reserveSink"][0]["claimable"], false);
        }
        // The leaf is durable with the queued SettleAll.
        let restored = Gw::boot_restored(&persisted.lock().unwrap()).unwrap();
        assert_eq!(restored.window_withdrawals.len(), 1);
        assert_eq!(restored.pending_withdrawals.len(), 1);
        *app.gw.lock().await = restored;
        let (witness, withdrawals) = app
            .gw
            .lock()
            .await
            .begin_window_settle(initial.batch_count)
            .unwrap()
            .unwrap();
        assert!(matches!(witness.ops.as_slice(), [BatchOp::SettleAll]));
        let prepared = prover_client::prove_and_prepare(
            &prover_client::MockProverClient,
            &witness,
            &withdrawals,
        )
        .unwrap();
        assert_eq!(prepared.outcome.wind_down_phase, 1);
        assert_eq!(prepared.outcome.withdrawals_root, sink.leaf());
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
        let gw = app.gw.lock().await;
        assert_eq!(
            gw.withdraw_proofs.get(&sink.leaf()),
            Some(&(sink.leaf(), Vec::new()))
        );
        let claim = &gw.v1_status_json()["windDown"]["reserveSink"][0];
        assert_eq!(claim["claimable"], true);
        assert_eq!(claim["root"], leaf);
        assert_eq!(claim["proof"], serde_json::json!([]));
        drop(gw);
        drop(app);
        writer.abort();
        server.abort();
        match previous {
            Some(value) => std::env::set_var("FIN_ADMIN_KEY", value),
            None => std::env::remove_var("FIN_ADMIN_KEY"),
        }
    }

    /// With no recipient bound (tests and demos), phase 1 leaves the reserves in
    /// place and publishes no leaf.
    #[test]
    fn without_a_recipient_phase_one_produces_no_leaf() {
        let gw = Gw::boot();
        let mut preview = gw.seq.state.clone();
        preview.apply_op(&BatchOp::EnterCloseOnly).unwrap();
        let outputs = preview.apply_batch(&[BatchOp::SettleAll]).unwrap();
        assert!(matches!(reserve_sink_leaf(&outputs.withdrawals), Ok(None)));
        assert!(preview.insurance_fund > 0, "the reserves stay");
        let out = perp_core::engine::WithdrawalOut {
            to: [1; 20],
            amount: 0,
            nonce: 1,
        };
        assert!(reserve_sink_leaf(&[out]).is_err());
        assert!(reserve_sink_leaf(&[out, out]).is_err());
    }

    #[test]
    fn snapshot_validates_the_terminal_latch() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let normal = gw.snapshot_plain();
        let flag = snapshot::PAYLOAD_MAGIC.len();
        assert_eq!(normal[flag], 0);
        let mut invalid = normal.clone();
        invalid[flag] = 1;
        assert!(
            Gw::boot_restored(&invalid).is_err(),
            "normal state cannot carry a terminal latch"
        );
        invalid[flag] = 2;
        assert!(Gw::boot_restored(&invalid).is_err());
        assert!(Gw::boot_restored(snapshot::PAYLOAD_MAGIC).is_err());
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        let current = gw.snapshot_plain();
        let restored = Gw::boot_restored(&current).unwrap();
        assert!(
            !restored.wind_down_started,
            "the flag distinguishes pre-phase-1 CloseOnly from the terminal latch"
        );
        let observation = Observation {
            block: 100,
            close_only: true,
            settled: false,
            batch_count: restored.seq.current_window_id(),
            root: restored.last_settled_root,
        };
        assert!(
            observation.check_start(&restored).is_ok(),
            "a restored pre-phase-1 CloseOnly can still start phase 1"
        );
        gw.wind_down_started = true;
        let latched = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert!(latched.wind_down_started);
        assert_eq!(latched.seq.state.state_root(), gw.seq.state.state_root());
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
    fn latched_ordinary_noop_stays_idle_across_restart() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.wind_down_started = true;
        let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert!(restored.wind_down_started, "the latch freezes ingress only");
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
    fn latched_root_neutral_phase_one_survives_failed_proof_retry() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        gw.seq.apply(&BatchOp::SettleAll).unwrap();
        gw.wind_down_started = true;
        let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
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
    fn latched_mixed_phase_window_remains_rejected() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.seq.seal_genesis_baseline();
        gw.last_settled_root = gw.seq.state.state_root();
        gw.seq.apply(&BatchOp::SettleAll).unwrap();
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        gw.wind_down_started = true;
        let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
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
