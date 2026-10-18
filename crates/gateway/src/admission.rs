//! What the gateway admits: the off-chain minimums, the engine close-only gate on
//! deposits, and the provable-history admission cap.
//!
//! None of this is an engine rule; each can change without a new program key.
//!
//! * **Minimums.** A deposit permit is issued for at least `MIN_DEPOSIT_PERMIT`; a
//!   withdrawal moves at least `MIN_WITHDRAWAL` unless it takes the whole free
//!   balance of its market (so a small remainder can always leave). The order-size
//!   minimum is the sequencer's (`sequencer::MIN_ORDER_NOTIONAL`).
//! * **Engine close-only.** Once a liquidation's bad debt trips the engine into
//!   close-only, the engine refuses every deposit. The gateway then issues no
//!   deposit permit and credits no deposit, and alerts the operator: governance
//!   should call `enterCloseOnly` so the wind-down can start. A deposit that landed
//!   on L1 meanwhile is never consumed by the settled state; the vault refunds it
//!   (`refundDeposit`) once the settlement is in close-only, which anyone can force
//!   after the deposit inclusion timeout.
//! * **Admission cap.** Every batch proof re-derives the whole note tree and the
//!   nullifier log, so the cost of proving (the final wind-down included) grows with
//!   the history the state has accumulated, not with its live entries. The cap keeps
//!   that history provable: at the soft cap (80%) new deposit permits and
//!   registrations are refused; at the hard cap deposits are no longer credited
//!   either. Exits keep working at both, so funds can always leave.
use super::*;

/// The smallest deposit permit, quote-scaled ($10).
pub(crate) const MIN_DEPOSIT_PERMIT: u128 = 10 * QUOTE_SCALE as u128;

/// The smallest withdrawal, quote-scaled ($1), unless the withdrawal takes the
/// whole free balance of its market.
pub(crate) const MIN_WITHDRAWAL: i128 = QUOTE_SCALE;

/// PROVISIONAL bound on the provable history: note-tree leaves plus spent
/// nullifiers. A placeholder until the CPU measurement gate measures the bound a
/// phase-0 and a phase-1 proof can still carry, with margin; the measured value
/// replaces it. It is admission policy only and changes no program key.
pub(crate) const PROVISIONAL_MAX_PROVABLE_HISTORY: u64 = 100_000;

/// PROVISIONAL bound on position entries (the wind-down settles every one of
/// them in a single proof). Replaced by the measured value with the history bound.
pub(crate) const PROVISIONAL_MAX_POSITIONS: u64 = 10_000;

/// PROVISIONAL bound on unspent notes (the wind-down may reissue every one of
/// them in a single proof). Replaced by the measured value with the history bound.
pub(crate) const PROVISIONAL_MAX_NOTES: u64 = 20_000;

/// Returned by deposit ingestion while the engine is in close-only.
pub(crate) const ENGINE_CLOSE_ONLY_INTAKE: &str = "the engine is in close-only: no deposit is \
     credited. A deposit the settled state never consumes is refunded by the vault \
     (refundDeposit) once the settlement is in close-only, which governance can enter at \
     once and anyone can force after the deposit inclusion timeout";

/// Returned by deposit ingestion at the hard admission cap.
pub(crate) const HISTORY_CAP_INTAKE: &str = "the provable-history admission cap is reached: \
     no further deposit is credited. A deposit the settled state never consumes is refunded \
     by the vault (refundDeposit) once the settlement is in close-only";

/// The proof-relevant size of an engine state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HistorySize {
    /// Note-tree leaves plus spent nullifiers: every proof re-derives both.
    pub history: u64,
    pub positions: u64,
    pub notes: u64,
}

impl HistorySize {
    pub(crate) fn of(state: &perp_core::State<Keccak256>) -> Self {
        Self {
            history: state
                .tree
                .len()
                .saturating_add(state.nullifiers.len() as u64),
            positions: state.positions.len() as u64,
            notes: state.notes.len() as u64,
        }
    }
}

/// The admission cap: one bound per dimension of `HistorySize`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionCap {
    pub max_history: u64,
    pub max_positions: u64,
    pub max_notes: u64,
}

/// The cap a gateway runs with until the measured bounds land.
pub(crate) fn provisional_cap() -> AdmissionCap {
    AdmissionCap {
        max_history: PROVISIONAL_MAX_PROVABLE_HISTORY,
        max_positions: PROVISIONAL_MAX_POSITIONS,
        max_notes: PROVISIONAL_MAX_NOTES,
    }
}

/// 80% of `max`, rounded down.
fn soft(max: u64) -> u64 {
    max - max / 5
}

impl AdmissionCap {
    /// Whether any dimension has reached 80% of its bound: new deposit permits and
    /// registrations are refused from here on.
    pub(crate) fn soft_reached(&self, size: HistorySize) -> bool {
        size.history >= soft(self.max_history)
            || size.positions >= soft(self.max_positions)
            || size.notes >= soft(self.max_notes)
    }

    /// Whether any dimension has reached its bound: deposits are no longer credited
    /// either. Only exits remain.
    pub(crate) fn hard_reached(&self, size: HistorySize) -> bool {
        size.history >= self.max_history
            || size.positions >= self.max_positions
            || size.notes >= self.max_notes
    }
}

impl Gw {
    /// Whether the engine is in close-only while L1 is not known to be: raise (or,
    /// once L1 close-only is observed, clear) the operator alert. Returns whether
    /// the engine is in close-only at all.
    pub(crate) fn note_engine_close_only(&self) -> bool {
        let engine = self.seq.state.mode == Mode::CloseOnly;
        if engine && !self.l1_close_only_observed() {
            self.ops_alerts
                .activate(ops_alerts::AlertKind::EngineCloseOnly);
        } else {
            self.ops_alerts
                .recover(ops_alerts::AlertKind::EngineCloseOnly);
        }
        engine
    }

    /// Whether the soft admission cap is reached, raising or clearing its alert.
    pub(crate) fn note_admission_cap(&self) -> bool {
        let size = HistorySize::of(&self.seq.state);
        let reached = self.admission_cap.soft_reached(size);
        if reached {
            self.ops_alerts
                .activate(ops_alerts::AlertKind::AdmissionCapReached);
        } else {
            self.ops_alerts
                .recover(ops_alerts::AlertKind::AdmissionCapReached);
        }
        reached
    }

    /// Why a new account may not register now, if it may not.
    pub(crate) fn registration_refusal(&self) -> Option<&'static str> {
        self.note_admission_cap().then_some(
            "the provable-history admission cap is reached; registration is closed. \
             Existing accounts can still withdraw",
        )
    }

    /// Why no deposit may be credited now, if none may: the engine is in
    /// close-only, or the hard admission cap is reached.
    pub(crate) fn credit_refusal(&self) -> Option<&'static str> {
        if self.note_engine_close_only() {
            return Some(ENGINE_CLOSE_ONLY_INTAKE);
        }
        self.note_admission_cap();
        self.admission_cap
            .hard_reached(HistorySize::of(&self.seq.state))
            .then_some(HISTORY_CAP_INTAKE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    const PAYER: [u8; 20] = [0x42; 20];

    async fn json_body(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn permit_request(key: &[u8; 32], amount: u128, reuse: Option<&str>) -> Request<Body> {
        let mut body = serde_json::json!({"from": hex0x(&PAYER), "amount": amount.to_string(),
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

    fn register_request() -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/accounts")
            .extension(axum::extract::ConnectInfo(
                "10.9.0.1:4000".parse::<std::net::SocketAddr>().unwrap(),
            ))
            .body(Body::empty())
            .unwrap()
    }

    /// An app whose durability barrier always acknowledges, with one account bound
    /// to `PAYER`.
    async fn permit_app() -> (Shared, [u8; 32], tokio::task::JoinHandle<()>) {
        let mut app = crate::tests::test_app();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let writer = tokio::spawn(async move {
            while let Some(ack) = rx.recv().await {
                let _ = ack.send(true);
            }
        });
        let key = {
            let mut gw = app.gw.lock().await;
            let (key, _) = gw.register_account(None);
            gw.accounts.get_mut(&key).unwrap().deposit_address = Some(PAYER);
            key
        };
        (app, key, writer)
    }

    #[tokio::test]
    async fn a_deposit_permit_below_ten_dollars_is_refused() {
        let (app, key, writer) = permit_app().await;
        let router = build_router(app.clone(), true);
        let (status, body) = json_body(
            router
                .clone()
                .oneshot(permit_request(&key, MIN_DEPOSIT_PERMIT - 1, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("BELOW_MINIMUM"));
        assert_eq!(body["minimum"], MIN_DEPOSIT_PERMIT.to_string());
        assert!(app.gw.lock().await.deposits.routes.is_empty());
        let (status, body) = json_body(
            router
                .oneshot(permit_request(&key, MIN_DEPOSIT_PERMIT, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        writer.abort();
    }

    #[tokio::test]
    async fn engine_close_only_refuses_fresh_and_held_permits_and_alerts() {
        let (app, key, writer) = permit_app().await;
        let router = build_router(app.clone(), true);
        let (status, held) = json_body(
            router
                .clone()
                .oneshot(permit_request(&key, MIN_DEPOSIT_PERMIT, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{held}");
        let commit = held["ownerCommit"].as_str().unwrap().to_string();
        app.gw
            .lock()
            .await
            .seq
            .apply(&BatchOp::EnterCloseOnly)
            .unwrap();
        for reuse in [None, Some(commit.as_str())] {
            let (status, body) = json_body(
                router
                    .clone()
                    .oneshot(permit_request(&key, MIN_DEPOSIT_PERMIT, reuse))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "{reuse:?}: {body}");
            assert!(body["error"].as_str().unwrap().contains("close-only"));
        }
        let gw = app.gw.lock().await;
        assert!(gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::EngineCloseOnly));
        assert_eq!(gw.deposits.routes.len(), 1, "no new permit was issued");
        drop(gw);
        writer.abort();
    }

    #[tokio::test]
    async fn the_soft_cap_refuses_new_permits_and_registrations_but_not_a_held_permit() {
        let (app, key, writer) = permit_app().await;
        let router = build_router(app.clone(), true);
        let (status, held) = json_body(
            router
                .clone()
                .oneshot(permit_request(&key, MIN_DEPOSIT_PERMIT, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{held}");
        {
            let mut gw = app.gw.lock().await;
            let (other, _) = gw.register_account(None);
            gw.account_deposit(&other, 0, 100 * QUOTE_SCALE).unwrap();
            gw.admission_cap = AdmissionCap {
                max_history: 2,
                max_positions: 100,
                max_notes: 100,
            };
        }
        let (status, body) = json_body(
            router
                .clone()
                .oneshot(permit_request(&key, MIN_DEPOSIT_PERMIT, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(body["error"].as_str().unwrap().contains("admission cap"));
        let (status, body) =
            json_body(router.clone().oneshot(register_request()).await.unwrap()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(body.get("apiKey").is_none());
        // Re-signing the permit already held issues nothing new.
        let (status, again) = json_body(
            router
                .oneshot(permit_request(
                    &key,
                    MIN_DEPOSIT_PERMIT,
                    held["ownerCommit"].as_str(),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["sig"], held["sig"]);
        assert!(app
            .gw
            .lock()
            .await
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::AdmissionCapReached));
        writer.abort();
    }

    fn size(history: u64, positions: u64, notes: u64) -> HistorySize {
        HistorySize {
            history,
            positions,
            notes,
        }
    }

    #[test]
    fn the_soft_cap_is_eighty_percent_of_each_bound() {
        let cap = AdmissionCap {
            max_history: 100,
            max_positions: 10,
            max_notes: 20,
        };
        assert!(!cap.soft_reached(size(79, 7, 15)));
        assert!(cap.soft_reached(size(80, 0, 0)));
        assert!(cap.soft_reached(size(0, 8, 0)));
        assert!(cap.soft_reached(size(0, 0, 16)));
        assert!(!cap.hard_reached(size(99, 9, 19)));
        assert!(cap.hard_reached(size(100, 0, 0)));
        assert!(cap.hard_reached(size(0, 10, 0)));
        assert!(cap.hard_reached(size(0, 0, 20)));
        let provisional = provisional_cap();
        assert!(provisional.soft_reached(size(80_000, 0, 0)));
        assert!(!provisional.soft_reached(size(79_999, 7_999, 15_999)));
    }

    #[test]
    fn history_counts_tree_leaves_and_spent_nullifiers() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        assert_eq!(HistorySize::of(&gw.seq.state), size(0, 0, 0));
        let (key, _) = gw.register_account(None);
        gw.account_deposit(&key, 0, 100 * QUOTE_SCALE).unwrap();
        // The deposit mints a note (one leaf) and funding spends it (one nullifier).
        assert_eq!(HistorySize::of(&gw.seq.state), size(2, 1, 0));
    }

    #[test]
    fn the_soft_cap_closes_registration_and_raises_its_alert() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        assert_eq!(gw.registration_refusal(), None);
        let (key, _) = gw.register_account(None);
        for _ in 0..4 {
            gw.account_deposit(&key, 0, 100 * QUOTE_SCALE).unwrap();
        }
        assert_eq!(HistorySize::of(&gw.seq.state).history, 8);
        gw.admission_cap = AdmissionCap {
            max_history: 10,
            max_positions: 100,
            max_notes: 100,
        };
        assert!(gw.registration_refusal().is_some());
        assert!(gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::AdmissionCapReached));
        // Below the hard cap, deposits are still credited.
        assert_eq!(gw.credit_refusal(), None);
        gw.admission_cap.max_history = 8;
        assert_eq!(gw.credit_refusal(), Some(HISTORY_CAP_INTAKE));
        gw.admission_cap = provisional_cap();
        assert_eq!(gw.registration_refusal(), None);
        assert!(!gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::AdmissionCapReached));
    }

    #[test]
    fn engine_close_only_refuses_credit_and_alerts_until_l1_close_only() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        assert_eq!(gw.credit_refusal(), None);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        assert_eq!(gw.credit_refusal(), Some(ENGINE_CLOSE_ONLY_INTAKE));
        assert!(gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::EngineCloseOnly));
        // Once L1 is in close-only too, the deposit stays refused but there is
        // nothing left for governance to do.
        gw.deposits.l1_close_only = true;
        assert_eq!(gw.credit_refusal(), Some(ENGINE_CLOSE_ONLY_INTAKE));
        assert!(!gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::EngineCloseOnly));
    }
}
