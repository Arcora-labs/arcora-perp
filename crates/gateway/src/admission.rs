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
//!   that history provable. It reads the state together with what the outstanding
//!   permits add once their deposits are credited (a leaf and a nullifier each, and
//!   a position entry for a permit that opens one), and it keeps room for one more
//!   exit of every position entry (a leaf and a nullifier) and of every unspent note
//!   (a nullifier):
//!   - at the soft cap (80% of a bound) no new permit is issued that would add to
//!     the dimension at it (history always; position entries only for a permit that
//!     opens one), and no account is registered while the state itself is at it;
//!   - a new permit is issued only while the state, the outstanding permits, the new
//!     permit and the reserved exits fit within the history bound;
//!   - a withdrawal that would need more room than the history bound leaves is
//!     refused, unless it is a full exit (the whole balance of a closed position,
//!     which removes the entry) that uses no room another exit or credit needs.
//!
//!   So the deposit of every outstanding permit can be credited and stays within the
//!   bounds, and funds can always leave: close the position, then withdraw its whole
//!   balance. Only a state already beyond a bound (one that was lowered under it)
//!   credits no deposit and re-signs no held permit. An account that holds no
//!   position entry yet holds permits for one market at a time until its first
//!   deposit is credited, so it reserves at most one entry. The bounds
//!   (`MAX_PROVABLE_HISTORY`, `MAX_POSITIONS`, `MAX_NOTES`) are measured.
use super::*;
use std::collections::BTreeSet;

/// The smallest deposit permit, quote-scaled ($10).
pub(crate) const MIN_DEPOSIT_PERMIT: u128 = 10 * QUOTE_SCALE as u128;

/// The smallest withdrawal, quote-scaled ($1), unless the withdrawal takes the
/// whole free balance of its market.
pub(crate) const MIN_WITHDRAWAL: i128 = QUOTE_SCALE;

/// Bound on the provable history: note-tree leaves plus spent nullifiers.
///
/// Measured by the CPU measurement gate on the keccak-precompile guest
/// (`docs/audits/2026-10-19-pkg3-measurement-gate/`): the largest history, in
/// steps of 80, at which the costliest batch (a phase-1 wind-down whose shortfall
/// reissues every note) still fits one proof. A proof may take half of the 900 s
/// prover budget, less the 250 s Groth16 wrap, at an assumed proving rate of
/// 1,000,000 cycles/s; the cost counts the precompile's proving work through SP1
/// gas. GPU day re-derives this bound, and the two below, from the measured
/// proving rate. Admission policy only: changing it needs no new program key.
pub(crate) const MAX_PROVABLE_HISTORY: u64 = 13_280;

/// Bound on position entries (the wind-down settles every one of them in a
/// single proof): a tenth of `MAX_PROVABLE_HISTORY`, the ratio the gate measured
/// the bound with. Same evidence and GPU-day re-derivation.
pub(crate) const MAX_POSITIONS: u64 = 1_328;

/// Bound on unspent notes (the wind-down may reissue every one of them in a
/// single proof): a fifth of `MAX_PROVABLE_HISTORY`, the ratio the gate measured
/// the bound with. Same evidence and GPU-day re-derivation.
pub(crate) const MAX_NOTES: u64 = 2_656;

/// Returned by deposit ingestion while the engine is in close-only.
pub(crate) const ENGINE_CLOSE_ONLY_INTAKE: &str = "the engine is in close-only: no deposit is \
     credited. A deposit the settled state never consumes is refunded by the vault \
     (refundDeposit) once the settlement is in close-only, which governance can enter at \
     once and anyone can force after the deposit inclusion timeout";

/// Returned by deposit ingestion for a state beyond a provable-history bound.
pub(crate) const HISTORY_CAP_INTAKE: &str = "the state is beyond a provable-history admission \
     bound: no further deposit is credited. A deposit the settled state never consumes is \
     refunded by the vault (refundDeposit) once the settlement is in close-only";

/// Returned for a withdrawal that would need more room than the history bound leaves.
pub(crate) const HISTORY_CAP_EXIT: &str = "HISTORY_CAP: the provable-history admission cap \
     leaves no room for a partial withdrawal. A full exit is still accepted: close the \
     position, then withdraw the whole balance of this market";

/// Returned for a full exit that would need more room than the history bound leaves:
/// the account's own outstanding deposit permit for the market could reopen the entry.
pub(crate) const HISTORY_CAP_EXIT_PERMIT: &str = "HISTORY_CAP: the provable-history admission \
     cap leaves no room for this exit while this account holds an outstanding deposit permit \
     for the market; retry once that deposit is credited or the permit expires";

/// The proof-relevant size of an engine state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HistorySize {
    /// Note-tree leaves plus spent nullifiers: every proof re-derives both.
    pub history: u64,
    pub positions: u64,
    pub notes: u64,
}

impl HistorySize {
    /// Both sizes added, per dimension (saturating).
    pub(crate) fn plus(self, other: HistorySize) -> Self {
        Self {
            history: self.history.saturating_add(other.history),
            positions: self.positions.saturating_add(other.positions),
            notes: self.notes.saturating_add(other.notes),
        }
    }

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

    /// The history once every position entry and every unspent note has made one
    /// more exit: a full exit adds a leaf and a nullifier (the unbound note and its
    /// spend), a note's withdrawal one nullifier (saturating).
    pub(crate) fn with_exits(self) -> u64 {
        self.history
            .saturating_add(self.positions.saturating_mul(2))
            .saturating_add(self.notes)
    }
}

/// The admission cap: one bound per dimension of `HistorySize`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionCap {
    pub max_history: u64,
    pub max_positions: u64,
    pub max_notes: u64,
}

/// The cap every gateway runs with: the measured bounds.
pub(crate) fn measured_cap() -> AdmissionCap {
    AdmissionCap {
        max_history: MAX_PROVABLE_HISTORY,
        max_positions: MAX_POSITIONS,
        max_notes: MAX_NOTES,
    }
}

/// 80% of `max`, rounded up (`max` less a fifth of it, the fifth rounded down).
fn soft(max: u64) -> u64 {
    max - max / 5
}

/// What crediting one deposit adds: a leaf and a nullifier, and the position entry
/// it opens, if any.
fn credit_of(opens: bool) -> HistorySize {
    HistorySize {
        history: 2,
        positions: u64::from(opens),
        notes: 0,
    }
}

impl AdmissionCap {
    /// Whether any dimension has reached 80% of its bound: the soft-cap alert, and
    /// for the state itself, closed registration.
    pub(crate) fn soft_reached(&self, size: HistorySize) -> bool {
        size.history >= soft(self.max_history)
            || size.positions >= soft(self.max_positions)
            || size.notes >= soft(self.max_notes)
    }

    /// Whether `size`, with one more exit of every position entry and note, fits the
    /// history bound.
    pub(crate) fn exits_fit(&self, size: HistorySize) -> bool {
        size.with_exits() <= self.max_history
    }

    /// Whether any dimension is beyond its bound: a state the measurement did not
    /// show provable. Only a bound lowered under an existing state reaches it.
    pub(crate) fn exceeded(&self, size: HistorySize) -> bool {
        size.history > self.max_history
            || size.positions > self.max_positions
            || size.notes > self.max_notes
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

    /// Whether `key` holds an outstanding collateral permit for `market`.
    fn holds_collateral_permit(&self, key: &[u8; 32], market: u64) -> bool {
        self.accounts.get(key).is_some_and(|account| {
            account.deposit_authorizations.keys().any(|commit| {
                self.deposits.routes.get(commit).is_some_and(|route| {
                    route.key == *key
                        && route.market == market
                        && route.purpose == deposit_ingestion::Purpose::Collateral
                })
            })
        })
    }

    /// Whether `key`'s account holds a position entry in any market.
    fn holds_any_position(&self, key: &[u8; 32]) -> bool {
        self.accounts.get(key).is_some_and(|account| {
            let owner = account.wallet.owner;
            self.seq
                .state
                .positions
                .range((owner, 0)..=(owner, u64::MAX))
                .next()
                .is_some()
        })
    }

    /// Whether a new permit for `key`, `market` and `purpose` would open a position
    /// entry once credited that the outstanding permits do not already count: a
    /// collateral permit for a market where the account holds no entry and no
    /// outstanding collateral permit.
    fn permit_opens_entry(
        &self,
        key: &[u8; 32],
        market: u64,
        purpose: deposit_ingestion::Purpose,
    ) -> bool {
        purpose == deposit_ingestion::Purpose::Collateral
            && self.accounts.get(key).is_some_and(|account| {
                self.seq
                    .state
                    .position(&account.wallet.owner, market)
                    .is_none()
            })
            && !self.holds_collateral_permit(key, market)
    }

    /// What crediting the deposits of every outstanding permit adds to the state:
    /// each deposit mints a note and spends it into a position or the insurance
    /// fund (one tree leaf and one nullifier), and a collateral deposit opens a
    /// position entry when its account holds none in that market yet. It adds no
    /// unspent note.
    pub(crate) fn outstanding_permit_size(&self) -> HistorySize {
        let mut history = 0u64;
        let mut opened = BTreeSet::new();
        for route in self.deposits.routes.values() {
            history = history.saturating_add(2);
            if route.purpose != deposit_ingestion::Purpose::Collateral {
                continue;
            }
            if let Some(account) = self.accounts.get(&route.key) {
                let owner = account.wallet.owner;
                if self.seq.state.position(&owner, route.market).is_none() {
                    opened.insert((owner, route.market));
                }
            }
        }
        HistorySize {
            history,
            positions: opened.len() as u64,
            notes: 0,
        }
    }

    /// The state together with what the outstanding permits add once credited.
    pub(crate) fn admission_size(&self) -> HistorySize {
        HistorySize::of(&self.seq.state).plus(self.outstanding_permit_size())
    }

    /// Whether a deposit can still be credited at all (no wind-down, no close-only):
    /// only then do the outstanding permits take room an exit cannot use.
    fn permits_creditable(&self) -> bool {
        !self.wind_down_started
            && !self.deposits.l1_close_only
            && self.seq.state.mode != Mode::CloseOnly
    }

    /// Whether the soft admission cap is reached, counting what the outstanding
    /// permits will add, raising or clearing its alert.
    pub(crate) fn note_admission_cap(&self) -> bool {
        let reached = self.admission_cap.soft_reached(self.admission_size());
        if reached {
            self.ops_alerts
                .activate(ops_alerts::AlertKind::AdmissionCapReached);
        } else {
            self.ops_alerts
                .recover(ops_alerts::AlertKind::AdmissionCapReached);
        }
        reached
    }

    /// Why a new account may not register now, if it may not: the state itself is
    /// at the soft cap. Outstanding permits never close registration.
    pub(crate) fn registration_refusal(&self) -> Option<&'static str> {
        self.note_admission_cap();
        self.admission_cap
            .soft_reached(HistorySize::of(&self.seq.state))
            .then_some(
                "the provable-history admission cap is reached; registration is closed. \
                 Existing accounts can still withdraw",
            )
    }

    /// Why a new deposit permit for `key`, `market` and `purpose` may not be issued
    /// under the admission cap, if it may not: an account with no position entry
    /// already reserves an entry in another market; the soft cap is reached in a
    /// dimension the permit adds to; or the permit would leave too little history
    /// for the reserved exits.
    pub(crate) fn permit_cap_refusal(
        &self,
        key: &[u8; 32],
        market: u64,
        purpose: deposit_ingestion::Purpose,
    ) -> Option<PermitGateRefusal> {
        self.note_admission_cap();
        let opens = self.permit_opens_entry(key, market, purpose);
        if opens && !self.holds_any_position(key) {
            let reserved_elsewhere = self.accounts.get(key).is_some_and(|account| {
                account.deposit_authorizations.keys().any(|commit| {
                    self.deposits.routes.get(commit).is_some_and(|route| {
                        route.purpose == deposit_ingestion::Purpose::Collateral
                            && route.market != market
                    })
                })
            });
            if reserved_elsewhere {
                return Some(PermitGateRefusal::OneMarketUntilFirstDeposit);
            }
        }
        let size = self.admission_size();
        let cap = &self.admission_cap;
        let refused = size.history >= soft(cap.max_history)
            || (opens && size.positions >= soft(cap.max_positions))
            || !cap.exits_fit(size.plus(credit_of(opens)));
        refused.then_some(PermitGateRefusal::AdmissionCap)
    }

    /// Whether crediting the deposit of the held permit `commit` now would take the
    /// state beyond a bound: then it is not re-signed.
    pub(crate) fn held_permit_beyond_cap(&self, commit: &[u8; 32]) -> bool {
        let opens = self.deposits.routes.get(commit).is_some_and(|route| {
            route.purpose == deposit_ingestion::Purpose::Collateral
                && self.accounts.get(&route.key).is_some_and(|account| {
                    self.seq
                        .state
                        .position(&account.wallet.owner, route.market)
                        .is_none()
                })
        });
        self.admission_cap
            .exceeded(HistorySize::of(&self.seq.state).plus(credit_of(opens)))
    }

    /// What crediting `page` adds to the state: a leaf and a nullifier per deposit
    /// (one nullifier for a resumed insurance bootstrap), and the position entries
    /// its collateral deposits open. An event without a route adds nothing here;
    /// ingestion refuses it.
    pub(crate) fn page_credit_size(&self, page: &deposit_rpc::Page) -> HistorySize {
        let mut opened = BTreeSet::new();
        for event in &page.events {
            let Some(route) = self.deposits.routes.get(&event.commit) else {
                continue;
            };
            if route.purpose != deposit_ingestion::Purpose::Collateral {
                continue;
            }
            if let Some(account) = self.accounts.get(&route.key) {
                let owner = account.wallet.owner;
                if self.seq.state.position(&owner, route.market).is_none() {
                    opened.insert((owner, route.market));
                }
            }
        }
        let resume = u64::from(matches!(
            self.bootstrap,
            bootstrap::Bootstrap::DepositApplied { .. }
        ));
        HistorySize {
            history: (page.events.len() as u64)
                .saturating_mul(2)
                .saturating_add(resume),
            positions: opened.len() as u64,
            notes: 0,
        }
    }

    /// Why no deposit may be credited now, if none may: the engine is in
    /// close-only, or crediting `credit` would take the state beyond a bound. The
    /// cap never refuses the deposit of a permit it counted: every admitted permit
    /// and exit keeps the state, the outstanding permits and the reserved exits
    /// within the bounds.
    pub(crate) fn credit_refusal(&self, credit: HistorySize) -> Option<&'static str> {
        if self.note_engine_close_only() {
            return Some(ENGINE_CLOSE_ONLY_INTAKE);
        }
        self.note_admission_cap();
        self.admission_cap
            .exceeded(HistorySize::of(&self.seq.state).plus(credit))
            .then_some(HISTORY_CAP_INTAKE)
    }

    /// Why a withdrawal of `amount` from `owner`'s (account `key`) entry in `market`
    /// may not be applied under the admission cap, if it may not. Each withdrawal
    /// adds a leaf and a nullifier. A full exit (a closed position's whole balance)
    /// also removes the entry and its reserved exit, so it needs no room, unless the
    /// account holds an outstanding permit for the market that could reopen it.
    /// Every other withdrawal needs the room the reserved exits and the outstanding
    /// permits leave under the history bound.
    pub(crate) fn exit_cap_refusal(
        &self,
        key: &[u8; 32],
        owner: &PubKey,
        market: u64,
        amount: i128,
    ) -> Option<&'static str> {
        let creditable = self.permits_creditable();
        let state = HistorySize::of(&self.seq.state);
        let before = if creditable {
            state.plus(self.outstanding_permit_size())
        } else {
            state
        };
        let full_exit = self
            .seq
            .state
            .position(owner, market)
            .is_some_and(|p| p.size == 0 && p.collateral == amount);
        let reopenable = full_exit && creditable && self.holds_collateral_permit(key, market);
        let after = HistorySize {
            history: before.history.saturating_add(2),
            positions: if full_exit && !reopenable {
                before.positions.saturating_sub(1)
            } else {
                before.positions
            },
            notes: before.notes,
        };
        if self.admission_cap.exits_fit(after) || after.with_exits() <= before.with_exits() {
            None
        } else if reopenable {
            Some(HISTORY_CAP_EXIT_PERMIT)
        } else {
            Some(HISTORY_CAP_EXIT)
        }
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
            // The state itself at the soft cap, below the hard cap.
            let mut gw = app.gw.lock().await;
            let (other, _) = gw.register_account(None);
            gw.account_deposit(&other, 0, 100 * QUOTE_SCALE).unwrap();
            let history = HistorySize::of(&gw.seq.state).history;
            gw.admission_cap = AdmissionCap {
                max_history: (1..).find(|max| soft(*max) == history).unwrap(),
                max_positions: 100,
                max_notes: 100,
            };
            assert_eq!(gw.credit_refusal(credit_of(true)), None);
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

    /// The soft cap counts what the outstanding permits will add: with the state
    /// itself just below it, one held permit is enough to stop new permits. It never
    /// closes registration, which reads the state alone, and the held permit is
    /// still re-signed.
    #[tokio::test]
    async fn outstanding_permits_count_toward_the_soft_cap() {
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
            let state = HistorySize::of(&gw.seq.state);
            // The smallest bound whose soft cap the state alone stays below.
            let max_history = (1..).find(|max| soft(*max) > state.history).unwrap();
            gw.admission_cap = AdmissionCap {
                max_history,
                max_positions: 1_000,
                max_notes: 1_000,
            };
            assert!(!gw.admission_cap.soft_reached(state));
            assert_eq!(gw.outstanding_permit_size().history, 2);
        }
        let (status, body) = json_body(
            router
                .clone()
                .oneshot(permit_request(&key, MIN_DEPOSIT_PERMIT + 1, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(body["error"].as_str().unwrap().contains("admission cap"));
        let (status, body) =
            json_body(router.clone().oneshot(register_request()).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("apiKey").is_some());
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
        let gw = app.gw.lock().await;
        assert_eq!(gw.deposits.routes.len(), 1);
        assert!(gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::AdmissionCapReached));
        drop(gw);
        writer.abort();
    }

    /// For a state beyond a bound (one lowered under it) the deposit of a held
    /// permit would not be credited, so the permit is not re-signed, as in engine
    /// close-only.
    #[tokio::test]
    async fn a_state_beyond_a_bound_does_not_re_sign_a_held_permit() {
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
            gw.admission_cap = AdmissionCap {
                max_history: HistorySize::of(&gw.seq.state).history,
                max_positions: 1_000,
                max_notes: 1_000,
            };
            assert_eq!(gw.credit_refusal(credit_of(true)), Some(HISTORY_CAP_INTAKE));
        }
        let (status, body) = json_body(
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
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(body["error"].as_str().unwrap().contains("not re-signed"));
        assert!(body.get("sig").is_none());
        writer.abort();
    }

    /// Each outstanding permit adds one leaf and one nullifier once credited, and a
    /// collateral permit adds a position entry when its account holds none in that
    /// market yet (once per account and market). Insurance adds no position.
    #[test]
    fn the_outstanding_permit_size_counts_what_crediting_adds() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let (key, _) = gw.register_account(None);
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(PAYER);
        let route = |gw: &mut Gw, market, purpose, amount| {
            gw.authorize_routed_deposit(&key, PAYER, amount, market, purpose, u64::MAX)
                .unwrap();
        };
        use deposit_ingestion::Purpose::{Collateral, InsuranceBootstrap};
        assert_eq!(gw.outstanding_permit_size(), size(0, 0, 0));
        route(&mut gw, 0, Collateral, 5_000_000);
        assert_eq!(gw.outstanding_permit_size(), size(2, 1, 0));
        route(&mut gw, 0, Collateral, 6_000_000);
        assert_eq!(gw.outstanding_permit_size(), size(4, 1, 0));
        gw.account_deposit(&key, 1, 100 * QUOTE_SCALE).unwrap();
        route(&mut gw, 1, Collateral, 7_000_000);
        assert_eq!(gw.outstanding_permit_size(), size(6, 1, 0));
        let floor = bootstrap::MIN_BOOTSTRAP_INSURANCE as u128;
        route(&mut gw, 0, InsuranceBootstrap, floor);
        assert_eq!(gw.outstanding_permit_size(), size(8, 1, 0));
        // Crediting moves a permit's share from the reservation into the state.
        let before = HistorySize::of(&gw.seq.state).plus(gw.outstanding_permit_size());
        let commit = *gw
            .deposits
            .routes
            .iter()
            .find(|(_, r)| r.market == 1)
            .unwrap()
            .0;
        let start = gw.deposit_cursor();
        let route = gw.deposits.routes[&commit].clone();
        let tip = perp_core::merkle::deposit_chain_fold(
            &start.tip,
            &perp_core::merkle::deposit_leaf(&PAYER, &commit, route.amount, start.count),
        );
        let block = deposit_rpc::Block {
            number: 1,
            hash: [7; 32],
            timestamp: None,
        };
        let page = deposit_rpc::Page {
            start: start.clone(),
            end: block.clone(),
            events: vec![deposit_rpc::Event {
                id: start.count,
                from: PAYER,
                commit,
                amount: route.amount,
                tip,
                tx: [9; 32],
                tx_index: 0,
                log_index: 0,
                block,
            }],
        };
        gw.apply_deposit_page(page).unwrap();
        assert_eq!(
            HistorySize::of(&gw.seq.state).plus(gw.outstanding_permit_size()),
            before
        );
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
        // A bound itself is provable: only a size beyond it is exceeded.
        assert!(!cap.exceeded(size(100, 10, 20)));
        assert!(cap.exceeded(size(101, 0, 0)));
        assert!(cap.exceeded(size(0, 11, 0)));
        assert!(cap.exceeded(size(0, 0, 21)));
        // One more exit per entry (a leaf and a nullifier) and per note (a nullifier).
        assert_eq!(size(10, 3, 4).with_exits(), 20);
        assert!(cap.exits_fit(size(90, 5, 0)));
        assert!(!cap.exits_fit(size(91, 5, 0)));
        assert!(!cap.exits_fit(size(90, 5, 1)));
    }

    /// The measured bounds and their soft caps, as recorded in
    /// `docs/audits/2026-10-19-pkg3-measurement-gate/measurement.json`
    /// (`scripts/local-verification/test_pin_coherence.py` compares the two).
    #[test]
    fn the_measured_cap_is_the_gate_s_recommendation() {
        let cap = measured_cap();
        assert_eq!(
            cap,
            AdmissionCap {
                max_history: 13_280,
                max_positions: 1_328,
                max_notes: 2_656,
            }
        );
        assert_eq!(MAX_PROVABLE_HISTORY % 80, 0);
        assert_eq!(MAX_POSITIONS, MAX_PROVABLE_HISTORY / 10);
        assert_eq!(MAX_NOTES, MAX_PROVABLE_HISTORY / 5);
        assert_eq!(soft(MAX_PROVABLE_HISTORY), 10_624);
        assert_eq!(soft(MAX_POSITIONS), 1_063);
        assert_eq!(soft(MAX_NOTES), 2_125);
        assert!(cap.soft_reached(size(10_624, 0, 0)));
        assert!(cap.soft_reached(size(0, 1_063, 0)));
        assert!(cap.soft_reached(size(0, 0, 2_125)));
        assert!(!cap.soft_reached(size(10_623, 1_062, 2_124)));
        assert!(cap.exceeded(size(13_281, 0, 0)));
        assert!(cap.exceeded(size(0, 1_329, 0)));
        assert!(cap.exceeded(size(0, 0, 2_657)));
        assert!(!cap.exceeded(size(13_280, 1_328, 2_656)));
        // Below both soft caps and with no unspent note, every entry still has room
        // for one more exit (and a deposit's notes are spent in the same page).
        assert!(cap.exits_fit(size(10_623, 1_062, 0).plus(credit_of(true))));
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
        // A deposit that keeps the state within the bound is still credited.
        assert_eq!(gw.credit_refusal(credit_of(false)), None);
        gw.admission_cap.max_history = 9;
        assert_eq!(
            gw.credit_refusal(credit_of(false)),
            Some(HISTORY_CAP_INTAKE)
        );
        gw.admission_cap = measured_cap();
        assert_eq!(gw.registration_refusal(), None);
        assert!(!gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::AdmissionCapReached));
    }

    #[test]
    fn engine_close_only_refuses_credit_and_alerts_until_l1_close_only() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        assert_eq!(gw.credit_refusal(credit_of(false)), None);
        gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
        assert_eq!(
            gw.credit_refusal(credit_of(false)),
            Some(ENGINE_CLOSE_ONLY_INTAKE)
        );
        assert!(gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::EngineCloseOnly));
        // Once L1 is in close-only too, the deposit stays refused but there is
        // nothing left for governance to do.
        gw.deposits.l1_close_only = true;
        assert_eq!(
            gw.credit_refusal(credit_of(false)),
            Some(ENGINE_CLOSE_ONLY_INTAKE)
        );
        assert!(!gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::EngineCloseOnly));
    }

    const SIGNER: [u8; 32] = [0x61; 32];

    /// A production gateway with one caller-signed account funded with $200 in
    /// market 0. Returns the account key, its signing key and its address.
    fn funded_withdrawer() -> (Gw, [u8; 32], k256::ecdsa::SigningKey, [u8; 20]) {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let sk = k256::ecdsa::SigningKey::from_slice(&SIGNER).unwrap();
        let address = eth_address(&sk);
        let (key, _) = gw.register_account(Some(address));
        gw.account_deposit(&key, 0, 200 * QUOTE_SCALE).unwrap();
        (gw, key, sk, address)
    }

    /// A signed withdrawal of `amount` from `key`'s market-0 balance to `to`.
    fn withdraw(
        gw: &mut Gw,
        key: &[u8; 32],
        sk: &k256::ecdsa::SigningKey,
        amount: i128,
        to: [u8; 20],
    ) -> Result<Withdrawal, String> {
        let (owner, auth_nonce) = {
            let a = &gw.accounts[key];
            (a.wallet.owner, a.last_withdraw_nonce + 1)
        };
        let digest =
            withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, auth_nonce);
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut wire = [0u8; 65];
        wire[..64].copy_from_slice(&sig.to_bytes());
        wire[64] = 27 + recid.to_byte();
        gw.account_withdraw(key, 0, amount, to, auth_nonce, &wire)
    }

    /// The one-deposit page that credits the held permit `commit`.
    fn credit_page(gw: &Gw, commit: [u8; 32]) -> deposit_rpc::Page {
        let start = gw.deposit_cursor();
        let route = gw.deposits.routes[&commit].clone();
        let tip = perp_core::merkle::deposit_chain_fold(
            &start.tip,
            &perp_core::merkle::deposit_leaf(&route.from, &commit, route.amount, start.count),
        );
        let block = deposit_rpc::Block {
            number: start.anchor.as_ref().map_or(1, |b| b.number + 1),
            hash: [7; 32],
            timestamp: None,
        };
        deposit_rpc::Page {
            start: start.clone(),
            end: block.clone(),
            events: vec![deposit_rpc::Event {
                id: start.count,
                from: route.from,
                commit,
                amount: route.amount,
                tip,
                tx: [9; 32],
                tx_index: 0,
                log_index: 0,
                block,
            }],
        }
    }

    /// A fresh account bound to `PAYER` holding one collateral permit for market 0.
    fn held_permit(gw: &mut Gw) -> ([u8; 32], [u8; 32]) {
        let (key, _) = gw.register_account(None);
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(PAYER);
        assert_eq!(
            gw.permit_cap_refusal(&key, 0, deposit_ingestion::Purpose::Collateral),
            None
        );
        let commit = gw
            .authorize_routed_deposit(
                &key,
                PAYER,
                MIN_DEPOSIT_PERMIT,
                0,
                deposit_ingestion::Purpose::Collateral,
                u64::MAX,
            )
            .unwrap();
        (key, commit)
    }

    /// Withdrawals made while a permit is held never take the history to where
    /// that permit's deposit would be refused: partial withdrawals stop where the
    /// state, the outstanding permit and one more exit per entry fill the bound;
    /// the deposit is then credited; and full exits still leave, at the bound.
    #[test]
    fn exits_under_a_held_permit_never_refuse_its_deposit() {
        let (mut gw, key, sk, to) = funded_withdrawer();
        let (depositor, commit) = held_permit(&mut gw);
        gw.admission_cap = AdmissionCap {
            max_history: 200,
            max_positions: 100,
            max_notes: 100,
        };
        // Issued below the soft cap: the state, the permit and their exits fit.
        assert_eq!(gw.admission_size(), size(4, 2, 0));
        let room = (200 - gw.admission_size().with_exits()) / 2;
        let mut partial = 0;
        let refusal = loop {
            match withdraw(&mut gw, &key, &sk, QUOTE_SCALE, to) {
                Ok(_) => partial += 1,
                Err(error) => break error,
            }
            assert!(gw.admission_size().with_exits() <= 200);
            assert!(partial <= room, "a partial withdrawal past the room");
        };
        assert_eq!(partial, room);
        assert_eq!(refusal, HISTORY_CAP_EXIT);
        assert_eq!(gw.admission_size().with_exits(), 200);
        // The held permit is still re-signed, and its deposit is credited.
        assert!(!gw.held_permit_beyond_cap(&commit));
        let page = credit_page(&gw, commit);
        assert_eq!(gw.credit_refusal(gw.page_credit_size(&page)), None);
        gw.apply_deposit_page(page).unwrap();
        assert!(gw.deposits.routes.is_empty());
        // The ingestion pass snapshots the credit.
        gw.deposits.dirty = false;
        // Both entries can still leave in full, and the history stays in bounds.
        let left = gw.market_free_of(&gw.accounts[&key].wallet.owner, 0);
        assert!(left > QUOTE_SCALE);
        assert_eq!(
            withdraw(&mut gw, &key, &sk, QUOTE_SCALE, to).unwrap_err(),
            HISTORY_CAP_EXIT
        );
        withdraw(&mut gw, &key, &sk, left, to).unwrap();
        let owner = gw.accounts[&depositor].wallet.owner;
        assert_eq!(
            gw.exit_cap_refusal(&depositor, &owner, 0, MIN_DEPOSIT_PERMIT as i128),
            None
        );
        assert!(HistorySize::of(&gw.seq.state).history <= 200);
        assert_eq!(gw.admission_size().with_exits(), 200);
    }

    /// At the bound a full exit by an account that holds an outstanding permit for
    /// the same market is refused: the permit's deposit would open the entry again
    /// and need an exit of its own. Once the permit is gone the exit is accepted.
    #[test]
    fn a_full_exit_that_a_held_permit_could_reopen_needs_room() {
        let (mut gw, key, sk, to) = funded_withdrawer();
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(PAYER);
        let commit = gw
            .authorize_routed_deposit(
                &key,
                PAYER,
                MIN_DEPOSIT_PERMIT,
                0,
                deposit_ingestion::Purpose::Collateral,
                u64::MAX,
            )
            .unwrap();
        // The state, the permit and one exit of the entry exactly fill the bound.
        assert_eq!(gw.admission_size(), size(4, 1, 0));
        gw.admission_cap = AdmissionCap {
            max_history: 6,
            max_positions: 100,
            max_notes: 100,
        };
        let all = 200 * QUOTE_SCALE;
        assert_eq!(
            withdraw(&mut gw, &key, &sk, all, to).unwrap_err(),
            HISTORY_CAP_EXIT_PERMIT
        );
        gw.deposits.routes.remove(&commit);
        gw.accounts
            .get_mut(&key)
            .unwrap()
            .deposit_authorizations
            .remove(&commit);
        withdraw(&mut gw, &key, &sk, all, to).unwrap();
        assert!(gw
            .seq
            .state
            .position(&gw.accounts[&key].wallet.owner, 0)
            .is_none());
    }

    /// Once the settlement or the engine is in close-only no permit can be
    /// credited, so outstanding permits take no room an exit needs.
    #[test]
    fn close_only_exits_do_not_wait_for_permits_that_cannot_land() {
        let (mut gw, key, sk, to) = funded_withdrawer();
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(PAYER);
        gw.authorize_routed_deposit(
            &key,
            PAYER,
            MIN_DEPOSIT_PERMIT,
            0,
            deposit_ingestion::Purpose::Collateral,
            u64::MAX,
        )
        .unwrap();
        gw.admission_cap = AdmissionCap {
            max_history: 6,
            max_positions: 100,
            max_notes: 100,
        };
        let owner = gw.accounts[&key].wallet.owner;
        let all = 200 * QUOTE_SCALE;
        assert_eq!(
            gw.exit_cap_refusal(&key, &owner, 0, all),
            Some(HISTORY_CAP_EXIT_PERMIT)
        );
        gw.deposits.l1_close_only = true;
        assert_eq!(gw.exit_cap_refusal(&key, &owner, 0, all), None);
        // A partial withdrawal still needs room for the entry's own exit after it.
        assert_eq!(gw.exit_cap_refusal(&key, &owner, 0, QUOTE_SCALE), None);
        gw.admission_cap.max_history = 5;
        assert_eq!(
            gw.exit_cap_refusal(&key, &owner, 0, QUOTE_SCALE),
            Some(HISTORY_CAP_EXIT)
        );
        withdraw(&mut gw, &key, &sk, all, to).unwrap();
    }

    /// Unfunded permits never close registration, and a fresh account (no position
    /// entry) reserves at most one entry: it holds permits for one market until
    /// its first deposit is credited. A permit that opens no entry (a top-up) is
    /// not refused for position headroom, and one that opens an entry is refused
    /// once the reservations reach the positions soft cap.
    #[test]
    fn fresh_permits_reserve_one_entry_each_and_never_close_registration() {
        use deposit_ingestion::Purpose::Collateral;
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.admission_cap = AdmissionCap {
            max_history: 1_000,
            max_positions: 5,
            max_notes: 1_000,
        };
        assert_eq!(soft(5), 4);
        let fresh = |gw: &mut Gw| {
            let (key, _) = gw.register_account(None);
            gw.accounts.get_mut(&key).unwrap().deposit_address = Some(PAYER);
            key
        };
        let issue = |gw: &mut Gw, key: &[u8; 32], market: u64| {
            gw.authorize_routed_deposit(
                key,
                PAYER,
                MIN_DEPOSIT_PERMIT,
                market,
                Collateral,
                u64::MAX,
            )
            .unwrap();
        };
        let first = fresh(&mut gw);
        assert_eq!(gw.permit_cap_refusal(&first, 0, Collateral), None);
        issue(&mut gw, &first, 0);
        // Another market is refused until the first deposit is credited; the same
        // market reserves nothing new.
        assert_eq!(
            gw.permit_cap_refusal(&first, 1, Collateral),
            Some(PermitGateRefusal::OneMarketUntilFirstDeposit)
        );
        assert_eq!(gw.permit_cap_refusal(&first, 0, Collateral), None);
        issue(&mut gw, &first, 0);
        assert_eq!(gw.outstanding_permit_size().positions, 1);
        for _ in 0..3 {
            let key = fresh(&mut gw);
            assert_eq!(gw.permit_cap_refusal(&key, 0, Collateral), None);
            issue(&mut gw, &key, 0);
        }
        assert_eq!(gw.admission_size().positions, 4);
        let late = fresh(&mut gw);
        assert_eq!(
            gw.permit_cap_refusal(&late, 0, Collateral),
            Some(PermitGateRefusal::AdmissionCap)
        );
        // Registration reads the state alone.
        assert_eq!(gw.registration_refusal(), None);
        assert!(gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::AdmissionCapReached));
        // A funded account tops up its entry, but opens no new one.
        let funded = fresh(&mut gw);
        gw.account_deposit(&funded, 0, 100 * QUOTE_SCALE).unwrap();
        assert_eq!(gw.permit_cap_refusal(&funded, 0, Collateral), None);
        assert_eq!(
            gw.permit_cap_refusal(&funded, 1, Collateral),
            Some(PermitGateRefusal::AdmissionCap)
        );
    }

    /// Over HTTP, a fresh account's permit for a second market is a conflict.
    #[tokio::test]
    async fn a_fresh_account_s_second_market_permit_is_a_conflict() {
        let (app, key, writer) = permit_app().await;
        let router = build_router(app.clone(), true);
        let request = |market: u64| {
            let body = serde_json::json!({"from": hex0x(&PAYER), "amount": MIN_DEPOSIT_PERMIT.to_string(),
                "marketId": market, "purpose": "collateral"});
            Request::builder()
                .method("POST")
                .uri("/v1/accounts/deposit/authorize")
                .header("content-type", "application/json")
                .header("x-api-key", hex0x(&key))
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let (status, body) = json_body(router.clone().oneshot(request(0)).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = json_body(router.clone().oneshot(request(1)).await.unwrap()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body["error"].as_str().unwrap().contains("one market"));
        assert!(body.get("sig").is_none());
        let (status, body) = json_body(router.oneshot(request(0)).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(app.gw.lock().await.deposits.routes.len(), 2);
        writer.abort();
    }
}
