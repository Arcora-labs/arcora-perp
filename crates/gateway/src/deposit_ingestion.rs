//! A01 durable routing and the single automatic/manual consumption path.
use super::*;
use crate::deposit_rpc::{Block, Cursor, Domain as DepositDomain, Error, Event, Page};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// Prefix is authenticated inside the snapshot ciphertext, unlike the outer magic.
/// The earlier deposit layout, without permit deadlines. Read only, and only when
/// it holds no outstanding permit: those were signed for the earlier vault ABI.
pub const SNAPSHOT_V6: &[u8] = b"\xffDPA01-SNAPSHOT-v6\0";
/// The current deposit layout: every route carries its permit deadline.
pub const SNAPSHOT_V7: &[u8] = b"\xffDPA01-SNAPSHOT-v7\0";

/// A held permit is re-issued only while at least this many seconds remain before
/// its deadline; otherwise a fresh permit is issued.
pub const PERMIT_REUSE_MARGIN_SECS: u64 = 60;

/// Returned once ingestion sees the settlement in close-only. Deposits that no
/// settled batch consumed are refunded by the vault instead of credited.
pub const CLOSE_ONLY_INTAKE: &str = "the settlement is in close-only: deposits it has not consumed are refunded by the vault (refundDeposit) and are not credited";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Purpose {
    Collateral,
    InsuranceBootstrap,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub key: [u8; 32],
    pub from: [u8; 20],
    pub amount: u128,
    pub market: u64,
    pub purpose: Purpose,
    /// The permit deadline (unix seconds) the gateway signed. The vault refuses the
    /// deposit in any block whose timestamp is later. 0 on credits restored from a
    /// v6 snapshot, whose permits had no deadline.
    pub valid_until: u64,
}
impl Route {
    /// The same permit request: every field except the deadline, which the gateway
    /// chose and the client never supplies.
    pub fn same_request(&self, other: &Route) -> bool {
        (self.key, self.from, self.amount, self.market, self.purpose)
            == (
                other.key,
                other.from,
                other.amount,
                other.market,
                other.purpose,
            )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credit {
    pub route: Route,
    pub event: Event,
}
#[derive(Default, Serialize, Deserialize)]
pub struct DepositState {
    pub domain: Option<DepositDomain>,
    /// Exact inherited v5 prefix; no fabricated historical receipt records.
    pub legacy_prefix: Option<(u64, [u8; 32])>,
    pub routes: BTreeMap<[u8; 32], Route>,
    pub credits: BTreeMap<u64, Credit>,
    pub anchor: Option<Block>,
    pub halt: Option<String>,
    /// Credits the close-only rebase removed because no settled batch consumed
    /// them. The vault refunds them (`refundDeposit`); they stay here for the
    /// confirm and account views.
    pub refunds: BTreeMap<u64, Credit>,
    // Runtime barriers. A loaded snapshot is already durable, but its L1 prefix
    // must be revalidated before production trading/settlement resumes.
    #[serde(skip)]
    pub required: bool,
    #[serde(skip)]
    pub ready: bool,
    #[serde(skip)]
    pub dirty: bool,
    #[serde(skip)]
    pub last_error: Option<String>,
    /// Set once a finalized L1 observation shows the settlement in close-only. From
    /// then on no deposit is credited, and credits the settled state has not
    /// consumed are reported as refundable. Close-only is irreversible on L1.
    #[serde(skip)]
    pub l1_close_only: bool,
    /// The settlement's `consumedDepositCount()` as last observed or settled. Credits
    /// at or above it are applied off-chain but not yet in settled state.
    #[serde(skip)]
    pub settled_count: Option<u64>,
}

/// The v6 route, without the permit deadline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RouteV6 {
    key: [u8; 32],
    from: [u8; 20],
    amount: u128,
    market: u64,
    purpose: Purpose,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CreditV6 {
    route: RouteV6,
    event: Event,
}
/// The v6 positional deposit layout (`DepositState` before permit deadlines).
#[derive(Default, Serialize, Deserialize)]
pub struct DepositStateV6 {
    domain: Option<DepositDomain>,
    legacy_prefix: Option<(u64, [u8; 32])>,
    routes: BTreeMap<[u8; 32], RouteV6>,
    credits: BTreeMap<u64, CreditV6>,
    anchor: Option<Block>,
    halt: Option<String>,
}
impl DepositStateV6 {
    /// Upgrade to the current layout. Refused while any permit is outstanding: it
    /// was signed without a deadline for the earlier vault ABI. Landed credits keep
    /// their receipts, with deadline 0.
    pub fn upgrade(self) -> Result<DepositState, String> {
        if !self.routes.is_empty() {
            return Err("v6 snapshot holds outstanding deposit permits signed for the earlier vault ABI; this gateway needs a fresh deployment".into());
        }
        let credits = self
            .credits
            .into_iter()
            .map(|(id, c)| {
                let RouteV6 {
                    key,
                    from,
                    amount,
                    market,
                    purpose,
                } = c.route;
                (
                    id,
                    Credit {
                        route: Route {
                            key,
                            from,
                            amount,
                            market,
                            purpose,
                            valid_until: 0,
                        },
                        event: c.event,
                    },
                )
            })
            .collect();
        Ok(DepositState {
            domain: self.domain,
            legacy_prefix: self.legacy_prefix,
            routes: BTreeMap::new(),
            credits,
            anchor: self.anchor,
            halt: self.halt,
            ..DepositState::default()
        })
    }
    /// Drop every route, for fixtures that test the rest of a v6 migration.
    #[cfg(test)]
    pub fn clear_routes(&mut self) {
        self.routes.clear();
    }
    /// The v6 encoding of `state`, for migration tests.
    #[cfg(test)]
    pub fn from_current(state: &DepositState) -> Self {
        let route = |r: &Route| RouteV6 {
            key: r.key,
            from: r.from,
            amount: r.amount,
            market: r.market,
            purpose: r.purpose,
        };
        Self {
            domain: state.domain.clone(),
            legacy_prefix: state.legacy_prefix,
            routes: state.routes.iter().map(|(c, r)| (*c, route(r))).collect(),
            credits: state
                .credits
                .iter()
                .map(|(id, c)| {
                    (
                        *id,
                        CreditV6 {
                            route: route(&c.route),
                            event: c.event.clone(),
                        },
                    )
                })
                .collect(),
            anchor: state.anchor.clone(),
            halt: state.halt.clone(),
        }
    }
}

/// How a credit stands against the settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreditStatus {
    /// A settled batch consumed it (or the settled count is not known yet).
    Credited,
    /// Applied off-chain; no settled batch has consumed it yet.
    CreditedUnsettled,
    /// Close-only began before any settled batch consumed it: the vault refunds it.
    Refundable,
}
impl CreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credited => "credited",
            Self::CreditedUnsettled => "credited_unsettled",
            Self::Refundable => "refundable",
        }
    }
}

/// `vault.refundDeposit(id, from, ownerCommit, amount, to)` arguments for a credit.
pub fn refund_json(c: &Credit) -> serde_json::Value {
    serde_json::json!({
        "id": c.event.id,
        "from": hex0x(&c.event.from),
        "ownerCommit": hex0x(&c.event.commit),
        "amount": c.event.amount.to_string(),
    })
}

impl DepositState {
    pub fn check_ready(&self) -> Result<(), String> {
        if let Some(reason) = &self.halt {
            return Err(format!("deposit safety halt: {reason}"));
        }
        if self.dirty || (self.required && !self.ready) {
            return Err(
                "deposit prefix/durability not verified; trading and settlement paused".into(),
            );
        }
        Ok(())
    }
}

impl Gw {
    pub(super) fn validate_deposit_state(&self) -> Result<(), String> {
        let (mut count, mut tip) = self.deposits.legacy_prefix.unwrap_or((0, [0; 32]));
        let mut consumed = BTreeSet::new();
        for (id, credit) in &self.deposits.credits {
            if *id != count
                || credit.event.id != count
                || !consumed.insert(credit.event.commit)
                || credit.route.from != credit.event.from
                || credit.route.amount != credit.event.amount
                || !self.accounts.contains_key(&credit.route.key)
            {
                return Err("inconsistent persisted deposit receipt ledger".into());
            }
            tip = perp_core::merkle::deposit_chain_fold(
                &tip,
                &perp_core::merkle::deposit_leaf(
                    &credit.event.from,
                    &credit.event.commit,
                    credit.event.amount,
                    count,
                ),
            );
            if tip != credit.event.tip {
                return Err("persisted deposit receipt tip mismatch".into());
            }
            count = count
                .checked_add(1)
                .ok_or("persisted deposit count overflow")?;
        }
        // Demo/internal sentinel minting predates A01 and has no L1 receipts.
        // Production legacy imports declare their actual inherited prefix above.
        if self.deposits.domain.is_some()
            && (count != self.seq.state.consumed_deposit_count
                || tip != self.seq.state.consumed_deposit_tip)
        {
            return Err("persisted deposit ledger disagrees with engine prefix".into());
        }
        // Refund rows sit above the consumed prefix, one per deposit id.
        for (id, refund) in &self.deposits.refunds {
            if *id < count
                || refund.event.id != *id
                || refund.route.from != refund.event.from
                || !self.accounts.contains_key(&refund.route.key)
            {
                return Err("inconsistent persisted deposit refund record".into());
            }
        }
        for (commit, route) in &self.deposits.routes {
            let a = self
                .accounts
                .get(&route.key)
                .ok_or("persisted route account missing")?;
            let blind = a
                .deposit_authorizations
                .get(commit)
                .ok_or("persisted route blind missing")?;
            if consumed.contains(commit) || owner_commit(&a.wallet.owner, blind) != *commit {
                return Err("persisted permit was consumed or has the wrong owner".into());
            }
        }
        Ok(())
    }

    fn deposit_domain(&self) -> DepositDomain {
        DepositDomain {
            chain: self.chain_id,
            vault: self.vault,
        }
    }
    fn deposit_cursor(&self) -> Cursor {
        Cursor {
            domain: self.deposit_domain(),
            count: self.seq.state.consumed_deposit_count,
            tip: self.seq.state.consumed_deposit_tip,
            anchor: self.deposits.anchor.clone(),
        }
    }
    /// Route terms that hold for the life of a permit: deployment, market, amount,
    /// account and the insurance floor. The payer is checked separately: at issuance
    /// against the bound address, at ingestion against the `Deposit` log.
    fn validate_route_terms(&self, route: &Route) -> Result<(), String> {
        if self
            .deposits
            .domain
            .as_ref()
            .is_some_and(|d| *d != self.deposit_domain())
        {
            return Err("persisted deposit domain differs from this deployment".into());
        }
        if self.mkt(route.market).is_none() {
            return Err("Unknown market.".into());
        }
        if route.amount == 0 || route.amount > i128::MAX as u128 {
            return Err("invalid deposit amount".into());
        }
        self.accounts.get(&route.key).ok_or("Unknown account.")?;
        if route.purpose == Purpose::InsuranceBootstrap
            && !bootstrap::amount_meets_floor(route.amount as i128)
        {
            return Err("insurance bootstrap below minimum".into());
        }
        Ok(())
    }
    /// Issuance-time check: the route terms plus the account's bound payer.
    fn validate_route(&self, route: &Route) -> Result<(), String> {
        self.validate_route_terms(route)?;
        if self.accounts[&route.key].deposit_address != Some(route.from) {
            return Err("route payer differs from bound address".into());
        }
        Ok(())
    }
    /// Capacity and pacing for one new user permit, checked before it is issued and
    /// charged with `charge_deposit_permit` only once it is. Global capacity is counted
    /// by routes: every permit this endpoint issues is routed. The operator's
    /// insurance bootstrap (FIN_ADMIN_KEY-authenticated) is exempt from these bounds.
    pub(super) fn admit_deposit_permit(
        &self,
        key: &[u8; 32],
        purpose: Purpose,
        now_s: u64,
    ) -> Result<(), (StatusCode, String)> {
        if purpose == Purpose::InsuranceBootstrap {
            return Ok(());
        }
        if self.deposits.routes.len() >= MAX_OPEN_DEPOSIT_PERMITS {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "deposit authorization capacity reached; retry after pending deposits land".into(),
            ));
        }
        let a = self
            .accounts
            .get(key)
            .ok_or((StatusCode::BAD_REQUEST, "Unknown account.".to_string()))?;
        if a.deposit_authorizations.len() >= MAX_OPEN_DEPOSIT_PERMITS_PER_ACCOUNT {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "this account already has {MAX_OPEN_DEPOSIT_PERMITS_PER_ACCOUNT} outstanding \
                     deposit authorizations; complete those deposits first"
                ),
            ));
        }
        let (start, count) = a.deposit_authorize_window;
        if now_s.saturating_sub(start) < 60 && count >= DEPOSIT_AUTHORIZE_RATE {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMIT: too many deposit authorizations for this account".into(),
            ));
        }
        Ok(())
    }
    /// Count one issued user permit against the account's `DEPOSIT_AUTHORIZE_RATE`.
    pub(super) fn charge_deposit_permit(&mut self, key: &[u8; 32], purpose: Purpose, now_s: u64) {
        if purpose == Purpose::InsuranceBootstrap {
            return;
        }
        if let Some(a) = self.accounts.get_mut(key) {
            let window = &mut a.deposit_authorize_window;
            if now_s.saturating_sub(window.0) >= 60 {
                *window = (now_s, 0);
            }
            window.1 += 1;
        }
    }
    /// The stored deadline of `commit` when this gateway still holds it as an
    /// outstanding permit for exactly `request` (same account, payer, amount, market
    /// and purpose, blind still stored) and at least `PERMIT_REUSE_MARGIN_SECS`
    /// remain at `now_s`. Re-signing that stored permit reproduces its signature.
    pub(super) fn held_permit_deadline(
        &self,
        commit: &[u8; 32],
        request: &Route,
        now_s: u64,
    ) -> Option<u64> {
        let stored = self.deposits.routes.get(commit)?;
        (stored.same_request(request)
            && stored.valid_until >= now_s.saturating_add(PERMIT_REUSE_MARGIN_SECS)
            && self.validate_route(stored).is_ok()
            && self
                .accounts
                .get(&stored.key)
                .is_some_and(|a| a.deposit_authorizations.contains_key(commit)))
        .then_some(stored.valid_until)
    }
    pub(super) fn authorize_routed_deposit(
        &mut self,
        key: &[u8; 32],
        from: [u8; 20],
        amount: u128,
        market: u64,
        purpose: Purpose,
        valid_until: u64,
    ) -> Result<[u8; 32], String> {
        let route = Route {
            key: *key,
            from,
            amount,
            market,
            purpose,
            valid_until,
        };
        self.validate_route(&route)?;
        let commit = self.account_authorize_deposit(key, from, amount)?;
        if self.deposits.domain.is_none() && self.deposits.legacy_prefix.is_none() {
            self.deposits.legacy_prefix = Some((
                self.seq.state.consumed_deposit_count,
                self.seq.state.consumed_deposit_tip,
            ));
        }
        self.deposits.domain = Some(self.deposit_domain());
        self.deposits.routes.insert(commit, route);
        Ok(commit)
    }
    /// Explicit, authenticated migration only. No authorization/confirm handler
    /// silently chooses a destination for an old blind-only permit. Route identity
    /// ignores the deadline; the stored (or newly recorded) deadline is returned.
    fn adopt_deposit_route(&mut self, commit: [u8; 32], route: Route) -> Result<u64, String> {
        self.validate_route(&route)?;
        let account = &self.accounts[&route.key];
        let blind = account
            .deposit_authorizations
            .get(&commit)
            .ok_or("no pending permit for this account")?;
        if owner_commit(&account.wallet.owner, blind) != commit {
            return Err("permit blind mismatch".into());
        }
        if let Some(old) = self.deposits.routes.get(&commit) {
            return if old.same_request(&route) {
                Ok(old.valid_until)
            } else {
                Err("deposit routing is immutable".into())
            };
        }
        let valid_until = route.valid_until;
        if self.deposits.domain.is_none() && self.deposits.legacy_prefix.is_none() {
            self.deposits.legacy_prefix = Some((
                self.seq.state.consumed_deposit_count,
                self.seq.state.consumed_deposit_tip,
            ));
        }
        self.deposits.domain = Some(self.deposit_domain());
        self.deposits.routes.insert(commit, route);
        Ok(valid_until)
    }
    /// Whether L1 close-only has been observed: a finalized read, or the operator
    /// wind-down that verified it at a pinned block.
    pub(super) fn l1_close_only_observed(&self) -> bool {
        self.deposits.l1_close_only || self.wind_down_started
    }
    /// How `credit` stands against the settlement's consumed deposit count.
    pub(super) fn credit_status(&self, credit: &Credit) -> CreditStatus {
        match self.deposits.settled_count {
            Some(consumed) if credit.event.id >= consumed => {
                if self.l1_close_only_observed() {
                    CreditStatus::Refundable
                } else {
                    CreditStatus::CreditedUnsettled
                }
            }
            _ => CreditStatus::Credited,
        }
    }
    /// The account's credits that the vault refunds after close-only, including
    /// those the close-only rebase already removed from the credit ledger.
    pub(super) fn refundable_credits(&self, key: &[u8; 32]) -> Vec<&Credit> {
        self.deposits
            .credits
            .values()
            .filter(|c| c.route.key == *key && self.credit_status(c) == CreditStatus::Refundable)
            .chain(
                self.deposits
                    .refunds
                    .values()
                    .filter(|c| c.route.key == *key),
            )
            .collect()
    }
    /// Record a settled or observed `consumedDepositCount()`. It never decreases on
    /// L1, so an older observation cannot lower it.
    pub(super) fn note_settled_deposit_count(&mut self, consumed: u64) {
        let known = self.deposits.settled_count.get_or_insert(consumed);
        *known = (*known).max(consumed);
    }
    /// Drop permits that can no longer land: un-landed routes, and their blinds,
    /// whose deadline is before `block_time`, the header timestamp of a finalized
    /// block ingestion has passed. Block timestamps strictly increase, so no later
    /// block can accept them. Never called with the gateway's own clock.
    fn gc_expired_permits(&mut self, block_time: u64) -> usize {
        let expired: Vec<([u8; 32], [u8; 32])> = self
            .deposits
            .routes
            .iter()
            .filter(|(_, r)| r.valid_until < block_time)
            .map(|(c, r)| (*c, r.key))
            .collect();
        for (commit, key) in &expired {
            self.deposits.routes.remove(commit);
            if let Some(a) = self.accounts.get_mut(key) {
                a.deposit_authorizations.remove(commit);
            }
        }
        if !expired.is_empty() {
            self.deposits.dirty = true;
        }
        expired.len()
    }
    /// Commit one complete block, including replay ops and all consumption records,
    /// under the gateway lock. Preparation and engine errors leave money untouched.
    fn apply_deposit_page(&mut self, page: Page) -> Result<usize, String> {
        self.refuse_if_wind_down_started()?;
        if self.deposits.l1_close_only {
            return Err(CLOSE_ONLY_INTAKE.into());
        }
        if self.deposit_cursor() != page.start {
            return Err("stale deposit page; retry".into());
        }
        if self
            .deposits
            .domain
            .as_ref()
            .is_some_and(|d| *d != page.start.domain)
        {
            return Err("persisted deposit domain mismatch".into());
        }
        if self.deposits.halt.is_some() {
            return Err("deposit intake is halted".into());
        }
        let mut ops = Vec::new();
        let mut notes = Vec::new();
        let mut records = Vec::new();
        let mut counters = BTreeMap::<[u8; 32], u64>::new();
        let mut seen = BTreeSet::new();
        let mut count = page.start.count;
        let mut tip = page.start.tip;
        let resume = if let bootstrap::Bootstrap::DepositApplied {
            note_commitment,
            spend_key,
            deposit_id,
        } = self.bootstrap
        {
            if deposit_id >= count {
                return Err("legacy bootstrap note is outside the verified prefix".into());
            }
            ops.push(BatchOp::FundInsurance {
                note_commitment,
                spend_key,
            });
            true
        } else {
            false
        };
        let mut insurance = resume;
        for event in &page.events {
            if event.block != page.end || event.id != count || !seen.insert(event.commit) {
                return Err("unordered/duplicate deposit page".into());
            }
            let route=self.deposits.routes.get(&event.commit).ok_or_else(||
                format!("deposit {} has no explicit routing; pending legacy/unknown permit quarantined",event.id))?.clone();
            // The payer is the permit's `from`, never the current binding: a rebind
            // after issuance must not fail ingestion of a permitted deposit.
            self.validate_route_terms(&route)?;
            if route.from != event.from || route.amount != event.amount {
                return Err("deposit differs from durable permit".into());
            }
            let a = &self.accounts[&route.key];
            let blind = *a
                .deposit_authorizations
                .get(&event.commit)
                .ok_or("permit already consumed or missing")?;
            if owner_commit(&a.wallet.owner, &blind) != event.commit {
                return Err("permit does not open ownerCommit".into());
            }
            let counter = counters.entry(route.key).or_insert(a.deposit_counter);
            let mut note_blind = [0xB0; 32];
            note_blind[..8].copy_from_slice(&counter.to_le_bytes());
            *counter = counter.checked_add(1).ok_or("deposit counter overflow")?;
            let note = Note::new(a.wallet.owner, 0, event.amount as i128, note_blind);
            ops.push(BatchOp::Deposit {
                owner: a.wallet.owner,
                asset_id: 0,
                amount: event.amount as i128,
                blinding: note_blind,
                from: event.from,
                deposit_id: event.id,
                deposit_blind: blind,
            });
            match route.purpose {
                Purpose::Collateral => ops.push(BatchOp::FundPosition {
                    owner: a.wallet.owner,
                    market_id: route.market,
                    note_commitment: note.commitment::<Keccak256>(),
                    spend_key: a.wallet.spend_key,
                }),
                Purpose::InsuranceBootstrap => {
                    insurance = true;
                    ops.push(BatchOp::FundInsurance {
                        note_commitment: note.commitment::<Keccak256>(),
                        spend_key: a.wallet.spend_key,
                    });
                }
            }
            tip = perp_core::merkle::deposit_chain_fold(
                &tip,
                &perp_core::merkle::deposit_leaf(
                    &event.from,
                    &event.commit,
                    event.amount,
                    event.id,
                ),
            );
            if tip != event.tip {
                return Err("deposit page tip mismatch".into());
            }
            count = count.checked_add(1).ok_or("deposit count overflow")?;
            notes.push((note, a.wallet.view_x25519_public()));
            records.push(Credit {
                route,
                event: event.clone(),
            });
        }
        self.seq
            .apply_atomic(&ops)
            .map_err(|e| format!("atomic deposit block refused: {e:?}"))?;
        // All fallible validations finish before the state swap. These updates are
        // infallible and become durable in the SAME snapshot as the replay op-log.
        for (note, pubkey) in notes {
            self.archive.record(
                self.seq.current_batch_id(),
                &note,
                &pubkey,
                rand::rngs::OsRng,
            );
        }
        for (key, counter) in counters {
            self.accounts.get_mut(&key).unwrap().deposit_counter = counter;
        }
        for credit in records {
            self.accounts
                .get_mut(&credit.route.key)
                .unwrap()
                .deposit_authorizations
                .remove(&credit.event.commit);
            self.deposits.routes.remove(&credit.event.commit);
            self.processed_deposit_txs.insert(hex0x(&credit.event.tx)); // legacy read compatibility, NOT the new dedup key
            self.deposits.credits.insert(credit.event.id, credit);
        }
        if insurance {
            self.bootstrap = bootstrap::Bootstrap::InsuranceApplied {
                window_id: self.seq.state.next_batch_id,
            };
        }
        let changed = self.deposits.anchor.as_ref() != Some(&page.end)
            || !ops.is_empty()
            || self.deposits.domain.is_none();
        self.deposits.domain = Some(page.start.domain);
        let block_time = page.end.timestamp;
        self.deposits.anchor = Some(page.end);
        self.deposits.ready = true;
        self.deposits.dirty |= changed;
        if let Some(t) = block_time {
            self.gc_expired_permits(t);
        }
        Ok(page.events.len())
    }
}

/// Serialize automatic polling and manual accelerators over RPC, application and
/// the durable ACK. Do not hold Gw across RPC or disk I/O. Cancellation leaves the
/// dirty barrier armed; the next caller retries persistence before doing more work.
pub async fn ingest_once(app: &Shared) -> Result<usize, String> {
    let _admission = app.clock_admission.enter().map_err(str::to_string)?;
    let _serial = app.deposit_serial.lock().await;
    if app.snapshot_req.is_none() {
        return Err("state persistence is required for deposit intake".into());
    }
    if app.gw.lock().await.deposits.dirty {
        snapshot_now(&app.snapshot_req).await?;
        app.gw.lock().await.deposits.dirty = false;
    }
    // After L1 close-only nothing more is credited, and the consumed prefix was
    // verified by the fetch that found it; there is nothing left to poll for.
    {
        let gw = app.gw.lock().await;
        if gw.deposits.l1_close_only && gw.deposits.ready {
            return Ok(0);
        }
    }
    let source = app
        .deposit_source
        .clone()
        .ok_or("automatic L1 deposit source is not configured")?;
    let cursor = {
        let gw = app.gw.lock().await;
        if let Some(e) = &gw.deposits.halt {
            gw.ops_alerts
                .activate(crate::ops_alerts::AlertKind::DepositHalted);
            return Err(format!("deposit safety halt: {e}"));
        }
        if gw
            .deposits
            .domain
            .as_ref()
            .is_some_and(|d| *d != gw.deposit_domain())
        {
            return Err("persisted deposit domain differs from configured domain".into());
        }
        gw.deposit_cursor()
    };
    let fetched = match tokio::task::spawn_blocking(move || source.fetch(cursor)).await {
        Ok(result) => result,
        Err(e) => Err(Error::Retry(format!("deposit reader task failed: {e}"))),
    };
    let page = match fetched {
        Ok(p) => p,
        Err(error) => {
            {
                let mut gw = app.gw.lock().await;
                gw.deposits.ready = false;
                gw.deposits.last_error = Some(error.to_string());
                if let Error::Halt(reason) = &error {
                    gw.deposits.halt = Some(reason.clone());
                    gw.deposits.dirty = true;
                    gw.ops_alerts
                        .activate(crate::ops_alerts::AlertKind::DepositHalted);
                }
            }
            if matches!(error, Error::Halt(_)) {
                snapshot_now(&app.snapshot_req).await?;
                app.gw.lock().await.deposits.dirty = false;
            }
            return Err(error.to_string());
        }
    };
    // A page that would credit deposits is applied only while a finalized read
    // shows the settlement accepting them. Once close-only is set, deposits that
    // no settled batch consumed are the vault's to refund.
    let latched = app.gw.lock().await.deposits.l1_close_only;
    let close_only = if latched {
        true
    } else if page.events.is_empty() {
        false
    } else if let Some(l1) = app.l1.clone() {
        match tokio::task::spawn_blocking(move || l1.close_only_finalized()).await {
            Ok(Ok(close_only)) => close_only,
            Ok(Err(e)) => {
                let mut gw = app.gw.lock().await;
                gw.deposits.ready = false;
                let error = format!("cannot read the settlement's close-only flag: {e}");
                gw.deposits.last_error = Some(error.clone());
                return Err(error);
            }
            Err(e) => {
                let mut gw = app.gw.lock().await;
                gw.deposits.ready = false;
                let error = format!("close-only read task failed: {e}");
                gw.deposits.last_error = Some(error.clone());
                return Err(error);
            }
        }
    } else {
        false
    };
    if close_only {
        let mut gw = app.gw.lock().await;
        let first = !gw.deposits.l1_close_only;
        gw.deposits.l1_close_only = true;
        // The fetch checked the consumed prefix against the finalized vault.
        gw.deposits.ready = true;
        gw.deposits.last_error = Some(CLOSE_ONLY_INTAKE.into());
        return if first {
            Err(CLOSE_ONLY_INTAKE.into())
        } else {
            Ok(0)
        };
    }
    let applied = {
        let mut gw = app.gw.lock().await;
        match gw.apply_deposit_page(page) {
            Ok(n) => n,
            Err(e) => {
                gw.deposits.ready = false;
                gw.deposits.last_error = Some(e.clone());
                return Err(e);
            }
        }
    };
    if app.gw.lock().await.deposits.dirty {
        snapshot_now(&app.snapshot_req).await?;
        app.gw.lock().await.deposits.dirty = false;
    }
    app.gw.lock().await.deposits.last_error = None;
    if applied > 0 {
        // A refresh hint carries no secret account identifiers or permit data.
        let snapshot = app.snapshot(&*app.gw.lock().await);
        let _ = app
            .tx
            .send(serde_json::to_string(&WsMsg::State { state: snapshot }).unwrap());
    }
    Ok(applied)
}

pub fn authorize_purpose(
    headers: &HeaderMap,
    purpose: Purpose,
    from: [u8; 20],
) -> Result<(), String> {
    if purpose == Purpose::Collateral {
        return Ok(());
    }
    let configured = std::env::var("FIN_ADMIN_KEY").ok();
    let presented = headers.get("x-admin-key").and_then(|v| v.to_str().ok());
    if !matches!(
        admin_resume_authz(configured.as_deref(), presented),
        AdminAuthz::Ok
    ) {
        return Err("insurance routing requires FIN_ADMIN_KEY / X-Admin-Key".into());
    }
    if std::env::var("INSURANCE_OPERATOR_ADDRESS")
        .ok()
        .as_deref()
        .and_then(parse_addr20_hex)
        != Some(from)
    {
        return Err("insurance routing requires the configured operator payer".into());
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct LegacyRouteReq {
    #[serde(rename = "ownerCommit")]
    owner_commit: String,
    #[serde(flatten)]
    permit: DepositAuthorizeReq,
}
pub async fn route_legacy(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<LegacyRouteReq>,
) -> axum::response::Response {
    let key = match api_key_from(&headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let Some(commit) = parse_hex32(&req.owner_commit) else {
        return err400("bad ownerCommit".into()).into_response();
    };
    let Some(from) = parse_addr20_hex(&req.permit.from) else {
        return err400("bad from".into()).into_response();
    };
    let Ok(amount) = req.permit.amount.parse::<u128>() else {
        return err400("bad amount".into()).into_response();
    };
    if let Err(e) = authorize_purpose(&headers, req.permit.purpose, from) {
        return err400(e).into_response();
    }
    if app.snapshot_req.is_none() {
        return unavailable("persistence required".into());
    }
    // Serialize with ingestion so an adopted route cannot be consumed before its
    // own durability barrier. A failed ACK leaves immutable routing, not a new guess.
    let _serial = app.deposit_serial.lock().await;
    // A newly adopted route gets the deadline a fresh permit would; an already
    // recorded one keeps its own. Identity never includes the deadline.
    let route = Route {
        key,
        from,
        amount,
        market: req.permit.market_id,
        purpose: req.permit.purpose,
        valid_until: (now_ms() / 1000).saturating_add(app.permit_ttl_secs),
    };
    let valid_until = match app.gw.lock().await.adopt_deposit_route(commit, route) {
        Ok(v) => v,
        Err(e) => return err400(e).into_response(),
    };
    if let Err(e) = snapshot_now(&app.snapshot_req).await {
        return unavailable(e);
    }
    Json(serde_json::json!({"ownerCommit":req.owner_commit,"routing":"recorded","durability":"confirmed","validUntil":valid_until})).into_response()
}
fn unavailable(error: String) -> axum::response::Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error":error,"durability":"unknown"})),
    )
        .into_response()
}
pub async fn confirm(
    app: &Shared,
    headers: &HeaderMap,
    tx: &str,
    market: u64,
    purpose: Purpose,
) -> axum::response::Response {
    let key = match api_key_from(headers) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };
    let Some(tx) = canon_tx_hash(tx) else {
        return err400("bad txHash".into()).into_response();
    };
    if !app.gw.lock().await.accounts.contains_key(&key) {
        return err400("Unknown account.".into()).into_response();
    }
    if let Err(e) = ingest_once(app).await {
        return unavailable(e);
    }
    let gw = app.gw.lock().await;
    confirmed_receipt(&gw, &key, &tx, market, purpose)
}

/// Keep the final durability check and receipt read under the same Gw lock.
/// `ingest_once` releases deposit_serial before its caller reacquires Gw: another
/// poller can apply a new page in that gap and still be waiting for its disk ACK.
/// A receipt from that page must not claim confirmed durability yet.
fn confirmed_receipt(
    gw: &Gw,
    key: &[u8; 32],
    tx: &str,
    market: u64,
    purpose: Purpose,
) -> axum::response::Response {
    if let Err(e) = gw.deposits.check_ready() {
        return unavailable(e);
    }
    let matching: Vec<_> = gw
        .deposits
        .credits
        .values()
        .chain(gw.deposits.refunds.values())
        .filter(|c| c.route.key == *key && hex0x(&c.event.tx) == tx)
        .collect();
    if matching
        .iter()
        .any(|c| c.route.market != market || c.route.purpose != purpose)
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"confirm cannot change the recorded market/purpose"})),
        )
            .into_response();
    }
    if matching.is_empty() {
        if gw.processed_deposit_txs.contains(tx) {
            return (StatusCode::CONFLICT,Json(serde_json::json!({"error":"legacy credited transaction; no new credit applied"}))).into_response();
        }
        if gw.l1_close_only_observed() {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": CLOSE_ONLY_INTAKE, "credited": "0"})),
            )
                .into_response();
        }
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"status":"pendingFinalizedIngestion","credited":"0"})),
        )
            .into_response();
    }
    let Some(amount) = matching
        .iter()
        .try_fold(0u128, |sum, c| sum.checked_add(c.event.amount))
    else {
        return unavailable("receipt total overflow".into());
    };
    // Refundable outranks unsettled, which outranks settled: the receipt reports
    // the least final state any of its deposits is in.
    let statuses: Vec<CreditStatus> = matching
        .iter()
        .map(|c| {
            if gw.deposits.refunds.contains_key(&c.event.id) {
                CreditStatus::Refundable
            } else {
                gw.credit_status(c)
            }
        })
        .collect();
    let status = [CreditStatus::Refundable, CreditStatus::CreditedUnsettled]
        .into_iter()
        .find(|s| statuses.contains(s))
        .unwrap_or(CreditStatus::Credited);
    let mut body = serde_json::json!({"status":status.as_str(),"credited":amount.to_string(),"durability":"confirmed",
        "depositIds":matching.iter().map(|c|c.event.id).collect::<Vec<_>>(),
        "purpose":purpose,"marketId":market,"account":gw.v1_account(key),"bootstrap":gw.bootstrap});
    if status == CreditStatus::Refundable {
        body["refundable"] = matching
            .iter()
            .zip(&statuses)
            .filter(|(_, s)| **s == CreditStatus::Refundable)
            .map(|(c, _)| refund_json(c))
            .collect();
    }
    Json(body).into_response()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "deposit_ingestion/receipt_tests.rs"]
mod receipt_tests;

#[cfg(test)]
#[path = "deposit_ingestion/paired_recovery_tests.rs"]
mod paired_recovery_tests;
