//! What the gateway admits: the off-chain minimums, the engine close-only gate on
//! deposits, and the provable-history admission cap.
//!
//! None of this is an engine rule; each can change without a new program key.
//!
//! * **Minimums.** A deposit permit is issued for at least `MIN_DEPOSIT_PERMIT`
//!   (`MIN_ENTRY_DEPOSIT` when it may open a position entry); a withdrawal moves at
//!   least `MIN_WITHDRAWAL` unless it takes the whole free balance of its market (so
//!   a small remainder can always leave), and leaves at least `MIN_ENTRY_BALANCE` in
//!   its entry unless it is a full exit. The order-size minimum is the sequencer's
//!   (`sequencer::MIN_ORDER_NOTIONAL`).
//! * **Withdrawal limits.** Every withdrawal adds a leaf and a nullifier to the
//!   provable history, which only grows, so one account must not spend it for
//!   everyone: a per-minute and a per-settlement-window rate limit per account, and
//!   a lifetime quota of partial withdrawals per account. A full exit (a closed
//!   position's whole balance) is exempt from the quota, so funds can always leave.
//!   The shared demo user (`/api/withdraw`, demo builds only) has the rate limits
//!   and the reserve but no quota, since every visitor shares it.
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
//!   Each account also has a lifetime quota of history units (`ACCOUNT_HISTORY_QUOTA`):
//!   every credited deposit and withdrawal is charged, and its outstanding collateral
//!   permits count against it too; a spent account gets no new permit and no partial
//!   withdrawal. Past `PARTIAL_WITHDRAWAL_HISTORY_CEILING` of history in the state
//!   itself (outstanding permits, which cost nothing, do not count) no account makes
//!   a partial withdrawal, so many accounts cannot fill the budget registration and
//!   deposits need. A full exit is always accepted.
//!
//!   So the deposit of every outstanding permit can be credited and stays within the
//!   bounds, and funds can always leave: close the position, then withdraw its whole
//!   balance. Only a state already beyond a bound (one that was lowered under it)
//!   credits no deposit and re-signs no held permit. An account that holds no
//!   position entry yet holds permits for one market at a time until its first
//!   deposit is credited, so it reserves at most one entry. The bounds
//!   (`MAX_PROVABLE_HISTORY`, `MAX_POSITIONS`, `MAX_NOTES`) are measured.
//! * **Position entries (audit G1-1).** Every entry costs the same to prove,
//!   whatever it holds: each batch re-derives the positions digest and the wind-down
//!   settles every entry in one proof. So a dust entry counts toward `MAX_POSITIONS`
//!   like any other, and the quota is kept from filling with dust instead:
//!   - registration adds no entry and never closes on the position entries;
//!   - a flat entry holding less than `MIN_ENTRY_BALANCE` is dust. A collateral
//!     permit for a market where the account holds no entry or only dust may open
//!     one (a sweep can remove dust before the deposit lands): it is issued for at
//!     least `MIN_ENTRY_DEPOSIT` and counts as opening an entry from its issuance;
//!   - the soft cap of `MAX_POSITIONS` bounds the state's own entries, not the
//!     outstanding permits, so unfunded permits cannot hold it: a permit that may
//!     open an entry is issued only while the state's entries are below the soft
//!     cap (unless a sweep makes room), and while the state's entries, the entries
//!     every outstanding permit may open and its own fit `MAX_POSITIONS`, so every
//!     deposit can still be credited. Once those reach the soft cap, one client
//!     group (an IPv4 address or an IPv6 /64) holds at most
//!     `MAX_GROUP_OPENING_PERMITS` of them, a further permit for a market it
//!     already reserves included;
//!   - below `MIN_ENTRY_BALANCE` no order adds exposure (opens, grows or flips a
//!     position), at intake and in the sequencer when a fill settles, so an entry
//!     below the minimum that holds a position got there through a trading loss
//!     after it opened at the minimum or above, and an entry below it that is flat
//!     stays flat until it is topped up to the minimum;
//!   - outside close-only a withdrawal leaves at least `MIN_ENTRY_BALANCE` in the
//!     entry, open position or not, unless it is a full exit, and a full exit waits
//!     while the account holds a permit below `MIN_ENTRY_DEPOSIT` for the market,
//!     whose deposit would otherwise open a new entry below the minimum. So no
//!     withdrawal of the account's own leaves dust: trading does, and so can a
//!     sweep, a liquidation or an old permit (a legacy one, or one held when a sweep
//!     or a liquidation removed its entry) landing in a missing entry, all flat and
//!     swept again;
//!   - when a permit that opens an entry is refused only by the position entries,
//!     and exiting as many dust entries of other accounts as it needs (at most
//!     `MAX_SWEEPS_PER_PERMIT`) admits it, the gateway sweeps them: a forced full
//!     exit of each one's whole balance to its account's bound deposit address,
//!     whatever permits that account holds, after cancelling that account's orders
//!     in the market, marked as such in its withdrawals and announced on its event
//!     stream once durable. Every exit is planned before the first is made, so a
//!     sweep runs only when all of them can. Entries at the minimum and entries
//!     holding an open position are never swept, and a sweep moves no value: the
//!     whole balance is claimable on L1. It is not charged to the swept account.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// The smallest deposit permit, quote-scaled ($10).
pub(crate) const MIN_DEPOSIT_PERMIT: u128 = 10 * QUOTE_SCALE as u128;

/// The smallest withdrawal, quote-scaled ($10, the order and deposit minimum),
/// unless the withdrawal takes the whole free balance of its market.
pub(crate) const MIN_WITHDRAWAL: i128 = 10 * QUOTE_SCALE;

/// The entry minimum, quote-scaled ($100, ten times the deposit minimum): a flat
/// position entry holding less is dust, which a sweep may exit in full to make room
/// for a new entry once the entries are at their soft cap, and a partial withdrawal
/// leaves at least this much in its entry.
pub(crate) const MIN_ENTRY_BALANCE: i128 = 100 * QUOTE_SCALE;

/// The smallest deposit permit that may open a position entry (a collateral permit
/// for a market where the account holds no entry or only dust, outstanding permits
/// or not, since whichever deposit is credited first opens it): `MIN_ENTRY_BALANCE`.
/// An entry the sweep leaves alone holds at least this much or an open position;
/// one below it with a position got there through a trading loss after it opened
/// at the minimum, and no order adds exposure below it. One open at up to 10x and a
/// partial close inside the 2% fill band leave about 65 USDC at a steady index; a
/// move of the index against the position before the close leaves about 30 USDC
/// at the edge of liquidation. So filling the soft cap of `MAX_POSITIONS` with
/// entries the sweep never takes locks roughly $30,000 to $70,000 (about $10,600
/// before), and needs 100 USDC passed through each entry to open it.
pub(crate) const MIN_ENTRY_DEPOSIT: u128 = MIN_ENTRY_BALANCE as u128;

/// Most outstanding permits that may open a position entry one client group (an
/// IPv4 address or an IPv6 /64, `service_policy::client_share_key`) may hold once
/// the state's entries and those every outstanding permit may open reach the soft
/// cap of `MAX_POSITIONS`. Below the soft cap there is room for every request; past
/// it, the room up to the bound is shared, so unfunded permits of one client cannot
/// hold it. Holding all the room above the soft cap (a fifth of the bound, 265
/// entries for the measured one) with unfunded permits takes 133 client groups.
pub(crate) const MAX_GROUP_OPENING_PERMITS: usize = 2;

/// Most dust entries one permit request sweeps. One is enough at the soft cap; more
/// only once a lowered bound or a voided window left the entries above it.
const MAX_SWEEPS_PER_PERMIT: u64 = 8;

/// The `reason` of a forced exit by a dust sweep, in its account event, and of the
/// cancellation of the swept account's orders in that market.
pub(crate) const DUST_SWEEP: &str = "DUST_SWEEP";

/// Returned for a full exit while the account holds a permit below the entry
/// minimum for the market (audit G1-1).
pub(crate) const TOP_UP_PERMIT_OUTSTANDING: &str = "TOP_UP_PERMIT_OUTSTANDING: this account \
     holds an outstanding deposit permit for this market below the 100 USDC entry \
     minimum, whose deposit would open a new entry below the minimum once this one is \
     gone. Retry once that deposit is credited or the permit expires (validUntil)";

/// Most withdrawals one account may make within a minute.
pub(crate) const MAX_WITHDRAWALS_PER_MINUTE: u32 = 3;

/// Most withdrawals one account may have in the open settlement window.
pub(crate) const MAX_WITHDRAWALS_PER_WINDOW: usize = 10;

/// History units one account may spend over its lifetime: 2 for every credited
/// deposit and 2 for every withdrawal (a leaf and a nullifier each), under 1% of
/// `MAX_PROVABLE_HISTORY`. Its outstanding collateral permits count against it too
/// (2 units each, what their credits will take). Once spent, the account gets no
/// new deposit permit and no partial withdrawal; a full exit is still accepted, and
/// it is bounded by the entries the account already holds, since no new entry opens
/// without a permit.
pub(crate) const ACCOUNT_HISTORY_QUOTA: u64 = 100;

/// History units one credited deposit or one withdrawal takes.
const HISTORY_UNITS_PER_OP: u64 = 2;

/// Past this much history in the state itself no partial withdrawal is accepted,
/// whatever the number of accounts: 60% of `MAX_PROVABLE_HISTORY`, well below the
/// soft cap, so registration, deposit permits and full exits keep the room above it.
/// A fixed reserve, not a fraction of the (test-lowered) live cap. Outstanding
/// permits do not count: they add no history until their deposits are credited and
/// cost nothing to take, they stop at the soft cap (`permit_cap_refusal`), and the
/// room their deposits need is kept by `exit_cap_refusal`.
pub(crate) const PARTIAL_WITHDRAWAL_HISTORY_CEILING: u64 = MAX_PROVABLE_HISTORY / 5 * 3;

/// From this much history in the state the `withdraw_reserve_near` alert is raised:
/// nine tenths of `PARTIAL_WITHDRAWAL_HISTORY_CEILING`. History never shrinks, so
/// once the reserve is reached partial withdrawals stay closed for every account.
pub(crate) const WITHDRAW_RESERVE_ALERT_HISTORY: u64 = PARTIAL_WITHDRAWAL_HISTORY_CEILING / 10 * 9;

const MINUTE_MS: u64 = 60_000;

/// Returned for a withdrawal over the per-minute rate limit.
pub(crate) const WITHDRAW_RATE_LIMIT_MINUTE: &str = "WITHDRAW_RATE_LIMIT_MINUTE: this account \
     made its maximum number of withdrawals in the last minute; retry shortly";

/// Returned for a withdrawal over the per-settlement-window rate limit.
pub(crate) const WITHDRAW_RATE_LIMIT_WINDOW: &str = "WITHDRAW_RATE_LIMIT_WINDOW: this account \
     already has its maximum number of withdrawals in the open settlement window; retry \
     after the next settlement";

/// Returned for a partial withdrawal over the account's lifetime history quota.
pub(crate) const WITHDRAW_QUOTA_EXCEEDED: &str = "WITHDRAW_QUOTA_EXCEEDED: this account used its \
     quota of provable history. A full exit is still accepted: close the position, then \
     withdraw the whole balance of this market";

/// Returned for a partial withdrawal once the exchange-wide history reserve is reached.
pub(crate) const WITHDRAW_RESERVE_REACHED: &str = "WITHDRAW_RESERVE_REACHED: the provable history \
     left for partial withdrawals is used up for every account. A full exit is still \
     accepted: close the position, then withdraw the whole balance of this market";

/// Runtime-only withdrawal rate of one account (the minute counter).
#[derive(Clone, Copy, Debug, Default)]
struct WithdrawUsage {
    minute_start_ms: u64,
    minute_count: u32,
}

/// Withdrawal usage per account owner: the runtime minute counters, and the
/// persisted ledger of history units (`DPWLIM01` snapshot section; absent in
/// snapshots written before it, which load with an empty ledger).
#[derive(Clone, Debug, Default)]
pub(crate) struct WithdrawLimits {
    by_owner: std::collections::BTreeMap<[u8; 32], WithdrawUsage>,
    history_units: std::collections::BTreeMap<[u8; 32], u64>,
}

impl WithdrawLimits {
    fn usage(&self, owner: &[u8; 32]) -> WithdrawUsage {
        self.by_owner.get(owner).copied().unwrap_or_default()
    }

    /// History units `owner` has spent on credited deposits and withdrawals.
    pub(crate) fn units(&self, owner: &[u8; 32]) -> u64 {
        self.history_units.get(owner).copied().unwrap_or(0)
    }

    fn charge(&mut self, owner: &[u8; 32]) {
        let u = self.history_units.entry(*owner).or_default();
        *u = u.saturating_add(HISTORY_UNITS_PER_OP);
    }

    fn refund(&mut self, owner: &[u8; 32]) {
        if let Some(u) = self.history_units.get_mut(owner) {
            *u = u.saturating_sub(HISTORY_UNITS_PER_OP);
            if *u == 0 {
                self.history_units.remove(owner);
            }
        }
    }

    /// Count a withdrawal that was applied at `now_ms`: the minute counter and the
    /// ledger.
    pub(crate) fn record(&mut self, owner: &[u8; 32], now_ms: u64) {
        self.record_rate(owner, now_ms);
        self.charge(owner);
    }

    /// Count a withdrawal that was applied at `now_ms` on the minute counter only:
    /// the shared demo user, which has no history quota.
    pub(crate) fn record_rate(&mut self, owner: &[u8; 32], now_ms: u64) {
        let u = self.by_owner.entry(*owner).or_default();
        if u.minute_count == 0 || !minute_holds(u.minute_start_ms, now_ms) {
            u.minute_start_ms = now_ms;
            u.minute_count = 0;
        }
        u.minute_count = u.minute_count.saturating_add(1);
    }

    /// Count a deposit credited to `owner`.
    pub(crate) fn record_credit(&mut self, owner: &[u8; 32]) {
        self.charge(owner);
    }

    /// Take back what a withdrawal that a voided window removed was charged.
    pub(crate) fn refund_withdrawal(&mut self, owner: &[u8; 32]) {
        if let Some(u) = self.by_owner.get_mut(owner) {
            u.minute_count = u.minute_count.saturating_sub(1);
        }
        self.refund(owner);
    }

    /// Take back what a deposit credit that a voided window reverted was charged.
    pub(crate) fn refund_credit(&mut self, owner: &[u8; 32]) {
        self.refund(owner);
    }
}

/// The leaves of the withdrawals that dust sweeps made, so the account's withdrawals
/// show them as forced exits (`DPSWEEP1` snapshot section, after the ledger; absent
/// in snapshots written before it, which load with none).
#[derive(Clone, Debug, Default)]
pub(crate) struct DustSweeps {
    leaves: BTreeSet<[u8; 32]>,
}

impl DustSweeps {
    /// Whether the withdrawal with `leaf` is a forced exit by a dust sweep.
    pub(crate) fn contains(&self, leaf: &[u8; 32]) -> bool {
        self.leaves.contains(leaf)
    }

    /// Which of `leaves` are forced exits.
    pub(crate) fn among(&self, leaves: &BTreeSet<[u8; 32]>) -> BTreeSet<[u8; 32]> {
        self.leaves.intersection(leaves).copied().collect()
    }

    /// Forget the forced exits among `leaves`: a voided window or the close-only
    /// rebase removed those withdrawals (and their entries are back), or the vault
    /// paid them and they are no longer listed.
    pub(crate) fn forget(&mut self, leaves: &BTreeSet<[u8; 32]>) {
        self.leaves.retain(|leaf| !leaves.contains(leaf));
    }
}

/// The client group each outstanding permit that may open a position entry was
/// issued to (audit G1-1), for `MAX_GROUP_OPENING_PERMITS`. Runtime-only: after a
/// restart the permits held then belong to no group, and still count toward the
/// bound.
#[derive(Clone, Debug, Default)]
pub(crate) struct PermitGroups {
    by_commit: BTreeMap<[u8; 32], std::net::IpAddr>,
}

/// A flat entry the sweep may exit, with what its forced exit needs.
struct DustEntry {
    key: [u8; 32],
    market: u64,
    amount: i128,
    to: [u8; 20],
    oracle: OracleTranscript,
}

/// A planned forced exit of a dust entry: its withdrawal nonce and the unbind and
/// burn that make it.
struct DustExit {
    dust: DustEntry,
    owner: PubKey,
    nonce: u64,
    ops: [BatchOp; 2],
}

/// Whether `entry` is dust: flat and holding less than `MIN_ENTRY_BALANCE`.
fn is_dust(entry: &Position) -> bool {
    entry.size == 0 && entry.collateral > 0 && entry.collateral < MIN_ENTRY_BALANCE
}

/// Whether a collateral deposit into `entry` (`None`: no entry) may open a position
/// entry by the time it is credited: there is none, or only dust, which a sweep can
/// exit before the deposit lands.
fn deposit_may_open(entry: Option<&Position>) -> bool {
    entry.is_none_or(is_dust)
}

/// The account event that tells the owner of a swept entry in `market` about its
/// forced exit `w` (`/v1/ws`, filtered to the owner like every account event).
pub(crate) fn forced_exit_event(market: u64, w: &Withdrawal) -> String {
    serde_json::json!({
        "owner": hex0x(&w.owner), "type": "forcedExit", "reason": DUST_SWEEP,
        "marketId": market, "amount": w.amount.to_string(), "to": hex0x(&w.to),
        "nonce": w.nonce, "leaf": hex0x(&w.leaf()),
    })
    .to_string()
}

/// Whether `now_ms` is within the minute that began at `start_ms`. A clock that
/// stepped back (`now_ms < start_ms`) starts a new minute.
fn minute_holds(start_ms: u64, now_ms: u64) -> bool {
    now_ms >= start_ms && now_ms - start_ms < MINUTE_MS
}

/// Whether `error` is a withdrawal rate-limit refusal, which the API answers with
/// `429` (every other withdrawal refusal is a `400`). The refusals are compared
/// whole, so another error that happens to share a prefix is never one.
pub(crate) fn is_withdraw_rate_limit(error: &str) -> bool {
    error == WITHDRAW_RATE_LIMIT_MINUTE || error == WITHDRAW_RATE_LIMIT_WINDOW
}

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

/// Snapshot section of the history-unit ledger, after the recovery section. It is
/// written only when the ledger is not empty, so a gateway with no usage writes the
/// bytes it always did, and a snapshot without it loads with an empty ledger.
const LEDGER_EXT: &[u8; 8] = b"DPWLIM01";

/// Snapshot section of the dust sweeps' withdrawal leaves, after the ledger section.
/// It is written only when a sweep is recorded, so a gateway that never swept writes
/// the bytes it always did, and a snapshot without it loads with none.
const SWEEP_EXT: &[u8; 8] = b"DPSWEEP1";

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
    /// Append the history-unit ledger section to a snapshot payload.
    pub(crate) fn append_withdraw_ledger(&self, bytes: &mut Vec<u8>) {
        if self.withdraw_limits.history_units.is_empty() {
            return;
        }
        let rows: Vec<([u8; 32], u64)> = self
            .withdraw_limits
            .history_units
            .iter()
            .map(|(owner, units)| (*owner, *units))
            .collect();
        bytes.extend_from_slice(LEDGER_EXT);
        bytes.extend_from_slice(&postcard::to_allocvec(&rows).expect("ledger snapshot encode"));
    }

    /// Append the dust sweeps' section to a snapshot payload, after the ledger.
    pub(crate) fn append_dust_sweeps(&self, bytes: &mut Vec<u8>) {
        if self.dust_sweeps.leaves.is_empty() {
            return;
        }
        let leaves: Vec<[u8; 32]> = self.dust_sweeps.leaves.iter().copied().collect();
        bytes.extend_from_slice(SWEEP_EXT);
        bytes.extend_from_slice(&postcard::to_allocvec(&leaves).expect("sweep snapshot encode"));
    }

    /// Restore the ledger section that may follow the recovery section, returning
    /// what follows it; a tail without it (a snapshot written without usage) leaves
    /// the ledger empty.
    pub(crate) fn restore_withdraw_ledger<'a>(
        &mut self,
        tail: &'a [u8],
    ) -> Result<&'a [u8], String> {
        let Some(payload) = tail.strip_prefix(LEDGER_EXT) else {
            return Ok(tail);
        };
        let (rows, rest): (Vec<([u8; 32], u64)>, _) = postcard::take_from_bytes(payload)
            .map_err(|e| format!("withdrawal ledger snapshot decode: {e}"))?;
        let mut ledger = std::collections::BTreeMap::new();
        for (owner, units) in rows {
            if ledger.insert(owner, units).is_some() {
                return Err("duplicate withdrawal ledger owner".into());
            }
        }
        self.withdraw_limits.history_units = ledger;
        Ok(rest)
    }

    /// Restore the dust sweeps' section that may follow the ledger section; an
    /// empty tail (a snapshot written before any sweep) leaves none, and anything
    /// else is refused.
    pub(crate) fn restore_dust_sweeps(&mut self, tail: &[u8]) -> Result<(), String> {
        if tail.is_empty() {
            return Ok(());
        }
        let payload = tail
            .strip_prefix(SWEEP_EXT)
            .ok_or("unknown snapshot section after the recovery extension")?;
        let (rows, rest): (Vec<[u8; 32]>, _) = postcard::take_from_bytes(payload)
            .map_err(|e| format!("dust sweep snapshot decode: {e}"))?;
        if !rest.is_empty() {
            return Err("trailing dust sweep snapshot bytes".into());
        }
        let mut leaves = BTreeSet::new();
        for leaf in rows {
            if !leaves.insert(leaf) {
                return Err("duplicate dust sweep leaf".into());
            }
        }
        self.dust_sweeps.leaves = leaves;
        Ok(())
    }

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

    /// Whether `key` holds an outstanding collateral permit for `market` below
    /// `MIN_ENTRY_DEPOSIT`: one issued while the entry held the minimum or an open
    /// position, or before the entry minimum, whose deposit would open a new entry
    /// below the minimum if it landed after the entry left.
    fn holds_top_up_permit(&self, key: &[u8; 32], market: u64) -> bool {
        self.accounts.get(key).is_some_and(|account| {
            account.deposit_authorizations.keys().any(|commit| {
                self.deposits.routes.get(commit).is_some_and(|route| {
                    route.key == *key
                        && route.market == market
                        && route.purpose == deposit_ingestion::Purpose::Collateral
                        && route.amount < MIN_ENTRY_DEPOSIT
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

    /// Whether a new permit for `key`, `market` and `purpose` may open a position
    /// entry once credited (audit G1-1): a collateral permit for a market where the
    /// account holds no entry or only dust (`deposit_may_open`). It needs the entry
    /// minimum, and the position entries may refuse it (`entries_refusal`) even when
    /// an outstanding permit already reserves that entry: a new one would keep the
    /// reservation past the old one's deadline.
    fn permit_reserves_entry(
        &self,
        key: &[u8; 32],
        market: u64,
        purpose: deposit_ingestion::Purpose,
    ) -> bool {
        purpose == deposit_ingestion::Purpose::Collateral
            && self.accounts.get(key).is_some_and(|account| {
                deposit_may_open(self.seq.state.position(&account.wallet.owner, market))
            })
    }

    /// Whether a new permit for `key`, `market` and `purpose` would open a position
    /// entry once credited that the outstanding permits do not already count: one
    /// that reserves an entry (`permit_reserves_entry`) for a market where the
    /// account holds no outstanding collateral permit.
    fn permit_opens_entry(
        &self,
        key: &[u8; 32],
        market: u64,
        purpose: deposit_ingestion::Purpose,
    ) -> bool {
        self.permit_reserves_entry(key, market, purpose)
            && !self.holds_collateral_permit(key, market)
    }

    /// What crediting the deposits of every outstanding permit adds to the state:
    /// each deposit mints a note and spends it into a position or the insurance
    /// fund (one tree leaf and one nullifier), and a collateral deposit opens a
    /// position entry when its account holds none in that market by then. A permit
    /// for a market where the account holds only dust counts as opening one too: a
    /// sweep may exit the dust first, and then each sweep frees an entry at once.
    /// It adds no unspent note.
    pub(crate) fn outstanding_permit_size(&self) -> HistorySize {
        let mut history = 0u64;
        let mut opened = BTreeSet::new();
        for route in self.deposits.routes.values() {
            history = history.saturating_add(2);
            if let Some(owner) = self.route_may_open(route) {
                opened.insert((owner, route.market));
            }
        }
        HistorySize {
            history,
            positions: opened.len() as u64,
            notes: 0,
        }
    }

    /// The owner whose entry the deposit of the outstanding permit `route` may open,
    /// if it may open one: a collateral permit for a market where the owner holds
    /// no entry or only dust (`deposit_may_open`).
    fn route_may_open(&self, route: &deposit_ingestion::Route) -> Option<PubKey> {
        if route.purpose != deposit_ingestion::Purpose::Collateral {
            return None;
        }
        let owner = self.accounts.get(&route.key)?.wallet.owner;
        deposit_may_open(self.seq.state.position(&owner, route.market)).then_some(owner)
    }

    /// How many outstanding permits that may open an entry the client `group` holds
    /// (none without a group).
    fn group_opening_permits(&self, group: Option<std::net::IpAddr>) -> usize {
        let Some(group) = group else {
            return 0;
        };
        self.permit_groups
            .by_commit
            .iter()
            .filter(|(commit, g)| {
                **g == group
                    && self
                        .deposits
                        .routes
                        .get(*commit)
                        .is_some_and(|route| self.route_may_open(route).is_some())
            })
            .count()
    }

    /// Record that the new permit `commit` was issued to the client `group` (only
    /// while it may open an entry does it count, `group_opening_permits`), and
    /// forget the groups of permits no longer outstanding.
    pub(crate) fn record_permit_group(
        &mut self,
        commit: [u8; 32],
        group: Option<std::net::IpAddr>,
    ) {
        let routes = &self.deposits.routes;
        self.permit_groups
            .by_commit
            .retain(|commit, _| routes.contains_key(commit));
        if let Some(group) = group {
            self.permit_groups.by_commit.insert(commit, group);
        }
    }

    /// Why the position entries refuse a new permit that may open one, if they do
    /// (audit G1-1), with `state` entries in the state, `permits` the outstanding
    /// permits may open, `opens` whether this one adds to those, and `group_holds`
    /// such permits held by the asking client group: the state's entries are at
    /// their soft cap; or the state's entries and every outstanding permit's, this
    /// one's included, would exceed the bound, so a deposit could not be credited;
    /// or, with those at the soft cap, the group already holds
    /// `MAX_GROUP_OPENING_PERMITS`.
    fn entries_refusal(
        &self,
        state: u64,
        permits: u64,
        opens: bool,
        group_holds: usize,
    ) -> Option<PermitGateRefusal> {
        let max = self.admission_cap.max_positions;
        let held = state.saturating_add(permits);
        if state >= soft(max) || held.saturating_add(u64::from(opens)) > max {
            Some(PermitGateRefusal::AdmissionCap)
        } else if held >= soft(max) && group_holds >= MAX_GROUP_OPENING_PERMITS {
            Some(PermitGateRefusal::ClientOpeningPermits)
        } else {
            None
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
    /// permits will add, raising or clearing its alert. Also raises or clears the
    /// alert of the partial-withdrawal reserve (`note_withdraw_reserve`).
    pub(crate) fn note_admission_cap(&self) -> bool {
        self.note_withdraw_reserve();
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

    /// Why a new account may not register now, if it may not: the state's own
    /// history or unspent notes are at their soft cap. Registration adds no position
    /// entry, so the position entries never close it (audit G1-1), and outstanding
    /// permits never do.
    pub(crate) fn registration_refusal(&self) -> Option<&'static str> {
        self.note_admission_cap();
        let state = HistorySize::of(&self.seq.state);
        let cap = &self.admission_cap;
        (state.history >= soft(cap.max_history) || state.notes >= soft(cap.max_notes)).then_some(
            "the provable-history admission cap is reached; registration is closed. \
             Existing accounts can still withdraw",
        )
    }

    /// Why a new permit of `amount` for `key`, `market` and `purpose` is below the
    /// entry minimum, if it is: a collateral permit for a market where the account
    /// holds no position entry or only dust may open one (`permit_reserves_entry`),
    /// so it needs `MIN_ENTRY_DEPOSIT`, held permits for that market or not
    /// (whichever deposit is credited first opens the entry). So a top-up of dust
    /// takes it to the minimum, and a deposit that lands after a sweep opens no
    /// dust. A top-up of any other entry keeps `MIN_DEPOSIT_PERMIT`.
    pub(crate) fn entry_minimum_refusal(
        &self,
        key: &[u8; 32],
        market: u64,
        purpose: deposit_ingestion::Purpose,
        amount: u128,
    ) -> Option<PermitGateRefusal> {
        (self.permit_reserves_entry(key, market, purpose) && amount < MIN_ENTRY_DEPOSIT)
            .then_some(PermitGateRefusal::BelowEntryMinimum)
    }

    /// Why a new deposit permit for `key`, `market` and `purpose`, asked by the
    /// client `group`, may not be issued under the admission cap, if it may not: an
    /// account with no position entry already reserves an entry in another market;
    /// the history is at its soft cap; the permit would leave too little history
    /// for the reserved exits; or, for a permit that may open an entry
    /// (`permit_reserves_entry`), the position entries refuse it
    /// (`entries_refusal`).
    pub(crate) fn permit_cap_refusal(
        &self,
        key: &[u8; 32],
        market: u64,
        purpose: deposit_ingestion::Purpose,
        group: Option<std::net::IpAddr>,
    ) -> Option<PermitGateRefusal> {
        self.note_admission_cap();
        if purpose == deposit_ingestion::Purpose::Collateral
            && self
                .committed_history_units(key)
                .saturating_add(HISTORY_UNITS_PER_OP)
                > ACCOUNT_HISTORY_QUOTA
        {
            return Some(PermitGateRefusal::AccountQuota);
        }
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
        let state = HistorySize::of(&self.seq.state);
        let permits = self.outstanding_permit_size();
        let size = state.plus(permits);
        let cap = &self.admission_cap;
        if size.history >= soft(cap.max_history) || !cap.exits_fit(size.plus(credit_of(opens))) {
            return Some(PermitGateRefusal::AdmissionCap);
        }
        if !self.permit_reserves_entry(key, market, purpose) {
            return None;
        }
        self.entries_refusal(
            state.positions,
            permits.positions,
            opens,
            self.group_opening_permits(group),
        )
    }

    /// Make room for the new permit `request` asks for, from the client `group`
    /// (audit G1-1): when the position entries alone refuse it, and exiting dust
    /// entries of other accounts admits it, sweep as few of them as admit it
    /// (`sweeps_needed`, `dust_candidates`, smallest first). Every exit is planned
    /// on a copy of the engine state before the first is made: a candidate whose
    /// exit fails there is skipped, and unless enough can be exited, none is.
    /// Nothing is swept for a permit refused for any other reason (its route, the
    /// entry minimum or `admit_deposit_permit` included), nor when one request may
    /// not sweep enough. The swept accounts' orders in those markets are cancelled
    /// first. Only a failure to make the permit durable afterwards leaves the
    /// sweeps without it; they stand like any applied withdrawal, and the room
    /// they made stays for the retry. Returns each forced exit with its market, for
    /// the caller to announce once a snapshot carries it (`forced_exit_event`).
    ///
    /// Each unbind is a timed engine operation, applied like a withdrawal's: a gate
    /// on the open window's timed operations must cover this path too.
    pub(crate) fn sweep_dust_for_permit(
        &mut self,
        request: &deposit_ingestion::Route,
        group: Option<std::net::IpAddr>,
        now_s: u64,
        price: PriceUse<'_>,
    ) -> Vec<(u64, Withdrawal)> {
        let (key, market, purpose) = (&request.key, request.market, request.purpose);
        if self.validate_route(request).is_err()
            || self
                .entry_minimum_refusal(key, market, purpose, request.amount)
                .is_some()
            || self.admit_deposit_permit(key, purpose, now_s).is_err()
        {
            return Vec::new();
        }
        let Some(needed) = self.sweeps_needed(key, market, purpose, group) else {
            return Vec::new();
        };
        let candidates = self.dust_candidates(key, price);
        if (candidates.len() as u64) < needed {
            return Vec::new();
        }
        let plan = self.plan_dust_exits(candidates, needed, price.now_ms);
        if (plan.len() as u64) < needed {
            return Vec::new();
        }
        for exit in &plan {
            self.cancel_swept_orders(&exit.dust.key, exit.dust.market);
        }
        let ops: Vec<BatchOp> = plan.iter().flat_map(|exit| exit.ops.clone()).collect();
        // The plan applied every op to a copy of this state in this order.
        if let Err(e) = self.seq.apply_atomic(&ops) {
            eprintln!("[admission] planned dust sweep refused: {e:?}");
            return Vec::new();
        }
        let mut swept = Vec::new();
        for exit in plan {
            self.next_withdraw_nonce = exit.nonce.saturating_add(1);
            let w = Withdrawal {
                owner: exit.owner,
                to: exit.dust.to,
                amount: exit.dust.amount as u128,
                nonce: exit.nonce,
            };
            self.pending_withdrawals.push(w.clone());
            self.window_withdrawals.push(w.clone());
            self.dust_sweeps.leaves.insert(w.leaf());
            swept.push((exit.dust.market, w));
        }
        println!(
            "[admission] swept {} dust position entries below {} USDC to make room for a new entry",
            swept.len(),
            MIN_ENTRY_BALANCE / QUOTE_SCALE
        );
        swept
    }

    /// How many dust entries must be exited for the permit, asked by the client
    /// `group`, to be issued, if a sweep can admit it: the permit opens an entry (a
    /// further permit for an entry its account already reserves never sweeps), the
    /// position entries refuse it, and with that many entries fewer, and the leaf
    /// and nullifier each exit adds, nothing refuses it, within
    /// `MAX_SWEEPS_PER_PERMIT`. An exit frees one entry of the state and changes
    /// nothing the permits may open: a permit for dust already counts as opening
    /// one (`outstanding_permit_size`).
    fn sweeps_needed(
        &self,
        key: &[u8; 32],
        market: u64,
        purpose: deposit_ingestion::Purpose,
        group: Option<std::net::IpAddr>,
    ) -> Option<u64> {
        if !self.permits_creditable() || !self.permit_opens_entry(key, market, purpose) {
            return None;
        }
        if !matches!(
            self.permit_cap_refusal(key, market, purpose, group),
            Some(PermitGateRefusal::AdmissionCap | PermitGateRefusal::ClientOpeningPermits)
        ) {
            return None;
        }
        let state = HistorySize::of(&self.seq.state);
        let permits = self.outstanding_permit_size();
        let group_holds = self.group_opening_permits(group);
        let cap = &self.admission_cap;
        (1..=MAX_SWEEPS_PER_PERMIT.min(state.positions)).find(|&n| {
            let entries = state.positions - n;
            let after = HistorySize {
                history: state
                    .history
                    .saturating_add(permits.history)
                    .saturating_add(n.saturating_mul(2)),
                positions: entries.saturating_add(permits.positions),
                notes: state.notes,
            };
            after.history < soft(cap.max_history)
                && cap.exits_fit(after.plus(credit_of(true)))
                && self
                    .entries_refusal(entries, permits.positions, true, group_holds)
                    .is_none()
        })
    }

    /// The dust entries a sweep may exit, in the order it exits them: every flat
    /// entry below `MIN_ENTRY_BALANCE`, smallest first (then in key order), whose
    /// account is not `asker` and has a bound deposit address (the exit's
    /// destination, the only one a server-custody account may withdraw to), in a
    /// market whose oracle report is usable at `price` (`sweep_oracle`). An
    /// outstanding permit of the account does not keep its dust: that permit
    /// already counts as opening an entry, and its deposit, if it lands, opens one
    /// at the entry minimum (or, for a permit from before the minimum, flat dust
    /// that can open no position and is swept again).
    fn dust_candidates(&self, asker: &[u8; 32], price: PriceUse<'_>) -> Vec<DustEntry> {
        let dust: Vec<(&(PubKey, u64), &Position)> = self
            .seq
            .state
            .positions
            .iter()
            .filter(|(_, entry)| is_dust(entry))
            .collect();
        if dust.is_empty() {
            return Vec::new();
        }
        let oracles: BTreeMap<u64, OracleTranscript> = self
            .mkts
            .iter()
            .filter_map(|m| self.sweep_oracle(m.id, price).map(|o| (m.id, o)))
            .collect();
        let mut candidates: Vec<DustEntry> = dust
            .into_iter()
            .filter_map(|((owner, market), entry)| {
                let key = self.key_of_owner(owner)?;
                let to = self.accounts[&key].deposit_address?;
                (key != *asker).then_some(DustEntry {
                    key,
                    market: *market,
                    amount: entry.collateral,
                    to,
                    oracle: *oracles.get(market)?,
                })
            })
            .collect();
        // Stable: equal amounts keep the key order.
        candidates.sort_by_key(|dust| dust.amount);
        candidates
    }

    /// The oracle report a sweep's unbind in `market` carries: the stored report,
    /// validated at `price` (in candidate mode also checked against the archive),
    /// never a stale price signed again with a fresh time. None while the market has
    /// no usable report: its dust waits.
    fn sweep_oracle(&self, market: u64, price: PriceUse<'_>) -> Option<OracleTranscript> {
        if let Some(oracle) = self.require_candidate_price(market, price).ok()? {
            return Some(oracle);
        }
        let oracle = *self.seq.oracle(market)?;
        let policy = self.seq.state.markets.get(&market)?;
        oracle.validate(policy, price.now_ms).ok()?;
        Some(oracle)
    }

    /// Plan the forced exits of the first `needed` of `candidates` that can be
    /// exited at `now_ms`, in order: each one's unbind and burn are applied to a
    /// copy of the engine state after the exits planned before it, and a candidate
    /// whose exit fails there is skipped. Nothing is applied to the state itself.
    fn plan_dust_exits(
        &self,
        candidates: Vec<DustEntry>,
        needed: u64,
        now_ms: u64,
    ) -> Vec<DustExit> {
        let Ok(mut nonce) = self.next_withdrawal_nonce() else {
            return Vec::new();
        };
        let mut trial = self.seq.state.clone();
        let mut plan = Vec::new();
        for dust in candidates {
            if plan.len() as u64 == needed {
                break;
            }
            let exit = match self.dust_exit(dust, nonce, now_ms) {
                Ok(exit) => exit,
                Err(e) => {
                    eprintln!("[admission] dust sweep skipped an entry: {e}");
                    continue;
                }
            };
            let mut next = trial.clone();
            match exit
                .ops
                .iter()
                .try_for_each(|op| next.apply_op(op).map(drop))
            {
                Ok(()) => {
                    trial = next;
                    plan.push(exit);
                    nonce = nonce.saturating_add(1);
                }
                Err(e) => eprintln!("[admission] dust sweep skipped an entry: {e:?}"),
            }
        }
        plan
    }

    /// The forced exit of the dust entry `dust` with the withdrawal `nonce` at
    /// `now_ms`: the unbind and burn of the account's own withdrawal of its whole
    /// balance, to its bound deposit address. Like any full exit it removes the
    /// entry and needs no history room; it ignores the quota, and the account's
    /// authorization nonce, withdrawal rate limits and history ledger are not
    /// touched (`withdrawal_rate_refusal` leaves forced exits out).
    fn dust_exit(&self, dust: DustEntry, nonce: u64, now_ms: u64) -> Result<DustExit, String> {
        let wallet = self
            .accounts
            .get(&dust.key)
            .ok_or("Unknown account.")?
            .wallet;
        if !self.is_full_exit(&wallet.owner, dust.market, dust.amount) {
            return Err("a dust sweep exits a flat entry's whole balance".into());
        }
        if let Some(refusal) =
            self.exit_cap_refusal(&dust.key, &wallet.owner, dust.market, dust.amount)
        {
            return Err(refusal.into());
        }
        let mut blind = [0xD0u8; 32];
        blind[..8].copy_from_slice(&nonce.to_le_bytes());
        let note = Note::new(wallet.owner, 0, dust.amount, blind);
        let ops = [
            BatchOp::Unbind {
                owner: wallet.owner,
                market_id: dust.market,
                amount: dust.amount,
                blinding: blind,
                oracle: dust.oracle,
                now_ms,
            },
            BatchOp::Withdraw {
                note_commitment: note.commitment::<Keccak256>(),
                spend_key: wallet.spend_key,
                to: Some(dust.to),
                nonce,
            },
        ];
        Ok(DustExit {
            dust,
            owner: wallet.owner,
            nonce,
            ops,
        })
    }

    /// Cancel the live orders of `key`'s account in `market` before a sweep exits
    /// its entry there: the entry is gone, and an order resting on it would only
    /// fail to fill (or hold collateral the exit takes). Each is recorded as
    /// cancelled for `DUST_SWEEP`.
    fn cancel_swept_orders(&mut self, key: &[u8; 32], market: u64) {
        let Some(account) = self.accounts.get_mut(key) else {
            return;
        };
        let owner = account.wallet.owner;
        for o in account
            .orders
            .iter_mut()
            .filter(|o| o.order.market_id == market)
        {
            if self
                .seq
                .cancellable_size(&owner, &o.order, o.sealed)
                .is_none()
                || execution::cancel(&mut self.seq, &owner, o).is_err()
            {
                continue;
            }
            if let Some(e) = o.execution.as_mut() {
                e.reason = Some(DUST_SWEEP.into());
            }
            if !self.pending_rejected.contains(&o.order_hash) {
                self.pending_rejected.push(o.order_hash);
            }
        }
    }

    /// The API key of the account whose owner is `owner`, from the owner index,
    /// checked against the account it names.
    fn key_of_owner(&self, owner: &PubKey) -> Option<[u8; 32]> {
        let key = self.owner_keys.get(owner)?;
        self.accounts
            .get(key)
            .is_some_and(|a| a.wallet.owner == *owner)
            .then_some(*key)
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

    /// Whether withdrawing `amount` is a full exit: the whole balance of a closed
    /// position, which removes its entry.
    pub(crate) fn is_full_exit(&self, owner: &PubKey, market: u64, amount: i128) -> bool {
        self.seq
            .state
            .position(owner, market)
            .is_some_and(|p| p.size == 0 && p.collateral == amount)
    }

    /// Why a withdrawal of `amount` from `owner`'s (account `key`) entry in `market`
    /// at `now_ms` exceeds the account's rate limits or history quota, or the
    /// exchange-wide history reserve, if it does. The rate limits apply to every
    /// withdrawal; the quota and the reserve to every one but a full exit, which
    /// must always be able to leave. The quota counts the account's outstanding
    /// collateral permits, as the permit gate does: their credits are never refused
    /// by it, so ignoring them here would let one account spend it twice.
    pub(crate) fn withdrawal_limit_refusal(
        &self,
        key: &[u8; 32],
        owner: &PubKey,
        market: u64,
        amount: i128,
        now_ms: u64,
    ) -> Option<&'static str> {
        if let Some(refusal) = self.withdrawal_rate_refusal(owner, now_ms) {
            return Some(refusal);
        }
        if self.is_full_exit(owner, market, amount) {
            return None;
        }
        if self
            .committed_history_units(key)
            .saturating_add(HISTORY_UNITS_PER_OP)
            > ACCOUNT_HISTORY_QUOTA
        {
            return Some(WITHDRAW_QUOTA_EXCEEDED);
        }
        self.withdrawal_reserve_refusal()
    }

    /// Why a withdrawal of `amount` by the shared demo user `owner` at `now_ms`
    /// exceeds the rate limits or the exchange-wide history reserve, if it does.
    /// No lifetime quota: every visitor of the demo build shares that one user and
    /// the demo deposit routes are not metered, so a quota would protect nothing
    /// and only close `/api/withdraw` for everyone.
    pub(crate) fn demo_withdrawal_limit_refusal(
        &self,
        owner: &PubKey,
        market: u64,
        amount: i128,
        now_ms: u64,
    ) -> Option<&'static str> {
        if let Some(refusal) = self.withdrawal_rate_refusal(owner, now_ms) {
            return Some(refusal);
        }
        if self.is_full_exit(owner, market, amount) {
            return None;
        }
        self.withdrawal_reserve_refusal()
    }

    /// Why a withdrawal by `owner` at `now_ms` exceeds the per-minute or the
    /// per-settlement-window rate limit, if it does. Both count the account's own
    /// withdrawals only, not the forced exits of dust sweeps.
    fn withdrawal_rate_refusal(&self, owner: &PubKey, now_ms: u64) -> Option<&'static str> {
        let usage = self.withdraw_limits.usage(owner);
        if minute_holds(usage.minute_start_ms, now_ms)
            && usage.minute_count >= MAX_WITHDRAWALS_PER_MINUTE
        {
            return Some(WITHDRAW_RATE_LIMIT_MINUTE);
        }
        let in_window = self
            .window_withdrawals
            .iter()
            .filter(|w| &w.owner == owner && !self.dust_sweeps.contains(&w.leaf()))
            .count();
        (in_window >= MAX_WITHDRAWALS_PER_WINDOW).then_some(WITHDRAW_RATE_LIMIT_WINDOW)
    }

    /// Why a withdrawal of `amount` from `owner`'s entry in `market` would leave it
    /// below the entry minimum, if it would (audit G1-1): while deposits can be
    /// credited, a withdrawal is a full exit or leaves at least `MIN_ENTRY_BALANCE`
    /// in the entry, whether it holds an open position or not. So no withdrawal
    /// leaves dust (`top_up_exit_refusal` keeps a top-up from landing after a full
    /// exit), and an entry holding a position the sweep never exits keeps the
    /// minimum unless trading lost it. In close-only no entry opens any more, and
    /// every exit is accepted.
    pub(crate) fn entry_balance_refusal(
        &self,
        owner: &PubKey,
        market: u64,
        amount: i128,
    ) -> Option<String> {
        if !self.permits_creditable() || self.is_full_exit(owner, market, amount) {
            return None;
        }
        let collateral = self
            .seq
            .state
            .position(owner, market)
            .map_or(0, |p| p.collateral);
        (collateral.saturating_sub(amount) < MIN_ENTRY_BALANCE).then(|| {
            format!(
                "BELOW_ENTRY_BALANCE: a withdrawal must leave at least {} USDC in this \
                 market, or be a full exit: close the position, then withdraw the whole \
                 balance of this market",
                MIN_ENTRY_BALANCE / QUOTE_SCALE
            )
        })
    }

    /// Why a full exit of `amount` from `owner`'s (account `key`) entry in `market`
    /// must wait, if it must (audit G1-1): while deposits can be credited, the
    /// account holds an outstanding permit below `MIN_ENTRY_DEPOSIT` for the
    /// market, issued for a top-up while the entry held the minimum or an open
    /// position. Its deposit would land in the missing entry and open a new one
    /// below the minimum, recycling the balance that left. It is accepted once that
    /// deposit is credited (the whole balance then leaves with it) or the permit
    /// has expired.
    pub(crate) fn top_up_exit_refusal(
        &self,
        key: &[u8; 32],
        owner: &PubKey,
        market: u64,
        amount: i128,
    ) -> Option<&'static str> {
        (self.permits_creditable()
            && self.is_full_exit(owner, market, amount)
            && self.holds_top_up_permit(key, market))
        .then_some(TOP_UP_PERMIT_OUTSTANDING)
    }

    /// Why an order of `owner` that opens, grows or flips a position in `market`
    /// is refused below the entry minimum, if it is (audit G1-1): its entry holds
    /// less than `MIN_ENTRY_BALANCE`. The sequencer holds every fill that adds
    /// exposure to the same rule (`Sequencer::set_min_entry_collateral`), so an
    /// order that rests from when the entry held the minimum does not fill below
    /// it either. Reductions are never refused.
    pub(crate) fn entry_order_refusal(&self, owner: &PubKey, market: u64) -> Option<String> {
        let collateral = self
            .seq
            .state
            .position(owner, market)
            .map_or(0, |p| p.collateral);
        (collateral < MIN_ENTRY_BALANCE).then(|| {
            format!(
                "BELOW_ENTRY_BALANCE: an order that opens or increases a position needs at \
                 least {} USDC in this market; deposit into it first. Orders that only \
                 reduce the position are accepted",
                MIN_ENTRY_BALANCE / QUOTE_SCALE
            )
        })
    }

    /// Take back what the withdrawal `w`, which a voided window or the close-only
    /// rebase removed, was charged; a forced exit was charged nothing. Call it
    /// before the sweeps forget `w`.
    pub(crate) fn refund_removed_withdrawal(&mut self, w: &Withdrawal) {
        if !self.dust_sweeps.contains(&w.leaf()) {
            self.withdraw_limits.refund_withdrawal(&w.owner);
        }
    }

    /// Why no partial withdrawal is accepted now, if none is: the state's own
    /// history reached the reserve. Past it nothing but a full exit is accepted, so
    /// the room above it stays for deposits, registration and exits (outside
    /// close-only, where no permit is credited and nothing is left to reserve it
    /// for).
    fn withdrawal_reserve_refusal(&self) -> Option<&'static str> {
        let reached = self.note_withdraw_reserve();
        (reached && self.permits_creditable()).then_some(WITHDRAW_RESERVE_REACHED)
    }

    /// Whether the state's own history reached `PARTIAL_WITHDRAWAL_HISTORY_CEILING`,
    /// raising the `withdraw_reserve_near` alert from `WITHDRAW_RESERVE_ALERT_HISTORY`
    /// on (or clearing it below, after a voided window).
    fn note_withdraw_reserve(&self) -> bool {
        let history = HistorySize::of(&self.seq.state).history;
        if history >= WITHDRAW_RESERVE_ALERT_HISTORY {
            self.ops_alerts
                .activate(ops_alerts::AlertKind::WithdrawReserveNear);
        } else {
            self.ops_alerts
                .recover(ops_alerts::AlertKind::WithdrawReserveNear);
        }
        history >= PARTIAL_WITHDRAWAL_HISTORY_CEILING
    }

    /// History units `key`'s account has spent, plus those its outstanding
    /// collateral permits will take once their deposits are credited.
    fn committed_history_units(&self, key: &[u8; 32]) -> u64 {
        let Some(account) = self.accounts.get(key) else {
            return 0;
        };
        let permits = self
            .deposits
            .routes
            .values()
            .filter(|r| r.key == *key && r.purpose == deposit_ingestion::Purpose::Collateral)
            .count() as u64;
        self.withdraw_limits
            .units(&account.wallet.owner)
            .saturating_add(permits.saturating_mul(HISTORY_UNITS_PER_OP))
    }

    /// Charge the deposit that was just credited under `route` to its account.
    pub(crate) fn charge_credited_deposit(&mut self, route: &deposit_ingestion::Route) {
        if route.purpose != deposit_ingestion::Purpose::Collateral {
            return;
        }
        if let Some(owner) = self.accounts.get(&route.key).map(|a| a.wallet.owner) {
            self.withdraw_limits.record_credit(&owner);
        }
    }

    /// Take back what the credit under `route` was charged: a discarded window
    /// removed it from the state.
    pub(crate) fn refund_credited_deposit(&mut self, route: &deposit_ingestion::Route) {
        if route.purpose != deposit_ingestion::Purpose::Collateral {
            return;
        }
        if let Some(owner) = self.accounts.get(&route.key).map(|a| a.wallet.owner) {
            self.withdraw_limits.refund_credit(&owner);
        }
    }

    /// Why a withdrawal of `amount` from `owner`'s (account `key`) entry in `market`
    /// may not be applied under the admission cap, if it may not. Each withdrawal
    /// adds a leaf and a nullifier. A full exit (a closed position's whole balance)
    /// also removes the entry and its reserved exit, so it needs no room, unless the
    /// account holds an outstanding permit for the market that could reopen it and
    /// is not counted as opening one yet (a permit for dust already is,
    /// `outstanding_permit_size`). Every other withdrawal needs the room the
    /// reserved exits and the outstanding permits leave under the history bound.
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
        let full_exit = self.is_full_exit(owner, market, amount);
        let reopenable = full_exit
            && creditable
            && self.holds_collateral_permit(key, market)
            && !deposit_may_open(self.seq.state.position(owner, market));
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
        // A top-up of an existing entry: a permit that opens one needs the entry
        // minimum (`audit_1116_g11_tests`).
        app.gw
            .lock()
            .await
            .account_deposit(&key, 0, MIN_ENTRY_BALANCE)
            .unwrap();
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
                .oneshot(permit_request(&key, MIN_ENTRY_DEPOSIT, None))
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
                    .oneshot(permit_request(&key, MIN_ENTRY_DEPOSIT, reuse))
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
                .oneshot(permit_request(&key, MIN_ENTRY_DEPOSIT, None))
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
                .oneshot(permit_request(&key, MIN_ENTRY_DEPOSIT, None))
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
                    MIN_ENTRY_DEPOSIT,
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
                .oneshot(permit_request(&key, MIN_ENTRY_DEPOSIT, None))
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
                .oneshot(permit_request(&key, MIN_ENTRY_DEPOSIT + 1, None))
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
                    MIN_ENTRY_DEPOSIT,
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
                .oneshot(permit_request(&key, MIN_ENTRY_DEPOSIT, None))
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
                    MIN_ENTRY_DEPOSIT,
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

    /// What `funded_withdrawer` holds: $300, so its partial withdrawals reach the
    /// history cap before the entry minimum.
    const FUNDED: i128 = 300 * QUOTE_SCALE;

    /// A production gateway with one caller-signed account funded with `FUNDED`
    /// in market 0. Returns the account key, its signing key and its address.
    fn funded_withdrawer() -> (Gw, [u8; 32], k256::ecdsa::SigningKey, [u8; 20]) {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let sk = k256::ecdsa::SigningKey::from_slice(&SIGNER).unwrap();
        let address = eth_address(&sk);
        let (key, _) = gw.register_account(Some(address));
        gw.account_deposit(&key, 0, FUNDED).unwrap();
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
            gw.permit_cap_refusal(&key, 0, deposit_ingestion::Purpose::Collateral, None),
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
            max_history: 40,
            max_positions: 100,
            max_notes: 100,
        };
        // Issued below the soft cap: the state, the permit and their exits fit.
        assert_eq!(gw.admission_size(), size(4, 2, 0));
        let room = (40 - gw.admission_size().with_exits()) / 2;
        let mut partial = 0;
        let refusal = loop {
            // This test is about the history cap, not the per-account limits.
            gw.withdraw_limits = Default::default();
            gw.window_withdrawals.clear();
            match withdraw(&mut gw, &key, &sk, MIN_WITHDRAWAL, to) {
                Ok(_) => partial += 1,
                Err(error) => break error,
            }
            assert!(gw.admission_size().with_exits() <= 40);
            assert!(partial <= room, "a partial withdrawal past the room");
        };
        assert_eq!(partial, room);
        assert_eq!(refusal, HISTORY_CAP_EXIT);
        assert_eq!(gw.admission_size().with_exits(), 40);
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
        assert!(left > MIN_WITHDRAWAL);
        gw.withdraw_limits = Default::default();
        gw.window_withdrawals.clear();
        assert_eq!(
            withdraw(&mut gw, &key, &sk, MIN_WITHDRAWAL, to).unwrap_err(),
            HISTORY_CAP_EXIT
        );
        withdraw(&mut gw, &key, &sk, left, to).unwrap();
        let owner = gw.accounts[&depositor].wallet.owner;
        assert_eq!(
            gw.exit_cap_refusal(&depositor, &owner, 0, MIN_DEPOSIT_PERMIT as i128),
            None
        );
        assert!(HistorySize::of(&gw.seq.state).history <= 40);
        assert_eq!(gw.admission_size().with_exits(), 40);
    }

    /// At the bound a full exit by an account that holds an outstanding permit for
    /// the same market is refused: the permit's deposit would open the entry again
    /// and need an exit of its own. Once the permit is gone the exit is accepted.
    #[test]
    fn a_full_exit_that_a_held_permit_could_reopen_needs_room() {
        let (mut gw, key, sk, to) = funded_withdrawer();
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(PAYER);
        // A permit at the entry minimum: one below it would hold any full exit
        // (`top_up_exit_refusal`), whatever the history.
        let commit = gw
            .authorize_routed_deposit(
                &key,
                PAYER,
                MIN_ENTRY_DEPOSIT,
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
        let all = FUNDED;
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
        let all = FUNDED;
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
    /// once the entries and the reservations fill the bound (past the soft cap the
    /// reservations share the room up to it, audit G1-1).
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
        assert_eq!(gw.permit_cap_refusal(&first, 0, Collateral, None), None);
        issue(&mut gw, &first, 0);
        // Another market is refused until the first deposit is credited; the same
        // market reserves nothing new.
        assert_eq!(
            gw.permit_cap_refusal(&first, 1, Collateral, None),
            Some(PermitGateRefusal::OneMarketUntilFirstDeposit)
        );
        assert_eq!(gw.permit_cap_refusal(&first, 0, Collateral, None), None);
        issue(&mut gw, &first, 0);
        assert_eq!(gw.outstanding_permit_size().positions, 1);
        for _ in 0..3 {
            let key = fresh(&mut gw);
            assert_eq!(gw.permit_cap_refusal(&key, 0, Collateral, None), None);
            issue(&mut gw, &key, 0);
        }
        assert_eq!(gw.admission_size().positions, 4);
        let late = fresh(&mut gw);
        assert_eq!(gw.permit_cap_refusal(&late, 0, Collateral, None), None);
        issue(&mut gw, &late, 0);
        assert_eq!(gw.admission_size().positions, 5);
        let later = fresh(&mut gw);
        assert_eq!(
            gw.permit_cap_refusal(&later, 0, Collateral, None),
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
        assert_eq!(gw.permit_cap_refusal(&funded, 0, Collateral, None), None);
        assert_eq!(
            gw.permit_cap_refusal(&funded, 1, Collateral, None),
            Some(PermitGateRefusal::AdmissionCap)
        );
    }

    /// Over HTTP, a fresh account's permit for a second market is a conflict.
    #[tokio::test]
    async fn a_fresh_account_s_second_market_permit_is_a_conflict() {
        let (app, key, writer) = permit_app().await;
        let router = build_router(app.clone(), true);
        let request = |market: u64| {
            let body = serde_json::json!({"from": hex0x(&PAYER), "amount": MIN_ENTRY_DEPOSIT.to_string(),
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
