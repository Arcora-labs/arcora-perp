//! Engine error taxonomy. Every variant is a *deterministic* rejection the prover
//! can reproduce — there is no nondeterministic failure in the state transition.

use crate::position::RiskError;

/// Which leg of a two-sided fill a rejection is attributable to (SEC-022 §6). Settlement
/// used to record the SAME reason against BOTH order hashes, so an innocent counterparty
/// was rejected alongside the offender. `Copy`, so `EngineError` stays `Copy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillLeg {
    Taker,
    Maker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// Referenced note is unknown or already spent (double-spend).
    UnknownOrSpentNote,
    /// Provided spend key does not own the note.
    BadSpendKey,
    /// Referenced market does not exist.
    UnknownMarket,
    /// Referenced position does not exist.
    UnknownPosition,
    /// Oracle transcript failed sanity checks (§8).
    Oracle(crate::oracle::OracleError),
    /// Risk / margin failure (§5, §12). `leg` is `Some` only when the failure arose
    /// inside a two-sided fill, where the engine knows which staged leg violated;
    /// `op_unbind` and the generic `From<RiskError>` have no leg to name.
    Risk {
        source: RiskError,
        leg: Option<FillLeg>,
    },
    /// Position is not liquidatable but a liquidation was attempted.
    NotLiquidatable,
    /// Withdrawals / opens blocked because the market is in close-only mode (§6).
    CloseOnly,
    /// Amount is non-positive where a positive amount is required.
    NonPositiveAmount,
    /// SEC-019: a deposit's `deposit_id` does not equal the number of L1 deposit
    /// leaves already consumed (`consumed_deposit_count`). Deposits MUST be applied
    /// in strict L1 order with no gaps — this rejects a replayed, skipped, or
    /// reordered deposit before any state is touched, so the in-circuit hash-chain
    /// fold stays bound to the real, ordered L1 `Deposited` event stream.
    DepositOutOfOrder,
    /// A note with this commitment already exists. Commitments must be unique
    /// (the blinding factor is a unique nonce); minting a duplicate would alias
    /// two notes in the unspent set and silently lose value. Rejected.
    DuplicateCommitment,
    /// Counterparties of a fill must take opposite sides at one price.
    MismatchedFill,
    /// A fill's taker and maker are the same account (self-trade). The matcher
    /// prevents this upstream; the engine rejects it defensively because a
    /// single-account two-leg fill would corrupt the position and conservation.
    SelfTrade,
    /// Arithmetic overflow — hard reject, never wrap.
    Overflow,
    /// The conservation invariant would be violated (should be impossible;
    /// surfaced defensively).
    ConservationViolated,
    /// The batch manifest's `previous_state_root` or `batch_id` does not match the
    /// pre-state — the manifest is not the one that produced this transition. Only
    /// reachable via `commitment::derive_roots` (root derivation), not the hot-path
    /// settlement ops.
    ManifestMismatch,
    /// ZK-001 (Task 4): an `AccrueFunding.mark` (the sequencer's raw book-mid witness)
    /// lies outside `max_mark_deviation_ratio` of the SIGNED oracle index. The mark is
    /// otherwise unconstrained, so it is bound to a symmetric band around the validated
    /// index before it can steer the funding rate; a mark out of band — or an overflow in
    /// the checked band arithmetic — is rejected fail-closed (never wrapped or panicked).
    MarkOutOfBand,
    /// SEC-022: a fill's execution price lies outside `max_fill_deviation_ratio` of the
    /// ATTESTED oracle mark. `op_fill` previously validated only `size > 0 && price > 0`
    /// and never compared `price` to `mark`, so two accounts could cross at any price and
    /// move value between them — the losing leg closing with negative collateral that no
    /// liquidation path revisits. An out-of-band price, or an overflow in the checked band
    /// arithmetic, is rejected fail-closed (never wrapped, never panicked in-guest).
    FillPriceOutOfBand,
    /// SEC-022: the fill would have left the identified leg either CLOSED with negative
    /// collateral — debt no liquidation path revisits, since `op_liquidate` and the
    /// maintenance pass both require `is_open()` — or still open and below maintenance
    /// margin. Two parties electing to trade always have "not trading" available, and it
    /// is strictly better for the protocol than parking unresolvable debt.
    FillWouldBankrupt(FillLeg),
    /// SEC-024: a retained-but-deprecated op was submitted. Always rejected.
    DeprecatedOp,
    /// SEC-024: the op requires the canonical quote asset (`asset_id == 0`).
    WrongAsset,
    /// A wind-down-only operation was mixed with ordinary operations, or the
    /// phase-specific batch grammar was otherwise violated.
    WindDownGrammar,
    /// The terminal socialization set cannot absorb the remaining deficit.
    WindDownInsolvent,
    /// 2026-10-08 review: a `Market` stored in the canonical state's `markets` map
    /// under a key different from its own `id`. Every state root hashes the map KEY,
    /// never `Market.id`, so a witness carrying `Market { id: X }` under key `Y ≠ X`
    /// produced the identical digest and the circuit was blind to the mismatch.
    /// Rejected fail-closed at root-derivation time.
    MarketIdMismatch,
    /// The manifest timestamp differs from the maximum original operation time.
    /// This consistency check does not authenticate external/L1 time.
    ClockMismatch,
}

impl From<RiskError> for EngineError {
    fn from(e: RiskError) -> Self {
        match e {
            RiskError::Overflow => EngineError::Overflow,
            other => EngineError::Risk {
                source: other,
                leg: None,
            },
        }
    }
}

impl From<crate::oracle::OracleError> for EngineError {
    fn from(e: crate::oracle::OracleError) -> Self {
        EngineError::Oracle(e)
    }
}
