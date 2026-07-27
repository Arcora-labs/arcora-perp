//! Engine error taxonomy. Every variant is a *deterministic* rejection the prover
//! can reproduce — there is no nondeterministic failure in the state transition.

use crate::position::RiskError;

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
    /// Risk / margin failure (§5, §12).
    Risk(RiskError),
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
}

impl From<RiskError> for EngineError {
    fn from(e: RiskError) -> Self {
        match e {
            RiskError::Overflow => EngineError::Overflow,
            other => EngineError::Risk(other),
        }
    }
}

impl From<crate::oracle::OracleError> for EngineError {
    fn from(e: crate::oracle::OracleError) -> Self {
        EngineError::Oracle(e)
    }
}
