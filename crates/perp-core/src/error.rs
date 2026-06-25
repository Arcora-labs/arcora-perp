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
