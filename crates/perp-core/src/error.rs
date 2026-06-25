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
    /// Counterparties of a fill must take opposite sides at one price.
    MismatchedFill,
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
