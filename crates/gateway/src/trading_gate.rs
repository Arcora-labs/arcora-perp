//! SEC-025-D: the launch gate. A **launch** gate, not a circuit breaker — it opens once
//! and never re-closes. Both `insurance_fund` and `Mode` are non-monotonic, so the
//! predicate can become false later; re-closing a blunt ingress gate would then block
//! reduce-only EXITS, trapping users exactly when they most need to leave. The answer to
//! a depleted fund is a separate exposure-increase breaker plus a recapitalization path;
//! neither exists yet, and both are recorded follow-ups.

use crate::bootstrap::MIN_BOOTSTRAP_INSURANCE;

/// How deep the pinned block must be before an observation may OPEN the gate. A reorg
/// that unwound the capitalization settle after opening would leave trading enabled
/// against a fund that no longer exists on L1. `cast` defaults to one confirmation;
/// inheriting that default silently is a policy choice made by accident.
// Consumed by `observe_gate_once` (main.rs), which rewinds its observation block
// this deep behind head before the three pinned reads.
pub const GATE_OPEN_CONFIRMATIONS: u64 = 12;

/// The minimum credited deposits a launch-ready deployment must show. The operator's own
/// bootstrap deposit is one, so this is deliberately small — it exists to reject a
/// deployment that has never credited anything, not to demand traffic.
// Passed as `predicate_met`'s `min_deposits` by `commit_window_settle`'s opening
// check (main.rs).
pub const MIN_BOOTSTRAP_DEPOSITS: u64 = 1;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TradingGate {
    Closed,
    Open,
}

/// What one block-pinned L1 observation says about opening.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GateObservation {
    /// Our `settleBatch` demonstrably landed and the chain is not in close-only.
    OpensGate,
    /// A different transition landed, or the chain IS in close-only — commit closed.
    StaysClosed,
    /// The read failed or lagged. **Must not resolve the gate**; retry or hold.
    Inconclusive,
}

/// Classify one block-pinned observation.
///
/// `finalSettle` advances `currentStateRoot` and `batchCount` identically to
/// `settleBatch`, so neither alone excludes a wind-down. But `finalSettle` REQUIRES
/// `closeOnly == true`, and `closeOnly` is terminal on-chain — never cleared anywhere in
/// `contracts/`. So the three read together at ONE block exclude it.
///
/// The asymmetry is deliberate and load-bearing: only a SUCCESSFULLY OBSERVED mismatch
/// may commit the gate closed. The opening check runs once per commit and a commit is not
/// repeatable, so resolving an errored or lagging read against opening would burn the only
/// opportunity — and 025-A's bootstrap endpoint is one-shot and cannot manufacture another.
// Production caller: `observe_gate_once` (main.rs), fed by the three pinned readers.
pub fn classify(
    chain_batch_count: u64,
    sealed_batch_id: u64,
    chain_root: [u8; 32],
    our_new_root: [u8; 32],
    close_only: bool,
) -> GateObservation {
    let Some(expected) = sealed_batch_id.checked_add(1) else {
        return GateObservation::Inconclusive;
    };
    if chain_batch_count < expected {
        // Lagging: the read landed on a block before our settle. Says nothing.
        return GateObservation::Inconclusive;
    }
    if chain_batch_count > expected || chain_root != our_new_root {
        return GateObservation::StaysClosed;
    }
    if close_only {
        return GateObservation::StaysClosed;
    }
    GateObservation::OpensGate
}

/// The capitalization half of the opening condition, judged on the PROVEN post-state.
// Production caller: `commit_window_settle`'s opening check (main.rs), over the
// `ProveOutcome` post-state terms — never the live `seq.state`, which has advanced
// past the proven window by the time a proof returns.
pub fn predicate_met(
    mode_is_normal: bool,
    insurance_fund: i128,
    deposit_count: u64,
    min_deposits: u64,
) -> bool {
    mode_is_normal && insurance_fund >= MIN_BOOTSTRAP_INSURANCE && deposit_count >= min_deposits
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1: [u8; 32] = [1u8; 32];
    const R2: [u8; 32] = [2u8; 32];

    #[test]
    fn a_close_only_chain_never_opens_the_gate_even_on_a_perfect_match() {
        // The finalSettle defence. Count and root match exactly — the two values a
        // wind-down advances identically — and only `closeOnly` distinguishes it.
        assert_eq!(classify(8, 7, R1, R1, true), GateObservation::StaysClosed);
        assert_eq!(classify(8, 7, R1, R1, false), GateObservation::OpensGate);
    }

    #[test]
    fn a_lagging_read_is_inconclusive_and_a_diverged_one_is_not() {
        // Lagging must NOT resolve against opening: the commit is not repeatable, so a
        // stale block would burn the only opening opportunity.
        assert_eq!(classify(7, 7, R1, R1, false), GateObservation::Inconclusive);
        assert_eq!(classify(0, 7, R1, R1, false), GateObservation::Inconclusive);
        // A genuinely different transition is an OBSERVED mismatch, so it may close.
        assert_eq!(classify(9, 7, R1, R1, false), GateObservation::StaysClosed);
        assert_eq!(classify(8, 7, R2, R1, false), GateObservation::StaysClosed);
        // An impossible id cannot be reasoned about.
        assert_eq!(
            classify(0, u64::MAX, R1, R1, false),
            GateObservation::Inconclusive
        );
    }

    #[test]
    fn the_predicate_needs_every_term_and_a_dust_fund_does_not_pass() {
        assert!(predicate_met(true, MIN_BOOTSTRAP_INSURANCE, 1, 1));
        // `insurance_fund > 0` is NOT capitalization — one base unit must fail.
        assert!(!predicate_met(true, 1, 1, 1));
        assert!(!predicate_met(true, MIN_BOOTSTRAP_INSURANCE - 1, 1, 1));
        assert!(!predicate_met(false, MIN_BOOTSTRAP_INSURANCE, 1, 1));
        assert!(!predicate_met(true, MIN_BOOTSTRAP_INSURANCE, 0, 1));
    }
}
