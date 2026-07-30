//! SEC-025-A: the operator insurance bootstrap state machine.
//!
//! Four states, not three. Keying completion on the window carrying the bootstrap
//! DEPOSIT is wrong in two orderings: (a) if `Deposit` lands and `FundInsurance` fails,
//! the deposit alone moves the state root, so that window settles and completion would
//! be recorded although no `FundInsurance` ever settled; (b) the first leg's window can
//! seal before the endpoint applies the second leg, because proving runs without the
//! gateway lock. So the window that matters is the SECOND leg's.

/// The minimum operator capitalization, in quote base units (USDC, 6dp) — 10,000 USDC.
///
/// A deployment risk policy with no source-derivable value, so it is a compile-time
/// constant rather than an env var: an env change must not be able to alter a
/// roll-forward decision made by a different process invocation.
///
/// SEC-025-D gates launch on `insurance_fund >= MIN_BOOTSTRAP_INSURANCE` and reads THIS
/// constant. The bootstrap endpoint is one-shot, so accepting a below-floor amount here
/// would spend the one-shot, leave 025-D permanently closed, and give neither piece a
/// retry path — an unlaunchable deployment. Hence the check, and hence one constant.
pub const MIN_BOOTSTRAP_INSURANCE: i128 = 10_000 * 1_000_000;

/// Where the operator insurance bootstrap has got to. Persisted inside `Gw`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Bootstrap {
    NotStarted,
    /// The L1 deposit was credited but the insurance transfer has not applied. Carries
    /// exactly what the second leg needs, because a pair-RETRY cannot work: the first
    /// `Deposit` already advanced `consumed_deposit_count`, so a retry fails
    /// `DepositOutOfOrder` before ever reaching `FundInsurance`.
    DepositApplied {
        note_commitment: [u8; 32],
        spend_key: [u8; 32],
        deposit_id: u64,
    },
    /// `FundInsurance` applied into this window. Completion waits for THIS id to commit.
    InsuranceApplied {
        window_id: u64,
    },
    Complete,
}

/// Whether an operator bootstrap amount is large enough to be worth the one-shot.
///
/// `expect(dead_code)`: Task 2 lands the record and the floor only; the first
/// production caller is the bootstrap endpoint in a later task (tests exercise it
/// today, hence `not(test)`) — the `snapshot_now` pattern. The moment a production
/// caller lands, the expectation goes unfulfilled and must be deleted — enforced by
/// CI, which runs clippy with `-D warnings`. Marking the fn alone suffices: rustc
/// treats an expected-dead item as a live root, so `MIN_BOOTSTRAP_INSURANCE` (read
/// here) counts as used and must NOT carry a marker of its own.
#[cfg_attr(not(test), expect(dead_code))]
pub fn amount_meets_floor(amount: i128) -> bool {
    amount >= MIN_BOOTSTRAP_INSURANCE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_floor_rejects_a_dust_bootstrap_and_accepts_exactly_the_floor() {
        // The whole reason the floor exists: `insurance_fund > 0` passes on one base unit.
        assert!(!amount_meets_floor(1));
        assert!(!amount_meets_floor(MIN_BOOTSTRAP_INSURANCE - 1));
        assert!(amount_meets_floor(MIN_BOOTSTRAP_INSURANCE));
        assert!(amount_meets_floor(MIN_BOOTSTRAP_INSURANCE + 1));
        // A non-positive amount can never satisfy the floor.
        assert!(!amount_meets_floor(0));
        assert!(!amount_meets_floor(-MIN_BOOTSTRAP_INSURANCE));
    }

    #[test]
    fn the_record_round_trips_through_postcard_in_every_state() {
        for st in [
            Bootstrap::NotStarted,
            Bootstrap::DepositApplied {
                note_commitment: [7u8; 32],
                spend_key: [9u8; 32],
                deposit_id: 3,
            },
            Bootstrap::InsuranceApplied { window_id: 11 },
            Bootstrap::Complete,
        ] {
            let bytes = postcard::to_allocvec(&st).expect("encode");
            let back: Bootstrap = postcard::from_bytes(&bytes).expect("decode");
            assert_eq!(st, back);
        }
    }
}
