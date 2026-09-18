//! Owner-scoped cancellation, serialized with matching by the gateway state lock.
//!
//! Proof-v1 replays accounting operations, not the matcher. Cancelling an unfilled
//! remainder changes no accounting state; it contributes a Cancelled rejection to
//! the open window manifest. Already-applied fills remain in that window's op log.
//! The committed rejection attests a reported outcome, not matching fairness or an
//! independently verified user cancellation signature. Those are Proof-v2 concerns.

use super::*;

impl Sequencer {
    /// Quantity the caller can cancel now. `submitted` is the gateway's stored
    /// submission marker, never request JSON. Finality is not an execution status:
    /// a maker can have settled fills and still have a live remainder.
    pub fn cancellable_size(&self, owner: &PubKey, order: &Order, submitted: bool) -> Option<i128> {
        if &order.owner != owner || order.size <= 0 {
            return None;
        }
        let hash = order.order_hash::<Keccak256>();
        if let Some(size) = self
            .matcher
            .book(order.market_id)
            .and_then(|book| book.remaining_for(owner, &hash))
        {
            return (size > 0).then_some(size);
        }
        // A not-yet-submitted accepted order lives in the gateway's ingress list,
        // not the book. Do not treat an IOC that already ran without filling, or a
        // rejected/fully-filled order, as pending merely because it has no depth.
        if !submitted
            && self.finality_of(&hash) == Some(Finality::Accepted)
            && self
                .inclusion
                .get(&hash)
                .is_some_and(|record| record.seen_in_batch.is_none())
        {
            Some(order.size)
        } else {
            None
        }
    }

    /// Cancel only the unfilled remainder. The gateway holds its exclusive state
    /// lock for this entire call AND for each complete matching tick/seal. Therefore
    /// cancel-before-fill and fill-before-cancel are the only possible orderings.
    /// No fill can be interleaved between the eligibility check and the removal.
    ///
    /// The gateway must remove the cancelled entry from its pending submission
    /// list before releasing the same lock. A production HTTP success additionally
    /// requires a durable snapshot acknowledgement (the library performs no I/O).
    pub fn cancel_order(&mut self, owner: &PubKey, order: &Order, submitted: bool) -> Option<i128> {
        let size = self.cancellable_size(owner, order, submitted)?;
        let hash = order.order_hash::<Keccak256>();
        let _ = self.matcher.cancel_order(&hash);
        // A legacy tick rollback must not resurrect a quote the owner withdrew.
        // Account balances/fills can roll back, but the cancellation intent survives.
        // Production window rollback does not restore a matcher at all: it prepends
        // the failed witness's ops/manifest to the current accumulators.
        for (_, matcher) in self.snapshots.values_mut() {
            let _ = matcher.cancel_order(&hash);
        }
        // Existing manifest encoding and RejectReason ordinal are preserved. An
        // order may be ordered earlier and cancelled later in the SAME window;
        // cancellation describes its remainder, never a reversal of prior fills.
        self.window_rejected.push((hash, RejectReason::Cancelled));
        // No off-chain withholding alarm for an order resolved by cancellation.
        // The original gateway receipt remains valid against the settled manifest.
        self.inclusion.remove(&hash);
        Some(size)
    }
}

#[cfg(test)]
mod tests;
