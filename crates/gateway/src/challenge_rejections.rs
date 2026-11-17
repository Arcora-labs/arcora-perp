//! Open inclusion challenges for orders the gateway does not know (audit GF-2,
//! second line).
//!
//! An order receipt's `l1Challenge` lets its holder open an inclusion challenge
//! on L1, which only a settled batch holding the order can answer. Receipts wait
//! for a durable snapshot, but should an order still be lost (a state restored
//! from an older backup, say), no batch would ever hold it and the bond would be
//! slashed. So when the watcher reads an open challenge for a hash that no
//! retained settled batch holds and the gateway has no record of, the gateway
//! declares the hash rejected (`Cancelled`, as a voided window's orders are) in
//! the open window. The next settled batch's rejected root holds it and the
//! watcher answers the challenge with it (`answerByRejection`).
//!
//! A hash is declared only while the gateway holds the lists of every batch the
//! settlement had settled at the read's block, so "in no batch" is checked
//! against all of them; while the chain is ahead (a settle the gateway has not
//! committed yet), the hash waits. The watcher declares only under a clock
//! admission permit, like every other change to the open window.
//!
//! Each declaration is recorded with the window it was made in, so a later round
//! declares nothing again while that window is open or settling; a void or a
//! rollback of that window publishes its rejections again itself. Only if a
//! batch at or after that window settles without the hash is it declared again.
//! A record goes once its challenge leaves the open set: the settlement then
//! refuses another challenge for that hash for good.
//!
//! The records are kept in a snapshot extension after the history extension, so
//! a restart neither repeats nor forgets a declaration. A snapshot without
//! records omits it and is the earlier layout byte for byte; one with records
//! carries it, which an earlier binary refuses as trailing bytes.

use crate::challenge_scan::Watcher;
use crate::Gw;
use perp_core::hash::Digest;
use perp_core::order::RejectReason;
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Order hash → the window (on-chain batch id) its rejection was declared in.
pub type Declarations = BTreeMap<Digest, u64>;

const EXT: &[u8; 8] = b"DPCHRJ1\0";

impl Gw {
    /// Declare rejected, in the open window, each hash of `unlocated` (open hashes
    /// of `watcher`'s latest read that no retained settled batch holds) that the
    /// gateway does not know, unless an earlier declaration of it is still on its
    /// way to a settled batch. Declares nothing while the settlement had settled a
    /// batch at the read's block that this gateway holds no lists for. Returns the
    /// hashes declared now.
    pub(super) fn reject_unknown_challenges(
        &mut self,
        watcher: &Watcher,
        unlocated: &[Digest],
    ) -> Vec<Digest> {
        let open: BTreeSet<Digest> = watcher.open().iter().copied().collect();
        self.challenge_rejections
            .retain(|hash, _| open.contains(hash));
        let settled = self
            .batch_orders
            .keys()
            .next_back()
            .map_or(0, |newest| newest.saturating_add(1));
        if watcher.batch_count() > settled {
            return Vec::new();
        }
        let mut candidates: Vec<Digest> = Vec::new();
        for hash in unlocated {
            if !open.contains(hash) || candidates.contains(hash) {
                continue;
            }
            let pending = self
                .challenge_rejections
                .get(hash)
                .is_some_and(|window| self.batch_orders.range(window..).next().is_none());
            if pending || self.holds_order_record(hash) {
                continue;
            }
            candidates.push(*hash);
        }
        if candidates.is_empty() {
            return candidates;
        }
        // The order rows last: the scan is over every row the gateway keeps.
        let rows: HashSet<Digest> = self
            .orders
            .iter()
            .chain(self.accounts.values().flat_map(|a| &a.orders))
            .map(|o| o.order_hash)
            .collect();
        candidates.retain(|hash| !rows.contains(hash));
        if candidates.is_empty() {
            return candidates;
        }
        let window = self.seq.current_window_id();
        self.seq
            .reject_in_window(&candidates, RejectReason::Cancelled);
        for hash in &candidates {
            self.challenge_rejections.insert(*hash, window);
        }
        candidates
    }

    /// Whether the sequencer or the open window holds a record of the order
    /// `hash` outside the settled batches: its receipt or finality record (kept
    /// until a settle hardens it into a batch, and while it rests on a book), the
    /// open window's rejections, or the legacy accumulators. The order rows are
    /// checked by the caller.
    fn holds_order_record(&self, hash: &Digest) -> bool {
        self.seq.finality_of(hash).is_some()
            || self.seq.window_rejected().iter().any(|(h, _)| h == hash)
            || self.pending_ordered.contains(hash)
            || self.pending_rejected.contains(hash)
    }
}

/// Append the extension when a declaration is recorded; otherwise the payload is
/// the earlier layout.
pub(super) fn append_snapshot(gw: &Gw, bytes: &mut Vec<u8>) {
    if gw.challenge_rejections.is_empty() {
        return;
    }
    bytes.extend_from_slice(EXT);
    bytes.extend_from_slice(
        &postcard::to_allocvec(&gw.challenge_rejections).expect("challenge snapshot encode"),
    );
}

/// Restore the extension: the rest of the payload after the history extension.
pub(super) fn restore_snapshot(gw: &mut Gw, trailer: &[u8]) -> Result<(), String> {
    if trailer.is_empty() {
        return Ok(());
    }
    let payload = trailer
        .strip_prefix(EXT)
        .ok_or("unknown snapshot extension")?;
    let (declarations, rest): (Declarations, _) = postcard::take_from_bytes(payload)
        .map_err(|e| format!("challenge snapshot decode: {e}"))?;
    if !rest.is_empty() {
        return Err("trailing challenge snapshot bytes".into());
    }
    if declarations.is_empty() {
        return Err("challenge snapshot extension records nothing".into());
    }
    gw.challenge_rejections = declarations;
    Ok(())
}
