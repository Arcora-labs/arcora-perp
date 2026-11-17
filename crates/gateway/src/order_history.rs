//! Per-order history kept beside the sealed snapshot instead of inside it (audit
//! GF-1 + SM-4).
//!
//! Two histories grow with every accepted order and can never be pruned: the
//! encrypted order log, and each settled batch's ordered/rejected hash lists (an
//! L1 inclusion challenge may name any order ever receipted, at any time, and is
//! answered from those lists). Inside the snapshot they made the payload grow
//! until it hit [`snapshot::MAX_PLAIN_BYTES`] and persistence stopped for good.
//!
//! With a state path, both are appended to [`side_log`]s beside the snapshot by
//! the snapshot writer (under its serialization guard, before the capture). The
//! snapshot then keeps only what was not appended yet, and a history extension
//! after the recovery extension records each side log's durable [`Position`].
//! A snapshot that relies on no side log omits the extension and is byte-for-byte
//! the earlier v10 layout, so every earlier snapshot loads (and migrates: its
//! history is appended at boot) and an earlier binary still reads a snapshot
//! that relies on nothing outside it. One that does rely on side logs carries
//! the extension, which an earlier binary refuses as trailing bytes.
//!
//! Boot reads both side logs from the start and checks each against the digest
//! the snapshot recorded at its durable end, so a missing, rolled-back or
//! foreign file is refused before anything is cut or appended. The order log's
//! entries are not kept: after that end, the entries the snapshot still holds
//! must match and later ones must continue the chain. The batch lists are all
//! loaded, since the challenge watcher answers from them.

use crate::order_log::{self, LogEntry};
use crate::side_log::{self, Kind, Position};
use crate::Gw;
use perp_core::hash::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One settled batch's (ordered, rejected) order hashes.
pub type BatchLists = (Vec<Digest>, Vec<Digest>);

/// Per ON-CHAIN batch id → its [`BatchLists`]. Every batch stays in memory for the
/// challenge watcher; the snapshot encodes only the batches not yet appended to
/// the batches side log, in the same positional layout as the plain map.
#[derive(Default)]
pub struct BatchOrders {
    all: BTreeMap<u64, BatchLists>,
    /// Every batch up to this id is in the side log, except those in `late`.
    appended_through: Option<u64>,
    late: BTreeSet<u64>,
}

impl std::ops::Deref for BatchOrders {
    type Target = BTreeMap<u64, BatchLists>;
    fn deref(&self) -> &Self::Target {
        &self.all
    }
}

impl BatchOrders {
    pub fn insert(&mut self, batch_id: u64, lists: BatchLists) {
        if self
            .appended_through
            .is_some_and(|through| batch_id <= through)
        {
            self.late.insert(batch_id);
        }
        self.all.insert(batch_id, lists);
    }

    /// The batches the side log does not hold yet.
    fn unappended(&self) -> impl Iterator<Item = (&u64, &BatchLists)> {
        self.all.iter().filter(|(id, _)| {
            self.appended_through.is_none_or(|through| **id > through) || self.late.contains(id)
        })
    }

    fn mark_appended(&mut self, ids: &[u64]) {
        let Some(&newest) = ids.iter().max() else {
            return;
        };
        let appended: BTreeSet<u64> = ids.iter().copied().collect();
        // A batch inserted while the append ran stays pending, wherever its id is.
        let from = self.appended_through.map_or(0, |t| t.saturating_add(1));
        if from <= newest {
            for id in self.all.range(from..=newest).map(|(id, _)| *id) {
                if !appended.contains(&id) {
                    self.late.insert(id);
                }
            }
        }
        for id in &appended {
            self.late.remove(id);
        }
        self.appended_through = Some(self.appended_through.map_or(newest, |t| t.max(newest)));
    }
}

impl serde::Serialize for BatchOrders {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let pending: Vec<_> = self.unappended().collect();
        let mut map = serializer.serialize_map(Some(pending.len()))?;
        for (id, lists) in pending {
            map.serialize_entry(id, lists)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for BatchOrders {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            all: BTreeMap::deserialize(deserializer)?,
            appended_through: None,
            late: BTreeSet::new(),
        })
    }
}

/// Runtime state of the side logs: never in the positional snapshot body.
#[derive(Default)]
pub struct HistoryState {
    /// The state path whose side logs the positions describe, once loaded at
    /// boot or first appended to.
    state: Option<PathBuf>,
    /// The durable end of each side log.
    order_log: Position,
    batches: Position,
}

/// The snapshot's history extension: where each side log's durable records end.
#[derive(serde::Serialize, serde::Deserialize)]
struct Extension {
    order_log: Position,
    /// The order-log chain head after `order_log.records` entries.
    order_log_head: Digest,
    batches: Position,
}

const EXT: &[u8; 8] = b"DPHIST1\0";

/// Append the history extension when the snapshot relies on a side log. Without
/// one the payload is exactly the earlier layout.
pub(super) fn append_snapshot(gw: &Gw, bytes: &mut Vec<u8>) {
    let history = &gw.history;
    if history.order_log.records == 0 && history.batches.records == 0 {
        return;
    }
    let extension = Extension {
        order_log: history.order_log,
        order_log_head: gw.order_log.base_head(),
        batches: history.batches,
    };
    bytes.extend_from_slice(EXT);
    bytes.extend_from_slice(&postcard::to_allocvec(&extension).expect("history snapshot encode"));
}

/// Restore the history extension (the rest of the payload after the recovery
/// extension): absent, every entry and batch is in the snapshot itself.
pub(super) fn restore_snapshot(gw: &mut Gw, trailer: &[u8]) -> Result<(), String> {
    if trailer.is_empty() {
        return gw.order_log.set_base(0, [0u8; 32]);
    }
    let payload = trailer
        .strip_prefix(EXT)
        .ok_or("unknown history snapshot extension")?;
    let (extension, rest): (Extension, _) =
        postcard::take_from_bytes(payload).map_err(|e| format!("history snapshot decode: {e}"))?;
    if !rest.is_empty() {
        return Err("trailing history snapshot bytes".into());
    }
    if extension.order_log.records == 0 && extension.batches.records == 0 {
        return Err("history snapshot extension records nothing".into());
    }
    gw.order_log
        .set_base(extension.order_log.records, extension.order_log_head)?;
    gw.history = HistoryState {
        state: None,
        order_log: extension.order_log,
        batches: extension.batches,
    };
    Ok(())
}

/// The records a snapshot writer appends before its capture.
pub(super) struct AppendJob {
    state: PathBuf,
    fresh: bool,
    order_log: Position,
    entries: Vec<Vec<u8>>,
    batches: Position,
    batch_ids: Vec<u64>,
    batch_records: Vec<Vec<u8>>,
}

/// What an [`AppendJob`] made durable. A failed side log keeps its position.
pub(super) struct Appended {
    state: PathBuf,
    order_log: Position,
    entries: usize,
    batches: Position,
    batch_ids: Vec<u64>,
    pub(super) error: Option<String>,
}

impl AppendJob {
    /// Append to both side logs. Needs no gateway lock; the caller holds the
    /// snapshot serialization guard, so no other append runs.
    pub(super) fn run(self, seed: &[u8; 32]) -> Appended {
        let mut done = Appended {
            state: self.state.clone(),
            order_log: self.order_log,
            entries: 0,
            batches: self.batches,
            batch_ids: Vec::new(),
            error: None,
        };
        // A state that never loaded its side logs must not cut into one an earlier
        // run left there.
        if self.fresh {
            for kind in [Kind::OrderLog, Kind::Batches] {
                if std::fs::metadata(kind.path(&self.state)).is_ok_and(|m| m.len() > 0) {
                    done.error = Some(format!(
                        "side log {} exists but this state never loaded it",
                        kind.path(&self.state).display()
                    ));
                    return done;
                }
            }
        }
        let path = Kind::OrderLog.path(&self.state);
        match side_log::append(&path, Kind::OrderLog, &self.order_log, &self.entries, seed) {
            Ok(end) => {
                done.order_log = end;
                done.entries = self.entries.len();
            }
            Err(e) => done.error = Some(format!("order log append: {e}")),
        }
        let path = Kind::Batches.path(&self.state);
        match side_log::append(
            &path,
            Kind::Batches,
            &self.batches,
            &self.batch_records,
            seed,
        ) {
            Ok(end) => {
                done.batches = end;
                done.batch_ids = self.batch_ids;
            }
            Err(e) => {
                done.error
                    .get_or_insert(format!("batch history append: {e}"));
            }
        }
        done
    }
}

impl Gw {
    /// Load the side logs beside `state` against what the restored snapshot
    /// recorded, or, for a fresh genesis (`fresh`), make sure there are none.
    /// Every check precedes mutation of the history; on `Err` boot must stop.
    pub(super) fn attach_history(
        &mut self,
        state: &Path,
        seed: &[u8; 32],
        fresh: bool,
    ) -> Result<(), String> {
        if fresh {
            for kind in [Kind::OrderLog, Kind::Batches] {
                if kind.path(state).try_exists().unwrap_or(true) {
                    return Err(format!(
                        "side log {} exists without a snapshot that relies on it; move it \
                         aside to start a fresh genesis",
                        kind.path(state).display()
                    ));
                }
            }
            self.history.state = Some(state.to_path_buf());
            return Ok(());
        }

        // The order log: read from the start, so the digest at the snapshot's
        // durable end proves the records it relies on are ours (a longer file of
        // another history is refused, never cut as a torn tail). Only the records
        // after that end are compared or adopted.
        let order_path = Kind::OrderLog.path(state);
        let order_from = self.history.order_log;
        let tail = self.order_log.tail();
        let mut head = self.order_log.base_head();
        let (mut matched, mut adopted) = (0usize, 0u64);
        let order_end = side_log::read(
            &order_path,
            Kind::OrderLog,
            &Position::default(),
            &order_from,
            seed,
            |index, record| {
                if index < order_from.records {
                    return Ok(());
                }
                let entry: LogEntry = postcard::from_bytes(record)
                    .map_err(|e| format!("order log record {index}: {e}"))?;
                let k = (index - order_from.records) as usize;
                if k < tail.len() {
                    if entry != tail[k] {
                        return Err(format!(
                            "order log record {index} differs from the snapshot's; the side \
                             log belongs to another history"
                        ));
                    }
                    matched += 1;
                } else {
                    if !order_log::links(&head, &entry) {
                        return Err(format!(
                            "order log record {index} does not continue the chain"
                        ));
                    }
                    adopted += 1;
                }
                head = entry.entry_hash;
                Ok(())
            },
        )?;

        // The batch lists: all of them, checked at the snapshot's durable end.
        let batch_path = Kind::Batches.path(state);
        let batch_expect = self.history.batches;
        let mut stored: BTreeMap<u64, BatchLists> = BTreeMap::new();
        let batch_end = side_log::read(
            &batch_path,
            Kind::Batches,
            &Position::default(),
            &batch_expect,
            seed,
            |index, record| {
                let (id, ordered, rejected): (u64, Vec<Digest>, Vec<Digest>) =
                    postcard::from_bytes(record)
                        .map_err(|e| format!("batch history record {index}: {e}"))?;
                stored.insert(id, (ordered, rejected));
                Ok(())
            },
        )?;
        for (id, lists) in self.batch_orders.unappended() {
            if stored.get(id).is_some_and(|s| s != lists) {
                return Err(format!(
                    "settled batch {id} differs between the snapshot and its side log"
                ));
            }
        }

        // Every check passed: cut torn tails, then install.
        for (path, end) in [(&order_path, &order_end), (&batch_path, &batch_end)] {
            if end.torn {
                eprintln!(
                    "[state] cutting an incomplete append off {} at byte {}",
                    path.display(),
                    end.end.bytes
                );
                side_log::truncate(path, &end.end)
                    .map_err(|e| format!("side log {} cannot be repaired: {e}", path.display()))?;
            }
        }
        if adopted > 0 {
            self.order_log.adopt(order_end.end.records, head);
        } else {
            self.order_log.mark_appended(matched);
        }
        let newest = stored.keys().next_back().copied();
        let inline = std::mem::take(&mut self.batch_orders.all);
        let mut all = stored;
        let mut late = BTreeSet::new();
        for (id, lists) in inline {
            if newest.is_some_and(|n| id <= n) && !all.contains_key(&id) {
                late.insert(id);
            }
            all.insert(id, lists);
        }
        self.batch_orders = BatchOrders {
            all,
            appended_through: newest,
            late,
        };
        self.history = HistoryState {
            state: Some(state.to_path_buf()),
            order_log: order_end.end,
            batches: batch_end.end,
        };
        Ok(())
    }

    /// The side-log appends the next snapshot of `state` should make first.
    pub(super) fn history_append_job(&self, state: &Path) -> Result<Option<AppendJob>, String> {
        match &self.history.state {
            Some(attached) if attached != state => {
                return Err("the side logs belong to another state path".into())
            }
            None if self.history.order_log.records > 0 || self.history.batches.records > 0 => {
                return Err("the restored side logs were never loaded".into())
            }
            _ => {}
        }
        let entries: Vec<Vec<u8>> = self
            .order_log
            .tail()
            .iter()
            .map(|e| postcard::to_allocvec(e).expect("order log record encode"))
            .collect();
        let (batch_ids, batch_records): (Vec<u64>, Vec<Vec<u8>>) = self
            .batch_orders
            .unappended()
            .map(|(id, (ordered, rejected))| {
                (
                    *id,
                    postcard::to_allocvec(&(*id, ordered, rejected)).expect("batch record encode"),
                )
            })
            .unzip();
        if entries.is_empty() && batch_ids.is_empty() {
            return Ok(None);
        }
        Ok(Some(AppendJob {
            state: state.to_path_buf(),
            fresh: self.history.state.is_none(),
            order_log: self.history.order_log,
            entries,
            batches: self.history.batches,
            batch_ids,
            batch_records,
        }))
    }

    /// Record what an append made durable; the next capture leaves it out.
    pub(super) fn history_appended(&mut self, done: &Appended) {
        if done.entries == 0 && done.batch_ids.is_empty() {
            return;
        }
        self.order_log.mark_appended(done.entries);
        self.batch_orders.mark_appended(&done.batch_ids);
        self.history = HistoryState {
            state: Some(done.state.clone()),
            order_log: done.order_log,
            batches: done.batches,
        };
    }
}
