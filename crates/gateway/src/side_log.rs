//! Sealed, append-only side logs next to the state snapshot (audit GF-1 + SM-4).
//!
//! The order log and the settled batches' order-hash lists grow with every
//! accepted order and are never pruned: an L1 inclusion challenge can name any
//! order ever receipted, at any time. Kept inside the sealed snapshot they made
//! the payload grow until it hit the 64 MiB ceiling and persistence stopped. They
//! now live in these files; the snapshot keeps only the records not yet appended
//! and the [`Position`] of the durable end of each file.
//!
//! ## File format
//!
//! A file is a sequence of frames, `len (u32 LE) ‖ sealed`, where `sealed` is
//! [`snapshot::seal`] of `magic (8) ‖ first index (u64 LE) ‖ postcard(records)`:
//! encrypted and authenticated under the enclave seed exactly like the snapshot,
//! so a file of one kind (or a snapshot, or a journal) is never read as another.
//! Each record also folds into a running SHA-256 digest; a snapshot records the
//! digest at the durable end, so a replaced or rolled-back file is refused.
//!
//! ## Durability
//!
//! [`append`] first cuts the file back to the last acknowledged [`Position`]
//! (dropping whatever an earlier failed append left), writes the frames, then
//! `fsync`s the file, and the parent directory on the first acknowledged append
//! — the same discipline as [`snapshot::write_atomic`]. Only an `Ok` advances the
//! position a later snapshot may reference. A crash during an append leaves a
//! torn frame after the last acknowledged position, which [`read`] reports so the
//! caller can cut it off.

use crate::snapshot;
use perp_core::hash::Digest;
use sha2::{Digest as _, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Records per frame are capped so one frame always fits the sealed envelope's
/// size bound, even for the one-time migration of a legacy snapshot.
const MAX_FRAME_PLAIN_BYTES: usize = 8 * 1024 * 1024;

/// What a side log holds. Its magic sits inside every authenticated frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `order_log::LogEntry` records, one per accepted order.
    OrderLog,
    /// `(batch id, ordered hashes, rejected hashes)`, one per settled batch.
    Batches,
}

impl Kind {
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Kind::OrderLog => b"DPOLOG1\0",
            Kind::Batches => b"DPBORD1\0",
        }
    }
    fn suffix(self) -> &'static str {
        match self {
            Kind::OrderLog => ".orderlog",
            Kind::Batches => ".batches",
        }
    }
    /// The side log beside `state`: the full state file name plus a suffix
    /// (appended, like the rollback journal's, never an extension replacement).
    pub fn path(self, state: &Path) -> PathBuf {
        let mut os = state.as_os_str().to_os_string();
        os.push(self.suffix());
        PathBuf::from(os)
    }
}

/// The durable end of a side log: how many records precede it, its byte offset
/// and the running digest over those records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Position {
    pub records: u64,
    pub bytes: u64,
    pub digest: Digest,
}

fn fold(kind: Kind, digest: &Digest, index: u64, record: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(b"arcora.gateway.side-log.v1");
    h.update(kind.magic());
    h.update(digest);
    h.update(index.to_le_bytes());
    h.update((record.len() as u64).to_le_bytes());
    h.update(record);
    h.finalize().into()
}

/// Append `records` after `at`, the last acknowledged end of the file. Returns the
/// new end once the data (and, for a new file, its directory entry) is synced.
pub fn append(
    path: &Path,
    kind: Kind,
    at: &Position,
    records: &[Vec<u8>],
    seed: &[u8; 32],
) -> std::io::Result<Position> {
    if records.is_empty() {
        return Ok(*at);
    }
    let mut end = *at;
    let mut frames = Vec::new();
    let mut start = 0;
    while start < records.len() {
        let mut stop = start;
        let mut size = 0usize;
        while stop < records.len()
            && (stop == start || size + records[stop].len() + 8 <= MAX_FRAME_PLAIN_BYTES)
        {
            size += records[stop].len() + 8;
            stop += 1;
        }
        let mut plain = kind.magic().to_vec();
        plain.extend_from_slice(&end.records.to_le_bytes());
        plain.extend(postcard::to_allocvec(&records[start..stop]).map_err(std::io::Error::other)?);
        let sealed = snapshot::seal(&plain, seed);
        if sealed.len() > snapshot::MAX_SEALED_BYTES {
            // `read` (and `snapshot::open`) would refuse it: never write it.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a side-log record exceeds the sealed frame limit",
            ));
        }
        let len = u32::try_from(sealed.len()).map_err(std::io::Error::other)?;
        frames.extend_from_slice(&len.to_le_bytes());
        frames.extend_from_slice(&sealed);
        for record in &records[start..stop] {
            end.digest = fold(kind, &end.digest, end.records, record);
            end.records += 1;
        }
        start = stop;
    }
    end.bytes = at.bytes + frames.len() as u64;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // The first acknowledged append also makes the directory entry durable, even
    // when an earlier, failed attempt already created the (empty) file.
    let first = at.bytes == 0 || !path.try_exists()?;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    if file.metadata()?.len() < at.bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "side log is shorter than its acknowledged end; preserve it for reconciliation",
        ));
    }
    let result = (|| {
        file.set_len(at.bytes)?;
        file.seek(SeekFrom::Start(at.bytes))?;
        file.write_all(&frames)?;
        file.sync_all()?;
        if first {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(end)
    })();
    if result.is_err() {
        // Best effort: the next append cuts back to `at` anyway.
        let _ = file.set_len(at.bytes);
    }
    result
}

/// What [`read`] found after the records it delivered.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadEnd {
    /// The end of the last complete, authentic frame.
    pub end: Position,
    /// Bytes after `end` that do not form such a frame: a torn or failed append.
    pub torn: bool,
}

/// Deliver every record from `from` (a frame boundary) to the end of the file, in
/// order, with its index. `expect` (at or after `from`) is the durable end a
/// snapshot recorded: the file must reach it at a frame boundary with the same
/// digest, or it is refused (the records the snapshot relies on are gone or
/// differ) before the frame that reaches it delivers any record. A missing file
/// reads as empty when `expect` is its start. Reading
/// stops at the first frame that is incomplete, does not authenticate, or does
/// not continue the index; everything from there on is reported as `torn`.
pub fn read(
    path: &Path,
    kind: Kind,
    from: &Position,
    expect: &Position,
    seed: &[u8; 32],
    mut each: impl FnMut(u64, &[u8]) -> Result<(), String>,
) -> Result<ReadEnd, String> {
    let missing = || {
        format!(
            "side log {} does not hold the {} records the snapshot relies on; \
             preserve the state files for offline reconciliation",
            path.display(),
            expect.records
        )
    };
    let reached = |end: &Position| end.records >= expect.records;
    if from.records > expect.records || (from.records == expect.records && from != expect) {
        return Err(missing());
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && expect.bytes == 0 => {
            return Ok(ReadEnd {
                end: *from,
                torn: false,
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(missing()),
        Err(e) => return Err(format!("side log {} cannot be read: {e}", path.display())),
    };
    let size = file
        .metadata()
        .map_err(|e| format!("side log {}: {e}", path.display()))?
        .len();
    if size < expect.bytes {
        return Err(missing());
    }
    let mut reader = std::io::BufReader::new(file);
    reader
        .seek(SeekFrom::Start(from.bytes))
        .map_err(|e| format!("side log {}: {e}", path.display()))?;
    let mut end = *from;
    let stop = |end: Position, torn: bool| {
        if reached(&end) {
            Ok(ReadEnd { end, torn })
        } else {
            Err(missing())
        }
    };
    loop {
        let mut len = [0u8; 4];
        match read_exact_or_eof(&mut reader, &mut len) {
            Ok(false) => return stop(end, false),
            Ok(true) => {}
            Err(_) => return stop(end, true),
        }
        let len = u32::from_le_bytes(len) as u64;
        if len > snapshot::MAX_SEALED_BYTES as u64 || end.bytes + 4 + len > size {
            return stop(end, true);
        }
        let mut sealed = vec![0u8; len as usize];
        if reader.read_exact(&mut sealed).is_err() {
            return stop(end, true);
        }
        let Some(records) = open_frame(kind, &end, &sealed, seed) else {
            return stop(end, true);
        };
        let mut next = end;
        for record in &records {
            next.digest = fold(kind, &next.digest, next.records, record);
            next.records += 1;
        }
        next.bytes = end.bytes + 4 + len;
        // Check the frame that reaches the snapshot's end before delivering any of
        // its records.
        if end.records < expect.records && next.records >= expect.records && next != *expect {
            return Err(format!(
                "side log {} does not match the snapshot's record of it; preserve the state \
                 files for offline reconciliation",
                path.display()
            ));
        }
        for (index, record) in (end.records..).zip(&records) {
            each(index, record)?;
        }
        end = next;
    }
}

fn open_frame(kind: Kind, at: &Position, sealed: &[u8], seed: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
    let plain = snapshot::open(sealed, seed).ok()?;
    let body = plain.strip_prefix(kind.magic())?;
    let (first, body) = body.split_first_chunk::<8>()?;
    if u64::from_le_bytes(*first) != at.records {
        return None;
    }
    let (records, rest): (Vec<Vec<u8>>, _) = postcard::take_from_bytes(body).ok()?;
    rest.is_empty().then_some(records)
}

/// `Ok(false)` at a clean end of file, `Err` for a partial read.
fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..])? {
            0 if filled == 0 => return Ok(false),
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            n => filled += n,
        }
    }
    Ok(true)
}

/// Cut a torn tail off: the file ends at `end` afterwards, synced.
pub fn truncate(path: &Path, end: &Position) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(end.bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).unwrap();
            let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::env::temp_dir().join(format!("arcora-side-log-{name}"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const SEED: [u8; 32] = [0x5A; 32];

    fn all(path: &Path, kind: Kind, from: &Position) -> (Vec<(u64, Vec<u8>)>, ReadEnd) {
        let mut out = Vec::new();
        let end = read(path, kind, from, from, &SEED, |i, r| {
            out.push((i, r.to_vec()));
            Ok(())
        })
        .unwrap();
        (out, end)
    }

    #[test]
    fn audit_1116_gf1_side_log_appends_reads_and_cuts_a_torn_tail() {
        let dir = Dir::new();
        let path = Kind::OrderLog.path(&dir.0.join("state"));
        assert!(path.ends_with("state.orderlog"));
        let records: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 3 + i as usize]).collect();
        let first = append(
            &path,
            Kind::OrderLog,
            &Position::default(),
            &records[..2],
            &SEED,
        )
        .unwrap();
        let second = append(&path, Kind::OrderLog, &first, &records[2..], &SEED).unwrap();
        assert_eq!(second.records, 5);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), second.bytes);

        let (read_back, end) = all(&path, Kind::OrderLog, &Position::default());
        assert_eq!(
            end,
            ReadEnd {
                end: second,
                torn: false
            }
        );
        assert_eq!(
            read_back,
            records
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, r)| (i as u64, r))
                .collect::<Vec<_>>()
        );
        // Reading from a durable position delivers only what follows it.
        let (tail, _) = all(&path, Kind::OrderLog, &first);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].0, 2);

        // Another kind, or another seed, never reads these frames.
        let (none, end) = all(&path, Kind::Batches, &Position::default());
        assert!(none.is_empty() && end.torn);

        // A torn append is reported and cut off; the next append resumes cleanly.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&[9, 0, 0, 0, 1, 2]).unwrap();
        let (_, end) = all(&path, Kind::OrderLog, &Position::default());
        assert_eq!(
            end,
            ReadEnd {
                end: second,
                torn: true
            }
        );
        truncate(&path, &end.end).unwrap();
        let third = append(&path, Kind::OrderLog, &second, &[vec![7]], &SEED).unwrap();
        let (read_back, end) = all(&path, Kind::OrderLog, &Position::default());
        assert_eq!(read_back.len(), 6);
        assert_eq!(end.end, third);
        assert!(!end.torn);

        // An append from a stale (earlier) position replaces what followed it, so
        // a failed append never leaves garbage between acknowledged frames.
        let again = append(&path, Kind::OrderLog, &second, &[vec![8]], &SEED).unwrap();
        assert_eq!(again.records, 6);
        assert_ne!(again.digest, third.digest, "the digest binds the record");
        let (read_back, _) = all(&path, Kind::OrderLog, &Position::default());
        assert_eq!(read_back.last().unwrap().1, vec![8]);
    }

    #[test]
    fn audit_1116_gf1_side_log_refuses_a_file_shorter_than_its_position() {
        let dir = Dir::new();
        let path = Kind::Batches.path(&dir.0.join("state"));
        let at = append(
            &path,
            Kind::Batches,
            &Position::default(),
            &[vec![1; 40]],
            &SEED,
        )
        .unwrap();
        truncate(
            &path,
            &Position {
                bytes: at.bytes - 1,
                ..at
            },
        )
        .unwrap();
        assert!(append(&path, Kind::Batches, &at, &[vec![2]], &SEED).is_err());
        let error = read(&path, Kind::Batches, &at, &at, &SEED, |_, _| Ok(())).unwrap_err();
        assert!(error.contains("does not hold the 1 records"), "{error}");
        let from_start = Position::default();
        let error = read(&path, Kind::Batches, &from_start, &at, &SEED, |_, _| Ok(())).unwrap_err();
        assert!(error.contains("does not hold the 1 records"), "{error}");
        // From the start, the cut frame reads as a torn tail.
        let (none, end) = all(&path, Kind::Batches, &Position::default());
        assert!(none.is_empty() && end.torn);
        // A missing file reads as empty from the start, and is refused past it.
        let absent = dir.0.join("absent");
        let (none, end) = all(&absent, Kind::Batches, &Position::default());
        assert!(none.is_empty() && !end.torn);
        assert!(read(&absent, Kind::Batches, &at, &at, &SEED, |_, _| Ok(())).is_err());
        // A file with the right count but other records is refused at the end.
        let other = dir.0.join("other");
        let path = Kind::Batches.path(&other);
        let elsewhere = append(
            &path,
            Kind::Batches,
            &Position::default(),
            &[vec![3; 40]],
            &SEED,
        )
        .unwrap();
        assert_eq!(elsewhere.records, at.records);
        let error = read(&path, Kind::Batches, &from_start, &at, &SEED, |_, _| Ok(())).unwrap_err();
        assert!(error.contains("does not match"), "{error}");
    }
}
