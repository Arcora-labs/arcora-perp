//! Authenticated staged recovery for the OFFLINE candidate harness only.
//! The protocol owns the meaning of each opaque observation. This store owns
//! exact bytes, bounded framing, adjacent stage transitions and durable cuts.
//! There is no runtime activation, v3 migration or cross-process writer lock.
use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

const MAGIC: &[u8; 8] = b"DPCINT4\0";
const VERSION: u8 = 4;
pub(crate) const MAX_REQUEST_BYTES: usize = 24 * 1024 * 1024;
pub(crate) const MAX_OBSERVATION_BYTES: usize = 64 * 1024;
pub(crate) const MAX_PREPARED_BYTES: usize = 16 * 1024 * 1024;
const HEADER_BYTES: usize = 8 + 1 + 1 + 4 * 4;
const MAX_PLAIN_BYTES: usize =
    HEADER_BYTES + MAX_REQUEST_BYTES + 2 * MAX_OBSERVATION_BYTES + MAX_PREPARED_BYTES;
pub(crate) const MAX_SEALED_BYTES: usize = MAX_PLAIN_BYTES + 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Intent,
    ClockPending,
    ClockObserved,
    ReportsPending,
    ReportsObserved,
    Prepared,
}
impl Stage {
    fn number(self) -> u8 {
        match self {
            Self::Intent => 0,
            Self::ClockPending => 1,
            Self::ClockObserved => 2,
            Self::ReportsPending => 3,
            Self::ReportsObserved => 4,
            Self::Prepared => 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) request: Vec<u8>,
    pub(crate) stage: Stage,
    pub(crate) clock: Option<Vec<u8>>,
    pub(crate) reports: Option<Vec<u8>>,
    pub(crate) prepared: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreError {
    Bounds,
    Version,
    Malformed,
    Authentication,
    Read,
    Write,
    /// Publication happened, but its directory acknowledgement is uncertain.
    /// Stop subsequent callbacks and reload exact bytes before reconciliation.
    AmbiguousWrite,
    Exists,
    Missing,
    Conflict,
    RequestMismatch,
    PayloadMismatch,
    Stage,
    Poisoned,
}

/// One owned offline store. The mutex serializes reads and compare-and-advance
/// writes on this handle. Independent handles/processes must not share writers.
pub(crate) struct RecoveryStore {
    path: PathBuf,
    seed: [u8; 32],
    serial: Mutex<()>,
    fail_write: AtomicBool,
    fail_rename: AtomicBool,
    fail_directory_sync: AtomicBool,
}

impl RecoveryStore {
    pub(crate) fn new(path: PathBuf, seed: [u8; 32]) -> Self {
        Self {
            path,
            seed,
            serial: Mutex::new(()),
            fail_write: AtomicBool::new(false),
            fail_rename: AtomicBool::new(false),
            fail_directory_sync: AtomicBool::new(false),
        }
    }

    pub(crate) fn load(&self) -> Result<Option<Record>, StoreError> {
        let _serial = self.serial.lock().map_err(|_| StoreError::Poisoned)?;
        self.load_locked()
    }

    /// Fresh mode refuses every existing target, including unreadable, foreign
    /// or malformed files. It never reuses an old Intent as a fresh invocation.
    pub(crate) fn create(&self, request: &[u8]) -> Result<Record, StoreError> {
        validate_nonempty(request, MAX_REQUEST_BYTES)?;
        let _serial = self.serial.lock().map_err(|_| StoreError::Poisoned)?;
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => return Err(StoreError::Exists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Read),
        }
        let record = Record {
            request: request.to_vec(),
            stage: Stage::Intent,
            clock: None,
            reports: None,
            prepared: None,
        };
        self.write_locked(&record, true)?;
        Ok(record)
    }

    /// Compare the exact previous cut, then publish one adjacent stage. Already
    /// published identical bytes are idempotent and do not reseal or use hooks.
    /// Request and each established observation can never be replaced or reset.
    pub(crate) fn advance(&self, expected: &Record, next: Record) -> Result<Record, StoreError> {
        validate_record(expected)?;
        validate_record(&next)?;
        let _serial = self.serial.lock().map_err(|_| StoreError::Poisoned)?;
        let old = self.load_locked()?.ok_or(StoreError::Missing)?;
        if expected.request != old.request || next.request != old.request {
            return Err(StoreError::RequestMismatch);
        }
        if old == next {
            return Ok(old);
        }
        if old != *expected {
            return Err(StoreError::Conflict);
        }
        if next.stage.number() != old.stage.number() + 1 {
            return Err(StoreError::Stage);
        }
        if old.clock.is_some() && old.clock != next.clock
            || old.reports.is_some() && old.reports != next.reports
            || old.prepared.is_some() && old.prepared != next.prepared
        {
            return Err(StoreError::PayloadMismatch);
        }
        self.write_locked(&next, false)?;
        Ok(next)
    }

    /// Per-handle hooks exist only in this test-only module. Exact idempotent
    /// operations perform no write and leave all hooks armed.
    pub(crate) fn fail_next_write(&self) {
        self.fail_write.store(true, Ordering::SeqCst);
    }

    pub(crate) fn fail_next_rename(&self) {
        self.fail_rename.store(true, Ordering::SeqCst);
    }

    pub(crate) fn fail_next_directory_sync(&self) {
        self.fail_directory_sync.store(true, Ordering::SeqCst);
    }

    fn load_locked(&self) -> Result<Option<Record>, StoreError> {
        let before = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Read),
        };
        if !before.is_file() {
            return Err(StoreError::Read);
        }
        if before.len() > MAX_SEALED_BYTES as u64 {
            return Err(StoreError::Bounds);
        }
        let file = std::fs::File::open(&self.path).map_err(|_| StoreError::Read)?;
        let opened = file.metadata().map_err(|_| StoreError::Read)?;
        if !opened.is_file() {
            return Err(StoreError::Read);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if opened.dev() != before.dev() || opened.ino() != before.ino() {
                return Err(StoreError::Read);
            }
        }
        if opened.len() > MAX_SEALED_BYTES as u64 {
            return Err(StoreError::Bounds);
        }
        let mut sealed = Vec::new();
        file.take(MAX_SEALED_BYTES as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(|_| StoreError::Read)?;
        if sealed.len() > MAX_SEALED_BYTES {
            return Err(StoreError::Bounds);
        }
        let plain =
            crate::snapshot::open(&sealed, &self.seed).map_err(|_| StoreError::Authentication)?;
        decode(&plain).map(Some)
    }

    fn write_locked(&self, record: &Record, fresh: bool) -> Result<(), StoreError> {
        let plain = encode(record)?;
        if self.fail_write.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Write);
        }
        let sealed = crate::snapshot::seal(&plain, &self.seed);
        self.publish(&sealed, fresh)
    }

    /// Private exclusive temporary + file fsync + atomic publication + directory
    /// fsync. Fresh creation uses an atomic no-clobber hard link; advances rename
    /// over the owned target. No error ever restores or deletes a published cut.
    fn publish(&self, sealed: &[u8], fresh: bool) -> Result<(), StoreError> {
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let directory = std::fs::File::open(parent).map_err(|_| StoreError::Write)?;
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| StoreError::Write)?;
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".tmp.");
        name.push(
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        let tmp = PathBuf::from(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(|_| StoreError::Write)?;
        let result = (|| {
            file.write_all(sealed).map_err(|_| StoreError::Write)?;
            file.sync_all().map_err(|_| StoreError::Write)?;
            if self.fail_rename.swap(false, Ordering::SeqCst) {
                return Err(StoreError::Write);
            }
            if fresh {
                std::fs::hard_link(&tmp, &self.path).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        StoreError::Exists
                    } else {
                        StoreError::Write
                    }
                })?;
                std::fs::remove_file(&tmp).map_err(|_| StoreError::AmbiguousWrite)?;
            } else {
                std::fs::rename(&tmp, &self.path).map_err(|_| StoreError::Write)?;
            }
            if self.fail_directory_sync.swap(false, Ordering::SeqCst) {
                return Err(StoreError::AmbiguousWrite);
            }
            directory.sync_all().map_err(|_| StoreError::AmbiguousWrite)
        })();
        // Only remove our exclusive temporary. A publication failure can leave
        // the NEW target visible, so callers must reload; never roll it back.
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

fn validate_nonempty(bytes: &[u8], limit: usize) -> Result<(), StoreError> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(StoreError::Bounds);
    }
    Ok(())
}

fn validate_fields(
    stage: Stage,
    request: &[u8],
    clock: Option<&[u8]>,
    reports: Option<&[u8]>,
    prepared: Option<&[u8]>,
) -> Result<(), StoreError> {
    validate_nonempty(request, MAX_REQUEST_BYTES)?;
    for observation in [clock, reports].into_iter().flatten() {
        validate_nonempty(observation, MAX_OBSERVATION_BYTES)?;
    }
    if let Some(bytes) = prepared {
        validate_nonempty(bytes, MAX_PREPARED_BYTES)?;
    }
    let fields = (clock.is_some(), reports.is_some(), prepared.is_some());
    let required = match stage {
        Stage::Intent | Stage::ClockPending => (false, false, false),
        Stage::ClockObserved | Stage::ReportsPending => (true, false, false),
        Stage::ReportsObserved => (true, true, false),
        Stage::Prepared => (true, true, true),
    };
    if fields != required {
        return Err(StoreError::Malformed);
    }
    Ok(())
}

fn validate_record(record: &Record) -> Result<(), StoreError> {
    validate_fields(
        record.stage,
        &record.request,
        record.clock.as_deref(),
        record.reports.as_deref(),
        record.prepared.as_deref(),
    )
}

/// Fixed u32 lengths have exactly one encoding. A zero observation length means
/// absent; populated empty observations are invalid and cannot alias absence.
fn encode(record: &Record) -> Result<Vec<u8>, StoreError> {
    validate_record(record)?;
    let fields = [
        record.request.as_slice(),
        record.clock.as_deref().unwrap_or_default(),
        record.reports.as_deref().unwrap_or_default(),
        record.prepared.as_deref().unwrap_or_default(),
    ];
    let mut plain =
        Vec::with_capacity(HEADER_BYTES + fields.iter().map(|b| b.len()).sum::<usize>());
    plain.extend_from_slice(MAGIC);
    plain.push(VERSION);
    plain.push(record.stage.number());
    for bytes in fields {
        plain.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        plain.extend_from_slice(bytes);
    }
    Ok(plain)
}

fn decode(plain: &[u8]) -> Result<Record, StoreError> {
    if plain.len() > MAX_PLAIN_BYTES {
        return Err(StoreError::Bounds);
    }
    let mut rest = plain
        .strip_prefix(MAGIC.as_slice())
        .ok_or(StoreError::Version)?;
    if take_byte(&mut rest)? != VERSION {
        return Err(StoreError::Version);
    }
    let stage = match take_byte(&mut rest)? {
        0 => Stage::Intent,
        1 => Stage::ClockPending,
        2 => Stage::ClockObserved,
        3 => Stage::ReportsPending,
        4 => Stage::ReportsObserved,
        5 => Stage::Prepared,
        _ => return Err(StoreError::Malformed),
    };
    // Bound and validate ALL borrowed fields before copying any payload vector.
    let request = take_bytes(&mut rest, MAX_REQUEST_BYTES)?;
    let clock = take_bytes(&mut rest, MAX_OBSERVATION_BYTES)?;
    let reports = take_bytes(&mut rest, MAX_OBSERVATION_BYTES)?;
    let prepared = take_bytes(&mut rest, MAX_PREPARED_BYTES)?;
    if !rest.is_empty() {
        return Err(StoreError::Malformed);
    }
    validate_fields(
        stage,
        request,
        optional(clock),
        optional(reports),
        optional(prepared),
    )?;
    let record = Record {
        request: request.to_vec(),
        stage,
        clock: optional(clock).map(Vec::from),
        reports: optional(reports).map(Vec::from),
        prepared: optional(prepared).map(Vec::from),
    };
    if encode(&record)? != plain {
        return Err(StoreError::Malformed);
    }
    Ok(record)
}

fn optional(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

fn take_byte(rest: &mut &[u8]) -> Result<u8, StoreError> {
    let (&byte, tail) = rest.split_first().ok_or(StoreError::Malformed)?;
    *rest = tail;
    Ok(byte)
}

fn take_bytes<'a>(rest: &mut &'a [u8], limit: usize) -> Result<&'a [u8], StoreError> {
    let length = rest.get(..4).ok_or(StoreError::Malformed)?;
    let length = u32::from_be_bytes(length.try_into().map_err(|_| StoreError::Malformed)?) as usize;
    *rest = &rest[4..];
    if length > limit {
        return Err(StoreError::Bounds);
    }
    let bytes = rest.get(..length).ok_or(StoreError::Malformed)?;
    *rest = &rest[length..];
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::getrandom(&mut random).unwrap();
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("arcora-staged-recovery-{suffix}"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn store(&self) -> RecoveryStore {
            RecoveryStore::new(self.0.join("candidate.recovery"), [0x44; 32])
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn next(old: &Record) -> Record {
        let mut record = old.clone();
        match old.stage {
            Stage::Intent => record.stage = Stage::ClockPending,
            Stage::ClockPending => {
                record.stage = Stage::ClockObserved;
                record.clock = Some(b"exact-clock-anchor".to_vec());
            }
            Stage::ClockObserved => record.stage = Stage::ReportsPending,
            Stage::ReportsPending => {
                record.stage = Stage::ReportsObserved;
                record.reports = Some(b"exact-report-anchor".to_vec());
            }
            Stage::ReportsObserved => {
                record.stage = Stage::Prepared;
                record.prepared = Some(b"exact-typed-mock-proof".to_vec());
            }
            Stage::Prepared => panic!("terminal stage"),
        }
        record
    }

    #[test]
    fn each_durable_cut_restarts_exactly_and_fresh_never_reuses_it() {
        let scratch = Scratch::new();
        let store = scratch.store();
        assert_eq!(store.load().unwrap(), None);
        let mut cut = store.create(b"immutable-offline-request").unwrap();
        assert_eq!(store.create(&cut.request), Err(StoreError::Exists));
        while cut.stage != Stage::Prepared {
            let successor = next(&cut);
            let prior = cut.clone();
            cut = store.advance(&cut, successor).unwrap();
            let bytes = std::fs::read(&store.path).unwrap();
            assert_eq!(scratch.store().load().unwrap(), Some(cut.clone()));
            // Repeating publication after a lost acknowledgement is exact and
            // byte-stable, including its original sealing nonce.
            assert_eq!(store.advance(&prior, cut.clone()).unwrap(), cut);
            assert_eq!(store.advance(&cut, cut.clone()).unwrap(), cut);
            assert_eq!(std::fs::read(&store.path).unwrap(), bytes);
            assert_eq!(store.create(b"replacement"), Err(StoreError::Exists));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn skips_regressions_stale_cas_and_payload_replacements_preserve_disk() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let intent = store.create(b"immutable-request").unwrap();
        let pending = next(&intent);
        let observed = next(&pending);
        let original = std::fs::read(&store.path).unwrap();
        assert_eq!(
            store.advance(&intent, observed.clone()),
            Err(StoreError::Stage)
        );
        assert_eq!(std::fs::read(&store.path).unwrap(), original);
        let pending = store.advance(&intent, pending).unwrap();
        let observed = store.advance(&pending, observed).unwrap();
        let bytes = std::fs::read(&store.path).unwrap();
        assert_eq!(
            store.advance(&observed, intent.clone()),
            Err(StoreError::Stage)
        );
        assert_eq!(
            store.advance(&pending, next(&observed)),
            Err(StoreError::Conflict)
        );
        let mut changed_request = next(&observed);
        changed_request.request.push(0);
        assert_eq!(
            store.advance(&observed, changed_request),
            Err(StoreError::RequestMismatch)
        );
        let mut changed_clock = next(&observed);
        changed_clock.clock.as_mut().unwrap().push(0);
        assert_eq!(
            store.advance(&observed, changed_clock),
            Err(StoreError::PayloadMismatch)
        );
        let mut empty_clock = next(&pending);
        empty_clock.clock = Some(Vec::new());
        assert_eq!(
            store.advance(&observed, empty_clock),
            Err(StoreError::Bounds)
        );
        let reports_pending = store.advance(&observed, next(&observed)).unwrap();
        let reports = store
            .advance(&reports_pending, next(&reports_pending))
            .unwrap();
        let latest = std::fs::read(&store.path).unwrap();
        let mut changed_reports = next(&reports);
        changed_reports.reports.as_mut().unwrap().push(0);
        assert_eq!(
            store.advance(&reports, changed_reports),
            Err(StoreError::PayloadMismatch)
        );
        assert_eq!(std::fs::read(&store.path).unwrap(), latest);
        assert_ne!(latest, bytes);
        assert_eq!(scratch.store().load().unwrap(), Some(reports));
    }

    #[test]
    fn concurrent_compare_and_advance_has_one_immutable_observation() {
        let scratch = Scratch::new();
        let store = std::sync::Arc::new(scratch.store());
        let intent = store.create(b"immutable-request").unwrap();
        let pending = store.advance(&intent, next(&intent)).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for byte in [0x41, 0x42] {
            let store = store.clone();
            let barrier = barrier.clone();
            let expected = pending.clone();
            workers.push(std::thread::spawn(move || {
                let mut observation = next(&expected);
                observation.clock = Some(vec![byte]);
                barrier.wait();
                store.advance(&expected, observation)
            }));
        }
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(StoreError::Conflict))
                .count(),
            1
        );
        let winner = results.into_iter().find_map(Result::ok).unwrap();
        assert_eq!(store.load().unwrap(), Some(winner));
    }

    #[test]
    fn pre_write_and_pre_rename_failures_keep_exact_previous_cut() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let cut = store.create(b"immutable-request").unwrap();
        let original = std::fs::read(&store.path).unwrap();
        store.fail_next_write();
        assert_eq!(store.advance(&cut, cut.clone()).unwrap(), cut);
        assert_eq!(store.advance(&cut, next(&cut)), Err(StoreError::Write));
        assert_eq!(std::fs::read(&store.path).unwrap(), original);
        store.fail_next_rename();
        assert_eq!(store.advance(&cut, next(&cut)), Err(StoreError::Write));
        assert_eq!(std::fs::read(&store.path).unwrap(), original);
        assert_eq!(scratch.store().load().unwrap(), Some(cut));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);
    }

    #[test]
    fn post_publication_failure_requires_reload_without_rollback() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let cut = store.create(b"immutable-request").unwrap();
        let original = std::fs::read(&store.path).unwrap();
        let pending = next(&cut);
        store.fail_next_directory_sync();
        assert_eq!(
            store.advance(&cut, pending.clone()),
            Err(StoreError::AmbiguousWrite)
        );
        assert_ne!(std::fs::read(&store.path).unwrap(), original);
        assert_eq!(scratch.store().load().unwrap(), Some(pending.clone()));
        let published = std::fs::read(&store.path).unwrap();
        assert_eq!(store.advance(&cut, pending.clone()).unwrap(), pending);
        assert_eq!(std::fs::read(&store.path).unwrap(), published);
        assert_eq!(store.create(b"replacement"), Err(StoreError::Exists));
    }

    #[test]
    fn actual_pre_rename_io_error_keeps_old_target_and_missing_never_advances() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let cut = store.create(b"immutable-request").unwrap();
        let original = std::fs::read(&store.path).unwrap();
        // Legal NAME_MAX target, but our exclusive sibling temp exceeds it.
        let long_path = scratch.0.join("r".repeat(240));
        std::fs::rename(&store.path, &long_path).unwrap();
        let long_store = RecoveryStore::new(long_path.clone(), store.seed);
        assert_eq!(long_store.advance(&cut, next(&cut)), Err(StoreError::Write));
        assert_eq!(std::fs::read(&long_path).unwrap(), original);
        assert_eq!(long_store.load().unwrap(), Some(cut.clone()));
        assert_eq!(store.advance(&cut, next(&cut)), Err(StoreError::Missing));
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn authenticated_version_stage_bounds_and_trailing_confusion_refuse() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let cut = store.create(b"immutable-request").unwrap();
        let valid = encode(&cut).unwrap();
        let mut version = valid.clone();
        version[8] = 3;
        let mut stage = valid.clone();
        stage[9] = 6;
        let mut incoherent = valid.clone();
        incoherent[9] = Stage::ClockObserved.number();
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut oversized = valid.clone();
        oversized[10..14].copy_from_slice(&((MAX_REQUEST_BYTES as u32) + 1).to_be_bytes());
        let mut oversized_clock = encode(&next(&next(&cut))).unwrap();
        let clock_len_at = 14 + cut.request.len();
        oversized_clock[clock_len_at..clock_len_at + 4]
            .copy_from_slice(&((MAX_OBSERVATION_BYTES as u32) + 1).to_be_bytes());
        let observed = next(&next(&cut));
        let reports = next(&next(&observed));
        let mut oversized_reports = encode(&reports).unwrap();
        let reports_len_at = clock_len_at + 4 + reports.clock.as_ref().unwrap().len();
        oversized_reports[reports_len_at..reports_len_at + 4]
            .copy_from_slice(&((MAX_OBSERVATION_BYTES as u32) + 1).to_be_bytes());
        let mut oversized_prepared = encode(&next(&reports)).unwrap();
        let prepared_len_at = reports_len_at + 4 + reports.reports.as_ref().unwrap().len();
        oversized_prepared[prepared_len_at..prepared_len_at + 4]
            .copy_from_slice(&((MAX_PREPARED_BYTES as u32) + 1).to_be_bytes());
        let mut truncated = valid;
        truncated.pop();
        for (plain, error) in [
            (b"DPCINT3\0old-intent".to_vec(), StoreError::Version),
            (b"DPCINT2\0old-intent".to_vec(), StoreError::Version),
            (version, StoreError::Version),
            (stage, StoreError::Malformed),
            (incoherent, StoreError::Malformed),
            (trailing, StoreError::Malformed),
            (oversized, StoreError::Bounds),
            (oversized_clock, StoreError::Bounds),
            (oversized_reports, StoreError::Bounds),
            (oversized_prepared, StoreError::Bounds),
            (truncated, StoreError::Malformed),
        ] {
            let sealed = crate::snapshot::seal(&plain, &store.seed);
            crate::snapshot::write_atomic(&store.path, &sealed).unwrap();
            assert_eq!(store.load(), Err(error));
            assert_eq!(store.advance(&cut, next(&cut)), Err(error));
            assert_eq!(store.create(b"replacement"), Err(StoreError::Exists));
            assert_eq!(std::fs::read(&store.path).unwrap(), sealed);
        }
    }

    #[test]
    fn authentication_sparse_file_and_nonregular_paths_fail_closed() {
        let scratch = Scratch::new();
        let store = scratch.store();
        assert_eq!(store.create(b""), Err(StoreError::Bounds));
        let cut = store.create(b"immutable-request").unwrap();
        let wrong_seed = RecoveryStore::new(store.path.clone(), [0x45; 32]);
        assert_eq!(wrong_seed.load(), Err(StoreError::Authentication));
        let mut corrupted = std::fs::read(&store.path).unwrap();
        *corrupted.last_mut().unwrap() ^= 1;
        std::fs::write(&store.path, &corrupted).unwrap();
        assert_eq!(store.load(), Err(StoreError::Authentication));
        assert_eq!(
            store.advance(&cut, next(&cut)),
            Err(StoreError::Authentication)
        );
        assert_eq!(std::fs::read(&store.path).unwrap(), corrupted);
        std::fs::File::create(&store.path)
            .unwrap()
            .set_len(MAX_SEALED_BYTES as u64 + 1)
            .unwrap();
        assert_eq!(store.load(), Err(StoreError::Bounds));
        std::fs::remove_file(&store.path).unwrap();
        std::fs::create_dir(&store.path).unwrap();
        assert_eq!(store.load(), Err(StoreError::Read));
        assert_eq!(store.create(b"replacement"), Err(StoreError::Exists));
        std::fs::remove_dir(&store.path).unwrap();
        #[cfg(unix)]
        {
            let other = scratch.0.join("operator-file");
            std::fs::write(&other, b"preserved-user-bytes").unwrap();
            std::os::unix::fs::symlink(&other, &store.path).unwrap();
            assert_eq!(store.load(), Err(StoreError::Read));
            assert_eq!(store.create(b"replacement"), Err(StoreError::Exists));
            assert_eq!(std::fs::read(&other).unwrap(), b"preserved-user-bytes");
        }
    }
}
