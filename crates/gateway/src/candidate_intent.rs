//! Authenticated durable intent for the OFFLINE candidate protocol harness.
//! This module is test-only. It does not change the runtime journal, prover
//! route or production HOLD. Request/prepared bytes belong to the protocol's
//! explicit v3 types; the store binds their exact bytes without reinterpretation.
use std::{
    io::Read,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

const MAGIC: &[u8; 8] = b"DPCINT3\0";
pub(crate) const MAX_REQUEST_BYTES: usize = 24 * 1024 * 1024;
pub(crate) const MAX_PREPARED_BYTES: usize = 16 * 1024 * 1024;
const HEADER_BYTES: usize = 8 + 1 + 1 + 4 + 4;
const MAX_PLAIN_BYTES: usize = HEADER_BYTES + MAX_REQUEST_BYTES + MAX_PREPARED_BYTES;
const MAX_SEALED_BYTES: usize = MAX_PLAIN_BYTES + 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntentStage {
    Intent,
    Prepared,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IntentRecord {
    pub(crate) version: u8,
    pub(crate) request: Vec<u8>,
    pub(crate) stage: IntentStage,
    pub(crate) prepared: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntentError {
    Bounds,
    Version,
    Malformed,
    Authentication,
    Read,
    Write,
    RequestMismatch,
    PreparedMismatch,
    MissingIntent,
    Poisoned,
}

/// One owned offline harness store. The mutex serializes compare-and-replace
/// operations on this handle; separate processes/handles are not coordinated.
pub(crate) struct IntentStore {
    path: PathBuf,
    seed: [u8; 32],
    serial: Mutex<()>,
    fail_next: AtomicBool,
}

impl IntentStore {
    pub(crate) fn new(path: PathBuf, seed: [u8; 32]) -> Self {
        Self {
            path,
            seed,
            serial: Mutex::new(()),
            fail_next: AtomicBool::new(false),
        }
    }

    pub(crate) fn load(&self) -> Result<Option<IntentRecord>, IntentError> {
        let _serial = self.serial.lock().map_err(|_| IntentError::Poisoned)?;
        self.load_locked()
    }

    /// Persist before any registration/prove callback. An identical retry reads
    /// the old record without resealing or regressing an already prepared stage.
    pub(crate) fn save_intent(&self, request: &[u8]) -> Result<IntentRecord, IntentError> {
        validate_request(request)?;
        let _serial = self.serial.lock().map_err(|_| IntentError::Poisoned)?;
        if let Some(old) = self.load_locked()? {
            if old.request != request {
                return Err(IntentError::RequestMismatch);
            }
            return Ok(old);
        }
        let record = IntentRecord {
            version: 3,
            request: request.to_vec(),
            stage: IntentStage::Intent,
            prepared: None,
        };
        self.write_locked(&record)?;
        Ok(record)
    }

    /// Persist the exact checked response/clock/report observations before any
    /// broadcast callback. Existing prepared material can never be replaced.
    pub(crate) fn save_prepared(
        &self,
        request: &[u8],
        prepared: &[u8],
    ) -> Result<IntentRecord, IntentError> {
        validate_request(request)?;
        validate_prepared(prepared)?;
        let _serial = self.serial.lock().map_err(|_| IntentError::Poisoned)?;
        let old = self.load_locked()?.ok_or(IntentError::MissingIntent)?;
        if old.request != request {
            return Err(IntentError::RequestMismatch);
        }
        if old.stage == IntentStage::Prepared {
            if old.prepared.as_deref() != Some(prepared) {
                return Err(IntentError::PreparedMismatch);
            }
            return Ok(old);
        }
        let record = IntentRecord {
            version: 3,
            request: old.request,
            stage: IntentStage::Prepared,
            prepared: Some(prepared.to_vec()),
        };
        self.write_locked(&record)?;
        Ok(record)
    }

    /// Per-store pre-commit failure, never global or selectable in production.
    /// Idempotent reads do not consume this hook because they perform no write.
    pub(crate) fn fail_next_save(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }

    fn load_locked(&self) -> Result<Option<IntentRecord>, IntentError> {
        let file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(IntentError::Read),
        };
        let metadata = file.metadata().map_err(|_| IntentError::Read)?;
        if !metadata.is_file() {
            return Err(IntentError::Read);
        }
        if metadata.len() > MAX_SEALED_BYTES as u64 {
            return Err(IntentError::Bounds);
        }
        let mut sealed = Vec::new();
        file.take(MAX_SEALED_BYTES as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(|_| IntentError::Read)?;
        if sealed.len() > MAX_SEALED_BYTES {
            return Err(IntentError::Bounds);
        }
        let plain =
            crate::snapshot::open(&sealed, &self.seed).map_err(|_| IntentError::Authentication)?;
        decode(&plain).map(Some)
    }

    fn write_locked(&self, record: &IntentRecord) -> Result<(), IntentError> {
        let plain = encode(record)?;
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(IntentError::Write);
        }
        let sealed = crate::snapshot::seal(&plain, &self.seed);
        // A failure before rename preserves the old target. A directory fsync
        // error after rename has uncertain completion: return Err, stop every
        // later callback, and reload/reconcile exact bytes; never roll it back.
        crate::snapshot::write_atomic(&self.path, &sealed).map_err(|_| IntentError::Write)
    }
}

fn validate_request(request: &[u8]) -> Result<(), IntentError> {
    if request.is_empty() || request.len() > MAX_REQUEST_BYTES {
        return Err(IntentError::Bounds);
    }
    Ok(())
}

fn validate_prepared(prepared: &[u8]) -> Result<(), IntentError> {
    if prepared.is_empty() || prepared.len() > MAX_PREPARED_BYTES {
        return Err(IntentError::Bounds);
    }
    Ok(())
}

/// Fixed-width lengths prevent alternate integer encodings and let the decoder
/// bound each vector BEFORE copying any authenticated but malformed payload.
fn encode(record: &IntentRecord) -> Result<Vec<u8>, IntentError> {
    if record.version != 3 {
        return Err(IntentError::Version);
    }
    validate_request(&record.request)?;
    let prepared = match (record.stage, record.prepared.as_deref()) {
        (IntentStage::Intent, None) => &[][..],
        (IntentStage::Prepared, Some(bytes)) => {
            validate_prepared(bytes)?;
            bytes
        }
        _ => return Err(IntentError::Malformed),
    };
    let mut plain = Vec::with_capacity(HEADER_BYTES + record.request.len() + prepared.len());
    plain.extend_from_slice(MAGIC);
    plain.push(record.version);
    plain.push(match record.stage {
        IntentStage::Intent => 0,
        IntentStage::Prepared => 1,
    });
    plain.extend_from_slice(&(record.request.len() as u32).to_be_bytes());
    plain.extend_from_slice(&record.request);
    plain.extend_from_slice(&(prepared.len() as u32).to_be_bytes());
    plain.extend_from_slice(prepared);
    Ok(plain)
}

fn decode(plain: &[u8]) -> Result<IntentRecord, IntentError> {
    if plain.len() > MAX_PLAIN_BYTES {
        return Err(IntentError::Bounds);
    }
    let mut rest = plain
        .strip_prefix(MAGIC.as_slice())
        .ok_or(IntentError::Version)?;
    let version = take_byte(&mut rest)?;
    if version != 3 {
        return Err(IntentError::Version);
    }
    let stage = match take_byte(&mut rest)? {
        0 => IntentStage::Intent,
        1 => IntentStage::Prepared,
        _ => return Err(IntentError::Malformed),
    };
    let request = take_bytes(&mut rest, MAX_REQUEST_BYTES)?;
    validate_request(request)?;
    let prepared = take_bytes(&mut rest, MAX_PREPARED_BYTES)?;
    if !rest.is_empty() {
        return Err(IntentError::Malformed);
    }
    let prepared = match stage {
        IntentStage::Intent if prepared.is_empty() => None,
        IntentStage::Prepared => {
            validate_prepared(prepared)?;
            Some(prepared.to_vec())
        }
        _ => return Err(IntentError::Malformed),
    };
    let record = IntentRecord {
        version,
        request: request.to_vec(),
        stage,
        prepared,
    };
    if encode(&record)? != plain {
        return Err(IntentError::Malformed);
    }
    Ok(record)
}

fn take_byte(rest: &mut &[u8]) -> Result<u8, IntentError> {
    let (&byte, tail) = rest.split_first().ok_or(IntentError::Malformed)?;
    *rest = tail;
    Ok(byte)
}

fn take_bytes<'a>(rest: &mut &'a [u8], limit: usize) -> Result<&'a [u8], IntentError> {
    let length = rest.get(..4).ok_or(IntentError::Malformed)?;
    let length =
        u32::from_be_bytes(length.try_into().map_err(|_| IntentError::Malformed)?) as usize;
    *rest = &rest[4..];
    if length > limit {
        return Err(IntentError::Bounds);
    }
    let bytes = rest.get(..length).ok_or(IntentError::Malformed)?;
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
            let path = std::env::temp_dir().join(format!("arcora-offline-intent-{suffix}"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn store(&self) -> IntentStore {
            IntentStore::new(self.0.join("candidate.intent"), [0x49; 32])
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn durable_intent_restart_requires_exact_request_and_prepared_bytes() {
        let scratch = Scratch::new();
        let store = scratch.store();
        assert_eq!(store.load().unwrap(), None);
        let intent = store.save_intent(b"synthetic-v3-request").unwrap();
        let initial = std::fs::read(&store.path).unwrap();
        assert_eq!(scratch.store().load().unwrap(), Some(intent.clone()));
        assert_eq!(store.save_intent(&intent.request).unwrap(), intent);
        assert_eq!(std::fs::read(&store.path).unwrap(), initial);
        assert_eq!(
            store.save_intent(b"replacement-v3-request"),
            Err(IntentError::RequestMismatch)
        );
        let prepared = store
            .save_prepared(
                &intent.request,
                b"synthetic-response-plus-original-receipts",
            )
            .unwrap();
        let committed = std::fs::read(&store.path).unwrap();
        let restarted = scratch.store();
        assert_eq!(restarted.load().unwrap(), Some(prepared.clone()));
        assert_eq!(restarted.save_intent(&intent.request).unwrap(), prepared);
        assert_eq!(
            restarted
                .save_prepared(&intent.request, prepared.prepared.as_deref().unwrap())
                .unwrap(),
            prepared
        );
        assert_eq!(std::fs::read(&store.path).unwrap(), committed);
        assert_eq!(
            restarted.save_prepared(&intent.request, b"refreshed-response"),
            Err(IntentError::PreparedMismatch)
        );
        assert_eq!(
            restarted.save_prepared(b"changed-witness", b"new-response"),
            Err(IntentError::RequestMismatch)
        );
        assert_eq!(std::fs::read(&store.path).unwrap(), committed);
    }

    #[test]
    fn failed_prepared_save_preserves_previous_exact_checkpoint() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let intent = store.save_intent(b"owned-synthetic-request").unwrap();
        let original = std::fs::read(&store.path).unwrap();
        store.fail_next_save();
        // Idempotent reads do not consume the next-write failure.
        assert_eq!(store.save_intent(&intent.request).unwrap(), intent);
        assert_eq!(
            store.save_prepared(&intent.request, b"owned-synthetic-response"),
            Err(IntentError::Write)
        );
        assert_eq!(std::fs::read(&store.path).unwrap(), original);
        assert_eq!(scratch.store().load().unwrap(), Some(intent.clone()));
        store
            .save_prepared(&intent.request, b"owned-synthetic-response")
            .unwrap();
        assert_eq!(store.load().unwrap().unwrap().stage, IntentStage::Prepared);
    }

    #[test]
    fn actual_pre_rename_io_failure_keeps_old_target_bytes() {
        let scratch = Scratch::new();
        let original_store = scratch.store();
        let intent = original_store.save_intent(b"synthetic-request").unwrap();
        let original = std::fs::read(&original_store.path).unwrap();
        // Legal NAME_MAX target; snapshot's exclusive random temporary name
        // exceeds NAME_MAX, so the actual filesystem write fails before rename.
        let long_path = scratch.0.join("i".repeat(240));
        std::fs::rename(&original_store.path, &long_path).unwrap();
        let store = IntentStore::new(long_path.clone(), [0x49; 32]);
        assert_eq!(
            store.save_prepared(&intent.request, b"synthetic-prepared"),
            Err(IntentError::Write)
        );
        assert_eq!(std::fs::read(&long_path).unwrap(), original);
        assert_eq!(store.load().unwrap(), Some(intent));
    }

    #[test]
    fn authenticated_foreign_v2_or_malformed_records_are_never_replaced() {
        let scratch = Scratch::new();
        let store = scratch.store();
        let valid = encode(&IntentRecord {
            version: 3,
            request: b"synthetic-request".to_vec(),
            stage: IntentStage::Intent,
            prepared: None,
        })
        .unwrap();
        let mut wrong_version = valid.clone();
        wrong_version[8] = 2;
        let mut wrong_stage = valid.clone();
        wrong_stage[9] = 9;
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut excessive_length = valid.clone();
        excessive_length[10..14].copy_from_slice(&((MAX_REQUEST_BYTES as u32) + 1).to_be_bytes());
        let mut truncated = valid;
        truncated.pop();
        for (plain, expected) in [
            (
                b"DPCINT2\0old-candidate-intent".to_vec(),
                IntentError::Version,
            ),
            (
                b"DPRBJL6\0foreign-runtime-journal".to_vec(),
                IntentError::Version,
            ),
            (wrong_version, IntentError::Version),
            (wrong_stage, IntentError::Malformed),
            (trailing, IntentError::Malformed),
            (excessive_length, IntentError::Bounds),
            (truncated, IntentError::Malformed),
        ] {
            let sealed = crate::snapshot::seal(&plain, &store.seed);
            crate::snapshot::write_atomic(&store.path, &sealed).unwrap();
            assert_eq!(store.load(), Err(expected));
            assert_eq!(store.save_intent(b"new-request"), Err(expected));
            assert_eq!(std::fs::read(&store.path).unwrap(), sealed);
        }
    }

    #[test]
    fn authentication_file_and_vector_bounds_refuse_before_replacement() {
        let scratch = Scratch::new();
        let store = scratch.store();
        assert_eq!(
            store.save_prepared(b"request", b"response"),
            Err(IntentError::MissingIntent)
        );
        assert_eq!(store.save_intent(b""), Err(IntentError::Bounds));
        let intent = store.save_intent(b"owned-request").unwrap();
        let original = std::fs::read(&store.path).unwrap();
        let wrong_seed = IntentStore::new(store.path.clone(), [0x48; 32]);
        assert_eq!(wrong_seed.load(), Err(IntentError::Authentication));
        assert_eq!(
            store.save_prepared(&intent.request, b""),
            Err(IntentError::Bounds)
        );
        assert_eq!(std::fs::read(&store.path).unwrap(), original);
        let mut corrupted = original;
        *corrupted.last_mut().unwrap() ^= 1;
        std::fs::write(&store.path, &corrupted).unwrap();
        assert_eq!(store.load(), Err(IntentError::Authentication));
        assert_eq!(
            store.save_intent(b"owned-request"),
            Err(IntentError::Authentication)
        );
        assert_eq!(std::fs::read(&store.path).unwrap(), corrupted);
        // A sparse oversized file is refused from metadata without allocating
        // the claimed length or attempting to decrypt it.
        std::fs::File::create(&store.path)
            .unwrap()
            .set_len(MAX_SEALED_BYTES as u64 + 1)
            .unwrap();
        assert_eq!(store.load(), Err(IntentError::Bounds));
        assert_eq!(
            std::fs::metadata(&store.path).unwrap().len(),
            MAX_SEALED_BYTES as u64 + 1
        );
    }
}
