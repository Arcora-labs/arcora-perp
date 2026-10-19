//! Filesystem coordination for the OFFLINE staged-preparation harness only.
//! The canonical source spelling determines one immutable binding and one
//! stable advisory lock. Source basenames are lowercase ASCII to exclude
//! case-insensitive aliases. The lock namespace uses physical parent identity,
//! while the authenticated binding retains the exact absolute source spelling.
//! Cooperating writers hold its lease for the entire invocation. This is neither chain finality nor a same-user hostile sandbox.
use crate::candidate_recovery_store::{Record, RecoveryStore};
use std::{
    cell::Cell,
    fs::{File, Metadata, OpenOptions, TryLockError},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const MAGIC: &[u8; 8] = b"DPCREG1\0";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"Arcora/offline/preparation-binding/v1\0";
const SEED_DOMAIN: &[u8] = b"Arcora/DPCREG1/binding-seed/v1\0";
const LANE_DOMAIN: &[u8] = b"Arcora/DPCREG1/physical-source-lane/v1\0";
const PLAIN_BYTES: usize = 8 + 1 + DOMAIN.len() + 32 + 32 + 8 + 8 + 4;
pub(crate) const MAX_BINDING_SEALED_BYTES: usize = PLAIN_BYTES + 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) source_path_sha256: [u8; 32],
    pub(crate) request_sha256: [u8; 32],
    pub(crate) lock_dev: u64,
    pub(crate) lock_ino: u64,
    pub(crate) lock_uid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreError {
    Bounds,
    Version,
    Malformed,
    Authentication,
    Read,
    Write,
    AmbiguousWrite,
    Exists,
    MissingBinding,
    BindingMismatch,
    Busy,
    Path,
    Permissions,
    Identity,
    Poisoned,
    Source(crate::candidate_recovery_store::StoreError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Inode {
    dev: u64,
    ino: u64,
    uid: u32,
}
impl Inode {
    fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileCut {
    inode: Inode,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl FileCut {
    fn of(metadata: &Metadata) -> Self {
        Self {
            inode: Inode::of(metadata),
            len: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

pub(crate) struct CoordinationStore {
    source_path: PathBuf,
    binding_path: PathBuf,
    lock_path: PathBuf,
    parent: PathBuf,
    directory: File,
    directory_inode: Inode,
    lock_inode: Inode,
    path_sha256: [u8; 32],
    binding_seed: [u8; 32],
    // Ownership prevents a caller from directing a guarded write to another
    // path or using another seed. Existing RecoveryStore bytes are untouched.
    source: RecoveryStore,
    fail_write: AtomicBool,
    fail_rename: AtomicBool,
    fail_directory_sync: AtomicBool,
}

pub(crate) struct Lease<'a> {
    store: &'a CoordinationStore,
    lock: File,
    source: Cell<Option<FileCut>>,
    binding: Cell<Option<FileCut>>,
    poisoned: Cell<bool>,
}

impl CoordinationStore {
    pub(crate) fn new(source_path: PathBuf, seed: [u8; 32]) -> Result<Self, StoreError> {
        let parent = source_path.parent().ok_or(StoreError::Path)?.to_path_buf();
        let name = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(StoreError::Path)?;
        if !source_path.is_absolute()
            || parent.join(name).as_os_str() != source_path.as_os_str()
            || name.is_empty()
            || name.len() > 128
            || name == "."
            || name == ".."
            || !name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
            || name.ends_with(".lock")
            || name.starts_with(".dpcreg1-")
            || parent
                .canonicalize()
                .map_err(|_| StoreError::Path)?
                .as_os_str()
                != parent.as_os_str()
        {
            return Err(StoreError::Path);
        }
        let before = std::fs::symlink_metadata(&parent).map_err(|_| StoreError::Path)?;
        private_directory(&before)?;
        let directory = File::open(&parent).map_err(|_| StoreError::Path)?;
        let opened = directory.metadata().map_err(|_| StoreError::Path)?;
        private_directory(&opened)?;
        let directory_inode = Inode::of(&before);
        if Inode::of(&opened) != directory_inode {
            return Err(StoreError::Identity);
        }
        let path_sha256 = crate::candidate_protocol::sha256(source_path.as_os_str().as_bytes());
        // The raw absolute path remains the authenticated binding pin. A
        // physical directory alias must nevertheless contend on the SAME lock:
        // path spelling never contributes to this coordination namespace.
        let digest = lane_sha256(directory_inode, name)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let binding_path = parent.join(format!(".dpcreg1-{digest}.binding"));
        let lock_path = parent.join(format!(".dpcreg1-{digest}.lock"));
        let probe = temporary_path(&binding_path)?;
        let probe_file = private_create(&probe)?;
        let probe_owner = probe_file.metadata().map_err(|_| StoreError::Write)?.uid();
        drop(probe_file);
        std::fs::remove_file(&probe).map_err(|_| StoreError::Write)?;
        if probe_owner != directory_inode.uid {
            return Err(StoreError::Permissions);
        }
        if matches!(std::fs::symlink_metadata(&lock_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
            && std::fs::symlink_metadata(&binding_path).is_ok()
        {
            return Err(StoreError::Identity);
        }
        let lock = match private_create(&lock_path) {
            Ok(file) => {
                file.sync_all().map_err(|_| StoreError::Write)?;
                directory.sync_all().map_err(|_| StoreError::Write)?;
                file
            }
            Err(StoreError::Exists) => checked_open(&lock_path, directory_inode.uid, true)?,
            Err(error) => return Err(error),
        };
        let metadata = lock.metadata().map_err(|_| StoreError::Read)?;
        private_regular(&metadata, directory_inode.uid)?;
        if metadata.len() != 0 {
            return Err(StoreError::Identity);
        }
        let mut key_material = Vec::with_capacity(SEED_DOMAIN.len() + seed.len());
        key_material.extend_from_slice(SEED_DOMAIN);
        key_material.extend_from_slice(&seed);
        let store = Self {
            source: RecoveryStore::new(source_path.clone(), seed),
            source_path,
            binding_path,
            lock_path,
            parent,
            directory,
            directory_inode,
            lock_inode: Inode::of(&metadata),
            path_sha256,
            binding_seed: crate::candidate_protocol::sha256(&key_material),
            fail_write: AtomicBool::new(false),
            fail_rename: AtomicBool::new(false),
            fail_directory_sync: AtomicBool::new(false),
        };
        store.check_paths()?;
        store.cuts()?;
        Ok(store)
    }

    pub(crate) fn source_path(&self) -> &Path {
        &self.source_path
    }
    pub(crate) fn binding_path(&self) -> &Path {
        &self.binding_path
    }
    pub(crate) fn lock_path(&self) -> &Path {
        &self.lock_path
    }
    pub(crate) fn fail_next_binding_write(&self) {
        self.fail_write.store(true, Ordering::SeqCst);
    }
    pub(crate) fn fail_next_binding_rename(&self) {
        self.fail_rename.store(true, Ordering::SeqCst);
    }
    pub(crate) fn fail_next_binding_directory_sync(&self) {
        self.fail_directory_sync.store(true, Ordering::SeqCst);
    }
    pub(crate) fn fail_next_source_write(&self) {
        self.source.fail_next_write();
    }
    pub(crate) fn fail_next_source_rename(&self) {
        self.source.fail_next_rename();
    }
    pub(crate) fn fail_next_source_directory_sync(&self) {
        self.source.fail_next_directory_sync();
    }

    pub(crate) fn try_lease(&self) -> Result<Lease<'_>, StoreError> {
        self.check_paths()?;
        let lock = checked_open(&self.lock_path, self.directory_inode.uid, true)?;
        if Inode::of(&lock.metadata().map_err(|_| StoreError::Read)?) != self.lock_inode {
            return Err(StoreError::Identity);
        }
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(StoreError::Busy),
            Err(TryLockError::Error(_)) => return Err(StoreError::Read),
        }
        #[cfg(test)]
        tests::observe_locked(&lock);
        // Own the kernel lock first so every refusal below releases it via Drop.
        let lease = Lease {
            store: self,
            lock,
            source: Cell::new(None),
            binding: Cell::new(None),
            poisoned: Cell::new(false),
        };
        self.check_paths()?;
        let (source, binding) = self.cuts()?;
        lease.source.set(source);
        lease.binding.set(binding);
        lease.check()?;
        lease.load_binding()?;
        Ok(lease)
    }

    fn check_paths(&self) -> Result<(), StoreError> {
        if self.parent.canonicalize().map_err(|_| StoreError::Path)? != self.parent {
            return Err(StoreError::Identity);
        }
        for metadata in [
            std::fs::symlink_metadata(&self.parent).map_err(|_| StoreError::Path)?,
            self.directory.metadata().map_err(|_| StoreError::Path)?,
        ] {
            private_directory(&metadata)?;
            if Inode::of(&metadata) != self.directory_inode {
                return Err(StoreError::Identity);
            }
        }
        let lock = std::fs::symlink_metadata(&self.lock_path).map_err(|_| StoreError::Identity)?;
        private_regular(&lock, self.directory_inode.uid)?;
        if Inode::of(&lock) != self.lock_inode || lock.len() != 0 {
            return Err(StoreError::Identity);
        }
        Ok(())
    }

    fn cut(&self, path: &Path, maximum: usize) -> Result<Option<FileCut>, StoreError> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Read),
        };
        private_regular(&metadata, self.directory_inode.uid)?;
        if Inode::of(&metadata) == self.lock_inode {
            return Err(StoreError::Identity);
        }
        if metadata.len() > maximum as u64 {
            return Err(StoreError::Bounds);
        }
        Ok(Some(FileCut::of(&metadata)))
    }
    fn cuts(&self) -> Result<(Option<FileCut>, Option<FileCut>), StoreError> {
        let source = self.cut(
            &self.source_path,
            crate::candidate_recovery_store::MAX_SEALED_BYTES,
        )?;
        let binding = self.cut(&self.binding_path, MAX_BINDING_SEALED_BYTES)?;
        if let (Some(source), Some(binding)) = (source, binding) {
            if source.inode == binding.inode {
                return Err(StoreError::Identity);
            }
        }
        Ok((source, binding))
    }
}

impl Drop for Lease<'_> {
    /// Unlock explicitly instead of relying on close. The lock belongs to the
    /// open file description, and close releases it only with the last
    /// reference: a process created by any thread while this lease is held
    /// keeps one until it execs or exits. LOCK_UN releases it immediately.
    /// Every acquisition opens its own description, so this never releases
    /// another lease's lock.
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

impl Lease<'_> {
    pub(crate) fn check(&self) -> Result<(), StoreError> {
        if self.poisoned.get() {
            return Err(StoreError::Poisoned);
        }
        self.check_stable()?;
        if self.store.cuts()? != (self.source.get(), self.binding.get()) {
            return Err(StoreError::Identity);
        }
        Ok(())
    }
    fn check_stable(&self) -> Result<(), StoreError> {
        self.store.check_paths()?;
        let metadata = self.lock.metadata().map_err(|_| StoreError::Identity)?;
        private_regular(&metadata, self.store.directory_inode.uid)?;
        if Inode::of(&metadata) != self.store.lock_inode || metadata.len() != 0 {
            return Err(StoreError::Identity);
        }
        Ok(())
    }

    pub(crate) fn load_binding(&self) -> Result<Option<Binding>, StoreError> {
        self.check()?;
        let Some(cut) = self.binding.get() else {
            return Ok(None);
        };
        let file = checked_open(
            &self.store.binding_path,
            self.store.directory_inode.uid,
            false,
        )?;
        if FileCut::of(&file.metadata().map_err(|_| StoreError::Read)?) != cut {
            return Err(StoreError::Identity);
        }
        let mut sealed = Vec::new();
        file.take(MAX_BINDING_SEALED_BYTES as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(|_| StoreError::Read)?;
        let binding = decode_sealed(&sealed, &self.store.binding_seed)?;
        if binding.source_path_sha256 != self.store.path_sha256
            || (binding.lock_dev, binding.lock_ino, binding.lock_uid)
                != (
                    self.store.lock_inode.dev,
                    self.store.lock_inode.ino,
                    self.store.lock_inode.uid,
                )
        {
            return Err(StoreError::Identity);
        }
        self.check()?;
        Ok(Some(binding))
    }

    /// Adoption is explicit: an unbound source may be inspected by the runner,
    /// but binding publication independently authenticates its exact request.
    /// Normal source access always requires this immutable binding first.
    pub(crate) fn create_binding(&self, request_sha256: [u8; 32]) -> Result<Binding, StoreError> {
        if let Some(binding) = self.load_binding()? {
            if binding.request_sha256 != request_sha256 {
                return Err(StoreError::BindingMismatch);
            }
            return Ok(binding);
        }
        if self.source.get().is_some() {
            let existing = self
                .store
                .source
                .load()
                .map_err(StoreError::Source)?
                .ok_or(StoreError::Identity)?;
            self.check()?;
            if crate::candidate_protocol::sha256(&existing.request) != request_sha256 {
                return Err(StoreError::BindingMismatch);
            }
        }
        let binding = Binding {
            source_path_sha256: self.store.path_sha256,
            request_sha256,
            lock_dev: self.store.lock_inode.dev,
            lock_ino: self.store.lock_inode.ino,
            lock_uid: self.store.lock_inode.uid,
        };
        self.publish_binding(binding)?;
        Ok(binding)
    }

    pub(crate) fn source_exists(&self) -> Result<bool, StoreError> {
        self.check()?;
        Ok(self.source.get().is_some())
    }
    /// The explicit Adopt route validates this opaque cut before publishing a
    /// binding. Other modes have no unbound authenticated-read fallback.
    pub(crate) fn inspect_adoption_source(&self) -> Result<Option<Record>, StoreError> {
        if self.load_binding()?.is_some() {
            return Err(StoreError::Exists);
        }
        let record = self.store.source.load().map_err(StoreError::Source)?;
        self.check()?;
        Ok(record)
    }

    pub(crate) fn load_source(&self) -> Result<Option<Record>, StoreError> {
        let binding = self.load_binding()?.ok_or(StoreError::MissingBinding)?;
        let record = self.store.source.load().map_err(StoreError::Source)?;
        self.check()?;
        if record.as_ref().is_some_and(|record| {
            crate::candidate_protocol::sha256(&record.request) != binding.request_sha256
        }) {
            return Err(StoreError::BindingMismatch);
        }
        Ok(record)
    }
    pub(crate) fn create_source(&self, request: &[u8]) -> Result<Record, StoreError> {
        let binding = self.load_binding()?.ok_or(StoreError::MissingBinding)?;
        if crate::candidate_protocol::sha256(request) != binding.request_sha256 {
            return Err(StoreError::BindingMismatch);
        }
        self.check()?;
        if self.source.get().is_some() {
            return Err(StoreError::Exists);
        }
        self.poisoned.set(true);
        let record = self
            .store
            .source
            .create(request)
            .map_err(StoreError::Source)?;
        self.refresh_source(&record)?;
        Ok(record)
    }
    pub(crate) fn advance_source(
        &self,
        expected: &Record,
        next: Record,
    ) -> Result<Record, StoreError> {
        let binding = self.load_binding()?.ok_or(StoreError::MissingBinding)?;
        if crate::candidate_protocol::sha256(&expected.request) != binding.request_sha256
            || crate::candidate_protocol::sha256(&next.request) != binding.request_sha256
        {
            return Err(StoreError::BindingMismatch);
        }
        self.check()?;
        self.poisoned.set(true);
        let record = self
            .store
            .source
            .advance(expected, next)
            .map_err(StoreError::Source)?;
        self.refresh_source(&record)?;
        Ok(record)
    }

    /// Only a successful OWNED store operation may refresh the source cut.
    /// Every error leaves this lease poisoned, including pre-publication errors.
    /// A successful decoded readback must retain binding, parent and lock.
    fn refresh_source(&self, expected: &Record) -> Result<(), StoreError> {
        self.check_stable()
            .map_err(|_| StoreError::AmbiguousWrite)?;
        let (source, binding) = self.store.cuts().map_err(|_| StoreError::AmbiguousWrite)?;
        if binding != self.binding.get() || source.is_none() {
            return Err(StoreError::AmbiguousWrite);
        }
        let loaded = self
            .store
            .source
            .load()
            .map_err(|_| StoreError::AmbiguousWrite)?;
        if loaded.as_ref() != Some(expected) {
            return Err(StoreError::AmbiguousWrite);
        }
        self.check_stable()
            .map_err(|_| StoreError::AmbiguousWrite)?;
        if self.store.cuts().map_err(|_| StoreError::AmbiguousWrite)? != (source, binding) {
            return Err(StoreError::AmbiguousWrite);
        }
        self.source.set(source);
        self.poisoned.set(false);
        let result = self.check();
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    fn publish_binding(&self, binding: Binding) -> Result<(), StoreError> {
        self.check()?;
        // Stop on any error, even before publication. The next invocation must
        // reacquire the unchanged lock and explicitly reconcile actual bytes.
        self.poisoned.set(true);
        if self.store.fail_write.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Write);
        }
        let sealed = crate::snapshot::seal(&encode(binding), &self.store.binding_seed);
        let tmp = temporary_path(&self.store.binding_path)?;
        let mut file = private_create(&tmp)?;
        let result = (|| {
            private_regular(
                &file.metadata().map_err(|_| StoreError::Write)?,
                self.store.directory_inode.uid,
            )?;
            file.write_all(&sealed).map_err(|_| StoreError::Write)?;
            file.sync_all().map_err(|_| StoreError::Write)?;
            self.check_stable()?;
            if self.store.cuts()? != (self.source.get(), self.binding.get()) {
                return Err(StoreError::Identity);
            }
            if self.store.fail_rename.swap(false, Ordering::SeqCst) {
                return Err(StoreError::Write);
            }
            std::fs::hard_link(&tmp, &self.store.binding_path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    StoreError::Exists
                } else {
                    StoreError::Write
                }
            })?;
            // From publication onward, all failed acknowledgements are ambiguous.
            std::fs::remove_file(&tmp).map_err(|_| StoreError::AmbiguousWrite)?;
            let metadata = std::fs::symlink_metadata(&self.store.binding_path)
                .map_err(|_| StoreError::AmbiguousWrite)?;
            private_regular(&metadata, self.store.directory_inode.uid)
                .map_err(|_| StoreError::AmbiguousWrite)?;
            let written = file.metadata().map_err(|_| StoreError::AmbiguousWrite)?;
            if Inode::of(&metadata) != Inode::of(&written) || metadata.len() != sealed.len() as u64
            {
                return Err(StoreError::AmbiguousWrite);
            }
            self.check_stable()
                .map_err(|_| StoreError::AmbiguousWrite)?;
            let cuts = self.store.cuts().map_err(|_| StoreError::AmbiguousWrite)?;
            if cuts.0 != self.source.get() || cuts.1 != Some(FileCut::of(&metadata)) {
                return Err(StoreError::AmbiguousWrite);
            }
            if self.store.fail_directory_sync.swap(false, Ordering::SeqCst) {
                return Err(StoreError::AmbiguousWrite);
            }
            self.store
                .directory
                .sync_all()
                .map_err(|_| StoreError::AmbiguousWrite)?;
            self.binding.set(cuts.1);
            self.poisoned.set(false);
            if self
                .load_binding()
                .map_err(|_| StoreError::AmbiguousWrite)?
                != Some(binding)
            {
                self.poisoned.set(true);
                return Err(StoreError::AmbiguousWrite);
            }
            Ok(())
        })();
        let _ = std::fs::remove_file(&tmp);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }
}

/// Fixed domain, big-endian u32 byte lengths, then little-endian physical
/// identity fields and the allowed ASCII basename. No parent spelling enters
/// the namespace; dev/ino/uid is taken from the checked open private directory.
fn lane_sha256(parent: Inode, basename: &str) -> [u8; 32] {
    let mut framed = Vec::with_capacity(LANE_DOMAIN.len() + 4 * 4 + 8 + 8 + 4 + basename.len());
    framed.extend_from_slice(LANE_DOMAIN);
    for field in [
        parent.dev.to_le_bytes().as_slice(),
        parent.ino.to_le_bytes().as_slice(),
        parent.uid.to_le_bytes().as_slice(),
        basename.as_bytes(),
    ] {
        framed.extend_from_slice(&(field.len() as u32).to_be_bytes());
        framed.extend_from_slice(field);
    }
    crate::candidate_protocol::sha256(&framed)
}

fn encode(binding: Binding) -> Vec<u8> {
    let mut plain = Vec::with_capacity(PLAIN_BYTES);
    plain.extend_from_slice(MAGIC);
    plain.push(VERSION);
    plain.extend_from_slice(DOMAIN);
    plain.extend_from_slice(&binding.source_path_sha256);
    plain.extend_from_slice(&binding.request_sha256);
    plain.extend_from_slice(&binding.lock_dev.to_le_bytes());
    plain.extend_from_slice(&binding.lock_ino.to_le_bytes());
    plain.extend_from_slice(&binding.lock_uid.to_le_bytes());
    plain
}
fn decode(plain: &[u8]) -> Result<Binding, StoreError> {
    if plain.len() > PLAIN_BYTES {
        return Err(StoreError::Bounds);
    }
    if plain.len() != PLAIN_BYTES {
        return Err(StoreError::Malformed);
    }
    if &plain[..8] != MAGIC || plain[8] != VERSION {
        return Err(StoreError::Version);
    }
    let offset = 9 + DOMAIN.len();
    if &plain[9..offset] != DOMAIN {
        return Err(StoreError::Version);
    }
    let binding = Binding {
        source_path_sha256: plain[offset..offset + 32].try_into().unwrap(),
        request_sha256: plain[offset + 32..offset + 64].try_into().unwrap(),
        lock_dev: u64::from_le_bytes(plain[offset + 64..offset + 72].try_into().unwrap()),
        lock_ino: u64::from_le_bytes(plain[offset + 72..offset + 80].try_into().unwrap()),
        lock_uid: u32::from_le_bytes(plain[offset + 80..offset + 84].try_into().unwrap()),
    };
    if binding.lock_ino == 0 {
        return Err(StoreError::Malformed);
    }
    Ok(binding)
}
fn decode_sealed(bytes: &[u8], seed: &[u8; 32]) -> Result<Binding, StoreError> {
    if bytes.len() > MAX_BINDING_SEALED_BYTES {
        return Err(StoreError::Bounds);
    }
    let plain = crate::snapshot::open(bytes, seed).map_err(|_| StoreError::Authentication)?;
    decode(&plain)
}

fn private_directory(metadata: &Metadata) -> Result<(), StoreError> {
    if !metadata.is_dir() {
        return Err(StoreError::Path);
    }
    if metadata.mode() & 0o7777 != 0o700 {
        return Err(StoreError::Permissions);
    }
    Ok(())
}
fn private_regular(metadata: &Metadata, owner: u32) -> Result<(), StoreError> {
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(StoreError::Identity);
    }
    if metadata.mode() & 0o7777 != 0o600 || metadata.uid() != owner {
        return Err(StoreError::Permissions);
    }
    Ok(())
}
fn private_create(path: &Path) -> Result<File, StoreError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                StoreError::Exists
            } else {
                StoreError::Write
            }
        })
}
fn checked_open(path: &Path, owner: u32, write: bool) -> Result<File, StoreError> {
    let before = std::fs::symlink_metadata(path).map_err(|_| StoreError::Read)?;
    private_regular(&before, owner)?;
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .open(path)
        .map_err(|_| StoreError::Read)?;
    let opened = file.metadata().map_err(|_| StoreError::Read)?;
    private_regular(&opened, owner)?;
    if Inode::of(&before) != Inode::of(&opened) {
        return Err(StoreError::Identity);
    }
    Ok(file)
}
fn temporary_path(path: &Path) -> Result<PathBuf, StoreError> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random).map_err(|_| StoreError::Write)?;
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp.");
    name.push(
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    Ok(PathBuf::from(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_recovery_store::{Stage, StoreError as SourceError};
    use std::cell::RefCell;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    thread_local! {
        static DUPLICATES: RefCell<Option<Vec<File>>> = const { RefCell::new(None) };
    }

    /// `try_lease` calls this as soon as it holds the lock. While a test on this
    /// thread collects duplicates, keep one more reference to the locked open
    /// file description, as a process created at that moment would.
    pub(super) fn observe_locked(lock: &File) {
        DUPLICATES.with(|slot| {
            if let Some(held) = slot.borrow_mut().as_mut() {
                held.push(lock.try_clone().unwrap());
            }
        });
    }

    /// Run `f` and return, with its value, a duplicate of every lock that
    /// `try_lease` took on this thread meanwhile. The duplicates stay open
    /// until the caller drops them.
    fn holding_duplicates<T>(f: impl FnOnce() -> T) -> (T, Vec<File>) {
        struct Disarm;
        impl Drop for Disarm {
            fn drop(&mut self) {
                DUPLICATES.with(|slot| slot.borrow_mut().take());
            }
        }
        DUPLICATES.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
        let _disarm = Disarm;
        let value = f();
        let held = DUPLICATES.with(|slot| slot.borrow_mut().take());
        (value, held.unwrap_or_default())
    }

    const SEED: [u8; 32] = [0x62; 32];
    const REQUEST: &[u8] = b"exact immutable offline candidate request";
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).unwrap();
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = std::env::temp_dir().join(format!("arcora-preparation-store-{suffix}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path.canonicalize().unwrap())
        }
        fn path(&self) -> PathBuf {
            self.0.join("prepared.dpcint4")
        }
        fn store(&self) -> CoordinationStore {
            CoordinationStore::new(self.path(), SEED).unwrap()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn hash() -> [u8; 32] {
        crate::candidate_protocol::sha256(REQUEST)
    }
    fn establish(store: &CoordinationStore) -> Record {
        let lease = store.try_lease().unwrap();
        lease.create_binding(hash()).unwrap();
        lease.create_source(REQUEST).unwrap()
    }
    fn pending(record: &Record) -> Record {
        Record {
            stage: Stage::ClockPending,
            ..record.clone()
        }
    }
    fn replace(path: &Path, bytes: &[u8]) {
        let tmp = temporary_path(path).unwrap();
        let mut file = private_create(&tmp).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        std::fs::rename(tmp, path).unwrap();
    }

    #[test]
    fn preparation_store_deterministic_lane_and_private_canonical_paths() {
        let dir = Scratch::new();
        let first = dir.store();
        let second = dir.store();
        assert_eq!(first.binding_path(), second.binding_path());
        assert_eq!(first.lock_path(), second.lock_path());
        assert_eq!(first.source_path(), dir.path());
        let parent = Inode::of(&std::fs::symlink_metadata(&dir.0).unwrap());
        let lane = lane_sha256(parent, "prepared.dpcint4");
        // Same physical identity has one namespace regardless of a parent's
        // spelling; a different source name or physical parent has another.
        assert_eq!(lane, lane_sha256(parent, "prepared.dpcint4"));
        assert_ne!(lane, lane_sha256(parent, "other.dpcint4"));
        for changed in [
            Inode {
                dev: parent.dev ^ 1,
                ..parent
            },
            Inode {
                ino: parent.ino ^ 1,
                ..parent
            },
            Inode {
                uid: parent.uid ^ 1,
                ..parent
            },
        ] {
            assert_ne!(lane, lane_sha256(changed, "prepared.dpcint4"));
        }
        let lease = first.try_lease().unwrap();
        assert!(matches!(second.try_lease(), Err(StoreError::Busy)));
        let other = CoordinationStore::new(dir.0.join("other.dpcint4"), SEED).unwrap();
        assert_ne!(first.lock_path(), other.lock_path());
        other.try_lease().unwrap().check().unwrap();
        assert_eq!(lease.load_binding(), Ok(None));
        assert!(matches!(
            CoordinationStore::new(dir.0.join(".").join("prepared.dpcint4"), SEED),
            Err(StoreError::Path)
        ));
        let alias = dir.0.join("alias");
        std::os::unix::fs::symlink(&dir.0, &alias).unwrap();
        assert!(matches!(
            CoordinationStore::new(alias.join("prepared.dpcint4"), SEED),
            Err(StoreError::Path)
        ));
        assert!(matches!(
            CoordinationStore::new(dir.0.join(".dpcreg1-fake.binding"), SEED),
            Err(StoreError::Path)
        ));
        assert!(matches!(
            CoordinationStore::new(PathBuf::from("relative.dpcint4"), SEED),
            Err(StoreError::Path)
        ));
    }

    /// Any process created while a lease is held (by this or any other thread)
    /// keeps a reference to the lease's open file description until it execs
    /// or exits. Here a duplicate descriptor stands in for that reference.
    /// Dropping the lease must still release the lock immediately, for the same
    /// handle and for an independent one.
    #[test]
    fn preparation_store_lease_release_does_not_wait_for_duplicate_descriptors() {
        let dir = Scratch::new();
        let store = dir.store();
        let peer = dir.store();
        let lease = store.try_lease().unwrap();
        let duplicate = lease.lock.try_clone().unwrap();
        assert!(matches!(peer.try_lease(), Err(StoreError::Busy)));
        drop(lease);
        let relet = store.try_lease().unwrap();
        assert!(matches!(peer.try_lease(), Err(StoreError::Busy)));
        drop(relet);
        assert_eq!(peer.try_lease().unwrap().load_binding(), Ok(None));
        drop(duplicate);
    }

    /// A refusal after `try_lease` has taken the lock must release it as well,
    /// while another reference to the locked description is still open. Case 0
    /// refuses when the lease takes its cuts, case 1 when it loads the binding.
    #[test]
    fn preparation_store_refusals_after_locking_release_the_lock() {
        for case in 0..2 {
            let dir = Scratch::new();
            let store = dir.store();
            let peer = dir.store();
            let (path, expected) = if case == 0 {
                private_create(store.source_path())
                    .unwrap()
                    .set_len(crate::candidate_recovery_store::MAX_SEALED_BYTES as u64 + 1)
                    .unwrap();
                (store.source_path(), StoreError::Bounds)
            } else {
                replace(store.binding_path(), b"not a sealed binding");
                (store.binding_path(), StoreError::Authentication)
            };
            let (refused, duplicates) = holding_duplicates(|| store.try_lease().map(|_| ()));
            assert_eq!(refused, Err(expected));
            assert_eq!(duplicates.len(), 1, "the refusal must come after locking");
            assert_eq!(peer.try_lease().map(|_| ()), Err(expected));
            std::fs::remove_file(path).unwrap();
            assert_eq!(peer.try_lease().unwrap().load_binding(), Ok(None));
            drop(duplicates);
        }
    }

    #[test]
    fn preparation_store_uppercase_source_basename_cannot_create_another_lane() {
        let dir = Scratch::new();
        let holder = dir.store();
        establish(&holder);
        let lease = holder.try_lease().unwrap();
        let alias = dir.0.join("PREPARED.DPCINT4");
        // The new coordinator namespace must reject uppercase universally,
        // including on Linux where this spelling names a separate file.
        assert!(matches!(
            CoordinationStore::new(alias, SEED),
            Err(StoreError::Path)
        ));
        lease.check().unwrap();
    }

    #[test]
    fn preparation_store_parent_case_alias_cannot_acquire_second_physical_lease() {
        let dir = Scratch::new();
        let upper_name = dir
            .0
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_uppercase();
        let alias_parent = dir.0.parent().unwrap().join(upper_name);
        let original = Inode::of(&std::fs::symlink_metadata(&dir.0).unwrap());
        let alias = match std::fs::symlink_metadata(&alias_parent) {
            Ok(metadata) if Inode::of(&metadata) == original => alias_parent,
            _ => {
                println!("PREPARATION_PARENT_CASE_ALIAS_UNAVAILABLE: case-sensitive filesystem; uppercase basename namespace policy remains unconditional");
                return;
            }
        };
        let holder = dir.store();
        establish(&holder);
        let lease = holder.try_lease().unwrap();
        let original_lock = Inode::of(&std::fs::symlink_metadata(holder.lock_path()).unwrap());
        match CoordinationStore::new(alias.join("prepared.dpcint4"), SEED) {
            Err(StoreError::Path) => {
                println!(
                    "PREPARATION_PARENT_CASE_ALIAS_REJECTED: Rust canonical parent spelling check"
                );
            }
            Ok(peer) => {
                assert_eq!(
                    Inode::of(&std::fs::symlink_metadata(peer.lock_path()).unwrap()),
                    original_lock,
                    "a physical parent case alias created a second stable lock inode"
                );
                assert!(matches!(peer.try_lease(), Err(StoreError::Busy)));
            }
            Err(error) => panic!(
                "parent case alias should reject Path or share the physical lease, got {error:?}"
            ),
        }
        lease.check().unwrap();
    }

    #[test]
    fn preparation_store_binding_fixed_format_domain_authentication_and_identity() {
        let dir = Scratch::new();
        let store = dir.store();
        let binding = store.try_lease().unwrap().create_binding(hash()).unwrap();
        let plain = encode(binding);
        assert_eq!(plain.len(), PLAIN_BYTES);
        assert_eq!(decode(&plain), Ok(binding));
        for size in 0..PLAIN_BYTES {
            assert!(decode(&plain[..size]).is_err());
        }
        let mut extra = plain.clone();
        extra.push(0);
        assert_eq!(decode(&extra), Err(StoreError::Bounds));
        for offset in [0, 8, 9] {
            let mut bad = plain.clone();
            bad[offset] ^= 1;
            assert_eq!(decode(&bad), Err(StoreError::Version));
        }
        let mut bad = binding;
        bad.lock_ino = 0;
        assert_eq!(decode(&encode(bad)), Err(StoreError::Malformed));
        let sealed = std::fs::read(store.binding_path()).unwrap();
        assert_eq!(decode_sealed(&sealed, &store.binding_seed), Ok(binding));
        assert_eq!(
            decode_sealed(&sealed, &SEED),
            Err(StoreError::Authentication)
        );
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            decode_sealed(&tampered, &store.binding_seed),
            Err(StoreError::Authentication)
        );
        assert_eq!(
            decode_sealed(&vec![0; MAX_BINDING_SEALED_BYTES + 1], &store.binding_seed),
            Err(StoreError::Bounds)
        );
        for mutate_path in [false, true] {
            let mut foreign = binding;
            if mutate_path {
                foreign.source_path_sha256[0] ^= 1;
            } else {
                foreign.lock_ino += 1;
            }
            replace(
                store.binding_path(),
                &crate::snapshot::seal(&encode(foreign), &store.binding_seed),
            );
            assert!(matches!(store.try_lease(), Err(StoreError::Identity)));
        }
    }

    #[test]
    fn preparation_store_explicit_existing_source_adoption_pins_exact_request() {
        let dir = Scratch::new();
        let existing = RecoveryStore::new(dir.path(), SEED);
        let expected = existing.create(REQUEST).unwrap();
        let source_bytes = std::fs::read(dir.path()).unwrap();
        let store = dir.store();
        let lease = store.try_lease().unwrap();
        assert_eq!(lease.load_source(), Err(StoreError::MissingBinding));
        assert_eq!(lease.source_exists(), Ok(true));
        assert_eq!(lease.inspect_adoption_source(), Ok(Some(expected.clone())));
        assert_eq!(
            lease.create_binding([3; 32]),
            Err(StoreError::BindingMismatch)
        );
        assert!(!store.binding_path().exists());
        let binding = lease.create_binding(hash()).unwrap();
        assert_eq!(lease.load_source(), Ok(Some(expected)));
        assert_eq!(lease.inspect_adoption_source(), Err(StoreError::Exists));
        let bytes = std::fs::read(store.binding_path()).unwrap();
        store.fail_next_binding_write();
        assert_eq!(lease.create_binding(hash()), Ok(binding));
        assert_eq!(
            lease.create_binding([4; 32]),
            Err(StoreError::BindingMismatch)
        );
        assert_eq!(std::fs::read(store.binding_path()).unwrap(), bytes);
        assert_eq!(std::fs::read(dir.path()).unwrap(), source_bytes);
        lease.check().unwrap();
    }

    #[test]
    fn preparation_store_owned_adjacent_writes_refresh_only_exact_source_cut() {
        let dir = Scratch::new();
        let store = dir.store();
        let lease = store.try_lease().unwrap();
        assert_eq!(
            lease.create_source(REQUEST),
            Err(StoreError::MissingBinding)
        );
        assert_eq!(lease.source_exists(), Ok(false));
        assert_eq!(lease.inspect_adoption_source(), Ok(None));
        lease.create_binding(hash()).unwrap();
        assert_eq!(
            lease.create_source(b"different request"),
            Err(StoreError::BindingMismatch)
        );
        assert!(!dir.path().exists());
        assert_eq!(lease.load_source(), Ok(None));
        let record = lease.create_source(REQUEST).unwrap();
        lease.check().unwrap();
        assert_eq!(lease.load_source(), Ok(Some(record.clone())));
        assert_eq!(lease.create_source(REQUEST), Err(StoreError::Exists));
        let next = pending(&record);
        assert_eq!(
            lease.advance_source(&record, next.clone()),
            Ok(next.clone())
        );
        let raw = std::fs::read(dir.path()).unwrap();
        store.fail_next_source_write();
        assert_eq!(
            lease.advance_source(&record, next.clone()),
            Ok(next.clone())
        );
        assert_eq!(std::fs::read(dir.path()).unwrap(), raw);
        assert_eq!(lease.load_source(), Ok(Some(next.clone())));
        let failed = Record {
            stage: Stage::ClockObserved,
            clock: Some(b"opaque observed clock".to_vec()),
            ..next.clone()
        };
        assert_eq!(
            lease.advance_source(&next, failed),
            Err(StoreError::Source(SourceError::Write))
        );
        assert_eq!(lease.check(), Err(StoreError::Poisoned));
        assert_eq!(std::fs::read(dir.path()).unwrap(), raw);
    }

    #[test]
    fn preparation_store_binding_failures_poison_without_rollback() {
        for hook in 0..3 {
            let dir = Scratch::new();
            let store = dir.store();
            let lease = store.try_lease().unwrap();
            match hook {
                0 => store.fail_next_binding_write(),
                1 => store.fail_next_binding_rename(),
                _ => store.fail_next_binding_directory_sync(),
            }
            let expected = if hook == 2 {
                StoreError::AmbiguousWrite
            } else {
                StoreError::Write
            };
            assert_eq!(lease.create_binding(hash()), Err(expected));
            assert_eq!(lease.check(), Err(StoreError::Poisoned));
            assert!(!dir.path().exists());
            let bytes = std::fs::read(store.binding_path()).ok();
            assert_eq!(bytes.is_some(), hook == 2);
            drop(lease);
            let reloaded = store.try_lease().unwrap();
            let established = reloaded.load_binding().unwrap();
            assert_eq!(established.is_some(), hook == 2);
            reloaded.create_binding(hash()).unwrap();
            if let Some(bytes) = bytes {
                assert_eq!(std::fs::read(store.binding_path()).unwrap(), bytes);
            }
            reloaded.check().unwrap();
        }
    }

    #[test]
    fn preparation_store_source_failures_preserve_or_expose_exact_new_cut() {
        for create in [true, false] {
            for hook in 0..3 {
                let dir = Scratch::new();
                let store = dir.store();
                let lease = store.try_lease().unwrap();
                lease.create_binding(hash()).unwrap();
                let record = if create {
                    None
                } else {
                    Some(lease.create_source(REQUEST).unwrap())
                };
                let before = std::fs::read(dir.path()).ok();
                match hook {
                    0 => store.fail_next_source_write(),
                    1 => store.fail_next_source_rename(),
                    _ => store.fail_next_source_directory_sync(),
                }
                let attempted = match &record {
                    None => lease.create_source(REQUEST),
                    Some(record) => lease.advance_source(record, pending(record)),
                };
                let expected = if hook == 2 {
                    SourceError::AmbiguousWrite
                } else {
                    SourceError::Write
                };
                assert_eq!(attempted, Err(StoreError::Source(expected)));
                assert_eq!(lease.check(), Err(StoreError::Poisoned));
                let published = std::fs::read(dir.path()).ok();
                if hook != 2 {
                    assert_eq!(published, before);
                } else {
                    assert_ne!(published, before);
                }
                drop(lease);
                let recovered = store.try_lease().unwrap().load_source().unwrap();
                match (create, hook) {
                    (true, 2) => assert_eq!(recovered.unwrap().stage, Stage::Intent),
                    (true, _) => assert_eq!(recovered, None),
                    (false, 2) => assert_eq!(recovered.unwrap().stage, Stage::ClockPending),
                    (false, _) => assert_eq!(recovered, record),
                }
                assert_eq!(std::fs::read(dir.path()).ok(), published);
            }
        }
    }

    #[test]
    fn preparation_store_replacements_external_creates_and_stable_lock_loss_refuse() {
        for target in 0..4 {
            let dir = Scratch::new();
            let store = dir.store();
            establish(&store);
            let lease = store.try_lease().unwrap();
            let path = match target {
                0 => store.source_path(),
                1 => store.binding_path(),
                _ => store.lock_path(),
            };
            let bytes = std::fs::read(path).unwrap();
            if target == 3 {
                let mut file = OpenOptions::new().append(true).open(path).unwrap();
                file.write_all(b"changed in place").unwrap();
            } else {
                replace(path, &bytes);
            }
            assert_eq!(lease.check(), Err(StoreError::Identity));
            if target == 2 {
                assert!(matches!(store.try_lease(), Err(StoreError::Identity)));
            }
        }
        let dir = Scratch::new();
        let store = dir.store();
        let lease = store.try_lease().unwrap();
        RecoveryStore::new(dir.path(), SEED)
            .create(REQUEST)
            .unwrap();
        assert_eq!(lease.check(), Err(StoreError::Identity));
        drop(lease);
        let lease = store.try_lease().unwrap();
        lease.create_binding(hash()).unwrap();
        drop(lease);
        let binding = std::fs::read(store.binding_path()).unwrap();
        // Keep the removed inode alive so this recreation test cannot depend
        // on a filesystem reusing its inode number immediately.
        let old_lock = File::open(store.lock_path()).unwrap();
        std::fs::remove_file(store.lock_path()).unwrap();
        assert!(matches!(
            CoordinationStore::new(dir.path(), SEED),
            Err(StoreError::Identity)
        ));
        assert_eq!(std::fs::read(store.binding_path()).unwrap(), binding);
        assert!(!store.lock_path().exists());
        private_create(store.lock_path())
            .unwrap()
            .sync_all()
            .unwrap();
        let reopened = dir.store();
        assert!(matches!(reopened.try_lease(), Err(StoreError::Identity)));
        drop(old_lock);
    }

    #[test]
    fn preparation_store_alias_permissions_bounds_and_parent_replacement_fail_closed() {
        for target in 0..3 {
            let dir = Scratch::new();
            let store = dir.store();
            establish(&store);
            let path = [store.source_path(), store.binding_path(), store.lock_path()][target];
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(store.try_lease(), Err(StoreError::Permissions)));
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let duplicate = dir.0.join("hardlink");
            std::fs::hard_link(path, &duplicate).unwrap();
            assert!(matches!(store.try_lease(), Err(StoreError::Identity)));
            std::fs::remove_file(&duplicate).unwrap();
            let saved = dir.0.join("saved");
            std::fs::rename(path, &saved).unwrap();
            std::os::unix::fs::symlink(&saved, path).unwrap();
            assert!(matches!(store.try_lease(), Err(StoreError::Identity)));
        }
        for binding in [false, true] {
            let dir = Scratch::new();
            let store = dir.store();
            let (path, size) = if binding {
                (store.binding_path(), MAX_BINDING_SEALED_BYTES)
            } else {
                (
                    store.source_path(),
                    crate::candidate_recovery_store::MAX_SEALED_BYTES,
                )
            };
            private_create(path)
                .unwrap()
                .set_len(size as u64 + 1)
                .unwrap();
            assert!(matches!(store.try_lease(), Err(StoreError::Bounds)));
        }
        let dir = Scratch::new();
        let store = dir.store();
        establish(&store);
        let lease = store.try_lease().unwrap();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(lease.check(), Err(StoreError::Permissions));
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moved = dir.0.with_extension("moved");
        std::fs::rename(&dir.0, &moved).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir.0)
            .unwrap();
        assert!(lease.check().is_err());
        std::fs::remove_dir_all(&dir.0).unwrap();
        std::fs::rename(moved, &dir.0).unwrap();
    }
}
