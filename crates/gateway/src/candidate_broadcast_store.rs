//! Bounded authenticated broadcast cuts for the OFFLINE harness only.
//! A lease holds an advisory local file lock through validation and callbacks.
//! Cooperating writers use one private canonical directory and never replace,
//! rename or unlink its stable lock inode. This is not a chain submission lock,
//! a hostile same-user filesystem sandbox, or an exactly-once network guarantee.
use std::{
    cell::Cell,
    fs::{File, Metadata, OpenOptions, TryLockError},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

const MAGIC: &[u8; 8] = b"DPCBTX1\0";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 8 + 1 + 1 + 4 + 4 + 8 + 8 + 4;
pub(crate) const MAX_PLAN_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_OUTCOME_BYTES: usize = 64 * 1024;
const MAX_PLAIN_BYTES: usize = HEADER_BYTES + MAX_PLAN_BYTES + MAX_OUTCOME_BYTES;
pub(crate) const MAX_SEALED_BYTES: usize = MAX_PLAIN_BYTES + 72;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) plan: Vec<u8>,
    pub(crate) outcome: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreError {
    Bounds,
    Version,
    Malformed,
    Authentication,
    Read,
    Write,
    /// The cut may already be published. Drop the lease; explicitly reload and
    /// reconcile in another invocation. Never restore old bytes or retry a call.
    AmbiguousWrite,
    Exists,
    Missing,
    Conflict,
    PlanMismatch,
    OutcomeMismatch,
    Busy,
    Path,
    Permissions,
    Identity,
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

pub(crate) struct BroadcastStore {
    path: PathBuf,
    lock_path: PathBuf,
    parent: PathBuf,
    directory: File,
    directory_inode: Inode,
    lock_inode: Inode,
    seed: [u8; 32],
    fail_write: AtomicBool,
    fail_rename: AtomicBool,
    fail_directory_sync: AtomicBool,
}

pub(crate) struct Lease<'a> {
    store: &'a BroadcastStore,
    lock: File,
    target: Cell<Option<FileCut>>,
    ambiguous: Cell<bool>,
}

impl BroadcastStore {
    /// The caller creates a private 0700 directory first. Require its canonical
    /// absolute spelling and a short ASCII basename; aliases are not stores.
    /// A fresh exclusive owner probe establishes the effective creator's uid
    /// without a new dependency or an unsafe uid syscall.
    pub(crate) fn new(path: PathBuf, seed: [u8; 32]) -> Result<Self, StoreError> {
        let parent = path.parent().ok_or(StoreError::Path)?.to_path_buf();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(StoreError::Path)?;
        if !path.is_absolute()
            || parent.join(name).as_os_str() != path.as_os_str()
            || name.is_empty()
            || name.len() > 128
            || name == "."
            || name == ".."
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || name.ends_with(".lock")
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

        // Exclusive creation yields the effective owner's uid even when this
        // directory belongs to a different user accessible to a privileged uid.
        let probe = temporary_path(&path)?;
        let probe_file = private_create(&probe)?;
        let probe_owner = probe_file.metadata().map_err(|_| StoreError::Write)?.uid();
        drop(probe_file);
        std::fs::remove_file(&probe).map_err(|_| StoreError::Write)?;
        if probe_owner != directory_inode.uid {
            return Err(StoreError::Permissions);
        }

        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        if matches!(
            std::fs::symlink_metadata(&lock_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ) && std::fs::symlink_metadata(&path).is_ok()
        {
            // Losing a lock beside an established cut cannot turn into a new
            // lock domain. An authenticated cut also pins the original inode.
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
        let store = Self {
            path,
            lock_path,
            parent,
            directory,
            directory_inode,
            lock_inode: Inode::of(&metadata),
            seed,
            fail_write: AtomicBool::new(false),
            fail_rename: AtomicBool::new(false),
            fail_directory_sync: AtomicBool::new(false),
        };
        store.check_paths()?;
        store.target_cut()?;
        Ok(store)
    }

    /// A new descriptor per acquisition avoids platform-dependent reentrant
    /// locking of a cloned/already-locked descriptor. Never wait behind a call.
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
            target: Cell::new(None),
            ambiguous: Cell::new(false),
        };
        self.check_paths()?;
        lease.target.set(self.target_cut()?);
        #[cfg(test)]
        tests::before_first_check();
        lease.check()?;
        Ok(lease)
    }

    pub(crate) fn fail_next_write(&self) {
        self.fail_write.store(true, Ordering::SeqCst);
    }
    pub(crate) fn fail_next_rename(&self) {
        self.fail_rename.store(true, Ordering::SeqCst);
    }
    pub(crate) fn fail_next_directory_sync(&self) {
        self.fail_directory_sync.store(true, Ordering::SeqCst);
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

    fn target_cut(&self) -> Result<Option<FileCut>, StoreError> {
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Read),
        };
        private_regular(&metadata, self.directory_inode.uid)?;
        if Inode::of(&metadata) == self.lock_inode {
            return Err(StoreError::Identity);
        }
        if metadata.len() > MAX_SEALED_BYTES as u64 {
            return Err(StoreError::Bounds);
        }
        Ok(Some(FileCut::of(&metadata)))
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
    /// Dispatcher calls this immediately before every callback. Detect path,
    /// inode, permission and in-place cut changes since acquisition/publication.
    pub(crate) fn check(&self) -> Result<(), StoreError> {
        if self.ambiguous.get() {
            return Err(StoreError::AmbiguousWrite);
        }
        self.store.check_paths()?;
        let lock = self.lock.metadata().map_err(|_| StoreError::Identity)?;
        private_regular(&lock, self.store.directory_inode.uid)?;
        if Inode::of(&lock) != self.store.lock_inode || lock.len() != 0 {
            return Err(StoreError::Identity);
        }
        if self.store.target_cut()? != self.target.get() {
            return Err(StoreError::Identity);
        }
        Ok(())
    }

    pub(crate) fn load(&self) -> Result<Option<Record>, StoreError> {
        self.check()?;
        let Some(cut) = self.target.get() else {
            return Ok(None);
        };
        let file = checked_open(&self.store.path, self.store.directory_inode.uid, false)?;
        if FileCut::of(&file.metadata().map_err(|_| StoreError::Read)?) != cut {
            return Err(StoreError::Identity);
        }
        let mut sealed = Vec::new();
        file.take(MAX_SEALED_BYTES as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(|_| StoreError::Read)?;
        let (record, lock_inode) = decode_sealed_with_inode(&sealed, &self.store.seed)?;
        if lock_inode != self.store.lock_inode {
            return Err(StoreError::Identity);
        }
        self.check()?;
        Ok(Some(record))
    }

    pub(crate) fn create_pending(&self, plan: &[u8]) -> Result<Record, StoreError> {
        bounded_nonempty(plan, MAX_PLAN_BYTES)?;
        self.check()?;
        if self.target.get().is_some() {
            return Err(StoreError::Exists);
        }
        let record = Record {
            plan: plan.to_vec(),
            outcome: None,
        };
        self.write(&record, true)?;
        Ok(record)
    }

    /// Exact Pending -> Outcome only. Identical already-published outcomes are
    /// idempotent without rewriting; neither plan nor outcome can be replaced.
    pub(crate) fn finish(&self, expected: &Record, outcome: &[u8]) -> Result<Record, StoreError> {
        validate(expected)?;
        bounded_nonempty(outcome, MAX_OUTCOME_BYTES)?;
        let old = self.load()?.ok_or(StoreError::Missing)?;
        if old.plan != expected.plan {
            return Err(StoreError::PlanMismatch);
        }
        if let Some(established) = &old.outcome {
            if established == outcome {
                return Ok(old);
            }
            return Err(StoreError::OutcomeMismatch);
        }
        if old != *expected {
            return Err(StoreError::Conflict);
        }
        let next = Record {
            plan: old.plan,
            outcome: Some(outcome.to_vec()),
        };
        self.write(&next, false)?;
        Ok(next)
    }

    fn write(&self, record: &Record, fresh: bool) -> Result<(), StoreError> {
        self.check()?;
        let plain = encode(record, self.store.lock_inode)?;
        if self.store.fail_write.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Write);
        }
        let sealed = crate::snapshot::seal(&plain, &self.store.seed);
        let tmp = temporary_path(&self.store.path)?;
        let mut file = private_create(&tmp)?;
        let result = (|| {
            private_regular(
                &file.metadata().map_err(|_| StoreError::Write)?,
                self.store.directory_inode.uid,
            )?;
            file.write_all(&sealed).map_err(|_| StoreError::Write)?;
            file.sync_all().map_err(|_| StoreError::Write)?;
            self.check()?;
            if self.store.fail_rename.swap(false, Ordering::SeqCst) {
                return Err(StoreError::Write);
            }
            if fresh {
                std::fs::hard_link(&tmp, &self.store.path).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        StoreError::Exists
                    } else {
                        StoreError::Write
                    }
                })?;
                self.ambiguous.set(true);
                std::fs::remove_file(&tmp).map_err(|_| StoreError::AmbiguousWrite)?;
            } else {
                std::fs::rename(&tmp, &self.store.path).map_err(|_| StoreError::Write)?;
                self.ambiguous.set(true);
            }
            // Publication is already visible. Every failure after this point is
            // ambiguous, including target validation or directory fsync.
            let metadata = std::fs::symlink_metadata(&self.store.path)
                .map_err(|_| StoreError::AmbiguousWrite)?;
            private_regular(&metadata, self.store.directory_inode.uid)
                .map_err(|_| StoreError::AmbiguousWrite)?;
            let written = file.metadata().map_err(|_| StoreError::AmbiguousWrite)?;
            if Inode::of(&metadata) != Inode::of(&written) || metadata.len() != sealed.len() as u64
            {
                return Err(StoreError::AmbiguousWrite);
            }
            self.store
                .check_paths()
                .map_err(|_| StoreError::AmbiguousWrite)?;
            if self.store.fail_directory_sync.swap(false, Ordering::SeqCst) {
                return Err(StoreError::AmbiguousWrite);
            }
            self.store
                .directory
                .sync_all()
                .map_err(|_| StoreError::AmbiguousWrite)?;
            self.target.set(Some(FileCut::of(&metadata)));
            self.ambiguous.set(false);
            Ok(())
        })();
        // Only our exclusive temporary is eligible for cleanup. A published
        // target and the persistent lock are never rolled back or removed.
        let _ = std::fs::remove_file(&tmp);
        result
    }
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
fn bounded_nonempty(bytes: &[u8], bound: usize) -> Result<(), StoreError> {
    if bytes.is_empty() || bytes.len() > bound {
        return Err(StoreError::Bounds);
    }
    Ok(())
}
fn validate(record: &Record) -> Result<(), StoreError> {
    bounded_nonempty(&record.plan, MAX_PLAN_BYTES)?;
    if let Some(outcome) = &record.outcome {
        bounded_nonempty(outcome, MAX_OUTCOME_BYTES)?;
    }
    Ok(())
}
fn encode(record: &Record, lock_inode: Inode) -> Result<Vec<u8>, StoreError> {
    validate(record)?;
    let outcome = record.outcome.as_deref().unwrap_or_default();
    let mut plain = Vec::with_capacity(HEADER_BYTES + record.plan.len() + outcome.len());
    plain.extend_from_slice(MAGIC);
    plain.push(VERSION);
    plain.push(u8::from(record.outcome.is_some()));
    plain.extend_from_slice(&(record.plan.len() as u32).to_le_bytes());
    plain.extend_from_slice(&(outcome.len() as u32).to_le_bytes());
    plain.extend_from_slice(&lock_inode.dev.to_le_bytes());
    plain.extend_from_slice(&lock_inode.ino.to_le_bytes());
    plain.extend_from_slice(&lock_inode.uid.to_le_bytes());
    plain.extend_from_slice(&record.plan);
    plain.extend_from_slice(outcome);
    Ok(plain)
}
fn decode(plain: &[u8]) -> Result<(Record, Inode), StoreError> {
    if plain.len() > MAX_PLAIN_BYTES {
        return Err(StoreError::Bounds);
    }
    if plain.len() < HEADER_BYTES {
        return Err(StoreError::Malformed);
    }
    if &plain[..8] != MAGIC || plain[8] != VERSION {
        return Err(StoreError::Version);
    }
    let plan_len = u32::from_le_bytes(plain[10..14].try_into().unwrap()) as usize;
    let outcome_len = u32::from_le_bytes(plain[14..18].try_into().unwrap()) as usize;
    if plan_len == 0 || plan_len > MAX_PLAN_BYTES || outcome_len > MAX_OUTCOME_BYTES {
        return Err(StoreError::Bounds);
    }
    if !matches!((plain[9], outcome_len), (0, 0) | (1, 1..)) {
        return Err(StoreError::Malformed);
    }
    // Validate every fixed length and the exact total before allocating payloads.
    if plain.len() != HEADER_BYTES + plan_len + outcome_len {
        return Err(StoreError::Malformed);
    }
    let lock_inode = Inode {
        dev: u64::from_le_bytes(plain[18..26].try_into().unwrap()),
        ino: u64::from_le_bytes(plain[26..34].try_into().unwrap()),
        uid: u32::from_le_bytes(plain[34..38].try_into().unwrap()),
    };
    if lock_inode.ino == 0 {
        return Err(StoreError::Malformed);
    }
    Ok((
        Record {
            plan: plain[HEADER_BYTES..HEADER_BYTES + plan_len].to_vec(),
            outcome: (outcome_len != 0).then(|| plain[HEADER_BYTES + plan_len..].to_vec()),
        },
        lock_inode,
    ))
}

/// Pure bounded authenticated decoder lets mocks inspect the durable callback
/// barrier without reacquiring the already-held cooperative lease.
pub(crate) fn decode_sealed(bytes: &[u8], seed: &[u8; 32]) -> Result<Record, StoreError> {
    decode_sealed_with_inode(bytes, seed).map(|(record, _)| record)
}
fn decode_sealed_with_inode(bytes: &[u8], seed: &[u8; 32]) -> Result<(Record, Inode), StoreError> {
    if bytes.len() > MAX_SEALED_BYTES {
        return Err(StoreError::Bounds);
    }
    let plain = crate::snapshot::open(bytes, seed).map_err(|_| StoreError::Authentication)?;
    decode(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    thread_local! {
        static DUPLICATES: RefCell<Option<Vec<File>>> = const { RefCell::new(None) };
        static BEFORE_FIRST_CHECK: RefCell<Option<Box<dyn FnOnce()>>> =
            const { RefCell::new(None) };
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

    /// `try_lease` calls this after it has read the target's cut and before its
    /// first `Lease::check`. A change a test on this thread set up runs here, as
    /// another writer's could, so only that check can see it.
    pub(super) fn before_first_check() {
        if let Some(change) = BEFORE_FIRST_CHECK.with(|slot| slot.borrow_mut().take()) {
            change();
        }
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

    const TEST_LOCK: Inode = Inode {
        dev: 1,
        ino: 2,
        uid: 3,
    };

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).unwrap();
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = std::env::temp_dir().join(format!("arcora-broadcast-store-{suffix}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path.canonicalize().unwrap())
        }
        fn path(&self) -> PathBuf {
            self.0.join("pending.bin")
        }
        fn store(&self) -> BroadcastStore {
            BroadcastStore::new(self.path(), [7; 32]).unwrap()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn broadcast_store_framing_authentication_and_allocation_bounds() {
        let pending = Record {
            plan: b"exact opaque plan".to_vec(),
            outcome: None,
        };
        let mut finished = pending.clone();
        finished.outcome = Some(b"exact opaque outcome".to_vec());
        for record in [pending.clone(), finished] {
            let plain = encode(&record, TEST_LOCK).unwrap();
            assert_eq!(decode(&plain), Ok((record.clone(), TEST_LOCK)));
            let sealed = crate::snapshot::seal(&plain, &[7; 32]);
            assert_eq!(decode_sealed(&sealed, &[7; 32]), Ok(record));
            assert_eq!(
                decode_sealed(&sealed, &[8; 32]),
                Err(StoreError::Authentication)
            );
            let mut tampered = sealed;
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert_eq!(
                decode_sealed(&tampered, &[7; 32]),
                Err(StoreError::Authentication)
            );
        }
        let plain = encode(&pending, TEST_LOCK).unwrap();
        let mut foreign = plain.clone();
        foreign[..8].copy_from_slice(b"DPCINT4\0");
        assert_eq!(
            decode_sealed(&crate::snapshot::seal(&foreign, &[7; 32]), &[7; 32]),
            Err(StoreError::Version)
        );
        let mut version = plain.clone();
        version[8] = 2;
        assert_eq!(decode(&version), Err(StoreError::Version));
        let mut huge = plain.clone();
        huge[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&huge), Err(StoreError::Bounds));
        let mut bad_outcome = plain.clone();
        bad_outcome[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&bad_outcome), Err(StoreError::Bounds));
        let mut missing_outcome = plain.clone();
        missing_outcome[9] = 1;
        assert_eq!(decode(&missing_outcome), Err(StoreError::Malformed));
        let mut unknown_stage = plain.clone();
        unknown_stage[9] = 2;
        assert_eq!(decode(&unknown_stage), Err(StoreError::Malformed));
        let mut trailing = plain.clone();
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(StoreError::Malformed));
        assert_eq!(
            decode(&plain[..plain.len() - 1]),
            Err(StoreError::Malformed)
        );
        assert_eq!(
            decode(&plain[..HEADER_BYTES - 1]),
            Err(StoreError::Malformed)
        );
        assert_eq!(
            decode_sealed(&vec![0; MAX_SEALED_BYTES + 1], &[7; 32]),
            Err(StoreError::Bounds)
        );
    }

    #[test]
    fn broadcast_store_independent_handle_lease_and_immutable_cas() {
        let dir = Scratch::new();
        let a = dir.store();
        let b = dir.store();
        let inode = Inode::of(&std::fs::metadata(&a.lock_path).unwrap());
        let lease = a.try_lease().unwrap();
        assert!(matches!(a.try_lease(), Err(StoreError::Busy)));
        assert!(matches!(b.try_lease(), Err(StoreError::Busy)));
        assert_eq!(lease.load(), Ok(None));
        assert_eq!(
            lease.finish(
                &Record {
                    plan: b"plan".to_vec(),
                    outcome: None,
                },
                b"outcome"
            ),
            Err(StoreError::Missing)
        );
        assert_eq!(lease.create_pending(&[]), Err(StoreError::Bounds));
        assert_eq!(
            lease.create_pending(&vec![0; MAX_PLAN_BYTES + 1]),
            Err(StoreError::Bounds)
        );
        let pending = lease.create_pending(b"plan").unwrap();
        assert_eq!(lease.create_pending(b"plan"), Err(StoreError::Exists));
        let mut wrong_plan = pending.clone();
        wrong_plan.plan.push(1);
        assert_eq!(
            lease.finish(&wrong_plan, b"outcome"),
            Err(StoreError::PlanMismatch)
        );
        let mut wrong_cut = pending.clone();
        wrong_cut.outcome = Some(b"not the disk cut".to_vec());
        assert_eq!(
            lease.finish(&wrong_cut, b"outcome"),
            Err(StoreError::Conflict)
        );
        assert_eq!(lease.finish(&pending, &[]), Err(StoreError::Bounds));
        assert_eq!(
            lease.finish(&pending, &vec![0; MAX_OUTCOME_BYTES + 1]),
            Err(StoreError::Bounds)
        );
        let finished = lease.finish(&pending, b"outcome").unwrap();
        let disk = std::fs::read(dir.path()).unwrap();
        a.fail_next_write();
        assert_eq!(lease.finish(&pending, b"outcome"), Ok(finished.clone()));
        assert!(a.fail_write.load(Ordering::SeqCst));
        assert_eq!(std::fs::read(dir.path()).unwrap(), disk);
        assert_eq!(
            lease.finish(&pending, b"changed outcome"),
            Err(StoreError::OutcomeMismatch)
        );
        assert_eq!(Inode::of(&std::fs::metadata(&a.lock_path).unwrap()), inode);
        drop(lease);
        assert_eq!(b.try_lease().unwrap().load(), Ok(Some(finished)));
        assert_eq!(Inode::of(&std::fs::metadata(&a.lock_path).unwrap()), inode);
    }

    /// Any process created while a lease is held (by this or any other thread)
    /// inherits a reference to the lease's open file description until it
    /// execs or exits. Dropping the lease must still release the kernel lock
    /// immediately, for the same handle and for an independent one.
    #[test]
    fn broadcast_store_lease_release_does_not_wait_for_inherited_descriptors() {
        struct Reaped(std::process::Child);
        impl Drop for Reaped {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let dir = Scratch::new();
        let store = dir.store();
        let peer = dir.store();
        let lease = store.try_lease().unwrap();
        // The child holds the inherited reference as its stdin; the parent's
        // duplicate closes with the temporary Command at the end of the statement.
        let child = Reaped(
            std::process::Command::new("/bin/sleep")
                .arg("600")
                .stdin(lease.lock.try_clone().unwrap())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert!(matches!(peer.try_lease(), Err(StoreError::Busy)));
        drop(lease);
        let relet = store.try_lease().unwrap();
        assert!(matches!(peer.try_lease(), Err(StoreError::Busy)));
        drop(relet);
        assert_eq!(peer.try_lease().unwrap().load(), Ok(None));
        drop(child);
    }

    /// A refusal after `try_lease` has taken the lock must release it as well,
    /// while another reference to the locked description is still open. Both
    /// cases refuse when the lease reads the target's cut.
    #[test]
    fn broadcast_store_refusals_after_locking_release_the_lock() {
        for case in 0..2 {
            let dir = Scratch::new();
            let store = dir.store();
            let peer = dir.store();
            let expected = if case == 0 {
                private_create(&dir.path())
                    .unwrap()
                    .set_len(MAX_SEALED_BYTES as u64 + 1)
                    .unwrap();
                StoreError::Bounds
            } else {
                std::os::unix::fs::symlink(dir.0.join("elsewhere"), dir.path()).unwrap();
                StoreError::Identity
            };
            let (refused, duplicates) = holding_duplicates(|| store.try_lease().map(|_| ()));
            assert_eq!(refused, Err(expected));
            assert_eq!(duplicates.len(), 1, "the refusal must come after locking");
            assert_eq!(peer.try_lease().map(|_| ()), Err(expected));
            std::fs::remove_file(dir.path()).unwrap();
            assert_eq!(peer.try_lease().unwrap().load(), Ok(None));
            drop(duplicates);
        }
    }

    /// A refusal by the first `Lease::check` inside `try_lease` must release the
    /// lock too, while another reference to the locked description is still
    /// open. The target changes in place after the lease has read its cut.
    #[test]
    fn broadcast_store_first_check_refusal_releases_the_lock() {
        let dir = Scratch::new();
        let store = dir.store();
        let peer = dir.store();
        let pending = store.try_lease().unwrap().create_pending(b"plan").unwrap();
        let target = dir.path();
        BEFORE_FIRST_CHECK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                OpenOptions::new()
                    .write(true)
                    .open(target)
                    .unwrap()
                    .set_modified(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap();
            }))
        });
        let (refused, duplicates) = holding_duplicates(|| store.try_lease().map(|_| ()));
        assert_eq!(refused, Err(StoreError::Identity));
        assert!(
            BEFORE_FIRST_CHECK.with(|slot| slot.borrow().is_none()),
            "the refusal must come from the first check"
        );
        assert_eq!(duplicates.len(), 1, "the refusal must come after locking");
        assert_eq!(peer.try_lease().unwrap().load(), Ok(Some(pending)));
        drop(duplicates);
    }

    #[test]
    fn broadcast_store_prepublication_failures_preserve_previous_bytes() {
        let dir = Scratch::new();
        let store = dir.store();
        let lease = store.try_lease().unwrap();
        store.fail_next_write();
        assert_eq!(lease.create_pending(b"plan"), Err(StoreError::Write));
        assert!(!dir.path().exists());
        store.fail_next_rename();
        assert_eq!(lease.create_pending(b"plan"), Err(StoreError::Write));
        assert!(!dir.path().exists());
        let pending = lease.create_pending(b"plan").unwrap();
        let disk = std::fs::read(dir.path()).unwrap();
        store.fail_next_write();
        assert_eq!(lease.finish(&pending, b"outcome"), Err(StoreError::Write));
        assert_eq!(std::fs::read(dir.path()).unwrap(), disk);
        store.fail_next_rename();
        assert_eq!(lease.finish(&pending, b"outcome"), Err(StoreError::Write));
        assert_eq!(std::fs::read(dir.path()).unwrap(), disk);
        assert_eq!(lease.load(), Ok(Some(pending)));
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[test]
    fn broadcast_store_postpublication_ambiguity_requires_new_lease() {
        let dir = Scratch::new();
        let store = dir.store();
        let lease = store.try_lease().unwrap();
        store.fail_next_directory_sync();
        assert_eq!(
            lease.create_pending(b"plan"),
            Err(StoreError::AmbiguousWrite)
        );
        assert_eq!(lease.check(), Err(StoreError::AmbiguousWrite));
        assert_eq!(lease.load(), Err(StoreError::AmbiguousWrite));
        drop(lease);
        let lease = store.try_lease().unwrap();
        let pending = lease.load().unwrap().unwrap();
        assert_eq!(pending.plan, b"plan");
        assert_eq!(pending.outcome, None);
        store.fail_next_directory_sync();
        assert_eq!(
            lease.finish(&pending, b"outcome"),
            Err(StoreError::AmbiguousWrite)
        );
        assert_eq!(lease.load(), Err(StoreError::AmbiguousWrite));
        drop(lease);
        let restarted = dir.store();
        let finished = restarted.try_lease().unwrap().load().unwrap().unwrap();
        assert_eq!(finished.plan, pending.plan);
        assert_eq!(finished.outcome, Some(b"outcome".to_vec()));
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
    }

    #[test]
    fn broadcast_store_rejects_aliases_permissions_and_unbounded_file() {
        let dir = Scratch::new();
        let alias = dir.0.join("directory-alias");
        std::os::unix::fs::symlink(&dir.0, &alias).unwrap();
        assert!(matches!(
            BroadcastStore::new(alias.join("pending.bin"), [7; 32]),
            Err(StoreError::Path)
        ));
        assert!(matches!(
            BroadcastStore::new(dir.0.join("already.lock"), [7; 32]),
            Err(StoreError::Path)
        ));
        assert!(matches!(
            BroadcastStore::new(dir.0.join("x".repeat(129)), [7; 32]),
            Err(StoreError::Path)
        ));
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(dir.store_result(), Err(StoreError::Permissions)));
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = dir.store();
        std::os::unix::fs::symlink(&store.lock_path, dir.path()).unwrap();
        assert!(matches!(store.try_lease(), Err(StoreError::Identity)));
        std::fs::remove_file(dir.path()).unwrap();
        let file = private_create(&dir.path()).unwrap();
        file.set_len(MAX_SEALED_BYTES as u64 + 1).unwrap();
        assert!(matches!(store.try_lease(), Err(StoreError::Bounds)));
    }

    #[test]
    fn broadcast_store_refuses_lock_or_target_replacement_and_in_place_change() {
        for attack in 0..6 {
            let dir = Scratch::new();
            let store = dir.store();
            let lease = store.try_lease().unwrap();
            lease.create_pending(b"plan").unwrap();
            match attack {
                0 => {
                    std::fs::rename(&store.lock_path, dir.0.join("old-lock")).unwrap();
                    private_create(&store.lock_path).unwrap();
                }
                1 => {
                    std::fs::hard_link(&store.lock_path, dir.0.join("lock-alias")).unwrap();
                }
                2 => {
                    std::fs::hard_link(dir.path(), dir.0.join("record-alias")).unwrap();
                }
                3 => {
                    let sealed = std::fs::read(dir.path()).unwrap();
                    std::fs::rename(dir.path(), dir.0.join("old-record")).unwrap();
                    let mut file = private_create(&dir.path()).unwrap();
                    file.write_all(&sealed).unwrap();
                }
                4 => {
                    OpenOptions::new()
                        .append(true)
                        .open(dir.path())
                        .unwrap()
                        .write_all(&[0])
                        .unwrap();
                }
                5 => {
                    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let expected = if attack == 5 {
                StoreError::Permissions
            } else {
                StoreError::Identity
            };
            assert_eq!(lease.check(), Err(expected));
            assert_eq!(lease.load(), Err(expected));
        }
    }

    #[test]
    fn broadcast_store_parent_replacement_and_foreign_existing_cut_refuse() {
        let dir = Scratch::new();
        let store = dir.store();
        let lease = store.try_lease().unwrap();
        lease.create_pending(b"plan").unwrap();
        let moved = dir.0.with_extension("moved");
        std::fs::rename(&dir.0, &moved).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir.0)
            .unwrap();
        assert_eq!(lease.check(), Err(StoreError::Identity));
        std::fs::remove_dir(&dir.0).unwrap();
        std::fs::rename(moved, &dir.0).unwrap();
        drop(lease);
        let store = dir.store();
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(dir.path())
            .unwrap();
        file.write_all(&crate::snapshot::seal(b"DPCINT4\0foreign", &[7; 32]))
            .unwrap();
        drop(file);
        let lease = store.try_lease().unwrap();
        assert_eq!(lease.create_pending(b"new plan"), Err(StoreError::Exists));
        assert!(lease.load().is_err());
    }

    #[test]
    fn broadcast_store_authenticated_lock_pin_refuses_recreated_domain() {
        let dir = Scratch::new();
        let store = dir.store();
        let lease = store.try_lease().unwrap();
        let pending = lease.create_pending(b"plan").unwrap();
        let original = std::fs::read(dir.path()).unwrap();
        drop(lease);
        let saved_lock = dir.0.join("original-lock");
        std::fs::rename(&store.lock_path, &saved_lock).unwrap();
        assert!(matches!(dir.store_result(), Err(StoreError::Identity)));
        assert!(!store.lock_path.exists());
        private_create(&store.lock_path).unwrap();
        let replacement_handle = dir.store();
        let replacement_lease = replacement_handle.try_lease().unwrap();
        assert_eq!(replacement_lease.load(), Err(StoreError::Identity));
        assert_eq!(
            replacement_lease.create_pending(b"plan"),
            Err(StoreError::Exists)
        );
        assert_eq!(std::fs::read(dir.path()).unwrap(), original);
        drop(replacement_lease);
        std::fs::remove_file(&store.lock_path).unwrap();
        std::fs::rename(&saved_lock, &store.lock_path).unwrap();
        let resumed = dir.store();
        assert_eq!(resumed.try_lease().unwrap().load(), Ok(Some(pending)));

        // Exact authenticated bytes are also tied to the stable lock at this
        // path. Copying them beside another valid lock is not a store migration.
        let other = Scratch::new();
        let other_store = other.store();
        let mut target = private_create(&other.path()).unwrap();
        target.write_all(&original).unwrap();
        drop(target);
        assert_eq!(
            other_store.try_lease().unwrap().load(),
            Err(StoreError::Identity)
        );
    }

    impl Scratch {
        fn store_result(&self) -> Result<BroadcastStore, StoreError> {
            BroadcastStore::new(self.path(), [7; 32])
        }
    }
}
