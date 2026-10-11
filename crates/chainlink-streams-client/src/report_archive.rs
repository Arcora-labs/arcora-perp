//! Immutable paired-report archive for a trusted, private Unix service directory.
//! Hashes detect substitution only when the expected ID comes from a trusted journal.
//! They are not DON signatures. Full records remain append-only; finite logical
//! byte/entry limits refuse growth rather than deleting recovery or user history.
//! No latest-file fallback or key storage.
use crate::{
    decode_hex, hex,
    report_pair::{policy_binding, PairError, PreparedPair},
    Network, UnverifiedReport,
};
use chainlink_oracle::{
    policy::Policy,
    report::{body_from_full_report, MAX_FULL_REPORT},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

const MAX_RECORD: usize = 32 * 1024;
pub const MAX_ARCHIVE_RECORDS: usize = 65_536;
/// Host operational limits, separate from the report or guest protocol limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_bytes: u64,
    pub max_records: usize,
}
impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024,
            max_records: MAX_ARCHIVE_RECORDS,
        }
    }
}
impl ArchiveLimits {
    fn validate(self) -> Result<Self> {
        if self.max_bytes == 0 || self.max_records == 0 || self.max_records > MAX_ARCHIVE_RECORDS {
            return Err(ArchiveError::Bounds);
        }
        Ok(self)
    }
}
/// Conservative logical directory usage. Crash-leftover `.pending-` files are
/// charged as entries and bytes too, including any hard-linked duplicate. This
/// is a quota, not a guarantee of free physical filesystem blocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArchiveUsage {
    pub bytes: u64,
    pub records: usize,
}
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveError {
    Io,
    Path,
    Missing,
    Bounds,
    Encoding,
    Identity,
    Capacity,
    Pair(PairError),
}
impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "report archive {self:?}")
    }
}
impl std::error::Error for ArchiveError {}
impl From<std::io::Error> for ArchiveError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::NotFound {
            Self::Missing
        } else {
            Self::Io
        }
    }
}
impl From<PairError> for ArchiveError {
    fn from(e: PairError) -> Self {
        Self::Pair(e)
    }
}
type Result<T> = std::result::Result<T, ArchiveError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArchiveId([u8; 32]);
impl ArchiveId {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() != 64
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ArchiveError::Identity);
        }
        let bytes = decode_hex(text, 32).map_err(|_| ArchiveError::Identity)?;
        Ok(Self(bytes.try_into().map_err(|_| ArchiveError::Identity)?))
    }
    pub fn hex(self) -> String {
        hex(&self.0)
    }
    fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    policy_binding: String,
    market_id: u64,
    prepared_at_ms: u64,
    base_received_ms: u64,
    quote_received_ms: u64,
    base_full_report: String,
    quote_full_report: String,
}
fn encode(pair: &PreparedPair) -> Result<Vec<u8>> {
    pair.for_operation(pair.prepared_at_ms)?;
    let record = Record {
        schema: 1,
        policy_binding: hex(&policy_binding(&pair.policy)?),
        market_id: pair.market_id,
        prepared_at_ms: pair.prepared_at_ms,
        base_received_ms: pair.base.received_ms(),
        quote_received_ms: pair.quote.received_ms(),
        base_full_report: hex(pair.base.full_report()),
        quote_full_report: hex(pair.quote.full_report()),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| ArchiveError::Encoding)?;
    if bytes.len() > MAX_RECORD {
        return Err(ArchiveError::Bounds);
    }
    Ok(bytes)
}
fn reconstruct(full: &str, network: Network, received_ms: u64) -> Result<UnverifiedReport> {
    let full_report = decode_hex(full, MAX_FULL_REPORT).map_err(|_| ArchiveError::Encoding)?;
    let body = body_from_full_report(&full_report).map_err(|_| ArchiveError::Encoding)?;
    let decoded = body.decode().map_err(|_| ArchiveError::Encoding)?;
    Ok(UnverifiedReport {
        full_report,
        body,
        decoded,
        network,
        received_ms,
    })
}
fn decode(bytes: &[u8], policy: &Policy, market_id: u64) -> Result<PreparedPair> {
    let record: Record = serde_json::from_slice(bytes).map_err(|_| ArchiveError::Encoding)?;
    if record.schema != 1
        || record.market_id != market_id
        || record.policy_binding != hex(&policy_binding(policy)?)
    {
        return Err(ArchiveError::Identity);
    }
    let network = match (policy.chain_id, policy.network) {
        (84532, 0) => Network::Testnet,
        (8453, 1) => Network::Mainnet,
        _ => return Err(ArchiveError::Identity),
    };
    let pair = PreparedPair::new(
        policy,
        market_id,
        reconstruct(&record.base_full_report, network, record.base_received_ms)?,
        reconstruct(&record.quote_full_report, network, record.quote_received_ms)?,
        record.prepared_at_ms,
    )?;
    // One canonical encoding: no alternate hex, whitespace, unknown or duplicate fields.
    if encode(&pair)? != bytes {
        return Err(ArchiveError::Encoding);
    }
    Ok(pair)
}

/// Keep this ID in the caller's durably written, integrity-protected journal.
/// Receiving it is NOT an acknowledgment of an order, settlement, or DON verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredPair {
    pub id: ArchiveId,
    pub bytes: usize,
}

pub struct ReportArchive {
    root: PathBuf,
    directory: File,
    device: u64,
    inode: u64,
    limits: ArchiveLimits,
    writer: Mutex<()>,
}
impl ReportArchive {
    /// Create a NEW private directory. Existing directories are never silently reused.
    pub fn create(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(ArchiveError::Path);
        }
        fs::DirBuilder::new().mode(0o700).create(path)?;
        let archive = Self::open_existing(path)?;
        File::open(archive.root.parent().ok_or(ArchiveError::Path)?)?.sync_all()?;
        Ok(archive)
    }
    /// Recovery never creates an empty archive in place of a missing backup.
    /// The directory and its parents must be controlled by the service operator.
    pub fn open_existing(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(ArchiveError::Path);
        }
        let m = fs::symlink_metadata(path)?;
        if !m.is_dir() || m.mode() & 0o077 != 0 {
            return Err(ArchiveError::Path);
        }
        let root = path.canonicalize()?;
        let directory = File::open(&root)?;
        let opened = directory.metadata()?;
        if (opened.dev(), opened.ino()) != (m.dev(), m.ino()) {
            return Err(ArchiveError::Path);
        }
        Ok(Self {
            root,
            directory,
            device: m.dev(),
            inode: m.ino(),
            limits: ArchiveLimits::default(),
            writer: Mutex::new(()),
        })
    }
    /// Configure finite host limits. Lowering a limit never removes existing
    /// history: exact idempotent writes remain available; novel IDs HOLD.
    pub fn with_limits(mut self, limits: ArchiveLimits) -> Result<Self> {
        self.set_limits(limits)?;
        Ok(self)
    }
    pub fn set_limits(&mut self, limits: ArchiveLimits) -> Result<()> {
        self.limits = limits.validate()?;
        Ok(())
    }
    /// Inventory only the private archive's direct entries. Never follow links,
    /// recurse, adopt foreign files, or promote crash leftovers. Enumeration is
    /// bounded even when an unexpected number of entries exists.
    pub fn usage(&self) -> Result<ArchiveUsage> {
        let _writer = self.writer.lock().map_err(|_| ArchiveError::Io)?;
        self.inventory()
    }
    fn inventory(&self) -> Result<ArchiveUsage> {
        // Independent of a lowered quota: existing valid history must remain
        // available for exact idempotent reconciliation above the new limit.
        self.inventory_with_budget(MAX_ARCHIVE_RECORDS * 2 + 64)
    }
    fn inventory_with_budget(&self, scan_limit: usize) -> Result<ArchiveUsage> {
        self.check_root()?;
        // A store transiently has both a temp and immutable hard-link. Allow
        // bounded crash leftovers in the scan while charging them to the quota.
        let mut usage = ArchiveUsage::default();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if usage.records >= scan_limit {
                return Err(ArchiveError::Capacity);
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or(ArchiveError::Path)?;
            let pending = name
                .strip_prefix(".pending-")
                .is_some_and(|suffix| !suffix.is_empty());
            let record = name
                .strip_suffix(".json")
                .is_some_and(|id| ArchiveId::parse(id).is_ok());
            if !pending && !record {
                return Err(ArchiveError::Path);
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
                return Err(ArchiveError::Path);
            }
            if metadata.len() > MAX_RECORD as u64 || (record && metadata.len() == 0) {
                return Err(ArchiveError::Bounds);
            }
            usage.records += 1;
            usage.bytes = usage
                .bytes
                .checked_add(metadata.len())
                .ok_or(ArchiveError::Bounds)?;
        }
        self.check_root()?;
        Ok(usage)
    }
    fn check_root(&self) -> Result<()> {
        let m = fs::symlink_metadata(&self.root)?;
        if !m.is_dir() || m.mode() & 0o077 != 0 || (m.dev(), m.ino()) != (self.device, self.inode) {
            return Err(ArchiveError::Path);
        }
        Ok(())
    }
    fn path(&self, id: ArchiveId) -> PathBuf {
        self.root.join(format!("{}.json", id.hex()))
    }
    /// Deterministic before writing, allowing reconciliation after an uncertain write outcome.
    pub fn id_for(pair: &PreparedPair) -> Result<ArchiveId> {
        Ok(ArchiveId::of(&encode(pair)?))
    }
    pub fn store(&self, pair: &PreparedPair) -> Result<StoredPair> {
        self.store_with_checkpoint(pair, |_| Ok(()))
    }
    fn store_with_checkpoint(
        &self,
        pair: &PreparedPair,
        mut checkpoint: impl FnMut(&str) -> Result<()>,
    ) -> Result<StoredPair> {
        // One archive handle serializes quota preflight and publication, including
        // its concurrent callers. The private directory must have one owning
        // service writer; separate processes are not a distributed quota lock.
        let _writer = self.writer.lock().map_err(|_| ArchiveError::Io)?;
        self.check_root()?;
        let bytes = encode(pair)?;
        let id = ArchiveId::of(&bytes);
        let target = self.path(id);
        let usage = self.inventory()?;
        match fs::symlink_metadata(&target) {
            Ok(_) => {
                if self.read_exact(id)? != bytes {
                    return Err(ArchiveError::Identity);
                }
                File::open(&target)?.sync_all()?;
                self.directory.sync_all()?;
                return Ok(StoredPair {
                    id,
                    bytes: bytes.len(),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if usage.records >= self.limits.max_records
            || usage
                .bytes
                .checked_add(bytes.len() as u64)
                .is_none_or(|next| next > self.limits.max_bytes)
        {
            return Err(ArchiveError::Capacity);
        }
        let (temporary, mut file) = self.new_temporary()?;
        // A drop guard cleans only this call's create_new-owned temporary file.
        let cleanup = Temporary(temporary);
        file.write_all(&bytes)?;
        checkpoint("written")?;
        file.sync_all()?;
        checkpoint("file_synced")?;
        self.check_root()?;
        match fs::hard_link(&cleanup.0, &target) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if self.read_exact(id)? != bytes {
                    return Err(ArchiveError::Identity);
                }
            }
            Err(e) => return Err(e.into()),
        }
        checkpoint("published")?;
        // Existing identical files are also synced before an idempotent success.
        File::open(&target)?.sync_all()?;
        self.directory.sync_all()?;
        checkpoint("directory_synced")?;
        fs::remove_file(&cleanup.0)?;
        self.directory.sync_all()?;
        Ok(StoredPair {
            id,
            bytes: bytes.len(),
        })
    }
    fn new_temporary(&self) -> Result<(PathBuf, File)> {
        for _ in 0..32 {
            let n = NEXT_TEMP
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| ArchiveError::Bounds)?;
            let path = self
                .root
                .join(format!(".pending-{}-{n}", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(ArchiveError::Io)
    }
    fn read_exact(&self, id: ArchiveId) -> Result<Vec<u8>> {
        self.check_root()?;
        let path = self.path(id);
        let before = fs::symlink_metadata(&path)?;
        if !before.is_file() || before.mode() & 0o077 != 0 {
            return Err(ArchiveError::Path);
        }
        if before.len() == 0 || before.len() > MAX_RECORD as u64 {
            return Err(ArchiveError::Bounds);
        }
        let file = File::open(path)?;
        let opened = file.metadata()?;
        if !opened.is_file() || (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(ArchiveError::Path);
        }
        let mut bytes = Vec::new();
        file.take(MAX_RECORD as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_RECORD {
            return Err(ArchiveError::Bounds);
        }
        if ArchiveId::of(&bytes) != id {
            return Err(ArchiveError::Identity);
        }
        self.check_root()?;
        Ok(bytes)
    }
    /// Load only an externally expected immutable ID. Historical data is returned
    /// unchanged; call for_operation(new_time) before any new admission.
    pub fn load(&self, id: ArchiveId, policy: &Policy, market_id: u64) -> Result<PreparedPair> {
        decode(&self.read_exact(id)?, policy, market_id)
    }
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
#[path = "report_archive_tests.rs"]
mod tests;
