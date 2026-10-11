//! Candidate gateway binding: Chainlink report archive → oracle admission →
//! sealed rollback journal → recovery verification. CANDIDATE, opt-in only;
//! PRODUCTION RELEASE HOLD. The reviewed v2 guest, witness format, and prover
//! routing are untouched — this binds the actual op stream to immutable archived
//! reports on the host so a future candidate guest (v3) can be wired without a
//! journal-format break.
//!
//! Ordering guarantees (durability barriers, in order):
//!   archive record durable  →  state-changing oracle admission
//!   archive-bound journal durable  →  any prove/broadcast side effect
//! Recovery requires every referenced record to exist, decode, and re-normalize
//! to the exact op transcript under the configured policy; any mismatch, missing
//! or corrupt record is a versioned HOLD, never a substitution.
use crate::rollback_journal::{ArchiveEnvelope, ArchiveRef};
use chainlink_oracle::policy::{Normalized, Policy};
use chainlink_streams_client::{
    report_archive::{ArchiveId, ReportArchive},
    report_pair::{policy_binding, PreparedPair},
    UnverifiedReport,
};
use perp_core::engine::BatchOp;
use std::collections::VecDeque;

pub(crate) const MODE_ENV: &str = "DARKPERP_CHAINLINK_ARCHIVE";
pub(crate) const DIR_ENV: &str = "DARKPERP_CHAINLINK_ARCHIVE_DIR";
pub(crate) const POLICY_ENV: &str = "DARKPERP_CHAINLINK_POLICY_JSON";

/// Candidate-mode persistence boundary.
///
/// The archive requirement is a RUNTIME gate (env + in-memory binding), which
/// serde skips everywhere — a gateway that ever settled candidate windows and
/// persisted state must not be able to boot as legacy just because the
/// operator omitted the flag (a restored snapshot, including one with an
/// UNSEALED open window admitted from archived reports, would then keep
/// settling unbound). This sidecar adds mode protection: written ONLY in
/// candidate mode, sealed exactly like the rollback journal, versioned by
/// magic. The snapshot envelope separately persists the policy and index.
const MARKER_MAGIC: &[u8; 8] = b"DPCAM1\0\0";

#[derive(serde::Serialize, serde::Deserialize)]
struct CandidateModeMarkerV1 {
    policy_binding: [u8; 32],
}

/// `<state>.chainlink` (appended, like the `.rollback` sidecar).
pub(crate) fn marker_path(state_path: &std::path::Path) -> std::path::PathBuf {
    let mut os = state_path.as_os_str().to_os_string();
    os.push(".chainlink");
    std::path::PathBuf::from(os)
}

pub(crate) fn write_marker(
    path: &std::path::Path,
    policy_binding: [u8; 32],
    seed: &[u8; 32],
) -> Result<(), String> {
    let body = postcard::to_allocvec(&CandidateModeMarkerV1 { policy_binding })
        .map_err(|e| format!("mode marker encode: {e}"))?;
    let mut plain = Vec::with_capacity(MARKER_MAGIC.len() + body.len());
    plain.extend_from_slice(MARKER_MAGIC);
    plain.extend_from_slice(&body);
    let sealed = crate::snapshot::seal(&plain, seed);
    crate::snapshot::write_atomic(path, &sealed).map_err(|e| format!("mode marker write: {e}"))
}

/// `Ok(None)` = no marker (legacy state, never candidate). `Ok(Some(binding))`
/// = sealed marker. `Err` = a marker EXISTS but is unreadable (wrong seed /
/// tampered / future version): never treated as absent — the caller refuses
/// startup rather than risk a legacy boot of candidate-used state.
pub(crate) fn read_marker(
    path: &std::path::Path,
    seed: &[u8; 32],
) -> Result<Option<[u8; 32]>, String> {
    let sealed = match crate::snapshot::read_file(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("mode marker read: {e}")),
    };
    let plain =
        crate::snapshot::open(&sealed, seed).map_err(|e| format!("mode marker open: {e}"))?;
    let body = plain
        .strip_prefix(MARKER_MAGIC.as_slice())
        .ok_or("mode marker magic/version mismatch")?;
    let (CandidateModeMarkerV1 { policy_binding }, rest) =
        postcard::take_from_bytes(body).map_err(|e| format!("mode marker decode: {e}"))?;
    if !rest.is_empty() {
        return Err(format!(
            "mode marker decode: {} trailing bytes after the payload",
            rest.len()
        ));
    }
    Ok(Some(policy_binding))
}

/// Candidate recovery envelope INSIDE the authenticated snapshot plaintext.
/// The state bytes (including the open operation window), policy binding and
/// canonical admitted identities are captured under the same gateway/archive
/// locks and committed by one atomic snapshot write. The sidecar is additional
/// mode protection, never the source of the admission index.
pub(crate) const SNAPSHOT_TAG_MAGIC: &[u8; 8] = b"DPCAS2\0\0";
const OLD_SNAPSHOT_TAG_MAGIC: &[u8; 8] = b"DPCAS1\0\0";

#[derive(serde::Serialize, serde::Deserialize)]
struct CandidateSnapshotV2 {
    state_plain: Vec<u8>,
    policy_binding: [u8; 32],
    #[serde(deserialize_with = "deserialize_admissions")]
    admissions: Vec<Admission>,
}

/// Reject the encoded admission count before allocating or decoding entries.
/// A successfully authenticated malformed snapshot is still untrusted input.
fn deserialize_admissions<'de, D>(deserializer: D) -> Result<Vec<Admission>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AdmissionsVisitor;
    impl<'de> serde::de::Visitor<'de> for AdmissionsVisitor {
        type Value = Vec<Admission>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "at most {MAX_ADMISSIONS} canonical admissions")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let size = seq.size_hint().unwrap_or(0);
            if size > MAX_ADMISSIONS {
                return Err(serde::de::Error::custom("admission count exceeds capacity"));
            }
            let mut admissions = Vec::with_capacity(size);
            while let Some(admission) = seq.next_element()? {
                if admissions.len() >= MAX_ADMISSIONS {
                    return Err(serde::de::Error::custom("admission count exceeds capacity"));
                }
                admissions.push(admission);
            }
            Ok(admissions)
        }
    }
    deserializer.deserialize_seq(AdmissionsVisitor)
}

/// Decode only the authenticated envelope, verify every EXACT archived record
/// under the configured policy at its original preparation time, then replace
/// the admission index atomically. No archive discovery or sibling fallback.
/// The caller decodes `Gw` from the returned bytes before any recovery mutation.
pub(crate) fn restore_snapshot_plain(
    plain: &[u8],
    binding: Option<&mut ArchiveBinding>,
) -> Result<Vec<u8>, String> {
    if plain.len() > crate::snapshot::MAX_PLAIN_BYTES {
        return Err("candidate snapshot exceeds 64 MiB payload limit".into());
    }
    if plain.starts_with(OLD_SNAPSHOT_TAG_MAGIC) {
        return Err(
            "candidate snapshot DPCAS1 has no canonical admission index; preserve it for reconciliation"
                .into(),
        );
    }
    let Some(body) = plain.strip_prefix(SNAPSHOT_TAG_MAGIC.as_slice()) else {
        if plain.starts_with(b"DPCAS") {
            return Err("candidate snapshot magic/version mismatch".into());
        }
        return Ok(plain.to_vec()); // valid legacy plaintext bytes are unchanged
    };
    let binding = binding.ok_or(
        "authenticated candidate snapshot restored without candidate configuration; refusing legacy boot",
    )?;
    let (envelope, rest): (CandidateSnapshotV2, _) = postcard::take_from_bytes(body)
        .map_err(|_| "candidate snapshot decode failed or admission count exceeds capacity")?;
    if !rest.is_empty() {
        return Err("candidate snapshot has trailing bytes".into());
    }
    if postcard::to_allocvec(&envelope).map_err(|_| "candidate snapshot re-encode failed")? != body
    {
        return Err("candidate snapshot encoding is not canonical".into());
    }
    if envelope.state_plain.is_empty() || envelope.state_plain.starts_with(b"DPCAS") {
        return Err("candidate snapshot state payload is empty or nested".into());
    }
    if envelope.policy_binding != binding.policy_binding {
        return Err("candidate snapshot policy binding does not match configured policy".into());
    }
    if envelope.admissions.len() > binding.max_admissions {
        return Err("candidate snapshot admission count exceeds configured capacity".into());
    }
    let mut restored = VecDeque::with_capacity(envelope.admissions.len());
    for admission in envelope.admissions {
        if restored.iter().any(|existing: &Admission| {
            existing.market_id == admission.market_id && existing.transcript == admission.transcript
        }) {
            return Err("candidate snapshot has duplicate canonical admission identity".into());
        }
        let pair = binding
            .archive
            .load(admission.id, &binding.policy, admission.market_id)
            .map_err(|_| "candidate snapshot selected archive record is missing or invalid")?;
        let (normalized, _) = pair
            .for_operation(pair.prepared_at_ms())
            .map_err(|_| "candidate snapshot selected archive record does not normalize")?;
        if normalized != admission.transcript {
            return Err(
                "candidate snapshot admitted transcript does not match selected record".into(),
            );
        }
        restored.push_back(admission);
    }
    binding.admissions = restored;
    Ok(envelope.state_plain)
}

/// Pure boot-gate decision over (persisted marker, configured binding).
/// Testable without env or filesystem; the caller performs the IO.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ModeGate {
    /// Legacy state, legacy config: unchanged behavior.
    Legacy,
    /// Candidate-configured boot must durably write the marker first.
    CandidateWriteMarker,
    /// Candidate-configured boot with a matching persisted marker.
    CandidateContinue,
    /// Refuse startup before ANY recovery mutation, with the reason.
    Refuse(String),
}

pub(crate) fn mode_gate(
    marker: Result<Option<[u8; 32]>, String>,
    configured: Option<[u8; 32]>,
) -> ModeGate {
    match (marker, configured) {
        (Err(e), _) => ModeGate::Refuse(format!(
            "candidate mode marker exists but is unreadable ({e}); refusing to boot rather than guess the mode"
        )),
        (Ok(None), None) => {
            // Marker absence is NOT proof of "never candidate" — but with no
            // marker, no config, and an untagged snapshot there is nothing
            // authenticated to distinguish, and this remains the reviewed
            // legacy path. Any snapshot that ever ran candidate IS tagged
            // (DPCAS2) and is refused by `restore_snapshot_plain`, and
            // any marker that exists is refused by the arms below.
            ModeGate::Legacy
        }
        (Ok(None), Some(_pb)) => ModeGate::CandidateWriteMarker,
        (Ok(Some(_persisted)), None) => ModeGate::Refuse(
            "state was persisted in candidate archive mode (marker present) but \
             DARKPERP_CHAINLINK_ARCHIVE is not configured; refusing to boot as legacy"
                .into(),
        ),
        (Ok(Some(persisted)), Some(pb)) => {
            if persisted == pb {
                ModeGate::CandidateContinue
            } else {
                ModeGate::Refuse(
                    "candidate mode marker policy binding does not match the configured policy"
                        .into(),
                )
            }
        }
    }
}

/// Default admission-index ceiling. Hitting it REFUSES new admissions (the
/// operator must reconcile); it never evicts — an evicted identity could
/// strand the ops of an unsealed window.
const MAX_ADMISSIONS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Admission {
    pub(crate) market_id: u64,
    pub(crate) id: ArchiveId,
    /// The exact normalization admitted at preparation time. Binding keys on
    /// this VALUE (with the market), never on recency: a window may carry both
    /// earlier and later transcripts for the same market, and repeated use of
    /// the same valid archive ID is legitimate.
    transcript: Normalized,
}

/// A durably stored record awaiting the caller's downstream admission result.
/// The ledger entry is installed ONLY via `ArchiveBinding::install`, after the
/// gateway has ACCEPTED the transcript — a rejected admission never becomes
/// selectable, so it can never shadow or replace an existing identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingAdmission {
    pub(crate) market_id: u64,
    pub(crate) id: ArchiveId,
    pub(crate) transcript: Normalized,
}

pub(crate) struct ArchiveBinding {
    archive: ReportArchive,
    policy: Policy,
    policy_binding: [u8; 32],
    admissions: VecDeque<Admission>,
    max_admissions: usize,
}

/// Why a binding step refused. Fixed categories only — never credential, path,
/// or report contents in the message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BindError {
    Config,
    Policy,
    Archive,
    NoAdmission,
    Mismatch,
    /// The admission index is at capacity; the caller must reject the
    /// admission and reconcile rather than silently lose a binding.
    Capacity,
    /// Invalid or oversized candidate snapshot envelope.
    Snapshot,
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chainlink archive binding {self:?}")
    }
}

fn config_env(name: &str) -> Result<Option<String>, BindError> {
    match std::env::var(name) {
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(BindError::Config),
    }
}

/// The operator-pinned policy is PUBLIC data, never credentials: it must be a
/// bounded, regular, non-symlink file. A symlink, directory, empty file, or
/// oversized file refuses — no substitution, no discovery.
fn read_policy_file(path: &std::path::Path) -> Result<Vec<u8>, BindError> {
    const MAX_POLICY_BYTES: u64 = 64 * 1024;
    let meta = std::fs::symlink_metadata(path).map_err(|_| BindError::Config)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(BindError::Config);
    }
    if meta.len() == 0 || meta.len() > MAX_POLICY_BYTES {
        return Err(BindError::Config);
    }
    let bytes = std::fs::read(path).map_err(|_| BindError::Config)?;
    if bytes.len() as u64 != meta.len() {
        return Err(BindError::Config); // changed under us
    }
    Ok(bytes)
}

/// Candidate mode requires the pinned policy to cover EVERY configured
/// gateway market — otherwise some price could be admitted outside the archive
/// and every price-bearing window would wedge at seal time. Returns the first
/// uncovered market id. Pure and unit-tested.
pub(crate) fn uncovered_market(policy: &Policy, market_ids: &[u64]) -> Option<u64> {
    market_ids
        .iter()
        .copied()
        .find(|id| policy.market(*id).is_err())
}

/// Classify oracle-bearing ops EXACTLY like the candidate guest
/// (crates/chainlink-oracle/src/binding.rs::used_oracle): a new BatchOp variant
/// must be added here in the same change that adds it there, or seal-time binding
/// fails closed (the op has no archive record → window never seals).
pub(crate) fn used_oracle(
    op: &BatchOp,
) -> Option<(u64, u64, &perp_core::oracle::OracleTranscript)> {
    match op {
        BatchOp::Fill {
            market_id,
            now_ms,
            oracle,
            ..
        }
        | BatchOp::AccrueFunding {
            market_id,
            now_ms,
            oracle,
            ..
        }
        | BatchOp::Liquidate {
            market_id,
            now_ms,
            oracle,
            ..
        }
        | BatchOp::Unbind {
            market_id,
            now_ms,
            oracle,
            ..
        } => Some((*market_id, *now_ms, oracle)),
        BatchOp::Deposit { .. }
        | BatchOp::FundPosition { .. }
        | BatchOp::Withdraw { .. }
        | BatchOp::EnterCloseOnly
        | BatchOp::DeprecatedSeedInsurance { .. }
        | BatchOp::FundInsurance { .. }
        | BatchOp::SettleAll
        | BatchOp::WindDownUnbind { .. }
        | BatchOp::WindDownWithdraw { .. } => None,
    }
}

impl ArchiveBinding {
    /// Opt-in config: absent / "disabled" ⇒ `None` (legacy behavior everywhere);
    /// "candidate" ⇒ an operator-owned archive dir plus an operator-pinned
    /// policy file. STRICT partial-config handling: a DIR or POLICY setting
    /// without `MODE=candidate` is an ERROR, never a silent disable; an
    /// explicitly disabled mode must not carry candidate settings either.
    pub(crate) fn from_env() -> Result<Option<Self>, BindError> {
        Self::configured(
            config_env(MODE_ENV)?,
            config_env(DIR_ENV)?,
            config_env(POLICY_ENV)?,
        )
    }

    pub(crate) fn configured(
        mode: Option<String>,
        dir: Option<String>,
        policy: Option<String>,
    ) -> Result<Option<Self>, BindError> {
        match mode.as_deref() {
            None | Some("disabled") => {
                if dir.is_some() || policy.is_some() {
                    // Partial candidate settings must fail loudly, not disable.
                    return Err(BindError::Config);
                }
                Ok(None)
            }
            Some("candidate") => {
                let dir = dir.ok_or(BindError::Config)?;
                let policy_path = policy.ok_or(BindError::Config)?;
                // Recovery never creates an empty archive in place of a missing
                // backup; the directory and its parents belong to the operator.
                let archive = ReportArchive::open_existing(std::path::Path::new(&dir))
                    .map_err(|_| BindError::Archive)?;
                let bytes = read_policy_file(std::path::Path::new(&policy_path))?;
                let policy: Policy =
                    serde_json::from_slice(&bytes).map_err(|_| BindError::Config)?;
                Self::new(archive, policy).map(Some)
            }
            Some(_) => Err(BindError::Config),
        }
    }

    #[cfg(test)]
    pub(crate) fn create_in(dir: &std::path::Path, policy: Policy) -> Result<Self, BindError> {
        Self::new(
            ReportArchive::create(&dir.join("store")).map_err(|_| BindError::Archive)?,
            policy,
        )
    }

    fn new(archive: ReportArchive, policy: Policy) -> Result<Self, BindError> {
        // The pinned policy must itself be a valid candidate policy and carry a
        // computable archive binding before any admission is accepted.
        let policy_binding = policy_binding(&policy).map_err(|_| BindError::Policy)?;
        policy.hash().map_err(|_| BindError::Policy)?;
        Ok(Self {
            archive,
            policy,
            policy_binding,
            admissions: VecDeque::new(),
            max_admissions: MAX_ADMISSIONS,
        })
    }

    #[cfg(test)]
    fn with_capacity(mut self, n: usize) -> Self {
        self.max_admissions = n;
        self
    }

    pub(crate) fn policy(&self) -> &Policy {
        &self.policy
    }

    pub(crate) fn policy_binding(&self) -> [u8; 32] {
        self.policy_binding
    }

    /// The caller holds both gateway and archive locks so `state_plain` and
    /// this canonical index describe one cut. Snapshot encryption and atomic
    /// file replacement apply to the entire returned envelope together.
    pub(crate) fn snapshot_plain(&self, state_plain: Vec<u8>) -> Result<Vec<u8>, BindError> {
        if self.admissions.len() > self.max_admissions || self.admissions.len() > MAX_ADMISSIONS {
            return Err(BindError::Capacity);
        }
        if state_plain.is_empty()
            || state_plain.starts_with(b"DPCAS")
            || state_plain.len() > crate::snapshot::MAX_PLAIN_BYTES
        {
            return Err(BindError::Snapshot);
        }
        let envelope = CandidateSnapshotV2 {
            state_plain,
            policy_binding: self.policy_binding,
            admissions: self.admissions.iter().copied().collect(),
        };
        let body = postcard::to_allocvec(&envelope).map_err(|_| BindError::Snapshot)?;
        if body.len() > crate::snapshot::MAX_PLAIN_BYTES - SNAPSHOT_TAG_MAGIC.len() {
            return Err(BindError::Snapshot);
        }
        let mut plain = Vec::with_capacity(SNAPSHOT_TAG_MAGIC.len() + body.len());
        plain.extend_from_slice(SNAPSHOT_TAG_MAGIC);
        plain.extend(body);
        Ok(plain)
    }

    /// An authenticated sealed journal can be newer than its paired snapshot.
    /// After exact verification, restore the accepted identities it names so a
    /// rollback can return those operations to the open window without losing
    /// their canonical IDs. Existing selections may never be replaced, even by
    /// an equal-normalized sibling. Install nothing on any verification failure.
    pub(crate) fn recover_journal(
        &mut self,
        ops: &[BatchOp],
        envelope: &ArchiveEnvelope,
    ) -> Result<(), BindError> {
        self.verify(ops, envelope)?;
        let mut restored = self.admissions.clone();
        for ((market_id, _, oracle), reference) in
            ops.iter().filter_map(used_oracle).zip(&envelope.refs)
        {
            let transcript = Normalized {
                price: oracle.price,
                publish_time_ms: oracle.publish_time_ms,
                confidence: oracle.confidence,
                backup_twap: oracle.backup_twap,
            };
            if let Some(existing) = restored
                .iter()
                .find(|a| a.market_id == market_id && a.transcript == transcript)
            {
                if existing.id != reference.archive_id {
                    return Err(BindError::Mismatch);
                }
            } else {
                if restored.len() >= self.max_admissions || restored.len() >= MAX_ADMISSIONS {
                    return Err(BindError::Capacity);
                }
                restored.push_back(Admission {
                    market_id,
                    id: reference.archive_id,
                    transcript,
                });
            }
        }
        self.admissions = restored;
        Ok(())
    }

    /// Whether the admission index is at capacity (install would refuse).
    /// Lets the intake reject a fetch BEFORE storing/admitting downstream.
    pub(crate) fn is_full(&self) -> bool {
        self.admissions.len() >= self.max_admissions
    }

    /// Durable archive FIRST, ledger entry NEVER. Stores the immutable
    /// hash-named record (file + directory fsync) and returns the exact
    /// normalization plus the record's ID. The caller applies the transcript
    /// downstream and calls `install` ONLY on acceptance; a refused admission
    /// leaves the record permanently unreferenced — never replayed as fresh
    /// admission, never selectable for binding.
    pub(crate) fn admit(
        &mut self,
        market_id: u64,
        base: UnverifiedReport,
        quote: UnverifiedReport,
        now_ms: u64,
    ) -> Result<PendingAdmission, BindError> {
        let pair = PreparedPair::new(&self.policy, market_id, base, quote, now_ms)
            .map_err(|_| BindError::Policy)?;
        let (normalized, _) = pair
            .for_operation(now_ms)
            .map_err(|_| BindError::Mismatch)?;
        // The durability barrier: the record exists before any state-changing
        // admission can cite it.
        let stored = self.archive.store(&pair).map_err(|_| BindError::Archive)?;
        Ok(PendingAdmission {
            market_id,
            id: stored.id,
            transcript: normalized,
        })
    }

    /// One exclusive binding borrow covers durable storage, downstream acceptance
    /// and the index update. No fallible index step or mutex reacquisition occurs
    /// AFTER the gateway has accepted the price. A rejected callback leaves only
    /// an unreferenced immutable record, never a selectable admission.
    pub(crate) fn admit_with(
        &mut self,
        market_id: u64,
        base: UnverifiedReport,
        quote: UnverifiedReport,
        now_ms: u64,
        accept: impl FnOnce(Normalized) -> bool,
    ) -> Result<bool, BindError> {
        if self.is_full() {
            return Err(BindError::Capacity);
        }
        let pending = self.admit(market_id, base, quote, now_ms)?;
        let already_selected = self
            .admissions
            .iter()
            .any(|a| a.market_id == pending.market_id && a.transcript == pending.transcript);
        if !accept(pending.transcript) {
            return Ok(false);
        }
        // The callback cannot mutate this exclusively borrowed index. Capacity
        // was checked before storage; inserting this one entry cannot fail a
        // policy check after downstream mutation. Keep the first selected ID.
        if !already_selected {
            self.admissions.push_back(Admission {
                market_id: pending.market_id,
                id: pending.id,
                transcript: pending.transcript,
            });
        }
        Ok(true)
    }

    /// Install an ACCEPTED admission into the binding index. The index maps
    /// each (market, transcript) identity to exactly ONE canonical ArchiveId —
    /// the FIRST accepted admission for that identity. Two different original
    /// full-report records CAN normalize identically; the original selection
    /// is NEVER replaced by a later equal-value record (insert-if-absent), and
    /// a later record can never shadow a rejected one (rejected admissions are
    /// never installed at all). Capacity REFUSES rather than silently evicting:
    /// an evicted entry could strand an unsealed window's ops, so the caller
    /// must reject the admission and reconcile instead.
    #[cfg(test)]
    pub(crate) fn install(&mut self, pending: PendingAdmission) -> Result<(), BindError> {
        if self
            .admissions
            .iter()
            .any(|a| a.market_id == pending.market_id && a.transcript == pending.transcript)
        {
            return Ok(()); // canonical ID already installed; the original wins
        }
        if self.admissions.len() >= self.max_admissions {
            return Err(BindError::Capacity);
        }
        self.admissions.push_back(Admission {
            market_id: pending.market_id,
            id: pending.id,
            transcript: pending.transcript,
        });
        Ok(())
    }

    /// Bind the ACTUAL op stream — ordered, one ref per oracle-bearing op,
    /// repeated use included — to exact archived records. References are
    /// derived in OP ORDER from the binding index: an op binds to the
    /// canonical ArchiveId of the (market, transcript) identity the gateway
    /// actually admitted — never a reverse scan by value, never a fallback to
    /// an equal-price or same-normalized sibling record. Before the envelope is
    /// returned, every SELECTED record is loaded from the durable archive: a
    /// missing exact ID is Err → the seal fails, even when another record with
    /// an identical normalization exists. (Repeated use of one ID is
    /// legitimate; each unique ID is loaded once.)
    pub(crate) fn bind_ops(&self, ops: &[BatchOp]) -> Result<ArchiveEnvelope, BindError> {
        let mut refs = Vec::new();
        for op in ops {
            let Some((market_id, now_ms, oracle)) = used_oracle(op) else {
                continue;
            };
            // Canonical (market, transcript) identity — never recency, never a
            // latest-pair-per-market map, never substitution on load failure.
            let want = Normalized {
                price: oracle.price,
                publish_time_ms: oracle.publish_time_ms,
                confidence: oracle.confidence,
                backup_twap: oracle.backup_twap,
            };
            let found = self
                .admissions
                .iter()
                .find(|a| a.market_id == market_id && a.transcript == want)
                .map(|a| a.id);
            let Some(id) = found else {
                return Err(
                    if self.admissions.iter().any(|a| a.market_id == market_id) {
                        BindError::Mismatch
                    } else {
                        BindError::NoAdmission
                    },
                );
            };
            refs.push(ArchiveRef {
                market_id,
                now_ms,
                archive_id: id,
            });
        }
        // Existence barrier at seal time: the EXACT selected record must be
        // loadable from the durable archive. No substitution: an unreadable
        // selected ID fails the whole seal even if an equal-normalized sibling
        // exists — the envelope may only ever name the original record.
        let mut checked: Vec<ArchiveId> = Vec::new();
        for r in &refs {
            if checked.contains(&r.archive_id) {
                continue;
            }
            checked.push(r.archive_id);
            self.archive
                .load(r.archive_id, &self.policy, r.market_id)
                .map_err(|_| BindError::Archive)?;
        }
        Ok(ArchiveEnvelope {
            policy_binding: self.policy_binding,
            refs,
        })
    }

    /// Recovery/handoff: the sealed envelope must name THIS policy and every
    /// referenced record must still decode and re-normalize to the exact op
    /// transcript. Missing, corrupt, wrong-policy/market/op-time, or transcript
    /// mismatch ⇒ Err ⇒ the caller HOLDs. Never substitute another record.
    pub(crate) fn verify(
        &self,
        ops: &[BatchOp],
        envelope: &ArchiveEnvelope,
    ) -> Result<(), BindError> {
        if envelope.policy_binding != self.policy_binding {
            return Err(BindError::Policy);
        }
        let used: Vec<(u64, u64, &perp_core::oracle::OracleTranscript)> =
            ops.iter().filter_map(used_oracle).collect();
        if used.len() != envelope.refs.len() {
            return Err(BindError::Mismatch);
        }
        for ((market_id, now_ms, oracle), r) in used.iter().zip(&envelope.refs) {
            if r.market_id != *market_id || r.now_ms != *now_ms {
                return Err(BindError::Mismatch);
            }
            let pair = self
                .archive
                .load(r.archive_id, &self.policy, *market_id)
                .map_err(|_| BindError::Archive)?;
            let (normalized, _) = pair
                .for_operation(*now_ms)
                .map_err(|_| BindError::Mismatch)?;
            if !normalized.matches(oracle) {
                return Err(BindError::Mismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "report_archive_binding_tests.rs"]
mod tests;
