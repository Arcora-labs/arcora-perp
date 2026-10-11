//! Fixed-source native -> local mock-contract bridge, compiled only by tests.
//! A fresh target-context witness retains the original A3 pre-state, operations,
//! manifest, evidence and full containers. No old intent is resumed or rewritten.
//! Reconstructed archive receipt/admission metadata and IDs are NEW synthetic
//! data; the old corpus does not contain historical archive records to verify.
use crate::{
    candidate_protocol::{
        sha256, validate, ProgramIdentity, ProtocolRequest, TargetIdentity, TrustedRequest,
        UptimeObservation,
    },
    candidate_registration::{registration, UptimeEpoch},
    report_archive_binding::{
        used_oracle, ArchiveBinding, CandidateMaterial, CandidateReportEntry,
    },
};
use chainlink_oracle::{
    binding::{CandidateOutput, CandidateWitness, WIRE_MAGIC},
    report::body_from_full_report,
};
use chainlink_streams_client::{
    parse_response, report_pair::policy_binding, FeedId, Network, Request, UnverifiedReport,
};
use perp_core::{
    clock::ClockContext,
    commitment::{derive_roots, DerivedRoots},
    hash::Keccak256,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

const SOURCE_MANIFEST: &[u8] = include_bytes!(
    "../../../docs/audits/2026-10-11-chainlink-candidate-protocol/fixtures/manifest.json"
);
const SOURCE_PARITY: &[u8] =
    include_bytes!("../../../contracts/test/fixtures/chainlink-candidate-protocol.json");
const NORMAL: &[u8] = include_bytes!("../../../docs/audits/2026-10-11-chainlink-candidate-protocol/fixtures/normal-lifecycle.witness.bin");
const LIQUIDATION: &[u8] = include_bytes!(
    "../../../docs/audits/2026-10-11-chainlink-candidate-protocol/fixtures/liquidation.witness.bin"
);
const MANIFEST_SHA: &str = "3147718b8db6036f0ecb540157dfaea260f010726abdc2895d53baf4d08c6480";
const PARITY_SHA: &str = "1263230407bfe0c340a61d4106e952812abd7f16e93cac3397d3e68412bf2067";
const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 64 * 1024;
const MOCK_PROOF: &[u8] = b"arcora-native-contract-bridge-mock-proof-v1";
const PROVENANCE: &str = "fixed-source full containers; NEW synthetic receipt/admission metadata from report observations; NEW target archive IDs; no old archive identity or receipt revalidation";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BridgeError {
    Bounds,
    Format,
    Source,
    Context,
    Archive,
    Native,
    Write,
    Exists,
}

/// Captured from the actual, disposable Foundry context. Hashes are observer
/// pins, not independent RPC/deployment authentication supplied by this module.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BridgeContext {
    pub(crate) name: String,
    pub(crate) chain_id: u64,
    pub(crate) network: u8,
    pub(crate) clock_verifier: String,
    pub(crate) settlement: String,
    pub(crate) oracle_wrapper: String,
    pub(crate) verifier_proxy: String,
    pub(crate) sp1_adapter: String,
    pub(crate) sp1_gateway: String,
    pub(crate) uptime_feed: String,
    pub(crate) prefix_vault: String,
    pub(crate) clock_verifier_code_hash: String,
    pub(crate) settlement_code_hash: String,
    pub(crate) oracle_wrapper_code_hash: String,
    pub(crate) verifier_proxy_code_hash: String,
    pub(crate) sp1_adapter_code_hash: String,
    pub(crate) sp1_gateway_code_hash: String,
    pub(crate) uptime_feed_code_hash: String,
    pub(crate) prefix_vault_code_hash: String,
    pub(crate) anchored_at_ms: u64,
    pub(crate) max_window_ms: u64,
    pub(crate) clock_skew_ms: u64,
    pub(crate) uptime_round_id: String,
    pub(crate) uptime_started_at: u64,
    pub(crate) grace_seconds: u64,
    pub(crate) registered_receipt: String,
    pub(crate) clock_commitment: String,
    pub(crate) source_witness_sha256: String,
    pub(crate) base_commitment: String,
    pub(crate) policy_hash: String,
    pub(crate) post_consumed_deposit_count: u64,
    pub(crate) post_consumed_deposit_tip: String,
    pub(crate) program_vkey: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextDocument {
    schema: String,
    cases: Vec<BridgeContext>,
}

struct SourceCase {
    name: &'static str,
    bytes: &'static [u8],
    witness: CandidateWitness,
    entries: Vec<CandidateReportEntry>,
    roots: DerivedRoots,
    post_count: u64,
    post_tip: [u8; 32],
    native: CandidateOutput,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}
fn digest<const N: usize>(text: &str) -> Result<[u8; N], BridgeError> {
    let body = text.strip_prefix("0x").ok_or(BridgeError::Format)?;
    if body.len() != N * 2
        || !body
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Format);
    }
    let mut out = [0; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&body[i * 2..i * 2 + 2], 16).map_err(|_| BridgeError::Format)?;
    }
    Ok(out)
}
fn encoded(witness: &CandidateWitness) -> Result<Vec<u8>, BridgeError> {
    let body = postcard::to_allocvec(witness).map_err(|_| BridgeError::Format)?;
    if body.len() + WIRE_MAGIC.len() > chainlink_oracle::binding::MAX_WITNESS_BYTES {
        return Err(BridgeError::Bounds);
    }
    let mut bytes = WIRE_MAGIC.to_vec();
    bytes.extend(body);
    Ok(bytes)
}
fn sources() -> Result<Vec<SourceCase>, BridgeError> {
    if hex(&sha256(SOURCE_MANIFEST))[2..] != *MANIFEST_SHA
        || hex(&sha256(SOURCE_PARITY))[2..] != *PARITY_SHA
    {
        return Err(BridgeError::Source);
    }
    let manifest: Value =
        serde_json::from_slice(SOURCE_MANIFEST).map_err(|_| BridgeError::Source)?;
    let parity: Value = serde_json::from_slice(SOURCE_PARITY).map_err(|_| BridgeError::Source)?;
    for document in [&manifest, &parity] {
        if document["synthetic"] != true
            || document["real_don_verified"] != false
            || document["proof_generated"] != false
            || document["candidate_submission"] != "HOLD"
        {
            return Err(BridgeError::Source);
        }
    }
    for (name, bytes) in [
        (
            "candidate_registration.rs",
            include_bytes!("candidate_registration.rs").as_slice(),
        ),
        (
            "report_archive_binding.rs",
            include_bytes!("report_archive_binding.rs").as_slice(),
        ),
        (
            "price_lifecycle_tests.rs",
            include_bytes!("price_lifecycle_tests.rs").as_slice(),
        ),
        (
            "candidate_protocol_tests.rs",
            include_bytes!("candidate_protocol_tests.rs").as_slice(),
        ),
    ] {
        if manifest["sources_sha256"][name] != hex(&sha256(bytes))
            || parity["sources_sha256"][name] != manifest["sources_sha256"][name]
        {
            return Err(BridgeError::Source);
        }
    }
    let manifest_cases = manifest["cases"].as_array().ok_or(BridgeError::Source)?;
    let parity_cases = parity["cases"].as_array().ok_or(BridgeError::Source)?;
    if manifest_cases.len() != 2 || parity_cases.len() != 2 {
        return Err(BridgeError::Source);
    }
    let mut cases = Vec::new();
    for (name, bytes) in [("normal-lifecycle", NORMAL), ("liquidation", LIQUIDATION)] {
        let meta = manifest_cases
            .iter()
            .find(|c| c["name"] == name)
            .ok_or(BridgeError::Source)?;
        let original = parity_cases
            .iter()
            .find(|c| c["name"] == name)
            .ok_or(BridgeError::Source)?;
        if bytes.len() > chainlink_oracle::binding::MAX_WITNESS_BYTES
            || meta["witness_sha256"] != hex(&sha256(bytes))[2..]
            || original["witness_sha256"] != hex(&sha256(bytes))
        {
            return Err(BridgeError::Source);
        }
        let body = bytes.strip_prefix(WIRE_MAGIC).ok_or(BridgeError::Source)?;
        let (witness, rest): (CandidateWitness, _) =
            postcard::take_from_bytes(body).map_err(|_| BridgeError::Source)?;
        if !rest.is_empty() || encoded(&witness)? != bytes {
            return Err(BridgeError::Source);
        }
        let entries: Vec<CandidateReportEntry> =
            serde_json::from_value(original["original_entries"].clone())
                .map_err(|_| BridgeError::Source)?;
        let registered = registration(&witness.policy, &witness.clock.3, &entries)
            .map_err(|_| BridgeError::Source)?;
        let native =
            chainlink_oracle::binding::run_encoded(bytes).map_err(|_| BridgeError::Native)?;
        if meta["expected_commitment"] != hex(&native.commitment)[2..]
            || original["input_hash"] != hex(&registered.input_hash)
            || original["entries_abi"] != hex(&registered.entries_abi)
            || original["evidence_hash"] != hex(&native.evidence_hash)
            || registered.evidence_hash != native.evidence_hash
            || original["policy_hash"] != hex(&native.policy_hash)
            || serde_json::from_value::<ClockContext>(original["clock"].clone())
                .map_err(|_| BridgeError::Source)?
                != witness.clock.3
        {
            return Err(BridgeError::Source);
        }
        let mut post = witness.clock.0.clone();
        let roots = derive_roots(&mut post, &witness.clock.1, &witness.clock.2)
            .map_err(|_| BridgeError::Native)?;
        if roots.wind_down_phase != 0
            || post.consumed_deposit_count != 9
            || post.consumed_deposit_tip == [0; 32]
            || roots.deposits_root != post.consumed_deposit_tip
            || roots.commitment::<Keccak256>() != witness.clock.3.base_commitment
        {
            return Err(BridgeError::Source);
        }
        cases.push(SourceCase {
            name,
            bytes,
            witness,
            entries,
            roots,
            post_count: post.consumed_deposit_count,
            post_tip: post.consumed_deposit_tip,
            native,
        });
    }
    Ok(cases)
}
fn root_json(r: &DerivedRoots) -> Value {
    json!({"prev_state_root":hex(&r.prev_state_root),"manifest_hash":hex(&r.manifest_hash),"new_state_root":hex(&r.new_state_root),"ordered_root":hex(&r.ordered_root),"withdrawals_root":hex(&r.withdrawals_root),"rejected_root":hex(&r.rejected_root),"deposits_root":hex(&r.deposits_root)})
}
fn entry_json(entries: &[CandidateReportEntry]) -> Vec<Value> {
    entries.iter().map(|e| json!({"market_id":e.market_id,"now_ms":e.now_ms,"base_full_report":hex(&e.base_report),"quote_full_report":hex(&e.quote_report)})).collect()
}
fn clock_json(c: &ClockContext) -> Value {
    json!({"chain_id":c.chain_id,"verifier":hex(&c.verifier),"settlement":hex(&c.settlement),"batch_id":c.batch_id,"previous_root":hex(&c.previous_root),"base_commitment":hex(&c.base_commitment),"phase":c.phase,"first_ms":c.first_ms,"last_ms":c.last_ms,"timed_ops":c.timed_ops,"anchored_at_ms":c.anchored_at_ms,"max_window_ms":c.max_window_ms,"clock_skew_ms":c.clock_skew_ms})
}
fn source_json(source: &SourceCase) -> Result<Value, BridgeError> {
    let c = &source.witness.clock.3;
    let registered = registration(&source.witness.policy, c, &source.entries)
        .map_err(|_| BridgeError::Source)?;
    Ok(
        json!({"name":source.name,"source_witness_sha256":hex(&sha256(source.bytes)),"batch_id":c.batch_id,"phase":source.roots.wind_down_phase,"roots":root_json(&source.roots),"post_consumed_deposit_count":source.post_count,"post_consumed_deposit_tip":hex(&source.post_tip),"base_commitment":hex(&c.base_commitment),"first_ms":c.first_ms,"last_ms":c.last_ms,"timed_ops":c.timed_ops,"max_window_ms":c.max_window_ms,"clock_skew_ms":c.clock_skew_ms,"policy_hash":hex(&source.native.policy_hash),"source_policy_binding":hex(&policy_binding(&source.witness.policy).map_err(|_| BridgeError::Source)?),"source_clock_receipt":hex(&c.receipt()),"source_clock_commitment":hex(&source.native.clock_commitment),"source_candidate_commitment":hex(&source.native.commitment),"evidence_hash":hex(&source.native.evidence_hash),"input_hash":hex(&registered.input_hash),"entries_abi":hex(&registered.entries_abi),"entries":entry_json(&source.entries),"archive_provenance":PROVENANCE}),
    )
}

fn fresh_dir(path: &Path) -> Result<(), BridgeError> {
    std::fs::create_dir(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            BridgeError::Exists
        } else {
            BridgeError::Write
        }
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| BridgeError::Write)?;
    }
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), BridgeError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| BridgeError::Write)?;
    file.write_all(bytes).map_err(|_| BridgeError::Write)?;
    file.sync_all().map_err(|_| BridgeError::Write)
}
fn write_json(path: &Path, value: &Value) -> Result<(), BridgeError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| BridgeError::Format)?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(BridgeError::Bounds);
    }
    write_new(path, &bytes)
}
fn read_context(path: &Path) -> Result<(ContextDocument, [u8; 32]), BridgeError> {
    let before = std::fs::symlink_metadata(path).map_err(|_| BridgeError::Context)?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_CONTEXT_BYTES as u64 {
        return Err(BridgeError::Bounds);
    }
    let file = File::open(path).map_err(|_| BridgeError::Context)?;
    let opened = file.metadata().map_err(|_| BridgeError::Context)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(BridgeError::Context);
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONTEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BridgeError::Context)?;
    if bytes.len() as u64 != before.len() || bytes.len() > MAX_CONTEXT_BYTES {
        return Err(BridgeError::Bounds);
    }
    let document: ContextDocument =
        serde_json::from_slice(&bytes).map_err(|_| BridgeError::Format)?;
    if document.schema != "arcora-native-contract-bridge-context-v1"
        || document.cases.len() != 2
        || document
            .cases
            .iter()
            .filter(|c| c.name == "normal-lifecycle")
            .count()
            != 1
        || document
            .cases
            .iter()
            .filter(|c| c.name == "liquidation")
            .count()
            != 1
    {
        return Err(BridgeError::Context);
    }
    Ok((document, sha256(&bytes)))
}

pub(crate) fn export_source(dest: &Path) -> Result<(), BridgeError> {
    let sources = sources()?;
    let cases = sources
        .iter()
        .map(source_json)
        .collect::<Result<Vec<_>, _>>()?;
    fresh_dir(dest)?;
    for source in &sources {
        write_new(
            &dest.join(format!("{}.source-witness.bin", source.name)),
            source.bytes,
        )?;
        write_new(
            &dest.join(format!("{}.source-native-public.bin", source.name)),
            &source.native.commitment,
        )?;
    }
    write_json(
        &dest.join("source.json"),
        &json!({"schema":"arcora-native-contract-bridge-source-v1","synthetic":true,"real_don_verified":false,"proof_generated":false,"candidate_submission":"HOLD","source_manifest_sha256":hex(&sha256(SOURCE_MANIFEST)),"source_registration_json_sha256":hex(&sha256(SOURCE_PARITY)),"cases":cases}),
    )
}

fn reconstructed_report(
    full: &[u8],
    network: Network,
    max_age_ms: u64,
) -> Result<UnverifiedReport, BridgeError> {
    let decoded = body_from_full_report(full)
        .map_err(|_| BridgeError::Archive)?
        .decode()
        .map_err(|_| BridgeError::Archive)?;
    let response = json!({"report":{"feedID":hex(&decoded.feed_id),"validFromTimestamp":decoded.valid_from,"observationsTimestamp":decoded.observations,"fullReport":hex(full)}});
    let request = Request::new(
        network,
        FeedId::parse_v3(&hex(&decoded.feed_id)).map_err(|_| BridgeError::Archive)?,
        max_age_ms,
    )
    .map_err(|_| BridgeError::Archive)?;
    parse_response(
        &serde_json::to_vec(&response).map_err(|_| BridgeError::Format)?,
        &request,
        u64::from(decoded.observations) * 1000,
    )
    .map_err(|_| BridgeError::Archive)
}

fn derive_case(
    source: &SourceCase,
    context: &BridgeContext,
    archive_dir: &Path,
) -> Result<(Vec<u8>, CandidateMaterial, Value), BridgeError> {
    let addresses = [
        &context.clock_verifier,
        &context.settlement,
        &context.oracle_wrapper,
        &context.verifier_proxy,
        &context.sp1_adapter,
        &context.sp1_gateway,
        &context.uptime_feed,
        &context.prefix_vault,
    ]
    .into_iter()
    .map(|s| digest::<20>(s))
    .collect::<Result<Vec<_>, _>>()?;
    if addresses.contains(&[0; 20])
        || addresses
            .iter()
            .enumerate()
            .any(|(i, a)| addresses[..i].contains(a))
    {
        return Err(BridgeError::Context);
    }
    let hashes = [
        &context.clock_verifier_code_hash,
        &context.settlement_code_hash,
        &context.oracle_wrapper_code_hash,
        &context.verifier_proxy_code_hash,
        &context.sp1_adapter_code_hash,
        &context.sp1_gateway_code_hash,
        &context.uptime_feed_code_hash,
        &context.prefix_vault_code_hash,
    ]
    .into_iter()
    .map(|s| digest::<32>(s))
    .collect::<Result<Vec<_>, _>>()?;
    if hashes.contains(&[0; 32])
        || context.name != source.name
        || context.chain_id != source.witness.policy.chain_id
        || context.network != source.witness.policy.network
        || context.anchored_at_ms == 0
        || !context.anchored_at_ms.is_multiple_of(1000)
        || context.max_window_ms != source.witness.clock.3.max_window_ms
        || context.clock_skew_ms != source.witness.clock.3.clock_skew_ms
        || digest::<32>(&context.source_witness_sha256)? != sha256(source.bytes)
        || digest::<32>(&context.base_commitment)? != source.roots.commitment::<Keccak256>()
        || digest::<32>(&context.policy_hash)? != source.native.policy_hash
        || context.post_consumed_deposit_count != source.post_count
        || digest::<32>(&context.post_consumed_deposit_tip)? != source.post_tip
        || digest::<32>(&context.program_vkey)? != ProgramIdentity::pinned().vkey
    {
        return Err(BridgeError::Context);
    }
    let mut witness = source.witness.clone();
    witness.policy.oracle_wrapper = addresses[2];
    witness.policy.verifier_proxy = addresses[3];
    let clock = &mut witness.clock.3;
    clock.verifier = addresses[0];
    clock.settlement = addresses[1];
    clock.anchored_at_ms = context.anchored_at_ms;
    if digest::<32>(&context.registered_receipt)? != clock.receipt()
        || digest::<32>(&context.clock_commitment)? != clock.commitment()
    {
        return Err(BridgeError::Context);
    }
    let mut post = witness.clock.0.clone();
    let roots = derive_roots(&mut post, &witness.clock.1, &witness.clock.2)
        .map_err(|_| BridgeError::Native)?;
    if roots != source.roots
        || post.consumed_deposit_count != source.post_count
        || post.consumed_deposit_tip != source.post_tip
    {
        return Err(BridgeError::Source);
    }
    let ops: Vec<_> = witness.clock.1.iter().filter_map(used_oracle).collect();
    if ops.len() != source.entries.len() {
        return Err(BridgeError::Source);
    }
    fresh_dir(archive_dir)?;
    let mut binding = ArchiveBinding::create_in(archive_dir, witness.policy.clone())
        .map_err(|_| BridgeError::Archive)?;
    let mut metadata = Vec::new();
    let network = match context.network {
        0 => Network::Testnet,
        1 => Network::Mainnet,
        _ => return Err(BridgeError::Context),
    };
    for ((market, now_ms, oracle), entry) in ops.iter().zip(&source.entries) {
        if (*market, *now_ms) != (entry.market_id, entry.now_ms) {
            return Err(BridgeError::Source);
        }
        let max_age = witness
            .policy
            .market(*market)
            .map_err(|_| BridgeError::Archive)?
            .max_report_age_ms;
        let base = reconstructed_report(&entry.base_report, network, max_age)?;
        let quote = reconstructed_report(&entry.quote_report, network, max_age)?;
        let prepared_at = base.received_ms().max(quote.received_ms());
        metadata.push(json!({"market_id":market,"operation_now_ms":now_ms,"synthetic_prepared_at_ms":prepared_at,"synthetic_base_received_ms":base.received_ms(),"synthetic_quote_received_ms":quote.received_ms()}));
        if !binding
            .admit_with(*market, base, quote, prepared_at, |n| n.matches(oracle))
            .map_err(|_| BridgeError::Archive)?
        {
            return Err(BridgeError::Archive);
        }
    }
    let envelope = binding
        .bind_ops(&witness.clock.1)
        .map_err(|_| BridgeError::Archive)?;
    let material = binding
        .candidate_material(&witness.clock.1, &envelope)
        .map_err(|_| BridgeError::Archive)?;
    if postcard::to_allocvec(&material.entries).map_err(|_| BridgeError::Format)?
        != postcard::to_allocvec(&source.entries).map_err(|_| BridgeError::Format)?
        || postcard::to_allocvec(&material.evidence).map_err(|_| BridgeError::Format)?
            != postcard::to_allocvec(&source.witness.evidence).map_err(|_| BridgeError::Format)?
    {
        return Err(BridgeError::Source);
    }
    let bytes = encoded(&witness)?;
    let native = chainlink_oracle::binding::run_encoded(&bytes).map_err(|_| BridgeError::Native)?;
    let registered = registration(&witness.policy, &witness.clock.3, &material.entries)
        .map_err(|_| BridgeError::Native)?;
    let initial_uptime = UptimeObservation {
        epoch: UptimeEpoch {
            round_id: digest::<10>(&context.uptime_round_id)?,
            started_at: context.uptime_started_at,
        },
        ready: true,
        observed_at_seconds: context.anchored_at_ms / 1000,
    };
    let target = TargetIdentity {
        chain_id: context.chain_id,
        network: context.network,
        clock_verifier: addresses[0],
        settlement: addresses[1],
        oracle_wrapper: addresses[2],
        verifier_proxy: addresses[3],
        policy_hash: native.policy_hash,
        clock_version: 2,
        uptime_feed: addresses[6],
        grace_seconds: context.grace_seconds,
        settlement_code_hash: hashes[1],
        clock_code_hash: hashes[0],
        wrapper_code_hash: hashes[2],
        proxy_code_hash: hashes[3],
        uptime_code_hash: hashes[6],
    };
    let request = ProtocolRequest {
        program: ProgramIdentity::pinned(),
        target: target.clone(),
        witness: bytes.clone(),
        material: material.clone(),
        initial_uptime,
    };
    validate(
        &request,
        &TrustedRequest::extracted(&request, target, initial_uptime),
    )
    .map_err(|_| BridgeError::Context)?;
    if native.evidence_hash != source.native.evidence_hash
        || registered.input_hash
            != registration(
                &source.witness.policy,
                &source.witness.clock.3,
                &source.entries,
            )
            .map_err(|_| BridgeError::Source)?
            .input_hash
        || native.policy_hash != source.native.policy_hash
    {
        return Err(BridgeError::Source);
    }
    let program = ProgramIdentity::pinned();
    let value = json!({"name":source.name,"source_witness_sha256":hex(&sha256(source.bytes)),"witness_sha256":hex(&sha256(&bytes)),"witness_bytes":bytes.len(),"roots":root_json(&roots),"batch_id":witness.clock.3.batch_id,"phase":roots.wind_down_phase,"post_consumed_deposit_count":post.consumed_deposit_count,"post_consumed_deposit_tip":hex(&post.consumed_deposit_tip),"base_commitment":hex(&witness.clock.3.base_commitment),"clock":clock_json(&witness.clock.3),"clock_receipt":hex(&witness.clock.3.receipt()),"clock_commitment":hex(&native.clock_commitment),"policy_hash":hex(&native.policy_hash),"evidence_hash":hex(&native.evidence_hash),"input_hash":hex(&registered.input_hash),"entries_abi":hex(&registered.entries_abi),"entries":entry_json(&material.entries),"candidate_commitment":hex(&native.commitment),"mock_proof":hex(MOCK_PROOF),"program":{"wire_magic":hex(&program.wire_magic),"sdk_release":program.sdk_release,"elf_sha256":hex(&program.elf_sha256),"vkey":hex(&program.vkey)},"target_context":context_json(context),"policy_binding":hex(&material.policy_binding),"material_hash":hex(&material.material_hash),"new_archive_refs":material.refs,"new_synthetic_admission_metadata":metadata,"archive_provenance":PROVENANCE,"op_count":witness.clock.1.len(),"evidence_count":witness.evidence.len()});
    Ok((bytes, material, value))
}

fn context_json(context: &BridgeContext) -> Value {
    // The exact caller-owned code hashes are preserved for Solidity replay
    // assertions; Rust does not independently load EVM runtime code.
    serde_json::to_value(context).expect("fixed scalar context serialization")
}

pub(crate) fn export_derived(context_file: &Path, dest: &Path) -> Result<(), BridgeError> {
    let (document, context_sha256) = read_context(context_file)?;
    let sources = sources()?;
    fresh_dir(dest)?;
    let mut cases = Vec::new();
    let mut cpu_cases = Vec::new();
    for source in &sources {
        let context = document
            .cases
            .iter()
            .find(|c| c.name == source.name)
            .ok_or(BridgeError::Context)?;
        let (bytes, material, value) = derive_case(
            source,
            context,
            &dest.join(format!("reconstructed-archive-{}", source.name)),
        )?;
        write_new(&dest.join(format!("{}.witness.bin", source.name)), &bytes)?;
        write_new(
            &dest.join(format!("{}.native-public.bin", source.name)),
            &digest::<32>(
                value["candidate_commitment"]
                    .as_str()
                    .ok_or(BridgeError::Format)?,
            )?,
        )?;
        write_new(
            &dest.join(format!("{}.material.bin", source.name)),
            &postcard::to_allocvec(&material).map_err(|_| BridgeError::Format)?,
        )?;
        cpu_cases.push(json!({"name":source.name,"witness_file":format!("{}.witness.bin",source.name),"witness_sha256":hex(&sha256(&bytes))[2..],"witness_bytes":bytes.len(),"outcome":"PASS","native_error":null,"expected_commitment":value["candidate_commitment"].as_str().ok_or(BridgeError::Format)?[2..],"op_count":value["op_count"],"evidence_count":value["evidence_count"]}));
        cases.push(value);
    }
    let fingerprints = json!({"candidate_bridge.rs":hex(&sha256(include_bytes!("candidate_bridge.rs"))),"original_four_builders":serde_json::from_slice::<Value>(SOURCE_MANIFEST).map_err(|_|BridgeError::Source)?["sources_sha256"]});
    write_json(
        &dest.join("bridge.json"),
        &json!({"schema":"arcora-native-contract-bridge-v1","synthetic":true,"real_don_verified":false,"proof_generated":false,"candidate_submission":"HOLD","mock_vault_prefix":true,"captured_context_sha256":hex(&context_sha256),"source_manifest_sha256":hex(&sha256(SOURCE_MANIFEST)),"source_registration_json_sha256":hex(&sha256(SOURCE_PARITY)),"sources_sha256":fingerprints,"cases":cases}),
    )?;
    write_json(
        &dest.join("manifest.json"),
        &json!({"synthetic":true,"real_don_verified":false,"proof_generated":false,"candidate_submission":"HOLD","sources_sha256":fingerprints,"cases":cpu_cases}),
    )
}

#[test]
fn bridge_fixed_source_roots_full_containers_and_native_identity_are_pinned() {
    let cases = sources().unwrap();
    assert_eq!(cases.len(), 2);
    for source in cases {
        assert_eq!(source.roots.wind_down_phase, 0);
        assert_eq!(source.post_count, 9);
        assert_ne!(source.post_tip, [0; 32]);
        assert_eq!(
            source.native.clock_commitment,
            source.witness.clock.3.commitment()
        );
    }
}

struct OwnedDirectory(std::path::PathBuf);
impl OwnedDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "arcora-native-bridge-{}-{}",
            std::process::id(),
            hex(&crate::csprng_bytes32())
        ));
        fresh_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn synthetic_context(source: &SourceCase) -> BridgeContext {
    // Unit-test caller-owned hints. The exported acceptance contexts instead
    // come from the actual dedicated Foundry capture and replay assertions.
    let mut clock = source.witness.clock.3;
    clock.verifier = [0x41; 20];
    clock.settlement = [0x42; 20];
    clock.anchored_at_ms = 2_001_000;
    BridgeContext {
        name: source.name.into(),
        chain_id: source.witness.policy.chain_id,
        network: source.witness.policy.network,
        clock_verifier: hex(&clock.verifier),
        settlement: hex(&clock.settlement),
        oracle_wrapper: hex(&[0x43; 20]),
        verifier_proxy: hex(&[0x44; 20]),
        sp1_adapter: hex(&[0x45; 20]),
        sp1_gateway: hex(&[0x46; 20]),
        uptime_feed: hex(&[0x47; 20]),
        prefix_vault: hex(&[0x48; 20]),
        clock_verifier_code_hash: hex(&[0x51; 32]),
        settlement_code_hash: hex(&[0x52; 32]),
        oracle_wrapper_code_hash: hex(&[0x53; 32]),
        verifier_proxy_code_hash: hex(&[0x54; 32]),
        sp1_adapter_code_hash: hex(&[0x55; 32]),
        sp1_gateway_code_hash: hex(&[0x56; 32]),
        uptime_feed_code_hash: hex(&[0x57; 32]),
        prefix_vault_code_hash: hex(&[0x58; 32]),
        anchored_at_ms: clock.anchored_at_ms,
        max_window_ms: clock.max_window_ms,
        clock_skew_ms: clock.clock_skew_ms,
        uptime_round_id: "0x0102030405060708090a".into(),
        uptime_started_at: 1_000,
        grace_seconds: 60,
        registered_receipt: hex(&clock.receipt()),
        clock_commitment: hex(&clock.commitment()),
        source_witness_sha256: hex(&sha256(source.bytes)),
        base_commitment: hex(&clock.base_commitment),
        policy_hash: hex(&source.native.policy_hash),
        post_consumed_deposit_count: source.post_count,
        post_consumed_deposit_tip: hex(&source.post_tip),
        program_vkey: hex(&ProgramIdentity::pinned().vkey),
    }
}

#[test]
fn bridge_fresh_target_keeps_source_execution_times_and_full_containers_exact() {
    let directory = OwnedDirectory::new();
    for source in sources().unwrap() {
        let context = synthetic_context(&source);
        let path = directory.0.join(source.name);
        let (bytes, material, export) = derive_case(&source, &context, &path).unwrap();
        let witness: CandidateWitness = postcard::from_bytes(&bytes[8..]).unwrap();
        assert_eq!(
            postcard::to_allocvec(&(
                &witness.clock.0,
                &witness.clock.1,
                &witness.clock.2,
                &witness.evidence
            ))
            .unwrap(),
            postcard::to_allocvec(&(
                &source.witness.clock.0,
                &source.witness.clock.1,
                &source.witness.clock.2,
                &source.witness.evidence
            ))
            .unwrap()
        );
        assert_eq!(witness.clock.3.first_ms, source.witness.clock.3.first_ms);
        assert_eq!(witness.clock.3.last_ms, source.witness.clock.3.last_ms);
        assert_eq!(witness.clock.3.anchored_at_ms, 2_001_000);
        assert_eq!(
            postcard::to_allocvec(&material.entries).unwrap(),
            postcard::to_allocvec(&source.entries).unwrap()
        );
        assert_ne!(bytes, source.bytes);
        assert_ne!(
            export["candidate_commitment"],
            hex(&source.native.commitment)
        );
        assert_ne!(
            material.policy_binding,
            policy_binding(&source.witness.policy).unwrap()
        );
        assert_eq!(material.material_hash, material.recomputed_hash().unwrap());
        let archive = chainlink_streams_client::report_archive::ReportArchive::open_existing(
            &path.join("store"),
        )
        .unwrap();
        for (reference, entry) in material.refs.iter().zip(&material.entries) {
            let pair = archive
                .load(reference.archive_id, &material.policy, reference.market_id)
                .unwrap();
            assert_eq!(pair.base().full_report(), entry.base_report);
            assert_eq!(pair.quote().full_report(), entry.quote_report);
            assert!(archive
                .load(
                    reference.archive_id,
                    &source.witness.policy,
                    reference.market_id
                )
                .is_err());
            assert!(pair.prepared_at_ms() <= entry.now_ms);
            assert_eq!(
                pair.base().received_ms(),
                u64::from(pair.base().decoded().observations) * 1000
            );
        }
    }
}

#[test]
fn bridge_wrong_context_identity_anchor_count_and_epoch_refuse_derivation() {
    let directory = OwnedDirectory::new();
    let source = sources().unwrap().remove(0);
    let original = synthetic_context(&source);
    for (index, kind) in [
        "source",
        "chain",
        "network",
        "base",
        "policy",
        "count",
        "tip",
        "vkey",
        "receipt",
        "commitment",
        "subsecond",
        "window",
        "skew",
        "zero_address",
        "alias",
        "zero_code",
        "epoch",
        "grace",
        "wrong_name",
    ]
    .iter()
    .enumerate()
    {
        let mut context = original.clone();
        match *kind {
            "source" => context.source_witness_sha256 = hex(&[0x99; 32]),
            "chain" => context.chain_id = 8453,
            "network" => context.network = 1,
            "base" => context.base_commitment = hex(&[0x99; 32]),
            "policy" => context.policy_hash = hex(&[0x99; 32]),
            "count" => context.post_consumed_deposit_count += 1,
            "tip" => context.post_consumed_deposit_tip = hex(&[0; 32]),
            "vkey" => context.program_vkey = hex(&[0x99; 32]),
            "receipt" => context.registered_receipt = hex(&[0x99; 32]),
            "commitment" => context.clock_commitment = hex(&[0x99; 32]),
            "subsecond" => context.anchored_at_ms += 1,
            "window" => context.max_window_ms += 1,
            "skew" => context.clock_skew_ms += 1,
            "zero_address" => context.sp1_adapter = hex(&[0; 20]),
            "alias" => context.sp1_gateway = context.verifier_proxy.clone(),
            "zero_code" => context.sp1_gateway_code_hash = hex(&[0; 32]),
            "epoch" => context.uptime_round_id = hex(&[0; 10]),
            "grace" => context.grace_seconds = 1_000,
            "wrong_name" => context.name = "liquidation".into(),
            _ => unreachable!(),
        }
        assert!(
            derive_case(
                &source,
                &context,
                &directory.0.join(format!("refused-{index}"))
            )
            .is_err(),
            "{kind}"
        );
    }
}

#[test]
fn bridge_bounded_context_format_and_fresh_export_never_replace_existing_data() {
    let directory = OwnedDirectory::new();
    let contexts: Vec<_> = sources().unwrap().iter().map(synthetic_context).collect();
    let good = json!({"schema":"arcora-native-contract-bridge-context-v1","cases":contexts});
    let path = directory.0.join("context.json");
    let bytes = serde_json::to_vec(&good).unwrap();
    write_new(&path, &bytes).unwrap();
    assert_eq!(read_context(&path).unwrap().1, sha256(&bytes));
    let output = directory.0.join("source");
    export_source(&output).unwrap();
    let before = std::fs::read(output.join("source.json")).unwrap();
    assert_eq!(export_source(&output), Err(BridgeError::Exists));
    assert_eq!(std::fs::read(output.join("source.json")).unwrap(), before);
    assert_eq!(
        std::fs::read(output.join("normal-lifecycle.source-witness.bin")).unwrap(),
        NORMAL
    );
    let mut cases = vec![good.clone(); 4];
    cases[0]["schema"] = "DPCINT4".into();
    cases[1]["cases"][0]["unknown"] = true.into();
    cases[2]["cases"][1] = cases[2]["cases"][0].clone();
    cases[3]["cases"][0]["program_vkey"] = 99.into();
    for (index, value) in cases.iter().enumerate() {
        let path = directory.0.join(format!("bad-{index}.json"));
        write_new(&path, &serde_json::to_vec(value).unwrap()).unwrap();
        assert!(read_context(&path).is_err());
    }
    let large = directory.0.join("large.json");
    write_new(&large, &vec![b' '; MAX_CONTEXT_BYTES + 1]).unwrap();
    assert!(matches!(read_context(&large), Err(BridgeError::Bounds)));
    #[cfg(unix)]
    {
        let link = directory.0.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_context(&link).is_err());
    }
}

#[test]
fn bridge_actual_captured_context_rederives_exact_contract_and_cpu_corpus() {
    // These are the NEW target-bound fixtures. This does not rewrite or resume
    // any original source witness or Pending/Prepared protocol record.
    const CONTEXT: &[u8] = include_bytes!(
        "../../../contracts/test/fixtures/chainlink-native-contract-bridge-context.json"
    );
    const CONTRACT: &[u8] =
        include_bytes!("../../../contracts/test/fixtures/chainlink-native-contract-bridge.json");
    const BRIDGE: &[u8] = include_bytes!(
        "../../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures/bridge.json"
    );
    const CPU_MANIFEST: &[u8] = include_bytes!(
        "../../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures/manifest.json"
    );
    type GoldenCase = (&'static str, &'static [u8], &'static [u8], &'static [u8]);
    let corpus: [GoldenCase; 2] = [
        (
            "normal-lifecycle",
            include_bytes!("../../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures/normal-lifecycle.witness.bin"),
            include_bytes!("../../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures/normal-lifecycle.native-public.bin"),
            include_bytes!("../../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures/normal-lifecycle.material.bin"),
        ),
        (
            "liquidation",
            include_bytes!("../../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures/liquidation.witness.bin"),
            include_bytes!("../../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures/liquidation.native-public.bin"),
            include_bytes!("../../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures/liquidation.material.bin"),
        ),
    ];
    let directory = OwnedDirectory::new();
    let context_file = directory.0.join("actual-context.json");
    write_new(&context_file, CONTEXT).unwrap();
    let destination = directory.0.join("derived");
    export_derived(&context_file, &destination).unwrap();
    let actual: Value =
        serde_json::from_slice(&std::fs::read(destination.join("bridge.json")).unwrap()).unwrap();
    let contract: Value = serde_json::from_slice(CONTRACT).unwrap();
    let committed: Value = serde_json::from_slice(BRIDGE).unwrap();
    let cpu: Value = serde_json::from_slice(CPU_MANIFEST).unwrap();
    let actual_cpu: Value =
        serde_json::from_slice(&std::fs::read(destination.join("manifest.json")).unwrap()).unwrap();
    for key in [
        "schema",
        "synthetic",
        "real_don_verified",
        "proof_generated",
        "candidate_submission",
        "mock_vault_prefix",
        "captured_context_sha256",
        "source_manifest_sha256",
        "source_registration_json_sha256",
        "cases",
    ] {
        assert_eq!(actual[key], contract[key], "contract fixture {key}");
        assert_eq!(actual[key], committed[key], "native fixture {key}");
    }
    assert_eq!(actual["captured_context_sha256"], hex(&sha256(CONTEXT)));
    assert_eq!(actual_cpu["cases"], cpu["cases"]);
    assert_eq!(actual["cases"].as_array().unwrap().len(), corpus.len());
    // Source metadata includes this module's own hash, which changes when the
    // guard is added. All execution, context and archive payloads remain pinned.
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures");
    for (name, witness, public, material) in corpus {
        for (extension, expected) in [
            ("witness.bin", witness),
            ("native-public.bin", public),
            ("material.bin", material),
        ] {
            assert_eq!(
                std::fs::read(destination.join(format!("{name}.{extension}"))).unwrap(),
                expected,
                "{name} {extension}"
            );
        }
        let native = chainlink_oracle::binding::run_encoded(witness).unwrap();
        assert_eq!(native.commitment.as_slice(), public);
        let material: CandidateMaterial = postcard::from_bytes(material).unwrap();
        assert_eq!(material.material_hash, material.recomputed_hash().unwrap());
        for reference in &material.refs {
            let relative = Path::new(&format!("reconstructed-archive-{name}"))
                .join("store")
                .join(format!("{}.json", reference.archive_id.hex()));
            assert_eq!(
                std::fs::read(destination.join(&relative)).unwrap(),
                std::fs::read(fixture_root.join(&relative)).unwrap(),
                "{name} exact new synthetic archive record"
            );
        }
    }
    assert_eq!(
        export_derived(&context_file, &destination),
        Err(BridgeError::Exists)
    );
    assert_eq!(
        std::fs::read(destination.join("normal-lifecycle.witness.bin")).unwrap(),
        corpus[0].1
    );
}

#[test]
#[ignore = "explicit fresh-directory public fixed-source bridge export"]
fn export_native_contract_bridge_source() {
    let dest = std::path::PathBuf::from(
        std::env::var_os("ARCORA_CHAINLINK_BRIDGE_SOURCE_EXPORT")
            .expect("fresh explicit output directory"),
    );
    export_source(&dest).unwrap();
}
#[test]
#[ignore = "explicit owned Foundry-context bridge derivation; no proof generation"]
fn export_native_contract_bridge_derived() {
    let context = std::path::PathBuf::from(
        std::env::var_os("ARCORA_CHAINLINK_BRIDGE_CONTEXT_JSON")
            .expect("explicit captured context file"),
    );
    let dest = std::path::PathBuf::from(
        std::env::var_os("ARCORA_CHAINLINK_BRIDGE_EXPORT")
            .expect("fresh explicit output directory"),
    );
    export_derived(&context, &dest).unwrap();
}
