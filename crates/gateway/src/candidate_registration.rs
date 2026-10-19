//! Offline candidate registration encoding. Compiled only by the test host.
//! Canonical containers and policy checks do not authenticate DON signatures.
use crate::report_archive_binding::CandidateReportEntry;
use chainlink_oracle::{
    binding::MAX_ENTRIES,
    policy::Policy,
    report::{body_from_full_report, MAX_FULL_REPORT},
};
use perp_core::clock::{abi_u64, keccak, ClockContext};

// abi.encode(single Entry[]): top offset, length, tuple offsets, and tuple tails.
pub(crate) const MAX_ENTRIES_ABI_BYTES: usize =
    64 + MAX_ENTRIES * (32 + 128 + 2 * (32 + MAX_FULL_REPORT));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegistrationError {
    Bounds,
    Report,
    Policy,
    Clock,
    Epoch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Registration {
    /// Exactly Solidity abi.encode(entries), excluding selector/batch/phase.
    pub(crate) entries_abi: Vec<u8>,
    pub(crate) input_hash: [u8; 32],
    pub(crate) evidence_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct UptimeEpoch {
    /// Canonical unsigned uint80 encoded as ten big-endian bytes.
    pub(crate) round_id: [u8; 10],
    pub(crate) started_at: u64,
}

/// Match the strict epoch grace checks in the oracle wrapper. This requires an
/// independently obtained healthy status observation; it is not a feed reader.
/// Price-free records skip uptime exactly as the Solidity wrapper does.
pub(crate) fn validate_epoch(
    epoch: UptimeEpoch,
    observed_at_seconds: u64,
    grace_seconds: u64,
    first_operation_ms: Option<u64>,
) -> Result<(), RegistrationError> {
    let Some(first_ms) = first_operation_ms else {
        return Ok(());
    };
    if epoch.round_id == [0; 10]
        || epoch.started_at == 0
        || grace_seconds == 0
        || observed_at_seconds <= epoch.started_at
        || observed_at_seconds - epoch.started_at <= grace_seconds
        || first_ms / 1000 <= epoch.started_at
        || first_ms / 1000 - epoch.started_at <= grace_seconds
    {
        return Err(RegistrationError::Epoch);
    }
    Ok(())
}

fn word(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&abi_u64(value));
}

fn bytes_tail(out: &mut Vec<u8>, value: &[u8]) {
    // Full-report validation makes every container a multiple of 32 bytes.
    word(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// Build the exact Solidity Entry[] encoding and independently derive ordered
/// evidence from the original report containers, never from caller hash labels.
/// The caller additionally binds this result to native operation evidence and
/// to observed immutable on-chain clock/report records before proving.
pub(crate) fn registration(
    policy: &Policy,
    clock: &ClockContext,
    entries: &[CandidateReportEntry],
) -> Result<Registration, RegistrationError> {
    if entries.len() > MAX_ENTRIES {
        return Err(RegistrationError::Bounds);
    }
    let policy_hash = policy.hash().map_err(|_| RegistrationError::Policy)?;
    if clock.chain_id != policy.chain_id
        || clock.timed_ops != entries.len() as u64
        || clock.phase > 2
        || clock.first_ms > clock.last_ms
        || clock.last_ms - clock.first_ms > clock.max_window_ms
        || clock.max_window_ms == 0
        || (entries.is_empty() && (clock.first_ms != 0 || clock.last_ms != 0))
    {
        return Err(RegistrationError::Clock);
    }
    let mut evidence_words = Vec::with_capacity(96);
    evidence_words.extend_from_slice(&keccak(b"arcora:chainlink-evidence:v1"));
    evidence_words.extend_from_slice(&policy_hash);
    word(&mut evidence_words, entries.len() as u64);
    let mut evidence_hash = keccak(&evidence_words);
    let mut total_bytes = 64 + 32 * entries.len();
    let mut previous_ms = clock.first_ms;
    for (index, entry) in entries.iter().enumerate() {
        if entry.now_ms == 0
            || entry.now_ms < previous_ms
            || entry.now_ms < clock.first_ms
            || entry.now_ms > clock.last_ms
            || (index == 0 && entry.now_ms != clock.first_ms)
            || (index + 1 == entries.len() && entry.now_ms != clock.last_ms)
        {
            return Err(RegistrationError::Clock);
        }
        previous_ms = entry.now_ms;
        let base =
            body_from_full_report(&entry.base_report).map_err(|_| RegistrationError::Report)?;
        let quote =
            body_from_full_report(&entry.quote_report).map_err(|_| RegistrationError::Report)?;
        policy
            .market(entry.market_id)
            .and_then(|market| market.normalize(&base.decode()?, &quote.decode()?, entry.now_ms))
            .map_err(|_| RegistrationError::Policy)?;
        evidence_words.clear();
        evidence_words.extend_from_slice(&evidence_hash);
        word(&mut evidence_words, entry.market_id);
        word(&mut evidence_words, entry.now_ms);
        evidence_words.extend_from_slice(&keccak(&base.0));
        evidence_words.extend_from_slice(&keccak(&quote.0));
        evidence_hash = keccak(&evidence_words);
        total_bytes = total_bytes
            .checked_add(128 + 64 + entry.base_report.len() + entry.quote_report.len())
            .ok_or(RegistrationError::Bounds)?;
    }
    if total_bytes > MAX_ENTRIES_ABI_BYTES {
        return Err(RegistrationError::Bounds);
    }
    let mut entries_abi = Vec::with_capacity(total_bytes);
    word(&mut entries_abi, 32);
    word(&mut entries_abi, entries.len() as u64);
    // Dynamic-array element offsets are relative to the first offset word,
    // not to the array length word and not to the top-level tuple head.
    let mut offset = entries.len() * 32;
    for entry in entries {
        word(&mut entries_abi, offset as u64);
        offset += 128 + 64 + entry.base_report.len() + entry.quote_report.len();
    }
    for entry in entries {
        word(&mut entries_abi, entry.market_id);
        word(&mut entries_abi, entry.now_ms);
        word(&mut entries_abi, 128);
        word(
            &mut entries_abi,
            (128 + 32 + entry.base_report.len()) as u64,
        );
        bytes_tail(&mut entries_abi, &entry.base_report);
        bytes_tail(&mut entries_abi, &entry.quote_report);
    }
    debug_assert_eq!(entries_abi.len(), total_bytes);
    Ok(Registration {
        input_hash: keccak(&entries_abi),
        entries_abi,
        evidence_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainlink_oracle::binding::{append_evidence, initial_evidence, CandidateWitness};

    // Public committed A3 bodies. These unit-test-only containers deliberately
    // use synthetic nonzero r/s values; no original-container claim is made.
    fn fixture() -> (Policy, ClockContext, Vec<CandidateReportEntry>) {
        let bytes = include_bytes!("../../../docs/audits/2026-10-11-chainlink-price-lifecycle/fixtures/normal-lifecycle.witness.bin");
        let w: CandidateWitness = postcard::from_bytes(&bytes[8..]).unwrap();
        let entries = w
            .evidence
            .iter()
            .map(|e| CandidateReportEntry {
                market_id: e.market_id,
                now_ms: e.now_ms,
                base_report: synthetic_container(&e.base.0),
                quote_report: synthetic_container(&e.quote.0),
            })
            .collect();
        (w.policy, w.clock.3, entries)
    }

    fn synthetic_container(body: &[u8]) -> Vec<u8> {
        assert_eq!(body.len(), 288);
        let mut full = vec![0; 224];
        full[96..128].copy_from_slice(&abi_u64(224));
        full[128..160].copy_from_slice(&abi_u64(544));
        full[160..192].copy_from_slice(&abi_u64(608));
        word(&mut full, 288);
        full.extend_from_slice(body);
        word(&mut full, 1);
        full.extend_from_slice(&[0x11; 32]);
        word(&mut full, 1);
        full.extend_from_slice(&[0x22; 32]);
        full
    }

    fn at(bytes: &[u8], offset: usize) -> u64 {
        assert!(bytes[offset..offset + 24].iter().all(|b| *b == 0));
        u64::from_be_bytes(bytes[offset + 24..offset + 32].try_into().unwrap())
    }

    /// Frozen candidate lane: the committed lifecycle witness these unit tests
    /// read predates the current state layout and is refused.
    #[test]
    fn frozen_lane_registration_fixture_is_refused_by_the_current_layout() {
        use crate::candidate_frozen_fixtures::{assert_refused, PRICE_LIFECYCLE};
        assert_refused(PRICE_LIFECYCLE, &["normal-lifecycle.witness.bin"]);
    }

    // Its generation-source fingerprint covers this file, which changed only to
    // freeze the lane, so it is frozen with the lane.
    #[test]
    #[ignore = "frozen candidate lane"]
    fn committed_original_archive_vectors_match_native_and_solidity_bytes() {
        use sha2::{Digest as _, Sha256};
        // Runtime reads prevent a circular generated-file/source fingerprint.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path = root.join("contracts/test/fixtures/chainlink-candidate-protocol.json");
        assert!(std::fs::metadata(&path).unwrap().len() < 1024 * 1024);
        let bytes = std::fs::read(&path).unwrap();
        let vectors: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let solidity = std::fs::read_to_string(
            root.join("contracts/test/fixtures/ChainlinkCandidateProtocolVector.sol"),
        )
        .unwrap();
        assert!(solidity.contains(&format!(
            "JSON SHA256: {}",
            &crate::hex0x(&Sha256::digest(&bytes))[2..]
        )));
        assert_eq!(vectors["synthetic"], true);
        assert_eq!(vectors["original_archive_containers"], true);
        assert_eq!(vectors["real_don_verified"], false);
        assert_eq!(vectors["proof_generated"], false);
        assert_eq!(vectors["candidate_submission"], "HOLD");
        for (name, source) in [
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
            assert_eq!(
                vectors["sources_sha256"][name],
                crate::hex0x(&Sha256::digest(source)),
                "generation source {name}"
            );
        }
        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 2);
        for (index, case) in cases.iter().enumerate() {
            let name = case["name"].as_str().unwrap();
            assert_eq!(name, ["normal-lifecycle", "liquidation"][index]);
            assert_eq!(case["reference_flow_compared"], true);
            assert_eq!(case["new_random_account_witness_identity_claim"], false);
            assert_eq!(
                case["reference_a3_witness_sha256"],
                [
                    "587d8a9f065a04c4df2a441e4cbabfd2d407accc117772f1ee8745bcae4eb980",
                    "5910ca22fd419bb53d29df9a11c15e6e7c90eee55210ef99000349c86a37a14d"
                ][index]
            );
            let policy: Policy = serde_json::from_value(case["policy"].clone()).unwrap();
            let clock: ClockContext = serde_json::from_value(case["clock"].clone()).unwrap();
            let entries: Vec<CandidateReportEntry> =
                serde_json::from_value(case["original_entries"].clone()).unwrap();
            let encoded = registration(&policy, &clock, &entries).unwrap();
            assert_eq!(case["policy_hash"], crate::hex0x(&policy.hash().unwrap()));
            assert_eq!(case["input_hash"], crate::hex0x(&encoded.input_hash));
            assert_eq!(case["evidence_hash"], crate::hex0x(&encoded.evidence_hash));
            let abi_hex = crate::hex0x(&encoded.entries_abi);
            assert!(case["entries_abi"] == abi_hex, "exact original ABI: {name}");
            assert!(
                solidity.contains(&format!("hex\"{}\"", &abi_hex[2..])),
                "Solidity embeds exact native bytes: {name}"
            );
            assert!(solidity.contains(&crate::hex0x(&encoded.input_hash)));
            assert!(solidity.contains(&crate::hex0x(&encoded.evidence_hash)));
            for (entry, public) in entries.iter().zip(case["entries"].as_array().unwrap()) {
                assert!(public["base_full_report"] == crate::hex0x(&entry.base_report));
                assert!(public["quote_full_report"] == crate::hex0x(&entry.quote_report));
                assert!(
                    public["base_body"]
                        == crate::hex0x(&body_from_full_report(&entry.base_report).unwrap().0)
                );
                assert!(
                    public["quote_body"]
                        == crate::hex0x(&body_from_full_report(&entry.quote_report).unwrap().0)
                );
            }
        }
    }

    #[test]
    #[ignore = "frozen candidate lane"]
    fn exact_nested_abi_offsets_and_independent_a3_body_evidence() {
        let (policy, clock, entries) = fixture();
        let encoded = registration(&policy, &clock, &entries).unwrap();
        let mut evidence = initial_evidence(policy.hash().unwrap(), entries.len()).unwrap();
        for e in &entries {
            evidence = append_evidence(
                evidence,
                &chainlink_oracle::binding::PairEvidence {
                    market_id: e.market_id,
                    now_ms: e.now_ms,
                    base: body_from_full_report(&e.base_report).unwrap(),
                    quote: body_from_full_report(&e.quote_report).unwrap(),
                },
            );
        }
        assert_eq!(encoded.evidence_hash, evidence);
        assert_eq!(encoded.input_hash, keccak(&encoded.entries_abi));
        assert_eq!(at(&encoded.entries_abi, 0), 32);
        assert_eq!(at(&encoded.entries_abi, 32), entries.len() as u64);
        let mut offset = entries.len() * 32;
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(at(&encoded.entries_abi, 64 + i * 32), offset as u64);
            let start = 64 + offset;
            assert_eq!(at(&encoded.entries_abi, start), e.market_id);
            assert_eq!(at(&encoded.entries_abi, start + 32), e.now_ms);
            assert_eq!(at(&encoded.entries_abi, start + 64), 128);
            assert_eq!(at(&encoded.entries_abi, start + 96), 832);
            assert_eq!(at(&encoded.entries_abi, start + 128), 672);
            assert_eq!(
                &encoded.entries_abi[start + 160..start + 832],
                &e.base_report
            );
            assert_eq!(at(&encoded.entries_abi, start + 832), 672);
            assert_eq!(
                &encoded.entries_abi[start + 864..start + 1536],
                &e.quote_report
            );
            offset += 1536;
        }
        assert_eq!(encoded.entries_abi.len(), 64 + offset);
    }

    #[test]
    #[ignore = "frozen candidate lane"]
    fn full_signature_container_changes_input_but_preserves_body_evidence() {
        let (policy, clock, mut entries) = fixture();
        let original = registration(&policy, &clock, &entries).unwrap();
        entries[0].base_report[576] ^= 1;
        let changed = registration(&policy, &clock, &entries).unwrap();
        assert_ne!(changed.input_hash, original.input_hash);
        assert_eq!(changed.evidence_hash, original.evidence_hash);
    }

    #[test]
    #[ignore = "frozen candidate lane"]
    fn missing_extra_reordered_wrong_clock_and_bad_container_fail() {
        let (policy, clock, entries) = fixture();
        let mut missing = entries.clone();
        missing.pop();
        assert_eq!(
            registration(&policy, &clock, &missing),
            Err(RegistrationError::Clock)
        );
        let mut extra = entries.clone();
        extra.push(entries.last().unwrap().clone());
        assert_eq!(
            registration(&policy, &clock, &extra),
            Err(RegistrationError::Clock)
        );
        let mut reordered = entries.clone();
        reordered.reverse();
        assert_eq!(
            registration(&policy, &clock, &reordered),
            Err(RegistrationError::Clock)
        );
        let mut wrong_clock = clock;
        wrong_clock.chain_id = 8453;
        assert_eq!(
            registration(&policy, &wrong_clock, &entries),
            Err(RegistrationError::Clock)
        );
        let mut bad = entries.clone();
        bad[0].base_report[127] = 225;
        assert_eq!(
            registration(&policy, &clock, &bad),
            Err(RegistrationError::Report)
        );
        bad = entries.clone();
        bad[0].quote_report.resize(4097, 0);
        assert_eq!(
            registration(&policy, &clock, &bad),
            Err(RegistrationError::Report)
        );
    }

    #[test]
    #[ignore = "frozen candidate lane"]
    fn encoding_is_bounded_and_price_free_array_has_two_words() {
        let (policy, mut clock, original) = fixture();
        let mut entries = vec![original[0].clone(); MAX_ENTRIES];
        clock.first_ms = entries[0].now_ms;
        clock.last_ms = clock.first_ms;
        clock.timed_ops = MAX_ENTRIES as u64;
        assert!(
            registration(&policy, &clock, &entries)
                .unwrap()
                .entries_abi
                .len()
                <= MAX_ENTRIES_ABI_BYTES
        );
        entries.push(original[0].clone());
        assert_eq!(
            registration(&policy, &clock, &entries),
            Err(RegistrationError::Bounds)
        );
        clock.timed_ops = 0;
        clock.first_ms = 0;
        clock.last_ms = 0;
        let empty = registration(&policy, &clock, &[]).unwrap();
        assert_eq!(empty.entries_abi, [abi_u64(32), abi_u64(0)].concat());
    }

    #[test]
    fn epoch_grace_is_strict_at_observation_and_first_operation() {
        let mut round = [0; 10];
        round[0] = 1; // uint80 value above u64 remains representable.
        let epoch = UptimeEpoch {
            round_id: round,
            started_at: 1,
        };
        assert_eq!(validate_epoch(epoch, 100, 10, Some(100_000)), Ok(()));
        assert_eq!(
            validate_epoch(epoch, 11, 10, Some(100_000)),
            Err(RegistrationError::Epoch)
        );
        assert_eq!(
            validate_epoch(epoch, 100, 10, Some(11_999)),
            Err(RegistrationError::Epoch)
        );
        assert_eq!(validate_epoch(epoch, 100, 10, Some(12_000)), Ok(()));
        assert_eq!(
            validate_epoch(
                UptimeEpoch {
                    round_id: [0; 10],
                    started_at: 1
                },
                100,
                10,
                Some(100_000)
            ),
            Err(RegistrationError::Epoch)
        );
        assert_eq!(
            validate_epoch(
                UptimeEpoch {
                    round_id: [0; 10],
                    started_at: 0
                },
                0,
                0,
                None
            ),
            Ok(())
        );
        assert_eq!(
            validate_epoch(epoch, u64::MAX, u64::MAX, Some(u64::MAX)),
            Err(RegistrationError::Epoch)
        );
    }
}
