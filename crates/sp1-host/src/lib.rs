//! Synthetic clock-bound witnesses, their negative controls and reproducible
//! artifacts: the normal fixture (an ordinary batch), the case witnesses and
//! engine refusals of [`cases`] (ordinary and wind-down batches). Never sends
//! chain transactions.
//!
//! Every witness here is the one encoding the guest accepts, produced by the one
//! helper [`encode_clock_witness`] and decoded by its strict counterpart
//! [`decode_clock_witness`] (both from `prover`, the guest's native twin).

pub mod cases;

pub use cases::{case_witnesses, engine_negative_cases, CaseWitness};
pub use perp_core::clock::ClockWitness;
pub use prover::{decode_clock_witness, encode_clock_witness, ProverError};

use perp_core::clock::{bind_transition, BoundTransition, ClockContext, TimeBounds, WIRE_MAGIC};
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{Digest, Keccak256};
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, Note};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{BatchManifest, Side};
use perp_core::state::TREE_DEPTH;
use perp_core::{DefaultState, EngineError};
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

/// Fail before expensive proving when an interrupted SDK download left a directory
/// that exists but has no usable circuit files. This is a prerequisite check, not
/// proof verification or a guarantee that all proving-key bytes are uncorrupted.
pub fn check_groth16_prerequisites(directory: &Path) -> io::Result<()> {
    for name in ["groth16_vk.bin", "groth16_circuit.bin", "groth16_pk.bin"] {
        let metadata = fs::symlink_metadata(directory.join(name))?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing regular nonempty circuit artifact: {name}"),
            ));
        }
    }
    let key = directory.join("groth16_vk.bin");
    if fs::metadata(&key)?.len() != 492 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong SP1 6.1.0 verification-key size",
        ));
    }
    if sha256(&fs::read(key)?) != "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "circuit key differs from the pinned real target verifier",
        ));
    }
    Ok(())
}

/// The public synthetic oracle signing key of the normal fixture and the case
/// witnesses. It is a test value, never a deployment key.
pub(crate) const FIXTURE_ORACLE_KEY: [u8; 32] = [7; 32];

/// A signed transcript of market 0 at `price`, published at `now_ms` by `key`.
fn fixture_oracle(key: &k256::ecdsa::SigningKey, price: i128, now_ms: u64) -> OracleTranscript {
    OracleTranscript {
        price,
        publish_time_ms: now_ms,
        confidence: 0,
        backup_twap: price,
        signature: OracleSig::sign(key, &oracle_digest(0, price, now_ms, 0, price)),
    }
}

/// The traders of the normal fixture's pre-state, by synthetic spend key: a long,
/// a short and the holder of an unspent note. Test values, never deployment keys.
const NORMAL_LONG: [u8; 32] = [0xA1; 32];
const NORMAL_SHORT: [u8; 32] = [0xA2; 32];
const NORMAL_HOLDER: [u8; 32] = [0xA3; 32];
/// The wind-down recipient of the normal fixture's pre-state (a synthetic address).
pub const NORMAL_RECIPIENT: [u8; 20] = [0x5E; 20];

/// The normal fixture's pre-state: hand-built, not reached by batches from a
/// genesis root, so its batch counter (0), deposit accumulator (genesis tip, count
/// 0) and withdrawal nonce (0) are those of a fresh settlement, as
/// `ClockBoundRealProof.t.sol` deploys one. On a depth-[`TREE_DEPTH`] tree with a
/// wind-down recipient and market 0 (`Market::conservative`, published by the
/// fixture oracle key):
///
/// * three notes are allocated outside the deposit accumulator ($500 to the long,
///   $500 to the short, $200 to the holder): each is appended to the tree and
///   counted as external value in, so conservation holds;
/// * the engine's own ops (`apply_op`, never `apply_batch`) then bind the long's
///   and the short's notes as collateral, which spends them (two nullifiers, in an
///   insertion order that is not their sorted order), open 0.2 long against 0.2
///   short at $1,000, and run two funding ticks. The second commits 36,543 ms at the
///   +0.05% rate the first adopted and adopts +0.03%, so the stored rate, the
///   carried remainder and the recorded price are all non-zero.
///
/// The holder's note stays unspent.
fn normal_pre_state(key: &k256::ecdsa::SigningKey) -> DefaultState {
    let price = 1000 * PRICE_SCALE;
    let mut state = DefaultState::new(TREE_DEPTH);
    let mut market = Market::conservative(0);
    let probe = oracle_digest(0, price, 1, 0, price);
    market.oracle_pubkey = OracleSig::sign(key, &probe)
        .recover(&probe)
        .expect("fixture key recovers");
    state.add_market(market);
    state.set_wind_down_recipient(NORMAL_RECIPIENT);
    let mut allocate = |spend_key: &[u8; 32], dollars: i128, blinding: u8| {
        let amount = dollars * QUOTE_SCALE;
        let note = Note::new(
            owner_from_spend_key::<Keccak256>(spend_key),
            0,
            amount,
            [blinding; 32],
        );
        let cm = note.commitment::<Keccak256>();
        state.tree.append(cm).expect("tree capacity");
        state.notes.insert(cm, note);
        state.external_in += amount;
        cm
    };
    let long_note = allocate(&NORMAL_LONG, 500, 0xB1);
    let short_note = allocate(&NORMAL_SHORT, 500, 0xB2);
    allocate(&NORMAL_HOLDER, 200, 0xB3);
    let fund = |spend_key: &[u8; 32], note_commitment: Digest| BatchOp::FundPosition {
        owner: owner_from_spend_key::<Keccak256>(spend_key),
        market_id: 0,
        note_commitment,
        spend_key: *spend_key,
    };
    let tick = |mark: i128, now_ms: u64| BatchOp::AccrueFunding {
        market_id: 0,
        mark,
        oracle: fixture_oracle(key, price, now_ms),
        now_ms,
    };
    let history = [
        fund(&NORMAL_LONG, long_note),
        fund(&NORMAL_SHORT, short_note),
        BatchOp::Fill {
            taker: owner_from_spend_key::<Keccak256>(&NORMAL_LONG),
            maker: owner_from_spend_key::<Keccak256>(&NORMAL_SHORT),
            market_id: 0,
            taker_side: Side::Buy,
            size: SIZE_SCALE / 5,
            price,
            oracle: fixture_oracle(key, price, 40_000),
            now_ms: 40_000,
        },
        // +0.1% premium, clamped to +0.05%
        tick(1001 * PRICE_SCALE, 40_000),
        // +0.03% premium
        tick(100_030 * PRICE_SCALE / 100, 76_543),
    ];
    for op in &history {
        state.apply_op(op).expect("pre-state op");
        assert!(state.conservation_holds(), "the pre-state conserves value");
    }
    state
}

/// The normal fixture, in exactly the shape `ClockBoundRealProof.t.sol` hard-codes:
/// chain 84532, verifier `0x11…11`, settlement `0x22…22`, batch 0 anchored at
/// 101,000 ms with a 10,000 ms window and 2,000 ms skew, over the hand-built
/// [`normal_pre_state`]. Its four ops:
///
/// * a deposit of 1,000,000 with deposit id 0 from payer address(0), whose owner
///   is bound by a blinded owner commit (so the batch's deposit count becomes 1);
/// * a withdrawal of that note, 1,000,000 to `0xAB…AB` with nonce 1, the batch's
///   only withdrawal leaf;
/// * the two timed ops, both funding ticks: at 100,000 ms one commits the
///   23,457 ms span at the stored +0.03% rate, carrying the remainder, and adopts
///   +0.05%; at 100,700 ms the other commits its 700 ms at +0.05% (a non-zero index
///   delta) and adopts -0.05%.
///
/// Public test values only: the deposit is NOT an observed L1 event.
pub fn normal_witness() -> ClockWitness {
    let spend_key = [3u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&spend_key);
    let blind = [9u8; 32];
    let amount = 1_000_000i128;
    let key = k256::ecdsa::SigningKey::from_slice(&FIXTURE_ORACLE_KEY).expect("fixture key");
    let state = normal_pre_state(&key);
    let price = 1000 * PRICE_SCALE;
    let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
    let mut ops = vec![
        BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount,
            blinding: blind,
            from: [0u8; 20],
            deposit_id: 0,
            deposit_blind: [0x0D; 32],
        },
        BatchOp::Withdraw {
            note_commitment: cm,
            spend_key,
            to: Some([0xAB; 20]),
            nonce: 1,
        },
    ];
    for (now_ms, mark) in [(100_000, 1001), (100_700, 999)] {
        ops.push(BatchOp::AccrueFunding {
            market_id: 0,
            mark: mark * PRICE_SCALE,
            oracle: fixture_oracle(&key, price, now_ms),
            now_ms,
        });
    }
    let manifest = BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        batch_time_ms: perp_core::commitment::batch_time_ms(&ops),
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    };
    let roots = perp_core::commitment::derive_roots(&mut state.clone(), &ops, &manifest)
        .expect("valid normal transition");
    let bounds = TimeBounds::derive(&ops).expect("ordered fixture times");
    let clock = ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: manifest.batch_id,
        previous_root: roots.prev_state_root,
        base_commitment: roots.commitment::<Keccak256>(),
        phase: roots.wind_down_phase,
        first_ms: bounds.first_ms,
        last_ms: bounds.last_ms,
        timed_ops: bounds.count,
        anchored_at_ms: 101_000,
        max_window_ms: 10_000,
        clock_skew_ms: 2_000,
    };
    (state, ops, manifest, clock)
}

/// The exact bytes given to the guest for `witness`.
pub fn witness_bytes(witness: &ClockWitness) -> Vec<u8> {
    encode_clock_witness(&witness.0, &witness.1, &witness.2, &witness.3)
}

/// Derive the native result from the exact bytes given to SP1, exactly as the
/// guest does: the strict decode, then `bind_transition`. Returns the bound
/// transition (its `commitment` is the guest's public value) and the post-batch
/// deposit count.
pub fn native_from_bytes(bytes: &[u8]) -> Result<(BoundTransition, u64), ProverError> {
    let (bound, state) = native_case_from_bytes(bytes)?;
    assert_eq!(
        bound.roots.wind_down_phase, 0,
        "this harness is ordinary-only"
    );
    Ok((bound, state.consumed_deposit_count))
}

/// [`native_from_bytes`] for a batch of any wind-down phase: the bound transition
/// and the post-batch state.
pub fn native_case_from_bytes(
    bytes: &[u8],
) -> Result<(BoundTransition, DefaultState), ProverError> {
    let (mut state, ops, manifest, clock) = decode_clock_witness(bytes)?;
    let bound = bind_transition(&mut state, &ops, &manifest, &clock)?;
    Ok((bound, state))
}

pub struct NegativeCase {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub expected_error: ProverError,
}

/// Engine refusals of a well-framed witness whose clock context is the honest one.
pub fn normal_negative_cases() -> Vec<NegativeCase> {
    let mut bad_manifest = normal_witness();
    bad_manifest.2.previous_state_root[0] ^= 1;
    let mut bad_spend = normal_witness();
    match &mut bad_spend.1[1] {
        BatchOp::Withdraw { spend_key, .. } => *spend_key = [4u8; 32],
        _ => unreachable!("the second normal operation is a withdrawal"),
    }
    // 2026-10-08 review: a witness state whose in-map Market.id disagrees with its
    // map key must be rejected even though the state root hashes only the key.
    let mut bad_market_id = normal_witness();
    bad_market_id.0.markets.get_mut(&0).expect("market 0").id = 99;
    vec![
        NegativeCase {
            name: "bad-manifest",
            bytes: witness_bytes(&bad_manifest),
            expected_error: ProverError::Transition(EngineError::ManifestMismatch),
        },
        NegativeCase {
            name: "unauthorized-withdrawal",
            bytes: witness_bytes(&bad_spend),
            expected_error: ProverError::Transition(EngineError::BadSpendKey),
        },
        NegativeCase {
            name: "market-id-not-map-key",
            bytes: witness_bytes(&bad_market_id),
            expected_error: ProverError::Transition(EngineError::MarketIdMismatch),
        },
    ]
}

/// The clock negatives: an honest batch under a clock context that misstates its
/// bounds, timed-op count, batch, base commitment or anchor time.
pub fn clock_negative_cases(witness: &ClockWitness) -> Vec<NegativeCase> {
    [
        "wrong-bounds",
        "wrong-count",
        "wrong-batch",
        "wrong-base",
        "backdated",
    ]
    .into_iter()
    .map(|name| {
        let mut bad = witness.3;
        match name {
            "wrong-bounds" => bad.first_ms += 1,
            "wrong-count" => bad.timed_ops -= 1,
            "wrong-batch" => bad.batch_id += 1,
            "wrong-base" => bad.base_commitment[0] ^= 1,
            _ => bad.anchored_at_ms += 20_000,
        }
        NegativeCase {
            name,
            bytes: encode_clock_witness(&witness.0, &witness.1, &witness.2, &bad),
            expected_error: ProverError::Transition(EngineError::ClockMismatch),
        }
    })
    .collect()
}

/// The framing negatives: every input that is not exactly `WIRE_MAGIC ‖
/// postcard(ClockWitness)`. The guest refuses each; natively, input without the
/// magic is `UnboundWitness` and a framed body that does not decode exactly is
/// `WitnessDecode`.
pub fn framing_negative_cases(witness: &ClockWitness) -> Vec<NegativeCase> {
    let bytes = witness_bytes(witness);
    let body = &bytes[WIRE_MAGIC.len()..];
    let reframed = |magic: &[u8]| [magic, body].concat();
    let legacy = postcard::to_allocvec(&(&witness.0, &witness.1, &witness.2))
        .expect("unframed tuple encodes");
    let mut trailing = bytes.clone();
    trailing.push(0);
    vec![
        NegativeCase {
            name: "legacy-tuple",
            bytes: legacy,
            expected_error: ProverError::UnboundWitness,
        },
        NegativeCase {
            name: "empty-input",
            bytes: Vec::new(),
            expected_error: ProverError::UnboundWitness,
        },
        NegativeCase {
            name: "seven-byte-magic",
            bytes: WIRE_MAGIC[..7].to_vec(),
            expected_error: ProverError::UnboundWitness,
        },
        NegativeCase {
            name: "dpclk2-magic",
            bytes: reframed(b"DPCLK2\0\0"),
            expected_error: ProverError::UnboundWitness,
        },
        NegativeCase {
            name: "dpclk3-magic",
            bytes: reframed(b"DPCLK3\0\0"),
            expected_error: ProverError::UnboundWitness,
        },
        NegativeCase {
            name: "trailing-byte",
            bytes: trailing,
            expected_error: ProverError::WitnessDecode,
        },
    ]
}

/// Every negative `clock-proof` runs, in its order: the clock negatives of
/// `witness`, the engine refusals of the normal fixture, the engine refusals of
/// fresh and case-derived batches ([`engine_negative_cases`]), and the framing
/// negatives of `witness`. Names are unique.
pub fn reviewed_negative_cases(witness: &ClockWitness) -> Vec<NegativeCase> {
    clock_negative_cases(witness)
        .into_iter()
        .chain(normal_negative_cases())
        .chain(engine_negative_cases())
        .chain(framing_negative_cases(witness))
        .collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Payload guards only. The caller MUST also use the real SDK verifier before
/// claiming proof success or writing a successful proof manifest.
pub fn groth16_payload_for_verification(
    proof: &SP1ProofWithPublicValues,
    expected: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    if !matches!(&proof.proof, SP1Proof::Groth16(_)) {
        return Err("Groth16 proof required");
    }
    let bytes = proof.bytes();
    if bytes.len() <= 4 {
        return Err("empty/mock proof must not be accepted");
    }
    if proof.public_values.as_slice() != expected.as_slice() {
        return Err("guest/native divergence");
    }
    Ok(bytes)
}

/// The derived roots, the base commitment, the clock receipt and the bound
/// commitment (the guest's public value) of `bound`.
pub fn roots_json(bound: &BoundTransition, deposit_count: u64) -> Value {
    let roots = &bound.roots;
    json!({
        "prev_root": format!("0x{}", hex(&roots.prev_state_root)),
        "manifest_hash": format!("0x{}", hex(&roots.manifest_hash)),
        "new_root": format!("0x{}", hex(&roots.new_state_root)),
        "ordered_root": format!("0x{}", hex(&roots.ordered_root)),
        "withdrawals_root": format!("0x{}", hex(&roots.withdrawals_root)),
        "rejected_root": format!("0x{}", hex(&roots.rejected_root)),
        "deposits_root": format!("0x{}", hex(&roots.deposits_root)),
        "new_deposit_count": deposit_count,
        "wind_down_phase": roots.wind_down_phase,
        "base_commitment": format!("0x{}", hex(&roots.commitment::<Keccak256>())),
        "clock_receipt": format!("0x{}", hex(&bound.receipt)),
        "commitment": format!("0x{}", hex(&bound.commitment))
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub output_dir: Option<PathBuf>,
    pub check_negatives: bool,
}

pub fn options(
    args: impl IntoIterator<Item = String>,
    allow_negatives: bool,
) -> Result<Options, String> {
    let mut result = Options::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-dir" if result.output_dir.is_none() => {
                let value = args
                    .next()
                    .filter(|v| !v.is_empty() && !v.starts_with("--"))
                    .ok_or("--output-dir requires a new directory path")?;
                result.output_dir = Some(PathBuf::from(value));
            }
            "--check-negatives" if allow_negatives && !result.check_negatives => {
                result.check_negatives = true
            }
            _ => return Err(format!("unsupported or repeated option: {arg}")),
        }
    }
    Ok(result)
}

/// A run requires a fresh directory, preserving previous evidence. Completion
/// manifest is written last, only after all requested checks succeed.
pub struct Artifacts {
    dir: PathBuf,
    entries: Map<String, Value>,
}

impl Artifacts {
    pub fn new(dir: &Path) -> io::Result<Self> {
        fs::create_dir(dir)?;
        Ok(Self {
            dir: dir.to_owned(),
            entries: Map::new(),
        })
    }

    pub fn write(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact must be a filename",
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.dir.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.entries.insert(
            name.into(),
            json!({ "sha256": sha256(bytes), "size_bytes": bytes.len() }),
        );
        Ok(())
    }

    pub fn finish(mut self, mut manifest: Value) -> io::Result<()> {
        manifest["schema_version"] = json!(1);
        manifest["artifacts"] = Value::Object(self.entries.clone());
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        self.write("manifest.json", &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT, recomputed from the current perp-core sources (not from a reviewed
    /// ELF): the normal fixture's base commitment, receipt and bound commitment.
    #[test]
    fn normal_reference_consumes_exact_serialized_witness() {
        let witness = normal_witness();
        let bytes = witness_bytes(&witness);
        assert!(bytes.starts_with(WIRE_MAGIC));
        let decoded = decode_clock_witness(&bytes).unwrap();
        assert_eq!(witness_bytes(&decoded), bytes);
        let (bound, count) = native_from_bytes(&bytes).unwrap();
        assert_eq!(count, 1);
        assert_eq!(bound.receipt, witness.3.receipt());
        assert_eq!(bound.commitment, witness.3.commitment());
        assert_eq!(
            prover::public_from_witness(&bytes)
                .unwrap()
                .commitment::<Keccak256>(),
            bound.commitment
        );
        assert_eq!((witness.3.first_ms, witness.3.last_ms), (100_000, 100_700));
        assert_eq!(witness.3.timed_ops, 2);
        assert_eq!(
            hex(&bound.roots.commitment::<Keccak256>()),
            "a94f1820a9e1f3cc571c1e18bb6aeecd2fe3a737b6c5aa84bd9e02745383aa5e"
        );
        assert_eq!(
            hex(&bound.receipt),
            "255eb8deb1c4975362a787724d71be5c56f59b726bcc85bc22104c59abf73995"
        );
        assert_eq!(
            hex(&bound.commitment),
            "6e382af92ac5b4872e4a1f6c0f6bdf6d1a246bb2ca6f834dc7aeb3748edab5ab"
        );
        let fields = roots_json(&bound, count);
        assert_eq!(fields["new_deposit_count"], 1);
        assert_eq!(
            fields["deposits_root"],
            format!("0x{}", hex(&bound.roots.deposits_root))
        );
        assert_eq!(
            fields["commitment"],
            format!("0x{}", hex(&bound.commitment))
        );
        assert_eq!(fields.as_object().unwrap().len(), 12);
    }

    /// The normal fixture has exactly the shape `ClockBoundRealProof.t.sol`
    /// hard-codes (its clock context, its one deposit and one withdrawal leaf, zero
    /// ordered and rejected roots, a fresh deposit chain), over a pre-state whose
    /// funding and nullifier history are not trivial.
    #[test]
    fn normal_fixture_has_the_real_proof_shape_over_a_non_trivial_pre_state() {
        use perp_core::merkle::{deposit_chain_fold, deposit_leaf, owner_commit, withdrawal_leaf};
        use perp_core::state::Mode;
        let (pre, ops, manifest, clock) = normal_witness();
        assert_eq!(
            (clock.chain_id, clock.verifier, clock.settlement),
            (84532, [0x11; 20], [0x22; 20])
        );
        assert_eq!((clock.batch_id, clock.phase, manifest.batch_id), (0, 0, 0));
        assert_eq!(
            (clock.first_ms, clock.last_ms, clock.timed_ops),
            (100_000, 100_700, 2)
        );
        assert_eq!(
            (
                clock.anchored_at_ms,
                clock.max_window_ms,
                clock.clock_skew_ms
            ),
            (101_000, 10_000, 2_000)
        );

        // The pre-state: a fresh settlement's counters, non-trivial contents.
        assert_eq!((pre.next_batch_id, pre.last_withdrawal_nonce), (0, 0));
        assert_eq!(
            (pre.consumed_deposit_count, pre.consumed_deposit_tip),
            (0, [0u8; 32])
        );
        assert_eq!((pre.mode, pre.tree.depth()), (Mode::Normal, TREE_DEPTH));
        assert_eq!(pre.wind_down_recipient, NORMAL_RECIPIENT);
        assert!(pre.conservation_holds());
        pre.validate_witness_shape().unwrap();
        let log = pre.nullifiers.log().to_vec();
        let mut sorted = log.clone();
        sorted.sort_unstable();
        assert!(log.len() >= 2 && log != sorted, "an unsorted nullifier log");
        assert_eq!((pre.tree.len(), pre.notes.len()), (3, 1));
        assert_eq!(pre.positions.values().filter(|p| p.size != 0).count(), 2);
        let funding = pre.funding[&0];
        assert!(funding.is_well_formed());
        assert!(funding.rate != 0 && funding.remainder != 0 && funding.last_price != 0);

        // The ops: one deposit, its withdrawal, two funding ticks.
        assert_eq!(ops.len(), 4);
        let BatchOp::Deposit {
            owner,
            amount,
            blinding,
            from,
            deposit_id,
            deposit_blind,
            ..
        } = ops[0]
        else {
            panic!("the first op is the deposit")
        };
        assert_eq!((amount, from, deposit_id), (1_000_000, [0u8; 20], 0));
        assert_ne!(deposit_blind, [0u8; 32], "a blinded owner commit");
        let note = Note::new(owner, 0, amount, blinding).commitment::<Keccak256>();
        assert!(matches!(
            ops[1],
            BatchOp::Withdraw { note_commitment, to: Some(to), nonce: 1, .. }
                if note_commitment == note && to == [0xAB; 20]
        ));
        let times: Vec<u64> = ops[2..]
            .iter()
            .map(|op| match op {
                BatchOp::AccrueFunding { now_ms, .. } => *now_ms,
                _ => panic!("the timed ops are funding ticks"),
            })
            .collect();
        assert_eq!(times, [100_000, 100_700]);

        // The first tick commits a span at the stored non-zero rate, carrying the
        // remainder, and changes the rate; the second moves the index.
        let mut state = pre.clone();
        state.apply_batch(&ops[..2]).unwrap();
        state.apply_op(&ops[2]).unwrap();
        let first = state.funding[&0];
        let mut span = funding;
        span.settle_to(1000 * PRICE_SCALE, 100_000);
        assert_eq!(
            (first.cumulative_index, first.remainder),
            (span.cumulative_index, span.remainder)
        );
        assert!(first.cumulative_index > funding.cumulative_index && first.remainder != 0);
        assert!(first.rate != funding.rate && first.rate != 0);
        state.apply_op(&ops[3]).unwrap();
        let second = state.funding[&0];
        assert_ne!(second.cumulative_index, first.cumulative_index);
        assert_eq!(second.last_update_ms, 100_700);

        // The roots the Solidity test rebuilds: one withdrawal leaf (claimed with no
        // siblings), one deposit folded onto an empty chain, zero ordered and
        // rejected roots, and a deposit count of 1.
        let (bound, count) = native_from_bytes(&witness_bytes(&normal_witness())).unwrap();
        let roots = &bound.roots;
        assert_eq!(count, 1);
        assert_eq!(
            (roots.ordered_root, roots.rejected_root),
            ([0u8; 32], [0u8; 32])
        );
        assert_eq!(
            roots.withdrawals_root,
            withdrawal_leaf(&[0xAB; 20], 1_000_000, 1)
        );
        let leaf = deposit_leaf(
            &[0u8; 20],
            &owner_commit(&owner, &deposit_blind),
            1_000_000,
            0,
        );
        assert_eq!(roots.deposits_root, deposit_chain_fold(&[0u8; 32], &leaf));
        assert_eq!(roots.prev_state_root, pre.state_root());
    }

    #[test]
    fn normal_negative_controls_reject_for_the_intended_reasons() {
        let witness = normal_witness();
        let honest = witness_bytes(&witness);
        let cases = normal_negative_cases()
            .into_iter()
            .chain(clock_negative_cases(&witness))
            .chain(framing_negative_cases(&witness))
            .collect::<Vec<_>>();
        assert_eq!(cases.len(), 14);
        let mut names = cases.iter().map(|case| case.name).collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), cases.len(), "negative names are unique");
        for case in &cases {
            assert_eq!(
                native_from_bytes(&case.bytes).unwrap_err(),
                case.expected_error,
                "{}",
                case.name
            );
            assert_eq!(
                prover::public_from_witness(&case.bytes).unwrap_err(),
                case.expected_error,
                "{}",
                case.name
            );
            assert_ne!(case.bytes, honest, "{}", case.name);
        }
    }

    /// The negatives `clock-proof` runs: every set, each name once, and every one
    /// refused natively with its expected error.
    #[test]
    fn reviewed_negatives_cover_every_set_with_unique_names() {
        let witness = normal_witness();
        let cases = reviewed_negative_cases(&witness);
        let mut names = cases.iter().map(|case| case.name).collect::<Vec<_>>();
        assert_eq!(names.len(), 5 + 3 + 8 + 6);
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), cases.len(), "negative names are unique");
        for case in &cases {
            assert_eq!(
                prover::public_from_witness(&case.bytes).unwrap_err(),
                case.expected_error,
                "{}",
                case.name
            );
        }
        let cases = case_witnesses();
        assert!(cases.iter().all(|case| !names.contains(&case.name)));
    }

    #[test]
    fn optional_cli_preserves_default_and_rejects_ambiguous_arguments() {
        assert_eq!(options(Vec::new(), true).unwrap(), Options::default());
        assert!(options(vec!["--output-dir".into()], true).is_err());
        assert!(options(vec!["--check-negatives".into()], false).is_err());
        assert!(options(
            vec!["--output-dir".into(), "--check-negatives".into()],
            true
        )
        .is_err());
    }

    #[test]
    fn artifacts_hash_exact_bytes_and_refuse_overwrite() {
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("sp1-host-artifacts-{}-{stamp}", std::process::id()));
        let mut artifacts = Artifacts::new(&path).unwrap();
        assert!(Artifacts::new(&path).is_err());
        artifacts.write("witness.bin", b"abc").unwrap();
        assert!(artifacts.write("witness.bin", b"changed").is_err());
        assert!(artifacts.write("../escape", b"no").is_err());
        assert!(artifacts.write("/", b"no").is_err());
        artifacts.finish(json!({"proof_generated": false})).unwrap();
        let manifest: Value =
            serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["artifacts"]["witness.bin"]["sha256"],
            sha256(b"abc")
        );
        assert_eq!(fs::read(path.join("witness.bin")).unwrap(), b"abc");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn proof_payload_guard_rejects_empty_mock_and_divergent_public_values() {
        // SDK-shaped dummy payloads, with no proving or execution. Guards reject
        // these before local SDK verification could be called.
        let variant = |encoded: &str| -> SP1Proof {
            serde_json::from_value(json!({"Groth16": {
                "encoded_proof": encoded, "groth16_vkey_hash": vec![0; 32],
                "public_inputs": ["", "", "", "", ""], "raw_proof": ""
            }}))
            .unwrap()
        };
        let expected = [1u8; 32];
        let empty = SP1ProofWithPublicValues::new(
            variant(""),
            sp1_sdk::SP1PublicValues::from(&expected),
            "6.1.0".into(),
        );
        assert_eq!(
            groth16_payload_for_verification(&empty, &expected),
            Err("empty/mock proof must not be accepted")
        );
        let divergent = SP1ProofWithPublicValues::new(
            variant("00"),
            sp1_sdk::SP1PublicValues::from(&[2u8; 32]),
            "6.1.0".into(),
        );
        assert_eq!(
            groth16_payload_for_verification(&divergent, &expected),
            Err("guest/native divergence")
        );
    }
}

#[cfg(test)]
mod circuit_prerequisite_tests {
    use super::*;
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!(
                "arcora-circuit-preflight-{}-{stamp}",
                std::process::id()
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn partial_download_directory_is_not_ready_for_proving() {
        let dir = Scratch::new();
        fs::write(dir.0.join("artifacts.tar.gz"), b"partial download").unwrap();
        assert_eq!(
            check_groth16_prerequisites(&dir.0).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
    #[test]
    fn fabricated_or_truncated_circuit_key_is_refused() {
        let dir = Scratch::new();
        for name in ["groth16_circuit.bin", "groth16_pk.bin"] {
            fs::write(dir.0.join(name), b"placeholder").unwrap();
        }
        for key in [vec![0; 1], vec![0; 492]] {
            fs::write(dir.0.join("groth16_vk.bin"), key).unwrap();
            assert_eq!(
                check_groth16_prerequisites(&dir.0).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
