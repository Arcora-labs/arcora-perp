//! The guest accepts exactly one witness framing and runs exactly one transition:
//! `WIRE_MAGIC ‖ postcard(ClockWitness)` with no trailing bytes, fed to
//! `clock::bind_transition`. These tests pin the framing constants, the bound
//! transition (every clock field is checked against the batch it claims), and,
//! with `serde`, the strict framing rule that the guest entrypoint
//! (`crates/sp1-guest/src/main.rs`) implements.

use k256::ecdsa::SigningKey;
use perp_core::clock::{
    bind_commitment, bind_transition, ClockContext, DOMAIN_TEXT, PROOF_MAGIC, WIRE_MAGIC,
};
use perp_core::commitment::derive_roots;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE};
use perp_core::hash::{Digest, Keccak256};
use perp_core::market::Market;
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::BatchManifest;
use perp_core::state::Mode;
use perp_core::{DefaultState, EngineError, Note};

type Parts = (DefaultState, Vec<BatchOp>, BatchManifest, ClockContext);

const SPEND_KEY: Digest = [3; 32];
const BLIND: Digest = [5; 32];
const AMOUNT: i128 = 1_000 * QUOTE_SCALE;

fn oracle_key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}

fn oracle(now_ms: u64) -> OracleTranscript {
    let price = 100_000 * PRICE_SCALE;
    let digest = oracle_digest(0, price, now_ms, 0, price);
    OracleTranscript {
        price,
        publish_time_ms: now_ms,
        confidence: 0,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &digest),
    }
}

fn manifest_for(state: &DefaultState, batch_time_ms: u64) -> BatchManifest {
    BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        batch_time_ms,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0; 32],
        sequencer_pubkey_epoch: 0,
    }
}

/// The clock context an honest prover builds for `ops` against `state`.
fn honest_clock(state: &DefaultState, ops: &[BatchOp], manifest: &BatchManifest) -> ClockContext {
    let roots = derive_roots(&mut state.clone(), ops, manifest).expect("honest batch");
    let ticks: Vec<u64> = ops
        .iter()
        .filter_map(|op| match op {
            BatchOp::AccrueFunding { now_ms, .. } => Some(*now_ms),
            _ => None,
        })
        .collect();
    let first_ms = ticks.first().copied().unwrap_or(0);
    let last_ms = ticks.last().copied().unwrap_or(0);
    ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: manifest.batch_id,
        previous_root: roots.prev_state_root,
        base_commitment: roots.commitment::<Keccak256>(),
        phase: roots.wind_down_phase,
        first_ms,
        last_ms,
        timed_ops: ticks.len() as u64,
        anchored_at_ms: last_ms,
        max_window_ms: 5_000,
        clock_skew_ms: 1_000,
    }
}

/// An ordinary batch: a deposit, one funding tick per entry of `ticks`, and an L1
/// withdrawal of the deposited note.
fn ordinary(ticks: &[u64]) -> Parts {
    let digest = oracle_digest(0, 1, 1, 0, 1);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = OracleSig::sign(&oracle_key(), &digest)
        .recover(&digest)
        .unwrap();
    let mut state = DefaultState::new(16);
    state.add_market(market);

    let owner = owner_from_spend_key::<Keccak256>(&SPEND_KEY);
    let note = Note::new(owner, 0, AMOUNT, BLIND).commitment::<Keccak256>();
    let mut ops = vec![BatchOp::Deposit {
        owner,
        asset_id: 0,
        amount: AMOUNT,
        blinding: BLIND,
        from: [0x44; 20],
        deposit_id: 0,
        deposit_blind: [0x55; 32],
    }];
    for &now_ms in ticks {
        ops.push(BatchOp::AccrueFunding {
            market_id: 0,
            mark: 100_000 * PRICE_SCALE,
            oracle: oracle(now_ms),
            now_ms,
        });
    }
    ops.push(BatchOp::Withdraw {
        note_commitment: note,
        spend_key: SPEND_KEY,
        to: Some([0xAB; 20]),
        nonce: 1,
    });
    let manifest = manifest_for(&state, ticks.iter().copied().max().unwrap_or(0));
    let clock = honest_clock(&state, &ops, &manifest);
    (state, ops, manifest, clock)
}

fn bind(parts: &Parts) -> Result<perp_core::clock::BoundTransition, EngineError> {
    let (state, ops, manifest, clock) = parts;
    bind_transition(&mut state.clone(), ops, manifest, clock)
}

#[test]
fn wire_magic_names_the_only_accepted_framing() {
    assert_eq!(WIRE_MAGIC, b"DPCLK4\0\0");
    // Neither the previous framing nor the chainlink-oracle candidate framing.
    assert_ne!(WIRE_MAGIC, b"DPCLK2\0\0");
    assert_ne!(WIRE_MAGIC, b"DPCLK3\0\0");
    // The receipt domain and the gateway proof transport are separate constants.
    assert_eq!(DOMAIN_TEXT, b"arcora:clock-bound-proof:v2");
    assert_eq!(PROOF_MAGIC, b"DPCLPR2\0");
    assert_ne!(&WIRE_MAGIC[..], &PROOF_MAGIC[..]);
}

#[test]
fn bind_transition_returns_the_derived_roots_and_the_bound_commitment() {
    let parts = ordinary(&[10_000]);
    let (state, ops, manifest, clock) = &parts;

    let mut post = state.clone();
    let bound = bind_transition(&mut post, ops, manifest, clock).unwrap();

    let mut reference = state.clone();
    let roots = derive_roots(&mut reference, ops, manifest).unwrap();
    assert_eq!(bound.roots, roots);
    assert_eq!(post.state_root(), reference.state_root());
    assert_eq!(post.state_root(), roots.new_state_root);
    assert_ne!(
        roots.withdrawals_root, [0; 32],
        "the withdrawal reached the roots"
    );

    assert_eq!(bound.receipt, clock.receipt());
    assert_eq!(
        bound.commitment,
        bind_commitment(roots.commitment::<Keccak256>(), clock.receipt())
    );
    // Once `validate` has accepted the context, its own helper agrees.
    assert_eq!(bound.commitment, clock.commitment());
    // The public value is always the bound commitment, never the base commitment.
    assert_ne!(bound.commitment, roots.commitment::<Keccak256>());
}

/// `ClockContext::commitment` is a function of the context alone: it binds the
/// base commitment the context carries to its receipt. Checking the context
/// against a batch is `bind_transition`'s job, which refuses a context whose
/// base commitment is not the batch's.
#[test]
fn the_context_helper_binds_the_base_commitment_it_carries() {
    let mut parts = ordinary(&[10_000]);
    parts.3.base_commitment = [0x99; 32];
    assert_eq!(
        parts.3.commitment(),
        bind_commitment([0x99; 32], parts.3.receipt())
    );
    assert_eq!(bind(&parts).unwrap_err(), EngineError::ClockMismatch);
}

#[test]
fn bind_transition_refuses_any_clock_field_that_disagrees_with_the_batch() {
    let honest = ordinary(&[10_000, 12_000]);
    assert!(bind(&honest).is_ok());
    for case in 0..12 {
        let mut parts = honest.clone();
        let c = &mut parts.3;
        match case {
            0 => c.batch_id += 1,
            1 => c.previous_root[0] ^= 1,
            2 => c.base_commitment[0] ^= 1,
            3 => c.phase = 1,
            4 => c.first_ms -= 1,
            5 => c.last_ms += 1,
            6 => c.timed_ops -= 1,
            7 => c.chain_id = 0,
            8 => c.verifier = [0; 20],
            9 => c.settlement = [0; 20],
            10 => c.max_window_ms = 0,
            _ => c.max_window_ms = 1_999,
        }
        assert_eq!(
            bind(&parts).unwrap_err(),
            EngineError::ClockMismatch,
            "case {case}"
        );
    }
    // The window bound is inclusive.
    let mut exact = honest;
    exact.3.max_window_ms = 2_000;
    assert!(bind(&exact).is_ok());
}

#[test]
fn bind_transition_keeps_the_anchor_within_the_skew() {
    for (anchored_at_ms, accepted) in [
        (8_999, false),
        (9_000, true),
        (10_000, true),
        (11_000, true),
        (11_001, false),
    ] {
        let mut parts = ordinary(&[10_000]);
        parts.3.anchored_at_ms = anchored_at_ms;
        assert_eq!(bind(&parts).is_ok(), accepted, "anchor {anchored_at_ms}");
    }
}

#[test]
fn bind_transition_reports_an_engine_refusal_before_the_clock() {
    let mut parts = ordinary(&[10_000]);
    parts.2.previous_state_root = [0x99; 32];
    // The clock context is wrong as well; the manifest refusal is reported.
    parts.3.chain_id = 0;
    assert_eq!(bind(&parts).unwrap_err(), EngineError::ManifestMismatch);
}

#[test]
fn bind_transition_binds_the_wind_down_phase() {
    let mut state = DefaultState::new(16);
    state.add_market(Market::conservative(0));
    state.mode = Mode::CloseOnly;
    let ops = vec![BatchOp::SettleAll];
    let manifest = manifest_for(&state, 0);
    let clock = honest_clock(&state, &ops, &manifest);
    assert_eq!(clock.phase, 1);
    assert_eq!((clock.first_ms, clock.last_ms, clock.timed_ops), (0, 0, 0));

    let parts = (state, ops, manifest, clock);
    let bound = bind(&parts).unwrap();
    assert_eq!(bound.roots.wind_down_phase, 1);
    assert_eq!(
        bound.commitment,
        bind_commitment(bound.roots.commitment::<Keccak256>(), clock.receipt())
    );

    let mut wrong_phase = parts;
    wrong_phase.3.phase = 0;
    assert_eq!(bind(&wrong_phase).unwrap_err(), EngineError::ClockMismatch);
}

#[test]
fn clock_receipt_and_bound_commitment_match_the_solidity_vector() {
    let c = ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: 7,
        previous_root: [0x33; 32],
        base_commitment: [0x44; 32],
        phase: 0,
        first_ms: 9_000,
        last_ms: 10_000,
        timed_ops: 2,
        anchored_at_ms: 11_000,
        max_window_ms: 5_000,
        clock_skew_ms: 1_000,
    };
    let hex = |d: Digest| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(c.receipt()),
        "cbfb7dcc2d499142a37c266092a6fa09588217870260d0141df68e3cb256f411"
    );
    assert_eq!(
        hex(bind_commitment([0x44; 32], c.receipt())),
        "5b443bd8d8b1939c024bb51c33edcb759be76402d0a06b6ecd67f703261fb77b"
    );
}

/// The guest entrypoint itself (`crates/sp1-guest/src/main.rs`, which perp-core
/// does not build) keeps the strict rule the `framing` tests restate: one strip
/// of the exact magic, one `take_from_bytes` whose rest must be empty, the raw
/// bytes dropped before the transition, one `bind_transition`, one commit of its
/// commitment, and no other decode, root or commitment path.
#[test]
fn the_guest_entrypoint_decodes_strictly_and_runs_only_the_bound_transition() {
    let source = include_str!("../../sp1-guest/src/main.rs");
    // the code without its comments, and without whitespace, so the checks do
    // not depend on formatting
    let code: String = source
        .lines()
        .map(|line| line.find("//").map_or(line, |i| &line[..i]))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    let count = |needle: &str| code.matches(needle).count();
    for (needle, n) in [
        ("sp1_zkvm::io::read_vec()", 1),
        (".strip_prefix(perp_core::clock::WIRE_MAGIC)", 1),
        ("strip_prefix", 1),
        ("postcard::take_from_bytes(body)", 1),
        ("from_bytes", 1),
        ("assert!(rest.is_empty()", 1),
        ("drop(bytes)", 1),
        (
            "perp_core::clock::bind_transition(&mutstate,&ops,&manifest,&clock)",
            1,
        ),
        ("sp1_zkvm::io::commit_slice(&bound.commitment)", 1),
        ("sp1_zkvm::io::commit", 1),
    ] {
        assert_eq!(count(needle), n, "{needle}");
    }
    for absent in [
        "else",
        "iflet",
        "match",
        "unwrap_or",
        "derive_roots",
        "run_transition",
        ".commitment()",
        "Witness=",
    ] {
        assert_eq!(count(absent), 0, "{absent}");
    }
    assert!(code.find("drop(bytes)") < code.find("bind_transition("));
}

#[cfg(feature = "serde")]
mod framing {
    use super::*;
    use perp_core::clock::ClockWitness;

    #[derive(Debug, PartialEq, Eq)]
    enum Refusal {
        Framing,
        Decode,
        Trailing,
    }

    /// The guest entrypoint's framing rule, restated: the exact magic, one
    /// `ClockWitness`, nothing after it.
    fn accept(bytes: &[u8]) -> Result<ClockWitness, Refusal> {
        let body = bytes.strip_prefix(WIRE_MAGIC).ok_or(Refusal::Framing)?;
        let (witness, rest): (ClockWitness, _) =
            postcard::take_from_bytes(body).map_err(|_| Refusal::Decode)?;
        if !rest.is_empty() {
            return Err(Refusal::Trailing);
        }
        Ok(witness)
    }

    fn body(parts: &Parts) -> Vec<u8> {
        postcard::to_allocvec(parts).unwrap()
    }

    fn framed(magic: &[u8], parts: &Parts) -> Vec<u8> {
        let mut bytes = magic.to_vec();
        bytes.extend(body(parts));
        bytes
    }

    #[test]
    fn framed_witness_decodes_to_the_same_bound_commitment() {
        let parts = ordinary(&[10_000, 12_000]);
        let decoded = accept(&framed(WIRE_MAGIC, &parts)).unwrap();
        assert_eq!(postcard::to_allocvec(&decoded).unwrap(), body(&parts));
        let (mut state, ops, manifest, clock) = decoded;
        assert_eq!(state.state_root(), parts.0.state_root());
        let bound = bind_transition(&mut state, &ops, &manifest, &clock).unwrap();
        assert_eq!(bound, bind(&parts).unwrap());
        assert_eq!(
            bound.commitment,
            bind_commitment(bound.roots.commitment::<Keccak256>(), parts.3.receipt())
        );
    }

    #[test]
    fn input_without_the_exact_magic_is_refused_before_decoding() {
        let parts = ordinary(&[10_000]);
        let (state, ops, manifest, _) = &parts;
        let bare_tuple = postcard::to_allocvec(&(state, ops, manifest)).unwrap();
        let cases: [(&str, Vec<u8>); 7] = [
            ("empty input", vec![]),
            ("tuple without a clock context", bare_tuple),
            ("clock witness without the magic", body(&parts)),
            ("previous magic", framed(b"DPCLK2\0\0", &parts)),
            ("candidate magic", framed(b"DPCLK3\0\0", &parts)),
            ("seven-byte magic alone", WIRE_MAGIC[..7].to_vec()),
            (
                "seven-byte magic before the body",
                framed(&WIRE_MAGIC[..7], &parts),
            ),
        ];
        for (name, bytes) in cases {
            assert_eq!(accept(&bytes).err(), Some(Refusal::Framing), "{name}");
        }
    }

    #[test]
    fn magic_over_anything_but_one_whole_clock_witness_is_refused() {
        let parts = ordinary(&[10_000]);
        let (state, ops, manifest, _) = &parts;

        assert_eq!(accept(WIRE_MAGIC).err(), Some(Refusal::Decode));

        let mut no_clock = WIRE_MAGIC.to_vec();
        no_clock.extend(postcard::to_allocvec(&(state, ops, manifest)).unwrap());
        assert_eq!(accept(&no_clock).err(), Some(Refusal::Decode));

        let whole = framed(WIRE_MAGIC, &parts);
        for end in [WIRE_MAGIC.len() + 1, whole.len() / 2, whole.len() - 1] {
            assert_eq!(accept(&whole[..end]).err(), Some(Refusal::Decode), "{end}");
        }

        let mut trailing = whole;
        trailing.push(0);
        assert_eq!(accept(&trailing).err(), Some(Refusal::Trailing));
    }
}
