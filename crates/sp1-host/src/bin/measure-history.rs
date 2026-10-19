//! CPU measurement of the guest's cost against the size of the state it carries.
//! Execution only: no setup and no proving, on the execute-only light client.
//! Synthetic, public test data only; never contacts a chain or a service.
//!
//! Every batch proof decodes the whole pre-state, derives the state root before
//! and after the batch (each root rehashes every note-tree leaf), and replays the
//! nullifier log, so its cost grows with the history the state has accumulated
//! (note-tree leaves plus spent nullifiers), not with its live entries. This tool
//! builds conservation-consistent pre-states of a chosen history `H` and executes
//! the guest ELF given with `--elf` on three batches over each:
//!
//! * `phase0`: an ordinary window: one deposit, two fills between the same pair of
//!   traders in market 0 (a taker buy that grows both positions, then a partial
//!   reverse), one L1 withdrawal and two funding ticks on market 0;
//! * `phase1`: the one-shot wind-down `SettleAll` over the whole state, with no
//!   shortfall, so the reserves are paid to the wind-down recipient as one
//!   withdrawal leaf;
//! * `phase1-haircut`: the same `SettleAll` when the last recorded prices leave a
//!   shortfall the (empty) reserves cannot cover, so the pro-rata haircut reissues
//!   every unspent note and appends one tree leaf per note before the post-root.
//!
//! The size mapping, for a history `H` that is a positive multiple of 80:
//! unspent notes `N = H/5`, positions `P = H/10` over 4 markets, tree leaves
//! `L = (H + N)/2 = 3N` and spent nullifiers `F = H − L = L − N` (every spent note
//! left exactly one nullifier). `H = 500,000` gives `P = 50,000` and
//! `N = 100,000`.
//!
//! Each witness is framed by the shared `sp1_host::encode_clock_witness`. Each run
//! checks that the guest's public value equals the native commitment
//! (`prover::public_from_witness`), and records the guest cycle count, the
//! executor's gas (SP1's own proving-cost estimate), the guest execution wall
//! time, the process's peak RSS (`getrusage`), the witness size, and the
//! Keccak-256 work of the same transition run natively with a counting `Hasher`
//! (hash calls, absorbed bytes, keccak-f permutations). Three tiny calibration
//! witnesses that differ only in tree depth give the guest cycles of one 65-byte
//! node hash (one software keccak-f permutation with its absorb and loop
//! overhead), from which the keccak share of each run's cycles is estimated.
//! Keccak computed outside the `Hasher` trait (the clock receipt, the
//! settlement-tree roots, deposit leaves, oracle-signer addresses) is a fixed few
//! dozen permutations per batch and is not counted.
//!
//! Usage:
//! `measure-history --elf GUEST_ELF --out NEW_JSON [--history H[,H...]]
//!  [--batch phase0,phase1,phase1-haircut]`
use perp_core::clock::{ClockContext, TimeBounds, WIRE_MAGIC};
use perp_core::commitment::{batch_time_ms, classify_wind_down_ops, derive_roots, DerivedRoots};
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::funding::FundingState;
use perp_core::hash::{word_u64, Digest, Domain, Hasher, Keccak256};
use perp_core::market::Market;
use perp_core::merkle::{
    ordered_root, rejected_root, withdrawals_root, MerkleTree, WithdrawalLeaf,
};
use perp_core::note::{owner_from_spend_key, Note};
use perp_core::nullifier::NullifierSet;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{BatchManifest, Side};
use perp_core::position::Position;
use perp_core::state::TREE_DEPTH;
use perp_core::{BatchOp, DefaultState, Mode, State};
use serde_json::{json, Value};
use sp1_host::{encode_clock_witness, sha256};
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin, StatusCode};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const USAGE: &str = "usage: measure-history --elf GUEST_ELF --out NEW_JSON \
     [--history H[,H...]] [--batch phase0,phase1,phase1-haircut]";
const DEFAULT_HISTORY: [u64; 5] = [10_000, 50_000, 100_000, 250_000, 500_000];
const BATCHES: [&str; 3] = ["phase0", "phase1", "phase1-haircut"];
const MAX_ELF_BYTES: u64 = 16 * 1024 * 1024;
const MARKETS: u64 = 4;
/// The public synthetic oracle signing key of these witnesses (a test value).
const ORACLE_KEY: [u8; 32] = [7; 32];
/// Start of the measured window, ms.
const T0: u64 = 1_800_000_000_000;
/// Keccak-256 absorbs 136 bytes per keccak-f[1600] permutation.
const KECCAK_RATE: u64 = 136;
/// Tree depths of the calibration witnesses.
const CALIBRATION_DEPTHS: [u8; 3] = [8, 36, 64];

// ---------------------------------------------------------------------------
// Counting hasher: Keccak-256 exactly, plus counters.
// ---------------------------------------------------------------------------

static HASH_CALLS: AtomicU64 = AtomicU64::new(0);
static ABSORBED: AtomicU64 = AtomicU64::new(0);
static PERMUTATIONS: AtomicU64 = AtomicU64::new(0);

/// `Keccak256` with a count of its calls, absorbed bytes and permutations. Every
/// digest equals `Keccak256`'s, so a state over it has the same roots.
#[derive(Clone, Copy, Debug, Default)]
struct CountingKeccak;

impl Hasher for CountingKeccak {
    fn hash_words(domain: Domain, words: &[Digest]) -> Digest {
        // One domain byte, then 32 bytes per word; padding adds at least one byte,
        // so a message of `m` bytes takes `m / 136 + 1` permutations.
        let bytes = 1 + 32 * words.len() as u64;
        HASH_CALLS.fetch_add(1, Ordering::Relaxed);
        ABSORBED.fetch_add(bytes, Ordering::Relaxed);
        PERMUTATIONS.fetch_add(bytes / KECCAK_RATE + 1, Ordering::Relaxed);
        Keccak256::hash_words(domain, words)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct KeccakCount {
    calls: u64,
    absorbed: u64,
    permutations: u64,
}

impl KeccakCount {
    fn now() -> Self {
        Self {
            calls: HASH_CALLS.load(Ordering::Relaxed),
            absorbed: ABSORBED.load(Ordering::Relaxed),
            permutations: PERMUTATIONS.load(Ordering::Relaxed),
        }
    }

    fn since(self, start: Self) -> Self {
        Self {
            calls: self.calls - start.calls,
            absorbed: self.absorbed - start.absorbed,
            permutations: self.permutations - start.permutations,
        }
    }

    fn json(self) -> Value {
        json!({"hash_calls": self.calls, "absorbed_bytes": self.absorbed,
            "permutations": self.permutations})
    }
}

/// The guest's transition (`bind_transition` after the strict decode), run over
/// `State<CountingKeccak>`. Returns the Keccak work of each stage and the two
/// state roots, which the caller compares with the uncounted native run.
fn counted_transition(bytes: &[u8]) -> Result<(Value, KeccakCount, Digest, Digest), String> {
    type CountedWitness = (
        State<CountingKeccak>,
        Vec<BatchOp>,
        BatchManifest,
        ClockContext,
    );
    let start = KeccakCount::now();
    let body = bytes
        .strip_prefix(WIRE_MAGIC)
        .ok_or("witness lacks the framing magic")?;
    let ((mut state, ops, manifest, clock), rest): (CountedWitness, _) =
        postcard::take_from_bytes(body).map_err(|e| format!("witness decode: {e}"))?;
    if !rest.is_empty() {
        return Err("trailing witness bytes".into());
    }
    let decoded = KeccakCount::now();
    let phase = classify_wind_down_ops(&ops).map_err(|e| format!("{e:?}"))?;
    let prev = state.state_root();
    let prev_root = KeccakCount::now();
    if manifest.previous_state_root != prev || manifest.batch_id != state.next_batch_id {
        return Err("manifest does not match the pre-state".into());
    }
    state
        .validate_witness_shape()
        .map_err(|e| format!("{e:?}"))?;
    if manifest.batch_time_ms != batch_time_ms(&ops) {
        return Err("manifest batch time".into());
    }
    let outputs = state.apply_batch(&ops).map_err(|e| format!("{e:?}"))?;
    let applied = KeccakCount::now();
    let new = state.state_root();
    let new_root = KeccakCount::now();
    let batch_id = manifest.batch_id;
    let rejected: Vec<Digest> = manifest.rejected.iter().map(|(h, _)| *h).collect();
    let leaves: Vec<WithdrawalLeaf> = outputs
        .withdrawals
        .iter()
        .map(WithdrawalLeaf::from)
        .collect();
    let roots = DerivedRoots {
        prev_state_root: prev,
        manifest_hash: manifest.hash::<CountingKeccak>(),
        new_state_root: new,
        ordered_root: ordered_root(batch_id, &manifest.ordered),
        withdrawals_root: withdrawals_root(&leaves),
        rejected_root: rejected_root(batch_id, &rejected),
        deposits_root: state.consumed_deposit_tip,
        wind_down_phase: phase,
    };
    // The guest takes the base commitment twice: once in the clock check, once
    // to bind it to the receipt.
    let _ = roots.commitment::<CountingKeccak>();
    let base = roots.commitment::<CountingKeccak>();
    if base != clock.base_commitment {
        return Err("base commitment differs from the clock context".into());
    }
    let end = KeccakCount::now();
    let stages = json!({
        "decode": decoded.since(start).json(),
        "prev_state_root": prev_root.since(decoded).json(),
        "apply_batch": applied.since(prev_root).json(),
        "new_state_root": new_root.since(applied).json(),
        "commitment": end.since(new_root).json(),
    });
    Ok((stages, end.since(start), prev, new))
}

// ---------------------------------------------------------------------------
// Peak RSS.
// ---------------------------------------------------------------------------

/// `struct rusage` of 64-bit Linux and macOS: two `timeval`s (16 bytes each),
/// then fourteen `long`s, the first of which is `ru_maxrss`.
#[repr(C)]
struct RUsage {
    utime: [i64; 2],
    stime: [i64; 2],
    longs: [i64; 14],
}

extern "C" {
    fn getrusage(who: i32, usage: *mut RUsage) -> i32;
}

/// The process's peak resident set size in bytes (`ru_maxrss` is in bytes on
/// macOS and in KiB on Linux).
fn peak_rss_bytes() -> u64 {
    let mut usage = RUsage {
        utime: [0; 2],
        stime: [0; 2],
        longs: [0; 14],
    };
    // SAFETY: `usage` is a valid, writable `struct rusage` for this target, and
    // RUSAGE_SELF (0) only reads this process's counters.
    let rc = unsafe { getrusage(0, &mut usage) };
    assert_eq!(rc, 0, "getrusage failed");
    let maxrss = usage.longs[0].max(0) as u64;
    if cfg!(target_os = "macos") {
        maxrss
    } else {
        maxrss * 1024
    }
}

// ---------------------------------------------------------------------------
// Synthetic pre-states.
// ---------------------------------------------------------------------------

/// Deterministic public test keys and blindings: `H(KeyDerivation, [kind, i])`.
fn derived(kind: u64, i: u64) -> Digest {
    Keccak256::hash_words(Domain::KeyDerivation, &[word_u64(kind), word_u64(i)])
}
const KIND_TRADER: u64 = 1;
const KIND_NOTE: u64 = 2;
const KIND_BLIND: u64 = 3;
const KIND_DEPOSIT: u64 = 4;
const KIND_ORDER: u64 = 5;

#[derive(Clone, Copy, Debug)]
struct Shape {
    history: u64,
    leaves: u64,
    nullifiers: u64,
    notes: u64,
    positions: u64,
}

impl Shape {
    fn of(history: u64) -> Result<Self, String> {
        if history == 0 || !history.is_multiple_of(80) {
            return Err(format!(
                "history {history} must be a positive multiple of 80"
            ));
        }
        let notes = history / 5;
        let leaves = (history + notes) / 2;
        Ok(Self {
            history,
            leaves,
            nullifiers: history - leaves,
            notes,
            positions: history / 10,
        })
    }

    fn json(&self) -> Value {
        json!({"history": self.history, "tree_leaves": self.leaves,
            "spent_nullifiers": self.nullifiers, "unspent_notes": self.notes,
            "positions": self.positions, "markets": MARKETS})
    }
}

fn market_price(m: u64) -> i128 {
    (1_000 + 500 * m as i128) * PRICE_SCALE
}

/// Note `i`: one public spend key per note; leaf `i` is unspent iff `i % 3 == 2`.
fn note(i: u64) -> (Digest, Note) {
    let spend_key = derived(KIND_NOTE, i);
    let owner = owner_from_spend_key::<Keccak256>(&spend_key);
    let amount = (50 + (i % 97) as i128) * QUOTE_SCALE;
    (
        spend_key,
        Note::new(owner, 0, amount, derived(KIND_BLIND, i)),
    )
}

fn trader(t: u64) -> Digest {
    owner_from_spend_key::<Keccak256>(&derived(KIND_TRADER, t))
}

#[derive(Clone, Copy, PartialEq)]
enum Scenario {
    /// Positions close inside their collateral; the reserves are paid out.
    Solvent,
    /// Prices doubled since entry and the reserves are empty: the shorts' losses
    /// exceed their collateral and the haircut takes the shortfall.
    Shortfall,
}

/// A conservation-consistent pre-state of `shape`. Traders `2k` and `2k+1` hold
/// opposite positions of equal size, entry and funding entry in every market, so
/// realized PnL and funding net to zero across each pair.
fn pre_state(
    shape: &Shape,
    oracle_address: [u8; 20],
    scenario: Scenario,
    mode: Mode,
) -> DefaultState {
    let mut state = DefaultState::new(TREE_DEPTH);
    for m in 0..MARKETS {
        let mut market = Market::with_fees_treasury(m, 5, 1, 2);
        market.oracle_pubkey = oracle_address;
        state.add_market(market);
        let recorded = match scenario {
            Scenario::Solvent => market_price(m),
            Scenario::Shortfall => 2 * market_price(m),
        };
        state.funding.insert(
            m,
            FundingState {
                cumulative_index: 1_000 + 37 * m as i128,
                last_update_ms: T0 - 700,
                rate: 25,
                remainder: 12_345,
                last_price: recorded,
                last_price_ms: T0 - 700,
            },
        );
    }
    let mut leaves = Vec::with_capacity(shape.leaves as usize);
    let mut log = Vec::with_capacity(shape.nullifiers as usize);
    let mut spent_value = 0i128;
    for i in 0..shape.leaves {
        let (spend_key, n) = note(i);
        let cm = n.commitment::<Keccak256>();
        leaves.push(cm);
        if i % 3 == 2 {
            state.notes.insert(cm, n);
        } else {
            log.push(n.nullifier::<Keccak256>(&spend_key));
            spent_value += n.amount;
        }
    }
    assert_eq!(state.notes.len() as u64, shape.notes);
    state.tree = MerkleTree::from_leaves(TREE_DEPTH, leaves).expect("unique leaves");
    state.nullifiers = NullifierSet::from_log(log).expect("unique nullifiers");
    let traders = shape.positions / MARKETS;
    let mut positions = BTreeMap::new();
    for t in 0..traders {
        let owner = trader(t);
        let k = t / 2;
        for m in 0..MARKETS {
            let size = (1 + (k % 5) as i128) * SIZE_SCALE / 100;
            let long = (t + m) % 2 == 0;
            let entry = market_price(m) / 1000 * (990 + (k % 21) as i128);
            let collateral = (50 + (k % 13) as i128) * QUOTE_SCALE;
            let funding_entry = 1_000 + 37 * m as i128 - (k % 50) as i128;
            positions.insert(
                (owner, m),
                Position {
                    owner,
                    market_id: m,
                    size: if long { size } else { -size },
                    entry_price: entry,
                    collateral,
                    funding_entry,
                },
            );
        }
    }
    state.positions = positions;
    assert_eq!(state.positions.len() as u64, shape.positions);
    if scenario == Scenario::Solvent {
        state.insurance_fund = 5_000 * QUOTE_SCALE;
        state.treasury = 2_000 * QUOTE_SCALE;
        state.vault_pool = 1_000 * QUOTE_SCALE;
    }
    state.external_out = spent_value;
    state.external_in = state.internal_value().expect("no overflow") + spent_value;
    state.consumed_deposit_count = shape.leaves;
    state.consumed_deposit_tip = derived(KIND_DEPOSIT, u64::MAX);
    state.next_batch_id = shape.history / 10;
    state.last_withdrawal_nonce = shape.nullifiers;
    state.set_wind_down_recipient([0x5D; 20]);
    state.mode = mode;
    assert!(state.conservation_holds(), "synthetic pre-state conserves");
    state
}

fn transcript(key: &k256::ecdsa::SigningKey, market: u64, now_ms: u64) -> OracleTranscript {
    let price = market_price(market);
    OracleTranscript {
        price,
        publish_time_ms: now_ms,
        confidence: 0,
        backup_twap: price,
        signature: OracleSig::sign(key, &oracle_digest(market, price, now_ms, 0, price)),
    }
}

fn phase0_ops(state: &DefaultState, key: &k256::ecdsa::SigningKey) -> Vec<BatchOp> {
    let (taker, maker) = (trader(0), trader(1));
    let (spend_key, n) = note(2);
    let depositor = derived(KIND_DEPOSIT, 0);
    let fill = |side: Side, size: i128, now_ms: u64| BatchOp::Fill {
        taker,
        maker,
        market_id: 0,
        taker_side: side,
        size,
        price: market_price(0),
        oracle: transcript(key, 0, now_ms),
        now_ms,
    };
    let tick = |now_ms: u64| BatchOp::AccrueFunding {
        market_id: 0,
        mark: market_price(0) / 1000 * 1001,
        oracle: transcript(key, 0, now_ms),
        now_ms,
    };
    vec![
        BatchOp::Deposit {
            owner: owner_from_spend_key::<Keccak256>(&depositor),
            asset_id: 0,
            amount: 250 * QUOTE_SCALE,
            blinding: derived(KIND_DEPOSIT, 1),
            from: [0x0D; 20],
            deposit_id: state.consumed_deposit_count,
            deposit_blind: derived(KIND_DEPOSIT, 2),
        },
        fill(Side::Buy, 2 * SIZE_SCALE / 100, T0),
        fill(Side::Sell, SIZE_SCALE / 100, T0 + 100),
        BatchOp::Withdraw {
            note_commitment: n.commitment::<Keccak256>(),
            spend_key,
            to: Some([0xAB; 20]),
            nonce: state.last_withdrawal_nonce + 1,
        },
        tick(T0 + 300),
        tick(T0 + 700),
    ]
}

/// A witness of `ops` over `state`, with its honest manifest and clock context.
/// Returns the framed bytes and the commitment the guest must commit.
fn witness(
    state: &DefaultState,
    ops: Vec<BatchOp>,
    ordered: Vec<Digest>,
    anchored_at_ms: u64,
) -> (Vec<u8>, [u8; 32]) {
    let manifest = BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        batch_time_ms: batch_time_ms(&ops),
        ordered,
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    };
    let roots = derive_roots(&mut state.clone(), &ops, &manifest).expect("valid transition");
    let bounds = TimeBounds::derive(&ops).expect("ordered times");
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
        anchored_at_ms,
        max_window_ms: 30_000,
        clock_skew_ms: 30_000,
    };
    let bytes = encode_clock_witness(state, &ops, &manifest, &clock);
    let native = prover::public_from_witness(&bytes).expect("native twin accepts the witness");
    let commitment = native.commitment::<Keccak256>();
    assert_eq!(
        commitment,
        clock.commitment(),
        "native twin binds the clock"
    );
    (bytes, commitment)
}

// ---------------------------------------------------------------------------
// Execution.
// ---------------------------------------------------------------------------

struct Guest<P: Prover> {
    client: P,
    elf: Elf,
}

struct Executed {
    cycles: u64,
    gas: Option<u64>,
    wall_s: f64,
}

impl<P: Prover> Guest<P> {
    async fn execute(&self, bytes: &[u8], expected: &[u8; 32]) -> Executed {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(bytes.to_vec());
        let started = Instant::now();
        let (values, report) = self
            .client
            .execute(self.elf.clone(), stdin)
            // The cycle report and the final state come from the executor's gas
            // pass, so it stays on (the SDK default).
            .calculate_gas(true)
            .expected_exit_code(StatusCode::SUCCESS)
            .await
            .expect("guest execution");
        let wall_s = started.elapsed().as_secs_f64();
        assert_eq!(
            values.as_slice(),
            expected,
            "guest commits the native commitment"
        );
        Executed {
            cycles: report.total_instruction_count(),
            gas: report.gas(),
            wall_s,
        }
    }
}

/// Guest cycles of one keccak-f permutation: tiny witnesses with one leaf and no
/// ops that differ only in tree depth, so each extra level adds one 65-byte node
/// hash to decoding and to each of the two state roots, and nothing else.
async fn calibrate<P: Prover>(guest: &Guest<P>) -> Value {
    let mut points = Vec::new();
    for depth in CALIBRATION_DEPTHS {
        let mut state = DefaultState::new(depth);
        state.add_market(Market::conservative(0));
        state
            .tree
            .append(derived(KIND_BLIND, u64::MAX))
            .expect("room");
        let (bytes, expected) = witness(&state, vec![], vec![], T0);
        let (_, keccak, _, _) = counted_transition(&bytes).expect("counted calibration run");
        let run = guest.execute(&bytes, &expected).await;
        points.push((depth, run.cycles, keccak.permutations, run.gas.unwrap_or(0)));
    }
    let (first, last) = (points[0], points[points.len() - 1]);
    let permutations = (last.2 - first.2) as f64;
    let per_permutation = (last.1 - first.1) as f64 / permutations;
    let gas_per_permutation = (last.3 as f64 - first.3 as f64) / permutations;
    // Linearity check: the middle point predicted from the outer two.
    let mid = points[1];
    let predicted = first.1 as f64 + per_permutation * (mid.2 - first.2) as f64;
    json!({
        "method": "tree-depth differential: one leaf, no ops, depths 8/36/64; each level adds one 65-byte MerkleNode hash to decode and to each of the two state roots",
        "points": points.iter().map(|(d, c, p, g)| json!({"tree_depth": d, "cycles": c, "permutations": p, "gas": g})).collect::<Vec<_>>(),
        "cycles_per_permutation": per_permutation,
        "gas_per_permutation": gas_per_permutation,
        "midpoint_prediction_error": (mid.1 as f64 - predicted) / mid.1 as f64,
    })
}

async fn measure<P: Prover>(
    guest: &Guest<P>,
    oracle_key: &k256::ecdsa::SigningKey,
    oracle_address: [u8; 20],
    history: u64,
    batch: &str,
    per_permutation: f64,
) -> Value {
    let shape = Shape::of(history).unwrap_or_else(|e| panic!("{e}"));
    let built = Instant::now();
    let (state, ops, ordered, anchored_at_ms) = match batch {
        "phase0" => {
            let state = pre_state(&shape, oracle_address, Scenario::Solvent, Mode::Normal);
            let ops = phase0_ops(&state, oracle_key);
            (
                state,
                ops,
                vec![derived(KIND_ORDER, 0), derived(KIND_ORDER, 1)],
                T0 + 1_000,
            )
        }
        "phase1" | "phase1-haircut" => {
            let scenario = if batch == "phase1" {
                Scenario::Solvent
            } else {
                Scenario::Shortfall
            };
            let state = pre_state(&shape, oracle_address, scenario, Mode::CloseOnly);
            (state, vec![BatchOp::SettleAll], vec![], T0 + 3_600_000)
        }
        other => panic!("unknown batch {other}; {USAGE}"),
    };
    let op_names: Vec<&str> = ops
        .iter()
        .map(|op| match op {
            BatchOp::Deposit { .. } => "Deposit",
            BatchOp::Fill { .. } => "Fill",
            BatchOp::Withdraw { .. } => "Withdraw",
            BatchOp::AccrueFunding { .. } => "AccrueFunding",
            BatchOp::SettleAll => "SettleAll",
            _ => "other",
        })
        .collect();
    let (bytes, expected) = witness(&state, ops, ordered, anchored_at_ms);
    let build_s = built.elapsed().as_secs_f64();

    // Native twin, timed, and its post-state for the record.
    let native_started = Instant::now();
    let (mut post, ops, manifest, clock) = prover::decode_clock_witness(&bytes).expect("decode");
    let bound = perp_core::clock::bind_transition(&mut post, &ops, &manifest, &clock)
        .expect("native transition");
    let native_s = native_started.elapsed().as_secs_f64();
    assert_eq!(bound.commitment, expected);
    let (stages, keccak, prev, new) = counted_transition(&bytes).expect("counted native run");
    assert_eq!(
        (prev, new),
        (bound.roots.prev_state_root, bound.roots.new_state_root),
        "the counted run derives the same roots"
    );
    drop(state);
    let rss_before_execute = peak_rss_bytes();

    let run = guest.execute(&bytes, &expected).await;
    let keccak_cycles = keccak.permutations as f64 * per_permutation;
    let result = json!({
        "batch": batch,
        "shape": shape.json(),
        "ops": op_names,
        "witness_bytes": bytes.len(),
        "witness_sha256": sha256(&bytes),
        "commitment": format!("0x{}", sp1_host::hex(&expected)),
        "native_guest_equal": true,
        "withdrawals_root": format!("0x{}", sp1_host::hex(&bound.roots.withdrawals_root)),
        "post_state": {"tree_leaves": post.tree.len(), "spent_nullifiers": post.nullifiers.len(),
            "unspent_notes": post.notes.len(), "positions": post.positions.len(),
            "mode": format!("{:?}", post.mode)},
        "cycles": run.cycles,
        "gas": run.gas,
        "guest_execute_wall_s": run.wall_s,
        "witness_build_s": build_s,
        "native_transition_s": native_s,
        "peak_rss_bytes_before_execute": rss_before_execute,
        "peak_rss_bytes": peak_rss_bytes(),
        "keccak_native": keccak.json(),
        "keccak_native_by_stage": stages,
        "keccak_share_estimate": keccak_cycles / run.cycles as f64,
    });
    eprintln!(
        "MEASURED {batch} history={history} cycles={} wall_s={:.1} keccak_share={:.3}",
        run.cycles,
        run.wall_s,
        keccak_cycles / run.cycles as f64
    );
    result
}

/// Read a bounded regular (non-symlink) ELF file.
fn read_elf(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| format!("guest ELF: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err("guest ELF must be a regular non-symlink file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_ELF_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("guest ELF: {e}"))?;
    if bytes.len() as u64 > MAX_ELF_BYTES || !bytes.starts_with(b"\x7fELF") {
        return Err("guest ELF input is not a bounded ELF file".into());
    }
    Ok(bytes)
}

struct Args {
    elf: String,
    out: String,
    history: Vec<u64>,
    batches: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let (mut elf, mut out, mut history, mut batches) = (None, None, None, None);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = || rest.next().cloned().ok_or_else(|| USAGE.to_string());
        match arg.as_str() {
            "--elf" if elf.is_none() => elf = Some(value()?),
            "--out" if out.is_none() => out = Some(value()?),
            "--history" if history.is_none() => {
                let list = value()?
                    .split(',')
                    .map(|h| h.parse::<u64>().map_err(|_| USAGE.to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
                for h in &list {
                    Shape::of(*h)?;
                }
                history = Some(list);
            }
            "--batch" if batches.is_none() => {
                let list: Vec<String> = value()?.split(',').map(str::to_string).collect();
                if list.iter().any(|b| !BATCHES.contains(&b.as_str())) {
                    return Err(USAGE.into());
                }
                batches = Some(list);
            }
            _ => return Err(USAGE.into()),
        }
    }
    Ok(Args {
        elf: elf.ok_or(USAGE)?,
        out: out.ok_or(USAGE)?,
        history: history.unwrap_or_else(|| DEFAULT_HISTORY.to_vec()),
        batches: batches.unwrap_or_else(|| BATCHES.iter().map(|b| b.to_string()).collect()),
    })
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv).unwrap_or_else(|e| panic!("{e}"));
    let elf_bytes = read_elf(Path::new(&args.elf)).unwrap_or_else(|e| panic!("{e}"));
    // Create the output first, so a run never overwrites earlier evidence.
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.out)
        .expect("new output file");
    let oracle_key = k256::ecdsa::SigningKey::from_slice(&ORACLE_KEY).expect("test key");
    let probe = oracle_digest(0, PRICE_SCALE, 1, 0, PRICE_SCALE);
    let oracle_address = OracleSig::sign(&oracle_key, &probe)
        .recover(&probe)
        .expect("recovers");
    let guest = Guest {
        client: ProverClient::builder().light().build().await,
        elf: Elf::from(elf_bytes.clone()),
    };
    let calibration = calibrate(&guest).await;
    let per_permutation = calibration["cycles_per_permutation"]
        .as_f64()
        .expect("calibrated");
    eprintln!("CALIBRATED cycles_per_permutation={per_permutation:.1}");
    let mut runs = Vec::new();
    for history in &args.history {
        for batch in &args.batches {
            runs.push(
                measure(
                    &guest,
                    &oracle_key,
                    oracle_address,
                    *history,
                    batch,
                    per_permutation,
                )
                .await,
            );
        }
    }
    let report = json!({
        "kind": "pkg3-history-measurement",
        "sdk_version": "6.1.0",
        "executor": "sp1-sdk light client, execute only (no setup, no proving)",
        "elf_sha256": sha256(&elf_bytes),
        "host_os": std::env::consts::OS,
        "host_arch": std::env::consts::ARCH,
        "size_mapping": "H a multiple of 80; unspent notes N = H/5; positions P = H/10 over 4 markets; tree leaves L = (H+N)/2 = 3N; spent nullifiers F = H - L = L - N",
        "calibration": calibration,
        "runs": runs,
    });
    out.write_all(&serde_json::to_vec_pretty(&report).expect("json"))
        .and_then(|()| out.sync_all())
        .expect("write output");
}
