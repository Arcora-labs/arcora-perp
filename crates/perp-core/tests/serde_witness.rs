//! Witness serialization round-trips (the documented prerequisite for the real
//! zkVM guest, docs/PROVING.md). Run with `cargo test -p perp-core --features serde`.
//! Proves a full state + the batch ops encode and decode losslessly with a
//! no_std-friendly binary format (postcard), so the host can write the witness to
//! the prover and the guest can read it back identically.
#![cfg(feature = "serde")]

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::Side;
use perp_core::{DefaultState, Note};

/// Owner id bound to spend key `[i as u8; 32]` (audit DP-003): each owner funds its
/// note with this key, so the note owner must derive from it.
fn owner(i: u64) -> [u8; 32] {
    owner_from_spend_key::<Keccak256>(&[i as u8; 32])
}

/// ZK-001: fixture publisher key; markets set `oracle_pubkey` to its address so the
/// signed transcripts clear the real fail-closed gate on apply.
fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn oracle_addr() -> [u8; 20] {
    let d = oracle_digest(0, 1, 1, 0, 1);
    OracleSig::sign(&oracle_key(), &d).recover(&d).unwrap()
}

fn signed_market(m: Market) -> Market {
    let mut m = m;
    m.oracle_pubkey = oracle_addr();
    m
}

fn oracle(p: i128, now: u64) -> OracleTranscript {
    let (price, confidence, backup_twap) = (p * PRICE_SCALE, 10 * PRICE_SCALE, p * PRICE_SCALE);
    let d = oracle_digest(0, price, now, confidence, backup_twap);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn built_state() -> DefaultState {
    let mut s = DefaultState::new(20);
    s.add_market(signed_market(Market::conservative(0)));
    s.add_market(signed_market(Market::conservative(1)));
    for i in 1u64..=3 {
        let o = owner(i);
        let blind = [i as u8; 32];
        let amt = 50_000 * QUOTE_SCALE;
        let cm = Note::new(o, 0, amt, blind).commitment::<Keccak256>();
        s.apply_op(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: blind,
            from: [i as u8; 20],
            deposit_id: i - 1,
            deposit_blind: [0xDBu8; 32],
        })
        .unwrap();
        s.apply_op(&BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm,
            spend_key: [i as u8; 32],
        })
        .unwrap();
    }
    // open a couple of positions so the state has interesting structure
    s.apply_op(&BatchOp::Fill {
        taker: owner(1),
        maker: owner(2),
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE / 2,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();
    s
}

#[test]
fn state_round_trips_losslessly() {
    let s = built_state();
    let bytes = postcard::to_allocvec(&s).expect("serialize state");
    let back: DefaultState = postcard::from_bytes(&bytes).expect("deserialize state");
    // the state root is the canonical fingerprint — equal ⇒ identical witness
    assert_eq!(
        s.state_root(),
        back.state_root(),
        "state root survives round-trip"
    );
    assert_eq!(s.conservation_holds(), back.conservation_holds());
    assert_eq!(
        s.position(&owner(1), 0).map(|p| p.size),
        back.position(&owner(1), 0).map(|p| p.size),
    );
}

#[test]
fn ops_round_trip_and_replay_identically() {
    // a witness's ops list must decode to the same ops that re-derive the same root
    let ops = vec![
        BatchOp::Deposit {
            owner: word_u64(9),
            asset_id: 0,
            amount: 1_000 * QUOTE_SCALE,
            blinding: [9; 32],
            from: [9u8; 20],
            // built_state() consumes 3 L1 deposits (ids 0..2); this is the next one.
            deposit_id: 3,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::AccrueFunding {
            market_id: 0,
            mark: 100_050 * PRICE_SCALE,
            oracle: oracle(100_000, 2_000),
            now_ms: 2_000,
        },
        BatchOp::EnterCloseOnly,
    ];
    let bytes = postcard::to_allocvec(&ops).expect("serialize ops");
    let back: Vec<BatchOp> = postcard::from_bytes(&bytes).expect("deserialize ops");

    let mut a = built_state();
    let mut b = built_state();
    for op in &ops {
        let _ = a.apply_op(op);
    }
    for op in &back {
        let _ = b.apply_op(op);
    }
    assert_eq!(
        a.state_root(),
        b.state_root(),
        "decoded ops replay to the same root"
    );
}

/// The guest's witness: `WIRE_MAGIC ‖ postcard(ClockWitness)`. Decoding the framed
/// bytes and running `bind_transition` reproduces the identical bound commitment.
#[test]
fn full_witness_round_trips_and_rederives_commitment() {
    use perp_core::clock::{bind_transition, ClockContext, ClockWitness, WIRE_MAGIC};
    use perp_core::commitment::derive_roots;
    use perp_core::order::BatchManifest;

    let s = built_state();
    let ops = vec![BatchOp::AccrueFunding {
        market_id: 0,
        mark: 100_050 * PRICE_SCALE,
        oracle: oracle(100_000, 2_000),
        now_ms: 2_000,
    }];
    let manifest = BatchManifest {
        previous_state_root: s.state_root(),
        batch_id: s.next_batch_id,
        batch_time_ms: 2_000, // matches the op's now_ms above
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    };
    let roots = derive_roots(&mut s.clone(), &ops, &manifest).unwrap();
    let clock = ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: manifest.batch_id,
        previous_root: roots.prev_state_root,
        base_commitment: roots.commitment::<Keccak256>(),
        phase: roots.wind_down_phase,
        first_ms: 2_000,
        last_ms: 2_000,
        timed_ops: 1,
        anchored_at_ms: 2_000,
        max_window_ms: 5_000,
        clock_skew_ms: 1_000,
    };
    let witness: ClockWitness = (s.clone(), ops.clone(), manifest.clone(), clock);
    let mut bytes = WIRE_MAGIC.to_vec();
    bytes.extend(postcard::to_allocvec(&witness).expect("serialize witness"));

    let body = bytes.strip_prefix(WIRE_MAGIC).expect("framed");
    let ((mut s2, ops2, manifest2, clock2), rest): (ClockWitness, _) =
        postcard::take_from_bytes(body).expect("deserialize witness");
    assert!(rest.is_empty(), "no trailing bytes");

    let a = bind_transition(&mut s.clone(), &ops, &manifest, &clock).unwrap();
    let b = bind_transition(&mut s2, &ops2, &manifest2, &clock2).unwrap();
    assert_eq!(a, b, "decoded witness re-derives the identical transition");
    assert_eq!(b.commitment, clock.commitment());
}

// ---------------------------------------------------------------------------
// SEC-026 — failure atomicity, pinned at the STRONGEST granularity: a rejected
// mint must leave the full postcard encoding of the state byte-for-byte
// unchanged (not merely the state root). Before SEC-026, `op_deposit` mutated
// `tree` and `notes` before the fallible `external_in` add, and a duplicate of a
// SPENT commitment was accepted outright.
// ---------------------------------------------------------------------------

/// A rejected duplicate (same tuple as a previously-spent note) leaves the full
/// postcard bytes unchanged — no tree append, no `external_in`, no deposit-count
/// advance, no notes-map entry.
#[test]
fn sec026_rejected_duplicate_leaves_postcard_bytes_unchanged() {
    use perp_core::EngineError;
    let mut s = DefaultState::new(20);
    s.add_market(signed_market(Market::conservative(0)));
    let o = owner(1);
    let bl = [9u8; 32];
    let amt = 1_000 * QUOTE_SCALE;
    let cm = Note::new(o, 0, amt, bl).commitment::<Keccak256>();
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: amt,
        blinding: bl,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    })
    .unwrap();
    s.apply_op(&BatchOp::Withdraw {
        note_commitment: cm,
        spend_key: [1u8; 32],
        to: None,
        nonce: 0,
    })
    .unwrap();

    let before = postcard::to_allocvec(&s).expect("serialize state");
    let err = s
        .apply_op(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: bl,
            from: [0xA1u8; 20],
            deposit_id: 1, // in-order: historical uniqueness is what rejects
            deposit_blind: [0xDBu8; 32],
        })
        .unwrap_err();
    assert_eq!(err, EngineError::DuplicateCommitment);
    let after = postcard::to_allocvec(&s).expect("serialize state");
    assert_eq!(
        before, after,
        "a rejected duplicate must leave the state byte-for-byte unchanged"
    );
    assert!(s.conservation_holds());
}

/// An `external_in` overflow must reject the deposit with NO partial mutation.
/// Before SEC-026, `tree`/`notes` had already mutated when the add failed.
#[test]
fn sec026_overflowing_deposit_leaves_postcard_bytes_unchanged() {
    use perp_core::EngineError;
    let mut s = DefaultState::new(20);
    // conservation-consistent extreme: internal_value == external_in − external_out
    s.insurance_fund = i128::MAX;
    s.external_in = i128::MAX;
    assert!(s.conservation_holds());

    let before = postcard::to_allocvec(&s).expect("serialize state");
    let err = s
        .apply_op(&BatchOp::Deposit {
            owner: owner(1),
            asset_id: 0,
            amount: 1_000 * QUOTE_SCALE,
            blinding: [4u8; 32],
            from: [0xA1u8; 20],
            deposit_id: 0,
            deposit_blind: [0xDBu8; 32],
        })
        .unwrap_err();
    assert_eq!(err, EngineError::Overflow);
    let after = postcard::to_allocvec(&s).expect("serialize state");
    assert_eq!(
        before, after,
        "an overflowing deposit must not partially mutate the state"
    );
    assert!(s.conservation_holds());
}

/// A tree-full mint rejects with NO partial mutation (the append fails before any
/// insertion, and nothing else may have moved first).
#[test]
fn sec026_tree_full_deposit_leaves_postcard_bytes_unchanged() {
    use perp_core::EngineError;
    let mut s = DefaultState::new(1); // capacity 2
    for i in 0..2u64 {
        s.apply_op(&BatchOp::Deposit {
            owner: owner(1),
            asset_id: 0,
            amount: 1_000 * QUOTE_SCALE,
            blinding: [i as u8; 32],
            from: [0xA1u8; 20],
            deposit_id: i,
            deposit_blind: [0xDBu8; 32],
        })
        .unwrap();
    }
    let before = postcard::to_allocvec(&s).expect("serialize state");
    let err = s
        .apply_op(&BatchOp::Deposit {
            owner: owner(1),
            asset_id: 0,
            amount: 1_000 * QUOTE_SCALE,
            blinding: [7u8; 32],
            from: [0xA1u8; 20],
            deposit_id: 2,
            deposit_blind: [0xDBu8; 32],
        })
        .unwrap_err();
    assert_eq!(err, EngineError::Overflow);
    let after = postcard::to_allocvec(&s).expect("serialize state");
    assert_eq!(
        before, after,
        "a tree-full mint must not partially mutate the state"
    );
    assert!(s.conservation_holds());
}

/// The nightmare case for a derived index: a state restored from bytes (snapshot /
/// witness) whose index arrived silently empty would re-accept spent tuples and
/// reintroduce the bug. Deserialization must rebuild the index, so the RESTORED
/// state still rejects a historical duplicate on both mint paths.
#[test]
fn sec026_restored_state_still_rejects_historical_duplicates() {
    use perp_core::EngineError;
    let mut s = DefaultState::new(20);
    s.add_market(signed_market(Market::conservative(0)));
    let o = owner(1);
    let bl = [9u8; 32];
    let amt = 1_000 * QUOTE_SCALE;
    let cm = Note::new(o, 0, amt, bl).commitment::<Keccak256>();
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: amt,
        blinding: bl,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    })
    .unwrap();
    s.apply_op(&BatchOp::Withdraw {
        note_commitment: cm,
        spend_key: [1u8; 32],
        to: None,
        nonce: 0,
    })
    .unwrap();

    // round-trip through the wire format, exactly like a snapshot/witness load
    let bytes = postcard::to_allocvec(&s).expect("serialize state");
    let mut back: DefaultState = postcard::from_bytes(&bytes).expect("deserialize state");
    assert_eq!(s.state_root(), back.state_root());

    let err = back
        .apply_op(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: bl,
            from: [0xA1u8; 20],
            deposit_id: 1,
            deposit_blind: [0xDBu8; 32],
        })
        .unwrap_err();
    assert_eq!(
        err,
        EngineError::DuplicateCommitment,
        "the restored state must remember every historical commitment"
    );
    assert!(back.conservation_holds());
}

// ---------------------------------------------------------------------------
// Witness binding. A decoded pre-state is trusted only through its state root,
// which the batch manifest (and L1) anchor. Every serialized field is therefore
// either hashed into the root, derived on decode from root-bound fields, or
// checked against a root-bound key by `validate_witness_shape`:
//
// * the commitment tree encodes `(depth, leaves)`; its empty-subtree roots and
//   leaf index are derived;
// * the nullifier set encodes its insertion-order log; its membership index and
//   its digest (a hash chain over the log) are derived;
// * every funding field is hashed into the root, and the shape check also
//   refuses a value outside the range the engine maintains.
//
// So a pre-state that differs from the anchored one in any encoded value fails
// to decode, fails the shape check, or has a different root and fails
// `ManifestMismatch` against the anchored manifest.
// ---------------------------------------------------------------------------
mod binding {
    use super::*;
    use perp_core::commitment::{batch_time_ms, derive_roots};
    use perp_core::funding::FundingState;
    use perp_core::hash::{Digest, Domain, Hasher};
    use perp_core::market::MarketId;
    use perp_core::note::PubKey;
    use perp_core::order::BatchManifest;
    use perp_core::position::Position;
    use perp_core::state::{Mode, TREE_DEPTH};
    use perp_core::EngineError;
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet};

    /// The encoded layout of `DefaultState`, field for field (postcard is
    /// positional). `layout_mirror_encodes_identically` pins it to the real type.
    #[derive(Clone, Serialize, Deserialize)]
    struct StateWire {
        tree: TreeWire,
        nullifiers: NullifierWire,
        notes: BTreeMap<Digest, Note>,
        markets: BTreeMap<MarketId, Market>,
        funding: BTreeMap<MarketId, FundingState>,
        positions: BTreeMap<(PubKey, MarketId), Position>,
        insurance_fund: i128,
        vault_pool: i128,
        treasury: i128,
        external_in: i128,
        external_out: i128,
        mode: Mode,
        next_batch_id: u64,
        last_withdrawal_nonce: u64,
        consumed_deposit_tip: Digest,
        consumed_deposit_count: u64,
        wind_down_recipient: [u8; 20],
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct TreeWire {
        depth: u8,
        leaves: Vec<Digest>,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct NullifierWire {
        log: Vec<Digest>,
    }

    const PAYOUT: [u8; 20] = [0xAB; 20];

    fn to_wire(s: &DefaultState) -> StateWire {
        postcard::from_bytes(&postcard::to_allocvec(s).unwrap()).unwrap()
    }

    fn encode(w: &StateWire) -> Vec<u8> {
        postcard::to_allocvec(w).unwrap()
    }

    /// Decode exactly one state, with nothing after it.
    fn decode(bytes: &[u8]) -> Result<DefaultState, ()> {
        match postcard::take_from_bytes::<DefaultState>(bytes) {
            Ok((s, [])) => Ok(s),
            _ => Err(()),
        }
    }

    fn deposit(owner_key: u8, amount: i128, blind: u8, deposit_id: u64) -> (BatchOp, Digest) {
        let o = owner(owner_key as u64);
        let op = BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount,
            blinding: [blind; 32],
            from: [owner_key; 20],
            deposit_id,
            deposit_blind: [0xDB; 32],
        };
        (
            op,
            Note::new(o, 0, amount, [blind; 32]).commitment::<Keccak256>(),
        )
    }

    fn withdraw(owner_key: u8, cm: Digest, nonce: u64) -> BatchOp {
        BatchOp::Withdraw {
            note_commitment: cm,
            spend_key: [owner_key; 32],
            to: Some(PAYOUT),
            nonce,
        }
    }

    /// The anchored pre-state: two markets (one with a stored funding rate and a
    /// non-zero carry), three funded positions (two of them open), one live note,
    /// one withdrawn note, four nullifiers whose insertion order is not their
    /// sorted order, and a wind-down recipient.
    struct Fixture {
        state: DefaultState,
        /// A note that is still unspent.
        live: (u8, Digest),
        /// The deposit tuple of a note that was withdrawn.
        spent: (u8, i128, u8),
    }

    fn fixture() -> Fixture {
        let mut s = built_state();
        // a premium tick stores a rate; the next tick commits a span at it
        for now in [1_000, 1_700] {
            s.apply_op(&BatchOp::AccrueFunding {
                market_id: 0,
                mark: 101_000 * PRICE_SCALE,
                oracle: oracle(100_000, now),
                now_ms: now,
            })
            .unwrap();
        }
        let f = s.funding[&0];
        assert!(f.rate != 0 && f.remainder != 0 && f.cumulative_index != 0);
        s.set_wind_down_recipient([0xEE; 20]);
        let amount = 1_000 * QUOTE_SCALE;
        let (op, live_cm) = deposit(4, amount, 0x44, s.consumed_deposit_count);
        s.apply_op(&op).unwrap();
        let (op, spent_cm) = deposit(5, amount, 0x55, s.consumed_deposit_count);
        s.apply_op(&op).unwrap();
        s.apply_op(&withdraw(5, spent_cm, 1)).unwrap();
        let log = to_wire(&s).nullifiers.log;
        assert_eq!(log.len(), 4);
        let mut sorted = log.clone();
        sorted.sort();
        assert_ne!(
            log, sorted,
            "fixture: insertion order differs from sorted order"
        );
        assert!(s.conservation_holds());
        Fixture {
            state: s,
            live: (4, live_cm),
            spent: (5, amount, 0x55),
        }
    }

    impl Fixture {
        /// Re-mint the withdrawn note's exact tuple (backed by a new deposit) and
        /// spend it again.
        fn remint_and_respend(&self) -> Vec<BatchOp> {
            let (key, amount, blind) = self.spent;
            let (op, cm) = deposit(key, amount, blind, self.state.consumed_deposit_count);
            vec![op, withdraw(key, cm, 2)]
        }

        /// Spend the live note.
        fn spend_live(&self) -> Vec<BatchOp> {
            let (key, cm) = self.live;
            vec![withdraw(key, cm, 2)]
        }

        fn live_nullifier(&self) -> Digest {
            let (key, cm) = self.live;
            self.state.notes[&cm].nullifier::<Keccak256>(&[key; 32])
        }

        /// The manifest anchored to the honest pre-state.
        fn anchored(&self, ops: &[BatchOp]) -> BatchManifest {
            BatchManifest {
                previous_state_root: self.state.state_root(),
                batch_id: self.state.next_batch_id,
                batch_time_ms: batch_time_ms(ops),
                ordered: vec![],
                rejected: vec![],
                oracle_updates: vec![],
                matching_rule_version: 0,
                enclave_measurement: [0u8; 32],
                sequencer_pubkey_epoch: 0,
            }
        }

        /// Run `ops` on `pre` against the manifest anchored to the honest state.
        fn run(&self, pre: &DefaultState, ops: &[BatchOp]) -> Result<(), EngineError> {
            derive_roots(&mut pre.clone(), ops, &self.anchored(ops)).map(|_| ())
        }

        /// Decode a forged encoding and run `ops` on it against the anchored
        /// manifest.
        fn run_forged(&self, w: &StateWire, ops: &[BatchOp]) -> Result<(), EngineError> {
            let forged = decode(&encode(w)).expect("forgery decodes");
            self.run(&forged, ops)
        }
    }

    #[test]
    fn layout_mirror_encodes_identically() {
        let f = fixture();
        let bytes = postcard::to_allocvec(&f.state).unwrap();
        assert_eq!(encode(&to_wire(&f.state)), bytes);
    }

    #[test]
    fn honest_pre_state_refuses_the_remint_and_accepts_the_live_spend() {
        let f = fixture();
        assert_eq!(
            f.run(&f.state, &f.remint_and_respend()),
            Err(EngineError::DuplicateCommitment)
        );
        assert_eq!(f.run(&f.state, &f.spend_live()), Ok(()));
    }

    /// Any change to the nullifier log changes the root, so a pre-state with a
    /// forged log fails against the anchored manifest; a repeated entry fails to
    /// decode.
    #[test]
    fn forged_nullifier_logs_fail_the_anchored_manifest() {
        let f = fixture();
        let honest = to_wire(&f.state);
        let log = honest.nullifiers.log.clone();
        let mut forgeries: Vec<(String, Vec<Digest>)> = vec![("emptied".into(), vec![])];
        for i in 0..log.len() {
            let mut l = log.clone();
            l.remove(i);
            forgeries.push((format!("entry {i} dropped"), l));
        }
        let mut l = log.clone();
        l.push(f.live_nullifier());
        forgeries.push(("live nullifier appended".into(), l));
        let mut l = log.clone();
        l.insert(0, f.live_nullifier());
        forgeries.push(("live nullifier prepended".into(), l));
        for i in 0..log.len() - 1 {
            let mut l = log.clone();
            l.swap(i, i + 1);
            forgeries.push((format!("entries {i} and {} swapped", i + 1), l));
        }
        let mut sorted = log.clone();
        sorted.sort();
        forgeries.push(("sorted".into(), sorted));

        for (name, forged_log) in forgeries {
            let mut w = honest.clone();
            w.nullifiers.log = forged_log;
            for ops in [f.remint_and_respend(), f.spend_live()] {
                assert_eq!(
                    f.run_forged(&w, &ops),
                    Err(EngineError::ManifestMismatch),
                    "{name}"
                );
            }
        }

        let mut w = honest.clone();
        w.nullifiers.log.push(log[1]);
        assert!(
            decode(&encode(&w)).is_err(),
            "a repeated nullifier fails to decode"
        );
    }

    /// The tree's empty-subtree roots are derived from its depth, so history
    /// cannot be erased or truncated without changing the root.
    #[test]
    fn forged_tree_histories_fail_the_anchored_manifest() {
        let f = fixture();
        let honest = to_wire(&f.state);
        let leaves = honest.tree.leaves.clone();
        assert!(leaves.len() >= 5);

        let mut erased = honest.clone();
        erased.tree.leaves.clear();
        let mut erased_with_log = erased.clone();
        erased_with_log.nullifiers.log.clear();
        let mut cases = vec![
            ("leaves cleared".to_string(), erased),
            (
                "leaves and nullifier log cleared".to_string(),
                erased_with_log,
            ),
        ];
        for keep in 0..leaves.len() {
            let mut w = honest.clone();
            w.tree.leaves.truncate(keep);
            cases.push((format!("truncated to {keep} leaves"), w));
        }
        let mut w = honest.clone();
        w.tree.leaves.swap(0, 1);
        cases.push(("two leaves swapped".into(), w));
        for (name, depth) in [("depth - 1", 19u8), ("depth + 1", 21), ("depth 64", 64)] {
            assert_eq!(honest.tree.depth, 20);
            let mut w = honest.clone();
            w.tree.depth = depth;
            cases.push((name.into(), w));
        }

        for (name, w) in cases {
            for ops in [f.remint_and_respend(), f.spend_live()] {
                assert_eq!(
                    f.run_forged(&w, &ops),
                    Err(EngineError::ManifestMismatch),
                    "{name}"
                );
            }
        }
    }

    /// Tree encodings whose derived parts cannot be rebuilt fail to decode.
    #[test]
    fn malformed_tree_encodings_fail_to_decode() {
        let honest = to_wire(&fixture().state);
        let leaves = honest.tree.leaves.clone();
        let mut cases: Vec<(String, StateWire)> = Vec::new();
        for depth in [0u8, 65, 200, u8::MAX] {
            let mut w = honest.clone();
            w.tree.depth = depth;
            cases.push((format!("depth {depth}"), w));
        }
        // capacity 2^depth: depth 2 holds 4 leaves; the fixture has more
        let mut w = honest.clone();
        w.tree.depth = 2;
        cases.push(("leaves above capacity".into(), w));
        let mut w = honest.clone();
        w.tree.depth = 1;
        w.tree.leaves = vec![leaves[0], leaves[1], leaves[2]];
        cases.push(("three leaves at depth 1".into(), w));
        let mut w = honest.clone();
        w.tree.leaves.push(leaves[0]);
        cases.push(("repeated leaf appended".into(), w));
        let mut w = honest.clone();
        w.tree.leaves[2] = leaves[1];
        cases.push(("repeated leaf in place".into(), w));
        for (name, w) in cases {
            assert!(decode(&encode(&w)).is_err(), "{name}");
        }
    }

    /// Capacity is compared in `u128`, so a depth-64 tree with several leaves is
    /// within capacity: it decodes, and its root is that of the same leaves
    /// appended to a fresh depth-64 tree.
    #[test]
    fn depth_64_tree_with_several_leaves_decodes() {
        let leaves: Vec<Digest> = (1..=3u64).map(word_u64).collect();
        let mut honest = DefaultState::new(64);
        for leaf in &leaves {
            honest.tree.append(*leaf).unwrap();
        }
        let mut w = to_wire(&DefaultState::new(64));
        w.tree.leaves = leaves;
        let decoded = decode(&encode(&w)).expect("depth 64 decodes");
        assert_eq!(decoded.tree.depth(), 64);
        assert_eq!(decoded.tree.capacity(), 1u128 << 64);
        assert_eq!(decoded.tree.root(), honest.tree.root());
        assert_eq!(decoded.state_root(), honest.state_root());
    }

    /// The encoded layout round-trips, and every derived part is rebuilt: the
    /// decoded state behaves exactly like the original.
    #[test]
    fn layout_round_trips_and_rebuilds_derived_parts() {
        let f = fixture();
        let bytes = postcard::to_allocvec(&f.state).unwrap();
        let back = decode(&bytes).expect("decode");
        assert_eq!(postcard::to_allocvec(&back).unwrap(), bytes);
        assert_eq!(back.state_root(), f.state.state_root());
        assert_eq!(back.tree.root(), f.state.tree.root());
        assert_eq!(back.tree.depth(), f.state.tree.depth());
        assert_eq!(back.nullifiers.digest(), f.state.nullifiers.digest());
        assert_eq!(back.nullifiers.log(), f.state.nullifiers.log());
        let w = to_wire(&f.state);
        for leaf in &w.tree.leaves {
            assert!(back.tree.contains_leaf(leaf));
        }
        for nf in &w.nullifiers.log {
            assert!(back.nullifiers.contains(nf));
        }
        assert!(!back.nullifiers.contains(&f.live_nullifier()));
        assert_eq!(
            f.run(&back, &f.remint_and_respend()),
            Err(EngineError::DuplicateCommitment)
        );
        let mut a = f.state.clone();
        let mut b = back;
        let ops = f.spend_live();
        let ra = derive_roots(&mut a, &ops, &f.anchored(&ops)).unwrap();
        let rb = derive_roots(&mut b, &ops, &f.anchored(&ops)).unwrap();
        assert_eq!(ra, rb);
    }

    /// The canonical genesis (depth `TREE_DEPTH`, one `Market::conservative(0)`,
    /// a wind-down recipient) decodes to the same state and passes the shape
    /// check. Its root is pinned in perp-core's state tests.
    #[test]
    fn canonical_genesis_round_trips() {
        assert_eq!(TREE_DEPTH, 24);
        let mut g = DefaultState::new(TREE_DEPTH);
        g.add_market(Market::conservative(0));
        let mut recipient = [0u8; 20];
        recipient[19] = 1;
        g.set_wind_down_recipient(recipient);
        let bytes = postcard::to_allocvec(&g).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.state_root(), g.state_root());
        assert_eq!(back.wind_down_recipient, recipient);
        assert_eq!(back.validate_witness_shape(), Ok(()));
        assert_eq!(postcard::to_allocvec(&back).unwrap(), bytes);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The previous state layout, which also encoded the tree's empty-subtree
    /// roots and the nullifier index and chain. Its encoding of an empty depth-16
    /// state is pinned below.
    #[derive(Serialize)]
    struct PreviousStateWire {
        tree: (u8, Vec<Digest>, Vec<Digest>),
        nullifiers: (BTreeSet<Digest>, Digest),
        rest: PreviousRest,
    }

    #[derive(Serialize)]
    struct PreviousRest {
        notes: BTreeMap<Digest, Note>,
        markets: BTreeMap<MarketId, Market>,
        funding: BTreeMap<MarketId, FundingState>,
        positions: BTreeMap<(PubKey, MarketId), Position>,
        balances: [i128; 5],
        mode: Mode,
        next_batch_id: u64,
        next_seq: u64,
        consumed_deposit_tip: Digest,
        consumed_deposit_count: u64,
    }

    /// A state encoded in the previous layout is never decoded as that state: the
    /// bytes either fail to decode or decode to a state with a different root.
    #[test]
    fn previous_layout_does_not_decode_to_the_same_state() {
        let depth = 16u8;
        let mut empty = vec![Keccak256::hash_words(Domain::MerkleEmpty, &[[0u8; 32]])];
        for i in 0..depth as usize {
            let lower = empty[i];
            empty.push(Keccak256::compress(Domain::MerkleNode, &lower, &lower));
        }
        let previous = PreviousStateWire {
            tree: (depth, vec![], empty),
            nullifiers: (BTreeSet::new(), [0u8; 32]),
            rest: PreviousRest {
                notes: BTreeMap::new(),
                markets: BTreeMap::new(),
                funding: BTreeMap::new(),
                positions: BTreeMap::new(),
                balances: [0; 5],
                mode: Mode::Normal,
                next_batch_id: 0,
                next_seq: 0,
                consumed_deposit_tip: [0u8; 32],
                consumed_deposit_count: 0,
            },
        };
        let bytes = postcard::to_allocvec(&previous).unwrap();
        assert_eq!(bytes.len(), 625);
        assert_eq!(
            hex(&perp_core::clock::keccak(&bytes)),
            "4fc7c794fe978a764d294880b49bf796d462d0b9bccada04f2373a8ebb827222",
            "the previous layout's pinned encoding of an empty depth-16 state"
        );
        let original = DefaultState::new(depth).state_root();
        match decode(&bytes) {
            Err(()) => {}
            Ok(s) => assert_ne!(s.state_root(), original),
        }
    }

    // ----- structure-aware malleability property ------------------------------

    /// xorshift64*: a deterministic generator, so the property is reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn digest(&mut self) -> Digest {
            let mut d = [0u8; 32];
            for chunk in d.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes());
            }
            d
        }
        fn i128(&mut self) -> i128 {
            match self.below(4) {
                0 => 0,
                1 => 1,
                2 => -1,
                _ => ((self.next() as i128) << 32) ^ self.next() as i128,
            }
        }
    }

    fn mutate_list(v: &mut Vec<Digest>, rng: &mut Rng) {
        let n = v.len();
        match rng.below(8) {
            0 => v.clear(),
            1 if n > 0 => {
                v.pop();
            }
            2 if n > 0 => {
                v.remove(rng.below(n));
            }
            3 if n > 1 => {
                let (i, j) = (rng.below(n), rng.below(n));
                v.swap(i, j);
            }
            4 if n > 0 => {
                let i = rng.below(n);
                v[i] = rng.digest();
            }
            5 if n > 0 => {
                let d = v[rng.below(n)];
                v.push(d);
            }
            6 => {
                let i = rng.below(n + 1);
                v.insert(i, rng.digest());
            }
            _ => v.push(rng.digest()),
        }
    }

    fn pick_key<K: Clone + Ord, V>(m: &BTreeMap<K, V>, rng: &mut Rng) -> Option<K> {
        if m.is_empty() {
            return None;
        }
        m.keys().nth(rng.below(m.len())).cloned()
    }

    fn mutate_market(m: &mut Market, rng: &mut Rng) {
        let v = rng.i128();
        match rng.below(13) {
            0 => m.id = rng.next() % 4,
            1 => m.initial_margin_ratio = v,
            2 => m.maintenance_margin_ratio = v,
            3 => m.liquidation_fee_ratio = v,
            4 => m.max_oracle_staleness_ms = rng.next(),
            5 => m.max_oracle_confidence_ratio = v,
            6 => m.max_oracle_deviation_ratio = v,
            7 => m.taker_fee_ratio = v,
            8 => m.maker_rebate_ratio = v,
            9 => m.treasury_fee_ratio = v,
            10 => m.oracle_pubkey[rng.below(20)] ^= 1 << rng.below(8),
            11 => m.max_mark_deviation_ratio = v,
            _ => m.max_fill_deviation_ratio = v,
        }
    }

    fn mutate_position(p: &mut Position, rng: &mut Rng) {
        let v = rng.i128();
        match rng.below(6) {
            0 => p.owner = owner(1 + rng.next() % 6),
            1 => p.market_id = rng.next() % 4,
            2 => p.size = v,
            3 => p.entry_price = v,
            4 => p.collateral = v,
            _ => p.funding_entry = v,
        }
    }

    fn mutate_note(n: &mut Note, rng: &mut Rng) {
        match rng.below(4) {
            0 => n.owner = owner(1 + rng.next() % 6),
            1 => n.asset_id = rng.next() % 3,
            2 => n.amount = rng.i128(),
            _ => n.blinding = rng.digest(),
        }
    }

    /// Change one encoded value somewhere in the state. Returns the field's name.
    fn mutate(w: &mut StateWire, rng: &mut Rng) -> &'static str {
        match rng.below(21) {
            0 => {
                w.tree.depth = rng.next() as u8;
                "tree.depth"
            }
            1 => {
                mutate_list(&mut w.tree.leaves, rng);
                "tree.leaves"
            }
            2 => {
                mutate_list(&mut w.nullifiers.log, rng);
                "nullifiers.log"
            }
            3 => {
                if let Some(k) = pick_key(&w.notes, rng) {
                    match rng.below(3) {
                        0 => {
                            w.notes.remove(&k);
                        }
                        1 => {
                            let n = w.notes.remove(&k).unwrap();
                            w.notes.insert(rng.digest(), n);
                        }
                        _ => mutate_note(w.notes.get_mut(&k).unwrap(), rng),
                    }
                } else {
                    w.notes
                        .insert(rng.digest(), Note::new(owner(1), 0, 1, rng.digest()));
                }
                "notes"
            }
            4 => {
                if let Some(k) = pick_key(&w.markets, rng) {
                    match rng.below(3) {
                        0 => {
                            w.markets.remove(&k);
                        }
                        1 => {
                            let m = w.markets.remove(&k).unwrap();
                            w.markets.insert(rng.next() % 4, m);
                        }
                        _ => mutate_market(w.markets.get_mut(&k).unwrap(), rng),
                    }
                }
                "markets"
            }
            5 => {
                let Some(k) = pick_key(&w.funding, rng) else {
                    return "funding";
                };
                let f = w.funding.get_mut(&k).unwrap();
                match rng.below(8) {
                    0 => {
                        w.funding.remove(&k);
                        "funding"
                    }
                    1 => {
                        let f = w.funding.remove(&k).unwrap();
                        w.funding.insert(rng.next() % 4, f);
                        "funding"
                    }
                    2 => {
                        f.cumulative_index = rng.i128();
                        "funding"
                    }
                    3 => {
                        f.last_update_ms = rng.next();
                        "funding"
                    }
                    4 => {
                        f.rate = rng.i128();
                        "funding.rate"
                    }
                    5 => {
                        f.remainder = rng.i128();
                        "funding.remainder"
                    }
                    6 => {
                        f.last_price = rng.i128();
                        "funding.last_price"
                    }
                    _ => {
                        f.last_price_ms = rng.next();
                        "funding.last_price_ms"
                    }
                }
            }
            6 => {
                if let Some(k) = pick_key(&w.positions, rng) {
                    match rng.below(4) {
                        0 => {
                            w.positions.remove(&k);
                        }
                        1 => {
                            let p = w.positions.remove(&k).unwrap();
                            w.positions.insert((owner(1 + rng.next() % 6), k.1), p);
                        }
                        2 => {
                            let p = w.positions.remove(&k).unwrap();
                            w.positions.insert((k.0, rng.next() % 4), p);
                        }
                        _ => mutate_position(w.positions.get_mut(&k).unwrap(), rng),
                    }
                }
                "positions"
            }
            7 => {
                w.insurance_fund = w.insurance_fund.wrapping_add(rng.i128());
                "insurance_fund"
            }
            8 => {
                w.vault_pool = w.vault_pool.wrapping_add(rng.i128());
                "vault_pool"
            }
            9 => {
                w.treasury = w.treasury.wrapping_add(rng.i128());
                "treasury"
            }
            10 => {
                w.external_in = w.external_in.wrapping_add(rng.i128());
                "external_in"
            }
            11 => {
                w.external_out = w.external_out.wrapping_add(rng.i128());
                "external_out"
            }
            12 => {
                w.mode = match w.mode {
                    Mode::Normal => Mode::CloseOnly,
                    Mode::CloseOnly => Mode::Normal,
                };
                "mode"
            }
            13 => {
                w.next_batch_id = rng.next() % 8;
                "next_batch_id"
            }
            14 => {
                w.last_withdrawal_nonce = rng.next() % 8;
                "last_withdrawal_nonce"
            }
            15 => {
                w.consumed_deposit_tip[rng.below(32)] ^= 1 << rng.below(8);
                "consumed_deposit_tip"
            }
            16 => {
                w.consumed_deposit_count = rng.next() % 8;
                "consumed_deposit_count"
            }
            17 => {
                // a new position under a fresh key
                let o = owner(6);
                let mut p = Position::empty(o, 0);
                p.collateral = rng.i128();
                w.positions.insert((o, 0), p);
                "positions (inserted)"
            }
            18 => {
                // a new market with its funding entry, as add_market would create
                let id = 2 + rng.next() % 2;
                w.markets.insert(id, Market::conservative(id));
                w.funding.insert(id, FundingState::default());
                "markets (inserted)"
            }
            19 => {
                w.wind_down_recipient[rng.below(20)] ^= 1 << rng.below(8);
                "wind_down_recipient"
            }
            _ => {
                let (a, b) = (rng.next() % 4, rng.next() % 4);
                if let Some(fa) = w.funding.get(&a).copied() {
                    w.funding.insert(b, fa);
                }
                "funding (copied)"
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Unchanged,
        DecodeError,
        ShapeError,
        DifferentRoot,
        Accepted,
    }

    fn outcome(honest: &[u8], root: &Digest, w: &StateWire) -> Outcome {
        let bytes = encode(w);
        if bytes == honest {
            return Outcome::Unchanged;
        }
        let Ok(s) = decode(&bytes) else {
            return Outcome::DecodeError;
        };
        if s.validate_witness_shape().is_err() {
            Outcome::ShapeError
        } else if s.state_root() != *root {
            Outcome::DifferentRoot
        } else {
            Outcome::Accepted
        }
    }

    /// Changing any encoded value — one at a time or several together — gives a
    /// decode error, a shape error, or a different root. Never the anchored root.
    #[test]
    fn every_encoded_field_is_bound() {
        let f = fixture();
        let honest_bytes = postcard::to_allocvec(&f.state).unwrap();
        let root = f.state.state_root();
        let honest = to_wire(&f.state);
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut seen: BTreeMap<&'static str, [usize; 3]> = BTreeMap::new();
        for round in 0..6_000 {
            let mut w = honest.clone();
            let mut fields = Vec::new();
            for _ in 0..1 + (round % 3) {
                fields.push(mutate(&mut w, &mut rng));
            }
            let o = outcome(&honest_bytes, &root, &w);
            assert_ne!(o, Outcome::Accepted, "round {round}: {fields:?}");
            if fields.len() == 1 {
                let slot = match o {
                    Outcome::DecodeError => Some(0),
                    Outcome::ShapeError => Some(1),
                    Outcome::DifferentRoot => Some(2),
                    _ => None,
                };
                if let Some(i) = slot {
                    seen.entry(fields[0]).or_default()[i] += 1;
                }
            }
        }
        // every mutator was exercised, and each refusal class occurred
        assert_eq!(seen.len(), 25, "{seen:?}");
        for i in 0..3 {
            assert!(
                seen.values().any(|c| c[i] > 0),
                "class {i} never seen: {seen:?}"
            );
        }
        // the fields the root does not hash are caught by the shape check
        for field in ["markets", "positions"] {
            assert!(seen[field][1] > 0, "{field}: {:?}", seen[field]);
        }
        // an out-of-range funding value fails the shape check; an in-range one
        // moves the root
        for field in ["funding.rate", "funding.remainder", "funding.last_price"] {
            let c = seen[field];
            assert!(c[1] > 0 && c[2] > 0, "{field}: {c:?}");
        }
        assert!(seen["funding.last_price_ms"][1] > 0);
        assert!(seen["wind_down_recipient"][2] > 0);
    }
}
