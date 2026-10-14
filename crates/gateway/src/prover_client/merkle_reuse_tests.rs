//! Differential tests against the exact PR69 prepare/prove functions.
//! Only function identifiers in the literal baseline copy are renamed.
use super::*;
use perp_core::clock::{ClockContext, TimeBounds};
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn baseline_prepare_unproved(
    witness: &WindowWitness,
    ww: &[Withdrawal],
) -> Result<PreparedSettle, String> {
    baseline_prepare_unproved_with_roots(witness, ww).map(|(prepared, _)| prepared)
}

fn baseline_prepare_unproved_with_roots(
    witness: &WindowWitness,
    ww: &[Withdrawal],
) -> Result<(PreparedSettle, DerivedRoots), String> {
    let mut post = witness.pre_state.clone();
    if witness.batch_id != witness.manifest.batch_id {
        return Err("local replay failed: ManifestMismatch (witness batch differs)".into());
    }
    let d = derive_roots(&mut post, &witness.ops, &witness.manifest)
        .map_err(|e| format!("local replay failed: {e:?}"))?;
    let outcome = ProveOutcome {
        prev_root: d.prev_state_root,
        manifest_hash: d.manifest_hash,
        new_root: d.new_state_root,
        ordered_root: d.ordered_root,
        withdrawals_root: d.withdrawals_root,
        rejected_root: d.rejected_root,
        deposits_root: d.deposits_root,
        wind_down_phase: d.wind_down_phase,
        new_deposit_count: post.consumed_deposit_count,
        post_mode_is_normal: post.mode == perp_core::Mode::Normal,
        post_insurance_fund: post.insurance_fund,
        commitment: d.commitment::<Keccak256>(),
        proof: Vec::new(),
    };
    let leaves: Vec<Digest> = ww.iter().map(|w| w.leaf()).collect();
    if merkle_root(&leaves) != outcome.withdrawals_root {
        return Err("withdrawals root mismatch: gateway tree vs derived".into());
    }
    let withdraw_proofs = ww
        .iter()
        .enumerate()
        .map(|(i, w)| {
            (
                w.leaf(),
                (outcome.withdrawals_root, merkle_proof(&leaves, i)),
            )
        })
        .collect();
    Ok((
        PreparedSettle {
            outcome,
            withdraw_proofs,
        },
        d,
    ))
}

pub fn baseline_prove_and_prepare(
    client: &dyn ProverClient,
    witness: &WindowWitness,
    ww: &[Withdrawal],
) -> Result<PreparedSettle, String> {
    let (mut prepared, roots) = baseline_prepare_unproved_with_roots(witness, ww)?;
    let o = &prepared.outcome;
    let clock = client
        .clock_context(witness)
        .map_err(|e| format!("clock preparation: {e:?}"))?;
    if client.clock_enabled() && clock.is_none() {
        return Err("clock-required client omitted context".into());
    }
    let expected = match &clock {
        Some(c) => {
            c.validate(witness.batch_id, &roots, &witness.ops)
                .map_err(|e| format!("clock context: {e:?}"))?;
            c.commitment()
        }
        None => o.commitment,
    };
    let remote = match &clock {
        Some(c) => client.prove_clocked(witness, c),
        None => client.prove(witness),
    }
    .map_err(|e| format!("prove: {e:?}"))?;
    if remote.commitment != expected {
        let mut which = Vec::new();
        for (name, ours, theirs) in [
            ("prev_root", o.prev_root, remote.roots.prev_root),
            ("manifest_hash", o.manifest_hash, remote.roots.manifest_hash),
            ("new_root", o.new_root, remote.roots.new_root),
            ("ordered_root", o.ordered_root, remote.roots.ordered_root),
            (
                "withdrawals_root",
                o.withdrawals_root,
                remote.roots.withdrawals_root,
            ),
            ("rejected_root", o.rejected_root, remote.roots.rejected_root),
            ("deposits_root", o.deposits_root, remote.roots.deposits_root),
        ] {
            if theirs.is_some_and(|t| t != ours) {
                which.push(name);
            }
        }
        return Err(format!(
            "commitment mismatch: {}",
            if which.is_empty() {
                "no itemised prover root differs (roots absent or all matching ours)".into()
            } else {
                which.join(", ")
            }
        ));
    }
    if remote.proof.is_empty() {
        return Err("prover returned an empty proof".into());
    }
    // The journal retains the base transition commitment. The configured on-chain
    // adapter recomputes the bound digest from its immutable registered receipt.
    prepared.outcome.proof = if let Some(c) = clock {
        let mut envelope = perp_core::clock::PROOF_MAGIC.to_vec();
        envelope.extend_from_slice(&c.receipt());
        envelope.extend(remote.proof);
        envelope
    } else {
        remote.proof
    };
    Ok(prepared)
}

fn bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).unwrap()
}

#[test]
fn cached_levels_match_all_native_paths_across_odd_and_power_of_two_boundaries() {
    for count in (0..=65).chain([95, 96, 97, 127, 128, 129, 159, 160, 161, 255, 256, 257]) {
        for pattern in 0..3 {
            let leaves: Vec<Digest> = (0..count)
                .map(|index| {
                    let mut leaf = [0xa7; 32];
                    let value = match pattern {
                        0 => index,
                        1 => index % 3,
                        _ => 0,
                    };
                    leaf[..8].copy_from_slice(&(value as u64).to_be_bytes());
                    leaf
                })
                .collect();
            let before = leaves.clone();
            let tree = ClaimTree::new(&leaves);
            assert_eq!(
                tree.root(),
                merkle_root(&leaves),
                "count={count} pattern={pattern}"
            );
            let mut old_map = BTreeMap::new();
            let mut new_map = BTreeMap::new();
            for (index, leaf) in leaves.iter().enumerate() {
                let old = merkle_proof(&leaves, index);
                let new = tree.proof(index);
                assert_eq!(new, old, "count={count} index={index} pattern={pattern}");
                assert!(perp_core::merkle::verify(tree.root(), *leaf, &new));
                old_map.insert(*leaf, (tree.root(), old));
                new_map.insert(*leaf, (tree.root(), new));
            }
            // Repeated leaves retain BTreeMap's original last-insert-wins behavior.
            assert_eq!(bytes(&old_map), bytes(&new_map));
            assert_eq!(leaves, before);
        }
    }
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    Context,
    MissingContext,
    BadClock,
    Transport,
    Empty,
    WrongCommitment,
    DiagnosticOnly,
}

struct Client {
    prepared: PreparedSettle,
    input: Vec<u8>,
    clock: ClockContext,
    clocked: bool,
    fault: Fault,
    calls: [AtomicUsize; 3],
}
impl Client {
    fn new(w: &WindowWitness, ww: &[Withdrawal], clocked: bool, fault: Fault) -> Self {
        let prepared = baseline_prepare_unproved(w, ww).unwrap();
        let bounds = TimeBounds::derive(&w.ops).unwrap();
        let o = &prepared.outcome;
        let clock = ClockContext {
            chain_id: 84532,
            verifier: [1; 20],
            settlement: [2; 20],
            batch_id: w.batch_id,
            previous_root: o.prev_root,
            base_commitment: o.commitment,
            phase: o.wind_down_phase,
            first_ms: bounds.first_ms,
            last_ms: bounds.last_ms,
            timed_ops: bounds.count,
            anchored_at_ms: bounds.last_ms,
            max_window_ms: 60_000,
            clock_skew_ms: 2_000,
        };
        Self {
            prepared,
            input: bytes(w),
            clock,
            clocked,
            fault,
            calls: std::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }
    fn counts(&self) -> [usize; 3] {
        self.calls.each_ref().map(|c| c.load(Ordering::Relaxed))
    }
    fn response(&self) -> Result<RemoteProveResp, ProverClientError> {
        if matches!(self.fault, Fault::Transport) {
            return Err(ProverClientError::Http("fixed transport".into()));
        }
        let o = &self.prepared.outcome;
        let mut commitment = if self.clocked {
            self.clock.commitment()
        } else {
            o.commitment
        };
        if matches!(self.fault, Fault::WrongCommitment) {
            commitment[0] ^= 1;
        }
        let mut roots = RemoteRoots {
            prev_root: Some(o.prev_root),
            manifest_hash: Some(o.manifest_hash),
            new_root: Some(o.new_root),
            ordered_root: Some(o.ordered_root),
            withdrawals_root: Some(o.withdrawals_root),
            rejected_root: Some(o.rejected_root),
            deposits_root: Some(o.deposits_root),
        };
        if matches!(self.fault, Fault::DiagnosticOnly) {
            roots.new_root = Some([0x99; 32]);
        }
        Ok(RemoteProveResp {
            roots,
            commitment,
            proof: if matches!(self.fault, Fault::Empty) {
                Vec::new()
            } else {
                vec![0x6a; 32]
            },
        })
    }
}
impl ProverClient for Client {
    fn clock_enabled(&self) -> bool {
        self.clocked
    }
    fn clock_context(&self, w: &WindowWitness) -> Result<Option<ClockContext>, ProverClientError> {
        assert_eq!(bytes(w), self.input);
        self.calls[0].fetch_add(1, Ordering::Relaxed);
        if matches!(self.fault, Fault::Context) {
            return Err(ProverClientError::Unauthorized);
        }
        if matches!(self.fault, Fault::MissingContext) || !self.clocked {
            return Ok(None);
        }
        let mut clock = self.clock;
        if matches!(self.fault, Fault::BadClock) {
            clock.timed_ops += 1;
        }
        Ok(Some(clock))
    }
    fn prove(&self, w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
        assert!(!self.clocked);
        assert_eq!(bytes(w), self.input);
        self.calls[1].fetch_add(1, Ordering::Relaxed);
        self.response()
    }
    fn prove_clocked(
        &self,
        w: &WindowWitness,
        clock: &ClockContext,
    ) -> Result<RemoteProveResp, ProverClientError> {
        assert!(self.clocked);
        assert_eq!(bytes(w), self.input);
        assert_eq!(*clock, self.clock);
        self.calls[2].fetch_add(1, Ordering::Relaxed);
        self.response()
    }
}

fn compare(
    w: &WindowWitness,
    ww: &[Withdrawal],
    old: &Client,
    new: &Client,
    counts: [usize; 3],
) -> Result<PreparedSettle, String> {
    let original = bytes(&(w, ww));
    let expected = baseline_prove_and_prepare(old, w, ww);
    let actual = prove_and_prepare(new, w, ww);
    match (&expected, &actual) {
        (Ok(a), Ok(b)) => assert_eq!(bytes(a), bytes(b)),
        (Err(a), Err(b)) => assert_eq!(a, b, "exact error and precedence"),
        _ => panic!("baseline/current acceptance differs: {expected:?} / {actual:?}"),
    }
    assert_eq!(old.counts(), counts);
    assert_eq!(new.counts(), counts);
    assert_eq!(bytes(&(w, ww)), original);
    actual
}

#[test]
fn finite_native_prepared_wire_and_journal_bytes_match_immediate_baseline() {
    use crate::rollback_journal::{OpenedJournal, RollbackJournal};
    for case in 0..3 {
        let (w, ww) = finite_profile_tests::native_fixture(case);
        let intent = baseline_prepare_unproved(&w, &ww).unwrap();
        assert_eq!(bytes(&prepare_unproved(&w, &ww).unwrap()), bytes(&intent));
        for clocked in [false, true] {
            for fault in [Fault::None, Fault::DiagnosticOnly] {
                let old = Client::new(&w, &ww, clocked, fault);
                let new = Client::new(&w, &ww, clocked, fault);
                let actual = compare(
                    &w,
                    &ww,
                    &old,
                    &new,
                    if clocked { [1, 0, 1] } else { [1, 1, 0] },
                )
                .unwrap();
                let expected =
                    baseline_prove_and_prepare(&Client::new(&w, &ww, clocked, fault), &w, &ww)
                        .unwrap();
                for withdrawal in &ww {
                    let (root, path) = &actual.withdraw_proofs[&withdrawal.leaf()];
                    assert!(perp_core::merkle::verify(*root, withdrawal.leaf(), path));
                }
                let wire = if clocked {
                    [
                        perp_core::clock::WIRE_MAGIC,
                        bytes(&(&w.pre_state, &w.ops, &w.manifest, &old.clock)).as_slice(),
                    ]
                    .concat()
                } else {
                    bytes(&(&w.pre_state, &w.ops, &w.manifest))
                };
                let root = [0x91; 32];
                let measurement = [0xab; 32];
                let sealed = prover::SealedWitness::seal(
                    &wire,
                    &prover::SoftwareSealProvider::new(root, measurement),
                    measurement,
                    seal_nonce(&root, &wire),
                )
                .unwrap();
                let expected_hex = format!(
                    "0x{}",
                    bytes(&sealed)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                );
                assert_eq!(
                    seal_witness_with_clock(
                        &w,
                        &root,
                        &measurement,
                        None,
                        clocked.then_some(&new.clock)
                    )
                    .unwrap(),
                    expected_hex
                );
                for (old_prepared, new_prepared) in [
                    (None, None),
                    (
                        Some(intent.clone()),
                        Some(prepare_unproved(&w, &ww).unwrap()),
                    ),
                    (Some(expected), Some(actual)),
                ] {
                    let old_j = RollbackJournal {
                        batch_id: w.batch_id,
                        witness: w.clone(),
                        ww: ww.clone(),
                        prepared: old_prepared,
                    };
                    let new_j = RollbackJournal {
                        batch_id: w.batch_id,
                        witness: w.clone(),
                        ww: ww.clone(),
                        prepared: new_prepared,
                    };
                    assert_eq!(bytes(&old_j), bytes(&new_j));
                    let plain = [b"DPRBJL5\0".as_slice(), bytes(&new_j).as_slice()].concat();
                    let frame = crate::snapshot::seal(&plain, &[0x44; 32]);
                    match crate::rollback_journal::open_versioned(&frame, &[0x44; 32]).unwrap() {
                        OpenedJournal::Legacy(decoded) => {
                            assert_eq!(bytes(&decoded), bytes(&old_j))
                        }
                        _ => panic!("wrong journal version"),
                    }
                }
            }
        }
        // Owner is not committed; swapping a complete sibling pair preserves
        // sorted-pair roots. Preserve both existing acceptance cases.
        for variant in 0..2 {
            let mut equivalent = ww.clone();
            if variant == 0 {
                equivalent[0].owner = [0xee; 32];
            } else {
                equivalent.swap(0, 1);
            }
            assert_eq!(
                bytes(&baseline_prepare_unproved(&w, &equivalent).unwrap()),
                bytes(&intent)
            );
            assert_eq!(
                bytes(&prepare_unproved(&w, &equivalent).unwrap()),
                bytes(&intent)
            );
        }
    }
}

#[test]
fn finite_multifault_errors_and_callbacks_match_immediate_baseline() {
    for case in 0..3 {
        let (w, ww) = finite_profile_tests::native_fixture(case);
        for variant in 0..6 {
            let mut bad_w = w.clone();
            let mut bad_ww = ww.clone();
            match variant {
                0 => bad_w.batch_id += 1,
                1 => bad_w.manifest.previous_state_root[0] ^= 1,
                2 => bad_ww[0].to[0] ^= 1,
                3 => bad_ww[0].amount += 1,
                4 => bad_ww[0].nonce += 1,
                _ => {
                    bad_ww.pop();
                }
            }
            let old = Client::new(&w, &ww, true, Fault::Context);
            let new = Client::new(&w, &ww, true, Fault::Context);
            assert!(compare(&bad_w, &bad_ww, &old, &new, [0, 0, 0]).is_err());
        }
        for fault in [
            Fault::Context,
            Fault::MissingContext,
            Fault::BadClock,
            Fault::Transport,
            Fault::Empty,
            Fault::WrongCommitment,
        ] {
            let old = Client::new(&w, &ww, true, fault);
            let new = Client::new(&w, &ww, true, fault);
            let counts = if matches!(
                fault,
                Fault::Context | Fault::MissingContext | Fault::BadClock
            ) {
                [1, 0, 0]
            } else {
                [1, 0, 1]
            };
            assert!(compare(&w, &ww, &old, &new, counts).is_err());
        }
    }
}
