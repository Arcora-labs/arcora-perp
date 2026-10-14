//! Literal pre-change replay comparators and fixed native withdrawal fixtures.
//! No gateway boot, account ingress, service, live clock, filesystem WAL, or proof.
use super::*;
use perp_core::clock::{ClockContext, TimeBounds};
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE};
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::Note;
use sequencer::Sequencer;
use std::sync::atomic::{AtomicUsize, Ordering};

// Copied from c069's prover_client.BASE.rs. Only the two function names and
// the old prove function's call to its old prepare function are substituted.
fn old_prepare_unproved(
    witness: &WindowWitness,
    ww: &[Withdrawal],
) -> Result<PreparedSettle, String> {
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
    Ok(PreparedSettle {
        outcome,
        withdraw_proofs,
    })
}

fn old_prove_and_prepare(
    client: &dyn ProverClient,
    witness: &WindowWitness,
    ww: &[Withdrawal],
) -> Result<PreparedSettle, String> {
    let mut prepared = old_prepare_unproved(witness, ww)?;
    let o = &prepared.outcome;
    let clock = client
        .clock_context(witness)
        .map_err(|e| format!("clock preparation: {e:?}"))?;
    if client.clock_enabled() && clock.is_none() {
        return Err("clock-required client omitted context".into());
    }
    let expected = match &clock {
        Some(c) => {
            let mut post = witness.pre_state.clone();
            let roots = derive_roots(&mut post, &witness.ops, &witness.manifest)
                .map_err(|e| format!("local replay: {e:?}"))?;
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

fn oracle(at: u64) -> OracleTranscript {
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let (price, confidence) = (100_000 * PRICE_SCALE, 10 * PRICE_SCALE);
    OracleTranscript {
        price,
        publish_time_ms: at,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&key, &oracle_digest(0, price, at, confidence, price)),
    }
}

fn unbind(seq: &mut Sequencer, key: u8, amount: i128, blind: u8, at: u64) -> Note {
    let owner = owner_from_spend_key::<Keccak256>(&[key; 32]);
    seq.apply(&BatchOp::Unbind {
        owner,
        market_id: 0,
        amount,
        blinding: [blind; 32],
        oracle: oracle(at),
        now_ms: at,
    })
    .unwrap();
    Note::new(owner, 0, amount, [blind; 32])
}

fn fixture() -> (WindowWitness, Vec<Withdrawal>) {
    // Actual PR65 old-source Sequencer bytes: funded positions and a real open
    // window, with fixed historical signed oracles and no new mint constructor.
    let mut seq: Sequencer = postcard::from_bytes(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/audits/2026-10-14-seal-window-ownership/baseline-export/",
        "normal-00-before_first_seal_seq.bin"
    )))
    .unwrap();
    let note = unbind(&mut seq, 1, 1_000 * QUOTE_SCALE, 0x71, 2_200);
    seq.apply(&BatchOp::FundInsurance {
        note_commitment: note.commitment::<Keccak256>(),
        spend_key: [1; 32],
    })
    .unwrap();
    let mut ww = Vec::new();
    for (key, at) in [(1, 2_300), (2, 2_400)] {
        let amount = i128::from(key) * 1_000 * QUOTE_SCALE;
        let note = unbind(&mut seq, key, amount, 0x71 + key, at);
        let to = [key; 20];
        let nonce = u64::from(key) + 64;
        seq.apply(&BatchOp::Withdraw {
            note_commitment: note.commitment::<Keccak256>(),
            spend_key: [key; 32],
            to: Some(to),
            nonce,
        })
        .unwrap();
        ww.push(Withdrawal {
            owner: note.owner,
            to,
            amount: amount as u128,
            nonce,
        });
    }
    let w = seq.seal_window();
    assert_eq!(ww.len(), 2);
    assert_eq!(w.pre_state.consumed_deposit_count, 2);
    assert_eq!(
        w.ops
            .iter()
            .filter(|o| matches!(o, BatchOp::Withdraw { to: Some(_), .. }))
            .count(),
        2
    );
    let mut post = w.pre_state.clone();
    let d = derive_roots(&mut post, &w.ops, &w.manifest).unwrap();
    assert_eq!(d.new_state_root, seq.state.state_root());
    assert_eq!(post.insurance_fund, 1_000 * QUOTE_SCALE);
    (w, ww)
}

fn clock(w: &WindowWitness, prepared: &PreparedSettle) -> ClockContext {
    let b = TimeBounds::derive(&w.ops).unwrap();
    let o = &prepared.outcome;
    assert!(b.count > 0);
    ClockContext {
        chain_id: 84532,
        verifier: [1; 20],
        settlement: [2; 20],
        batch_id: w.batch_id,
        previous_root: o.prev_root,
        base_commitment: o.commitment,
        phase: o.wind_down_phase,
        first_ms: b.first_ms,
        last_ms: b.last_ms,
        timed_ops: b.count,
        anchored_at_ms: b.last_ms,
        max_window_ms: 60_000,
        clock_skew_ms: 2_000,
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Good,
    Error,
    Empty,
    BadAbsent,
    BadAll,
    DiagnosticOnly,
}

struct Client {
    prepared: PreparedSettle,
    input: Vec<u8>,
    clock: Option<ClockContext>,
    required: bool,
    context_error: bool,
    reply: Reply,
    context_calls: AtomicUsize,
    legacy_calls: AtomicUsize,
    clocked_calls: AtomicUsize,
}

impl Client {
    fn new(w: &WindowWitness, ww: &[Withdrawal], clocked: bool) -> Self {
        let prepared = old_prepare_unproved(w, ww).unwrap();
        let context = clocked.then(|| clock(w, &prepared));
        Self {
            prepared,
            input: bytes(w),
            clock: context,
            required: clocked,
            context_error: false,
            reply: Reply::Good,
            context_calls: AtomicUsize::new(0),
            legacy_calls: AtomicUsize::new(0),
            clocked_calls: AtomicUsize::new(0),
        }
    }
    fn counts(&self) -> (usize, usize, usize) {
        (
            self.context_calls.load(Ordering::Relaxed),
            self.legacy_calls.load(Ordering::Relaxed),
            self.clocked_calls.load(Ordering::Relaxed),
        )
    }
    fn response(&self) -> Result<RemoteProveResp, ProverClientError> {
        if matches!(self.reply, Reply::Error) {
            return Err(ProverClientError::Http("fixed transport".into()));
        }
        let o = &self.prepared.outcome;
        let mut roots = RemoteRoots {
            prev_root: Some(o.prev_root),
            manifest_hash: Some(o.manifest_hash),
            new_root: Some(o.new_root),
            ordered_root: Some(o.ordered_root),
            withdrawals_root: Some(o.withdrawals_root),
            rejected_root: Some(o.rejected_root),
            deposits_root: Some(o.deposits_root),
        };
        let mut commitment = self.clock.map_or(o.commitment, |c| c.commitment());
        if matches!(self.reply, Reply::BadAbsent) {
            roots = RemoteRoots::default();
        }
        if matches!(self.reply, Reply::BadAll | Reply::DiagnosticOnly) {
            for root in [
                &mut roots.prev_root,
                &mut roots.manifest_hash,
                &mut roots.new_root,
                &mut roots.ordered_root,
                &mut roots.withdrawals_root,
                &mut roots.rejected_root,
                &mut roots.deposits_root,
            ] {
                root.as_mut().unwrap()[0] ^= 1;
            }
        }
        if matches!(self.reply, Reply::BadAbsent | Reply::BadAll) {
            commitment[0] ^= 1;
        }
        Ok(RemoteProveResp {
            roots,
            commitment,
            // Synthetic bytes: comparator and receipt envelope, never a proof claim.
            proof: if matches!(self.reply, Reply::Empty | Reply::BadAbsent | Reply::BadAll) {
                Vec::new()
            } else {
                vec![0x6a, 0x53, 0x19, 0x80]
            },
        })
    }
}

impl ProverClient for Client {
    fn clock_enabled(&self) -> bool {
        self.required
    }
    fn clock_context(&self, w: &WindowWitness) -> Result<Option<ClockContext>, ProverClientError> {
        assert_eq!(bytes(w), self.input);
        self.context_calls.fetch_add(1, Ordering::Relaxed);
        if self.context_error {
            Err(ProverClientError::Unauthorized)
        } else {
            Ok(self.clock)
        }
    }
    fn prove(&self, w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
        assert_eq!(bytes(w), self.input);
        assert!(
            self.clock.is_none(),
            "clock mode cannot downgrade to legacy"
        );
        self.legacy_calls.fetch_add(1, Ordering::Relaxed);
        self.response()
    }
    fn prove_clocked(
        &self,
        w: &WindowWitness,
        c: &ClockContext,
    ) -> Result<RemoteProveResp, ProverClientError> {
        assert_eq!(bytes(w), self.input);
        assert_eq!(Some(*c), self.clock);
        self.clocked_calls.fetch_add(1, Ordering::Relaxed);
        self.response()
    }
}

fn compare(
    w: &WindowWitness,
    ww: &[Withdrawal],
    make: impl Fn() -> Client,
    expected_calls: (usize, usize, usize),
) -> Result<PreparedSettle, String> {
    let inputs = bytes(&(w, ww));
    let old_client = make();
    let old = old_prove_and_prepare(&old_client, w, ww);
    let current_client = make();
    let current = prove_and_prepare(&current_client, w, ww);
    match (&current, &old) {
        (Ok(a), Ok(b)) => assert_eq!(bytes(a), bytes(b), "whole PreparedSettle"),
        (Err(a), Err(b)) => assert_eq!(a, b, "exact refusal and precedence"),
        _ => panic!("old/current acceptance differs: old={old:?}, current={current:?}"),
    }
    assert_eq!(old_client.counts(), expected_calls);
    assert_eq!(current_client.counts(), expected_calls);
    assert_eq!(bytes(&(w, ww)), inputs);
    current
}

#[test]
fn roots_carry_real_claim_paths_and_post_state_match_literal_prepare() {
    let (w, ww) = fixture();
    for close_only in [false, true] {
        let mut witness = w.clone();
        if close_only {
            witness.ops.push(BatchOp::EnterCloseOnly);
        }
        let original = bytes(&(&witness, &ww));
        let old = old_prepare_unproved(&witness, &ww).unwrap();
        let current = prepare_unproved(&witness, &ww).unwrap();
        assert_eq!(bytes(&current), bytes(&old));
        let o = &current.outcome;
        assert_eq!(o.new_deposit_count, 2);
        assert_eq!(o.post_mode_is_normal, !close_only);
        assert_eq!(o.post_insurance_fund, 1_000 * QUOTE_SCALE);
        assert_eq!(o.wind_down_phase, 0);
        assert!(o.proof.is_empty());
        assert_eq!(current.withdraw_proofs.len(), 2);
        for (i, withdrawal) in ww.iter().enumerate() {
            let (root, path) = &current.withdraw_proofs[&withdrawal.leaf()];
            assert_eq!(*root, o.withdrawals_root);
            assert_eq!(path, &vec![ww[1 - i].leaf()]);
            assert!(perp_core::merkle::verify(*root, withdrawal.leaf(), path));
        }
        assert_eq!(bytes(&(&witness, &ww)), original);
        for clocked in [false, true] {
            compare(
                &witness,
                &ww,
                || Client::new(&witness, &ww, clocked),
                if clocked { (1, 0, 1) } else { (1, 1, 0) },
            )
            .unwrap();
        }
    }
}

#[test]
fn roots_carry_legacy_clock_wire_receipts_and_journal_bodies_match_literal() {
    use crate::rollback_journal::{ArchiveEnvelope, ArchiveRef, OpenedJournal, RollbackJournal};
    let (w, ww) = fixture();
    let intent = old_prepare_unproved(&w, &ww).unwrap();
    let context = clock(&w, &intent);
    let env = ArchiveEnvelope {
        policy_binding: [0x31; 32],
        // Synthetic archived-record identities exercise codec order, not authenticity.
        refs: vec![ArchiveRef {
            market_id: 0,
            now_ms: 2_400,
            archive_id: chainlink_streams_client::report_archive::ArchiveId::parse(
                &"42".repeat(32),
            )
            .unwrap(),
        }],
    };
    let journal = |prepared| RollbackJournal {
        batch_id: w.batch_id,
        witness: w.clone(),
        ww: ww.clone(),
        prepared,
    };
    let initial_inputs = bytes(&(&w, &ww));
    for clocked in [false, true] {
        let client = Client::new(&w, &ww, clocked);
        let old = old_prove_and_prepare(&client, &w, &ww).unwrap();
        let current = compare(
            &w,
            &ww,
            || Client::new(&w, &ww, clocked),
            if clocked { (1, 0, 1) } else { (1, 1, 0) },
        )
        .unwrap();
        let proof = if clocked {
            [
                perp_core::clock::PROOF_MAGIC.as_slice(),
                context.receipt().as_slice(),
                &[0x6a, 0x53, 0x19, 0x80],
            ]
            .concat()
        } else {
            vec![0x6a, 0x53, 0x19, 0x80]
        };
        assert_eq!(current.outcome.proof, proof);
        assert_eq!(current.outcome.commitment, intent.outcome.commitment);
        let wire = if clocked {
            [
                perp_core::clock::WIRE_MAGIC.as_slice(),
                bytes(&(&w.pre_state, &w.ops, &w.manifest, context)).as_slice(),
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
        let expected = format!(
            "0x{}",
            bytes(&sealed)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(
            seal_witness_with_clock(&w, &root, &measurement, None, clocked.then_some(&context))
                .unwrap(),
            expected
        );
        for (old_stage, new_stage) in [
            (None, None),
            (
                Some(intent.clone()),
                Some(prepare_unproved(&w, &ww).unwrap()),
            ),
            (Some(old), Some(current)),
        ] {
            let old_journal = journal(old_stage);
            let new_journal = journal(new_stage);
            let v5 = bytes(&old_journal);
            assert_eq!(bytes(&new_journal), v5);
            let old_v6 = bytes(&(old_journal, &env));
            assert_eq!(bytes(&(&new_journal, &env)), old_v6);
            for (magic, body, candidate) in [
                (b"DPRBJL5\0".as_slice(), v5, false),
                (b"DPRBJL6\0".as_slice(), old_v6, true),
            ] {
                let plaintext = [magic, body.as_slice()].concat();
                let sealed = crate::snapshot::seal(&plaintext, &[0x44; 32]);
                let decoded =
                    crate::rollback_journal::open_versioned(&sealed, &[0x44; 32]).unwrap();
                match decoded {
                    OpenedJournal::Legacy(j) => {
                        assert!(!candidate);
                        assert_eq!(bytes(&j), bytes(&new_journal));
                    }
                    OpenedJournal::Candidate {
                        journal: j,
                        envelope,
                    } => {
                        assert!(candidate);
                        assert_eq!(bytes(&(&j, envelope)), bytes(&(&new_journal, &env)));
                    }
                }
            }
        }
    }
    assert_eq!(bytes(&(&w, &ww)), initial_inputs);
}

#[test]
fn roots_carry_local_multifault_errors_precede_all_callbacks() {
    let (w, ww) = fixture();
    for failure in 0..3 {
        let mut bad = w.clone();
        match failure {
            0 => bad.batch_id += 1,
            1 => bad.manifest.previous_state_root[0] ^= 1,
            _ => {
                let op = bad
                    .ops
                    .iter_mut()
                    .find(|o| matches!(o, BatchOp::Withdraw { .. }))
                    .unwrap();
                if let BatchOp::Withdraw { spend_key, .. } = op {
                    *spend_key = [0; 32];
                }
            }
        }
        let mut bad_ww = ww.clone();
        bad_ww[0].amount += 1;
        let expected = old_prepare_unproved(&bad, &bad_ww).unwrap_err();
        let actual = compare(
            &bad,
            &bad_ww,
            || {
                let mut client = Client::new(&w, &ww, true);
                client.context_error = true;
                client.reply = Reply::Error;
                client
            },
            (0, 0, 0),
        )
        .unwrap_err();
        assert_eq!(actual, expected);
        assert!(actual.starts_with("local replay failed:"));
    }
}

#[test]
fn roots_carry_context_errors_omission_and_invalid_binding_precede_prove() {
    let (w, ww) = fixture();
    let error = compare(
        &w,
        &ww,
        || {
            let mut c = Client::new(&w, &ww, true);
            c.context_error = true;
            c.reply = Reply::Error;
            c
        },
        (1, 0, 0),
    )
    .unwrap_err();
    assert_eq!(error, "clock preparation: Unauthorized");
    let error = compare(
        &w,
        &ww,
        || {
            let mut c = Client::new(&w, &ww, true);
            c.clock = None;
            c.reply = Reply::Error;
            c
        },
        (1, 0, 0),
    )
    .unwrap_err();
    assert_eq!(error, "clock-required client omitted context");
    for fault in 0..9 {
        let error = compare(
            &w,
            &ww,
            || {
                let mut c = Client::new(&w, &ww, true);
                let context = c.clock.as_mut().unwrap();
                match fault {
                    0 => context.batch_id += 1,
                    1 => context.previous_root[0] ^= 1,
                    2 => context.base_commitment[0] ^= 1,
                    3 => context.phase += 1,
                    4 => context.first_ms += 1,
                    5 => context.last_ms += 1,
                    6 => context.timed_ops += 1,
                    7 => context.anchored_at_ms += context.clock_skew_ms + 1,
                    _ => context.max_window_ms = 1,
                }
                c.reply = Reply::Error;
                c
            },
            (1, 0, 0),
        )
        .unwrap_err();
        assert_eq!(error, "clock context: ClockMismatch");
    }
}

#[test]
fn roots_carry_remote_errors_diagnostics_and_empty_proof_precedence_match() {
    let (w, ww) = fixture();
    for clocked in [false, true] {
        let counts = if clocked { (1, 0, 1) } else { (1, 1, 0) };
        for (reply, expected) in [
            (Reply::Error, "prove: Http(\"fixed transport\")"),
            (Reply::Empty, "prover returned an empty proof"),
            (Reply::BadAbsent, "commitment mismatch: no itemised prover root differs (roots absent or all matching ours)"),
            (Reply::BadAll, "commitment mismatch: prev_root, manifest_hash, new_root, ordered_root, withdrawals_root, rejected_root, deposits_root"),
        ] {
            assert_eq!(compare(&w, &ww, || { let mut c = Client::new(&w, &ww, clocked); c.reply = reply; c }, counts).unwrap_err(), expected);
        }
        // Wrong diagnostic roots with the correct commitment are accepted by BASE.
        compare(
            &w,
            &ww,
            || {
                let mut c = Client::new(&w, &ww, clocked);
                c.reply = Reply::DiagnosticOnly;
                c
            },
            counts,
        )
        .unwrap();
    }
}

#[test]
fn roots_carry_withdrawal_leaf_semantics_match_literal_without_tightening() {
    let (w, ww) = fixture();
    let reference = old_prepare_unproved(&w, &ww).unwrap();
    let mut reverse = ww.clone();
    reverse.reverse();
    let mut owner_only = ww.clone();
    owner_only[0].owner = [0xf2; 32];
    for equivalent in [reverse, owner_only] {
        assert_eq!(
            bytes(&prepare_unproved(&w, &equivalent).unwrap()),
            bytes(&reference)
        );
        assert_eq!(
            bytes(&old_prepare_unproved(&w, &equivalent).unwrap()),
            bytes(&reference)
        );
        compare(
            &w,
            &equivalent,
            || Client::new(&w, &equivalent, true),
            (1, 0, 1),
        )
        .unwrap();
    }
    for field in 0..4 {
        let mut bad = ww.clone();
        match field {
            0 => bad[0].to[0] ^= 1,
            1 => bad[0].amount += 1,
            2 => bad[0].nonce += 1,
            _ => {
                bad.pop();
            }
        }
        assert_eq!(
            prepare_unproved(&w, &bad).unwrap_err(),
            "withdrawals root mismatch: gateway tree vs derived"
        );
        assert_eq!(
            compare(
                &w,
                &bad,
                || {
                    let mut c = Client::new(&w, &ww, true);
                    c.context_error = true;
                    c.reply = Reply::Error;
                    c
                },
                (0, 0, 0)
            )
            .unwrap_err(),
            "withdrawals root mismatch: gateway tree vs derived"
        );
    }
}
