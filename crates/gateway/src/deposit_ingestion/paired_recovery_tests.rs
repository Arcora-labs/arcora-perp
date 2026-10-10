//! Synthetic, public test fixtures only. Recovery uses the real snapshot, journal,
//! ingestion and boot decision code; L1 observations and proof are explicitly fake.
use super::*;
use crate::{
    recovery_checkpoint::JournalPolicy,
    rollback_journal::{self, RollbackJournal},
    snapshot,
};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
const TEST_SEED: [u8; 32] = [0x65; 32];

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("arcora-pair-state-{suffix}"));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn permit(gw: &mut Gw, amount: u128, signer: Option<[u8; 20]>) -> ([u8; 32], [u8; 32]) {
    let (key, _) = gw.register_account(signer);
    let from = signer.unwrap_or([0x42; 20]);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(from);
    let commit = gw
        .authorize_routed_deposit(&key, from, amount, 0, Purpose::Collateral)
        .unwrap();
    (key, commit)
}
fn page(gw: &Gw, commits: &[[u8; 32]]) -> Page {
    let start = gw.deposit_cursor();
    let mut tip = start.tip;
    let height = start.anchor.as_ref().map_or(1, |a| a.number + 1);
    let block = Block {
        number: height,
        hash: [height as u8; 32],
    };
    let events = commits
        .iter()
        .enumerate()
        .map(|(offset, commit)| {
            let route = &gw.deposits.routes[commit];
            let id = start.count + offset as u64;
            tip = perp_core::merkle::deposit_chain_fold(
                &tip,
                &perp_core::merkle::deposit_leaf(&route.from, commit, route.amount, id),
            );
            Event {
                id,
                from: route.from,
                commit: *commit,
                amount: route.amount,
                tip,
                tx: [9; 32],
                tx_index: 0,
                log_index: offset as u64,
                block: block.clone(),
            }
        })
        .collect();
    Page {
        start,
        end: block,
        events,
    }
}
fn cursor_json(gw: &Gw) -> serde_json::Value {
    let cursor = gw.deposit_cursor();
    serde_json::json!({"chain":cursor.domain.chain, "vault":format!("0x{}", cursor.domain.vault.iter().map(|b| format!("{b:02x}")).collect::<String>()),
        "count":cursor.count, "tip":crate::hex32(&cursor.tip), "anchor":cursor.anchor})
}

fn create_fixture(directory: &Path) -> serde_json::Value {
    std::fs::create_dir(directory).unwrap();
    let state = directory.join("state.snapshot");
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let sk = k256::ecdsa::SigningKey::from_slice(&[0x63; 32]).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    let hash = sha3::Keccak256::digest(&point.as_bytes()[1..]);
    let mut signer = [0; 20];
    signer.copy_from_slice(&hash[12..]);
    let (key, first) = permit(&mut gw, 20_000_000, Some(signer));
    let (_, second) = permit(&mut gw, 7_000_000, None);
    assert_eq!(
        gw.apply_deposit_page(page(&gw, &[first, second])).unwrap(),
        2
    );
    // Exercise a real signed withdrawal and retain the drained claim leaf.
    let owner = gw.accounts[&key].wallet.owner;
    let digest =
        crate::withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000_000, &[0x71; 20], 1);
    let (signature, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut wire = [0; 65];
    wire[..64].copy_from_slice(&signature.to_bytes());
    wire[64] = 27 + recid.to_byte();
    // The normal production writer's ACK is modeled by an actual file persist;
    // this fixture has no live RPC source, remote attestation or admission service.
    crate::persist_recovery(&gw, &state, &TEST_SEED).unwrap();
    gw.deposits.dirty = false;
    gw.account_withdraw(&key, 0, 5_000_000, [0x71; 20], 1, &wire)
        .unwrap();
    let batch_id = gw.seq.state.next_batch_id;
    let (witness, ww) = gw.begin_window_settle(batch_id).unwrap().unwrap();
    assert_eq!(ww.len(), 1);
    let journal = RollbackJournal {
        batch_id,
        witness,
        ww,
        prepared: None,
    };
    // A third L1 deposit is received while the first window is in flight.
    let (_, third) = permit(&mut gw, 11_000_000, None);
    assert_eq!(gw.apply_deposit_page(page(&gw, &[third])).unwrap(), 1);
    gw.validate_deposit_state().unwrap();
    crate::persist_recovery(&gw, &state, &TEST_SEED).unwrap();
    rollback_journal::write(
        &rollback_journal::journal_path(&state),
        &journal,
        &TEST_SEED,
    )
    .unwrap();
    let meta = serde_json::json!({"schema":"arcora-public-test-recovery/v1", "synthetic_public_fixture":true,
        "created_os":std::env::consts::OS,"created_arch":std::env::consts::ARCH,
        "snapshot_sha256":sha(&std::fs::read(&state).unwrap()),
        "journal_sha256":sha(&std::fs::read(rollback_journal::journal_path(&state)).unwrap()),
        "cursor":cursor_json(&gw),"batch_id":batch_id,
        "withdrawal_leaf":crate::hex32(&journal.ww[0].leaf()),"credit_records":3,
        "scope":"Synthetic engine/receipt data, known public test seed; never operational data or funds."});
    std::fs::write(
        directory.join("checkpoint.json"),
        serde_json::to_vec_pretty(&meta).unwrap(),
    )
    .unwrap();
    meta
}
fn load(directory: &Path, meta: &serde_json::Value) -> (Gw, RollbackJournal) {
    let path = directory.join("state.snapshot");
    let snapshot_policy =
        snapshot::RestorePolicy::parse(Some("1"), meta["snapshot_sha256"].as_str()).unwrap();
    let sealed = snapshot_policy.read_for_boot(Some(&path)).unwrap().unwrap();
    let policy = JournalPolicy::parse(
        meta["journal_sha256"].as_str(),
        meta["snapshot_sha256"].as_str(),
    )
    .unwrap();
    let journal_bytes = policy.read_for_boot(Some(&path)).unwrap().unwrap();
    let gw = Gw::boot_restored(&snapshot::open(&sealed, &TEST_SEED).unwrap()).unwrap();
    (
        gw,
        rollback_journal::open(&journal_bytes, &TEST_SEED).unwrap(),
    )
}
fn assert_cursor(gw: &Gw, meta: &serde_json::Value) {
    assert_eq!(cursor_json(gw), meta["cursor"]);
    assert_eq!(gw.deposits.credits.len(), 3);
    gw.validate_deposit_state().unwrap();
    assert!(gw.seq.state.conservation_holds());
}
fn verify_recovery(directory: &Path, meta: &serde_json::Value) {
    assert_eq!(meta["schema"], "arcora-public-test-recovery/v1");
    assert_eq!(meta["synthetic_public_fixture"], true);
    let (mut gw, journal) = load(directory, meta);
    assert_cursor(&gw, meta);
    assert_eq!(journal.ww.len(), 1);
    assert_eq!(crate::hex32(&journal.ww[0].leaf()), meta["withdrawal_leaf"]);
    // Restoring a cursor cannot by itself unlock L1 intake. Fresh canonical
    // provider verification is still required in a configured production service.
    assert!(!gw.deposits.ready);
    gw.deposits.required = true;
    assert!(gw.deposits.check_ready().is_err());
    gw.deposits.required = false;
    let immutable_ledger = postcard::to_allocvec(&gw.deposits).unwrap();
    let before = gw.snapshot_plain();
    let batch = journal.batch_id;
    assert_eq!(
        crate::apply_boot_recovery(
            &mut gw,
            journal.clone(),
            batch + 2,
            "0x00",
            0,
            trading_gate::GateObservation::Inconclusive
        ),
        crate::BootRecoveryOutcome::KeepJournal
    );
    assert_eq!(
        gw.snapshot_plain(),
        before,
        "uncertain chain cannot mutate snapshot/cursor"
    );
    let pre_root = crate::hex32(&journal.witness.pre_state.state_root());
    assert_eq!(
        crate::apply_boot_recovery(
            &mut gw,
            journal,
            batch,
            &pre_root,
            0,
            trading_gate::GateObservation::Inconclusive
        ),
        crate::BootRecoveryOutcome::DeleteJournal { mutated: true }
    );
    assert_cursor(&gw, meta);
    assert_eq!(
        postcard::to_allocvec(&gw.deposits).unwrap(),
        immutable_ledger
    );
    let recovered = Scratch::new();
    let state = recovered.0.join("restored.snapshot");
    let jp = rollback_journal::journal_path(&state);
    std::fs::copy(directory.join("state.snapshot.rollback"), &jp).unwrap();
    assert!(crate::finish_boot_recovery(
        &gw, true, &state, &jp, &TEST_SEED
    ));
    assert!(!jp.exists());
    let mut gw = Gw::boot_restored(
        &snapshot::open(&snapshot::read_file(&state).unwrap(), &TEST_SEED).unwrap(),
    )
    .unwrap();
    assert_cursor(&gw, meta);
    let (resealed, ww) = gw.begin_window_settle(batch).unwrap().unwrap();
    assert_eq!(ww.len(), 1);
    assert_eq!(crate::hex32(&ww[0].leaf()), meta["withdrawal_leaf"]);
    assert_eq!(
        resealed
            .ops
            .iter()
            .filter(|op| matches!(op, BatchOp::Deposit { .. }))
            .count(),
        3
    );
    let mut replay = resealed.pre_state.clone();
    perp_core::commitment::derive_roots(&mut replay, &resealed.ops, &resealed.manifest).unwrap();
    assert_eq!(replay.consumed_deposit_count, 3);
    assert_eq!(
        replay.consumed_deposit_tip,
        gw.seq.state.consumed_deposit_tip
    );
    let mut stale = page(&gw, &[]);
    stale.start.count = 0;
    let before = gw.snapshot_plain();
    assert!(gw.apply_deposit_page(stale).is_err());
    assert_eq!(gw.snapshot_plain(), before);
    // Separate post-broadcast shape, with the existing explicitly mock prover.
    let (mut gw, mut journal) = load(directory, meta);
    let prepared = crate::prover_client::prove_and_prepare(
        &crate::prover_client::MockProverClient,
        &journal.witness,
        &journal.ww,
    )
    .unwrap();
    let chain_root = crate::hex32(&prepared.outcome.new_root);
    journal.prepared = Some(prepared);
    assert_eq!(
        crate::apply_boot_recovery(
            &mut gw,
            journal.clone(),
            batch + 1,
            &chain_root,
            0,
            trading_gate::GateObservation::Inconclusive
        ),
        crate::BootRecoveryOutcome::DeleteJournal { mutated: true }
    );
    assert_cursor(&gw, meta);
    assert_eq!(gw.withdraw_proofs.len(), 1);
    let after = gw.snapshot_plain();
    assert_eq!(
        crate::apply_boot_recovery(
            &mut gw,
            journal,
            batch + 1,
            &chain_root,
            0,
            trading_gate::GateObservation::Inconclusive
        ),
        crate::BootRecoveryOutcome::DeleteJournal { mutated: false }
    );
    assert_eq!(
        gw.snapshot_plain(),
        after,
        "repeat recovery cannot duplicate credits or claims"
    );
}
#[test]
fn paired_recovery_preserves_deposit_cursor_and_withdrawal_across_rollback_and_forward() {
    let root = Scratch::new();
    let source = root.0.join("source");
    let meta = create_fixture(&source);
    let moved = root.0.join("moved");
    std::fs::rename(&source, &moved).unwrap();
    assert!(!source.exists());
    verify_recovery(&moved, &meta);
}
#[test]
#[ignore = "explicit export of public synthetic test data into a new directory"]
fn export_paired_recovery_fixture() {
    let path = PathBuf::from(
        std::env::var_os("ARCORA_PUBLIC_RECOVERY_EXPORT").expect("explicit new fixture directory"),
    );
    let meta = create_fixture(&path);
    verify_recovery(&path, &meta);
    println!("PAIR_EXPORT public synthetic fixture verified; no live chain or proof");
}

#[test]
fn public_macos_pair_restores_with_identical_cursor_and_recovery_semantics() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/paired-recovery");
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("checkpoint.json")).unwrap()).unwrap();
    assert_eq!(meta["created_os"], "macos");
    assert_eq!(meta["created_arch"], "aarch64");
    verify_recovery(&root, &meta);
    let report = serde_json::json!({"status":"PASS_PUBLIC_FIXTURE_PAIRED_RECOVERY", "fixture_source_os":meta["created_os"],
        "fixture_source_arch":meta["created_arch"],"execution_os":std::env::consts::OS,"execution_arch":std::env::consts::ARCH,
        "snapshot_sha256":meta["snapshot_sha256"],"journal_sha256":meta["journal_sha256"],
        "deposit_records":3,"drained_withdrawal_leaves":1,"rollback_replay_deposits":3,
        "hold_no_mutation":true,"roll_forward_claims":1,"repeat_commit_no_mutation":true,
        "stale_deposit_page_rejected":true,"fresh_l1_revalidation_still_required":true,
        "live_chain_verified":false,"new_proof_generated":false,"production_service_relocated":false,"release_gate":"HOLD"});
    if let Some(path) = std::env::var_os("ARCORA_PAIR_EVIDENCE") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(&serde_json::to_vec_pretty(&report).unwrap())
            .unwrap();
    }
    println!("PAIR_RECOVERY_VERIFIED {}", report);
}
