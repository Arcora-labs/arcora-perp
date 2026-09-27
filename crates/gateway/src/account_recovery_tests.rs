use super::*;
use crate::deposit_ingestion::Purpose;
use crate::deposit_rpc::{Block, Cursor, DepositSource, Domain as DepositDomain, Event, Page};
use k256::ecdsa::SigningKey;

fn prepared() -> (Gw, [u8; 32], PubKey, SigningKey, [u8; 20]) {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let sk = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let public = sk.verifying_key().to_encoded_point(false);
    let hash = <RawKeccak as sha3::Digest>::digest(&public.as_bytes()[1..]);
    let payer: [u8; 20] = hash[12..].try_into().unwrap();
    let (key, owner) = gw.register_account(Some(payer));
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(payer);
    (gw, key, owner, sk, payer)
}

fn signature(gw: &Gw, sk: &SigningKey, owner: &PubKey, nonce: u64) -> [u8; 65] {
    let d = digest(gw.chain_id, &gw.vault, owner, nonce);
    let (sig, recovery) = sk.sign_prehash_recoverable(&d).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = recovery.to_byte() + 27;
    wire
}

#[test]
fn a07_rotation_preserves_pending_routes_and_other_accounts() {
    let (mut gw, old, owner, sk, payer) = prepared();
    let collateral = gw
        .authorize_routed_deposit(&old, payer, 7_000_000, 1, Purpose::Collateral)
        .unwrap();
    let insurance = gw
        .authorize_routed_deposit(
            &old,
            payer,
            bootstrap::MIN_BOOTSTRAP_INSURANCE as u128,
            0,
            Purpose::InsuranceBootstrap,
        )
        .unwrap();
    let (other, _) = gw.register_account(None);
    gw.accounts.get_mut(&other).unwrap().deposit_address = Some([0x42; 20]);
    let foreign = gw
        .authorize_routed_deposit(&other, [0x42; 20], 3_000_000, 0, Purpose::Collateral)
        .unwrap();
    let foreign_route = gw.deposits.routes[&foreign].clone();
    let before_account = postcard::to_allocvec(&gw.accounts[&old]).unwrap();
    let before_seq = postcard::to_allocvec(&gw.seq).unwrap();
    let mut expected_collateral = gw.deposits.routes[&collateral].clone();
    let mut expected_insurance = gw.deposits.routes[&insurance].clone();
    let sig = signature(&gw, &sk, &owner, 0);
    let new = gw.recover_account(owner, 0, &sig).unwrap();
    expected_collateral.key = new;
    expected_insurance.key = new;
    assert!(!gw.accounts.contains_key(&old));
    assert_eq!(gw.accounts[&new].recovery_nonce, 1);
    assert_eq!(gw.deposits.routes[&collateral], expected_collateral);
    assert_eq!(gw.deposits.routes[&insurance], expected_insurance);
    assert_eq!(gw.deposits.routes[&foreign], foreign_route);
    assert_eq!(
        postcard::to_allocvec(&gw.accounts[&new]).unwrap(),
        before_account
    );
    assert_eq!(postcard::to_allocvec(&gw.seq).unwrap(), before_seq);
    gw.validate_deposit_state().unwrap();
    let snapshot = gw.snapshot_plain();
    // S1 round-3: replaying a USED authorization is always rejected — there is
    // no idempotent-retry acceptance. After an unknown outcome the client must
    // GET the recovery view and sign the CURRENT nonce (a fresh challenge).
    assert!(
        gw.recover_account(owner, 0, &sig).is_err(),
        "replay rejected"
    );
    assert_eq!(gw.snapshot_plain(), snapshot, "rejection mutates nothing");
    let sig1 = signature(&gw, &sk, &owner, 1);
    let new2 = gw.recover_account(owner, 1, &sig1).unwrap();
    assert_ne!(new2, new);
    assert_eq!(gw.accounts[&new2].recovery_nonce, 2);
    assert!(
        gw.recover_account(owner, 1, &sig1).is_err(),
        "replay of the newest authorization is also rejected"
    );
    let restored = Gw::boot_restored(&snapshot).unwrap();
    assert_eq!(restored.snapshot_plain(), snapshot);
    assert_eq!(restored.accounts[&new].recovery_nonce, 1);
    // The fixture must detect exactly the dangling reference this fixes.
    gw.deposits.routes.get_mut(&collateral).unwrap().key = old;
    assert!(gw.validate_deposit_state().is_err());
    assert!(Gw::boot_restored(&gw.snapshot_plain()).is_err());
}

struct OnePage(Page);
impl DepositSource for OnePage {
    fn fetch(&self, cursor: Cursor) -> Result<Page, crate::deposit_rpc::Error> {
        assert_eq!(cursor, self.0.start);
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn a07_rotation_preserves_ingested_receipts_prefix_and_proof_replay() {
    let (mut gw, old, owner, sk, payer) = prepared();
    let commit = gw
        .authorize_routed_deposit(&old, payer, 5_000_000, 0, Purpose::Collateral)
        .unwrap();
    let pending = gw
        .authorize_routed_deposit(&old, payer, 7_000_000, 1, Purpose::Collateral)
        .unwrap();
    let start = Cursor {
        domain: DepositDomain {
            chain: gw.chain_id,
            vault: gw.vault,
        },
        count: gw.seq.state.consumed_deposit_count,
        tip: gw.seq.state.consumed_deposit_tip,
        anchor: None,
    };
    let block = Block {
        number: 1,
        hash: [7; 32],
    };
    let event = Event {
        id: start.count,
        from: payer,
        commit,
        amount: 5_000_000,
        tip: perp_core::merkle::deposit_chain_fold(
            &start.tip,
            &perp_core::merkle::deposit_leaf(&payer, &commit, 5_000_000, start.count),
        ),
        tx: [9; 32],
        tx_index: 0,
        log_index: 0,
        block: block.clone(),
    };
    let mut app = crate::tests::test_app();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
    let state = Arc::get_mut(&mut app).unwrap();
    state.gw = Mutex::new(gw);
    state.snapshot_req = Some(tx);
    state.deposit_source = Some(Arc::new(OnePage(Page {
        start,
        end: block,
        events: vec![event.clone()],
    })));
    let job = tokio::spawn({
        let app = app.clone();
        async move { crate::deposit_ingestion::ingest_once(&app).await }
    });
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap()
        .send(true)
        .unwrap();
    assert_eq!(job.await.unwrap().unwrap(), 1);
    let mut gw = app.gw.lock().await;
    let before_seq = postcard::to_allocvec(&gw.seq).unwrap();
    let mut receipt = gw.deposits.credits[&event.id].clone();
    let sig = signature(&gw, &sk, &owner, 0);
    let new = gw.recover_account(owner, 0, &sig).unwrap();
    receipt.route.key = new;
    assert_eq!(gw.deposits.credits.len(), 1);
    assert_eq!(gw.deposits.credits[&event.id], receipt);
    assert_eq!(gw.deposits.routes[&pending].key, new);
    assert_eq!(postcard::to_allocvec(&gw.seq).unwrap(), before_seq);
    gw.validate_deposit_state().unwrap();
    let snapshot = gw.snapshot_plain();
    let restored = Gw::boot_restored(&snapshot).unwrap();
    assert_eq!(restored.snapshot_plain(), snapshot);
    assert_eq!(restored.seq.state.consumed_deposit_count, event.id + 1);
    assert_eq!(restored.seq.state.consumed_deposit_tip, event.tip);
    let witness = gw.seq.seal_window();
    let roots = perp_core::commitment::derive_roots(
        &mut witness.pre_state.clone(),
        &witness.ops,
        &witness.manifest,
    )
    .unwrap();
    assert_eq!(roots.new_state_root, gw.seq.state.state_root());
    assert_eq!(roots.deposits_root, event.tip);
}

fn local_sign(sk: &SigningKey, digest: &[u8; 32]) -> [u8; 65] {
    let (sig, recovery) = sk.sign_prehash_recoverable(digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = recovery.to_byte() + 27;
    wire
}

fn local_address(sk: &SigningKey) -> [u8; 20] {
    let public = sk.verifying_key().to_encoded_point(false);
    let hash = <RawKeccak as sha3::Digest>::digest(&public.as_bytes()[1..]);
    hash[12..].try_into().unwrap()
}

#[test]
fn local_rebind_nonce_exhaustion_rejects_before_any_mutation() {
    let (mut gw, key, owner, old_sk, old_address) = prepared();
    let new_sk = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let new_address = local_address(&new_sk);
    gw.accounts.get_mut(&key).unwrap().rebind_counter = u64::MAX;
    let proof = local_sign(&new_sk, &deposit_bind_digest(&owner, &new_address));
    let authorization = local_sign(
        &old_sk,
        &rebind_auth_digest(
            gw.chain_id,
            &gw.vault,
            &owner,
            u64::MAX,
            &old_address,
            &new_address,
        ),
    );
    let before = gw.snapshot_plain();
    assert!(gw
        .account_set_deposit_address(&key, new_address, &proof, Some(&authorization))
        .is_err());
    assert_eq!(
        gw.snapshot_plain(),
        before,
        "exhausted rebind must not partially change its authorizer"
    );
}

#[test]
fn local_recovery_authority_and_domain_matrix_preserves_rejected_state() {
    let (base, key, owner, signer_sk, _) = prepared();
    let bound_sk = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let foreign_sk = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
    for caller_signed in [false, true] {
        let mut gw = Gw::boot_restored(&base.snapshot_plain()).unwrap();
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(local_address(&bound_sk));
        if !caller_signed {
            gw.accounts.get_mut(&key).unwrap().signer = None;
        }
        let authorizer = if caller_signed { &signer_sk } else { &bound_sk };
        let non_authorizer = if caller_signed { &bound_sk } else { &signer_sk };
        let valid = digest(gw.chain_id, &gw.vault, &owner, 0);
        let invalid = [
            ("other_authority", local_sign(non_authorizer, &valid)),
            ("unrelated_signer", local_sign(&foreign_sk, &valid)),
            (
                "wrong_chain",
                local_sign(authorizer, &digest(gw.chain_id ^ 1, &gw.vault, &owner, 0)),
            ),
            (
                "wrong_vault",
                local_sign(authorizer, &digest(gw.chain_id, &[0x99; 20], &owner, 0)),
            ),
            (
                "wrong_owner",
                local_sign(authorizer, &digest(gw.chain_id, &gw.vault, &[0x99; 32], 0)),
            ),
            (
                "wrong_nonce",
                local_sign(authorizer, &digest(gw.chain_id, &gw.vault, &owner, 1)),
            ),
            ("malformed_signature", [0; 65]),
        ];
        for (label, sig) in invalid {
            let before = gw.snapshot_plain();
            assert!(
                gw.recover_account(owner, 0, &sig).is_err(),
                "accepted {label}, caller_signed={caller_signed}"
            );
            assert_eq!(gw.snapshot_plain(), before, "rejection mutated {label}");
        }
        let signature = local_sign(authorizer, &valid);
        let rotated = gw.recover_account(owner, 0, &signature).unwrap();
        assert!(!gw.accounts.contains_key(&key));
        assert_eq!(gw.accounts[&rotated].recovery_nonce, 1);
        let before = gw.snapshot_plain();
        assert!(gw.recover_account(owner, 0, &signature).is_err());
        assert_eq!(gw.snapshot_plain(), before, "replay changed state");
        let restored = Gw::boot_restored(&before).unwrap();
        assert_eq!(restored.snapshot_plain(), before);
        assert_eq!(
            restored.recovery_view(&owner).unwrap()["authorizer"],
            hex0x(&local_address(authorizer))
        );
    }
}
