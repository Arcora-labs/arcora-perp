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
