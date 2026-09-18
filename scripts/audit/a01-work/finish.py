from pathlib import Path
import sys
r=Path(sys.argv[1])
def edit(path, fn):
    p=r/path;p.write_text(fn(p.read_text()))

def main(s):
    s=s.replace('bootstrap_window','deposit_window')
    s=s.replace('deposit_ops, 7,','deposit_ops, 9,').replace('expected exactly 7 occurrences of `{deposit_op_needle}`','expected exactly 9 occurrences of `{deposit_op_needle}`')
    s=s.replace('constructing one; found {deposit_ops}.','constructing one; plus A01 atomic intake and its post-seal persistence pattern; found {deposit_ops}.')
    s=s.replace('let deposit_ops = count(deposit_op_needle);','assert_eq!(include_str!("deposit_ingestion.rs").matches(deposit_op_needle).count(), 1, "one prefix-verified atomic intake constructor");\n        let deposit_ops = count(deposit_op_needle);')
    s=s.replace('The scan is non-recursive because `crates/gateway/src` is flat;', 'The scan covers top-level production modules; nested A01 modules are test-only;')
    s=s.replace('// SEC-025-A Task 5: this window carries the bootstrap\'s SECOND leg, so','// A01: every deposit-bearing window and resumed bootstrap second leg needs durability;')
    s=s.replace('[l1] bootstrap window {batch_id}: post-seal snapshot','[l1] deposit window {batch_id}: post-seal snapshot')
    a=s.index('    /// Verify a confirmed `vault.deposit`') if '    /// Verify a confirmed `vault.deposit`' in s else -1
    s=s.replace('"required": ["from","amount"], "properties": { "from":','"required": ["from","amount","marketId","purpose"], "properties": { "marketId": { "type": "integer", "minimum": 0 }, "purpose": { "type": "string", "enum": ["collateral","insuranceBootstrap"], "description": "Immutable routing; insurance also requires admin authorization and the bound operator payer" }, "from":')
    s=s.replace('"summary": "Credit a real on-chain USDC deposit by tx hash"','"summary": "Optional finalized ingestion accelerator and durable receipt; cannot change routing"')
    s=s.replace('"responses": ok("credited + account")','"responses": { "200": { "description": "Owned durable credit receipt" }, "202": { "description": "pendingFinalizedIngestion; do not send funds again" }, "409": { "description": "Routing mismatch or legacy receipt" }, "503": { "description": "Ingestion unavailable or durability unknown" } }')
    i=s.index('    if !prod {',s.index('fn v1_openapi_json'))
    s=s[:i]+'''    let mut route = spec["paths"]["/v1/accounts/deposit/authorize"].clone();
    route["post"]["summary"] = serde_json::json!("Explicitly adopt a legacy permit; routing is immutable");
    let schema = &mut route["post"]["requestBody"]["content"]["application/json"]["schema"];
    schema["required"].as_array_mut().unwrap().push(serde_json::json!("ownerCommit"));
    schema["properties"]["ownerCommit"] = serde_json::json!({"type":"string"});
    route["post"]["responses"] = ok("ownerCommit + routing + durability; no new signature");
    spec["paths"]["/v1/accounts/deposit/route"] = route;
'''+s[i:]
    a=s.index('/// SEC-025-A Task 4: `POST /v1/admin/insurance/bootstrap`');b=s.index('async fn post_v1_admin_insurance_bootstrap',a)
    s=s[:a]+'''/// A01: optional operator receipt/acceleration endpoint. Payer and purpose are
/// fixed by the durable permit, never inferred from this confirm request.
'''+s[b:]
    return s
edit('crates/gateway/src/main.rs',main)
def l1(s):
    a=s.index('    /// Verify a confirmed `vault.deposit`');b=s.index('    /// Slice 3b-2a',a);s=s[:a]+s[b:]
    for name in ['parse_addr20','data_word','parse_u256_low128']:
        s=s.replace('fn '+name+'(', '#[cfg(test)]\nfn '+name+'(')
    return s
edit('crates/gateway/src/l1.rs',l1)
def rpc(s):
    s=s.replace('.chunks_exact(2)', '.as_chunks::<2>().0.iter()')
    old='let v=self.rpc.call("eth_getBlockByNumber",vec![tag,json!(false)])?;\n        Ok(Block { number:quantity(&v["number"])?, hash:digest(&v["hash"])? })'
    assert old in s
    return s.replace(old,'''let v=self.rpc.call("eth_getBlockByNumber",vec![tag.clone(),json!(false)])?;
        let block=Block { number:quantity(&v["number"])?, hash:digest(&v["hash"])? };
        if tag!=json!("finalized") && quantity(&tag)?!=block.number {
            return Err("RPC returned the wrong block height".into());
        }
        Ok(block)''')
edit('crates/gateway/src/deposit_rpc.rs',rpc)
def rpc_tests(s):
    s=s.replace('#[derive(Clone)]\nstruct MockRpc','type Requests = Arc<Mutex<Vec<(String,Vec<Value>)>>>;\n#[derive(Clone)]\nstruct MockRpc')
    s=s.replace('requests:Arc<Mutex<Vec<(String,Vec<Value>)>>>','requests:Requests')
    return s+'''
#[test]
fn a01_rpc_wrong_historical_header_number_is_rejected() {
    struct WrongHeight(MockRpc);
    impl Rpc for WrongHeight {
        fn call(&self,m:&str,p:Vec<Value>)->Result<Value,String> {
            let historical=m=="eth_getBlockByNumber" && p[0]!=json!("finalized");
            let mut v=self.0.call(m,p)?;
            if historical {v["number"]=json!("0xffff");}
            Ok(v)
        }
    }
    assert!(VaultSource::new(WrongHeight(MockRpc::default())).fetch(cursor()).is_err());
}
'''
edit('crates/gateway/src/deposit_rpc/tests.rs',rpc_tests)
def tests(s):
    s=s.replace('.chunks_exact(2)', '.as_chunks::<2>().0.iter()')
    return s+'''
#[tokio::test]
async fn a01_cancellation_at_ack_keeps_barrier_and_retry_never_recredits() {
    let mut gw=fresh();let (_,c)=permit(&mut gw,5_000_000,Purpose::Collateral,0);let p=page(&gw,&[c]);
    let (app,source,mut rx)=app_with_page(gw,p);
    let job=tokio::spawn({let app=app.clone();async move {ingest_once(&app).await}});
    let abandoned_ack=rx.recv().await.unwrap();job.abort();assert!(job.await.unwrap_err().is_cancelled());
    assert!(app.gw.lock().await.deposits.check_ready().is_err());drop(abandoned_ack);
    let job=tokio::spawn({let app=app.clone();async move {ingest_once(&app).await}});
    let ack=rx.recv().await.unwrap();assert_eq!(source.calls.load(std::sync::atomic::Ordering::SeqCst),1);
    let path=std::env::temp_dir().join(format!("a01-restart-{}",hex0x(&csprng_bytes32())));
    assert!(write_snapshot(&app,&path,[42;32],Arc::new(Mutex::new(()))).await);
    ack.send(true).unwrap();assert_eq!(job.await.unwrap().unwrap(),0);
    let plain=snapshot::open(&std::fs::read(&path).unwrap(),&[42;32]).unwrap();std::fs::remove_file(path).unwrap();
    let restored=Gw::boot_restored(&plain).unwrap();assert_eq!(restored.seq.state.consumed_deposit_count,1);
    assert_eq!(restored.deposits.credits.len(),1);assert_eq!(restored.accounts.values().next().unwrap().deposit_counter,1);
}
#[test]
fn a01_legacy_bootstrap_half_transfer_resumes_without_minting_or_user_credit() {
    let mut gw=fresh();let (key,c)=permit(&mut gw,bootstrap::MIN_BOOTSTRAP_INSURANCE as u128,Purpose::InsuranceBootstrap,0);
    let a=&gw.accounts[&key];let wallet=a.wallet;let blind=a.deposit_authorizations[&c];
    let amount=bootstrap::MIN_BOOTSTRAP_INSURANCE;let mut note_blind=[0xb0;32];note_blind[..8].copy_from_slice(&0u64.to_le_bytes());
    let note=Note::new(wallet.owner,0,amount,note_blind);
    gw.seq.apply(&BatchOp::Deposit {owner:wallet.owner,asset_id:0,amount,blinding:note_blind,
        from:[0x42;20],deposit_id:0,deposit_blind:blind}).unwrap();
    gw.bootstrap=bootstrap::Bootstrap::DepositApplied {note_commitment:note.commitment::<Keccak256>(),spend_key:wallet.spend_key,deposit_id:0};
    gw.accounts.get_mut(&key).unwrap().deposit_counter=1;
    let prices:Vec<_>=gw.mkts.iter().map(|m|(m.id,m.reference_price,m.px,m.live)).collect();
    let legacy=postcard::to_allocvec(&(&gw,prices)).unwrap();let mut gw=Gw::boot_restored(&legacy).unwrap();
    let p=Page {start:gw.deposit_cursor(),end:Block {number:1,hash:[7;32]},events:vec![]};
    gw.apply_deposit_page(p).unwrap();assert_eq!(gw.seq.state.insurance_fund,amount);
    assert_eq!(gw.seq.state.consumed_deposit_count,1);assert_eq!(gw.accounts[&key].deposit_counter,1);
    assert!(!gw.seq.state.positions.keys().any(|(owner,_)|*owner==wallet.owner));
    assert!(matches!(gw.bootstrap,bootstrap::Bootstrap::InsuranceApplied {..}));
    let mut restored=Gw::boot_restored(&gw.snapshot_plain()).unwrap();
    let p=Page {start:restored.deposit_cursor(),end:Block {number:1,hash:[7;32]},events:vec![]};
    restored.apply_deposit_page(p).unwrap();assert_eq!(restored.seq.state.insurance_fund,amount);
    let w=restored.seq.seal_window();let mut state=w.pre_state.clone();
    let roots=perp_core::commitment::derive_roots(&mut state,&w.ops,&w.manifest).unwrap();
    assert_eq!(roots.new_state_root,restored.seq.state.state_root());assert!(state.conservation_holds());
}
'''
edit('crates/gateway/src/deposit_ingestion/tests.rs',tests)
def frontend(s):
    s=s.replace('Deposit received on-chain and awaiting finalized ingestion. It will be credited automatically; do not send another deposit.','Deposit is not yet confirmed by the finalized ingester. Valid authorized deposits are credited automatically; do not send another deposit.')
    return s.replace('''   * `POST /v1/accounts/deposit/onchain` — credit a CONFIRMED on-chain
   * `vault.deposit` tx (the gateway verifies the receipt + `from`==bound EOA +
   * dedups by hash). Returns the credited amount in USDC base units.''','''   * Request a durable receipt from the autonomous finalized ingester.
   * Cannot choose a new market or consume deposits out of order.
   * A pending result is not zero credit and never means send funds again.''')
edit('frontend/src/api/realClient.ts',frontend)
def frontend_tests(s):
    s=s.replace('let authorizeStatus = 200;', 'let onchainPending = false;\nlet authorizeStatus = 200;')
    s=s.replace('  authorizeStatus = 200;', '  onchainPending = false;\n  authorizeStatus = 200;')
    s=s.replace('return json({ credited: "1000000" });','return onchainPending ? json({ status: "pendingFinalizedIngestion", credited: "0" }, 202) : json({ credited: "1000000" });')
    return s+'''
describe("A01 autonomous deposit receipts", () => {
  it("never reports pending finality as successful zero credit", async () => {
    const client = await bootstrapClient();
    onchainPending = true;
    await expect(client.creditOnchainDeposit("0x" + "11".repeat(32))).rejects.toThrow(/credited automatically; do not send another deposit/);
  });
  it("binds selected market and collateral purpose at authorization", async () => {
    const client = await bootstrapClient();
    await client.selectMarket(1);
    await client.authorizeDeposit("0x" + "22".repeat(20), 5_000_000n);
    expect(calls.find((c) => c.path === "/v1/accounts/deposit/authorize")!.body)
      .toEqual({ from: "0x" + "22".repeat(20), amount: "5000000", marketId: 1, purpose: "collateral" });
  });
});
'''
edit('frontend/src/api/realClient.test.ts',frontend_tests)
