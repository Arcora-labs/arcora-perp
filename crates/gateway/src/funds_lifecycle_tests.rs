//! Opt-in real HTTP + local EVM funds lifecycle. The proof backend is explicitly
//! ClockBoundVerifier + MockZkVerifier: this is NOT an SP1, TEE or release gate.
//! Optional ARCORA_FUNDS_WITNESS_DIR exports exact synthetic v2 inputs for guest replay.
//! Run `forge build --root contracts`, then the ignored test below. All wallets,
//! contracts, ports and snapshots are disposable; no configured chain is used.
use super::*;
use k256::sha2::{Digest as _, Sha256};
use serde_json::{json, Value};
use std::path::{Path as FsPath, PathBuf};
use std::process::{Child, Command, Output, Stdio};

const SEED: [u8; 32] = [0x69; 32];
const ADMIN: &str = "local-funds-lifecycle-test-admin";
const CHAIN: u64 = 31337;

fn command(program: &str, args: &[&str]) -> Output {
    Command::new(program).args(args).output().unwrap()
}
fn successful(output: Output) -> String {
    assert!(
        output.status.success(),
        "subprocess failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}
fn sign(sk: &k256::ecdsa::SigningKey, digest: &[u8; 32]) -> String {
    let (sig, rec) = sk.sign_prehash_recoverable(digest).unwrap();
    let mut wire = [0; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = 27 + rec.to_byte();
    hex0x(&wire)
}
struct User {
    sk: k256::ecdsa::SigningKey,
    address: [u8; 20],
    key: String,
    owner: PubKey,
}
impl User {
    fn fixture(byte: u8) -> Self {
        let sk = k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap();
        let address = GatewaySigner::from_parts([byte; 32], CHAIN, [0; 20])
            .unwrap()
            .address();
        Self {
            sk,
            address,
            key: String::new(),
            owner: [0; 32],
        }
    }
    fn private_hex(&self) -> String {
        hex0x(&self.sk.to_bytes())
    }
}
struct Evm {
    child: Child,
    url: String,
    scratch: PathBuf,
    output: Option<std::thread::JoinHandle<()>>,
}
impl Evm {
    fn start() -> Self {
        let scratch = std::env::temp_dir().join(format!(
            "arcora-funds-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&scratch).unwrap();
        let mut child = Command::new("anvil")
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--chain-id",
                "31337",
                "--slots-in-an-epoch",
                "1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let startup_output = child.stderr.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let output = std::thread::spawn(move || {
            use std::io::BufRead as _;
            let mut reader = std::io::BufReader::new(startup_output);
            let mut line = String::new();
            let mut startup_bytes = 0;
            let mut found = false;
            while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                if !found {
                    startup_bytes += line.len();
                    if startup_bytes > 128 * 1024 {
                        return;
                    }
                    if let Some(port) = line
                        .trim()
                        .strip_prefix("Listening on 127.0.0.1:")
                        .and_then(|s| s.parse::<u16>().ok())
                        .filter(|p| *p != 0)
                    {
                        let _ = send.send(port);
                        found = true;
                    }
                }
                line.clear(); // Drain owned child's output; never print test key banners.
            }
        });
        let mut evm = Self {
            child,
            url: String::new(),
            scratch,
            output: Some(output),
        };
        let port = receive
            .recv_timeout(Duration::from_secs(10))
            .expect("owned Anvil must announce allocated port");
        assert!(
            evm.child.try_wait().unwrap().is_none(),
            "owned Anvil exited"
        );
        evm.url = format!("http://127.0.0.1:{port}");
        evm
    }
    fn cast(&self, args: &[&str]) -> Output {
        let mut all = vec![args[0], "--rpc-url", &self.url];
        all.extend_from_slice(&args[1..]);
        command("cast", &all)
    }
    fn rpc(&self, method: &str, params: &[Value]) -> Value {
        let payload = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
        let raw = successful(command(
            "curl",
            &[
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "-H",
                "content-type: application/json",
                "--data",
                &payload,
                &self.url,
            ],
        ));
        let value: Value = serde_json::from_str(&raw).unwrap();
        assert!(value.get("error").is_none(), "RPC {method}: {value}");
        value["result"].clone()
    }
    fn fund(&self, user: &User) {
        self.rpc(
            "anvil_setBalance",
            &[json!(hex0x(&user.address)), json!("0x3635c9adc5dea00000")],
        );
    }
    fn send_result(&self, user: &User, to: &str, signature: &str, args: &[String]) -> Output {
        let key = user.private_hex(); // Public, fixed test fixture; never a configured wallet.
        let mut all = vec!["send", "--json", "--private-key", &key, to, signature];
        all.extend(args.iter().map(String::as_str));
        self.cast(&all)
    }
    fn send(&self, user: &User, to: &str, signature: &str, args: &[String]) -> Value {
        let receipt: Value =
            serde_json::from_str(&successful(self.send_result(user, to, signature, args))).unwrap();
        assert_eq!(receipt["status"], "0x1", "transaction reverted");
        receipt
    }
    fn reject(&self, user: &User, to: &str, signature: &str, args: &[String]) {
        let result = self.send_result(user, to, signature, args);
        if result.status.success() {
            let receipt: Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(receipt["status"], "0x0", "invalid transaction was accepted");
        } else {
            let error = format!(
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(
                error.contains("revert"),
                "transport/tool failure is not contract rejection ({signature}): {error}"
            );
        }
    }
    fn call(&self, to: &str, signature: &str, args: &[String]) -> String {
        let mut all = vec!["call", to, signature];
        all.extend(args.iter().map(String::as_str));
        successful(self.cast(&all))
            .split_whitespace()
            .next()
            .unwrap()
            .to_string()
    }
    fn deploy(
        &self,
        user: &User,
        artifact: &str,
        constructor: Option<(&str, Vec<String>)>,
    ) -> String {
        let root = FsPath::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/out");
        let raw: Value = serde_json::from_slice(
            &std::fs::read(root.join(artifact)).expect("run forge build --root contracts first"),
        )
        .unwrap();
        let mut code = raw["bytecode"]["object"].as_str().unwrap().to_string();
        if let Some((signature, args)) = constructor {
            let mut input = vec!["abi-encode", signature];
            input.extend(args.iter().map(String::as_str));
            code.push_str(successful(command("cast", &input)).trim_start_matches("0x"));
        }
        let receipt: Value = serde_json::from_str(&successful(self.cast(&[
            "send",
            "--json",
            "--private-key",
            &user.private_hex(),
            "--create",
            &code,
        ])))
        .unwrap();
        assert_eq!(receipt["status"], "0x1");
        receipt["contractAddress"].as_str().unwrap().to_string()
    }
}
impl Drop for Evm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(output) = self.output.take() {
            let _ = output.join();
        }
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}
#[derive(Clone)]
struct Rpc(String);
impl deposit_rpc::Rpc for Rpc {
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
        let payload = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
        let output = command(
            "curl",
            &[
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "-H",
                "content-type: application/json",
                "--data",
                &payload,
                &self.0,
            ],
        );
        if !output.status.success() {
            return Err("local RPC transport failed".into());
        }
        let value: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
        if value.get("error").is_some() {
            return Err(format!("local RPC error: {}", value["error"]));
        }
        Ok(value["result"].clone())
    }
}
struct Http {
    app: Shared,
    url: String,
    state: PathBuf,
    server: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}
impl Http {
    async fn start(mut gw: Gw, evm: &Evm, vault: &str) -> Self {
        let mut app = tests::test_app();
        let inner = Arc::get_mut(&mut app).unwrap();
        gw.prod = true;
        gw.chain_id = CHAIN;
        gw.vault = parse_addr20_hex(vault).unwrap();
        gw.window_settle_mode = true;
        gw.seq.set_retain_tick_snapshots(false);
        gw.deposits.required = true;
        inner.gw = Mutex::new(gw);
        inner.gateway_signer =
            GatewaySigner::from_parts([0x33; 32], CHAIN, parse_addr20_hex(vault).unwrap()).unwrap();
        inner.deposit_source = Some(Arc::new(deposit_rpc::VaultSource::new(Rpc(evm
            .url
            .clone()))));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
        inner.snapshot_req = Some(tx);
        let state = evm.scratch.join("gateway.sealed");
        let writer_app = app.clone();
        let writer_state = state.clone();
        let writer = tokio::spawn(async move {
            while let Some(ack) = rx.recv().await {
                let result = persist_recovery(&*writer_app.gw.lock().await, &writer_state, &SEED);
                let _ = ack.send(result.is_ok());
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = build_router(app.clone(), false);
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            app,
            url,
            state,
            server,
            writer,
        }
    }
    fn request(
        &self,
        method: &str,
        path: &str,
        key: &str,
        body: Option<Value>,
        status: u16,
    ) -> Value {
        let body = body.map(|v| v.to_string());
        let auth = format!("x-api-key: {key}");
        let admin = format!("x-admin-key: {ADMIN}");
        let url = format!("{}{path}", self.url);
        let mut args = vec![
            "--silent",
            "--show-error",
            "--max-time",
            "20",
            "-X",
            method,
            "-H",
            "content-type: application/json",
            "-H",
            &auth,
            "-H",
            &admin,
            "-w",
            "\n%{http_code}",
            &url,
        ];
        if let Some(ref body) = body {
            args.extend(["--data", body]);
        }
        let raw = successful(command("curl", &args));
        let (json, code) = raw.rsplit_once('\n').unwrap();
        assert_eq!(
            code.parse::<u16>().unwrap(),
            status,
            "{method} {path}: {json}"
        );
        serde_json::from_str(json).unwrap()
    }
    fn register(&self, user: &mut User) {
        let value = self.request(
            "POST",
            "/v1/accounts",
            "",
            Some(json!({"signer":hex0x(&user.address)})),
            200,
        );
        user.key = value["apiKey"].as_str().unwrap().into();
        user.owner = parse_hex32(value["owner"].as_str().unwrap()).unwrap();
        let sig = sign(&user.sk, &deposit_bind_digest(&user.owner, &user.address));
        self.request(
            "POST",
            "/v1/accounts/deposit/address",
            &user.key,
            Some(json!({"address":hex0x(&user.address),"signature":sig})),
            200,
        );
    }
    async fn restore(&self) {
        let raw = snapshot::open(&snapshot::read_file(&self.state).unwrap(), &SEED).unwrap();
        let mut gw = Gw::boot_restored(&raw).unwrap();
        gw.prod = true;
        gw.chain_id = CHAIN;
        gw.vault = self.app.gateway_signer.vault;
        gw.window_settle_mode = true;
        gw.seq.set_retain_tick_snapshots(false);
        gw.deposits.required = true;
        *self.app.gw.lock().await = gw;
    }
    async fn order(&self, user: &User, side: Side, nonce: u64, reduce: bool) -> Value {
        let gw = self.app.gw.lock().await;
        let epoch = gw.epochs.current();
        let terms = OrderTerms {
            market_id: 0,
            side,
            size: SIZE_SCALE / 10,
            limit_price: gw.px_of(0),
            tif: TimeInForce::Gtc,
            reduce_only: reduce,
            nonce,
        };
        let order = mk_order(
            user.owner,
            0,
            side,
            terms.size,
            terms.limit_price,
            nonce,
            terms.tif,
            reduce,
        );
        let mut extra = epoch.epoch_id.to_le_bytes().to_vec();
        extra.extend_from_slice(&user.owner);
        let aad = sealed_box::domain_aad(Domain::OrderEncryptAad as u8, &extra);
        let mut eph = [0; 32];
        let mut iv = [0; 24];
        getrandom::getrandom(&mut eph).unwrap();
        getrandom::getrandom(&mut iv).unwrap();
        let sealed = sealed_box::seal_with_ephemeral(
            &epoch.public,
            &serialize_order_terms(&terms),
            &aad,
            &eph,
            &iv,
        );
        json!({"epochId":epoch.epoch_id,"sealed":hex0x(&sealed.to_bytes()),"signature":sign(&user.sk, &order.order_hash::<Keccak256>())})
    }
}
impl Drop for Http {
    fn drop(&mut self) {
        self.server.abort();
        self.writer.abort();
    }
}

struct ClockMock(perp_core::clock::ClockContext);
impl prover_client::ProverClient for ClockMock {
    fn clock_enabled(&self) -> bool {
        true
    }
    fn clock_context(
        &self,
        _: &sequencer::WindowWitness,
    ) -> Result<Option<perp_core::clock::ClockContext>, prover_client::ProverClientError> {
        Ok(Some(self.0))
    }
    fn prove(
        &self,
        _: &sequencer::WindowWitness,
    ) -> Result<prover_client::RemoteProveResp, prover_client::ProverClientError> {
        panic!("clock test must not use legacy prove")
    }
    fn prove_clocked(
        &self,
        _: &sequencer::WindowWitness,
        clock: &perp_core::clock::ClockContext,
    ) -> Result<prover_client::RemoteProveResp, prover_client::ProverClientError> {
        assert_eq!(*clock, self.0);
        Ok(prover_client::RemoteProveResp {
            roots: Default::default(),
            commitment: clock.commitment(),
            proof: clock.commitment().to_vec(),
        })
    }
}

async fn settle(
    http: &Http,
    evm: &Evm,
    operator: &User,
    settlement: &str,
    clock_verifier: &str,
    recover: bool,
) -> Value {
    let batch = evm
        .call(settlement, "batchCount()(uint64)", &[])
        .parse::<u64>()
        .unwrap();
    let jpath = rollback_journal::journal_path(&http.state);
    let mut journal = {
        let mut gw = http.app.gw.lock().await;
        let j = begin_journaled_window_settle(&mut gw, batch, Some(&jpath), &SEED)
            .unwrap()
            .unwrap();
        persist_recovery(&gw, &http.state, &SEED).unwrap();
        j
    };
    // Write the immutable unproved intent BEFORE the on-chain registration.
    journal.prepared =
        Some(prover_client::prepare_unproved(&journal.witness, &journal.ww).unwrap());
    rollback_journal::write(&jpath, &journal, &SEED).unwrap();
    let w = &journal.witness;
    let bounds = perp_core::clock::TimeBounds::derive(&w.ops).unwrap();
    let base = &journal.prepared.as_ref().unwrap().outcome;
    let registration = evm.send(
        operator,
        clock_verifier,
        "register(uint64,bytes32,bytes32,uint64,uint64,uint64,uint8)",
        &[
            batch.to_string(),
            hex0x(&base.prev_root),
            hex0x(&base.commitment),
            bounds.first_ms.to_string(),
            bounds.last_ms.to_string(),
            bounds.count.to_string(),
            "0".into(),
        ],
    );
    let block = evm.rpc(
        "eth_getBlockByHash",
        &[registration["blockHash"].clone(), json!(false)],
    );
    let anchored_at_ms = u64::from_str_radix(
        block["timestamp"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap()
        * 1000;
    let clock = perp_core::clock::ClockContext {
        chain_id: CHAIN,
        verifier: parse_addr20_hex(clock_verifier).unwrap(),
        settlement: parse_addr20_hex(settlement).unwrap(),
        batch_id: batch,
        previous_root: base.prev_root,
        base_commitment: base.commitment,
        phase: 0,
        first_ms: bounds.first_ms,
        last_ms: bounds.last_ms,
        timed_ops: bounds.count,
        anchored_at_ms,
        max_window_ms: 60_000,
        clock_skew_ms: 60_000,
    };
    let mut bytes = perp_core::clock::WIRE_MAGIC.to_vec();
    bytes.extend(postcard::to_allocvec(&(&w.pre_state, &w.ops, &w.manifest, clock)).unwrap());
    let public = prover::public_from_witness(&bytes).unwrap();
    assert_eq!(public.commitment::<Keccak256>(), clock.commitment());
    // The adapter must reject a legacy (unbound) commitment, even though the
    // inner mock would accept it directly. Its actual receipt is checked below
    // by successful bound settlement, not merely by trusting these host fields.
    let prepared = prover_client::prove_and_prepare(&ClockMock(clock), w, &journal.ww).unwrap();
    if let Some(dir) = std::env::var_os("ARCORA_FUNDS_WITNESS_DIR") {
        use std::io::Write as _;
        let path = PathBuf::from(dir).join(format!("batch-{batch}.witness.bin"));
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }
    let clock_evidence = json!({"receipt":hex0x(&clock.receipt()),"commitment":hex0x(&clock.commitment()),"registrationTx":registration["transactionHash"],"registrationBlock":registration["blockHash"],"anchoredAtMs":anchored_at_ms,"timedOps":bounds.count,"witnessSha256":hex0x(&Sha256::digest(&bytes)),"witnessBytes":bytes.len(),"filename":format!("batch-{batch}.witness.bin")});
    let p = &prepared.outcome;
    let signature =
        "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)";
    let mut args = vec![
        hex0x(&p.prev_root),
        hex0x(&p.manifest_hash),
        hex0x(&p.new_root),
        hex0x(&p.ordered_root),
        hex0x(&p.withdrawals_root),
        hex0x(&p.rejected_root),
        hex0x(&p.deposits_root),
        p.new_deposit_count.to_string(),
        "0xdeadbeef".into(),
    ];
    evm.reject(operator, settlement, signature, &args);
    assert_eq!(
        evm.call(settlement, "currentStateRoot()(bytes32)", &[]),
        hex0x(&p.prev_root)
    );
    args[8] = hex0x(&p.commitment);
    evm.reject(operator, settlement, signature, &args);
    let envelope = p.proof.strip_prefix(perp_core::clock::PROOF_MAGIC).unwrap();
    assert_eq!(&envelope[..32], clock.receipt());
    args[8] = hex0x(&envelope[32..]);
    journal.prepared = Some(prepared.clone());
    rollback_journal::write(&jpath, &journal, &SEED).unwrap();
    let receipt = evm.send(operator, settlement, signature, &args);
    let root = evm.call(settlement, "currentStateRoot()(bytes32)", &[]);
    let chain_batch = evm
        .call(settlement, "batchCount()(uint64)", &[])
        .parse::<u64>()
        .unwrap();
    assert_eq!(root, hex0x(&p.new_root));
    assert_eq!(chain_batch, batch + 1);
    assert_eq!(evm.call(settlement, "closeOnly()(bool)", &[]), "false");
    let observed = trading_gate::classify(
        chain_batch,
        batch,
        parse_hex32(&root).unwrap(),
        p.new_root,
        false,
    );
    let bond = evm
        .call(settlement, "sequencerBond()(uint256)", &[])
        .parse::<u128>()
        .unwrap();
    if recover {
        // Actual encrypted snapshot + prepared WAL, restored after a mined tx but
        // before local commit. EVM facts drive the existing boot-recovery routine.
        http.restore().await;
        let read = rollback_journal::read(&jpath, &SEED).unwrap().unwrap();
        let mut gw = http.app.gw.lock().await;
        assert_eq!(
            apply_boot_recovery(&mut gw, read, chain_batch, &root, bond, observed),
            BootRecoveryOutcome::DeleteJournal { mutated: true }
        );
        finish_boot_recovery(&gw, true, &http.state, &jpath, &SEED);
        assert!(!jpath.exists());
    } else {
        let status = L1Status {
            settled_root: root,
            batch_count: chain_batch,
            last_tx: receipt["transactionHash"].as_str().unwrap().into(),
            bond: bond.to_string(),
            withdrawals_root: hex0x(&p.withdrawals_root),
        };
        let mut gw = http.app.gw.lock().await;
        gw.commit_window_settle(
            batch,
            journal.witness.manifest.ordered.clone(),
            journal
                .witness
                .manifest
                .rejected
                .iter()
                .map(|(hash, _)| *hash)
                .collect(),
            prepared.clone(),
            status,
            observed,
        );
        persist_recovery(&gw, &http.state, &SEED).unwrap();
    }
    json!({"batch":batch,"tx":receipt["transactionHash"],"stateRoot":hex0x(&p.new_root),"depositTip":hex0x(&p.deposits_root),"depositCount":p.new_deposit_count,"withdrawalsRoot":hex0x(&p.withdrawals_root),"recoveredAfterMining":recover,"clock":clock_evidence})
}

#[test]
#[ignore = "requires forge-built contracts, Anvil, cast and curl; explicitly uses mock proof"]
fn real_http_evm_funds_lifecycle_with_native_mock_proof() {
    const CHILD: &str = "ARCORA_FUNDS_LIFECYCLE_CHILD";
    if std::env::var(CHILD).ok().as_deref() != Some("1") {
        let operator = User::fixture(0x11);
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "funds_lifecycle_tests::real_http_evm_funds_lifecycle_with_native_mock_proof",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("FIN_ADMIN_KEY", ADMIN)
            .env("INSURANCE_OPERATOR_ADDRESS", hex0x(&operator.address))
            .env_remove("TEE_BACKEND")
            .env_remove("ENCLAVE_SEED")
            .env_remove("ORACLE_SIGNER_KEY")
            .output()
            .unwrap();
        print!("{}", successful(output));
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_lifecycle());
}

async fn run_lifecycle() {
    let started = std::time::Instant::now();
    let evm = Evm::start();
    let mut operator = User::fixture(0x11);
    let mut alice = User::fixture(0x21);
    let mut bob = User::fixture(0x22);
    for user in [&operator, &alice, &bob] {
        evm.fund(user);
    }
    let gw = Gw::boot_with(GenesisMode::Production);
    assert_eq!(gw.seq.state.consumed_deposit_count, 0);
    assert_eq!(gw.seq.state.external_in, 0);
    let token = evm.deploy(&operator, "MockUSDC.sol/MockUSDC.json", None);
    if let Some(dir) = std::env::var_os("ARCORA_FUNDS_WITNESS_DIR") {
        std::fs::create_dir(dir).expect("witness export requires a fresh directory");
    }
    let inner_verifier = evm.deploy(&operator, "MockZkVerifier.sol/MockZkVerifier.json", None);
    let verifier = evm.deploy(
        &operator,
        "ClockBoundVerifier.sol/ClockBoundVerifier.json",
        Some((
            "constructor(address,uint64,uint64)",
            vec![inner_verifier, "60000".into(), "60000".into()],
        )),
    );
    let settlement = evm.deploy(&operator, "DarkPerpSettlement.sol/DarkPerpSettlement.json", Some(("constructor(address,address,address,bytes32,uint64,uint64,uint256,uint64,address,uint64)", vec![hex0x(&operator.address),hex0x(&operator.address),verifier.clone(),hex0x(&gw.seq.state.state_root()),"100000".into(),"100".into(),"0".into(),"0".into(),hex0x(&operator.address),"0".into()])));
    evm.send(
        &operator,
        &verifier,
        "bindSettlement(address)",
        std::slice::from_ref(&settlement),
    );
    let signer = GatewaySigner::from_parts([0x33; 32], CHAIN, [0; 20])
        .unwrap()
        .address();
    let vault = evm.deploy(
        &operator,
        "CollateralVault.sol/CollateralVault.json",
        Some((
            "constructor(address,address,address)",
            vec![settlement.clone(), token.clone(), hex0x(&signer)],
        )),
    );
    evm.send(
        &operator,
        &settlement,
        "setVault(address)",
        std::slice::from_ref(&vault),
    );
    evm.send(
        &operator,
        &token,
        "mint(address,uint256)",
        &[hex0x(&operator.address), "100000000000".into()],
    );
    evm.send(
        &operator,
        &token,
        "approve(address,uint256)",
        &[settlement.clone(), "10000000000".into()],
    );
    evm.send(
        &operator,
        &settlement,
        "postBond(uint256)",
        &["10000000000".into()],
    );
    let mut http = Http::start(gw, &evm, &vault).await;
    for user in [&mut operator, &mut alice, &mut bob] {
        http.register(user);
    }
    let mut deposits = Vec::new();
    for (user, amount, purpose) in [
        (
            &operator,
            bootstrap::MIN_BOOTSTRAP_INSURANCE as u128,
            "insuranceBootstrap",
        ),
        (&alice, 20_000 * QUOTE_SCALE as u128, "collateral"),
        (&bob, 20_000 * QUOTE_SCALE as u128, "collateral"),
    ] {
        evm.send(
            &operator,
            &token,
            "mint(address,uint256)",
            &[hex0x(&user.address), (amount * 2).to_string()],
        );
        let auth = http.request("POST","/v1/accounts/deposit/authorize",&user.key,Some(json!({"from":hex0x(&user.address),"amount":amount.to_string(),"marketId":0,"purpose":purpose})),200);
        let args = vec![
            amount.to_string(),
            auth["ownerCommit"].as_str().unwrap().into(),
            auth["sig"].as_str().unwrap().into(),
        ];
        evm.reject(user, &vault, "deposit(uint256,bytes32,bytes)", &args); // allowance absent
        evm.send(
            user,
            &token,
            "approve(address,uint256)",
            &[vault.clone(), (amount * 2).to_string()],
        );
        let mut wrong = args.clone();
        wrong[0] = (amount + 1).to_string();
        evm.reject(user, &vault, "deposit(uint256,bytes32,bytes)", &wrong);
        let receipt = evm.send(user, &vault, "deposit(uint256,bytes32,bytes)", &args);
        // Keep enough wallet balance AND allowance for a second transfer so the
        // replay refusal actually exercises authorization reuse prevention.
        assert!(
            evm.call(
                &token,
                "balanceOf(address)(uint256)",
                &[hex0x(&user.address)]
            )
            .parse::<u128>()
            .unwrap()
                >= amount
        );
        assert_eq!(
            evm.call(
                &token,
                "allowance(address,address)(uint256)",
                &[hex0x(&user.address), vault.clone()]
            ),
            amount.to_string()
        );
        evm.reject(user, &vault, "deposit(uint256,bytes32,bytes)", &args); // spent authorization
        deposits.push(json!({"payer":hex0x(&user.address),"amount":amount.to_string(),"tx":receipt["transactionHash"]}));
    }
    // Authorization snapshot already contains every blind; restore before intake.
    http.restore().await;
    evm.rpc("anvil_mine", &[json!("0x40")]);
    for _ in 0..4 {
        deposit_ingestion::ingest_once(&http.app).await.unwrap();
    }
    {
        let gw = http.app.gw.lock().await;
        assert_eq!(gw.seq.state.consumed_deposit_count, 3);
        assert_eq!(gw.seq.state.external_in, 50_000 * QUOTE_SCALE);
        assert_eq!(
            hex0x(&gw.seq.state.consumed_deposit_tip),
            evm.call(&vault, "depositChainTip()(bytes32)", &[])
        );
        assert_eq!(gw.deposits.credits.len(), 3);
        assert!(gw.seq.state.conservation_holds());
    }
    for (user, index) in [(&alice, 1usize), (&bob, 2usize)] {
        let body = json!({"txHash":deposits[index]["tx"],"marketId":0});
        for _ in 0..2 {
            http.request(
                "POST",
                "/v1/accounts/deposit/onchain",
                &user.key,
                Some(body.clone()),
                200,
            );
        }
    }
    let absent = http.request(
        "POST",
        "/v1/accounts/deposit/onchain",
        &alice.key,
        Some(json!({"txHash":hex0x(&[0xff;32]),"marketId":0})),
        202,
    );
    assert_eq!(absent["credited"], "0");
    assert_eq!(http.app.gw.lock().await.seq.state.consumed_deposit_count, 3);
    let mut batches = vec![settle(&http, &evm, &operator, &settlement, &verifier, false).await];
    assert_eq!(
        http.app.gw.lock().await.trading_gate,
        trading_gate::TradingGate::Open
    );
    let mut order_hashes = Vec::new();
    for (nonce, reduce, sides) in [
        (1, false, [Side::Sell, Side::Buy]),
        (2, true, [Side::Buy, Side::Sell]),
    ] {
        for (user, side) in [(&alice, sides[0]), (&bob, sides[1])] {
            let body = http.order(user, side, nonce, reduce).await;
            let mut bad = body.clone();
            bad["signature"] = json!(sign(&operator.sk, &[0x77; 32]));
            http.request("POST", "/v1/orders", &user.key, Some(bad), 400);
            let receipt = http.request("POST", "/v1/orders", &user.key, Some(body.clone()), 200);
            order_hashes.push(receipt["orderHash"].clone());
            http.request("POST", "/v1/orders", &user.key, Some(body), 400);
        }
        {
            let mut gw = http.app.gw.lock().await;
            for _ in 0..SETTLE_TICKS {
                gw.tick();
            }
            let expected = if reduce { 0 } else { SIZE_SCALE / 10 };
            assert_eq!(
                gw.seq.state.position(&alice.owner, 0).unwrap().size,
                -expected
            );
            assert_eq!(gw.seq.state.position(&bob.owner, 0).unwrap().size, expected);
            assert!(gw.seq.state.conservation_holds());
        }
        batches.push(settle(&http, &evm, &operator, &settlement, &verifier, false).await);
    }
    let mut claims = Vec::new();
    for user in [&alice, &bob] {
        let amount = 10_000 * QUOTE_SCALE;
        let signature = sign(
            &user.sk,
            &withdraw_auth_digest(
                CHAIN,
                &parse_addr20_hex(&vault).unwrap(),
                &user.owner,
                0,
                amount,
                &user.address,
                1,
            ),
        );
        let body = json!({"marketId":0,"amount":amount.to_string(),"to":hex0x(&user.address),"nonce":1,"signature":signature});
        let mut bad = body.clone();
        bad["to"] = json!(hex0x(&operator.address));
        http.request("POST", "/v1/accounts/withdraw", &user.key, Some(bad), 400);
        let withdrawal = http.request(
            "POST",
            "/v1/accounts/withdraw",
            &user.key,
            Some(body.clone()),
            200,
        );
        http.request("POST", "/v1/accounts/withdraw", &user.key, Some(body), 400);
        evm.reject(
            user,
            &vault,
            "claim(address,uint256,uint256,bytes32,bytes32[])",
            &[
                hex0x(&user.address),
                amount.to_string(),
                withdrawal["nonce"].to_string(),
                hex0x(&[0; 32]),
                "[]".into(),
            ],
        );
    }
    batches.push(settle(&http, &evm, &operator, &settlement, &verifier, true).await);
    deposit_ingestion::ingest_once(&http.app).await.unwrap();
    let retained: Vec<Value> = [&alice, &bob]
        .into_iter()
        .map(|user| http.request("GET", "/v1/accounts/withdrawals", &user.key, None, 200))
        .collect();
    {
        let gw = http.app.gw.lock().await;
        assert_eq!(gw.seq.state.consumed_deposit_count, 3);
        assert_eq!(gw.seq.state.external_out, 20_000 * QUOTE_SCALE);
        assert!(gw.seq.state.conservation_holds());
    }
    let stopped_address = http.url.strip_prefix("http://").unwrap().to_string();
    http.server.abort();
    http.writer.abort();
    assert!((&mut http.server).await.unwrap_err().is_cancelled());
    assert!((&mut http.writer).await.unwrap_err().is_cancelled());
    drop(http); // Both owned tasks have stopped BEFORE either claim.
    for _ in 0..100 {
        if std::net::TcpStream::connect(&stopped_address).is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        std::net::TcpStream::connect(&stopped_address).is_err(),
        "gateway must be offline before claims"
    );
    for (user, rows) in [&alice, &bob].into_iter().zip(&retained) {
        let withdrawal = &rows["withdrawals"][0];
        assert_eq!(withdrawal["claimable"], true);
        let proof = format!(
            "[{}]",
            withdrawal["proof"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>()
                .join(",")
        );
        let args = vec![
            hex0x(&user.address),
            withdrawal["amount"].as_str().unwrap().into(),
            withdrawal["nonce"].to_string(),
            withdrawal["root"].as_str().unwrap().into(),
            proof,
        ];
        let before = evm
            .call(
                &token,
                "balanceOf(address)(uint256)",
                &[hex0x(&user.address)],
            )
            .parse::<u128>()
            .unwrap();
        let receipt = evm.send(
            user,
            &vault,
            "claim(address,uint256,uint256,bytes32,bytes32[])",
            &args,
        );
        let after = evm
            .call(
                &token,
                "balanceOf(address)(uint256)",
                &[hex0x(&user.address)],
            )
            .parse::<u128>()
            .unwrap();
        assert_eq!(after - before, 10_000 * QUOTE_SCALE as u128);
        evm.reject(
            user,
            &vault,
            "claim(address,uint256,uint256,bytes32,bytes32[])",
            &args,
        );
        claims.push(json!({"to":hex0x(&user.address),"amount":args[1],"tx":receipt["transactionHash"],"balanceAfter":after.to_string()}));
    }
    assert_eq!(
        evm.call(&vault, "totalDeposited()(uint256)", &[]),
        "50000000000"
    );
    assert_eq!(
        evm.call(&vault, "totalWithdrawn()(uint256)", &[]),
        "20000000000"
    );
    assert_eq!(
        evm.call(
            &token,
            "balanceOf(address)(uint256)",
            std::slice::from_ref(&vault)
        ),
        "30000000000"
    );
    let report = json!({
        "status": "PASS",
        "elapsedSeconds": started.elapsed().as_secs_f64(),
        "timingScope": "local native/mock flow including HTTP and EVM transactions; excludes SP1 proof timing, clock admission duration and target-chain finality",
        "host": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cpu": if cfg!(target_os = "macos") { Some(successful(command("sysctl", &["-n", "machdep.cpu.brand_string"]))) } else { None },
            "availableParallelism": std::thread::available_parallelism().map(|n| n.get()).ok(),
            "rustupToolchain": std::env::var("RUSTUP_TOOLCHAIN").ok(),
            "anvil": successful(command("anvil", &["--version"]))
        },
        "proofBackend": "native replay + real ClockBoundVerifier + MockZkVerifier (NOT SP1)",
        "chainId": CHAIN,
        "gatewayTransport": "real loopback HTTP",
        "restart": "encrypted snapshot and WAL restoration after mined settlement before local commit; not OS crash",
        "deposits": deposits,
        "orders": order_hashes,
        "batches": batches,
        "claims": claims,
        "contracts": { "token": token, "vault": vault, "settlement": settlement, "clockVerifier": verifier },
        "syntheticWitnesses": true,
        "operatorOutageClaims": {"gatewayStoppedBeforeClaims":true,"retainedClaimData":true,"successfulClaims":2,"scope":"Previously published roots and saved proof data only; no new exit or production service loss claim"},
        "clockRegistration": "real owned-Anvil registration and adapter verification; test inner verifier; no target finality or production L1 reader claim",
        "clockPolicyMs": { "maxWindow": 60000, "skew": 60000 },
        "negativeCases": [
            "missing allowance", "wrong deposit tuple", "replayed deposit authorization",
            "nonexistent deposit credited zero", "wrong order signer", "duplicate signed order",
            "wrong withdrawal destination", "duplicate withdrawal authorization",
            "unsettled withdrawal claim", "invalid mock proof", "legacy proof rejected by clock adapter", "duplicate vault claim"
        ]
    });
    if let Some(dir) = std::env::var_os("ARCORA_FUNDS_WITNESS_DIR") {
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(PathBuf::from(dir).join("lifecycle.json"))
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&report).unwrap())
            .unwrap();
    }
    if let Ok(path) = std::env::var("ARCORA_FUNDS_EVIDENCE") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!("FUNDS_LIFECYCLE {}", report);
}
