//! Opt-in real HTTP + local EVM funds lifecycle against the settlement ABI v3
//! stack. The proof backend is explicitly ClockBoundVerifier + MockZkVerifier:
//! this is NOT an SP1, TEE or release gate.
//!
//! The run covers the 12-word settlement `Config` and the 4-word clock
//! constructor, a bond posted before the first deposit, deadline-bound deposit
//! permits, the bond-capacity gate (gateway refusal and on-chain revert, first
//! come first served), an enclave-authorized inclusion challenge answered by a
//! third party from the gateway's open-set plan, an empty keepalive batch, a
//! permissionless liveness close-only, the refund of a deposit no settled batch
//! consumed, and withdrawal claims while the gateway is offline.
//!
//! Optional ARCORA_FUNDS_WITNESS_DIR exports exact synthetic v2 inputs for guest
//! replay. Run `forge build --root contracts`, then the ignored test below. All
//! wallets, contracts, ports and snapshots are disposable; no configured chain is
//! used.
use super::*;
use k256::sha2::{Digest as _, Sha256};
use serde_json::{json, Value};
use std::path::{Path as FsPath, PathBuf};
use std::process::{Child, Command, Output, Stdio};

const SEED: [u8; 32] = [0x69; 32];
const ADMIN: &str = "local-funds-lifecycle-test-admin";
const CHAIN: u64 = 31337;
/// Settlement terms for the owned chain: short enough to cross the keepalive and
/// liveness thresholds by mining blocks.
const LIVENESS_BLOCKS: u64 = 400;
const CHALLENGE_GRACE_BLOCKS: u64 = 50;
const CHALLENGE_BOND_WEI: u128 = 10_000_000_000_000_000;
/// Orders are challengeable as soon as they are accepted.
const INCLUSION_DEADLINE_SECS: u64 = 0;
const FINAL_SETTLE_GRACE_BLOCKS: u64 = 10;
const PROGRESS_BATCHES: u64 = 2;
const SLASH_PAYOUT_CAP: u128 = 1_000 * 1_000_000;
/// Clock terms: the test policy the exported witnesses pin (`replay-funds`
/// checks it), not a production recommendation.
const CLOCK_WINDOW_MS: u64 = 60_000;
const CLOCK_SKEW_MS: u64 = 60_000;
const ANCHOR_TIMEOUT_MS: u64 = 3_600_000;
/// The sequencer bond posted before the first deposit. Deposit capacity is about
/// 20 times the bond.
const BOND: u128 = 4_000 * 1_000_000;
const DEPOSIT_SIG: &str = "deposit(uint256,bytes32,uint64,bytes)";
const REFUND_SIG: &str = "refundDeposit(uint64,address,bytes32,uint256,address)";
const CHALLENGE_SIG: &str = "challengeInclusion(bytes32,uint64,uint64,uint64,address,bytes)";

fn usdc(units: u128) -> u128 {
    units * QUOTE_SCALE as u128
}
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
/// The 4-byte selector of a custom error such as `BondCapacityExceeded()`.
fn error_selector(error: &str) -> String {
    successful(command("cast", &["sig", error])).to_ascii_lowercase()
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
    fn hex(&self) -> String {
        hex0x(&self.address)
    }
}
struct Evm {
    child: Child,
    url: String,
    scratch: PathBuf,
    output: Vec<std::thread::JoinHandle<()>>,
}

fn announced_anvil_port(line: &str) -> Option<u16> {
    // Foundry versions differ in stream selection and terminal colour defaults.
    // Strip ANSI CSI sequences, then accept only the owned child's exact banner.
    let mut plain = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.next() == Some('[') {
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
        .trim()
        .strip_prefix("Listening on 127.0.0.1:")?
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
}

fn drain_anvil_output(
    stream: impl std::io::Read + Send + 'static,
    send: std::sync::mpsc::Sender<u16>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        let mut reader = std::io::BufReader::new(stream);
        let mut line = String::new();
        let mut startup_bytes = 0;
        let mut found = false;
        while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
            if !found {
                startup_bytes += line.len();
                if startup_bytes > 128 * 1024 {
                    return;
                }
                if let Some(port) = announced_anvil_port(&line) {
                    let _ = send.send(port);
                    found = true;
                }
            }
            line.clear(); // Drain both owned pipes without printing fixture keys.
        }
    })
}

#[test]
fn owned_anvil_banner_accepts_plain_and_colored_streams() {
    assert_eq!(
        announced_anvil_port("Listening on 127.0.0.1:31337\n"),
        Some(31337)
    );
    assert_eq!(
        announced_anvil_port("\x1b[32mListening on \x1b[0m127.0.0.1:\x1b[1m31337\x1b[0m\r\n"),
        Some(31337)
    );
    for invalid in [
        "Listening on 0.0.0.0:31337",
        "Listening on 127.0.0.1:0",
        "Listening on 127.0.0.1:65536",
        "Listening on 127.0.0.1:31337bad",
    ] {
        assert_eq!(announced_anvil_port(invalid), None);
    }
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let output = vec![
            drain_anvil_output(child.stdout.take().unwrap(), send.clone()),
            drain_anvil_output(child.stderr.take().unwrap(), send),
        ];
        let mut evm = Self {
            child,
            url: String::new(),
            scratch,
            output,
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
    fn mine(&self, blocks: u64) {
        if blocks > 0 {
            self.rpc("anvil_mine", &[json!(format!("0x{blocks:x}"))]);
        }
    }
    fn fund(&self, user: &User) {
        self.rpc(
            "anvil_setBalance",
            &[json!(user.hex()), json!("0x3635c9adc5dea00000")],
        );
    }
    fn send_raw(
        &self,
        user: &User,
        value: Option<&str>,
        to: &str,
        signature: &str,
        args: &[String],
    ) -> Output {
        let key = user.private_hex(); // Public, fixed test fixture; never a configured wallet.
        let mut all = vec!["send", "--json", "--private-key", &key];
        if let Some(value) = value {
            all.extend(["--value", value]);
        }
        all.extend([to, signature]);
        all.extend(args.iter().map(String::as_str));
        self.cast(&all)
    }
    fn send_value(
        &self,
        user: &User,
        value: Option<&str>,
        to: &str,
        signature: &str,
        args: &[String],
    ) -> Value {
        let receipt: Value =
            serde_json::from_str(&successful(self.send_raw(user, value, to, signature, args)))
                .unwrap();
        assert_eq!(receipt["status"], "0x1", "transaction reverted");
        receipt
    }
    fn send(&self, user: &User, to: &str, signature: &str, args: &[String]) -> Value {
        self.send_value(user, None, to, signature, args)
    }
    fn reject(&self, user: &User, to: &str, signature: &str, args: &[String]) {
        let result = self.send_raw(user, None, to, signature, args);
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
    /// The contract refuses the call with exactly the custom error `error`, as the
    /// revert data of the gas estimate shows. Nothing is mined.
    fn refuse(
        &self,
        user: &User,
        value: Option<&str>,
        to: &str,
        signature: &str,
        args: &[String],
        error: &str,
    ) {
        let result = self.send_raw(user, value, to, signature, args);
        assert!(
            !result.status.success(),
            "{signature} was accepted; expected {error}"
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let selector = error_selector(error);
        let name = error.split('(').next().unwrap();
        assert!(
            text.to_ascii_lowercase().contains(&selector[2..]) || text.contains(name),
            "{signature}: expected {error} ({selector}), got: {text}"
        );
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
    fn uint(&self, to: &str, signature: &str, args: &[String]) -> u128 {
        self.call(to, signature, args).parse().unwrap()
    }
    fn creation(
        &self,
        user: &User,
        artifact: &str,
        constructor: Option<(&str, Vec<String>)>,
    ) -> Output {
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
        self.cast(&[
            "send",
            "--json",
            "--private-key",
            &user.private_hex(),
            "--create",
            &code,
        ])
    }
    fn deploy(
        &self,
        user: &User,
        artifact: &str,
        constructor: Option<(&str, Vec<String>)>,
    ) -> String {
        let receipt: Value =
            serde_json::from_str(&successful(self.creation(user, artifact, constructor))).unwrap();
        assert_eq!(receipt["status"], "0x1");
        receipt["contractAddress"].as_str().unwrap().to_string()
    }
    /// The constructor refuses `constructor` with exactly the custom error `error`.
    fn refuse_deploy(
        &self,
        user: &User,
        artifact: &str,
        constructor: (&str, Vec<String>),
        error: &str,
    ) {
        let result = self.creation(user, artifact, Some(constructor));
        assert!(
            !result.status.success(),
            "{artifact} deployed; expected {error}"
        );
        let text = String::from_utf8_lossy(&result.stderr).to_string()
            + &String::from_utf8_lossy(&result.stdout);
        let selector = error_selector(error);
        assert!(
            text.to_ascii_lowercase().contains(&selector[2..])
                || text.contains(error.split('(').next().unwrap()),
            "{artifact}: expected {error} ({selector}), got: {text}"
        );
    }
}
impl Drop for Evm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for output in self.output.drain(..) {
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
    settlement: [u8; 20],
    server: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}
impl Http {
    /// The gateway over loopback HTTP, with a read-only L1 bridge on the owned chain
    /// so permits are gated on the settlement's live deposit terms. The test sends
    /// every transaction itself.
    async fn start(mut gw: Gw, evm: &Evm, settlement: &str, vault: &str) -> Self {
        let mut app = tests::test_app();
        let inner = Arc::get_mut(&mut app).unwrap();
        let settlement_addr = parse_addr20_hex(settlement).unwrap();
        gw.prod = true;
        gw.chain_id = CHAIN;
        gw.vault = parse_addr20_hex(vault).unwrap();
        gw.window_settle_mode = true;
        gw.l1_settlement = Some(settlement_addr);
        gw.seq.set_retain_tick_snapshots(false);
        gw.deposits.required = true;
        inner.gw = Mutex::new(gw);
        let mut l1 = L1::test_reader(evm.url.clone());
        l1.settlement = settlement.to_string();
        l1.vault = Some(vault.to_string());
        inner.l1 = Some(l1);
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
                let result =
                    persist_recovery(&*writer_app.gw.lock().await, &writer_state, &SEED, None);
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
            settlement: settlement_addr,
            server,
            writer,
        }
    }
    fn l1(&self) -> L1 {
        self.app.l1.clone().unwrap()
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
    fn authorize(&self, user: &User, amount: u128, purpose: &str, status: u16) -> Value {
        self.request(
            "POST",
            "/v1/accounts/deposit/authorize",
            &user.key,
            Some(json!({"from":user.hex(),"amount":amount.to_string(),"marketId":0,"purpose":purpose})),
            status,
        )
    }
    fn confirm(&self, user: &User, tx: &Value, status: u16) -> Value {
        self.request(
            "POST",
            "/v1/accounts/deposit/onchain",
            &user.key,
            Some(json!({"txHash":tx,"marketId":0})),
            status,
        )
    }
    fn register(&self, user: &mut User) {
        let value = self.request(
            "POST",
            "/v1/accounts",
            "",
            Some(json!({"signer":user.hex()})),
            200,
        );
        user.key = value["apiKey"].as_str().unwrap().into();
        user.owner = parse_hex32(value["owner"].as_str().unwrap()).unwrap();
        let sig = sign(
            &user.sk,
            &deposit_bind_digest(
                CHAIN,
                &self.app.gateway_signer.vault,
                &user.owner,
                &user.address,
            ),
        );
        self.request(
            "POST",
            "/v1/accounts/deposit/address",
            &user.key,
            Some(json!({"address":user.hex(),"signature":sig})),
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
        gw.l1_settlement = Some(self.settlement);
        gw.seq.set_retain_tick_snapshots(false);
        gw.deposits.required = true;
        *self.app.gw.lock().await = gw;
    }
    /// One round of the gateway's L1 health task: liveness at the latest block,
    /// close-only and the consumed deposit count at the finalized block.
    async fn health(&self) -> l1::LivenessObservation {
        let l1 = self.l1();
        let (liveness, finality) = tokio::task::spawn_blocking(move || {
            (l1.liveness_observation(), l1.settlement_finality())
        })
        .await
        .unwrap();
        let observed = liveness.clone().unwrap();
        assert!(finality.is_ok(), "{finality:?}");
        self.app
            .gw
            .lock()
            .await
            .apply_l1_health(liveness, None, finality);
        observed
    }
    async fn liveness(&self) -> l1::LivenessObservation {
        let l1 = self.l1();
        tokio::task::spawn_blocking(move || l1.liveness_observation())
            .await
            .unwrap()
            .unwrap()
    }
    /// Read the settlement's open challenge set as the gateway's watcher does and
    /// plan answers from the batches it retains.
    async fn plan_answers(
        &self,
        watcher: &mut challenge_scan::Watcher,
    ) -> challenge_scan::AnswerPlan {
        let l1 = self.l1();
        let known = watcher.known();
        let read = tokio::task::spawn_blocking(move || {
            l1.open_challenge_set(&known, challenge_scan::MAX_NEW_DETAILS)
        })
        .await
        .unwrap()
        .unwrap();
        watcher.observe(read);
        watcher.plan(&self.app.gw.lock().await.batch_orders)
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

/// Deposit arguments from a gateway permit: `(amount, ownerCommit, validUntil, sig)`.
fn permit_args(amount: u128, permit: &Value) -> Vec<String> {
    vec![
        amount.to_string(),
        permit["ownerCommit"].as_str().unwrap().into(),
        permit["validUntil"].as_u64().unwrap().to_string(),
        permit["sig"].as_str().unwrap().into(),
    ]
}

/// The `challengeInclusion` arguments for an accepted order's receipt.
fn challenge_args(receipt: &Value, beneficiary: &str) -> Vec<String> {
    vec![
        receipt["orderHash"].as_str().unwrap().into(),
        receipt["seqNo"].to_string(),
        receipt["recvTimeMs"].to_string(),
        receipt["batchIdHint"].to_string(),
        beneficiary.into(),
        receipt["l1Challenge"]["signature"].as_str().unwrap().into(),
    ]
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettleMode {
    /// Seal the open window, register, prove, settle and commit locally.
    Normal,
    /// As `Normal`, but restore the encrypted snapshot and journal after the
    /// settle is mined and before the local commit, then run boot recovery.
    RecoverAfterMining,
    /// An idle window sealed empty: registered untimed, only advances the batch.
    Keepalive,
}

/// The exported witness of one window. The four wallet windows are the sequence
/// `replay-funds` replays; the keepalive's empty window is exported beside them
/// under its own name.
fn witness_file(batch: u64, mode: SettleMode) -> String {
    if mode == SettleMode::Keepalive {
        format!("keepalive-batch-{batch}.witness.bin")
    } else {
        format!("batch-{batch}.witness.bin")
    }
}

async fn settle(
    http: &Http,
    evm: &Evm,
    operator: &User,
    settlement: &str,
    clock_verifier: &str,
    mode: SettleMode,
) -> Value {
    let batch = evm
        .call(settlement, "batchCount()(uint64)", &[])
        .parse::<u64>()
        .unwrap();
    let jpath = rollback_journal::journal_path(&http.state);
    let mut journal = {
        let mut gw = http.app.gw.lock().await;
        let (j, _envelope) = begin_journaled_window_settle_mode(
            &mut gw,
            batch,
            Some(&jpath),
            &SEED,
            None,
            mode == SettleMode::Keepalive,
        )
        .unwrap()
        .unwrap();
        persist_recovery(&gw, &http.state, &SEED, None).unwrap();
        j
    };
    if mode == SettleMode::Keepalive {
        assert!(
            journal.witness.ops.is_empty(),
            "a keepalive window is empty"
        );
        assert!(journal.ww.is_empty());
        assert!(journal.witness.manifest.ordered.is_empty());
        assert!(journal.witness.manifest.rejected.is_empty());
    }
    // Write the immutable unproved intent BEFORE the on-chain registration.
    journal.prepared =
        Some(prover_client::prepare_unproved(&journal.witness, &journal.ww).unwrap());
    rollback_journal::write(&jpath, &journal, &SEED).unwrap();
    let w = &journal.witness;
    let bounds = perp_core::clock::TimeBounds::derive(&w.ops).unwrap();
    if mode == SettleMode::Keepalive {
        assert_eq!((bounds.count, bounds.first_ms, bounds.last_ms), (0, 0, 0));
    }
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
        max_window_ms: CLOCK_WINDOW_MS,
        clock_skew_ms: CLOCK_SKEW_MS,
    };
    let bytes = prover::encode_clock_witness(&w.pre_state, &w.ops, &w.manifest, &clock);
    let public = prover::public_from_witness(&bytes).unwrap();
    assert_eq!(public.commitment::<Keccak256>(), clock.commitment());
    // The adapter must reject a legacy (unbound) commitment, even though the
    // inner mock would accept it directly. Its actual receipt is checked below
    // by successful bound settlement, not merely by trusting these host fields.
    let prepared = prover_client::prove_and_prepare(&ClockMock(clock), w, &journal.ww).unwrap();
    if let Some(dir) = std::env::var_os("ARCORA_FUNDS_WITNESS_DIR") {
        use std::io::Write as _;
        let path = PathBuf::from(dir).join(witness_file(batch, mode));
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }
    let clock_evidence = json!({"receipt":hex0x(&clock.receipt()),"commitment":hex0x(&clock.commitment()),"registrationTx":registration["transactionHash"],"registrationBlock":registration["blockHash"],"anchoredAtMs":anchored_at_ms,"timedOps":bounds.count,"witnessSha256":hex0x(&Sha256::digest(&bytes)),"witnessBytes":bytes.len(),"filename":witness_file(batch, mode)});
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
    // The settle is the settlement's progress and its consumed deposit boundary.
    let settled_block = u64::from_str_radix(
        receipt["blockNumber"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    assert_eq!(
        evm.uint(settlement, "lastProgressBlock()(uint256)", &[]),
        settled_block as u128
    );
    assert_eq!(
        evm.uint(settlement, "consumedDepositCount()(uint64)", &[]),
        p.new_deposit_count as u128
    );
    let observed = trading_gate::classify(
        chain_batch,
        batch,
        parse_hex32(&root).unwrap(),
        p.new_root,
        false,
    );
    let bond = evm.uint(settlement, "sequencerBond()(uint256)", &[]);
    if mode == SettleMode::RecoverAfterMining {
        // Actual encrypted snapshot + prepared WAL, restored after a mined tx but
        // before local commit. EVM facts drive the existing boot-recovery routine.
        http.restore().await;
        let read = rollback_journal::read(&jpath, &SEED).unwrap().unwrap();
        let mut gw = http.app.gw.lock().await;
        assert_eq!(
            apply_boot_recovery(&mut gw, read, chain_batch, &root, bond, observed),
            BootRecoveryOutcome::DeleteJournal { mutated: true }
        );
        finish_boot_recovery(&gw, true, &http.state, &jpath, &SEED, None);
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
        persist_recovery(&gw, &http.state, &SEED, None).unwrap();
    }
    json!({"batch":batch,"tx":receipt["transactionHash"],"block":settled_block,"stateRoot":hex0x(&p.new_root),"depositTip":hex0x(&p.deposits_root),"depositCount":p.new_deposit_count,"withdrawalsRoot":hex0x(&p.withdrawals_root),"recoveredAfterMining":mode == SettleMode::RecoverAfterMining,"keepalive":mode == SettleMode::Keepalive,"clock":clock_evidence})
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
            .env("INSURANCE_OPERATOR_ADDRESS", operator.hex())
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
    // Inclusion challenges must recover to the enclave that signs the receipts.
    let enclave = gw.seq.enclave().eth_address();
    let token = evm.deploy(&operator, "MockUSDC.sol/MockUSDC.json", None);
    if let Some(dir) = std::env::var_os("ARCORA_FUNDS_WITNESS_DIR") {
        std::fs::create_dir(dir).expect("witness export requires a fresh directory");
    }

    // ── Stack: 4-word clock constructor, 12-word settlement Config, pairing ──
    let inner_verifier = evm.deploy(&operator, "MockZkVerifier.sol/MockZkVerifier.json", None);
    let verifier = evm.deploy(
        &operator,
        "ClockBoundVerifier.sol/ClockBoundVerifier.json",
        Some((
            "constructor(address,uint64,uint64,uint64)",
            vec![
                inner_verifier.clone(),
                CLOCK_WINDOW_MS.to_string(),
                CLOCK_SKEW_MS.to_string(),
                ANCHOR_TIMEOUT_MS.to_string(),
            ],
        )),
    );
    // `Config` is a static struct, so `abi.encode(c)` is its twelve flat words in
    // Solidity field order.
    const CONFIG: &str = "constructor(address,address,address,bytes32,uint256,uint256,uint256,uint256,address,uint256,uint256,uint256)";
    let config = |verifier: &str, progress_batches: u64| -> Vec<String> {
        vec![
            operator.hex(),
            hex0x(&enclave),
            verifier.to_string(),
            hex0x(&gw.seq.state.state_root()),
            LIVENESS_BLOCKS.to_string(),
            CHALLENGE_GRACE_BLOCKS.to_string(),
            CHALLENGE_BOND_WEI.to_string(),
            INCLUSION_DEADLINE_SECS.to_string(),
            operator.hex(),
            FINAL_SETTLE_GRACE_BLOCKS.to_string(),
            progress_batches.to_string(),
            SLASH_PAYOUT_CAP.to_string(),
        ]
    };
    let words = config(&verifier, PROGRESS_BATCHES);
    let mut input = vec!["abi-encode", CONFIG];
    input.extend(words.iter().map(String::as_str));
    let encoded = successful(command("cast", &input));
    assert_eq!(encoded.len(), 2 + 12 * 64, "the Config is twelve ABI words");
    const SETTLEMENT: &str = "DarkPerpSettlement.sol/DarkPerpSettlement.json";
    // The settlement refuses a verifier that is not an unbound clock adapter, and
    // a progress gate outside 1..16.
    evm.refuse_deploy(
        &operator,
        SETTLEMENT,
        (CONFIG, config(&inner_verifier, PROGRESS_BATCHES)),
        "InvalidConfig()",
    );
    evm.refuse_deploy(
        &operator,
        SETTLEMENT,
        (CONFIG, config(&verifier, 17)),
        "InvalidConfig()",
    );
    let settlement = evm.deploy(
        &operator,
        SETTLEMENT,
        Some((CONFIG, config(&verifier, PROGRESS_BATCHES))),
    );
    assert_eq!(evm.call(&settlement, "ABI_VERSION()(uint256)", &[]), "3");
    assert_eq!(
        evm.call(&settlement, "verifier()(address)", &[])
            .to_ascii_lowercase(),
        verifier.to_ascii_lowercase()
    );
    assert_eq!(
        evm.call(&settlement, "enclaveSigner()(address)", &[])
            .to_ascii_lowercase(),
        hex0x(&enclave)
    );
    assert_eq!(
        evm.uint(&settlement, "progressBatches()(uint256)", &[]),
        PROGRESS_BATCHES as u128
    );
    assert_eq!(
        evm.uint(&settlement, "slashPayoutCap()(uint256)", &[]),
        SLASH_PAYOUT_CAP
    );
    assert_eq!(
        evm.uint(&verifier, "anchorTimeoutMs()(uint64)", &[]),
        ANCHOR_TIMEOUT_MS as u128
    );
    assert_eq!(evm.uint(&verifier, "proofVersion()(uint64)", &[]), 2);
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
    // Only a vault that names this settlement can be paired.
    evm.refuse(
        &operator,
        None,
        &settlement,
        "setVault(address)",
        std::slice::from_ref(&token),
        "VaultMismatch()",
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
        &[operator.hex(), "100000000000".into()],
    );
    evm.send(
        &operator,
        &token,
        "approve(address,uint256)",
        &[settlement.clone(), BOND.to_string()],
    );

    let mut http = Http::start(gw, &evm, &settlement, &vault).await;
    for user in [&mut operator, &mut alice, &mut bob] {
        http.register(user);
    }
    // Permits are issued only once intake has verified the vault's deposit prefix.
    http.authorize(&alice, usdc(1), "collateral", 503);
    evm.mine(4);
    assert_eq!(deposit_ingestion::ingest_once(&http.app).await.unwrap(), 0);

    // ── No bond, no deposits: the gateway and the vault both refuse ──
    assert_eq!(evm.uint(&settlement, "sequencerBond()(uint256)", &[]), 0);
    assert_eq!(evm.uint(&settlement, "requiredBond()(uint256)", &[]), 0);
    assert_eq!(
        evm.call(&settlement, "acceptingDeposits()(bool)", &[]),
        "true"
    );
    let unbonded_capacity = evm.uint(&settlement, "depositCapacity()(uint256)", &[]);
    assert_eq!(unbonded_capacity, 19);
    let refused = http.authorize(
        &operator,
        bootstrap::MIN_BOOTSTRAP_INSURANCE as u128,
        "insuranceBootstrap",
        409,
    );
    assert_eq!(refused["capacity"], unbonded_capacity.to_string());
    let valid_until = now_ms() / 1000 + 600;
    let direct_permit = |user: &User, commit: [u8; 32], amount: u128, until: u64| -> Vec<String> {
        let sig = http
            .app
            .gateway_signer
            .sign(&user.address, &commit, amount, until)
            .unwrap();
        vec![
            amount.to_string(),
            hex0x(&commit),
            until.to_string(),
            hex0x(&sig),
        ]
    };
    evm.refuse(
        &alice,
        None,
        &vault,
        DEPOSIT_SIG,
        &direct_permit(&alice, [0x5a; 32], usdc(20_000), valid_until),
        "BondCapacityExceeded()",
    );

    // ── The bond is posted before the first deposit ──
    let bond_tx = evm.send(
        &operator,
        &settlement,
        "postBond(uint256)",
        &[BOND.to_string()],
    );
    assert_eq!(evm.uint(&settlement, "sequencerBond()(uint256)", &[]), BOND);
    let bonded_capacity = evm.uint(&settlement, "depositCapacity()(uint256)", &[]);
    assert_eq!(bonded_capacity, ((BOND + 1) * 10_000 - 1) / 500);
    // A permit past its deadline is refused on-chain.
    evm.refuse(
        &alice,
        None,
        &vault,
        DEPOSIT_SIG,
        &direct_permit(&alice, [0x5b; 32], usdc(1), 1),
        "PermitExpired()",
    );

    let mut deposits = Vec::new();
    let mut permits = Vec::new();
    for (user, amount, purpose) in [
        (
            &operator,
            bootstrap::MIN_BOOTSTRAP_INSURANCE as u128,
            "insuranceBootstrap",
        ),
        (&alice, usdc(20_000), "collateral"),
        (&bob, usdc(20_000), "collateral"),
    ] {
        evm.send(
            &operator,
            &token,
            "mint(address,uint256)",
            &[user.hex(), (amount * 2).to_string()],
        );
        let issued_at = now_ms() / 1000;
        let auth = http.authorize(user, amount, purpose, 200);
        let until = auth["validUntil"]
            .as_u64()
            .expect("validUntil is a JSON number");
        assert!(
            (issued_at + DEFAULT_DEPOSIT_PERMIT_TTL_SECS
                ..=now_ms() / 1000 + DEFAULT_DEPOSIT_PERMIT_TTL_SECS)
                .contains(&until),
            "validUntil is the issue time plus the permit TTL"
        );
        // A held permit is re-signed with its stored deadline: same bytes.
        let reused = http.request(
            "POST",
            "/v1/accounts/deposit/authorize",
            &user.key,
            Some(json!({"from":user.hex(),"amount":amount.to_string(),"marketId":0,"purpose":purpose,"reuseOwnerCommit":auth["ownerCommit"]})),
            200,
        );
        assert_eq!(
            (
                &reused["ownerCommit"],
                &reused["sig"],
                &reused["validUntil"]
            ),
            (&auth["ownerCommit"], &auth["sig"], &auth["validUntil"])
        );
        let args = permit_args(amount, &auth);
        evm.reject(user, &vault, DEPOSIT_SIG, &args); // allowance absent
        evm.send(
            user,
            &token,
            "approve(address,uint256)",
            &[vault.clone(), (amount * 2).to_string()],
        );
        let mut wrong_amount = args.clone();
        wrong_amount[0] = (amount + 1).to_string();
        evm.refuse(
            user,
            None,
            &vault,
            DEPOSIT_SIG,
            &wrong_amount,
            "BadGatewaySig()",
        );
        let mut wrong_deadline = args.clone();
        wrong_deadline[2] = (until + 1).to_string();
        evm.refuse(
            user,
            None,
            &vault,
            DEPOSIT_SIG,
            &wrong_deadline,
            "BadGatewaySig()",
        );
        let receipt = evm.send(user, &vault, DEPOSIT_SIG, &args);
        // Keep enough wallet balance AND allowance for a second transfer so the
        // replay refusal actually exercises permit reuse prevention.
        assert!(evm.uint(&token, "balanceOf(address)(uint256)", &[user.hex()]) >= amount);
        assert_eq!(
            evm.uint(
                &token,
                "allowance(address,address)(uint256)",
                &[user.hex(), vault.clone()]
            ),
            amount
        );
        evm.refuse(user, None, &vault, DEPOSIT_SIG, &args, "OwnerCommitUsed()");
        deposits.push(json!({"payer":user.hex(),"amount":amount.to_string(),"validUntil":until,"tx":receipt["transactionHash"]}));
        permits.push(args);
    }
    // No capacity is reserved: a deposit beyond what the bond still covers is
    // refused before any permit is issued.
    let remaining = bonded_capacity - usdc(50_000);
    assert_eq!(
        evm.uint(&settlement, "depositCapacity()(uint256)", &[]),
        remaining
    );
    let over = http.authorize(&alice, usdc(30_001), "collateral", 409);
    assert_eq!(over["capacity"], remaining.to_string());
    // Authorization snapshot already contains every blind; restore before intake.
    http.restore().await;
    evm.mine(0x40);
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
    // Credited off-chain, but no settled batch consumed them yet.
    let live = http.health().await;
    assert!(!live.liveness_low());
    for (user, index) in [(&alice, 1usize), (&bob, 2usize)] {
        for _ in 0..2 {
            let receipt = http.confirm(user, &deposits[index]["tx"], 200);
            assert_eq!(receipt["status"], "credited_unsettled");
        }
    }
    let absent = http.confirm(&alice, &json!(hex0x(&[0xff; 32])), 202);
    assert_eq!(absent["credited"], "0");
    assert_eq!(http.app.gw.lock().await.seq.state.consumed_deposit_count, 3);
    let mut batches = vec![
        settle(
            &http,
            &evm,
            &operator,
            &settlement,
            &verifier,
            SettleMode::Normal,
        )
        .await,
    ];
    assert_eq!(
        http.app.gw.lock().await.trading_gate,
        trading_gate::TradingGate::Open
    );
    assert_eq!(
        http.confirm(&alice, &deposits[1]["tx"], 200)["status"],
        "credited"
    );

    // ── Trading, with an inclusion challenge on alice's first order ──
    let mut watcher = challenge_scan::Watcher::default();
    let mut challenge = Value::Null;
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
            // The accept response carries the enclave-signed challenge kit.
            let kit = &receipt["l1Challenge"];
            assert_eq!(kit["chainId"], CHAIN);
            assert_eq!(kit["settlement"], settlement.to_ascii_lowercase());
            assert_eq!(kit["beneficiary"], user.hex());
            if nonce == 1 && user.address == alice.address {
                challenge = open_challenge(
                    &http,
                    &evm,
                    &settlement,
                    &operator,
                    &alice,
                    &bob,
                    &receipt,
                    &enclave,
                );
                let plan = http.plan_answers(&mut watcher).await;
                assert!(
                    plan.sends.is_empty(),
                    "no settled batch holds the order yet"
                );
                assert_eq!(plan.awaiting, 1);
                assert!(plan.unanswerable.is_empty());
            }
        }
        {
            let mut gw = http.app.gw.lock().await;
            // A production gateway takes prices from its feed, and a transcript
            // older than the market's staleness bound rejects every fill. Publish
            // a fresh one at the unchanged mark, as the feed task would.
            let px = gw.seq.oracle(0).unwrap().price;
            let fresh = oracle_of(px, now_ms(), 0, &gw.oracle_signer);
            gw.seq.set_oracle(0, fresh);
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
        batches.push(
            settle(
                &http,
                &evm,
                &operator,
                &settlement,
                &verifier,
                SettleMode::Normal,
            )
            .await,
        );
        if nonce == 1 {
            challenge["answer"] = answer_challenge(
                &http,
                &evm,
                &settlement,
                &alice,
                &bob,
                &mut watcher,
                &challenge,
            )
            .await;
        }
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
        let body = json!({"marketId":0,"amount":amount.to_string(),"to":user.hex(),"nonce":1,"signature":signature});
        let mut bad = body.clone();
        bad["to"] = json!(operator.hex());
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
                user.hex(),
                amount.to_string(),
                withdrawal["nonce"].to_string(),
                hex0x(&[0; 32]),
                "[]".into(),
            ],
        );
    }
    batches.push(
        settle(
            &http,
            &evm,
            &operator,
            &settlement,
            &verifier,
            SettleMode::RecoverAfterMining,
        )
        .await,
    );
    deposit_ingestion::ingest_once(&http.app).await.unwrap();
    {
        let gw = http.app.gw.lock().await;
        assert_eq!(gw.seq.state.consumed_deposit_count, 3);
        assert_eq!(gw.seq.state.external_out, 20_000 * QUOTE_SCALE);
        assert!(gw.seq.state.conservation_holds());
    }

    // ── Keepalive: an idle gateway settles an empty batch at a quarter of liveness ──
    let live = http.liveness().await;
    assert!(!live.keepalive_due());
    evm.mine(live.blocks_until_keepalive());
    let live = http.liveness().await;
    assert!(live.keepalive_due());
    assert!(http.app.gw.lock().await.window_is_idle());
    let keepalive = settle(
        &http,
        &evm,
        &operator,
        &settlement,
        &verifier,
        SettleMode::Keepalive,
    )
    .await;
    let after_keepalive = http.liveness().await;
    assert!(!after_keepalive.keepalive_due());
    assert_eq!(
        after_keepalive.last_progress_block,
        keepalive["block"].as_u64().unwrap()
    );

    // ── Late deposits: the vault's gate decides, first come first served ──
    let late = usdc(20_000);
    let mut late_permits = Vec::new();
    for user in [&alice, &bob] {
        evm.send(
            &operator,
            &token,
            "mint(address,uint256)",
            &[user.hex(), late.to_string()],
        );
        evm.send(
            user,
            &token,
            "approve(address,uint256)",
            &[vault.clone(), late.to_string()],
        );
        // Both fit the remaining capacity when issued; the gateway reserves none.
        late_permits.push(permit_args(
            late,
            &http.authorize(user, late, "collateral", 200),
        ));
    }
    let late_deposit = evm.send(&alice, &vault, DEPOSIT_SIG, &late_permits[0]);
    evm.refuse(
        &bob,
        None,
        &vault,
        DEPOSIT_SIG,
        &late_permits[1],
        "BondCapacityExceeded()",
    );
    assert_eq!(
        evm.uint(&settlement, "depositCapacity()(uint256)", &[]),
        remaining - late
    );
    let late_id = "3".to_string();
    let refund_args = |amount: u128, to: &User| -> Vec<String> {
        vec![
            late_id.clone(),
            alice.hex(),
            late_permits[0][1].clone(),
            amount.to_string(),
            to.hex(),
        ]
    };
    // Live: no refund, and the settlement is not stalled.
    evm.refuse(
        &bob,
        None,
        &vault,
        REFUND_SIG,
        &refund_args(late, &alice),
        "NotCloseOnly()",
    );
    evm.refuse(
        &bob,
        None,
        &settlement,
        "triggerCloseOnly()",
        &[],
        "LivenessNotExpired()",
    );
    evm.mine(0x40);
    deposit_ingestion::ingest_once(&http.app).await.unwrap();
    let credited = http.confirm(&alice, &late_deposit["transactionHash"], 200);
    assert_eq!(credited["status"], "credited_unsettled");
    assert_eq!(credited["depositIds"], json!([3]));

    // ── The operator stops settling: liveness runs out, anyone closes ──
    let live = http.health().await;
    evm.mine((LIVENESS_BLOCKS / 2).saturating_sub(live.idle_blocks()));
    let live = http.health().await;
    assert!(live.liveness_low());
    assert!(http
        .app
        .gw
        .lock()
        .await
        .ops_alerts
        .active()
        .contains(&ops_alerts::AlertKind::LivenessLow));
    let state = http.request("GET", "/api/state", "", None, 200);
    assert_eq!(state["mode"], "Normal");
    assert!(state["opsAlerts"]
        .as_array()
        .unwrap()
        .contains(&json!("liveness_low")));
    evm.mine((LIVENESS_BLOCKS + 1).saturating_sub(live.idle_blocks()));
    let close_tx = evm.send(&bob, &settlement, "triggerCloseOnly()", &[]);
    assert_eq!(evm.call(&settlement, "closeOnly()(bool)", &[]), "true");
    assert_eq!(
        evm.uint(&settlement, "closeOnlyBatchCount()(uint256)", &[]),
        5
    );
    assert_eq!(
        evm.uint(&settlement, "consumedDepositCount()(uint64)", &[]),
        3
    );
    assert_eq!(
        evm.call(&settlement, "acceptingDeposits()(bool)", &[]),
        "false"
    );
    evm.refuse(
        &bob,
        None,
        &vault,
        DEPOSIT_SIG,
        &late_permits[1],
        "InCloseOnly()",
    );
    evm.mine(4);
    http.health().await;
    {
        let mut gw = http.app.gw.lock().await;
        assert!(gw.deposits.l1_close_only, "finalized close-only is latched");
        assert!(!gw
            .ops_alerts
            .active()
            .contains(&ops_alerts::AlertKind::LivenessLow));
        // Only the wind-down's own windows can settle now.
        assert!(gw.begin_window_settle_mode(5, true).unwrap().is_none());
    }
    // The public state reports close-only before any wind-down has started.
    let state = http.request("GET", "/api/state", "", None, 200);
    assert_eq!(state["mode"], "CloseOnly");
    assert!(!state["opsAlerts"]
        .as_array()
        .unwrap()
        .contains(&json!("liveness_low")));
    http.authorize(&bob, usdc(1), "collateral", 409);
    let refundable = http.confirm(&alice, &late_deposit["transactionHash"], 200);
    assert_eq!(refundable["status"], "refundable");
    let row = json!({"id":3,"from":alice.hex(),"ownerCommit":late_permits[0][1],"amount":late.to_string()});
    assert_eq!(refundable["refundable"], json!([row.clone()]));
    let me = http.request("GET", "/v1/accounts/me", &alice.key, None, 200);
    assert_eq!(me["refundableDeposits"], json!([row.clone()]));
    let me = http.request("GET", "/v1/accounts/me", &bob.key, None, 200);
    assert_eq!(me["refundableDeposits"], json!([]));

    // ── Gateway offline: claims of settled withdrawals and the refund ──
    let retained: Vec<Value> = [&alice, &bob]
        .into_iter()
        .map(|user| http.request("GET", "/v1/accounts/withdrawals", &user.key, None, 200))
        .collect();
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
    assert_eq!(
        evm.uint(&vault, "refundableOutstanding()(uint256)", &[]),
        late
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
            user.hex(),
            withdrawal["amount"].as_str().unwrap().into(),
            withdrawal["nonce"].to_string(),
            withdrawal["root"].as_str().unwrap().into(),
            proof,
        ];
        let before = evm.uint(&token, "balanceOf(address)(uint256)", &[user.hex()]);
        let receipt = evm.send(
            user,
            &vault,
            "claim(address,uint256,uint256,bytes32,bytes32[])",
            &args,
        );
        let after = evm.uint(&token, "balanceOf(address)(uint256)", &[user.hex()]);
        assert_eq!(after - before, usdc(10_000));
        evm.refuse(
            user,
            None,
            &vault,
            "claim(address,uint256,uint256,bytes32,bytes32[])",
            &args,
            "AlreadyClaimed()",
        );
        claims.push(json!({"to":user.hex(),"amount":args[1],"tx":receipt["transactionHash"],"balanceAfter":after.to_string()}));
    }
    // The refund is permissionless, paid to the depositor only, from the exact leaf.
    let consumed = vec![
        "0".into(),
        operator.hex(),
        permits[0][1].clone(),
        permits[0][0].clone(),
        operator.hex(),
    ];
    evm.refuse(&bob, None, &vault, REFUND_SIG, &consumed, "NotRefundable()");
    evm.refuse(
        &bob,
        None,
        &vault,
        REFUND_SIG,
        &refund_args(late, &bob),
        "BadRefundRecipient()",
    );
    evm.refuse(
        &bob,
        None,
        &vault,
        REFUND_SIG,
        &refund_args(late + 1, &alice),
        "BadDepositPreimage()",
    );
    let before = evm.uint(&token, "balanceOf(address)(uint256)", &[alice.hex()]);
    let refund = evm.send(&bob, &vault, REFUND_SIG, &refund_args(late, &alice));
    assert_eq!(
        evm.uint(&token, "balanceOf(address)(uint256)", &[alice.hex()]) - before,
        late
    );
    evm.refuse(
        &alice,
        None,
        &vault,
        REFUND_SIG,
        &refund_args(late, &alice),
        "AlreadyRefunded()",
    );
    assert_eq!(
        evm.call(
            &vault,
            "depositRefunded(uint64)(bool)",
            std::slice::from_ref(&late_id)
        ),
        "true"
    );
    assert_eq!(
        evm.uint(&vault, "totalDeposited()(uint256)", &[]),
        usdc(70_000)
    );
    assert_eq!(
        evm.uint(&vault, "totalWithdrawn()(uint256)", &[]),
        usdc(20_000)
    );
    assert_eq!(evm.uint(&vault, "totalRefunded()(uint256)", &[]), late);
    assert_eq!(evm.uint(&vault, "refundableOutstanding()(uint256)", &[]), 0);
    assert_eq!(evm.uint(&vault, "tvl()(uint256)", &[]), usdc(30_000));
    assert_eq!(
        evm.uint(
            &token,
            "balanceOf(address)(uint256)",
            std::slice::from_ref(&vault)
        ),
        usdc(30_000)
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
        "settlementAbiVersion": 3,
        "settlementConfig": {
            "livenessTimeoutBlocks": LIVENESS_BLOCKS,
            "challengeGraceBlocks": CHALLENGE_GRACE_BLOCKS,
            "challengeBondWei": CHALLENGE_BOND_WEI.to_string(),
            "inclusionDeadlineSecs": INCLUSION_DEADLINE_SECS,
            "finalSettleGraceBlocks": FINAL_SETTLE_GRACE_BLOCKS,
            "progressBatches": PROGRESS_BATCHES,
            "slashPayoutCap": SLASH_PAYOUT_CAP.to_string()
        },
        "gatewayTransport": "real loopback HTTP",
        "restart": "encrypted snapshot and WAL restoration after mined settlement before local commit; not OS crash",
        "bond": {"amount": BOND.to_string(), "tx": bond_tx["transactionHash"], "capacityBefore": unbonded_capacity.to_string(), "capacityAfter": bonded_capacity.to_string(), "postedBeforeFirstDeposit": true},
        "deposits": deposits,
        "orders": order_hashes,
        "challenge": challenge,
        "batches": batches,
        "keepalive": keepalive,
        "claims": claims,
        "closeOnly": {"trigger": "triggerCloseOnly() by a non-operator after livenessTimeoutBlocks without progress", "tx": close_tx["transactionHash"], "closeOnlyBatchCount": 5, "consumedDepositCount": 3},
        "refund": {"depositId": 3, "from": row["from"], "amount": late.to_string(), "tx": refund["transactionHash"], "sender": "non-depositor; paid to the depositor"},
        "contracts": { "token": token, "vault": vault, "settlement": settlement, "clockVerifier": verifier },
        "syntheticWitnesses": true,
        "operatorOutageClaims": {"gatewayStoppedBeforeClaims":true,"retainedClaimData":true,"successfulClaims":2,"scope":"Previously published roots and saved proof data only; no new exit or production service loss claim"},
        "clockRegistration": "real owned-Anvil registration and adapter verification; test inner verifier; no target finality or production L1 reader claim",
        "clockPolicyMs": { "maxWindow": CLOCK_WINDOW_MS, "skew": CLOCK_SKEW_MS, "anchorTimeout": ANCHOR_TIMEOUT_MS },
        "negativeCases": [
            "settlement with a verifier that is not a clock adapter", "settlement with progressBatches outside 1..16",
            "vault that does not name the settlement", "deposit before any bond (gateway 409 and vault BondCapacityExceeded)",
            "expired permit", "missing allowance", "wrong deposit amount", "wrong permit deadline", "replayed permit",
            "deposit beyond remaining capacity (gateway 409)", "second permit over capacity at landing (BondCapacityExceeded)",
            "nonexistent deposit credited zero", "wrong order signer", "duplicate signed order",
            "challenge without the stake", "challenge naming another beneficiary", "re-opening an answered challenge",
            "bond withdrawal below the open-challenge floor", "slash of an answered challenge",
            "wrong withdrawal destination", "duplicate withdrawal authorization",
            "unsettled withdrawal claim", "invalid mock proof", "legacy proof rejected by clock adapter",
            "refund before close-only", "close-only before liveness expiry", "deposit after close-only",
            "permit after close-only (gateway 409)", "duplicate vault claim", "refund of a consumed deposit",
            "refund redirected by a third party", "refund with a wrong leaf", "duplicate refund"
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

/// Open an inclusion challenge on `receipt` with its enclave-signed kit, after
/// checking the kit against the settlement's own digest and enclave signer.
#[allow(clippy::too_many_arguments)]
fn open_challenge(
    http: &Http,
    evm: &Evm,
    settlement: &str,
    sequencer: &User,
    staker: &User,
    other: &User,
    receipt: &Value,
    enclave: &[u8; 20],
) -> Value {
    let order_hash = parse_hex32(receipt["orderHash"].as_str().unwrap()).unwrap();
    let auth = challenge_auth::ChallengeAuth {
        chain_id: CHAIN,
        settlement: http.settlement,
        order_hash,
        seq_no: receipt["seqNo"].as_u64().unwrap(),
        recv_time_ms: receipt["recvTimeMs"].as_u64().unwrap(),
        batch_id_hint: receipt["batchIdHint"].as_u64().unwrap(),
        beneficiary: staker.address,
    };
    let args = challenge_args(receipt, &staker.hex());
    assert_eq!(
        evm.call(
            settlement,
            "challengeAuthDigest(bytes32,uint64,uint64,uint64,address)(bytes32)",
            &args[..5]
        ),
        hex0x(&auth.digest())
    );
    let signature = parse_hex65(&args[5]).unwrap();
    assert_eq!(
        recover_eth_address(&auth.digest(), &signature),
        Some(*enclave)
    );
    let stake = CHALLENGE_BOND_WEI.to_string();
    evm.refuse(
        staker,
        None,
        settlement,
        CHALLENGE_SIG,
        &args,
        "WrongChallengeBond()",
    );
    evm.refuse(
        staker,
        Some(&stake),
        settlement,
        CHALLENGE_SIG,
        &challenge_args(receipt, &other.hex()),
        "BadReceiptSignature()",
    );
    let opened = evm.send_value(staker, Some(&stake), settlement, CHALLENGE_SIG, &args);
    assert_eq!(
        evm.uint(settlement, "openChallengeCount()(uint256)", &[]),
        1
    );
    // An open challenge raises the bond floor to at least one capped fine.
    let required = evm.uint(settlement, "requiredBond()(uint256)", &[]);
    let floor = required.max(SLASH_PAYOUT_CAP);
    evm.refuse(
        sequencer,
        None,
        settlement,
        "withdrawBond(uint256)",
        &[(BOND - floor + 1).to_string()],
        "WithdrawExceedsExcess()",
    );
    json!({"orderHash": args[0], "beneficiary": staker.hex(), "stakeWei": stake, "openTx": opened["transactionHash"], "openBatchCount": 1, "receipt": receipt})
}

/// Answer the open challenge from the gateway's plan, sent by a third party.
async fn answer_challenge(
    http: &Http,
    evm: &Evm,
    settlement: &str,
    staker: &User,
    third_party: &User,
    watcher: &mut challenge_scan::Watcher,
    challenge: &Value,
) -> Value {
    let plan = http.plan_answers(watcher).await;
    assert!(plan.unanswerable.is_empty());
    assert_eq!(plan.awaiting, 0);
    assert_eq!(plan.sends.len(), 1);
    let (batch_id, answers) = &plan.sends[0];
    assert_eq!(*batch_id, 1, "the order was ordered in batch 1");
    assert_eq!(answers.len(), 1);
    assert_eq!(
        hex0x(&answers[0].order_hash),
        challenge["orderHash"].as_str().unwrap()
    );
    assert!(!answers[0].by_rejection);
    let args = l1::answer_challenges_args(*batch_id, answers);
    let answered = evm.send(third_party, settlement, l1::ANSWER_CHALLENGES_SIG, &args);
    let hash = challenge["orderHash"].as_str().unwrap().to_string();
    assert_eq!(
        evm.uint(settlement, "openChallengeCount()(uint256)", &[]),
        0
    );
    assert_eq!(
        evm.call(
            settlement,
            "challengeResolved(bytes32)(bool)",
            std::slice::from_ref(&hash)
        ),
        "true"
    );
    // Answered by the batch the challenge waited for: the stake returns to the staker.
    assert_eq!(
        evm.uint(settlement, "pendingEth(address)(uint256)", &[staker.hex()]),
        CHALLENGE_BOND_WEI
    );
    evm.send(staker, settlement, "claimEthTo(address)", &[staker.hex()]);
    assert_eq!(
        evm.uint(settlement, "pendingEth(address)(uint256)", &[staker.hex()]),
        0
    );
    evm.refuse(
        third_party,
        None,
        settlement,
        "slashUnanswered(bytes32)",
        std::slice::from_ref(&hash),
        "NoSuchChallenge()",
    );
    let stake = CHALLENGE_BOND_WEI.to_string();
    evm.refuse(
        staker,
        Some(&stake),
        settlement,
        CHALLENGE_SIG,
        &[
            hash,
            "0".into(),
            "0".into(),
            "0".into(),
            staker.hex(),
            format!("0x{}", "00".repeat(65)),
        ],
        "AlreadyResolved()",
    );
    let plan = http.plan_answers(watcher).await;
    assert_eq!(plan, challenge_scan::AnswerPlan::default());
    json!({"batch": batch_id, "tx": answered["transactionHash"], "sender": "third party", "stakeReturnedTo": staker.hex()})
}
