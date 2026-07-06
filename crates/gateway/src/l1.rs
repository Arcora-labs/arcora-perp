//! Optional L1 settlement bridge (Base Sepolia / Phase 0).
//!
//! When configured, the gateway periodically advances the on-chain
//! `DarkPerpSettlement.currentStateRoot` to mirror the engine's live state root, and
//! publishes a **real cumulative withdrawals root** so users can claim **USDC** from
//! the `CollateralVault` on L1. It also confirms on-chain USDC deposits and tops up
//! the USDC sequencer bond as TVL grows.
//!
//! The only on-chain constraint with the testnet `MockZkVerifier` is
//! `prevRoot == currentStateRoot` and `proof == publicCommitment`, so the bridge
//! reads the current on-chain root live as `prev`, uses the engine root as `new`, and
//! submits. The real ZK proof replaces MockZkVerifier in a later milestone (see
//! docs/PROVING.md).
//!
//! Transport: shells out to `cast` (Foundry) — pragmatic for a testnet demo and
//! reuses the same signer path as deploy. A production bridge would use a native
//! signer (alloy) instead of a subprocess + key in argv.

use std::process::Command;

/// keccak256("Deposit(address,uint256)") — the vault's deposit log topic0.
const DEPOSIT_TOPIC0: &str = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c";

/// Per-RPC timeout handed to every `cast` invocation (bounds each JSON-RPC call).
const CAST_RPC_TIMEOUT_SECS: u64 = 15;
/// Hard wall-clock bound on a whole `cast` subprocess. `send()` holds the nonce lock
/// across the entire call (which waits for the receipt), so a wedged RPC or a receipt
/// wait that never returns would otherwise freeze settlement AND inclusion-challenge
/// answering indefinitely (risking a bond slash). On timeout the child is killed and
/// the call fails, so `send()` re-seeds the nonce from chain and the loop retries.
const CAST_WALL_TIMEOUT_SECS: u64 = 90;

/// L1 bridge configuration, read from env. `None` ⇒ L1 mode off (pure in-memory).
#[derive(Clone)]
pub struct L1 {
    pub rpc: String,
    pub settlement: String,
    /// Path to the V3 keystore encrypting the sequencer key, and to its (0600) password
    /// file. `cast` signs via `--keystore`/`--password-file`, so the raw key never enters a
    /// process argv (audit DP-013). A native in-process signer is the eventual full fix.
    keystore_path: String,
    password_file: String,
    /// RAII guard: removes the keystore temp dir when the LAST `L1` clone drops, so the
    /// on-disk key material does not persist / accumulate across restarts (DP-013 review).
    _keystore: std::sync::Arc<KeystoreDir>,
    /// USDC token (collateral asset) — needed for the bond top-up + deposit checks.
    pub usdc: Option<String>,
    /// CollateralVault — needed to read `claimed(leaf)` and match deposit logs.
    pub vault: Option<String>,
    /// Locally-tracked next transaction nonce, shared across clones. Base Sepolia's
    /// public RPC lags its `pending` nonce, so relying on cast's default nonce source
    /// makes back-to-back sends collide ("nonce too low" / "replacement underpriced"),
    /// which stalled settlement the moment a deposit made the bond non-zero. We seed
    /// from the confirmed chain nonce once, pass `--nonce` explicitly, and increment
    /// per confirmed send; the mutex is held across each send so all L1 transactions
    /// (settle loop + challenge-answer loop) serialize and never race. A failed send
    /// resets it to re-seed from chain on the next attempt.
    nonce: std::sync::Arc<std::sync::Mutex<Option<u64>>>,
}

/// What the bridge last published — surfaced to the UI so on-chain settlement is visible.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct L1Status {
    pub settled_root: String,
    pub batch_count: u64,
    pub last_tx: String,
    /// Sequencer bond, in USDC base units (the bond is USDC-denominated, audit Q1).
    pub bond: String,
    /// Cumulative withdrawals root last published to the vault (0x0 if none pending).
    pub withdrawals_root: String,
}

impl L1 {
    /// Configure from env. Requires `L1_SETTLEMENT` + `L1_SEQUENCER_KEY`; RPC defaults
    /// to Base Sepolia. `L1_USDC` + `L1_VAULT` enable the USDC bond, deposit
    /// confirmation, and withdrawal-claim pruning.
    pub fn from_env() -> Option<L1> {
        let settlement = std::env::var("L1_SETTLEMENT").ok()?;
        let key = std::env::var("L1_SEQUENCER_KEY").ok()?;
        let allow_unsafe = std::env::var("L1_ALLOW_MOCK_PROOF").ok().as_deref() == Some("1");
        let rpc = std::env::var("L1_RPC").unwrap_or_else(|_| "https://sepolia.base.org".into());
        // audit DP-007 (+ code-review): this bridge submits mock-shaped proofs (proof ==
        // publicCommitment), which only MockZkVerifier accepts, so it must run ONLY on an
        // allowlisted testnet. Skip the RPC query entirely when explicitly overridden (its
        // answer is unused). L1_CHAIN_ID is OPTIONAL: if set it must MATCH the RPC's real chain
        // (extra assurance against a proxied endpoint); if unset the guard is just the allowlist
        // on the RPC's actual chain — so upgrading without the new var no longer crashes boot.
        // The chain check runs BEFORE creating any on-disk key material, so a refusal leaks no
        // keystore, and the query retries so a transient RPC blip doesn't crash startup.
        if !allow_unsafe {
            let actual = query_chain_id_retry(&rpc);
            let declared = std::env::var("L1_CHAIN_ID")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(actual);
            if !l1_chain_ok(declared, actual, false) {
                eprintln!(
                    "[l1] REFUSING to start the settlement bridge: the RPC serves chain {actual} \
                     (declared L1_CHAIN_ID={declared}), not an allowlisted testnet this \
                     MockZkVerifier-shaped bridge may run on. Point L1_RPC at a testnet (and match \
                     L1_CHAIN_ID if set), or set L1_ALLOW_MOCK_PROOF=1 to override — UNSAFE, never \
                     on a real-value chain."
                );
                std::process::exit(1);
            }
        }
        // audit DP-013: encrypt the key into a keystore, so it never enters a cast argv.
        let (keystore_path, password_file, dir) = match create_keystore(&key) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[l1] REFUSING to start: could not create the sequencer keystore: {e}");
                std::process::exit(1);
            }
        };
        Some(L1 {
            rpc,
            settlement,
            keystore_path,
            password_file,
            _keystore: std::sync::Arc::new(KeystoreDir(dir)),
            usdc: std::env::var("L1_USDC").ok(),
            vault: std::env::var("L1_VAULT").ok(),
            nonce: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// The confirmed transaction count of the sequencer address = its next unused nonce.
    fn chain_nonce(&self) -> Result<u64, String> {
        let addr = self.sequencer_address()?;
        let out = self.cast(&["nonce", &addr, "--rpc-url", &self.rpc])?;
        out.split_whitespace()
            .next()
            .unwrap_or("")
            .parse::<u64>()
            .map_err(|e| format!("nonce parse: {e}"))
    }

    fn cast(&self, args: &[&str]) -> Result<String, String> {
        use std::io::Read;
        // Spawn with piped output and a hard wall-clock deadline: a black-hole RPC must
        // not hang forever holding the nonce lock (see CAST_WALL_TIMEOUT_SECS). ETH_RPC_
        // TIMEOUT additionally bounds each individual JSON-RPC call.
        let mut child = Command::new("cast")
            .args(args)
            .env("ETH_RPC_TIMEOUT", CAST_RPC_TIMEOUT_SECS.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("cast spawn failed (is Foundry installed?): {e}"))?;
        // Drain stdout/stderr on their OWN threads: a large child output (e.g. a
        // `cast logs --json` over many events) can exceed the ~64KB OS pipe buffer, and
        // if we only polled try_wait() without reading, the child would block on write()
        // and never exit — a deadlock until the kill deadline. Concurrent readers keep
        // the pipes drained so the child can always make progress and exit.
        let mut stdout_pipe = child.stdout.take().ok_or("cast: no stdout pipe")?;
        let mut stderr_pipe = child.stderr.take().ok_or("cast: no stderr pipe")?;
        let out_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout_pipe.read_to_end(&mut buf);
            buf
        });
        let err_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut buf);
            buf
        });
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(CAST_WALL_TIMEOUT_SECS);
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        // killing closes the pipes, so the readers unblock and finish
                        let _ = out_reader.join();
                        let _ = err_reader.join();
                        return Err(format!(
                            "cast timed out after {CAST_WALL_TIMEOUT_SECS}s (RPC wedged)"
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(format!("cast wait failed: {e}")),
            }
        };
        let stdout = out_reader.join().unwrap_or_default();
        let stderr = err_reader.join().unwrap_or_default();
        if !status.success() {
            return Err(String::from_utf8_lossy(&stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&stdout).trim().to_string())
    }

    /// `cast send <target> <sig> [args..]` signed by the sequencer key, returning the tx hash.
    ///
    /// Holds the shared nonce lock across the whole send (which waits for the receipt),
    /// so every L1 transaction serializes and gets an explicit, monotonic `--nonce` —
    /// immune to the public RPC's lagging `pending` nonce (see the `nonce` field). A
    /// failed send resets the tracker so the next attempt re-seeds from the chain.
    fn send(&self, target: &str, sig: &str, args: &[&str]) -> Result<String, String> {
        let mut guard = self.nonce.lock().map_err(|_| "nonce lock poisoned")?;
        let n = match *guard {
            Some(n) => n,
            None => self.chain_nonce()?,
        };
        let nonce_str = n.to_string();
        let mut a: Vec<&str> = vec!["send", target, sig];
        a.extend_from_slice(args);
        // audit DP-013: authenticate via the encrypted keystore + password FILE, never the
        // raw key in argv. Both are file paths — the key never appears in /proc/<pid>/cmdline.
        a.extend_from_slice(&[
            "--nonce",
            &nonce_str,
            "--keystore",
            &self.keystore_path,
            "--password-file",
            &self.password_file,
            "--rpc-url",
            &self.rpc,
            "--json",
        ]);
        match self.cast(&a) {
            Ok(out) => {
                *guard = Some(n + 1);
                Ok(tx_hash(&out))
            }
            Err(e) => {
                *guard = None; // re-seed from chain next time
                Err(e)
            }
        }
    }

    /// Explicitly remove the keystore temp dir (encrypted key + 0600 password file) NOW.
    /// The RAII `Drop` on `KeystoreDir` only fires when the last `L1` clone drops on a
    /// NORMAL return, but the gateway exits via `std::process::exit` from its signal
    /// handler — which skips destructors — so the shutdown path must call this or the key
    /// material persists in $TMPDIR and accumulates one dir per restart (audit #6 /
    /// DP-013 review).
    pub fn cleanup_keystore(&self) {
        let _ = std::fs::remove_dir_all(&self._keystore.0);
    }

    /// The on-chain `currentStateRoot` (the required `prev` for the next settle).
    pub fn current_root(&self) -> Result<String, String> {
        self.cast(&[
            "call",
            &self.settlement,
            "currentStateRoot()(bytes32)",
            "--rpc-url",
            &self.rpc,
        ])
    }

    fn read_u(&self, sig: &str) -> Result<u128, String> {
        let s = self.cast(&["call", &self.settlement, sig, "--rpc-url", &self.rpc])?;
        // cast may print "0" or "0 [0e0]" — take the leading integer token.
        s.split_whitespace()
            .next()
            .unwrap_or("0")
            .parse::<u128>()
            .map_err(|e| format!("parse {sig}: {e}"))
    }

    pub fn sequencer_bond(&self) -> Result<u128, String> {
        self.read_u("sequencerBond()(uint256)")
    }
    pub fn required_bond(&self) -> Result<u128, String> {
        self.read_u("requiredBond()(uint256)")
    }
    pub fn batch_count(&self) -> Result<u64, String> {
        self.read_u("batchCount()(uint256)").map(|v| v as u64)
    }

    /// The sequencer key's address (the `cast wallet` derivation; no key is printed).
    fn sequencer_address(&self) -> Result<String, String> {
        self.cast(&[
            "wallet",
            "address",
            "--keystore",
            &self.keystore_path,
            "--password-file",
            &self.password_file,
        ])
    }

    /// Ensure the USDC sequencer bond covers `requiredBond()` plus headroom. On the
    /// testnet MockUSDC faucet this mints what's short to the sequencer, approves the
    /// settlement, and `postBond`s it. Returns the postBond tx hash if it topped up.
    /// USDC-denominated so the posted bond shares a unit with the 5%-of-TVL floor (Q1).
    pub fn ensure_bond(&self) -> Result<Option<String>, String> {
        let usdc = self.usdc.as_ref().ok_or("L1_USDC not set")?;
        let req = self.required_bond()?;
        // No TVL yet ⇒ no bond required ⇒ post nothing. Forcing a floor here made the
        // bridge re-`mint` every tick while the previous mint was still pending, colliding
        // on the same nonce ("replacement transaction underpriced") — spurious churn that
        // only ever *needs* to run once a deposit makes `requiredBond > 0`.
        if req == 0 {
            return Ok(None);
        }
        let have = self.sequencer_bond()?;
        // target a 2x-floor cushion so TVL growth between settles stays covered.
        let target = req.saturating_add(req);
        if have >= target {
            return Ok(None);
        }
        let short = (target - have).to_string();
        let seq = self.sequencer_address()?;
        self.send(usdc, "mint(address,uint256)", &[&seq, &short])?;
        self.send(
            usdc,
            "approve(address,uint256)",
            &[&self.settlement, &short],
        )?;
        let tx = self.send(&self.settlement.clone(), "postBond(uint256)", &[&short])?;
        Ok(Some(tx))
    }

    /// Has the vault already paid out this withdrawal leaf? Used to prune claimed
    /// leaves from the cumulative root (the prover-side invariant on the vault).
    pub fn claimed(&self, leaf: &str) -> Result<bool, String> {
        let vault = self.vault.as_ref().ok_or("L1_VAULT not set")?;
        let out = self.cast(&[
            "call",
            vault,
            "claimed(bytes32)(bool)",
            leaf,
            "--rpc-url",
            &self.rpc,
        ])?;
        Ok(out.trim() == "true")
    }

    /// Verify a confirmed `vault.deposit` tx and return `(from20, amount)`: scan the
    /// receipt for a `Deposit(from, amount)` log emitted by the configured vault. The
    /// caller binds `from` to the account and dedups by tx hash before crediting.
    pub fn verify_deposit_tx(&self, tx: &str) -> Result<([u8; 20], u128), String> {
        let vault = self
            .vault
            .as_ref()
            .ok_or("L1_VAULT not set")?
            .to_lowercase();
        let json = self.cast(&["receipt", tx, "--rpc-url", &self.rpc, "--json"])?;
        let v: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| format!("receipt json: {e}"))?;
        let logs = v
            .get("logs")
            .and_then(|l| l.as_array())
            .ok_or("no logs in receipt")?;
        for log in logs {
            let addr = log
                .get("address")
                .and_then(|a| a.as_str())
                .unwrap_or("")
                .to_lowercase();
            let topics = log.get("topics").and_then(|t| t.as_array());
            let (Some(topics), true) = (topics, addr == vault) else {
                continue;
            };
            let t0 = topics.first().and_then(|t| t.as_str()).unwrap_or("");
            if !t0.eq_ignore_ascii_case(DEPOSIT_TOPIC0) || topics.len() < 2 {
                continue;
            }
            // from = indexed topic1 (last 20 bytes); amount = data (uint256)
            let from_hex = topics[1].as_str().unwrap_or("");
            let from = parse_addr20(from_hex).ok_or("bad from topic")?;
            let data = log.get("data").and_then(|d| d.as_str()).unwrap_or("");
            let amount = parse_u256_low128(data).ok_or("bad amount data")?;
            return Ok((from, amount));
        }
        Err("no Deposit log from the vault in this tx".into())
    }

    /// Settle: advance the on-chain root from `prev` to `new` with `manifest`, and publish the
    /// cumulative `withdrawals` root (so users can claim USDC) plus this batch's `ordered` and
    /// `rejected` order-hash roots — so the sequencer can answer an inclusion challenge for an
    /// order it either matched (`answerChallenge`) or validly rejected (`answerByRejection`),
    /// audit DP-004. The proof is the 32-byte public commitment itself (what MockZkVerifier checks).
    pub fn settle(
        &self,
        prev: &str,
        manifest: &str,
        new: &str,
        ordered: &str,
        withdrawals: &str,
        rejected: &str,
    ) -> Result<String, String> {
        let commitment = self.cast(&[
            "call",
            &self.settlement,
            "publicCommitment(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)(bytes32)",
            prev,
            manifest,
            new,
            ordered,
            withdrawals,
            rejected,
            "--rpc-url",
            &self.rpc,
        ])?;
        self.send(
            &self.settlement.clone(),
            "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes)",
            &[
                prev,
                manifest,
                new,
                ordered,
                withdrawals,
                rejected,
                &commitment,
            ],
        )
    }

    // ── inclusion-challenge answering (audit DP-004) ─────────────────────────────

    /// The current block number — the answering loop starts watching from here, skipping history.
    pub fn block_number(&self) -> Result<u64, String> {
        self.cast(&["block-number", "--rpc-url", &self.rpc])?
            .split_whitespace()
            .next()
            .unwrap_or("")
            .parse::<u64>()
            .map_err(|e| format!("block-number parse: {e}"))
    }

    /// The on-chain inclusion-challenge window in blocks (`challengeWindowBlocks`, a
    /// public immutable). A challenge is answerable only within this many blocks of
    /// being raised, so the watcher rewinds this far on boot to catch challenges raised
    /// while the gateway was down (audit #8).
    pub fn challenge_window_blocks(&self) -> Result<u64, String> {
        self.cast(&[
            "call",
            &self.settlement,
            "challengeWindowBlocks()(uint256)",
            "--rpc-url",
            &self.rpc,
        ])?
        // cast may render a uint as "300" or "300 [3e2]"; take the leading integer.
        .split_whitespace()
        .next()
        .unwrap_or("")
        .parse::<u64>()
        .map_err(|e| format!("challengeWindowBlocks parse: {e}"))
    }

    /// Order hashes with an `InclusionChallenged` log at/after `from_block`, plus the block to
    /// resume from next. The order hash is the first indexed topic.
    pub fn fetch_challenges(&self, from_block: u64) -> Result<(Vec<String>, u64), String> {
        let from = from_block.to_string();
        let out = self.cast(&[
            "logs",
            "--from-block",
            &from,
            "--address",
            &self.settlement,
            "InclusionChallenged(bytes32,address,uint256)",
            "--rpc-url",
            &self.rpc,
            "--json",
        ])?;
        let logs: serde_json::Value =
            serde_json::from_str(&out).map_err(|e| format!("logs json: {e}"))?;
        let mut hashes = Vec::new();
        let mut next = from_block;
        if let Some(arr) = logs.as_array() {
            for log in arr {
                if let Some(t1) = log
                    .get("topics")
                    .and_then(|t| t.as_array())
                    .and_then(|t| t.get(1))
                    .and_then(|t| t.as_str())
                {
                    hashes.push(t1.to_string());
                }
                if let Some(bn) = log.get("blockNumber").and_then(|b| b.as_str()) {
                    if let Ok(n) = u64::from_str_radix(bn.trim_start_matches("0x"), 16) {
                        next = next.max(n + 1);
                    }
                }
            }
        }
        Ok((hashes, next))
    }

    /// Is this order's inclusion challenge still open (not yet answered or slashed)? The
    /// `Challenge` tuple's last field is `open`.
    pub fn challenge_open(&self, order_hash: &str) -> Result<bool, String> {
        let out = self.cast(&[
            "call",
            &self.settlement,
            "challenges(bytes32)(address,uint64,uint256,uint256,uint256,bool)",
            order_hash,
            "--rpc-url",
            &self.rpc,
        ])?;
        Ok(out.split_whitespace().last() == Some("true"))
    }

    /// Answer an inclusion challenge: prove the order is in this batch's ordered root (matched,
    /// `answerChallenge`) or rejected root (validly rejected, `answerByRejection`) — audit DP-004.
    pub fn answer_challenge(
        &self,
        order_hash: &str,
        batch_id: u64,
        proof: &[[u8; 32]],
        by_rejection: bool,
    ) -> Result<String, String> {
        let sig = if by_rejection {
            "answerByRejection(bytes32,uint256,bytes32[])"
        } else {
            "answerChallenge(bytes32,uint256,bytes32[])"
        };
        let bid = batch_id.to_string();
        let proof_arg = format!(
            "[{}]",
            proof.iter().map(hex0x32).collect::<Vec<_>>().join(",")
        );
        self.send(
            &self.settlement.clone(),
            sig,
            &[order_hash, &bid, &proof_arg],
        )
    }
}

/// A 32-byte value as `0x`+64 hex, for cast calldata.
fn hex0x32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Chain ids this bridge may settle against. It submits mock-shaped proofs
/// (`proof == publicCommitment`), which only `MockZkVerifier` accepts, so running
/// it against a real-value chain is catastrophic (audit DP-007). Testnets are
/// allowlisted; anything else requires an explicit unsafe override.
///
/// KEEP IN SYNC with `DeployGuard.isTestnet` (contracts/script/DeployGuard.sol) — Solidity
/// can't call this, so the two allowlists are maintained by hand and must not drift.
pub fn l1_chain_allowed(chain_id: u64, allow_unsafe: bool) -> bool {
    if allow_unsafe {
        return true;
    }
    matches!(
        chain_id,
        84532        // Base Sepolia
        | 11155111   // Sepolia
        | 421614     // Arbitrum Sepolia
        | 11155420   // OP Sepolia
        | 80002      // Polygon Amoy
        | 31337      // anvil / hardhat
        | 1337 // ganache
    )
}

/// Whether the bridge may run against the RPC's chain: the operator-declared `L1_CHAIN_ID`
/// must EQUAL the chain the RPC actually serves AND be an allowlisted testnet. Trusting the
/// declared id alone let an operator point `L1_RPC` at mainnet while declaring a testnet and
/// still submit mock-shaped proofs (audit DP-007 follow-up). `allow_unsafe` overrides.
pub fn l1_chain_ok(declared: u64, actual: u64, allow_unsafe: bool) -> bool {
    if allow_unsafe {
        return true;
    }
    // `actual == 0` means the RPC chain id was unresolved (unreachable / parse fail) — fail
    // closed. Otherwise require the declared id to match ground truth AND be allowlisted.
    actual != 0 && declared == actual && l1_chain_allowed(actual, false)
}

/// Encrypt `key_hex` (a 32-byte secp256k1 scalar) into a fresh V3 keystore plus a 0600
/// password file, so `cast` can sign via `--keystore`/`--password-file` and the raw key
/// never enters any process argv (audit DP-013). Returns (keystore_path, password_file).
/// RAII guard that removes the keystore temp dir on drop (audit DP-013 review — otherwise
/// the encrypted key + password persist in $TMPDIR and accumulate one dir per restart).
struct KeystoreDir(std::path::PathBuf);
impl Drop for KeystoreDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The chain id the RPC serves — a free function (no keystore) so it can be checked BEFORE
/// any on-disk key material is created, and so a refusal leaks nothing (DP-007/DP-013 review).
fn query_chain_id(rpc: &str) -> Result<u64, String> {
    let out = Command::new("cast")
        .args(["chain-id", "--rpc-url", rpc])
        .env("ETH_RPC_TIMEOUT", "15") // bound the startup stall on a black-hole RPC
        .output()
        .map_err(|e| format!("cast spawn failed (is Foundry installed?): {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .parse::<u64>()
        .map_err(|e| format!("chain-id parse: {e}"))
}

/// `query_chain_id` with a few retries, so a TRANSIENT RPC blip at startup does not crash the
/// whole gateway (code-review follow-up). Returns 0 if the chain stays unresolved — which the
/// caller treats as fail-closed. Runs before the async server binds, so a brief block is fine.
fn query_chain_id_retry(rpc: &str) -> u64 {
    for attempt in 0..3 {
        match query_chain_id(rpc) {
            Ok(id) => return id,
            Err(e) => {
                eprintln!("[l1] chain-id query attempt {} failed: {e}", attempt + 1);
                if attempt < 2 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        }
    }
    0
}

fn create_keystore(key_hex: &str) -> Result<(String, String, std::path::PathBuf), String> {
    use std::io::Write as _;
    let raw = key_hex.strip_prefix("0x").unwrap_or(key_hex).trim();
    if raw.len() != 64 {
        return Err("L1_SEQUENCER_KEY must be a 32-byte hex secp256k1 scalar".into());
    }
    // Byte-safe nibble parse (same posture as main.rs `decode_hex`): a non-ASCII
    // byte in the env var errors cleanly instead of a mid-codepoint slice panic.
    let raw = raw.as_bytes();
    let mut pk = [0u8; 32];
    for (i, slot) in pk.iter_mut().enumerate() {
        *slot = match (crate::hex_nibble(raw[i * 2]), crate::hex_nibble(raw[i * 2 + 1])) {
            (Some(hi), Some(lo)) => hi << 4 | lo,
            _ => return Err("bad key hex".into()),
        };
    }
    // a random keystore password (kept only in memory + a 0600 file, never in argv)
    let mut pw = [0u8; 32];
    getrandom::getrandom(&mut pw).map_err(|e| format!("rng: {e}"))?;
    let password: String = pw.iter().map(|b| format!("{b:02x}")).collect();

    // An UNPREDICTABLE, owner-only (0700), atomically-created directory: a random name (not
    // the pid) plus a non-recursive create that FAILS if the path already exists, so an
    // attacker cannot pre-plant a symlink or a readable dir at a guessable path.
    let mut rnd = [0u8; 16];
    getrandom::getrandom(&mut rnd).map_err(|e| format!("rng: {e}"))?;
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("darkperp-keystore-{suffix}"));
    {
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            b.mode(0o700);
        }
        b.create(&dir).map_err(|e| format!("keystore dir: {e}"))?;
    }

    // encrypt_key writes the file to `dir/<name>` but RETURNS the uuid, so build the path
    // from the fixed name we chose, not the return value.
    let ksname = "sequencer";
    eth_keystore::encrypt_key(&dir, &mut rand::rngs::OsRng, pk, &password, Some(ksname))
        .map_err(|e| format!("encrypt keystore: {e}"))?;
    let keystore_path = dir.join(ksname);

    // Password file: create_new + 0600 in one step, so it is never briefly world-readable
    // and cannot follow an attacker-planted symlink (create_new fails if the path exists).
    let pw_path = dir.join("password");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&pw_path)
        .map_err(|e| format!("password file: {e}"))?;
    f.write_all(password.as_bytes())
        .map_err(|e| format!("password write: {e}"))?;

    // The keystore file lives inside the 0700 dir (already unreadable by other users);
    // tighten it to 0600 as defense in depth.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&keystore_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((
        keystore_path.to_string_lossy().into_owned(),
        pw_path.to_string_lossy().into_owned(),
        dir,
    ))
}

/// Pull `transactionHash` out of `cast send --json` output (falls back to raw).
fn tx_hash(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| {
            v.get("transactionHash")
                .and_then(|h| h.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| json.lines().next().unwrap_or("").to_string())
}

/// Parse a 32-byte-padded hex topic into the low 20 bytes (an address).
/// Byte-safe: RPC log topics are external data, so a non-ASCII byte returns a
/// clean `None` (never a mid-codepoint `&str` slice panic).
fn parse_addr20(s: &str) -> Option<[u8; 20]> {
    let h = s.strip_prefix("0x").unwrap_or(s).as_bytes();
    if h.len() < 40 {
        return None;
    }
    let start = h.len() - 40;
    let mut a = [0u8; 20];
    for (i, slot) in a.iter_mut().enumerate() {
        *slot = crate::hex_nibble(h[start + i * 2])? << 4 | crate::hex_nibble(h[start + i * 2 + 1])?;
    }
    Some(a)
}

/// Parse a uint256 hex word into u128 (USDC amounts fit comfortably); rejects overflow.
/// Byte-safe: operates on bytes (RPC data is external), so a non-ASCII byte returns a
/// clean `None` instead of a mid-codepoint `&str` slice panic.
fn parse_u256_low128(s: &str) -> Option<u128> {
    let h = s.strip_prefix("0x").unwrap_or(s).trim().as_bytes();
    if h.is_empty() {
        return None;
    }
    // Right-align into a 64-nibble window (matching the old zero-pad/truncate):
    // everything above the low 32 nibbles must be '0' (no overflow of a real
    // USDC amount), and the low 32 nibbles parse as the u128.
    let window = if h.len() > 64 { &h[h.len() - 64..] } else { h };
    let (high, low) = if window.len() > 32 {
        window.split_at(window.len() - 32)
    } else {
        (&[][..], window)
    };
    if high.iter().any(|&b| b != b'0') {
        return None;
    }
    let mut v: u128 = 0;
    for &b in low {
        v = v << 4 | u128::from(crate::hex_nibble(b)?);
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    // audit DP-007: the mock-proof bridge may only settle against testnets; real-value
    // chains are refused unless the operator explicitly opts into the unsound verifier.
    #[test]
    fn mock_proof_bridge_allows_testnets_and_refuses_real_chains() {
        // testnets the bridge may run against
        assert!(l1_chain_allowed(84532, false), "Base Sepolia allowed");
        assert!(l1_chain_allowed(11155111, false), "Sepolia allowed");
        assert!(l1_chain_allowed(31337, false), "anvil allowed");
        // real-value chains are refused (a mock proof there would drain the vault)
        assert!(!l1_chain_allowed(1, false), "Ethereum mainnet refused");
        assert!(!l1_chain_allowed(8453, false), "Base mainnet refused");
        assert!(!l1_chain_allowed(0, false), "unset/unknown chain refused");
        // an explicit unsafe override lifts the guard (the operator's informed choice)
        assert!(l1_chain_allowed(1, true), "override allows any chain");
    }

    // audit DP-007 follow-up: the declared L1_CHAIN_ID must match the chain the RPC
    // actually serves — declaring a testnet while pointing the RPC at mainnet is the bypass.
    #[test]
    fn bridge_cross_checks_declared_chain_against_the_rpc() {
        assert!(
            l1_chain_ok(84532, 84532, false),
            "declared == RPC testnet is allowed"
        );
        assert!(
            !l1_chain_ok(84532, 8453, false),
            "declared testnet but RPC is Base mainnet is refused"
        );
        assert!(
            !l1_chain_ok(8453, 8453, false),
            "a matched mainnet is still refused"
        );
        assert!(
            !l1_chain_ok(84532, 0, false),
            "an unresolved RPC chain fails closed"
        );
        assert!(l1_chain_ok(8453, 8453, true), "override allows any chain");
    }

    // audit DP-013: the sequencer key is encrypted into a keystore that cast reads via file
    // paths, so no `cast` command carries the raw key in argv (L1 no longer even stores it).
    // Verify the keystore actually round-trips the key (so cast can sign with it).
    #[test]
    fn keystore_roundtrips_the_sequencer_key() {
        let key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let (ks, pw, _dir) = create_keystore(key).expect("keystore created");
        let password = std::fs::read_to_string(&pw).expect("password file");
        let decrypted = eth_keystore::decrypt_key(&ks, password.trim()).expect("keystore decrypts");
        let mut expected = [0u8; 32];
        for (i, s) in expected.iter_mut().enumerate() {
            *s = u8::from_str_radix(&key[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(
            decrypted.as_slice(),
            &expected[..],
            "keystore round-trips the sequencer key"
        );
        let _ = std::fs::remove_dir_all(std::path::Path::new(&ks).parent().unwrap());
    }

    /// Byte-safety regression (pre-merge hygiene): non-ASCII input to the L1 hex
    /// parsers must fail CLEANLY. A 2-byte UTF-8 char at an odd byte offset used to
    /// make the old `&str`-slice loops panic mid-codepoint; the keystore key comes
    /// from an env var and the topic/amount parsers eat external RPC data.
    #[test]
    fn l1_hex_parsers_reject_non_ascii_without_panic() {
        // 64 BYTES with é straddling the first nibble-pair slice boundary.
        let bad_key = format!("aé{}", "a".repeat(61));
        assert!(create_keystore(&bad_key).is_err(), "bad key hex must be a clean Err");
        // 40-byte topic tail with the same straddle → clean None.
        let bad_topic = format!("aé{}", "a".repeat(37));
        assert_eq!(parse_addr20(&bad_topic), None);
        // amount word: non-ASCII in the low 32 nibbles → clean None.
        let bad_amount = format!("{}aé{}", "0".repeat(33), "0".repeat(29));
        assert_eq!(parse_u256_low128(&bad_amount), None);
        // sane inputs still parse.
        assert_eq!(
            parse_addr20(&format!("0x{}{}", "00".repeat(12), "ab".repeat(20))),
            Some([0xab; 20]),
        );
        assert_eq!(parse_u256_low128("0x0de0b6b3a7640000"), Some(1_000_000_000_000_000_000));
    }
}
