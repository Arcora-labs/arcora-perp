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

const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
/// keccak256("Deposit(address,uint256)") — the vault's deposit log topic0.
const DEPOSIT_TOPIC0: &str = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c";

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
    /// USDC token (collateral asset) — needed for the bond top-up + deposit checks.
    pub usdc: Option<String>,
    /// CollateralVault — needed to read `claimed(leaf)` and match deposit logs.
    pub vault: Option<String>,
}

/// What the bridge last published — surfaced to the UI so on-chain settlement is visible.
#[derive(Clone, Default)]
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
        // audit DP-007: this bridge submits mock-shaped proofs (proof == publicCommitment),
        // which only MockZkVerifier accepts. Refuse to settle against a real-value chain
        // unless the operator declares an allowlisted testnet (or explicitly overrides).
        let chain_id: u64 = std::env::var("L1_CHAIN_ID")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let allow_unsafe = std::env::var("L1_ALLOW_MOCK_PROOF").ok().as_deref() == Some("1");
        // audit DP-013: encrypt the key into a keystore now, so it never enters a cast argv.
        let (keystore_path, password_file) = match create_keystore(&key) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[l1] REFUSING to start: could not create the sequencer keystore: {e}");
                std::process::exit(1);
            }
        };
        let l1 = L1 {
            rpc: std::env::var("L1_RPC").unwrap_or_else(|_| "https://sepolia.base.org".into()),
            settlement,
            keystore_path,
            password_file,
            usdc: std::env::var("L1_USDC").ok(),
            vault: std::env::var("L1_VAULT").ok(),
        };
        // Cross-check the DECLARED chain id against the one the RPC actually serves — the
        // declared value alone is spoofable (declare a testnet, point L1_RPC at mainnet).
        let actual = l1.chain_id().unwrap_or(0);
        if !l1_chain_ok(chain_id, actual, allow_unsafe) {
            eprintln!(
                "[l1] REFUSING to start the settlement bridge: declared L1_CHAIN_ID={chain_id} but \
                 the RPC serves chain {actual}, and this bridge only submits MockZkVerifier-shaped \
                 proofs. Set L1_CHAIN_ID to the RPC's real (allowlisted testnet) id, or \
                 L1_ALLOW_MOCK_PROOF=1 to override — UNSAFE, never on a real-value chain."
            );
            std::process::exit(1);
        }
        Some(l1)
    }

    /// The chain id the configured RPC actually serves (ground truth for the DP-007 guard).
    pub fn chain_id(&self) -> Result<u64, String> {
        self.cast(&["chain-id", "--rpc-url", &self.rpc])?
            .split_whitespace()
            .next()
            .unwrap_or("")
            .parse::<u64>()
            .map_err(|e| format!("chain-id parse: {e}"))
    }

    fn cast(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new("cast")
            .args(args)
            .output()
            .map_err(|e| format!("cast spawn failed (is Foundry installed?): {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// `cast send <target> <sig> [args..]` signed by the sequencer key, returning the tx hash.
    fn send(&self, target: &str, sig: &str, args: &[&str]) -> Result<String, String> {
        let mut a: Vec<&str> = vec!["send", target, sig];
        a.extend_from_slice(args);
        // audit DP-013: authenticate via the encrypted keystore + password FILE, never the
        // raw key in argv. Both are file paths — the key never appears in /proc/<pid>/cmdline.
        a.extend_from_slice(&[
            "--keystore",
            &self.keystore_path,
            "--password-file",
            &self.password_file,
            "--rpc-url",
            &self.rpc,
            "--json",
        ]);
        let out = self.cast(&a)?;
        Ok(tx_hash(&out))
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
        let have = self.sequencer_bond()?;
        // target a 2x-floor cushion (min 1 USDC) so TVL growth between settles is covered.
        let target = req.saturating_add(req.max(1_000_000));
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

    /// Settle: advance the on-chain root from `prev` to `new` with `manifest`, and
    /// publish the cumulative `withdrawals` root (so users can claim USDC). The
    /// `ordered` root stays `0x0` (the inclusion-challenge tree is a separate user
    /// path). The proof is the 32-byte public commitment itself (what MockZkVerifier
    /// checks).
    pub fn settle(
        &self,
        prev: &str,
        manifest: &str,
        new: &str,
        withdrawals: &str,
    ) -> Result<String, String> {
        let commitment = self.cast(&[
            "call",
            &self.settlement,
            "publicCommitment(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)(bytes32)",
            prev,
            manifest,
            new,
            ZERO32,
            withdrawals,
            ZERO32,
            "--rpc-url",
            &self.rpc,
        ])?;
        self.send(
            &self.settlement.clone(),
            "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes)",
            &[prev, manifest, new, ZERO32, withdrawals, ZERO32, &commitment],
        )
    }
}

/// Chain ids this bridge may settle against. It submits mock-shaped proofs
/// (`proof == publicCommitment`), which only `MockZkVerifier` accepts, so running
/// it against a real-value chain is catastrophic (audit DP-007). Testnets are
/// allowlisted; anything else requires an explicit unsafe override.
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
fn create_keystore(key_hex: &str) -> Result<(String, String), String> {
    use std::io::Write as _;
    let raw = key_hex.strip_prefix("0x").unwrap_or(key_hex).trim();
    if raw.len() != 64 {
        return Err("L1_SEQUENCER_KEY must be a 32-byte hex secp256k1 scalar".into());
    }
    let mut pk = [0u8; 32];
    for (i, slot) in pk.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).map_err(|_| "bad key hex")?;
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
    let mut f = opts.open(&pw_path).map_err(|e| format!("password file: {e}"))?;
    f.write_all(password.as_bytes()).map_err(|e| format!("password write: {e}"))?;

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
fn parse_addr20(s: &str) -> Option<[u8; 20]> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() < 40 {
        return None;
    }
    let start = h.len() - 40;
    let mut a = [0u8; 20];
    for (i, slot) in a.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&h[start + i * 2..start + i * 2 + 2], 16).ok()?;
    }
    Some(a)
}

/// Parse a uint256 hex word into u128 (USDC amounts fit comfortably); rejects overflow.
fn parse_u256_low128(s: &str) -> Option<u128> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    let h = h.trim();
    if h.is_empty() {
        return None;
    }
    // high bytes beyond 16 must be zero (no overflow of a real USDC amount)
    let hex = if h.len() <= 64 {
        format!("{:0>64}", h)
    } else {
        h[h.len() - 64..].to_string()
    };
    if hex[..32].chars().any(|c| c != '0') {
        return None;
    }
    u128::from_str_radix(&hex[32..], 16).ok()
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
        assert!(l1_chain_ok(84532, 84532, false), "declared == RPC testnet is allowed");
        assert!(!l1_chain_ok(84532, 8453, false), "declared testnet but RPC is Base mainnet is refused");
        assert!(!l1_chain_ok(8453, 8453, false), "a matched mainnet is still refused");
        assert!(!l1_chain_ok(84532, 0, false), "an unresolved RPC chain fails closed");
        assert!(l1_chain_ok(8453, 8453, true), "override allows any chain");
    }

    // audit DP-013: the sequencer key is encrypted into a keystore that cast reads via file
    // paths, so no `cast` command carries the raw key in argv (L1 no longer even stores it).
    // Verify the keystore actually round-trips the key (so cast can sign with it).
    #[test]
    fn keystore_roundtrips_the_sequencer_key() {
        let key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let (ks, pw) = create_keystore(key).expect("keystore created");
        let password = std::fs::read_to_string(&pw).expect("password file");
        let decrypted = eth_keystore::decrypt_key(&ks, password.trim()).expect("keystore decrypts");
        let mut expected = [0u8; 32];
        for (i, s) in expected.iter_mut().enumerate() {
            *s = u8::from_str_radix(&key[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(decrypted.as_slice(), &expected[..], "keystore round-trips the sequencer key");
        let _ = std::fs::remove_dir_all(std::path::Path::new(&ks).parent().unwrap());
    }
}
