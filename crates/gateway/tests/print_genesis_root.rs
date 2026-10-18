//! `gateway --print-genesis-root`: the production genesis state root the L1
//! settlement must be deployed with, computed from the oracle publisher (its key, or
//! only its address) and the wind-down recipient, before any L1, attestation,
//! prover or state-file access.

use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

// Two fixed test scalars that are NOT default Anvil accounts, so this mode prints a
// root for them. Test material only.
const KEY_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEY_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

// Anvil's well-known first and second development keys (#1 is the built-in dev
// oracle default): public, so this mode must refuse them even when set explicitly.
const ANVIL_0: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_1: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
// Their addresses, and two synthetic recipients that are not default accounts.
const ANVIL_0_ADDRESS: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const RECIPIENT: &str = "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
const OTHER_RECIPIENT: &str = "0xc1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";

fn run(
    args: &[&str],
    key: Option<&str>,
    recipient: Option<&str>,
    state: &std::path::Path,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateway"));
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        // A production-looking environment that must NOT be touched by this mode.
        .env("DARKPERP_PROD", "1")
        .env(
            "L1_SETTLEMENT",
            "0x0000000000000000000000000000000000000001",
        )
        // Never read by this mode.
        .env("L1_SEQUENCER_KEY", ANVIL_1)
        .env("L1_RPC", "http://127.0.0.1:9")
        .env("PROVER_URL", "http://127.0.0.1:9")
        .env("DARKPERP_STATE", state);
    if let Some(key) = key {
        command.env("ORACLE_SIGNER_KEY", key);
    }
    if let Some(recipient) = recipient {
        command.env("WIND_DOWN_RECIPIENT", recipient);
    }
    command.output().expect("run gateway binary")
}

fn line(output: &Output, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .map(str::to_owned)
        .next()
}

fn root_line(output: &Output) -> Option<String> {
    line(output, "GENESIS_ROOT")
}

fn assert_refused(output: &Output, context: &str) {
    assert_eq!(output.status.code(), Some(2), "{context}");
    assert_eq!(root_line(output), None, "{context}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("REFUSING")
            || String::from_utf8_lossy(&output.stderr).contains("usage"),
        "{context}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn scratch() -> std::path::PathBuf {
    // The tests run in parallel inside one process and the clock can repeat between
    // them (microsecond resolution on macOS), so a per-process counter keeps the
    // directory names distinct.
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "arcora-genesis-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn prints_one_deterministic_root_and_both_addresses_without_side_effects() {
    let dir = scratch();
    let state = dir.join("state.snap");
    let first = run(
        &["--print-genesis-root"],
        Some(KEY_A),
        Some(RECIPIENT),
        &state,
    );
    let second = run(
        &["--print-genesis-root"],
        Some(KEY_A),
        Some(RECIPIENT),
        &state,
    );
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let root = root_line(&first).expect("GENESIS_ROOT line");
    assert_eq!(root.len(), 66);
    assert!(root.starts_with("0x") && root[2..].bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(root_line(&second).as_deref(), Some(root.as_str()));
    assert_eq!(
        line(&first, "WIND_DOWN_RECIPIENT").as_deref(),
        Some(RECIPIENT)
    );
    let oracle = line(&first, "ORACLE_SIGNER_ADDRESS").expect("ORACLE_SIGNER_ADDRESS line");
    assert_eq!(oracle.len(), 42);
    assert_eq!(
        String::from_utf8_lossy(&first.stdout).lines().count(),
        3,
        "exactly the three deploy values"
    );
    // Nothing was written next to the configured state path.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn the_root_depends_on_the_oracle_publisher_and_the_recipient() {
    let dir = scratch();
    let a = run(
        &["--print-genesis-root"],
        Some(KEY_A),
        Some(RECIPIENT),
        &dir.join("s"),
    );
    let b = run(
        &["--print-genesis-root"],
        Some(KEY_B),
        Some(RECIPIENT),
        &dir.join("s"),
    );
    let c = run(
        &["--print-genesis-root"],
        Some(KEY_A),
        Some(OTHER_RECIPIENT),
        &dir.join("s"),
    );
    assert_ne!(root_line(&a).unwrap(), root_line(&b).unwrap());
    assert_ne!(root_line(&a).unwrap(), root_line(&c).unwrap());
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn the_address_only_mode_prints_the_same_root_as_the_key_mode() {
    let dir = scratch();
    let keyed = run(
        &["--print-genesis-root"],
        Some(KEY_A),
        Some(RECIPIENT),
        &dir.join("s"),
    );
    let oracle = line(&keyed, "ORACLE_SIGNER_ADDRESS").unwrap();
    let args = ["--print-genesis-root", "--oracle-address", oracle.as_str()];
    // No oracle key on this machine at all.
    let addressed = run(&args, None, Some(RECIPIENT), &dir.join("s"));
    assert!(
        addressed.status.success(),
        "{}",
        String::from_utf8_lossy(&addressed.stderr)
    );
    assert_eq!(addressed.stdout, keyed.stdout);
    // A configured key must sign as the given address.
    let same = run(&args, Some(KEY_A), Some(RECIPIENT), &dir.join("s"));
    assert_eq!(same.stdout, keyed.stdout);
    assert_refused(
        &run(&args, Some(KEY_B), Some(RECIPIENT), &dir.join("s")),
        "key of another publisher",
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn refuses_a_missing_zero_malformed_or_shared_recipient() {
    let dir = scratch();
    let keyed = run(
        &["--print-genesis-root"],
        Some(KEY_A),
        Some(RECIPIENT),
        &dir.join("s"),
    );
    let oracle = line(&keyed, "ORACLE_SIGNER_ADDRESS").unwrap();
    let zero = format!("0x{}", "00".repeat(20));
    for recipient in [
        None,
        Some(""),
        Some(zero.as_str()),
        Some("0x1234"),
        Some("not-an-address"),
        // Never the oracle publisher, nor a default Anvil account.
        Some(oracle.as_str()),
        Some(ANVIL_0_ADDRESS),
    ] {
        let output = run(
            &["--print-genesis-root"],
            Some(KEY_A),
            recipient,
            &dir.join("s"),
        );
        assert_refused(&output, &format!("{recipient:?}"));
    }
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn refuses_the_built_in_development_oracle_key_and_extra_arguments() {
    let dir = scratch();
    let unset = run(
        &["--print-genesis-root"],
        None,
        Some(RECIPIENT),
        &dir.join("s"),
    );
    assert_refused(&unset, "unset key");
    for args in [
        &["--print-genesis-root", "now"][..],
        &["--print-genesis-root", "--oracle-address"][..],
        &[
            "--print-genesis-root",
            "--oracle-address",
            RECIPIENT,
            "extra",
        ][..],
    ] {
        let extra = run(args, Some(KEY_A), Some(RECIPIENT), &dir.join("s"));
        assert_refused(&extra, &format!("{args:?}"));
    }
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn refuses_a_public_development_oracle_key_or_address() {
    let dir = scratch();
    for key in [ANVIL_0, ANVIL_1] {
        let output = run(
            &["--print-genesis-root"],
            Some(key),
            Some(RECIPIENT),
            &dir.join("s"),
        );
        assert_refused(&output, key);
    }
    let zero = format!("0x{}", "00".repeat(20));
    for address in [ANVIL_0_ADDRESS, zero.as_str(), "0x1234"] {
        let output = run(
            &["--print-genesis-root", "--oracle-address", address],
            None,
            Some(RECIPIENT),
            &dir.join("s"),
        );
        assert_refused(&output, address);
    }
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir(&dir).unwrap();
}
