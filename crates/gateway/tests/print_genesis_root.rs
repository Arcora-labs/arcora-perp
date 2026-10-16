//! `gateway --print-genesis-root`: the production genesis state root the L1
//! settlement must be deployed with, computed from the oracle publisher key
//! alone, before any L1, attestation, prover or state-file access.

use std::process::{Command, Output};

// Anvil's well-known first and second development keys: public test material.
const KEY_A: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const KEY_B: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

fn run(args: &[&str], key: Option<&str>, state: &std::path::Path) -> Output {
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
        .env("L1_SEQUENCER_KEY", KEY_B)
        .env("L1_RPC", "http://127.0.0.1:9")
        .env("PROVER_URL", "http://127.0.0.1:9")
        .env("DARKPERP_STATE", state);
    if let Some(key) = key {
        command.env("ORACLE_SIGNER_KEY", key);
    }
    command.output().expect("run gateway binary")
}

fn root_line(output: &Output) -> Option<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix("GENESIS_ROOT="))
        .map(str::to_owned)
        .next()
}

fn scratch() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "arcora-genesis-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn prints_one_deterministic_root_without_side_effects() {
    let dir = scratch();
    let state = dir.join("state.snap");
    let first = run(&["--print-genesis-root"], Some(KEY_A), &state);
    let second = run(&["--print-genesis-root"], Some(KEY_A), &state);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let root = root_line(&first).expect("GENESIS_ROOT line");
    assert_eq!(root.len(), 66);
    assert!(root.starts_with("0x") && root[2..].bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(root_line(&second).as_deref(), Some(root.as_str()));
    // The existing boot log line carries the same value.
    assert!(String::from_utf8_lossy(&first.stdout).contains(&format!("genesis engine root {root}")));
    // Nothing was written next to the configured state path.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn the_root_depends_on_the_oracle_publisher_key() {
    let dir = scratch();
    let a = run(&["--print-genesis-root"], Some(KEY_A), &dir.join("s"));
    let b = run(&["--print-genesis-root"], Some(KEY_B), &dir.join("s"));
    assert_ne!(root_line(&a).unwrap(), root_line(&b).unwrap());
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn refuses_the_built_in_development_oracle_key_and_extra_arguments() {
    let dir = scratch();
    let unset = run(&["--print-genesis-root"], None, &dir.join("s"));
    assert!(!unset.status.success());
    assert_eq!(root_line(&unset), None);
    let extra = run(
        &["--print-genesis-root", "now"],
        Some(KEY_A),
        &dir.join("s"),
    );
    assert!(!extra.status.success());
    assert_eq!(root_line(&extra), None);
    std::fs::remove_dir(&dir).unwrap();
}
