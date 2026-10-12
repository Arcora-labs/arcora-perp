//! Shared build-only public checksum generator. No fallback identities.
//!
//! Exact file watches and selected safe source-directory watches avoid generated
//! output and private paths. New package layouts require an explicit rebuild;
//! this checksum describes local files at helper time, not compiler/process
//! attestation or a signed release.
use std::{env, fs, path::Path, process::Command};

pub fn build() {
    let manifest = env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required");
    let root = Path::new(&manifest)
        .ancestors()
        .nth(2)
        .expect("service crate must be below repository/crates")
        .canonicalize()
        .expect("source root must exist");
    build_with_root(&root);
}

/// The dependency-light harness uses the same helper with its explicit root.
pub fn build_with_root(root: &Path) {
    let root = root.canonicalize().expect("source root must exist");
    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR is required");
    let output = Path::new(&out_dir).join("service-build-identity.json");
    let run = Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(root.join("scripts/local-verification/service_build_identity.py"))
        .arg("--root")
        .arg(&root)
        .arg("--output")
        .arg(&output)
        .output()
        .expect("public service build identity helper could not start");
    assert!(run.status.success(), "public service build identity failed");
    let bytes = fs::read(output).expect("generated public build identity missing");
    assert!(bytes.len() <= 4096, "build identity exceeds bound");
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("invalid public build identity JSON");
    let object = value.as_object().expect("build identity object required");
    assert_eq!(object.len(), 4, "unexpected build identity fields");
    assert_eq!(
        object.get("schema").and_then(serde_json::Value::as_str),
        Some("arcora-service-build-identity/v1")
    );
    assert_eq!(
        object.get("algorithm").and_then(serde_json::Value::as_str),
        Some("sha256-canonical-source-map-v1")
    );
    assert!(
        object
            .get("source_files")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|count| (1..=8192).contains(&count)),
        "invalid source inventory count"
    );
    let checksum = object
        .get("source_sha256")
        .and_then(serde_json::Value::as_str)
        .expect("public source checksum required");
    assert!(
        checksum.len() == 64
            && checksum
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid public source checksum"
    );
    assert_eq!(
        serde_json::to_vec(&value).expect("canonical build identity serialization failed"),
        bytes,
        "noncanonical build identity"
    );
    assert!(
        run.stdout.len() <= 16 * 1024 * 1024,
        "watch output exceeds bound"
    );
    let watches = String::from_utf8(run.stdout).expect("invalid public watch output");
    assert!(!watches.is_empty(), "public source watches required");
    for line in watches.lines() {
        let path = line
            .strip_prefix("cargo:rerun-if-changed=")
            .expect("unexpected helper output");
        assert!(
            Path::new(path).is_absolute() && Path::new(path).starts_with(&root),
            "watch outside public source root"
        );
        println!("{line}");
    }
}
