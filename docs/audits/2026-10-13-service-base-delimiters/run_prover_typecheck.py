#!/usr/bin/env python3
"""Source-bound actual prover-service typecheck; never boot or prove.

Invoke only after the root agent freezes all sources and supplies that exact
covered-map checksum. Old PR55 tools/caches are reused, never its evidence.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
NEW_ROOT = ROOT / "target/service-base-validation-20261013"
OLD = ROOT / "target/candidate-service-validation-20261012/prover"
CACHE = OLD / "actual-typecheck"
BASE = "1caae328fe73a5ab96bb4200d5e28d926807d201"
REVIEWED = "contracts/integration/fixtures/clock-v2-verified"
CANDIDATE = "contracts/integration/fixtures/chainlink-candidate-v1"
UNCHANGED_MANIFESTS = (
    "Cargo.toml", "Cargo.lock", "crates/gateway/Cargo.toml",
    "crates/prover-service/Cargo.toml", "crates/prover-service/Cargo.lock",
    "scripts/local-verification/service-identity-harness/Cargo.toml",
    "scripts/local-verification/service-identity-harness/Cargo.lock",
)
ARTIFACTS = (
    REVIEWED + "/guest.elf", REVIEWED + "/program-vkey.bin",
    REVIEWED + "/proof-evidence.json", REVIEWED + "/clock.witness.bin",
    REVIEWED + "/proof.bin", REVIEWED + "/proof.sdk.json",
    REVIEWED + "/public-values.bin", CANDIDATE + "/guest.elf",
    CANDIDATE + "/metadata.json",
)


def require(ok):
    if not ok:
        raise ValueError("typecheck precondition refused")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def regular(path, limit=64 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit)
    data = path.read_bytes()
    require(len(data) <= limit)
    return data


def snapshot(identity, expected_source):
    pins = identity.verify_pins(ROOT)
    require(tuple(len(pins[k]) for k in (
        "reviewed_v2_sources_sha256", "candidate_sources_sha256",
        "candidate_auxiliary_test_sources_sha256")) == (21, 9, 2))
    sources = identity.source_inventory(ROOT)
    checksum = digest(canonical(sources))
    require(checksum == expected_source)
    manifests = {p: digest(regular(ROOT / p)) for p in UNCHANGED_MANIFESTS}
    for p, sha in manifests.items():
        require(digest(subprocess.check_output(["git", "show", BASE + ":" + p], cwd=ROOT)) == sha)
    artifacts = {p: {"bytes": len(regular(ROOT / p)), "sha256": digest(regular(ROOT / p))}
                 for p in ARTIFACTS}
    require(artifacts[REVIEWED + "/guest.elf"]["sha256"] == identity.legacy.clock.EXPECTED_ELF)
    require("0x" + regular(ROOT / REVIEWED / "program-vkey.bin").hex()
            == identity.legacy.clock.EXPECTED_VKEY)
    require(artifacts[CANDIDATE + "/guest.elf"]["sha256"] == identity.candidate.ELF_SHA)
    metadata = identity.decode_json(regular(ROOT / CANDIDATE / "metadata.json"))
    require(metadata["measured_program_vkey"] == identity.candidate.VKEY
            and metadata["elf_sha256"] == identity.candidate.ELF_SHA
            and metadata["candidate_runtime_sources_sha256"] == pins["candidate_sources_sha256"])
    skipped = CACHE / "cargo-target/elf-compilation/riscv64im-succinct-zkvm-elf/release/perp-core-guest"
    skipped_raw = regular(skipped)
    require(digest(skipped_raw) == identity.legacy.clock.EXPECTED_ELF)
    return {"covered_source_files": len(sources), "covered_source_sha256": checksum,
            "covered_source_files_sha256": sources, "protected_pins": pins,
            "unchanged_manifests_vs_base": manifests, "frozen_artifacts": artifacts,
            "candidate_vkey_metadata_only": identity.candidate.VKEY,
            "reviewed_vkey": identity.legacy.clock.EXPECTED_VKEY,
            "skipped_build_include_elf": {"path": str(skipped), "bytes": len(skipped_raw),
                                           "sha256": digest(skipped_raw)}}


def run(args):
    require(re.fullmatch(r"[0-9a-f]{64}", args.expected_source_sha256) is not None)
    out = args.output_dir.absolute()
    require(out.parent.is_dir() and out.parent.resolve() == out.parent
            and not out.exists() and not out.is_symlink() and out.is_relative_to(NEW_ROOT))
    require(1 <= args.timeout_seconds <= 1800)
    sys.path.insert(0, str(ROOT / "scripts/local-verification"))
    import candidate_identity_manifest as identity
    freeze_path = args.freeze_file.absolute()
    require(freeze_path.is_relative_to(NEW_ROOT) and freeze_path.parent.resolve() == freeze_path.parent)
    freeze_raw = regular(freeze_path, 2 * 1024 * 1024)
    freeze = identity.decode_json(freeze_raw)
    require(freeze["schema"] == "arcora-service-base-source-freeze/v1"
            and freeze["base"] == BASE and freeze["production_release"] == "HOLD"
            and freeze["source_sha256"] == args.expected_source_sha256)
    # Pure current-file pin/layout checks and explicit hash equality precede Cargo.
    before = snapshot(identity, args.expected_source_sha256)
    require(before["covered_source_files_sha256"] == freeze["source_files"]
            and before["covered_source_files"] == freeze["source_count"])
    cargo = "/Users/huseyinarslan/.rustup/toolchains/1.99.0-aarch64-apple-darwin/bin/cargo"
    tool_bin = Path(cargo).parent
    required = (Path(cargo), tool_bin / "rustc", CACHE / "cargo-home", CACHE / "cargo-target",
                CACHE / "tools/protoc", CACHE / "tools/include",
                CACHE / "tools/sp1-native-runner-existing", OLD / "python-bin/python3")
    require(all(p.exists() for p in required))
    fixed_env = {
        "RUSTC": str(tool_bin / "rustc"), "RUSTUP_TOOLCHAIN": "1.99.0",
        "CARGO_HOME": str(CACHE / "cargo-home"), "CARGO_TARGET_DIR": str(CACHE / "cargo-target"),
        "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true",
        "SP1_SKIP_PROGRAM_BUILD": "true",
        "SP1_CORE_RUNNER_OVERRIDE_BINARY": str(CACHE / "tools/sp1-native-runner-existing"),
        "PROTOC": str(CACHE / "tools/protoc"), "PROTOC_INCLUDE": str(CACHE / "tools/include"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    prefixes = [str(OLD / "python-bin"), str(tool_bin), str(CACHE / "tools")]
    env = dict(os.environ)
    env.update(fixed_env)
    env["PATH"] = ":".join(prefixes) + ":" + os.environ.get("PATH", "")
    versions = {}
    for name, command in (("cargo", [cargo, "--version"]),
                          ("rustc", [str(tool_bin / "rustc"), "--version"]),
                          ("python", ["python3", "--version"]),
                          ("protoc", [fixed_env["PROTOC"], "--version"])):
        result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=ROOT, timeout=15)
        require(result.returncode == 0)
        versions[name] = (result.stdout + result.stderr).decode().strip()
    require(versions["cargo"].startswith("cargo 1.99.0 ")
            and versions["rustc"].startswith("rustc 1.99.0 "))
    match = re.fullmatch(r"Python (\d+)\.(\d+)\..+", versions["python"])
    require(match is not None and tuple(map(int, match.groups())) >= (3, 11))
    # Fresh evidence directory; never open an old receipt/log with truncation.
    out.mkdir()
    command = [cargo, "check", "--offline", "--locked", "--manifest-path",
               "crates/prover-service/Cargo.toml", "--bin", "prover-service"]
    old_evidence_paths = [
        ROOT / "target/request-admission-validation-20261012/run_prover_typecheck.py",
        ROOT / "target/request-admission-validation-20261012/prover-typecheck-final/receipt.json",
        ROOT / "target/request-admission-validation-20261012/prover-typecheck-final/stdout.log",
        ROOT / "target/request-admission-validation-20261012/prover-typecheck-final/stderr.log",
        ROOT / "target/curl-bounds-validation-20261012/run_prover_typecheck_v3.py",
        ROOT / "target/curl-bounds-validation-20261012/prover-typecheck-final-v3/receipt.json",
        ROOT / "target/curl-bounds-validation-20261012/prover-typecheck-final-v3/stdout.log",
        ROOT / "target/curl-bounds-validation-20261012/prover-typecheck-final-v3/stderr.log",
    ]
    old_evidence_before = {str(p): digest(regular(p)) for p in old_evidence_paths}
    started = time.monotonic()
    timeout = False
    with (out / "stdout.log").open("xb") as stdout, (out / "stderr.log").open("xb") as stderr:
        try:
            child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                                     start_new_session=True)
            exit_code = child.wait(timeout=args.timeout_seconds)
        except subprocess.TimeoutExpired:
            timeout = True
            exit_code = None
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
    after = None
    after_refusal = None
    try:
        after = snapshot(identity, args.expected_source_sha256)
    except Exception as error:
        after_refusal = type(error).__name__
    freeze_unchanged = regular(freeze_path, 2 * 1024 * 1024) == freeze_raw
    old_evidence_after = {str(p): digest(regular(p)) for p in old_evidence_paths}
    old_evidence_unchanged = old_evidence_before == old_evidence_after
    passed = exit_code == 0 and not timeout and after == before and freeze_unchanged and old_evidence_unchanged
    record = {
        "schema": "arcora-service-base-actual-prover-typecheck/v1",
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "passed": passed, "command": command, "exit_code": exit_code, "timed_out": timeout,
        "elapsed_seconds": time.monotonic() - started, "timeout_seconds": args.timeout_seconds,
        "expected_source_sha256": args.expected_source_sha256,
        "root_source_freeze": {"path": str(freeze_path), "sha256": digest(freeze_raw),
                               "bytes": len(freeze_raw), "unchanged": freeze_unchanged},
        "runner_sha256": digest(Path(__file__).read_bytes()),
        "runner_adapted_from": {"path": str(ROOT / "target/request-admission-validation-20261012/run_prover_typecheck.py"), "sha256": "be7fb3f867c6e9eb2ac5a5fd73b4a3d0933378ec6624a06621599ed4676319ec"},
        "exact_toolchain_binary_no_rustup_sync": True,
        "prior_evidence_before": old_evidence_before, "prior_evidence_after": old_evidence_after,
        "prior_evidence_unchanged": old_evidence_unchanged,
        "toolchain": versions, "explicit_env_whitelist": fixed_env,
        "path_prefix_only": prefixes, "source_before": before, "source_after": after,
        "source_unchanged": after == before, "after_capture_refusal_kind": after_refusal,
        "stdout_sha256": digest((out / "stdout.log").read_bytes()),
        "stderr_sha256": digest((out / "stderr.log").read_bytes()),
        "scope": "Actual current prover-service production main/backend source/API typecheck only; "
                 "existing owned PR55 cache/tools and already copied reviewed ELF reused. "
                 "Offline Cargo with guest build skipped; no guest/core/source/pin mutation, "
                 "backend boot/setup/key derivation/prove/handshake/network/service or attestation claim. "
                 "No old PR55 receipt/log is opened for writing; no raw environment values recorded.",
    }
    with (out / "receipt.json").open("x") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"passed": passed, "exit_code": exit_code, "source_unchanged": after == before,
                      "receipt": str(out / "receipt.json"),
                      "receipt_sha256": digest((out / "receipt.json").read_bytes())}))
    return 0 if passed else (exit_code if isinstance(exit_code, int) and exit_code > 0 else 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--freeze-file", type=Path, default=NEW_ROOT / "source-freeze-final.json")
    parser.add_argument("--output-dir", type=Path, default=NEW_ROOT / "prover-typecheck-final")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()
    try:
        return run(args)
    except Exception as error:
        print("TYPECHECK_PRECHECK_REFUSED " + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
