#!/usr/bin/env python3
"""Run the exact synthetic Chainlink corpus using the real SP1 CPU executor.

No proving network or proof generation. A PASS requires exact expected guest
exits, public bytes and measured candidate vkey. Outputs are fresh and external.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import time

from check_chainlink_candidate import check as check_candidate
from verify_clock_proof import verify_guest_source

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "crates/chainlink-oracle/tests/fixtures/replay-v1"
ELF_SHA = "48a8eb8e6acd96057a72ca74db5077ac9e85d30d2ec830518ef1f1ac3832ef1f"
VKEY = "0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590"
FIXTURE_MANIFEST_SHA = "cc697713834cb455bb1a7cab24f419fe2badc84205a528f78ff710b7a0bd2567"


# Candidate runtime inputs measured with this ELF, separate from reviewed v2 pins.
CANDIDATE_SOURCES = {
    "crates/chainlink-oracle/Cargo.lock": "62f58aa9da1592de0a4419052c5145128425976b0e0c5520fcce0bb6c936b246",
    "crates/chainlink-oracle/Cargo.toml": "0b05c79f8fa37dd643466ad9e4b0013d6d6d257d7cfc414b8351cc7a11a88421",
    "crates/chainlink-oracle/src/binding.rs": "8c66dba2a1d49825c1c13b89aa1a55d47fcab42abe481a0fce308128215cc877",
    "crates/chainlink-oracle/src/lib.rs": "a107bf7464fe8654c69d9864c5ab6bcac6728d993634004d6d0075fbb707e224",
    "crates/chainlink-oracle/src/policy.rs": "c36d89a3212cd5d9893b19e77b6b4dba5dba364dcb2135b24424fdab5a42b285",
    "crates/chainlink-oracle/src/report.rs": "91b824e8a20bc7b1d8aa907813eb95061c659a655f72ef01fdc68409b7232d26",
    "crates/sp1-chainlink-guest/Cargo.lock": "de6dbb43b0b85968fa2f7f7de0d71d53c54adacebbc9786cfd17197491142cbe",
    "crates/sp1-chainlink-guest/Cargo.toml": "9f47d6f2cfc08fb71fdfcbc0877f09f083685a1ea016bbd67ea87dd60c8edc55",
    "crates/sp1-chainlink-guest/src/main.rs": "9e403b9f241e0a53afc2e58baa7bf978ddf81c28e5704acc7a6f734962874187",
}


def candidate_sources():
    for name, expected in CANDIDATE_SOURCES.items():
        require(sha(read_regular(ROOT / name)) == expected, "candidate runtime source changed: " + name)
    return dict(CANDIDATE_SOURCES)


def require(condition, label):
    if not condition:
        raise ValueError(label)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, limit=2 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink(), "regular non-symlink input required")
    with path.open("rb") as stream:
        require(os.fstat(stream.fileno()).st_size <= limit, "input size limit")
        data = stream.read(limit + 1)
    require(len(data) <= limit, "input size limit")
    return data


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def fixture_manifest():
    raw = read_regular(FIXTURES / "manifest.json")
    require(sha(raw) == FIXTURE_MANIFEST_SHA, "fixture manifest pin changed")
    manifest = decode(raw)
    for case in manifest["cases"]:
        data = read_regular(FIXTURES / (case["name"] + ".witness.bin"))
        require(sha(data) == case["witness_sha256"] and len(data) == case["witness_bytes"], "fixture mismatch")
    return manifest


def verify_report(directory):
    expected = fixture_manifest()["cases"]
    report = decode(read_regular(directory / "manifest.json"))
    require(report["status"] == "PASS" and report["kind"] == "synthetic-chainlink-candidate-cpu-replay", "wrong report kind/status")
    require(report["sdk_version"] == "6.1.0" and report["schema_version"] == 1, "report version")
    require(report["candidate_elf_sha256"] == ELF_SHA and report["program_vkey"] == VKEY, "candidate identity mismatch")
    require(report["fixture_manifest_sha256"] == FIXTURE_MANIFEST_SHA, "different replay corpus")
    for key in ("synthetic_inputs", "guest_executed", "native_guest_equal"):
        require(report[key] is True, "missing execution claim: " + key)
    for key in ("proof_generated", "real_don_verified", "live_deployment", "fresh_guest_build_performed"):
        require(report[key] is False, "unsupported evidence claim: " + key)
    rows = report["cases"]
    require(len(rows) == len(expected) == 19, "complete ordered corpus required")
    names = {case["name"] + ".public-values.bin" for case in expected}
    require(set(report["artifacts"]) == names, "missing or extra public-value artifacts")
    for row, case in zip(rows, expected):
        success = case["outcome"] == "PASS"
        require(row["case"] == case["name"] and row["expected_outcome"] == case["outcome"], "case order/outcome mismatch")
        require(row["witness_sha256"] == case["witness_sha256"] and row["native_error"] == case["native_error"], "input/error binding mismatch")
        require(type(row["guest_exit_code"]) is int and row["guest_exit_code"] == (0 if success else 1), "wrong guest exit")
        require(type(row["guest_cycles"]) is int and row["guest_cycles"] > 0, "guest cycle evidence required")
        require(type(row["guest_seconds"]) in (int, float) and math.isfinite(row["guest_seconds"]) and row["guest_seconds"] >= 0, "invalid execution duration")
        public = bytes.fromhex(case["expected_commitment"]) if success else b""
        require(row["public_values_hex"] == public.hex() and row["public_values_bytes"] == len(public), "wrong public commitment or rejection output")
        name = case["name"] + ".public-values.bin"
        actual = read_regular(directory / name, 32)
        require(actual == public, "public-value artifact mismatch")
        entry = report["artifacts"][name]
        require(entry["sha256"] == sha(actual) and entry["size_bytes"] == len(actual), "public-value artifact hash mismatch")
    return report


def run(binary, elf, output, timeout=600):
    binary = binary.resolve(strict=True)
    require(binary.is_file(), "executor binary required")
    require(sha(read_regular(elf)) == ELF_SHA, "candidate ELF pin mismatch")
    check_candidate()
    sources = candidate_sources()
    pins = verify_guest_source()
    fixture_manifest()
    require(not output.exists() and not output.is_symlink(), "fresh output directory required")
    output = output.resolve()
    require(not output.is_relative_to(ROOT), "execution output must be outside checkout")
    output.mkdir()
    for sub in ("home", "tmp", "guards"):
        (output / sub).mkdir()
    # Deliberately do not inherit secrets, prover backend, diagnostics or proxy settings.
    env = {"HOME": str(output / "home"), "TMPDIR": str(output / "tmp"),
           "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C",
           "RAYON_NUM_THREADS": "4", "TOKIO_WORKER_THREADS": "2"}
    binary_sha = sha(binary.read_bytes())
    guards = []
    invalid = output / "guards/wrong.elf"; invalid.write_bytes(b"not a guest")
    linked = output / "guards/linked.elf"; linked.symlink_to(elf.resolve(strict=True))
    exists = output / "guards/existing"; exists.mkdir(); (exists / "keep").write_bytes(b"preserve")
    for name, args in [
        ("wrong-elf", ["--elf", str(invalid), "--output-dir", str(output / "guards/wrong-out")]),
        ("symlink-elf", ["--elf", str(linked), "--output-dir", str(output / "guards/link-out")]),
        ("directory-elf", ["--elf", str(output / "guards"), "--output-dir", str(output / "guards/dir-out")]),
        ("duplicate-argument", ["--elf", str(elf), "--elf", str(elf), "--output-dir", str(output / "guards/duplicate-out")]),
        ("existing-output", ["--elf", str(elf), "--output-dir", str(exists)]),
    ]:
        with (output / "guards" / (name + ".log")).open("w") as log:
            result = subprocess.run([str(binary), *args], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=30)
        require(result.returncode != 0, "executor accepted invalid input: " + name)
        guards.append({"name": name, "exit_code": result.returncode})
    require((exists / "keep").read_bytes() == b"preserve", "existing evidence changed")
    require(not list((output / "guards").rglob("manifest.json")), "guard failure wrote success evidence")
    cmd = [str(binary), "--elf", str(elf.resolve()), "--output-dir", str(output / "execution")]
    started = time.monotonic()
    with (output / "execution.log").open("w") as log:
        result = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    require(result.returncode == 0, "real guest executor failed; inspect execution.log")
    report = verify_report(output / "execution")
    require(sha(binary.read_bytes()) == binary_sha and verify_guest_source() == pins, "binary/reviewed inputs changed")
    require(sha(read_regular(elf)) == ELF_SHA, "ELF changed")
    require(candidate_sources() == sources, "candidate sources changed")
    fixture_manifest()
    evidence = {"status": "PASS", "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "command": cmd, "exit_code": result.returncode, "elapsed_seconds": time.monotonic() - started,
                "binary_sha256": binary_sha, "candidate_elf_sha256": ELF_SHA, "program_vkey": VKEY,
                "candidate_sources_sha256": sources,
                "log_sha256": sha((output / "execution.log").read_bytes()), "reviewed_pins_unchanged": len(pins),
                "guards": guards, "success_cases": 4, "rejected_cases": 15, "proof_generated": False,
                "real_don_verified": False, "live_deployment": False,
                "execution_manifest_sha256": sha((output / "execution/manifest.json").read_bytes())}
    (output / "verification.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()
    require(0 < args.timeout_seconds <= 1800, "bounded positive timeout required")
    print(json.dumps(run(args.binary, args.elf, args.output_dir, args.timeout_seconds), indent=2))


if __name__ == "__main__":
    main()
