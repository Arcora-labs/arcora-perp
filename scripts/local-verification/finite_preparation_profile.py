#!/usr/bin/env python3
"""Run three finite native fixtures; collect release CPU and fresh-child RSS.

Run on macOS with Python 3.11+ and the selected Rust toolchain on PATH:
  python3 scripts/local-verification/finite_preparation_profile.py --output DIR
DIR must not exist. No service, RPC, real proof, cloud, or live keys are used.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "prover_client::finite_profile_tests::"
CASES = {
    "notes64_withdrawals16": (64, 16, "rss_64_16"),
    "notes160_withdrawals16": (160, 16, "rss_160_16"),
    "notes160_withdrawals48": (160, 48, "rss_160_48"),
}
PHASES = (
    "state_clone", "native_replay_owned", "claim_paths", "prepare_unproved_total",
    "legacy_prepare_cached_stub_total", "clocked_prepare_cached_stub_total",
    "legacy_software_seal_hex", "clocked_software_seal_hex",
)
FRAME_KEYS = {
    "pre_state_postcard_bytes", "witness_postcard_bytes", "prepared_intent_postcard_bytes",
    "withdrawal_list_postcard_bytes", "legacy_plaintext_bytes", "clocked_plaintext_bytes",
    "legacy_sealed_envelope_bytes", "clocked_sealed_envelope_bytes",
    "legacy_request_json_bytes", "clocked_request_json_bytes",
    "legacy_journal_intent_in_memory_bytes",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dump(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def source_identity():
    import candidate_identity_manifest as identity
    files = identity.source_inventory(ROOT)
    # Include the diagnostic runner, its validator tests and exact reused golden,
    # in addition to the existing public service-source inventory.
    for name in (
        "scripts/local-verification/finite_preparation_profile.py",
        "scripts/local-verification/test_finite_preparation_profile.py",
        "docs/audits/2026-10-14-seal-window-ownership/baseline-export/normal-00-before_first_seal_seq.bin",
    ):
        files[name] = sha((ROOT / name).read_bytes())
    return {
        "base_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "measurement_source_sha256": sha(identity.canonical(files)),
        "source_files": len(files), "files": files,
    }


def validate_metadata(row):
    name = row.get("fixture")
    require(name in CASES, "unknown fixture")
    notes, withdrawals, _ = CASES[name]
    for field, expected in {
        "pre_live_notes": notes, "post_live_notes": notes - withdrawals,
        "withdrawals": withdrawals, "ops": withdrawals + 1,
        "timed_ops": 1, "claim_count": withdrawals,
    }.items():
        require(type(row.get(field)) is int and row[field] == expected, f"invalid {field}")
    expected_paths = {4: 16} if withdrawals == 16 else {5: 16, 6: 32}
    paths = row.get("claim_path_siblings")
    require(isinstance(paths, list) and len(paths) == withdrawals
            and all(type(n) is int for n in paths)
            and Counter(paths) == expected_paths, "invalid claim paths")
    for field in ("witness_sha256", "prepared_intent_sha256"):
        require(isinstance(row.get(field), str)
                and re.fullmatch(r"[0-9a-f]{64}", row[field]), f"invalid {field}")
    frames = row.get("frames")
    require(isinstance(frames, dict) and set(frames) == FRAME_KEYS, "invalid frame fields")
    require(all(type(n) is int and n > 0 for n in frames.values()), "invalid frame length")
    require(row.get("proof") == "synthetic_cached_stub"
            and row.get("seal") == "software_test_keys", "invalid synthetic labels")
    return row


def validate_cpu(rows):
    fields = {"fixture", "phase", "round", "repetitions", "thread_cpu_ns", "wall_ns"}
    actual = {}
    for row in rows:
        require(isinstance(row, dict) and set(row) == fields, "invalid CPU fields")
        require(row["fixture"] in CASES and row["phase"] in PHASES, "unknown sample")
        require(all(type(row[k]) is int for k in ("round", "repetitions", "thread_cpu_ns", "wall_ns")),
                "CPU fields must be integers, not booleans")
        require(0 <= row["round"] < 5 and row["repetitions"] == 10, "invalid batch shape")
        require(row["thread_cpu_ns"] > 0 and row["wall_ns"] > 0, "invalid duration")
        key = (row["fixture"], row["phase"], row["round"])
        require(key not in actual, "duplicate CPU sample")
        actual[key] = row
    expected = {(case, phase, r) for case in CASES for phase in PHASES for r in range(5)}
    require(set(actual) == expected, "incomplete CPU grid; require exactly 120 samples")
    summary = {}
    for case in CASES:
        summary[case] = {}
        for phase in PHASES:
            group = [actual[(case, phase, r)] for r in range(5)]
            summary[case][phase] = {}
            for field in ("thread_cpu_ns", "wall_ns"):
                values = [row[field] / row["repetitions"] / 1000 for row in group]
                summary[case][phase][field.replace("_ns", "_us_per_operation")] = {
                    "median": statistics.median(values), "min": min(values), "max": max(values),
                    "rounds": 5, "repetitions_per_round": 10,
                }
    return summary


def records(text, label):
    result = []
    for line in text.splitlines():
        if label in line:
            result.append(json.loads(line.split(label, 1)[1].strip()))
    return result


def check_test_result(text, passed):
    results = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
    require(results == [("ok", str(passed), "0", "0")], "unexpected actual test result")


def capture(out, label, argv, timeout=900):
    """Collect wait4 for this exact PID, never cumulative RUSAGE_CHILDREN.

    stdout/stderr go to files, so waiting cannot deadlock on a full pipe. Each
    command is exec'd separately. On timeout only this owned process is killed.
    """
    started = time.time()
    with (out / f"{label}.stdout.log").open("xb") as stdout, (out / f"{label}.stderr.log").open("xb") as stderr:
        process = subprocess.Popen(argv, cwd=ROOT, stdout=stdout, stderr=stderr)
        deadline = time.monotonic() + timeout
        timed_out = False
        try:
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    process.kill()
                    pid, status, usage = os.wait4(process.pid, 0)
                    break
                time.sleep(0.05)
            process.returncode = os.waitstatus_to_exitcode(status)
        except BaseException:
            process.kill()
            _, status, _ = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
            raise
    logs = {}
    for kind in ("stdout", "stderr"):
        data = (out / f"{label}.{kind}.log").read_bytes()
        logs[kind] = {"bytes": len(data), "sha256": sha(data)}
    record = {
        "command": argv, "pid": process.pid, "started_unix": started,
        "wall_seconds": time.time() - started, "exit_code": process.returncode,
        "timed_out": timed_out, "wait4_ru_maxrss_raw": usage.ru_maxrss,
        "ru_maxrss_unit": "bytes (macOS)", "logs": logs,
    }
    dump(out / f"{label}.json", record)
    require(not timed_out and process.returncode == 0, f"{label} failed; inspect retained logs")
    return record, (out / f"{label}.stdout.log").read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    require(platform.system() == "Darwin", "this CPU runner is macOS-only; no wall-clock fallback")
    require(sys.version_info >= (3, 11), "Python 3.11+ required for the public source inventory")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = source_identity()
    dump(out / "source.json", before)
    environment = {
        "os": subprocess.check_output(["sw_vers"], text=True).strip(),
        "cpu": subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip(),
        "architecture": platform.machine(), "python": platform.python_version(),
        "rustc": subprocess.check_output(["rustc", "--version", "--verbose"], text=True).strip(),
        "profile": "release", "measurement_source_sha256": before["measurement_source_sha256"],
        "rss_api": "os.wait4(exact_child_pid, options).ru_maxrss; macOS bytes",
        "rss_scope": "whole fresh test child: harness, native fixture setup, correctness checks, cached proof callbacks and in-memory frame roundtrips; not phase allocation",
    }
    dump(out / "environment.json", environment)
    _, text = capture(out, "build", [args.cargo, "test", "-p", "gateway", "--bin", "gateway",
        "--release", "--locked", "--offline", "--no-run", "--message-format=json"])
    artifacts = []
    for line in text.splitlines():
        row = json.loads(line)
        if row.get("reason") == "compiler-artifact" and row.get("executable") and row.get("target", {}).get("name") == "gateway" and row.get("profile", {}).get("test"):
            artifacts.append(row["executable"])
    require(len(set(artifacts)) == 1, "require exactly one current gateway test executable")
    binary = artifacts[0]
    binary_sha = sha(Path(binary).read_bytes())
    dump(out / "binary.json", {"path": binary, "sha256": binary_sha})
    _, text = capture(out, "correctness", [binary, PREFIX, "--skip", "rss_", "--skip", "observation::",
        "--nocapture", "--test-threads=1"])
    check_test_result(text, 4)
    metadata = records(text, "FINITE_FIXTURE ")
    require(len(metadata) == 3 and {r["fixture"] for r in metadata} == set(CASES), "require three fixture records")
    metadata = {r["fixture"]: validate_metadata(r) for r in metadata}
    _, text = capture(out, "cpu", [binary, PREFIX + "observation::finite_preparation_cpu",
        "--exact", "--ignored", "--nocapture", "--test-threads=1"])
    check_test_result(text, 1)
    rows = records(text, "FINITE_CPU_SAMPLE ")
    cpu = validate_cpu(rows)
    rss = {}
    for name, (_, _, test) in CASES.items():
        record, text = capture(out, name, [binary, PREFIX + test, "--exact", "--ignored",
            "--nocapture", "--test-threads=1"])
        check_test_result(text, 1)
        result = records(text, "FINITE_RSS_FIXTURE ")
        require(len(result) == 1 and validate_metadata(result[0]) == metadata[name], "RSS child fixture identity differs")
        require(record["wait4_ru_maxrss_raw"] > 0, "missing RSS measurement")
        rss[name] = {"pid": record["pid"], "peak_rss_bytes": record["wait4_ru_maxrss_raw"],
            "peak_rss_mib": record["wait4_ru_maxrss_raw"] / (1024 * 1024), "samples": 1}
    require(len({r["pid"] for r in rss.values()}) == 3, "require three distinct child PIDs")
    after = source_identity()
    require(after == before, "source changed during measurement")
    require(sha(Path(binary).read_bytes()) == binary_sha, "test executable changed during measurement")
    summary = {
        "schema": "arcora-finite-preparation-profile/v1", "status": "PASS",
        "measurement_source_sha256": before["measurement_source_sha256"], "binary_sha256": binary_sha,
        "actual_tests": {"correctness_passed": 4, "cpu_passed": 1, "rss_passed": 3, "failed": 0, "ignored": 0},
        "cpu_samples": len(rows), "fixtures": metadata, "cpu": cpu, "rss": rss,
        "limits": ["Only the three fixed native inputs; no admission cap or capacity guarantee",
            "CPU is the median of five ten-call batch averages; overlapping phases must not be summed",
            "Setup/warmup/checks/output cleanup excluded from CPU; input destruction and result pushes included",
            "RSS is one whole fresh-child peak per fixture including setup/validation/frames, not preparation-only memory",
            "Synthetic cached proof and software test seal keys; no backend, real proof, chain, CC or durable WAL acceptance",
            "PRODUCTION RELEASE HOLD; candidate submission remains disabled"],
    }
    dump(out / "summary.json", summary)
    print(json.dumps({"status": "PASS", "cpu_samples": len(rows), "actual_tests": summary["actual_tests"],
        "rss": rss, "output": str(out)}, indent=2), flush=True)


if __name__ == "__main__":
    main()
