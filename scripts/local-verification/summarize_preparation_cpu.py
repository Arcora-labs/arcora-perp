#!/usr/bin/env python3
"""Summarize the bounded macOS preparation diagnostic; run on an explicit root cue."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics

MAX_LOG_BYTES = 512 * 1024
MARKER = "PREPARATION_CPU_SAMPLE "
PHASES = (
    "seq_encode", "seq_decode", "seq_seal_owned", "snapshot_preview_total",
    "state_clone", "replay_owned", "prepare_unproved_total",
    "clock_validate_derived", "clock_extra_replay_validate",
    "legacy_prepare_cached_stub_total", "clocked_prepare_cached_stub_total",
)
FIXTURES = {
    "normal": {"sequencer_bytes": 3105, "witness_bytes": 1639, "ops": 4,
               "notes": 0, "timed_ops": 4, "withdrawals": 0},
    "rollback_resealed": {"sequencer_bytes": 3670, "witness_bytes": 2062,
                          "ops": 6, "notes": 0, "timed_ops": 6, "withdrawals": 0},
}
FIELDS = {"fixture", "phase", "round", "repetitions", "thread_cpu_ns", "wall_ns",
          "preview_enclave", "proof", *FIXTURES["normal"]}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate sample JSON field")
        result[key] = value
    return result


def stats(values):
    return {"min": min(values), "median": statistics.median(values), "max": max(values)}


def summarize(raw, profile, log_path):
    text = raw.decode("utf-8")
    summaries = re.findall(
        r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;.*$",
        text, re.MULTILINE,
    )
    if summaries != [("ok", "2", "0", "0")]:
        raise ValueError("Require exactly one actual Rust summary: 2 passed, 0 failed, 0 ignored")
    rows = {}
    for line in text.splitlines():
        if MARKER not in line:
            continue
        if line.count(MARKER) != 1:
            raise ValueError("Ambiguous sample marker")
        prefix, payload = line.split(MARKER, 1)
        if prefix and prefix != "test cpu_profile_tests::observation::observe_small_preparation_cpu ... ":
            raise ValueError("Unexpected sample line prefix")
        row = json.loads(payload, object_pairs_hook=unique_object)
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise ValueError("Unexpected sample fields")
        fixture, phase = row["fixture"], row["phase"]
        if fixture not in FIXTURES or phase not in PHASES:
            raise ValueError("Unknown fixture or phase")
        integers = ["round", "repetitions", "thread_cpu_ns", "wall_ns", *FIXTURES[fixture]]
        if any(type(row[key]) is not int for key in integers):
            raise ValueError("Sample numeric fields must be integers, not booleans/floats")
        if row["round"] not in range(5) or row["repetitions"] != 10:
            raise ValueError("Require five rounds and ten repetitions per row")
        if row["thread_cpu_ns"] <= 0 or row["wall_ns"] <= 0:
            raise ValueError("Require positive independent thread CPU and wall durations")
        if any(row[key] != value for key, value in FIXTURES[fixture].items()):
            raise ValueError("Fixture sizes, operation counts or zero-withdrawal scope changed")
        if row["preview_enclave"] != "serde_placeholder" or row["proof"] != "synthetic_cached_stub":
            raise ValueError("Require serde-placeholder preview and cached synthetic proof stub")
        key = (fixture, phase, row["round"])
        if key in rows:
            raise ValueError("Duplicate fixture/phase/round")
        rows[key] = row
    expected = {(fixture, phase, round_) for fixture in FIXTURES for phase in PHASES for round_ in range(5)}
    if set(rows) != expected or len(rows) != 110:
        raise ValueError("Require exactly 110 distinct rows: two fixtures x eleven phases x five rounds")
    groups = {}
    for fixture in FIXTURES:
        groups[fixture] = {}
        for phase in PHASES:
            samples = [rows[fixture, phase, round_] for round_ in range(5)]
            groups[fixture][phase] = {
                "samples": 5, "repetitions_per_sample": 10,
                "thread_cpu_ns_batch": stats([r["thread_cpu_ns"] for r in samples]),
                "thread_cpu_ns_per_operation": stats([r["thread_cpu_ns"] / 10 for r in samples]),
                "wall_ns_batch": stats([r["wall_ns"] for r in samples]),
                "wall_ns_per_operation": stats([r["wall_ns"] / 10 for r in samples]),
            }
    return {
        "schema": "arcora-preparation-cpu-summary/v1", "profile": profile,
        "profile_basis": "Explicit caller-supplied actual build mode; not inferred from timings/stdout",
        "raw_log": {"path": str(log_path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        "samples": 110, "rounds": 5, "repetitions_per_sample": 10,
        "per_operation_basis": "Each ten-call batch divided by ten; not individual-call latency samples",
        "actual_rust_test_summary": {"passed": 2, "failed": 0, "ignored": 0},
        "fixtures": FIXTURES, "groups": groups,
        "scope": {
            "clock": "macOS CLOCK_THREAD_CPUTIME_ID (16); wall_ns reported separately",
            "withdrawals": 0, "proof": "cached synthetic stub; no real proving/backend",
            "preview_enclave": "serde placeholder, not original enclave identity",
            "timed": "Run, input destruction and result-vector pushes; setup, warmup, assertions and output cleanup excluded",
            "phase_totals": "Phases overlap and must not be summed as an end-to-end total",
            "elapsed_thresholds_asserted": False, "RSS_measured": False,
            "proof_generated": False, "production_capacity_claimed": False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--profile", choices=("debug", "release"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.log.open("rb") as stream:
            raw = stream.read(MAX_LOG_BYTES + 1)
        if len(raw) > MAX_LOG_BYTES:
            raise ValueError("Input log exceeds 512 KiB")
        result = summarize(raw, args.profile, args.log)
        encoded = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(encoded)
        print(json.dumps({"output": str(args.output), "samples": 110, "profile": args.profile}))
    except (OSError, ValueError, TypeError, OverflowError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
