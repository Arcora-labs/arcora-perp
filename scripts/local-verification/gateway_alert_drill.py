#!/usr/bin/env python3
"""Run source-bound local alert delivery checks; never configures an external sink."""
import argparse
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

from run_check import ROOT, identity

EXPECTED_CASES = {
    "held-recovery-rearm": 3,
    "filesystem-failure-recovery-rearm": 3,
    "durable-deposit-halt": 1,
    "collector-503-retains-failure": 1,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    argv = ["cargo", "test", "--locked", "-p", "gateway", "ops_alerts::", "--", "--nocapture", "--test-threads=1"]
    before = identity()
    started = time.time()
    log = output / "drill.log"
    timed_out = False
    with log.open("wb") as stream:
        try:
            result = subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = None
    after = identity()
    raw = log.read_bytes()
    text = raw.decode(errors="replace")
    cases = [json.loads(s) for s in re.findall(r"ALERT_DRILL_EVIDENCE (\{[^\n]+\})", text)]
    summaries = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", text)
    source_unchanged = before["source_sha256"] == after["source_sha256"]
    observed = {case["case"]: len(case["events"]) for case in cases}
    events_valid = len(cases) == len(EXPECTED_CASES) and observed == EXPECTED_CASES
    for case in cases:
        events_valid = events_valid and case.get("transport") == "actual-loopback-http"
        for event in case["events"]:
            events_valid = events_valid and set(event) == {"schema", "event", "transition", "episode"}
            events_valid = events_valid and event.get("schema") == "arcora.ops-alert.v1"
    passed = (
        exit_code == 0 and not timed_out and source_unchanged and events_valid
        and len(summaries) == 1 and summaries[0][:5] == ("ok", "6", "0", "0", "0")
    )
    record = {
        "status": "PASS" if passed else "FAIL",
        "argv": argv, "cwd": str(ROOT), "exit_code": exit_code,
        "timed_out": timed_out, "duration_seconds": round(time.time() - started, 3),
        "log_sha256": hashlib.sha256(raw).hexdigest(),
        "source_before": before, "source_after": after,
        "source_unchanged_during_check": source_unchanged,
        "rust_test_summaries": summaries, "captured_cases": cases,
        "boundaries": [
            "Controlled local event sources and real loopback HTTP delivery, not live-chain or operator delivery.",
            "Persistence scope is actual snapshot/final-snapshot writes, not every missing writer, ACK timeout, or journal failure.",
            "Deposit halt is terminal until separately reconciled; no automatic recovery or rearm is invented.",
            "Best effort bounded delivery; local structured log retained when collector rejects or times out.",
        ],
    }
    (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({key: record[key] for key in ["status", "exit_code", "duration_seconds", "source_unchanged_during_check", "rust_test_summaries"]}))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
