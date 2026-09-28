#!/usr/bin/env python3
"""Capture a local check's actual exit status, test counts and source identity.

Usage: python3 scripts/local-verification/run_check.py LABEL -- COMMAND [ARGS...]
       python3 scripts/local-verification/run_check.py --output-dir DIR LABEL -- COMMAND [ARGS...]
Run from the repository root. No environment values are recorded.
"""
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs/audits/2026-09-27-local/checks"


def identity():
    files = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
    ).decode().split("\0")
    hashes = {}
    for name in sorted(set(files)):
        if not name or name.startswith(("docs/audits/2026-09-27-local/", "docs/audits/2026-09-28-continuation/", "docs/audits/2026-09-28-runtime/", "docs/audits/2026-09-28-merge/")):
            continue
        path = ROOT / name
        if path.is_file():
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    encoded = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
    return {
        "head_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
        "tree_sha": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT).decode().strip(),
        "source_sha256": hashlib.sha256(encoded).hexdigest(),
        "files": hashes,
    }


def main():
    args = sys.argv[1:]
    out = OUT
    if len(args) >= 2 and args[0] == "--output-dir":
        out = Path(args[1]).resolve()
        args = args[2:]
    if len(args) < 3:
        raise SystemExit("Usage: run_check.py [--output-dir DIR] LABEL -- COMMAND [ARGS...]")
    label, separator, *argv = args
    if separator != "--" or not argv or not re.fullmatch(r"[a-zA-Z0-9_.-]+", label):
        raise SystemExit("Usage: run_check.py LABEL -- COMMAND [ARGS...]")
    out.mkdir(parents=True, exist_ok=True)
    before = identity()
    start = time.time()
    with (out / f"{label}.log").open("wb") as log:
        result = subprocess.run(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    raw = (out / f"{label}.log").read_bytes()
    after = identity()
    summaries = re.findall(
        r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
        raw.decode(errors="replace"),
    )
    record = {
        "argv": argv, "cwd": str(ROOT), "exit_code": result.returncode,
        "duration_seconds": round(time.time() - start, 3),
        "log_sha256": hashlib.sha256(raw).hexdigest(),
        "rust_test_summaries": summaries,
        "source_before": before, "source_after": after,
        "source_unchanged_during_check": before["source_sha256"] == after["source_sha256"],
    }
    (out / f"{label}.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({k: v for k, v in record.items() if not k.startswith("source_")}))
    print(raw.decode(errors="replace")[-4000:])
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
