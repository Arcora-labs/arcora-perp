#!/usr/bin/env python3
"""Read the frozen explicit public roster, with only authorized source/pointer exceptions."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import subprocess

HERE = Path(__file__).resolve().parent
NEW = HERE.parent
CHECKOUT = HERE.parents[2]
PARENT = CHECKOUT.parent
ACTIVE = {"crates/gateway/src/prover_client.rs", "crates/gateway/src/http_transport_tests.rs", "crates/gateway/src/prover_bearer_header.rs"}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def meta(path):
    assert path.is_file() and not path.is_symlink()
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": digest(data)}

def git(args, cwd=CHECKOUT):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True).stdout

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-freeze", type=Path)
parser.add_argument("--pointer-backup", type=Path)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
output = args.output.absolute()
assert output.is_relative_to(NEW) and output.parent.is_dir() and not output.exists()
baseline_path = HERE / "baseline.json"
raw = baseline_path.read_bytes()
baseline = json.loads(raw)
assert baseline["schema"] == "arcora-bearer-argv-baseline/v1" and baseline["passed"]
assert baseline["actual_head"] == "76f658433882e5448c12c05c3f80bd7f3d78de39"
assert set(baseline["active_authorized_source_changes"]) == ACTIVE
active_paths = {str(CHECKOUT / rel) for rel in ACTIVE}
pointer = Path(baseline["active_pointer"]["path"])
backup = None
if args.pointer_backup:
    backup = args.pointer_backup.absolute()
    assert backup == PARENT / "Arcora_Devam_2026-10-11_PR62_korunan.md"
    assert meta(backup) == {k: baseline["active_pointer"][k] for k in ("bytes", "sha256")}
verified = 0
for path, expected in baseline["immutable_inputs"].items():
    if path in active_paths:
        continue
    actual_path = backup if Path(path) == pointer and backup is not None else Path(path)
    assert meta(actual_path) == expected, path
    verified += 1
assert verified == baseline["immutable_unique_count"] - 2
source_result = None
if args.source_freeze:
    freeze_path = args.source_freeze.absolute()
    assert freeze_path.is_relative_to(NEW) and not freeze_path.is_symlink() and freeze_path.stat().st_size <= 2 * 1024 * 1024
    freeze_raw = freeze_path.read_bytes()
    freeze = json.loads(freeze_raw)
    assert freeze["base"] == baseline["actual_head"] and freeze["production_release"] == "HOLD"
    assert set(freeze["changed_public_sources"]) == ACTIVE
    sources = freeze["source_files"]
    assert set(sources) == set(baseline["source_files"]) | {"crates/gateway/src/prover_bearer_header.rs"}
    assert freeze["source_count"] == len(sources) == 379
    assert digest(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()) == freeze["source_sha256"]
    for rel, expected in sources.items():
        assert not Path(rel).is_absolute() and ".." not in Path(rel).parts
        assert meta(CHECKOUT / rel)["sha256"] == expected, rel
        if rel not in ACTIVE:
            assert expected == baseline["source_files"][rel]
    source_result = {"path": str(freeze_path), "source_count": 379, "source_sha256": freeze["source_sha256"], "freeze_sha256": digest(freeze_raw), "all_current_sources_equal": True}
external = []
for entry in baseline["external"]:
    directory = Path(entry["path"])
    assert git(["rev-parse", "HEAD"], directory).decode().strip() == entry["head"]
    assert git(["status", "--porcelain=v1", "--untracked-files=all"], directory).decode() == entry["status"]
    names = [name for name in git(["diff", "--cached", "--name-only", "-z"], directory).decode().split("\0") if name]
    assert names == entry["staged_names_whitelisted"] and set(names) <= set(entry["dirty_file_sha256"])
    diff = git(["diff", "--cached", "--binary", "--", *names], directory) if names else git(["diff", "--cached", "--binary"], directory)
    assert digest(diff) == entry["staged_binary_diff_sha256"]
    external.append({"name": entry["name"], "head": entry["head"], "dirty_count": entry["dirty_count"], "passed": True, "staged_names_before_diff": True})
assert baseline_path.read_bytes() == raw
result = {
    "schema": "arcora-bearer-argv-preservation-readback/v1", "captured_at": datetime.now(timezone.utc).isoformat(), "passed": True,
    "baseline_sha256": digest(raw), "immutable_unique_files": baseline["immutable_unique_count"], "non_active_files_verified": verified,
    "active_authorized_source_changes": sorted(ACTIVE), "source": source_result,
    "historical_source_only_when_no_current_freeze": args.source_freeze is None,
    "pointer_backup": str(backup) if backup else None,
    "external": external, "external_public_dirty_files": 82,
    "current_head": git(["rev-parse", "HEAD"]).decode().strip(), "current_status": git(["status", "--porcelain=v1", "--untracked-files=all"]).decode(),
    "production_release": "HOLD",
    "scope": "Only closed approved public roster read. Two existing authorized source paths skipped in historical immutable roster; optional current379-source freeze checks all sources, with only three authorized changed paths. Optional exact PR62 pointer backup preserves replaced pointer bytes. Staged whitelist verified before binary diff read. No private/env discovery, source/old/outside writes, service/GPU/proof/network/deployment/financial action; only one new ignored receipt written.",
}
data = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
with output.open("xb") as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
print(json.dumps({"passed": True, "receipt": str(output), "bytes": len(data), "sha256": digest(data), "non_active_files_verified": verified, "source": source_result}, indent=2))
