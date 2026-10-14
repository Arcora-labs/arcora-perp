#!/usr/bin/env python3
"""Verify the closed public roster and exact PR64 source/metadata allowance."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import subprocess

HERE = Path(__file__).resolve().parent
NEW = HERE.parent
ROOT = HERE.parents[2]
BASE = "c929c719e366e62fe4a95f0da9d4e327755116ec"
BASELINE_SHA = "0452dee5790d5db2fe8af1def2db83a4201bce471e6923e1b2d4eaa0a31ec82e"
FREEZE_SHA = "997db0d2893c3cf30cdb1911bab0fedd7e000b48ae5a42136c1b6caa9ff4e7d9"
SOURCE_SHA = "b43fe139894f3b8f36692c3b43ddc8b7ba0647ab8003828413b18fe011e33c38"
CLIENT = "crates/gateway/src/prover_client.rs"
ACTIVE_WORK = "docs/ACTIVE_WORK.md"
PACKET = "docs/audits/2026-10-14-plaintext-preflight/"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def meta(path):
    assert path.is_file() and not path.is_symlink(), "Expected regular public file"
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
            size += len(block)
    return {"bytes": size, "sha256": h.hexdigest()}


def git(args, cwd=ROOT):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True).stdout


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-freeze", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--expected-head", default=BASE)
parser.add_argument("--allow-metadata-path", action="append", default=[])
args = parser.parse_args()
output = args.output.absolute()
assert output.is_relative_to(NEW) and output.parent.is_dir() and not output.exists()
assert len(args.expected_head) == 40 and all(c in "0123456789abcdef" for c in args.expected_head)
head_before = git(["rev-parse", "HEAD"]).decode().strip()
assert head_before == args.expected_head
git(["merge-base", "--is-ancestor", BASE, "HEAD"])

baseline_path = HERE / "baseline.json"
baseline_raw = baseline_path.read_bytes()
assert digest(baseline_raw) == BASELINE_SHA
baseline = json.loads(baseline_raw)
assert baseline["passed"] and baseline["actual_head"] == BASE
assert baseline["immutable_unique_count"] == len(baseline["immutable_inputs"]) == 4037
freeze_path = args.source_freeze.absolute()
assert freeze_path == NEW / "source-freeze-final.json" and not freeze_path.is_symlink()
freeze_raw = freeze_path.read_bytes()
assert digest(freeze_raw) == FREEZE_SHA
freeze = json.loads(freeze_raw)
assert freeze["base"] == BASE and freeze["baseline_sha256"] == BASELINE_SHA
assert freeze["production_release"] == "HOLD"
assert freeze["changed_public_sources"] == [CLIENT]
sources = freeze["source_files"]
assert set(sources) == set(baseline["source_files"])
assert freeze["source_count"] == len(sources) == 379
assert digest(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()) == SOURCE_SHA
assert freeze["source_sha256"] == SOURCE_SHA
assert {p for p in sources if sources[p] != baseline["source_files"][p]} == {CLIENT}

# Metadata is a finite caller-declared list, never a wildcard status exception.
metadata = {}
assert len(args.allow_metadata_path) == len(set(args.allow_metadata_path))
for relative in args.allow_metadata_path:
    path = Path(relative)
    assert not path.is_absolute() and ".." not in path.parts
    assert relative == ACTIVE_WORK or relative.startswith(PACKET), "Unexpected metadata scope"
    assert str(ROOT / relative) not in baseline["immutable_inputs"], "Protected old metadata"
    if relative == ACTIVE_WORK:
        original = git(["show", BASE + ":" + ACTIVE_WORK])
        assert (ROOT / relative).read_bytes().startswith(original), "ACTIVE_WORK must be append-only"
    else:
        assert not git(["ls-tree", "-r", "--name-only", BASE, "--", relative]), "Packet path existed at BASE"
    metadata[relative] = meta(ROOT / relative)
allowed = {CLIENT} | set(metadata)


def status_paths(raw):
    entries = [entry for entry in raw.split(b"\0") if entry]
    paths = []
    for entry in entries:
        assert len(entry) >= 4 and entry[2:3] == b" "
        state = entry[:2].decode()
        assert state in {" M", "M ", "MM", "A ", "AM", "??"}, "Unexpected status/rename/conflict"
        path = entry[3:].decode()
        assert path in allowed, "Unexpected changed path"
        paths.append(path)
    return paths


status_before = git(["status", "--porcelain=v1", "--untracked-files=all", "-z"])
current_paths = status_paths(status_before)
committed_paths = [p.decode() for p in git(["diff", "--name-only", "-z", BASE, "HEAD"]).split(b"\0") if p]
assert set(committed_paths) <= allowed, "Unexpected committed delta"
verified = 0
for name, expected in baseline["immutable_inputs"].items():
    if name == str(ROOT / CLIENT):
        continue
    assert meta(Path(name)) == expected, "Closed immutable input changed"
    verified += 1
assert verified == 4036
for relative, expected in sources.items():
    assert not Path(relative).is_absolute() and ".." not in Path(relative).parts
    assert meta(ROOT / relative)["sha256"] == expected, "Source mismatch"
assert freeze["protected_pins"] == baseline["protected_pins"]
assert sorted(len(v) for v in freeze["protected_pins"].values()) == [2, 9, 21]
for entries in freeze["protected_pins"].values():
    for relative, expected in entries.items():
        assert meta(ROOT / relative)["sha256"] == expected, "Pinned source mismatch"
assert freeze["eight_manifests_and_locks"] == baseline["eight_manifests_and_locks"]
assert len(baseline["eight_manifests_and_locks"]) == 8
for relative, expected in baseline["eight_manifests_and_locks"].items():
    assert meta(ROOT / relative) == expected, "Manifest/lock mismatch"
assert freeze["nine_program_proof_artifact_sha256"] == baseline["nine_program_proof_artifact_sha256"]
assert len(baseline["nine_program_proof_artifact_sha256"]) == 9
for relative, expected in baseline["nine_program_proof_artifact_sha256"].items():
    assert meta(ROOT / relative)["sha256"] == (expected if isinstance(expected, str) else expected["sha256"])

external = []
for entry in baseline["external"]:
    directory = Path(entry["path"])
    assert git(["rev-parse", "HEAD"], directory).decode().strip() == entry["head"]
    assert git(["status", "--porcelain=v1", "--untracked-files=all"], directory).decode() == entry["status"]
    names = [n.decode() for n in git(["diff", "--cached", "--name-only", "-z"], directory).split(b"\0") if n]
    assert names == entry["staged_names_whitelisted"] and set(names) <= set(entry["dirty_file_sha256"])
    diff = git(["diff", "--cached", "--binary", "--", *names], directory) if names else git(["diff", "--cached", "--binary"], directory)
    assert digest(diff) == entry["staged_binary_diff_sha256"]
    for relative, expected in entry["dirty_file_sha256"].items():
        assert meta(directory / relative)["sha256"] == (expected if isinstance(expected, str) else expected["sha256"])
    external.append({"name": entry["name"], "head": entry["head"], "dirty_count": entry["dirty_count"], "passed": True, "staged_whitelist_before_diff": True})
assert sum(e["dirty_count"] for e in external) == 82
assert git(["rev-parse", "HEAD"]).decode().strip() == head_before
assert git(["status", "--porcelain=v1", "--untracked-files=all", "-z"]) == status_before
assert baseline_path.read_bytes() == baseline_raw and freeze_path.read_bytes() == freeze_raw
for relative, expected in metadata.items():
    assert meta(ROOT / relative) == expected, "Metadata changed during readback"

result = {
    "schema": "arcora-plaintext-preflight-preservation-readback/v1",
    "captured_at": datetime.now(timezone.utc).isoformat(), "passed": True,
    "baseline_sha256": BASELINE_SHA, "source_freeze_sha256": FREEZE_SHA,
    "immutable_unique_files": 4037, "non_active_files_verified": verified,
    "authorized_source_paths": [CLIENT], "source_count": 379, "source_sha256": SOURCE_SHA,
    "all_current_source_files_equal": True, "other_378_sources_equal_baseline": True,
    "protected_pin_counts": {k: len(v) for k, v in freeze["protected_pins"].items()},
    "eight_manifests_and_locks_unchanged": True, "nine_program_proof_artifacts_unchanged": True,
    "external": external, "external_public_dirty_files": 82,
    "current_head": head_before, "expected_head": args.expected_head,
    "current_tree": git(["rev-parse", "HEAD^{tree}"]).decode().strip(),
    "current_status_paths": current_paths, "committed_paths_from_BASE": committed_paths,
    "allowed_metadata_files": metadata, "unknown_status_paths_ignored": False,
    "production_release": "HOLD",
    "scope": "Only closed approved public paths, exact frozen source, staged whitelist and caller-declared finite new metadata list. No private/env discovery, network/build/test/source/old/outside writes. One NEW ignored receipt only; cooperative readback, not filesystem rollback/attestation proof.",
}
encoded = (json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
with output.open("xb") as stream:
    stream.write(encoded)
    stream.flush()
    os.fsync(stream.fileno())
print(json.dumps({"passed": True, "receipt": str(output), "bytes": len(encoded), "sha256": digest(encoded), "non_active_files_verified": verified, "source_count": 379, "source_sha256": SOURCE_SHA}))
