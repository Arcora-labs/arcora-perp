#!/usr/bin/env python3
"""Fresh static preservation receipt, only after root supplies frozen expectations.

No build, test, RPC, fetch, merge, tracked write or service operation. Reads only
the pristine public roster and earlier approved dirty-file/checksum roster.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parents[1]
BASELINE = PACKET / "baseline.json"
BASELINE_SHA = "360a0503c45f6314d48973caca14545300a140931d25028722090662d51c0f3e"
BASE_HEAD = "788d46fe793180b73aff2cb33eaf79c744b091ec"
ALLOWED = frozenset({
    "scripts/local-verification/candidate_identity_manifest.py",
    "scripts/local-verification/candidate_target_observer.py",
    "scripts/local-verification/test_candidate_identity_manifest.py",
    "scripts/local-verification/test_candidate_target_observer.py",
    "docs/CHAINLINK_CANDIDATE_IDENTITY.md", "docs/CHAINLINK_TARGET_OBSERVER.md",
    "docs/ACTIVE_WORK.md", ".gitattributes",
})
SOURCE_PATHS = frozenset(x for x in ALLOWED if x.endswith(".py"))
CODE_PATHS = ALLOWED - {"docs/ACTIVE_WORK.md", ".gitattributes"}
EXPECTATION_KEYS = {
    "schema", "code_commit", "expected_head", "expected_tree", "expected_status",
    "source_files", "source_sha256", "final_existing_sha256",
}


def require(ok, label):
    if not ok:
        raise ValueError(label)


def hex_string(value, size):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % size, value) is not None


def public_name(name):
    p = Path(name)
    require(not p.is_absolute() and ".." not in p.parts, "unsafe public roster name")
    require(not any(x.lower().startswith(".env") or re.search(
        r"(?:^|[._-])(?:secrets?|credentials?|private[-_]keys?)(?:[._-]|$)", x.lower())
        for x in p.parts), "private roster name refused")
    public_fixture = "crates/attestation/tests/fixtures/azure/ak.pem"
    require(not p.name.lower().endswith((".pem", ".key", ".p12", ".pfx"))
            or name == public_fixture or name == str(ROOT / public_fixture).lstrip("/"),
            "private-key roster refused")
    return p


def regular_public_path(path):
    path = Path(path).absolute()
    public_name(str(path).lstrip("/"))
    require(not any(p.is_symlink() for p in (path, *path.parents)),
            "symlink ancestor checksum input refused")
    require(path.is_file(), "regular public checksum input required")
    return path


def sha(path):
    path = regular_public_path(path)
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(*args, cwd=ROOT):
    return subprocess.check_output(["git", *args], cwd=cwd)


def audit(expectation_path, expectation_sha, receipt_name):
    require(hex_string(expectation_sha, 64), "expected expectation SHA-256 required")
    require(re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,110}\.json", receipt_name) is not None,
            "owned receipt basename required")
    output = PACKET / receipt_name
    require(not output.exists() and not output.is_symlink(), "receipt already exists")
    require(sha(BASELINE) == BASELINE_SHA, "immutable baseline changed")
    baseline = json.loads(regular_public_path(BASELINE).read_text())
    require(baseline["passed"] and baseline["base_main"] == BASE_HEAD
            and baseline["allowed_existing_paths"] == []
            and baseline["tracked_file_count"] == 3045
            and len(baseline["tracked_file_sha256"]) == 3045,
            "pristine baseline scope mismatch")
    expectation_path = regular_public_path(expectation_path)
    require(sha(expectation_path) == expectation_sha, "frozen expectations changed")
    expectation_bytes = expectation_path.read_bytes()
    expect = json.loads(expectation_bytes)
    require(isinstance(expect, dict) and set(expect) == EXPECTATION_KEYS
            and expect["schema"] == "arcora-candidate-public-path-final-expectations/v1",
            "explicit final expectations schema required")
    for key in ("code_commit", "expected_head", "expected_tree"):
        require(hex_string(expect[key], 40), "explicit Git identity required")
    require(type(expect["source_files"]) is int and expect["source_files"] == 375
            and hex_string(expect["source_sha256"], 64)
            and isinstance(expect["expected_status"], str), "explicit source/status identities required")
    final_hashes = expect["final_existing_sha256"]
    require(isinstance(final_hashes, dict) and set(final_hashes) == ALLOWED
            and all(hex_string(x, 64) for x in final_hashes.values()),
            "all eight permitted final paths must be pinned")
    head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    status = git("status", "--porcelain=v1", "--untracked-files=all").decode()
    require((head, tree, status) == (expect["expected_head"], expect["expected_tree"],
                                  expect["expected_status"]), "exact source head/tree/status mismatch")
    require(subprocess.run(["git", "merge-base", "--is-ancestor", BASE_HEAD, head],
                          cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
            and subprocess.run(["git", "merge-base", "--is-ancestor", expect["code_commit"], head],
                               cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0,
            "base/code ancestry mismatch")
    current = {name: sha(ROOT / public_name(name))
               for name in baseline["tracked_file_sha256"]}
    changed = {name: {"before": old, "after": current[name]}
               for name, old in baseline["tracked_file_sha256"].items() if current[name] != old}
    require(set(changed) <= ALLOWED, "unexpected existing public-file change")
    require({name: current[name] for name in ALLOWED} == final_hashes,
            "final source/document metadata mismatch")
    require(SOURCE_PATHS <= set(changed), "all four scoped Python repairs expected")
    code_hashes = {}
    for name in sorted(CODE_PATHS):
        expected = hashlib.sha256(git("show", expect["code_commit"] + ":" + name)).hexdigest()
        require(current[name] == expected, "current bytes differ from final code commit")
        code_hashes[name] = {"code_commit_sha256": expected, "actual_sha256": current[name],
                             "byte_exact": True}
    external = []
    for item in baseline["external"]:
        checkout = Path(item["path"])
        actual_head = git("rev-parse", "HEAD", cwd=checkout).decode().strip()
        actual_status = git("status", "--porcelain=v1", "--untracked-files=all", cwd=checkout).decode()
        staged_names = git("diff", "--cached", "--name-only", "-z", cwd=checkout).decode().split("\0")
        require(all(not name or name in item["dirty_file_sha256"] for name in staged_names),
                "unknown staged public-input path")
        staged_sha = hashlib.sha256(git("diff", "--cached", "--binary", cwd=checkout)).hexdigest()
        actual = {name: sha(checkout / public_name(name)) for name in item["dirty_file_sha256"]}
        checks = {"head": actual_head == item["head"], "status": actual_status == item["status"],
                  "staged_diff": staged_sha == item["staged_binary_diff_sha256"],
                  "dirty_bytes": actual == item["dirty_file_sha256"]}
        require(all(checks.values()), "external dirty preservation mismatch")
        external.append({"name": item["name"], "path": str(checkout), "head": actual_head,
                         "dirty_count": len(actual_status.splitlines()), "files_hashed": len(actual),
                         "checks": checks, "passed": True})
    require([x["dirty_count"] for x in external] == [13, 7, 62]
            and sum(x["files_hashed"] for x in external) == 82, "external82 count mismatch")
    # Imported helper performs only local, covered public source checksum reads.
    sys.path.insert(0, str(ROOT / "scripts/local-verification"))
    import candidate_identity_manifest as identity
    sources = identity.source_inventory(ROOT)
    source_sha = identity.digest(identity.canonical(sources))
    prior_sources = baseline["covered_source_inventory"]["source_sha256_map"]
    require(set(sources) == set(prior_sources) and len(sources) == 375
            and source_sha == expect["source_sha256"], "frozen source inventory mismatch")
    modified_sources = sorted(name for name in sources if sources[name] != prior_sources[name])
    require(set(modified_sources) == SOURCE_PATHS, "source changes exceed four Python files")
    expected_pin_maps = {"reviewed21": identity.legacy.clock.EXPECTED_GUEST_SOURCES,
                         "candidate9": identity.candidate.CANDIDATE_SOURCES,
                         "auxiliary2": identity.AUXILIARY_TEST_SOURCES}
    pins = {}
    for label, mapping in expected_pin_maps.items():
        actual = {name: sha(ROOT / public_name(name)) for name in mapping}
        require(mapping == baseline["pins"][label]["expected_sha256"] and actual == mapping,
                "reviewed source pin changed")
        pins[label] = {"count": len(mapping), "passed": True}
    require([pins[x]["count"] for x in ("reviewed21", "candidate9", "auxiliary2")] == [21, 9, 2],
            "pin roster changed")
    manifests = {name: sha(ROOT / name) for name in ("Cargo.toml", "Cargo.lock")}
    require(manifests == baseline["root_manifests_sha256"], "root Cargo manifests changed")
    delivered_dir = ROOT.parent / "Arcora_PR57_Kanit_2026-10-12"
    require(sha(delivered_dir / "delivery-ledger.json") == baseline["original_pr57_delivery_ledger_sha256"],
            "original PR57 delivery ledger changed")
    delivered = {}
    for name, expected in baseline["original_pr57_delivered_evidence"].items():
        path = regular_public_path(delivered_dir / public_name(name))
        actual = {"sha256": sha(path), "bytes": path.stat().st_size}
        require(actual == expected, "original PR57 delivered evidence changed")
        delivered[name] = actual
    reports = {name: sha(ROOT.parent / public_name(name))
               for name in baseline["original_public_reports_and_pointer_sha256"]}
    require(reports == baseline["original_public_reports_and_pointer_sha256"],
            "original reports or current pointer changed before final capture")
    require({name: sha(ROOT / public_name(name)) for name in current} == current
            and git("rev-parse", "HEAD").decode().strip() == head
            and git("rev-parse", "HEAD^{tree}").decode().strip() == tree
            and git("status", "--porcelain=v1", "--untracked-files=all").decode() == status
            and sha(expectation_path) == expectation_sha, "inputs changed during final capture")
    record = {
        "schema": "arcora-candidate-public-path-independent-preservation/v1",
        "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "Static public-path repair preservation only; no tests, RPC, builds, Git mutation, approval or release acceptance.",
        "baseline_sha256": BASELINE_SHA, "base_main": BASE_HEAD,
        "expectations_sha256": expectation_sha, "helper_sha256": sha(__file__),
        "actual_head": head, "actual_tree": tree, "checkout_status_filenames_only": status,
        "code_commit": expect["code_commit"], "code_commit_files": code_hashes,
        "tracked_baseline_files": len(current), "tracked_unchanged": len(current) - len(changed),
        "allowed_existing_paths": sorted(ALLOWED), "changed_existing_paths": changed,
        "unexpected_existing_changes": [], "missing_existing_files": [],
        "covered_source_inventory": {"source_files": len(sources), "source_sha256": source_sha,
                                     "modified_source_paths": modified_sources, "matches_frozen": True},
        "pins": pins, "root_manifests_sha256": manifests,
        "external": external, "external_total_dirty_files_hashed": 82,
        "original_pr57_evidence_files": len(delivered), "original_pr57_evidence_preserved": True,
        "original_public_reports_and_pointer_sha256": reports,
        "release_gate": "HOLD", "passed": True,
    }
    # Receipt path is fixed within our ignored packet and published exclusively.
    with output.open("x") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"receipt": str(output), "sha256": sha(output), "passed": True,
                      "tracked": len(current), "unchanged": len(current) - len(changed),
                      "changed": len(changed), "source_sha256": source_sha}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--expectations-sha256", required=True)
    parser.add_argument("--receipt", default="preservation-final.json")
    args = parser.parse_args()
    audit(args.expectations, args.expectations_sha256, args.receipt)
