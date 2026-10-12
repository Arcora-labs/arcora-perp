#!/usr/bin/env python3
"""Read-only public preservation capture; creates one exclusive ignored receipt."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "baseline.json"
PRIOR = ROOT / "target/candidate-seal-validation-20261012/baseline.json"
POSTMERGE = ROOT / "target/candidate-seal-validation-20261012/publication/preservation-postmerge.json"
EXPECTED_HEAD = "788d46fe793180b73aff2cb33eaf79c744b091ec"
EXPECTED_TREE = "eac7daa29cbb190d182ffc1f3db64f220786d80a"
EXPECTED_SOURCE = "ec07ccd9cba6f2b52b7600e149715805bd7d58e84195c4a947e4c75102cf9b89"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def public_path(name):
    p = Path(name)
    require(not p.is_absolute() and ".." not in p.parts, "unsafe public path")
    require(not any(x.lower().startswith(".env") or x.lower() in {
        "secrets", "credentials", "private-keys", "private_keys"
    } for x in p.parts), "private path refused")
    require(not p.name.lower().endswith((".pem", ".key", ".p12", ".pfx"))
            or name == "crates/attestation/tests/fixtures/azure/ak.pem",
            "private-key material refused")
    return p


def sha(p):
    p = Path(p)
    require(p.is_file() and not p.is_symlink(), "nonregular checksum input refused")
    with p.open("rb") as f:
        h = hashlib.sha256()
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
        return h.hexdigest()


def git(*args, cwd=ROOT):
    return subprocess.check_output(["git", *args], cwd=cwd)


def capture():
    require(not OUT.exists() and not OUT.is_symlink(), "baseline already exists")
    head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    status = git("status", "--porcelain=v1", "--untracked-files=all").decode()
    require(head == EXPECTED_HEAD and tree == EXPECTED_TREE and not status,
            "pristine merged main required before capture")
    prior = json.loads(PRIOR.read_text())
    post = json.loads(POSTMERGE.read_text())
    require(post["passed"] and post["actual_head"] == EXPECTED_HEAD,
            "prior merged preservation mismatch")
    tracked = git("ls-files", "-z").decode().split("\0")
    tracked = sorted(x for x in tracked if x)
    tracked_hashes = {name: sha(ROOT / public_path(name)) for name in tracked}
    external = []
    for item in prior["external"]:
        checkout = Path(item["path"])
        actual_head = git("rev-parse", "HEAD", cwd=checkout).decode().strip()
        actual_status = git("status", "--porcelain=v1", "--untracked-files=all", cwd=checkout).decode()
        # These existing staged files are all constrained by the prior public dirty map.
        staged_names = git("diff", "--cached", "--name-only", "-z", cwd=checkout).decode().split("\0")
        require(all(not x or x in item["dirty_file_sha256"] for x in staged_names),
                "staged input outside prior approved public map")
        staged = hashlib.sha256(git("diff", "--cached", "--binary", cwd=checkout)).hexdigest()
        dirty_hashes = {name: sha(checkout / public_path(name))
                        for name in item["dirty_file_sha256"]}
        checks = {
            "head": actual_head == item["head"],
            "status": actual_status == item["status"],
            "staged": staged == item["staged_binary_diff_sha256"],
            "dirty_bytes": dirty_hashes == item["dirty_file_sha256"],
        }
        require(all(checks.values()), "external public preservation mismatch: " + item["name"])
        external.append({"name": item["name"], "path": str(checkout),
                         "head": actual_head, "status": actual_status,
                         "dirty_count": len(actual_status.splitlines()),
                         "staged_binary_diff_sha256": staged,
                         "dirty_file_sha256": dirty_hashes,
                         "matches_previous_baseline": checks})
    require([x["dirty_count"] for x in external] == [13, 7, 62], "external dirty count mismatch")
    require(sum(len(x["dirty_file_sha256"]) for x in external) == 82, "external82 required")
    sys.path.insert(0, str(ROOT / "scripts/local-verification"))
    import candidate_identity_manifest as identity
    sources = identity.source_inventory(ROOT)
    source_sha = identity.digest(identity.canonical(sources))
    require(len(sources) == 375 and source_sha == EXPECTED_SOURCE, "current375 source inventory mismatch")
    pin_maps = {"reviewed21": identity.legacy.clock.EXPECTED_GUEST_SOURCES,
                "candidate9": identity.candidate.CANDIDATE_SOURCES,
                "auxiliary2": identity.AUXILIARY_TEST_SOURCES}
    require([len(x) for x in pin_maps.values()] == [21, 9, 2], "pin counts mismatch")
    pins = {}
    for label, expected in pin_maps.items():
        actual = {name: sha(ROOT / public_path(name)) for name in expected}
        require(expected == prior["pins"][label]["expected_sha256"] and actual == expected,
                "preserved pins mismatch")
        pins[label] = {"count": len(expected), "expected_sha256": expected,
                       "actual_sha256": actual, "passed": True}
    manifests = {name: sha(ROOT / name) for name in ("Cargo.toml", "Cargo.lock")}
    require(manifests == prior["root_manifests_sha256"], "root Cargo manifests changed")
    dest = ROOT.parent
    ledger_path = dest / "Arcora_PR57_Kanit_2026-10-12/delivery-ledger.json"
    ledger = json.loads(ledger_path.read_text())
    delivered = {}
    for name, expected in ledger["files"].items():
        p = ledger_path.parent / public_path(name)
        actual = {"sha256": sha(p), "bytes": p.stat().st_size}
        require(actual == expected, "original PR57 copied evidence mismatch")
        delivered[name] = actual
    report_pins = {
        "Arcora_Durum_Raporu_2026-10-12_PR57.md": ledger["report_sha256"],
        "Arcora_PR57_2026-10-12.json": ledger["publication_record_sha256"],
        "Arcora_Merge_57_2026-10-12.json": ledger["merge_record_sha256"],
        "Arcora_Devam_2026-10-11.md": ledger["continuation_pointer_sha256"],
        "Arcora_Devam_2026-10-11_PR56_korunan.md": ledger["prior_pointer_backup_sha256"],
        **ledger["old_reports_preserved"],
    }
    report_hashes = {name: sha(dest / public_path(name)) for name in report_pins}
    require(report_hashes == report_pins, "original reports/pointer mismatch")
    # Ensure no root writer began during this capture.
    require(git("rev-parse", "HEAD").decode().strip() == head
            and git("status", "--porcelain=v1", "--untracked-files=all").decode() == status,
            "checkout changed during baseline capture")
    require({name: sha(ROOT / public_path(name)) for name in tracked} == tracked_hashes,
            "tracked public bytes changed during capture")
    record = {
        "schema": "arcora-candidate-public-path-preservation-baseline/v1",
        "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "Fresh clean merged main before public ancestor-symlink repair. Public checksums and existing dirty map only; no secrets, services, tests, Git mutation or network.",
        "base_main": head, "base_tree": tree, "checkout_clean_at_capture": True,
        "allowed_existing_paths": [], "tracked_file_count": len(tracked_hashes),
        "tracked_file_sha256": tracked_hashes,
        "covered_source_inventory": {"source_files": len(sources), "source_sha256": source_sha,
                                     "source_sha256_map": sources},
        "pins": pins, "root_manifests_sha256": manifests,
        "previous_external_baseline": str(PRIOR.relative_to(ROOT)),
        "previous_external_baseline_sha256": sha(PRIOR),
        "previous_pr57_postmerge_preservation_sha256": sha(POSTMERGE),
        "external": external, "external_total_dirty_files": 82,
        "original_pr57_delivery_ledger_sha256": sha(ledger_path),
        "original_pr57_delivered_evidence": delivered,
        "original_public_reports_and_pointer_sha256": report_hashes,
        "passed": True,
    }
    with OUT.open("x") as f:
        json.dump(record, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    print(json.dumps({"path": str(OUT), "sha256": sha(OUT), "clean": True,
                      "tracked": len(tracked_hashes), "source_files": len(sources),
                      "source_sha256": source_sha, "external_dirty": [13, 7, 62],
                      "original_evidence_files": len(delivered), "passed": True}))


if __name__ == "__main__":
    capture()
