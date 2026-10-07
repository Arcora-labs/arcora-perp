#!/usr/bin/env python3
"""Bind completed local check records to source and preserve incomplete graph gates."""
import collections
import datetime
import hashlib
import json
import pathlib
import re
import subprocess

from run_check import ROOT, identity

OUT = ROOT / "docs/audits/2026-09-27-local"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


subject = identity()
write("source-manifest.json", subject)
tasks = json.loads((OUT / "task-status.json").read_text())
tasks["source_manifest"] = "source-manifest.json"
tasks["source_sha256"] = subject["source_sha256"]
write("task-status.json", tasks)
checks = {}
labels = ["workspace-integrated", "clippy-integrated", "fmt-integrated", "foundry-final",
          "core-debug-after", "core-release-integrated", "s3-final", "real-cast-portable",
          "core-no-std", "matcher-no-std", "ci-profile-regression", "prover-service-tests",
          "prover-service-real-elf", "sp1-host-with-protoc", "sp1-vkey",
          "guest-rebuild-pinned-path", "live-http-restore-integrated"]
for label in labels:
    path = OUT / "checks" / (label + ".json")
    record = json.loads(path.read_text())
    assert record["exit_code"] == 0, f"required local check failed: {label}"
    assert digest(path.with_suffix(".log")) == record["log_sha256"], label
    rows = record["rust_test_summaries"]
    before = record["source_before"]["files"]
    after = record["source_after"]["files"]
    changed_during = sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
    changed_since = sorted(k for k in after.keys() | subject["files"].keys() if after.get(k) != subject["files"].get(k))
    checks[label] = {
        "record": str(path.relative_to(OUT)), "record_sha256": digest(path),
        "exit_code": record["exit_code"], "duration_seconds": record["duration_seconds"],
        "passed": sum(int(x[1]) for x in rows) if rows else None,
        "failed": sum(int(x[2]) for x in rows) if rows else None,
        "ignored": sum(int(x[3]) for x in rows) if rows else None,
        "changed_during_check": changed_during, "changed_since_check": changed_since,
    }

# The final Rust source must match the integrated execution; docs and unrelated
# excluded/JS files are captured above, rather than being treated as compiled code.
workspace_inputs = lambda p: p in {"Cargo.toml", "Cargo.lock"} or (
    p.startswith("crates/") and not p.startswith(("crates/sp1-host/", "crates/sp1-guest/", "crates/prover-service/")))
for label in ["workspace-integrated", "clippy-integrated"]:
    assert not [p for p in checks[label]["changed_during_check"] + checks[label]["changed_since_check"] if workspace_inputs(p)], label
front = json.loads((OUT / "frontend/evidence.json").read_text())
for command in front["commands"]:
    assert command["exit_code"] == 0
    assert digest(OUT / "frontend" / command["log"]) == command["log_sha256"]
for task in tasks["tasks"]:
    for path in task["evidence"]:
        if path not in {"final-evidence-manifest.json", "protocol/release-manifest.json"}:
            assert (OUT / path).is_file(), (task["id"], path)
    if task["status"] == "PASS":
        assert all(c["passed"] for c in task["criteria"])
        assert not task["unpassed_dependencies"]

locks = {p: digest(ROOT / p) for p in ["Cargo.lock", "frontend/pnpm-lock.yaml",
         "crates/sp1-guest/Cargo.lock", "crates/sp1-host/Cargo.lock", "crates/prover-service/Cargo.lock"]}
write("baseline/final-lock-hashes.json", locks)
elf = ROOT / "crates/sp1-guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/perp-core-guest"
assert digest(elf) == json.loads((OUT / "protocol/guest-reproducibility-pinned-path.json").read_text())["after_sha256"]
vkey = re.search(r"0x[0-9a-f]{64}", (OUT / "checks/sp1-vkey.log").read_text()).group(0)
release = {
    "status": "LOCAL_CANDIDATE_PARTIAL_NO_RELEASE", "base_sha": subject["head_sha"],
    "base_tree": subject["tree_sha"], "dirty_source_sha256": subject["source_sha256"],
    "elf_path": str(elf.relative_to(ROOT)), "elf_sha256": digest(elf), "elf_bytes": elf.stat().st_size,
    "sp1_version": "6.0.0", "guest_rustc": "1.93.0-dev succinct", "program_vkey": vkey,
    "lock_hashes": locks, "real_proof": None, "real_verifier_receipt": None,
    "normal_native_guest_parity": "checks/sp1-host-with-protoc.json",
    "a06_gate": "protocol/a06-execution-gate.json",
    "rebuild": "protocol/guest-reproducibility-pinned-path.json",
    "limits": ["No release commit, proof, deployment or authorization inferred.",
               "Repository July vkey differs from measured local key; live deployment observation failed403, so live key unknown."],
}
write("protocol/release-manifest.json", release)

contract = {"schema_version": 1, "task_id": "arcora-local-20260927", "criteria": []}
report = {"schema_version": 1, "task_id": contract["task_id"], "subject": subject["source_sha256"], "checks": [], "blockers": []}
for task in tasks["tasks"]:
    contract["criteria"].append({"id": task["id"], "description": task["title"], "verifier": "inspection"})
    passed = task["status"] == "PASS"
    check = {"criterion_id": task["id"], "subject": subject["source_sha256"], "status": "PASS" if passed else "BLOCKED"}
    if passed:
        check.update(assertion="Integrator inspected current criteria, scoped runtime records and explicit limits in task-status.json.",
                     reviewer="Codex integrating agent; not external audit", evidence={"path": "task-status.json", "sha256": digest(OUT / "task-status.json")})
    else:
        report["blockers"].append(task["id"] + ": " + "; ".join(task["limits"]))
    report["checks"].append(check)
write("graph-contract.json", contract)
write("graph-report.json", report)
gate = subprocess.run(["python3", "<local-tooling>/skills/graph-engineering/scripts/check_gate.py",
                       str(OUT / "graph-contract.json"), str(OUT / "graph-report.json"),
                       "--expected-subject", subject["source_sha256"]], text=True, capture_output=True)
(OUT / "graph-gate.json").write_text(gate.stdout)
assert gate.returncode == 1 and json.loads(gate.stdout)["gate"] == "CLOSED", gate.stderr

artifacts = {str(p.relative_to(OUT)): {"sha256": digest(p), "bytes": p.stat().st_size}
             for p in sorted(OUT.rglob("*")) if p.is_file() and p.name != "final-evidence-manifest.json"}
manifest = {
    "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "status": "PARTIAL", "release_gate": "CLOSED", "worktree": str(ROOT),
    "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
    "source": {k: v for k, v in subject.items() if k != "files"},
    "task_counts": dict(collections.Counter(t["status"] for t in tasks["tasks"])),
    "local_checks": checks, "frontend_evidence": "frontend/evidence.json",
    "artifacts": artifacts,
    "count_rule": "Overlapping runs are separate selections and must not be summed.",
    "selected_final_check_log_hashes_verified": True,
}
write("final-evidence-manifest.json", manifest)
print(json.dumps({"tasks": manifest["task_counts"], "rust_tests": checks["workspace-integrated"]["passed"],
                  "source_sha256": subject["source_sha256"], "artifacts": len(artifacts), "release_gate": "CLOSED"}))
