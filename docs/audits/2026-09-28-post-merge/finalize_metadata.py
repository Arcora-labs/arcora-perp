#!/usr/bin/env python3
"""Bind this execution's retained evidence to the committed combined source."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("runner", ROOT / "scripts/local-verification/run_check.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2) + "\n")


def json_at(name):
    return json.loads((OUT / name).read_text())


current = runner.identity()
assert current["head_sha"].startswith("31f62652"), "run at the frozen source candidate"
for path in subprocess.check_output(["git", "diff", "HEAD", "--name-only"], cwd=ROOT).decode().splitlines():
    assert path.startswith("docs/audits/2026-09-28-post-merge/"), path
for path in subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT).decode().splitlines():
    assert path.startswith("docs/audits/2026-09-28-post-merge/"), path
write("source-manifest.json", current)

checks = {}
required = ["workspace-tests", "workspace-fmt", "workspace-clippy", "release-guards", "audit-all-locks",
            "deposit-cast-regression", "runtime-witness-cast", "normal-host-tests", "normal-guest-parity",
            "normal-vkey", "rsa-prover-service-final", "sp1-guest-build-rustup", "sp1-guest-clean-rebuild"]
for label in required:
    d = json_at(f"checks/{label}.json")
    assert d["exit_code"] == 0, label
    assert sha(OUT / f"checks/{label}.log") == d["log_sha256"], label
    before, after = d["source_before"]["files"], d["source_after"]["files"]
    names = set(before) | set(after) | set(current["files"])
    during = sorted(n for n in names if before.get(n) != after.get(n))
    since = sorted(n for n in names if after.get(n) != current["files"].get(n))
    allowed = {"docs/L1_RPC_WITNESS.md", "docs/SP1_LOCAL_VERIFICATION.md"}
    if label == "sp1-guest-build-rustup":
        # These host-only helpers are not guest build inputs. The final clean
        # guest rebuild and normal execution additionally bind the final source.
        allowed |= {"crates/sp1-host/src/lib.rs", "crates/sp1-host/src/bin/prove.rs"}
    assert not (set(during) | set(since)) - allowed, (label, during, since)
    checks[label] = {"exit_code": 0, "log_sha256": d["log_sha256"],
                     "changed_during": during, "changed_since": since,
                     "relevant_source_current": True,
                     "rust_test_summaries": d["rust_test_summaries"]}

artifacts = OUT / "normal/run-6.1.0"
normal = json.loads((artifacts / "manifest.json").read_text())
for name, data in normal["artifacts"].items():
    assert sha(artifacts / name) == data["sha256"], name
    assert (artifacts / name).stat().st_size == data["size_bytes"], name
assert normal["native_guest_equal"] and not normal["proof_generated"] and not normal["a06_executed"]
assert normal["guest_exit_code"] == 0 and len(normal["negatives"]) == 2
assert all(n["guest_exit_code"] == 1 and n["public_values_bytes"] == 0 for n in normal["negatives"])
assert "0x" + (artifacts / "normal.public-values.bin").read_bytes().hex() == normal["roots"]["commitment"]
vkey = re.search(r"VKEY=(0x[0-9a-f]{64})", (OUT / "checks/normal-vkey.log").read_text()).group(1)
elf_sha = normal["artifacts"]["guest.elf"]["sha256"]
repro = json_at("elf-reproducibility.json")
assert all(b["sha256"] == elf_sha and sha(Path(b["path"])) == elf_sha for b in repro["builds"])
binding = json_at("rsa/prover-elf-binding.json")
assert binding["new_consumer_sha256"] == elf_sha == sha(Path(binding["consumer_elf"]))
assert sha(Path(binding["test_binary"])) == binding["test_binary_sha256"]
assert binding["test_compiled_after_elf_replacement"] and binding["final_test_exit_code"] == 0

audits = [json.loads(line) for line in (OUT / "checks/audit-all-locks.log").read_text().splitlines() if line.startswith("{")]
locks = ["Cargo.lock", "crates/sp1-host/Cargo.lock", "crates/sp1-guest/Cargo.lock", "crates/prover-service/Cargo.lock", "scripts/tee-capture/Cargo.lock"]
assert len(audits) == len(locks)
audit_summary = []
for lock, audit in zip(locks, audits):
    assert audit["vulnerabilities"]["count"] == 0 and audit["settings"]["ignore"] == []
    assert '\nname = "rsa"\n' not in (ROOT / lock).read_text()
    audit_summary.append({"lock": lock, "sha256": sha(ROOT / lock), "vulnerabilities": 0, "ignored": [],
                          "warnings": {kind: [{"package": x["package"]["name"], "version": x["package"]["version"],
                                                "advisory": x["advisory"]["id"] if x.get("advisory") else None} for x in items]
                                       for kind, items in audit["warnings"].items()}})
write("dependency-summary.json", {"audits": audit_summary, "all_rsa_removed": True,
      "scope": "Zero vulnerability-category findings, not zero security concerns. In particular lru unsoundness warnings remain open and unsuppressed."})

tools = {}
for name, command in {
    "host_rustc": ["<cargo-home>/bin/rustc", "--version", "--verbose"],
    "guest_rustc": ["<cargo-home>/bin/rustc", "+succinct", "--version", "--verbose"],
    "cargo": ["cargo", "--version"], "cast": ["cast", "--version"],
    "sp1_cli": ["/tmp/arcora-tools/sp1-6.1.0/cargo-prove", "prove", "--version"],
    "protoc": ["/tmp/arcora-tools/protoc-29.3/bin/protoc", "--version"],
    "python": ["/opt/homebrew/bin/python3.13", "--version"],
}.items():
    tools[name] = {"argv": command, "output": subprocess.check_output(command, text=True).strip()}
tools["sp1_cli"]["binary_sha256"] = sha(Path(tools["sp1_cli"]["argv"][0]))
guest_rustc = subprocess.check_output(["rustup", "which", "--toolchain", "succinct", "rustc"], text=True).strip()
tools["guest_rustc"]["binary_sha256"] = sha(Path(guest_rustc))
write("tool-versions.json", tools)

manifest = {"source_commit": current["head_sha"], "source_sha256": current["source_sha256"],
            "sp1_version": "6.1.0", "guest_elf": {"path": "normal/run-6.1.0/guest.elf", "sha256": elf_sha, "size_bytes": 515336},
            "program_vkey": vkey, "program_vkey_generated_now": True,
            "witness_sha256": normal["witness_sha256"], "normal_public_commitment": normal["roots"]["commitment"],
            "normal_native_guest_equal": True, "normal_guest_negative_cases": normal["negatives"],
            "same_host_clean_rebuild_byte_equal": True, "cross_host_reproducibility": "not tested",
            "lockfiles": {name: sha(ROOT / name) for name in locks},
            "tool_versions": "tool-versions.json", "upstream_release_and_cli": "sp1-upstream-identity.json",
            "proof_generated": False, "a06_guest_executed": False, "target_verifier_executed": False,
            "release_gate": "HOLD", "current_deployment_matches_this_vkey": "unverified; deployment unchanged"}
write("release-manifest.json", manifest)
write("source-validation.json", {"status": "PASS", "source_commit": current["head_sha"],
      "source_sha256": current["source_sha256"], "source_files": len(current["files"]),
      "source_matches_commit": True, "checks": checks,
      "identity_limits": "Only documented non-input documentation/host-helper changes occurred in earlier commands. Final normal execution, vkey, prover consumer and runtime checks match the full frozen source. The initial wrong-Rust-path build and stale-ELF service run are not success evidence."})

status = json_at("task-status.json")
status["candidate_sha"] = current["head_sha"]
status["source_sha256"] = current["source_sha256"]
status["identity_status"] = "CURRENT_SOURCE_ELF_VKEY_BOUND"
status["delivery"]["new_work"] = "READY_FOR_REVIEW"
baseline = json.loads((ROOT / status["baseline_file"]).read_text())
original = {task["id"]: task for task in baseline["tasks"]}
for task in status["tasks"]:
    assert task["original_criteria"] == original[task["id"]]["criteria"]
    assert task["depends_on"] == original[task["id"]]["depends_on"]
assert sum(t["status"] != "PASS" for t in status["tasks"]) == 7
write("task-status.json", status)
print(json.dumps({"source_commit": current["head_sha"], "source_sha256": current["source_sha256"],
                  "checks_validated": len(checks), "normal_artifacts_validated": len(normal["artifacts"]), "original_remaining": 7}))
