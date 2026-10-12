"""Freeze source-bound local evidence without claiming publication CI."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys

ROOT = Path.cwd()
OUT = ROOT / "target/candidate-public-path-validation-20261012"
PACKET = ROOT / "docs/audits/2026-10-12-candidate-public-paths"
CODE = "bcdb52d24ce4ba363d566a0f398f4bff84186d46"
BASE = "788d46fe793180b73aff2cb33eaf79c744b091ec"
SOURCE = "1e3c1af3f823ca0ed2d74b277b98f11c28140a94c776e2e7ee19bcdfc7715345"
sys.path.insert(0, str(ROOT / "scripts/local-verification"))
import candidate_identity_manifest as identity

def checksum(path):
    assert path.is_file() and not path.is_symlink()
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(path):
    return json.loads(path.read_bytes())

assert not PACKET.exists()
assert subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip() == CODE
sources = identity.source_inventory(ROOT)
assert len(sources) == 375 and identity.digest(identity.canonical(sources)) == SOURCE
preservation = load(OUT / "preservation-final.json")
assert preservation["passed"]
qa = load(OUT / "publication/final-source-qa-v2.json")
assert qa["passed"]
labels = ["regression-before", "regression-before-valid", "relative-before", "regression-after",
          "neighbors-after", "candidate-anvil-after", "gateway-build-after"]
checks = {name: load(OUT / "checks" / (name + ".json")) for name in labels}
for name, value in checks.items():
    assert value["source_inventory_unchanged"] and value["pins_unchanged"]
    for stream in ("stdout", "stderr"):
        assert checksum(OUT / "checks" / (name + "." + stream + ".log")) == value[stream + "_sha256"]
for name in labels[3:]:
    value = checks[name]
    assert value["exit_code"] == 0 and value["source_before"] == sources == value["source_after"]
assert [checks[n]["exit_code"] for n in labels[:3]] == [1, 1, 1]
assert checks["regression-before-valid"]["test_summaries"][0]["tests"] == 55
assert checks["relative-before"]["test_summaries"][0]["tests"] == 1
assert checks["regression-after"]["test_summaries"][0]["tests"] == 56
assert checks["neighbors-after"]["test_summaries"][0]["tests"] == 126
assert "OK (skipped=1)" in (OUT / "checks/neighbors-after.stderr.log").read_text()
anvil = load(OUT / "checks/candidate-anvil-after-evidence.json")
assert anvil["pass"]["status"] == "VERIFIED_AT_FINALIZED_BLOCK" and len(anvil["refusals"]) == 12
assert all(value["status"] == "BLOCKED" for value in anvil["refusals"].values())
assert not any(anvil[n] for n in ("proof_generated", "real_don_verified", "running_services_attested"))
assert anvil["release_gate"] == "HOLD"
paths = subprocess.check_output(["git", "diff", "--name-only", BASE, CODE]).decode().splitlines()
assert len(paths) == 6
code_files = {name: {"sha256": checksum(ROOT / name), "bytes": (ROOT / name).stat().st_size} for name in paths}
for name, entry in code_files.items():
    assert hashlib.sha256(subprocess.check_output(["git", "show", CODE + ":" + name])).hexdigest() == entry["sha256"]

inputs = {}
def include(source, name):
    assert name not in inputs and not Path(name).is_absolute() and ".." not in Path(name).parts
    checksum(source)
    inputs[name] = source

for name in ["baseline.json", "capture_baseline.py", "preservation-expectations.json", "preservation-final.json",
             "record_check.py", "prepare_packet.py", "ancestor-symlink-reproduction.json",
             "test-addition-preservation-final.json", "initial-harness-observation.json"]:
    include(OUT / name, name)
for name in ["final-source-qa.json", "final-source-qa-v2.json", "preserve_final.py", "helper-preparation.json",
             "preservation-helper-initial-failure.json", "preserve_final.initial.py"]:
    include(OUT / "publication" / name, "review/" + name)
for source in sorted((OUT / "publication").glob("*repair*")):
    if source.is_file(): include(source, "review/" + source.name)
for name in labels:
    for suffix in (".json", ".stdout.log", ".stderr.log"):
        include(OUT / "checks" / (name + suffix), "checks/" + name + suffix)
include(OUT / "checks/candidate-anvil-after-evidence.json", "checks/candidate-anvil-after-evidence.json")
base_refresh = ROOT / "target/candidate-main-refresh-20261012-pr57"
for source in sorted(base_refresh.iterdir()):
    if source.is_file(): include(source, "base-main-refresh/" + source.name)

PACKET.mkdir()
artifacts = {}
for name, source in inputs.items():
    target = PACKET / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    assert target.read_bytes() == source.read_bytes()
    artifacts[name] = {"sha256": checksum(target), "bytes": target.stat().st_size,
                       "original": str(source.relative_to(ROOT))}
readme = f"""# Public JSON path checks — local evidence, 12 October 2026

Code `{CODE}` on merged #57 base `{BASE}` refuses prohibited path components,
symlink files and ancestor directories before public JSON I/O. Relative paths
are qualified against the physical current directory without resolving caller
symlinks. Both CLIs preflight all supplied paths and existing output before JSON
reads, compiler/build or RPC construction. Exclusive output creation rechecks
the path. These cooperative checks are not an atomic hostile-filesystem defense.

The code commit contains four Python files and two guides. Old 47 test bodies
are preserved; 25 identity + 31 observer tests include nine new regressions.
Schemas, configured runtime/build/program expectations, Rust and contract code,
reviewed21/candidate9/AUX2 pins and root Cargo files remain unchanged.

| Actual local check | Result |
| --- | --- |
| Accepted before-fix full suite | 55 tests; 30 negative subcase failures; old47 and both new regular CLI positives pass |
| Separate before-fix relative-cwd case | 1 test; 2 negative subcase failures, regular public relative-path positive passes |
| Final identity + observer | 56 PASS / 0 FAIL / 0 SKIP |
| Neighbor tools | 125 PASS / 1 optional legacy Anvil SKIP / 0 FAIL |
| Owned candidate Anvil | 1 PASS, seven real compiled roles, three explicit mocks, 12 BLOCKED refusals |
| Actual gateway build | cargo +1.99.0 check --locked -p gateway --bin gateway PASS; no new full local gateway test claim |

The first `regression-before` draft is **not accepted before-fix evidence**:
a new positive test used a MagicMock in place of a class and failed isinstance.
Its raw output is retained. `regression-before-valid` uses the repaired positive
harness; `relative-before` then adds the separate relative-cwd regression.
The final source map is 375 files / `{SOURCE}`. All four final command receipts
bind the same before/after map; each historical failure retains its own map.

Read [test preservation](test-addition-preservation-final.json),
[final source review](review/final-source-qa-v2.json),
[preservation](preservation-final.json) and [artifact ledger](artifact-ledger.json).
Check/raw-output receipts are under `checks/`. `base-main-refresh/` is only #57's
historical push evidence (three workflows / fourteen jobs SUCCESS), not this
code's publication CI. Publication-head CI and normal merge are recorded later.

The baseline is 3045 tracked files. The eight allowed existing paths include
the six code files plus .gitattributes and ACTIVE_WORK metadata. Original three
dirty worktrees and their 82 public dirty-file bodies/status/staged diffs, and
#57's delivered 247 files/reports/pointer, are preserved by the local audit.
Copied helper scripts document provenance; execute originals in the ignored
validation directory rather than relocating them as standalone commands.

No real secret was opened, no public target RPC or feed discovery was called,
no gateway/prover service was started, and no
new proof, candidate backend, attestation/key release, transaction, custody or
independent approval was obtained. Actual approved target/policy/service/key
inputs are missing. Live-feed discovery remains deferred; production HOLD.
"""
with (PACKET / "README.md").open("x") as stream: stream.write(readme)
artifacts["README.md"] = {"sha256": checksum(PACKET / "README.md"), "bytes": (PACKET / "README.md").stat().st_size}
ledger = {"schema": "arcora-candidate-public-path-artifact-ledger/v1", "code_commit": CODE, "base": BASE,
          "covered_source_files": len(sources), "covered_source_map_sha256": SOURCE,
          "covered_source_sha256": sources, "code_files": code_files, "artifacts": artifacts,
          "local_validation": {"final_unit_tests": 56, "new_tests": 9, "old_tests_unchanged": 47,
              "neighbor_passed": 125, "neighbor_skipped": 1, "candidate_anvil_passed": 1,
              "candidate_anvil_refusals": 12, "gateway_build_passed": True,
              "local_full_gateway_rerun": False, "invalid_initial_harness_excluded": True},
          "publication_ci_observed": False, "production_release": "HOLD"}
with (PACKET / "artifact-ledger.json").open("x") as stream: stream.write(json.dumps(ledger, indent=2) + "\n")
print(json.dumps({"artifacts": len(artifacts), "copied_originals": len(inputs),
                  "ledger_sha256": checksum(PACKET / "artifact-ledger.json"), "source_map": SOURCE}))
