"""Exclusive source-bound checks for the public JSON path regression."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time

ROOT = Path.cwd()
OUT = ROOT / "target/candidate-public-path-validation-20261012/checks"
OUT.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts/local-verification"))
import candidate_identity_manifest as identity

name = sys.argv[1]
patterns = {
    "regression-before": ["test_candidate_identity_manifest.py", "test_candidate_target_observer.py"],
    "regression-before-valid": ["test_candidate_identity_manifest.py", "test_candidate_target_observer.py"],
    "regression-after": ["test_candidate_identity_manifest.py", "test_candidate_target_observer.py"],
    "neighbors-after": ["test_service_build_identity.py", "test_service_identity_preflight.py",
                        "test_release_manifest.py", "test_operator_policy.py",
                        "test_read_deployment.py", "test_check_sp1_release.py",
                        "test_verify_clock_proof.py", "test_repository_policy.py"],
    "candidate-anvil-after": ["test_candidate_target_anvil.py"],
}
if name == "gateway-build-after":
    command = ["/Users/huseyinarslan/.cargo/bin/cargo", "+1.99.0", "check", "--locked", "-p", "gateway", "--bin", "gateway"]
elif name == "relative-before":
    command = [sys.executable, "-c", "import sys,unittest; sys.path.insert(0,'scripts/local-verification'); "
               "suite=unittest.defaultTestLoader.loadTestsFromName('test_candidate_identity_manifest.ManifestTests.test_relative_public_paths_bind_current_directory_before_private_name_checks'); "
               "r=unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(not r.wasSuccessful())"]
elif name in patterns:
    code = ("import sys,unittest; suite=unittest.TestSuite(); loader=unittest.TestLoader(); "
            + "".join("suite.addTests(loader.discover('scripts/local-verification',pattern="
                      + repr(pattern) + ")); " for pattern in patterns[name])
            + "r=unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(not r.wasSuccessful())")
    command = [sys.executable, "-c", code]
else:
    raise ValueError("unknown check label")
before = identity.source_inventory(ROOT)
pins_before = identity.verify_pins(ROOT)
env = os.environ.copy()
env["PYTHONDONTWRITEBYTECODE"] = "1"
env["PATH"] = str(ROOT / "target/candidate-service-validation-20261012/prover/python-bin") + ":" + env["PATH"]
if name == "candidate-anvil-after":
    env["ARCORA_RUN_CANDIDATE_TARGET_ANVIL"] = "1"
    env["ARCORA_CANDIDATE_TARGET_ANVIL_EVIDENCE"] = str(OUT / "candidate-anvil-after-evidence.json")
start = time.monotonic()
stdout_path = OUT / (name + ".stdout.log")
stderr_path = OUT / (name + ".stderr.log")
with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
    run = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, timeout=600)
after = identity.source_inventory(ROOT)
pins_after = identity.verify_pins(ROOT)
raw = stdout_path.read_bytes() + stderr_path.read_bytes()
summary = re.findall(rb"Ran (\d+) tests? in ([0-9.]+)s", raw)
receipt = {
    "schema": "arcora-public-path-check/v1", "label": name,
    "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
    "command": command, "exit_code": run.returncode, "elapsed_seconds": time.monotonic() - start,
    "source_before": before, "source_after": after, "source_files": len(after),
    "source_inventory_unchanged": before == after,
    "source_map_sha256": identity.digest(identity.canonical(after)),
    "pins_before": pins_before, "pins_after": pins_after, "pins_unchanged": pins_before == pins_after,
    "test_summaries": [{"tests": int(count), "seconds": float(seconds)} for count, seconds in summary],
    "stdout_sha256": hashlib.sha256(stdout_path.read_bytes()).hexdigest(),
    "stderr_sha256": hashlib.sha256(stderr_path.read_bytes()).hexdigest(), "production_release": "HOLD",
}
with (OUT / (name + ".json")).open("x") as stream:
    stream.write(json.dumps(receipt, indent=2) + "\n")
print(json.dumps({key: receipt[key] for key in ("label", "exit_code", "elapsed_seconds", "source_files",
                 "source_inventory_unchanged", "source_map_sha256", "pins_unchanged", "test_summaries")}))
sys.exit(run.returncode)
