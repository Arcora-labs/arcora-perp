#!/usr/bin/env python3
"""Reproduce known audit findings in a disposable copy of an exact commit.

Passing tests mean known-bad behavior was observed, NOT that the exchange is safe.
Never edits the checked-out application, deploys, signs transactions, or pushes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

BASELINE = "5eeb37fde378336fc9daae7c6798637317ffb319"
BLOBS = {
    "crates/gateway/src/main.rs": "c183d670a9b817ce6dc9b4419bdd6f8c17e6a6ab",
    "crates/gateway/src/snapshot.rs": "c739785bc84bb5a33a08cc42e70c40b51c349404",
}


def main() -> int:
    root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
    evidence = root / "target" / "audit-2026-09-17-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    status: dict[str, object] = {
        "baseline": BASELINE,
        "meaning": "PASS = known-bad baseline behavior reproduced, not remediated",
        "expected_tests": 8,
        "completed": False,
    }
    try:
        if not shutil.which("cargo"):
            raise RuntimeError("Rust cargo is required; no test result has been produced")
        for path, expected in BLOBS.items():
            actual = subprocess.check_output(["git", "rev-parse", f"{BASELINE}:{path}"], cwd=root, text=True).strip()
            if actual != expected:
                raise RuntimeError(f"Audit baseline blob mismatch: {path}")
        source = Path(__file__).with_name("gateway_repros.rs").read_bytes()
        status["test_source_sha256"] = hashlib.sha256(source).hexdigest()
        status["source_blobs"] = BLOBS
        with tempfile.TemporaryDirectory(prefix="dark-perp-audit-") as temporary:
            scratch = Path(temporary)
            archive = scratch / "source.tar"
            with archive.open("wb") as output:
                subprocess.run(["git", "archive", "--format=tar", BASELINE], cwd=root, stdout=output, check=True)
            with tarfile.open(archive) as bundle:
                # Require the safe extraction API; do not silently fall back on older Python.
                bundle.extractall(scratch / "repo", filter="data")
            checkout = scratch / "repo"
            gateway = checkout / "crates/gateway/src"
            (gateway / "audit_20260917.rs").write_bytes(source)
            with (gateway / "main.rs").open("a", encoding="utf-8") as output:
                output.write("\n#[cfg(test)]\nmod audit_20260917;\n")
            env = os.environ.copy()
            prefixes = ("L1_", "PROVER_", "ATTESTATION_", "FIN_", "INSURANCE_", "DARKPERP_", "ORACLE_")
            for name in list(env):
                if name.startswith(prefixes) or name in {"ENCLAVE_SEED", "GATEWAY_SIGNER_KEY", "DEV_INSECURE"}:
                    env.pop(name, None)
            env["CARGO_TARGET_DIR"] = str(root / "target" / "audit-2026-09-17-build")
            command = ["cargo", "test", "--locked", "-p", "gateway", "audit_20260917::", "--", "--test-threads=1", "--nocapture"]
            status["command"] = command
            with (evidence / "gateway-repros.log").open("w", encoding="utf-8") as log:
                proc = subprocess.run(command, cwd=checkout, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=1_050)
            text = (evidence / "gateway-repros.log").read_text(encoding="utf-8")
            print(text)
            # A zero-test or compile-only run is NOT a successful reproduction.
            success = proc.returncode == 0 and "8 passed; 0 failed" in text and text.count("AUDIT_CASE ") == 8
            status.update(completed=True, cargo_exit=proc.returncode, all_reproduced=success)
            return 0 if success else 1
    except (OSError, RuntimeError, subprocess.SubprocessError, tarfile.TarError) as exc:
        status["error"] = str(exc)
        print(f"Audit reproduction did not complete: {exc}", file=sys.stderr)
        return 1
    finally:
        (evidence / "status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
