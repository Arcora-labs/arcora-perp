#!/usr/bin/env python3
"""Verify the rebuilt clock-v2 guest's real Groth16 proof in an owned local EVM.

This new-development guest pin does not replace the legacy production release pin.
No live RPC, deployment, mock proof, or artifact-selected guest identity is allowed.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import verify_real_proof as target

EXPECTED_ELF = "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5"
EXPECTED_VKEY = "0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353"
EXPECTED_WITNESS = "e3bbb0db665d9c9394170dcf9c95af15bdbafbe13dd9127088e28babccfd570f"
EXPECTED_COMMITMENT = "0x4fc574af6cf22bc0aaf7a4d72532aabc2a7db8f2cda8d3872c47cf07b18f139e"


def load_clock_proof(directory):
    directory = directory.resolve()
    names = ("proof-evidence.json", "clock.witness.bin", "guest.elf", "program-vkey.bin",
             "proof.bin", "public-values.bin", "proof.sdk.json")
    files = {}
    for name in names:
        path = directory / name
        target.require(not path.is_symlink() and path.is_file(), f"missing/nonregular clock artifact: {name}")
        target.require(path.stat().st_size <= 64 * 1024 * 1024, f"oversized artifact: {name}")
        files[name] = path.read_bytes()
    manifest = json.loads(files["proof-evidence.json"])
    target.require(manifest.get("kind") == "clock-v2-native-guest", "clock-v2 evidence required")
    target.require(manifest.get("sdk_version") == "6.1.0", "wrong SP1 SDK")
    for field in ("proof_generated", "local_sdk_verified", "native_guest_equal"):
        target.require(manifest.get(field) is True, f"incomplete proof evidence: {field}")
    target.require(files["guest.elf"].startswith(b"\x7fELF"), "actual guest ELF required")
    target.require(target.sha256(files["guest.elf"]) == EXPECTED_ELF, "wrong rebuilt clock guest")
    target.require(manifest.get("elf_sha256") == EXPECTED_ELF, "ELF evidence mismatch")
    target.require(target.sha256(files["clock.witness.bin"]) == EXPECTED_WITNESS, "wrong signed-clock fixture")
    target.require(manifest.get("witness_sha256") == EXPECTED_WITNESS, "witness evidence mismatch")
    target.require("0x" + files["program-vkey.bin"].hex() == EXPECTED_VKEY, "wrong setup vkey")
    target.require(manifest.get("program_vkey") == EXPECTED_VKEY, "vkey evidence mismatch")
    target.require("0x" + files["public-values.bin"].hex() == EXPECTED_COMMITMENT, "wrong public digest")
    target.require(manifest.get("commitment") == EXPECTED_COMMITMENT, "native digest mismatch")
    proof = files["proof.bin"]
    target.require(len(proof) == 356 and proof[:4].hex() == target.VERIFIER_HASH[:8], "wrong Groth16 shape/selector")
    sdk = json.loads(files["proof.sdk.json"])
    target.require(str(sdk.get("sp1_version", "")).removeprefix("v") == "6.1.0", "wrong SDK proof version")
    expected = {"wrong-bounds", "wrong-count", "wrong-batch", "wrong-base", "backdated"}
    negatives = manifest.get("negatives", [])
    target.require(len(negatives) == len(expected) and {n.get("name") for n in negatives} == expected,
                   "clock guest negative set incomplete")
    target.require(all(n.get("guest_exit") == 1 and n.get("public_bytes") == 0 for n in negatives),
                   "guest rejection evidence incomplete")
    env = {"ARCORA_REAL_PROGRAM_VKEY": EXPECTED_VKEY,
           "ARCORA_REAL_PUBLIC_COMMITMENT": EXPECTED_COMMITMENT,
           "ARCORA_REAL_PROOF": "0x" + proof.hex()}
    return files, env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    target.verify_vendor()
    files, proof_env = load_clock_proof(args.artifact_dir)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update(proof_env)
    env["FOUNDRY_PROFILE"] = "default"
    target.run(["forge", "build", "--root", str(target.VENDOR)], output, "upstream-build", env)
    env["FOUNDRY_PROFILE"] = "real_proof"
    raw = target.run(["forge", "test", "--root", str(target.CONTRACTS), "--match-contract",
                      "SP1Real(VerifierGuard|Proof)Test", "--json"], output, "real-target-tests", env)
    counts = {}
    for suite_name, suite in json.loads(raw).items():
        name = suite_name.rsplit(":", 1)[-1]
        results = suite["test_results"]
        target.require(all(t["status"] == "Success" for t in results.values()), f"failed/skipped suite: {name}")
        counts[name] = len(results)
    target.require(counts == {"SP1RealVerifierGuardTest": 8, "SP1RealProofTest": 10}, "missing actual target suites")
    report = {"status": "PASS", "kind": "clock-v2-real-sp1-target-verification", "local_evm_only": True,
              "mock_proof_used": False, "production_deployed": False, "full_token_lifecycle": False,
              "clock_adapter_full_lifecycle": False, "application_proof_accepted": True,
              "scope": "Clock-v2 public digest accepted by real SP1 verifier, gateway and SP1ZkVerifier; separate clock-adapter tests do not become full token lifecycle evidence.",
              "guest_elf_sha256": EXPECTED_ELF, "program_vkey": EXPECTED_VKEY,
              "public_commitment": EXPECTED_COMMITMENT, "tests": counts,
              "input_artifacts": {name: {"sha256": target.sha256(data), "size_bytes": len(data)} for name, data in files.items()},
              "runner_sha256": target.sha256(Path(__file__).read_bytes())}
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"Clock target verification refused: {error}", file=sys.stderr)
        sys.exit(1)
