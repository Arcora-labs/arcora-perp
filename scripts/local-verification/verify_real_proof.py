#!/usr/bin/env python3
"""Verify a real ordinary Arcora SP1 proof in a fresh local Foundry EVM.

No network prover, chain RPC, broadcast, mock verifier, or fallback fixture.
--guards-only runs explicitly narrower malformed-proof/deployment checks.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
VENDOR = CONTRACTS / "vendor/sp1-contracts"
VERIFIER_HASH = "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"
# Reviewed against the downloaded commit archives. A source edit plus a rewritten
# hash map must not redefine the trusted verifier while retaining commit labels.
VENDOR_PROVENANCE_SHA256 = "46c7595268e5ed35e04feae8efb292ea25035398d57dae8f7cafa7f4f39add16"
# Current reviewed Arcora guest identity, independently recorded in
# docs/audits/2026-09-28-post-merge/release-manifest.json and
# elf-reproducibility.json. Update these pins only with a reviewed guest rebuild,
# fresh SP1 setup, and matching release evidence; input proof manifests cannot
# nominate another guest or program key.
EXPECTED_ARCORA_ELF_SHA256 = "82938f5db13d7da2cc48fc18e36ba6a5e6d5f0736154ae9e105b33b8717918d7"
EXPECTED_ARCORA_PROGRAM_VKEY = "0x00ab0d3f8dbcadb423593ef582e637e864ef538537f43e433a8f1466aaa2dfcf"
EXPECTED_UPSTREAMS = {
    "https://github.com/succinctlabs/sp1-contracts": "2ac5ecbbe473421a963d67e55f182e9a36576f7c",
    "https://github.com/OpenZeppelin/openzeppelin-contracts": "dbb6104ce834628e473d2173bbc9d47f81a9eec3",
}
EXPECTED_VENDOR_FILES = {
    "src/ISP1Verifier.sol",
    "src/ISP1VerifierGateway.sol",
    "src/SP1VerifierGateway.sol",
    "src/v6.1.0/SP1VerifierGroth16.sol",
    "src/v6.1.0/Groth16Verifier.sol",
    "lib/openzeppelin-contracts/LICENSE",
    "lib/openzeppelin-contracts/contracts/access/Ownable.sol",
    "lib/openzeppelin-contracts/contracts/utils/Context.sol",
}
VENDOR_LOCAL_FILES = {"PROVENANCE.json", "foundry.toml", "README.arcora.md"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_bound_file(base, name, entry):
    relative = Path(name)
    require(not relative.is_absolute() and ".." not in relative.parts, f"unsafe artifact path: {name}")
    path = base / relative
    require(path.resolve().is_relative_to(base.resolve()), f"artifact escapes directory: {name}")
    data = path.read_bytes()
    require(sha256(data) == entry["sha256"], f"artifact hash mismatch: {name}")
    require(len(data) == entry["size_bytes"], f"artifact size mismatch: {name}")
    return data


def verify_vendor():
    require(not VENDOR.is_symlink(), "vendored source directory must not be a symlink")
    inventory = set()
    for path in VENDOR.rglob("*"):
        relative = path.relative_to(VENDOR).as_posix()
        require(not path.is_symlink(), f"vendored symlink is forbidden: {relative}")
        require(path.is_dir() or path.is_file(), f"unsupported vendored entry: {relative}")
        if path.is_file():
            inventory.add(relative)
    require(inventory == EXPECTED_VENDOR_FILES | VENDOR_LOCAL_FILES, "unexpected vendored disk inventory")
    provenance_data = (VENDOR / "PROVENANCE.json").read_bytes()
    require(sha256(provenance_data) == VENDOR_PROVENANCE_SHA256, "unreviewed upstream provenance manifest")
    manifest = json.loads(provenance_data)
    upstreams = {row["repository"]: row["commit"] for row in manifest["upstreams"]}
    require(upstreams == EXPECTED_UPSTREAMS, "unexpected upstream verifier identity")
    require(set(manifest["files"]) == EXPECTED_VENDOR_FILES, "unexpected vendored file set")
    for name, entry in manifest["files"].items():
        require(EXPECTED_UPSTREAMS.get(entry["repository"]) == entry["commit"], f"wrong source: {name}")
        read_bound_file(VENDOR, name, entry)
    return manifest


def load_proof(directory):
    manifest_data = (directory / "manifest.json").read_bytes()
    manifest = json.loads(manifest_data)
    require(manifest.get("kind") == "ordinary-local-groth16-proof", "ordinary Arcora proof manifest required")
    require(manifest.get("sdk_version") == "6.1.0", "SP1 SDK 6.1.0 required")
    require(str(manifest.get("proof_sp1_version", "")).removeprefix("v") == "6.1.0", "SP1 proof version 6.1.0 required")
    for flag in ("proof_generated", "local_sdk_verified", "native_guest_equal", "native_deserialized_same_witness"):
        require(manifest.get(flag) is True, f"incomplete proof evidence: {flag}")
    require(manifest.get("a06_executed") is False, "ordinary proof scope required")
    names = {"normal.witness.bin", "guest.elf", "program-vkey.bin", "proof.bin", "public-values.bin", "proof.sdk.json"}
    artifacts = manifest.get("artifacts", {})
    require(names <= artifacts.keys(), "proof artifact set incomplete")
    bound = {name: read_bound_file(directory, name, entry) for name, entry in artifacts.items()}
    vkey, commitment, proof = (bound[name] for name in ("program-vkey.bin", "public-values.bin", "proof.bin"))
    require(len(vkey) == 32 and len(commitment) == 32, "program key and public commitment must be 32 bytes")
    require(len(proof) == 356, "SP1 v6.1 Groth16 payload must be 356 bytes")
    require(proof[:4].hex() == VERIFIER_HASH[:8], "wrong target-verifier selector")
    require(bound["guest.elf"].startswith(b"\x7fELF"), "guest ELF required")
    require(sha256(bound["guest.elf"]) == EXPECTED_ARCORA_ELF_SHA256, "unreviewed Arcora guest ELF")
    require("0x" + vkey.hex() == EXPECTED_ARCORA_PROGRAM_VKEY, "unreviewed Arcora program key")
    require(manifest.get("program_vkey") == "0x" + vkey.hex(), "program key manifest mismatch")
    require(manifest.get("roots", {}).get("commitment") == "0x" + commitment.hex(), "native/guest commitment mismatch")
    require(manifest.get("witness_sha256") == sha256(bound["normal.witness.bin"]), "witness manifest mismatch")
    json.loads(bound["proof.sdk.json"])
    return manifest, manifest_data, {
        "ARCORA_REAL_PROGRAM_VKEY": "0x" + vkey.hex(),
        "ARCORA_REAL_PUBLIC_COMMITMENT": "0x" + commitment.hex(),
        "ARCORA_REAL_PROOF": "0x" + proof.hex(),
    }


def run(command, output, label, env):
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    (output / f"{label}.stdout.log").write_text(result.stdout)
    (output / f"{label}.stderr.log").write_text(result.stderr)
    require(result.returncode == 0, f"{label} failed (exit {result.returncode}); see {output}")
    return result.stdout


def compiled_identity(relative_path):
    data = (CONTRACTS / relative_path).read_bytes()
    artifact = json.loads(data)
    metadata = artifact["metadata"]
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    return {
        "artifact_path": str(relative_path),
        "artifact_sha256": sha256(data),
        "compiler": metadata["compiler"]["version"],
        "creation_bytecode_sha256": sha256(bytes.fromhex(artifact["bytecode"]["object"].removeprefix("0x"))),
        "deployed_bytecode_template_sha256": sha256(bytes.fromhex(artifact["deployedBytecode"]["object"].removeprefix("0x"))),
        "note": "Adapter deployed bytecode contains constructor immutables; this hash identifies its compiler template.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--artifact-dir", type=Path)
    mode.add_argument("--guards-only", action="store_true")
    parser.add_argument("--output-dir", required=True, type=Path, help="fresh evidence directory")
    args = parser.parse_args()
    vendor = verify_vendor()
    manifest = manifest_data = None
    proof_env = {}
    if args.artifact_dir:
        manifest, manifest_data, proof_env = load_proof(args.artifact_dir.resolve())
    # Fail before compiling if the actual proof is missing or is not bound to its
    # witness, ELF, program key, public values and SDK verification manifest.
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env["FOUNDRY_PROFILE"] = "default"
    env.update(proof_env)
    forge_version = run(["forge", "--version"], output, "forge-version", env).strip()
    run(["forge", "build", "--root", str(VENDOR)], output, "upstream-build", env)
    env["FOUNDRY_PROFILE"] = "real_proof"
    selected = "SP1RealVerifierGuardTest" if args.guards_only else "SP1Real(VerifierGuard|Proof)Test"
    raw = run(["forge", "test", "--root", str(CONTRACTS), "--match-contract", selected, "--json"], output, "forge-tests", env)
    suites = json.loads(raw)
    expected = {"SP1RealVerifierGuardTest": 8}
    if not args.guards_only:
        expected["SP1RealProofTest"] = 10
    counts = {}
    for suite_name, suite in suites.items():
        name = suite_name.rsplit(":", 1)[-1]
        tests = suite["test_results"]
        require(name in expected, f"unexpected test suite: {name}")
        require(all(test["status"] == "Success" for test in tests.values()), f"non-passing or skipped tests: {name}")
        require(len(tests) == expected[name], f"incomplete test suite: {name}")
        counts[name] = len(tests)
    require(counts == expected, "required test suites did not all execute")
    identities = {
        "verifier": compiled_identity(Path("out/sp1-upstream/SP1VerifierGroth16.sol/SP1Verifier.json")),
        "gateway": compiled_identity(Path("out/sp1-upstream/SP1VerifierGateway.sol/SP1VerifierGateway.json")),
        "adapter": compiled_identity(Path("out/SP1ZkVerifier.sol/SP1ZkVerifier.json")),
    }
    require(identities["verifier"]["compiler"].startswith("0.8.20+"), "unexpected upstream compiler")
    require(identities["gateway"]["compiler"].startswith("0.8.20+"), "unexpected gateway compiler")
    require(identities["adapter"]["compiler"].startswith("0.8.24+"), "unexpected Arcora compiler")
    source_paths = [Path(__file__)] + list((CONTRACTS / "integration").glob("*.sol")) + [
        CONTRACTS / "src/SP1ZkVerifier.sol", CONTRACTS / "src/interfaces/ISP1Verifier.sol",
        CONTRACTS / "foundry.toml", VENDOR / "foundry.toml", VENDOR / "PROVENANCE.json",
    ]
    report = {
        "schema_version": 1,
        "kind": "real-sp1-verifier-guards" if args.guards_only else "ordinary-arcora-real-sp1-target-verification",
        "status": "PASS", "target_verifier_executed": not args.guards_only,
        "application_proof_accepted": not args.guards_only,
        "a06_executed": False, "production_deployed": False,
        "local_evm_only": True, "mock_verifier_used": False,
        "scope": "Malformed-proof/deployment guards only." if args.guards_only else "Ordinary proof, direct real verifier, real gateway, adapter, and binding/route negatives; not a full token lifecycle.",
        "verifier_hash": "0x" + VERIFIER_HASH,
        "expected_arcora_guest": {"elf_sha256": EXPECTED_ARCORA_ELF_SHA256, "program_vkey": EXPECTED_ARCORA_PROGRAM_VKEY},
        "vendor_upstreams": vendor["upstreams"], "compiled_contracts": identities,
        "forge_version": forge_version, "passed_test_counts": counts,
        "source_sha256": {str(p.relative_to(ROOT)): sha256(p.read_bytes()) for p in sorted(source_paths)},
    }
    if manifest is not None:
        (output / "input-proof-manifest.json").write_bytes(manifest_data)
        report["input_proof_manifest_sha256"] = sha256(manifest_data)
        report["input_artifacts"] = manifest["artifacts"]
        report["program_vkey"] = manifest["program_vkey"]
        report["public_commitment"] = manifest["roots"]["commitment"]
    report["evidence_sha256"] = {p.name: sha256(p.read_bytes()) for p in sorted(output.iterdir()) if p.is_file()}
    # The only success report is emitted after every required suite ran with no skips.
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "kind": report["kind"], "passed": sum(counts.values()), "application_proof_accepted": not args.guards_only, "report": str(output / "verification.json")}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"Real proof verification failed: {error}", file=sys.stderr)
        sys.exit(1)
