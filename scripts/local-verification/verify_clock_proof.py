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

# Independently pinned source inputs for the rebuilt guest above. A supplied
# proof manifest cannot choose a different program and still pass this gate.
EXPECTED_GUEST_SOURCES = {
    "Cargo.toml": "e3144a0ae3447244776e65b04cfff39267c238e410c2d9abf20b53e6b837bbfa",
    "crates/perp-core/Cargo.toml": "3bfb6981fa34a967185ce75abd07683e5262a694ebd60eb45a4f5c55aaf9704c",
    "crates/perp-core/src/clock.rs": "e89e50e11b3ffb3a4a1a89ab6dd4854b61606cc17eb1236492994df0b59d50e7",
    "crates/perp-core/src/commitment.rs": "43582ef5048d0d725e53976e3c2a1dfcf32984ed2ad1bb2ebd2032463e26ea92",
    "crates/perp-core/src/engine.rs": "4d6037f1189939a71a41e31882012e6fa50b887087b5ccc2bfce4502b61d0f9e",
    "crates/perp-core/src/error.rs": "0738da822be5639737e67f04a0f500af57fcc1f085dd64bec7fbe3b016c515c6",
    "crates/perp-core/src/fixed.rs": "fc77559a31c1cfdd7a641cafbd773871aeb203849e165dbd158aa7a1b65ef7cd",
    "crates/perp-core/src/funding.rs": "8f782cf3a4403c717eda44c6d2955789c31e4ef2a04bb4fdac8e61916018e781",
    "crates/perp-core/src/hash.rs": "88430a8c2558b247bcf241035ad48fa1dbf8a3e77a0d176dfdbd608c930f93b9",
    "crates/perp-core/src/lib.rs": "8f070fbec0f4b3d3fab5e594bcf808845803a59ece403dc42cb0f0df6e6253b5",
    "crates/perp-core/src/market.rs": "8053e89a9b1021d6e461d46d733dfb1935aff5fc2a45be8121f96560fa4ddc2d",
    "crates/perp-core/src/merkle.rs": "173f4667178ba4aa4048e43c2aeb9fa337918d6225b98c6597c004b59bc3a8f6",
    "crates/perp-core/src/note.rs": "5cece4d513537c10464bd64b4612f829cd32cb9c1a80d3c8e40c573aace62423",
    "crates/perp-core/src/nullifier.rs": "a252799c62dc42ec37c91ba6fd7674117b33c98c7f83e86b168f70898966ea78",
    "crates/perp-core/src/oracle.rs": "91ae09655e35432aafa1135b23588d6f1f324b41a278ac640ebc30f106d17da2",
    "crates/perp-core/src/order.rs": "99bb9b2be4948bcf8365c3022ef444be5941201ec6535de73d45a777e5a206d7",
    "crates/perp-core/src/position.rs": "99d120139086092d2dae4ed11d3a677906c1cf3efd7aff9e58f27f3437f2ae66",
    "crates/perp-core/src/state.rs": "e1026c1e2b56cfcbee4eff812e88ff3dcde052e46818deab980a071fcdbec388",
    "crates/sp1-guest/Cargo.lock": "113518cb212208aa46a629608af9d946f9a4006ac211035a15e9cb8c022fb8c3",
    "crates/sp1-guest/Cargo.toml": "d0ed7050076bb3548b9e3410f63066068752382f4dab31e344096c9c3e42dc85",
    "crates/sp1-guest/src/main.rs": "c0d33ff8645ebdcc8994d4d65729b8a60a224bcda18415423da15ed875c16f5c"
}


def verify_guest_source():
    for name, digest in EXPECTED_GUEST_SOURCES.items():
        path = target.ROOT / name
        target.require(path.is_file() and not path.is_symlink(), f"missing/nonregular guest source: {name}")
        target.require(target.sha256(path.read_bytes()) == digest, f"guest source changed; rebuild and reprove: {name}")
    return dict(EXPECTED_GUEST_SOURCES)


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
    for field in ("proof_generated", "native_guest_equal"):
        target.require(manifest.get(field) is True, f"incomplete proof evidence: {field}")
    sdk_verified = manifest.get("local_sdk_verified") is True
    rust_verified = (manifest.get("rust_sp1_verifier_verified") is True
                     and manifest.get("rust_verifier_version") == "6.1.0")
    target.require(sdk_verified or rust_verified, "incomplete proof evidence: cryptographic verification")
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
    verify_guest_source()
    vendor = target.verify_vendor()
    files, proof_env = load_clock_proof(args.artifact_dir)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update(proof_env)
    env["FOUNDRY_PROFILE"] = "default"
    target.run(["forge", "build", "--root", str(target.VENDOR)], output, "upstream-build", env)
    env["FOUNDRY_PROFILE"] = "real_proof"
    raw = target.run(["forge", "test", "--root", str(target.CONTRACTS), "--match-contract",
                      "(SP1Real(VerifierGuard|Proof)Test|ClockBoundRealProofTest)", "--json"], output, "real-target-tests", env)
    counts = {}
    for suite_name, suite in json.loads(raw).items():
        name = suite_name.rsplit(":", 1)[-1]
        results = suite["test_results"]
        target.require(all(t["status"] == "Success" for t in results.values()), f"failed/skipped suite: {name}")
        counts[name] = len(results)
    target.require(counts == {"SP1RealVerifierGuardTest": 8, "SP1RealProofTest": 10, "ClockBoundRealProofTest": 6}, "missing actual target suites")
    compiled = {
        "upstream_verifier": target.compiled_identity(Path("out/sp1-upstream/SP1VerifierGroth16.sol/SP1Verifier.json")),
        "upstream_gateway": target.compiled_identity(Path("out/sp1-upstream/SP1VerifierGateway.sol/SP1VerifierGateway.json")),
        "sp1_adapter": target.compiled_identity(Path("out/SP1ZkVerifier.sol/SP1ZkVerifier.json")),
        "clock_adapter": target.compiled_identity(Path("out/ClockBoundVerifier.sol/ClockBoundVerifier.json")),
        "settlement": target.compiled_identity(Path("out/DarkPerpSettlement.sol/DarkPerpSettlement.json")),
        "vault": target.compiled_identity(Path("out/CollateralVault.sol/CollateralVault.json")),
    }
    for name, identity in compiled.items():
        expected = "0.8.20+" if name.startswith("upstream_") else "0.8.24+"
        target.require(identity["compiler"].startswith(expected), f"unexpected compiler: {name}")
    paths = [Path(__file__), target.ROOT / "scripts/local-verification/verify_real_proof.py"]
    paths += sorted((target.CONTRACTS / "integration").glob("*.sol"))
    paths += [target.CONTRACTS / "src" / name for name in
              ("SP1ZkVerifier.sol", "ClockBoundVerifier.sol", "DarkPerpSettlement.sol", "CollateralVault.sol")]
    checked_sources = {str(path.relative_to(target.ROOT)): target.sha256(path.read_bytes()) for path in paths}
    report = {"status": "PASS", "kind": "clock-v2-real-sp1-target-verification", "local_evm_only": True,
              "mock_proof_used": False, "production_deployed": False, "full_token_lifecycle": False,
              "clock_adapter_full_lifecycle": False, "clock_adapter_synthetic_settlement_verified": True, "synthetic_vault_claim_verified": True, "mock_token_used": True, "fixture_address_constructors": True, "synthetic_zero_payer_impersonated": True, "application_proof_accepted": True,
              "scope": "Real clock-v2 proof through SP1 verifier, clock adapter, actual settlement and vault; fixed synthetic addresses and a mock token, not live payer provenance or full order/HTTP/production lifecycle.",
              "guest_elf_sha256": EXPECTED_ELF, "program_vkey": EXPECTED_VKEY,
              "public_commitment": EXPECTED_COMMITMENT, "tests": counts,
              "input_artifacts": {name: {"sha256": target.sha256(data), "size_bytes": len(data)} for name, data in files.items()},
              "runner_sha256": target.sha256(Path(__file__).read_bytes()),
              "guest_sources_sha256": EXPECTED_GUEST_SOURCES, "source_sha256": checked_sources,
              "compiled_contracts": compiled, "vendor_upstreams": vendor["upstreams"]}
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"Clock target verification refused: {error}", file=sys.stderr)
        sys.exit(1)
