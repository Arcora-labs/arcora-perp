#!/usr/bin/env python3
"""Verify a committed real clock-bound Groth16 proof in an owned local EVM.

Two identities are pinned separately and never stand in for each other:

* REVIEWED_GUEST / REVIEWED_FIXTURE: the guest program this checkout must build
  (sources, ELF, setup key) and the outputs of its reviewed normal fixture.
* PROOF_FIXTURE: the committed real proof that the Solidity gate verifies.

The forge environment's setup key and public commitment, and the identity in the
evidence, come only from PROOF_FIXTURE; the proof bytes are the verified
artifact's own. proof_status() reads the committed proof files from disk and is
PROVEN only when they pass the same validation and are the committed proof of
the reviewed fixture under the reviewed guest; otherwise it is PENDING_REPROOF.
Release creation and deployment to a chain that is not an owned test chain
require PROVEN.

This new-development guest pin does not replace the legacy production release pin.
No live RPC, deployment, mock proof, or artifact-selected guest identity is allowed.
"""
import argparse
import json
import os
from pathlib import Path
import sys
from types import MappingProxyType
import verify_real_proof as target

PROVEN = "PROVEN"
PENDING_REPROOF = "PENDING_REPROOF"
SDK_VERSION = "6.1.0"
CLOCK_ARTIFACTS = ("proof-evidence.json", "clock.witness.bin", "guest.elf", "program-vkey.bin",
                   "proof.bin", "public-values.bin", "proof.sdk.json")

# The guest program the checkout is reviewed to build. Its independently pinned
# source inputs mean a supplied proof manifest cannot choose a different program
# and still pass. `identity_dir` holds that program's ELF and setup key.
REVIEWED_GUEST = {
    "elf": "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5",
    "vkey": "0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353",
    "identity_dir": "contracts/integration/fixtures/clock-v2-verified",
    "sources": {
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
        "crates/sp1-guest/src/main.rs": "c0d33ff8645ebdcc8994d4d65729b8a60a224bcda18415423da15ed875c16f5c",
    },
}

# Expected outputs of the reviewed guest on its normal fixture: the witness, the
# bound public commitment, each rejected negative witness, and further case
# witnesses (none yet).
REVIEWED_FIXTURE = {
    "witness_sha256": "e3bbb0db665d9c9394170dcf9c95af15bdbafbe13dd9127088e28babccfd570f",
    "commitment": "0x4fc574af6cf22bc0aaf7a4d72532aabc2a7db8f2cda8d3872c47cf07b18f139e",
    "negatives": {
        "wrong-bounds": "e4057d36e7aec9f61eb537d46957d6ede75c7706c328c699025fbefcfbd26bf5",
        "wrong-count": "8b3ce13a156da3ea015181ee6e70478dd85eec8b4575dc8602ca276387695e46",
        "wrong-batch": "20c6cd884979d825e456666c8c67b77137761f1e192552d8ef6b06d626034d32",
        "wrong-base": "bfbd0612d87718c7560d188a5801e7bca14a9df7216a19177ce0f32fa962e611",
        "backdated": "0ea2e8577cd965c2ea42ba8bc7a2381239ef01e9b6798c862877a20645136c71",
    },
    "cases": {},
}

# The committed real proof and the identity it was generated under. The Solidity
# real-proof gate verifies exactly this proof; it says nothing about another guest.
PROOF_FIXTURE = {
    "dir": "contracts/integration/fixtures/clock-v2-verified",
    "kind": "clock-v2-native-guest",
    "elf": "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5",
    "vkey": "0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353",
    "witness_sha256": "e3bbb0db665d9c9394170dcf9c95af15bdbafbe13dd9127088e28babccfd570f",
    "commitment": "0x4fc574af6cf22bc0aaf7a4d72532aabc2a7db8f2cda8d3872c47cf07b18f139e",
    "proof_sha256": "67d11ec454839405ebb89c0a197dd34772071edf0897a6b776eaded80b0dcb89",
    "negatives": {
        "wrong-bounds": "e4057d36e7aec9f61eb537d46957d6ede75c7706c328c699025fbefcfbd26bf5",
        "wrong-count": "8b3ce13a156da3ea015181ee6e70478dd85eec8b4575dc8602ca276387695e46",
        "wrong-batch": "20c6cd884979d825e456666c8c67b77137761f1e192552d8ef6b06d626034d32",
        "wrong-base": "bfbd0612d87718c7560d188a5801e7bca14a9df7216a19177ce0f32fa962e611",
        "backdated": "0ea2e8577cd965c2ea42ba8bc7a2381239ef01e9b6798c862877a20645136c71",
    },
}

# Frozen record of the clock-v2 guest source pins as first reviewed. Provenance
# only: it is never compared with the checkout.
HISTORICAL_V2_GUEST_SOURCES = MappingProxyType({
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
    "crates/sp1-guest/src/main.rs": "c0d33ff8645ebdcc8994d4d65729b8a60a224bcda18415423da15ed875c16f5c",
})


def verify_guest_source():
    """Require the checkout's guest inputs to equal REVIEWED_GUEST's source pins."""
    sources = REVIEWED_GUEST["sources"]
    for name, digest in sources.items():
        path = target.ROOT / name
        target.require(path.is_file() and not path.is_symlink(), f"missing/nonregular guest source: {name}")
        target.require(target.sha256(path.read_bytes()) == digest, f"guest source changed; rebuild and reprove: {name}")
    return dict(sources)


def read_clock_artifacts(directory):
    files = {}
    for name in CLOCK_ARTIFACTS:
        path = directory / name
        target.require(not path.is_symlink() and path.is_file(), f"missing/nonregular clock artifact: {name}")
        target.require(path.stat().st_size <= 64 * 1024 * 1024, f"oversized artifact: {name}")
        files[name] = path.read_bytes()
    return files


def check_evidence(manifest):
    """Kind, SDK and verification fields of a committed proof's evidence record."""
    target.require(manifest.get("kind") == PROOF_FIXTURE["kind"], PROOF_FIXTURE["kind"] + " evidence required")
    target.require(manifest.get("sdk_version") == SDK_VERSION, "wrong SP1 SDK")
    for field in ("proof_generated", "native_guest_equal"):
        target.require(manifest.get(field) is True, f"incomplete proof evidence: {field}")
    sdk_verified = manifest.get("local_sdk_verified") is True
    rust_verified = (manifest.get("rust_sp1_verifier_verified") is True
                     and manifest.get("rust_verifier_version") == SDK_VERSION)
    target.require(sdk_verified or rust_verified, "incomplete proof evidence: cryptographic verification")


def check_sdk_proof(files):
    sdk = json.loads(files["proof.sdk.json"])
    target.require(isinstance(sdk, dict) and str(sdk.get("sp1_version", "")).removeprefix("v") == SDK_VERSION,
                   "wrong SDK proof version")


def load_clock_proof(directory):
    """Validate a proof artifact directory against PROOF_FIXTURE and return its forge inputs.

    The evidence, ELF, setup key, witness, public values and rejected negatives must
    be PROOF_FIXTURE's. The proof bytes are the artifact's own: their shape and
    verifier selector are checked here and their cryptography by the forge suites,
    so a re-wrapped proof of the same fixture is verified, not refused by its hash.
    """
    files = read_clock_artifacts(directory.resolve())
    manifest = json.loads(files["proof-evidence.json"])
    target.require(isinstance(manifest, dict), "invalid proof evidence")
    check_evidence(manifest)
    target.require(files["guest.elf"].startswith(b"\x7fELF"), "actual guest ELF required")
    target.require(target.sha256(files["guest.elf"]) == PROOF_FIXTURE["elf"], "wrong rebuilt clock guest")
    target.require(manifest.get("elf_sha256") == PROOF_FIXTURE["elf"], "ELF evidence mismatch")
    target.require(target.sha256(files["clock.witness.bin"]) == PROOF_FIXTURE["witness_sha256"],
                   "wrong signed-clock fixture")
    target.require(manifest.get("witness_sha256") == PROOF_FIXTURE["witness_sha256"], "witness evidence mismatch")
    target.require("0x" + files["program-vkey.bin"].hex() == PROOF_FIXTURE["vkey"], "wrong setup vkey")
    target.require(manifest.get("program_vkey") == PROOF_FIXTURE["vkey"], "vkey evidence mismatch")
    target.require("0x" + files["public-values.bin"].hex() == PROOF_FIXTURE["commitment"], "wrong public digest")
    target.require(manifest.get("commitment") == PROOF_FIXTURE["commitment"], "native digest mismatch")
    proof = files["proof.bin"]
    check_proof_shape(proof)
    check_sdk_proof(files)
    expected = PROOF_FIXTURE["negatives"]
    negatives = manifest.get("negatives", [])
    target.require(isinstance(negatives, list) and len(negatives) == len(expected)
                   and all(isinstance(n, dict) and isinstance(n.get("name"), str) for n in negatives)
                   and {n["name"] for n in negatives} == set(expected),
                   "clock guest negative set incomplete")
    target.require(all(n.get("guest_exit") == 1 and n.get("public_bytes") == 0 for n in negatives),
                   "guest rejection evidence incomplete")
    target.require(all(n.get("witness_sha256") == expected[n["name"]] for n in negatives),
                   "guest rejection witness mismatch")
    return files, forge_environment(proof)


def check_proof_shape(proof):
    target.require(len(proof) == 356 and proof[:4].hex() == target.VERIFIER_HASH[:8], "wrong Groth16 shape/selector")


def forge_environment(proof):
    """The real-proof suites' inputs: PROOF_FIXTURE's key and commitment, and the given proof bytes."""
    check_proof_shape(proof)
    return {"ARCORA_REAL_PROGRAM_VKEY": PROOF_FIXTURE["vkey"],
            "ARCORA_REAL_PUBLIC_COMMITMENT": PROOF_FIXTURE["commitment"],
            "ARCORA_REAL_PROOF": "0x" + proof.hex()}


def proof_status(root=None):
    """PROVEN only if the committed proof files on disk are a proof of the reviewed fixture.

    Every value is read from PROOF_FIXTURE["dir"]; editing a dict alone never
    changes the status. Required: the files pass load_clock_proof (the validation
    verify_clock_proof applies: evidence kind, SDK and verification fields, recorded
    identity, ELF, setup key, witness, public values, proof shape and the rejected
    negatives), the proof is the committed one (PROOF_FIXTURE["proof_sha256"]), the
    ELF and setup key equal REVIEWED_GUEST, and the witness and public values equal
    REVIEWED_FIXTURE.
    """
    root = target.ROOT if root is None else Path(root)
    try:
        files, _ = load_clock_proof(root / PROOF_FIXTURE["dir"])
        on_disk = (target.sha256(files["guest.elf"]), "0x" + files["program-vkey.bin"].hex(),
                   target.sha256(files["clock.witness.bin"]), "0x" + files["public-values.bin"].hex())
        proven = (target.sha256(files["proof.bin"]) == PROOF_FIXTURE["proof_sha256"]
                  and on_disk == (REVIEWED_GUEST["elf"], REVIEWED_GUEST["vkey"],
                                  REVIEWED_FIXTURE["witness_sha256"], REVIEWED_FIXTURE["commitment"]))
    except (ValueError, KeyError, OSError, UnicodeError):
        return PENDING_REPROOF
    return PROVEN if proven else PENDING_REPROOF


# Recorded next to `scope` in the real-proof evidence files.
IDENTITY_SCOPE = ("The forge suites verify the proof under PROOF_FIXTURE's setup key and public commitment. "
                  "The evidence attests that proof's own guest identity (PROOF_FIXTURE), which equals the "
                  "reviewed guest only if proof_matches_reviewed_guest is true.")


def proof_matches_reviewed_guest():
    return (PROOF_FIXTURE["elf"], PROOF_FIXTURE["vkey"]) == (REVIEWED_GUEST["elf"], REVIEWED_GUEST["vkey"])


def identities():
    """Both identities, recorded side by side in every real-proof evidence file."""
    return {"proof_fixture": {"dir": PROOF_FIXTURE["dir"], "kind": PROOF_FIXTURE["kind"],
                              "guest_elf_sha256": PROOF_FIXTURE["elf"], "program_vkey": PROOF_FIXTURE["vkey"],
                              "witness_sha256": PROOF_FIXTURE["witness_sha256"],
                              "public_commitment": PROOF_FIXTURE["commitment"],
                              "proof_sha256": PROOF_FIXTURE["proof_sha256"]},
            "reviewed_guest": {"identity_dir": REVIEWED_GUEST["identity_dir"],
                               "guest_elf_sha256": REVIEWED_GUEST["elf"], "program_vkey": REVIEWED_GUEST["vkey"],
                               "fixture_witness_sha256": REVIEWED_FIXTURE["witness_sha256"],
                               "fixture_commitment": REVIEWED_FIXTURE["commitment"]},
            "proof_matches_reviewed_guest": proof_matches_reviewed_guest(),
            "real_proof_status": proof_status()}


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
              "identity_scope": IDENTITY_SCOPE,
              "guest_elf_sha256": PROOF_FIXTURE["elf"], "program_vkey": PROOF_FIXTURE["vkey"],
              "public_commitment": PROOF_FIXTURE["commitment"], "tests": counts,
              **identities(),
              "input_artifacts": {name: {"sha256": target.sha256(data), "size_bytes": len(data)} for name, data in files.items()},
              "runner_sha256": target.sha256(Path(__file__).read_bytes()),
              # Same value under the existing key and under the record's name.
              "guest_sources_sha256": dict(REVIEWED_GUEST["sources"]),
              "reviewed_guest_sources_sha256": dict(REVIEWED_GUEST["sources"]), "source_sha256": checked_sources,
              "compiled_contracts": compiled, "vendor_upstreams": vendor["upstreams"]}
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"Clock target verification refused: {error}", file=sys.stderr)
        sys.exit(1)
