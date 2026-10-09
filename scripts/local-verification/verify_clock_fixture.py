#!/usr/bin/env python3
"""Verify pinned, real clock-v2 proof calldata in an owned EVM.

The proof is public synthetic test data, not a mock proof. This gate independently
verifies cryptography on the real target contracts and does not trust a claim
that an SDK, generator or earlier workflow passed. It sends no chain transaction.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import verify_clock_proof as clock
import verify_real_proof as target

PROOF_SHA256 = "67d11ec454839405ebb89c0a197dd34772071edf0897a6b776eaded80b0dcb89"
EXPECTED_TESTS = {"SP1RealVerifierGuardTest": 8, "SP1RealProofTest": 10, "ClockBoundRealProofTest": 6}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    source_hashes = clock.verify_guest_source()
    target.verify_vendor()
    path = target.CONTRACTS / "integration/fixtures/clock-v2/verified-calldata/proof.bin"
    target.require(path.is_file() and not path.is_symlink(), "regular pinned proof required")
    proof = path.read_bytes()
    target.require(len(proof) == 356 and target.sha256(proof) == PROOF_SHA256, "pinned proof changed")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR") if key in os.environ}
    env.update(ARCORA_REAL_PROGRAM_VKEY=clock.EXPECTED_VKEY,
               ARCORA_REAL_PUBLIC_COMMITMENT=clock.EXPECTED_COMMITMENT,
               ARCORA_REAL_PROOF="0x" + proof.hex(), FOUNDRY_PROFILE="default")
    target.run(["forge", "build", "--root", str(target.VENDOR)], output, "upstream-build", env)
    env["FOUNDRY_PROFILE"] = "real_proof"
    result = target.run(["forge", "test", "--root", str(target.CONTRACTS), "--match-contract",
                         "(SP1Real(VerifierGuard|Proof)Test|ClockBoundRealProofTest)", "--json"],
                        output, "real-target-tests", env)
    counts = {}
    for suite_name, suite in json.loads(result).items():
        name = suite_name.rsplit(":", 1)[-1]
        tests = suite["test_results"]
        target.require(all(test["status"] == "Success" for test in tests.values()),
                       "failed or skipped real proof suite: " + name)
        counts[name] = len(tests)
    target.require(counts == EXPECTED_TESTS, "missing real proof tests")
    report = {"status": "PASS", "tests": counts, "local_evm_only": True,
              "real_cryptographic_proof_verified": True, "mock_proof_used": False,
              "mock_token_used": True, "synthetic_zero_payer": True,
              "fixed_constructor_addresses": True, "production_deployed": False,
              "full_production_lifecycle": False, "sdk_verification_claimed": False,
              "proof_sha256": PROOF_SHA256, "guest_elf_sha256": clock.EXPECTED_ELF,
              "program_vkey": clock.EXPECTED_VKEY, "public_commitment": clock.EXPECTED_COMMITMENT,
              "guest_source_sha256": source_hashes,
              "scope": "Actual SP1 verifier, clock adapter, settlement and synthetic vault withdrawal; not full HTTP/order/production lifecycle."}
    (output / "verification.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print("Real clock fixture verification refused: " + str(error), file=sys.stderr)
        sys.exit(1)
