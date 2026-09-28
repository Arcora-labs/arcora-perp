"""Fail-closed checks for the real-proof artifact gate, including an actual EVM rejection.

The synthetic zero payload below is deliberately invalid. It must never yield a
successful application-proof report even if its manifest asserts SDK success.
"""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/local-verification/verify_real_proof.py"
spec = importlib.util.spec_from_file_location("verify_real_proof", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def invalid_proof_artifacts(directory):
    # Correct selector/header layout, but all Groth16 curve points are zero.
    proof = bytes.fromhex(gate.VERIFIER_HASH[:8]) + bytes(32)
    proof += bytes.fromhex("002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352")
    proof += bytes(32 * 9)
    files = {
        "normal.witness.bin": b"synthetic gate-rejection fixture",
        "guest.elf": (ROOT / "docs/audits/2026-09-28-post-merge/normal/run-6.1.0/guest.elf").read_bytes(),
        "program-vkey.bin": bytes.fromhex(gate.EXPECTED_ARCORA_PROGRAM_VKEY.removeprefix("0x")),
        "public-values.bin": bytes.fromhex("00" * 31 + "02"),
        "proof.bin": proof,
        "proof.sdk.json": b'{"fixture":"deliberately invalid; never real proof evidence"}',
    }
    manifest = {
        "kind": "ordinary-local-groth16-proof",
        "sdk_version": "6.1.0", "proof_sp1_version": "v6.1.0",
        "proof_generated": True, "local_sdk_verified": True,
        "native_guest_equal": True, "native_deserialized_same_witness": True,
        "a06_executed": False,
        "program_vkey": "0x" + files["program-vkey.bin"].hex(),
        "roots": {"commitment": "0x" + files["public-values.bin"].hex()},
        "witness_sha256": gate.sha256(files["normal.witness.bin"]),
        "artifacts": {},
    }
    for name, data in files.items():
        (directory / name).write_bytes(data)
        manifest["artifacts"][name] = {"sha256": gate.sha256(data), "size_bytes": len(data)}
    (directory / "manifest.json").write_text(json.dumps(manifest))
    return manifest


class RealProofGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="arcora-proof-gate-test-")
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.manifest = invalid_proof_artifacts(self.artifacts)

    def tearDown(self):
        self.temp.cleanup()

    def rewrite(self):
        (self.artifacts / "manifest.json").write_text(json.dumps(self.manifest))

    def test_missing_completion_manifest_rejected(self):
        (self.artifacts / "manifest.json").unlink()
        with self.assertRaises(FileNotFoundError):
            gate.load_proof(self.artifacts)

    def test_changed_witness_rejected(self):
        (self.artifacts / "normal.witness.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "artifact hash mismatch"):
            gate.load_proof(self.artifacts)

    def test_changed_native_commitment_rejected(self):
        self.manifest["roots"]["commitment"] = "0x" + "00" * 32
        self.rewrite()
        with self.assertRaisesRegex(ValueError, "commitment mismatch"):
            gate.load_proof(self.artifacts)

    def test_wrong_program_key_binding_rejected(self):
        self.manifest["program_vkey"] = "0x" + "00" * 32
        self.rewrite()
        with self.assertRaisesRegex(ValueError, "program key manifest mismatch"):
            gate.load_proof(self.artifacts)

    def test_old_version_rejected(self):
        self.manifest["sdk_version"] = "6.0.0"
        self.rewrite()
        with self.assertRaisesRegex(ValueError, "SDK 6.1.0 required"):
            gate.load_proof(self.artifacts)

    def test_incomplete_sdk_verification_rejected(self):
        self.manifest["local_sdk_verified"] = False
        self.rewrite()
        with self.assertRaisesRegex(ValueError, "local_sdk_verified"):
            gate.load_proof(self.artifacts)

    def test_path_escape_rejected(self):
        self.manifest["artifacts"]["../escaped"] = {"sha256": "", "size_bytes": 0}
        self.rewrite()
        with self.assertRaisesRegex(ValueError, "unsafe artifact path"):
            gate.load_proof(self.artifacts)

    def test_changed_source_and_provenance_cannot_redefine_upstream(self):
        vendor_copy = self.root / "vendor"
        shutil.copytree(gate.VENDOR, vendor_copy)
        source = vendor_copy / "src/v6.1.0/SP1VerifierGroth16.sol"
        source.write_bytes(source.read_bytes() + b"\n// unreviewed source change\n")
        provenance_path = vendor_copy / "PROVENANCE.json"
        provenance = json.loads(provenance_path.read_text())
        entry = provenance["files"]["src/v6.1.0/SP1VerifierGroth16.sol"]
        entry["sha256"] = gate.sha256(source.read_bytes())
        entry["size_bytes"] = source.stat().st_size
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
        # Commit labels and file inventory remain unchanged; the independently
        # pinned provenance digest must still reject the rewritten source map.
        with patch.object(gate, "VENDOR", vendor_copy):
            with self.assertRaisesRegex(ValueError, "unreviewed upstream provenance"):
                gate.verify_vendor()

    def test_extra_vendor_source_rejected(self):
        vendor_copy = self.root / "vendor"
        shutil.copytree(gate.VENDOR, vendor_copy)
        (vendor_copy / "src/Unreviewed.sol").write_text("pragma solidity ^0.8.20; contract Unreviewed {}\n")
        with patch.object(gate, "VENDOR", vendor_copy):
            with self.assertRaisesRegex(ValueError, "unexpected vendored disk inventory"):
                gate.verify_vendor()

    def test_vendor_symlink_rejected_even_with_unchanged_source_bytes(self):
        vendor_copy = self.root / "vendor"
        shutil.copytree(gate.VENDOR, vendor_copy)
        source = vendor_copy / "src/v6.1.0/SP1VerifierGroth16.sol"
        source.unlink()
        source.symlink_to(gate.VENDOR / "src/v6.1.0/SP1VerifierGroth16.sol")
        with patch.object(gate, "VENDOR", vendor_copy):
            with self.assertRaisesRegex(ValueError, "vendored symlink is forbidden"):
                gate.verify_vendor()

    def test_rehashed_other_elf_cannot_be_labeled_arcora(self):
        elf = self.artifacts / "guest.elf"
        elf.write_bytes(elf.read_bytes() + b"different guest")
        self.manifest["artifacts"]["guest.elf"] = {"sha256": gate.sha256(elf.read_bytes()), "size_bytes": elf.stat().st_size}
        self.rewrite()
        with self.assertRaisesRegex(ValueError, "unreviewed Arcora guest ELF"):
            gate.load_proof(self.artifacts)

    def test_rehashed_other_key_cannot_be_labeled_arcora(self):
        key = self.artifacts / "program-vkey.bin"
        changed = bytearray(key.read_bytes())
        changed[-1] ^= 1
        key.write_bytes(changed)
        self.manifest["artifacts"]["program-vkey.bin"] = {"sha256": gate.sha256(changed), "size_bytes": len(changed)}
        self.manifest["program_vkey"] = "0x" + changed.hex()
        self.rewrite()
        with self.assertRaisesRegex(ValueError, "unreviewed Arcora program key"):
            gate.load_proof(self.artifacts)

    def test_zero_payload_cannot_produce_success_report(self):
        output = self.root / "verification"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--artifact-dir", str(self.artifacts), "--output-dir", str(output)],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("forge-tests failed", result.stderr)
        self.assertFalse((output / "verification.json").exists())
        suites = json.loads((output / "forge-tests.stdout.log").read_text())
        proof_suite = next(value for key, value in suites.items() if key.endswith(":SP1RealProofTest"))
        for name in ("test_real_verifier_accepts_arcora_proof()", "test_real_gateway_accepts_arcora_proof()", "test_adapter_accepts_arcora_proof()"):
            self.assertEqual(proof_suite["test_results"][name]["status"], "Failure")


if __name__ == "__main__":
    unittest.main()
