import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import verify_clock_proof as clock


class ClockProofArtifactGuards(unittest.TestCase):
    def test_checked_out_guest_source_matches_independent_pin(self):
        self.assertEqual(clock.verify_guest_source(), clock.EXPECTED_GUEST_SOURCES)

    def test_changed_guest_cannot_reuse_a_passing_old_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = clock.target.ROOT
            for name in clock.EXPECTED_GUEST_SOURCES:
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((original / name).read_bytes())
            with patch.object(clock.target, "ROOT", root):
                clock.verify_guest_source()
                file = root / "crates/sp1-guest/src/main.rs"
                file.write_bytes(file.read_bytes() + b"\n// changed guest input\n")
                with self.assertRaisesRegex(ValueError, "guest source changed"):
                    clock.verify_guest_source()

    def test_missing_success_record_is_not_an_execution_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "missing"):
                clock.load_clock_proof(Path(directory))

    def test_artifact_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").write_text("{}")
            (root / "proof-evidence.json").symlink_to(root / "source")
            with self.assertRaisesRegex(ValueError, "nonregular"):
                clock.load_clock_proof(root)

    def test_unverified_or_wrong_version_evidence_is_refused(self):
        cases = [
            ({"kind": "ordinary-local-groth16-proof"}, "clock-v2"),
            ({"kind": "clock-v2-native-guest", "sdk_version": "6.0.0"}, "wrong SP1"),
            ({"kind": "clock-v2-native-guest", "sdk_version": "6.1.0", "proof_generated": False}, "incomplete"),
            ({"kind": "clock-v2-native-guest", "sdk_version": "6.1.0", "proof_generated": True,
              "local_sdk_verified": False}, "incomplete"),
        ]
        for record, error in cases:
            with self.subTest(record=record), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ["clock.witness.bin", "guest.elf", "program-vkey.bin", "proof.bin",
                             "public-values.bin", "proof.sdk.json"]:
                    (root / name).write_bytes(b"not a real proof")
                (root / "proof-evidence.json").write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, error):
                    clock.load_clock_proof(root)

    def test_arbitrary_guest_cannot_nominate_its_own_vkey(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["clock.witness.bin", "guest.elf", "program-vkey.bin", "proof.bin",
                         "public-values.bin", "proof.sdk.json"]:
                (root / name).write_bytes(b"\x7fELFfake")
            (root / "proof-evidence.json").write_text(json.dumps({
                "kind": "clock-v2-native-guest", "sdk_version": "6.1.0",
                "proof_generated": True, "local_sdk_verified": True, "native_guest_equal": True,
                "elf_sha256": "attacker-selected-hash", "program_vkey": "attacker-selected-key",
            }))
            with self.assertRaisesRegex(ValueError, "wrong rebuilt clock guest"):
                clock.load_clock_proof(root)


if __name__ == "__main__":
    unittest.main()
