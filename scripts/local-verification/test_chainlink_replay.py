"""Offline tests for replay evidence validation; generated reports are test doubles."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_chainlink_replay as replay


class ReplayEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="arcora-chainlink-evidence-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        manifest = replay.fixture_manifest()
        self.report = {"status": "PASS", "kind": "synthetic-chainlink-candidate-cpu-replay",
                       "sdk_version": "6.1.0", "schema_version": 1,
                       "candidate_elf_sha256": replay.ELF_SHA, "program_vkey": replay.VKEY,
                       "fixture_manifest_sha256": replay.FIXTURE_MANIFEST_SHA,
                       "synthetic_inputs": True, "guest_executed": True, "native_guest_equal": True,
                       "proof_generated": False, "real_don_verified": False, "live_deployment": False,
                       "fresh_guest_build_performed": False, "cases": [], "artifacts": {}}
        for case in manifest["cases"]:
            public = bytes.fromhex(case["expected_commitment"]) if case["outcome"] == "PASS" else b""
            name = case["name"] + ".public-values.bin"
            (self.root / name).write_bytes(public)
            self.report["artifacts"][name] = {"sha256": replay.sha(public), "size_bytes": len(public)}
            self.report["cases"].append({"case": case["name"], "expected_outcome": case["outcome"],
                "witness_sha256": case["witness_sha256"], "native_error": case["native_error"],
                "guest_exit_code": 0 if public else 1, "guest_cycles": 100, "guest_seconds": 0.1,
                "public_values_hex": public.hex(), "public_values_bytes": len(public)})

    def write(self, report=None):
        (self.root / "manifest.json").write_text(json.dumps(report or self.report))

    def reject(self, report):
        self.write(report)
        with self.assertRaises((ValueError, KeyError, TypeError, FileNotFoundError)):
            replay.verify_report(self.root)

    def test_complete_synthetic_test_report_validates_structure_only(self):
        self.write()
        self.assertEqual(len(replay.verify_report(self.root)["cases"]), 19)

    def test_identity_and_claims_cannot_be_substituted(self):
        for key, value in [("candidate_elf_sha256", "0" * 64), ("program_vkey", "0x" + "0" * 64),
                           ("fixture_manifest_sha256", "0" * 64), ("sdk_version", "6.8.1"),
                           ("kind", "real-proof"), ("guest_executed", False), ("native_guest_equal", False),
                           ("synthetic_inputs", False), ("proof_generated", True), ("real_don_verified", True),
                           ("live_deployment", True), ("fresh_guest_build_performed", True)]:
            with self.subTest(key=key):
                report = copy.deepcopy(self.report); report[key] = value; self.reject(report)

    def test_missing_extra_duplicate_and_reordered_cases_fail(self):
        for rows in [self.report["cases"][:-1], self.report["cases"] + self.report["cases"][:1],
                     [self.report["cases"][0]] * 19, list(reversed(self.report["cases"]))]:
            report = copy.deepcopy(self.report); report["cases"] = rows; self.reject(report)

    def test_executor_failure_is_not_an_expected_guest_rejection(self):
        for code in [0, 2, -1, 101, True]:
            report = copy.deepcopy(self.report); report["cases"][4]["guest_exit_code"] = code; self.reject(report)

    def test_negative_case_cannot_commit_any_output(self):
        report = copy.deepcopy(self.report)
        report["cases"][4]["public_values_hex"] = "00"; report["cases"][4]["public_values_bytes"] = 1
        self.reject(report)

    def test_modified_public_bytes_or_hash_fail(self):
        (self.root / "funding.public-values.bin").write_bytes(bytes(32))
        self.reject(self.report)

    def test_missing_extra_or_wrong_artifact_metadata_fail(self):
        for mutation in ["missing", "extra", "hash", "size"]:
            report = copy.deepcopy(self.report)
            if mutation == "missing": del report["artifacts"]["funding.public-values.bin"]
            if mutation == "extra": report["artifacts"]["proof.bin"] = {}
            if mutation == "hash": report["artifacts"]["funding.public-values.bin"]["sha256"] = "0" * 64
            if mutation == "size": report["artifacts"]["funding.public-values.bin"]["size_bytes"] = 0
            self.reject(report)

    def test_no_cycles_wrong_input_binding_or_false_error_fail(self):
        for key, value in [("guest_cycles", 0), ("guest_cycles", True), ("guest_seconds", -1),
                           ("witness_sha256", "0" * 64), ("native_error", "fake error")]:
            report = copy.deepcopy(self.report); report["cases"][0][key] = value; self.reject(report)

    def test_duplicate_and_nonfinite_json_are_rejected(self):
        for data in [b'{"status":"PASS","status":"PASS"}', b'{"x": NaN}', b'{"x": Infinity}']:
            with self.assertRaises(ValueError): replay.decode(data)

    def test_symlink_and_oversized_artifact_fail(self):
        path = self.root / "funding.public-values.bin"
        data = path.read_bytes(); path.unlink()
        target = self.root / "copy"; target.write_bytes(data); path.symlink_to(target)
        self.reject(self.report)
        path.unlink(); path.write_bytes(data + b"x")
        self.reject(self.report)

    def test_candidate_runtime_sources_are_pinned_separately(self):
        self.assertEqual(len(replay.candidate_sources()), 9)
        with patch.dict(replay.CANDIDATE_SOURCES, {"crates/chainlink-oracle/src/binding.rs": "0" * 64}):
            with self.assertRaises(ValueError): replay.candidate_sources()

    def test_fixture_manifest_pin_is_not_self_selected(self):
        with patch.object(replay, "FIXTURE_MANIFEST_SHA", "0" * 64):
            with self.assertRaises(ValueError): replay.fixture_manifest()


if __name__ == "__main__":
    unittest.main()
