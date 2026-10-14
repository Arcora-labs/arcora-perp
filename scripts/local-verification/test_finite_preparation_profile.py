#!/usr/bin/env python3
"""Fail-closed validation tests for finite preparation diagnostics."""
import copy
import unittest
import finite_preparation_profile as profile


def rows():
    return [{"fixture": case, "phase": phase, "round": r, "repetitions": 10,
             "thread_cpu_ns": 10_000, "wall_ns": 20_000}
            for case in profile.CASES for phase in profile.PHASES for r in range(5)]


class ProfileValidation(unittest.TestCase):
    def test_complete_grid_and_units(self):
        result = profile.validate_cpu(rows())
        self.assertEqual(result["notes64_withdrawals16"]["state_clone"]["thread_cpu_us_per_operation"]["median"], 1)

    def test_missing_duplicate_unknown_and_extra_fields(self):
        full = rows()
        for invalid in (full[:-1], full + [full[0]], []):
            with self.assertRaises(ValueError):
                profile.validate_cpu(invalid)
        for key, value in (("fixture", "other"), ("phase", "other"), ("extra", 1)):
            changed = copy.deepcopy(full)
            changed[0][key] = value
            with self.assertRaises(ValueError):
                profile.validate_cpu(changed)

    def test_booleans_batch_shape_and_duration_refused(self):
        for key, value in (("round", True), ("round", 5), ("repetitions", 1),
                           ("thread_cpu_ns", 0), ("wall_ns", -1)):
            changed = rows()
            changed[0][key] = value
            with self.assertRaises(ValueError):
                profile.validate_cpu(changed)

    def test_zero_tests_failure_and_ignored_are_not_passes(self):
        profile.check_test_result("test result: ok. 4 passed; 0 failed; 0 ignored;", 4)
        for line in ("", "test result: ok. 0 passed; 0 failed; 0 ignored;",
                     "test result: FAILED. 4 passed; 1 failed; 0 ignored;",
                     "test result: ok. 4 passed; 0 failed; 1 ignored;"):
            with self.assertRaises(ValueError):
                profile.check_test_result(line, 4)

    def test_metadata_shape_and_synthetic_labels(self):
        row = {
            "fixture": "notes160_withdrawals48", "pre_live_notes": 160,
            "post_live_notes": 112, "withdrawals": 48, "ops": 49, "timed_ops": 1,
            "claim_count": 48, "claim_path_siblings": [6] * 32 + [5] * 16,
            "witness_sha256": "a" * 64, "prepared_intent_sha256": "b" * 64,
            "frames": dict.fromkeys(profile.FRAME_KEYS, 100),
            "proof": "synthetic_cached_stub", "seal": "software_test_keys",
        }
        profile.validate_metadata(row)
        for key, value in (("post_live_notes", 160), ("claim_path_siblings", [0] * 48),
                           ("claim_path_siblings", [6] * 48),
                           ("proof", "real"), ("frames", {}), ("witness_sha256", "bad")):
            changed = copy.deepcopy(row)
            changed[key] = value
            with self.assertRaises(ValueError):
                profile.validate_metadata(changed)


if __name__ == "__main__":
    unittest.main()
