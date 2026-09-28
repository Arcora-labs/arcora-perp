"""Regression cases for downgrades/mixed dependencies missed by top-level pins."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("sp1_release", Path(__file__).with_name("check_sp1_release.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseGuard(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in MODULE.APPLICATIONS:
            target = self.root / directory
            target.mkdir(parents=True)
            for name in ("Cargo.toml", "Cargo.lock"):
                shutil.copyfile(MODULE.ROOT / directory / name, target / name)

    def replace(self, path, before, after):
        file = self.root / path
        data = file.read_text()
        self.assertIn(before, data)
        file.write_text(data.replace(before, after, 1))

    def test_current_complete_release_passes(self):
        result = MODULE.check(self.root)
        self.assertTrue(result["passed"], result["errors"])
        self.assertTrue(all(result["family_packages_checked"].values()))

    def test_known_affected_sdk_is_rejected(self):
        self.replace("crates/sp1-host/Cargo.toml", 'sp1-sdk = "=6.1.0"', 'sp1-sdk = "=6.0.0"')
        self.assertFalse(MODULE.check(self.root)["passed"])

    def test_mixed_transitive_release_is_rejected(self):
        self.replace("crates/prover-service/Cargo.lock", 'name = "sp1-prover"\nversion = "6.1.0"',
                     'name = "sp1-prover"\nversion = "6.8.1"')
        self.assertFalse(MODULE.check(self.root)["passed"])

    def test_unpinned_guest_is_rejected(self):
        self.replace("crates/sp1-guest/Cargo.toml", 'sp1-zkvm = "=6.1.0"', 'sp1-zkvm = "6.1.0"')
        self.assertFalse(MODULE.check(self.root)["passed"])

    def test_missing_lock_is_rejected(self):
        (self.root / "crates/sp1-guest/Cargo.lock").unlink()
        self.assertFalse(MODULE.check(self.root)["passed"])


if __name__ == "__main__":
    unittest.main()
