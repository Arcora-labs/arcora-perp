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
        shutil.copytree(MODULE.ROOT / "vendor/sp1-prover", self.root / "vendor/sp1-prover")
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

    def test_wrong_vendor_path_is_rejected(self):
        self.replace("crates/sp1-host/Cargo.toml", '../../vendor/sp1-prover', '../../another-prover')
        self.assertFalse(MODULE.check(self.root)["passed"])

    def test_vendor_source_change_is_rejected(self):
        path = self.root / "vendor/sp1-prover/src/verify.rs"
        path.write_text(path.read_text() + "\n// changed verifier\n")
        self.assertFalse(MODULE.check(self.root)["passed"])

    def test_changed_provenance_cannot_redefine_identity(self):
        path = self.root / "vendor/sp1-prover/PROVENANCE.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assertFalse(MODULE.check(self.root)["passed"])

    def test_old_lru_is_rejected(self):
        self.replace("crates/sp1-host/Cargo.lock", 'name = "lru"\nversion = "0.18.4"',
                     'name = "lru"\nversion = "0.12.5"')
        self.assertFalse(MODULE.check(self.root)["passed"])

    def test_unreviewed_registry_exception_is_rejected(self):
        self.replace("crates/sp1-host/Cargo.lock", 'name = "sp1-prover"\nversion = "6.1.0"',
                     'name = "sp1-prover"\nversion = "6.1.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"')
        self.assertFalse(MODULE.check(self.root)["passed"])

    def test_injected_vendor_build_script_is_rejected(self):
        (self.root / "vendor/sp1-prover/build.rs").write_text("fn main() {}\n")
        self.assertFalse(MODULE.check(self.root)["passed"])


if __name__ == "__main__":
    unittest.main()
