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

    def test_guest_takes_tiny_keccak_from_the_exact_git_pin(self):
        pin = MODULE.GUEST_GIT_DEPENDENCY
        self.assertEqual(MODULE.guest_dependency_errors(self.root), [])
        self.assertEqual(MODULE.GUEST_GIT_SOURCE,
                         f"git+{pin['repository']}?rev={pin['commit']}#{pin['commit']}")
        lock = (self.root / "crates/sp1-guest/Cargo.lock").read_text()
        self.assertIn(f'name = "tiny-keccak"\nversion = "2.0.2"\nsource = "{MODULE.GUEST_GIT_SOURCE}"', lock)
        self.assertEqual(MODULE.check(self.root)["guest_git_dependency"], pin)

    def assert_guest_rejected(self, path, before, after):
        self.replace(path, before, after)
        self.assertFalse(MODULE.check(self.root)["passed"])
        self.assertNotEqual(MODULE.guest_dependency_errors(self.root), [])

    def test_other_commit_in_the_guest_manifest_is_rejected(self):
        commit = MODULE.GUEST_GIT_DEPENDENCY["commit"]
        self.assert_guest_rejected("crates/sp1-guest/Cargo.toml", f'rev = "{commit}"', 'rev = "' + "0" * 40 + '"')

    def test_branch_or_tag_instead_of_the_commit_is_rejected(self):
        commit = MODULE.GUEST_GIT_DEPENDENCY["commit"]
        self.assert_guest_rejected("crates/sp1-guest/Cargo.toml", f'rev = "{commit}"', 'tag = "patch-2.0.2-sp1-6.0.0"')

    def test_other_repository_in_the_guest_manifest_is_rejected(self):
        self.assert_guest_rejected("crates/sp1-guest/Cargo.toml", "https://github.com/sp1-patches/tiny-keccak",
                                   "https://github.com/example/tiny-keccak")

    def test_dropped_guest_patch_is_rejected(self):
        self.assert_guest_rejected("crates/sp1-guest/Cargo.toml", "[patch.crates-io]\ntiny-keccak",
                                   "[patch.unused]\ntiny-keccak")

    def test_other_git_source_in_the_guest_lock_is_rejected(self):
        commit = MODULE.GUEST_GIT_DEPENDENCY["commit"]
        self.assert_guest_rejected("crates/sp1-guest/Cargo.lock", f"#{commit}", "#" + "1" * 40)

    def test_registry_tiny_keccak_in_the_guest_lock_is_rejected(self):
        self.assert_guest_rejected("crates/sp1-guest/Cargo.lock", f'source = "{MODULE.GUEST_GIT_SOURCE}"',
                                   f'source = "{MODULE.REGISTRY_SOURCE}"\nchecksum = "' + "ab" * 32 + '"')

    def test_checksum_on_the_git_package_is_rejected(self):
        self.assert_guest_rejected("crates/sp1-guest/Cargo.lock", f'source = "{MODULE.GUEST_GIT_SOURCE}"',
                                   f'source = "{MODULE.GUEST_GIT_SOURCE}"\nchecksum = "' + "ab" * 32 + '"')

    def test_second_git_package_in_the_guest_lock_is_rejected(self):
        self.assert_guest_rejected("crates/sp1-guest/Cargo.lock", 'name = "postcard"\nversion = "1.1.3"\n'
                                   f'source = "{MODULE.REGISTRY_SOURCE}"',
                                   'name = "postcard"\nversion = "1.1.3"\nsource = "'
                                   f'git+https://github.com/sp1-patches/tiny-keccak?rev={"2" * 40}#{"2" * 40}"')

    def test_git_or_alternate_registry_source_in_a_host_lock_is_rejected(self):
        for source in (MODULE.GUEST_GIT_SOURCE, "registry+https://example.invalid/index"):
            with self.subTest(source=source):
                self.setUp()
                self.replace("crates/sp1-host/Cargo.lock", f'name = "lru"\nversion = "0.18.4"\nsource = "{MODULE.REGISTRY_SOURCE}"',
                             f'name = "lru"\nversion = "0.18.4"\nsource = "{source}"')
                self.assertFalse(MODULE.check(self.root)["passed"])

    def test_upstream_audit_lock_names_the_patch_by_its_crates_io_identity(self):
        upstream = MODULE.upstream_audit_lock(self.root)
        original = (self.root / "crates/sp1-guest/Cargo.lock").read_text()
        self.assertNotIn("git+", upstream)
        self.assertIn(f'name = "tiny-keccak"\nversion = "2.0.2"\nsource = "{MODULE.REGISTRY_SOURCE}"\n'
                      'dependencies', upstream)
        changed = [(a, b) for a, b in zip(original.splitlines(), upstream.splitlines()) if a != b]
        self.assertEqual(changed, [(f'source = "{MODULE.GUEST_GIT_SOURCE}"', f'source = "{MODULE.REGISTRY_SOURCE}"')])

    def test_upstream_audit_lock_refuses_an_unreviewed_guest(self):
        self.replace("crates/sp1-guest/Cargo.toml", MODULE.GUEST_GIT_DEPENDENCY["commit"], "0" * 40)
        with self.assertRaises(ValueError):
            MODULE.upstream_audit_lock(self.root)

    def test_unreadable_guest_metadata_is_an_error(self):
        (self.root / "crates/sp1-guest/Cargo.lock").write_text("[[package]\n")
        self.assertNotEqual(MODULE.guest_dependency_errors(self.root), [])


if __name__ == "__main__":
    unittest.main()
