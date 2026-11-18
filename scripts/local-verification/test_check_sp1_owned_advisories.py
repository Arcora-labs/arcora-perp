import shutil
import tempfile
import unittest
from pathlib import Path

import check_sp1_owned_advisories as owned

ROOT = Path(__file__).resolve().parents[2]
ADVISORY = "RUSTSEC-2026-0387"
TEMPORARY = []
REGISTRY = 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'


def package(name, version, dependencies=(), local=False):
    text = f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
    if not local:
        text += REGISTRY
    if dependencies:
        text += "dependencies = [\n" + "".join(f' "{d}",\n' for d in dependencies) + "]\n"
    return text + "\n"


def lock(*packages):
    directory = Path(tempfile.mkdtemp())
    TEMPORARY.append(directory)
    path = directory / "Cargo.lock"
    path.write_text("version = 4\n\n" + "".join(packages))
    return path


# The shape of the guest lock after the k256 0.14 upgrade: only SP1 reaches 0.5.5.
SP1_ONLY = (
    package("crypto-bigint", "0.5.5"),
    package("crypto-bigint", "0.7.11"),
    package("elliptic-curve", "0.13.8", ["crypto-bigint 0.5.5"]),
    package("elliptic-curve", "0.14.3", ["crypto-bigint 0.7.11"]),
    package("k256", "0.14.0", ["elliptic-curve 0.14.3"]),
    package("sp1-lib", "6.1.0", ["elliptic-curve 0.13.8"]),
    package("sp1-zkvm", "6.1.0", ["sp1-lib"]),
    package("perp-core", "0.0.1", ["k256"], local=True),
    package("perp-core-guest", "0.0.0", ["perp-core", "sp1-zkvm"], local=True),
)


class SyntheticLocks(unittest.TestCase):
    def test_a_lock_that_reaches_the_advisory_only_through_sp1_passes(self):
        result = owned.check_lock(lock(*SP1_ONLY), ADVISORY)
        self.assertEqual(result["vulnerable"], ["crypto-bigint 0.5.5"])
        self.assertEqual(result["sp1_owners"], ["sp1-lib 6.1.0"])

    def test_a_repository_crate_on_the_old_curve_stack_is_refused(self):
        regressed = list(SP1_ONLY)
        regressed[-2] = package("perp-core", "0.0.1", ["k256 0.13.4"], local=True)
        regressed.append(package("ecdsa", "0.16.9", ["elliptic-curve 0.13.8"]))
        regressed.append(package("k256", "0.13.4", ["ecdsa", "elliptic-curve 0.13.8"]))
        with self.assertRaisesRegex(ValueError, "repository crates reach .* outside SP1: perp-core, perp-core-guest"):
            owned.check_lock(lock(*regressed), ADVISORY)

    def test_an_exception_with_nothing_to_except_is_refused(self):
        patched = [p for p in SP1_ONLY if '"0.5.5"' not in p and '"0.13.8"' not in p]
        patched = [p.replace('"elliptic-curve 0.13.8"', '"elliptic-curve 0.14.3"') for p in patched]
        with self.assertRaisesRegex(ValueError, "no longer present; remove its SP1 exception"):
            owned.check_lock(lock(*patched), ADVISORY)

    def test_an_unreviewed_sp1_release_is_refused(self):
        other = [p.replace('name = "sp1-lib"\nversion = "6.1.0"', 'name = "sp1-lib"\nversion = "6.0.0"')
                 for p in SP1_ONLY]
        with self.assertRaisesRegex(ValueError, "unreviewed SP1 crate: sp1-lib 6.0.0"):
            owned.check_lock(lock(*other), ADVISORY)

    def test_a_vulnerable_package_no_sp1_crate_uses_is_refused(self):
        orphan = [p for p in SP1_ONLY if "sp1-" not in p and '"perp-core-guest"' not in p]
        with self.assertRaisesRegex(ValueError, "not reached through an SP1 crate"):
            owned.check_lock(lock(*orphan), ADVISORY)

    def test_an_ambiguous_dependency_is_refused(self):
        ambiguous = list(SP1_ONLY) + [package("needs-bigint", "1.0.0", ["crypto-bigint"])]
        with self.assertRaisesRegex(ValueError, "unresolvable lock dependency"):
            owned.check_lock(lock(*ambiguous), ADVISORY)

    def test_the_command_line_fails_closed(self):
        self.assertEqual(owned.main(["--advisory", ADVISORY, str(lock(*SP1_ONLY))]), 0)
        self.assertEqual(owned.main(["--advisory", ADVISORY, str(ROOT / "Cargo.lock")]), 1)
        with self.assertRaises(SystemExit):
            owned.main(["--advisory", "RUSTSEC-0000-0000", str(lock(*SP1_ONLY))])


class CommittedLocks(unittest.TestCase):
    def test_the_sp1_locks_reach_the_advisory_only_through_sp1(self):
        for relative in ("crates/sp1-guest/Cargo.lock", "crates/sp1-host/Cargo.lock",
                         "crates/prover-service/Cargo.lock"):
            with self.subTest(lock=relative):
                result = owned.check_lock(ROOT / relative, ADVISORY)
                self.assertTrue(result["sp1_owners"])

    def test_the_application_and_tee_locks_carry_no_affected_crypto_bigint(self):
        for relative in ("Cargo.lock", "scripts/tee-capture/Cargo.lock"):
            with self.subTest(lock=relative):
                with self.assertRaisesRegex(ValueError, "no longer present"):
                    owned.check_lock(ROOT / relative, ADVISORY)


def tearDownModule():
    for directory in TEMPORARY:
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
