"""Synthetic public-inventory and build-output acceptance checks, without Git/RPC."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import service_build_identity as build


class ServiceBuildIdentityTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="arcora-service-build-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name).resolve()
        for name in ("Cargo.toml", "Cargo.lock", "contracts/foundry.toml",
                     "crates/gateway/src/main.rs", "crates/service-identity/public.rs",
                     "scripts/local-verification/helper.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic public source: " + name + "\n")
        self.output = self.root / "target/build/service-build-identity.json"
        self.output.parent.mkdir(parents=True)

    def test_exact_canonical_source_map_not_commit_or_file_order(self):
        with mock.patch.object(build.identity.legacy, "command",
                               side_effect=AssertionError("no Git or compiler")):
            value, sources = build.build_identity(self.root)
        self.assertEqual(set(value), {"schema", "algorithm", "source_files", "source_sha256"})
        self.assertEqual(value["schema"], build.SCHEMA)
        self.assertEqual(value["algorithm"], build.ALGORITHM)
        self.assertEqual(value["source_files"], 6)
        self.assertEqual(value["source_sha256"], build.identity.digest(build.identity.canonical(sources)))
        self.assertEqual(build.identity.canonical(sources),
                         build.identity.canonical(dict(reversed(list(sources.items())))))

    def test_changed_and_added_public_inputs_require_new_identity(self):
        initial, _ = build.build_identity(self.root)
        (self.root / "crates/gateway/src/main.rs").write_text("changed public source\n")
        changed, _ = build.build_identity(self.root)
        self.assertEqual(initial["source_files"], changed["source_files"])
        self.assertNotEqual(initial["source_sha256"], changed["source_sha256"])
        (self.root / "crates/gateway/src/new_public.rs").write_text("added public source\n")
        added, _ = build.build_identity(self.root)
        self.assertEqual(added["source_files"], initial["source_files"] + 1)
        self.assertNotEqual(changed["source_sha256"], added["source_sha256"])

    def test_excluded_private_generated_and_cache_inputs_are_never_opened(self):
        initial, _ = build.build_identity(self.root)
        excluded = ("crates/gateway/.env", "crates/gateway/private-key.json",
                    "crates/gateway/credentials.toml", "crates/gateway/secrets.rs",
                    "crates/gateway/target/cache.rs", "crates/gateway/out/result.json",
                    "scripts/local-verification/__pycache__/cache.py")
        for name in excluded:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic excluded fixture; never read\n")
        real_identity = build.identity.legacy.identity
        def guarded(root, name):
            self.assertNotIn(name, excluded)
            return real_identity(root, name)
        with mock.patch.object(build.identity.legacy, "identity", side_effect=guarded):
            after, sources = build.build_identity(self.root)
        self.assertEqual(initial, after)
        watches = build.rerun_paths(self.root, sources)
        self.assertTrue(all(str(self.root / name) not in map(str, watches) for name in excluded))
        self.assertNotIn(self.root / "crates/gateway", watches)
        self.assertNotIn(self.root / "scripts/local-verification", watches)

    def test_public_symlink_refuses_without_reading_its_target(self):
        outside = self.root / "outside-uncovered.txt"
        outside.write_text("synthetic external data\n")
        (self.root / "crates/gateway/src/alias.rs").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            build.build_identity(self.root)

    def test_missing_bounded_or_malformed_inventory_refuses(self):
        (self.root / "Cargo.lock").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            build.build_identity(self.root)
        invalid = ({}, {"crates/gateway/src/main.rs": "0x" + "a" * 64},
                   {"crates/gateway/src/main.rs": "A" * 64},
                   {"../outside.rs": "a" * 64}, {"crates/private-key.json": "a" * 64},
                   {"crates/gateway/src/new\n.rs": "a" * 64})
        for sources in invalid:
            with self.subTest(sources=sources), mock.patch.object(
                    build.identity, "source_inventory", return_value=sources):
                with self.assertRaises(ValueError):
                    build.build_identity(self.root)
        with mock.patch.object(build.identity, "MAX_SOURCE_FILES", 1), mock.patch.object(
                build.identity, "source_inventory", return_value={"Cargo.toml": "a" * 64,
                                                                   "Cargo.lock": "b" * 64}):
            with self.assertRaisesRegex(ValueError, "bounded"):
                build.build_identity(self.root)

    def test_build_artifact_is_canonical_replaceable_and_not_a_source_input(self):
        initial, _ = build.build_identity(self.root)
        build.write_identity(self.root, self.output, initial)
        self.assertEqual(self.output.read_bytes(), build.identity.canonical(initial))
        self.assertEqual(build.build_identity(self.root)[0], initial)
        (self.root / "crates/gateway/src/main.rs").write_text("new build source\n")
        updated, _ = build.build_identity(self.root)
        build.write_identity(self.root, self.output, updated)
        self.assertEqual(self.output.read_bytes(), build.identity.canonical(updated))
        self.assertFalse(list(self.output.parent.glob(".service-build-*.tmp")))
        with self.assertRaisesRegex(ValueError, "outside covered"):
            build.write_identity(self.root, self.root / "crates/service-identity/service-build-identity.json",
                                 updated)

    def test_output_symlink_cannot_replace_foreign_data(self):
        outside = self.root / "uncovered-original.txt"
        outside.write_text("synthetic original\n")
        self.output.symlink_to(outside)
        value, _ = build.build_identity(self.root)
        with self.assertRaisesRegex(ValueError, "regular build output"):
            build.write_identity(self.root, self.output, value)
        self.assertEqual(outside.read_text(), "synthetic original\n")

    def test_cli_success_emits_only_public_rerun_paths(self):
        command = [sys.executable, str(Path(build.__file__).resolve()), "--root", str(self.root),
                   "--output", str(self.output)]
        run = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        value, sources = build.build_identity(self.root)
        self.assertEqual(self.output.read_bytes(), build.identity.canonical(value))
        lines = run.stdout.splitlines()
        self.assertTrue(lines)
        self.assertTrue(all(line.startswith("cargo:rerun-if-changed=") for line in lines))
        watched = {line.removeprefix("cargo:rerun-if-changed=") for line in lines}
        self.assertTrue({str(self.root / name) for name in sources}.issubset(watched))
        self.assertIn(str(self.root / "crates/gateway/src"), watched)
        self.assertNotIn(str(self.root / "crates"), watched)
        self.assertFalse(any("/target/" in line for line in lines))

    def test_failed_generation_keeps_previous_artifact_and_has_no_fallback(self):
        value, _ = build.build_identity(self.root)
        build.write_identity(self.root, self.output, value)
        before = self.output.read_bytes()
        (self.root / "Cargo.lock").unlink()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = build.main(["--root", str(self.root), "--output", str(self.output)])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "service build identity generation failed\n")
        self.assertEqual(self.output.read_bytes(), before)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            self.assertEqual(build.main(["--unknown", "synthetic rejected input"]), 1)


if __name__ == "__main__":
    unittest.main()
