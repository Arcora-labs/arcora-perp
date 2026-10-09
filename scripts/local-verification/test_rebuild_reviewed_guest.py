#!/usr/bin/env python3
"""Fail-closed source and compiler-input guards; no compiler or proof required."""
import argparse
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import rebuild_reviewed_guest as recipe


class ReviewedGuestRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def args(self, name="perp_core"):
        source = "crates/perp-core/src/lib.rs" if name == "perp_core" else "crates/sp1-guest/src/main.rs"
        return ["--crate-name", name, source, "--target", recipe.TARGET,
                "-C", "metadata=current", "-C", "extra-filename=-keep",
                "--extern", "dependency=unchanged.rlib", *recipe.FLAGS]

    def source_copy(self):
        root = self.base / "checkout"
        for name in recipe.clock.EXPECTED_GUEST_SOURCES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(recipe.ROOT / name, path)
        return root

    def test_current_reviewed_source_passes(self):
        self.assertEqual(recipe.reviewed_sources(), recipe.clock.EXPECTED_GUEST_SOURCES)

    def test_only_metadata_and_path_are_normalized(self):
        for name, metadata in recipe.METADATA.items():
            before = self.args(name)
            after = recipe.normalized_args(before, cwd=recipe.ROOT)
            expected = before.copy()
            expected[expected.index("metadata=current")] = "metadata=" + metadata
            expected.append(f"--remap-path-prefix={recipe.ROOT}={recipe.REFERENCE_ROOT}")
            self.assertEqual(after, expected)
            self.assertIn("metadata=current", before)

    def test_registry_and_host_compiles_are_unchanged(self):
        for args in (self.args("registry_crate"), ["-vV"],
                     ["--crate-name", "perp_core", "src/lib.rs", "-C", "metadata=current"]):
            self.assertEqual(recipe.normalized_args(args), args)

    def test_wrong_source_missing_or_duplicate_metadata_and_remap_fail(self):
        variants = []
        wrong_source = self.args()
        wrong_source[2] = "other/lib.rs"
        variants.append(wrong_source)
        missing = self.args()
        del missing[5:7]
        variants += [missing, self.args() + ["-C", "metadata=duplicate"],
                     self.args() + ["--remap-path-prefix=a=b"]]
        for args in variants:
            with self.subTest(args=args), self.assertRaises(ValueError):
                recipe.normalized_args(args, cwd=recipe.ROOT)

    def assert_source_rejected_before_execution(self, root):
        output = self.base / "output"
        args = argparse.Namespace(cargo=Path("missing-cargo"), rustc=Path("missing-rustc"),
                                  output_dir=output, timeout_seconds=1)
        with (patch.object(recipe, "ROOT", root),
              patch.object(recipe.subprocess, "check_output") as tool,
              patch.object(recipe.os, "execv") as compiler):
            with self.assertRaises(ValueError):
                recipe.build(args)
            with self.assertRaises(ValueError):
                recipe.compiler_wrapper(["missing-rustc", str(self.base / "argv.jsonl"), "missing-rustc"])
            tool.assert_not_called()
            compiler.assert_not_called()
        self.assertFalse(output.exists())
        self.assertFalse((self.base / "argv.jsonl").exists())

    def test_modified_source_rejected_before_tools_output_or_normalization(self):
        root = self.source_copy()
        (root / "crates/sp1-guest/src/main.rs").write_text("fn main() {}\n")
        self.assert_source_rejected_before_execution(root)

    def test_unpinned_build_inputs_and_symlink_rejected(self):
        root = self.source_copy()
        for relative in ("crates/sp1-guest/build.rs", "crates/perp-core/src/extra.rs", ".cargo/config.toml"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// extra input\n")
            self.assert_source_rejected_before_execution(root)
            path.unlink()
        source = root / "crates/sp1-guest/src/main.rs"
        source.unlink()
        source.symlink_to(recipe.ROOT / "crates/sp1-guest/src/main.rs")
        self.assert_source_rejected_before_execution(root)

    def test_output_is_exclusive_and_outside_checkout(self):
        existing = self.base / "existing"
        existing.mkdir()
        marker = existing / "preserve"
        marker.write_text("owned by someone else")
        with self.assertRaises(FileExistsError):
            recipe.prepare_output(existing)
        self.assertEqual(marker.read_text(), "owned by someone else")
        with self.assertRaises(ValueError):
            recipe.prepare_output(recipe.ROOT / "must-not-create")
        created = recipe.prepare_output(self.base / "new")
        self.assertEqual(list((created / "target").iterdir()), [])

    def test_cargo_rustup_shim_is_not_dereferenced(self):
        rustup = self.base / "rustup"
        rustup.write_text("not executed")
        cargo = self.base / "cargo"
        cargo.symlink_to(rustup)
        rustc = self.base / "rustc"
        rustc.write_text("not executed")
        args = argparse.Namespace(cargo=cargo, rustc=rustc, output_dir=self.base / "output", timeout_seconds=1)
        with patch.object(recipe.subprocess, "check_output", side_effect=[recipe.CARGO_VERSION, "wrong rustc"]) as tool:
            with self.assertRaisesRegex(ValueError, "different SP1 compiler"):
                recipe.build(args)
        self.assertEqual(tool.call_args_list[0].args[0], [str(cargo), "+1.99.0", "--version"])
        self.assertFalse(args.output_dir.exists())


if __name__ == "__main__":
    unittest.main()
