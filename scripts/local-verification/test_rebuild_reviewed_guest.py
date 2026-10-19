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
        for name in recipe.clock.REVIEWED_GUEST["sources"]:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(recipe.ROOT / name, path)
        return root

    def test_current_reviewed_source_passes(self):
        self.assertEqual(recipe.reviewed_sources(), recipe.clock.REVIEWED_GUEST["sources"])

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

    def test_guest_dependency_source_is_checked_with_the_source_pins(self):
        root = self.source_copy()
        manifest = root / "crates/sp1-guest/Cargo.toml"
        commit = recipe.check_sp1_release.GUEST_GIT_DEPENDENCY["commit"]
        manifest.write_text(manifest.read_text().replace(commit, "0" * 40))
        # Even with pins that match the changed copy, the source policy refuses it.
        pins = {name: recipe.sha(root / name) for name in recipe.clock.REVIEWED_GUEST["sources"]}
        with (patch.object(recipe, "ROOT", root),
              patch.dict(recipe.clock.REVIEWED_GUEST, {"sources": pins})):
            with self.assertRaisesRegex(ValueError, "unreviewed guest dependency source"):
                recipe.reviewed_sources()

    def checkout(self, home):
        pin = recipe.check_sp1_release.GUEST_GIT_DEPENDENCY
        checkout = home / "git/checkouts" / (pin["name"] + "-0123456789abcdef") / pin["commit"][:7]
        (checkout / "src").mkdir(parents=True)
        (checkout / "src/lib.rs").write_text("pub fn keccakf() {}\n")
        (checkout / ".cargo-ok").write_text("")
        (checkout / ".git").mkdir()
        (checkout / ".git/HEAD").write_text("ref: refs/heads/master\n")
        files = {"src/lib.rs": recipe.sha(checkout / "src/lib.rs")}
        patcher = patch.dict(pin, {"files": 1, "source_tree_sha256": recipe.tree_digest(files)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return checkout

    def test_git_dependency_checkout_must_hold_the_reviewed_tree(self):
        home = self.base / "cargo-home"
        with self.assertRaisesRegex(ValueError, "not checked out"):
            recipe.git_checkout_inventory(home)
        checkout = self.checkout(home)
        self.assertEqual(list(recipe.git_checkout_inventory(home).values())[0]["files"], 1)
        (checkout / ".git/index").write_text("git metadata is not compiled")
        recipe.git_checkout_inventory(home)
        for change in ("src/lib.rs", "build.rs"):
            with self.subTest(change=change):
                original = (checkout / "src/lib.rs").read_text()
                (checkout / change).write_text("// unreviewed\n")
                with self.assertRaisesRegex(ValueError, "differs from the reviewed source tree"):
                    recipe.git_checkout_inventory(home)
                (checkout / "src/lib.rs").write_text(original)
                if change == "build.rs":
                    (checkout / change).unlink()
        # A second checkout of the same commit (another URL spelling) must match too.
        other = home / "git/checkouts/tiny-keccak-fedcba9876543210" / checkout.name
        (other / "src").mkdir(parents=True)
        (other / "src/lib.rs").write_text("// unreviewed\n")
        with self.assertRaisesRegex(ValueError, "differs from the reviewed source tree"):
            recipe.git_checkout_inventory(home)

    def test_build_refuses_without_the_checkout_before_creating_output(self):
        args = argparse.Namespace(cargo=self.base / "cargo", rustc=self.base / "rustc",
                                  output_dir=self.base / "output", timeout_seconds=1)
        args.cargo.write_text("not executed")
        args.rustc.write_text("not executed")
        with (patch.object(recipe, "reviewed_sources", return_value={}),
              patch.dict(recipe.os.environ, {"CARGO_HOME": str(self.base / "empty-cargo-home")}),
              patch.object(recipe.subprocess, "check_output",
                           side_effect=[recipe.CARGO_VERSION, recipe.RUSTC_VERSION]),
              patch.object(recipe.subprocess, "Popen") as build):
            with self.assertRaisesRegex(ValueError, "not checked out"):
                recipe.build(args)
            build.assert_not_called()
        self.assertFalse(args.output_dir.exists())

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
