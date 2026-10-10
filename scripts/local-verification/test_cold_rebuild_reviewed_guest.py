"""CPU-only guards for the cold registry/compiler build; no downloads required."""
import argparse
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import cold_rebuild_reviewed_guest as cold


class ColdBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_environment_does_not_inherit_secrets_cache_wrappers_or_profiles(self):
        dirty = {'SECRET_TOKEN': 'private-sentinel', 'CARGO_HOME': '/shared-cache',
                 'RUSTFLAGS': 'modified', 'RUSTC_WRAPPER': '/unreviewed',
                 'CARGO_PROFILE_RELEASE_OPT_LEVEL': '0', 'HTTPS_PROXY': 'private-sentinel',
                 'SP1_SKIP_PROGRAM_BUILD': 'true', 'RUSTUP_TOOLCHAIN': 'other'}
        with patch.dict(os.environ, dirty):
            env = cold.isolated_environment(self.base, Path('/tools/cargo'), Path('/sp1/bin/rustc'))
        self.assertFalse(any(k in env for k in dirty if k != 'CARGO_HOME'))
        self.assertEqual(env['CARGO_HOME'], str(self.base / 'cargo-home'))
        self.assertEqual(env['HOME'], str(self.base / 'home'))
        self.assertEqual(env['CARGO_TARGET_DIR'], str(self.base / 'target'))
        self.assertNotIn('private-sentinel', json.dumps(env))
        self.assertEqual(env['CARGO_ENCODED_RUSTFLAGS'], '\x1f'.join(cold.recipe.FLAGS))

    def test_ambient_cargo_configuration_is_refused(self):
        checkout = self.base / 'parent' / 'checkout'
        checkout.mkdir(parents=True)
        cold.no_ambient_config(checkout)
        config = self.base / '.cargo/config.toml'
        config.parent.mkdir()
        config.write_text('private-sentinel')
        with self.assertRaisesRegex(ValueError, 'ambient Cargo configuration') as error:
            cold.no_ambient_config(checkout)
        self.assertNotIn('private-sentinel', str(error.exception))

    def test_dangling_ambient_config_symlink_is_refused(self):
        config = self.base / '.cargo/config'
        config.parent.mkdir()
        config.symlink_to(self.base / 'absent')
        with self.assertRaises(ValueError):
            cold.no_ambient_config(self.base)

    def args(self, crate='perp_core'):
        source = 'crates/perp-core/src/lib.rs' if crate == 'perp_core' else 'registry.rs'
        return ['--crate-name', crate, source, '--target', cold.recipe.TARGET,
                '-C', 'metadata=original']

    def test_workspace_metadata_and_both_paths_are_normalized(self):
        args = self.args()
        after = cold.normalized_args(args, self.base, cwd=cold.ROOT)
        self.assertIn('metadata=' + cold.recipe.METADATA['perp_core'], after)
        self.assertEqual(after[-2:], [f'--remap-path-prefix={cold.ROOT}={cold.recipe.REFERENCE_ROOT}',
                                      f'--remap-path-prefix={self.base}={cold.REFERENCE_CARGO_HOME}'])
        self.assertIn('metadata=original', args)

    def test_dependency_metadata_is_not_rewritten(self):
        args = self.args('dep')
        after = cold.normalized_args(args, self.base)
        self.assertEqual(after[:-1], args)
        self.assertEqual(after[-1], f'--remap-path-prefix={self.base}={cold.REFERENCE_CARGO_HOME}')

    def test_host_and_version_queries_are_unchanged(self):
        for args in (['-vV'], ['--crate-name', 'host', 'src/lib.rs']):
            self.assertEqual(cold.normalized_args(args, self.base), args)

    def test_preexisting_remap_and_wrong_workspace_source_are_rejected(self):
        for args in (self.args('dep') + ['--remap-path-prefix=wrong=path'],
                     ['--crate-name', 'perp_core', 'elsewhere.rs', '--target', cold.recipe.TARGET,
                      '-C', 'metadata=original']):
            with self.assertRaises(ValueError):
                cold.normalized_args(args, self.base, cwd=cold.ROOT)

    def test_changed_archive_is_rejected_before_extraction(self):
        archive = self.base / 'toolchain.tar.gz'
        archive.write_bytes(b'not-the-approved-archive')
        dest = self.base / 'unpack'
        with self.assertRaisesRegex(ValueError, 'archive SHA-256 mismatch'):
            cold.unpack_toolchain(archive, dest)
        self.assertFalse(dest.exists())

    def test_archive_symlink_is_not_accepted(self):
        target = self.base / 'data'
        target.write_bytes(b'public-test-data')
        link = self.base / 'archive'
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'regular input'):
            cold.unpack_toolchain(link, self.base / 'out')

    def archive(self, members):
        path = self.base / 'test.tar.gz'
        with tarfile.open(path, 'w:gz') as bundle:
            for name, data in members:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))
        return path

    def test_archive_path_escape_is_rejected(self):
        archive = self.archive([('../escape', b'fixture')])
        with patch.object(cold, 'TOOLCHAIN_SHA256', cold.sha(archive)):
            with self.assertRaisesRegex(ValueError, 'unsafe toolchain archive path'):
                cold.unpack_toolchain(archive, self.base / 'out')
        self.assertFalse((self.base / 'escape').exists())

    def test_compiler_digest_checked_after_archive_digest(self):
        archive = self.archive([('bin/rustc', b'not-the-compiler')])
        with patch.object(cold, 'TOOLCHAIN_SHA256', cold.sha(archive)):
            with self.assertRaisesRegex(ValueError, 'compiler binary SHA-256 mismatch'):
                cold.unpack_toolchain(archive, self.base / 'out')

    def registry(self):
        home = self.base / 'cargo-home'
        archive = home / 'registry/cache/test-registry/fixture-1.0.0.crate'
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b'public-registry-fixture')
        lock = self.base / 'Cargo.lock'
        lock.write_text('version = 4\n[[package]]\nname="fixture"\nversion="1.0.0"\n'
                        f'source="{cold.REGISTRY_SOURCE}"\nchecksum="{cold.sha(archive)}"\n')
        return home, archive, lock

    def test_matching_registry_archives_are_bound_to_lock(self):
        home, archive, lock = self.registry()
        self.assertEqual(cold.registry_inventory(home, lock), {archive.name: cold.sha(archive)})

    def test_changed_missing_or_extra_registry_archive_is_rejected(self):
        home, archive, lock = self.registry()
        original = archive.read_bytes()
        archive.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            cold.registry_inventory(home, lock)
        archive.unlink()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            cold.registry_inventory(home, lock)
        archive.write_bytes(original)
        archive.with_name('unreviewed-1.0.0.crate').write_bytes(b'other')
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            cold.registry_inventory(home, lock)

    def test_alternate_registry_or_git_source_is_rejected(self):
        home, _, lock = self.registry()
        original = lock.read_text()
        for source in ('git+https://example.invalid/repo', 'registry+https://example.invalid'):
            lock.write_text(original.replace(cold.REGISTRY_SOURCE, source))
            with self.assertRaisesRegex(ValueError, 'unreviewed dependency'):
                cold.registry_inventory(home, lock)

    def unpacked(self):
        home = self.base / 'fresh-home'
        archive = home / 'registry/cache/registry/fixture-1.0.0.crate'
        archive.parent.mkdir(parents=True)
        with tarfile.open(archive, 'w:gz') as bundle:
            for name, data in (('Cargo.toml', b'[package]'), ('src/lib.rs', b'pub fn fixture() {}')):
                member = tarfile.TarInfo('fixture-1.0.0/' + name)
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))
        source = home / 'registry/src/registry/fixture-1.0.0'
        (source / 'src').mkdir(parents=True)
        (source / 'Cargo.toml').write_bytes(b'[package]')
        (source / 'src/lib.rs').write_bytes(b'pub fn fixture() {}')
        (source / '.cargo-ok').write_text('marker')
        return home, archive, source

    def test_unpacked_registry_matches_archives_and_allows_only_cargo_marker(self):
        home, archive, _ = self.unpacked()
        inventory = cold.unpacked_registry_inventory(home, {archive.name: cold.sha(archive)})
        self.assertEqual(inventory['fixture-1.0.0']['files'], 2)

    def test_changed_extracted_source_is_rejected_even_when_archive_is_unchanged(self):
        home, archive, source = self.unpacked()
        expected = {archive.name: cold.sha(archive)}
        (source / 'src/lib.rs').write_text('modified code')
        with self.assertRaisesRegex(ValueError, 'extracted dependency source mismatch'):
            cold.unpacked_registry_inventory(home, expected)

    def test_extra_unpacked_build_file_is_rejected(self):
        home, archive, source = self.unpacked()
        (source / 'build.rs').write_text('unreviewed build script')
        with self.assertRaisesRegex(ValueError, 'extracted dependency source mismatch'):
            cold.unpacked_registry_inventory(home, {archive.name: cold.sha(archive)})

    def test_symlinked_unpacked_code_is_rejected(self):
        home, archive, source = self.unpacked()
        file = source / 'src/lib.rs'
        file.unlink()
        other = self.base / 'alternate.rs'
        other.write_text('pub fn fixture() {}')
        file.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'symlinked extracted dependency'):
            cold.unpacked_registry_inventory(home, {archive.name: cold.sha(archive)})

    def test_compiler_wrapper_refuses_changed_binary_before_exec(self):
        compiler = self.base / 'rustc'
        compiler.write_bytes(b'changed-compiler')
        with patch.object(cold.os, 'execv') as execute:
            with self.assertRaisesRegex(ValueError, 'compiler changed'):
                cold.compiler_wrapper([str(compiler), str(self.base), str(self.base/'log'), str(compiler), '-vV'])
        execute.assert_not_called()

    def test_failed_command_is_not_reported_as_success(self):
        with self.assertRaisesRegex(ValueError, 'command failed'):
            cold.command(['/bin/sh', '-c', 'exit 7'], self.base, {'PATH': '/usr/bin:/bin'},
                         self.base/'failure.log', 3)


if __name__ == '__main__':
    unittest.main()
