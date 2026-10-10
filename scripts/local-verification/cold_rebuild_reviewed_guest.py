#!/usr/bin/env python3
"""Rebuild the reviewed guest with empty Cargo/home/target directories.

Uses an independently SHA-pinned official SP1 compiler archive, locked registry
archives fetched into a new cache, then an offline compile. Does not generate a
proof or infer machine independence from self-reported CI environment variables.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shlex
import signal
import subprocess
import sys
import tarfile
import time
import tomllib

import rebuild_reviewed_guest as recipe

ROOT = Path(__file__).resolve().parents[2]
TOOLCHAIN_URL = ('https://github.com/succinctlabs/rust/releases/download/'
                 'succinct-1.93.0-64bit/rust-toolchain-aarch64-apple-darwin.tar.gz')
TOOLCHAIN_SHA256 = '8ee4ea0f27efbf73ddfe8a2038ced4c0802fdcf9e1ee109349763b9f4a808cf6'
RUSTC_SHA256 = '985c33069083f55ed42b68ef51a8528d0cb1632e43428ffdb5c489306154f964'
REFERENCE_CARGO_HOME = '/Users/huseyinarslan/.cargo'
REGISTRY_SOURCE = 'registry+https://github.com/rust-lang/crates.io-index'


def require(ok, label):
    if not ok:
        raise ValueError(label)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def require_regular(path):
    require(path.is_file() and not path.is_symlink(), 'regular input file required')


def no_ambient_config(root):
    for parent in (root, *root.parents):
        for name in ('.cargo/config', '.cargo/config.toml'):
            path = parent / name
            require(not path.exists() and not path.is_symlink(), 'ambient Cargo configuration refused')


def isolated_environment(output, cargo, rustc):
    # Deliberately do not inherit env, registry credentials, wrappers, profile
    # overrides, proxies, RUSTFLAGS, toolchain overrides or user linker settings.
    return {'HOME': str(output / 'home'), 'CARGO_HOME': str(output / 'cargo-home'),
            'CARGO_TARGET_DIR': str(output / 'target'), 'TMPDIR': str(output / 'tmp'),
            'PATH': ':'.join((str(cargo.parent), str(rustc.parent), '/usr/bin', '/bin', '/usr/sbin', '/sbin')),
            'LANG': 'C', 'LC_ALL': 'C', 'CARGO_BUILD_JOBS': '2', 'CARGO_TERM_COLOR': 'never',
            'RUSTC': str(rustc), 'RUSTC_BOOTSTRAP': '1', 'CARGO_HTTP_TIMEOUT': '30',
            'CARGO_NET_RETRY': '2', 'CARGO_REGISTRIES_CRATES_IO_PROTOCOL': 'sparse',
            'CARGO_ENCODED_RUSTFLAGS': '\x1f'.join(recipe.FLAGS)}


def unpack_toolchain(archive, destination):
    require_regular(archive)
    require(sha(archive) == TOOLCHAIN_SHA256, 'official SP1 toolchain archive SHA-256 mismatch')
    destination.mkdir()
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        require(len(members) <= 50000 and sum(m.size for m in members) <= 4 * 1024**3,
                'toolchain archive resource limit')
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts, 'unsafe toolchain archive path')
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(), 'unsupported toolchain archive entry')
        bundle.extractall(destination, members=members, filter='data')
    rustc = destination / 'bin/rustc'
    require_regular(rustc)
    require(sha(rustc) == RUSTC_SHA256, 'SP1 compiler binary SHA-256 mismatch')
    return rustc


def registry_inventory(home, lock_path):
    """Require every fetched archive to match its reviewed lock checksum."""
    lock = tomllib.loads(lock_path.read_text())
    expected = {}
    for package in lock['package']:
        if 'source' not in package:
            continue
        require(package['source'] == REGISTRY_SOURCE, 'unreviewed dependency registry or git source')
        name = package['name'] + '-' + package['version'] + '.crate'
        require(name not in expected, 'ambiguous locked dependency identity')
        expected[name] = package['checksum']
    actual = {}
    for path in (home / 'registry/cache').glob('*/*.crate'):
        require_regular(path)
        require(path.name in expected and path.name not in actual, 'unexpected cached dependency')
        actual[path.name] = sha(path)
        require(actual[path.name] == expected[path.name], 'locked dependency archive checksum mismatch')
    require(actual == expected and bool(actual), 'incomplete locked registry fetch')
    return actual


def unpacked_registry_inventory(home, archives):
    """Bind compiled source bytes to the already checksum-verified .crate files.

    Cargo's unpack marker is the only allowed extra file. Generated outputs must
    stay in OUT_DIR, not modify registry source or introduce unreviewed modules.
    """
    result = {}
    for archive in sorted((home / 'registry/cache').glob('*/*.crate')):
        require(archive.name in archives and sha(archive) == archives[archive.name],
                'registry archive changed before source verification')
        name = archive.name.removesuffix('.crate')
        source = home / 'registry/src' / archive.parent.name / name
        require(source.is_dir() and not source.is_symlink(), 'regular extracted dependency directory required')
        expected = {}
        with tarfile.open(archive, 'r:gz') as bundle:
            for member in bundle:
                path = PurePosixPath(member.name)
                require(not path.is_absolute() and '..' not in path.parts and path.parts[0] == name,
                        'unsafe registry archive path')
                if member.isdir():
                    continue
                require(member.isfile(), 'unsupported registry archive entry')
                relative = '/'.join(path.parts[1:])
                require(relative and relative not in expected and member.size <= 64 * 1024**2,
                        'invalid or oversized registry archive member')
                expected[relative] = hashlib.sha256(bundle.extractfile(member).read()).hexdigest()
        actual = {}
        for path in source.rglob('*'):
            require(not path.is_symlink(), 'symlinked extracted dependency refused')
            if path.is_dir():
                continue
            require_regular(path)
            relative = path.relative_to(source).as_posix()
            if relative == '.cargo-ok' and relative not in expected:
                continue
            actual[relative] = sha(path)
        require(actual == expected and bool(actual), 'extracted dependency source mismatch')
        result[name] = {'files': len(actual), 'source_tree_sha256': hashlib.sha256(
            json.dumps(actual, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    require(len(result) == len(archives), 'incomplete extracted dependency inventory')
    return result


def normalized_args(args, home, root=ROOT, cwd=None):
    after = recipe.normalized_args(args, root=root, cwd=cwd)
    if '--target' in args and args[args.index('--target') + 1] == recipe.TARGET:
        # The reviewed ELF contains registry source locations too. Remap that
        # new cache path, never bytes in the ELF or reviewed source files.
        require(not any(value.startswith('--remap-path-prefix') for value in args),
                'unexpected existing registry path remap')
        after.append(f'--remap-path-prefix={home}={REFERENCE_CARGO_HOME}')
    return after


def compiler_wrapper(argv):
    recipe.reviewed_sources()
    expected, home, log, compiler, *args = argv
    require(Path(compiler).resolve() == Path(expected).resolve(), 'unexpected compiler executable')
    require(sha(compiler) == RUSTC_SHA256, 'compiler changed during build')
    after = normalized_args(args, Path(home))
    if after != args:
        with Path(log).open('a') as stream:
            stream.write(json.dumps({'crate': args[args.index('--crate-name') + 1],
                                     'original_args': args, 'normalized_args': after}) + '\n')
    os.execv(compiler, [compiler, *after])


def command(argv, cwd, env, logfile, timeout):
    started = time.monotonic()
    with logfile.open('xb') as log:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            raise ValueError('owned build/fetch process group exceeded deadline') from None
    require(code == 0, 'build/fetch command failed; inspect phase log')
    return {'argv': argv, 'seconds': round(time.monotonic() - started, 6), 'exit_code': code}


def build(args):
    sources = recipe.reviewed_sources()
    no_ambient_config(ROOT)
    require(type(args.timeout_seconds) is int and 1 <= args.timeout_seconds <= 900, 'invalid build deadline')
    require_regular(args.archive)
    require(sha(args.archive) == TOOLCHAIN_SHA256, 'official SP1 toolchain archive SHA-256 mismatch')
    cargo = args.cargo.resolve(strict=True)  # Direct Cargo binary; rustup shim is NOT accepted.
    require_regular(cargo)
    require(cargo.name == 'cargo', 'direct installed Cargo binary required, not a rustup shim')
    output = recipe.prepare_output(args.output_dir)
    result = {'status': 'FAIL', 'phase': 'prepare', 'release_gate': 'HOLD',
              'proof_generated': False, 'guest_executed': False, 'program_vkey_rederived': False,
              'dependency_registry_cache_reused': False, 'fresh_home': True, 'fresh_target': True,
              'machine_independence_asserted': False, 'commands': []}
    try:
        for name in ('home', 'cargo-home', 'tmp'):
            (output / name).mkdir()
        result['phase'] = 'toolchain'
        rustc = unpack_toolchain(args.archive, output / 'toolchain')
        env = isolated_environment(output, cargo, rustc)
        cargo_version = subprocess.check_output([str(cargo), '--version'], env=env, text=True, timeout=15).strip()
        rustc_version = subprocess.check_output([str(rustc), '-vV'], env=env, text=True, timeout=15).strip()
        require(cargo_version == recipe.CARGO_VERSION, 'different Cargo build; reviewed recipe pins 1.99.0')
        require(rustc_version == recipe.RUSTC_VERSION, 'different SP1 compiler version or host')
        result.update(cargo=cargo_version, rustc=rustc_version, cargo_sha256=sha(cargo),
                      rustc_sha256=sha(rustc), toolchain_archive_sha256=sha(args.archive),
                      toolchain_source=TOOLCHAIN_URL, os=platform.system(), architecture=platform.machine(),
                      source_pins_before_and_after=sources, recipe_sha256=sha(__file__),
                      base_recipe_sha256=sha(recipe.__file__))
        manifest = str(ROOT / 'crates/sp1-guest/Cargo.toml')
        result['phase'] = 'fetch'
        fetch_env = {**env, 'CARGO_NET_OFFLINE': 'false'}
        result['commands'].append(command([str(cargo), 'fetch', '--manifest-path', manifest, '--locked'],
                                          ROOT, fetch_env, output / 'fetch.log', args.timeout_seconds))
        dependencies = registry_inventory(output / 'cargo-home', ROOT / 'crates/sp1-guest/Cargo.lock')
        result['registry_archives_sha256'] = dependencies
        unpacked = unpacked_registry_inventory(output / 'cargo-home', dependencies)
        result['registry_sources'] = unpacked
        wrapper = output / 'rustc-wrapper.sh'
        invocation_log = output / 'compiler-invocations.jsonl'
        wrapper_args = [sys.executable, str(Path(__file__).resolve()), '--compiler-wrapper', str(rustc),
                        str(output / 'cargo-home'), str(invocation_log)]
        wrapper.write_text('#!/bin/sh\nexec ' + ' '.join(map(shlex.quote, wrapper_args)) + ' "$@"\n')
        wrapper.chmod(0o700)
        env.update(RUSTC_WRAPPER=str(wrapper), CARGO_NET_OFFLINE='true')
        result['phase'] = 'compile'
        result['commands'].append(command([str(cargo), 'build', '--manifest-path', manifest,
                    '--locked', '--offline', '--release', '--target', recipe.TARGET],
                    ROOT, env, output / 'build.log', args.timeout_seconds))
        result['phase'] = 'identity'
        require(recipe.reviewed_sources() == sources, 'guest inputs changed during build')
        require(registry_inventory(output / 'cargo-home', ROOT / 'crates/sp1-guest/Cargo.lock') == dependencies,
                'dependency archives changed during build')
        require(unpacked_registry_inventory(output / 'cargo-home', dependencies) == unpacked,
                'extracted dependency sources changed during build')
        require(sha(__file__) == result['recipe_sha256'] and sha(recipe.__file__) == result['base_recipe_sha256'],
                'build recipe changed during compilation')
        require(sha(cargo) == result['cargo_sha256'] and sha(rustc) == result['rustc_sha256'],
                'compiler or Cargo changed during compilation')
        elf = output / 'target' / recipe.TARGET / 'release/perp-core-guest'
        require_regular(elf)
        result.update(elf_sha256=sha(elf), elf_bytes=elf.stat().st_size)
        require(result['elf_sha256'] == recipe.clock.EXPECTED_ELF, 'compiled ELF differs from reviewed identity')
        invocations = [json.loads(row) for row in invocation_log.read_text().splitlines()]
        require(set(recipe.METADATA) <= {row['crate'] for row in invocations}, 'reviewed compiler invocation missing')
        (output / 'guest.elf').write_bytes(elf.read_bytes())
        result.update(status='PASS_COLD_BYTE_EXACT_REVIEWED_ELF_REBUILD', phase='complete',
                      compiler_invocations_sha256=sha(invocation_log),
                      normalization={'workspace_metadata': recipe.METADATA,
                                     'checkout_path': recipe.REFERENCE_ROOT, 'cargo_home_path': REFERENCE_CARGO_HOME},
                      scope='Fresh registry/home/target and pinned official compiler archive. Offline Cargo compilation, not a network sandbox or independent compiler bootstrap. Machine independence requires external runner provenance; no proof, hardware attestation or deployment claim.')
    except Exception as error:
        result['failure_type'] = type(error).__name__
        # Fixed labels only; subprocess output remains in the phase log.
        if type(error) is ValueError:
            result['failure_check'] = str(error)
        raise
    finally:
        for name in ('fetch.log', 'build.log'):
            if (output / name).is_file():
                result[name.replace('.', '_') + '_sha256'] = sha(output / name)
        with (output / 'verification.json').open('x') as stream:
            stream.write(json.dumps(result, indent=2) + '\n')
    return result


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--compiler-wrapper':
        compiler_wrapper(sys.argv[2:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo', type=Path, required=True, help='direct Cargo 1.99.0 binary, not a rustup shim')
    parser.add_argument('--archive', type=Path, required=True, help='SHA-pinned official ARM64 Mac compiler archive')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--timeout-seconds', type=int, default=600)
    args = parser.parse_args()
    try:
        result = build(args)
    except Exception as error:
        print(json.dumps({'status': 'FAIL', 'failure_type': type(error).__name__}), flush=True)
        raise SystemExit(1) from None
    print(json.dumps({key: result[key] for key in ('status', 'elf_sha256', 'elf_bytes', 'release_gate')}))


if __name__ == '__main__':
    main()
