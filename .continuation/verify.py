#!/usr/bin/env python3
"""Isolated, no-live-transactions verification of the execution remediation."""
import base64
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path.cwd()
OUT = ROOT / 'execution-evidence'
OUT.mkdir(exist_ok=True)
BASE = '3b15ee469dfde89a4b0477d8d2a62edfc4f020b1'
PATCH_SHA = '2d189a08f16c0c290726a0236a52b28fe2a86f290de583e33dfca90104cc6075'
PATHS = ['crates/gateway/src/execution.rs', 'crates/gateway/src/execution_regression_tests.rs', 'crates/gateway/src/main.rs', 'crates/gateway/src/snapshot.rs', 'crates/matcher/src/book.rs', 'crates/matcher/src/lib.rs', 'crates/sequencer/src/lib.rs', 'frontend/src/api/realClient.test.ts', 'frontend/src/api/realClient.ts', 'frontend/src/components/Tables.execution.test.tsx', 'frontend/src/components/Tables.tsx', 'frontend/src/domain/types.ts']
status = {'baseline': BASE, 'runner_commit': os.environ.get('GITHUB_SHA'), 'run_id': os.environ.get('GITHUB_RUN_ID'), 'commands': {}, 'all_passed': False, 'real_proof': False, 'live_transactions': False}
env = dict(os.environ)
for key in list(env):
    if key.startswith(('L1_', 'ENCLAVE_', 'ORACLE_SIGNER_', 'GATEWAY_SIGNER_', 'PROVER_', 'ATTESTATION_', 'DARKPERP_', 'FIN_', 'INSURANCE_')):
        env.pop(key)
env.update(CARGO_TERM_COLOR='never', NO_COLOR='1', CARGO_PROFILE_TEST_OPT_LEVEL='2', CARGO_PROFILE_TEST_DEBUG_ASSERTIONS='true', CARGO_PROFILE_TEST_OVERFLOW_CHECKS='true', CARGO_TARGET_DIR=str(ROOT / 'target'))

def save():
    (OUT / 'status.json').write_text(json.dumps(status, indent=2) + '\n')

def run(name, cmd, cwd=ROOT, timeout=900, tests=False, expected_red=False):
    log = OUT / (name + '.log')
    print('RUN', name, flush=True)
    with log.open('w') as stream:
        try:
            p = subprocess.run(cmd, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
            code = p.returncode
        except subprocess.TimeoutExpired:
            code = 124
    text = log.read_text(errors='replace')
    counts = [tuple(map(int, m)) for m in re.findall(r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored', text)]
    result = {'command': cmd, 'exit': code, 'passed': code == 0, 'rust_counts': counts}
    if tests and cmd[0] == 'cargo':
        result['passed'] = code == 0 and bool(counts) and sum(x[0] for x in counts) > 0 and sum(x[1] for x in counts) == 0
    if expected_red:
        required = ['sealed_maker_cancel_removes_remainder_and_commits_manifest', 'partial_maker_reports_actual_size_and_emits_fill_once', 'multi_level_taker_uses_execution_vwap_not_limit_or_zero']
        result['expected_failure'] = True
        result['passed'] = code == 101 and bool(counts) and all(re.search(r'test [^\n]*' + n + r' \.\.\. FAILED', text) for n in required)
    status['commands'][name] = result
    save()
    print(name, 'exit=', code, 'accepted=', result['passed'], text[-2200:], flush=True)
    return result['passed']

try:
    assert subprocess.check_output(['git', 'diff', '--name-only', BASE, 'HEAD', '--', *PATHS], text=True).strip() == '', 'source changed since pinned base'
    encoded = ''.join((ROOT / '.continuation' / ('payload.' + str(n))).read_text().strip() for n in range(3))
    patch = lzma.decompress(base64.b64decode(encoded, validate=True))
    assert hashlib.sha256(patch).hexdigest() == PATCH_SHA, 'payload checksum mismatch'
    patch_paths = re.findall(r'^diff --git a/(.*?) b/.*$', patch.decode(), re.M)
    assert sorted(patch_paths) == sorted(PATHS), 'unexpected changed paths'
    (OUT / 'input.patch').write_bytes(patch)
    subprocess.run(['git', 'apply', '--check', str(OUT / 'input.patch')], check=True)
    subprocess.run(['git', 'apply', str(OUT / 'input.patch')], check=True)
    subprocess.run([sys.executable, '.continuation/adjust.py'], check=True)
    subprocess.run(['git', 'add', '-N', '--', *PATHS], check=True)
    if not run('format', ['cargo', 'fmt', '--all']):
        raise RuntimeError('Rust formatting failed')
    if not run('format-included-tests', ['rustfmt', '--edition', '2021', 'crates/gateway/src/execution_regression_tests.rs']):
        raise RuntimeError('test formatting failed')
    if not run('gateway', ['cargo', 'test', '-p', 'gateway', '--locked', '--', '--test-threads=1'], tests=True):
        raise RuntimeError('gateway verification failed')
    # The exact same tests must compile on the old program and expose real failures.
    with tempfile.TemporaryDirectory(prefix='dark-perp-red-') as tmp:
        red = Path(tmp)
        archive = subprocess.check_output(['git', 'archive', BASE])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(red, filter='data')
        shutil.copy2(ROOT / 'crates/gateway/src/execution_regression_tests.rs', red / 'crates/gateway/src/execution_regression_tests.rs')
        p = red / 'crates/gateway/src/main.rs'
        s = p.read_text()
        anchor = '    include!("audit_remediation_tests.rs");'
        assert s.count(anchor) == 1
        p.write_text(s.replace(anchor, anchor + '\n    include!("execution_regression_tests.rs");'))
        if not run('baseline-red', ['cargo', 'test', '-p', 'gateway', '--locked', 'execution_regressions', '--', '--test-threads=1'], cwd=red, expected_red=True):
            raise RuntimeError('red control failed to establish the expected baseline defects')
    jobs = [
        ('format-check', ['cargo', 'fmt', '--all', '--check'], ROOT, False),
        ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings'], ROOT, False),
        ('workspace', ['cargo', 'test', '--workspace', '--locked'], ROOT, True),
        ('core-serde', ['cargo', 'test', '-p', 'perp-core', '--features', 'serde', '--locked'], ROOT, True),
        ('core-no-std-serde', ['cargo', 'build', '-p', 'perp-core', '--no-default-features', '--features', 'serde', '--locked'], ROOT, False),
        ('matcher-no-std', ['cargo', 'build', '-p', 'matcher', '--no-default-features', '--locked'], ROOT, False),
        ('frontend-install', ['pnpm', 'install', '--frozen-lockfile'], ROOT / 'frontend', False),
        ('frontend-test', ['pnpm', 'test'], ROOT / 'frontend', False),
        ('frontend-build', ['pnpm', 'build'], ROOT / 'frontend', False),
        ('contracts', ['forge', 'test', '--summary'], ROOT / 'contracts', False),
        ('diff-check', ['git', 'diff', '--check'], ROOT, False),
    ]
    for name, cmd, cwd, tests in jobs:
        run(name, cmd, cwd=cwd, timeout=1500, tests=tests)
    status['all_passed'] = all(x['passed'] for x in status['commands'].values())
    patch = subprocess.check_output(['git', 'diff', '--binary', '--', *PATHS])
    (OUT / 'verified.patch').write_bytes(patch)
    status['verified_patch_sha256'] = hashlib.sha256(patch).hexdigest()
    status['input_patch_sha256'] = PATCH_SHA
    status['changed_paths'] = PATHS
    status['source_blob_ids'] = {p: subprocess.check_output(['git', 'hash-object', p], text=True).strip() for p in PATHS}
    status['toolchains'] = {tool: subprocess.check_output([tool, '--version'], text=True).strip() for tool in ['rustc', 'cargo', 'pnpm', 'node', 'forge']}
    save()
except Exception as e:
    status['error'] = str(e)
    save()
    raise
sys.exit(0 if status['all_passed'] else 1)
