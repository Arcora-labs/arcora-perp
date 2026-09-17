from pathlib import Path
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time

out = Path('/tmp/remediation-evidence')
out.mkdir(exist_ok=True)
jobs = [
    ('rustfmt', ['rustfmt', '--edition', '2021', 'crates/gateway/src/audit_remediation_tests.rs'], '.'),
    ('cargo-fmt', ['cargo', 'fmt', '--all'], '.'),
    ('gateway-regressions', ['cargo', 'test', '-p', 'gateway', '--locked', 'audit_remediation', '--', '--nocapture'], '.'),
    ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings'], '.'),
    ('workspace-tests', ['cargo', 'test', '--workspace', '--locked'], '.'),
    ('serde-tests', ['cargo', 'test', '-p', 'perp-core', '--features', 'serde', '--locked'], '.'),
    ('no-std', ['cargo', 'build', '-p', 'perp-core', '--no-default-features', '--features', 'serde', '--locked'], '.'),
    ('frontend-install', ['pnpm', 'install', '--frozen-lockfile'], 'frontend'),
    ('frontend-tests', ['pnpm', 'test'], 'frontend'),
    ('frontend-build', ['pnpm', 'build'], 'frontend'),
    ('diff-check', ['git', 'diff', '--check'], '.'),
]
results = []
env = os.environ.copy()
env.update(CARGO_TERM_COLOR='never', NO_COLOR='1', CARGO_PROFILE_TEST_OPT_LEVEL='2', CARGO_PROFILE_TEST_DEBUG_ASSERTIONS='true', CARGO_PROFILE_TEST_OVERFLOW_CHECKS='true')
for name, cmd, cwd in jobs:
    print('RUN', name, flush=True)
    started = time.monotonic()
    with (out / (name + '.log')).open('w') as log:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = proc.wait(timeout=600)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            code = 124
    text = (out / (name + '.log')).read_text()
    if name == 'gateway-regressions' and code == 0 and not re.search(r'test result: ok\. 14 passed; 0 failed; 0 ignored;', text):
        code = 125
    results.append({'name': name, 'exit': code, 'seconds': round(time.monotonic() - started, 2)})
    (out / 'progress.json').write_text(json.dumps(results, indent=2))
    print(name, code, flush=True)
    print('\n'.join(text.splitlines()[-35:]), flush=True)
    if code and name in {'rustfmt', 'cargo-fmt', 'gateway-regressions'}:
        break
allowed = {'crates/gateway/src/main.rs', 'crates/gateway/src/snapshot.rs', 'crates/gateway/src/audit_remediation_tests.rs', 'frontend/src/api/realClient.ts', 'frontend/src/api/realClient.test.ts', 'frontend/src/domain/types.ts', 'frontend/src/components/OrderBook.tsx', 'frontend/src/components/OrderBook.unavailable.test.tsx'}
subprocess.run(['git', 'add', '-N', 'crates/gateway/src/audit_remediation_tests.rs', 'frontend/src/components/OrderBook.unavailable.test.tsx'], check=True)
changed = set(subprocess.check_output(['git', 'diff', '--name-only'], text=True).splitlines())
assert changed <= allowed, changed - allowed
patch = subprocess.check_output(['git', 'diff', '--binary'])
(out / 'verified.patch').write_bytes(patch)
passed = len(results) == len(jobs) and all(r['exit'] == 0 for r in results)
status = {'source_commit': os.environ['GITHUB_SHA'], 'test_profile': {'opt_level': 2, 'debug_assertions': True, 'overflow_checks': True}, 'results': results, 'patch_sha256': hashlib.sha256(patch).hexdigest(), 'changed_paths': sorted(changed), 'all_passed': passed}
(out / 'status.json').write_text(json.dumps(status, indent=2))
print(json.dumps(status, indent=2))
sys.exit(0 if passed else 1)
