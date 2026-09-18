"""Verify A04 on an isolated checkout. No production credentials or chain calls."""
from __future__ import annotations
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path.cwd()
OUT = ROOT / 'a04-evidence'
OUT.mkdir(exist_ok=True)
REPORT = {'base_main': '48e03ac3db123cdf159c10f1e0c86262043a377e',
          'workflow_head': os.environ.get('GITHUB_SHA'),
          'run_id': os.environ.get('GITHUB_RUN_ID'),
          'complete': False, 'all_passed': False, 'commands': [],
          'test_profile': {'opt_level': 2, 'debug_assertions': True, 'overflow_checks': True},
          'real_sp1_proof': False, 'live_tee': False, 'live_payments': False}
ENV = {k: v for k, v in os.environ.items()
       if not k.startswith(('DARKPERP_', 'ENCLAVE_', 'ORACLE_', 'ATTESTATION_', 'L1_',
                            'PROVER_', 'FIN_', 'INSURANCE_', 'VITE_'))
       and k not in ('DEV_INSECURE', 'GATEWAY_URL', 'PORT', 'GATEWAY_SIGNER_KEY',
                     'GITHUB_TOKEN', 'GH_TOKEN')}
ENV.update(CARGO_PROFILE_TEST_OPT_LEVEL='2', CARGO_PROFILE_TEST_DEBUG_ASSERTIONS='true',
           CARGO_PROFILE_TEST_OVERFLOW_CHECKS='true', CARGO_TERM_COLOR='never', NO_COLOR='1')

def save() -> None:
    (OUT / 'status.json').write_text(json.dumps(REPORT, indent=2) + '\n')

def run(name: str, args: list[str], cwd: Path = ROOT, negative: bool = False) -> str:
    print('RUN', name, flush=True)
    entry = {'name': name, 'command': args, 'exit_code': None, 'expected_failure': negative}
    try:
        with (OUT / f'{name}.log').open('w') as log:
            result = subprocess.run(args, cwd=cwd, env=ENV, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=1500)
        entry['exit_code'] = result.returncode
    except subprocess.TimeoutExpired:
        entry['timed_out'] = True
    REPORT['commands'].append(entry)
    save()
    text = (OUT / f'{name}.log').read_text()
    valid = (entry['exit_code'] == 101 and 'test result: FAILED. 0 passed; 1 failed;' in text
             if negative else entry['exit_code'] == 0)
    if not valid:
        print(text[-12000:], flush=True)
        raise RuntimeError(f'{name}: command did not produce its required result')
    return text

save()
try:
    run('format', ['cargo', 'fmt', '--all'])
    formatted = Path('crates/gateway/src/main.rs').read_text()
    assert len(re.findall(r'(?m)^        let cancelled\b', formatted)) == 1, 'cancel mutation anchor missing'
    assert len(re.findall(r'o\.sealed\s*&&\s*o\.last_finality == "SETTLED"\s*&&\s*!live\.contains\(&o\.order_hash\)', formatted)) == 1, 'history mutation anchor missing'
    run('gateway-a04', ['cargo', 'test', '--locked', '-p', 'gateway', 'audit_cancellation'])
    run('sequencer-a04', ['cargo', 'test', '--locked', '-p', 'sequencer', 'cancellation'])
    run('workspace', ['cargo', 'test', '--workspace', '--locked'])
    run('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings'])
    run('serde', ['cargo', 'test', '-p', 'perp-core', '--features', 'serde', '--locked'])
    run('no-std-core', ['cargo', 'build', '-p', 'perp-core', '--no-default-features', '--features', 'serde', '--locked'])
    run('no-std-matcher', ['cargo', 'build', '-p', 'matcher', '--no-default-features', '--locked'])
    run('frontend-install', ['pnpm', 'install', '--frozen-lockfile'], ROOT / 'frontend')
    run('frontend-tests', ['pnpm', 'test'], ROOT / 'frontend')
    run('frontend-build', ['pnpm', 'build'], ROOT / 'frontend')

    source = ROOT / 'crates/gateway/src/main.rs'
    good = source.read_bytes()
    text = good.decode()
    refusal = r'(?m)^        let cancelled\b'
    history = r'o\.sealed\s*&&\s*o\.last_finality == "SETTLED"\s*&&\s*!live\.contains\(&o\.order_hash\)'
    assert len(re.findall(refusal, text)) == len(re.findall(history, text)) == 1
    mutants = [
        ('negative-sealed', re.sub(refusal, lambda m: '        if submitted { return Err("legacy sealed-order refusal".into()); }\n' + m[0], text),
         'sealed_resting_order_cancels_and_appears_in_the_window_manifest'),
        ('negative-history', re.sub(history, 'o.last_finality == "SETTLED"', text),
         'settled_partial_maker_survives_history_pruning_and_remains_cancellable'),
    ]
    for name, mutant, test in mutants:
        try:
            source.write_text(mutant)
            run(name, ['cargo', 'test', '--locked', '-p', 'gateway',
                       f'tests::audit_cancellation::{test}', '--', '--exact'], negative=True)
        finally:
            source.write_bytes(good)
        assert source.read_bytes() == good
    run('gateway-restored', ['cargo', 'test', '--locked', '-p', 'gateway', 'audit_cancellation'])
    run('format-check', ['cargo', 'fmt', '--all', '--check'])
    run('diff-check', ['git', 'diff', '--check', 'HEAD'])

    for name in ('gateway-a04', 'gateway-restored', 'sequencer-a04', 'workspace', 'serde'):
        text = (OUT / f'{name}.log').read_text()
        results = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
        counts = [sum(int(row[i]) for row in results) for i in range(3)]
        assert counts[0] > 0 and counts[1:] == [0, 0], (name, counts)
        REPORT[name] = dict(zip(('passed', 'failed', 'ignored'), counts))
    assert REPORT['gateway-a04']['passed'] == REPORT['gateway-restored']['passed'] == 11
    assert REPORT['sequencer-a04']['passed'] == 10 and REPORT['workspace']['passed'] >= 630
    text = re.sub(r'\x1b\[[0-9;]*m', '', (OUT / 'frontend-tests.log').read_text())
    match = re.search(r'Tests\s+(\d+) passed(?:\s*\|\s*(\d+) skipped)?', text)
    assert match and int(match[1]) >= 270
    REPORT['frontend'] = {'passed': int(match[1]), 'skipped': int(match[2] or 0)}
    REPORT['negative_controls'] = {'legacy_sealed_refusal': 'one executed test failed as expected',
                                   'legacy_history_pruning': 'one executed test failed as expected'}
    allowed = set(json.loads(Path('.remediation-a04/allowed.json').read_text()))
    changed = set(subprocess.check_output(['git', 'diff', 'HEAD', '--name-only'], text=True).splitlines())
    assert changed == allowed, (changed - allowed, allowed - changed)
    patch = subprocess.check_output(['git', 'diff', 'HEAD', '--binary', '--full-index', '--', *sorted(allowed)])
    (OUT / 'verified.patch').write_bytes(patch)
    REPORT['verified_patch_sha256'] = hashlib.sha256(patch).hexdigest()
    REPORT['source_files'] = {path: {'git_blob': subprocess.check_output(['git', 'hash-object', path], text=True).strip(),
                                    'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}
                              for path in sorted(allowed)}
    REPORT.update(complete=True, all_passed=True, finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
except BaseException as exc:
    REPORT['error'] = f'{type(exc).__name__}: {exc}'
    save()
    raise
save()
print(json.dumps(REPORT, indent=2))
