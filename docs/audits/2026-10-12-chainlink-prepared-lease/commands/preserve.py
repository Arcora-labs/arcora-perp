import datetime, hashlib, json, subprocess, sys
from pathlib import Path

ROOT = Path.cwd()
OUT = ROOT / 'target/prepared-lease-validation-20261012'
b = json.loads((OUT / 'baseline.json').read_text())
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
changed = [p for p, digest in b['frozen_sha256'].items()
           if not (ROOT / p).is_file() or sha(ROOT / p) != digest]
allowed = {b['allowed_existing_protocol_edit'].split(':', 1)[0], *b['allowed_metadata_and_test_wires']}
unexpected = [p for p in changed if p not in allowed]
external = []
for e in b['external']:
    p = Path(e['path'])
    status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=p, text=True)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=p, text=True).strip()
    staged = hashlib.sha256(subprocess.check_output(['git', 'diff', '--cached', '--binary'], cwd=p)).hexdigest()
    dirty = [f for f, digest in e['dirty_file_sha256'].items()
             if not (p / f).is_file() or sha(p / f) != digest]
    external.append({'name': e['name'], 'path': str(p), 'head': head,
                     'dirty_count': len(status.splitlines()), 'same_status': status == e['status'],
                     'same_head': head == e['head'], 'same_staged_diff': staged == e['staged_binary_diff_sha256'],
                     'dirty_files_changed': dirty,
                     'passed': status == e['status'] and head == e['head'] and staged == e['staged_binary_diff_sha256'] and not dirty})
main = (ROOT / 'crates/gateway/src/main.rs').read_text()
old = subprocess.check_output(['git', 'show', b['base_main'] + ':crates/gateway/src/main.rs'], text=True)
for module in ['candidate_preparation', 'candidate_preparation_lock_tests', 'candidate_preparation_store', 'candidate_preparation_tests']:
    main = main.replace('#[cfg(test)]\nmod ' + module + ';\n', '')
old_ci = subprocess.check_output(['git', 'show', b['base_main'] + ':.github/workflows/ci.yml'])
r = {'schema': 'arcora-prepared-lease-preservation-v1',
     'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
     'base_main': b['base_main'], 'base_tree': b['base_tree'],
     'frozen_file_count': len(b['frozen_sha256']),
     'unchanged_frozen_file_count': len(b['frozen_sha256']) - len(changed),
     'changed_frozen_files': changed,
     'allowed_existing_protocol_edit': b['allowed_existing_protocol_edit'],
     'unexpected_changed_frozen_files': unexpected, 'external': external,
     'production_main_unchanged_after_removing_test_wires': main == old,
     'ci_workflow_byte_exact': (ROOT / '.github/workflows/ci.yml').read_bytes() == old_ci}
r['passed'] = not unexpected and all(e['passed'] for e in external) and main == old and r['ci_workflow_byte_exact']
path = OUT / (sys.argv[1] + '.json')
assert not path.exists(), 'fresh preservation receipt required'
path.write_text(json.dumps(r, indent=2) + '\n')
print(json.dumps(r))
assert r['passed']
