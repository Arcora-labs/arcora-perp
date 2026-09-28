#!/usr/bin/env python3
"""Check the imported archive files and the exact manifest-only patch offline."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
provenance = json.loads((root / 'PROVENANCE.json').read_text())
failures = []
for name, upstream_sha in provenance['upstream_files_sha256'].items():
    data = (root / name).read_bytes()
    if name == 'Cargo.toml':
        # Reconstruct the upstream normalized manifest. This must be the only
        # difference, not just whatever hash somebody records as the patch.
        text = data.decode()
        if text.count('    "rsa/default",\n') != 1:
            failures.append('Cargo.toml: expected one explicit RSA default feature')
        text = text.replace('    "rsa/default",\n', '')
        needle = '    "pki-types/alloc",\n'
        if text.count(needle) != 1:
            failures.append('Cargo.toml: expected one alloc feature list')
        text = text.replace(needle, needle + '    "rsa?/default",\n')
        actual = hashlib.sha256(text.encode()).hexdigest()
    else:
        actual = hashlib.sha256(data).hexdigest()
    if actual != upstream_sha:
        failures.append(name + ': differs from the pinned upstream archive')
expected = set(provenance['upstream_files_sha256']) | {
    'PROVENANCE.json', 'PATCH.md', 'verify_provenance.py'
}
actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
if actual != expected:
    failures.append('unexpected or missing vendor files: ' + repr(actual ^ expected))
print(json.dumps({'upstream_files_checked': len(provenance['upstream_files_sha256']),
                  'unchanged_rust_source_files': sum(n.endswith('.rs') for n in provenance['upstream_files_sha256']),
                  'manifest_patch_only': not failures, 'failures': failures}, indent=2))
raise SystemExit(bool(failures))
