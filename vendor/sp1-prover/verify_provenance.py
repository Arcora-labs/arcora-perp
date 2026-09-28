#!/usr/bin/env python3
"""Verify the full upstream archive contents and exact one-line manifest patch."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
provenance = json.loads((root / "PROVENANCE.json").read_text())
failures = []
for name, expected_hash in provenance["upstream_files_sha256"].items():
    path = root / name
    if not path.is_file() or path.is_symlink():
        failures.append(name + ": missing or symlinked upstream file")
        continue
    data = path.read_bytes()
    if name == "Cargo.toml":
        patched = b'[dependencies.lru]\nversion = "=0.18.4"'
        upstream = b'[dependencies.lru]\nversion = "0.12.4"'
        if data.count(patched) != 1:
            failures.append("Cargo.toml: expected one exact patched LRU dependency")
        data = data.replace(patched, upstream)
    if hashlib.sha256(data).hexdigest() != expected_hash:
        failures.append(name + ": differs from the pinned upstream archive")

for name, license_info in provenance["upstream_license_files"].items():
    path = root / name
    if not path.is_file() or path.is_symlink():
        failures.append(name + ": missing or symlinked upstream license")
    elif hashlib.sha256(path.read_bytes()).hexdigest() != license_info["sha256"]:
        failures.append(name + ": differs from the pinned upstream license")

expected = set(provenance["upstream_files_sha256"]) | set(provenance["upstream_license_files"]) | {
    "PROVENANCE.json", "PATCH.md", "verify_provenance.py"
}
actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
if actual != expected:
    failures.append("unexpected or missing vendor files: " + repr(actual ^ expected))
print(json.dumps({
    "upstream_files_checked": len(provenance["upstream_files_sha256"]),
    "unchanged_rust_source_files": sum(n.endswith(".rs") for n in provenance["upstream_files_sha256"]),
    "restored_upstream_license_files": len(provenance["upstream_license_files"]),
    "manifest_patch_only": not failures,
    "failures": failures,
}, indent=2))
raise SystemExit(bool(failures))
