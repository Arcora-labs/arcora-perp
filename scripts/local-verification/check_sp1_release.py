#!/usr/bin/env python3
"""Reject affected or mixed SP1 releases before building release evidence.

GHSA-63x8-x938-vx33 identifies 6.1.0 as patched. Pin the reviewed release
including transitive SP1/slop crates: top-level exact pins alone allow Cargo to
resolve a newer, incompatible release family. This is a version/identity guard,
not proof verification or a complete vulnerability audit.
"""
import hashlib
import json
from pathlib import Path
import sys
import tomllib

RELEASE = "6.1.0"
LRU_RELEASE = "0.18.4"
LRU_CHECKSUM = "ff9840bcc50b71349309900da0ce7279aa336ae71d73250b07998932c7d97c25"
# Binds the exact reviewed upstream file map, rather than trusting an edited map.
VENDOR_PROVENANCE_SHA256 = "e6f54c8692277d6bb7896cebb106d87fe9910e5cf00603ed894e835237f0c857"
ROOT = Path(__file__).resolve().parents[2]
APPLICATIONS = {
    "crates/sp1-guest": {"dependencies": ("sp1-zkvm",)},
    "crates/sp1-host": {
        "dependencies": ("sp1-sdk",), "build-dependencies": ("sp1-build",)
    },
    "crates/prover-service": {
        "dependencies": ("sp1-sdk",), "build-dependencies": ("sp1-build",)
    },
}


def vendor_errors(root):
    vendor = root / "vendor/sp1-prover"
    errors = []
    try:
        raw = (vendor / "PROVENANCE.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != VENDOR_PROVENANCE_SHA256:
            return ["sp1-prover: unreviewed provenance manifest"]
        provenance = json.loads(raw)
        for name, expected in provenance["upstream_files_sha256"].items():
            path = vendor / name
            if path.is_symlink() or not path.is_file():
                errors.append(f"sp1-prover: missing or symlinked {name}")
                continue
            data = path.read_bytes()
            if name == "Cargo.toml":
                expected = provenance["modified_files"][name]["sha256"]
            if hashlib.sha256(data).hexdigest() != expected:
                errors.append(f"sp1-prover: modified {name}")
        for name, info in provenance["upstream_license_files"].items():
            path = vendor / name
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != info["sha256"]:
                errors.append(f"sp1-prover: missing/modified upstream license {name}")
        expected_names = set(provenance["upstream_files_sha256"]) | set(provenance["upstream_license_files"]) | {
            "PROVENANCE.json", "PATCH.md", "verify_provenance.py"
        }
        actual_names = {p.relative_to(vendor).as_posix() for p in vendor.rglob("*") if p.is_file()}
        if expected_names != actual_names:
            errors.append("sp1-prover: unexpected or missing vendor files")
    except (OSError, ValueError, KeyError, TypeError):
        errors.append("sp1-prover: unreadable vendor provenance")
    return errors


def check(root=ROOT):
    errors, counts = vendor_errors(root), {}
    for directory, sections in APPLICATIONS.items():
        try:
            manifest = tomllib.loads((root / directory / "Cargo.toml").read_text())
            lock = tomllib.loads((root / directory / "Cargo.lock").read_text())
            required = set()
            for section, names in sections.items():
                for name in names:
                    required.add(name)
                    spec = manifest.get(section, {}).get(name)
                    version = spec.get("version") if isinstance(spec, dict) else spec
                    if version != "=" + RELEASE:
                        errors.append(f"{directory}: {name} must pin ={RELEASE}")
                    if isinstance(spec, dict) and any(k in spec for k in ("path", "git", "registry")):
                        errors.append(f"{directory}: {name} must use the reviewed crates.io release")
            family = [p for p in lock.get("package", [])
                      if p["name"].startswith(("sp1-", "slop-")) and p["name"] != "sp1-host"]
            if directory != "crates/sp1-guest":
                required.add("sp1-prover")
                patch = manifest.get("patch", {}).get("crates-io", {}).get("sp1-prover")
                if patch != {"path": "../../vendor/sp1-prover"}:
                    errors.append(f"{directory}: exact reviewed sp1-prover path patch required")
                lru = [p for p in lock.get("package", []) if p["name"] == "lru"]
                if len(lru) != 1 or lru[0].get("version") != LRU_RELEASE or lru[0].get("checksum") != LRU_CHECKSUM or lru[0].get("source") != "registry+https://github.com/rust-lang/crates.io-index":
                    errors.append(f"{directory}: exact patched LRU lock required")
            for p in family:
                # The only non-registry exception is the checked manifest-only patch.
                if p["name"] == "sp1-prover" and directory != "crates/sp1-guest":
                    if p["version"] != RELEASE or "source" in p or "checksum" in p:
                        errors.append(f"{directory}: unreviewed local sp1-prover identity")
                    continue
                if p["version"] != RELEASE or p.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
                    errors.append(f"{directory}: unreviewed {p['name']} {p['version']}")
                if len(p.get("checksum", "")) != 64:
                    errors.append(f"{directory}: missing registry checksum for {p['name']}")
            missing = required - {p["name"] for p in family}
            if missing:
                errors.append(f"{directory}: missing locked packages {sorted(missing)}")
            counts[directory] = len(family)
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(f"{directory}: unreadable release metadata ({type(error).__name__})")
    return {
        "reviewed_sp1_release": RELEASE,
        "reviewed_lru_release": LRU_RELEASE,
        "advisory": "https://github.com/succinctlabs/sp1/security/advisories/GHSA-63x8-x938-vx33",
        "family_packages_checked": counts,
        "passed": not errors,
        "errors": errors,
        "scope": "Manifest and lock identity only; guest execution, proof and target verifier require separate evidence.",
    }


if __name__ == "__main__":
    result = check()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["passed"] else 1)
