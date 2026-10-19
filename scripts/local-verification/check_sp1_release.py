#!/usr/bin/env python3
"""Reject affected or mixed SP1 releases before building release evidence.

GHSA-63x8-x938-vx33 identifies 6.1.0 as patched. Pin the reviewed release
including transitive SP1/slop crates: top-level exact pins alone allow Cargo to
resolve a newer, incompatible release family. Every locked package must come
from crates.io with a checksum or be a local path package; the guest's single
exception is the commit-pinned tiny-keccak precompile patch (GUEST_GIT_DEPENDENCY).
This is a version/identity guard, not proof verification or a complete
vulnerability audit.
"""
import hashlib
import json
from pathlib import Path
import sys
import tomllib

RELEASE = "6.1.0"
LRU_RELEASE = "0.18.4"
LRU_CHECKSUM = "ff9840bcc50b71349309900da0ce7279aa336ae71d73250b07998932c7d97c25"
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
# The reviewed guest's only dependency that does not come from crates.io:
# Succinct's patch of tiny-keccak 2.0.2 (tag patch-2.0.2-sp1-6.0.0, the one for
# SP1 >= 6.0.0 and < 6.2). On the zkVM target it runs keccak-f through the
# KECCAK_PERMUTE syscall (sp1-lib); the host code path is unchanged. It is
# accepted from this repository URL at this commit only, through the guest's
# [patch.crates-io] table, and its checked-out files must hash to
# `source_tree_sha256` (sha256 of the sorted {path: sha256} map of every file
# outside `.git`, without Cargo's `.cargo-ok` marker; no symlinks).
GUEST_GIT_DEPENDENCY = {
    "name": "tiny-keccak",
    "version": "2.0.2",
    "repository": "https://github.com/sp1-patches/tiny-keccak",
    "commit": "957430a459f7a2332ab5bab4a12f9b473bb95c87",
    "tag": "patch-2.0.2-sp1-6.0.0",
    "files": 33,
    "source_tree_sha256": "6bff63bc9c6a4cc1405d13a824992d3a4485f9b810bda9fe817571710af20b9d",
}
GUEST_GIT_SOURCE = "git+{repository}?rev={commit}#{commit}".format(**GUEST_GIT_DEPENDENCY)
GUEST_PATCH = {"crates-io": {GUEST_GIT_DEPENDENCY["name"]: {
    "git": GUEST_GIT_DEPENDENCY["repository"], "rev": GUEST_GIT_DEPENDENCY["commit"]}}}
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


def source_errors(directory, manifest, lock):
    """Every locked package comes from crates.io with a checksum, or is a local
    path package; the guest's one exception is the exact tiny-keccak git pin."""
    errors = []
    guest = directory == "crates/sp1-guest"
    if guest and manifest.get("patch") != GUEST_PATCH:
        errors.append(f"{directory}: exact reviewed tiny-keccak git patch required")
    git = []
    for p in lock.get("package", []):
        if "source" not in p:
            continue
        if p["source"].startswith("git+"):
            git.append(p)
            if not (guest and p["name"] == GUEST_GIT_DEPENDENCY["name"]
                    and p["version"] == GUEST_GIT_DEPENDENCY["version"]
                    and p["source"] == GUEST_GIT_SOURCE and "checksum" not in p):
                errors.append(f"{directory}: unreviewed git dependency {p['name']} {p['version']}")
            continue
        if p["source"] != REGISTRY_SOURCE:
            errors.append(f"{directory}: unreviewed dependency source for {p['name']} {p['version']}")
        elif len(p.get("checksum", "")) != 64:
            errors.append(f"{directory}: missing registry checksum for {p['name']}")
    if guest:
        keccak = [p for p in lock.get("package", []) if p["name"] == GUEST_GIT_DEPENDENCY["name"]]
        if len(git) != 1 or len(keccak) != 1 or keccak[0].get("source") != GUEST_GIT_SOURCE:
            errors.append(f"{directory}: exactly one tiny-keccak, from the reviewed git pin, required")
    return errors


def guest_dependency_errors(root=ROOT):
    """The guest manifest and lock source policy alone (for the rebuild recipes)."""
    directory = "crates/sp1-guest"
    try:
        manifest = tomllib.loads((root / directory / "Cargo.toml").read_text())
        lock = tomllib.loads((root / directory / "Cargo.lock").read_text())
        return source_errors(directory, manifest, lock)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        return [f"{directory}: unreadable dependency metadata ({type(error).__name__})"]


def upstream_audit_lock(root=ROOT):
    """The guest lock with the reviewed git patch under its upstream crates.io
    identity (same name and version, no checksum). `cargo audit` matches only
    crates.io packages against advisories, so auditing this copy as well keeps
    the advisories of upstream tiny-keccak 2.0.2 in scope for the patch."""
    errors = guest_dependency_errors(root)
    if errors:
        raise ValueError("; ".join(errors))
    text = (root / "crates/sp1-guest/Cargo.lock").read_text()
    old = f'source = "{GUEST_GIT_SOURCE}"\n'
    if text.count(old) != 1:
        raise ValueError("crates/sp1-guest: the reviewed git source must appear exactly once")
    return text.replace(old, f'source = "{REGISTRY_SOURCE}"\n')


def check(root=ROOT):
    errors, counts = vendor_errors(root), {}
    for directory, sections in APPLICATIONS.items():
        try:
            manifest = tomllib.loads((root / directory / "Cargo.toml").read_text())
            lock = tomllib.loads((root / directory / "Cargo.lock").read_text())
            errors.extend(source_errors(directory, manifest, lock))
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
                if len(lru) != 1 or lru[0].get("version") != LRU_RELEASE or lru[0].get("checksum") != LRU_CHECKSUM or lru[0].get("source") != REGISTRY_SOURCE:
                    errors.append(f"{directory}: exact patched LRU lock required")
            for p in family:
                # The only non-registry exception is the checked manifest-only patch.
                if p["name"] == "sp1-prover" and directory != "crates/sp1-guest":
                    if p["version"] != RELEASE or "source" in p or "checksum" in p:
                        errors.append(f"{directory}: unreviewed local sp1-prover identity")
                    continue
                if p["version"] != RELEASE or p.get("source") != REGISTRY_SOURCE:
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
        "guest_git_dependency": dict(GUEST_GIT_DEPENDENCY),
        "advisory": "https://github.com/succinctlabs/sp1/security/advisories/GHSA-63x8-x938-vx33",
        "family_packages_checked": counts,
        "passed": not errors,
        "errors": errors,
        "scope": "Manifest and lock identity only; guest execution, proof and target verifier require separate evidence.",
    }


def main(argv):
    if argv[:1] == ["--upstream-audit-lock"] and len(argv) == 2:
        # Exclusive: never overwrite an existing file.
        with Path(argv[1]).open("x") as stream:
            stream.write(upstream_audit_lock())
        return 0
    if argv:
        print("usage: check_sp1_release.py [--upstream-audit-lock NEW_PATH]", file=sys.stderr)
        return 2
    result = check()
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
