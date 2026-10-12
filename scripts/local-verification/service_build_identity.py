#!/usr/bin/env python3
"""Embed a checksum of the covered public source map at build-helper time.

This is self-reported local provenance, not compiler or process attestation.
Only the candidate identity tool's existing public inventory is read. There is
no Git, process-configuration, credential, RPC, setup or proving operation.
"""
import argparse
import os
from pathlib import Path
import re
import sys
import tempfile

import candidate_identity_manifest as identity

SCHEMA = "arcora-service-build-identity/v1"
ALGORITHM = "sha256-canonical-source-map-v1"
OUTPUT_NAME = "service-build-identity.json"
EXCLUDED_PARTS = {"target", "out", "node_modules", "__pycache__", ".git"}


def require(ok, label):
    if not ok:
        raise ValueError(label)


def public_name(name):
    return (isinstance(name, str) and bool(name)
            and not Path(name).is_absolute() and ".." not in Path(name).parts
            and not any(c in name for c in "\r\n\\")
            and not identity.prohibited_public_path(name)
            and not any(part in EXCLUDED_PARTS for part in Path(name).parts))


def build_identity(root):
    root = Path(root)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(),
            "canonical source root required")
    require(root.resolve() == root, "canonical source root required")
    sources = identity.source_inventory(root)
    require(isinstance(sources, dict) and 0 < len(sources) <= identity.MAX_SOURCE_FILES,
            "bounded public source map required")
    require(all(public_name(name) and isinstance(sha, str)
                and re.fullmatch(r"[0-9a-f]{64}", sha) for name, sha in sources.items()),
            "invalid public source map")
    result = {"schema": SCHEMA, "algorithm": ALGORITHM,
              "source_files": len(sources),
              "source_sha256": identity.digest(identity.canonical(sources))}
    return result, sources


def rerun_paths(root, sources):
    """Exact public files plus safe existing source directories.

    Cargo directory watches are recursive and cannot filter descendants. Avoid
    broad crate/vendor roots and any directory containing excluded entries.
    New package layouts outside these existing directories require an explicit
    rebuild. A current-source comparison must refuse stale embedded checksums.
    """
    root = Path(root)
    selected = set(sources)
    candidates = {Path(name).parent.as_posix() for name in sources
                  if "/" in name and Path(name).parent.as_posix() not in {
                      "crates", "vendor", "contracts", "scripts"}}
    for name in sorted(candidates):
        directory = root / name
        require(public_name(name) and directory.is_dir() and not directory.is_symlink(),
                "invalid public source directory")
        # Metadata checks only; no excluded file is opened or hashed.
        if any(not public_name(path.relative_to(root).as_posix())
               or path.is_symlink() for path in directory.rglob("*")):
            continue
        selected.add(name)
    return [root / name for name in sorted(selected)]


def write_identity(root, output, value):
    output = Path(output)
    require(output.is_absolute() and output.name == OUTPUT_NAME,
            "build output pathname required")
    require(output.parent.is_dir() and output.parent.resolve() == output.parent
            and not output.is_symlink() and (not output.exists() or output.is_file()),
            "regular build output required")
    try:
        relative = output.relative_to(root).as_posix()
    except ValueError:
        relative = None
    require(relative is None or not public_name(relative),
            "build output must be outside covered public inputs")
    data = identity.canonical(value)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".service-build-",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("invalid service build arguments")


def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--root", required=True, type=Path)
        parser.add_argument("--output", required=True, type=Path)
        args = parser.parse_args(argv)
        value, sources = build_identity(args.root)
        watches = rerun_paths(args.root, sources)
        write_identity(args.root, args.output, value)
        for path in watches:
            print("cargo:rerun-if-changed=" + str(path))
        return 0
    except (ValueError, OSError):
        print("service build identity generation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
