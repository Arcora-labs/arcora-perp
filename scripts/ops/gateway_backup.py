#!/usr/bin/env python3
"""Back up a running gateway's sealed snapshot and rollback journal as one pair.

The gateway replaces `DARKPERP_STATE` and `<state>.rollback` only by atomic
rename (snapshot.rs `write_atomic`), so a file whose (dev, inode, size,
mtime_ns) identity is the same before and after copying was not replaced
in between. When both identities hold across the copy, the two copies
coexisted on disk and form a pair the boot recovery table accepts; otherwise
the attempt is discarded and retried. The gateway is never stopped.

Both files are sealed under ENCLAVE_SEED; this tool never reads secrets. The
manifest carries the exact restore pins the gateway checks at boot
(DARKPERP_RESTORE_SHA256 / DARKPERP_RESTORE_JOURNAL). Candidate archive mode
(`<state>.chainlink`) is refused instead of producing a partial backup.

    gateway_backup.py --state /var/lib/darkperp/state.snap \
        --dest /var/backups/darkperp --keep 96 [--offsite user@host:/srv/darkperp-backups/]
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCHEMA = "arcora.gateway-backup.v1"
NAME = re.compile(r"[0-9]{8}T[0-9]{6}Z")


class BackupError(Exception):
    pass


def _identity(path):
    try:
        st = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not os.path.isfile(path) or os.path.islink(path):
        raise BackupError(f"{path.name} must be a regular file")
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _copy(source, target):
    digest = hashlib.sha256()
    size = 0
    with open(source, "rb") as reader, open(target, "xb") as writer:
        os.fchmod(writer.fileno(), 0o600)
        for block in iter(lambda: reader.read(1 << 20), b""):
            digest.update(block)
            writer.write(block)
            size += len(block)
        writer.flush()
        os.fsync(writer.fileno())
    return {"file": target.name, "bytes": size, "sha256": digest.hexdigest()}


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def backup(state, dest, now=None, max_tries=5, _during_copy=None, _sleep=time.sleep):
    """Return the finished backup directory or raise BackupError."""
    state = Path(state)
    journal = Path(str(state) + ".rollback")
    if Path(str(state) + ".chainlink").exists():
        raise BackupError("candidate archive mode is not covered by this backup; refusing")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    final = Path(dest) / now.strftime("%Y%m%dT%H%M%SZ")
    if final.exists():
        raise BackupError(f"backup {final.name} already exists")
    Path(dest).mkdir(parents=True, exist_ok=True)

    for attempt in range(1, max_tries + 1):
        partial = Path(tempfile.mkdtemp(prefix=".partial-", dir=dest))
        try:
            before = (_identity(state), _identity(journal))
            if before[0] is None:
                raise BackupError("snapshot file is missing")
            snapshot = _copy(state, partial / state.name)
            journal_copy = _copy(journal, partial / journal.name) if before[1] else None
            if _during_copy:
                _during_copy()
            after = (_identity(state), _identity(journal))
            if after != before:
                shutil.rmtree(partial)
                _sleep(0.2 * attempt)
                continue
            manifest = {
                "schema": SCHEMA,
                "created_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "attempts": attempt,
                "snapshot": snapshot,
                "journal": journal_copy or "absent",
                "restore_env": {
                    "DARKPERP_REQUIRE_RESTORE": "1",
                    "DARKPERP_RESTORE_SHA256": snapshot["sha256"],
                    "DARKPERP_RESTORE_JOURNAL": journal_copy["sha256"] if journal_copy else "absent",
                },
            }
            with open(partial / "manifest.json", "x") as stream:
                json.dump(manifest, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_dir(partial)
            os.rename(partial, final)
            _fsync_dir(dest)
            return final
        except BaseException:
            shutil.rmtree(partial, ignore_errors=True)
            raise
    raise BackupError(f"snapshot/journal kept changing for {max_tries} attempts")


def prune(dest, keep):
    """Remove all but the newest `keep` backups this tool wrote; return removed names."""
    ours = sorted(
        p.name for p in Path(dest).iterdir()
        if p.is_dir() and NAME.fullmatch(p.name) and (p / "manifest.json").is_file()
    )
    removed = ours[:-keep] if keep > 0 else ours
    for name in removed:
        shutil.rmtree(Path(dest) / name)
    return removed


def build_parser():
    parser = argparse.ArgumentParser(description="Back up the gateway snapshot/journal pair.")
    parser.add_argument("--state", required=True, type=Path, help="DARKPERP_STATE path")
    parser.add_argument("--dest", required=True, type=Path, help="local backup directory")
    parser.add_argument("--keep", type=int, default=96, help="newest backups to keep (default 96)")
    parser.add_argument("--max-tries", type=int, default=5)
    parser.add_argument(
        "--offsite",
        default=os.environ.get("DARKPERP_BACKUP_OFFSITE") or None,
        help="rsync destination for the new backup, e.g. host:/srv/backups/ (default: $DARKPERP_BACKUP_OFFSITE)",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        final = backup(args.state, args.dest, max_tries=args.max_tries)
    except (BackupError, OSError) as error:
        print(f"[backup] FAILED: {error}", file=sys.stderr)
        return 1
    manifest = json.loads((final / "manifest.json").read_text())
    print(json.dumps({"backup": str(final), "restore_env": manifest["restore_env"]}, sort_keys=True))
    prune(args.dest, args.keep)
    if args.offsite:
        result = subprocess.run(["rsync", "-a", "--", str(final), args.offsite], check=False)
        if result.returncode != 0:
            print(f"[backup] offsite copy FAILED (rsync exit {result.returncode}); local backup kept", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
