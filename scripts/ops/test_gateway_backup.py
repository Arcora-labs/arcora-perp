"""gateway_backup: consistent snapshot/journal pair with the gateway's restore pins."""
import datetime
import hashlib
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import gateway_backup


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def replace_atomically(path, data):
    tmp = Path(str(path) + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def at(minute):
    return datetime.datetime(2026, 10, 16, 12, minute, 0, tzinfo=datetime.timezone.utc)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.live = self.root / "live"
        self.live.mkdir()
        self.state = self.live / "state.snap"
        self.journal = self.live / "state.snap.rollback"
        self.dest = self.root / "backups"
        self.state.write_bytes(b"sealed-snapshot-v1")

    def entries(self):
        return sorted(p.name for p in self.dest.iterdir()) if self.dest.exists() else []


class Pair(Fixture):
    def test_backup_records_restore_pins_for_snapshot_and_journal(self):
        self.journal.write_bytes(b"sealed-journal-v1")
        out = gateway_backup.backup(self.state, self.dest, now=at(0))
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual((out / "state.snap").read_bytes(), b"sealed-snapshot-v1")
        self.assertEqual((out / "state.snap.rollback").read_bytes(), b"sealed-journal-v1")
        self.assertEqual(manifest["restore_env"], {
            "DARKPERP_REQUIRE_RESTORE": "1",
            "DARKPERP_RESTORE_SHA256": sha(self.state),
            "DARKPERP_RESTORE_JOURNAL": sha(self.journal),
        })
        self.assertEqual(manifest["schema"], "arcora.gateway-backup.v1")
        self.assertEqual(manifest["attempts"], 1)

    def test_missing_journal_is_pinned_as_absent(self):
        out = gateway_backup.backup(self.state, self.dest, now=at(0))
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual(manifest["restore_env"]["DARKPERP_RESTORE_JOURNAL"], "absent")
        self.assertFalse((out / "state.snap.rollback").exists())

    def test_missing_snapshot_fails_without_leaving_a_partial_backup(self):
        self.state.unlink()
        with self.assertRaises(gateway_backup.BackupError):
            gateway_backup.backup(self.state, self.dest, now=at(0))
        self.assertEqual(self.entries(), [])

    def test_candidate_archive_mode_is_refused_rather_than_half_copied(self):
        (self.live / "state.snap.chainlink").write_bytes(b"marker")
        with self.assertRaises(gateway_backup.BackupError):
            gateway_backup.backup(self.state, self.dest, now=at(0))
        self.assertEqual(self.entries(), [])


class Consistency(Fixture):
    def test_a_replacement_during_copy_is_retried_and_the_new_pair_pinned(self):
        self.journal.write_bytes(b"sealed-journal-v1")
        calls = []

        def writer_runs_once():
            if not calls:
                replace_atomically(self.state, b"sealed-snapshot-v2")
                replace_atomically(self.journal, b"sealed-journal-v2")
            calls.append(1)

        out = gateway_backup.backup(self.state, self.dest, now=at(0), _during_copy=writer_runs_once)
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual(manifest["attempts"], 2)
        self.assertEqual((out / "state.snap").read_bytes(), b"sealed-snapshot-v2")
        self.assertEqual(manifest["restore_env"]["DARKPERP_RESTORE_SHA256"], sha(self.state))
        self.assertEqual(manifest["restore_env"]["DARKPERP_RESTORE_JOURNAL"], sha(self.journal))

    def test_constant_churn_gives_up_after_the_bound(self):
        counter = [0]

        def writer_always_runs():
            counter[0] += 1
            replace_atomically(self.state, b"v%d" % counter[0])

        with self.assertRaises(gateway_backup.BackupError):
            gateway_backup.backup(self.state, self.dest, now=at(0), max_tries=3,
                                  _during_copy=writer_always_runs, _sleep=lambda _s: None)
        self.assertEqual(counter[0], 3)
        self.assertEqual(self.entries(), [])

    def test_journal_appearing_during_copy_is_not_pinned_absent(self):
        def journal_appears_once():
            if not self.journal.exists():
                self.journal.write_bytes(b"sealed-journal-new")

        out = gateway_backup.backup(self.state, self.dest, now=at(0), _during_copy=journal_appears_once)
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual(manifest["restore_env"]["DARKPERP_RESTORE_JOURNAL"], sha(self.journal))


class Retention(Fixture):
    def test_prune_keeps_the_newest_backups_and_ignores_foreign_entries(self):
        for minute in range(5):
            gateway_backup.backup(self.state, self.dest, now=at(minute))
        (self.dest / "notes.txt").write_text("operator file")
        removed = gateway_backup.prune(self.dest, keep=2)
        self.assertEqual(len(removed), 3)
        self.assertEqual(self.entries(), ["20261016T120300Z", "20261016T120400Z", "notes.txt"])

    def test_same_second_backup_does_not_overwrite(self):
        gateway_backup.backup(self.state, self.dest, now=at(0))
        with self.assertRaises(gateway_backup.BackupError):
            gateway_backup.backup(self.state, self.dest, now=at(0))


class Cli(Fixture):
    def test_main_writes_backup_prunes_and_prints_restore_env(self):
        code = gateway_backup.main(["--state", str(self.state), "--dest", str(self.dest), "--keep", "1"])
        self.assertEqual(code, 0)
        [entry] = self.entries()
        self.assertTrue((self.dest / entry / "manifest.json").is_file())

    def test_main_fails_nonzero_for_missing_state(self):
        self.state.unlink()
        self.assertEqual(gateway_backup.main(["--state", str(self.state), "--dest", str(self.dest)]), 1)

    @unittest.skipUnless(shutil.which("rsync"), "rsync not installed")
    def test_offsite_target_can_come_from_the_service_environment(self):
        offsite = self.root / "offsite-env"
        offsite.mkdir()
        with unittest.mock.patch.dict(os.environ, {"DARKPERP_BACKUP_OFFSITE": str(offsite) + "/"}):
            code = gateway_backup.main(["--state", str(self.state), "--dest", str(self.dest)])
        self.assertEqual(code, 0)
        self.assertEqual(len(list(offsite.iterdir())), 1)

    def test_empty_offsite_environment_means_local_only(self):
        with unittest.mock.patch.dict(os.environ, {"DARKPERP_BACKUP_OFFSITE": ""}):
            code = gateway_backup.main(["--state", str(self.state), "--dest", str(self.dest)])
        self.assertEqual(code, 0)

    @unittest.skipUnless(shutil.which("rsync"), "rsync not installed")
    def test_offsite_copy_with_rsync_to_a_local_target(self):
        offsite = self.root / "offsite"
        offsite.mkdir()
        code = gateway_backup.main([
            "--state", str(self.state), "--dest", str(self.dest), "--offsite", str(offsite) + "/",
        ])
        self.assertEqual(code, 0)
        [entry] = self.entries()
        self.assertEqual((offsite / entry / "state.snap").read_bytes(), b"sealed-snapshot-v1")


if __name__ == "__main__":
    unittest.main()
