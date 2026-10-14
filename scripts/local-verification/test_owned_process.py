"""Actual POSIX children exercise supervision without Cargo, networks or keys."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import owned_process as owned

CHILD = r'''
import os, pathlib, signal, sys, time
if sys.argv[2] == 'ignore':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(30)
'''
PARENT = r'''
import json, os, pathlib, signal, subprocess, sys, time
root = pathlib.Path(sys.argv[1]); mode = sys.argv[2]
if mode == 'ignore':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([sys.executable, '-S', '-c', sys.argv[3], str(root/'child.pid'), mode])
while not (root/'child.pid').exists():
    time.sleep(.01)
(root/'ready.json').write_text(json.dumps({'parent':os.getpid(), 'child':child.pid, 'pgid':os.getpgrp()}))
if mode == 'leave':
    sys.exit(0)
if mode == 'graceful':
    def stop(_sig, _frame):
        child.wait(timeout=3)
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
(root/'handler-ready').write_text('ready')
time.sleep(30)
'''


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'wait4'), 'POSIX required')
class OwnedProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.real_popen = subprocess.Popen
        self.real_wait4 = os.wait4
        self.previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

    def tearDown(self):
        # Explicit fallback contains failed test runs, never a name-based kill.
        path = self.root/'ready.json'
        if path.exists():
            pgid = json.loads(path.read_text())['pgid']
            if pgid > 1 and pgid != os.getpgrp():
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        for sig, handler in self.previous.items():
            self.assertEqual(signal.getsignal(sig), handler)
        self.temp.cleanup()

    def run_capture(self, argv, **options):
        with (self.root/'stdout').open('wb') as stdout, (self.root/'stderr').open('wb') as stderr:
            return owned.supervise(argv, cwd=self.root, stdout=stdout, stderr=stderr,
                                   timeout=options.pop('timeout', 5),
                                   term_grace=.15, kill_grace=.3, **options)

    def parent(self, mode):
        return [sys.executable, '-S', '-c', PARENT, str(self.root), mode, CHILD]

    def await_ready(self, handler=True):
        marker = self.root/('handler-ready' if handler else 'ready.json')
        end = time.monotonic() + 5
        while not marker.exists():
            if time.monotonic() >= end:
                raise AssertionError('owned fixture did not become ready')
            time.sleep(.01)

    def spawn_ready(self, *args, **kwargs):
        p = self.real_popen(*args, **kwargs)
        try:
            self.await_ready()
            return p
        except BaseException:
            # A broken fixture must not lose the PID before supervise owns it.
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait(timeout=3)
            raise

    def stopped(self, pid):
        # An adopted zombie cannot execute. Reaping it belongs to the OS's init,
        # not wait4 of a non-child; Linux containers need not reap it promptly.
        end = time.monotonic() + 3
        while time.monotonic() < end:
            if sys.platform.startswith('linux'):
                p = Path(f'/proc/{pid}/stat')
                try:
                    stat = p.read_text().rsplit(')', 1)[1].split()[0]
                except FileNotFoundError:
                    return
            else:
                result = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)],
                                        capture_output=True, text=True, timeout=2)
                stat = result.stdout.strip()
                if not stat:
                    return
            if stat.startswith('Z'):
                return
            time.sleep(.02)
        self.fail(f'owned fixture {pid} is still executing')

    def assert_tree_stopped(self):
        pids = json.loads((self.root/'ready.json').read_text())
        self.assertNotEqual(pids['pgid'], os.getpgrp())
        for key in ('parent', 'child'):
            self.stopped(pids[key])

    def test_success_and_nonzero_preserve_actual_status_and_usage(self):
        for code in (0, 7):
            with self.subTest(code=code):
                result = self.run_capture([sys.executable, '-S', '-c', f'print("ok");raise SystemExit({code})'])
                m = result.metadata
                self.assertEqual(m['exit_code'], code)
                self.assertEqual(m['success'], code == 0)
                self.assertTrue(m['leader_reaped'])
                self.assertTrue(m['cleanup_complete'])
                self.assertEqual(m['cleanup_signals'], [])
                self.assertGreater(m['wait4_ru_maxrss_raw'], 0)
                self.assertEqual((self.root/'stdout').read_text(), 'ok\n')

    def test_timeout_kills_ignoring_tree_but_not_unrelated_session(self):
        other = self.real_popen([sys.executable, '-S', '-c', 'import time; time.sleep(15)'], start_new_session=True)
        try:
            with mock.patch.object(owned.subprocess, 'Popen', side_effect=self.spawn_ready):
                result = self.run_capture(self.parent('ignore'), timeout=.05)
            self.assertIsNone(other.poll())
            self.assertTrue(result.metadata['timed_out'])
            self.assertFalse(result.metadata['success'])
            self.assertEqual(result.metadata['cleanup_signals'], ['SIGTERM', 'SIGKILL'])
            self.assertEqual(result.metadata['exit_code'], -signal.SIGKILL)
            self.assertTrue(result.metadata['leader_reaped'])
            self.assert_tree_stopped()
        finally:
            other.terminate()
            other.wait(timeout=3)

    def test_graceful_timeout_zero_exit_cannot_be_success(self):
        with mock.patch.object(owned.subprocess, 'Popen', side_effect=self.spawn_ready):
            result = self.run_capture(self.parent('graceful'), timeout=.05)
        self.assertTrue(result.metadata['timed_out'])
        self.assertEqual(result.metadata['exit_code'], 0)
        self.assertEqual(result.metadata['cleanup_signals'], ['SIGTERM'])
        self.assertFalse(result.metadata['success'])
        self.assert_tree_stopped()

    def test_signal_during_spawn_return_keeps_ownership_and_restores_handlers(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(sig=sig):
                for name in ('ready.json', 'child.pid', 'handler-ready'):
                    (self.root/name).unlink(missing_ok=True)
                def spawn(*args, **kwargs):
                    p = self.spawn_ready(*args, **kwargs)
                    signal.raise_signal(sig)
                    return p
                with mock.patch.object(owned.subprocess, 'Popen', side_effect=spawn):
                    result = self.run_capture(self.parent('ignore'))
                self.assertIsInstance(result.error, owned.CaptureCancelled)
                self.assertEqual(result.metadata['interrupted_signal'], signal.Signals(sig).name)
                self.assertFalse(result.metadata['success'])
                self.assertTrue(result.metadata['leader_reaped'])
                self.assert_tree_stopped()
                for s, h in self.previous.items():
                    self.assertEqual(signal.getsignal(s), h)

    def test_exception_and_keyboard_interrupt_cleanup_then_preserve_original(self):
        for error in (RuntimeError('fixture failure'), KeyboardInterrupt('fixture interruption')):
            with self.subTest(error=type(error).__name__):
                for name in ('ready.json', 'child.pid', 'handler-ready'):
                    (self.root/name).unlink(missing_ok=True)
                thrown = False
                def wait(*args):
                    nonlocal thrown
                    if not thrown:
                        self.await_ready()
                        thrown = True
                        raise error
                    return self.real_wait4(*args)
                with mock.patch.object(owned.os, 'wait4', side_effect=wait):
                    result = self.run_capture(self.parent('ignore'))
                self.assertIs(result.error, error)
                self.assertFalse(result.metadata['success'])
                self.assertTrue(result.metadata['leader_reaped'])
                self.assert_tree_stopped()

    def test_exited_leader_with_leftover_child_is_not_success(self):
        result = self.run_capture(self.parent('leave'))
        self.assertEqual(result.metadata['exit_code'], 0)
        self.assertTrue(result.metadata['unexpected_descendants'])
        self.assertFalse(result.metadata['success'])
        self.assert_tree_stopped()

    def test_spawn_failure_is_recorded_without_any_group_signal(self):
        result = self.run_capture([str(self.root/'missing-executable')])
        self.assertIsInstance(result.error, FileNotFoundError)
        self.assertIsNone(result.metadata['pid'])
        self.assertIsNone(result.metadata['exit_code'])
        self.assertEqual(result.metadata['cleanup_signals'], [])
        self.assertFalse(result.metadata['success'])

    def test_permission_probe_failure_is_never_success(self):
        with mock.patch.object(owned, '_group_exists', side_effect=PermissionError('denied')):
            result = self.run_capture([sys.executable, '-S', '-c', 'pass'])
        self.assertEqual(result.metadata['exit_code'], 0)
        self.assertTrue(result.metadata['leader_reaped'])
        self.assertFalse(result.metadata['success'])
        self.assertFalse(result.metadata['cleanup_complete'])
        self.assertIsInstance(result.error, PermissionError)
        self.assertEqual(result.metadata['cleanup_errors'], ['PermissionError'])

    def test_invalid_arguments_never_spawn(self):
        for value in (0, -1, True, float('nan'), float('inf')):
            with self.subTest(value=value), mock.patch.object(owned.subprocess, 'Popen') as spawn:
                with self.assertRaises(ValueError):
                    self.run_capture([sys.executable], timeout=value)
                spawn.assert_not_called()

    def test_large_output_goes_to_files_not_blocking_pipes(self):
        result = self.run_capture([sys.executable, '-S', '-c', 'import sys;sys.stdout.write("x"*300000);sys.stderr.write("y"*300000)'])
        self.assertTrue(result.metadata['success'])
        self.assertEqual((self.root/'stdout').stat().st_size, 300000)
        self.assertEqual((self.root/'stderr').stat().st_size, 300000)


if __name__ == '__main__':
    unittest.main()
