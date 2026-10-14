"""Bounded POSIX supervision of one freshly owned process group.

Only same-group descendants are covered. Descendants that deliberately create a
new session/group, SIGKILL of this supervisor, and kernel-uninterruptible tasks
require an external service/container supervisor. No process-name matching or
system-wide termination is performed. wait4 accounts for the exact direct child;
its ru_maxrss is not a process-tree memory measurement.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import math
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import BinaryIO, Sequence


@dataclass
class Outcome:
    metadata: dict
    error: BaseException | None = None


class CaptureCancelled(KeyboardInterrupt):
    """Cancellation is re-raised by the caller after retaining its evidence."""


@contextmanager
def _cancellation_signals():
    # The CLI is single-threaded. Explicitly refuse unsupported use rather than
    # launch a child before signal.signal discovers the wrong thread.
    if threading.current_thread() is not threading.main_thread():
        raise ValueError("process capture must run in the main thread")
    cancelled = []
    previous = {}

    def request(signum, _frame):
        # Do not raise inside Popen: ownership must be established even if a
        # signal arrives between fork/exec and assignment of the returned PID.
        if not cancelled:
            cancelled.append(signum)

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, request)
        yield cancelled
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    return True


def supervise(argv: Sequence[str], *, cwd: Path, stdout: BinaryIO,
              stderr: BinaryIO, timeout: float = 900,
              term_grace: float = 1, kill_grace: float = 2) -> Outcome:
    """Run argv without a shell, retaining failure/cancellation status.

    A new session makes PID == owned process-group ID. Timeout, cancellation,
    exceptions, or an exited leader with remaining descendants trigger bounded
    TERM then KILL for that group, followed by exact-child reaping. A leftover
    group (including unreaped adopted zombies) is reported, never called clean.
    No successful exit can override a timeout or unexpected descendants.
    """
    if os.name != "posix" or not hasattr(os, "wait4"):
        raise ValueError("POSIX wait4 and process groups are required")
    for value in (timeout, term_grace, kill_grace):
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError("timeouts must be finite positive numbers")
    if not argv or isinstance(argv, (str, bytes)) or not all(isinstance(v, str) for v in argv):
        raise ValueError("a nonempty argument vector is required")

    started = time.time()
    start_clock = time.monotonic()
    process = None
    usage = None
    error = None
    metadata = {
        "command": list(argv), "pid": None, "pgid": None,
        "started_unix": started, "exit_code": None, "timed_out": False,
        "interrupted_signal": None, "exception_type": None,
        "unexpected_descendants": False, "leader_reaped": False,
        "group_still_present": None, "cleanup_signals": [], "cleanup_errors": [],
        "wait4_ru_maxrss_raw": None,
    }

    def reap():
        nonlocal usage
        if process is None or process.returncode is not None:
            return
        try:
            pid, status, child_usage = os.wait4(process.pid, os.WNOHANG)
        except InterruptedError:
            return
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            usage = child_usage
            metadata["exit_code"] = process.returncode
            metadata["leader_reaped"] = True

    def group_exists():
        present = _group_exists(process.pid)
        metadata["group_still_present"] = present
        return present

    def send(sig):
        # Popen(start_new_session=True) owns this numeric group. Do not target
        # the caller's group or chase any process by a name or a stale pid list.
        if process.pid <= 1 or process.pid == os.getpgrp():
            raise RuntimeError("refusing an unowned process group")
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            metadata["group_still_present"] = False
            return
        metadata["cleanup_signals"].append(signal.Signals(sig).name)

    def cleanup():
        for sig, grace in ((signal.SIGTERM, term_grace), (signal.SIGKILL, kill_grace)):
            if not group_exists():
                reap()
                break
            send(sig)
            deadline = time.monotonic() + grace
            while True:
                reap()
                if not group_exists():
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
        reap()
        group_exists()

    with _cancellation_signals() as cancelled:
        try:
            process = subprocess.Popen(list(argv), cwd=cwd, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
            metadata["pid"] = metadata["pgid"] = process.pid
            deadline = time.monotonic() + timeout
            while True:
                if cancelled:
                    metadata["interrupted_signal"] = signal.Signals(cancelled[0]).name
                    raise CaptureCancelled(metadata["interrupted_signal"])
                reap()
                if process.returncode is not None:
                    metadata["unexpected_descendants"] = group_exists()
                    break
                if time.monotonic() >= deadline:
                    metadata["timed_out"] = True
                    break
                time.sleep(0.02)
        except BaseException as caught:
            error = caught
            metadata["exception_type"] = type(caught).__name__
        finally:
            if process is not None:
                try:
                    # Even an exception after leader exit must drain the group.
                    # Reaping and final group disappearance are separate facts.
                    cleanup()
                except BaseException as cleanup_error:
                    metadata["cleanup_errors"].append(type(cleanup_error).__name__)
                    if error is None:
                        error = cleanup_error
                        metadata["exception_type"] = type(cleanup_error).__name__
            if cancelled:
                metadata["interrupted_signal"] = signal.Signals(cancelled[0]).name
                if error is None:
                    error = CaptureCancelled(metadata["interrupted_signal"])
                    metadata["exception_type"] = type(error).__name__

    metadata["wall_seconds"] = time.monotonic() - start_clock
    if usage is not None:
        metadata["wait4_ru_maxrss_raw"] = usage.ru_maxrss
    metadata["cleanup_complete"] = (
        process is not None and metadata["leader_reaped"]
        and metadata["group_still_present"] is False and not metadata["cleanup_errors"]
    )
    metadata["success"] = (
        metadata["exit_code"] == 0 and not metadata["timed_out"]
        and metadata["interrupted_signal"] is None and error is None
        and not metadata["unexpected_descendants"] and metadata["cleanup_complete"]
    )
    return Outcome(metadata, error)
