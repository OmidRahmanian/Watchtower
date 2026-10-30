"""Run external tools in their own process group, so cancelling a job stops everything it started.

``run_in_group`` has the contract of ``adapters.discovery.process.run_bounded``
(argument arrays, no shell, a timeout, bounded output) and adds:

* the tool starts a new session, so it and every child it forks share one
  process group;
* timeout, output overflow and cancellation signal the whole group:
  SIGTERM, then SIGKILL after ``grace`` seconds, so grandchildren cannot
  outlive the job.
"""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Sequence
from typing import Any

from watchtower.adapters.discovery.process import (
    DEFAULT_MAX_STDERR, DEFAULT_MAX_STDOUT, DEFAULT_TIMEOUT, ProcessResult, _drain,
)

POLL_SECONDS = 0.1


def kill_group(pid: int, grace: float = 2.0) -> None:
    """SIGTERM the process group led by ``pid``, then SIGKILL whatever is left after ``grace``.

    ``ProcessLookupError`` means the group is empty. macOS reports
    ``PermissionError`` instead when only zombies are left (the unreaped
    leader), so that also counts as gone.
    """
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        try:
            os.killpg(pid, 0)
        except (ProcessLookupError, PermissionError):
            return
        time.sleep(0.05)
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_in_group(
    argv: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_stdout: int = DEFAULT_MAX_STDOUT,
    max_stderr: int = DEFAULT_MAX_STDERR,
    cancel: Any = None,  # a CancelToken, or anything with a ``cancelled`` attribute
    grace: float = 2.0,
) -> ProcessResult:
    argv = [str(arg) for arg in argv]
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, start_new_session=True,
        )
    except OSError as exc:
        return ProcessResult(argv, None, b"", b"", error=f"could not start {argv[0]}: {exc}")

    stopping = threading.Event()

    def stop() -> None:
        stopping.set()

    stdout, stderr = bytearray(), bytearray()
    stdout_full, stderr_full = threading.Event(), threading.Event()
    readers = [
        threading.Thread(target=_drain, args=(process.stdout, max_stdout, stdout, stdout_full, stop), daemon=True),
        threading.Thread(target=_drain, args=(process.stderr, max_stderr, stderr, stderr_full, lambda: None),
                         daemon=True),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    timed_out = cancelled = False
    while process.poll() is None:
        if cancel is not None and cancel.cancelled:
            cancelled = True
        elif time.monotonic() >= deadline:
            timed_out = True
        if cancelled or timed_out or stopping.is_set():
            break
        try:
            process.wait(timeout=POLL_SECONDS)
        except subprocess.TimeoutExpired:
            continue
    # Even after the leader exits, children it forked may still hold the group.
    kill_group(process.pid, grace if process.poll() is None else 0.2)
    process.wait()
    for reader in readers:
        reader.join(timeout=5)
    for stream in (process.stdout, process.stderr):
        stream.close()
    return ProcessResult(
        argv, process.returncode, bytes(stdout), bytes(stderr), timed_out=timed_out,
        truncated=stdout_full.is_set(), error="cancelled" if cancelled else "",
    )
