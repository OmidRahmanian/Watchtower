"""Run external tools with argument arrays, a timeout, and bounded output."""
from __future__ import annotations

import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass

DEFAULT_TIMEOUT = 300.0
DEFAULT_MAX_STDOUT = 8 * 1024 * 1024
DEFAULT_MAX_STDERR = 64 * 1024


@dataclass
class ProcessResult:
    argv: list[str]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    truncated: bool = False
    error: str = ""


def _drain(stream, limit: int, sink: bytearray, overflow: threading.Event, on_overflow) -> None:
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return
        room = limit - len(sink)
        if room > 0:
            sink.extend(chunk[:room])
        if len(chunk) > room:
            overflow.set()
            on_overflow()
            return


def run_bounded(
    argv: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_stdout: int = DEFAULT_MAX_STDOUT,
    max_stderr: int = DEFAULT_MAX_STDERR,
) -> ProcessResult:
    """Run `argv` without a shell; kill it on timeout or once stdout exceeds `max_stdout`."""
    argv = [str(arg) for arg in argv]
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        return ProcessResult(argv, None, b"", b"", error=f"could not start {argv[0]}: {exc}")

    stdout, stderr = bytearray(), bytearray()
    stdout_full, stderr_full = threading.Event(), threading.Event()
    readers = [
        threading.Thread(target=_drain, args=(process.stdout, max_stdout, stdout, stdout_full, process.kill), daemon=True),
        # A chatty stderr is truncated but never stops the tool.
        threading.Thread(target=_drain, args=(process.stderr, max_stderr, stderr, stderr_full, lambda: None), daemon=True),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    for reader in readers:
        reader.join(timeout=5)
    for stream in (process.stdout, process.stderr):
        stream.close()

    return ProcessResult(
        argv,
        process.returncode,
        bytes(stdout),
        bytes(stderr),
        timed_out=timed_out,
        truncated=stdout_full.is_set(),
    )
