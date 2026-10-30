"""Single-session coordination shared by the launcher and monitoring process."""

import fcntl
import os
import shlex
import signal
import subprocess
import time


def running_pid(root):
    """Ignore stale PID files and processes that are not WatchTower."""
    try:
        pid = int((root / "files/watchtower.pid").read_text().strip())
        if pid <= 1 or pid == os.getpid():
            return None
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True, text=True, check=False,
        )
        if result.returncode == 0 and any(
            arg == "watch.py" or arg == str(root / "watch.py")
            for arg in shlex.split(result.stdout.strip())
        ):
            return pid
    except (OSError, ValueError):
        pass
    return None


def stop_session(pid):
    try:
        if os.getpgid(pid) == pid:
            os.killpg(pid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    raise RuntimeError("The existing WatchTower session has not stopped. Try again shortly.")


def acquire_session(root, inherited_fd=None):
    directory = root / "files"
    directory.mkdir(exist_ok=True)
    path = directory / "watchtower.lock"
    if inherited_fd is not None:
        handle = os.fdopen(int(inherited_fd), "a+")
        if os.fstat(handle.fileno()).st_ino != path.stat().st_ino:
            handle.close()
            raise RuntimeError("Invalid WatchTower session lock.")
    else:
        handle = path.open("a+")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise RuntimeError("Another WatchTower session or setup is already running.") from None
    return handle
