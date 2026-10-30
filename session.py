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


def platform_requested(argv, environ):
    """``watch.py --platform`` or ``WATCHTOWER_RUNTIME=platform`` selects the platform runtime."""
    return "--platform" in argv or environ.get("WATCHTOWER_RUNTIME", "") == "platform"


def run_platform(root, inherited_fd=None, *, schedule_every="6h", stop=None):
    """Run the platform runtime as this WatchTower session.

    It takes the same session lock and PID file as the legacy monitor, so
    launcher.py can start, find and stop it exactly as before. Inside, it runs
    the PostgreSQL-backed workers and notifier (``watchtower.workers``) and
    enqueues scheduled runs every ``schedule_every``; settings come from
    WATCHTOWER_PROFILE and WATCHTOWER__* variables. Stopping the session
    (SIGTERM to its process group) requeues in-flight jobs for the next start.
    """
    import sys
    import threading

    if sys.version_info < (3, 11):
        raise RuntimeError("The platform runtime needs Python 3.11+; install it with: pip install -e '.[workers]'")
    from watchtower.config import load_settings
    from watchtower.persistence.database import Database
    from watchtower.services.jobs import RunService
    from watchtower.services.scope import ScopeService
    from watchtower.workers import egress
    from watchtower.workers.cli import interval
    from watchtower.workers.runtime import serve
    from watchtower.workers.scheduler import schedule_due

    if inherited_fd is None and running_pid(root):
        raise RuntimeError("WatchTower is already running. Use launcher.py to change its target.")
    every = interval(schedule_every)
    # A bad configuration fails here, before the session is taken.
    settings = load_settings()
    database = Database.from_settings(settings.database)
    scope = ScopeService(database, settings.scope)
    runs = RunService(database, scope, settings=settings)
    stop = stop or threading.Event()
    with acquire_session(root, inherited_fd):
        pid_path = root / "files/watchtower.pid"

        def scheduler():
            while not stop.is_set():
                try:
                    started = schedule_due(database, runs, interval=every)
                    print(f"Scheduled runs this slot: {len(started)}", flush=True)
                except Exception as exc:
                    print(f"Scheduling failed: {type(exc).__name__}: {exc}", flush=True)
                stop.wait(300)

        try:
            pid_path.write_text(str(os.getpid()) + "\n")
            egress.install(settings)
            print(f"WatchTower platform runtime: {settings.runtime.concurrency} workers, runs every {schedule_every}",
                  flush=True)
            threading.Thread(target=scheduler, name="scheduler", daemon=True).start()
            serve(database, scope, settings, stop=stop)
        finally:
            stop.set()
            database.dispose()
            if pid_path.exists() and pid_path.read_text().strip() == str(os.getpid()):
                pid_path.unlink()
    return 0
