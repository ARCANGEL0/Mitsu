from __future__ import annotations

import os
from pathlib import Path
from typing import IO


class InstanceAlreadyRunning(RuntimeError):
    pass


def _lock_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Mitsu"
    else:
        runtime = os.environ.get("XDG_RUNTIME_DIR")
        if runtime and Path(runtime).is_dir() and os.access(runtime, os.W_OK):
            root = Path(runtime) / "mitsu"
        else:
            root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "mitsu"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root / "instance.lock"


def acquire_instance_lock() -> IO[str]:
    """Acquire a per-user lock held for the lifetime of the Mitsu process."""
    path = _lock_path()
    handle = path.open("a+", encoding="utf-8")
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            if path.stat().st_size == 0:
                handle.write(" ")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise InstanceAlreadyRunning("Another Mitsu instance is already running.") from error
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                handle.seek(0)
                owner = handle.read().strip()
                detail = f" (PID {owner})" if owner.isdigit() else ""
                raise InstanceAlreadyRunning(f"Another Mitsu instance is already running{detail}.") from error
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        return handle
    except BaseException:
        handle.close()
        raise


def release_instance_lock(handle: IO[str]) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    finally:
        handle.close()
