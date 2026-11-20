from __future__ import annotations

import os
import signal
import time
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


def _lock_owner(path: Path) -> int | None:
    try:
        owner = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return owner if owner > 1 else None


def _is_mitsu_process(pid: int) -> bool:
    if os.name == "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        name = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip().casefold()
    except OSError:
        return False
    return name == "mitsu" or any(
        part == "mitsu" or part.endswith("/mitsu") or part.endswith("/mitsu/__main__.py")
        for part in command.split()
    )


def _try_acquire_instance_lock() -> IO[str]:
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


def _wait_for_lock_release(owner: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            handle = _try_acquire_instance_lock()
        except InstanceAlreadyRunning:
            time.sleep(0.1)
            continue
        release_instance_lock(handle)
        return True
    return not _is_mitsu_process(owner)


def terminate_existing_instance(timeout: float = 8.0) -> None:
    try:
        handle = _try_acquire_instance_lock()
    except InstanceAlreadyRunning:
        handle = None
    if handle is not None:
        release_instance_lock(handle)
        return
    path = _lock_path()
    owner = _lock_owner(path)
    if owner is None or not _is_mitsu_process(owner):
        raise InstanceAlreadyRunning("The instance lock is held, but its owner could not be verified as Mitsu.")
    if owner == os.getpid():
        raise InstanceAlreadyRunning("Refusing to terminate the current Mitsu process.")
    try:
        os.kill(owner, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError as error:
        raise InstanceAlreadyRunning(f"Could not stop Mitsu process {owner}: {error}") from error
    if _wait_for_lock_release(owner, timeout):
        return
    try:
        if _is_mitsu_process(owner):
            os.kill(owner, getattr(signal, "SIGKILL", signal.SIGTERM))
    except ProcessLookupError:
        pass
    except OSError as error:
        raise InstanceAlreadyRunning(f"Could not force-stop Mitsu process {owner}: {error}") from error
    if not _wait_for_lock_release(owner, 3.0):
        raise InstanceAlreadyRunning(f"Mitsu process {owner} did not release its instance lock.")


def acquire_instance_lock(terminate_existing: bool = False) -> IO[str]:
    try:
        return _try_acquire_instance_lock()
    except InstanceAlreadyRunning:
        if not terminate_existing:
            raise
    terminate_existing_instance()
    return _try_acquire_instance_lock()


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
