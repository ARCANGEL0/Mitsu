"""Detect and persist the host OS and its native package manager."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import tempfile


@dataclass(frozen=True)
class HostEnvironment:
    os_id: str
    os_name: str
    package_manager_id: str
    package_manager_name: str
    package_manager_path: str


_PACKAGE_MANAGERS = (
    ("apt-get", "APT"),
    ("pacman", "Pacman"),
    ("dnf", "DNF"),
    ("zypper", "Zypper"),
    ("apk", "APK"),
    ("yum", "YUM"),
)
_MANAGER_NAMES = dict(_PACKAGE_MANAGERS)


def _config_path() -> Path:
    root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return root / "mitsu" / "host.json"


def _os_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key in {"ID", "PRETTY_NAME"}:
            values[key] = value.strip().strip('"').strip("'")
    return values.get("ID", "unknown").lower(), values.get("PRETTY_NAME", "Linux")


def detect_host_environment() -> HostEnvironment:
    os_id, os_name = _os_release()
    distro_preferences = {
        "arch": "pacman",
        "blackarch": "pacman",
        "garuda": "pacman",
        "manjaro": "pacman",
        "debian": "apt-get",
        "kali": "apt-get",
        "linuxmint": "apt-get",
        "pop": "apt-get",
        "ubuntu": "apt-get",
        "fedora": "dnf",
        "rhel": "dnf",
        "centos": "dnf",
        "rocky": "dnf",
        "almalinux": "dnf",
        "opensuse": "zypper",
        "opensuse-leap": "zypper",
        "opensuse-tumbleweed": "zypper",
        "sles": "zypper",
        "alpine": "apk",
    }
    preferred_manager = distro_preferences.get(os_id)
    manager_order = sorted(
        _PACKAGE_MANAGERS,
        key=lambda entry: entry[0] != preferred_manager,
    )
    package_manager = next(
        (
            (manager_id, name, path)
            for manager_id, name in manager_order
            if (path := shutil.which(manager_id))
        ),
        None,
    )
    if package_manager is None:
        return HostEnvironment(os_id, os_name, "", "Unavailable", "")
    manager_id, manager_name, manager_path = package_manager
    return HostEnvironment(os_id, os_name, manager_id, manager_name, manager_path)


def _save_host_environment(environment: HostEnvironment) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".host-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(
                {
                    "os_id": environment.os_id,
                    "os_name": environment.os_name,
                    "package_manager": environment.package_manager_id,
                },
                stream,
                indent=2,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def load_host_environment() -> HostEnvironment:
    """Use install-time metadata when valid, refreshing it if the host changed."""

    current = detect_host_environment()
    try:
        saved = json.loads(_config_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        saved = {}
    if not isinstance(saved, dict):
        saved = {}

    saved_manager = str(saved.get("package_manager", ""))
    manager_path = shutil.which(saved_manager) if saved_manager else None
    if (
        current.os_id == str(saved.get("os_id", ""))
        and saved_manager in _MANAGER_NAMES
        and saved_manager == current.package_manager_id
        and manager_path
    ):
        environment = HostEnvironment(
            current.os_id,
            current.os_name,
            saved_manager,
            _MANAGER_NAMES[saved_manager],
            manager_path,
        )
    else:
        environment = current
    _save_host_environment(environment)
    return environment
