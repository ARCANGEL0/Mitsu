"""Install Docker Engine using the host's native Linux package manager."""

from __future__ import annotations

from dataclasses import dataclass
import getpass
import os
import shutil
import subprocess
import sys
from typing import Callable


Progress = Callable[[str], None]
Command = tuple[str, ...]


class DockerInstallError(RuntimeError):
    """Raised when Docker Engine cannot be installed or started."""


@dataclass(frozen=True)
class PackageManager:
    executable: str
    name: str
    install: Command
    refresh: tuple[Command, ...] = ()


_PACKAGE_MANAGERS = (
    PackageManager("apt-get", "APT", ("install", "-y", "docker.io"), (("update",),)),
    PackageManager("dnf", "DNF", ("install", "-y", "moby-engine", "docker-cli")),
    PackageManager("pacman", "Pacman", ("-S", "--needed", "--noconfirm", "docker")),
    PackageManager(
        "zypper",
        "Zypper",
        ("--non-interactive", "--auto-agree-with-licenses", "install", "docker"),
        (("--non-interactive", "--gpg-auto-import-keys", "refresh"),),
    ),
    PackageManager("apk", "APK", ("add", "docker", "shadow-login"), (("update",),)),
    PackageManager("yum", "YUM", ("install", "-y", "docker")),
)
_PACKAGE_MANAGER_NAMES = ", ".join(manager.executable for manager in _PACKAGE_MANAGERS)


def detect_package_manager() -> tuple[PackageManager, str] | None:
    """Return the first supported package manager found on PATH and its full path."""

    for manager in _PACKAGE_MANAGERS:
        executable = shutil.which(manager.executable)
        if executable:
            return manager, executable
    return None
