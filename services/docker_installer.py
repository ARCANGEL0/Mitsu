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


def install_docker_engine(password: str, progress: Progress | None = None) -> None:
    """Install Docker through the native package manager and enable its service."""

    if not sys.platform.startswith("linux"):
        raise DockerInstallError("Automatic Docker installation is available on Linux only.")

    is_root = os.geteuid() == 0
    sudo = None if is_root else shutil.which("sudo")
    if not is_root and not sudo:
        raise DockerInstallError("sudo was not found. Install Docker with an administrator account.")
    if not is_root and not password:
        raise DockerInstallError("Enter your sudo password to install Docker.")

    detected = detect_package_manager()
    if detected is None:
        raise DockerInstallError(
            f"No supported package manager was found. Supported managers: {_PACKAGE_MANAGER_NAMES}."
        )
    manager, executable = detected
    report = progress or (lambda _message: None)
    environment = os.environ.copy()

    for arguments in manager.refresh:
        report(f"Refreshing {manager.name} package lists…")
        _run_as_admin(
            [executable, *arguments],
            manager,
            password,
            sudo,
            is_root,
            environment,
            timeout=900,
        )

    report(f"Installing Docker with {manager.name}…")
    _run_as_admin(
        [executable, *manager.install],
        manager,
        password,
        sudo,
        is_root,
        environment,
        timeout=1800,
    )

    if not is_root:
        _ensure_docker_group(manager, password, sudo, environment)
        report("Adding your account to the docker group…")
        membership_command = (
            ["addgroup", getpass.getuser(), "docker"]
            if manager.executable == "apk"
            else ["usermod", "-aG", "docker", getpass.getuser()]
        )
        _run_as_admin(
            membership_command,
            manager,
            password,
            sudo,
            is_root,
            environment,
            timeout=60,
        )

    _start_docker_service(manager, password, sudo, is_root, environment, report)
    report("Docker is installed and running.")


def _ensure_docker_group(
    manager: PackageManager,
    password: str,
    sudo: str | None,
    environment: dict[str, str],
) -> None:
    import grp

    try:
        grp.getgrnam("docker")
    except KeyError:
        create_group = ["addgroup", "-S", "docker"] if manager.executable == "apk" else ["groupadd", "-f", "docker"]
        _run_as_admin(
            create_group,
            manager,
            password,
            sudo,
            False,
            environment,
            timeout=60,
        )


def _start_docker_service(
    manager: PackageManager,
    password: str,
    sudo: str | None,
    is_root: bool,
    environment: dict[str, str],
    report: Progress,
) -> None:
    report("Starting the Docker service…")
    if manager.executable == "apk":
        commands = (["rc-update", "add", "docker", "default"], ["rc-service", "docker", "start"])
    elif shutil.which("systemctl") and os.path.isdir("/run/systemd/system"):
        commands = (["systemctl", "enable", "--now", "docker.service"],)
    elif shutil.which("service"):
        commands = (["service", "docker", "start"],)
    else:
        raise DockerInstallError("Docker was installed, but no supported service manager was found.")

    for command in commands:
        _run_as_admin(
            list(command),
            manager,
            password,
            sudo,
            is_root,
            environment,
            timeout=120,
        )


def _run_as_admin(
    command: list[str],
    manager: PackageManager,
    password: str,
    sudo: str | None,
    is_root: bool,
    environment: dict[str, str],
    *,
    timeout: int,
) -> None:
    command_label = command[0]
    if manager.executable == "apt-get":
        command = ["env", "DEBIAN_FRONTEND=noninteractive", *command]

    if is_root:
        elevated_command = command
        command_input = None
    else:
        if sudo is None:
            raise DockerInstallError("sudo was not found. Install Docker with an administrator account.")
        # sudo reads the password; the root shell redirects stdin before launching the package command.
        elevated_command = [
            sudo,
            "-S",
            "-p",
            "",
            "--",
            "sh",
            "-c",
            'exec </dev/null; exec "$@"',
            "mitsu-package-install",
            *command,
        ]
        command_input = f"{password}\n"

    try:
        result = subprocess.run(
            elevated_command,
            input=command_input,
            stdin=None if command_input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        raise DockerInstallError(f"{manager.name} could not run `{command_label}`.") from error
    except subprocess.TimeoutExpired as error:
        raise DockerInstallError(f"{manager.name} did not finish `{command_label}` in time.") from error
    except OSError as error:
        raise DockerInstallError(f"Could not run `{command_label}` with {manager.name}: {error}") from error

    if result.returncode:
        lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
        detail = " · ".join(lines[-3:]) or "No details were returned."
        if len(detail) > 480:
            detail = f"…{detail[-477:]}"
        raise DockerInstallError(f"{manager.name} failed: {detail}")
