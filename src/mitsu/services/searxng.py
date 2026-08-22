"""Manage Mitsu's loopback-only SearXNG container and lifecycle."""

from __future__ import annotations

import json
import getpass
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


Progress = Callable[[str], None]
_IMAGES = (
    "ghcr.io/searxng/searxng:latest",
    "docker.io/searxng/searxng:latest",
)


class SearXNGSetupError(RuntimeError):
    pass


class DockerNotInstalledError(SearXNGSetupError):
    pass


def _runtime_command(runtime: str, args: list[str]) -> list[str]:
    """Use a newly granted docker group without restarting Mitsu's process."""

    command = [runtime, *args]
    if runtime != "docker" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        return command

    try:
        import grp

        docker_group = grp.getgrnam("docker")
    except (ImportError, KeyError):
        return command

    if docker_group.gr_gid in os.getgroups() or os.getegid() == docker_group.gr_gid:
        return command
    if getpass.getuser() not in docker_group.gr_mem:
        return command

    sg = shutil.which("sg")
    if not sg:
        return command
    return [sg, "docker", "-c", shlex.join(command)]


def _run(runtime: str, args: list[str], *, timeout: int = 90) -> str:
    try:
        completed = subprocess.run(
            _runtime_command(runtime, args),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise SearXNGSetupError(f"{runtime} is no longer available on PATH.") from error
    except subprocess.TimeoutExpired as error:
        raise SearXNGSetupError(f"{runtime} did not finish within {timeout} seconds.") from error
    output = (completed.stdout or "").strip()
    if completed.returncode:
        detail = output[-1200:] or f"exit code {completed.returncode}"
        raise SearXNGSetupError(f"{runtime} {args[0]} failed: {detail}")
    return output


def _image_available(runtime: str, image: str) -> bool:
    try:
        result = subprocess.run(
            _runtime_command(runtime, ["image", "inspect", image]),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _ensure_image(runtime: str, progress: Progress) -> str:
    for image in _IMAGES:
        if _image_available(runtime, image):
            progress("Found a cached official SearXNG image; reusing it without downloading.")
            return image

    failures: list[str] = []
    for image in _IMAGES:
        progress(f"Downloading the official SearXNG image from {image.split('/')[0]}…")
        try:
            _run(runtime, ["pull", image], timeout=900)
            return image
        except SearXNGSetupError as error:
            failures.append(str(error))
    raise SearXNGSetupError(
        "Could not fetch the official SearXNG image from GHCR or Docker Hub. "
        + " · ".join(failures[-2:])
    )


def _write_container_settings(runtime: str, volume_name: str, settings_text: str, image: str) -> None:
    _run(runtime, ["volume", "create", volume_name], timeout=30)
    command = _runtime_command(runtime, [
        "run", "--rm", "--interactive", "--user", "0:0",
        "--volume", f"{volume_name}:/etc/searxng",
        "--entrypoint", "sh", image, "-c", "umask 077; cat > /etc/searxng/settings.yml",
    ])
    try:
        completed = subprocess.run(
            command,
            input=settings_text,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=45,
        )
    except subprocess.TimeoutExpired as error:
        raise SearXNGSetupError("Writing the private SearXNG settings timed out.") from error
    output = (completed.stdout or "").strip()
    if completed.returncode:
        raise SearXNGSetupError(f"Could not write SearXNG settings into its private container volume: {output[-1000:]}")


def _runtime() -> str:
    if not shutil.which("docker"):
        raise DockerNotInstalledError(
            "Docker is not installed. Choose Install Docker or return to the search engine list."
        )
    try:
        _run("docker", ["info"], timeout=15)
    except SearXNGSetupError as error:
        raise SearXNGSetupError(
            "Docker is installed, but the daemon is not ready or this user cannot access it. "
            "Start Docker and check Docker group access, then try again."
        ) from error
    return "docker"


def _container_state(runtime: str, name: str) -> bool | None:
    try:
        result = subprocess.run(
            _runtime_command(runtime, ["container", "inspect", "--format", "{{.State.Running}}", name]),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=12,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    return result.stdout.strip().lower() == "true"


def _port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _probe(base_url: str) -> bool:
    request = Request(
        f"{base_url}/search?q=mitsu%20local%20search&format=json",
        headers={"Accept": "application/json", "User-Agent": "Mitsu/0.1"},
    )
    try:
        with urlopen(request, timeout=3) as response:
            payload = json.loads(response.read(1_000_000).decode("utf-8", errors="replace"))
        return isinstance(payload, dict) and isinstance(payload.get("results"), list)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return False
