from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen


PYPI_RELEASE_URL = "https://pypi.org/pypi/mitsu/json"
_VERSION_PATTERN = re.compile(r"v?(\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?)")


class UpdateError(RuntimeError):
    pass


@dataclass(frozen=True)
class Installation:
    kind: str
    manager: str
    current_version: str
    checkout_path: Path | None = None
    repository_url: str | None = None
    requested_revision: str | None = None
    installed_commit: str | None = None

    @property
    def source_name(self) -> str:
        source = {
            "checkout": "GitHub checkout",
            "git": "Git source",
            "pypi": "PyPI",
        }.get(self.kind, "Unknown source")
        manager = {"uv_tool": "uv tool", "uv_project": "uv project", "pip": "pip"}.get(
            self.manager, self.manager
        )
        return f"{source} · {manager}"


@dataclass(frozen=True)
class UpdateCheck:
    installation: Installation
    available: bool
    latest_version: str | None = None
    remote_commit: str | None = None
    detail: str = ""


def _run(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 20,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise UpdateError("The updater command could not be completed.") from error
    return result


def _git_root(path: Path) -> Path | None:
    current = path if path.is_dir() else path.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _local_path_from_url(url: str) -> Path | None:
    parsed = urlsplit(url)
    if parsed.scheme != "file":
        return None
    raw_path = unquote(parsed.path)
    if os.name == "nt" and raw_path.startswith("/"):
        raw_path = raw_path[1:]
    path = Path(raw_path)
    return path if path.is_dir() else None


def _uv_tool_directory() -> Path | None:
    configured = os.environ.get("UV_TOOL_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    uv = shutil.which("uv")
    if not uv:
        return None
    try:
        result = _run([uv, "tool", "dir"], timeout=5)
    except UpdateError:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return Path(result.stdout.strip()).expanduser().resolve()


def detect_installation(current_version: str) -> Installation:
    direct_url: dict = {}
    try:
        package = distribution("mitsu")
        current_version = package.version or current_version
        direct_url_text = package.read_text("direct_url.json")
        if direct_url_text:
            direct_url = json.loads(direct_url_text)
    except (PackageNotFoundError, json.JSONDecodeError, OSError):
        pass

    vcs_info = direct_url.get("vcs_info", {})
    requested_revision = vcs_info.get("requested_revision")
    installed_commit = vcs_info.get("commit_id")
    repository_url = str(direct_url.get("url") or "") or None
    checkout_path: Path | None = None

    if repository_url:
        checkout_path = _git_root(_local_path_from_url(repository_url) or Path("/nonexistent"))
    if checkout_path is None:
        checkout_path = _git_root(Path(__file__).resolve())

    if checkout_path is not None:
        kind = "checkout"
        git_remote = _run(["git", "remote", "get-url", "origin"], cwd=checkout_path)
        repository_url = git_remote.stdout.strip() if git_remote.returncode == 0 else repository_url
    elif vcs_info.get("vcs") == "git" and repository_url:
        kind = "git"
    else:
        kind = "pypi"

    manager = "pip"
    tool_directory = _uv_tool_directory()
    prefix = Path(sys.prefix).resolve()
    if tool_directory is not None:
        tool_prefix = (tool_directory / "mitsu").resolve()
        try:
            prefix.relative_to(tool_prefix)
        except ValueError:
            pass
        else:
            manager = "uv_tool"
    if manager != "uv_tool" and checkout_path is not None:
        try:
            prefix.relative_to((checkout_path / ".venv").resolve())
        except ValueError:
            pass
        else:
            manager = "uv_project"

    return Installation(
        kind=kind,
        manager=manager,
        current_version=current_version,
        checkout_path=checkout_path,
        repository_url=repository_url,
        requested_revision=str(requested_revision) if requested_revision else None,
        installed_commit=str(installed_commit) if installed_commit else None,
    )


def compare_versions(left: str, right: str) -> int:
    left_match = _VERSION_PATTERN.search(left)
    right_match = _VERSION_PATTERN.search(right)
    if not left_match or not right_match:
        raise ValueError("Could not parse a Mitsu version.")
    left_parts = tuple(int(part) for part in re.findall(r"\d+", left_match.group(1)))
    right_parts = tuple(int(part) for part in re.findall(r"\d+", right_match.group(1)))
    width = max(len(left_parts), len(right_parts))
    left_parts += (0,) * (width - len(left_parts))
    right_parts += (0,) * (width - len(right_parts))
    return (left_parts > right_parts) - (left_parts < right_parts)


def _fetch_json(url: str) -> dict:
    request = Request(url, headers={"User-Agent": "Mitsu updater"})
    try:
        with urlopen(request, timeout=12) as response:
            return json.loads(response.read(1024 * 1024).decode("utf-8"))
    except Exception as error:
        raise UpdateError(f"Could not check for updates: {error}") from error


def _git_tracking_ref(path: Path) -> tuple[str, str]:
    branch = _run(["git", "branch", "--show-current"], cwd=path)
    branch_name = branch.stdout.strip() if branch.returncode == 0 else ""
    if branch_name:
        upstream = _run(
            ["git", "for-each-ref", "--format=%(upstream:short)", f"refs/heads/{branch_name}"],
            cwd=path,
        )
        upstream_name = upstream.stdout.strip()
        if upstream_name and "/" in upstream_name:
            remote, remote_branch = upstream_name.split("/", 1)
            return remote, f"refs/heads/{remote_branch}"
    return "origin", "refs/heads/main"


def _remote_commit(repository: str, ref: str) -> str | None:
    result = _run(["git", "ls-remote", repository, ref], timeout=20)
    if result.returncode != 0:
        raise UpdateError("Could not reach the Git remote.")
    line = next((line for line in result.stdout.splitlines() if line.strip()), "")
    return line.split()[0] if line else None


def _is_ancestor(path: Path, ancestor: str, descendant: str) -> bool:
    result = _run(["git", "merge-base", "--is-ancestor", ancestor, descendant], cwd=path)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise UpdateError("Could not compare this checkout with its update source.")


def check_for_updates(installation: Installation) -> UpdateCheck:
    if installation.kind == "pypi":
        data = _fetch_json(PYPI_RELEASE_URL)
        latest = str(data.get("info", {}).get("version", ""))
        if not _VERSION_PATTERN.fullmatch(latest):
            raise UpdateError("PyPI returned an invalid Mitsu version.")
        available = compare_versions(latest, installation.current_version) > 0
        detail = (
            f"Mitsu v{latest} is available from PyPI."
            if available
            else f"You’re up to date on PyPI: v{installation.current_version}."
        )
        return UpdateCheck(installation, available, latest_version=latest, detail=detail)

    if installation.kind == "checkout" and installation.checkout_path:
        repository, ref = _git_tracking_ref(installation.checkout_path)
        fetch = _run(
            ["git", "fetch", "--quiet", repository, ref.removeprefix("refs/heads/")],
            cwd=installation.checkout_path,
            timeout=60,
        )
        if fetch.returncode != 0:
            raise UpdateError("Could not fetch the checkout’s update source.")
        remote = _run(["git", "rev-parse", "FETCH_HEAD"], cwd=installation.checkout_path)
        local = _run(["git", "rev-parse", "HEAD"], cwd=installation.checkout_path)
        if local.returncode != 0 or not local.stdout.strip() or remote.returncode != 0:
            raise UpdateError("Could not read this checkout’s current Git revision.")
        remote_commit = remote.stdout.strip()
        local_commit = local.stdout.strip()
        if remote_commit == local_commit:
            return UpdateCheck(
                installation,
                False,
                remote_commit=remote_commit,
                detail=f"This checkout is up to date at v{installation.current_version}.",
            )
        status = _run(["git", "status", "--porcelain"], cwd=installation.checkout_path)
        if status.returncode != 0:
            raise UpdateError("Could not check this checkout’s local changes.")
        if status.stdout.strip():
            return UpdateCheck(
                installation,
                False,
                remote_commit=remote_commit,
                detail="An update is available, but this checkout has local changes. Save them before updating.",
            )
        available = remote_commit != local_commit and _is_ancestor(
            installation.checkout_path, local_commit, remote_commit
        )
        if available:
            detail = f"A newer Git revision is available ({remote_commit[:8]})."
        elif remote_commit == local_commit:
            detail = f"This checkout is up to date at v{installation.current_version}."
        elif _is_ancestor(installation.checkout_path, remote_commit, local_commit):
            detail = "This checkout is ahead of its remote; it has no incoming changes."
        else:
            detail = "This checkout and its remote have diverged; reconcile the Git history manually."
        return UpdateCheck(
            installation,
            available,
            remote_commit=remote_commit,
            detail=detail,
        )

    if installation.kind == "git" and installation.repository_url:
        revision = installation.requested_revision
        if revision and re.fullmatch(r"[0-9a-fA-F]{40}", revision):
            return UpdateCheck(
                installation,
                False,
                detail="This Git install is pinned to a commit; reinstall it from a branch to update it.",
            )
        ref = f"refs/heads/{revision}" if revision else "HEAD"
        remote_commit = _remote_commit(installation.repository_url, ref)
        if revision and remote_commit is None:
            tag_commit = _remote_commit(installation.repository_url, f"refs/tags/{revision}")
            if tag_commit:
                return UpdateCheck(
                    installation,
                    False,
                    detail="This Git install is pinned to a tag; install from a branch to receive updates.",
                )
        available = bool(remote_commit and installation.installed_commit != remote_commit)
        detail = (
            f"A newer Git revision is available ({remote_commit[:8]})."
            if available and remote_commit
            else f"This Git install is up to date at v{installation.current_version}."
        )
        return UpdateCheck(installation, available, remote_commit=remote_commit, detail=detail)

    raise UpdateError("Mitsu could not identify this installation source.")


def _require_success(args: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> None:
    result = _run(args, cwd=cwd, timeout=timeout)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "The update command failed."
        detail = re.sub(r"(https?://)[^/@\s]*@", r"\1***@", detail)
        raise UpdateError(detail[-1200:])


def _update_checkout(installation: Installation) -> None:
    path = installation.checkout_path
    if path is None or not (path / ".git").exists():
        raise UpdateError("The Git checkout could not be found.")
    status = _run(["git", "status", "--porcelain"], cwd=path)
    if status.returncode != 0:
        raise UpdateError("Could not check the Git checkout status.")
    if status.stdout.strip():
        raise UpdateError("This checkout has local changes. Save or commit them before updating.")
    remote, ref = _git_tracking_ref(path)
    _require_success(["git", "fetch", "--prune", remote, ref.removeprefix("refs/heads/")], cwd=path)
    relation = _run(["git", "merge-base", "--is-ancestor", "HEAD", "FETCH_HEAD"], cwd=path)
    if relation.returncode == 1:
        raise UpdateError("The checkout cannot fast-forward to the remote. Reconcile its Git history manually.")
    if relation.returncode != 0:
        raise UpdateError("Could not compare the checkout with its remote.")
    _require_success(["git", "merge", "--ff-only", "FETCH_HEAD"], cwd=path)

    uv = shutil.which("uv")
    if installation.manager == "uv_tool" and uv:
        _require_success([uv, "tool", "install", "--force", "--reinstall", str(path)])
    elif installation.manager == "uv_project" and uv:
        _require_success([uv, "sync", "--project", str(path)])
    else:
        _require_success(
            [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall", str(path)]
        )


def apply_update(installation: Installation) -> None:
    if installation.kind == "checkout":
        _update_checkout(installation)
        return

    uv = shutil.which("uv")
    if installation.manager == "uv_tool" and uv:
        if installation.kind == "pypi":
            _require_success([uv, "tool", "upgrade", "mitsu"])
            return
        if installation.kind == "git" and installation.repository_url:
            requirement = "mitsu @ git+" + installation.repository_url
            if installation.requested_revision:
                requirement += "@" + installation.requested_revision
            _require_success([uv, "tool", "install", "--force", "--reinstall", requirement])
            return
    if installation.kind == "pypi":
        _require_success([sys.executable, "-m", "pip", "install", "--upgrade", "mitsu"])
        return
    if installation.kind == "git" and installation.repository_url:
        requirement = "mitsu @ git+" + installation.repository_url
        if installation.requested_revision:
            requirement += "@" + installation.requested_revision
        _require_success(
            [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall", requirement]
        )
        return
    raise UpdateError("No safe updater is available for this installation.")
