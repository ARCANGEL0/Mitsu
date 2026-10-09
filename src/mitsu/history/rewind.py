"""Capture and restore conversation-linked workspace changes."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import stat
import tempfile
from typing import Mapping


_SKIP_DIRECTORIES = {
    ".git",
    ".mitsu",
    ".aws",
    ".gnupg",
    ".pytest_cache",
    ".ruff_cache",
    ".secrets",
    ".ssh",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_WORKSPACE_BYTES = 64 * 1024 * 1024
_MAX_DELTA_BYTES = 8 * 1024 * 1024


def _is_sensitive(path: Path) -> bool:
    name = path.name.casefold()
    return (
        name.startswith(".env")
        or name in {
            "id_rsa",
            "id_ed25519",
            "credentials",
            "credentials.json",
            "secrets.json",
            "tokens.json",
            "backup-codes.txt",
            "backup_codes.txt",
        }
        or name.endswith((".pem", ".key", ".p12", ".pfx"))
    )


def capture_workspace(root: Path) -> dict[str, bytes] | None:
    """Capture bounded regular files for a per-turn undo point; never follow symlinks."""
    root = root.resolve()
    snapshot: dict[str, bytes] = {}
    total = 0
    for directory, names, filenames in os.walk(root, followlinks=False):
        names[:] = sorted(
            name
            for name in names
            if name not in _SKIP_DIRECTORIES and not (Path(directory) / name).is_symlink()
        )
        for filename in filenames:
            path = Path(directory) / filename
            if path.is_symlink() or _is_sensitive(path):
                continue
            try:
                metadata = path.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                size = metadata.st_size
                if size > _MAX_FILE_BYTES or total + size > _MAX_WORKSPACE_BYTES:
                    return None
                content = path.read_bytes()
            except OSError:
                return None
            total += len(content)
            snapshot[path.relative_to(root).as_posix()] = content
    return snapshot


def diff_workspace(
    before: Mapping[str, bytes] | None,
    after: Mapping[str, bytes] | None,
) -> dict[str, str | None] | None:
    """Return base64 before-images for changed files, or None if snapshots are incomplete."""
    if before is None or after is None:
        return None
    changed: dict[str, str | None] = {}
    total = 0
    for relative_path in before.keys() | after.keys():
        old = before.get(relative_path)
        new = after.get(relative_path)
        if old == new:
            continue
        if old is None:
            changed[relative_path] = None
        else:
            total += len(old)
            if total > _MAX_DELTA_BYTES:
                return None
            changed[relative_path] = base64.b64encode(old).decode("ascii")
    return changed


def apply_undo_changes(root: Path, change_sets: list[dict[str, str | None]]) -> list[str]:
    """Apply ordered before-images beneath root; return paths that could not be restored."""
    root = root.resolve()
    failed: list[str] = []
    for changes in change_sets:
        for relative_path, encoded in changes.items():
            relative = Path(relative_path)
            if relative.is_absolute() or ".." in relative.parts:
                failed.append(relative_path)
                continue
            path = root / relative
            parent = path.parent
            try:
                if path.is_symlink() or not parent.resolve().is_relative_to(root):
                    failed.append(relative_path)
                    continue
                parent.mkdir(parents=True, exist_ok=True)
                if not parent.resolve().is_relative_to(root) or path.is_symlink():
                    failed.append(relative_path)
                    continue
                if encoded is None:
                    if path.exists():
                        path.unlink()
                    continue
                content = base64.b64decode(encoded, validate=True)
                with tempfile.NamedTemporaryFile(dir=parent, delete=False) as stream:
                    temporary = Path(stream.name)
                    stream.write(content)
                temporary.replace(path)
            except (OSError, ValueError):
                failed.append(relative_path)
    return failed
