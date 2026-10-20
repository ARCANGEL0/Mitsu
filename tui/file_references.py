from __future__ import annotations

import os
import shlex
from pathlib import Path
from urllib.parse import unquote, urlsplit


_SKIPPED_DIRECTORIES = {".git", ".venv", "__pycache__", "node_modules", "venv"}


def workspace_file_index(root: Path | None = None) -> list[Path]:
    root = (root or Path.cwd()).resolve()
    paths: list[Path] = []
    for directory, names, files in os.walk(root):
        names[:] = sorted(
            name for name in names
            if name not in _SKIPPED_DIRECTORIES and not name.startswith(".")
        )
        for name in sorted(files):
            paths.append(Path(directory, name))
            if len(paths) >= 20000:
                return paths
    return paths


def workspace_files(
    index: list[Path], query: str, limit: int = 8, root: Path | None = None
) -> list[Path]:
    root = (root or Path.cwd()).resolve()
    needle = query.casefold()
    matches: list[Path] = []
    for path in index:
        relative = path.relative_to(root).as_posix()
        if not needle.startswith(".") and any(part.startswith(".") for part in Path(relative).parts):
            continue
        if needle not in relative.casefold():
            continue
        matches.append(path)
        if len(matches) >= limit:
            break
    return matches


def normalize_file_paste(value: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    uris = [line for line in lines if line.startswith("file://")]
    if not uris or any(not line.startswith(("file://", "#")) for line in lines):
        return value
    paths: list[str] = []
    for uri in uris:
        parsed = urlsplit(uri)
        if parsed.netloc not in {"", "localhost"}:
            continue
        path = unquote(parsed.path)
        if path and Path(path).is_file():
            paths.append(shlex.quote(path))
    return " ".join(paths) if paths else value


def file_reference_at_cursor(
    value: str, cursor: tuple[int, int]
) -> tuple[int, int, str] | None:
    row, column = cursor
    lines = value.splitlines(keepends=True)
    offset = sum(len(line) for line in lines[:row]) + column
    prefix = value[:offset]
    start = prefix.rfind("@")
    if start < 0 or (start and not prefix[start - 1].isspace()):
        return None
    query = prefix[start + 1:]
    if any(character.isspace() for character in query):
        return None
    end = start + 1
    while end < len(value) and not value[end].isspace():
        end += 1
    return start, end, query


def quote_path(path: Path) -> str:
    value = str(path.resolve())
    return shlex.quote(value) if any(character.isspace() for character in value) else value
