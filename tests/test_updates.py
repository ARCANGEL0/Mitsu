from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from mitsu.tui import updates


def test_versions() -> None:
    assert updates.compare_versions("1.4.21", "1.4.22") == -1
    assert updates.compare_versions("v1.5", "1.5.0") == 0


def test_bad_version() -> None:
    with pytest.raises(ValueError):
        updates.compare_versions("current", "1.5.0")


def test_pypi(monkeypatch: pytest.MonkeyPatch) -> None:
    installation = updates.Installation("pypi", "pip", "1.4.21")
    monkeypatch.setattr(updates, "_fetch_json", lambda _url: {"info": {"version": "1.4.22"}})

    result = updates.check_for_updates(installation)

    assert result.available
    assert result.latest_version == "1.4.22"


def test_uvtool(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(updates.shutil, "which", lambda name: "/usr/bin/uv" if name == "uv" else None)
    monkeypatch.setattr(updates, "_require_success", lambda args, **_kwargs: commands.append(args))

    updates.apply_update(updates.Installation("pypi", "uv_tool", "1.4.21"))

    assert commands == [["/usr/bin/uv", "tool", "upgrade", "mitsu"]]


def test_dirty(tmp_path: Path) -> None:
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Mitsu test"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "mitsu-test@example.invalid"],
        check=True,
    )
    (tmp_path / "tracked.txt").write_text("original", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "initial"], check=True, capture_output=True)
    (tmp_path / "tracked.txt").write_text("local edit", encoding="utf-8")

    installation = updates.Installation(
        "checkout",
        "pip",
        "1.4.21",
        checkout_path=tmp_path,
    )

    with pytest.raises(updates.UpdateError, match="local changes"):
        updates._update_checkout(installation)
