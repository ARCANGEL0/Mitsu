"""Persistent credential, preference, and session stores."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
import re
import tempfile
from typing import Any

from .catalog import PROVIDERS, PROVIDER_BY_ID, THEMES


def _config_root() -> Path:
    configured = os.environ.get("XDG_CONFIG_HOME")
    return (Path(configured) if configured else Path.home() / ".config") / "mitsu"


def _data_root() -> Path:
    configured = os.environ.get("XDG_DATA_HOME")
    return (Path(configured) if configured else Path.home() / ".local" / "share") / "mitsu"


def _read_json(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback.copy()
    return value if isinstance(value, dict) else fallback.copy()


def _atomic_json(path: Path, value: dict[str, Any], private: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o755)
    if private:
        path.parent.chmod(0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".mitsu-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        if private:
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if private:
            path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


class CredentialStore:
    def __init__(self) -> None:
        self.path = _config_root() / "credentials.json"

    def load(self) -> dict[str, Any]:
        return _read_json(self.path, {"active_provider": None, "providers": {}})

    def active(self) -> dict[str, Any] | None:
        data = self.load()
        provider_id = data.get("active_provider")
        return self.profile_for(str(provider_id)) if provider_id else None

    def profile_for(self, provider_id: str) -> dict[str, Any] | None:
        data = self.load()
        providers = data.get("providers")
        profile = providers.get(provider_id) if isinstance(providers, dict) else None
        if not isinstance(profile, dict):
            return None
        return {**profile, "provider_id": provider_id}

    def configured_profiles(self) -> list[dict[str, Any]]:
        data = self.load()
        profiles = data.get("providers")
        if not isinstance(profiles, dict):
            return []
        configured = []
        for spec in PROVIDERS:
            profile = profiles.get(spec.id)
            if not isinstance(profile, dict):
                continue
            # LiteLLM routes by model ID and needs a base URL only for self-hosted endpoints.
            if not profile.get("base_url") and spec.protocol != "litellm":
                continue
            if spec.requires_api_key and not profile.get("api_key"):
                continue
            if spec.id == "cloudflare" and "{account_id}" in str(profile.get("base_url", "")):
                continue
            configured.append({**profile, "provider_id": spec.id})
        return configured

    def ready(self) -> bool:
        profile = self.active()
        if not profile or not profile.get("model"):
            return False
        if not profile.get("base_url") and profile.get("protocol") != "litellm":
            return False
        spec = PROVIDER_BY_ID.get(str(profile.get("provider_id")))
        if not spec:
            return False
        if spec.requires_api_key and not profile.get("api_key"):
            return False
        return True

    def save_profile(self, profile: dict[str, Any]) -> None:
        provider_id = str(profile["provider_id"])
        data = self.load()
        providers = data.get("providers")
        if not isinstance(providers, dict):
            providers = {}
        previous = providers.get(provider_id)
        if not profile.get("api_key") and isinstance(previous, dict):
            profile["api_key"] = previous.get("api_key", "")
        providers[provider_id] = {
            key: profile.get(key, "")
            for key in (
                "base_url",
                "model",
                "api_key",
                "protocol",
                "reasoning_enabled",
                "reasoning_parameter",
                "reasoning_effort",
            )
        }
        data["active_provider"] = provider_id
        data["providers"] = providers
        _atomic_json(self.path, data, private=True)

    def search_engines(self) -> dict[str, dict[str, Any]]:
        engines = self.load().get("search_engines", {})
        if not isinstance(engines, dict):
            return {}
        return {
            str(engine_id): dict(settings)
            for engine_id, settings in engines.items()
            if isinstance(settings, dict)
        }

    def save_search_engines(self, engines: dict[str, dict[str, Any]]) -> None:
        data = self.load()
        data["search_engines"] = {
            str(engine_id): dict(settings)
            for engine_id, settings in engines.items()
            if isinstance(settings, dict)
        }
        _atomic_json(self.path, data, private=True)


class PreferencesStore:
    def __init__(self) -> None:
        self.path = _config_root() / "settings.json"

    def load(self) -> dict[str, Any]:
        data = _read_json(self.path, {})
        data.setdefault("theme", "ember")
        data.setdefault("companion", "mitsu")
        data.setdefault("onboarding_complete", False)
        return data

    def save(self, values: dict[str, Any]) -> None:
        current = self.load()
        current.update(values)
        _atomic_json(self.path, current, private=False)


class SessionStore:
    SESSION_ID = re.compile(r"[a-f0-9]{32}")

    def __init__(self) -> None:
        self.path = _data_root() / "sessions"

    def list_sessions(self) -> list[dict[str, Any]]:
        from datetime import datetime, timezone

        self._ensure_private_directory()
        sessions: list[dict[str, Any]] = []
        for session_path in self.path.glob("*.json"):
            if not self.SESSION_ID.fullmatch(session_path.stem):
                continue
            record = _read_json(session_path, {})
            if record.get("id") == session_path.stem:
                sessions.append(record)

        def session_order(record: dict[str, Any]) -> tuple[datetime, str]:
            for field in ("updated_at", "created_at"):
                try:
                    updated = datetime.fromisoformat(str(record.get(field, "")))
                except (TypeError, ValueError):
                    continue
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
                return updated.astimezone(timezone.utc), str(record.get("id", ""))
            return datetime.min.replace(tzinfo=timezone.utc), str(record.get("id", ""))

        return sorted(sessions, key=session_order, reverse=True)

    def load_session(self, session_id: str) -> dict[str, Any] | None:
        if not self.SESSION_ID.fullmatch(session_id):
            return None
        record = _read_json(self.path / f"{session_id}.json", {})
        return record if record.get("id") == session_id else None

    def delete_session(self, session_id: str) -> bool:
        if not self.SESSION_ID.fullmatch(session_id):
            return False
        path = self.path / f"{session_id}.json"
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        attachments = self.path / f"{session_id}.images"
        if attachments.is_symlink():
            attachments.unlink(missing_ok=True)
        elif attachments.is_dir():
            shutil.rmtree(attachments, ignore_errors=True)
        artifacts = self.path / session_id
        if artifacts.is_symlink():
            artifacts.unlink(missing_ok=True)
        elif artifacts.is_dir():
            shutil.rmtree(artifacts, ignore_errors=True)
        return True

    def create_session(self, provider: dict[str, Any]) -> dict[str, Any]:
        from datetime import datetime, timezone
        from uuid import uuid4

        now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        record = {
            "id": uuid4().hex,
            "title": "New session",
            "title_source": "default",
            "created_at": now,
            "updated_at": now,
            "provider_id": provider.get("provider_id", ""),
            "model": provider.get("model", ""),
            "mode": "Investigate",
            "targets": [],
            "active_target": None,
            "intel": {"schema_version": 1, "assets": [], "observations": [], "findings": [], "exploits": []},
            "messages": [],
        }
        self.save_session(record)
        return record

    def save_session(self, record: dict[str, Any]) -> None:
        from datetime import datetime, timezone

        if not self.SESSION_ID.fullmatch(str(record.get("id", ""))):
            raise ValueError("Invalid session ID.")
        record["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        self._ensure_private_directory()
        _atomic_json(self.path / f"{record['id']}.json", record, private=True)

    def _ensure_private_directory(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.chmod(0o700)
