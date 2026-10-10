"""Remove common inline secrets from displayed and persisted tool arguments."""

from __future__ import annotations

import copy
import json
import re
from typing import Any


_SECRET_KEY = re.compile(r"(?:password|passwd|token|secret|api[_-]?key|credential)", re.IGNORECASE)
_SECRET_VALUE = r"(?:'[^']*'|\"[^\"]*\"|[^\s;&|]+)"
_SECRET_ASSIGNMENT = re.compile(
    rf"(?i)(\b--?(?:password|passwd|pass|token|secret|api[_-]?key)(?:\s+|=)|\b/password:|\b/p:)(\s*{_SECRET_VALUE})"
)
_SSHPASS_VALUE = re.compile(rf"(?i)(\bsshpass\s+-p\s+){_SECRET_VALUE}")
_LAB_PASSWORD_VALUE = re.compile(rf"(?i)(\bpassword\s*[:=]\s*){_SECRET_VALUE}")
_URL_CREDENTIAL = re.compile(r"(https?://[^:/\s]+:)[^@/\s]+(@)", re.IGNORECASE)


def redact_command(value: str) -> str:
    """Mask common CLI password/token forms while preserving command structure."""
    redacted = _SECRET_ASSIGNMENT.sub(r"\1[REDACTED]", value)
    redacted = _SSHPASS_VALUE.sub(r"\1[REDACTED]", redacted)
    redacted = _LAB_PASSWORD_VALUE.sub(r"\1[REDACTED]", redacted)
    return _URL_CREDENTIAL.sub(r"\1[REDACTED]\2", redacted)


def redact_value(value: Any, key: str = "") -> Any:
    """Return a recursively sanitized copy suitable for display or persistence."""
    if _SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, str):
        if key == "arguments":
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                return redact_command(value)
            return json.dumps(redact_value(decoded), ensure_ascii=False, separators=(",", ":"))
        return redact_command(value)
    if isinstance(value, list):
        redacted_items = []
        mask_next = False
        secret_flags = {"--password", "--passwd", "--pass", "--token", "--secret", "--api-key", "--api_key"}
        for item in value:
            if mask_next:
                redacted_items.append("[REDACTED]")
                mask_next = False
                continue
            redacted_items.append(redact_value(item, key))
            mask_next = isinstance(item, str) and item.casefold() in secret_flags
        return redacted_items
    if isinstance(value, tuple):
        return tuple(redact_value(item, key) for item in value)
    if isinstance(value, dict):
        return {str(item_key): redact_value(item, str(item_key)) for item_key, item in value.items()}
    return copy.deepcopy(value)


def redact_history(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitize provider history before writing it to session storage."""
    return redact_value(history)
