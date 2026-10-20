from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_DEFAULT_TERMS = (
    "clickhouse",
    "jdbc:",
    "db_username",
    "db_password",
    "username",
    "password",
    "passwd",
    "secret",
    "kafka",
    "datasourceconfig",
    "spring.datasource",
)


def search_artifact(
    path: Path,
    terms: list[str] | None = None,
    context_bytes: int = 256,
    limit: int = 60,
    min_offset: int = 0,
) -> str:
    size = path.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"Artifact is {size} bytes; the limit is {MAX_ARTIFACT_BYTES} bytes.")
    data = path.read_bytes()
    requested_terms = _normalize_terms(terms)
    context_size = max(0, min(int(context_bytes), 2048))
    result_limit = max(1, min(int(limit), 20))
    offset_floor = max(0, int(min_offset))
    digest = hashlib.sha256(data).hexdigest()
    header = data[:32].split(b"\0", 1)[0].decode("ascii", errors="replace")
    format_name = header if header.startswith("JAVA PROFILE ") else "binary or text artifact"
    counts = {term: 0 for term in requested_terms}
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    for match in _PRINTABLE.finditer(data):
        start, end = match.span()
        if start < offset_floor:
            continue
        value = match.group().decode("ascii", errors="replace").strip()
        folded = value.casefold()
        matching_terms = [term for term in requested_terms if term in folded]
        if not matching_terms:
            continue
        for term in matching_terms:
            counts[term] += 1
        identity = folded
        if identity in seen:
            continue
        seen.add(identity)
        context = []
        if context_size:
            left = max(0, start - context_size)
            right = min(len(data), end + context_size)
            context = [
                item.group().decode("ascii", errors="replace").strip()[:180]
                for item in _PRINTABLE.finditer(data, left, right)
            ]
        score = sum(min(len(term), 16) for term in matching_terms)
        found.append(
            {
                "offset": start,
                "score": score,
                "terms": matching_terms,
                "text": value[:300],
                "nearby_strings": context[:6],
            }
        )

    found.sort(key=lambda item: (-item["score"], item["offset"]))
    total_matches = len(found)
    for item in found:
        item.pop("score", None)
    payload = {
        "path": path.name,
        "format": format_name,
        "size_bytes": size,
        "sha256": digest,
        "terms": counts,
        "unique_matches": total_matches,
        "returned": min(total_matches, result_limit),
        "matches": found[:result_limit],
        "truncated": total_matches > result_limit,
    }
    return json.dumps(payload, ensure_ascii=False)


def _normalize_terms(terms: list[str] | None) -> list[str]:
    source = terms if terms else list(_DEFAULT_TERMS)
    normalized = []
    seen = set()
    for value in source[:16]:
        term = str(value).strip().casefold()[:80]
        if term and term not in seen:
            normalized.append(term)
            seen.add(term)
    return normalized or list(_DEFAULT_TERMS)
