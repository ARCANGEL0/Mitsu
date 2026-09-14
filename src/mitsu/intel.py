"""Structured, session-local assessment intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from typing import Any


ASSET_TYPES = {
    "target",
    "domain",
    "hostname",
    "ip",
    "url",
    "service",
    "endpoint",
    "technology",
    "account",
    "other",
}
CONFIDENCE_LEVELS = {"low", "medium", "high", "unknown"}
ASSET_VERIFICATION_STATES = {"discovered", "validated", "rejected"}
SCOPE_STATES = {"unknown", "in_scope", "out_of_scope"}
FINDING_SEVERITIES = {"critical", "high", "medium", "low", "informational", "unknown"}
FINDING_STATES = {"lead", "confirmed", "false_positive", "remediated"}
EXPLOIT_STATES = {"candidate", "confirmed"}
MAX_ASSETS = 2_000
MAX_FINDINGS = 1_000
MAX_OBSERVATIONS = 4_000
MAX_EXPLOITS = 1_000
MAX_EVIDENCE_PER_RECORD = 100


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _stable_id(*parts: str) -> str:
    material = "\0".join(part.strip().casefold() for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _guess_asset_type(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if "/" not in value and "." in value:
            return "domain"
        return "target"
    return "ip"


def empty_intel() -> dict[str, Any]:
    return {"schema_version": 1, "assets": [], "observations": [], "findings": [], "exploits": []}


def ensure_intel(session: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Normalize the structured store and migrate the old sidebar lists once."""
    changed = False
    value = session.get("intel")
    if not isinstance(value, dict):
        value = empty_intel()
        session["intel"] = value
        changed = True
    value.setdefault("schema_version", 1)
    if not isinstance(value.get("assets"), list):
        value["assets"] = []
        changed = True
    if not isinstance(value.get("findings"), list):
        value["findings"] = []
        changed = True
    if not isinstance(value.get("observations"), list):
        value["observations"] = []
        changed = True
    if not isinstance(value.get("exploits"), list):
        value["exploits"] = []
        changed = True

    # Older sessions kept scope, IPs, and findings in independent string lists.
    known = {
        (str(item.get("type", "")).casefold(), str(item.get("value", "")).casefold())
        for item in value["assets"]
        if isinstance(item, dict)
    }
    by_value = {
        str(item.get("value", "")).casefold(): item
        for item in value["assets"]
        if isinstance(item, dict) and item.get("value")
    }
    now = _now()
    for target in session.get("targets", []) if isinstance(session.get("targets"), list) else []:
        target_value = str(target).strip()
        asset_type = _guess_asset_type(target_value)
        key = (asset_type, target_value.casefold())
        existing = by_value.get(target_value.casefold())
        if target_value and existing is not None:
            if existing.get("scope") != "in_scope":
                existing["scope"] = "in_scope"
                changed = True
        elif target_value and key not in known:
            value["assets"].append(
                {
                    "id": _stable_id(asset_type, target_value),
                    "type": asset_type,
                    "value": target_value,
                    "parent": "",
                    "verification": "validated",
                    "scope": "in_scope",
                    "confidence": "high",
                    "attributes": {},
                    "evidence": [{
                        "source": "Earlier session target list",
                        "details": "Migrated from the session's previous authorized-target list.",
                        "confidence": "high",
                        "recorded_at": now,
                    }],
                    "first_seen": now,
                    "updated_at": now,
                }
            )
            known.add(key)
            by_value[target_value.casefold()] = value["assets"][-1]
            changed = True
    for ip in session.get("ips", []) if isinstance(session.get("ips"), list) else []:
        ip_value = str(ip).strip()
        key = ("ip", ip_value.casefold())
        if ip_value and key not in known:
            value["assets"].append(
                {
                    "id": _stable_id("ip", ip_value),
                    "type": "ip",
                    "value": ip_value,
                    "parent": "",
                    "verification": "discovered",
                    "scope": "unknown",
                    "confidence": "unknown",
                    "attributes": {},
                    "evidence": [{
                        "source": "Earlier session IP list",
                        "details": "Migrated from the session's previous IP list; scope was not recorded.",
                        "confidence": "unknown",
                        "recorded_at": now,
                    }],
                    "first_seen": now,
                    "updated_at": now,
                }
            )
            known.add(key)
            by_value[ip_value.casefold()] = value["assets"][-1]
            changed = True

    findings = value["findings"]
    existing_finding_titles = {
        str(item.get("title", "")).casefold()
        for item in findings
        if isinstance(item, dict)
    }
    for legacy in session.get("findings", []) if isinstance(session.get("findings"), list) else []:
        if isinstance(legacy, dict):
            continue
        title = str(legacy).strip()
        if title and title.casefold() not in existing_finding_titles:
            findings.append(
                {
                    "id": _stable_id("legacy-finding", title),
                    "title": title[:240],
                    "asset": "",
                    "severity": "unknown",
                    "status": "lead",
                    "summary": title[:2_000],
                    "recommendation": "",
                    "confidence": "unknown",
                    "evidence": [],
                    "first_seen": now,
                    "updated_at": now,
                }
            )
            existing_finding_titles.add(title.casefold())
            changed = True
    known_exploits = {
        str(item.get("legacy_value", "")).casefold()
        for item in value["exploits"]
        if isinstance(item, dict)
    }
    for legacy in session.get("exploits", []) if isinstance(session.get("exploits"), list) else []:
        rendered = str(legacy).strip()
        lowered = rendered.casefold()
        is_unverified_reference = "[edb-" in lowered and "[candidate]" not in lowered and "[confirmed]" not in lowered
        if rendered and not is_unverified_reference and lowered not in known_exploits:
            status = "candidate"
            title = rendered
            asset = ""
            evidence_text = rendered
            if rendered.startswith(("[CANDIDATE] ", "[CONFIRMED] ")):
                status_label, _, remainder = rendered.partition("] ")
                status = "confirmed" if status_label == "[CONFIRMED" else "candidate"
                title_part, separator, detail = remainder.partition(" · ")
                if separator:
                    title = title_part
                    asset_part, evidence_separator, evidence_part = detail.partition(" — ")
                    asset = asset_part if evidence_separator else ""
                    evidence_text = evidence_part if evidence_separator else detail
            value["exploits"].append(
                {
                    "id": _stable_id("exploit", title, asset),
                    "title": title[:240],
                    "asset": asset[:1_000],
                    "status": status,
                    "confidence": "unknown",
                    "evidence": [{
                        "source": "Earlier session exploit Intel",
                        "details": evidence_text[:4_000],
                        "confidence": "unknown",
                        "recorded_at": now,
                    }],
                    "legacy_value": rendered,
                    "first_seen": now,
                    "updated_at": now,
                }
            )
            known_exploits.add(rendered.casefold())
            changed = True
    return value, changed
