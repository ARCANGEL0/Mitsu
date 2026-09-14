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


def record_evidence(source: str, details: str, confidence: str) -> dict[str, str]:
    source = _required_text(source, "source", 500)
    details = _required_text(details, "evidence", 8_000)
    confidence = _choice(confidence, CONFIDENCE_LEVELS, "confidence")
    return {
        "source": source,
        "details": details,
        "confidence": confidence,
        "recorded_at": _now(),
    }


def upsert_asset(
    intel: dict[str, Any],
    *,
    asset_type: str,
    value: str,
    source: str,
    evidence: str,
    parent: str = "",
    verification: str | None = None,
    scope: str | None = None,
    confidence: str = "medium",
    attributes: dict[str, str] | None = None,
    primary: bool = False,
) -> tuple[dict[str, Any], bool]:
    asset_type = _choice(asset_type, ASSET_TYPES, "asset type")
    value = _required_text(value, "asset value", 1_000)
    parent = parent.strip()[:1_000]
    if any(ord(character) < 32 for character in value + parent):
        raise ValueError("asset values and parents cannot contain control characters")
    if verification is not None:
        verification = _choice(verification, ASSET_VERIFICATION_STATES, "verification status")
    confidence = _choice(confidence, CONFIDENCE_LEVELS, "confidence")
    if scope is not None:
        scope = _choice(scope, SCOPE_STATES, "scope status")
    if primary and scope != "in_scope":
        raise ValueError("a primary target must be explicitly marked in_scope")
    if attributes is None:
        attributes = {}
    if not isinstance(attributes, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in attributes.items()
    ):
        raise ValueError("attributes must be a string-to-string object")
    if len(attributes) > 64 or any(len(key) > 100 or len(item) > 2_000 for key, item in attributes.items()):
        raise ValueError("attributes may contain at most 64 short string values")

    entries = intel["assets"]
    asset = next(
        (
            item
            for item in entries
            if isinstance(item, dict)
            and str(item.get("type", "")).casefold() == asset_type
            and str(item.get("value", "")).casefold() == value.casefold()
            and str(item.get("parent", "")).casefold() == parent.casefold()
        ),
        None,
    )
    now = _now()
    evidence_record = record_evidence(source, evidence, confidence)
    created = asset is None
    if asset is None:
        if len(entries) >= MAX_ASSETS:
            raise ValueError(f"session Intel already contains the maximum of {MAX_ASSETS} assets")
        asset = {
            "id": _stable_id(asset_type, value, parent),
            "type": asset_type,
            "value": value,
            "parent": parent,
            "verification": verification or "discovered",
            "scope": scope or "unknown",
            "confidence": confidence,
            "attributes": {},
            "evidence": [],
            "first_seen": now,
        }
        entries.append(asset)
    else:
        if verification is not None:
            asset["verification"] = verification
        asset["confidence"] = confidence
        if scope is not None:
            asset["scope"] = scope
    if primary:
        for item in entries:
            if isinstance(item, dict) and item is not asset:
                item["primary"] = False
    elif scope == "out_of_scope":
        asset["primary"] = False
    asset.setdefault("attributes", {}).update(attributes)
    evidence_items = asset.setdefault("evidence", [])
    if not any(
        item.get("source") == evidence_record["source"] and item.get("details") == evidence_record["details"]
        for item in evidence_items
        if isinstance(item, dict)
    ):
        evidence_items.append(evidence_record)
        del evidence_items[:-MAX_EVIDENCE_PER_RECORD]
    asset["primary"] = primary if primary else bool(asset.get("primary", False))
    asset["updated_at"] = now
    return asset, created
