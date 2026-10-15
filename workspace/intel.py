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
    "nameserver",
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
OBSERVATION_STATES = {"draft", "active", "unverified", "validated", "rejected", "resolved"}
ACCOUNT_TYPES = {"user", "group", "service", "token", "credential", "flag", "other"}
SECRET_TYPES = {"password", "token", "hash", "key", "flag", "other"}
ACCOUNT_STATES = {"discovered", "validated", "rejected"}
MANHUNT_TYPES = {"name", "email", "phone", "social", "organization", "location", "other"}
MAX_ASSETS = 2_000
MAX_FINDINGS = 1_000
MAX_OBSERVATIONS = 4_000
MAX_EXPLOITS = 1_000
MAX_ACCOUNTS = 2_000
MAX_MANHUNT = 2_000
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
    return {
        "schema_version": 2,
        "assets": [],
        "observations": [],
        "findings": [],
        "exploits": [],
        "accounts": [],
        "manhunt": [],
    }


def ensure_intel(session: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Normalize the structured store and migrate the old sidebar lists once."""
    changed = False
    value = session.get("intel")
    if not isinstance(value, dict):
        value = empty_intel()
        session["intel"] = value
        changed = True
    if value.get("schema_version") != 2:
        value["schema_version"] = 2
        changed = True
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
    if not isinstance(value.get("accounts"), list):
        value["accounts"] = []
        changed = True
    if not isinstance(value.get("manhunt"), list):
        value["manhunt"] = []
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


def upsert_finding(
    intel: dict[str, Any],
    *,
    title: str,
    asset: str,
    severity: str,
    status: str,
    summary: str,
    source: str,
    evidence: str,
    recommendation: str = "",
    confidence: str = "medium",
) -> tuple[dict[str, Any], bool]:
    title = _required_text(title, "finding title", 240)
    asset = asset.strip()[:1_000]
    severity = _choice(severity, FINDING_SEVERITIES, "severity")
    status = _choice(status, FINDING_STATES, "finding status")
    summary = _required_text(summary, "finding summary", 4_000)
    recommendation = recommendation.strip()[:4_000]
    confidence = _choice(confidence, CONFIDENCE_LEVELS, "confidence")
    evidence_record = record_evidence(source, evidence, confidence)

    entries = intel["findings"]
    finding = next(
        (
            item
            for item in entries
            if isinstance(item, dict)
            and str(item.get("title", "")).casefold() == title.casefold()
            and str(item.get("asset", "")).casefold() == asset.casefold()
        ),
        None,
    )
    now = _now()
    created = finding is None
    if finding is None:
        if len(entries) >= MAX_FINDINGS:
            raise ValueError(f"session Intel already contains the maximum of {MAX_FINDINGS} findings")
        finding = {
            "id": _stable_id("finding", title, asset),
            "title": title,
            "asset": asset,
            "evidence": [],
            "first_seen": now,
        }
        entries.append(finding)
    finding.update(
        {
            "severity": severity,
            "status": status,
            "summary": summary,
            "recommendation": recommendation,
            "confidence": confidence,
        }
    )
    evidence_items = finding.setdefault("evidence", [])
    if not any(
        item.get("source") == evidence_record["source"] and item.get("details") == evidence_record["details"]
        for item in evidence_items
        if isinstance(item, dict)
    ):
        evidence_items.append(evidence_record)
        del evidence_items[:-MAX_EVIDENCE_PER_RECORD]
    finding["updated_at"] = now
    return finding, created


def upsert_observation(
    intel: dict[str, Any],
    *,
    title: str,
    asset: str,
    category: str,
    status: str,
    details: str,
    source: str,
    confidence: str = "medium",
    worked: str = "",
    failed: str = "",
    next_step: str = "",
) -> tuple[dict[str, Any], bool]:
    title = _required_text(title, "observation title", 240)
    asset = asset.strip()[:1_000]
    category = _choice(
        category,
        {"recon", "service", "authentication", "behavior", "configuration", "exploit", "credentials", "pivot", "enumeration", "workflow", "other"},
        "observation category",
    )
    status = _choice(status, OBSERVATION_STATES, "observation status")
    details = _required_text(details, "observation details", 8_000)
    worked = worked.strip()[:2_000]
    failed = failed.strip()[:2_000]
    next_step = next_step.strip()[:2_000]
    confidence = _choice(confidence, CONFIDENCE_LEVELS, "confidence")
    evidence_record = record_evidence(source, details, confidence)

    entries = intel["observations"]
    observation = next(
        (
            item
            for item in entries
            if isinstance(item, dict)
            and str(item.get("title", "")).casefold() == title.casefold()
            and str(item.get("asset", "")).casefold() == asset.casefold()
        ),
        None,
    )
    now = _now()
    created = observation is None
    if observation is None:
        if len(entries) >= MAX_OBSERVATIONS:
            raise ValueError(f"session Intel already contains the maximum of {MAX_OBSERVATIONS} observations")
        observation = {
            "id": _stable_id("observation", title, asset),
            "title": title,
            "asset": asset,
            "evidence": [],
            "first_seen": now,
        }
        entries.append(observation)
    observation.update(
        {
            "category": category,
            "status": status,
            "confidence": confidence,
            "details": details,
            "worked": worked,
            "failed": failed,
            "next_step": next_step,
            "source": source,
        }
    )
    evidence_items = observation.setdefault("evidence", [])
    if not any(
        item.get("source") == evidence_record["source"] and item.get("details") == evidence_record["details"]
        for item in evidence_items
        if isinstance(item, dict)
    ):
        evidence_items.append(evidence_record)
        del evidence_items[:-MAX_EVIDENCE_PER_RECORD]
    observation["updated_at"] = now
    return observation, created


def upsert_exploit(
    intel: dict[str, Any],
    *,
    title: str,
    asset: str,
    evidence: str,
    status: str,
    summary: str = "",
    source: str = "Mitsu session analysis",
) -> tuple[dict[str, Any], bool]:
    title = _required_text(title, "exploit title", 240)
    asset = _required_text(asset, "affected asset", 1_000)
    evidence = _required_text(evidence, "exploit evidence", 4_000)
    status = _choice(status, EXPLOIT_STATES, "exploit status")
    summary = summary.strip()[:4_000]
    evidence_record = record_evidence(source or "Mitsu session analysis", evidence, "high" if status == "confirmed" else "medium")
    entries = intel["exploits"]
    exploit = next(
        (
            item for item in entries
            if isinstance(item, dict)
            and str(item.get("title", "")).casefold() == title.casefold()
            and str(item.get("asset", "")).casefold() == asset.casefold()
        ),
        None,
    )
    now = _now()
    created = exploit is None
    if exploit is None:
        if len(entries) >= MAX_EXPLOITS:
            raise ValueError(f"session Intel already contains the maximum of {MAX_EXPLOITS} exploit records")
        exploit = {
            "id": _stable_id("exploit", title, asset),
            "title": title,
            "asset": asset,
            "evidence": [],
            "first_seen": now,
        }
        entries.append(exploit)
    exploit["status"] = status
    exploit["confidence"] = "high" if status == "confirmed" else "medium"
    if summary:
        exploit["summary"] = summary
    exploit["source"] = source or "Mitsu session analysis"
    exploit["legacy_value"] = f"[{status.upper()}] {title} · {asset} — {evidence}"
    evidence_items = exploit.setdefault("evidence", [])
    if not any(
        item.get("source") == evidence_record["source"] and item.get("details") == evidence_record["details"]
        for item in evidence_items
        if isinstance(item, dict)
    ):
        evidence_items.append(evidence_record)
        del evidence_items[:-MAX_EVIDENCE_PER_RECORD]
    exploit["updated_at"] = now
    return exploit, created


def upsert_account(
    intel: dict[str, Any],
    *,
    name: str,
    account_type: str,
    target: str,
    secret_type: str,
    secret: str,
    access: str,
    status: str,
    details: str,
    source: str,
    evidence: str,
    confidence: str = "medium",
) -> tuple[dict[str, Any], bool]:
    name = _required_text(name, "account name", 500)
    account_type = _choice(account_type, ACCOUNT_TYPES, "account type")
    target = target.strip()[:1_000]
    secret_type = _choice(secret_type, SECRET_TYPES, "secret type")
    if not isinstance(secret, str) or len(secret) > 8_000 or "\0" in secret:
        raise ValueError("secret must be text of at most 8000 characters")
    access = access.strip()[:1_000]
    status = _choice(status, ACCOUNT_STATES, "account status")
    details = details.strip()[:4_000]
    confidence = _choice(confidence, CONFIDENCE_LEVELS, "confidence")
    evidence_record = record_evidence(source, evidence, confidence)
    entries = intel["accounts"]
    record = next(
        (
            item for item in entries
            if isinstance(item, dict)
            and str(item.get("name", "")).casefold() == name.casefold()
            and str(item.get("type", "")).casefold() == account_type
            and str(item.get("target", "")).casefold() == target.casefold()
            and str(item.get("secret_type", "")).casefold() == secret_type
        ),
        None,
    )
    now = _now()
    created = record is None
    if record is None:
        if len(entries) >= MAX_ACCOUNTS:
            raise ValueError(f"session Intel already contains the maximum of {MAX_ACCOUNTS} account records")
        record = {
            "id": _stable_id("account", name, account_type, target, secret_type),
            "first_seen": now,
            "evidence": [],
        }
        entries.append(record)
    record.update(
        {
            "name": name,
            "type": account_type,
            "target": target,
            "secret_type": secret_type,
            "secret": secret,
            "access": access,
            "status": status,
            "details": details,
            "source": source,
            "confidence": confidence,
        }
    )
    evidence_items = record.setdefault("evidence", [])
    if not any(
        item.get("source") == evidence_record["source"] and item.get("details") == evidence_record["details"]
        for item in evidence_items if isinstance(item, dict)
    ):
        evidence_items.append(evidence_record)
        del evidence_items[:-MAX_EVIDENCE_PER_RECORD]
    record["updated_at"] = now
    return record, created


def upsert_manhunt(
    intel: dict[str, Any],
    *,
    person: str,
    detail_type: str,
    value: str,
    relationship: str,
    details: str,
    source: str,
    evidence: str,
    status: str,
    confidence: str = "medium",
) -> tuple[dict[str, Any], bool]:
    person = _required_text(person, "person", 500)
    detail_type = _choice(detail_type, MANHUNT_TYPES, "manhunt detail type")
    value = _required_text(value, "person detail", 2_000)
    relationship = relationship.strip()[:1_000]
    details = details.strip()[:4_000]
    status = _choice(status, {"unverified", "validated", "rejected"}, "manhunt status")
    confidence = _choice(confidence, CONFIDENCE_LEVELS, "confidence")
    evidence_record = record_evidence(source, evidence, confidence)
    entries = intel["manhunt"]
    record = next(
        (
            item for item in entries
            if isinstance(item, dict)
            and str(item.get("person", "")).casefold() == person.casefold()
            and str(item.get("detail_type", "")).casefold() == detail_type
            and str(item.get("value", "")).casefold() == value.casefold()
        ),
        None,
    )
    now = _now()
    created = record is None
    if record is None:
        if len(entries) >= MAX_MANHUNT:
            raise ValueError(f"session Intel already contains the maximum of {MAX_MANHUNT} manhunt records")
        record = {
            "id": _stable_id("manhunt", person, detail_type, value),
            "first_seen": now,
            "evidence": [],
        }
        entries.append(record)
    record.update(
        {
            "person": person,
            "detail_type": detail_type,
            "value": value,
            "relationship": relationship,
            "details": details,
            "status": status,
            "confidence": confidence,
            "source": source,
        }
    )
    evidence_items = record.setdefault("evidence", [])
    if not any(
        item.get("source") == evidence_record["source"] and item.get("details") == evidence_record["details"]
        for item in evidence_items if isinstance(item, dict)
    ):
        evidence_items.append(evidence_record)
        del evidence_items[:-MAX_EVIDENCE_PER_RECORD]
    record["updated_at"] = now
    return record, created


def _required_text(value: str, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\0" in value:
        raise ValueError(f"{label} must be non-empty text of at most {maximum} characters")
    return value.strip()


def _choice(value: str, allowed: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise ValueError(f"{label} must be one of: {choices}")
    return value


def intel_page(intel: dict[str, Any], section: str, offset: int = 0, limit: int = 8) -> str:
    """Return a bounded JSON view so larger session maps remain readable by an LLM."""
    sections = {
        "summary", "assets", "targets", "services", "findings", "exploits",
        "domains", "ips", "accounts", "manhunt", "observations",
    }
    if section not in sections:
        raise ValueError("section must name a session Intel tab")
    offset = max(0, int(offset))
    limit = min(8, max(1, int(limit)))
    assets = [item for item in intel.get("assets", []) if isinstance(item, dict)]
    findings = [item for item in intel.get("findings", []) if isinstance(item, dict)]
    observations = [item for item in intel.get("observations", []) if isinstance(item, dict)]
    exploits = [item for item in intel.get("exploits", []) if isinstance(item, dict)]
    accounts = [item for item in intel.get("accounts", []) if isinstance(item, dict)]
    manhunt = [item for item in intel.get("manhunt", []) if isinstance(item, dict)]
    targets = [
        item for item in assets
        if item.get("type") == "target" or item.get("primary") or item.get("scope") == "in_scope"
    ]
    services = [item for item in assets if item.get("type") == "service"]
    domains = [item for item in assets if item.get("type") in {"domain", "hostname", "nameserver"}]
    ips = [item for item in assets if item.get("type") == "ip"]
    accounts.extend(item for item in assets if item.get("type") == "account")
    if section == "summary":
        return json.dumps(
            {
                "schema_version": intel.get("schema_version", 1),
                "updated_at": intel.get("updated_at"),
                "asset_count": len(assets),
                "asset_types": _count_values(assets, "type"),
                "scope_statuses": _count_values(assets, "scope"),
                "target_count": len(targets),
                "service_count": len(services),
                "domain_count": len(domains),
                "ip_count": len(ips),
                "finding_count": len(findings),
                "finding_severities": _count_values(findings, "severity"),
                "finding_statuses": _count_values(findings, "status"),
                "observation_count": len(observations),
                "observation_categories": _count_values(observations, "category"),
                "exploit_count": len(exploits),
                "exploit_statuses": _count_values(exploits, "status"),
                "account_count": len(accounts),
                "manhunt_count": len(manhunt),
                "primary_assets": [
                    {"type": item.get("type"), "value": item.get("value"), "scope": item.get("scope")}
                    for item in assets if item.get("primary")
                ],
                "usage": "Request a named Intel section with offset to read paginated records.",
            },
            ensure_ascii=False,
            indent=2,
        )

    records = {
        "assets": assets,
        "targets": targets,
        "services": services,
        "observations": observations,
        "findings": findings,
        "exploits": exploits,
        "domains": domains,
        "ips": ips,
        "accounts": accounts,
        "manhunt": manhunt,
    }[section]
    page = [_bounded_record(record) for record in records[offset : offset + limit]]
    next_offset = offset + len(page)
    return json.dumps(
        {
            "section": section,
            "total": len(records),
            "offset": offset,
            "records": page,
            "next_offset": next_offset if next_offset < len(records) else None,
        },
        ensure_ascii=False,
        indent=2,
    )


def intel_context(intel: dict[str, Any], limit: int = 12) -> str:
    assets = [item for item in intel.get("assets", []) if isinstance(item, dict)]
    findings = [item for item in intel.get("findings", []) if isinstance(item, dict)]
    exploits = [item for item in intel.get("exploits", []) if isinstance(item, dict)]
    observations = [item for item in intel.get("observations", []) if isinstance(item, dict)]
    accounts = [item for item in intel.get("accounts", []) if isinstance(item, dict)]
    manhunt = [item for item in intel.get("manhunt", []) if isinstance(item, dict)]
    sections = (
        ("Targets", [item for item in assets if item.get("type") == "target" or item.get("primary") or item.get("scope") == "in_scope"]),
        ("Services", [item for item in assets if item.get("type") == "service"]),
        ("Findings", findings),
        ("Exploits and vulnerabilities", exploits),
        ("Domains", [item for item in assets if item.get("type") in {"domain", "hostname", "nameserver"}]),
        ("IPs", [item for item in assets if item.get("type") == "ip"]),
        ("Passwords and accounts", accounts + [item for item in assets if item.get("type") == "account"]),
        ("Manhunt", manhunt),
        ("Observations", observations),
    )
    lines = ["Session Intel is the current evidence record. Use it to continue from verified results; update it when new evidence arrives."]
    for label, records in sections:
        lines.append(f"{label} ({len(records)}):")
        selected = records[-limit:]
        if not selected:
            lines.append("- none")
            continue
        for record in selected:
            item = _bounded_record(record)
            if label == "Observations":
                item = {
                    key: item[key]
                    for key in ("title", "asset", "category", "status", "details", "worked", "failed", "next_step", "confidence", "source")
                    if key in item
                }
            lines.append("- " + json.dumps(item, ensure_ascii=False, separators=(",", ":")))
        if len(records) > limit:
            lines.append(f"- {len(records) - limit} earlier records; use intel_get_map for those.")
    return "\n".join(lines)


def _count_values(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        value = str(record.get(key, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return counts


def _bounded_record(record: dict[str, Any]) -> dict[str, Any]:
    bounded = {
        key: value[:1_200] if key in {"summary", "recommendation"} and isinstance(value, str)
        else value
        for key, value in record.items()
        if key not in {"evidence", "attributes"}
    }
    attributes = record.get("attributes")
    if isinstance(attributes, dict):
        bounded["attributes"] = {
            str(key)[:100]: str(value)[:200]
            for key, value in list(attributes.items())[:12]
        }
        if len(attributes) > 12:
            bounded["attributes_truncated"] = len(attributes) - 12
    evidence = record.get("evidence", [])
    if isinstance(evidence, list):
        bounded["evidence"] = [
            {
                "source": str(item.get("source", ""))[:300],
                "details": str(item.get("details", ""))[:800],
                "confidence": str(item.get("confidence", "unknown")),
                "recorded_at": str(item.get("recorded_at", "")),
            }
            for item in evidence[-2:]
            if isinstance(item, dict)
        ]
    return bounded
