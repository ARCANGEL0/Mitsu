"""Build a session-local graph from recorded engagement Intel."""

from __future__ import annotations

import html
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Any


_CATEGORY_ORDER = ("asset", "service", "finding", "exploit", "observation", "account", "person")
_ASSET_CATEGORIES = {
    "target": "asset",
    "domain": "asset",
    "hostname": "asset",
    "nameserver": "asset",
    "ip": "asset",
    "url": "asset",
    "service": "service",
    "endpoint": "service",
    "technology": "service",
    "other": "asset",
}


def _text(value: Any, limit: int = 1_000) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return str(value or "").strip()[:limit]


def _record_id(section: str, record: dict[str, Any], index: int) -> str:
    identity = _text(record.get("id"), 120)
    if identity:
        return f"{section}:{identity}"
    label = _text(record.get("value") or record.get("title") or record.get("name"), 200)
    return f"{section}:{index}:{label.casefold()}"


def _collect_text(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _collect_text(item)]
    if isinstance(value, list):
        return [text for item in value for text in _collect_text(item)]
    return []


def _node_details(record: dict[str, Any], category: str) -> list[dict[str, str]]:
    fields = {
        "asset": ("type", "scope", "verification", "confidence", "parent", "attributes"),
        "service": ("type", "scope", "verification", "confidence", "parent", "attributes"),
        "finding": ("severity", "status", "confidence", "asset", "summary", "recommendation"),
        "exploit": ("status", "confidence", "asset", "summary", "source"),
        "observation": ("category", "status", "confidence", "asset", "details", "worked", "failed", "next_step"),
        "account": ("type", "secret_type", "secret", "access", "status", "confidence", "target", "details"),
        "person": ("detail_type", "relationship", "status", "confidence", "details", "source"),
    }.get(category, ())
    details = [
        {"label": key.replace("_", " ").title(), "value": _text(record.get(key), 1_600)}
        for key in fields
        if record.get(key) not in (None, "", [], {})
    ]
    evidence = record.get("evidence", [])
    if isinstance(evidence, list):
        for item in evidence[:12]:
            if not isinstance(item, dict):
                continue
            source = _text(item.get("source"), 200)
            details_text = _text(item.get("details"), 1_600)
            recorded_at = _text(item.get("recorded_at"), 80)
            value = " · ".join(part for part in (source, recorded_at, details_text) if part)
            if value:
                details.append({"label": "Evidence", "value": value})
    return details


def build_surface_graph(
    session: dict[str, Any],
    extra_nodes: list[dict[str, Any]] | None = None,
    connections: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    intel = session.get("intel") if isinstance(session.get("intel"), dict) else {}
    nodes: list[dict[str, Any]] = []
    assets: list[tuple[dict[str, Any], str]] = []
    record_nodes: list[tuple[str, dict[str, Any], str]] = []
    by_reference: dict[str, list[str]] = {}

    sections = (
        ("assets", "asset"),
        ("findings", "finding"),
        ("exploits", "exploit"),
        ("observations", "observation"),
        ("accounts", "account"),
        ("manhunt", "person"),
    )
    for section, category in sections:
        records = intel.get(section, [])
        if not isinstance(records, list):
            continue
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            node_id = _record_id(section, record, index)
            record_type = _text(record.get("type"), 80).casefold()
            node_category = _ASSET_CATEGORIES.get(record_type, category) if section == "assets" else category
            if section == "assets":
                label = _text(record.get("value"), 500) or "Unnamed asset"
                assets.append((record, node_id))
                for value in (record.get("id"), record.get("value")):
                    normalized = _text(value, 1_000).casefold()
                    if normalized:
                        by_reference.setdefault(normalized, []).append(node_id)
            elif section == "accounts":
                label = _text(record.get("name"), 500) or "Account"
            elif section == "manhunt":
                name = _text(record.get("person"), 250) or "Person"
                value = _text(record.get("value"), 250)
                label = f"{name} · {value}" if value else name
            else:
                label = _text(record.get("title"), 500) or section.title()
            node = {
                "id": node_id,
                "label": label,
                "category": node_category,
                "kind": record_type or section.rstrip("s"),
                "timestamp": _text(record.get("first_seen") or record.get("updated_at"), 80),
                "details": _node_details(record, node_category),
            }
            nodes.append(node)
            record_nodes.append((section, record, node_id))
            for value in (record.get("title"), record.get("name"), record.get("person")):
                normalized = _text(value, 1_000).casefold()
                if normalized:
                    by_reference.setdefault(normalized, []).append(node_id)

    messages = session.get("messages", [])
    transcript = messages if isinstance(messages, list) else []
    evidence_text = "\n".join(_collect_text((intel, transcript))).casefold()
    known_labels = {node["label"].casefold() for node in nodes}
    allowed_categories = set(_CATEGORY_ORDER)
    for item in (extra_nodes or [])[:300]:
        if not isinstance(item, dict):
            continue
        label = _text(item.get("label"), 500)
        category = _text(item.get("category"), 40).casefold()
        evidence = _text(item.get("evidence"), 1_000)
        if not label or category not in allowed_categories or label.casefold() in known_labels:
            continue
        if len(evidence) < 5 or evidence.casefold() not in evidence_text:
            continue
        # Chat-only notes stay unverified until Intel has them.
        node_id = "transcript:" + hashlib.sha256(f"{category}\0{label}".encode()).hexdigest()[:20]
        nodes.append({
            "id": node_id,
            "label": label,
            "category": category,
            "kind": _text(item.get("kind"), 80) or "session note",
            "timestamp": "",
            "details": [
                {"label": "Status", "value": "Unverified · captured from session conversation"},
                {"label": "Transcript evidence", "value": evidence},
            ],
        })
        known_labels.add(label.casefold())

    edges: list[dict[str, str]] = []
    edge_keys: set[tuple[str, str, str]] = set()
    valid_ids = {node["id"] for node in nodes}
    by_label: dict[str, list[str]] = {}
    for node in nodes:
        by_label.setdefault(node["label"].casefold(), []).append(node["id"])

    def add_edge(source: str, target: str, label: str, evidence: str = "") -> None:
        if not source or not target or source == target or source not in valid_ids or target not in valid_ids:
            return
        key = (source, target, label.casefold())
        if key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({"source": source, "target": target, "label": label[:100], "evidence": evidence[:500]})

    # If there are multiple asset matches, skip the link.
    for asset, node_id in assets:
        parent = _text(asset.get("parent"), 1_000).casefold()
        candidates = by_reference.get(parent, [])
        parent_matches = [candidate for candidate in candidates if candidate != node_id]
        parent_id = parent_matches[0] if len(parent_matches) == 1 else ""
        if parent_id:
            parent_record = next((item for item, ident in assets if ident == parent_id), {})
            parent_type = _text(parent_record.get("type"), 80).casefold()
            child_type = _text(asset.get("type"), 80).casefold()
            if parent_type in {"domain", "target"} and child_type == "hostname":
                label = "has hostname"
            elif parent_type in {"domain", "hostname"} and child_type == "ip":
                label = "resolves to"
            elif parent_type in {"ip", "hostname", "target"} and child_type == "service":
                label = "exposes"
            elif parent_type == "service" and child_type == "technology":
                label = "runs"
            elif parent_type in {"domain", "target"}:
                label = "contains"
            else:
                label = "related to"
            add_edge(parent_id, node_id, label, f"Intel parent: {_text(asset.get('parent'), 250)}")

    relation_labels = {
        "findings": "has finding",
        "exploits": "has vulnerability reference",
        "observations": "has observation",
        "accounts": "has account",
        "manhunt": "has person detail",
    }
    for section, record, node_id in record_nodes:
        if section == "assets":
            continue
        reference = _text(record.get("asset") or record.get("target"), 1_000).casefold()
        asset_matches = by_reference.get(reference, [])
        if len(asset_matches) == 1:
            add_edge(asset_matches[0], node_id, relation_labels.get(section, "related to"), reference)

    for network_record, network_id in assets:
        network_value = _text(network_record.get("value"), 200)
        if _text(network_record.get("type"), 80).casefold() != "target" or "/" not in network_value:
            continue
        try:
            network = ipaddress.ip_network(network_value, strict=False)
        except ValueError:
            continue
        for ip_record, ip_id in assets:
            if _text(ip_record.get("type"), 80).casefold() != "ip":
                continue
            try:
                address = ipaddress.ip_address(_text(ip_record.get("value"), 200))
            except ValueError:
                continue
            if address.version == network.version and address in network:
                add_edge(network_id, ip_id, "contains address", f"{address} is within {network}")

    if connections:
        for connection in connections[:300]:
            if not isinstance(connection, dict):
                continue
            source = _text(connection.get("source"), 160)
            target = _text(connection.get("target"), 160)
            label = _text(connection.get("label"), 100) or "related to"
            evidence = _text(connection.get("evidence"), 500)
            source_id = source if source in valid_ids else next(iter(by_label.get(source.casefold(), [])), "")
            target_id = target if target in valid_ids else next(iter(by_label.get(target.casefold(), [])), "")
            source_matches = by_label.get(source.casefold(), [])
            target_matches = by_label.get(target.casefold(), [])
            if (
                source_id
                and target_id
                and (source in valid_ids or len(source_matches) == 1)
                and (target in valid_ids or len(target_matches) == 1)
                and len(evidence) >= 5
                and evidence.casefold() in evidence_text
            ):
                add_edge(source_id, target_id, label, evidence)

    nodes.sort(key=lambda item: (_CATEGORY_ORDER.index(item["category"]) if item["category"] in _CATEGORY_ORDER else len(_CATEGORY_ORDER), item["label"].casefold(), item["id"]))
    for node in nodes:
        node["details"] = node["details"][:40]
    created_at = _text(session.get("created_at"), 80)
    updated_at = _text(session.get("updated_at"), 80)
    return {
        "title": _text(session.get("title"), 160) or "Untitled session",
        "session_id": _text(session.get("id"), 64),
        "mode": _text(session.get("mode"), 40),
        "created_at": created_at,
        "updated_at": updated_at,
        "targets": [_text(target, 500) for target in session.get("targets", []) if _text(target, 500)] if isinstance(session.get("targets"), list) else [],
        "nodes": nodes,
        "edges": edges,
        "transcript_node_count": sum(node["id"].startswith("transcript:") for node in nodes),
        "counts": {category: sum(node["category"] == category for node in nodes) for category in _CATEGORY_ORDER},
    }


def _basic_html(graph: dict[str, Any]) -> str:
    title = html.escape(str(graph["title"]))
    nodes = []
    for node in graph["nodes"]:
        details = "".join(
            f"<li><strong>{html.escape(item['label'])}:</strong> {html.escape(item['value'])}</li>"
            for item in node["details"]
        )
        nodes.append(
            f"<article><h3>{html.escape(node['label'])}</h3>"
            f"<p>{html.escape(node['category'])} · {html.escape(node['kind'])}</p><ul>{details}</ul></article>"
        )
    links = "".join(
        f"<li>{html.escape(edge['source'])} → {html.escape(edge['target'])}: {html.escape(edge['label'])}</li>"
        for edge in graph["edges"]
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Mitsu Attack Surface</title>
<style>body{{max-width:1100px;margin:40px auto;padding:0 20px;background:#101923;color:#e8f0f7;font:15px/1.5 system-ui}}h1,h2{{color:#80deea}}article{{margin:12px 0;padding:14px;background:#182737;border:1px solid #344b60;border-radius:10px}}article p{{color:#9eafc0}}li{{overflow-wrap:anywhere}}.nodes{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}}</style>
</head><body><h1>✦ Mitsu · {title}</h1><p>Attack surface map · {len(graph['nodes'])} nodes · {len(graph['edges'])} relationships</p>
<h2>Nodes</h2><section class="nodes">{''.join(nodes)}</section><h2>Relationships</h2><ul>{links}</ul></body></html>"""

def create_surface_map(
    session: dict[str, Any],
    session_root: Path,
    extra_nodes: list[dict[str, Any]] | None = None,
    connections: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    session_id = _text(session.get("id"), 64)
    if not re.fullmatch(r"[a-f0-9]{32}", session_id):
        raise ValueError("This session has no valid ID for saving its map.")
    graph = build_surface_graph(session, extra_nodes, connections)
    directory = session_root / session_id / "artifacts"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    destination = directory / "attack-surface-map.html"
    temporary = directory / ".attack-surface-map.html.tmp"
    # These map files can contain secrets, so keep the permissions locked down just in case.
    temporary.write_text(_basic_html(graph), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(destination)
    return {
        "path": str(destination),
        "node_count": len(graph["nodes"]),
        "edge_count": len(graph["edges"]),
        "transcript_node_count": graph["transcript_node_count"],
        "title": graph["title"],
    }
