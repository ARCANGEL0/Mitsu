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
    safe_graph = json.dumps(graph, ensure_ascii=False, separators=(",", ":"), default=str)
    safe_graph = safe_graph.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    title = html.escape(str(graph["title"]))
    # Keep the styles and data here so the map works offline.
    template = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ · Mitsu Attack Surface</title>
<style>
:root{color-scheme:dark;--bg:#091019;--panel:#101b27;--panel-2:#142333;--line:#263b50;--ink:#e8f0f7;--muted:#9eafc0;--cyan:#80deea;--violet:#ab97ff;--pink:#ed8cab;--green:#82d6b2;--gold:#e7c77a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 20% 0,#142b3e,var(--bg) 55%);color:var(--ink);font:14px/1.45 system-ui,sans-serif}
header{display:flex;justify-content:space-between;align-items:center;gap:20px;padding:20px 26px;border-bottom:1px solid var(--line);background:#0b131de8}
header small{color:var(--cyan);letter-spacing:.13em;text-transform:uppercase}h1{margin:4px 0 0;font-size:clamp(22px,3vw,32px)}.brand{color:var(--muted);font-size:12px}
.meta{display:flex;gap:8px;flex-wrap:wrap;padding:12px 20px;border-bottom:1px solid var(--line)}.pill{padding:6px 10px;border:1px solid var(--line);border-radius:999px;color:var(--muted);background:var(--panel)}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--line);background:#0d1722}.toolbar input{min-width:220px;flex:1}.toolbar input,.toolbar button{height:36px;padding:0 11px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);font:inherit}.toolbar button{cursor:pointer}.toolbar button:hover{border-color:var(--cyan);color:var(--cyan)}.filters{display:flex;gap:6px;flex-wrap:wrap}.filter{padding:6px 9px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:11px;cursor:pointer}.filter input{width:auto;min-width:0;height:auto;margin:0 5px 0 0;accent-color:var(--cyan)}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 330px;min-height:calc(100vh - 205px)}.canvas-wrap{min-width:0;min-height:65vh;overflow:hidden;background-color:#0b141e;background-image:radial-gradient(#294055 1px,transparent 1px);background-size:22px 22px;cursor:grab}.canvas-wrap.dragging{cursor:grabbing}
svg{display:block;width:100%;height:100%;min-height:65vh;touch-action:none}.edge{fill:none;stroke:#47647c;stroke-width:1.6;opacity:.72}.edge-label{fill:#94a9bb;font-size:11px;text-anchor:middle;pointer-events:none}.map-node{cursor:pointer}.map-node[hidden],.edge[hidden],.edge-label[hidden]{display:none}.map-node rect{fill:#132332;stroke:#52718d;stroke-width:1.5;rx:12}.map-node text{pointer-events:none}.map-node .node-title{fill:var(--ink);font-size:13px;font-weight:650}.map-node .node-sub{fill:var(--muted);font-size:10px}.map-node:hover rect,.map-node.active rect{stroke:var(--cyan);stroke-width:3;filter:drop-shadow(0 0 7px #80deea66)}.map-node.search-match rect{stroke:#fff;stroke-width:3;filter:drop-shadow(0 0 8px #fff8)}.map-node.search-muted{opacity:.2}
.map-node[data-category=service] rect{stroke:#65aed0}.map-node[data-category=finding] rect{stroke:var(--gold)}.map-node[data-category=exploit] rect{stroke:var(--pink)}.map-node[data-category=observation] rect{stroke:var(--violet)}.map-node[data-category=account] rect{stroke:var(--green)}.map-node[data-category=person] rect{stroke:#d98ad7}
aside{padding:18px;border-left:1px solid var(--line);background:#0d1722}.aside-title{color:var(--cyan);font-size:11px;font-weight:750;letter-spacing:.12em;text-transform:uppercase}.empty{margin-top:14px;color:var(--muted)}.detail-title{margin:8px 0 2px;font-size:19px;overflow-wrap:anywhere}.detail-sub{color:var(--muted);font-size:12px}.field{padding:12px 0;border-bottom:1px solid #213243}.field strong{display:block;margin-bottom:4px;color:#b9d6e5;font-size:11px;letter-spacing:.05em;text-transform:uppercase}.field p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--ink)}
.legend{display:flex;gap:14px;flex-wrap:wrap;padding:12px 20px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}.legend span:before{display:inline-block;width:9px;height:9px;margin-right:6px;border:2px solid currentColor;border-radius:3px;content:""}.legend .asset{color:var(--cyan)}.legend .finding{color:var(--gold)}.legend .exploit{color:var(--pink)}.legend .observation{color:var(--violet)}.legend .account{color:var(--green)}footer{padding:12px;text-align:center;color:#718397;font-size:11px}
@media(max-width:850px){.layout{grid-template-columns:1fr}.canvas-wrap{min-height:55vh}svg{min-height:55vh}aside{border-left:0;border-top:1px solid var(--line)}}
</style></head><body>
<header><div><small>✦ Mitsu · Session Intel</small><h1>__TITLE__</h1></div><div class="brand">ATTACK SURFACE MAP</div></header>
<div class="meta" id="meta"></div>
<div class="toolbar"><input id="search" type="search" placeholder="Find a node…" aria-label="Find a node"><div class="filters" id="filters"></div><button id="zoom-out" type="button" aria-label="Zoom out">−</button><button id="zoom-in" type="button" aria-label="Zoom in">+</button><button id="reset-view" type="button">Reset view</button></div>
<div class="layout"><section class="canvas-wrap" id="canvas"><svg id="map" role="img" aria-label="Interactive graph of session attack surface"></svg></section>
<aside><div class="aside-title">Node details</div><div class="empty" id="empty">Select a node to view its recorded details, evidence, and connections.</div><div id="detail" hidden></div></aside></div>
<div class="legend" id="legend"></div><footer>Built from this session’s Intel and cited transcript notes · Mitsu</footer>
<script>
const graph=__GRAPH__;
const labels={asset:"Targets & network",service:"Services & technologies",finding:"Findings",exploit:"Vulnerabilities & exploits",observation:"Observations",account:"Accounts & credentials",person:"People"};
const order=Object.keys(labels),svg=document.querySelector("#map"),canvas=document.querySelector("#canvas"),ns="http://www.w3.org/2000/svg";
const meta=document.querySelector("#meta"),legend=document.querySelector("#legend"),positions=new Map(),nodeElements=new Map(),edgeElements=new Map(),byId=new Map(graph.nodes.map(node=>[node.id,node]));
for(const [label,value] of [["Mode",graph.mode||"—"],["Created",graph.created_at||"—"],["Updated",graph.updated_at||"—"],["Nodes",String(graph.nodes.length)],["Links",String(graph.edges.length)]]){const pill=document.createElement("span");pill.className="pill";pill.textContent=label+": "+value;meta.append(pill)}
for(const key of order){if(!graph.counts[key])continue;const item=document.createElement("span");item.className=key;item.textContent=labels[key]+" · "+graph.counts[key];legend.append(item);const filter=document.createElement("label");filter.className="filter";const toggle=document.createElement("input");toggle.type="checkbox";toggle.checked=true;toggle.dataset.category=key;toggle.addEventListener("change",()=>{for(const node of graph.nodes.filter(node=>node.category===key))nodeElements.get(node.id).hidden=!toggle.checked;updateEdges()});filter.append(toggle,labels[key]);document.querySelector("#filters").append(filter)}
const columns=order.map(key=>[key,graph.nodes.filter(node=>node.category===key)]).filter(([,nodes])=>nodes.length);
const width=Math.max(1050,columns.length*270+80),height=Math.max(720,...columns.map(([,nodes])=>nodes.length*104+120));
svg.setAttribute("viewBox",`0 0 ${width} ${height}`);svg.setAttribute("width",width);svg.setAttribute("height",height);
const defs=document.createElementNS(ns,"defs"),marker=document.createElementNS(ns,"marker");marker.setAttribute("id","arrow");marker.setAttribute("markerWidth","8");marker.setAttribute("markerHeight","8");marker.setAttribute("refX","7");marker.setAttribute("refY","4");marker.setAttribute("orient","auto");marker.setAttribute("markerUnits","strokeWidth");const arrow=document.createElementNS(ns,"path");arrow.setAttribute("d","M0,0 L8,4 L0,8 z");arrow.setAttribute("fill","#7891a8");marker.append(arrow);defs.append(marker);svg.append(defs);
const world=document.createElementNS(ns,"g");world.setAttribute("id","world");svg.append(world);let scale=1,offsetX=0,offsetY=0;
// Move the view, not every node, when zooming and panning.
function setView(){world.setAttribute("transform",`translate(${offsetX} ${offsetY}) scale(${scale})`)}
function updateEdges(){for(const edge of graph.edges){const hidden=nodeElements.get(edge.source).hidden||nodeElements.get(edge.target).hidden;for(const element of edgeElements.get(edge)||[])element.hidden=hidden}}
for(const [column,[category,nodes]] of columns.entries()){const x=55+column*270;for(const [index,node] of nodes.entries())positions.set(node.id,{x,y:72+index*104,category})}
for(const edge of graph.edges){const from=positions.get(edge.source),to=positions.get(edge.target);if(!from||!to)continue;const startX=from.x+208,startY=from.y+30,endX=to.x,endY=to.y+30,midX=(startX+endX)/2,path=document.createElementNS(ns,"path");path.setAttribute("class","edge");path.setAttribute("d",`M ${startX} ${startY} C ${midX} ${startY}, ${midX} ${endY}, ${endX} ${endY}`);path.setAttribute("marker-end","url(#arrow)");path.setAttribute("aria-label",edge.label);world.append(path);const elements=[path];if(edge.label){const text=document.createElementNS(ns,"text");text.setAttribute("class","edge-label");text.setAttribute("x",midX);text.setAttribute("y",(startY+endY)/2-5);text.textContent=edge.label;world.append(text);elements.push(text)}edgeElements.set(edge,elements)}
function showNode(node,element){document.querySelectorAll(".map-node.active").forEach(item=>item.classList.remove("active"));element.classList.add("active");document.querySelector("#empty").hidden=true;const panel=document.querySelector("#detail");panel.hidden=false;panel.replaceChildren();const title=document.createElement("div");title.className="detail-title";title.textContent=node.label;panel.append(title);const subtitle=document.createElement("div");subtitle.className="detail-sub";subtitle.textContent=[labels[node.category],node.kind,node.timestamp].filter(Boolean).join(" · ");panel.append(subtitle);for(const field of node.details){const row=document.createElement("div");row.className="field";const name=document.createElement("strong");name.textContent=field.label;const value=document.createElement("p");value.textContent=field.value;row.append(name,value);panel.append(row)}const links=graph.edges.filter(edge=>edge.source===node.id||edge.target===node.id);if(links.length){const row=document.createElement("div");row.className="field";const name=document.createElement("strong");name.textContent="Connections";row.append(name);for(const edge of links){const related=byId.get(edge.source===node.id?edge.target:edge.source);const value=document.createElement("p");value.textContent=`${edge.label} · ${related?.label||"Unknown node"}${edge.evidence?"\\n"+edge.evidence:""}`;row.append(value)}panel.append(row)}}
for(const node of graph.nodes){const pos=positions.get(node.id),group=document.createElementNS(ns,"g");group.setAttribute("class","map-node");group.setAttribute("data-category",node.category);group.setAttribute("transform",`translate(${pos.x} ${pos.y})`);group.setAttribute("tabindex","0");group.setAttribute("role","button");group.setAttribute("aria-label",`${node.label}, ${labels[node.category]}`);const title=document.createElementNS(ns,"title");title.textContent=node.label;const rect=document.createElementNS(ns,"rect");rect.setAttribute("width","208");rect.setAttribute("height","62");const name=document.createElementNS(ns,"text");name.setAttribute("class","node-title");name.setAttribute("x","12");name.setAttribute("y","25");name.textContent=node.label.length>27?node.label.slice(0,26)+"…":node.label;const sub=document.createElementNS(ns,"text");sub.setAttribute("class","node-sub");sub.setAttribute("x","12");sub.setAttribute("y","46");sub.textContent=[node.kind,node.timestamp].filter(Boolean).join(" · ").slice(0,38);group.append(title,rect,name,sub);group.addEventListener("click",()=>showNode(node,group));group.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();showNode(node,group)}});world.append(group);nodeElements.set(node.id,group)}
document.querySelector("#search").addEventListener("input",event=>{const query=event.target.value.trim().toLocaleLowerCase();for(const node of graph.nodes){const element=nodeElements.get(node.id),match=!query||node.label.toLocaleLowerCase().includes(query)||node.details.some(field=>field.value.toLocaleLowerCase().includes(query));element.classList.toggle("search-match",Boolean(query&&match));element.classList.toggle("search-muted",Boolean(query&&!match))}});
document.querySelector("#zoom-in").addEventListener("click",()=>{scale=Math.min(2.5,scale*1.2);setView()});document.querySelector("#zoom-out").addEventListener("click",()=>{scale=Math.max(.45,scale/1.2);setView()});document.querySelector("#reset-view").addEventListener("click",()=>{scale=1;offsetX=0;offsetY=0;setView()});
let drag=null;canvas.addEventListener("pointerdown",event=>{if(event.target.closest(".map-node"))return;drag={x:event.clientX-offsetX,y:event.clientY-offsetY};canvas.classList.add("dragging");canvas.setPointerCapture(event.pointerId)});canvas.addEventListener("pointermove",event=>{if(!drag)return;offsetX=event.clientX-drag.x;offsetY=event.clientY-drag.y;setView()});canvas.addEventListener("pointerup",()=>{drag=null;canvas.classList.remove("dragging")});canvas.addEventListener("wheel",event=>{event.preventDefault();scale=Math.max(.45,Math.min(2.5,scale*(event.deltaY<0?1.1:.9)));setView()},{passive:false});
</script></body></html>"""
    return template.replace("__TITLE__", title).replace("__GRAPH__", safe_graph)


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
