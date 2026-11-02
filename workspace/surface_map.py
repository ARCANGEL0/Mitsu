"""Build a session-local graph from recorded engagement Intel."""

from __future__ import annotations

import html
import json
import base64
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit


_types = {
    "target": "target", "domain": "domain", "hostname": "host",
    "nameserver": "nameserver", "ip": "ip", "url": "domain",
    "service": "service", "endpoint": "service", "technology": "service",
    "email": "email", "person": "person", "account": "account", "other": "target",
}
_groups = {
    "target": "Targets & network", "domain": "Targets & network", "host": "Targets & network",
    "nameserver": "Targets & network", "ip": "Targets & network",
    "service": "Services & technologies", "email": "People", "person": "People", "account": "Accounts & credentials",
}

_colors = {
    "target": "#70d8e8", "ip": "#83aaff", "domain": "#b59aff", "host": "#5ec8ff",
    "nameserver": "#4fdfc2", "service": "#f0bd68", "email": "#ff91c8",
    "person": "#ff718f", "account": "#85d9ad",
}
def _text(value: Any, limit: int = 1_000) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return str(value or "").strip()[:limit]


def _id(section: str, record: dict[str, Any], index: int) -> str:
    return _text(record.get("id"), 120) or f"{section}:{index}:{_text(record.get('value') or record.get('name'), 160).casefold()}"


def _evidence_summary(value: Any) -> str:
    # Evidence can be a JSON string, so unpack it before showing it.
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = value
        if isinstance(decoded, (dict, list)):
            value = decoded
    entries = value if isinstance(value, list) else [value]
    summaries = []
    for entry in entries:
        if isinstance(entry, dict):
            source = _text(entry.get("source"), 120)
            detail = _text(entry.get("details"), 1_200)
            confidence = _text(entry.get("confidence"), 40)
            recorded = _text(entry.get("recorded_at"), 80)
            if recorded:
                recorded = recorded.replace("T", " ").replace("+00:00", " UTC").split(".", 1)[0]
            summary = f"{source}: {detail}" if source and detail else detail or source
            if confidence:
                summary += f" ({confidence} confidence)"
            if recorded:
                summary += f" · {recorded}"
        else:
            summary = _text(entry, 1_200)
        if summary:
            summaries.append(summary)
    return "\n".join(summaries)


def _fields(record: dict[str, Any], skip: set[str] | None = None, section: str = "Asset") -> list[dict[str, str]]:
    skip = skip or set()
    out = []

    def add(label: str, value: Any) -> None:
        label = label.replace("_", " ").title()
        if value in (None, "", [], {}):
            return
        if isinstance(value, dict):
            if label == "Evidence":
                source = _text(value.get("source"), 160)
                detail = _text(value.get("details"), 1_200)
                recorded = _text(value.get("recorded_at"), 80)
                confidence = _text(value.get("confidence"), 40)
                evidence_label = "Evidence" + (f" · {source}" if source else "")
                evidence_value = detail or ", ".join(f"{k}: {_text(v, 250)}" for k, v in value.items() if v not in (None, "", [], {}))
                if recorded:
                    evidence_value += f" · {recorded}"
                if confidence:
                    evidence_value += f" · {confidence} confidence"
                if evidence_value:
                    out.append({"section": section, "label": evidence_label, "value": evidence_value})
                return
            for key, item in value.items():
                add(f"{label} · {key}", item)
            return
        if isinstance(value, list):
            for item in value:
                add(label, item)
            return
        out.append({"section": section, "label": label, "value": _text(value, 1_600)})

    for key, value in record.items():
        if key in skip or value in (None, "", [], {}):
            continue
        add(key, value)
    return out


def build_surface_graph(session: dict[str, Any], connections: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    intel = session.get("intel") if isinstance(session.get("intel"), dict) else {}
    nodes: list[dict[str, Any]] = []
    refs: dict[str, list[str]] = {}
    canonical: dict[tuple[str, str], str] = {}
    parent_links: list[tuple[str, str, str]] = []
    for section in ("assets", "manhunt"):
        rows = intel.get(section, [])
        if not isinstance(rows, list):
            continue
        for index, record in enumerate(rows):
            if not isinstance(record, dict):
                continue
            kind = _text(record.get("type") or ("person" if section == "manhunt" else "asset"), 60).casefold()
            category = _types.get(kind, "target" if section == "assets" else None)
            if section == "manhunt":
                category = "email" if "@" in _text(record.get("value"), 250) else "person"
            if not category:
                continue
            label = _text(record.get("value") or record.get("name") or record.get("person"), 400)
            if not label:
                continue
            if category == "target":
                # Targets can be domains or IPs; keep their real type in the graph.
                if "@" in label:
                    category = "email"
                elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", label):
                    category = "ip"
                elif re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", label, re.I):
                    category = "domain"
            key = (category, label.casefold())
            node_id = canonical.get(key)
            node_fields = _fields(record, {"value", "name", "person", "id", "type", "primary", "evidence"})
            node_fields.extend(_fields({"evidence": record.get("evidence")}, section="Evidence"))
            if node_id:
                node = next(item for item in nodes if item["id"] == node_id)
                existing = {(field["label"], field["value"]) for field in node["details"]}
                node["details"].extend(field for field in node_fields if (field["label"], field["value"]) not in existing)
                node["primary"] = node["primary"] or record.get("primary") is True or kind == "target"
            else:
                node_id = _id(section, record, index)
                display_kind = category if kind == "target" and category != "target" else kind
                display_label = label
                if category == "service" and label.casefold().startswith(("http://", "https://")):
                    parsed_url = urlsplit(label)
                    display_label = parsed_url.path.rstrip("/") or parsed_url.netloc
                node = {"id": node_id, "label": label, "kind": display_kind, "category": category,
                        "display_label": display_label,
                        "primary": record.get("primary") is True or kind == "target",
                        "os": "windows" if re.search(r"\b(windows|win10|win11)\b", _text(record, 2_000), re.I) else "linux" if re.search(r"\b(linux|ubuntu|debian|kali|fedora|centos)\b", _text(record, 2_000), re.I) else "",
                        "details": node_fields, "group": _groups[category]}
                nodes.append(node)
                canonical[key] = node_id
            for value in (record.get("id"), record.get("value"), record.get("name"), record.get("person")):
                key = _text(value, 1_000).casefold()
                if key:
                    matches = refs.setdefault(key, [])
                    if node_id not in matches:
                        matches.append(node_id)
            parent = _text(record.get("parent"), 1_000)
            if parent:
                parent_links.append((node_id, parent, _evidence_summary(record.get("evidence"))))

    by_id = {node["id"]: node for node in nodes}
    details_seen = {node["id"]: set() for node in nodes}
    for section in ("findings", "exploits", "observations", "accounts", "manhunt"):
        rows = intel.get(section, [])
        if not isinstance(rows, list):
            continue
        for record in rows:
            if not isinstance(record, dict):
                continue
            ref = _text(record.get("asset") or record.get("target") or record.get("email") or record.get("person"), 1_000).casefold()
            matches = refs.get(ref, [])
            if len(matches) != 1:
                continue
            node_id = matches[0]
            title = _text(record.get("title") or record.get("name") or record.get("person") or section.title(), 240)
            signature = f"{section}:{title}:{_text(record.get('id'), 100)}"
            if signature in details_seen[node_id]:
                continue
            details_seen[node_id].add(signature)
            group = section[:-1].title() if section.endswith("s") else section.title()
            entries = _fields(record, {"id", "asset", "target", "email", "person", "title", "evidence", "details", "summary", "worked", "failed"}, group)
            heading = _text(record.get("details") or record.get("summary") or record.get("worked") or record.get("failed"), 1_200)
            by_id[node_id]["details"].extend(entries)
            if heading:
                by_id[node_id]["details"].append({"section": group, "label": title, "value": heading})
            by_id[node_id]["details"].extend(_fields({"evidence": record.get("evidence")}, section="Evidence"))

    valid = {node["id"] for node in nodes}
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(source: str, target: str, label: str, evidence: str) -> None:
        if source not in valid or target not in valid or source == target or not evidence:
            return
        key = (source, target, label.casefold())
        if key not in seen:
            seen.add(key)
            edges.append({"source": source, "target": target, "label": label[:80], "evidence": evidence[:500]})

    evidence_pool = json.dumps(intel, ensure_ascii=False, default=str).casefold()
    # The saved parent field is the link between these two nodes.
    for child_id, parent_label, evidence in parent_links:
        parent_ids = refs.get(parent_label.casefold(), [])
        parent_id = next((item for item in parent_ids if item != child_id and by_id[item].get("primary")), None)
        if parent_id is None:
            parent_id = next((item for item in parent_ids if item != child_id), None)
        if parent_id:
            add(parent_id, child_id, "parent of", evidence or f"Recorded parent asset: {parent_label}")
    for item in (connections or [])[:300]:
        if not isinstance(item, dict):
            continue
        source, target = _text(item.get("source"), 160), _text(item.get("target"), 160)
        if source not in valid or target not in valid:
            continue
        evidence = _text(item.get("evidence"), 500)
        if len(evidence) < 5 or evidence.casefold() not in evidence_pool:
            continue
        add(source, target, _text(item.get("label"), 80) or "related to", _evidence_summary(evidence))

    nodes.sort(key=lambda node: (node["group"], node["label"].casefold(), node["id"]))
    categories = sorted({node["category"] for node in nodes})
    return {"title": _text(session.get("title"), 160) or "Untitled session", "mode": _text(session.get("mode"), 40),
        "created_at": _text(session.get("created_at"), 80), "updated_at": _text(session.get("updated_at"), 80),
            "nodes": nodes, "edges": edges, "categories": categories,
            "counts": {category: sum(node["category"] == category for node in nodes) for category in categories}}


def _basic_html(graph: dict[str, Any]) -> str:
    data = json.dumps(graph, ensure_ascii=False, separators=(",", ":"), default=str)
    data = data.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    title = html.escape(str(graph["title"]))
    logo_path = Path(__file__).resolve().parents[1] / "assets" / "example" / "icon.svg"
    logo = "data:image/svg+xml;base64," + base64.b64encode(logo_path.read_bytes()).decode("ascii")
    page = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__ · Mitsu</title>
<style>
:root{color-scheme:dark;--bg:#09121c;--panel:#0e1a26;--line:#20394b;--ink:#e4eef5;--muted:#91a6b7;--cyan:#70d8e8}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,sans-serif;height:100vh;display:grid;grid-template-rows:72px 1fr 38px;overflow:hidden}header{display:flex;align-items:center;justify-content:space-between;padding:0 24px;border-bottom:1px solid var(--line);background:#0b1620}header small{color:var(--cyan);letter-spacing:.14em;text-transform:uppercase;font-size:11px}h1{font-size:20px;margin:3px 0 0}.brand{color:var(--muted);font-size:11px;letter-spacing:.08em}main{min-height:0;display:grid;grid-template-columns:230px minmax(0,1fr) 330px}.tree,.info{min-width:0;background:var(--panel);overflow:auto}.tree{border-right:1px solid var(--line);padding:16px 12px}.info{border-left:1px solid var(--line);padding:18px}.tree-title,.info-title{font-size:11px;font-weight:750;color:var(--cyan);letter-spacing:.13em;text-transform:uppercase;padding:0 8px 13px}.branch{margin:4px 0 14px}.branch-name{font-size:12px;color:var(--muted);padding:7px 8px;border-bottom:1px solid #1c3040}.leaf{display:block;width:100%;text-align:left;border:0;background:transparent;color:var(--ink);padding:7px 8px 7px 16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer;border-radius:5px}.leaf:hover,.leaf.active{background:#192c3c;color:#fff}.leaf i{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--c);margin-right:8px}.stage{display:grid;grid-template-rows:54px minmax(0,1fr);min-width:0;min-height:0}.tools{display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid var(--line)}input,button{height:34px;color:var(--ink);background:#101e2b;border:1px solid #294355;border-radius:7px;padding:0 10px;font:inherit}input{flex:1;min-width:100px}button{cursor:pointer}button:hover{border-color:var(--cyan)}#canvas{min-height:0;overflow:hidden;touch-action:none;cursor:grab;background-color:#0a141e;background-image:radial-gradient(#263b4c 1px,transparent 1px);background-size:22px 22px}#canvas.grab{cursor:grabbing}svg{width:100%;height:100%;display:block;touch-action:none}.edge{stroke:#526a7c;stroke-width:1.4;opacity:.72}.edge.active{stroke:#e6f4fa;stroke-width:2.5;opacity:1}.node{cursor:grab;outline:none}.node:focus{outline:none}.node circle{fill:#0f1d29;stroke:var(--c);stroke-width:2.5;transition:fill .16s,stroke-width .16s,filter .16s}.node.primary circle{stroke-width:4;filter:drop-shadow(0 0 7px color-mix(in srgb,var(--c),transparent 35%))}.node:hover circle,.node.active circle,.node:focus-visible circle{fill:color-mix(in srgb,var(--c),#0f1d29 78%);stroke-width:3.5;filter:drop-shadow(0 0 14px color-mix(in srgb,var(--c),transparent 15%))}.node text{fill:var(--ink);font-size:13px;paint-order:stroke;stroke:#0a141e;stroke-width:3px;stroke-linejoin:round;pointer-events:none}.node[hidden],.edge[hidden]{display:none}.empty{color:var(--muted);line-height:1.7}.detail-name{font-size:21px;overflow-wrap:anywhere;margin:3px 0}.detail-kind{color:var(--muted);font-size:12px;margin-bottom:14px}.field{padding:12px 0;border-bottom:1px solid var(--line)}.field strong{display:block;font-size:10px;letter-spacing:.08em;color:#a9c9d8;margin-bottom:4px}.field p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.counts{display:flex;gap:6px;flex-wrap:wrap;padding:0 8px 12px}.count{font-size:10px;color:var(--muted);border:1px solid var(--line);padding:3px 6px;border-radius:20px}footer{display:flex;align-items:center;justify-content:center;border-top:1px solid var(--line);color:var(--muted);font-size:11px;letter-spacing:.04em;background:#0b1620}@media(max-width:900px){main{grid-template-columns:185px minmax(0,1fr)}.info{position:absolute;right:0;top:72px;bottom:38px;width:min(330px,85vw);box-shadow:-12px 0 35px #0008}body{grid-template-rows:72px 1fr 38px}}@media(max-width:600px){main{grid-template-columns:140px minmax(0,1fr)}.tree{padding:12px 6px}.tools{gap:4px;padding:6px}button{padding:0 7px}}
<style>.lane-title{fill:#9aafbe;font-size:15px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}.lane-divider{stroke:#263542;stroke-width:1;stroke-dasharray:3 8;opacity:.7}.detail-summary{color:#c3d5e0;line-height:1.65;margin:10px 0 18px}.detail-section{margin:18px 0 22px}.detail-section h3{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--cyan);margin:0 0 4px;padding-bottom:7px;border-bottom:1px solid var(--line)}.detail-section .field{padding:10px 2px}.detail-section .field strong{font-size:10px;color:#93aebe;letter-spacing:.04em;text-transform:none}.detail-section .field p{font-size:13px;line-height:1.55;color:var(--ink)}.node .node-mark{stroke:none;paint-order:normal;font-size:13px;dominant-baseline:central;text-anchor:middle}:root{--bg:#0c131a;--panel:#111a22;--line:#263744;--ink:#e8edf2;--muted:#94a3af}body{background:#0c131a}header,footer{background:#111a22;border-color:#263744}header{padding:0 28px}.mast{display:flex;align-items:center;gap:14px}.mast img{width:42px;height:42px;object-fit:contain}main{background:#0c131a}.tree,.info{background:#111a22}.tree{padding:16px 10px}.info{padding:18px}.branch-name,.field{border-color:#18232d}.leaf,input,button,.count{border-radius:0}.leaf{border-left:2px solid transparent}.leaf:hover,.leaf.active{background:#101820;border-left-color:var(--cyan)}.count{padding:4px 7px}.tools{background:#111a22}input,button{background:#151f28;border-color:#304351}button:hover{border-color:var(--cyan)}#canvas{background-color:#0b1218;background-image:linear-gradient(#17232d 1px,transparent 1px),linear-gradient(90deg,#17232d 1px,transparent 1px);background-size:72px 72px}.edge{stroke:#536878}.edge.active{stroke:#dceaf2}footer{letter-spacing:.08em}</style></head><body><header><div class="mast"><img src="__LOGO__" alt="Mitsu"><div><small>✦ Mitsu · Session Intel</small><h1>__TITLE__</h1></div></div><div class="brand">ATTACK SURFACE MAP</div></header><main><nav class="tree"><div class="tree-title">Session Intel</div><div class="counts" id="counts"></div><div id="tree"></div></nav><section class="stage"><div class="tools"><input id="search" type="search" placeholder="Find a node…" aria-label="Find a node"><button id="minus" aria-label="Zoom out">−</button><button id="plus" aria-label="Zoom in">+</button><button id="reset">Reset view</button></div><div id="canvas"><svg id="map" aria-label="Interactive graph"></svg></div></section><aside class="info"><div class="info-title">Node details</div><div id="empty" class="empty">Select a node to view its recorded details, evidence, and connections.</div><div id="detail" hidden></div></aside></main><footer id="footer"></footer>
<script>
const graph=__GRAPH__,svg=document.querySelector('#map'),canvas=document.querySelector('#canvas'),ns='http://www.w3.org/2000/svg',colors={target:'#70d8e8',domain:'#b59aff',host:'#5ec8ff',nameserver:'#4fdfc2',ip:'#83aaff',service:'#f0bd68',email:'#ff91c8',person:'#ff718f',account:'#85d9ad'},glyphs={target:'◎',domain:'◎',host:'⌂',nameserver:'⌘',ip:'⌖',service:'▤',email:'✉',person:'♙',account:'◈'},groups=[...new Set(graph.nodes.map(n=>n.group))],pos=new Map(),els=new Map(),edgeEls=new Map(),byId=new Map(graph.nodes.map(n=>[n.id,n]));
const tree=document.querySelector('#tree'),counts=document.querySelector('#counts');for(const [kind,total] of Object.entries(graph.counts)){const c=document.createElement('span');c.className='count';c.textContent=kind+' · '+total;counts.append(c)}
for(const group of groups){const box=document.createElement('section');box.className='branch';const heading=document.createElement('div');heading.className='branch-name';heading.textContent=group;box.append(heading);for(const node of graph.nodes.filter(n=>n.group===group)){const item=document.createElement('button');item.className='leaf';item.innerHTML='<i></i>';item.lastChild.style.setProperty('--c',colors[node.category]);item.append(document.createTextNode(node.label));item.addEventListener('click',()=>selectNode(node));box.append(item);node.treeItem=item}tree.append(box)}
// Lay out linked nodes by distance from the primary asset; group the rest by type.
const categoryOrder=["target","domain","host","ip","nameserver","service","person","email","account"],categoryNames={target:"Targets",domain:"Domains",host:"Hosts",ip:"IP addresses",nameserver:"Nameservers",service:"Services",person:"People",email:"Email addresses",account:"Accounts"},categories=[...new Set([...categoryOrder.filter(c=>graph.nodes.some(n=>n.category===c)),...graph.nodes.map(n=>n.category).filter(c=>!categoryOrder.includes(c)).sort()])],rank=new Map(categories.map((category,index)=>[category,index])),neighbors=new Map(graph.nodes.map(n=>[n.id,[]])),depths=new Map();for(const e of graph.edges){if(neighbors.has(e.source)&&neighbors.has(e.target)){neighbors.get(e.source).push(e.target);neighbors.get(e.target).push(e.source)}}const root=graph.nodes.find(n=>n.primary)||graph.nodes[0];if(root){depths.set(root.id,0);const queue=[root.id];for(let cursor=0;cursor<queue.length;cursor++){const id=queue[cursor];for(const other of neighbors.get(id)||[]){if(!depths.has(other)){depths.set(other,depths.get(id)+1);queue.push(other)}}}}const maxDepth=Math.max(0,...depths.values()),rows=[],rowLimit=5;for(let depth=0;depth<=maxDepth;depth++){const layer=graph.nodes.filter(n=>depths.get(n.id)===depth).sort((a,b)=>(rank.get(a.category)??99)-(rank.get(b.category)??99)||a.label.localeCompare(b.label));for(let i=0;i<layer.length;i+=rowLimit)rows.push(layer.slice(i,i+rowLimit))}for(const category of categories){const layer=graph.nodes.filter(n=>!depths.has(n.id)&&n.category===category).sort((a,b)=>a.label.localeCompare(b.label));for(let i=0;i<layer.length;i+=rowLimit)rows.push(layer.slice(i,i+rowLimit))}const rowGap=230,nodeGap=220,width=Math.max(900,Math.max(1,...rows.map(row=>row.length))*nodeGap+160),height=Math.max(720,130+rows.length*rowGap);svg.setAttribute("viewBox",`0 0 ${width} ${height}`);const defs=document.createElementNS(ns,"defs"),arrow=document.createElementNS(ns,"marker"),arrowPath=document.createElementNS(ns,"path");arrow.setAttribute("id","edge-arrow");arrow.setAttribute("viewBox","0 0 10 10");arrow.setAttribute("refX","8");arrow.setAttribute("refY","5");arrow.setAttribute("markerWidth","6");arrow.setAttribute("markerHeight","6");arrow.setAttribute("orient","auto");arrowPath.setAttribute("d","M 0 0 L 10 5 L 0 10 z");arrowPath.setAttribute("fill","#718899");arrow.append(arrowPath);defs.append(arrow);svg.append(defs);const world=document.createElementNS(ns,"g");svg.append(world);let scale=1,ox=0,oy=0,moving=null,panning=null;rows.forEach((row,rowIndex)=>{const startX=(width-(row.length-1)*nodeGap)/2;row.forEach((n,index)=>pos.set(n.id,{x:startX+index*nodeGap,y:145+rowIndex*rowGap}));});let minX=Infinity,minY=Infinity,maxX=-Infinity,maxY=-Infinity;for(const n of graph.nodes){const p=pos.get(n.id);minX=Math.min(minX,p.x-24);maxX=Math.max(maxX,p.x+28+(n.display_label||n.label).length*8);minY=Math.min(minY,p.y-24);maxY=Math.max(maxY,p.y+24)}const fit=Math.min(1.3,(width-160)/(maxX-minX||1),(height-140)/(maxY-minY||1));scale=fit;ox=width/2-(minX+maxX)/2*scale;oy=height/2-(minY+maxY)/2*scale;function view(){world.setAttribute('transform',`translate(${ox} ${oy}) scale(${scale})`)}view();
function pathFor(e){const a=pos.get(e.source),b=pos.get(e.target);if(!a||!b)return '';const dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||1,ra=22,rb=22;return `M${a.x+dx/d*ra} ${a.y+dy/d*ra} L${b.x-dx/d*rb} ${b.y-dy/d*rb}`}
for(const e of graph.edges){const line=document.createElementNS(ns,'path');line.setAttribute('class','edge');line.setAttribute('d',pathFor(e));line.setAttribute('marker-end','url(#edge-arrow)');line.dataset.edge=graph.edges.indexOf(e);const title=document.createElementNS(ns,'title');title.textContent=[e.label,e.evidence].filter(Boolean).join(' · ');line.append(title);world.append(line);edgeEls.set(e,line)}
for(const n of graph.nodes){const p=pos.get(n.id),g=document.createElementNS(ns,'g');g.classList.add('node');if(n.primary)g.classList.add('primary');g.style.setProperty('--c',colors[n.category]||'#70d8e8');g.setAttribute('transform',`translate(${p.x} ${p.y})`);g.setAttribute('tabindex','0');g.setAttribute('role','button');g.setAttribute('aria-label',n.label);const circle=document.createElementNS(ns,'circle');circle.setAttribute('r',n.primary?'19':'15');const mark=document.createElementNS(ns,'text');mark.setAttribute('class','node-mark');mark.setAttribute('dominant-baseline','central');mark.setAttribute('text-anchor','middle');mark.setAttribute('y','0');mark.setAttribute('x','0');mark.textContent=n.os==='windows'?'▦':n.os==='linux'?'🐧':glyphs[n.category]||'•';g.append(circle,mark);const label=document.createElementNS(ns,'text');label.setAttribute('x','25');label.setAttribute('y','5');label.textContent=n.display_label||n.label;const title=document.createElementNS(ns,'title');title.textContent=n.label;g.prepend(title);g.append(label);g.addEventListener('click',()=>{if(!moving)selectNode(n)});g.addEventListener('pointerdown',ev=>{ev.stopPropagation();moving={node:n,el:g};g.setPointerCapture(ev.pointerId)});g.addEventListener('pointermove',ev=>{if(!moving||moving.node!==n)return;const r=svg.getBoundingClientRect(),x=(ev.clientX-r.left)/r.width*width,y=(ev.clientY-r.top)/r.height*height;p.x=(x-ox)/scale;p.y=(y-oy)/scale;g.setAttribute('transform',`translate(${p.x} ${p.y})`);for(const e of graph.edges)if(e.source===n.id||e.target===n.id)edgeEls.get(e).setAttribute('d',pathFor(e))});g.addEventListener('pointerup',()=>{moving=null});g.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();selectNode(n)}});world.append(g);els.set(n.id,g)}
function addDetails(title,items){const section=document.createElement('section');section.className='detail-section';const heading=document.createElement('h3');heading.textContent=title;section.append(heading);for(const field of items){const row=document.createElement('div');row.className='field';const label=document.createElement('strong');label.textContent=field.label;const value=document.createElement('p');value.textContent=field.value;row.append(label,value);section.append(row)}document.querySelector('#detail').append(section)}
function selectNode(n){for(const el of els.values())el.classList.remove('active');for(const item of tree.querySelectorAll('.leaf'))item.classList.remove('active');els.get(n.id).classList.add('active');n.treeItem.classList.add('active');document.querySelector('#empty').hidden=true;const panel=document.querySelector('#detail');panel.hidden=false;panel.replaceChildren();const name=document.createElement('div');name.className='detail-name';name.textContent=n.label;panel.append(name);const kind=document.createElement('div');kind.className='detail-kind';kind.textContent=n.group+' · '+n.kind+(n.os?' · '+n.os:'');panel.append(kind);if(n.summary){const summary=document.createElement('p');summary.className='detail-summary';summary.textContent=n.summary;panel.append(summary)}if(Array.isArray(n.sections)){for(const section of n.sections)addDetails(section.section,section.items)}else{const sections=new Map();for(const field of n.details){const title=field.section||'Asset';if(!sections.has(title))sections.set(title,[]);sections.get(title).push(field)}for(const [title,items] of sections)addDetails(title,items)}const links=graph.edges.filter(e=>e.source===n.id||e.target===n.id).map(e=>{const other=byId.get(e.source===n.id?e.target:e.source);const relation=e.source===n.id?e.label:e.label==='parent of'?'child of':e.label;return{label:other?.label||'Connection',value:[relation,e.evidence].filter(Boolean).join('\n')}});if(links.length)addDetails('Connections',links)}
function point(ev){const r=svg.getBoundingClientRect();return{x:(ev.clientX-r.left)/r.width*width,y:(ev.clientY-r.top)/r.height*height}}canvas.addEventListener('pointerdown',ev=>{if(ev.target.closest('.node'))return;const p=point(ev);panning={x:p.x-ox,y:p.y-oy};canvas.classList.add('grab');canvas.setPointerCapture(ev.pointerId)});canvas.addEventListener('pointermove',ev=>{if(!panning)return;const p=point(ev);ox=p.x-panning.x;oy=p.y-panning.y;view()});canvas.addEventListener('pointerup',()=>{panning=null;canvas.classList.remove('grab')});canvas.addEventListener('wheel',ev=>{ev.preventDefault();scale=Math.max(.35,Math.min(3,scale*(ev.deltaY<0?1.1:.9)));view()},{passive:false});document.querySelector('#plus').onclick=()=>{scale=Math.min(3,scale*1.2);view()};document.querySelector('#minus').onclick=()=>{scale=Math.max(.35,scale/1.2);view()};document.querySelector('#reset').onclick=()=>{scale=fit;ox=width/2-(minX+maxX)/2*scale;oy=height/2-(minY+maxY)/2*scale;view()};document.querySelector('#search').addEventListener('input',ev=>{const q=ev.target.value.toLowerCase().trim();for(const n of graph.nodes){const match=!q||n.label.toLowerCase().includes(q)||n.details.some(f=>f.value.toLowerCase().includes(q));els.get(n.id).style.opacity=match?'1':'.12';n.treeItem.hidden=!match}});document.querySelector('#footer').textContent='Mitsu · '+graph.nodes.length+' nodes · '+graph.edges.length+' links · '+(graph.mode||'Session Intel');
</script></body></html>'''
    return page.replace("__TITLE__", title).replace("__GRAPH__", data).replace("__LOGO__", logo)


def create_surface_map(session: dict[str, Any], session_root: Path, mapPlan: dict[str, Any] | None = None) -> dict[str, Any]:
    session_id = _text(session.get("id"), 64)
    if not re.fullmatch(r"[a-f0-9]{32}", session_id):
        raise ValueError("This session has no valid ID for saving its map.")
    mapPlan = mapPlan if isinstance(mapPlan, dict) else {}
    graph = build_surface_graph(session, mapPlan.get("connections", []))
    by_id = {node["id"]: node for node in graph["nodes"]}
    entities = mapPlan.get("entities", [])
    if isinstance(entities, list):
        for item in entities:
            if not isinstance(item, dict):
                continue
            node = by_id.get(_text(item.get("id"), 160))
            summary = item.get("summary")
            if node is None or not isinstance(summary, str) or summary.lstrip().startswith(("{", "[")):
                continue
            node["summary"] = summary.strip()[:1_200]
            sections = item.get("sections", [])
            if not isinstance(sections, list):
                continue
            clean = []
            for section in sections[:20]:
                if not isinstance(section, dict) or not isinstance(section.get("items"), list):
                    continue
                title = section.get("title")
                if not isinstance(title, str) or not title.strip():
                    continue
                fields = []
                for field in section["items"][:40]:
                    if not isinstance(field, dict):
                        continue
                    label, value = field.get("label"), field.get("value")
                    if not isinstance(label, str) or not isinstance(value, str) or not label.strip() or not value.strip():
                        continue
                    if value.lstrip().startswith(("{", "[")):
                        continue
                    fields.append({"label": label.strip()[:160], "value": value.strip()[:2_000]})
                if fields:
                    clean.append({"section": title.strip()[:100], "items": fields})
            if clean:
                node["sections"] = clean
    directory = session_root / session_id / "artifacts"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    destination = directory / "attack-surface-map.html"
    temporary = directory / ".attack-surface-map.html.tmp"
    temporary.write_text(_basic_html(graph), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(destination)
    return {"path": str(destination), "node_count": len(graph["nodes"]), "edge_count": len(graph["edges"]), "transcript_node_count": 0, "title": graph["title"]}
