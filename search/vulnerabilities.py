"""Search saved product intel across configured web engines and Exploit-DB."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import re
import shutil
import subprocess
from typing import Any, Callable

from .engines import search_web


_QUERY_CHARS = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:/+#-]{0,219}\Z")
_CVE = re.compile(r"\bCVE-\d{4}-\d{3,}\b", re.IGNORECASE)
_VERSION_CLUE = re.compile(r"\b[A-Za-z][A-Za-z0-9_.+-]*\s+v?\d+(?:\.\d+){0,3}\b")
_ATTRIBUTES = {"product", "vendor", "version", "technology", "service", "cpe"}


def _query_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    value = " ".join(value.split()).strip(" .,:;/")
    if len(value) > 220 or not _QUERY_CHARS.fullmatch(value):
        return ""
    try:
        ipaddress.ip_address(value)
        return ""
    except ValueError:
        return value


def vulnerability_queries(
    criteria: str, intel: dict[str, Any], limit: int = 4
) -> list[str]:
    queries: list[str] = []
    seen: set[str] = set()

    def add(value: Any, product_record: bool = False) -> None:
        query = _query_text(value)
        if not query or (not product_record and not _CVE.search(query) and not _VERSION_CLUE.search(query)):
            return
        key = query.casefold()
        if key not in seen and len(queries) < max(1, min(limit, 4)):
            seen.add(key)
            queries.append(query)

    if criteria.strip():
        query = _query_text(criteria)
        if not query:
            return []
        add(query, product_record=True)

    for asset in intel.get("assets", []):
        if not isinstance(asset, dict):
            continue
        attributes = asset.get("attributes", {})
        if not isinstance(attributes, dict):
            attributes = {}
        has_product = any(
            str(attributes.get(key, "")).strip()
            for key in ("vendor", "product", "technology", "cpe")
        )
        if asset.get("type") not in {"technology", "service"} and not has_product:
            continue
        parts = []
        if asset.get("type") == "technology" or not has_product:
            parts.append(_query_text(asset.get("value", "")))
        if isinstance(attributes, dict):
            parts.extend(
                _query_text(value)
                for key, value in attributes.items()
                if str(key).casefold() in _ATTRIBUTES
            )
        unique_parts = []
        seen_parts = set()
        for part in parts:
            if part and part.casefold() not in seen_parts:
                seen_parts.add(part.casefold())
                unique_parts.append(part)
        product_query = " ".join(unique_parts)
        add(product_query, product_record=True)
        if product_query and not _CVE.search(product_query):
            add(f"{product_query} CVE vulnerability", product_record=True)
            add(f"{product_query} RCE exploit", product_record=True)

    for section in ("findings", "exploits", "observations"):
        for record in intel.get(section, []):
            if isinstance(record, dict):
                add(record.get("title", ""))

    return queries


def search_exploitdb(
    query: str,
    executable: str | None = None,
    prefix: tuple[str, ...] = (),
) -> tuple[list[dict[str, str]], str | None]:
    executable = executable or shutil.which("searchsploit")
    if not executable:
        return [], "searchsploit is not installed"
    try:
        result = subprocess.run(
            [executable, *prefix, "--json", query],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return [], str(error) or type(error).__name__
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        detail = result.stderr.strip() or result.stdout.strip()
        return [], (detail[:240] if detail else "searchsploit returned unreadable output")

    rows = payload.get("RESULTS_EXPLOIT", []) if isinstance(payload, dict) else []
    references = []
    for row in rows[:8] if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        references.append(
            {
                "title": str(row.get("Title", "Untitled reference"))[:240],
                "id": str(row.get("EDB-ID", ""))[:40],
                "path": str(row.get("Path", ""))[:500],
            }
        )
    return references, None


def search_vulnx(
    query: str,
    executable: str | None = None,
    prefix: tuple[str, ...] = (),
) -> tuple[str, str | None]:
    executable = executable or shutil.which("vulnx")
    if not executable:
        return "", "vulnx is not installed"
    try:
        result = subprocess.run(
            [executable, *prefix, "search", query, "--limit", "8", "--json", "--silent"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return "", str(error) or type(error).__name__
    output = result.stdout.strip()
    if result.returncode:
        detail = result.stderr.strip() or output or f"vulnx exited with status {result.returncode}"
        return "", detail[:320]
    if not output:
        return "No matching vulnerability records.", None
    try:
        payload = json.loads(output)
        records = payload.get("results", []) if isinstance(payload, dict) else []
        if isinstance(records, list):
            fields = (
                "cve_id", "name", "description", "remediation", "severity", "cvss_score",
                "version", "affected_version", "affected_versions", "vulnerable_versions",
                "product", "vendor", "vuln_status",
                "poc", "poc_url", "exploit", "exploit_url", "references", "links",
                "url", "source_url",
            )
            compact_records = []
            for record in records[:8]:
                if not isinstance(record, dict):
                    continue
                compact = {key: record[key] for key in fields if key in record}
                for key, maximum in (
                    ("name", 180), ("description", 750), ("remediation", 300),
                    ("version", 200), ("affected_version", 240),
                    ("affected_versions", 300), ("vulnerable_versions", 300),
                    ("product", 100), ("vendor", 100), ("vuln_status", 80),
                    ("poc", 1000), ("poc_url", 500), ("exploit", 1000),
                    ("exploit_url", 500), ("references", 1200), ("links", 1000),
                    ("url", 500), ("source_url", 500),
                ):
                    if key not in compact:
                        continue
                    value = compact[key]
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, ensure_ascii=False)
                    if isinstance(value, str):
                        compact[key] = value[:maximum]
                citations = record.get("citations", [])
                if isinstance(citations, list):
                    compact["citations"] = [
                        {key: str(citation.get(key, ""))[:220] for key in ("source", "url") if citation.get(key)}
                        for citation in citations[:2]
                        if isinstance(citation, dict)
                    ]
                compact_records.append(compact)
            payload = {"count": payload.get("count", len(compact_records)), "results": compact_records}
        output = json.dumps(payload, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        pass
    return output[:32_000], None


def search_vulnerabilities(
    criteria: str,
    intel: dict[str, Any],
    configured: dict[str, dict[str, Any]],
    *,
    web_searcher: Callable[[str, int, dict[str, dict[str, Any]]], str] | None = None,
    local_searcher: Callable[[str], tuple[list[dict[str, str]], str | None]] | None = None,
    vulnx_searcher: Callable[[str], tuple[str, str | None]] | None = None,
    vulnx_result_sink: Callable[[str, str], None] | None = None,
    vulnx_status_sink: Callable[[str, str], None] | None = None,
    web_result_sink: Callable[[str, list[dict[str, Any]], list[str]], None] | None = None,
    local_result_sink: Callable[[str, list[dict[str, str]], str | None], None] | None = None,
    local_status: str = "",
    vulnx_status: str = "",
) -> str:
    if criteria.strip() and not _query_text(criteria):
        return "Use product, version, CVE, or vulnerability terms up to 220 characters."

    queries = vulnerability_queries(criteria, intel)
    if not queries:
        return "Add a product/version to session Intel or pass criteria, for example /vulnsearch OpenAM 16.0.5."

    use_default_web_searcher = web_searcher is None
    web_searcher = web_searcher or search_web
    local_searcher = local_searcher or search_exploitdb
    vulnx_queries = queries[:2] if vulnx_searcher else []
    web_results: list[tuple[str, str]] = []
    exploit_refs: list[tuple[str, dict[str, str]]] = []
    local_errors: list[str] = []
    vulnx_results: list[tuple[str, str]] = []
    vulnx_errors: list[str] = []
    seen_refs: set[str] = set()

    def search_web_query(query: str) -> tuple[str, str]:
        try:
            if use_default_web_searcher:
                result = search_web(
                    query,
                    3,
                    configured,
                    result_sink=(
                        (lambda records, errors: web_result_sink(query, records, errors))
                        if web_result_sink else None
                    ),
                )
                return query, result
            return query, web_searcher(query, 3, configured)
        except Exception as error:
            detail = f"Search provider error: {type(error).__name__}: {error}"
            if web_result_sink:
                web_result_sink(query, [], [detail])
            return query, detail

    with ThreadPoolExecutor(max_workers=min(4, len(queries))) as pool:
        web_results = list(pool.map(search_web_query, queries))

    for query in queries:
        try:
            references, error = local_searcher(query)
        except Exception as error:
            references, error = [], str(error) or type(error).__name__
        if error and error not in local_errors:
            local_errors.append(error)
        if local_result_sink:
            local_result_sink(query, references, error)
        for reference in references:
            identity = reference.get("id") or reference.get("title", "").casefold()
            if identity and identity not in seen_refs:
                seen_refs.add(identity)
                exploit_refs.append((query, reference))

    for query in vulnx_queries:
        try:
            result, error = vulnx_searcher(query)
        except Exception as error:
            result, error = "", str(error) or type(error).__name__
        if error and error not in vulnx_errors:
            vulnx_errors.append(error)
        if error and vulnx_status_sink:
            vulnx_status_sink(query, error)
        if result:
            vulnx_results.append((query, result))
            if vulnx_result_sink:
                vulnx_result_sink(query, result)

    lines = ["VULNSEARCH · leads from session Intel", "Queries: " + " · ".join(queries), "", "WEB REFERENCES"]
    for query, result in web_results:
        lines.extend((f"[{query}]", result[:5_000], ""))
    lines.append("LOCAL EXPLOIT-DB SNAPSHOT (SearchSploit)")
    for query, reference in exploit_refs[:12]:
        suffix = f" [EDB-{reference['id']}]" if reference.get("id") else ""
        if reference.get("path"):
            suffix += f" · {reference['path']}"
        lines.append(f"• {reference.get('title', 'Untitled reference')}{suffix} · query: {query}")
    if not exploit_refs:
        detail = local_status or ("; ".join(local_errors) if local_errors else "")
        lines.append("No references in the local Exploit-DB snapshot." if not detail else "Local lookup unavailable: " + detail)
    lines.append("VULNX REFERENCES")
    for query, result in vulnx_results:
        lines.extend((f"[{query}]", result, ""))
    if not vulnx_results:
        detail = vulnx_status or ("; ".join(vulnx_errors) if vulnx_errors else "not run")
        lines.append(f"No Vulnx results · {detail}")
    lines.extend(("", "Search results are unverified references. Check affected versions and prerequisites; no exploit was opened or run."))
    return "\n".join(lines)[:18_000]
