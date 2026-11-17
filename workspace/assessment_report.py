from __future__ import annotations

from datetime import datetime, timezone
import base64
from collections import Counter
import html
from html.parser import HTMLParser
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any
import unicodedata
import webbrowser

from mitsu import __version__
from mitsu.tools.redaction import redact_value


REPORT_SECTIONS = (
    ("assets", "Assets and services"),
    ("observations", "Observations"),
    ("exploits", "Exploit references"),
    ("accounts", "Accounts and access records"),
    ("manhunt", "People and external identities"),
)
REPORTABLE_SEVERITIES = {"critical", "high", "medium", "low"}

_SECRET_QUERY = re.compile(
    r"(?i)([?&](?:api[_-]?key|auth[_-]?token|refresh[_-]?token|id[_-]?token|access[_-]?token|"
    r"oob[_-]?code|password|passwd|secret|credential)=)[^&#\s\"'<>]+"
)
_FIREBASE_KEY = re.compile(r"(?i)\bAIza[0-9A-Za-z_-]*")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")
_PASSWORD_VALUE = re.compile(r"(?i)\b(password|passwd)(\s*[:=]\s*)([^\s,;]+)")
_JSON_SECRET = re.compile(
    r"(?i)([\"']?(?:password|passwd|token|secret|api[_-]?key|credential|oob[_-]?code)[\"']?\s*:\s*[\"']?)([^\"'\s,}&]+)"
)
_HTML_JSON_SECRET = re.compile(
    r"(?i)(&quot;(?:password|passwd|token|secret|api[_-]?key|credential|oob[_-]?code)&quot;\s*:\s*&quot;)(.*?)(?=&quot;)"
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


def _safe_text(value: str) -> str:
    value = re.sub(
        r"\[(?:critical|high|medium|low|informational|unknown)\s*\|\s*(?:confirmed|lead|candidate|unverified)\]\s*",
        "",
        value,
        flags=re.IGNORECASE,
    )
    value = _SECRET_QUERY.sub(r"\1[REDACTED]", value)
    value = _FIREBASE_KEY.sub("[REDACTED API KEY]", value)
    value = _JWT.sub("[REDACTED TOKEN]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _JSON_SECRET.sub(r"\1[REDACTED]", value)
    value = _HTML_JSON_SECRET.sub(r"\1[REDACTED]", value)
    value = _PASSWORD_VALUE.sub(r"\1\2[REDACTED]", value)
    value = _EMAIL.sub("[REDACTED EMAIL]", value)
    replacements = {
        "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
        "\u2212": "-", "\u00a0": " ", "\u202f": " ", "\u2022": "-", "\u00b7": "|",
        "\u2026": "...", "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    }
    for source, replacement in replacements.items():
        value = value.replace(source, replacement)
    value = unicodedata.normalize("NFKD", value)
    return "".join(
        character if ord(character) < 128 else "" if unicodedata.category(character) == "Mn" else " "
        for character in value
    )


def sanitize_report_value(value: Any) -> Any:
    value = redact_value(value)
    if isinstance(value, dict):
        return {key: sanitize_report_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_report_value(item) for item in value]
    if isinstance(value, str):
        return _safe_text(value)
    return value


class _ReportHTMLSanitizer(HTMLParser):
    _allowed = {
        "article", "blockquote", "br", "code", "dd", "div", "dl", "dt", "em", "footer", "h1", "h2", "h3", "h4",
        "header", "hr", "li", "main", "ol", "p", "pre", "section", "small", "span", "strong", "sub", "sup", "table",
        "tbody", "td", "tfoot", "th", "thead", "tr", "ul", "pdf:nextpage", "pdf:toc",
    }
    _void = {"br", "hr", "pdf:nextpage", "pdf:toc"}
    _discard = {"audio", "button", "canvas", "embed", "form", "iframe", "img", "input", "math", "object", "script", "style", "svg", "video"}
    _classes = {"cover", "finding", "note", "callout", "severity", "critical", "high", "medium", "low", "informational", "lead", "asset-table", "evidence", "toc-title"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.output: list[str] = []
        self.stack: list[str] = []
        self.discard_depth = 0
        self.toc_count = 0
        self.page_break_count = 0
        self.table_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.discard_depth:
            if tag not in self._void:
                self.discard_depth += 1
            return
        if tag == "table":
            self.table_count += 1
            if self.table_count > 2:
                self.discard_depth = 1
                return
        if tag in self._discard:
            self.discard_depth = 1
            return
        if tag not in self._allowed:
            return
        if tag == "pdf:toc":
            self.toc_count += 1
            if self.toc_count > 1:
                return
            self.output.append("<pdf:toc leader=\"dots\" />")
            return
        if tag == "pdf:nextpage":
            self.page_break_count += 1
            if self.page_break_count > 1:
                return
            self.output.append("<pdf:nextpage />")
            return
        safe_attrs = []
        for name, value in attrs:
            if value is None:
                continue
            if name == "class":
                classes = [item for item in value.split() if item in self._classes]
                if classes:
                    safe_attrs.append(f'class="{html.escape(" ".join(classes), quote=True)}"')
            elif tag in {"td", "th"} and name in {"colspan", "rowspan"} and value.isdigit():
                safe_attrs.append(f'{name}="{min(int(value), 20)}"')
            elif tag in {"table", "td", "th"} and name == "width" and re.fullmatch(r"\d{1,3}%?", value):
                safe_attrs.append(f'width="{value}"')
        attributes = "".join(f" {item}" for item in safe_attrs)
        if tag in self._void:
            self.output.append(f"<{tag}{attributes} />")
        else:
            self.output.append(f"<{tag}{attributes}>")
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self._void:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if self.discard_depth:
            self.discard_depth -= 1
            return
        if tag not in self.stack:
            return
        while self.stack:
            current = self.stack.pop()
            self.output.append(f"</{current}>")
            if current == tag:
                break

    def handle_data(self, data: str) -> None:
        if not self.discard_depth and data:
            self.output.append(html.escape(_safe_text(data), quote=False))

    def result(self, engagement: str = "Not recorded") -> str:
        while self.stack:
            self.output.append(f"</{self.stack.pop()}>")
        rendered = "".join(self.output).strip()
        if not rendered:
            raise ValueError("The model returned an empty HTML assessment.")
        if len(rendered) > 1_500_000:
            raise ValueError("The model-generated assessment is too large to convert safely.")
        def keep_code_only_for_code(match: re.Match[str]) -> str:
            content = match.group(1)
            plain = html.unescape(re.sub(r"<[^>]+>", "", content))
            if len(plain) > 120 and len(plain.split()) > 10:
                return content
            return match.group(0)

        rendered = re.sub(r"<code>(.*?)</code>", keep_code_only_for_code, rendered, flags=re.IGNORECASE | re.DOTALL)
        # Missing authorization is not useful report content; omit the model's empty placeholder.
        rendered = re.sub(
            r"<(p|li|dd)\b[^>]*>(?:(?!</\1>).)*(?:authorization|engagement authority)(?:(?!</\1>).)*not recorded(?:(?!</\1>).)*</\1>",
            "",
            rendered,
            flags=re.IGNORECASE | re.DOTALL,
        )
        cover = re.search(r'<(section|div|article|header|main) class="cover">.*?</\1>', rendered, flags=re.IGNORECASE | re.DOTALL)
        if cover is None:
            fallback_cover = (
                '<section class="cover"><h1>Vulnerability Assessment Report</h1>'
                f"<p>{html.escape(engagement, quote=True)}</p></section><pdf:nextpage />"
            )
            rendered = fallback_cover + rendered
            cover = re.search(r'<(section|div|article|header|main) class="cover">.*?</\1>', rendered, flags=re.IGNORECASE | re.DOTALL)
        if not re.search(r"<h[1-3](?:\s|>)", rendered, flags=re.IGNORECASE):
            rendered = rendered[:cover.end()] + "<section><h1>Assessment Details</h1></section>" + rendered[cover.end():]
            cover = re.search(r'<(section|div|article|header|main) class="cover">.*?</\1>', rendered, flags=re.IGNORECASE | re.DOTALL)
        after_cover = rendered[cover.end():]
        next_page = re.match(r"\s*<pdf:nextpage\s*/>", after_cover, flags=re.IGNORECASE)
        if not next_page:
            rendered = rendered[:cover.end()] + "<pdf:nextpage />" + after_cover
            break_end = cover.end() + len("<pdf:nextpage />")
        else:
            break_end = cover.end() + len(next_page.group(0))
        if self.toc_count == 0:
            toc = '<section><p class="toc-title">Table of Contents</p><pdf:toc leader="dots" /><pdf:nextpage /></section>'
            rendered = rendered[:break_end] + toc + rendered[break_end:]
        toc = re.search(r"<pdf:toc\s+leader=\"dots\"\s*/>", rendered, flags=re.IGNORECASE)
        if toc and not re.match(r"\s*<pdf:nextpage\s*/>", rendered[toc.end():], flags=re.IGNORECASE):
            rendered = rendered[:toc.end()] + "<pdf:nextpage />" + rendered[toc.end():]
        return rendered


def sanitize_report_html(value: str, engagement: str = "Not recorded") -> str:
    sanitizer = _ReportHTMLSanitizer()
    sanitizer.feed(value)
    sanitizer.close()
    return sanitizer.result(engagement)


def prepare_report_intel(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    selected = dict(source)
    for section, _ in REPORT_SECTIONS + (("findings", "Findings"),):
        records = source.get(section, [])
        if not isinstance(records, list):
            selected[section] = []
            continue
        latest: dict[str, tuple[str, Any]] = {}
        unique: list[Any] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict) or not record.get("id"):
                unique.append(record)
                continue
            record_id = str(record["id"])
            recorded = str(record.get("updated_at") or record.get("first_seen") or "")
            previous = latest.get(record_id)
            if previous is None:
                latest[record_id] = (recorded, record)
            elif recorded >= previous[0]:
                latest[record_id] = (recorded, record)
        unique.extend(item for _, item in latest.values())
        selected[section] = unique
    return sanitize_report_value(selected)


def _compact_report_value(value: Any, limit: int = 600, depth: int = 0) -> Any:
    if depth >= 3:
        return _text(value, limit)
    if isinstance(value, dict):
        return {
            str(key): _compact_report_value(item, limit, depth + 1)
            for key, item in value.items()
            if key not in {"legacy_value", "schema_version", "raw_output", "debug"}
        }
    if isinstance(value, list):
        return [_compact_report_value(item, limit, depth + 1) for item in value[:3]]
    if isinstance(value, str):
        return _safe_text(value.strip())[:limit]
    return value


def _target_value(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("value") or value.get("target") or value.get("host") or value.get("name") or ""
    return _text(value, 240)


def _scope_tag(value: Any) -> str:
    return re.sub(r"[\s-]+", "_", str(value or "").casefold().strip())


def _target_matches(reference: Any, target: str) -> bool:
    value = _target_value(reference).casefold().strip().rstrip("/")
    wanted = target.casefold().strip().rstrip("/")
    if not value or not wanted:
        return False
    value = re.sub(r"^https?://", "", value)
    wanted = re.sub(r"^https?://", "", wanted)
    return value == wanted or value.endswith("." + wanted) or value.startswith(wanted + "/") or value.startswith(wanted + ":")


def _asset_type_label(value: Any) -> str:
    key = str(value or "other").casefold().replace("_", " ").strip()
    labels = {
        "ip": "IP address",
        "ip address": "IP address",
        "endpoint": "API endpoint",
        "api endpoint": "API endpoint",
        "technology": "Technology",
        "domain": "Domain",
        "service": "Service",
        "target": "Target",
        "url": "URL",
    }
    return labels.get(key, key.title())


def _protective_control(record: dict[str, Any]) -> bool:
    text = " ".join(
        str(record.get(key) or "")
        for key in ("title", "summary", "description", "evidence", "recommendation")
    ).casefold()
    rules_block = re.search(r"(?:firestore|database|security) rules?.{0,100}(?:block|deny|prevent)", text)
    denied_write = "permission_denied" in text and re.search(r"credit|forge|unauthor|write", text)
    waf_block = "waf" in text and ("x-vercel-mitigated" in text or "403" in text) and "bypass" not in text
    return bool(rules_block or denied_write or waf_block)


def _token_url_pattern_only(record: dict[str, Any]) -> bool:
    text = " ".join(
        str(record.get(key) or "")
        for key in ("title", "summary", "description", "evidence", "proof_of_concept", "reproduction_steps")
    ).casefold()
    token_parameter = re.search(r"\b(?:auth|refresh|id|access)[_-]?token\b", text)
    pattern_marker = re.search(r"<\s*jwt\s*>|\bpatterns?\b|placeholder", text)
    validated_use = re.search(r"(?:token|credential).{0,80}(?:replay(?:ed|ability)?|accepted|authorized)|(?:replay(?:ed|ability)?|authorized).{0,80}(?:token|credential)", text)
    return bool(token_parameter and pattern_marker and not validated_use)


def _requires_owner_confirmation(record: dict[str, Any]) -> bool:
    text = " ".join(
        str(record.get(key) or "")
        for key in ("title", "summary", "description", "evidence", "recommendation")
    ).casefold()
    signup_behavior = re.search(r"(?:unauthenticated|public|open) account registration|account registration", text)
    reset_behavior = re.search(r"send.?oob.?code|oob confirmation|password reset", text)
    explicit_policy = re.search(r"disabled sign.?up|registration (?:is )?(?:prohibited|disabled)|invite.only|policy forbids", text)
    demonstrated_abuse = re.search(r"email enumeration (?:confirmed|validated)|rate limit(?:ing)? bypass|mail bomb(?:ing)? confirmed", text)
    if (signup_behavior or reset_behavior) and not (explicit_policy or demonstrated_abuse):
        return True
    return False


def _report_finding_copy(record: dict[str, Any]) -> dict[str, Any]:
    item = dict(record)
    title = str(item.get("title") or item.get("name") or "")
    text = " ".join(str(item.get(key) or "") for key in ("title", "summary", "description", "evidence")).casefold()
    if re.search(r"auth_token|refresh_token|jwt", text) and re.search(r"url|query.string|parameter", text):
        item["title"] = "Authentication tokens exposed in URL parameters"
        item["summary"] = (
            "Session Intel records URL query-string patterns containing auth_token or refresh_token values. "
            "Values are redacted in this report. The session does not establish whether a captured token was active "
            "or replayable, so account access or takeover was not confirmed."
        )
        item["impact"] = (
            "If a captured token remained active and replayable, it could allow access using the associated session's "
            "privileges. This impact was not validated in the session."
        )
        item["recommendation"] = (
            "Keep bearer and refresh tokens out of URLs. Use secure authorization headers or cookies, review browser, "
            "proxy and server logs for token exposure, and revoke tokens confirmed to be active."
        )
    elif title.casefold().startswith("firebase api key"):
        item["title"] = "Firebase authentication behavior requires security review"
    return item


def _reportable_findings(intel: dict[str, Any]) -> list[dict[str, Any]]:
    findings = [
        record for record in intel.get("findings", [])
        if isinstance(record, dict)
        and str(record.get("status", "")).casefold() == "confirmed"
        and str(record.get("severity", "")).casefold() in REPORTABLE_SEVERITIES
        and not _protective_control(record)
        and not _token_url_pattern_only(record)
        and not _requires_owner_confirmation(record)
    ]
    unique: list[dict[str, Any]] = []
    for record in findings:
        text = " ".join(str(record.get(key) or "") for key in ("title", "summary", "evidence")).casefold()
        if "project id discovered" in str(record.get("title", "")).casefold() and not re.search(
            r"token|credential|unauthor|data exposure|access bypass", text
        ):
            continue
        unique.append(record)
    return [_report_finding_copy(record) for record in unique]


def _reporting_scope(session: dict[str, Any], intel: dict[str, Any]) -> dict[str, list[str]]:
    raw_targets = session.get("targets", [])
    if isinstance(raw_targets, str):
        raw_targets = [raw_targets]
    targets = list(dict.fromkeys(filter(None, (_target_value(item) for item in raw_targets)))) if isinstance(raw_targets, list) else []
    assets = [row for row in intel.get("assets", []) if isinstance(row, dict)]
    explicit_in = [
        _target_value(row.get("value") or row.get("name"))
        for row in assets
        if _scope_tag(row.get("scope")) in {"in", "in_scope"}
    ]
    explicit_out = [
        _target_value(row.get("value") or row.get("name"))
        for row in assets
        if _scope_tag(row.get("scope")) in {"out", "out_of_scope"}
    ]
    return {
        "operator_targets": targets,
        "explicit_in_scope_assets": list(dict.fromkeys(filter(None, explicit_in))),
        "explicit_exclusions": list(dict.fromkeys(filter(None, explicit_out))),
    }


def _scope_section(session: dict[str, Any], intel: dict[str, Any]) -> str:
    scope = _reporting_scope(session, intel)
    targets = scope["operator_targets"]
    in_scope = scope["explicit_in_scope_assets"]
    exclusions = scope["explicit_exclusions"]
    known = {value.casefold().rstrip("/") for value in targets + in_scope + exclusions}
    unknown_assets = [
        _target_value(row.get("value") or row.get("name"))
        for row in intel.get("assets", [])
        if isinstance(row, dict)
        and _scope_tag(row.get("scope")) in {"", "unknown", "not_recorded"}
        and _target_value(row.get("value") or row.get("name")).casefold().rstrip("/") not in known
    ]
    parts = [
        '<section class="assessment-scope"><h1>Objectives and Scope</h1>',
        '<p>The assessment objective was to identify and validate security weaknesses affecting the named target. '
        'Only issues supported by recorded evidence are reported as findings.</p>',
    ]
    if targets:
        parts.append(f'<p><strong>Assessment target:</strong> {_esc(", ".join(targets))}</p>')
    if in_scope:
        additional = [value for value in in_scope if value.casefold().rstrip("/") not in {target.casefold().rstrip("/") for target in targets}]
        if additional:
            parts.append(f'<p><strong>Additional assets explicitly in scope:</strong> {_esc(", ".join(additional))}</p>')
    if exclusions:
        parts.append(f'<p><strong>Explicit exclusions:</strong> {_esc(", ".join(exclusions))}</p>')
    if unknown_assets:
        parts.append(
            '<p>Additional discovered assets had no recorded scope designation. They are treated as observations and are not '
            'represented as in-scope assessment targets.</p>'
        )
    parts.append("</section>")
    return "".join(parts)


def _target_profiles(session: dict[str, Any], intel: dict[str, Any]) -> list[dict[str, Any]]:
    raw_targets = session.get("targets", [])
    if isinstance(raw_targets, str):
        raw_targets = [raw_targets]
    targets = list(dict.fromkeys(filter(None, (_target_value(item) for item in raw_targets)))) if isinstance(raw_targets, list) else []
    assets = [row for row in intel.get("assets", []) if isinstance(row, dict)]
    if not targets:
        targets = list(dict.fromkeys(
            _target_value(row.get("value") or row.get("name"))
            for row in assets
            if row.get("primary") or str(row.get("scope", "")).casefold() in {"in", "in-scope", "in_scope"}
        ))
        targets = [target for target in targets if target]
    findings = [row for row in intel.get("findings", []) if isinstance(row, dict)]
    reportable = _reportable_findings(intel)
    observations = [row for row in intel.get("observations", []) if isinstance(row, dict)]
    exploits = [row for row in intel.get("exploits", []) if isinstance(row, dict)]
    profiles = []
    for target in targets[:20]:
        target_assets = [row for row in assets if _target_matches(row.get("value") or row.get("name"), target)]
        target_findings = [row for row in findings if _target_matches(row.get("asset") or row.get("target"), target)]
        target_reportable = [row for row in reportable if _target_matches(row.get("asset") or row.get("target"), target)]
        target_observations = [row for row in observations if _target_matches(row.get("asset"), target)]
        target_exploits = [row for row in exploits if _target_matches(row.get("asset") or row.get("target"), target)]
        if len(targets) == 1:
            target_assets = assets
            target_findings = findings
            target_reportable = reportable
            target_observations = observations
            target_exploits = exploits
        confirmed = [
            row for row in target_reportable
            if str(row.get("status", "")).casefold() == "confirmed"
        ]
        severity_counts = Counter(str(row.get("severity") or "Not rated").casefold() for row in confirmed)
        asset_types = Counter(str(row.get("type") or "Other").casefold() for row in target_assets)
        profiles.append({
            "target": target,
            "asset_count": len(target_assets),
            "asset_types": dict(asset_types),
            "confirmed_count": len(confirmed),
            "confirmed_by_severity": dict(severity_counts),
            "observation_count": len(target_observations),
            "exploit_record_count": len(target_exploits),
            "confirmed_findings": [
                _compact_report_value({
                    key: row.get(key)
                    for key in ("id", "title", "severity", "asset")
                    if row.get(key) not in (None, "", [], {})
                }, 180)
                for row in confirmed[:15]
            ],
        })
    return profiles


def report_model_context(session: dict[str, Any]) -> dict[str, Any]:
    intel = prepare_report_intel(session.get("intel", {}))
    confirmed = []
    control_observations = []
    for record in _reportable_findings(intel):
        fields = {
            "id": record.get("id"),
            "title": record.get("title") or record.get("name"),
            "status": record.get("status"),
            "severity": record.get("severity"),
            "confidence": record.get("confidence"),
            "asset": record.get("asset") or record.get("target"),
            "summary": record.get("summary") or record.get("description"),
            "evidence": record.get("evidence"),
            "recommendation": record.get("recommendation"),
            "cve": record.get("cve"),
            "recorded_at": record.get("first_seen"),
        }
        confirmed.append(_compact_report_value(fields, 700))
    for record in intel.get("findings", []):
        if not isinstance(record, dict):
            continue
        status = str(record.get("status", "")).casefold()
        if status == "confirmed" and _token_url_pattern_only(record):
            continue
        if status == "confirmed" and (_protective_control(record) or str(record.get("severity", "")).casefold() == "informational"):
            control_observations.append(_compact_report_value({
                "title": record.get("title") or record.get("name"),
                "summary": record.get("summary") or record.get("description"),
            }, 260))
            continue
        # Only validated findings and useful controls belong in a client deliverable.
        # Leads, scan matches, and owner-policy-dependent behavior stay in session Intel.
        if status != "confirmed":
            continue
    sections: dict[str, Any] = {}
    fields_by_section = {
        "assets": ("id", "value", "name", "type", "scope", "verification", "confidence", "parent"),
        "observations": ("id", "title", "asset", "category", "status", "confidence", "details", "evidence", "worked", "failed", "next_step", "source", "first_seen"),
        "exploits": ("id", "title", "name", "cve", "asset", "target", "status", "summary", "evidence", "confidence", "source"),
        "accounts": ("id", "name", "username", "email", "asset", "role", "status", "details", "source"),
        "manhunt": ("id", "name", "role", "organization", "profile", "source", "details", "confidence", "status"),
    }
    for section, fields in fields_by_section.items():
        rows = intel.get(section, [])
        if section == "observations":
            rows = [
                row for row in rows if isinstance(row, dict)
                and str(row.get("status", "")).casefold() not in {"lead", "candidate", "unverified", "unknown"}
                and not re.search(r"\bCVE-\d{4}-\d+|vulnx", str(row.get("title") or row.get("name") or ""), re.IGNORECASE)
            ]
        elif section == "exploits":
            rows = [
                row for row in rows if isinstance(row, dict)
                and (str(row.get("status", "")).casefold() in {"confirmed", "validated", "successful", "exploited"}
                     or row.get("worked") is True)
            ]
        sections[section] = [
            _compact_report_value({key: row.get(key) for key in fields if row.get(key) not in (None, "", [], {})}, 160)
            for row in rows
            if isinstance(row, dict)
        ]
    return {
        "session": _compact_report_value({
            key: session.get(key)
            for key in ("id", "title", "summary", "targets", "created_at", "updated_at")
        }, 1_200),
        "reporting_scope": _reporting_scope(session, intel),
        "assets_and_intel": sections,
        "target_profiles": _target_profiles(session, intel),
        "findings": {
            "confirmed": confirmed,
            "confirmed_count": len(confirmed),
            "other_statuses": [],
        },
        "controls_observed": control_observations[:8],
        "appendix_policy": "Include only confirmed, evidence-supported security findings rated low, medium, high, or critical. Exclude unverified leads, candidate CVEs, scan-only matches, and ordinary behavior that has no demonstrated security impact from the client-facing report.",
    }


def _text(value: Any, limit: int = 8_000) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = _readable(value)
    return _safe_text(str(value).strip())[:limit]


def _readable(value: Any) -> str:
    if isinstance(value, dict):
        if {"source", "details"} & value.keys():
            parts = []
            source = _text(value.get("source"), 300)
            details = _text(value.get("details"), 4_000)
            confidence = _text(value.get("confidence"), 80)
            recorded = _text(value.get("recorded_at"), 100)
            if source:
                parts.append(source)
            if details:
                parts.append(details)
            if confidence:
                parts.append(f"{confidence} confidence")
            if recorded:
                parts.append(recorded.replace("T", " ").replace("+00:00", " UTC"))
            return " · ".join(parts)
        return "\n".join(f"{_text(key, 200)}: {_readable(item)}" for key, item in value.items())
    if isinstance(value, list):
        return "\n".join(_readable(item) for item in value if item not in (None, "", [], {}))
    return str(value)


def _esc(value: Any) -> str:
    return html.escape(_text(value), quote=True).replace("\n", "<br>")


def _finding_evidence(value: Any) -> str:
    text = _text(value, 1_600)
    text = re.sub(r"\s*\|\s*", "\n", text)
    text = re.sub(
        r"\s*(?:\||·)\s*(?:critical|high|medium|low|informational|unknown)\s+confidence\b.*$",
        "",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return text.strip()


def _excerpt(value: Any, limit: int) -> str:
    text = _text(value, limit + 1)
    return text[:limit - 3].rstrip() + "..." if len(text) > limit else text


def _intel_appendices(intel: dict[str, Any], session: dict[str, Any]) -> tuple[str, str]:
    findings = _reportable_findings(intel)
    controls = [
        record for record in intel.get("findings", [])
        if isinstance(record, dict)
        and str(record.get("status", "")).casefold() == "confirmed"
        and (
            str(record.get("severity", "")).casefold() == "informational"
            or _protective_control(record)
        )
    ]
    control_summary = ""
    if controls:
        control_items = []
        for record in controls:
            title = _text(record.get("title") or record.get("name"), 160)
            summary = _excerpt(record.get("summary") or record.get("description"), 220)
            if _protective_control(record) or re.search(
                r"waf|firewall|permission denied|not accessible|blocked",
                title + " " + summary,
                re.IGNORECASE,
            ):
                control_items.append(f"<li>{_esc(summary or title)}</li>")
        if control_items:
            control_summary = (
                '<section class="control-notes"><h2>Controls observed</h2>'
                '<p>These observations describe protective behavior, not vulnerabilities.</p>'
                f'<ul>{"".join(control_items[:4])}</ul></section>'
            )
    target_names = [profile["target"] for profile in _target_profiles(session, intel)]
    target_groups: list[tuple[str, list[dict[str, Any]]]] = []
    assigned: set[str] = set()
    for target in target_names:
        group = [
            record for record in findings
            if _target_matches(record.get("asset") or record.get("target"), target)
        ]
        if len(target_names) == 1:
            group = findings
        target_groups.append((target, group))
        assigned.update(str(record.get("id") or id(record)) for record in group)
    remaining = [record for record in findings if str(record.get("id") or id(record)) not in assigned]
    if remaining or not target_groups:
        target_groups.append(("Unattributed findings", remaining or findings))

    finding_sections = []
    for target, records in target_groups:
        if not records:
            continue
        cards = []
        for index, record in enumerate(records, 1):
            title = record.get("title") or record.get("name") or f"Finding {index}"
            severity = str(record.get("severity") or "Not rated").casefold()
            severity_class = severity if severity in {"critical", "high", "medium", "low", "informational"} else "unknown"
            record_id = _text(record.get("id"), 64)
            asset = _text(record.get("asset") or record.get("target"), 240)
            summary = _excerpt(record.get("summary") or record.get("description"), 420)
            evidence = _excerpt(_finding_evidence(record.get("evidence")), 900)
            proof = _excerpt(
                record.get("proof_of_concept") or record.get("poc") or record.get("reproduction_steps") or record.get("steps"),
                480,
            )
            impact = _excerpt(record.get("impact") or record.get("business_impact"), 420)
            recommendation = _excerpt(record.get("recommendation") or record.get("remediation"), 480)
            cve = _text(record.get("cve"), 160)
            cvss = _text(record.get("cvss") or record.get("cvss_score"), 80)
            confidence = _text(record.get("confidence"), 60)
            metadata = [f'<span class="severity-badge {severity_class}">{_esc(severity.title())}</span>']
            if asset:
                metadata.append(f'<span><strong>Asset</strong> {_esc(asset)}</span>')
            if cve:
                metadata.append(f'<span><strong>{_esc(cve)}</strong></span>')
            if cvss:
                metadata.append(f'<span><strong>CVSS</strong> {_esc(cvss)}</span>')
            if record_id:
                metadata.append(f'<span><strong>ID</strong> {_esc(record_id[:12])}</span>')
            if confidence:
                metadata.append(f'<span><strong>Confidence</strong> {_esc(confidence.title())}</span>')
            parts = [
                f'<div class="finding-card"><h3>{index}. {_esc(title)}</h3>',
                f'<p class="finding-meta">{" · ".join(metadata)}</p>',
            ]
            if summary:
                parts.append(f'<p><strong>Finding</strong><br>{_esc(summary)}</p>')
            if impact:
                parts.append(f'<p><strong>Impact</strong><br>{_esc(impact)}</p>')
            if proof:
                parts.append(f'<p><strong>Reproduction</strong><br>{_esc(proof)}</p>')
            if evidence:
                parts.append(f'<p><strong>Evidence</strong><br>{_esc(evidence)}</p>')
            if recommendation:
                parts.append(f'<p><strong>Recommended remediation</strong><br>{_esc(recommendation)}</p>')
            parts.append("</div>")
            cards.append("".join(parts))
        finding_sections.append(
            f'<section class="target-finding-group"><h2>{_esc(target)} · Confirmed findings ({len(records)})</h2>{"".join(cards)}</section>'
        )

    if not finding_sections and not control_summary and not any(intel.get(key, []) for key in ("assets", "observations", "exploits")):
        return "", ""
    assets = [record for record in intel.get("assets", []) if isinstance(record, dict)][:20]
    asset_rows = []
    for record in assets:
        name = record.get("value") or record.get("name") or record.get("id") or "Asset"
        asset_type = _asset_type_label(record.get("type"))
        details = [asset_type] if asset_type else []
        scope = _scope_tag(record.get("scope"))
        scope_label = {
            "in": "In scope",
            "in_scope": "In scope",
            "in-scope": "In scope",
            "out": "Explicitly out of scope",
            "out_of_scope": "Explicitly out of scope",
            "out-of-scope": "Explicitly out of scope",
            "unknown": "Scope not established",
        }.get(scope)
        if scope_label:
            details.append(scope_label)
        verification = str(record.get("verification") or "").casefold()
        verification_label = {
            "validated": "Verified",
            "discovered": "Discovered",
            "unverified": "Not verified",
        }.get(verification)
        if verification_label:
            details.append(verification_label)
        detail_text = " · ".join(_text(item, 120) for item in details)
        asset_rows.append(f"<li><strong>{_esc(name)}</strong>{' · ' + _esc(detail_text) if detail_text else ''}</li>")
    activity_sections = []
    for key, label, detail_fields in (
        ("observations", "Test activity", ("details", "evidence", "next_step")),
        ("exploits", "Exploit references", ("summary", "evidence")),
    ):
        records = [record for record in intel.get(key, []) if isinstance(record, dict)]
        if key == "observations":
            records = [record for record in records
                       if str(record.get("status", "")).casefold() not in {"lead", "candidate", "unverified", "unknown"}
                       and not re.search(r"\bCVE-\d{4}-\d+|vulnx", str(record.get("title") or record.get("name") or ""), re.IGNORECASE)]
        else:
            records = [record for record in records
                       if str(record.get("status", "")).casefold() in {"confirmed", "validated", "successful", "exploited"}
                       or record.get("worked") is True]
        if not records:
            continue
        entries = []
        for record in records[:8]:
            title = record.get("title") or record.get("name") or record.get("id") or label
            if key == "observations" and re.search(r"\bCVE-\d{4}-\d+|vulnx", str(title), re.IGNORECASE):
                continue
            if record.get("worked") is True or str(record.get("worked", "")).casefold() in {"yes", "true", "worked", "success"}:
                state = "validated"
            elif record.get("failed") is True or str(record.get("failed", "")).casefold() in {"yes", "true", "failed"}:
                state = "blocked or unsuccessful"
            else:
                state = record.get("status")
            detail = next((_excerpt(record.get(field), 120 if key == "observations" else 150) for field in detail_fields if record.get(field)), "")
            suffix = f" <span class=\"activity-state\">({_esc(state)})</span>" if state else ""
            entries.append(f"<li><strong>{_esc(title)}</strong>{suffix}{'<br>' + _esc(detail) if detail else ''}</li>")
        activity_sections.append(f"<section><h2>{label}</h2><ul class=\"activity-list\">{''.join(entries)}</ul></section>")
    asset_section = (
        f'<section><h2>Observed asset register ({len(intel.get("assets", []))})</h2><ul class="asset-list">{"".join(asset_rows)}</ul></section>'
        if asset_rows else ""
    )
    findings_report = ""
    if finding_sections:
        findings_report = (
            '<pdf:nextpage /><section><h1>Detailed Findings</h1>'
            '<p>Each confirmed issue is presented with its affected asset, recorded validation evidence, and recommended corrective action.</p></section>'
            + "".join(finding_sections)
        )
    results_notes = control_summary
    supporting_appendices = asset_section + "".join(activity_sections)
    return findings_report + results_notes, supporting_appendices


def _target_visuals(session: dict[str, Any], intel: dict[str, Any]) -> str:
    profiles = _target_profiles(session, intel)
    if not profiles:
        return ""
    severity_order = ("critical", "high", "medium", "low")
    colors = {
        "critical": "#b4232f",
        "high": "#df5a35",
        "medium": "#d79525",
        "low": "#3d8c69",
    }
    panels = []
    for profile in profiles:
        name = _esc(profile["target"])
        risk = profile["confirmed_by_severity"]
        risk_total = sum(risk.values())
        risk_rows = []
        if risk_total:
            for severity in severity_order:
                count = int(risk.get(severity, 0))
                if not count:
                    continue
                width = max(3, round(count / risk_total * 100))
                risk_rows.append(
                    f'<div class="chart-row"><span class="chart-label">{_esc(severity.title())}</span>'
                    f'<span class="chart-track"><span class="chart-fill" style="width:{width}%;background-color:{colors[severity]}"></span></span>'
                    f'<strong class="chart-value">{count}</strong></div>'
                )
            risk_markup = "".join(risk_rows)
        else:
            risk_markup = '<p class="chart-empty">No confirmed findings recorded.</p>'
        asset_types = profile["asset_types"]
        asset_total = sum(asset_types.values())
        asset_rows = []
        for asset_type, count in sorted(asset_types.items(), key=lambda pair: (-pair[1], pair[0]))[:6]:
            width = max(3, round(count / asset_total * 100)) if asset_total else 0
            asset_rows.append(
                f'<div class="chart-row"><span class="chart-label">{_esc(_asset_type_label(asset_type))}</span>'
                f'<span class="chart-track"><span class="chart-fill asset-fill" style="width:{width}%"></span></span>'
                f'<strong class="chart-value">{count}</strong></div>'
            )
        asset_markup = "".join(asset_rows) or '<p class="chart-empty">No asset categories recorded.</p>'
        panels.append(
        f'<section class="target-visual"><h2>{name}</h2>'
            f'<p>{profile["asset_count"]} indexed assets · {profile["confirmed_count"]} confirmed findings</p>'
        f'<h3>Confirmed findings by severity</h3>{risk_markup}'
        f'<h3>Observed asset types</h3>{asset_markup}'
            '</section>'
        )
    return '<section class="target-visuals"><h1>Target Overview</h1>' + "".join(panels) + "</section>"


def _report_cover(session: dict[str, Any], intel: dict[str, Any]) -> str:
    profiles = _target_profiles(session, intel)
    targets = [profile["target"] for profile in profiles]
    target_label = " · ".join(_esc(target) for target in targets[:4])
    if len(targets) > 4:
        target_label += f" and {len(targets) - 4} additional targets"
    subtitle = f'<p class="cover-subtitle">{target_label}</p>' if target_label else ""
    return (
        '<div class="cover report-cover">'
        '<img class="cover-background" src="cover.png" alt="" />'
        '<div class="cover-content">'
        '<h1>Vulnerability Assessment Report</h1>'
        '<div class="cover-rule"></div>'
        + subtitle
        + '</div>'
        + '<div class="cover-brand">'
        + '<img src="mitsu-logo.png" alt="" />'
        + '<strong>Mitsu</strong>'
        + '<span>Agentic RedTeam Framework</span>'
        + '</div>'
        + '</div>'
    )


def build_assessment_html(session: dict[str, Any], report_html: str) -> str:
    engagement = _text(session.get("title"), 180) or "Not recorded"
    body = sanitize_report_html(report_html, engagement)
    body = re.sub(
        r'<(section|div|article|header|main) class="cover">.*?</\1>\s*(?:<pdf:nextpage\s*/>)?',
        "",
        body,
        count=1,
        flags=re.IGNORECASE | re.DOTALL,
    )
    body = re.sub(
        r"(?is)<li\b[^>]*>(?:(?!</li>).)*(?:authorization|rules[- ]of[- ]engagement)(?:(?!</li>).)*(?:not recorded|was not recorded)(?:(?!</li>).)*</li>",
        "",
        body,
    )
    body = re.sub(
        r"(?i)\bNo authorization\b[^.;!?]*(?:was|is)\s+recorded[^.;!?]*[;.]?\s*",
        "",
        body,
    )
    body = re.sub(r"(?is)<p>\s*The renderer supplies[^<]*?</p>", "", body)
    # AI prose must not reintroduce speculative Intel as client-facing sections.
    body = re.sub(
        r"(?is)<section\b[^>]*>\s*<h[1-4]\b[^>]*>\s*(?:Unverified Leads?(?: \(Summary\))?|Unverified lead summary(?: \(\d+\))?|Owner[- ]Review Observations(?: \(Behavior Requiring Confirmation\))?|Behavior Requiring Confirmation|Validation note)\s*</h[1-4]>.*?</section>",
        "",
        body,
    )
    body = re.sub(
        r"(?is)<h[1-4]\b[^>]*>\s*(?:Unverified Leads?(?: \(Summary\))?|Unverified lead summary(?: \(\d+\))?|Owner[- ]Review Observations(?: \(Behavior Requiring Confirmation\))?|Behavior Requiring Confirmation|Validation note)\s*</h[1-4]>.*?(?=<h[1-4]\b|</section>|$)",
        "",
        body,
    )
    body = re.sub(
        r"(?is)<section>\s*<h[1-3]\b[^>]*>\s*Detailed Findings\s*</h[1-3]>\s*(?:<p>.*?</p>\s*)?</section>",
        "",
        body,
    )
    body = re.sub(
        r"(?is)<h[1-3]\b[^>]*>\s*Detailed Findings\s*</h[1-3]>\s*(?:<p\b[^>]*>.*?</p>\s*)?",
        "",
        body,
    )
    body = re.sub(r"(?is)<section>\s*</section>", "", body)
    intel = prepare_report_intel(session.get("intel", {}))
    body = re.sub(
        r"(?is)<section>\s*<h[1-3]\b[^>]*>\s*(?:Objectives and Scope|Scope)\s*</h[1-3]>.*?</section>",
        "",
        body,
    )
    scope_section = _scope_section(session, intel)
    executive_heading = re.search(r"<h[1-3]\b[^>]*>\s*Executive Summary\s*</h[1-3]>", body, flags=re.IGNORECASE)
    if executive_heading:
        executive_end = body.find("</section>", executive_heading.end())
        if executive_end >= 0:
            executive_end += len("</section>")
            body = body[:executive_end] + scope_section + body[executive_end:]
        else:
            body = scope_section + body
    else:
        body = scope_section + body
    appendices_heading = re.search(r"<h[1-3]\b[^>]*>\s*Supporting Appendices\s*</h[1-3]>", body, flags=re.IGNORECASE)
    if appendices_heading:
        appendices_start = body.rfind("<section", 0, appendices_heading.start())
        body = body[:appendices_start if appendices_start >= 0 else appendices_heading.start()]
    body = re.sub(r'<(?:p|h[1-6])\b[^>]*class="[^"]*\btoc-title\b[^"]*"[^>]*>.*?</(?:p|h[1-6])>', "", body, flags=re.IGNORECASE | re.DOTALL)
    body = re.sub(r"<pdf:toc\b[^>]*/>", "", body, flags=re.IGNORECASE)
    body = re.sub(r"<pdf:nextpage\b[^>]*/>", "", body, flags=re.IGNORECASE)
    body = re.sub(r"<section>\s*</section>", "", body, flags=re.IGNORECASE)
    toc_page = '<section class="report-toc"><h1 class="toc-title">Table of Contents</h1><pdf:toc leader="dots" /></section><pdf:nextpage />'
    body = (
        '<pdf:nexttemplate name="cover" />'
        + _report_cover(session, intel)
        + '<pdf:nextpage name="report" />'
        + toc_page
        + body
    )
    visuals = _target_visuals(session, intel)
    if visuals:
        results_heading = re.search(
            r"<h[1-3]\b[^>]*>[^<]*(?:target[- ]specific results|results by target|target results)[^<]*</h[1-3]>",
            body,
            flags=re.IGNORECASE,
        )
        if results_heading:
            insertion = body.find("</p>", results_heading.end())
            if insertion >= 0:
                insertion += len("</p>")
            else:
                insertion = results_heading.end()
            body = body[:insertion] + visuals + body[insertion:]
        else:
            body += visuals
    rating_basis = (
        '<section class="reporting-notes"><h2>Rating and evidence basis</h2>'
        '<p>Severity and confidence are reproduced from session Intel. Mitsu has not independently calculated CVSS or '
        'business risk. Findings are limited to confirmed security weaknesses with evidence-supported impact.</p></section>'
    ) if _reportable_findings(intel) else ""
    findings_and_results_notes, supporting_appendices = _intel_appendices(intel, session)
    result_insertion = re.search(
        r"<h[1-3]\b[^>]*>[^<]*(?:remediation (?:priorities|roadmap|plan)|retest status|conclusion)[^<]*</h[1-3]>",
        body,
        flags=re.IGNORECASE,
    )
    if result_insertion:
        insertion = result_insertion.start()
        body = body[:insertion] + rating_basis + findings_and_results_notes + body[insertion:]
    else:
        body += rating_basis + findings_and_results_notes
    body += supporting_appendices
    page_title = engagement or "Vulnerability Assessment Report"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{_esc(page_title)}</title>
<style>
@page cover{{size:a4 portrait;@frame cover_content_frame{{left:0pt;width:595pt;top:0pt;height:842pt}}@frame header_frame{{-pdf-frame-content:header_content;left:45pt;width:505pt;top:14pt;height:46pt}}@frame footer_frame{{-pdf-frame-content:footer_content;left:45pt;width:505pt;top:802pt;height:20pt}}}}
@page report{{size:a4 portrait;@frame header_frame{{-pdf-frame-content:header_content;left:45pt;width:505pt;top:14pt;height:46pt}}@frame content_frame{{left:45pt;width:505pt;top:68pt;height:726pt}}@frame footer_frame{{-pdf-frame-content:footer_content;left:45pt;width:505pt;top:802pt;height:20pt}}}}
body{{margin:0;color:#1c2c42;font:10pt/1.4 Helvetica,Arial,sans-serif;letter-spacing:0}}h1,h2,h3,h4{{font-family:Helvetica,Arial,sans-serif;color:#152d4b;line-height:1.16;page-break-after:avoid}}h1{{font-size:19pt;margin:0 0 4mm;-pdf-outline:true;-pdf-outline-level:0}}h2{{font-size:14pt;margin:0 0 3mm;padding-bottom:1.5mm;border-bottom:1px solid #9eb1c5;-pdf-outline:true;-pdf-outline-level:1}}h3{{font-size:11pt;margin:3mm 0 1.5mm;color:#205d76;-pdf-outline:true;-pdf-outline-level:2}}h4{{font-size:10pt;margin:3mm 0 1.5mm;-pdf-outline:true;-pdf-outline-level:3}}p{{margin:0 0 2mm}}li{{margin:0 0 1.5mm}}section{{margin:0 0 5mm}}section.cover{{padding:12mm 4mm 4mm}}section.cover h1{{-pdf-outline:false}}section.cover h2{{-pdf-outline:false}}.cover p{{font-size:11pt;color:#52677f}}table{{width:100%;margin:2mm 0 4mm;border-collapse:collapse;font-size:8.5pt}}thead{{display:table-header-group}}th,td{{padding:2mm;border:1px solid #c7d2df;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-wrap:break-word}}th{{background:#eaf0f5;color:#18314e;font-weight:bold}}tr{{page-break-inside:avoid}}ul,ol{{padding-left:7mm}}pre,code{{font-family:Courier,monospace;font-size:8pt;word-wrap:break-word}}pre{{white-space:pre-wrap;background:#edf1f5;padding:2.5mm;border-left:3px solid #56718e}}blockquote{{margin:3mm 0;padding:2.5mm 4mm;border-left:3px solid #2a8592;background:#edf5f6;color:#304a5d}}hr{{border:0;border-top:1px solid #c7d2df;margin:4mm 0}}.finding{{border-top:2px solid #557390;padding-top:3mm;margin:0 0 6mm}}.finding-card{{border:1px solid #c7d2df;border-left:3px solid #557390;padding:3mm 4mm;margin:0 0 3mm}}.finding-card h3{{margin:0 0 1.5mm;font-size:11pt}}.finding-card p{{margin:1mm 0}}.finding-meta{{color:#52677f;font-size:8pt}}.severity-badge{{display:inline-block;padding:.7mm 1.5mm;margin-right:1.5mm;background:#eaf0f5;font-weight:bold}}.severity-badge.critical{{color:#a72f37;background:#f9e8e9}}.severity-badge.high{{color:#bc4b3d;background:#fbefeb}}.severity-badge.medium{{color:#a46e10;background:#fbf3df}}.severity-badge.low{{color:#31734a;background:#eaf4ee}}.severity-badge.informational{{color:#477ca8;background:#eaf1f7}}.finding-confidence{{color:#61758a;font-size:8pt}}.asset-list,.activity-list{{margin:1.5mm 0 3mm}}.activity-list li{{margin:0 0 2mm}}.activity-state{{color:#61758a;font-size:8pt}}.note,.callout{{padding:2.5mm;border-left:3px solid #2a8592;background:#edf5f6}}.critical{{color:#a72f37}}.high{{color:#bc4b3d}}.medium{{color:#a46e10}}.low,.informational{{color:#31734a}}.lead{{color:#775a19}}.target-visual{{border-top:1px solid #aebdcd;padding-top:2.5mm;margin-bottom:5mm;page-break-inside:avoid}}.chart-row{{height:7mm;margin:.8mm 0;white-space:nowrap}}.chart-label{{display:inline-block;width:85pt;color:#40566d}}.chart-track{{display:inline-block;width:330pt;height:4.5mm;background:#e8edf2;vertical-align:middle}}.chart-fill{{display:block;height:4.5mm}}.asset-fill{{background:#417da2}}.chart-value{{display:inline-block;width:25pt;text-align:right;margin-left:4pt;color:#273c55}}.chart-empty{{color:#5d7083;font-style:italic}}#header_content{{height:34pt;border-bottom:1px solid #aebdcd;color:#27425f;font-size:8pt}}#header_content img{{width:28pt;height:28pt;vertical-align:middle;margin-right:7pt}}#header_content strong{{font-size:12pt;color:#17385d}}#header_content span{{display:block;margin-left:36pt;margin-top:-10pt;color:#547087;font-size:7pt;letter-spacing:.3pt}}#footer_content{{border-top:1px solid #c7d2df;padding-top:3pt;color:#586b7e;font-size:7.5pt;text-align:right}}pdftoc{{display:block;margin:2mm 0 4mm;font-size:9.5pt;color:#273c55}}.pdftoclevel0{{-pdf-toc-leader:dots;font-weight:bold;margin:1.5mm 0}}.pdftoclevel1{{-pdf-toc-leader:dots;margin:1mm 0 1mm 7mm}}.pdftoclevel2{{-pdf-toc-leader:dots;margin:1mm 0 1mm 13mm;font-size:8.5pt}}h1.toc-title{{-pdf-outline:false}}
</style><style>
.report-cover{{position:relative;min-height:680pt;padding:80pt 58pt 4mm}}
.report-cover h1{{-pdf-outline:false}}
.report-cover h2{{-pdf-outline:false}}
.report-cover .cover-background{{display:block;position:absolute;left:0;top:0;width:595pt;height:842pt;z-index:-1}}
.report-cover .cover-content{{position:relative;z-index:1}}
.report-cover .cover-brand{{position:absolute;top:337pt;left:0;width:595pt;text-align:center;color:#183452;z-index:1}}
.report-cover .cover-brand img{{display:block;width:104pt;height:104pt;margin:0 auto 8pt}}
.report-cover .cover-brand strong{{display:block;font-size:32pt;line-height:1.1}}
.report-cover .cover-brand span{{display:block;margin-top:7pt;color:#45627e;font-size:12pt;letter-spacing:.4pt}}
.report-cover .cover-rule{{width:40pt;height:3pt;background:#df5a55;margin:0 0 5mm}}
.report-cover h1{{font-size:27pt;line-height:1.06;color:#183452;margin:0 0 4mm}}
.report-cover .cover-subtitle{{font-size:19pt;line-height:1.15;font-weight:bold;color:#355b7b;margin:0}}
.toc-title{{font-size:20pt;font-weight:bold;color:#152d4b;margin:0 0 5mm}}
.control-notes{{border-left:3pt solid #4c8b70;padding:3mm 5mm;background:#eff6f2;margin:5mm 0}}
.control-notes h2{{font-size:12pt;border:0;margin:0 0 2mm;padding:0;color:#356951}}
.control-notes p{{font-size:8.5pt;color:#546e60}}
.control-notes li{{font-size:8.5pt;color:#405c4c;margin-bottom:1mm}}
.small-note{{font-size:8pt;color:#6b7e8d}}
.reporting-notes{{margin:3mm 0 5mm;padding:2mm 0;border-top:1px solid #cbd6e0}}
.reporting-notes h2{{font-size:10pt;border:0;padding:0;margin:0 0 1.5mm;color:#355b7b}}
.reporting-notes p{{font-size:8pt;color:#52677f;margin:0}}
</style></head><body>
<div id="header_content"><img src="mitsu-logo.png"/><strong>Mitsu</strong><span>Agentic RedTeam Framework</span></div>
<div id="footer_content">Mitsu | Assessment report | Page <pdf:pagenumber example="00"/> of <pdf:pagecount/></div>
{body}
</body></html>"""


def _convert_html_to_pdf(html_path: Path, pdf_path: Path) -> None:
    from xhtml2pdf import pisa

    with html_path.open("r", encoding="utf-8") as source, pdf_path.open("wb") as destination:
        result = pisa.CreatePDF(
            source.read(),
            dest=destination,
            path=str(html_path),
            context_meta={"title": "Mitsu Vulnerability Assessment", "author": "Mitsu"},
            raise_exception=True,
        )
    if result.err or not pdf_path.is_file() or pdf_path.stat().st_size < 5:
        raise RuntimeError("xhtml2pdf did not produce a usable assessment PDF.")


def create_assessment_report(session: dict[str, Any], session_root: Path, report_html: str) -> dict[str, str]:
    session_id = _text(session.get("id"), 64)
    if not session_id or any(character not in "0123456789abcdef" for character in session_id):
        raise ValueError("This session has no valid ID for saving its report.")
    directory = session_root / session_id / "artifacts"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    logo_source = Path(__file__).resolve().parents[1] / "assets" / "example" / "icon.svg"
    logo_match = re.search(r"data:image/png;base64,([A-Za-z0-9+/=]+)", logo_source.read_text(encoding="utf-8"))
    if logo_match is None:
        raise RuntimeError("Mitsu's report logo could not be loaded.")
    logo_path = directory / "mitsu-logo.png"
    logo_path.write_bytes(base64.b64decode(logo_match.group(1)))
    logo_path.chmod(0o600)
    cover_art_source = Path(__file__).resolve().parents[1] / "assets" / "example" / "cover.png"
    cover_art_path = directory / "cover.png"
    shutil.copyfile(cover_art_source, cover_art_path)
    cover_art_path.chmod(0o600)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = directory / f"vulnerability-assessment-{stamp}"
    html_path = base.with_suffix(".html")
    pdf_path = base.with_suffix(".pdf")
    html_temp = directory / f".{base.name}.html.tmp"
    html_temp.write_text(build_assessment_html(session, report_html), encoding="utf-8")
    html_temp.chmod(0o600)
    html_temp.replace(html_path)
    conversion_error = ""
    try:
        _convert_html_to_pdf(html_path, pdf_path)
        pdf_path.chmod(0o600)
    except Exception as error:
        conversion_error = str(error)
        try:
            pdf_path.unlink(missing_ok=True)
        except OSError:
            pass
    return {"html_path": str(html_path), "pdf_path": str(pdf_path) if pdf_path.is_file() else "", "conversion_error": conversion_error}


def open_assessment_pdf(pdf_path: str | Path, html_path: str | Path) -> str:
    pdf = Path(pdf_path).resolve() if pdf_path else None
    if pdf is not None and os.name == "nt":
        opener = getattr(os, "startfile", None)
        if opener is not None:
            try:
                opener(str(pdf))
                return "pdf"
            except OSError:
                pass
    elif pdf is not None and os.name != "nt" and os.uname().sysname == "Darwin":
        opener = shutil.which("open")
        if opener:
            try:
                subprocess.Popen([opener, str(pdf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                return "pdf"
            except OSError:
                pass
    elif pdf is not None:
        mime_query = shutil.which("xdg-mime")
        opener = shutil.which("xdg-open")
        if mime_query and opener:
            try:
                default_app = subprocess.run([mime_query, "query", "default", "application/pdf"], capture_output=True, text=True, timeout=5, check=False).stdout.strip()
                if default_app:
                    subprocess.Popen([opener, str(pdf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                    return "pdf"
            except (OSError, subprocess.TimeoutExpired):
                pass
    if pdf is not None and webbrowser.open_new_tab(pdf.as_uri()):
        return "browser"
    if webbrowser.open_new_tab(Path(html_path).resolve().as_uri()):
        return "html"
    raise RuntimeError("No PDF handler or browser could open the assessment report.")
