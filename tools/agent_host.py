"""Expose built-in and MCP tools to agent turns."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
import json
import os
from pathlib import Path
import platform
import re
import shutil
import shlex
import signal
import socket
import sys
import time
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import urlsplit

from mcp import Client, StdioServerParameters
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from mitsu.search import fetch_web_page, search_web as perform_web_search
from mitsu.search.vulnerabilities import (
    search_exploitdb,
    search_vulnx,
    search_vulnerabilities,
    vulnerability_queries,
)
from mitsu.armory import CATEGORY_BY_ID, TOOLS, TOOL_BY_ID
from mitsu.services.host_environment import load_host_environment
from mitsu.services.redteam_armory import (
    ArmoryError,
    build_install_script,
    forget_managed_install,
    inspect_tool,
    record_managed_install,
)
from mitsu.tools.armory_mcp import (
    ArmoryMCPAdapter,
    ArmoryMCPError,
    normalize_armory_selection,
    resolve_executable,
)
from mitsu.tools.artifacts import search_artifact
from mitsu.tools.custom_mcp import CustomMCPAdapter


MAX_TOOL_RESULT = 40_000
IntelUpdateHandler = Callable[[str, dict[str, Any]], Awaitable[str]]
OperatorDialogHandler = Callable[[dict[str, Any]], Awaitable[str | None]]
SudoPasswordHandler = Callable[[str], Awaitable[str | None]]
ShowCommandHandler = Callable[[str, str], Awaitable[bool]]
ModeDialogHandler = Callable[[str], Awaitable[str]]
ToolResultHandler = Callable[[str, dict[str, Any], str], Awaitable[str]]


def _is_low_impact_recon_command(command: str) -> bool:
    """Allow a small set of non-mutating local and low-rate recon commands in Recon."""
    if not command.strip() or len(command) > 500:
        return False
    if any(character in command for character in "|;&<>`$()\n\r"):
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False

    executable = Path(parts[0]).name.casefold()
    arguments = parts[1:]
    if executable in {"curl", "nmap"}:
        return False
    if executable in {"pwd", "ls", "stat", "file"}:
        return True
    if executable == "find":
        return not any(
            argument.casefold() == "-delete"
            or argument.casefold().startswith(("-exec", "-ok", "-fprint", "-fls"))
            for argument in arguments
        )
    if executable == "git":
        return bool(arguments) and arguments[0].casefold() in {"status", "diff", "log", "show"}
    if executable == "whois":
        return len(arguments) == 1 and not arguments[0].startswith("-")
    if executable in {"host", "nslookup"}:
        return len(arguments) == 1 and not arguments[0].startswith("-")
    if executable == "dig":
        allowed_options = {"+short", "+noall", "+answer", "+norecurse"}
        record_types = {
            "a", "aaaa", "caa", "cname", "https", "mx", "ns", "ptr", "soa",
            "srv", "txt", "https", "svcb", "dnskey", "ds", "rrsig", "nsec",
        }
        query_names = []
        query_type_seen = False
        for argument in arguments:
            lowered = argument.casefold()
            if lowered in allowed_options:
                continue
            if lowered in {"axfr", "ixfr", "any"} or argument.startswith(("-", "@")):
                return False
            if lowered in record_types and not query_type_seen:
                query_type_seen = True
                continue
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", argument):
                return False
            query_names.append(argument)
        return len(query_names) == 1
    return False


def _installation_request(command: str) -> tuple[str, str] | None:
    rules = (
        ("pacman", r"\b(?:pacman|yay|paru)\s+-S(?:yyu|yu|y|u)?\s+(?P<packages>[^;&|<>\n]+)"),
        ("system package manager", r"\b(?:apt-get|apt|dnf|yum|zypper|apk|brew|snap|flatpak|conda|mamba)\s+(?:-[\w-]+\s+)*(?:install|add|upgrade|dist-upgrade)\s*(?P<packages>[^;&|<>\n]*)"),
        ("Python package manager", r"\b(?:pipx|pip(?:\d+(?:\.\d+)*)?|uv\s+pip|python[\w.]*\s+-m\s+pip)\s+(?:install|inject)\s+(?P<packages>[^;&|<>\n]+)"),
        ("uv", r"\buv\s+(?:tool\s+install|add)\s+(?P<packages>[^;&|<>\n]+)"),
        ("Node package manager", r"\b(?:npm|pnpm|yarn|bun)\s+(?:install|add|i|update)(?:\s+(?P<packages>[^;&|<>\n]+))?"),
        ("language package manager", r"\b(?:gem|cargo|go|dotnet\s+tool)\s+(?:install|update)\s+(?P<packages>[^;&|<>\n]+)"),
        ("project installer", r"\b(?:uv\s+sync|poetry\s+install|bundle\s+install|composer\s+install|cargo\s+add|make\s+install|cmake\s+--install|python[\w.]*\s+setup\.py\s+install)\b(?P<packages>[^;&|<>\n]*)"),
        ("system binary installer", r"\b(?:cp|install|mv|ln\s+-s)\b[^;&|<>]*\s+/usr/(?:local/)?bin/(?P<packages>[A-Za-z0-9_.+-]+)"),
        ("remote install script", r"\b(?:curl|wget)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b"),
        ("shell installer", r"\b(?:bash|sh|zsh)\s+(?:\./)?[^\s;&|<>]*(?:install|setup|bootstrap)[^\s;&|<>]*"),
    )
    managers = []
    packages = []
    manager_names = {
        "apt", "apt-get", "pacman", "yay", "paru", "dnf", "yum", "zypper", "apk",
        "brew", "snap", "flatpak", "conda", "mamba", "pip", "pipx", "npm", "pnpm",
        "yarn", "bun", "gem", "cargo", "go", "dotnet", "uv",
    }
    options_with_values = {
        "-r", "--requirement", "-c", "--constraint", "--index-url", "--extra-index-url",
        "--trusted-host", "--config-settings", "--python", "--python-version", "--prefix",
        "--root", "--target", "--cache-dir", "--from", "--source",
    }
    for manager, pattern in rules:
        for match in re.finditer(pattern, command, re.IGNORECASE):
            try:
                command_tokens = shlex.split(match.group(0), posix=True)
            except ValueError:
                command_tokens = []
            actual_manager = next(
                (Path(token).name.casefold() for token in command_tokens if Path(token).name.casefold() in manager_names),
                manager,
            )
            managers.append(actual_manager)
            package_text = match.groupdict().get("packages", "")
            try:
                tokens = shlex.split(package_text, posix=True) if package_text else []
            except ValueError:
                tokens = []
            skip_next = False
            for token in tokens:
                if skip_next:
                    skip_next = False
                    continue
                if token in options_with_values:
                    skip_next = True
                    continue
                if token.startswith("-"):
                    continue
                if any(token.startswith(f"{option}=") for option in options_with_values):
                    continue
                if re.fullmatch(r"[A-Za-z0-9_.@:+/-]{1,120}", token) and token not in packages:
                    packages.append(token)
                if len(packages) == 12:
                    break
    if not managers:
        return None
    manager_summary = ", ".join(dict.fromkeys(managers))
    package_summary = ", ".join(packages) if packages else "requested dependencies or tool"
    return manager_summary, package_summary


def _dialog_install_targets(dialog: dict[str, Any], install_target: str) -> set[str]:
    targets = AgentToolHost._normalize_install_targets(install_target)
    if targets:
        return targets

    parts = [str(dialog.get("title", "")), str(dialog.get("message", ""))]
    for question in dialog.get("questions", []):
        if not isinstance(question, dict):
            continue
        parts.append(str(question.get("prompt", "")))
        parts.extend(str(option) for option in question.get("options", []))
    text = " ".join(parts)
    if not re.search(r"\binstall(?:ing|ation)?\b", text, re.IGNORECASE):
        return set()

    ignored = {
        "it", "this", "that", "something", "package", "tool", "dependency",
        "the", "a", "an", "to", "using", "via", "request",
    }
    found = re.findall(
        r"\binstall(?:ing)?\s+([A-Za-z0-9][A-Za-z0-9_.+:-]{0,119})",
        text,
        re.IGNORECASE,
    )
    names = [name for name in found if name.casefold() not in ignored]
    return AgentToolHost._normalize_install_targets(",".join(names))


class ToolHostError(Exception):
    pass


class AgentToolHost:
    def __init__(
        self,
        workspace: Path,
        ask_user: Callable[[str, list[str]], Awaitable[str]],
        update_intel: IntelUpdateHandler | None = None,
        search_settings: Callable[[], dict[str, dict[str, Any]]] | None = None,
        operator_dialog: OperatorDialogHandler | None = None,
        sudo_password: SudoPasswordHandler | None = None,
        show_command: ShowCommandHandler | None = None,
        mode_dialog: ModeDialogHandler | None = None,
        tool_result_handler: ToolResultHandler | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.ask_user = ask_user
        self.update_intel = update_intel
        self.search_settings = search_settings or (lambda: {})
        self.operator_dialog = operator_dialog or self._default_operator_dialog
        self.sudo_password = sudo_password
        self.show_command = show_command
        self.mode_dialog = mode_dialog
        self.tool_result_handler = tool_result_handler
        self.install_approvals: dict[str, float] = {}
        self.server = MCPServer("Mitsu built-in tools")
        self._stack = AsyncExitStack()
        self._clients: dict[str, tuple[Client, str, bool]] = {}
        self._tools: dict[str, dict[str, Any]] = {}
        self.armory_tool_count = 0
        self.custom_tool_count = 0
        self.armory_enabled = True
        self.armory_selection: set[str] = {"*"}
        self.connection_messages: list[str] = []
        self._connected = False
        self._armory_adapter = ArmoryMCPAdapter(self.workspace)
        self._custom_adapter = CustomMCPAdapter(self.workspace)
        self._register_builtin_tools()

    def set_workspace(self, workspace: Path) -> None:
        self.workspace = workspace.resolve()
        self._armory_adapter.workspace = self.workspace
        self._custom_adapter.workspace = self.workspace

    def _register_builtin_tools(self) -> None:
        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True))
        async def bash(command: str, purpose: str = "") -> str:
            "Run a shell command in the current workspace."
            return await self._run_bash(command, purpose)

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def system_info() -> str:
            "Return basic operating system and workspace information."
            return json.dumps(
                {
                    "platform": platform.platform(),
                    "python": sys.version.split()[0],
                    "workspace": str(self.workspace),
                    "hostname": socket.gethostname(),
                },
                ensure_ascii=False,
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def list_files(path: str = ".", limit: int = 100) -> str:
            "List a directory under the current workspace."
            directory = self._safe_list_path(path)
            if not directory.is_dir():
                raise ToolHostError(f"Not a directory: {path}")
            entries = sorted(directory.iterdir(), key=lambda item: (not item.is_dir(), item.name.casefold()))
            bounded = max(1, min(int(limit), 200))
            lines = [f"{'[DIR] ' if item.is_dir() else '[FILE] '}{item.name}" for item in entries[:bounded]]
            if len(entries) > bounded:
                lines.append(f"… {len(entries) - bounded} more entries")
            return "\n".join(lines) or "(empty directory)"

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def read_file(path: str, max_bytes: int = 100_000) -> str:
            "Read a UTF-8 text file under the current workspace."
            file_path = self._safe_path(path)
            if not file_path.is_file():
                raise ToolHostError(f"Not a file: {path}")
            maximum = max(1, min(int(max_bytes), 200_000))
            raw = file_path.read_bytes()[:maximum]
            text = raw.decode("utf-8", errors="replace")
            if file_path.stat().st_size > maximum:
                text += f"\n… file truncated at {maximum} bytes"
            return text

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def artifact_search(
            path: str,
            terms: list[str] | None = None,
            context_bytes: int = 256,
            limit: int = 60,
            min_offset: int = 0,
        ) -> str:
            file_path = self._safe_artifact_path(path)
            if not file_path.is_file():
                raise ToolHostError(f"Not a file in the current workspace or /tmp: {path}")
            try:
                return await asyncio.to_thread(
                    search_artifact,
                    file_path,
                    terms,
                    context_bytes,
                    limit,
                    min_offset,
                )
            except (OSError, ValueError) as error:
                raise ToolHostError(f"Could not inspect artifact: {error}") from error

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True))
        async def web_search(query: str, max_results: int = 5) -> str:
            "Search configured web engines, or open a supplied HTTP or HTTPS URL and return readable page text. If a supplied URL will not open, search its host and page path for a working result. Prefer this tool over shell curl or wget for ordinary web research and operator-provided links."
            if not query.strip():
                raise ToolHostError("Enter a search query.")
            query = query.strip()
            if query.casefold().startswith(("http://", "https://")):
                try:
                    return await asyncio.to_thread(fetch_web_page, query)
                except (OSError, TimeoutError, ValueError) as error:
                    parsed = urlsplit(query)
                    page_terms = re.sub(r"[-_/]+", " ", parsed.path).strip()
                    host = (parsed.hostname or "").removeprefix("www.")
                    fallback = " ".join(part for part in (host, page_terms) if part)
                    if not fallback:
                        raise
                    results = await asyncio.to_thread(
                        perform_web_search, fallback, max_results, self.search_settings()
                    )
                    return f"Could not open {query}: {error}\n\nSearch results for {fallback}:\n{results}"
            return await asyncio.to_thread(
                perform_web_search, query, max_results, self.search_settings()
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True))
        async def vulnsearch(criteria: str = "") -> str:
            "Search session Intel, configured web engines, local Exploit-DB, and Vulnx for vulnerability leads. Ask before installing either local search tool if it is missing. Leave criteria empty to search saved product and version clues. Results are references, not proof; no exploit is run."
            intel = await self._vulnerability_intel()
            local_searcher, local_status, vulnx_searcher, vulnx_status = (
                await self._prepare_vulnsearch_backends(criteria, intel)
            )
            vulnx_records: list[tuple[str, str]] = []
            related_records: list[tuple[str, dict[str, Any]]] = []

            def capture_web(query: str, records: list[dict[str, Any]], _errors: list[str]) -> None:
                related_records.extend(
                    (query, lead)
                    for lead in self._cve_search_leads(query, records, "Web search")
                )

            def capture_local(
                query: str,
                records: list[dict[str, str]],
                _error: str | None,
            ) -> None:
                related_records.extend(
                    (query, lead)
                    for lead in self._cve_search_leads(query, records, "SearchSploit")
                )

            result = await asyncio.to_thread(
                search_vulnerabilities,
                criteria,
                intel,
                self.search_settings(),
                local_searcher=local_searcher,
                vulnx_searcher=vulnx_searcher,
                vulnx_result_sink=lambda query, data: vulnx_records.append((query, data)),
                web_result_sink=capture_web,
                local_result_sink=capture_local,
                local_status=local_status,
                vulnx_status=vulnx_status,
            )
            saved = await self._save_vulnerability_leads(criteria, intel, [*vulnx_records, *related_records])
            if saved:
                result += f"\n\nSaved {saved} CVE lead(s) to Findings and Exploits Intel for review."
            return result

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def ask_user(question: str, choices: list[str] | None = None) -> str:
            "Ask the operator a question and wait for their answer."
            options = [str(choice) for choice in (choices or []) if str(choice).strip()][:8]
            return await self.ask_user(question.strip(), options)

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def user_dialog(
            title: str,
            message: str,
            questions: list[dict[str, Any]],
            submit_label: str = "Continue",
            cancel_label: str = "Cancel",
            install_target: str = "",
        ) -> str:
            """Design and open an operator dialog. Provide a title, message, and one or more question objects with an id, prompt, and type ('choice', 'multi_choice', or 'text'). Choice questions also need options; optional fields are allow_other, required, and placeholder. Use several questions for a short questionnaire, and choose clear submit/cancel labels. For install consent, set install_target and make the first required choice question offer explicit Yes and No options."""
            if not title.strip() or not message.strip():
                raise ToolHostError("Provide a title and message for the dialog.")
            if not isinstance(questions, list) or not questions or len(questions) > 6:
                raise ToolHostError("Provide between one and six dialog questions.")

            clean_questions: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            for index, raw_question in enumerate(questions, start=1):
                if not isinstance(raw_question, dict):
                    raise ToolHostError("Each dialog question must be an object.")
                question_id = str(raw_question.get("id", f"question_{index}")).strip()
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", question_id) or question_id in seen_ids:
                    raise ToolHostError("Dialog question IDs must be unique and use letters, numbers, '_' or '-'.")
                prompt = str(raw_question.get("prompt", "")).strip()
                question_type = str(raw_question.get("type", "")).strip().casefold()
                if not prompt:
                    raise ToolHostError(f"Dialog question {question_id} needs a prompt.")
                if question_type not in {"choice", "multi_choice", "text"}:
                    raise ToolHostError(f"Dialog question {question_id} needs type choice, multi_choice, or text.")
                raw_options = raw_question.get("options", [])
                if not isinstance(raw_options, list):
                    raise ToolHostError(f"Options for {question_id} must be a list of strings.")
                options = [str(option).strip()[:160] for option in raw_options if str(option).strip()][:10]
                if question_type in {"choice", "multi_choice"} and not options:
                    raise ToolHostError(f"Dialog question {question_id} needs at least one option.")
                if question_type == "text" and options:
                    raise ToolHostError(f"Text question {question_id} cannot include choices.")
                seen_ids.add(question_id)
                clean_questions.append(
                    {
                        "id": question_id,
                        "prompt": prompt[:240],
                        "type": question_type,
                        "options": options,
                        "allow_other": bool(raw_question.get("allow_other", False)),
                        "required": bool(raw_question.get("required", True)),
                        "placeholder": str(raw_question.get("placeholder", "Type your answer…"))[:120],
                    }
                )

            install_names = _dialog_install_targets(
                {"title": title, "message": message, "questions": clean_questions},
                install_target,
            )
            if install_names:
                first_question = clean_questions[0]
                first_options = first_question["options"]
                if (
                    first_question["type"] != "choice"
                    or not first_question["required"]
                    or not any(option.casefold().startswith("yes") for option in first_options)
                    or not any(option.casefold().startswith("no") for option in first_options)
                ):
                    raise ToolHostError("Install consent needs a required first choice with explicit Yes and No options.")

            dialog = {
                "title": title.strip()[:80],
                "message": message.strip()[:1200],
                "questions": clean_questions,
                "submit_label": submit_label.strip()[:24] or "Continue",
                "cancel_label": cancel_label.strip()[:24] or "Cancel",
            }
            answer = await self.operator_dialog(dialog)
            try:
                response = json.loads(answer or "{}")
            except json.JSONDecodeError:
                response = {}
            answers = response.get("answers", {}) if isinstance(response, dict) else {}
            decision = answers.get(clean_questions[0]["id"]) if isinstance(answers, dict) else None
            if install_names and isinstance(decision, str) and decision.casefold().startswith("yes"):
                self.install_approvals.update(
                    {name: time.monotonic() + 1800 for name in install_names}
                )
                response["install_approved"] = sorted(install_names)
                return json.dumps(response, ensure_ascii=False)
            if isinstance(response, dict) and install_target:
                response["install_approved"] = []
                response["install_approval_note"] = (
                    "The dialog did not approve installation; ask before running an install command."
                )
                return json.dumps(response, ensure_ascii=False)
            return answer or json.dumps({"answers": {}, "cancelled": True})

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def request_mode(reason: str) -> str:
            """Open the mode-switch dialog when a requested step needs active target interaction from Recon. The selection changes the active session mode."""
            if not reason.strip():
                raise ToolHostError("Explain why an active mode is needed.")
            if self.mode_dialog is None:
                raise ToolHostError("The mode-switch dialog is unavailable.")
            return await self.mode_dialog(reason.strip()[:1200])

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def show_cmd(message: str, command: str) -> str:
            """Show the operator a short explanation and command with Copy and Cancel choices. Use when the operator needs to run a command themselves."""
            if not message.strip() or not command.strip():
                raise ToolHostError("Provide an explanation and the command to show.")
            if self.show_command is None:
                raise ToolHostError("The command handoff dialog is unavailable.")
            copied = await self.show_command(message.strip()[:1200], command.strip())
            return (
                "The operator copied the command."
                if copied
                else "The operator cancelled the command handoff."
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def armory_tool_catalog(category: str = "") -> str:
            """List Mitsu's catalogued Armory tools, install status, descriptions, and categories."""
            requested_category = category.strip().casefold()
            rows = []
            for tool in TOOLS:
                group = CATEGORY_BY_ID[tool.category_id]
                if requested_category and not (
                    requested_category in tool.category_id.casefold()
                    or requested_category in group.name.casefold()
                ):
                    continue
                installed = resolve_executable(tool) is not None
                rows.append(
                    {
                        "id": tool.id,
                        "name": tool.name,
                        "category": group.name,
                        "installed": installed,
                        "enabled": self._armory_tool_selected(tool.id),
                        "description": tool.description,
                    }
                )
            return json.dumps(rows, ensure_ascii=False)

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True))
        async def armory_run(
            tool_id: str,
            argv: list[str],
            purpose: str = "",
            timeout_seconds: int = 120,
        ) -> str:
            """Run one catalogued Armory tool by ID with separate CLI arguments. If missing, Mitsu asks before installing it, then runs it."""
            return await self._run_armory_tool(tool_id, argv, purpose, timeout_seconds)

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False))
        async def session_upsert(title: str) -> str:
            """Set a concise title for a session that still has its default title. An operator-set title always takes priority."""
            return await self._update_session_intel("upsert_title", {"title": title})

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def intel_get_map(
            section: Literal[
                "summary", "assets", "targets", "findings", "services", "exploits",
                "domains", "ips", "accounts", "manhunt", "observations",
            ] = "summary",
            offset: int = 0,
            limit: int = 8,
        ) -> str:
            """Read a section of the session Intel map. Sections are targets, findings, services, exploits, domains, IPs, accounts, manhunt, and observations. Pages contain at most eight records; follow next_offset when needed."""
            return await self._update_session_intel(
                "get_map", {"section": section, "offset": offset, "limit": limit}
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False))
        async def intel_upsert_asset(
            asset_type: Literal[
                "target", "domain", "hostname", "ip", "url", "service",
                "nameserver", "endpoint", "technology", "account", "other",
            ],
            value: str,
            source: str,
            evidence: str,
            parent: str = "",
            verification: Literal["discovered", "validated", "rejected"] | None = None,
            scope: Literal["unknown", "in_scope", "out_of_scope"] | None = None,
            confidence: Literal["low", "medium", "high", "unknown"] = "medium",
            attributes: dict[str, str] | None = None,
            primary: bool = False,
        ) -> str:
            """Add or update a target, service, domain, nameserver, IP, or other map asset with provenance and observed evidence.

            Mark the primary target explicitly. Record service ports, protocols, banners, product,
            version, and confirmation evidence in attributes. Record domain relationships, DNS
            answers, authoritative nameservers, and related IPs with parent links. Repeated calls
            merge evidence into the same asset.
            """
            return await self._update_session_intel(
                "upsert_asset",
                {
                    "asset_type": asset_type,
                    "value": value,
                    "source": source,
                    "evidence": evidence,
                    "parent": parent,
                    "verification": verification,
                    "scope": scope,
                    "confidence": confidence,
                    "attributes": attributes or {},
                    "primary": primary,
                },
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False))
        async def intel_upsert_observation(
            title: str,
            asset: str,
            category: Literal[
                "recon", "service", "authentication", "behavior", "configuration",
                "exploit", "credentials", "pivot", "enumeration", "workflow", "other",
            ],
            status: Literal["draft", "active", "unverified", "validated", "rejected", "resolved"],
            details: str,
            source: str,
            confidence: Literal["low", "medium", "high", "unknown"] = "medium",
            worked: str = "",
            failed: str = "",
            next_step: str = "",
        ) -> str:
            """Save or update working notes for this lead. Include what worked, what failed, and one evidence-based next step; use draft or active while investigating, then validated, rejected, or resolved as evidence changes."""
            return await self._update_session_intel(
                "upsert_observation",
                {
                    "title": title,
                    "asset": asset,
                    "category": category,
                    "status": status,
                    "details": details,
                    "source": source,
                    "confidence": confidence,
                    "worked": worked,
                    "failed": failed,
                    "next_step": next_step,
                },
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False))
        async def intel_upsert_finding(
            title: str,
            asset: str,
            severity: Literal["critical", "high", "medium", "low", "informational", "unknown"],
            status: Literal["lead", "confirmed", "false_positive", "remediated"],
            summary: str,
            source: str,
            evidence: str,
            recommendation: str = "",
            confidence: Literal["low", "medium", "high", "unknown"] = "medium",
        ) -> str:
            """Add or update useful confirmed information in Findings. Keep unverified leads marked lead, and include the affected target, source, and evidence."""
            return await self._update_session_intel(
                "upsert_finding",
                {
                    "title": title,
                    "asset": asset,
                    "severity": severity,
                    "status": status,
                    "summary": summary,
                    "source": source,
                    "evidence": evidence,
                    "recommendation": recommendation,
                    "confidence": confidence,
                },
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False))
        async def record_exploit(
            title: str,
            target: str,
            evidence: str,
            status: str = "candidate",
            summary: str = "",
            source: str = "Mitsu session analysis",
        ) -> str:
            """Record an exploit or vulnerability with a short description and source.

            Keep search-only references as candidates. Add product/version evidence and update
            status after validation; confirm exploitation only when the tool result demonstrates it.
            """
            return await self._update_session_intel(
                "record_exploit",
                {
                    "title": title,
                    "target": target,
                    "evidence": evidence,
                    "status": status,
                    "summary": summary,
                    "source": source,
                },
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False))
        async def intel_upsert_account(
            name: str,
            account_type: Literal["user", "group", "service", "token", "credential", "flag", "other"],
            target: str,
            secret_type: Literal["password", "token", "hash", "key", "flag", "other"],
            secret: str,
            access: str,
            status: Literal["discovered", "validated", "rejected"],
            details: str,
            source: str,
            evidence: str,
            confidence: Literal["low", "medium", "high", "unknown"] = "medium",
        ) -> str:
            """Save account, group, access, password, token, key, hash, or CTF flag evidence in Passwords/Accounts. Keep the secret with its owner, target/service, source, and validation state so it can be used later in this authorized session."""
            return await self._update_session_intel(
                "upsert_account",
                {
                    "name": name,
                    "account_type": account_type,
                    "target": target,
                    "secret_type": secret_type,
                    "secret": secret,
                    "access": access,
                    "status": status,
                    "details": details,
                    "source": source,
                    "evidence": evidence,
                    "confidence": confidence,
                },
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False))
        async def intel_upsert_manhunt(
            person: str,
            detail_type: Literal["name", "email", "phone", "social", "organization", "location", "other"],
            value: str,
            relationship: str,
            details: str,
            source: str,
            evidence: str,
            status: Literal["unverified", "validated", "rejected"],
            confidence: Literal["low", "medium", "high", "unknown"] = "medium",
        ) -> str:
            """Save person-scoped OSINT such as names, email addresses, phone numbers, social accounts, organizations, and relationships in Manhunt. Keep it separate from system accounts and credentials."""
            return await self._update_session_intel(
                "upsert_manhunt",
                {
                    "person": person,
                    "detail_type": detail_type,
                    "value": value,
                    "relationship": relationship,
                    "details": details,
                    "source": source,
                    "evidence": evidence,
                    "status": status,
                    "confidence": confidence,
                },
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False))
        async def remove_exploit(title: str, target: str, reason: str) -> str:
            """Remove a previously recorded exploit when evidence shows it does not apply or work."""
            return await self._update_session_intel(
                "remove_exploit", {"title": title, "target": target, "reason": reason}
            )

    async def connect(self, config_path: Path) -> None:
        if self._connected:
            return
        await self._stack.__aenter__()
        self._connected = True

        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            config = {}
        except (OSError, json.JSONDecodeError) as error:
            self.connection_messages.append(f"MCP config could not be read: {error}")
            config = {}
        if not isinstance(config, dict):
            self.connection_messages.append("MCP config must contain a JSON object.")
            config = {}
        armory_configuration = config.get("armory")
        try:
            self.armory_enabled, self.armory_selection = normalize_armory_selection(
                armory_configuration
            )
            registered, _unavailable = self._armory_adapter.register(
                self.server,
                armory_configuration,
            )
            self.armory_tool_count = registered
        except (ArmoryMCPError, AttributeError) as error:
            self.connection_messages.append(f"RedTeam Armory MCP configuration: {error}")
        try:
            self.custom_tool_count, custom_tool_issues = self._custom_adapter.register(
                self.server,
                config.get("custom_tools", []),
            )
            self.connection_messages.extend(custom_tool_issues)
        except (ValueError, AttributeError) as error:
            self.connection_messages.append(f"Custom CLI MCP configuration: {error}")

        local_client = Client(self.server)
        await self._stack.enter_async_context(local_client)
        await self._register_client("mitsu", local_client)
        servers = config.get("servers", []) if isinstance(config, dict) else []
        if not isinstance(servers, list):
            self.connection_messages.append("MCP config has no valid servers list.")
            return
        for definition in servers:
            if not isinstance(definition, dict):
                continue
            name = str(definition.get("name", "")).strip()
            if not name:
                continue
            try:
                if isinstance(definition.get("url"), str):
                    client = Client(definition["url"])
                else:
                    command = str(definition.get("command", "")).strip()
                    args = definition.get("args", [])
                    env = definition.get("env", {})
                    if not command or not isinstance(args, list) or not isinstance(env, dict):
                        raise ToolHostError("expected a command, string args, and string environment variables")
                    if any(not isinstance(value, str) for value in args) or any(
                        not isinstance(key, str) or not isinstance(value, str) for key, value in env.items()
                    ):
                        raise ToolHostError("args and environment values must be strings")
                    client = Client(StdioServerParameters(command=command, args=args, env=env))
                await asyncio.wait_for(self._stack.enter_async_context(client), timeout=15)
                await asyncio.wait_for(self._register_client(name, client), timeout=15)
            except Exception as error:
                self.connection_messages.append(f"{name}: {type(error).__name__}: {error}")

    async def _register_client(self, server_name: str, client: Client) -> None:
        response = await client.list_tools()
        server_slug = self._slug(server_name)
        for tool in response.tools:
            public_name = f"{server_slug}__{self._slug(tool.name)}"[:64]
            suffix = 2
            base_name = public_name
            while public_name in self._tools:
                ending = f"_{suffix}"
                public_name = f"{base_name[:64 - len(ending)]}{ending}"
                suffix += 1
            annotations = getattr(tool, "annotations", None)
            read_only = bool(
                getattr(annotations, "read_only_hint", False)
                or getattr(annotations, "readOnlyHint", False)
            )
            self._clients[public_name] = (client, tool.name, read_only)
            self._tools[public_name] = {
                "name": public_name,
                "description": f"{server_name}: {tool.description or tool.name}",
                "parameters": tool.input_schema or {"type": "object", "properties": {}},
                "read_only": read_only,
                "server": server_name,
                "original_name": tool.name,
            }

    def provider_tools(self, mode: str) -> list[dict[str, Any]]:
        tools = []
        for name, definition in self._tools.items():
            tools.append(
                {
                    "name": name,
                    "description": definition["description"],
                    "parameters": definition["parameters"],
                    "read_only": definition["read_only"],
                }
            )
        return tools

    def is_read_only(self, name: str) -> bool:
        definition = self._tools.get(name)
        return bool(definition and definition["read_only"])

    def requires_guided_approval(self, name: str) -> bool:
        definition = self._tools.get(name)
        if (
            definition is not None
            and definition.get("server") == "mitsu"
            and (
                name.endswith(("__record_exploit", "__remove_exploit"))
                or name.endswith("__session_upsert")
                or name.removeprefix("mitsu__").startswith("intel_")
            )
        ):
            return False
        return bool(
            definition is None
            or not definition["read_only"]
            or definition.get("server") != "mitsu"
        )

    def recon_action_is_low_impact(self, name: str, arguments: Any) -> bool:
        definition = self._tools.get(name)
        if definition is None:
            return False
        if (
            definition.get("server") == "mitsu"
            and (
                name.endswith(("__record_exploit", "__remove_exploit"))
                or name.endswith("__session_upsert")
                or name.removeprefix("mitsu__").startswith("intel_")
            )
        ):
            return True
        if definition.get("server") != "mitsu":
            description = f"{name} {definition.get('description', '')}".casefold()
            active_terms = (
                "scan", "nmap", "port", "probe", "exploit", "attack", "execute",
                "shell", "command", "write", "delete", "modify", "create", "edit",
                "update", "brute", "fuzz", "crawl", "enumerat", "inject", "upload",
            )
            passive_terms = ("search", "lookup", "whois", "dns", "read", "list", "fetch", "get")
            return (
                bool(definition["read_only"])
                and any(term in description for term in passive_terms)
                and not any(term in description for term in active_terms)
            )
        if definition["read_only"]:
            return True
        if not name.endswith("__bash") or not isinstance(arguments, dict):
            return False
        return _is_low_impact_recon_command(str(arguments.get("command", "")))

    async def _update_session_intel(self, action: str, values: dict[str, Any]) -> str:
        if self.update_intel is None:
            return "Session Intel updates are unavailable."
        return await self.update_intel(action, values)

    async def _record_artifact_search(self, output: str) -> str:
        if self.update_intel is None:
            return ""
        try:
            artifact = json.loads(output)
        except json.JSONDecodeError:
            return ""
        if not isinstance(artifact, dict) or not artifact.get("unique_matches"):
            return ""
        path = str(artifact.get("path", "artifact"))
        digest = str(artifact.get("sha256", ""))[:16]
        terms = artifact.get("terms", {})
        matches = artifact.get("matches", [])
        if not isinstance(matches, list):
            matches = []
        term_summary = ", ".join(
            f"{term}: {count}" for term, count in terms.items() if count
        ) if isinstance(terms, dict) else ""
        offsets = [
            str(item.get("offset"))
            for item in matches[:8]
            if isinstance(item, dict) and item.get("offset") is not None
        ]
        saved = await self._update_session_intel(
            "upsert_observation",
            {
                "title": f"Artifact review: {path}",
                "asset": "",
                "category": "workflow",
                "status": "active",
                "details": (
                    f"Searched {artifact.get('format', 'artifact')} ({artifact.get('size_bytes', 0)} bytes, "
                    f"SHA-256 {artifact.get('sha256', 'unknown')}). Found {artifact.get('unique_matches', 0)} "
                    f"unique printable-string matches. Match counts by term: {term_summary or 'none'}; "
                    f"sample byte offsets: {', '.join(offsets) or 'none'}."
                ),
                "source": f"artifact_search: {path} ({digest})",
                "confidence": "medium",
                "worked": f"Found {artifact.get('unique_matches', 0)} unique matching strings in the local artifact.",
                "failed": "",
                "next_step": "",
            },
        )
        if saved.startswith("Observation was not saved"):
            return saved
        return f"Saved the artifact search summary to Intel Notes. {saved}"

    async def _vulnerability_intel(self) -> dict[str, list[dict[str, Any]]]:
        try:
            summary = json.loads(
                await self._update_session_intel("get_map", {"section": "summary"})
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        if not isinstance(summary, dict):
            return {}

        totals = {
            "assets": summary.get("asset_count", 0),
            "observations": summary.get("observation_count", 0),
            "findings": summary.get("finding_count", 0),
            "exploits": summary.get("exploit_count", 0),
        }
        intel: dict[str, list[dict[str, Any]]] = {section: [] for section in totals}
        for section, raw_total in totals.items():
            try:
                total = max(0, int(raw_total))
            except (TypeError, ValueError):
                continue
            for offset in range(0, total, 8):
                try:
                    page = json.loads(
                        await self._update_session_intel(
                            "get_map", {"section": section, "offset": offset, "limit": 8}
                        )
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                records = page.get("records", []) if isinstance(page, dict) else []
                intel[section].extend(
                    record for record in records if isinstance(record, dict)
                )
        return intel

    async def _save_vulnerability_leads(
        self,
        criteria: str,
        intel: dict[str, Any],
        vulnx_results: list[tuple[str, str | dict[str, Any]]],
    ) -> int:
        assets = [item for item in intel.get("assets", []) if isinstance(item, dict)]

        def asset_for(query: str) -> str:
            terms = {
                term for term in re.findall(r"[a-z0-9.]+", query.casefold()) if len(term) > 2
            }
            best_asset = ""
            best_score = 0
            for asset in assets:
                material_parts = [str(asset.get("value", ""))]
                attributes = asset.get("attributes", {})
                if isinstance(attributes, dict):
                    material_parts.extend(str(value) for value in attributes.values())
                material = " ".join(material_parts).casefold()
                score = sum(term in material for term in terms)
                if score > best_score:
                    best_asset = str(asset.get("value", ""))
                    best_score = score
            return best_asset or next(
                (
                    str(asset.get("value", ""))
                    for asset in assets
                    if asset.get("primary") or asset.get("scope") == "in_scope"
                ),
                (criteria.strip() or query.strip())[:255],
            )

        records: list[tuple[str, dict[str, Any]]] = []
        for query, result in vulnx_results:
            if isinstance(result, dict):
                entries = [result]
            else:
                try:
                    payload = json.loads(result)
                except json.JSONDecodeError:
                    continue
                entries = payload.get("results", []) if isinstance(payload, dict) else []
            if isinstance(entries, list):
                records.extend(
                    (query, item)
                    for item in entries
                    if isinstance(item, dict)
                    and re.fullmatch(r"CVE-\d{4}-\d{3,}", str(item.get("cve_id", "")), re.IGNORECASE)
                )

        saved = 0
        seen: set[tuple[str, str]] = set()
        for query, record in records:
            cve = str(record.get("cve_id", "")).upper()
            target = asset_for(query)
            identity = (cve, target.casefold())
            if identity in seen:
                continue
            seen.add(identity)
            title = str(record.get("name") or cve).strip()[:200]
            description = str(record.get("description") or "Vulnerability record returned by Vulnx.").strip()
            remediation = str(record.get("remediation") or "").strip()
            source_type = str(record.get("_source_type") or "Vulnx")
            citations = record.get("citations", [])
            source_urls = [
                str(item.get("url", "")).strip()
                for item in citations
                if isinstance(item, dict) and str(item.get("url", "")).strip()
            ] if isinstance(citations, list) else []
            source = (source_urls[0] if source_urls else "Vulnx vulnerability search")[:500]
            severity = str(record.get("severity", "unknown")).casefold()
            if severity == "moderate":
                severity = "medium"
            if severity not in {"critical", "high", "medium", "low", "informational"}:
                score = record.get("cvss_score")
                if isinstance(score, dict):
                    score = score.get("baseScore") or score.get("base_score") or score.get("score")
                try:
                    score_value = float(score)
                except (TypeError, ValueError):
                    score_value = -1
                severity = (
                    "critical" if score_value >= 9 else
                    "high" if score_value >= 7 else
                    "medium" if score_value >= 4 else
                    "low" if score_value > 0 else
                    "unknown"
                )
            evidence = (
                f"{source_type} returned {cve} for query {query!r}. {description[:1800]}"
                + (f" Source: {', '.join(source_urls[:4])}." if source_urls else "")
                + " Affected-version compatibility has not been checked against the observed service."
            )[:3900]
            summary = description[:2500]
            if remediation:
                summary += f" Remediation listed by source: {remediation[:900]}"
            summary += " Applicability to the observed version is unverified."

            current = next(
                (
                    item for item in intel.get("exploits", [])
                    if isinstance(item, dict)
                    and cve in str(item.get("title", "")).upper()
                    and str(item.get("asset", "")).casefold() == target.casefold()
                ),
                None,
            )
            current_finding = next(
                (
                    item for item in intel.get("findings", [])
                    if isinstance(item, dict)
                    and cve in str(item.get("title", "")).upper()
                    and str(item.get("asset", "")).casefold() == target.casefold()
                ),
                None,
            )
            await self._update_session_intel(
                "upsert_finding",
                {
                    "title": f"{cve}: {title}",
                    "asset": target,
                    "severity": severity,
                    "status": (
                        current_finding.get("status")
                        if current_finding and current_finding.get("status") in {"confirmed", "false_positive", "remediated"}
                        else "lead"
                    ),
                    "summary": summary,
                    "source": source,
                    "evidence": evidence,
                    "recommendation": remediation,
                    "confidence": "medium",
                },
            )
            current_observation = next(
                (
                    item for item in intel.get("observations", [])
                    if isinstance(item, dict)
                    and str(item.get("title", "")).casefold() == f"{cve} applicability".casefold()
                    and str(item.get("asset", "")).casefold() == target.casefold()
                ),
                None,
            )
            observation_status = (
                current_observation.get("status")
                if current_observation and current_observation.get("status") in {"validated", "rejected", "resolved"}
                else "unverified"
            )
            await self._update_session_intel(
                "upsert_observation",
                {
                    "title": f"{cve} applicability",
                    "asset": target,
                    "category": "exploit",
                    "status": observation_status,
                    "details": evidence[:7900],
                    "source": source,
                    "confidence": "medium",
                    "worked": f"Found a {source_type} reference for {cve}.",
                    "failed": "Target-side applicability has not been verified.",
                    "next_step": "Compare the observed product version and prerequisites with this record, then validate only with a safe check.",
                },
            )
            if (
                (not current or current.get("status") != "confirmed")
                and not (
                    current_finding
                    and current_finding.get("status") in {"false_positive", "remediated"}
                )
            ):
                await self._update_session_intel(
                    "record_exploit",
                    {
                        "title": f"{cve}: {title}",
                        "target": target,
                        "evidence": evidence,
                        "status": "candidate",
                        "summary": summary,
                        "source": source,
                    },
                )
            saved += 1
        return saved

    @staticmethod
    def _cve_search_leads(
        query: str,
        references: list[dict[str, Any]],
        source_type: str,
    ) -> list[dict[str, Any]]:
        leads = []
        for reference in references:
            title = str(reference.get("title") or reference.get("name") or "Search reference").strip()
            description = str(reference.get("snippet") or reference.get("description") or "").strip()
            cves = set(
                re.findall(r"\bCVE-\d{4}-\d{3,}\b", f"{title} {description}", re.IGNORECASE)
            )
            for cve in cves:
                url = str(reference.get("url", "")).strip()
                exploit_id = str(reference.get("id", "")).strip()
                if source_type == "SearchSploit" and exploit_id:
                    url = f"https://www.exploit-db.com/exploits/{exploit_id}"
                    description = (
                        f"{title}. EDB-ID {exploit_id}. Local reference: {reference.get('path', '')}"
                    )
                elif not description:
                    description = f"{title} matched the {source_type} search for {query}."
                leads.append({
                    "cve_id": cve.upper(),
                    "name": title,
                    "description": description[:1800] or title,
                    "severity": reference.get("severity", "unknown"),
                    "citations": [{"source": source_type, "url": url}] if url else [],
                    "_source_type": source_type,
                })
        return leads

    async def _prepare_vulnsearch_backends(
        self, criteria: str, intel: dict[str, Any]
    ) -> tuple[
        Callable[[str], tuple[list[dict[str, str]], str | None]] | None,
        str,
        Callable[[str], tuple[str, str | None]] | None,
        str,
    ]:
        if not vulnerability_queries(criteria, intel):
            return None, "", None, ""

        local_searcher, local_status = await self._prepare_vulnsearch_backend(
            "exploitdb",
            "search the local Exploit-DB snapshot for matching references",
        )
        vulnx_searcher, vulnx_status = await self._prepare_vulnsearch_backend(
            "vulnx",
            "search vulnerability records for the product/version clues in session Intel",
        )
        return local_searcher, local_status, vulnx_searcher, vulnx_status

    async def _prepare_vulnsearch_backend(
        self, tool_id: str, purpose: str
    ) -> tuple[Callable[..., Any] | None, str]:
        tool = TOOL_BY_ID[tool_id]
        is_vulnx = tool_id == "vulnx"
        if not self._armory_tool_selected(tool_id):
            status = f"{tool.name} is disabled in Armory settings."
            return (lambda query: ("", None) if is_vulnx else ([], None)), status

        executable = resolve_executable(tool)
        if executable is None:
            installed, detail = await self._install_armory_tool(tool_id, purpose)
            if not installed:
                return (lambda query: ("", None) if is_vulnx else ([], None)), detail
            executable = resolve_executable(tool)
        if executable is None:
            status = f"{tool.name} could not be found after installation."
            return (lambda query: ("", None) if is_vulnx else ([], None)), status

        binary, prefix = executable
        if is_vulnx:
            return lambda query: search_vulnx(query, binary, prefix), ""
        return lambda query: search_exploitdb(query, binary, prefix), ""

    async def _default_operator_dialog(
        self,
        dialog: dict[str, Any],
    ) -> str | None:
        questions = dialog.get("questions", [])
        if not questions:
            return None
        first = questions[0]
        options = first.get("options", [])
        question = f"{dialog.get('message', '')}\n\n{first.get('prompt', '')}".strip()
        answer = await self.ask_user(question, options)
        value: Any = answer if first.get("type") == "text" or answer not in options else answer
        return json.dumps(
            {"answers": {first.get("id", "question_1"): value}, "cancelled": False},
            ensure_ascii=False,
        )

    async def _confirm_install(self, message: str, yes_label: str, no_label: str) -> bool:
        answer = await self.operator_dialog(
            {
                "title": "MITSU ASKS",
                "message": message,
                "questions": [
                    {
                        "id": "install",
                        "prompt": "May I go ahead?",
                        "type": "choice",
                        "options": [yes_label, no_label],
                        "required": True,
                    }
                ],
                "submit_label": "Continue",
                "cancel_label": "Cancel",
            }
        )
        try:
            response = json.loads(answer or "{}")
        except json.JSONDecodeError:
            return False
        answers = response.get("answers", {}) if isinstance(response, dict) else {}
        choice = answers.get("install", "") if isinstance(answers, dict) else ""
        return isinstance(choice, str) and choice.casefold().startswith("yes")

    @staticmethod
    def _normalize_install_targets(value: str) -> set[str]:
        if not isinstance(value, str):
            return set()
        targets = set()
        for item in value.split(","):
            name = re.sub(r"\s*\([^)]*\)", "", item).split()
            if name:
                targets.add(re.sub(r"[-_.]+", "-", name[0].strip().casefold()))
        return targets

    def _armory_tool_selected(self, tool_id: str) -> bool:
        tool = TOOL_BY_ID[tool_id]
        return self.armory_enabled and (
            "*" in self.armory_selection
            or tool_id in self.armory_selection
            or tool.category_id in self.armory_selection
        )

    async def _run_armory_tool(
        self,
        tool_id: str,
        argv: list[str],
        purpose: str,
        timeout_seconds: int,
    ) -> str:
        tool = TOOL_BY_ID.get(tool_id.strip())
        if tool is None:
            raise ToolHostError(f"Unknown Armory tool ID: {tool_id}.")
        if not self._armory_tool_selected(tool.id):
            raise ToolHostError(f"{tool.name} is not enabled in MCP configuration. Enable it under /config first.")
        install_detail = ""
        if resolve_executable(tool) is None:
            installed, detail = await self._install_armory_tool(tool.id, purpose)
            if not installed:
                raise ToolHostError(detail)
            install_detail = detail
        result = await self._armory_adapter.run_tool(
            tool.id,
            argv,
            purpose,
            timeout_seconds,
        )
        return f"{install_detail}\n\n{result}" if install_detail else result

    async def _install_armory_tool(self, tool_id: str, purpose: str) -> tuple[bool, str]:
        tool = TOOL_BY_ID[tool_id]
        environment = await asyncio.to_thread(load_host_environment)
        status = await asyncio.to_thread(inspect_tool, tool, environment)
        if status.installed:
            return True, f"{tool.name} is already installed."

        approved = await self._confirm_install(
            f"Hey operator, {tool.name} is missing. I need it to {purpose.strip() or 'continue the requested investigation'}.",
            f"Yes · install {tool.name}",
            "No · skip this tool",
        )
        if not approved:
            return False, f"Installation of {tool.name} was cancelled by the operator."
        try:
            script, method_id, privileged_commands = await asyncio.to_thread(
                build_install_script,
                tool,
                environment,
                "install",
            )
        except ArmoryError as error:
            return False, f"Could not prepare the {tool.name} installer: {error}"

        password = None
        if privileged_commands:
            if self.sudo_password is None:
                return False, f"{tool.name} needs sudo, but no password dialog is available."
            password = await self.sudo_password(privileged_commands[0])
            if password is None:
                return False, f"Installation of {tool.name} was cancelled before sudo ran."
            script = script.replace("sudo --", "sudo -S -p '' --")

        try:
            process = await asyncio.create_subprocess_exec(
                "/bin/bash",
                "-o",
                "pipefail",
                "-c",
                script,
                cwd=self.workspace,
                stdin=asyncio.subprocess.PIPE if password is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as error:
            return False, f"Could not start the {tool.name} installer: {error}"

        output_task = asyncio.create_task(self._read_command_output(process.stdout))
        if password is not None and process.stdin is not None:
            try:
                process.stdin.write(((password + "\n") * len(privileged_commands)).encode())
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                process.stdin.close()
                password = None
        try:
            await asyncio.wait_for(process.wait(), timeout=900)
            output, truncated = await output_task
        except TimeoutError:
            self._kill_command(process)
            await process.wait()
            output, truncated = await output_task
            return False, f"{tool.name} installation timed out after 15 minutes.\n{output.decode('utf-8', errors='replace')}"
        except asyncio.CancelledError:
            self._kill_command(process)
            await process.wait()
            await output_task
            raise

        details = output.decode("utf-8", errors="replace")
        if truncated:
            details += "\n… installer output truncated"
        if process.returncode == 0 and method_id.startswith("official-script:"):
            await asyncio.to_thread(record_managed_install, tool.id, method_id)
        installed = await asyncio.to_thread(inspect_tool, tool, environment)
        if process.returncode == 0 and installed.installed:
            return True, f"{tool.name} installed successfully.\n{details}"
        if process.returncode == 0 and method_id.startswith("official-script:"):
            await asyncio.to_thread(forget_managed_install, tool.id)
        return False, f"{tool.name} installation failed (status {process.returncode}).\n{details}"

    async def call(self, name: str, arguments: Any) -> tuple[str, bool, bool]:
        registration = self._tools.get(name)
        client_info = self._clients.get(name)
        if registration is None or client_info is None:
            return f"Unknown tool: {name}", True, False
        if not isinstance(arguments, dict):
            return "Tool arguments must be a JSON object.", True, not registration["read_only"]
        client, original_name, read_only = client_info
        try:
            result = await client.call_tool(original_name, arguments)
        except Exception as error:
            return f"{type(error).__name__}: {error}", True, not read_only
        pieces = []
        for block in result.content or []:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                pieces.append(text)
            else:
                block_type = getattr(block, "type", "result")
                pieces.append(f"[{block_type} result omitted]")
        if not pieces and result.structured_content is not None:
            pieces.append(json.dumps(result.structured_content, ensure_ascii=False, default=str))
        output = "\n".join(pieces) or "(tool completed with no output)"
        if len(output) > MAX_TOOL_RESULT:
            output = output[:MAX_TOOL_RESULT] + "\n… result truncated"
        failed_status = re.search(r"(?:exit_code=|exited with status )(-?\d+)", output)
        failed = bool(result.is_error) or bool(failed_status and int(failed_status.group(1)) != 0)
        failed = failed or any(
            marker in output.casefold()
            for marker in ("timed out after", "installation failed", "could not start")
        )
        if original_name == "artifact_search":
            note = await self._record_artifact_search(output)
            if note:
                output += f"\n\n{note}"
        if self.tool_result_handler:
            try:
                note = await self.tool_result_handler(name, arguments, output)
            except Exception as error:
                note = f"Intel capture failed: {type(error).__name__}: {error}"
            if note:
                output += f"\n\n{note}"
        return output, failed, not read_only

    async def close(self) -> None:
        if self._connected:
            self._connected = False
            await self._stack.aclose()

    async def _run_bash(self, command: str, purpose: str) -> str:
        if not command.strip():
            raise ToolHostError("Command cannot be empty.")
        install_request = _installation_request(command)
        if install_request is not None:
            manager, packages = install_request
            install_targets = self._normalize_install_targets(packages)
            now = time.monotonic()
            self.install_approvals = {
                target: expires
                for target, expires in self.install_approvals.items()
                if expires > now
            }
            approved_targets = {
                target for target, expires in self.install_approvals.items() if expires > now
            }
            missing_targets = install_targets - approved_targets
            if missing_targets:
                reason = purpose.strip() or "continue the requested investigation"
                missing_packages = ", ".join(sorted(missing_targets))
                approved = await self._confirm_install(
                    f"Hey operator, I need to install {missing_packages} using {manager} so I can {reason}.",
                    f"Yes · install {missing_packages}",
                    "No · continue without installing",
                )
                if not approved:
                    return "exit_code=130\nThe operator declined the installation request; nothing was installed and the command was not run."
                self.install_approvals.update(
                    {target: time.monotonic() + 1800 for target in missing_targets}
                )
        needs_sudo = os.name == "posix" and os.geteuid() != 0 and bool(
            re.search(r"(?<![A-Za-z0-9_])sudo(?![A-Za-z0-9_])", command)
        )
        password: str | None = None
        if needs_sudo:
            sudo_path = shutil.which("sudo")
            if sudo_path is None:
                raise ToolHostError("This command uses sudo, but sudo is not installed on this host.")
            if self.sudo_password is None:
                raise ToolHostError("This command needs sudo, but Mitsu has no password dialog available.")
            password = await self.sudo_password(command)
            if password is None:
                return f"exit_code=130\npurpose={purpose or '(not specified)'}\nThe operator cancelled the sudo prompt; the command was not run."
            executable = sudo_path
            arguments = ["-S", "-p", "", "--", "/bin/bash", "-o", "pipefail", "-c", command]
            command_stdin = asyncio.subprocess.PIPE
        else:
            executable = "/bin/bash"
            arguments = ["-o", "pipefail", "-c", command]
            command_stdin = asyncio.subprocess.DEVNULL
        process = await asyncio.create_subprocess_exec(
            executable,
            *arguments,
            cwd=self.workspace,
            stdin=command_stdin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        if password is not None and process.stdin is not None:
            try:
                process.stdin.write(password.encode("utf-8") + b"\n")
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                process.stdin.close()
                password = None
        output_task = asyncio.create_task(self._read_command_output(process.stdout))
        try:
            await asyncio.wait_for(process.wait(), timeout=60)
        except TimeoutError:
            self._kill_command(process)
            await process.wait()
            output, truncated = await output_task
            text = output.decode("utf-8", errors="replace")
            if truncated:
                text += "\n… output truncated"
            return f"Command timed out after 60 seconds.\n{text}"
        except asyncio.CancelledError:
            self._kill_command(process)
            await process.wait()
            await output_task
            raise
        try:
            output, truncated = await asyncio.wait_for(output_task, timeout=2)
        except TimeoutError:
            self._kill_command(process)
            await process.wait()
            output, truncated = await output_task
        text = output.decode("utf-8", errors="replace")
        if truncated:
            text += "\n… output truncated"
        if install_request is not None and process.returncode == 0:
            for target in install_targets:
                self.install_approvals.pop(target, None)
        return f"exit_code={process.returncode}\npurpose={purpose or '(not specified)'}\n{text}"

    @staticmethod
    async def _read_command_output(stream: asyncio.StreamReader | None) -> tuple[bytes, bool]:
        if stream is None:
            return b"", False
        chunks = []
        stored = 0
        truncated = False
        while chunk := await stream.read(65_536):
            remaining = MAX_TOOL_RESULT - stored
            if remaining > 0:
                chunks.append(chunk[:remaining])
                stored += min(len(chunk), remaining)
            if len(chunk) > remaining:
                truncated = True
        return b"".join(chunks), truncated

    @staticmethod
    def _kill_command(process: asyncio.subprocess.Process) -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass

    def _safe_path(self, value: str) -> Path:
        candidate = (self.workspace / value).resolve()
        try:
            candidate.relative_to(self.workspace)
        except ValueError as error:
            raise ToolHostError("File access is limited to the current workspace.") from error
        return candidate

    def _safe_artifact_path(self, value: str) -> Path:
        requested = Path(value).expanduser()
        candidate = (requested if requested.is_absolute() else self.workspace / requested).resolve()
        for root in (self.workspace, Path("/tmp").resolve()):
            try:
                candidate.relative_to(root)
                return candidate
            except ValueError:
                continue
        raise ToolHostError("Artifact access is limited to the current workspace and /tmp.")

    def _safe_list_path(self, value: str) -> Path:
        requested = Path(value).expanduser()
        candidate = (requested if requested.is_absolute() else self.workspace / requested).resolve()
        if candidate != self.workspace and not candidate.is_relative_to(self.workspace):
            raise ToolHostError("Directory listing is limited to the current workspace.")
        return candidate

    @staticmethod
    def _slug(value: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", value).strip("_")
        return slug[:36] or "tool"
