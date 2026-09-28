"""Expose built-in and MCP tools to agent turns."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
import ipaddress
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
from typing import Any, Awaitable, Callable, Literal

from mcp import Client, StdioServerParameters
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from mitsu.search import search_web as perform_web_search
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
from mitsu.tools.custom_mcp import CustomMCPAdapter


MAX_TOOL_RESULT = 40_000
IntelUpdateHandler = Callable[[str, dict[str, Any]], Awaitable[str]]
OperatorDialogHandler = Callable[[str, list[str], str, bool], Awaitable[str | None]]
SudoPasswordHandler = Callable[[str], Awaitable[str | None]]


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
    if executable == "curl":
        allowed_flags = {"-s", "-S", "-sS", "-I", "--head", "-L", "--location"}
        urls = []
        index = 0
        while index < len(arguments):
            argument = arguments[index]
            if argument in allowed_flags:
                index += 1
                continue
            if argument in {"--max-time", "--connect-timeout"}:
                index += 1
                if index >= len(arguments) or not arguments[index].isdigit():
                    return False
                index += 1
                continue
            if argument.startswith(("http://", "https://")):
                urls.append(argument)
                index += 1
                continue
            return False
        return len(urls) == 1
    if executable == "nmap":
        timing: set[str] = set()
        scan_types: set[str] = set()
        fast_scan = False
        ports: str | None = None
        targets: list[str] = []
        index = 0
        while index < len(arguments):
            argument = arguments[index]
            if argument in {"-T1", "-T2"}:
                timing.add(argument)
            elif argument in {"-sT", "-sn"}:
                scan_types.add(argument)
            elif argument == "-F":
                fast_scan = True
            elif argument == "-p":
                index += 1
                if index >= len(arguments):
                    return False
                ports = arguments[index]
                if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?){0,19}", ports):
                    return False
                ranges = [item.split("-", 1) for item in ports.split(",")]
                if any(int(part) > 65535 for item in ranges for part in item):
                    return False
                if any(len(item) == 2 and int(item[0]) > int(item[1]) for item in ranges):
                    return False
                port_count = sum(
                    (int(item[1]) - int(item[0]) + 1) if len(item) == 2 else 1
                    for item in ranges
                )
                if port_count > 20:
                    return False
            elif argument.startswith("-"):
                return False
            else:
                targets.append(argument)
            index += 1
        target = targets[0] if len(targets) == 1 else ""
        if not target or "/" in target or "," in target:
            return False
        try:
            ipaddress.ip_address(target)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", target):
                return False
        if "-sn" in scan_types:
            return bool(timing)
        return "-sT" in scan_types and bool(timing) and (fast_scan or ports is not None)
    return False


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
    ) -> None:
        self.workspace = workspace.resolve()
        self.ask_user = ask_user
        self.update_intel = update_intel
        self.search_settings = search_settings or (lambda: {})
        self.operator_dialog = operator_dialog or self._default_operator_dialog
        self.sudo_password = sudo_password
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
            "List a directory under the current workspace or the operator's home directory."
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

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True))
        async def web_search(query: str, max_results: int = 5) -> str:
            "Search all configured web engines concurrently. Return merged titles, URLs, snippets, and which engines found each link. If none are configured, tell the operator to use /config."
            if not query.strip():
                raise ToolHostError("Enter a search query.")
            return await asyncio.to_thread(
                perform_web_search, query.strip(), max_results, self.search_settings()
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def ask_user(question: str, choices: list[str] | None = None) -> str:
            "Ask the operator a question and wait for their answer."
            options = [str(choice) for choice in (choices or []) if str(choice).strip()][:8]
            return await self.ask_user(question.strip(), options)

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def user_dialog(
            question: str,
            options: list[str] | None = None,
            mode: Literal["single", "multiple", "yes_no", "text"] = "single",
            allow_other: bool = False,
        ) -> str:
            """Ask the operator in an interactive dialog with single-choice, multi-select, yes/no, or text input."""
            choices = [str(option).strip()[:240] for option in (options or []) if str(option).strip()][:12]
            if mode == "yes_no" and not choices:
                choices = ["Yes", "Yes, but…", "No"]
            if mode in {"single", "multiple", "yes_no"} and not choices:
                raise ToolHostError("Provide at least one option for this dialog.")
            if not question.strip():
                raise ToolHostError("The dialog question cannot be empty.")
            answer = await self.operator_dialog(question.strip()[:1200], choices, mode, allow_other)
            return answer or json.dumps({"selected": [], "text": "", "cancelled": True})

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

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
        async def intel_get_map(
            section: Literal["summary", "assets", "observations", "findings", "exploits"] = "summary",
            offset: int = 0,
            limit: int = 8,
        ) -> str:
            """Read this session's Intel summary or a page of assets, observations, findings, and evidence."""
            return await self._update_session_intel(
                "get_map", {"section": section, "offset": offset, "limit": limit}
            )

        @self.server.tool(annotations=ToolAnnotations(read_only_hint=False, open_world_hint=False))
        async def intel_upsert_asset(
            asset_type: Literal[
                "target", "domain", "hostname", "ip", "url", "service",
                "endpoint", "technology", "account", "other",
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
            """Add or update a target-map asset with provenance and observed evidence.

            Record operator-provided targets and evidence-backed discoveries. Keep discovered
            assets at unknown scope; mark an asset in_scope only when the operator's request
            explicitly authorizes it. Use attributes for details such as port, protocol, banner,
            product, version, or DNS records. Repeated calls merge evidence into the same asset.
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
            category: Literal["recon", "service", "authentication", "behavior", "configuration", "other"],
            status: Literal["unverified", "validated", "rejected"],
            details: str,
            source: str,
            confidence: Literal["low", "medium", "high", "unknown"] = "medium",
        ) -> str:
            """Save a sourced technical observation or useful lead to this session's Intel."""
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
            """Add or update an evidence-backed finding in this session's local Intel."""
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
            title: str, target: str, evidence: str, status: str = "candidate"
        ) -> str:
            """Add an applicable exploit to this session's Intel.

            Use only after observed target evidence matches the exploit's product/version or
            after validation. Mark confirmed only when the test succeeded; local search hits
            alone are not evidence and must never be recorded.
            """
            return await self._update_session_intel(
                "record_exploit",
                {"title": title, "target": target, "evidence": evidence, "status": status},
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

    async def _default_operator_dialog(
        self,
        question: str,
        options: list[str],
        mode: str,
        allow_other: bool,
    ) -> str | None:
        answer = await self.ask_user(question, options)
        selected = [answer] if answer in options else []
        text = answer if mode == "text" or allow_other or not options else ""
        return json.dumps({"selected": selected, "text": text}, ensure_ascii=False)

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
            installed, detail = await self._install_armory_tool(tool.id)
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

    async def _install_armory_tool(self, tool_id: str) -> tuple[bool, str]:
        tool = TOOL_BY_ID[tool_id]
        environment = await asyncio.to_thread(load_host_environment)
        status = await asyncio.to_thread(inspect_tool, tool, environment)
        if status.installed:
            return True, f"{tool.name} is already installed."

        answer = await self.operator_dialog(
            f"{tool.name} is not installed. Want me to install it, then run it?",
            [f"Yes · install {tool.name}", "No · skip this tool"],
            "single",
            False,
        )
        if not answer:
            return False, f"Installation of {tool.name} was cancelled by the operator."
        try:
            selection = json.loads(answer)
        except json.JSONDecodeError:
            selection = {"selected": [answer]}
        selected = selection.get("selected", []) if isinstance(selection, dict) else []
        if not selected or not str(selected[0]).startswith("Yes"):
            return False, f"{tool.name} was not installed; the operator declined."

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
        return output, failed, not read_only

    async def close(self) -> None:
        if self._connected:
            self._connected = False
            await self._stack.aclose()

    async def _run_bash(self, command: str, purpose: str) -> str:
        if not command.strip():
            raise ToolHostError("Command cannot be empty.")
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

    def _safe_list_path(self, value: str) -> Path:
        requested = Path(value).expanduser()
        candidate = (requested if requested.is_absolute() else self.workspace / requested).resolve()
        allowed_roots = (self.workspace, Path.home().resolve())
        if not any(candidate == root or candidate.is_relative_to(root) for root in allowed_roots):
            raise ToolHostError("Directory listing is limited to the current workspace or home directory.")
        return candidate

    @staticmethod
    def _slug(value: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", value).strip("_")
        return slug[:36] or "tool"
