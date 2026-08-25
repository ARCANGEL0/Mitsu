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
import shlex
import signal
import socket
import sys
from typing import Any, Awaitable, Callable

from mcp import Client, StdioServerParameters
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from mitsu.search import search_web as perform_web_search


MAX_TOOL_RESULT = 40_000
IntelUpdateHandler = Callable[[str, dict[str, Any]], Awaitable[str]]


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
    ) -> None:
        self.workspace = workspace.resolve()
        self.ask_user = ask_user
        self.update_intel = update_intel
        self.search_settings = search_settings or (lambda: {})
        self.server = MCPServer("Mitsu built-in tools")
        self._stack = AsyncExitStack()
        self._clients: dict[str, tuple[Client, str, bool]] = {}
        self._tools: dict[str, dict[str, Any]] = {}
        self.connection_messages: list[str] = []
        self._connected = False
        self._register_builtin_tools()
