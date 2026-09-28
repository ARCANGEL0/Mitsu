"""MCP adapters for installed RedTeam Armory command-line tools."""

from __future__ import annotations

import asyncio
import inspect
import os
from pathlib import Path
import shutil
import signal
from typing import Annotated, Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mitsu.armory import CATEGORY_BY_ID, TOOLS, TOOL_BY_ID, ToolSpec


MAX_ARGUMENT_COUNT = 128
MAX_ARGUMENT_SIZE = 8_192
MAX_ARGUMENT_BYTES = 32_768
MAX_OUTPUT_BYTES = 40_000
DEFAULT_TIMEOUT_SECONDS = 120
MAX_TIMEOUT_SECONDS = 600

_CATEGORY_GUIDANCE = {
    "osint-recon": "Use a scoped domain, organization, or consented username as this tool requires; favor public sources.",
    "network-mapping": "Limit targets to approved hosts or ranges. Avoid broad scans; start with the narrowest useful check.",
    "web-assessment": "Use the exact in-scope URL. Avoid destructive checks, high request rates, and state-changing options.",
    "api-assessment": "Use an in-scope API endpoint or schema. Do not include secrets in arguments unless the user authorized their use.",
    "database-assessment": "Use an approved test database and credentials supplied for this engagement; avoid changes to stored data.",
    "vulnerability": "Scan only confirmed in-scope assets or local files, and choose safe checks where the CLI supports them.",
    "password-auditing": "Use only supplied test hashes, files, or accounts. Do not target live accounts without explicit approval.",
    "exploitation": "Use only a lab or explicitly approved target. Explain the proposed validation before any state-changing test.",
    "active-directory": "Use only an approved domain and authorized test identities; avoid modifying directory objects.",
    "post-exploitation": "Use only an approved lab session or host. Do not add persistence, evade monitoring, or expand access.",
    "traffic-assessment": "Capture or inspect only traffic and interfaces the user is authorized to assess.",
    "wireless": "Use only owned or explicitly authorized access points, adapters, and capture files.",
    "hardware-radio": "Operate only on owned or explicitly authorized devices and frequencies.",
    "social-engineering": "Use only consent-based simulations with an approved audience and infrastructure.",
    "cloud-container": "Use an explicitly authorized account, tenant, cluster, or local image; prefer read-only audit modes.",
    "mobile": "Use an application package, emulator, or device supplied for this authorized assessment.",
    "forensics-reversing": "Analyze supplied copies or lab binaries; preserve original evidence and avoid modifying source files.",
}


class ArmoryMCPError(RuntimeError):
    """Raised when an Armory MCP call cannot be run safely."""


def normalize_armory_selection(value: object) -> tuple[bool, set[str]]:
    """Return the enabled flag and selected tool IDs from MCP configuration."""
    if value is None:
        value = {"enabled": True, "tools": ["*"]}
    if not isinstance(value, dict):
        raise ArmoryMCPError('The "armory" MCP setting must be an object.')
    enabled = value.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ArmoryMCPError('The "armory.enabled" setting must be true or false.')
    selected = value.get("tools", ["*"])
    if isinstance(selected, dict):
        if any(not isinstance(tool_id, str) or not isinstance(enabled, bool) for tool_id, enabled in selected.items()):
            raise ArmoryMCPError('The "armory.tools" map must associate tool IDs with true or false.')
        unknown = set(selected) - set(TOOL_BY_ID)
        if unknown:
            names = ", ".join(sorted(unknown))
            raise ArmoryMCPError(f"Unknown Armory tool ID(s): {names}.")
        identifiers = {
            tool_id.strip()
            for tool_id, enabled in selected.items()
            if enabled and tool_id.strip()
        }
    elif isinstance(selected, list) and all(isinstance(item, str) for item in selected):
        identifiers = {item.strip() for item in selected if item.strip()}
    else:
        raise ArmoryMCPError('The "armory.tools" setting must be a tool-ID map or a list of tool/category IDs.')
    unknown = identifiers - {"*"} - set(TOOL_BY_ID) - set(CATEGORY_BY_ID)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ArmoryMCPError(f"Unknown Armory tool or category ID(s): {names}.")
    return enabled, identifiers


def _data_root() -> Path:
    configured = os.environ.get("XDG_DATA_HOME")
    return (Path(configured) if configured else Path.home() / ".local" / "share") / "mitsu"


def _armory_install_root(tool: ToolSpec) -> Path:
    return _data_root() / "armory" / tool.id


def _is_runnable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _user_bin_directories() -> tuple[Path, ...]:
    directories = [
        Path.home() / ".local" / "bin",
        Path.home() / ".cargo" / "bin",
        Path.home() / "go" / "bin",
    ]
    for variable in ("GOBIN", "CARGO_HOME", "GEM_HOME"):
        configured = os.environ.get(variable, "").strip()
        if configured:
            path = Path(configured).expanduser()
            directories.append(path if variable == "GOBIN" else path / "bin")
    directories.extend(
        Path(path).expanduser() / "bin"
        for path in os.environ.get("GOPATH", "").split(os.pathsep)
        if path.strip()
    )
    for gem_root in (
        Path.home() / ".gem" / "ruby",
        Path.home() / ".local" / "share" / "gem" / "ruby",
    ):
        if gem_root.is_dir():
            try:
                directories.extend(path / "bin" for path in gem_root.iterdir() if path.is_dir())
            except OSError:
                continue
    return tuple(dict.fromkeys(directories))


def resolve_executable(tool: ToolSpec) -> tuple[str, tuple[str, ...]] | None:
    """Find a catalogued executable, including Mitsu-managed user installs."""
    install_root = _armory_install_root(tool)
    user_bins = _user_bin_directories()

    for executable in tool.executables:
        located = shutil.which(executable)
        if located:
            return located, ()

        candidates = tuple(path / executable for path in user_bins) + (
            install_root / "venv" / "bin" / executable,
            install_root / "source" / executable,
            install_root / executable,
        )
        for candidate in candidates:
            if _is_runnable(candidate):
                return str(candidate.resolve()), ()
            if candidate.is_file() and candidate.suffix == ".sh":
                shell = shutil.which("bash") or shutil.which("sh")
                if shell:
                    return shell, (str(candidate.resolve()),)
            if candidate.is_file() and candidate.suffix == ".py":
                python = shutil.which("python3") or shutil.which("python")
                if python:
                    return python, (str(candidate.resolve()),)

        # Source checkouts can place scripts in a project-specific subdirectory.
        if install_root.is_dir():
            try:
                candidate = next(install_root.rglob(executable), None)
            except OSError:
                candidate = None
            if candidate and _is_runnable(candidate):
                return str(candidate.resolve()), ()
            if candidate and candidate.is_file() and candidate.suffix == ".sh":
                shell = shutil.which("bash") or shutil.which("sh")
                if shell:
                    return shell, (str(candidate.resolve()),)
            if candidate and candidate.is_file() and candidate.suffix == ".py":
                python = shutil.which("python3") or shutil.which("python")
                if python:
                    return python, (str(candidate.resolve()),)
    return None


def _selected_tools(identifiers: set[str]) -> tuple[ToolSpec, ...]:
    if "*" in identifiers:
        return TOOLS
    categories = {
        tool_id
        for category_id in identifiers
        if category_id in CATEGORY_BY_ID
        for tool_id in (tool.id for tool in TOOLS if tool.category_id == category_id)
    }
    tool_ids = (identifiers & set(TOOL_BY_ID)) | categories
    return tuple(tool for tool in TOOLS if tool.id in tool_ids)


class ArmoryMCPAdapter:
    """Register one approval-gated MCP tool for each selected installed binary."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.resolve()

    def register(self, server: MCPServer[Any], configuration: object) -> tuple[int, int]:
        enabled, identifiers = normalize_armory_selection(configuration)
        if not enabled:
            return 0, 0

        selected = _selected_tools(identifiers)
        registered = 0
        unavailable = 0
        for tool in selected:
            executable = resolve_executable(tool)
            if executable is None:
                unavailable += 1
                continue
            self._register_tool(server, tool, executable)
            registered += 1
        return registered, unavailable

    async def run_tool(
        self,
        tool_id: str,
        argv: list[str],
        purpose: str = "",
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> str:
        """Run a catalogued executable resolved at call time, including tools installed mid-session."""
        tool = TOOL_BY_ID.get(tool_id)
        if tool is None:
            raise ArmoryMCPError(f"Unknown Armory tool ID: {tool_id}.")
        executable = resolve_executable(tool)
        if executable is None:
            raise ArmoryMCPError(f"{tool.name} is not installed.")
        command, prefix_arguments = executable
        return await self._run(
            tool,
            command,
            prefix_arguments,
            argv,
            purpose,
            timeout_seconds,
        )

    def _register_tool(
        self,
        server: MCPServer[Any],
        tool: ToolSpec,
        executable: tuple[str, tuple[str, ...]],
    ) -> None:
        public_name = f"armory_{tool.id.replace('-', '_')}"
        argument_name = f"{tool.id.replace('-', '_')}_argv"
        command, prefix_arguments = executable
        category = CATEGORY_BY_ID[tool.category_id]
        target_guidance = _CATEGORY_GUIDANCE.get(
            tool.category_id,
            "Use only the assets and files explicitly included in the authorized assessment.",
        )
        description = (
            f"{tool.description}\n\n"
            f"Category: {category.name}. Executable: {Path(command).name}.\n"
            f"Scope: {target_guidance}\n"
            f"Input: {argument_name} is a JSON array containing one CLI argument per item; do not include the executable "
            "and do not put shell syntax in an item. If the exact flags are unknown, call this tool with "
            '["--help"] first and use the returned usage text.\n'
            "Mitsu applies the current session approval and mode rules before running this tool. "
            "The process runs without a shell, has no stdin, and its output and duration are bounded."
        )
        argv_description = (
            f"Separate command-line arguments for {tool.name} ({Path(command).name}). "
            f"Purpose: {tool.description} Scope guidance: {target_guidance} "
            "Pass each flag and value as its own array item, omit the executable, and never use shell operators. "
            'Use ["--help"] first when this tool\'s installed version has unfamiliar options.'
        )

        async def run_tool(**arguments: Any) -> str:
            """Run this specific installed RedTeam Armory tool."""
            return await self._run(
                tool,
                command,
                prefix_arguments,
                arguments[argument_name],
                arguments.get("purpose", ""),
                arguments.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            )

        run_tool.__name__ = public_name
        run_tool.__signature__ = inspect.Signature(
            parameters=[
                inspect.Parameter(
                    argument_name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    annotation=Annotated[
                        list[Annotated[str, Field(max_length=MAX_ARGUMENT_SIZE)]],
                        Field(description=argv_description, max_length=MAX_ARGUMENT_COUNT),
                    ],
                ),
                inspect.Parameter(
                    "purpose",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default="",
                    annotation=Annotated[
                        str,
                        Field(description=f"Short reason for using {tool.name}.", max_length=500),
                    ],
                ),
                inspect.Parameter(
                    "timeout_seconds",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=DEFAULT_TIMEOUT_SECONDS,
                    annotation=Annotated[
                        int,
                        Field(
                            description=f"Maximum runtime for {tool.name}, in seconds.",
                            ge=1,
                            le=MAX_TIMEOUT_SECONDS,
                        ),
                    ],
                ),
            ],
            return_annotation=str,
        )
        server.tool(
            name=public_name,
            title=tool.name,
            description=description,
            meta={
                "mitsu/armory_tool_id": tool.id,
                "mitsu/armory_category": tool.category_id,
                "mitsu/executable": Path(command).name,
            },
            annotations=ToolAnnotations(
                read_only_hint=False,
                destructive_hint=True,
                open_world_hint=True,
            ),
        )(run_tool)

    async def _run(
        self,
        tool: ToolSpec,
        command: str,
        prefix_arguments: tuple[str, ...],
        argv: list[str],
        purpose: str,
        timeout_seconds: int,
    ) -> str:
        checked_arguments = self._validate_arguments(argv)
        timeout = max(1, min(int(timeout_seconds), MAX_TIMEOUT_SECONDS))
        process = await asyncio.create_subprocess_exec(
            command,
            *prefix_arguments,
            *checked_arguments,
            cwd=self.workspace,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        output_task = asyncio.create_task(self._read_output(process.stdout))
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout)
            output, truncated = await output_task
        except TimeoutError:
            await self._stop_process(process)
            output, truncated = await output_task
            text = output.decode("utf-8", errors="replace")
            if truncated:
                text += "\n… output truncated"
            return f"{tool.name} timed out after {timeout} seconds and was stopped.\n{text}"
        except asyncio.CancelledError:
            await self._stop_process(process)
            await output_task
            raise
        except OSError as error:
            output_task.cancel()
            await asyncio.gather(output_task, return_exceptions=True)
            raise ArmoryMCPError(f"Could not start {tool.name}: {error}") from error

        text = output.decode("utf-8", errors="replace") or "(no output)"
        status = process.returncode
        heading = f"{tool.name} exited with status {status}."
        if purpose.strip():
            heading += f" Purpose: {purpose.strip()[:500]}"
        if truncated:
            text += "\n… output truncated"
        return f"{heading}\n{text}"

    @staticmethod
    def _validate_arguments(argv: list[str]) -> tuple[str, ...]:
        if not isinstance(argv, list) or len(argv) > MAX_ARGUMENT_COUNT:
            raise ArmoryMCPError(f"argv must contain at most {MAX_ARGUMENT_COUNT} string arguments.")
        if any(not isinstance(argument, str) for argument in argv):
            raise ArmoryMCPError("Every argv entry must be a string.")
        if any("\0" in argument for argument in argv):
            raise ArmoryMCPError("Command arguments cannot contain NUL bytes.")
        if any(len(argument.encode("utf-8")) > MAX_ARGUMENT_SIZE for argument in argv):
            raise ArmoryMCPError(f"Each command argument must be at most {MAX_ARGUMENT_SIZE} bytes.")
        if sum(len(argument.encode("utf-8")) for argument in argv) > MAX_ARGUMENT_BYTES:
            raise ArmoryMCPError(f"The complete argument list must be at most {MAX_ARGUMENT_BYTES} bytes.")
        if not argv:
            raise ArmoryMCPError("Provide at least one command-line argument; interactive launches are not supported.")
        return tuple(argv)

    @staticmethod
    async def _read_output(stream: asyncio.StreamReader | None) -> tuple[bytes, bool]:
        if stream is None:
            return b"", False
        chunks: list[bytes] = []
        size = 0
        truncated = False
        while chunk := await stream.read(8_192):
            remaining = MAX_OUTPUT_BYTES - size
            if remaining > 0:
                chunks.append(chunk[:remaining])
                size += min(len(chunk), remaining)
            if len(chunk) > remaining:
                truncated = True
        return b"".join(chunks), truncated

    @staticmethod
    async def _stop_process(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
