"""Expose user-configured command-line programs as documented MCP tools."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import inspect
import os
from pathlib import Path
import re
import shutil
import signal
from typing import Annotated, Any, Literal

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field


MAX_CUSTOM_TOOLS = 128
MAX_PARAMETERS = 48
MAX_ARGUMENT_COUNT = 128
MAX_ARGUMENT_BYTES = 32_768
MAX_ARGUMENT_SIZE = 8_192
MAX_OUTPUT_BYTES = 40_000
MAX_TIMEOUT_SECONDS = 600
DEFAULT_TIMEOUT_SECONDS = 120
_TOOL_ID = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")
_PARAMETER_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$")
_PARAMETER_TYPES = {"string", "integer", "number", "boolean", "string_list"}


class CustomMCPToolError(ValueError):
    """Raised when a custom command tool definition is invalid."""


@dataclass(frozen=True)
class CustomParameter:
    name: str
    kind: str
    description: str
    flag: str
    required: bool
    default: Any = None
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class CustomTool:
    id: str
    name: str
    command: str
    description: str
    usage: str
    examples: tuple[str, ...]
    args: tuple[str, ...]
    parameters: tuple[CustomParameter, ...]
    env: dict[str, str]
    timeout_seconds: int
    read_only: bool


def parse_custom_tool(value: object) -> CustomTool:
    """Validate and normalize one custom CLI-to-MCP tool definition."""
    if not isinstance(value, dict):
        raise CustomMCPToolError("each custom tool must be an object")

    tool_id = value.get("id")
    if not isinstance(tool_id, str) or not _TOOL_ID.fullmatch(tool_id):
        raise CustomMCPToolError('"id" must start with a lowercase letter and contain only letters, numbers, _ or -')
    name = value.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise CustomMCPToolError('"name" must be a non-empty title of at most 120 characters')
    command = value.get("command")
    if not isinstance(command, str) or not command.strip() or "\0" in command:
        raise CustomMCPToolError('"command" must name an executable or an absolute executable path')
    description = value.get("description")
    if not isinstance(description, str) or not description.strip() or len(description) > 4_000:
        raise CustomMCPToolError('"description" must explain the tool and be at most 4,000 characters')
    usage = value.get("usage", "")
    if not isinstance(usage, str) or len(usage) > 12_000:
        raise CustomMCPToolError('"usage" must be text of at most 12,000 characters')

    examples_value = value.get("examples", [])
    if not isinstance(examples_value, list) or len(examples_value) > 12 or any(
        not isinstance(example, str) or len(example) > 1_000 for example in examples_value
    ):
        raise CustomMCPToolError('"examples" must be a list of up to 12 short strings')

    args_value = value.get("args", [])
    if not isinstance(args_value, list) or any(
        not isinstance(argument, str) or "\0" in argument or len(argument.encode("utf-8")) > MAX_ARGUMENT_SIZE
        for argument in args_value
    ):
        raise CustomMCPToolError('"args" must be a list of fixed string arguments')

    parameters_value = value.get("parameters", [])
    if not isinstance(parameters_value, list) or len(parameters_value) > MAX_PARAMETERS:
        raise CustomMCPToolError(f'"parameters" must be a list with at most {MAX_PARAMETERS} entries')
    parameters: list[CustomParameter] = []
    parameter_names: set[str] = set()
    for index, item in enumerate(parameters_value, start=1):
        if not isinstance(item, dict):
            raise CustomMCPToolError(f"parameter {index} must be an object")
        parameter_name = item.get("name")
        if not isinstance(parameter_name, str) or not _PARAMETER_NAME.fullmatch(parameter_name):
            raise CustomMCPToolError(f"parameter {index} needs a valid name")
        if parameter_name in parameter_names or parameter_name in {"purpose", "timeout_seconds"}:
            raise CustomMCPToolError(f"parameter name {parameter_name!r} is duplicated or reserved")
        parameter_names.add(parameter_name)

        kind = item.get("type", "string")
        if not isinstance(kind, str) or kind not in _PARAMETER_TYPES:
            raise CustomMCPToolError(
                f"parameter {parameter_name!r} type must be one of {', '.join(sorted(_PARAMETER_TYPES))}"
            )
        parameter_description = item.get("description")
        if not isinstance(parameter_description, str) or not parameter_description.strip() or len(parameter_description) > 2_000:
            raise CustomMCPToolError(f"parameter {parameter_name!r} needs a description of at most 2,000 characters")
        flag = item.get("flag", "")
        if not isinstance(flag, str) or "\0" in flag or len(flag) > 128:
            raise CustomMCPToolError(f"parameter {parameter_name!r} flag must be a short string")
        required = item.get("required", False)
        if not isinstance(required, bool):
            raise CustomMCPToolError(f"parameter {parameter_name!r} required must be true or false")
        if kind == "boolean" and not flag:
            raise CustomMCPToolError(f"boolean parameter {parameter_name!r} needs a flag")

        default = item.get("default")
        if "default" in item and not _valid_parameter_value(kind, default):
            raise CustomMCPToolError(f"parameter {parameter_name!r} has a default that does not match its type")
        if required and "default" in item:
            raise CustomMCPToolError(f"required parameter {parameter_name!r} cannot have a default")

        choices_value = item.get("choices", [])
        if not isinstance(choices_value, list) or any(not isinstance(choice, str) for choice in choices_value):
            raise CustomMCPToolError(f"parameter {parameter_name!r} choices must be a list of strings")
        if choices_value and kind != "string":
            raise CustomMCPToolError(f"parameter {parameter_name!r} choices are supported only for string values")
        if default is not None and choices_value and default not in choices_value:
            raise CustomMCPToolError(f"parameter {parameter_name!r} default must be one of its choices")

        parameters.append(
            CustomParameter(
                name=parameter_name,
                kind=kind,
                description=parameter_description.strip(),
                flag=flag,
                required=required,
                default=default,
                choices=tuple(choices_value),
            )
        )

    env_value = value.get("env", {})
    if not isinstance(env_value, dict) or any(
        not isinstance(key, str) or not key or "=" in key or "\0" in key
        or not isinstance(env_item, str) or "\0" in env_item
        for key, env_item in env_value.items()
    ):
        raise CustomMCPToolError('"env" must map environment variable names to string values')
    timeout = value.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise CustomMCPToolError(f'"timeout_seconds" must be between 1 and {MAX_TIMEOUT_SECONDS}')
    read_only = value.get("read_only", False)
    if not isinstance(read_only, bool):
        raise CustomMCPToolError('"read_only" must be true or false')

    return CustomTool(
        id=tool_id,
        name=name.strip(),
        command=command.strip(),
        description=description.strip(),
        usage=usage.strip(),
        examples=tuple(example.strip() for example in examples_value if example.strip()),
        args=tuple(args_value),
        parameters=tuple(parameters),
        env=dict(env_value),
        timeout_seconds=timeout,
        read_only=read_only,
    )


def validate_custom_tool_definition(value: object) -> bool:
    """Return whether a persisted custom tool definition is safe to load."""
    try:
        parse_custom_tool(value)
    except CustomMCPToolError:
        return False
    return True


def validate_custom_tool_definitions(value: object) -> bool:
    """Validate a complete custom-tool list, including IDs after MCP name normalization."""
    if not isinstance(value, list) or len(value) > MAX_CUSTOM_TOOLS:
        return False
    identifiers: set[str] = set()
    public_names: set[str] = set()
    for definition in value:
        if not validate_custom_tool_definition(definition):
            return False
        tool_id = definition["id"]
        public_name = f"custom_{tool_id.replace('-', '_')}"
        if tool_id in identifiers or public_name in public_names:
            return False
        identifiers.add(tool_id)
        public_names.add(public_name)
    return True


def _valid_parameter_value(kind: str, value: object) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "string_list":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    return False


def _resolve_command(command: str) -> str | None:
    expanded = str(Path(command).expanduser()) if "~" in command else command
    resolved = shutil.which(expanded)
    return str(Path(resolved).resolve()) if resolved else None


def _annotation(parameter: CustomParameter) -> Any:
    type_by_name: dict[str, Any] = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "string_list": list[str],
    }
    annotation = type_by_name[parameter.kind]
    if parameter.choices:
        annotation = Literal.__getitem__(parameter.choices)
    if not parameter.required:
        annotation = annotation | None
    description = parameter.description
    if parameter.flag:
        description += f" CLI flag: {parameter.flag}."
    field = Field(description=description)
    return Annotated[annotation, field]


class CustomMCPAdapter:
    """Register user-defined executables as distinct, documented MCP tools."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.resolve()

    def register(self, server: MCPServer[Any], definitions: object) -> tuple[int, list[str]]:
        if definitions is None:
            return 0, []
        if not isinstance(definitions, list):
            return 0, ['"custom_tools" must be a list']
        if len(definitions) > MAX_CUSTOM_TOOLS:
            return 0, [f'"custom_tools" may contain at most {MAX_CUSTOM_TOOLS} entries']

        registered = 0
        issues: list[str] = []
        seen_ids: set[str] = set()
        seen_names: set[str] = set()
        for index, definition in enumerate(definitions, start=1):
            try:
                tool = parse_custom_tool(definition)
            except CustomMCPToolError as error:
                issues.append(f"Custom tool #{index}: {error}.")
                continue
            if tool.id in seen_ids:
                issues.append(f"Custom tool #{index}: duplicate id {tool.id!r}.")
                continue
            seen_ids.add(tool.id)
            public_name = f"custom_{tool.id.replace('-', '_')}"
            if public_name in seen_names:
                issues.append(
                    f"Custom tool #{index}: id {tool.id!r} conflicts with another tool after MCP name normalization."
                )
                continue
            seen_names.add(public_name)
            executable = _resolve_command(tool.command)
            if executable is None:
                issues.append(
                    f"{tool.name}: executable {tool.command!r} was not found on PATH; use its full path or install it."
                )
                continue
            self._register_tool(server, tool, executable)
            registered += 1
        return registered, issues

    def _register_tool(self, server: MCPServer[Any], tool: CustomTool, executable: str) -> None:
        public_name = f"custom_{tool.id.replace('-', '_')}"
        parameter_descriptions = "; ".join(
            f"{parameter.name}: {parameter.description}"
            for parameter in tool.parameters
        ) or "No user inputs are required."
        description_parts = [tool.description]
        description_parts.append(f"Configured executable: {Path(executable).name}.")
        description_parts.append(f"Parameters: {parameter_descriptions}")
        if tool.usage:
            description_parts.append("Usage notes:\n" + tool.usage)
        if tool.examples:
            description_parts.append("Examples:\n" + "\n".join(f"- {example}" for example in tool.examples))
        description_parts.append(
            "The configured command runs without a shell, with no interactive stdin, a bounded timeout, "
            "and Mitsu's session approval rules."
        )

        async def run_custom_tool(**arguments: Any) -> str:
            """Run this user-configured command-line tool."""
            return await self._run(tool, executable, arguments)

        parameters: list[inspect.Parameter] = []
        for parameter in tool.parameters:
            default = inspect.Parameter.empty if parameter.required else parameter.default
            parameters.append(
                inspect.Parameter(
                    parameter.name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=default,
                    annotation=_annotation(parameter),
                )
            )
        parameters.extend(
            (
                inspect.Parameter(
                    "purpose",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default="",
                    annotation=Annotated[str, Field(description="Why this tool is being used.", max_length=500)],
                ),
                inspect.Parameter(
                    "timeout_seconds",
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=tool.timeout_seconds,
                    annotation=Annotated[
                        int,
                        Field(
                            description="Maximum time for this command, in seconds.",
                            ge=1,
                            le=MAX_TIMEOUT_SECONDS,
                        ),
                    ],
                ),
            )
        )
        run_custom_tool.__name__ = public_name
        run_custom_tool.__signature__ = inspect.Signature(parameters=parameters, return_annotation=str)
        server.tool(
            name=public_name,
            title=tool.name,
            description="\n\n".join(description_parts),
            meta={"mitsu/custom_tool_id": tool.id, "mitsu/executable": Path(executable).name},
            annotations=ToolAnnotations(
                read_only_hint=tool.read_only,
                destructive_hint=not tool.read_only,
                open_world_hint=True,
            ),
        )(run_custom_tool)

    async def _run(self, tool: CustomTool, executable: str, values: dict[str, Any]) -> str:
        arguments = self._build_arguments(tool, values)
        argv = (executable, *tool.args, *arguments)
        argument_bytes = sum(len(argument.encode("utf-8")) for argument in argv[1:])
        if len(argv) - 1 > MAX_ARGUMENT_COUNT:
            raise CustomMCPToolError(f"The command may contain at most {MAX_ARGUMENT_COUNT} arguments.")
        if argument_bytes > MAX_ARGUMENT_BYTES:
            raise CustomMCPToolError(f"The command arguments exceed {MAX_ARGUMENT_BYTES} bytes.")
        environment = os.environ.copy()
        environment.update(tool.env)
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=self.workspace,
                env=environment,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as error:
            raise CustomMCPToolError(f"Could not start {tool.name}: {error}") from error

        output_task = asyncio.create_task(self._read_output(process.stdout))
        timeout = min(
            max(1, int(values.get("timeout_seconds", tool.timeout_seconds))),
            MAX_TIMEOUT_SECONDS,
        )
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

        output_text = output.decode("utf-8", errors="replace") or "(no output)"
        if truncated:
            output_text += "\n… output truncated"
        purpose = str(values.get("purpose", "")).strip()
        heading = f"{tool.name} exited with status {process.returncode}."
        if purpose:
            heading += f" Purpose: {purpose[:500]}"
        return f"{heading}\n{output_text}"

    @staticmethod
    def _build_arguments(tool: CustomTool, values: dict[str, Any]) -> tuple[str, ...]:
        result: list[str] = []
        for parameter in tool.parameters:
            value = values.get(parameter.name)
            if value is None:
                continue
            if parameter.choices and value not in parameter.choices:
                raise CustomMCPToolError(
                    f"{parameter.name} must be one of: {', '.join(parameter.choices)}"
                )
            if parameter.kind == "boolean":
                if value:
                    result.append(parameter.flag)
                continue

            values_to_add = value if parameter.kind == "string_list" else [value]
            for item in values_to_add:
                if not isinstance(item, str):
                    item = str(item)
                if "\0" in item or len(item.encode("utf-8")) > MAX_ARGUMENT_SIZE:
                    raise CustomMCPToolError(
                        f"{parameter.name} values must be at most {MAX_ARGUMENT_SIZE} bytes and contain no NUL bytes."
                    )
                if parameter.flag:
                    result.append(parameter.flag)
                result.append(item)
        return tuple(result)

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
