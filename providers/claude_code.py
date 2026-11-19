from __future__ import annotations

import asyncio
import inspect
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

from mcp.server import MCPServer
from mcp.server.mcpserver.utilities.func_metadata import ArgModelBase
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import ConfigDict, Field, create_model

from mitsu.providers.client import ProviderRequestError, ProviderTurn


# Change of plans: use Claude Code with Mitsu's MCP bridge instead of direct OAuth.
# Direct OAuth emulation is unreliable and can put a user's Anthropic account at risk.
CLAUDE_MODELS = ("opus", "sonnet", "haiku")
ToolDispatcher = Callable[[str, dict[str, Any]], Awaitable[tuple[str, bool]]]
ProgressHandler = Callable[[str, dict[str, Any]], None]


def _clean_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
    ):
        environment.pop(key, None)
    return environment


def claude_binary() -> str:
    binary = shutil.which("claude")
    if not binary:
        raise ProviderRequestError(
            "Claude Code is not installed or is missing from PATH. Install Claude Code, then restart Mitsu."
        )
    return binary


def account_status() -> dict[str, Any]:
    binary = claude_binary()
    with tempfile.TemporaryDirectory(prefix="mitsu-claude-check-") as working_directory:
        try:
            result = subprocess.run(
                [binary, "auth", "status", "--json"],
                cwd=working_directory,
                env=_clean_environment(),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ProviderRequestError(f"Could not check Claude Code sign-in: {error}") from error
    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ProviderRequestError(
            f"Claude Code returned an unreadable sign-in status{': ' + detail[:240] if detail else '.'}"
        ) from error
    if result.returncode or not isinstance(status, dict):
        detail = result.stderr.strip() or "Claude Code could not verify the saved account."
        raise ProviderRequestError(detail[:400])
    if status.get("loggedIn") is not True:
        raise ProviderRequestError("Claude Code is not signed in. Run `claude auth login`, then retry.")
    if str(status.get("authMethod", "")).casefold() != "claude.ai":
        raise ProviderRequestError(
            "Claude Code is signed in with a different authentication method. Sign in to Claude.ai with `claude auth login`."
        )
    if status.get("apiProvider") not in {None, "firstParty"}:
        raise ProviderRequestError("Claude Code is using a configured third-party provider, not the signed-in Claude account.")
    return status


def model_name(model: str) -> str:
    selected = model.strip().casefold()
    if selected in CLAUDE_MODELS:
        return selected
    if "opus" in selected:
        return "opus"
    if "sonnet" in selected:
        return "sonnet"
    if "haiku" in selected:
        return "haiku"
    raise ProviderRequestError(f"Unsupported Claude Code model selection: {model or '(empty)'}")


def test_connection(profile: dict[str, Any]) -> str:
    account_status()
    binary = claude_binary()
    model = model_name(str(profile.get("model", "opus")))
    with tempfile.TemporaryDirectory(prefix="mitsu-claude-probe-") as working_directory:
        try:
            result = subprocess.run(
                [
                    binary,
                    "-p",
                    "--output-format",
                    "json",
                    "--model",
                    model,
                    "Reply exactly MITSU_OK.",
                    "--no-session-persistence",
                    "--strict-mcp-config",
                    "--restricted",
                    "--tools",
                    "",
                ],
                cwd=working_directory,
                env=_clean_environment(),
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ProviderRequestError("Claude Code model verification timed out after 90 seconds.") from error
        except OSError as error:
            raise ProviderRequestError(f"Could not start Claude Code: {error}") from error
    if result.returncode:
        detail = _response_text(result.stdout) or result.stderr.strip() or "Claude Code model verification failed."
        raise ProviderRequestError(detail[:500])
    response = _response_text(result.stdout)
    if response.strip() != "MITSU_OK":
        raise ProviderRequestError(
            f"Claude Code ran, but the selected model did not pass verification: {response[:300] or 'empty reply'}"
        )
    return f"Claude Code account and {model.title()} model reply verified."


def _response_text(output: str) -> str:
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        candidates = value if isinstance(value, list) else [value]
        for candidate in reversed(candidates):
            if isinstance(candidate, dict) and candidate.get("type") == "result":
                return str(candidate.get("result", ""))
    return output.strip()


def complete(profile: dict[str, Any], messages: list[dict[str, Any]]) -> str:
    account_status()
    binary = claude_binary()
    model = model_name(str(profile.get("model", "opus")))
    system_prompt = "\n\n".join(
        str(message.get("content", ""))
        for message in messages
        if message.get("role") == "system"
    )
    conversation = [
        {"role": str(message.get("role", "user")), "content": message.get("content", "")}
        for message in messages
        if message.get("role") in {"user", "assistant"}
    ]
    prompt = "\n\n".join(
        f"{message['role'].upper()}: {message['content']}"
        for message in conversation
    )
    if not prompt.strip():
        raise ProviderRequestError("Claude Code needs a message to respond to.")
    command = [
        binary,
        "-p",
        prompt,
        "--output-format",
        "json",
        "--model",
        model,
        "--no-session-persistence",
        "--strict-mcp-config",
        "--restricted",
        "--tools",
        "",
    ]
    if system_prompt:
        command.extend(["--system-prompt", system_prompt])
    with tempfile.TemporaryDirectory(prefix="mitsu-claude-complete-") as working_directory:
        try:
            result = subprocess.run(
                command,
                cwd=working_directory,
                env=_clean_environment(),
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ProviderRequestError("Claude Code timed out before returning a response.") from error
        except OSError as error:
            raise ProviderRequestError(f"Could not start Claude Code: {error}") from error
    response = _response_text(result.stdout)
    if result.returncode:
        raise ProviderRequestError((response or result.stderr.strip() or "Claude Code request failed.")[:1200])
    return response


def _argument_type(schema: dict[str, Any]) -> Any:
    kind = schema.get("type")
    if kind == "string":
        return str
    if kind == "integer":
        return int
    if kind == "number":
        return float
    if kind == "boolean":
        return bool
    if kind == "array":
        return list[Any]
    if kind == "object":
        return dict[str, Any]
    return Any


def _tool_server_name(name: str) -> str:
    local_name = name.removeprefix("mitsu__").replace("__", "_")
    return local_name[:64]


def _mcp_server(tools: list[dict[str, Any]], dispatch: ToolDispatcher) -> tuple[MCPServer, list[str]]:
    server = MCPServer("Mitsu tool bridge", log_level="CRITICAL")
    allowed_tools = []
    registered_names: set[str] = set()
    for definition in tools:
        provider_name = str(definition.get("name", ""))
        tool_name = _tool_server_name(provider_name)
        if not tool_name or tool_name in registered_names:
            continue
        registered_names.add(tool_name)
        schema = definition.get("parameters")
        if not isinstance(schema, dict):
            schema = {"type": "object", "properties": {}}
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        required = set(schema.get("required", []))
        fields: dict[str, tuple[Any, Any]] = {}
        for index, (key, raw_spec) in enumerate(properties.items()):
            if not isinstance(key, str):
                continue
            spec = raw_spec if isinstance(raw_spec, dict) else {}
            internal_name = key if key.isidentifier() else f"argument_{index}"
            default = ... if key in required else None
            field = Field(default, alias=key) if internal_name != key else Field(default)
            fields[internal_name] = (_argument_type(spec), field)
        argument_model = create_model(
            f"MitsuTool_{len(registered_names)}_Arguments",
            __base__=ArgModelBase,
            __config__=ConfigDict(extra="forbid", populate_by_name=True),
            **fields,
        )

        async def invoke(_provider_name: str = provider_name, **kwargs: Any) -> CallToolResult:
            kwargs.pop("_provider_name", None)
            result, is_error = await dispatch(_provider_name, kwargs)
            return CallToolResult(content=[TextContent(type="text", text=result)], is_error=is_error)

        signature_parameters = []
        annotations: dict[str, Any] = {}
        for index, (key, raw_spec) in enumerate(properties.items()):
            if not isinstance(key, str):
                continue
            internal_name = key if key.isidentifier() else f"argument_{index}"
            spec = raw_spec if isinstance(raw_spec, dict) else {}
            annotations[internal_name] = _argument_type(spec)
            default = inspect.Parameter.empty if key in required else None
            signature_parameters.append(
                inspect.Parameter(internal_name, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=annotations[internal_name])
            )
        invoke.__signature__ = inspect.Signature(signature_parameters)
        invoke.__annotations__ = {**annotations, "return": CallToolResult}
        server.add_tool(
            invoke,
            name=tool_name,
            description=str(definition.get("description", provider_name)),
            annotations=ToolAnnotations(read_only_hint=bool(definition.get("read_only"))),
        )
        registered = server._tool_manager._tools[tool_name]
        registered.parameters = schema
        registered.fn_metadata.arg_model = argument_model
        allowed_tools.append(f"mcp__mitsu__{tool_name}")
    return server, allowed_tools


async def _wait_server(port: int, task: asyncio.Task[Any]) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if task.done():
            error = task.exception()
            if error:
                raise ProviderRequestError(f"Mitsu MCP bridge could not start: {error}") from error
            raise ProviderRequestError("Mitsu MCP bridge stopped before it was ready.")
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise ProviderRequestError("Mitsu MCP bridge did not become ready within five seconds.")


async def request_turn(
    profile: dict[str, Any],
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    dispatch: ToolDispatcher,
    session_id: str,
    resumed: bool,
    on_event: ProgressHandler,
    cancellation: Callable[[], bool] | None = None,
) -> ProviderTurn:
    account_status()
    binary = claude_binary()
    selected_model = model_name(str(profile.get("model", "opus")))
    system_prompt = next(
        (str(message.get("content", "")) for message in messages if message.get("role") == "system"),
        "You are Mitsu, a security assessment assistant.",
    )
    user_message = next((message for message in reversed(messages) if message.get("role") == "user"), None)
    if not isinstance(user_message, dict):
        raise ProviderRequestError("Claude Code needs a user message to start the turn.")
    prompt_content = user_message.get("content", "")
    if not isinstance(prompt_content, str):
        text_parts = [
            str(block.get("text", ""))
            for block in prompt_content
            if isinstance(block, dict) and block.get("type") == "text"
        ] if isinstance(prompt_content, list) else []
        if any(isinstance(block, dict) and block.get("type") == "mitsu_image" for block in prompt_content):
            raise ProviderRequestError("Claude Code account mode does not yet support image attachments.")
        prompt_content = "\n".join(text_parts)
    prompt = str(prompt_content).strip()
    if not prompt:
        raise ProviderRequestError("Claude Code received an empty user message.")

    server, allowed_tools = _mcp_server(tools, dispatch)
    token = uuid.uuid4().hex
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    server_task = asyncio.create_task(
        server.run_streamable_http_async(
            host="127.0.0.1",
            port=port,
            streamable_http_path=f"/{token}/mcp",
            json_response=True,
            stateless_http=True,
        )
    )
    process: asyncio.subprocess.Process | None = None
    stderr_task: asyncio.Task[bytes] | None = None
    try:
        await _wait_server(port, server_task)
        mcp_config = json.dumps(
            {"mcpServers": {"mitsu": {"type": "http", "url": f"http://127.0.0.1:{port}/{token}/mcp"}}},
            separators=(",", ":"),
        )
        command = [
            binary,
            "-p",
            "--output-format",
            "stream-json",
            "--include-partial-messages",
            "--model",
            selected_model,
            "--system-prompt",
            system_prompt,
            "--system-prompt-snapshot",
            "off",
            "--setting-sources",
            "user",
            "--disable-slash-commands",
            "--strict-mcp-config",
            "--mcp-config",
            mcp_config,
            "--tools",
            "",
            "--permission-mode",
            "dontAsk",
        ]
        if allowed_tools:
            command.extend(["--allowedTools", *allowed_tools])
        command.extend(["--resume", session_id] if resumed else ["--session-id", session_id])
        command.append(prompt)
        session_directory = Path(tempfile.gettempdir()) / "mitsu-claude-sessions" / session_id
        session_directory.mkdir(parents=True, exist_ok=True)
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=session_directory,
            env=_clean_environment(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stderr_task = asyncio.create_task(process.stderr.read())
        final_result: dict[str, Any] | None = None
        streamed_text: list[str] = []
        deadline = time.monotonic() + 300
        while True:
            if cancellation is not None and cancellation():
                raise asyncio.CancelledError
            if time.monotonic() >= deadline:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except TimeoutError:
                    process.kill()
                    await process.wait()
                raise ProviderRequestError("Claude Code request timed out after five minutes.")
            try:
                line = await asyncio.wait_for(
                    process.stdout.readline(),
                    timeout=min(0.15, max(0.01, deadline - time.monotonic())),
                )
            except TimeoutError:
                if process.returncode is not None:
                    break
                continue
            if not line:
                if process.returncode is not None:
                    break
                continue
            try:
                event = json.loads(line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("type") == "stream_event":
                raw_event = event.get("event")
                delta = raw_event.get("delta") if isinstance(raw_event, dict) else None
                if isinstance(delta, dict) and delta.get("type") == "text_delta":
                    text = str(delta.get("text", ""))
                    if text:
                        streamed_text.append(text)
                        on_event("delta", {"text": text})
            elif event.get("type") == "result":
                final_result = event
        return_code = await process.wait()
        stderr = (await stderr_task).decode("utf-8", errors="replace") if stderr_task else ""
        if return_code != 0 or not final_result or final_result.get("is_error") is True:
            detail = str((final_result or {}).get("result", "")).strip() or stderr.strip()
            raise ProviderRequestError(detail[:1200] or f"Claude Code exited with status {return_code}.")
        final_text = str(final_result.get("result", "")).strip()
        if not final_text:
            final_text = "".join(streamed_text).strip()
        if not final_text:
            raise ProviderRequestError("Claude Code finished without returning a reply.")
        return ProviderTurn(
            final_text,
            {"role": "assistant", "content": final_text},
            [],
            final_result.get("usage", {}) if isinstance(final_result.get("usage"), dict) else {},
            {
                "session_id": str(final_result.get("session_id", session_id)),
                "finish_reason": str(final_result.get("stop_reason", "end_turn")),
            },
        )
    except asyncio.CancelledError:
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()
                await process.wait()
        raise
    except ProviderRequestError:
        raise
    except (OSError, URLError, TimeoutError) as error:
        raise ProviderRequestError(f"Claude Code bridge failed: {error}") from error
    finally:
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()
                await process.wait()
        if stderr_task is not None and not stderr_task.done():
            stderr_task.cancel()
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
