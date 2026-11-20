from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

from mitsu.providers.client import ProviderRequestError, ProviderTurn
from mitsu.providers.claude_code import _mcp_server, _wait_server


DEFAULT_MODEL = "default"
ToolDispatcher = Callable[[str, dict[str, Any]], Awaitable[tuple[str, bool]]]
ProgressHandler = Callable[[str, dict[str, Any]], None]


def codex_binary() -> str:
    binary = shutil.which("codex")
    if not binary:
        raise ProviderRequestError(
            "Codex CLI is not installed or missing from PATH. Install Codex CLI, run `codex login`, then retry."
        )
    return binary


def account_status() -> str:
    binary = codex_binary()
    try:
        result = subprocess.run(
            [binary, "login", "status"],
            cwd=tempfile.gettempdir(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProviderRequestError(f"Could not check Codex account sign-in: {error}") from error
    detail = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode or "logged in using chatgpt" not in detail.casefold():
        raise ProviderRequestError(
            "Codex CLI is not signed in with a ChatGPT account. Run `codex login`, then retry."
        )
    return "ChatGPT account login verified through Codex CLI."


def sign_in() -> str:
    binary = codex_binary()
    try:
        return account_status()
    except ProviderRequestError:
        pass
    try:
        result = subprocess.run(
            [binary, "login"],
            cwd=tempfile.gettempdir(),
            stdin=None,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ProviderRequestError("Codex account sign-in timed out. Complete the browser sign-in and retry.") from error
    except OSError as error:
        raise ProviderRequestError(f"Could not start Codex account sign-in: {error}") from error
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "Codex account sign-in failed."
        raise ProviderRequestError(detail[:800])
    return account_status()


def model_argument(profile: dict[str, Any]) -> str | None:
    model = str(profile.get("model", DEFAULT_MODEL)).strip()
    return None if model.casefold() in {"", DEFAULT_MODEL, "codex default"} else model


def _config_argument(key: str, value: str) -> str:
    return f"{key}={json.dumps(value, ensure_ascii=False)}"


def _prompt(messages: list[dict[str, Any]]) -> str:
    parts = []
    for message in messages:
        role = str(message.get("role", "user")).upper()
        if role not in {"USER", "ASSISTANT"}:
            continue
        content = message.get("content", "")
        if isinstance(content, list):
            content = "\n".join(
                str(block.get("text", ""))
                for block in content
                if isinstance(block, dict) and block.get("type") in {"text", "tool_result"}
            )
        if str(content).strip():
            parts.append(f"{role}: {content}")
    return "\n\n".join(parts).strip()


async def _run_exec(
    profile: dict[str, Any],
    system_prompt: str,
    prompt: str,
    session_directory: Path,
    on_event: ProgressHandler,
    mcp_url: str = "",
    thread_id: str = "",
    cancellation: Callable[[], bool] | None = None,
    ephemeral: bool = False,
) -> tuple[str, str, dict[str, Any]]:
    binary = codex_binary()
    command = [binary, "exec"]
    if thread_id:
        command.append("resume")
    command.extend(["--json"])
    if thread_id:
        command.append(thread_id)
    command.extend(
        [
            "--ignore-user-config",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--cd",
            str(session_directory),
            "--config",
            'approval_policy="never"',
            "--config",
            _config_argument("developer_instructions", system_prompt),
        ]
    )
    selected_model = model_argument(profile)
    if selected_model:
        command.extend(["--model", selected_model])
    if mcp_url:
        command.extend(
            [
                "--config",
                _config_argument("mcp_servers.mitsu.url", mcp_url),
                "--config",
                "mcp_servers.mitsu.enabled=true",
            ]
        )
    if ephemeral:
        command.append("--ephemeral")
    command.append(prompt)
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=session_directory,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as error:
        raise ProviderRequestError(f"Could not start Codex CLI: {error}") from error
    stderr_task = asyncio.create_task(process.stderr.read())
    deadline = time.monotonic() + 300
    thread = thread_id
    final_text = ""
    final_event: dict[str, Any] = {}
    try:
        while True:
            if cancellation is not None and cancellation():
                raise asyncio.CancelledError
            if time.monotonic() >= deadline:
                raise ProviderRequestError("Codex CLI request timed out after five minutes.")
            try:
                line = await asyncio.wait_for(
                    process.stdout.readline(),
                    timeout=min(0.15, max(0.01, deadline - time.monotonic())),
                )
            except TimeoutError:
                continue
            if not line:
                if process.returncode is not None:
                    break
                await asyncio.sleep(0.05)
                continue
            try:
                event = json.loads(line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("type") == "thread.started":
                thread = str(event.get("thread_id", thread))
            elif event.get("type") == "item.completed":
                item = event.get("item")
                if isinstance(item, dict) and item.get("type") == "agent_message":
                    final_text = str(item.get("text", ""))
            elif event.get("type") in {"turn.failed", "error"}:
                final_event = event
            elif event.get("type") == "turn.completed":
                final_event = event
            on_event("codex_event", event)
    except BaseException:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()
                await process.wait()
        await asyncio.gather(stderr_task, return_exceptions=True)
        raise
    return_code = await process.wait()
    stderr = (await stderr_task).decode("utf-8", errors="replace").strip()
    if return_code or not final_text:
        detail = str(final_event.get("message", "")).strip() or stderr
        raise ProviderRequestError(detail[:1200] or f"Codex CLI exited with status {return_code} without a reply.")
    return final_text, thread, final_event


def test_connection(profile: dict[str, Any]) -> str:
    account_status()
    with tempfile.TemporaryDirectory(prefix="mitsu-codex-probe-") as directory:
        session_directory = Path(directory)
        try:
            result = subprocess.run(
                [
                    codex_binary(),
                    "exec",
                    "--json",
                    "--ephemeral",
                    "--ignore-user-config",
                    "--skip-git-repo-check",
                    "--sandbox",
                    "read-only",
                    "--cd",
                    directory,
                    "--config",
                    'approval_policy="never"',
                    "--config",
                    _config_argument("developer_instructions", "Reply exactly MITSU_OK and do not use tools."),
                    *(["--model", model_argument(profile)] if model_argument(profile) else []),
                    "Reply exactly MITSU_OK.",
                ],
                cwd=directory,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ProviderRequestError("Codex CLI model verification timed out after 120 seconds.") from error
        except OSError as error:
            raise ProviderRequestError(f"Could not start Codex CLI: {error}") from error
    response = ""
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = event.get("item") if isinstance(event, dict) else None
        if event.get("type") == "item.completed" and isinstance(item, dict) and item.get("type") == "agent_message":
            response = str(item.get("text", ""))
    if result.returncode or response.strip() != "MITSU_OK":
        detail = result.stderr.strip() or response or "Codex CLI did not return the expected model response."
        raise ProviderRequestError(detail[:800])
    return "Codex CLI ChatGPT account and model reply verified."


def complete(profile: dict[str, Any], messages: list[dict[str, Any]]) -> str:
    account_status()
    prompt = _prompt(messages)
    if not prompt:
        raise ProviderRequestError("Codex CLI needs a message to respond to.")
    system_prompt = "\n\n".join(
        str(message.get("content", ""))
        for message in messages
        if message.get("role") == "system"
    ) or "You are Mitsu, a security assessment assistant."
    with tempfile.TemporaryDirectory(prefix="mitsu-codex-complete-") as directory:
        text, _, _ = asyncio.run(
            _run_exec(
                profile,
                system_prompt,
                prompt,
                Path(directory),
                lambda _kind, _event: None,
                ephemeral=True,
            )
        )
    return text


async def request_turn(
    profile: dict[str, Any],
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    dispatch: ToolDispatcher,
    thread_id: str,
    on_event: ProgressHandler,
    cancellation: Callable[[], bool] | None = None,
) -> ProviderTurn:
    account_status()
    system_prompt = next(
        (str(message.get("content", "")) for message in messages if message.get("role") == "system"),
        "You are Mitsu, a security assessment assistant.",
    )
    conversation = [message for message in messages if message.get("role") != "system"]
    if thread_id:
        conversation = next(
            ([message] for message in reversed(conversation) if message.get("role") == "user"),
            [],
        )
    prompt = _prompt(conversation)
    if not prompt:
        raise ProviderRequestError("Codex CLI needs a user message to start the turn.")
    server, _ = _mcp_server(tools, dispatch)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    token = secrets.token_urlsafe(32)
    server_task = asyncio.create_task(
        server.run_streamable_http_async(
            host="127.0.0.1",
            port=port,
            streamable_http_path=f"/{token}/mcp",
            json_response=True,
            stateless_http=True,
        )
    )
    session_directory = Path(tempfile.gettempdir()) / "mitsu-codex-sessions" / (thread_id or secrets.token_hex(16))
    session_directory.mkdir(parents=True, exist_ok=True)
    try:
        await _wait_server(port, server_task)
        text, current_thread, event = await _run_exec(
            profile,
            system_prompt,
            prompt,
            session_directory,
            on_event,
            mcp_url=f"http://127.0.0.1:{port}/{token}/mcp",
            thread_id=thread_id,
            cancellation=cancellation,
        )
    finally:
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
    return ProviderTurn(
        text,
        {"role": "assistant", "content": text},
        [],
        event.get("usage", {}) if isinstance(event.get("usage"), dict) else {},
        {"thread_id": current_thread},
    )
