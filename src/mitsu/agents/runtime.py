"""Run agent turns and maintain normalized conversation history."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from typing import Any, AsyncIterator, Awaitable, Callable

from mitsu.tools import AgentToolHost
from mitsu.providers import ProviderRequestError, ProviderTurn, RequestCancellation, request_agent_turn


@dataclass(frozen=True)
class AgentEvent:
    kind: str
    data: dict[str, Any]


ApprovalHandler = Callable[[str, dict[str, Any]], Awaitable[bool]]
HistoryHandler = Callable[[], None]
RequestTurn = Callable[
    [dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]], Awaitable[ProviderTurn]
]


async def run_agent_turn(
    profile: dict[str, Any],
    system_prompt: str,
    history: list[dict[str, Any]],
    prompt: str,
    tool_host: AgentToolHost,
    mode: str,
    approve: ApprovalHandler,
    on_history: HistoryHandler,
    max_tool_calls: int = 32,
    request_turn: RequestTurn | None = None,
) -> AsyncIterator[AgentEvent]:
    anthropic = profile.get("protocol") == "anthropic"
    history.append({"role": "user", "content": prompt})
    on_history()
    tool_calls_run = 0
    seen_calls: set[str] = set()
    for _ in range(20):
        request_messages = [{"role": "system", "content": system_prompt}, *history]
        tools = tool_host.provider_tools(mode)
        for retry_number in range(11):
            try:
                if request_turn:
                    turn = await request_turn(profile, request_messages, tools)
                else:
                    loop = asyncio.get_running_loop()
                    progress: asyncio.Queue[AgentEvent] = asyncio.Queue()
                    cancellation = RequestCancellation()

                    def report_progress(kind: str, data: dict[str, Any]) -> None:
                        try:
                            loop.call_soon_threadsafe(progress.put_nowait, AgentEvent(kind, data))
                        except RuntimeError:
                            pass

                    request_task = asyncio.create_task(
                        asyncio.to_thread(
                            request_agent_turn,
                            profile,
                            request_messages,
                            tools,
                            report_progress,
                            cancellation,
                        )
                    )
                    try:
                        while not request_task.done():
                            try:
                                event = await asyncio.wait_for(progress.get(), timeout=0.1)
                            except TimeoutError:
                                continue
                            yield event
                        turn = await request_task
                        await asyncio.sleep(0)
                        while not progress.empty():
                            yield progress.get_nowait()
                    except asyncio.CancelledError:
                        cancellation.cancel()
                        request_task.cancel()
                        raise
                break
            except ProviderRequestError as error:
                if retry_number >= 10 or not _is_transient_provider_error(error):
                    raise
                retry_attempt = retry_number + 1
                yield AgentEvent(
                    "api_retry",
                    {
                        "attempt": retry_attempt,
                        "max_attempts": 10,
                        "delay": 10,
                        "error": str(error),
                    },
                )
                await asyncio.sleep(10)
                yield AgentEvent("api_retrying", {"attempt": retry_attempt})
        if turn.usage:
            yield AgentEvent("usage", {"usage": turn.usage})
        history.append(turn.assistant_message)
        on_history()
        yield AgentEvent(
            "assistant_turn",
            {
                "text": turn.text,
                "tool_calls": len(turn.tool_calls),
                "response_info": turn.response_info,
            },
        )
        if not turn.tool_calls:
            yield AgentEvent("done", {})
            return
        anthropic_results: list[dict[str, Any]] = []
        for call_index, invocation in enumerate(turn.tool_calls):
            tool_calls_run += 1
            yield AgentEvent(
                "tool_started",
                {"name": invocation.name, "arguments": invocation.arguments},
            )
            is_read_only = tool_host.is_read_only(invocation.name)
            result = ""
            is_error = False
            try:
                fingerprint = json.dumps(
                    [invocation.name, invocation.arguments],
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                )
                if fingerprint in seen_calls:
                    result = (
                        "This exact tool call already ran during the current request. "
                        "Review its earlier result and choose a different command or next step."
                    )
                    is_error = True
                else:
                    seen_calls.add(fingerprint)
                    needs_approval = (mode == "Guided" and tool_host.requires_guided_approval(invocation.name)) or (
                        mode == "Recon"
                        and not tool_host.recon_action_is_low_impact(
                            invocation.name, invocation.arguments
                        )
                    )
                    if needs_approval:
                        allowed = await approve(invocation.name, invocation.arguments if isinstance(invocation.arguments, dict) else {})
                        if not allowed:
                            result, is_error = "The operator declined this action. Choose a lower-impact step or ask what to do differently.", True
                        else:
                            result, is_error, _ = await tool_host.call(invocation.name, invocation.arguments)
                    else:
                        result, is_error, _ = await tool_host.call(invocation.name, invocation.arguments)
            except asyncio.CancelledError:
                result = "The operator interrupted this tool call. Do not retry it unless asked."
                is_error = True
                if anthropic:
                    anthropic_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": invocation.id,
                            "content": result,
                            "is_error": True,
                        }
                    )
                    for remaining in turn.tool_calls[call_index + 1 :]:
                        anthropic_results.append(
                            {
                                "type": "tool_result",
                                "tool_use_id": remaining.id,
                                "content": result,
                                "is_error": True,
                            }
                        )
                    history.append({"role": "user", "content": anthropic_results})
                else:
                    history.append(
                        {"role": "tool", "tool_call_id": invocation.id, "content": result}
                    )
                    for remaining in turn.tool_calls[call_index + 1 :]:
                        history.append(
                            {"role": "tool", "tool_call_id": remaining.id, "content": result}
                        )
                on_history()
                raise
            if anthropic:
                anthropic_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": invocation.id,
                        "content": result,
                        "is_error": is_error,
                    }
                )
                on_history()
            else:
                history.append(
                    {
                        "role": "tool",
                        "tool_call_id": invocation.id,
                        "content": result,
                    }
                )
                on_history()
            yield AgentEvent(
                "tool_finished",
                {"name": invocation.name, "result": result, "is_error": is_error},
            )
            if tool_calls_run >= max_tool_calls:
                for remaining in turn.tool_calls[call_index + 1 :]:
                    notice = f"Tool loop stopped after {max_tool_calls} calls to keep the session responsive."
                    if anthropic:
                        anthropic_results.append(
                            {
                                "type": "tool_result",
                                "tool_use_id": remaining.id,
                                "content": notice,
                                "is_error": True,
                            }
                        )
                    else:
                        history.append(
                            {"role": "tool", "tool_call_id": remaining.id, "content": notice}
                        )
                if anthropic_results:
                    history.append({"role": "user", "content": anthropic_results})
                on_history()
                yield AgentEvent("limit", {"message": f"Tool loop stopped after {max_tool_calls} calls."})
                return
        if anthropic_results:
            history.append({"role": "user", "content": anthropic_results})
            on_history()
    yield AgentEvent("limit", {"message": "Tool loop stopped after 20 model turns."})


def history_from_legacy(entries: list[Any]) -> list[dict[str, Any]]:
    history: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("role") not in {"user", "assistant"}:
            continue
        content = str(entry.get("content", ""))
        if not content:
            continue
        if entry.get("role") == "user" and content.lstrip().startswith("/"):
            continue
        if history and history[-1].get("role") == entry["role"]:
            history[-1]["content"] += "\n\n" + content
        else:
            history.append({"role": entry["role"], "content": content})
    while history and history[0].get("role") == "assistant":
        history.pop(0)
    if len(history) > 40:
        history = history[-40:]
        if history and history[0].get("role") == "assistant":
            history.pop(0)
    return history


def _is_transient_provider_error(error: ProviderRequestError) -> bool:
    message = str(error).casefold()
    if "provider request failed (429)" in message:
        return True
    for status in range(500, 600):
        if f"provider request failed ({status})" in message:
            return True
    return any(
        marker in message
        for marker in (
            "could not reach the provider",
            "provider stream ended unexpectedly",
            "provider returned an unreadable streamed response",
        )
    )
