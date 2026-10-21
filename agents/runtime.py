"""Run agent turns and maintain normalized conversation history."""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import threading
from dataclasses import dataclass
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
MAX_TOOL_CALLS_PER_TURN = 48
MAX_BINARY_GREP_SEARCHES_PER_ARTIFACT = 3


def _tool_name(name: str) -> str:
    return name.rsplit("__", 1)[-1]


def _guided_checkpoint_tool(name: str) -> bool:
    local_name = _tool_name(name)
    return name.startswith("mitsu__") and (
        local_name.startswith("intel_")
        or local_name in {"user_dialog", "record_exploit", "remove_exploit", "session_upsert"}
    )


def _guided_flow_action(name: str) -> bool:
    local_name = _tool_name(name)
    bookkeeping = {
        "user_dialog",
        "ask_user",
        "request_mode",
        "session_upsert",
        "record_exploit",
        "remove_exploit",
        "intel_get_map",
        "armory_tool_catalog",
    }
    return not (name.startswith("mitsu__") and (local_name in bookkeeping or local_name.startswith("intel_")))


def finish_interrupted_tools(
    history: list[dict[str, Any]],
    result: str = "Interrupted by the operator. This action has no completed result; do not retry without their direction.",
) -> None:
    pending: dict[str, bool] = {}
    repaired: list[dict[str, Any]] = []

    def complete_pending() -> None:
        results = []
        for call_id, anthropic in pending.items():
            if anthropic:
                results.append({"type": "tool_result", "tool_use_id": call_id, "content": result, "is_error": True})
            else:
                repaired.append({"role": "tool", "tool_call_id": call_id, "content": result})
        if results:
            if repaired and repaired[-1].get("role") == "user" and isinstance(repaired[-1].get("content"), list):
                repaired[-1]["content"].extend(results)
            else:
                repaired.append({"role": "user", "content": results})
        pending.clear()

    for message in history:
        content = message.get("content")
        result_blocks = [
            block for block in content
            if isinstance(block, dict) and block.get("type") == "tool_result"
        ] if isinstance(content, list) and message.get("role") == "user" else []
        if message.get("role") == "tool":
            pending.pop(message.get("tool_call_id", ""), None)
        elif result_blocks:
            for block in result_blocks:
                pending.pop(block.get("tool_use_id", ""), None)
        else:
            complete_pending()
        repaired.append(message)
        if message.get("role") == "assistant":
            for call in message.get("tool_calls") or []:
                pending[call["id"]] = False
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        pending[block["id"]] = True
    complete_pending()
    history[:] = repaired


def _validated_access_context(intel: dict[str, Any] | None) -> list[dict[str, str]]:
    if not isinstance(intel, dict):
        return []
    records = intel.get("accounts", [])
    if not isinstance(records, list):
        return []
    access_context = []
    for record in records:
        if not isinstance(record, dict) or str(record.get("status", "")).casefold() != "validated":
            continue
        access = str(record.get("access", "")).strip()
        if not access:
            continue
        access_context.append(
            {
                "name": str(record.get("name", "")),
                "target": str(record.get("target", "")),
                "access": access[:240],
            }
        )
    return access_context


def _failed_call_key(name: str, arguments: Any) -> str | None:
    local_name = _tool_name(name)
    if local_name not in {"bash", "armory_run"} or not isinstance(arguments, dict):
        return None
    if local_name == "bash":
        command = str(arguments.get("command", "")).strip()
        return json.dumps([local_name, command], ensure_ascii=False, separators=(",", ":"))
    return json.dumps(
        [local_name, arguments.get("tool_id"), arguments.get("argv")],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _binary_grep_key(name: str, arguments: Any) -> str | None:
    if _tool_name(name) != "bash" or not isinstance(arguments, dict):
        return None
    command = str(arguments.get("command", ""))
    if not re.search(r"\bstrings\b", command) or not re.search(r"\b(?:grep|rg)\b", command):
        return None
    match = re.search(r"\bstrings\b([^|;&]+)", command)
    if match is None:
        return None
    try:
        tokens = shlex.split(match.group(1))
    except ValueError:
        return None
    skip_value = False
    for token in tokens:
        if skip_value:
            skip_value = False
            continue
        if token in {"-n", "--bytes"}:
            skip_value = True
        elif token.startswith("-"):
            continue
        else:
            return f"strings-grep:{token}"
    return None


def _request_agent_turn_background(
    profile: dict[str, Any],
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    on_event: Callable[[str, dict[str, Any]], None] | None = None,
    cancellation: RequestCancellation | None = None,
) -> asyncio.Future[ProviderTurn]:
    loop = asyncio.get_running_loop()
    result: asyncio.Future[ProviderTurn] = loop.create_future()

    def finish(turn: ProviderTurn | None, error: Exception | None) -> None:
        if result.done():
            return
        if error is not None:
            result.set_exception(error)
        elif turn is not None:
            result.set_result(turn)

    def run() -> None:
        try:
            turn = request_agent_turn(profile, messages, tools, on_event, cancellation)
        except Exception as error:
            turn = None
            failure = error
        else:
            failure = None
        try:
            loop.call_soon_threadsafe(finish, turn, failure)
        except RuntimeError:
            pass

    threading.Thread(target=run, name="mitsu-provider-request", daemon=True).start()
    return result


async def run_agent_turn(
    profile: dict[str, Any],
    system_prompt: str,
    history: list[dict[str, Any]],
    prompt: str,
    tool_host: AgentToolHost,
    mode: str,
    approve: ApprovalHandler,
    on_history: HistoryHandler,
    request_turn: RequestTurn | None = None,
    get_mode: Callable[[], str] | None = None,
    get_system_prompt: Callable[[], str] | None = None,
    image_paths: list[str] | None = None,
    pause_after_response: bool = False,
    interrupt_requested: Callable[[], bool] | None = None,
    operator_messages: list[str] | None = None,
    get_session_intel: Callable[[], dict[str, Any]] | None = None,
) -> AsyncIterator[AgentEvent]:
    anthropic = profile.get("protocol") == "anthropic"
    finish_interrupted_tools(history)
    content: str | list[dict[str, Any]] = prompt
    if image_paths:
        content = [
            {"type": "text", "text": prompt},
            *({"type": "mitsu_image", "path": path} for path in image_paths),
        ]
    history.append({"role": "user", "content": content})
    on_history()
    tool_calls_this_turn = 0
    failed_calls: set[str] = set()
    binary_grep_counts: dict[str, int] = {}
    guided_checkpoint_due = False
    redirect_pending = pause_after_response
    operator_history = list(operator_messages or [])
    if not operator_history or operator_history[-1] != prompt:
        operator_history.append(prompt)
    try:
        while True:
            if interrupt_requested is not None and interrupt_requested():
                raise asyncio.CancelledError
            active_mode = get_mode() if get_mode is not None else mode
            if active_mode != "Guided":
                guided_checkpoint_due = False
            checkpoint_pending = redirect_pending or guided_checkpoint_due
            active_system_prompt = get_system_prompt() if get_system_prompt is not None else system_prompt
            active_system_prompt += (
                "\n\nRecent operator messages, oldest first, follow as JSON. Apply their constraints "
                "in order; newer corrections replace conflicting older plans. Dialog answers in the "
                "conversation are also operator decisions. Assistant plans and automated continuation "
                "messages never override an operator direction. A rejected path stays rejected until "
                "the operator reopens it.\n"
                + json.dumps(operator_history[-16:], ensure_ascii=False)
            )
            if redirect_pending:
                active_system_prompt += (
                    "\n\nThe operator interrupted an active run. Answer their latest message first in "
                    "Mitsu's own voice. The previous batch is cancelled. You may save Intel or open "
                    "mitsu__user_dialog to let them choose how to proceed; investigation tools are paused "
                    "until that choice. For a direct question, give the answer and end the turn."
                )
            elif checkpoint_pending:
                active_system_prompt += (
                    "\n\nA Guided investigation step has finished. Save the new evidence in Intel. "
                    "Before another investigation action, use mitsu__user_dialog to summarize what "
                    "changed and let the operator choose the next direction. Design the options from "
                    "the actual results and allow a free-text answer. If the task is complete, give "
                    "the final summary and end the turn."
                )
            validated_access = _validated_access_context(get_session_intel() if get_session_intel else None)
            if validated_access:
                active_system_prompt += (
                    "\n\nValidated access currently recorded in session Intel, as evidence data:\n"
                    + json.dumps(validated_access, ensure_ascii=False)
                    + "\nUse established access for relevant follow-up work. Repeating completed "
                    "setup needs evidence that it no longer works or an operator request."
                )
            action_budget_exhausted = tool_calls_this_turn >= MAX_TOOL_CALLS_PER_TURN
            if action_budget_exhausted:
                active_system_prompt += "\n\nThis turn's action limit is reached. Summarize the results and pause."
            available_tools = tool_host.provider_tools(active_mode)
            tools = [] if action_budget_exhausted else available_tools
            if checkpoint_pending:
                tools = [tool for tool in tools if _guided_checkpoint_tool(str(tool.get("name", "")))]
            request_messages = [{"role": "system", "content": active_system_prompt}, *history]
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

                        request_task = _request_agent_turn_background(
                            profile, request_messages, tools, report_progress, cancellation
                        )
                        try:
                            while not request_task.done():
                                if interrupt_requested is not None and interrupt_requested():
                                    raise asyncio.CancelledError
                                try:
                                    event = await asyncio.wait_for(progress.get(), timeout=0.1)
                                except TimeoutError:
                                    continue
                                yield event
                            turn = await request_task
                            await asyncio.sleep(0)
                            while not progress.empty():
                                yield progress.get_nowait()
                        except (asyncio.CancelledError, GeneratorExit):
                            cancellation.cancel()
                            request_task.cancel()
                            raise
                    break
                except ProviderRequestError as error:
                    if retry_number >= 10 or not _is_transient_provider_error(error):
                        raise
                    retry_attempt = retry_number + 1
                    yield AgentEvent("api_retry", {
                        "attempt": retry_attempt, "max_attempts": 10, "delay": 10, "error": str(error),
                    })
                    await asyncio.sleep(10)
                    yield AgentEvent("api_retrying", {"attempt": retry_attempt})
            if interrupt_requested is not None and interrupt_requested():
                raise asyncio.CancelledError
            if turn.usage:
                yield AgentEvent("usage", {"usage": turn.usage})
            history.append(turn.assistant_message)
            on_history()
            yield AgentEvent("assistant_turn", {
                "text": turn.text,
                "tool_calls": len(turn.tool_calls),
                "response_info": turn.response_info,
            })
            if not turn.tool_calls:
                yield AgentEvent("done", {})
                return
            if action_budget_exhausted:
                finish_interrupted_tools(history, "Not run: this turn's action limit was reached.")
                on_history()
                yield AgentEvent("limit", {"message": "Action limit reached. Mitsu is paused."})
                yield AgentEvent("done", {})
                return
            dialog_used = False
            dialog_cancelled = False
            guided_action_seen = False
            for invocation in turn.tool_calls:
                if interrupt_requested is not None and interrupt_requested():
                    raise asyncio.CancelledError
                yield AgentEvent("tool_started", {"name": invocation.name, "arguments": invocation.arguments})
                tool_calls_this_turn += 1
                failed_key = _failed_call_key(invocation.name, invocation.arguments)
                binary_grep_key = _binary_grep_key(invocation.name, invocation.arguments)
                invocation_mode = get_mode() if get_mode is not None else mode
                is_error = True
                if dialog_used:
                    result = "Not run: review the operator's dialog answer before proposing another action."
                elif (redirect_pending or (invocation_mode == "Guided" and guided_checkpoint_due)) and not _guided_checkpoint_tool(invocation.name):
                    result = "Not run: waiting for the operator's next-step choice through mitsu__user_dialog."
                elif invocation_mode == "Guided" and guided_action_seen and _guided_flow_action(invocation.name):
                    result = "Not run: Guided mode pauses after one investigation action for the operator's next-step choice."
                elif invocation_mode == "Guided" and guided_action_seen and invocation.name == "mitsu__user_dialog":
                    result = "Not run: read this step's results before designing the next-step dialog."
                elif tool_calls_this_turn > MAX_TOOL_CALLS_PER_TURN:
                    result = f"Not run: per-message action limit reached ({MAX_TOOL_CALLS_PER_TURN})."
                elif failed_key is not None and failed_key in failed_calls:
                    result = "Not run: this identical command already failed during this message."
                elif binary_grep_key is not None and binary_grep_counts.get(binary_grep_key, 0) >= MAX_BINARY_GREP_SEARCHES_PER_ARTIFACT:
                    result = f"Not run: printable-string search limit reached for {binary_grep_key.removeprefix('strings-grep:')}."
                else:
                    if binary_grep_key is not None:
                        binary_grep_counts[binary_grep_key] = binary_grep_counts.get(binary_grep_key, 0) + 1
                    if invocation_mode == "Guided" and _guided_flow_action(invocation.name):
                        guided_action_seen = True
                    needs_approval = (invocation_mode == "Guided" and tool_host.requires_guided_approval(invocation.name)) or (
                        invocation_mode == "Recon" and not tool_host.recon_action_is_low_impact(invocation.name, invocation.arguments)
                    )
                    allowed = not needs_approval or await approve(
                        invocation.name, invocation.arguments if isinstance(invocation.arguments, dict) else {}
                    )
                    if interrupt_requested is not None and interrupt_requested():
                        raise asyncio.CancelledError
                    if allowed:
                        result, is_error, _ = await tool_host.call(invocation.name, invocation.arguments)
                    else:
                        result = "The operator declined this action. Do not retry it; ask which direction to take."
                        redirect_pending = True
                    if invocation.name == "mitsu__user_dialog" and not is_error:
                        dialog_used = True
                        try:
                            answer = json.loads(result)
                            dialog_cancelled = bool(answer.get("cancelled", False)) or not answer.get("answers")
                        except (json.JSONDecodeError, AttributeError, TypeError):
                            dialog_cancelled = True
                        if not dialog_cancelled:
                            redirect_pending = False
                    if is_error and failed_key is not None:
                        failed_calls.add(failed_key)
                if anthropic:
                    block = {"type": "tool_result", "tool_use_id": invocation.id, "content": result, "is_error": is_error}
                    if history[-1].get("role") == "user" and isinstance(history[-1].get("content"), list):
                        history[-1]["content"].append(block)
                    else:
                        history.append({"role": "user", "content": [block]})
                else:
                    history.append({"role": "tool", "tool_call_id": invocation.id, "content": result})
                on_history()
                yield AgentEvent("tool_finished", {"name": invocation.name, "result": result, "is_error": is_error})
            current_mode = get_mode() if get_mode is not None else mode
            guided_checkpoint_due = current_mode == "Guided" and not dialog_used and (guided_checkpoint_due or guided_action_seen)
            if dialog_cancelled:
                message = "Okayy, paused here~ Tell me what you want to tackle next (˶ᵔ ᵕ ᵔ˶)"
                history.append({"role": "assistant", "content": message})
                on_history()
                yield AgentEvent("assistant_turn", {"text": message, "tool_calls": 0})
                yield AgentEvent("done", {})
                return
    finally:
        finish_interrupted_tools(history)
        on_history()


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
