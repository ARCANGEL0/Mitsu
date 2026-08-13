"""HTTP clients for supported language model providers."""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from typing import Any, Callable


class ProviderRequestError(Exception):
    pass


@dataclass(frozen=True)
class ToolInvocation:
    id: str
    name: str
    arguments: Any


@dataclass(frozen=True)
class ProviderTurn:
    text: str
    assistant_message: dict[str, Any]
    tool_calls: list[ToolInvocation]
    usage: dict[str, Any] = field(default_factory=dict)
    response_info: dict[str, Any] = field(default_factory=dict)


StreamCallback = Callable[[str, dict[str, Any]], None]


class RequestCancellation:
    """Close an in-flight streamed response when the operator interrupts it."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._response: Any = None

    def cancelled(self) -> bool:
        return self._event.is_set()

    def attach(self, response: Any) -> None:
        with self._lock:
            if self._event.is_set():
                response.close()
            else:
                self._response = response

    def detach(self, response: Any) -> None:
        with self._lock:
            if self._response is response:
                self._response = None

    def cancel(self) -> None:
        self._event.set()
        with self._lock:
            response = self._response
            self._response = None
        if response is not None:
            response.close()


def request_agent_turn(
    profile: dict[str, Any],
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    on_event: StreamCallback | None = None,
    cancellation: RequestCancellation | None = None,
) -> ProviderTurn:
    protocol = profile.get("protocol", "openai")
    base_url = str(profile.get("base_url", "")).rstrip("/")
    model = str(profile.get("model", ""))
    api_key = str(profile.get("api_key", ""))
    if not base_url or not model:
        raise ProviderRequestError("Provider setup is incomplete. Reopen provider setup from the main menu.")
    try:
        if protocol == "anthropic":
            return _request_anthropic_turn(
                base_url, model, api_key, messages, tools, on_event, cancellation
            )
        return _request_openai_turn(
            base_url,
            model,
            api_key,
            messages,
            tools,
            str(profile.get("reasoning_parameter", "")) if profile.get("reasoning_enabled") else "",
            str(profile.get("reasoning_effort", "medium")),
            on_event,
            cancellation,
        )
    except ProviderRequestError as error:
        message = _hide_secret(str(error), api_key)
        raise ProviderRequestError(message) from error


def _request_openai_turn(
    base_url: str,
    model: str,
    api_key: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    reasoning_parameter: str,
    reasoning_effort: str,
    on_event: StreamCallback | None = None,
    cancellation: RequestCancellation | None = None,
) -> ProviderTurn:
    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": tool["parameters"],
                },
            }
            for tool in tools
        ],
        "stream": False,
    }
    if reasoning_parameter == "reasoning_effort":
        payload["reasoning_effort"] = reasoning_effort
    elif reasoning_parameter == "reasoning":
        payload["reasoning"] = {"effort": reasoning_effort}
    if on_event is not None:
        streamed = _request_openai_stream(endpoint, headers, payload, on_event, cancellation)
        if streamed is not None:
            return streamed
    if cancellation is not None and cancellation.cancelled():
        return ProviderTurn("", {"role": "assistant", "content": ""}, [])
    response = _request_json(endpoint, headers, payload, cancellation)
    return _openai_turn_from_response(response, on_event)


def _openai_turn_from_response(response: dict[str, Any], on_event: StreamCallback | None = None) -> ProviderTurn:
    try:
        choice = response["choices"][0]
        message = choice["message"]
    except (KeyError, IndexError, TypeError) as error:
        raise ProviderRequestError("The provider returned a response Mitsu could not read.") from error
    if not isinstance(message, dict):
        raise ProviderRequestError("The provider returned an unexpected assistant message.")
    raw_calls = message.get("tool_calls") or []
    if not raw_calls and isinstance(message.get("function_call"), dict):
        raw_calls = [{"type": "function", "function": message["function_call"]}]
    calls: list[ToolInvocation] = []
    normalized_calls: list[dict[str, Any]] = []
    for raw in raw_calls:
        if not isinstance(raw, dict):
            raise ProviderRequestError("The provider returned a malformed tool call.")
        function = raw.get("function")
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            raise ProviderRequestError("The provider returned a malformed tool call.")
        raw_arguments = function.get("arguments", "{}")
        try:
            arguments = json.loads(raw_arguments) if isinstance(raw_arguments, str) else raw_arguments
        except json.JSONDecodeError:
            arguments = raw_arguments
        call_id = str(raw.get("id") or f"call_{uuid.uuid4().hex}")
        calls.append(ToolInvocation(call_id, function["name"], arguments))
        normalized_function = dict(function)
        if not isinstance(raw_arguments, str):
            normalized_function["arguments"] = json.dumps(raw_arguments, ensure_ascii=False, default=str)
        normalized_call = {**raw, "id": call_id, "type": "function", "function": normalized_function}
        normalized_calls.append(normalized_call)
    assistant_message = {
        "role": "assistant",
        "content": message.get("content"),
    }
    if raw_calls:
        assistant_message["tool_calls"] = normalized_calls
    content = message.get("content")
    text = _openai_content_text(content)
    refusal = message.get("refusal")
    if not text and isinstance(refusal, str):
        text = refusal
        assistant_message["content"] = refusal
    if not raw_calls and not text:
        # Keep the conversation role sequence valid if a compatible server
        # sends a genuinely empty completion.
        assistant_message["content"] = ""
    if text and on_event is not None:
        on_event("delta", {"text": text})
    usage = response.get("usage")
    response_info = _openai_response_info(response, choice, message)
    return ProviderTurn(
        text,
        assistant_message,
        calls,
        usage if isinstance(usage, dict) else {},
        response_info,
    )


def _openai_content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            str(block.get("text", block.get("content", "")))
            for block in content
            if isinstance(block, dict) and block.get("type") in {"text", "output_text", None}
        )
    return ""


def _openai_response_info(
    response: dict[str, Any], choice: dict[str, Any], message: dict[str, Any]
) -> dict[str, Any]:
    info: dict[str, Any] = {}
    finish_reason = choice.get("finish_reason")
    if isinstance(finish_reason, str) and finish_reason:
        info["finish_reason"] = finish_reason
    model = response.get("model")
    if isinstance(model, str) and model:
        info["model"] = model
    reasoning = message.get("reasoning_content", message.get("reasoning"))
    if reasoning and not _openai_content_text(message.get("content")):
        # Record only the fact that reasoning was present; never expose its text.
        info["reasoning_only"] = True
    return info
