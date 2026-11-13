"""HTTP clients for supported language model providers."""

from __future__ import annotations

import base64
import json
import mimetypes
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
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


class _ReplyFilter:
    def __init__(self) -> None:
        self.inside_think = False
        self.pending = ""

    def feed(self, text: str) -> str:
        text = self.pending + text
        self.pending = ""
        visible: list[str] = []
        while text:
            closing = "</think>"
            opening = "<think>"
            lowered = text.lower()
            if self.inside_think:
                index = lowered.find(closing)
                markers = (closing,)
            else:
                opening_index = lowered.find(opening)
                closing_index = lowered.find(closing)
                if opening_index < 0:
                    index = closing_index
                    markers = (closing, opening)
                elif closing_index < 0 or opening_index < closing_index:
                    index = opening_index
                    markers = (opening, closing)
                else:
                    index = closing_index
                    markers = (closing, opening)
            if index >= 0:
                if not self.inside_think:
                    visible.append(text[:index])
                marker = next(marker for marker in markers if lowered.startswith(marker, index))
                if marker == opening:
                    self.inside_think = True
                text = text[index + len(marker):]
                if marker == closing:
                    self.inside_think = False
                continue
            marker = closing if self.inside_think else opening
            keep = 0
            for size in range(1, min(len(marker), len(text) + 1)):
                if text.lower().endswith(marker[:size]):
                    keep = size
            split = len(text) - keep
            if not self.inside_think:
                visible.append(text[:split])
            self.pending = text[split:]
            break
        return "".join(visible)

    def finish(self) -> str:
        pending = self.pending
        self.pending = ""
        return pending if not self.inside_think else ""


def _visible_reply(text: str) -> str:
    reply_filter = _ReplyFilter()
    return reply_filter.feed(text) + reply_filter.finish()


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
    if not model or (not base_url and protocol != "litellm"):
        raise ProviderRequestError("Provider setup is incomplete. Reopen provider setup from the main menu.")
    try:
        if protocol == "litellm":
            return _request_litellm_turn(profile, messages, tools, on_event, cancellation)
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
            str(profile.get("reasoning_parameter", "")),
            str(profile.get("reasoning_effort", "medium")),
            profile.get("reasoning_enabled") is True,
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
    reasoning_enabled: bool,
    on_event: StreamCallback | None = None,
    cancellation: RequestCancellation | None = None,
) -> ProviderTurn:
    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload: dict[str, Any] = {
        "model": model,
        "messages": _openai_messages(messages),
        "tools": _openai_tools(tools),
        "stream": False,
    }
    if reasoning_parameter == "reasoning_effort" and reasoning_enabled:
        payload["reasoning_effort"] = reasoning_effort
    elif reasoning_parameter == "reasoning" and reasoning_enabled:
        payload["reasoning"] = {"effort": reasoning_effort}
    elif reasoning_parameter == "nvidia_chat_template":
        template_options = {"enable_thinking": reasoning_enabled}
        if reasoning_enabled and tools:
            template_options["force_nonempty_content"] = True
        if reasoning_enabled and reasoning_effort == "medium":
            template_options["medium_effort"] = True
        payload["chat_template_kwargs"] = template_options
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
    content, text = _clean_openai_content(message.get("content"))
    assistant_message = {"role": "assistant", "content": content}
    if raw_calls:
        assistant_message["tool_calls"] = normalized_calls
    refusal = message.get("refusal")
    if not text and isinstance(refusal, str):
        text = _visible_reply(refusal)
        assistant_message["content"] = text
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


def _clean_openai_content(content: Any) -> tuple[Any, str]:
    if isinstance(content, str):
        visible = _visible_reply(content)
        return visible, visible
    if not isinstance(content, list):
        return content, ""
    reply_filter = _ReplyFilter()
    cleaned = []
    last_text: tuple[dict[str, Any], str] | None = None
    for block in content:
        if not isinstance(block, dict) or block.get("type") not in {"text", "output_text", None}:
            cleaned.append(block)
            continue
        field = "text" if isinstance(block.get("text"), str) else "content"
        value = block.get(field)
        if not isinstance(value, str):
            cleaned.append(block)
            continue
        item = dict(block)
        item[field] = reply_filter.feed(value)
        cleaned.append(item)
        last_text = item, field
    tail = reply_filter.finish()
    if tail and last_text is not None:
        item, field = last_text
        item[field] += tail
    return cleaned, _openai_content_text(cleaned)


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


def _request_openai_stream(
    endpoint: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    on_event: StreamCallback,
    cancellation: RequestCancellation | None,
    include_usage: bool = True,
) -> ProviderTurn | None:
    streamed_payload = {**payload, "stream": True}
    if include_usage:
        streamed_payload["stream_options"] = {"include_usage": True}
    request = Request(
        endpoint,
        data=json.dumps(streamed_payload).encode("utf-8"),
        headers={**headers, "Accept": "text/event-stream"},
        method="POST",
    )
    try:
        response = urlopen(request, timeout=120)
    except HTTPError as error:
        message = _http_error_message(error)
        normalized = message.casefold()
        if include_usage and error.code in {400, 422, 501} and "stream_options" in normalized:
            return _request_openai_stream(
                endpoint, headers, payload, on_event, cancellation, include_usage=False
            )
        if error.code in {400, 422, 501} and ("stream" in normalized or "unsupported" in normalized):
            return None
        raise ProviderRequestError(f"Provider request failed ({error.code}): {message}") from error
    except (URLError, TimeoutError, OSError) as error:
        if cancellation is not None and cancellation.cancelled():
            return ProviderTurn("", {"role": "assistant", "content": ""}, [])
        raise ProviderRequestError(f"Could not reach the provider: {error}") from error

    if cancellation is not None:
        cancellation.attach(response)
    content_type = response.headers.get_content_type()
    if content_type in {"application/json", "application/problem+json"} or content_type.endswith("+json"):
        try:
            decoded = json.loads(response.read().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            if cancellation is not None:
                cancellation.detach(response)
            response.close()
            raise ProviderRequestError("The provider returned an unreadable streamed response.") from error
        finally:
            if cancellation is not None:
                cancellation.detach(response)
            response.close()
        if not isinstance(decoded, dict):
            raise ProviderRequestError("The provider returned an unexpected response.")
        return _openai_turn_from_response(decoded, on_event)
    return _read_openai_stream(response, on_event, cancellation)


def _read_openai_stream(
    response: Any,
    on_event: StreamCallback,
    cancellation: RequestCancellation | None,
) -> ProviderTurn | None:
    """Assemble a turn from Chat Completions stream lines (``data: {chunk}``), emitting text deltas as they arrive."""
    text_parts: list[str] = []
    reply_filter = _ReplyFilter()
    tool_calls: dict[int, dict[str, Any]] = {}
    legacy_function_call: dict[str, str] = {"name": "", "arguments": ""}
    usage: dict[str, Any] = {}
    response_info: dict[str, Any] = {}
    saw_choice = False
    try:
        for raw_line in response:
            if cancellation is not None and cancellation.cancelled():
                break
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or line.startswith(":") or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            if not isinstance(chunk, dict):
                continue
            response_id = chunk.get("id")
            if isinstance(response_id, str) and response_id:
                response_info["response_id"] = response_id
            response_model = chunk.get("model")
            if isinstance(response_model, str) and response_model:
                response_info["model"] = response_model
            chunk_usage = chunk.get("usage")
            if isinstance(chunk_usage, dict):
                usage.update(chunk_usage)
            choices = chunk.get("choices")
            if not isinstance(choices, list) or not choices:
                continue
            choice = choices[0]
            if not isinstance(choice, dict):
                continue
            saw_choice = True
            finish_reason = choice.get("finish_reason")
            if isinstance(finish_reason, str) and finish_reason:
                response_info["finish_reason"] = finish_reason
            delta = choice.get("delta")
            if not isinstance(delta, dict) and isinstance(choice.get("message"), dict):
                delta = choice["message"]
            if not isinstance(delta, dict):
                completion_text = choice.get("text")
                if isinstance(completion_text, str) and completion_text:
                    visible = reply_filter.feed(completion_text)
                    if visible:
                        text_parts.append(visible)
                        on_event("delta", {"text": visible})
                continue
            content = delta.get("content")
            content_text = _openai_content_text(content)
            if not content_text and isinstance(delta.get("refusal"), str):
                content_text = delta["refusal"]
            if content_text:
                visible = reply_filter.feed(content_text)
                if visible:
                    text_parts.append(visible)
                    on_event("delta", {"text": visible})
            chunks = delta.get("tool_calls")
            if not isinstance(chunks, list):
                chunks = []
            for call in chunks:
                if not isinstance(call, dict):
                    continue
                try:
                    index = int(call.get("index", 0))
                except (TypeError, ValueError):
                    continue
                current = tool_calls.setdefault(
                    index,
                    {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
                )
                if call.get("id"):
                    current["id"] = str(call["id"])
                function = call.get("function")
                if isinstance(function, dict):
                    if isinstance(function.get("name"), str):
                        current["function"]["name"] += function["name"]
                    if isinstance(function.get("arguments"), str):
                        current["function"]["arguments"] += function["arguments"]
                    elif isinstance(function.get("arguments"), (dict, list)):
                        current["function"]["arguments"] += json.dumps(
                            function["arguments"], ensure_ascii=False
                        )
            legacy = delta.get("function_call")
            if isinstance(legacy, dict):
                if isinstance(legacy.get("name"), str):
                    legacy_function_call["name"] += legacy["name"]
                if isinstance(legacy.get("arguments"), str):
                    legacy_function_call["arguments"] += legacy["arguments"]
            reasoning = delta.get("reasoning_content", delta.get("reasoning"))
            if reasoning and not content_text:
                response_info["reasoning_only"] = True
        if cancellation is not None and cancellation.cancelled():
            return ProviderTurn("", {"role": "assistant", "content": ""}, [], usage)
    except (OSError, TimeoutError) as error:
        if cancellation is not None and cancellation.cancelled():
            return ProviderTurn("", {"role": "assistant", "content": ""}, [], usage)
        raise ProviderRequestError(f"Provider stream ended unexpectedly: {error}") from error
    finally:
        if cancellation is not None:
            cancellation.detach(response)
        response.close()

    if not saw_choice:
        # Some OpenAI-compatible gateways label a non-SSE response as an event
        # stream, or return an SSE envelope this parser cannot recognize. Let
        # the caller retry once using the ordinary JSON response path.
        return None

    if legacy_function_call["name"]:
        raw = {
            "id": f"call_{uuid.uuid4().hex}",
            "type": "function",
            "function": {
                "name": legacy_function_call["name"],
                "arguments": legacy_function_call["arguments"] or "{}",
            },
        }
        tool_calls.setdefault(-1, raw)

    normalized_calls: list[dict[str, Any]] = []
    invocations: list[ToolInvocation] = []
    for _index, raw in sorted(tool_calls.items()):
        name = raw["function"]["name"]
        if not name:
            raise ProviderRequestError("The provider returned a malformed streamed tool call.")
        call_id = raw["id"] or f"call_{uuid.uuid4().hex}"
        arguments_text = raw["function"]["arguments"] or "{}"
        try:
            arguments = json.loads(arguments_text)
        except json.JSONDecodeError:
            arguments = arguments_text
        raw["id"] = call_id
        normalized_calls.append(raw)
        invocations.append(ToolInvocation(call_id, name, arguments))
    tail = reply_filter.finish()
    if tail:
        text_parts.append(tail)
        on_event("delta", {"text": tail})
    content = "".join(text_parts)
    assistant_message: dict[str, Any] = {"role": "assistant", "content": content or ""}
    if normalized_calls:
        assistant_message["tool_calls"] = normalized_calls
    if not content and not invocations:
        response_info.setdefault("empty", True)
    return ProviderTurn(content, assistant_message, invocations, usage, response_info)


def _request_anthropic_turn(
    base_url: str,
    model: str,
    api_key: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    on_event: StreamCallback | None = None,
    cancellation: RequestCancellation | None = None,
) -> ProviderTurn:
    endpoint = f"{base_url}/messages" if base_url.endswith("/v1") else f"{base_url}/v1/messages"
    headers = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
    if api_key:
        headers["x-api-key"] = api_key
    system_messages = [str(message["content"]) for message in messages if message.get("role") == "system"]
    conversation = [
        _anthropic_message(message)
        for message in messages
        if message.get("role") != "system"
    ]
    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": 8192,
        "messages": conversation,
        "tools": [
            {
                "name": tool["name"],
                "description": tool["description"],
                "input_schema": tool["parameters"],
            }
            for tool in tools
        ],
    }
    if system_messages:
        payload["system"] = "\n\n".join(system_messages)
    if on_event is not None:
        streamed = _request_anthropic_stream(endpoint, headers, payload, on_event, cancellation)
        if streamed is not None:
            return streamed
    if cancellation is not None and cancellation.cancelled():
        return ProviderTurn("", {"role": "assistant", "content": []}, [])
    response = _request_json(endpoint, headers, payload, cancellation)
    return _anthropic_turn_from_response(response, on_event)


def _anthropic_turn_from_response(
    response: dict[str, Any], on_event: StreamCallback | None = None
) -> ProviderTurn:
    raw_content = response.get("content")
    if not isinstance(raw_content, list):
        raise ProviderRequestError("The provider returned a response Mitsu could not read.")
    calls = []
    normalized_content = []
    for block in raw_content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            normalized_content.append(block)
            continue
        name = block.get("name")
        if not isinstance(name, str) or not name:
            raise ProviderRequestError("The provider returned a malformed tool call.")
        call_id = str(block.get("id") or f"toolu_{uuid.uuid4().hex}")
        calls.append(ToolInvocation(call_id, name, block.get("input", {})))
        normalized_content.append({**block, "id": call_id})
    normalized_content = _clean_anthropic_content(normalized_content)
    text = "\n".join(
        str(block.get("text", ""))
        for block in normalized_content
        if isinstance(block, dict) and block.get("type") == "text"
    )
    if text and on_event is not None:
        on_event("delta", {"text": text})
    usage = response.get("usage")
    return ProviderTurn(
        text,
        {"role": "assistant", "content": normalized_content},
        calls,
        usage if isinstance(usage, dict) else {},
    )


def _clean_anthropic_content(content: list[Any]) -> list[Any]:
    reply_filter = _ReplyFilter()
    cleaned = []
    last_text: dict[str, Any] | None = None
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "text":
            cleaned.append(block)
            continue
        item = dict(block)
        item["text"] = reply_filter.feed(str(item.get("text", "")))
        cleaned.append(item)
        last_text = item
    tail = reply_filter.finish()
    if tail and last_text is not None:
        last_text["text"] += tail
    return cleaned


def _request_anthropic_stream(
    endpoint: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    on_event: StreamCallback,
    cancellation: RequestCancellation | None,
) -> ProviderTurn | None:
    request = Request(
        endpoint,
        data=json.dumps({**payload, "stream": True}).encode("utf-8"),
        headers={**headers, "Accept": "text/event-stream"},
        method="POST",
    )
    try:
        response = urlopen(request, timeout=120)
    except HTTPError as error:
        failure = _stream_http_failure(error)
        if failure is None:
            return None
        raise failure from error
    except (URLError, TimeoutError, OSError) as error:
        if cancellation is not None and cancellation.cancelled():
            return ProviderTurn("", {"role": "assistant", "content": []}, [])
        raise ProviderRequestError(f"Could not reach the provider: {error}") from error

    if cancellation is not None:
        cancellation.attach(response)
    content_type = response.headers.get_content_type()
    if content_type in {"application/json", "application/problem+json"} or content_type.endswith("+json"):
        try:
            decoded = json.loads(response.read().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            if cancellation is not None:
                cancellation.detach(response)
            response.close()
            raise ProviderRequestError("The provider returned an unreadable streamed response.") from error
        finally:
            if cancellation is not None:
                cancellation.detach(response)
            response.close()
        if not isinstance(decoded, dict):
            raise ProviderRequestError("The provider returned an unexpected response.")
        return _anthropic_turn_from_response(decoded, on_event)
    blocks: dict[int, dict[str, Any]] = {}
    usage: dict[str, Any] = {}
    reply_filter = _ReplyFilter()
    try:
        for raw_line in response:
            if cancellation is not None and cancellation.cancelled():
                break
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or line.startswith(":") or not line.startswith("data:"):
                continue
            try:
                event = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            event_type = event.get("type")
            if event_type == "message_start":
                message = event.get("message")
                if isinstance(message, dict) and isinstance(message.get("usage"), dict):
                    usage.update(message["usage"])
            elif event_type == "content_block_start":
                index = int(event.get("index", 0))
                block = event.get("content_block")
                if isinstance(block, dict):
                    blocks[index] = dict(block)
                    if block.get("type") == "text":
                        blocks[index]["text"] = str(block.get("text", ""))
                        visible = reply_filter.feed(blocks[index]["text"])
                        if visible:
                            on_event("delta", {"text": visible})
                    elif block.get("type") == "tool_use":
                        blocks[index]["input_json"] = ""
            elif event_type == "content_block_delta":
                index = int(event.get("index", 0))
                delta = event.get("delta")
                if not isinstance(delta, dict):
                    continue
                block = blocks.setdefault(index, {"type": "text", "text": ""})
                if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
                    content = delta["text"]
                    block["text"] = str(block.get("text", "")) + content
                    visible = reply_filter.feed(content)
                    if visible:
                        on_event("delta", {"text": visible})
                elif delta.get("type") == "input_json_delta" and isinstance(delta.get("partial_json"), str):
                    block["input_json"] = str(block.get("input_json", "")) + delta["partial_json"]
            elif event_type == "message_delta":
                delta_usage = event.get("usage")
                if isinstance(delta_usage, dict):
                    usage.update(delta_usage)
        if cancellation is not None and cancellation.cancelled():
            return ProviderTurn("", {"role": "assistant", "content": []}, [], usage)
    except (OSError, TimeoutError, ValueError) as error:
        if cancellation is not None and cancellation.cancelled():
            return ProviderTurn("", {"role": "assistant", "content": []}, [], usage)
        raise ProviderRequestError(f"Provider stream ended unexpectedly: {error}") from error
    finally:
        if cancellation is not None:
            cancellation.detach(response)
        response.close()

    tail = reply_filter.finish()
    if tail:
        on_event("delta", {"text": tail})

    normalized_content: list[dict[str, Any]] = []
    calls: list[ToolInvocation] = []
    for _index, block in sorted(blocks.items()):
        if block.get("type") == "tool_use":
            raw_json = str(block.pop("input_json", ""))
            if raw_json:
                try:
                    block["input"] = json.loads(raw_json)
                except json.JSONDecodeError as error:
                    raise ProviderRequestError("The provider returned malformed streamed tool arguments.") from error
            block.setdefault("input", {})
            if not isinstance(block.get("input"), dict):
                raise ProviderRequestError("The provider returned malformed streamed tool arguments.")
            call_id = str(block.get("id") or f"toolu_{uuid.uuid4().hex}")
            block["id"] = call_id
            calls.append(ToolInvocation(call_id, str(block.get("name", "")), block["input"]))
        normalized_content.append(block)
    normalized_content = _clean_anthropic_content(normalized_content)
    text = "\n".join(
        str(block.get("text", ""))
        for block in normalized_content
        if isinstance(block, dict) and block.get("type") == "text"
    )
    return ProviderTurn(
        text,
        {"role": "assistant", "content": normalized_content},
        calls,
        usage,
    )


def send_chat(profile: dict[str, Any], messages: list[dict[str, str]]) -> str:
    protocol = profile.get("protocol", "openai")
    base_url = str(profile.get("base_url", "")).rstrip("/")
    model = str(profile.get("model", ""))
    api_key = str(profile.get("api_key", ""))
    if not model or (not base_url and protocol != "litellm"):
        raise ProviderRequestError("Provider setup is incomplete. Reopen provider setup from the main menu.")
    try:
        if protocol == "litellm":
            turn = _request_litellm_turn(profile, messages, [], None, None)
            return turn.text
        if protocol == "anthropic":
            return _send_anthropic(base_url, model, api_key, messages)
        return _send_openai_compatible(
            base_url,
            model,
            api_key,
            messages,
            str(profile.get("reasoning_parameter", "")),
            str(profile.get("reasoning_effort", "medium")),
            profile.get("reasoning_enabled") is True,
        )
    except ProviderRequestError as error:
        message = str(error)
        if api_key:
            message = message.replace(api_key, "[hidden]")
        raise ProviderRequestError(message) from error


def test_connection(profile: dict[str, Any]) -> str:
    protocol = profile.get("protocol", "openai")
    base_url = str(profile.get("base_url", "")).rstrip("/")
    api_key = str(profile.get("api_key", ""))
    if protocol == "litellm":
        return _test_litellm(profile)
    if not base_url:
        raise ProviderRequestError("Enter a provider base URL first.")
    if protocol == "anthropic":
        endpoint = f"{base_url}/models?limit=1" if base_url.endswith("/v1") else f"{base_url}/v1/models?limit=1"
        headers = {"anthropic-version": "2023-06-01"}
        if api_key:
            headers["x-api-key"] = api_key
    else:
        endpoint = f"{base_url}/models"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
    request = Request(endpoint, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=15) as response:
            status = response.status
    except HTTPError as error:
        detail = error.read(1024).decode("utf-8", errors="replace")
        message = f"Provider returned HTTP {error.code}."
        if detail:
            try:
                body = json.loads(detail)
                detail_message = _response_error_detail(body)
            except json.JSONDecodeError:
                detail_message = None
            if detail_message:
                message = f"Provider returned HTTP {error.code}: {detail_message}"
        if api_key:
            message = message.replace(api_key, "[hidden]")
        raise ProviderRequestError(message) from error
    except (URLError, TimeoutError, OSError) as error:
        message = f"Could not reach the provider: {error}"
        if api_key:
            message = message.replace(api_key, "[hidden]")
        raise ProviderRequestError(message) from error
    if status < 200 or status >= 300:
        raise ProviderRequestError(f"Provider returned HTTP {status}.")
    return "Connection succeeded. Check that the model ID is available on your account."


def list_models(profile: dict[str, Any]) -> list[str]:
    protocol = str(profile.get("protocol", "openai"))
    base_url = str(profile.get("base_url", "")).rstrip("/")
    api_key = str(profile.get("api_key", ""))
    provider_id = str(profile.get("provider_id", ""))
    if protocol == "litellm":
        return _list_litellm_models(profile)
    if not base_url:
        raise ProviderRequestError("Enter a provider base URL first.")
    if provider_id == "cloudflare":
        parsed = urlsplit(base_url)
        if not parsed.path.endswith("/ai/v1"):
            raise ProviderRequestError("Cloudflare base URL must end in /ai/v1.")
        endpoint = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path[:-6] + "/ai/models/search", "", "")
        )
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        cursor_parameter = "page"
    elif protocol == "anthropic":
        endpoint = f"{base_url}/models" if base_url.endswith("/v1") else f"{base_url}/v1/models"
        headers = {"anthropic-version": "2023-06-01"}
        if api_key:
            headers["x-api-key"] = api_key
        cursor_parameter = "after_id"
    else:
        endpoint = f"{base_url}/models"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        cursor_parameter = "after"

    model_ids: set[str] = set()
    cursor: str | None = None
    visited_cursors: set[str] = set()
    for _ in range(20):
        query: dict[str, str] = {}
        if provider_id == "cloudflare":
            query["per_page"] = "100"
            query["hide_experimental"] = "true"
            query["format"] = "openrouter"
            query[cursor_parameter] = cursor or "1"
        elif protocol == "anthropic":
            query["limit"] = "1000"
        if cursor and provider_id != "cloudflare":
            query[cursor_parameter] = cursor
        url = f"{endpoint}?{urlencode(query)}" if query else endpoint
        request = Request(url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=20) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            detail = error.read(2048).decode("utf-8", errors="replace")
            message = f"Provider returned HTTP {error.code}."
            try:
                body = json.loads(detail)
                detail_message = _response_error_detail(body)
            except json.JSONDecodeError:
                detail_message = None
            if detail_message:
                message = f"Provider returned HTTP {error.code}: {detail_message}"
            raise ProviderRequestError(_hide_secret(message, api_key)) from error
        except (URLError, TimeoutError, OSError) as error:
            raise ProviderRequestError(_hide_secret(f"Could not reach the provider: {error}", api_key)) from error
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ProviderRequestError("The provider returned invalid JSON while listing models.") from error

        if not isinstance(decoded, dict):
            raise ProviderRequestError("The provider returned an unexpected model list.")
        if provider_id == "cloudflare" and decoded.get("success") is False:
            message = _response_error_detail(decoded) or "Cloudflare could not list available models."
            raise ProviderRequestError(_hide_secret(message, api_key))
        if provider_id == "cloudflare":
            result = decoded.get("result", [])
            items = result.get("data", result.get("models", [])) if isinstance(result, dict) else result
        else:
            items = decoded.get("data", decoded.get("models", []))
        if not isinstance(items, list):
            raise ProviderRequestError("The provider returned an unexpected model list.")
        page_ids: list[str] = []
        for item in items:
            if isinstance(item, str):
                model_id = item
            elif isinstance(item, dict):
                model_id = item.get("id") or item.get("name") or item.get("model")
            else:
                model_id = None
            if isinstance(model_id, str) and model_id.strip():
                page_ids.append(model_id.strip())
        model_ids.update(page_ids)

        if provider_id == "cloudflare":
            result_info = decoded.get("result_info", {})
            total_pages = result_info.get("total_pages", 1) if isinstance(result_info, dict) else 1
            current_page = int(cursor or "1")
            try:
                has_more = current_page < int(total_pages or 1)
            except (TypeError, ValueError):
                has_more = False
            if not has_more or not page_ids:
                break
            cursor = str(current_page + 1)
        elif not decoded.get("has_more") or not page_ids:
            break
        else:
            cursor = str(decoded.get("last_id") or page_ids[-1])
            if cursor in visited_cursors:
                break
            visited_cursors.add(cursor)

    if not model_ids:
        raise ProviderRequestError("The provider returned no selectable models.")
    return sorted(model_ids, key=str.casefold)


def check_reasoning_support(profile: dict[str, Any]) -> str | None:
    protocol = str(profile.get("protocol", "openai"))
    provider_id = str(profile.get("provider_id", ""))
    model = str(profile.get("model", ""))
    if protocol == "anthropic":
        return None
    if protocol == "litellm":
        supported = _litellm_capability("supports_reasoning", model)
        if supported is None:
            return None
        # LiteLLM maps reasoning_effort onto each provider's own thinking controls.
        return "reasoning_effort" if supported else "unsupported"
    if provider_id == "nvidia_nim" and "nemotron-3-ultra" in model.casefold():
        return "nvidia_chat_template"
    base_url = str(profile.get("base_url", "")).rstrip("/")
    api_key = str(profile.get("api_key", ""))
    if not base_url or not model:
        raise ProviderRequestError("Provider setup is incomplete. Choose a provider and model first.")
    endpoint = f"{base_url}/models"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = Request(endpoint, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=15) as response:
            decoded = json.loads(response.read(2_000_000).decode("utf-8"))
    except HTTPError as error:
        detail = error.read(1024).decode("utf-8", errors="replace")
        try:
            body = json.loads(detail)
            message = _response_error_detail(body) or f"Provider returned HTTP {error.code}."
        except json.JSONDecodeError:
            message = f"Provider returned HTTP {error.code}."
        raise ProviderRequestError(_hide_secret(message, api_key)) from error
    except (URLError, TimeoutError, OSError) as error:
        raise ProviderRequestError(_hide_secret(f"Could not reach the provider: {error}", api_key)) from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProviderRequestError("The provider returned invalid model metadata.") from error
    if not isinstance(decoded, dict):
        return None
    if provider_id == "cloudflare" and isinstance(decoded.get("result"), dict):
        decoded = decoded["result"]
    items = decoded.get("data", decoded.get("models", []))
    if not isinstance(items, list):
        return None
    metadata = next(
        (
            item for item in items
            if isinstance(item, dict)
            and str(item.get("id") or item.get("name") or item.get("model") or "") == model
        ),
        None,
    )
    if metadata is None:
        return None
    parameters = metadata.get("supported_parameters")
    if isinstance(parameters, list):
        normalized = {str(parameter).casefold() for parameter in parameters}
        if "reasoning_effort" in normalized:
            return "reasoning_effort"
        if "reasoning" in normalized:
            return "reasoning"
    capabilities = metadata.get("capabilities")
    if isinstance(capabilities, dict) and isinstance(capabilities.get("reasoning"), bool):
        if not capabilities["reasoning"]:
            return "unsupported"
        parameter = metadata.get("reasoning_parameter")
        return str(parameter) if parameter in {"reasoning", "reasoning_effort"} else None
    if metadata.get("supports_reasoning") is False:
        return "unsupported"
    if metadata.get("supports_reasoning") is True:
        parameter = metadata.get("reasoning_parameter")
        return str(parameter) if parameter in {"reasoning", "reasoning_effort"} else None
    if isinstance(parameters, list):
        return "unsupported"
    return None


def check_image_input_support(profile: dict[str, Any]) -> bool | None:
    protocol = str(profile.get("protocol", "openai"))
    provider_id = str(profile.get("provider_id", ""))
    base_url = str(profile.get("base_url", "")).rstrip("/")
    model = str(profile.get("model", ""))
    api_key = str(profile.get("api_key", ""))
    if protocol == "litellm":
        return _litellm_capability("supports_vision", model)
    if not base_url or not model:
        return None
    if provider_id == "cloudflare":
        parsed = urlsplit(base_url)
        endpoint = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path.removesuffix("/ai/v1") + "/ai/models/search", "", "")
        )
        query = urlencode(
            {"per_page": "100", "hide_experimental": "true", "format": "openrouter", "page": "1"}
        )
        endpoint = f"{endpoint}?{query}"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
    elif protocol == "anthropic":
        endpoint = f"{base_url}/models" if base_url.endswith("/v1") else f"{base_url}/v1/models"
        headers = {"anthropic-version": "2023-06-01"}
        if api_key:
            headers["x-api-key"] = api_key
    else:
        endpoint = f"{base_url}/models"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
    request = Request(endpoint, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=15) as response:
            decoded = json.loads(response.read(2_000_000).decode("utf-8"))
    except HTTPError as error:
        detail = error.read(1024).decode("utf-8", errors="replace")
        message = f"Provider returned HTTP {error.code}."
        try:
            body = json.loads(detail)
            message = _response_error_detail(body) or message
        except json.JSONDecodeError:
            pass
        raise ProviderRequestError(_hide_secret(message, api_key)) from error
    except (URLError, TimeoutError, OSError) as error:
        raise ProviderRequestError(_hide_secret(f"Could not reach the provider: {error}", api_key)) from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProviderRequestError("The provider returned invalid model metadata.") from error
    if not isinstance(decoded, dict):
        return None
    cloudflare_items = None
    if provider_id == "cloudflare":
        result = decoded.get("result")
        if isinstance(result, dict):
            decoded = result
        elif isinstance(result, list):
            cloudflare_items = result
    items = cloudflare_items or decoded.get("data", decoded.get("models", []))
    if not isinstance(items, list):
        return None
    metadata = next(
        (
            item for item in items
            if isinstance(item, dict)
            and str(item.get("id") or item.get("name") or item.get("model") or "").casefold()
            == model.casefold()
        ),
        None,
    )
    return _image_capability(metadata) if metadata is not None else None


def _image_capability(metadata: dict[str, Any]) -> bool | None:
    for key in ("supports_vision", "supports_images", "supports_image_input", "vision"):
        value = metadata.get(key)
        if isinstance(value, bool):
            return value
    capability = metadata.get("capabilities")
    if isinstance(capability, dict):
        for key in ("vision", "image", "images", "image_input"):
            value = capability.get(key)
            if isinstance(value, bool):
                return value
            if isinstance(value, dict):
                for nested_key in ("input", "enabled", "supported"):
                    nested = value.get(nested_key)
                    if isinstance(nested, bool):
                        return nested
        for key in ("input_modalities", "modalities", "input"):
            modalities = capability.get(key)
            if isinstance(modalities, list):
                return any(
                    "image" in str(item).casefold() or "vision" in str(item).casefold()
                    for item in modalities
                )
    elif isinstance(capability, list):
        return any("image" in str(item).casefold() or "vision" in str(item).casefold() for item in capability)
    for source in (metadata, metadata.get("architecture", {})):
        if not isinstance(source, dict):
            continue
        for key in ("input_modalities", "modalities"):
            modalities = source.get(key)
            if isinstance(modalities, list):
                return any(
                    "image" in str(item).casefold() or "vision" in str(item).casefold()
                    for item in modalities
                )
    return None


def _image_data(path: str) -> tuple[str, str]:
    image_path = Path(path)
    media_type = mimetypes.guess_type(image_path.name)[0]
    if media_type not in {"image/png", "image/jpeg", "image/webp", "image/gif"}:
        raise ProviderRequestError(f"Mitsu cannot send this image format to the provider: {image_path.name}")
    try:
        encoded = base64.b64encode(image_path.read_bytes()).decode("ascii")
    except OSError as error:
        raise ProviderRequestError(f"The attached image is no longer available: {image_path.name}") from error
    return media_type, encoded


def _openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["parameters"],
            },
        }
        for tool in tools
    ]


def _openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for message in messages:
        content = message.get("content")
        if not isinstance(content, list):
            normalized.append(message)
            continue
        blocks = []
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "mitsu_image":
                blocks.append(block)
                continue
            media_type, data = _image_data(str(block.get("path", "")))
            blocks.append(
                {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{data}"}}
            )
        normalized.append({**message, "content": blocks})
    return normalized


def _anthropic_message(message: dict[str, Any]) -> dict[str, Any]:
    content = message.get("content")
    if not isinstance(content, list):
        return message
    blocks = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "mitsu_image":
            blocks.append(block)
            continue
        media_type, data = _image_data(str(block.get("path", "")))
        blocks.append(
            {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": data}}
        )
    return {**message, "content": blocks}


def apply_reasoning_default(profile: dict[str, Any]) -> bool:
    if isinstance(profile.get("reasoning_enabled"), bool):
        return False
    capability = check_reasoning_support(profile)
    if capability == "unsupported":
        profile["reasoning_enabled"] = False
        profile["reasoning_parameter"] = ""
        profile["reasoning_effort"] = "medium"
        return True
    if capability is None:
        return False
    profile["reasoning_enabled"] = True
    profile["reasoning_parameter"] = capability
    profile["reasoning_effort"] = "medium"
    return True


def _litellm() -> Any:
    try:
        import litellm
    except ImportError as error:
        raise ProviderRequestError(
            "The LiteLLM provider needs the LiteLLM SDK: pip install 'mitsu[litellm]'"
        ) from error
    litellm.suppress_debug_info = True  # its help banners print to stdout, under the TUI
    return litellm


class _LiteLLMStream:
    """A LiteLLM completion stream presented as the ``data:`` lines _read_openai_stream reads."""

    def __init__(self, chunks: Any) -> None:
        self._chunks = chunks

    def __iter__(self):
        for chunk in self._chunks:
            data = chunk.model_dump(exclude_none=True) if hasattr(chunk, "model_dump") else chunk
            yield b"data: " + json.dumps(data, default=str).encode("utf-8")
        yield b"data: [DONE]"

    def close(self) -> None:
        close = getattr(self._chunks, "close", None)
        if callable(close):
            close()


def _litellm_request(profile: dict[str, Any]) -> dict[str, Any]:
    """Arguments shared by every LiteLLM call: credentials come from each provider's own environment
    variables unless the profile carries a key, and an endpoint only for self-hosted routes."""
    request: dict[str, Any] = {"model": str(profile.get("model", "")), "drop_params": True, "timeout": 120}
    base_url = str(profile.get("base_url", "")).rstrip("/")
    api_key = str(profile.get("api_key", ""))
    if base_url:
        request["api_base"] = base_url
    if api_key:
        request["api_key"] = api_key
    return request


def _request_litellm_turn(
    profile: dict[str, Any],
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    on_event: StreamCallback | None,
    cancellation: RequestCancellation | None,
) -> ProviderTurn:
    litellm = _litellm()
    request = {**_litellm_request(profile), "messages": _openai_messages(messages)}
    if tools:
        request["tools"] = _openai_tools(tools)
    if profile.get("reasoning_enabled") is True and profile.get("reasoning_parameter") == "reasoning_effort":
        request["reasoning_effort"] = str(profile.get("reasoning_effort", "medium"))
    try:
        if on_event is not None:
            stream = _LiteLLMStream(
                litellm.completion(**request, stream=True, stream_options={"include_usage": True})
            )
            if cancellation is not None:
                cancellation.attach(stream)
            try:
                streamed = _read_openai_stream(stream, on_event, cancellation)
            finally:
                if cancellation is not None:
                    cancellation.detach(stream)
            if streamed is not None:
                return streamed
        if cancellation is not None and cancellation.cancelled():
            return ProviderTurn("", {"role": "assistant", "content": ""}, [])
        response = litellm.completion(**request)
    except ProviderRequestError:
        raise
    except Exception as error:
        raise ProviderRequestError(f"Provider request failed: {_litellm_error(error)}") from error
    return _openai_turn_from_response(response.model_dump(), on_event)


def _litellm_error(error: Exception) -> str:
    message = str(getattr(error, "message", "") or error)
    return message.splitlines()[0][:400] if message else type(error).__name__


def _test_litellm(profile: dict[str, Any]) -> str:
    litellm = _litellm()
    if not profile.get("model"):
        return "LiteLLM SDK found. Choose a provider/model to finish the connection check."
    try:
        litellm.completion(
            **_litellm_request(profile), messages=[{"role": "user", "content": "Reply with OK."}], max_tokens=5
        )
    except Exception as error:
        message = f"Provider request failed: {_litellm_error(error)}"
        raise ProviderRequestError(_hide_secret(message, str(profile.get("api_key", "")))) from error
    return "Connection succeeded."


def _list_litellm_models(profile: dict[str, Any]) -> list[str]:
    """Models of the providers whose credentials LiteLLM finds in the environment, plus the saved one."""
    litellm = _litellm()
    try:
        models = set(litellm.get_valid_models())
    except Exception as error:
        raise ProviderRequestError(f"Could not list LiteLLM models: {_litellm_error(error)}") from error
    if profile.get("model"):
        models.add(str(profile["model"]))
    if not models:
        raise ProviderRequestError(
            "LiteLLM found no provider credentials. Set a provider's API key (e.g. ANTHROPIC_API_KEY) "
            "or enter a provider/model ID."
        )
    return sorted(models, key=str.casefold)


def _litellm_capability(check: str, model: str) -> bool | None:
    try:
        litellm = _litellm()
        return bool(getattr(litellm, check)(model=model))
    except Exception:
        return None


def _hide_secret(message: str, secret: str) -> str:
    return message.replace(secret, "[hidden]") if secret else message


def _response_error_detail(body: Any) -> str | None:
    if not isinstance(body, dict):
        return None
    error = body.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        if isinstance(message, str) and message:
            return message
    elif isinstance(error, str) and error:
        return error
    errors = body.get("errors")
    if isinstance(errors, list):
        messages = [
            str(item.get("message")) if isinstance(item, dict) and item.get("message") else str(item)
            for item in errors
            if item
        ]
        if messages:
            return "; ".join(messages)
    message = body.get("message")
    return message if isinstance(message, str) and message else None


def _send_openai_compatible(
    base_url: str,
    model: str,
    api_key: str,
    messages: list[dict[str, str]],
    reasoning_parameter: str = "",
    reasoning_effort: str = "medium",
    reasoning_enabled: bool = False,
) -> str:
    endpoint = base_url if base_url.endswith("/chat/completions") else f"{base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = {"model": model, "messages": messages, "stream": False}
    if reasoning_parameter == "reasoning_effort" and reasoning_enabled:
        payload["reasoning_effort"] = reasoning_effort
    elif reasoning_parameter == "reasoning" and reasoning_enabled:
        payload["reasoning"] = {"effort": reasoning_effort}
    elif reasoning_parameter == "nvidia_chat_template":
        template_options = {"enable_thinking": reasoning_enabled}
        if reasoning_enabled and reasoning_effort == "medium":
            template_options["medium_effort"] = True
        payload["chat_template_kwargs"] = template_options
    response = _request_json(endpoint, headers, payload)
    try:
        return str(response["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as error:
        raise ProviderRequestError("The provider returned a response Mitsu could not read.") from error


def _send_anthropic(
    base_url: str,
    model: str,
    api_key: str,
    messages: list[dict[str, str]],
) -> str:
    endpoint = f"{base_url}/messages" if base_url.endswith("/v1") else f"{base_url}/v1/messages"
    headers = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
    if api_key:
        headers["x-api-key"] = api_key
    system_messages = [message["content"] for message in messages if message["role"] == "system"]
    conversation = [message for message in messages if message["role"] != "system"]
    payload = {"model": model, "max_tokens": 2048, "messages": conversation}
    if system_messages:
        payload["system"] = "\n\n".join(system_messages)
    response = _request_json(endpoint, headers, payload)
    try:
        return "\n".join(
            str(block["text"])
            for block in response["content"]
            if block.get("type") == "text"
        )
    except (KeyError, TypeError) as error:
        raise ProviderRequestError("The provider returned a response Mitsu could not read.") from error


def _provider_http_error(error: HTTPError) -> ProviderRequestError:
    message = _http_error_message(error)
    return ProviderRequestError(f"Provider request failed ({error.code}): {message}")


def _http_error_message(error: HTTPError) -> str:
    detail = error.read(2048).decode("utf-8", errors="replace")
    try:
        body = json.loads(detail)
        message = _response_error_detail(body) or detail
    except json.JSONDecodeError:
        message = detail or error.reason
    return message


def _stream_http_failure(error: HTTPError) -> ProviderRequestError | None:
    message = _http_error_message(error)
    normalized = message.casefold()
    if error.code in {400, 422, 501} and ("stream" in normalized or "unsupported" in normalized):
        return None
    return ProviderRequestError(f"Provider request failed ({error.code}): {message}")


def _request_json(
    endpoint: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    cancellation: RequestCancellation | None = None,
) -> dict[str, Any]:
    request = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        response = urlopen(request, timeout=120)
        if cancellation is not None:
            cancellation.attach(response)
        try:
            decoded = json.loads(response.read().decode("utf-8"))
        finally:
            if cancellation is not None:
                cancellation.detach(response)
            response.close()
    except HTTPError as error:
        raise _provider_http_error(error) from error
    except (URLError, TimeoutError, OSError) as error:
        raise ProviderRequestError(f"Could not reach the provider: {error}") from error
    except json.JSONDecodeError as error:
        raise ProviderRequestError("The provider returned invalid JSON.") from error
    if not isinstance(decoded, dict):
        raise ProviderRequestError("The provider returned an unexpected response.")
    return decoded
