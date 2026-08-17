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
    text_parts: list[str] = []
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
                    text_parts.append(completion_text)
                    on_event("delta", {"text": completion_text})
                continue
            content = delta.get("content")
            content_text = _openai_content_text(content)
            if not content_text and isinstance(delta.get("refusal"), str):
                content_text = delta["refusal"]
            if content_text:
                text_parts.append(content_text)
                on_event("delta", {"text": content_text})
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
    conversation = [message for message in messages if message.get("role") != "system"]
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
                    on_event("delta", {"text": content})
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

    normalized_content: list[dict[str, Any]] = []
    calls: list[ToolInvocation] = []
    text_parts: list[str] = []
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
        elif block.get("type") == "text":
            text_parts.append(str(block.get("text", "")))
        normalized_content.append(block)
    return ProviderTurn(
        "\n".join(text_parts),
        {"role": "assistant", "content": normalized_content},
        calls,
        usage,
    )


def send_chat(profile: dict[str, Any], messages: list[dict[str, str]]) -> str:
    protocol = profile.get("protocol", "openai")
    base_url = str(profile.get("base_url", "")).rstrip("/")
    model = str(profile.get("model", ""))
    api_key = str(profile.get("api_key", ""))
    if not base_url or not model:
        raise ProviderRequestError("Provider setup is incomplete. Reopen provider setup from the main menu.")
    try:
        if protocol == "anthropic":
            return _send_anthropic(base_url, model, api_key, messages)
        return _send_openai_compatible(
            base_url,
            model,
            api_key,
            messages,
            str(profile.get("reasoning_parameter", "")) if profile.get("reasoning_enabled") else "",
            str(profile.get("reasoning_effort", "medium")),
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
