from __future__ import annotations

import json
import sys
import types
from types import SimpleNamespace
from typing import Any

import pytest

from mitsu.config import PROVIDER_BY_ID, CredentialStore
from mitsu.providers import client

PROFILE = {
    "provider_id": "litellm",
    "protocol": "litellm",
    "base_url": "",
    "api_key": "",
    "model": "bedrock/anthropic.claude-sonnet-4-6",
}
TOOLS = [{"name": "run_nmap", "description": "Scan a host.", "parameters": {"type": "object", "properties": {}}}]


class Response:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return self.data


def completion_response(content: str | None, tool_calls: list[dict[str, Any]] | None = None) -> Response:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return Response({"id": "resp_1", "model": "claude", "choices": [{"index": 0, "message": message,
                     "finish_reason": "tool_calls" if tool_calls else "stop"}], "usage": {"total_tokens": 12}})


@pytest.fixture
def litellm(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    calls: list[dict[str, Any]] = []
    sdk = types.ModuleType("litellm")
    sdk.calls = calls
    sdk.reply = completion_response("Recon done.")
    sdk.stream = None

    def completion(**kwargs: Any) -> Any:
        calls.append(kwargs)
        if kwargs.get("stream"):
            return iter(sdk.stream)
        return sdk.reply

    sdk.completion = completion
    sdk.get_valid_models = lambda: ["anthropic/claude-sonnet-4-6", "gpt-4.1-mini"]
    sdk.supports_reasoning = lambda model: model.startswith("anthropic/")
    sdk.supports_vision = lambda model: "vision" in model or model.startswith("anthropic/")
    monkeypatch.setitem(sys.modules, "litellm", sdk)
    return sdk


def test_catalog_offers_litellm_without_a_required_key() -> None:
    spec = PROVIDER_BY_ID["litellm"]
    assert (spec.protocol, spec.base_url, spec.requires_api_key) == ("litellm", "", False)


def test_a_litellm_profile_without_base_url_is_configured_and_ready(tmp_path, monkeypatch) -> None:
    store = CredentialStore()
    monkeypatch.setattr(store, "path", tmp_path / "credentials.json")
    store.path.write_text(json.dumps({"active_provider": "litellm", "providers": {"litellm": PROFILE}}))

    assert [p["provider_id"] for p in store.configured_profiles()] == ["litellm"]
    assert store.ready()


def test_agent_turn_sends_tools_and_reads_tool_calls(litellm) -> None:
    litellm.reply = completion_response(
        None, [{"id": "call_1", "type": "function", "function": {"name": "run_nmap", "arguments": '{"host": "10.0.0.5"}'}}]
    )

    turn = client.request_agent_turn(PROFILE, [{"role": "user", "content": "scan it"}], TOOLS)

    request = litellm.calls[0]
    assert request["model"] == "bedrock/anthropic.claude-sonnet-4-6"
    assert request["drop_params"] is True
    assert request["tools"][0]["function"]["name"] == "run_nmap"
    assert "api_base" not in request and "api_key" not in request and "reasoning_effort" not in request
    assert [(c.name, c.arguments) for c in turn.tool_calls] == [("run_nmap", {"host": "10.0.0.5"})]
    assert turn.usage == {"total_tokens": 12}


def test_endpoint_key_and_reasoning_are_passed_when_set(litellm) -> None:
    profile = {**PROFILE, "base_url": "http://localhost:11434/", "api_key": "sk-x",
               "reasoning_enabled": True, "reasoning_parameter": "reasoning_effort", "reasoning_effort": "high"}

    client.request_agent_turn(profile, [{"role": "user", "content": "hi"}], [])

    request = litellm.calls[0]
    assert (request["api_base"], request["api_key"], request["reasoning_effort"]) == ("http://localhost:11434", "sk-x", "high")
    assert "tools" not in request


def test_streamed_turn_emits_deltas_and_assembles_tool_calls(litellm) -> None:
    litellm.stream = [
        {"id": "c1", "model": "claude", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Scanning "}}]},
        {"id": "c1", "choices": [{"index": 0, "delta": {"content": "now."}}]},
        {"id": "c1", "choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "id": "call_9", "type": "function", "function": {"name": "run_nmap", "arguments": '{"host": '}}]}}]},
        {"id": "c1", "choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": '"10.0.0.5"}'}}]}, "finish_reason": "tool_calls"}]},
        {"id": "c1", "choices": [], "usage": {"prompt_tokens": 20, "completion_tokens": 9}},
    ]
    events: list[str] = []

    turn = client.request_agent_turn(PROFILE, [{"role": "user", "content": "scan"}], TOOLS,
                                     on_event=lambda kind, data: events.append(data["text"]))

    assert litellm.calls[0]["stream"] is True
    assert litellm.calls[0]["stream_options"] == {"include_usage": True}
    assert events == ["Scanning ", "now."]
    assert turn.text == "Scanning now."
    assert [(c.id, c.name, c.arguments) for c in turn.tool_calls] == [("call_9", "run_nmap", {"host": "10.0.0.5"})]
    assert turn.usage == {"prompt_tokens": 20, "completion_tokens": 9}
    assert turn.response_info["finish_reason"] == "tool_calls"


def test_provider_errors_are_wrapped_and_the_key_hidden(litellm) -> None:
    def fail(**_: Any) -> Any:
        raise RuntimeError("AuthenticationError: key sk-secret rejected by anthropic")

    litellm.completion = fail
    with pytest.raises(client.ProviderRequestError) as error:
        client.request_agent_turn({**PROFILE, "api_key": "sk-secret"}, [{"role": "user", "content": "x"}], [])
    assert "Provider request failed" in str(error.value)
    assert "sk-secret" not in str(error.value)
    assert litellm.suppress_debug_info is True


def test_send_chat_returns_the_reply_text(litellm) -> None:
    assert client.send_chat(PROFILE, [{"role": "user", "content": "summarize"}]) == "Recon done."
    assert "tools" not in litellm.calls[0]


def test_models_come_from_the_credentials_litellm_finds(litellm) -> None:
    assert client.list_models(PROFILE) == [
        "anthropic/claude-sonnet-4-6", "bedrock/anthropic.claude-sonnet-4-6", "gpt-4.1-mini"
    ]


def test_capabilities_come_from_litellm_model_info(litellm) -> None:
    anthropic = {**PROFILE, "model": "anthropic/claude-sonnet-4-6"}
    assert client.check_reasoning_support(anthropic) == "reasoning_effort"
    assert client.check_reasoning_support({**PROFILE, "model": "gpt-4.1-mini"}) == "unsupported"
    assert client.check_image_input_support(anthropic) is True
    assert client.check_image_input_support({**PROFILE, "model": "gpt-4.1-mini"}) is False


def test_connection_check_runs_a_small_completion(litellm) -> None:
    assert client.test_connection(PROFILE) == "Connection succeeded."
    assert litellm.calls[0]["max_tokens"] == 5


def test_missing_sdk_names_the_install(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "litellm", None)
    with pytest.raises(client.ProviderRequestError, match=r"mitsu\[litellm\]"):
        client.request_agent_turn(PROFILE, [{"role": "user", "content": "x"}], [])
