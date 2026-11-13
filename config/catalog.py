"""Provider definitions and theme presets."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderSpec:
    id: str
    name: str
    base_url: str
    protocol: str
    requires_api_key: bool = True
    note: str = ""


PROVIDERS = (
    ProviderSpec("openai", "OpenAI", "https://api.openai.com/v1", "openai"),
    ProviderSpec("anthropic", "Anthropic", "https://api.anthropic.com", "anthropic"),
    ProviderSpec("openrouter", "OpenRouter", "https://openrouter.ai/api/v1", "openai"),
    ProviderSpec("ollama", "Ollama", "http://localhost:11434/v1", "openai", False),
    ProviderSpec("deepseek", "DeepSeek", "https://api.deepseek.com", "openai"),
    ProviderSpec("moonshot", "Moonshot", "https://api.moonshot.ai/v1", "openai"),
    ProviderSpec("nvidia_nim", "NVIDIA NIM", "https://integrate.api.nvidia.com/v1", "openai"),
    ProviderSpec(
        "cloudflare",
        "Cloudflare Models",
        "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1",
        "openai",
        note="Replace {account_id} with your Cloudflare account ID.",
    ),
    ProviderSpec(
        "litellm",
        "LiteLLM",
        "",
        "litellm",
        False,
        note="provider/model IDs (bedrock/..., vertex_ai/..., azure/...); credentials from each provider's environment.",
    ),
    ProviderSpec("custom", "Custom", "", "openai", False),
)

PROVIDER_BY_ID = {provider.id: provider for provider in PROVIDERS}
THEMES = {
    "ember": {
        "name": "Soft Ember",
        "accent": "#e58b6b",
        "code": {
            "keyword": "#f29a78",
            "function": "#55e5e8",
            "string": "#b6d490",
            "number": "#cbabed",
            "comment": "#817c77",
            "operator": "#e6b8a5",
        },
        "ui": {
            "background": "#0b0a0b", "surface": "#101417", "panel": "#0d1215",
            "border": "#403633", "muted": "#aaa6a0", "user": "#171319", "code": "#111115",
        },
    },
    "moss": {
        "name": "Mint Garden",
        "accent": "#91bd9b",
        "code": {
            "keyword": "#a6d49c",
            "function": "#55e5e8",
            "string": "#e4cf87",
            "number": "#b7a8eb",
            "comment": "#818f83",
            "operator": "#b8d6c0",
        },
        "ui": {
            "background": "#090e0a", "surface": "#111812", "panel": "#0e1710",
            "border": "#385341", "muted": "#9baa9d", "user": "#172018", "code": "#101710",
        },
    },
    "lilac": {
        "name": "Lilac Night",
        "accent": "#b8a4d7",
        "code": {
            "keyword": "#c6a5e9",
            "function": "#55e5e8",
            "string": "#e9b4ce",
            "number": "#efcc85",
            "comment": "#90859c",
            "operator": "#cfb8e4",
        },
        "ui": {
            "background": "#0d0a11", "surface": "#17121d", "panel": "#14101a",
            "border": "#514064", "muted": "#a89bad", "user": "#201722", "code": "#15101b",
        },
    },
    "ocean": {
        "name": "Moonlit Ocean",
        "accent": "#67c9e4",
        "code": {
            "keyword": "#67c9e4",
            "function": "#55e5e8",
            "string": "#a2dca3",
            "number": "#ddb7f0",
            "comment": "#829ca9",
            "operator": "#93d9e5",
        },
        "ui": {
            "background": "#071014", "surface": "#0d171b", "panel": "#101a1f",
            "border": "#315459", "muted": "#91a7ad", "user": "#142027", "code": "#0c1519",
        },
    },
    "rose": {
        "name": "Rose Quartz",
        "accent": "#e996b4",
        "code": {
            "keyword": "#e996b4",
            "function": "#55e5e8",
            "string": "#b7da99",
            "number": "#c6adef",
            "comment": "#a18a91",
            "operator": "#f2b9c8",
        },
        "ui": {
            "background": "#100b0e", "surface": "#1b1117", "panel": "#1a1116",
            "border": "#61404e", "muted": "#b29aa1", "user": "#26151e", "code": "#1a1118",
        },
    },
    "gold": {
        "name": "Starlight Gold",
        "accent": "#e9c46a",
        "code": {
            "keyword": "#e9c46a",
            "function": "#55e5e8",
            "string": "#a9d18e",
            "number": "#d0a9e8",
            "comment": "#928c79",
            "operator": "#f0d58e",
        },
        "ui": {
            "background": "#100e08", "surface": "#1a170e", "panel": "#18150b",
            "border": "#5f512b", "muted": "#aa9c74", "user": "#241d10", "code": "#19160e",
        },
    },
    "blue": {
        "name": "Blue Hour",
        "accent": "#8baceb",
        "code": {
            "keyword": "#8baceb",
            "function": "#55e5e8",
            "string": "#a9d18e",
            "number": "#e0a9d1",
            "comment": "#858da5",
            "operator": "#b0c2f0",
        },
        "ui": {
            "background": "#090c14", "surface": "#111725", "panel": "#101522",
            "border": "#3c4d72", "muted": "#9da9c3", "user": "#192033", "code": "#121827",
        },
    },
}
