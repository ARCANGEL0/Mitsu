"""Provider configuration dialog."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, OptionList, Static

from mitsu.config import CredentialStore, PROVIDERS, PROVIDER_BY_ID
from mitsu.providers import ProviderRequestError, apply_reasoning_default, list_models


class ProviderDialog(ModalScreen[dict | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel", priority=True)]

    def __init__(self, credentials: CredentialStore, action: str) -> None:
        super().__init__()
        self.credentials = credentials
        self.dialog_kind = action if action in {"connect", "model"} else "model"
        self.stage = "provider_list" if self.dialog_kind == "connect" else "model_list"
        self.pending_profile: dict | None = None
        self.model_choices: list[tuple[dict, str]] = []
        self.key_prompted = False
        self.endpoint_prompted = False

    def compose(self) -> ComposeResult:
        with Vertical(id="provider-dialog"):
            yield Static("", id="provider-dialog-title", markup=False)
            yield Static("", id="provider-dialog-detail", markup=False)
            yield OptionList(id="provider-dialog-list", compact=True)
            yield Input(placeholder="", id="provider-dialog-input")
            yield Static("↑ / ↓ move    Enter select    Esc close", id="provider-dialog-hint", markup=False)

    def on_mount(self) -> None:
        if self.dialog_kind == "connect":
            self._show_providers()
        else:
            self.run_worker(self._load_all_models(), name="provider-dialog-models", exclusive=True)

    async def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "provider-dialog-list" or event.option_index is None:
            return
        if self.stage == "provider_list":
            await self._choose_provider(event.option_index)
        elif self.stage == "model_list":
            if self.model_choices and event.option_index < len(self.model_choices):
                profile, model = self.model_choices[event.option_index]
                await self._save_selection(profile, model)
        elif self.stage == "retry_models":
            self.run_worker(self._load_all_models(), name="provider-dialog-models", exclusive=True)
        elif self.stage == "retry_provider_models":
            self.run_worker(self._load_provider_models(), name="provider-dialog-models", exclusive=True)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "provider-dialog-input" or not self.pending_profile:
            return
        value = event.value.strip()
        event.input.value = ""
        stage = self.stage
        profile = self.pending_profile
        if stage == "base_url":
            if not self._valid_endpoint(value):
                self.query_one("#provider-dialog-detail", Static).update(
                    "Enter a complete http:// or https:// URL. Esc closes this window."
                )
                event.input.focus()
                return
            profile["base_url"] = value.rstrip("/")
            profile["protocol"] = str(profile.get("protocol") or "openai")
        elif stage == "api_key":
            spec = PROVIDER_BY_ID[str(profile["provider_id"])]
            if spec.requires_api_key and not value and not profile.get("api_key"):
                self.query_one("#provider-dialog-detail", Static).update(
                    f"{spec.name} requires an API key. Enter it or press Esc to cancel."
                )
                event.input.focus()
                return
            if value:
                profile["api_key"] = value
        elif stage == "account_id":
            if not re.fullmatch(r"[A-Fa-f0-9]{32}", value):
                self.query_one("#provider-dialog-detail", Static).update(
                    "Enter the 32-character Cloudflare account ID."
                )
                event.input.focus()
                return
            profile["base_url"] = PROVIDER_BY_ID["cloudflare"].base_url.format(account_id=value)
        elif stage == "model_name":
            if not value:
                self.query_one("#provider-dialog-detail", Static).update("Enter the model name.")
                event.input.focus()
                return
            await self._save_selection(profile, value)
            return
        self.query_one("#provider-dialog-input", Input).display = False
        self._continue_connect()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _show_providers(self) -> None:
        configured = {profile["provider_id"] for profile in self.credentials.configured_profiles()}
        active = self.credentials.load().get("active_provider")
        options = []
        for provider in PROVIDERS:
            state = " · active" if provider.id == active else " · saved" if provider.id in configured else ""
            options.append(f"{provider.name}{state}")
        self.query_one("#provider-dialog-title", Static).update("CONNECT A PROVIDER")
        self.query_one("#provider-dialog-detail", Static).update(
            "Choose a provider to save its own key and model. Other provider setups stay saved."
        )
        self.query_one("#provider-dialog-list", OptionList).clear_options()
        self.query_one("#provider-dialog-list", OptionList).add_options(options)
        self.query_one("#provider-dialog-list", OptionList).focus()

    async def _choose_provider(self, index: int) -> None:
        spec = PROVIDERS[index]
        saved = self.credentials.profile_for(spec.id)
        self.pending_profile = dict(saved) if saved else {
            "provider_id": spec.id,
            "base_url": spec.base_url,
            "model": "",
            "api_key": "",
            "protocol": spec.protocol,
        }
        self.key_prompted = False
        self.endpoint_prompted = False
        self._continue_connect()

    def _continue_connect(self) -> None:
        profile = self.pending_profile
        if profile is None:
            return
        provider_id = str(profile["provider_id"])
        spec = PROVIDER_BY_ID[provider_id]
        if provider_id == "custom" and not self.endpoint_prompted:
            self.endpoint_prompted = True
            self._request_input(
                "base_url",
                "CUSTOM ENDPOINT",
                "Enter the endpoint base URL.",
                "https://host.example/v1",
                initial_value=str(profile.get("base_url", "")),
            )
            return
        if spec.requires_api_key and not self.key_prompted:
            self.key_prompted = True
            detail = f"Please input your API key for {spec.name}."
            if profile.get("api_key"):
                detail = "API key already set. Leave empty to keep it unchanged, or enter a replacement."
            self._request_input("api_key", f"{spec.name.upper()} API KEY", detail, "Paste API key", True)
            return
        if provider_id == "custom" and not self.key_prompted:
            self.key_prompted = True
            detail = "Please set your custom endpoint API key (if applicable)."
            if profile.get("api_key"):
                detail = "API key already set. Leave empty to keep it unchanged, or enter a replacement."
            self._request_input("api_key", "CUSTOM API KEY", detail, "API key (optional)", True)
            return
        if provider_id == "litellm" and not self.key_prompted:
            self.key_prompted = True
            detail = (
                "Optional. LiteLLM reads each provider's own credentials (ANTHROPIC_API_KEY, AWS, Google ADC). "
                "Enter a key only to override them."
            )
            if profile.get("api_key"):
                detail = "API key already set. Leave empty to keep it unchanged, or enter a replacement."
            self._request_input("api_key", "LITELLM API KEY", detail, "API key (optional)", True)
            return
        if provider_id == "litellm":
            self._request_input(
                "model_name",
                "LITELLM MODEL",
                "Enter a LiteLLM provider/model ID, e.g. anthropic/claude-sonnet-4-6 or vertex_ai/gemini-2.5-flash.",
                "provider/model",
                initial_value=str(profile.get("model", "")),
            )
            return
        if provider_id == "cloudflare" and not self._has_cloudflare_account(str(profile.get("base_url", ""))):
            self._request_input("account_id", "CLOUDFLARE ACCOUNT", "Enter the account ID for Workers AI.", "Account ID")
            return
        if provider_id == "custom":
            self._request_input("model_name", "MODEL NAME", "Enter the model ID exactly as the endpoint expects it.", "Model ID")
            return
        self.run_worker(self._load_provider_models(), name="provider-dialog-models", exclusive=True)

    def _request_input(
        self,
        stage: str,
        title: str,
        prompt: str,
        placeholder: str,
        secret: bool = False,
        initial_value: str = "",
    ) -> None:
        self.stage = stage
        self.query_one("#provider-dialog-title", Static).update(title)
        self.query_one("#provider-dialog-detail", Static).update(prompt)
        listing = self.query_one("#provider-dialog-list", OptionList)
        listing.clear_options()
        listing.display = False
        field = self.query_one("#provider-dialog-input", Input)
        field.display = True
        field.password = secret
        field.placeholder = placeholder
        field.value = "" if secret else initial_value
        field.focus()

    async def _load_provider_models(self) -> None:
        profile = self.pending_profile
        if profile is None:
            return
        spec = PROVIDER_BY_ID[str(profile["provider_id"])]
        self.stage = "retry_provider_models"
        self.query_one("#provider-dialog-title", Static).update(f"{spec.name.upper()} MODELS")
        self.query_one("#provider-dialog-detail", Static).update(f"Loading models from {spec.name}…")
        try:
            models = await asyncio.to_thread(list_models, profile)
        except ProviderRequestError as error:
            self._show_retry(str(error), "retry_provider_models")
            return
        self._show_models([(profile, model) for model in models], f"Choose a model from {spec.name}.")

    async def _load_all_models(self) -> None:
        profiles = self.credentials.configured_profiles()
        self.stage = "model_list"
        self.query_one("#provider-dialog-title", Static).update("CHOOSE A MODEL")
        if not profiles:
            self._show_retry("No providers are configured yet. Use /connect to add one.", "retry_models")
            return
        self.query_one("#provider-dialog-detail", Static).update("Loading models from every configured provider…")
        results = await asyncio.gather(
            *(asyncio.to_thread(list_models, profile) for profile in profiles),
            return_exceptions=True,
        )
        choices = []
        errors = []
        for profile, result in zip(profiles, results):
            if isinstance(result, BaseException):
                errors.append(f"{PROVIDER_BY_ID[str(profile['provider_id'])].name}: {result}")
                continue
            choices.extend((profile, model) for model in result)
        detail = "Choose a provider/model with ↑ / ↓ and Enter."
        if errors:
            detail += " Unavailable: " + " · ".join(errors)
        if choices:
            self._show_models(choices, detail)
        else:
            self._show_retry(detail, "retry_models")

    def _show_models(self, choices: list[tuple[dict, str]], detail: str) -> None:
        self.stage = "model_list"
        self.model_choices = choices
        options = []
        current = self.credentials.load().get("active_provider")
        active_profile = self.credentials.active() or {}
        for profile, model in choices:
            name = PROVIDER_BY_ID[str(profile["provider_id"])].name
            active = "› " if profile["provider_id"] == current and model == active_profile.get("model") else "  "
            options.append(f"{active}{name}  ·  {model}")
        self.query_one("#provider-dialog-title", Static).update("CHOOSE A MODEL")
        self.query_one("#provider-dialog-detail", Static).update(detail)
        listing = self.query_one("#provider-dialog-list", OptionList)
        listing.clear_options()
        listing.add_options(options)
        listing.display = True
        self.query_one("#provider-dialog-input", Input).display = False
        listing.focus()

    def _show_retry(self, detail: str, stage: str) -> None:
        self.stage = stage
        self.model_choices = []
        self.query_one("#provider-dialog-detail", Static).update(detail)
        listing = self.query_one("#provider-dialog-list", OptionList)
        listing.clear_options()
        listing.add_option("↻  TRY AGAIN")
        listing.display = True
        listing.focus()

    async def _save_selection(self, profile: dict, model: str) -> None:
        selected = dict(profile)
        if model != str(profile.get("model", "")):
            selected["reasoning_enabled"] = None
            selected["reasoning_parameter"] = ""
            selected["reasoning_effort"] = "medium"
        selected["model"] = model
        if not isinstance(selected.get("reasoning_enabled"), bool):
            self.query_one("#provider-dialog-detail", Static).update("Checking model reasoning support…")
            try:
                await asyncio.to_thread(apply_reasoning_default, selected)
            except ProviderRequestError:
                pass
        try:
            self.credentials.save_profile(selected)
        except OSError as error:
            self.query_one("#provider-dialog-detail", Static).update(f"Could not save provider: {error}")
            return
        self.dismiss(self.credentials.active() or selected)

    @staticmethod
    def _valid_endpoint(value: str) -> bool:
        try:
            parsed = urlsplit(value)
            return (
                parsed.scheme in {"http", "https"}
                and parsed.hostname is not None
                and parsed.username is None
                and parsed.password is None
                and not parsed.query
                and not parsed.fragment
                and (parsed.port is None or 1 <= parsed.port <= 65535)
            )
        except ValueError:
            return False

    @staticmethod
    def _has_cloudflare_account(base_url: str) -> bool:
        return re.search(r"/accounts/[A-Fa-f0-9]{32}/", base_url) is not None
