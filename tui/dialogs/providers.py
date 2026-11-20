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
from mitsu.providers import ProviderRequestError, apply_reasoning_default, list_models, test_connection
from mitsu.providers import codex_cli


class ProviderDialog(ModalScreen[dict | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel", priority=True)]

    def __init__(self, credentials: CredentialStore, action: str) -> None:
        super().__init__()
        self.credentials = credentials
        self.dialog_kind = action if action in {"connect", "model"} else "model"
        self.stage = "provider_list" if self.dialog_kind == "connect" else "model_list"
        self.pending_profile: dict | None = None
        self.model_choices: list[tuple[dict, str]] = []
        self.all_model_choices: list[tuple[dict, str]] = []
        self.key_prompted = False
        self.endpoint_prompted = False
        self.auth_method_prompted = False

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
        elif self.stage == "auth_method":
            await self._choose_auth_method(event.option_index)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "provider-dialog-input" and self.stage == "model_list":
            event.stop()
            listing = self.query_one("#provider-dialog-list", OptionList)
            index = listing.highlighted
            if index is not None and 0 <= index < len(self.model_choices):
                profile, model = self.model_choices[index]
                await self._save_selection(profile, model)
            return
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
            profile["auth_method"] = "api_key"
            profile["access_token"] = ""
            profile["refresh_token"] = ""
            profile["expires_at"] = 0
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
        self.query_one("#provider-dialog-input", Input).display = False
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
        self.auth_method_prompted = False
        self._continue_connect()

    def _continue_connect(self) -> None:
        profile = self.pending_profile
        if profile is None:
            return
        provider_id = str(profile["provider_id"])
        spec = PROVIDER_BY_ID[provider_id]
        if provider_id in {"anthropic", "openai"} and not self.auth_method_prompted:
            self.auth_method_prompted = True
            self.stage = "auth_method"
            name = "Anthropic" if provider_id == "anthropic" else "OpenAI"
            self.query_one("#provider-dialog-title", Static).update(f"{name.upper()} SIGN-IN")
            self.query_one("#provider-dialog-detail", Static).update(f"Choose how to connect {name}.")
            listing = self.query_one("#provider-dialog-list", OptionList)
            listing.clear_options()
            listing.add_options(["Sign in with account", "Sign in with API key"])
            listing.display = True
            listing.focus()
            return
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
        if spec.requires_api_key and profile.get("auth_method") not in {"account", "claude_code", "codex_cli"} and not self.key_prompted:
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
        if provider_id == "amazon_bedrock":
            self._request_input(
                "model_name",
                "AMAZON BEDROCK MODEL",
                "Enter a LiteLLM Bedrock model ID (bedrock/<model-or-inference-profile-id>). Install Mitsu's litellm extra and configure AWS credentials and region locally.",
                "bedrock/model-id",
                initial_value=str(profile.get("model", "")),
            )
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
        if provider_id in {"zai", "mistral", "fireworks"}:
            provider_name = PROVIDER_BY_ID[provider_id].name
            examples = {
                "zai": "glm-4.6",
                "mistral": "mistral-small-latest",
                "fireworks": "accounts/fireworks/models/llama-v3p1-8b-instruct",
            }
            self._request_input(
                "model_name",
                f"{provider_name.upper()} MODEL",
                f"Enter a {provider_name} model ID, such as {examples[provider_id]}, from its model catalog.",
                "Model ID",
                initial_value=str(profile.get("model", "")),
            )
            return
        if provider_id == "vercel_gateway":
            self._request_input(
                "model_name",
                "VERCEL AI GATEWAY MODEL",
                "Enter a provider/model ID from the Vercel AI Gateway model catalog, such as openai/gpt-5.4.",
                "provider/model",
                initial_value=str(profile.get("model", "")),
            )
            return
        if provider_id == "ollama_cloud":
            self._request_input(
                "model_name",
                "OLLAMA CLOUD MODEL",
                "Enter an Ollama cloud model ID. Choose a model that supports tool calling for Mitsu agent actions.",
                "Model ID",
                initial_value=str(profile.get("model", "")),
            )
            return
        if provider_id == "custom":
            self._request_input("model_name", "MODEL NAME", "Enter the model ID exactly as the endpoint expects it.", "Model ID")
            return
        self.run_worker(self._load_provider_models(), name="provider-dialog-models", exclusive=True)

    async def _choose_auth_method(self, index: int) -> None:
        profile = self.pending_profile
        if profile is None:
            return
        listing = self.query_one("#provider-dialog-list", OptionList)
        listing.display = False
        provider_id = str(profile.get("provider_id"))
        if provider_id == "openai":
            if index == 0:
                profile["auth_method"] = "codex_cli"
                profile["model"] = "default"
                profile["api_key"] = ""
                for key in (
                    "access_token", "refresh_token", "expires_at", "id_token", "client_id",
                    "host_id", "subject", "email", "scopes", "nonce",
                ):
                    profile[key] = 0 if key == "expires_at" else ""
                self.stage = "codex_cli"
                self.query_one("#provider-dialog-title", Static).update("OPENAI ACCOUNT SIGN-IN")
                self.query_one("#provider-dialog-detail", Static).update(
                    "Verifying Codex CLI account sign-in and model access…"
                )
                self.run_worker(self._finish_codex_login(), name="provider-dialog-openai-account", exclusive=True)
                return
        elif provider_id == "anthropic" and index == 0:
            profile["auth_method"] = "claude_code"
            profile["model"] = str(profile.get("model") or "opus")
            profile["api_key"] = ""
            for key in ("access_token", "refresh_token", "expires_at", "id_token"):
                profile[key] = 0 if key == "expires_at" else ""
            self.query_one("#provider-dialog-title", Static).update("VERIFYING CLAUDE CODE")
            self.query_one("#provider-dialog-detail", Static).update(
                "Checking the Claude Code binary, account login, and Opus model reply…"
            )
            try:
                await asyncio.to_thread(test_connection, profile)
            except ProviderRequestError as error:
                self.stage = "auth_method"
                self.auth_method_prompted = False
                self.query_one("#provider-dialog-title", Static).update("CLAUDE CODE ACCOUNT")
                self.query_one("#provider-dialog-detail", Static).update(str(error))
                listing.clear_options()
                listing.add_options(["Check Claude Code again", "Use API key"])
                listing.display = True
                listing.focus()
                return
            self.auth_method_prompted = True
            self._continue_connect()
            return
        profile["auth_method"] = "api_key"
        self.auth_method_prompted = True
        for key in ("access_token", "refresh_token", "expires_at", "id_token"):
            profile[key] = 0 if key == "expires_at" else ""
        self.key_prompted = False
        self._continue_connect()

    async def _finish_codex_login(self) -> None:
        profile = self.pending_profile
        if profile is None:
            return
        try:
            await asyncio.to_thread(codex_cli.sign_in)
        except ProviderRequestError as error:
            self.stage = "auth_method"
            self.query_one("#provider-dialog-title", Static).update("OPENAI ACCOUNT SIGN-IN")
            self.query_one("#provider-dialog-detail", Static).update(str(error))
            listing = self.query_one("#provider-dialog-list", OptionList)
            listing.clear_options()
            listing.add_options(["Try account sign-in again", "Use API key"])
            listing.display = True
            listing.focus()
            return
        self.query_one("#provider-dialog-title", Static).update("VERIFYING OPENAI ACCOUNT")
        self.query_one("#provider-dialog-detail", Static).update(
            "Checking that Mitsu can receive a model reply from this account…"
        )
        try:
            await asyncio.to_thread(test_connection, profile)
        except ProviderRequestError as error:
            self.stage = "auth_method"
            self.query_one("#provider-dialog-title", Static).update("OPENAI ACCOUNT SIGN-IN")
            self.query_one("#provider-dialog-detail", Static).update(
                f"Account sign-in completed, but model verification failed:\n{error}"
            )
            listing = self.query_one("#provider-dialog-list", OptionList)
            listing.clear_options()
            listing.add_options(["Try account sign-in again", "Use API key"])
            listing.display = True
            listing.focus()
            return
        self.auth_method_prompted = True
        self._continue_connect()

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
        self.query_one("#provider-dialog-input", Input).display = False
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
        self.query_one("#provider-dialog-input", Input).display = False
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
        self.query_one("#provider-dialog-input", Input).display = False
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
        self.all_model_choices = choices
        current = self.credentials.load().get("active_provider")
        active_profile = self.credentials.active() or {}
        self.query_one("#provider-dialog-title", Static).update("CHOOSE A MODEL")
        self.query_one("#provider-dialog-detail", Static).update(detail)
        search = self.query_one("#provider-dialog-input", Input)
        search.value = ""
        search.password = False
        search.placeholder = "Filter providers and models"
        search.display = True
        listing = self.query_one("#provider-dialog-list", OptionList)
        listing.display = True
        listing.styles.max_height = 8
        self.query_one("#provider-dialog-hint", Static).update(
            "Type to filter    Tab to browse    ↑ / ↓ choose    Enter select    Esc close"
        )
        self._filter_models(search.value, current, active_profile)
        search.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "provider-dialog-input" and self.stage == "model_list":
            current = self.credentials.load().get("active_provider")
            active_profile = self.credentials.active() or {}
            self._filter_models(event.value, current, active_profile)

    def _filter_models(
        self,
        query: str,
        current_provider: str | None = None,
        active_profile: dict | None = None,
    ) -> None:
        normalized = query.casefold().strip()
        active_profile = active_profile or {}
        self.model_choices = [
            (profile, model)
            for profile, model in self.all_model_choices
            if not normalized
            or normalized in model.casefold()
            or normalized in PROVIDER_BY_ID[str(profile["provider_id"])].name.casefold()
        ]
        listing = self.query_one("#provider-dialog-list", OptionList)
        listing.clear_options()
        options = []
        for profile, model in self.model_choices:
            name = PROVIDER_BY_ID[str(profile["provider_id"])].name
            active = "› " if profile["provider_id"] == current_provider and model == active_profile.get("model") else "  "
            options.append(f"{active}{name}  ·  {model}")
        listing.add_options(options or ["No matching models"])
        if options:
            listing.highlighted = next(
                (
                    index
                    for index, (profile, model) in enumerate(self.model_choices)
                    if not normalized
                    and profile["provider_id"] == current_provider
                    and model == active_profile.get("model")
                ),
                0,
            )

    def _show_retry(self, detail: str, stage: str) -> None:
        self.stage = stage
        self.model_choices = []
        self.all_model_choices = []
        self.query_one("#provider-dialog-input", Input).display = False
        self.query_one("#provider-dialog-hint", Static).update("↑ / ↓ move    Enter select    Esc close")
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
        if selected.get("provider_id") == "anthropic" and selected.get("auth_method") == "claude_code":
            self.query_one("#provider-dialog-detail", Static).update(
                f"Verifying Claude Code account and {model} response before saving…"
            )
            try:
                await asyncio.to_thread(test_connection, selected)
            except ProviderRequestError as error:
                self.query_one("#provider-dialog-detail", Static).update(
                    f"The selected Claude model did not pass verification:\n{error}"
                )
                return
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
