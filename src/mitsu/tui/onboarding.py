from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Input, OptionList, Static

from mitsu.companions import COMPANIONS, companion_by_id
from mitsu.config import PROVIDERS, PROVIDER_BY_ID, THEMES, CredentialStore, PreferencesStore
from mitsu.providers import ProviderRequestError, list_models
from mitsu.tui.branding import MOON_YELLOW
from mitsu.tui.dialogs import SearchEnginePanel
from mitsu.tui.widgets import CityScene, MitsuCompanion, MoonScene


class OnboardingScreen(Screen):
    BINDINGS = [
        Binding("escape", "back_step", "Back"),
        Binding("enter", "continue_setup", "Continue setup"),
        Binding("left", "wizard_left", "Previous step", priority=True),
        Binding("right", "wizard_right", "Next step", priority=True),
    ]

    def __init__(
        self,
        credentials: CredentialStore,
        preferences: PreferencesStore,
        configuration_mode: str | None = None,
    ) -> None:
        super().__init__()
        self.credentials = credentials
        self.preferences = preferences
        self.configuration_mode = configuration_mode if configuration_mode in {"provider", "model"} else None
        self.credential_data = credentials.load()
        self.saved_profiles = self.credential_data.get("providers", {})
        if not isinstance(self.saved_profiles, dict):
            self.saved_profiles = {}
        active_provider = self.credential_data.get("active_provider")
        self.provider_id = active_provider if active_provider in PROVIDER_BY_ID else PROVIDERS[0].id
        self.profile = self._saved_profile(self.provider_id)
        self.provider_confirmed = self.configuration_mode == "model"
        self.protocol_id = str(self.profile.get("protocol", PROVIDER_BY_ID[self.provider_id].protocol))
        self.base_url = str(self.profile.get("base_url", PROVIDER_BY_ID[self.provider_id].base_url) or "")
        self.api_key = ""
        self.model_id = str(self.profile.get("model", "") or "")
        self.cloudflare_account_id = self._account_id(self.base_url)
        self.model_options: list[str] = []
        self.loading_models = False
        self.preferences_data = preferences.load()
        self.theme_id = self.preferences_data.get("theme", "ember")
        self.companion_id = self.preferences_data.get("companion", "mitsu")
        if self.companion_id not in {companion.id for companion in COMPANIONS}:
            self.companion_id = "mitsu"
        if self.theme_id not in THEMES:
            self.theme_id = "ember"
        self.steps = self._steps()
        self.step_index = 0

    def compose(self) -> ComposeResult:
        city = CityScene(accent=THEMES[self.theme_id]["accent"], id="wizard-city")
        mascot = MitsuCompanion(
            sprite_path=companion_by_id(self.companion_id).path,
            animation_interval=1 / 6,
            kitty_anchor=city,
            kitty_offset=(4, 2),
            scene_overlay=True,
            id="wizard-mascot",
        )
        city.set_companion(mascot, (4, 2))
        with Vertical(id="wizard-shell", classes=f"theme-{self.theme_id}"):
            with Vertical(id="wizard-masthead"):
                yield MoonScene(accent=MOON_YELLOW, show_brand=True, id="wizard-moon")
                with Vertical(id="wizard-landscape"):
                    yield city
                    yield mascot
            with VerticalScroll(id="wizard-pages"):
                with Vertical(id="wizard-page-welcome", classes="wizard-page"):
                    yield Static("Welcome to Mitsu   *       .       *", id="welcome-eyebrow", markup=False)
                    yield Static("Let’s get your workspace set up", classes="wizard-title", markup=False)
                    yield Static(
                        "Just a few settings, then you’re ready to start.",
                        classes="wizard-copy",
                        markup=False,
                    )
                    yield Static(
                        "›  Press Enter or → to begin",
                        id="welcome-prompt",
                        markup=False,
                    )
                with Vertical(id="wizard-page-provider", classes="wizard-page"):
                    yield Static("CHOOSE YOUR PROVIDER", classes="wizard-title", markup=False)
                    yield Static(
                        "Pick a provider to continue. Use the arrow keys, then press Enter.",
                        classes="wizard-copy",
                        markup=False,
                    )
                    yield OptionList(
                        *(provider.name for provider in PROVIDERS),
                        id="provider-list",
                        compact=True,
                    )
                    yield Static("Your key stays in Mitsu's private user config.", classes="wizard-note", markup=False)
                with Vertical(id="wizard-page-custom-url", classes="wizard-page"):
                    yield Static("CUSTOM ENDPOINT", classes="wizard-title", markup=False)
                    yield Static("Enter the base URL, then choose its API style.", classes="wizard-copy", markup=False)
                    yield Static("Base URL", classes="field-label", markup=False)
                    yield Input(placeholder="https://your-endpoint.example/v1", id="custom-base-url")
                    yield Static("API style", classes="field-label", markup=False)
                    yield OptionList("OpenAI-compatible", "Anthropic-compatible", id="protocol-list", compact=True)
                with Vertical(id="wizard-page-api-key", classes="wizard-page"):
                    yield Static("PROVIDER KEY", id="provider-key-title", classes="wizard-title", markup=False)
                    yield Static("", id="provider-key-prompt", classes="wizard-copy", markup=False)
                    yield Input(placeholder="Paste API key", password=True, id="provider-api-key")
                    yield Static("", id="provider-key-note", classes="wizard-note", markup=False)
                with Vertical(id="wizard-page-cloudflare-account", classes="wizard-page"):
                    yield Static("CLOUDFLARE ACCOUNT", classes="wizard-title", markup=False)
                    yield Static("Enter the account ID used by your Workers AI endpoint.", classes="wizard-copy", markup=False)
                    yield Input(placeholder="Cloudflare account ID", id="cloudflare-account-id")
                with Vertical(id="wizard-page-models", classes="wizard-page"):
                    yield Static("CHOOSE A MODEL", classes="wizard-title", markup=False)
                    yield Static("Available models from this provider. Select one with Enter.", classes="wizard-copy", markup=False)
                    yield OptionList(id="model-list", compact=True)
                with Vertical(id="wizard-page-custom-model", classes="wizard-page"):
                    yield Static("MODEL NAME", classes="wizard-title", markup=False)
                    yield Static("Enter the model ID exactly as your endpoint expects it.", classes="wizard-copy", markup=False)
                    yield Input(placeholder="Provider model ID", id="custom-model-name")
                with Vertical(id="wizard-page-search", classes="wizard-page"):
                    yield SearchEnginePanel(
                        self.credentials,
                        onboarding=True,
                        on_finish=self._search_engine_page_finished,
                        id="wizard-search-engines",
                    )
                with Vertical(id="wizard-page-style", classes="wizard-page"):
                    yield Static("PICK YOUR COLORS", classes="wizard-title", markup=False)
                    yield Static("Choose the glow for your command center.", classes="wizard-copy", markup=False)
                    with Horizontal(id="theme-layout"):
                        yield OptionList(*(theme["name"] for theme in THEMES.values()), id="theme-list", compact=True)
                        yield Static(
                            "",
                            id="theme-preview",
                            classes="theme-sample",
                        )
                with Vertical(id="wizard-page-companion", classes="wizard-page"):
                    yield Static("PICK YOUR LITTLE PARTNER", classes="wizard-title", markup=False)
                    yield Static("↑ / ↓ to browse    Enter to choose", classes="wizard-copy", markup=False)
                    yield OptionList(
                        *(companion.name for companion in COMPANIONS),
                        id="companion-list",
                        compact=True,
                    )
            yield Static("", id="wizard-status", markup=False)
            yield Static("", id="wizard-controls", markup=False)
            yield Static("made by: @arcangel0", id="wizard-credit", markup=False)

    def on_mount(self) -> None:
        self.query_one("#provider-list", OptionList).highlighted = next(
            (index for index, provider in enumerate(PROVIDERS) if provider.id == self.provider_id), 0
        )
        self.query_one("#theme-list", OptionList).highlighted = next(
            (index for index, theme_id in enumerate(THEMES) if theme_id == self.theme_id), 0
        )
        self.query_one("#companion-list", OptionList).highlighted = next(
            (index for index, companion in enumerate(COMPANIONS) if companion.id == self.companion_id), 0
        )
        self.query_one("#protocol-list", OptionList).highlighted = 1 if self.protocol_id == "anthropic" else 0
        self.query_one("#custom-base-url", Input).value = self.base_url if self.provider_id == "custom" else ""
        self.query_one("#custom-model-name", Input).value = self.model_id if self.provider_id == "custom" else ""
        self.query_one("#cloudflare-account-id", Input).value = self.cloudflare_account_id
        saved_key = str(self.profile.get("api_key", "") or "")
        self.query_one("#provider-api-key", Input).placeholder = "Saved key will be kept" if saved_key else "Paste API key"
        self._update_provider_key_title()
        self._show_companion()
        self._show_step()
        self._apply_theme()
        self.query_one(MitsuCompanion).set_state("running_right")
