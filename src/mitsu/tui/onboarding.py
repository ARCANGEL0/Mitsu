from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import ScreenResume, ScreenSuspend
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

    def on_screen_suspend(self, _event: ScreenSuspend) -> None:
        for mascot in self.query(MitsuCompanion):
            mascot.set_modal_suspended(True)

    def on_screen_resume(self, _event: ScreenResume) -> None:
        for mascot in self.query(MitsuCompanion):
            mascot.set_modal_suspended(False)

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_index is None:
            return
        if event.option_list.id == "provider-list" and self.stage == "provider":
            self._change_provider(PROVIDERS[event.option_index].id)
        elif event.option_list.id == "protocol-list":
            self.protocol_id = "anthropic" if event.option_index == 1 else "openai"
        elif event.option_list.id == "theme-list":
            self._select_theme(event.option_index)
        elif event.option_list.id == "companion-list":
            self._select_companion(event.option_index)

    async def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        list_id = event.option_list.id
        if list_id == "provider-list":
            self._select_provider(event.option_index)
        elif list_id == "protocol-list":
            self.protocol_id = "anthropic" if event.option_index == 1 else "openai"
            self._go_to("api_key")
        elif list_id == "model-list":
            if self.loading_models:
                return
            await self._select_model(event.option_index)
        elif list_id == "theme-list":
            self._select_theme(event.option_index)
            self._go_to("companion")
        elif list_id == "companion-list":
            self._select_companion(event.option_index)
            await self._finish_setup()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "custom-base-url" and self.stage == "custom_url":
            base_url = event.value.strip().rstrip("/")
            if not self._valid_base_url(base_url):
                self._set_status("Enter a complete http:// or https:// base URL.")
                return
            self.base_url = base_url
            self.query_one("#protocol-list", OptionList).focus()
        elif event.input.id == "provider-api-key" and self.stage == "api_key":
            await self._submit_api_key(event.value.strip())
        elif event.input.id == "cloudflare-account-id" and self.stage == "cloudflare_account":
            account_id = event.value.strip()
            if not re.fullmatch(r"[A-Fa-f0-9]{32}", account_id):
                self._set_status("Enter the 32-character Cloudflare account ID.")
                return
            self.cloudflare_account_id = account_id
            self.base_url = PROVIDER_BY_ID["cloudflare"].base_url.format(account_id=account_id)
            await self._fetch_models()
        elif event.input.id == "custom-model-name" and self.stage == "custom_model":
            await self._accept_custom_model(event.value)

    async def action_back_step(self) -> None:
        if self.step_index > 0:
            self.step_index -= 1
            self._show_step()
        elif self.configuration_mode is not None:
            await self.app.open_menu()

    async def action_wizard_left(self) -> None:
        focused = self.app.focused
        if isinstance(focused, Input):
            if self.stage == "search":
                panel = self.query_one("#wizard-search-engines", SearchEnginePanel)
                if panel.stage != "list":
                    focused.action_cursor_left()
                    return
            if focused.cursor_position > 0:
                focused.action_cursor_left()
                return
        if self.stage == "search":
            panel = self.query_one("#wizard-search-engines", SearchEnginePanel)
            if panel.stage == "list":
                panel._finish(False)
            return
        await self.action_back_step()

    async def action_wizard_right(self) -> None:
        focused = self.app.focused
        if isinstance(focused, Input):
            if self.stage == "search":
                panel = self.query_one("#wizard-search-engines", SearchEnginePanel)
                if panel.stage != "list":
                    focused.action_cursor_right()
                    return
            if focused.cursor_position < len(focused.value):
                focused.action_cursor_right()
                return
        if self.stage == "search":
            panel = self.query_one("#wizard-search-engines", SearchEnginePanel)
            if panel.stage == "list":
                panel._save_and_close()
            return
        await self._advance_step()

    def action_continue_setup(self) -> None:
        if self.stage == "welcome":
            self._go_to("provider")

    async def _advance_step(self) -> None:
        if self.stage == "welcome":
            self._go_to("provider")
        elif self.stage == "provider":
            selected = self.query_one("#provider-list", OptionList).highlighted
            self._select_provider(selected if selected is not None else 0)
        elif self.stage == "custom_url":
            base_input = self.query_one("#custom-base-url", Input)
            if self.app.focused is base_input:
                base_url = base_input.value.strip().rstrip("/")
                if not self._valid_base_url(base_url):
                    self._set_status("Enter a complete http:// or https:// base URL.")
                    return
                self.base_url = base_url
                self.query_one("#protocol-list", OptionList).focus()
                return
            selected = self.query_one("#protocol-list", OptionList).highlighted
            self.protocol_id = "anthropic" if selected == 1 else "openai"
            self._go_to("api_key")
        elif self.stage == "api_key":
            await self._submit_api_key(self.query_one("#provider-api-key", Input).value.strip())
        elif self.stage == "cloudflare_account":
            field = self.query_one("#cloudflare-account-id", Input)
            account_id = field.value.strip()
            if not re.fullmatch(r"[A-Fa-f0-9]{32}", account_id):
                self._set_status("Enter the 32-character Cloudflare account ID.")
                return
            self.cloudflare_account_id = account_id
            self.base_url = PROVIDER_BY_ID["cloudflare"].base_url.format(account_id=account_id)
            await self._fetch_models()
        elif self.stage == "models":
            if self.loading_models:
                return
            highlighted = self.query_one("#model-list", OptionList).highlighted
            if not self.model_options:
                self._go_to("api_key")
            elif highlighted is not None:
                await self._select_model(highlighted)
        elif self.stage == "custom_model":
            await self._accept_custom_model(self.query_one("#custom-model-name", Input).value)
        elif self.stage == "style":
            highlighted = self.query_one("#theme-list", OptionList).highlighted
            self._select_theme(highlighted if highlighted is not None else 0)
            self._go_to("companion")
        elif self.stage == "companion":
            highlighted = self.query_one("#companion-list", OptionList).highlighted
            self._select_companion(highlighted if highlighted is not None else 0)
            await self._finish_setup()

    async def _select_model(self, index: int | None) -> None:
        if not self.model_options:
            self._go_to("api_key")
            return
        if index is None or not 0 <= index < len(self.model_options):
            return
        self.model_id = self.model_options[index]
        if self.configuration_mode:
            await self._finish_setup()
        else:
            self._open_search_engine_setup()

    async def _accept_custom_model(self, value: str) -> None:
        self.model_id = value.strip()
        if not self.model_id:
            self._set_status("Enter the model ID used by your endpoint.")
            return
        if self.configuration_mode:
            await self._finish_setup()
        else:
            self._open_search_engine_setup()

    async def _submit_api_key(self, entered_key: str) -> None:
        spec = PROVIDER_BY_ID[self.provider_id]
        saved_key = str(self.profile.get("api_key", "") or "")
        self.api_key = entered_key or saved_key
        if spec.requires_api_key and not self.api_key:
            self._set_status("This provider needs an API key to load its models.")
            return
        if self.provider_id == "custom":
            self._go_to("custom_model")
        elif self.provider_id == "cloudflare":
            self._go_to("cloudflare_account")
        else:
            await self._fetch_models()

    async def _fetch_models(self) -> None:
        self.loading_models = True
        self.model_options = []
        option_list = self.query_one("#model-list", OptionList)
        option_list.clear_options()
        option_list.add_option("Loading provider models...")
        self._go_to("models")
        profile = {
            "provider_id": self.provider_id,
            "base_url": self.base_url,
            "api_key": self.api_key,
            "protocol": self.protocol_id if self.provider_id == "custom" else PROVIDER_BY_ID[self.provider_id].protocol,
        }
        try:
            models = await asyncio.to_thread(list_models, profile)
        except ProviderRequestError as error:
            self.loading_models = False
            option_list.clear_options()
            option_list.add_option("Return to provider key")
            self._set_status(str(error))
            option_list.focus()
            return
        self.loading_models = False
        self.model_options = models
        option_list.clear_options()
        option_list.add_options(models)
        option_list.highlighted = next((index for index, model in enumerate(models) if model == self.model_id), 0)
        self._set_status(f"{len(models)} models available | Up/Down browse | Enter select")
        option_list.focus()

    async def _finish_setup(self) -> None:
        if not self.provider_confirmed or not self.model_id:
            self._set_status("Choose a provider and model before finishing setup.")
            return
        try:
            self.credentials.save_profile(
                {
                    "provider_id": self.provider_id,
                    "base_url": self.base_url,
                    "model": self.model_id,
                    "api_key": self.api_key,
                    "protocol": self.protocol_id if self.provider_id == "custom" else PROVIDER_BY_ID[self.provider_id].protocol,
                }
            )
            if self.configuration_mode is None:
                self.preferences.save(
                    {
                        "theme": self.theme_id,
                        "companion": self.companion_id,
                        "onboarding_complete": True,
                    }
                )
        except OSError as error:
            self._set_status(f"Could not save setup: {error}")
            return
        self.query_one("#wizard-mascot", MitsuCompanion).clear_terminal_graphics()
        await self.app.finish_setup()

    def _open_search_engine_setup(self) -> None:
        self._go_to("search")

    def _search_engine_page_finished(self, saved: bool) -> None:
        if saved:
            self._go_to("style")
        elif self.step_index > 0:
            self.step_index -= 1
            self._show_step()

    def _select_provider(self, index: int) -> None:
        self._change_provider(PROVIDERS[index].id)
        self.provider_confirmed = True
        self._rebuild_steps()
        self._go_to(self.steps[self.step_index + 1])

    def _change_provider(self, provider_id: str) -> None:
        if provider_id == self.provider_id:
            return
        self.provider_id = provider_id
        self.profile = self._saved_profile(provider_id)
        spec = PROVIDER_BY_ID[provider_id]
        self.protocol_id = str(self.profile.get("protocol", spec.protocol))
        self.base_url = str(self.profile.get("base_url", spec.base_url) or "")
        self.model_id = str(self.profile.get("model", "") or "")
        self.api_key = ""
        self.cloudflare_account_id = self._account_id(self.base_url)
        if self.is_mounted:
            self._update_provider_key_title()
            self.query_one("#provider-api-key", Input).value = ""
            self.query_one("#provider-api-key", Input).placeholder = (
                "Saved key will be kept" if self.profile.get("api_key") else "Paste API key"
            )
            self.query_one("#custom-base-url", Input).value = self.base_url if provider_id == "custom" else ""
            self.query_one("#custom-model-name", Input).value = self.model_id if provider_id == "custom" else ""
            self.query_one("#cloudflare-account-id", Input).value = self.cloudflare_account_id
            self.query_one("#protocol-list", OptionList).highlighted = 1 if self.protocol_id == "anthropic" else 0

    def _select_theme(self, index: int) -> None:
        self.theme_id = tuple(THEMES)[index]
        self._apply_theme()

    def _select_companion(self, index: int) -> None:
        self.companion_id = COMPANIONS[index].id
        self._show_companion()

    def _steps(self) -> list[str]:
        if self.configuration_mode == "model":
            steps = ["api_key"]
            if self.provider_id == "custom":
                steps.append("custom_model")
            elif self.provider_id == "cloudflare":
                steps.extend(("cloudflare_account", "models"))
            else:
                steps.append("models")
            return steps
        if self.configuration_mode == "provider":
            steps = ["provider"]
            if self.provider_id == "custom":
                steps.extend(("custom_url", "api_key", "custom_model"))
            else:
                steps.append("api_key")
                if self.provider_id == "cloudflare":
                    steps.append("cloudflare_account")
                steps.append("models")
            return steps
        steps = ["welcome", "provider"]
        if self.provider_id == "custom":
            steps.extend(("custom_url", "api_key", "custom_model"))
        else:
            steps.append("api_key")
            if self.provider_id == "cloudflare":
                steps.append("cloudflare_account")
            steps.append("models")
        steps.extend(("search", "style", "companion"))
        return steps

    def _rebuild_steps(self) -> None:
        current = self.stage
        self.steps = self._steps()
        self.step_index = self.steps.index(current) if current in self.steps else self.steps.index("provider")

    @property
    def stage(self) -> str:
        return self.steps[self.step_index]

    def _go_to(self, stage: str) -> None:
        self._rebuild_steps()
        if stage not in self.steps:
            return
        self.step_index = self.steps.index(stage)
        self._show_step()

    def _show_step(self) -> None:
        page_ids = (
            "welcome", "provider", "custom-url", "api-key", "cloudflare-account",
            "models", "custom-model", "search", "style", "companion",
        )
        stage_to_page = {
            "custom_url": "custom-url",
            "api_key": "api-key",
            "cloudflare_account": "cloudflare-account",
            "custom_model": "custom-model",
        }
        active_page = stage_to_page.get(self.stage, self.stage)
        for page in page_ids:
            self.query_one(f"#wizard-page-{page}").display = page == active_page
        self.query_one("#wizard-status", Static).update("")
        self.query_one("#wizard-controls", Static).update(
            "" if self.stage == "welcome" else "← / →  previous / next     ↑ / ↓  browse     Enter  select     Esc  back"
        )
        focus_ids = {
            "provider": "provider-list",
            "custom_url": "custom-base-url",
            "api_key": "provider-api-key",
            "cloudflare_account": "cloudflare-account-id",
            "models": "model-list",
            "custom_model": "custom-model-name",
            "search": "search-engine-list",
            "style": "theme-list",
            "companion": "companion-list",
        }
        focus_id = focus_ids.get(self.stage)
        if focus_id:
            self.query_one(f"#{focus_id}").focus()
        else:
            self.set_focus(None)

    def _set_status(self, message: str) -> None:
        if self.is_mounted:
            self.query_one("#wizard-status", Static).update(message)

    def _apply_theme(self) -> None:
        if not self.is_mounted:
            return
        self.app.set_mitsu_theme(self.theme_id)
        shell = self.query_one("#wizard-shell")
        for theme_id in THEMES:
            shell.remove_class(f"theme-{theme_id}")
        shell.add_class(f"theme-{self.theme_id}")
        palette = THEMES[self.theme_id]
        accent = palette["accent"]
        preview = Text()
        code = palette["code"]
        preview.append("MITSU  /  READY\n", style=f"bold {accent}")
        preview.append("async ", style=f"bold {code['keyword']}")
        preview.append("def ", style=f"bold {code['keyword']}")
        preview.append("scope_check", style=f"bold {code['function']}")
        preview.append("(target):\n")
        preview.append("    if ", style=f"bold {code['keyword']}")
        preview.append("target.in_scope:\n        ")
        preview.append("score", style=code["function"])
        preview.append(" = ")
        preview.append("0.98", style=code["number"])
        preview.append("\n        ")
        preview.append("return ", style=f"bold {code['keyword']}")
        preview.append("await ", style=f"bold {code['keyword']}")
        preview.append("check", style=f"bold {code['function']}")
        preview.append("(")
        preview.append('"/scan"', style=code["string"])
        preview.append(")")
        self.query_one("#theme-preview", Static).update(preview)
        moon = self.query_one("#wizard-moon", MoonScene)
        moon.accent = MOON_YELLOW
        moon.refresh()
        city = self.query_one(CityScene)
        city.accent = accent
        city.refresh()

    def _show_companion(self) -> None:
        if not self.is_mounted:
            return
        companion = companion_by_id(self.companion_id)
        mascot = self.query_one("#wizard-mascot", MitsuCompanion)
        mascot.set_companion(
            companion.path,
            flip_running_right=companion.run_right_flip,
        )
        mascot.set_state("running_right")

    def _saved_profile(self, provider_id: str) -> dict:
        profile = self.saved_profiles.get(provider_id, {})
        return profile if isinstance(profile, dict) else {}

    def _update_provider_key_title(self) -> None:
        provider = PROVIDER_BY_ID[self.provider_id]
        self.query_one("#provider-key-title", Static).update(
            f"{provider.name.upper()} API KEY"
        )
        if self.provider_id == "custom":
            prompt = "Please set your custom endpoint API key (if applicable)."
        else:
            prompt = f"Please input your API key for {provider.name}."
        self.query_one("#provider-key-prompt", Static).update(prompt)
        saved_key = bool(self.profile.get("api_key"))
        if saved_key:
            note = "API key already set [!]. Leave empty to keep unchanged."
        elif provider.requires_api_key:
            note = "An API key is required for this provider."
        else:
            note = "Leave empty if no API key is used."
        self.query_one("#provider-key-note", Static).update(note)

    @staticmethod
    def _valid_base_url(base_url: str) -> bool:
        try:
            parsed = urlsplit(base_url)
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
    def _account_id(base_url: str) -> str:
        match = re.search(r"/accounts/([A-Fa-f0-9]{32})/", base_url)
        return match.group(1) if match else ""
