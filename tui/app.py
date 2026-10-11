from __future__ import annotations

import asyncio

from textual.app import App, ComposeResult
from textual.theme import Theme
from textual.widgets import Static

from mitsu.pets import companion_by_id
from mitsu.config import CredentialStore, PreferencesStore, SessionStore, THEMES
from mitsu.services.searxng import stop_local_searxng
from mitsu.tui.menu import MainMenuScreen
from mitsu.tui.onboarding import OnboardingScreen
from mitsu.tui.session import SessionScreen


class MitsuApp(App):
    TITLE = "Mitsu"
    SUB_TITLE = "A little companion for the work ahead"
    CSS_PATH = "theme.tcss"

    def __init__(self) -> None:
        super().__init__()
        self.credentials = CredentialStore()
        self.preferences = PreferencesStore()
        self.sessions = SessionStore()
        for theme_id, palette in THEMES.items():
            code = palette["code"]
            ui = palette["ui"]
            self.register_theme(
                Theme(
                    name=f"mitsu-{theme_id}",
                    primary=palette["accent"],
                    secondary=ui["border"],
                    accent=code["keyword"],
                    warning=code["operator"],
                    error="#f07882",
                    success=code["string"],
                    foreground="#e7e2dc",
                    background=ui["background"],
                    surface=ui["surface"],
                    panel=ui["panel"],
                    boost=ui["user"],
                    variables={
                        "text-muted": ui["muted"],
                    },
                )
            )
        configured_theme = self.preferences.load().get("theme", "ember")
        self._configured_theme_id = configured_theme if configured_theme in THEMES else "ember"

    def set_mitsu_theme(self, theme_id: str) -> None:
        if theme_id not in THEMES:
            theme_id = "ember"
        self.theme = f"mitsu-{theme_id}"
        self.console.show_cursor(False)

    def compose(self) -> ComposeResult:
        yield Static("Mitsu is waking up…", id="boot-screen")

    def on_mount(self) -> None:
        self.set_mitsu_theme(self._configured_theme_id)
        self.sessions.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.credentials.ready() and self.preferences.load().get("onboarding_complete"):
            self.push_screen(self.main_menu_screen())
        else:
            self.push_screen(OnboardingScreen(self.credentials, self.preferences))

    async def on_unmount(self) -> None:
        """Stop Mitsu's local SearXNG service when the application exits."""

        settings = self.credentials.search_engines().get("searxng", {})
        if not settings.get("managed_local"):
            return
        try:
            await asyncio.to_thread(stop_local_searxng, settings)
        except Exception as error:
            # Shutdown should still complete if the container runtime went away.
            self.log.error("Could not stop local SearXNG during shutdown: %s", error)

    async def finish_setup(self) -> None:
        if not self.credentials.ready() or not self.preferences.load().get("onboarding_complete"):
            return
        await self.switch_screen(self.main_menu_screen())

    async def open_setup(self, configuration_mode: str | None = None) -> None:
        await self.switch_screen(
            OnboardingScreen(self.credentials, self.preferences, configuration_mode=configuration_mode)
        )

    async def open_menu(self) -> None:
        await self.switch_screen(self.main_menu_screen())

    async def open_session(self, session_id: str | None = None) -> None:
        profile = self.credentials.active()
        if not profile:
            await self.open_setup()
            return
        if session_id:
            record = self.sessions.load_session(session_id)
            if not record or not record.get("id"):
                await self.open_menu()
                return
            session_provider = str(record.get("provider_id") or profile.get("provider_id"))
            selected_profile = self.credentials.profile_for(session_provider)
            if not selected_profile:
                await self.open_setup()
                return
            session_model = str(record.get("model") or selected_profile.get("model"))
            if session_model != str(selected_profile.get("model", "")):
                selected_profile["reasoning_enabled"] = False
                selected_profile["reasoning_parameter"] = ""
                selected_profile["reasoning_effort"] = "medium"
            selected_profile["model"] = session_model
        else:
            record = self.sessions.create_session(profile)
            selected_profile = profile
        companion = companion_by_id(self.preferences.load().get("companion", "mitsu"))
        theme_id = self.preferences.load().get("theme", "ember")
        screen = SessionScreen(
            record,
            selected_profile,
            companion.path,
            self.sessions,
            theme_id=theme_id if theme_id in THEMES else "ember",
        )
        await self.switch_screen(screen)
        screen.call_after_refresh(screen._focus_prompt)

    def main_menu_screen(self) -> MainMenuScreen:
        return MainMenuScreen(self.credentials, self.preferences, self.sessions)


def main() -> None:
    MitsuApp().run(mouse=True)
