from __future__ import annotations

import asyncio
import fcntl
import os
import signal
import subprocess
import sys
from pathlib import Path

from textual.app import App, ComposeResult
from textual.theme import Theme
from textual.widgets import Static

from mitsu.pets import companion_by_id
from mitsu.config import CredentialStore, PreferencesStore, SessionStore, THEMES
from mitsu.providers import ProviderRequestError, apply_reasoning_default
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
        self._ui_started = False
        self._shutdown_signals: list[signal.Signals] = []
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
        self._ui_started = True
        loop = asyncio.get_running_loop()
        for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"):
            signum = getattr(signal, name, None)
            if signum is None:
                continue
            try:
                loop.add_signal_handler(signum, self.exit)
            except (NotImplementedError, RuntimeError, ValueError):
                continue
            self._shutdown_signals.append(signum)
        self.set_mitsu_theme(self._configured_theme_id)
        self.sessions.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.credentials.ready() and self.preferences.load().get("onboarding_complete"):
            self.push_screen(self.main_menu_screen())
        else:
            self.push_screen(OnboardingScreen(self.credentials, self.preferences))

    async def on_unmount(self) -> None:
        settings = self.credentials.search_engines().get("searxng", {})
        if settings.get("managed_local"):
            try:
                await asyncio.to_thread(stop_local_searxng, settings)
            except Exception as error:
                self.log.error("Could not stop local SearXNG during shutdown: %s", error)
        loop = asyncio.get_running_loop()
        for signum in self._shutdown_signals:
            loop.remove_signal_handler(signum)
        self._shutdown_signals.clear()

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
        profile_model_matches_session = True
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
            stored_model = str(selected_profile.get("model", ""))
            session_model = str(record.get("model") or selected_profile.get("model"))
            profile_model_matches_session = session_model == stored_model
            if not profile_model_matches_session:
                selected_profile["reasoning_enabled"] = None
                selected_profile["reasoning_parameter"] = ""
                selected_profile["reasoning_effort"] = "medium"
            selected_profile["model"] = session_model
        else:
            record = self.sessions.create_session(profile)
            selected_profile = profile
        try:
            reasoning_defaulted = await asyncio.to_thread(apply_reasoning_default, selected_profile)
        except ProviderRequestError:
            reasoning_defaulted = False
        if reasoning_defaulted and profile_model_matches_session:
            self.credentials.save_profile(selected_profile)
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
    lock_path = Path("/tmp") / f"mitsu-{os.getuid()}.lock"
    lock_flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    os.fchmod(lock_fd, 0o600)
    lock_file = os.fdopen(lock_fd, "r+")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_file.close()
        print("Mitsu is already running for this user.", file=sys.stderr)
        return
    lock_file.seek(0)
    lock_file.truncate()
    lock_file.write(f"{os.getpid()}\n")
    lock_file.flush()
    try:
        app = MitsuApp()
        try:
            app.run(mouse=True)
        finally:
            if app._ui_started and sys.stdout.isatty() and app.return_code in (None, 0):
                subprocess.run(["reset"], check=False)
    finally:
        lock_file.close()
