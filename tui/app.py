from __future__ import annotations

import asyncio
import os
import signal
import shutil
import sys
from textual.binding import Binding

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from textual.app import App, ComposeResult
from textual.theme import Theme
from textual.widgets import Static

from mitsu.pets import companion_by_id
from mitsu.config import CredentialStore, PreferencesStore, SessionStore, THEMES
from mitsu.providers import ProviderRequestError, apply_reasoning_default
from mitsu.services.searxng import stop_local_searxng
from mitsu.services.single_instance import (
    InstanceAlreadyRunning,
    acquire_instance_lock,
    release_instance_lock,
)
from mitsu.tui.menu import MainMenuScreen
from mitsu.tui.onboarding import OnboardingScreen
from mitsu.tui.session import SessionScreen


class MitsuApp(App):
    BINDINGS = [Binding("ctrl+q", "quit", "Quit Mitsu", priority=True)]
    TITLE = "Mitsu"
    SUB_TITLE = "A little companion for the work ahead"
    CSS_PATH = "theme.tcss"

    def __init__(self) -> None:
        super().__init__()
        self._ui_started = False
        self._show_bye_banner = False
        self._restart_after_update = False
        self._shutdown_signals: list[signal.Signals] = []
        self._quit_task: asyncio.Task | None = None
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

    def quit_mitsu(self) -> None:
        self._show_bye_banner = True
        if self._quit_task is None:
            self._quit_task = asyncio.create_task(self._quit_after_cleanup())

    def request_update_restart(self) -> None:
        self._restart_after_update = True
        self.exit()

    async def _quit_after_cleanup(self) -> None:
        try:
            await asyncio.wait_for(self._close_sessions(), timeout=8)
        except TimeoutError:
            self.log.error("Session cleanup exceeded the 8 second shutdown deadline.")
        finally:
            self.exit()

    async def _close_sessions(self) -> None:
        for screen in reversed(self.screen_stack):
            if isinstance(screen, SessionScreen):
                await screen.close_session()

    async def action_quit(self) -> None:
        self.quit_mitsu()

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
                loop.add_signal_handler(signum, self.quit_mitsu)
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
                await asyncio.wait_for(asyncio.to_thread(stop_local_searxng, settings), timeout=4)
            except TimeoutError:
                self.log.error("Stopping local SearXNG exceeded the 4 second shutdown deadline.")
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
        await self._close_sessions()
        await self.switch_screen(
            OnboardingScreen(self.credentials, self.preferences, configuration_mode=configuration_mode)
        )

    async def open_menu(self) -> None:
        await self._close_sessions()
        screen = self.main_menu_screen()
        await self.switch_screen(screen)
        screen._restore_focus()
        screen.call_after_refresh(screen._restore_focus)

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
        await self._close_sessions()
        await self.switch_screen(screen)
        screen.call_after_refresh(screen._focus_prompt)

    def main_menu_screen(self) -> MainMenuScreen:
        return MainMenuScreen(self.credentials, self.preferences, self.sessions)


def main() -> None:
    try:
        instance_lock = acquire_instance_lock()
    except InstanceAlreadyRunning as error:
        print(f"{error} Close it before starting another.", file=sys.stderr)
        return

    app = MitsuApp()
    try:
        app.run(mouse=True)
    finally:
        if app._ui_started and app._show_bye_banner and sys.stdout.isatty():
            console = Console()
            console.clear()
            width, height = shutil.get_terminal_size(fallback=(80, 24))
            banner = Text("✦  M I T S U  ✦", style="bold #55d7df", justify="center")
            banner.append("\n\nSESSION SAVED!", style="bold #f08ab6")
            banner.append("\nBYE-BYEE, SEE YA SOON~!", style="#e7e2dc")
            panel = Panel(
                Align.center(banner),
                width=min(54, max(20, width - 4)),
                padding=(1, 3),
                border_style="#55d7df",
                style="on #101a24",
            )
            console.print("\n" * max(1, (height - 9) // 2), end="")
            console.print(Align.center(panel, width=width))
    if app._restart_after_update:
        release_instance_lock(instance_lock)
        os.execv(sys.executable, [sys.executable, "-m", "mitsu", *sys.argv[1:]])
    sys.stdout.flush()
    sys.stderr.flush()
    release_instance_lock(instance_lock)
    # UI shutdown is complete. Exit without waiting for abandoned executor threads
    # (for example, a cancelled report request blocked in network I/O).
    os._exit(0)
