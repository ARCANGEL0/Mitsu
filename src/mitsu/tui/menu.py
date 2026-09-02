from __future__ import annotations

import asyncio
import re
from datetime import datetime
from urllib.parse import urlsplit

from rich.style import Style
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Resize
from textual.screen import Screen
from textual.widgets import Input, Static

from mitsu import __version__
from mitsu.armory import CATEGORIES as ARMORY_CATEGORIES
from mitsu.armory import TOOLS_BY_CATEGORY, TOOL_BY_ID
from mitsu.companions import COMPANIONS, companion_by_id
from mitsu.config import CredentialStore, PreferencesStore, PROVIDERS, PROVIDER_BY_ID, SessionStore, THEMES
from mitsu.providers import ProviderRequestError, list_models
from mitsu.services.host_environment import HostEnvironment, load_host_environment
from mitsu.services.redteam_armory import (
    ArmoryError,
    ToolStatus,
    forget_managed_install,
    inspect_tool,
    open_install_terminal,
    record_managed_install,
)
from mitsu.tui.session import DeleteSessionDialog, MCPConfigDialog
from mitsu.tui.branding import MOON_YELLOW
from mitsu.tui.dialogs import SearchEngineDialog
from mitsu.tui.updates import compare_versions, fetch_latest_version
from mitsu.tui.widgets import CityScene, MitsuCompanion, MoonScene


def _runtime_info(provider: str, model: str) -> Text:
    output = Text()
    output.append(f"Current provider: {provider}\nModel: {model}\n\n")
    output.append(f"v{__version__}", style="dim")
    output.append("\n\n")
    output.append("made by: @arcangel0", style="dim italic")
    return output


class MenuList(Static):
    can_focus = True


class MainMenuScreen(Screen):
    BINDINGS = [
        Binding("up", "move_up", "Move up"),
        Binding("down", "move_down", "Move down"),
        Binding("left", "focus_left", "Command center"),
        Binding("right", "focus_right", "Open panel"),
        Binding("ctrl+left", "focus_left", "Command center"),
        Binding("ctrl+right", "focus_right", "Open panel"),
        Binding("enter", "select_current", "Select"),
        Binding("delete", "delete_selected_session", "Delete selected session", priority=True),
        Binding("tab", "toggle_panel", "Switch panel"),
        Binding("escape", "back_to_command_center", "Back", priority=True),
        Binding("q", "quit_app", "Quit"),
    ]

    LEFT_ITEMS = ("SESSIONS", "CONFIGURATION", "UPDATE MITSU", "QUIT")
    CONFIG_ITEMS = (
        ("CHANGE PROVIDER", "Saved provider keys are reused. Choose a provider and one of its models."),
        ("SET MODEL", "Uses the saved provider key to fetch and change the selected model."),
        ("CONFIGURE MCP SERVERS", "Connect Streamable HTTP or local stdio MCP servers for session tools."),
        ("SEARCH PROVIDERS", "Configure and validate one or more web search sources."),
        ("REDTEAM ARMORY", "Browse assessment tools and install them with native packages or supported upstream methods."),
        ("CHANGE COMPANION", "Preview companions with the arrow keys, then press Enter to save."),
    )

    def __init__(self, credentials: CredentialStore, preferences: PreferencesStore, sessions: SessionStore) -> None:
        super().__init__()
        self.credentials = credentials
        self.preferences = preferences
        self.sessions = sessions
        self.profile = credentials.active() or {}
        self.saved_preferences = preferences.load()
        self.records = sessions.list_sessions()
        self.theme_id = self.saved_preferences.get("theme", "ember")
        if self.theme_id not in THEMES:
            self.theme_id = "ember"
        self.accent = THEMES[self.theme_id]["accent"]
        self.left_index = 0
        self.right_index = 0
        self.active_panel = "left"
        self.panel_kind = "sessions"
        self.right_items: list[dict[str, str]] = []
        self.configured_model_items: list[dict[str, str]] = []
        self.configured_model_failures: list[str] = []
        self.armory_environment: HostEnvironment | None = None
        self.armory_category_id: str | None = None
        self.armory_tool_id: str | None = None
        self.armory_statuses: dict[str, ToolStatus] = {}
        self.armory_operation_process = None
        self.armory_operation: str | None = None
        self.armory_operation_method_id: str | None = None
        self.update_status = f"Installed version: v{__version__}\nLatest version: not checked"
        self.inline_flow: str | None = None
        self.input_stage: str | None = None
        self.pending_profile: dict | None = None
        self.api_key_prompted = False

    def compose(self) -> ComposeResult:
        companion = companion_by_id(self.saved_preferences.get("companion", "mitsu"))
        city = CityScene(accent=self.accent, id="menu-city")
        mascot = MitsuCompanion(
            sprite_path=companion.path,
            animation_interval=1 / 6,
            kitty_anchor=city,
            kitty_offset=(4, 2),
            scene_overlay=True,
            flip_running_right=companion.run_right_flip,
            id="menu-companion",
        )
        city.set_companion(mascot, (4, 2))
        provider = self._provider_name()
        model = self.profile.get("model") or "Not selected"
        with Vertical(id="menu-shell", classes=f"theme-{self.theme_id}"):
            with Vertical(id="menu-masthead"):
                yield MoonScene(accent=MOON_YELLOW, show_brand=True, id="menu-moon")
                with Vertical(id="menu-landscape"):
                    yield city
                    yield mascot
            with Horizontal(id="menu-dashboard"):
                with Vertical(id="menu-left-panel"):
                    yield Static("COMMAND CENTER", id="menu-left-title", classes="menu-section-title", markup=False)
                    yield Static("────────────────────", id="menu-left-rule", markup=False)
                    yield MenuList("", id="menu-left-list", markup=False)
                    yield Static("", id="menu-left-spacer")
                    yield Static(_runtime_info(provider, model), id="menu-runtime-info", markup=False)
                with Vertical(id="menu-right-panel"):
                    yield Static("", id="menu-right-title", classes="menu-section-title", markup=False)
                    yield Input(
                        placeholder="Filter models across configured providers",
                        id="menu-model-search",
                    )
                    yield MenuList("", id="menu-right-list", markup=False)
                    yield Static("", id="menu-right-detail", markup=False)
                    yield Input(placeholder="", password=True, id="menu-secret-input")
                    yield Input(placeholder="", id="menu-text-input")
            yield Static(
                "↑ / ↓ move    Enter select / open    Del remove session    ← / Esc command center    Tab switch panel    Q quit",
                id="menu-footer",
                markup=False,
            )

    def on_mount(self) -> None:
        moon = self.query_one("#menu-moon", MoonScene)
        moon.accent = MOON_YELLOW
        moon.refresh()
        self.query_one(MitsuCompanion).set_state("running_right")
        self._render_left_list()
        self._show_left_selection()
        self.query_one("#menu-left-list", MenuList).focus()

    def on_resize(self, _event: Resize) -> None:
        if self.is_mounted and self.right_items:
            self.call_after_refresh(self._render_right_list)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "menu-model-search" and self.panel_kind == "configured_models":
            await self._select_right_item()
            return
        if event.input.id not in {"menu-secret-input", "menu-text-input"} or not self.input_stage:
            return
        value = event.value.strip()
        event.input.value = ""
        await self._submit_inline_input(value)

    def on_input_changed(self, event: Input.Changed) -> None:
        if (
            event.input.id != "menu-model-search"
            or self.panel_kind != "configured_models"
            or event.input.disabled
        ):
            return
        self._filter_configured_models(event.value)

    def action_move_up(self) -> None:
        if self.active_panel == "left":
            self.left_index = (self.left_index - 1) % len(self.LEFT_ITEMS)
            self._render_left_list()
            self._show_left_selection()
            return
        if self.right_items:
            self.right_index = (self.right_index - 1) % len(self.right_items)
            self._render_right_list()

    def action_move_down(self) -> None:
        if self.active_panel == "left":
            self.left_index = (self.left_index + 1) % len(self.LEFT_ITEMS)
            self._render_left_list()
            self._show_left_selection()
            return
        if self.right_items:
            self.right_index = (self.right_index + 1) % len(self.right_items)
            self._render_right_list()

    def action_focus_left(self) -> None:
        if self.panel_kind.startswith("armory_") and self.active_panel == "right":
            self._armory_back()
            return
        if self.inline_flow:
            self._cancel_inline_flow()
        if self.panel_kind == "companions":
            selected = companion_by_id(self.saved_preferences.get("companion", "mitsu"))
            mascot = self.query_one("#menu-companion", MitsuCompanion)
            mascot.set_companion(selected.path)
            mascot.set_state("running_right")
        self.active_panel = "left"
        self._render_left_list()
        self.query_one("#menu-left-list", MenuList).focus()

    def action_focus_right(self) -> None:
        self.active_panel = "right"
        self._render_left_list()
        self._render_right_list()
        self.query_one("#menu-right-list", MenuList).focus()

    def action_toggle_panel(self) -> None:
        if self.input_stage:
            return
        if self.active_panel == "left":
            self.action_focus_right()
        else:
            self.action_focus_left()
