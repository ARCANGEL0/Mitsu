from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from rich.style import Style
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Key, Resize, ScreenResume, ScreenSuspend
from textual.screen import Screen
from textual.widgets import Input, Static, TextArea

from mitsu import __version__
from mitsu.armory import CATEGORIES as ARMORY_CATEGORIES
from mitsu.armory import TOOLS, TOOLS_BY_CATEGORY, TOOL_BY_ID
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
from mitsu.tools.armory_mcp import resolve_executable
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


CUSTOM_TOOL_FORM_STEPS = (
    ("name", "Tool name", "e.g. Acme Scanner", "This is the name the model will see.", True),
    ("command", "Executable", "e.g. acme-scan or /home/me/bin/acme-scan", "Enter the executable only. Put fixed switches in the next step.", True),
    ("args", "Fixed arguments", "e.g. scan --json", "Optional arguments always passed after the executable. No shell syntax.", False),
    ("description", "What does it do?", "Describe the tool and when Mitsu should use it", "This description is provided to the model with the tool.", True),
    ("usage", "Usage notes", "Prerequisites, safe-use notes, limits, or output details", "Add the most useful notes from the tool’s documentation, or leave blank.", False),
    ("parameters", "Inputs for the tool", "target|--target|required|Authorized host; profile|--profile|optional|Scan profile", "One input per semicolon: name|flag|required-or-optional|description. Leave flag blank for a positional value.", False),
    ("example", "Example use", "e.g. Check the approved staging host with the passive profile", "Optional example shown to the model. Press Enter to save.", False),
)


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
        Binding("ctrl+s", "save_mcp_configuration", "Save MCP configuration", priority=True),
        Binding("delete", "delete_selected_session", "Delete selected session", priority=True),
        Binding("tab", "toggle_panel", "Switch panel"),
        Binding("escape", "back_to_command_center", "Back", priority=True),
        Binding("q", "quit_app", "Quit"),
    ]

    LEFT_ITEMS = ("SESSIONS", "CONFIGURATION", "UPDATE MITSU", "QUIT")
    CONFIG_ITEMS = (
        ("CHANGE PROVIDER", "Saved provider keys are reused. Choose a provider and one of its models."),
        ("SET MODEL", "Uses the saved provider key to fetch and change the selected model."),
        ("CONFIGURE MCP SERVER", "Configure Mitsu’s built-in MCP server, its tools, custom CLI tools, and external MCP connections."),
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
        self.mcp_path = credentials.path.parent / "mcp_servers.json"
        self.mcp_config: dict = {
            "servers": [],
            "custom_tools": [],
            "armory": {"enabled": True, "tools": {tool.id: True for tool in TOOLS}},
        }
        self.mcp_selected_tool_ids: set[str] = set()
        self.mcp_installed_tool_ids: set[str] = set()
        self.mcp_category_id: str | None = None
        self.custom_tool_form_values: dict[str, str] = {}
        self.custom_tool_form_step = 0
        self.custom_tool_edit_index: int | None = None
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
                    yield TextArea("", id="menu-mcp-editor", language="json", show_line_numbers=True)
                    with Vertical(id="menu-custom-tool-form"):
                        yield Static("ADD A CLI TOOL", id="menu-custom-tool-form-title", markup=False)
                        yield Static("", id="menu-custom-tool-step", markup=False)
                        yield Input(placeholder="", id="menu-custom-tool-input")
                        yield Static("Enter next    Shift+Tab previous    Esc cancel", id="menu-custom-tool-nav-hint", markup=False)
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

    def on_screen_suspend(self, _event: ScreenSuspend) -> None:
        for mascot in self.query(MitsuCompanion):
            mascot.set_modal_suspended(True)

    def on_screen_resume(self, _event: ScreenResume) -> None:
        for mascot in self.query(MitsuCompanion):
            mascot.set_modal_suspended(False)

    def on_resize(self, _event: Resize) -> None:
        if self.is_mounted and self.right_items and self.panel_kind not in {"mcp_editor", "mcp_custom_tool_form"}:
            self.call_after_refresh(self._render_right_list)

    def on_key(self, event: Key) -> None:
        if (
            event.key == "space"
            and self.active_panel == "right"
            and self.panel_kind in {"mcp_categories", "mcp_armory_categories", "mcp_tools"}
            and self.right_items
            and self.right_items[self.right_index].get("action") in {
                "mcp_armory", "mcp_toggle_armory", "mcp_category", "mcp_tool"
            }
        ):
            event.stop()
            self.action_toggle_mcp_selection()
        elif (
            event.key.casefold() in {"e", "shift+e"}
            and self.active_panel == "right"
            and self.panel_kind in {"mcp_categories", "mcp_armory_categories", "mcp_tools", "mcp_custom_tools"}
        ):
            event.stop()
            self.action_edit_mcp_configuration()
        elif event.key == "shift+tab" and self.panel_kind == "mcp_custom_tool_form":
            event.stop()
            self._previous_custom_tool_field()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "menu-model-search" and self.panel_kind == "configured_models":
            await self._select_right_item()
            return
        if event.input.id == "menu-custom-tool-input" and self.panel_kind == "mcp_custom_tool_form":
            event.stop()
            self._submit_custom_tool_field(event.value)
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
        if self.panel_kind.startswith("mcp_") and self.active_panel == "right":
            self._mcp_back()
            return
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

    def action_back_to_command_center(self) -> None:
        if self.panel_kind.startswith("mcp_"):
            self._mcp_back()
            return
        if self.panel_kind.startswith("armory_"):
            self._armory_back()
            return
        if self.inline_flow:
            self._cancel_inline_flow()
            return
        self.action_focus_left()

    async def action_select_current(self) -> None:
        if self.active_panel == "left":
            if self.left_index == 3:
                self.app.exit()
                return
            if self.left_index == 2:
                await self._check_for_updates()
                return
            self.active_panel = "right"
            self._render_left_list()
            self._render_right_list()
            self.query_one("#menu-right-list", MenuList).focus()
            return
        if self.panel_kind == "update":
            await self._check_for_updates()
            return
        if self.panel_kind == "quit":
            self.app.exit()
            return
        await self._select_right_item()

    def action_delete_selected_session(self) -> None:
        if self.active_panel != "right" or self.panel_kind != "sessions" or not self.right_items:
            return
        item = self.right_items[self.right_index]
        if item.get("action") != "open_session":
            return
        session_id = item.get("session_id", "")
        title = item.get("label", "this session").split("] ", 1)[-1]
        selected_index = self.right_index
        dialog = DeleteSessionDialog(in_menu=True, session_title=title)

        def dismissed(confirmed: bool) -> None:
            if confirmed:
                self._delete_selected_session(session_id, title, selected_index)

        self.app.push_screen(dialog, dismissed)

    def _delete_selected_session(self, session_id: str, title: str, selected_index: int) -> None:
        try:
            deleted = self.sessions.delete_session(session_id)
        except OSError as error:
            self.query_one("#menu-right-detail", Static).update(
                f"Could not delete {title}: {error}"
            )
            return
        if not deleted:
            self.query_one("#menu-right-detail", Static).update(
                f"Could not find {title} on disk. The session list was not changed."
            )
            return

        self.records = [record for record in self.records if str(record.get("id", "")) != session_id]
        self._show_left_selection()
        self.right_index = min(selected_index, max(0, len(self.right_items) - 1))
        self._render_right_list()
        self.query_one("#menu-right-detail", Static).update(f"Removed {title} from saved sessions.")

    def action_quit_app(self) -> None:
        if self.input_stage:
            return
        self.app.exit()

    def action_toggle_mcp_selection(self) -> None:
        if self.active_panel != "right" or not self.right_items:
            return
        if self.panel_kind not in {"mcp_categories", "mcp_armory_categories", "mcp_tools"}:
            return
        item = self.right_items[self.right_index]
        action = item.get("action")
        if action in {"mcp_toggle_armory", "mcp_armory"}:
            self._toggle_armory_mcp()
        elif action == "mcp_category":
            self._toggle_mcp_category(item["category_id"])
        elif action == "mcp_tool":
            self._toggle_mcp_tool(item["tool_id"])

    def action_edit_mcp_configuration(self) -> None:
        if self.active_panel == "right" and self.panel_kind in {
            "mcp_categories", "mcp_armory_categories", "mcp_tools", "mcp_custom_tools"
        }:
            self._open_mcp_editor()

    async def action_save_mcp_configuration(self) -> None:
        if self.panel_kind == "mcp_editor":
            self._save_mcp_editor()

    async def _select_right_item(self) -> None:
        if not self.right_items or self.panel_kind == "armory_running":
            return
        item = self.right_items[self.right_index]
        action = item["action"]
        if action == "create_session":
            await self.app.open_session()
        elif action == "open_session":
            await self.app.open_session(item["session_id"])
        elif action == "change_provider":
            self._begin_provider_selection()
        elif action == "set_model":
            self._begin_model_selection()
        elif action == "mcp":
            await self._open_mcp_configuration()
        elif action == "mcp_toggle_armory":
            self._toggle_armory_mcp()
        elif action == "mcp_armory":
            self._show_mcp_armory_categories()
        elif action == "mcp_category":
            self._load_mcp_category(item["category_id"])
        elif action == "mcp_tool":
            self._toggle_mcp_tool(item["tool_id"])
        elif action == "mcp_custom":
            self._show_custom_tool_list()
        elif action == "mcp_custom_add":
            self._begin_custom_tool_form()
        elif action == "mcp_custom_edit":
            self._begin_custom_tool_form(int(item["tool_index"]))
        elif action == "mcp_external_servers":
            self._open_mcp_editor()
        elif action == "search_engines":
            self.app.push_screen(
                SearchEngineDialog(self.credentials),
                self._search_engines_closed,
            )
        elif action == "armory":
            await self._open_armory()
        elif action == "armory_category":
            await self._load_armory_tools(item["category_id"])
        elif action == "armory_tool":
            self._show_armory_confirmation(item["tool_id"])
        elif action == "armory_cancel":
            if self.armory_category_id:
                self._display_armory_tools(self.armory_category_id, selected_tool=self.armory_tool_id)
        elif action == "armory_install":
            await self._start_armory_operation("install")
        elif action == "armory_uninstall":
            await self._start_armory_operation("uninstall")
        elif action == "armory_running":
            return
        elif action == "change_companion":
            companion = companion_by_id(item["companion_id"])
            try:
                self.preferences.save({"companion": companion.id})
            except OSError as error:
                self.query_one("#menu-right-detail", Static).update(f"Could not save companion: {error}")
                return
            self.saved_preferences["companion"] = companion.id
            self._set_menu_companion(companion.id)
            self.left_index = 1
            self.active_panel = "right"
            self._show_left_selection()
            self.right_index = 5
            self.right_items[self.right_index]["detail"] = f"Saved {companion.name} as your companion."
            self._render_left_list()
            self._render_right_list()
        elif action == "companions":
            self.panel_kind = "companions"
            self.right_items = [
                {
                    "label": companion.name,
                    "action": "change_companion",
                    "companion_id": companion.id,
                    "detail": "Press Enter to use this companion.",
                }
                for companion in COMPANIONS
            ]
            self.right_index = next(
                (index for index, companion in enumerate(COMPANIONS)
                 if companion.id == self.saved_preferences.get("companion", "mitsu")),
                0,
            )
            self.query_one("#menu-right-title", Static).update("PET COMPANION")
            self._render_right_list()
        elif action == "check_updates":
            await self._check_for_updates()
        elif action == "select_provider":
            await self._choose_provider(item["provider_id"])
        elif action == "select_model":
            await self._save_pending_profile(item["model"])
        elif action == "select_configured_model":
            profile = self.credentials.profile_for(item["provider_id"])
            if profile is not None:
                self.pending_profile = profile
                self.inline_flow = "model"
                await self._save_pending_profile(item["model"])
        elif action == "retry_models":
            if self.panel_kind == "configured_models":
                await self._load_all_provider_models()
            else:
                await self._load_pending_models()
        elif action == "quit":
            self.app.exit()

    async def _open_mcp_configuration(self) -> None:
        self.panel_kind = "mcp_loading"
        self.query_one("#menu-right-title", Static).update("CONFIGURE MCP SERVER")
        self.query_one("#menu-right-list", MenuList).update("Checking installed Armory tools…")
        self.query_one("#menu-right-detail", Static).update("Reading your MCP and Armory settings.")
        self._read_mcp_configuration()
        self.mcp_installed_tool_ids = await asyncio.to_thread(
            lambda: {
                tool.id for tool in TOOLS
                if resolve_executable(tool) is not None
            }
        )
        if self.panel_kind != "mcp_loading":
            return
        self._show_mcp_categories()
        self.query_one("#menu-right-list", MenuList).focus()

    def _read_mcp_configuration(self) -> None:
        self.mcp_config = {
            "servers": [],
            "custom_tools": [],
            "armory": {"enabled": True, "tools": {tool.id: True for tool in TOOLS}},
        }
        self.mcp_selected_tool_ids = {tool.id for tool in TOOLS}
        self.mcp_load_error: str | None = None
        try:
            raw = self.mcp_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        except OSError as error:
            self.mcp_load_error = f"Could not read MCP settings: {error}"
            return
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            self.mcp_load_error = f"MCP settings contain invalid JSON at line {error.lineno}. Open Custom MCP configuration to repair it."
            return
        if not MCPConfigDialog._valid_config(value):
            self.mcp_load_error = "MCP settings do not match the supported format. Open Custom MCP configuration to repair them."
            return
        self.mcp_config = value
        self.mcp_config.setdefault("custom_tools", [])
        armory = dict(value.get("armory") or {"enabled": True})
        selection = armory.get("tools", ["*"])
        if isinstance(selection, dict):
            self.mcp_selected_tool_ids = {
                tool_id for tool_id, enabled in selection.items() if enabled is True
            }
        else:
            identifiers = set(selection)
            if "*" in identifiers:
                self.mcp_selected_tool_ids = {tool.id for tool in TOOLS}
            else:
                selected = identifiers & set(TOOL_BY_ID)
                for category_id in identifiers:
                    selected.update(tool.id for tool in TOOLS_BY_CATEGORY.get(category_id, ()))
                self.mcp_selected_tool_ids = selected
        # Convert legacy wildcard/category lists to an explicit, editable tool map.
        armory["tools"] = {tool.id: tool.id in self.mcp_selected_tool_ids for tool in TOOLS}
        self.mcp_config["armory"] = armory

    def _show_mcp_categories(self) -> None:
        self.panel_kind = "mcp_categories"
        self.mcp_category_id = None
        armory = self.mcp_config.get("armory") or {
            "enabled": True,
            "tools": {tool.id: tool.id in self.mcp_selected_tool_ids for tool in TOOLS},
        }
        armory_enabled = armory.get("enabled", True)
        installed_armory_tools = sum(tool.id in self.mcp_installed_tool_ids for tool in TOOLS)
        label = (
            f"RedTeam Armory · {'ENABLED' if armory_enabled else 'DISABLED'} · "
            f"{installed_armory_tools} of {len(TOOLS)} installed"
        )
        self.right_items = [
            {
                "label": label,
                "action": "mcp_armory",
                "detail": (
                    f"{len(self.mcp_selected_tool_ids)} of {len(TOOLS)} tools are selected; "
                    f"{installed_armory_tools} are installed. Enter opens categories. Space toggles Armory tools "
                    "inside Mitsu’s built-in MCP server."
                ),
            }
        ]
        server_count = len(self.mcp_config.get("servers", []))
        custom_tool_count = len(self.mcp_config.get("custom_tools", []))
        self.right_items.append({
            "label": f"Custom CLI tools  ·  {custom_tool_count} configured",
            "action": "mcp_custom",
            "detail": (
                "Add a command-line tool already available on this computer. Mitsu will ask what it does, how to run it, "
                "and which inputs it needs, then expose it as a named tool to the model."
            ),
        })
        self.right_items.append({
            "label": f"External MCP connections  ·  {server_count} configured",
            "action": "mcp_external_servers",
            "detail": (
                "Connect programs that already implement MCP. Enter opens the advanced MCP configuration; "
                "the servers list is for stdio or HTTP MCP connections."
            ),
        })
        self.right_index = 0
        self.query_one("#menu-right-title", Static).update("CONFIGURE MCP SERVER")
        self.query_one("#menu-footer", Static).update(
            "↑ / ↓ move    Enter open    Space toggle Armory    E advanced JSON    Esc back    Q quit"
        )
        self._set_mcp_editor_visible(False)
        self._set_custom_tool_form_visible(False)
        self._render_right_list()
        detail = self.query_one("#menu-right-detail", Static)
        if self.mcp_load_error:
            detail.update(self.mcp_load_error)
        else:
            detail.update(
                "One built-in Mitsu MCP server starts with each session. RedTeam Armory and custom CLI tools register "
                "inside it; External MCP connections are separate servers."
            )

    def _show_mcp_armory_categories(self) -> None:
        self.panel_kind = "mcp_armory_categories"
        self.right_items = []
        for category in ARMORY_CATEGORIES:
            tools = TOOLS_BY_CATEGORY[category.id]
            installed = sum(tool.id in self.mcp_installed_tool_ids for tool in tools)
            selected = sum(tool.id in self.mcp_selected_tool_ids for tool in tools)
            self.right_items.append({
                "label": f"{category.name}  ·  selected {selected}/{len(tools)}  ·  installed {installed}",
                "action": "mcp_category",
                "category_id": category.id,
                "detail": f"{category.description} Enter to inspect tools; Space toggles installed tools in this category.",
            })
        self.right_index = 0
        self.query_one("#menu-right-title", Static).update("REDTEAM ARMORY MCP TOOLS")
        self.query_one("#menu-footer", Static).update(
            "↑ / ↓ move    Enter inspect    Space toggle category    E advanced JSON    Esc server overview    Q quit"
        )
        self._set_mcp_editor_visible(False)
        self._set_custom_tool_form_visible(False)
        self._render_right_list()
        self.query_one("#menu-right-list", MenuList).focus()

    def _load_mcp_category(self, category_id: str) -> None:
        if category_id not in TOOLS_BY_CATEGORY:
            return
        self.mcp_category_id = category_id
        self.panel_kind = "mcp_tools"
        category = next(item for item in ARMORY_CATEGORIES if item.id == category_id)
        self.query_one("#menu-right-title", Static).update(category.name.upper())
        self.query_one("#menu-footer", Static).update(
            "↑ / ↓ move    Space enable / disable    E advanced JSON    Esc server overview    Q quit"
        )
        self._refresh_mcp_tools(TOOLS_BY_CATEGORY[category_id][0].id)
        self.query_one("#menu-right-list", MenuList).focus()

    def _toggle_armory_mcp(self) -> None:
        armory = self.mcp_config.get("armory") or {
            "enabled": True,
            "tools": {tool.id: tool.id in self.mcp_selected_tool_ids for tool in TOOLS},
        }
        self.mcp_config["armory"] = armory
        armory["enabled"] = not armory.get("enabled", True)
        if not self._write_mcp_configuration():
            armory["enabled"] = not armory["enabled"]
            return
        self._show_mcp_categories()

    def _toggle_mcp_category(self, category_id: str) -> None:
        if self.mcp_load_error:
            self.query_one("#menu-right-detail", Static).update(
                self.mcp_load_error + " Repair the file in Custom MCP configuration first."
            )
            return
        tools = TOOLS_BY_CATEGORY.get(category_id, ())
        installed_ids = {tool.id for tool in tools if tool.id in self.mcp_installed_tool_ids}
        if not installed_ids:
            self.query_one("#menu-right-detail", Static).update(
                "No tools in this category are installed. Install a tool from RedTeam Armory first."
            )
            return
        previous = set(self.mcp_selected_tool_ids)
        if installed_ids <= self.mcp_selected_tool_ids:
            self.mcp_selected_tool_ids.difference_update(installed_ids)
        else:
            self.mcp_selected_tool_ids.update(installed_ids)
        if not self._store_mcp_selection():
            self.mcp_selected_tool_ids = previous
            return
        self._show_mcp_armory_categories()
        self.right_index = next(
            (index for index, item in enumerate(self.right_items) if item.get("category_id") == category_id),
            0,
        )
        self._render_right_list()

    def _toggle_mcp_tool(self, tool_id: str) -> None:
        if self.mcp_load_error:
            self.query_one("#menu-right-detail", Static).update(
                self.mcp_load_error + " Repair the file in Custom MCP configuration first."
            )
            return
        if tool_id not in TOOL_BY_ID:
            return
        previous = set(self.mcp_selected_tool_ids)
        if tool_id in self.mcp_selected_tool_ids:
            self.mcp_selected_tool_ids.remove(tool_id)
        else:
            self.mcp_selected_tool_ids.add(tool_id)
        if not self._store_mcp_selection():
            self.mcp_selected_tool_ids = previous
            return
        if self.mcp_category_id:
            self._refresh_mcp_tools(tool_id)

    def _refresh_mcp_tools(self, selected_tool: str) -> None:
        category_id = self.mcp_category_id
        if category_id is None:
            return
        category = next(item for item in ARMORY_CATEGORIES if item.id == category_id)
        self.query_one("#menu-right-title", Static).update(category.name.upper())
        self.right_items = []
        for tool in TOOLS_BY_CATEGORY[category_id]:
            installed = tool.id in self.mcp_installed_tool_ids
            selected = tool.id in self.mcp_selected_tool_ids
            self.right_items.append({
                "label": (
                    f"{'✓' if selected else '○'} "
                    f"{'ENABLED' if selected else 'DISABLED'}  ·  "
                    f"{'INSTALLED' if installed else 'NOT INSTALLED'}  ·  {tool.name}"
                ),
                "action": "mcp_tool",
                "tool_id": tool.id,
                "status": "installed" if installed else "missing",
                "detail": (
                    f"MCP tool: mitsu__armory_{tool.id.replace('-', '_')}\n"
                    f"Input: {tool.id.replace('-', '_')}_argv\n{tool.description}"
                ) + (
                    "\nSpace toggles this tool for future sessions."
                    if installed else
                    "\nThis tool is not installed. Install it from RedTeam Armory before enabling its MCP tool."
                ),
            })
        self.right_index = next(
            (index for index, item in enumerate(self.right_items) if item.get("tool_id") == selected_tool),
            0,
        )
        self._render_right_list()

    def _store_mcp_selection(self) -> bool:
        selected = {tool.id: tool.id in self.mcp_selected_tool_ids for tool in TOOLS}
        armory = self.mcp_config.get("armory") or {"enabled": True}
        self.mcp_config["armory"] = armory
        previous = armory.get("tools", {tool.id: True for tool in TOOLS})
        armory["tools"] = selected
        if self._write_mcp_configuration():
            self.mcp_load_error = None
            return True
        armory["tools"] = previous
        return False

    def _show_custom_tool_list(self) -> None:
        self.panel_kind = "mcp_custom_tools"
        custom_tools = self.mcp_config.get("custom_tools", [])
        self.right_items = [{
            "label": "+ Add a CLI tool",
            "action": "mcp_custom_add",
            "detail": (
                "Add an installed command-line program to Mitsu’s built-in MCP server. "
                "A short guided setup collects the command and tells the model how to use it."
            ),
        }]
        for index, tool in enumerate(custom_tools):
            self.right_items.append({
                "label": f"{tool['name']}  ·  {tool['command']}",
                "action": "mcp_custom_edit",
                "tool_index": str(index),
                "detail": (
                    f"MCP tool: mitsu__custom_{tool['id'].replace('-', '_')}\n"
                    f"{tool['description']}\n\nEnter to edit this tool."
                ),
            })
        self.right_index = 0
        self.query_one("#menu-right-title", Static).update("CUSTOM CLI TOOLS")
        self.query_one("#menu-footer", Static).update(
            "↑ / ↓ move    Enter add / edit    E advanced JSON    Esc server overview    Q quit"
        )
        self._set_mcp_editor_visible(False)
        self._set_custom_tool_form_visible(False)
        self._render_right_list()
        self.query_one("#menu-right-list", MenuList).focus()

    def _begin_custom_tool_form(self, tool_index: int | None = None) -> None:
        configured = self.mcp_config.get("custom_tools", [])
        self.custom_tool_edit_index = tool_index
        if tool_index is None:
            self.custom_tool_form_values = {}
            title = "ADD A CLI TOOL"
        else:
            tool = configured[tool_index]
            parameter_lines = []
            for parameter in tool.get("parameters", []):
                flag = parameter.get("flag", "")
                required = "required" if parameter.get("required", False) else "optional"
                parameter_lines.append(
                    f"{parameter['name']}|{flag}|{required}|{parameter['description']}"
                )
            self.custom_tool_form_values = {
                "name": tool["name"],
                "command": tool["command"],
                "args": shlex.join(tool.get("args", [])),
                "description": tool["description"],
                "usage": tool.get("usage", ""),
                "parameters": "; ".join(parameter_lines),
                "example": "; ".join(tool.get("examples", [])),
            }
            title = f"EDIT {tool['name']}"
        self.custom_tool_form_step = 0
        self.panel_kind = "mcp_custom_tool_form"
        self.query_one("#menu-custom-tool-form-title", Static).update(title)
        self.query_one("#menu-right-title", Static).update("CUSTOM CLI TOOL SETUP")
        self.query_one("#menu-footer", Static).update(
            "Enter next / save    Shift+Tab previous    Esc cancel    Q quit"
        )
        self._set_mcp_editor_visible(False)
        self._set_custom_tool_form_visible(True)
        self._render_custom_tool_form_step()

    def _render_custom_tool_form_step(self) -> None:
        key, label, placeholder, help_text, _required = CUSTOM_TOOL_FORM_STEPS[self.custom_tool_form_step]
        step = self.custom_tool_form_step + 1
        self.query_one("#menu-custom-tool-step", Static).update(
            f"Step {step} of {len(CUSTOM_TOOL_FORM_STEPS)} · {label}\n{help_text}"
        )
        field = self.query_one("#menu-custom-tool-input", Input)
        field.placeholder = placeholder
        field.value = self.custom_tool_form_values.get(key, "")
        field.focus()
        self.query_one("#menu-right-detail", Static).update(
            "Changes are saved to the local MCP config and take effect in new sessions. "
            "Mitsu runs the configured executable directly, without a shell."
        )

    def _submit_custom_tool_field(self, raw_value: str) -> None:
        key, label, _placeholder, _help_text, required = CUSTOM_TOOL_FORM_STEPS[self.custom_tool_form_step]
        value = raw_value.strip()
        if required and not value:
            self.query_one("#menu-right-detail", Static).update(f"{label} is required.")
            return
        self.custom_tool_form_values[key] = value
        if self.custom_tool_form_step < len(CUSTOM_TOOL_FORM_STEPS) - 1:
            self.custom_tool_form_step += 1
            self._render_custom_tool_form_step()
            return
        self._save_custom_tool_form()

    def _previous_custom_tool_field(self) -> None:
        if self.custom_tool_form_step > 0:
            current_key = CUSTOM_TOOL_FORM_STEPS[self.custom_tool_form_step][0]
            self.custom_tool_form_values[current_key] = self.query_one("#menu-custom-tool-input", Input).value.strip()
            self.custom_tool_form_step -= 1
            self._render_custom_tool_form_step()

    def _save_custom_tool_form(self) -> None:
        values = self.custom_tool_form_values
        try:
            if len(values["name"]) > 120:
                raise ValueError("Tool name must be 120 characters or fewer.")
            if len(values["description"]) > 4_000:
                raise ValueError("Description must be 4,000 characters or fewer.")
            if len(values.get("usage", "")) > 12_000:
                raise ValueError("Usage notes must be 12,000 characters or fewer.")
            if len(values.get("example", "")) > 1_000:
                raise ValueError("Example must be 1,000 characters or fewer.")
            command_parts = shlex.split(values.get("command", ""))
            if len(command_parts) != 1:
                raise ValueError("Enter one executable only; put fixed arguments in the previous field.")
            fixed_args = shlex.split(values.get("args", ""))
            parameters = []
            parameter_names: set[str] = set()
            for entry in filter(str.strip, values.get("parameters", "").split(";")):
                parts = entry.strip().split("|", 3)
                if len(parts) != 4:
                    raise ValueError("Each input must look like name|--flag|required|description.")
                name, flag, required, description = (part.strip() for part in parts)
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
                    raise ValueError(f"Input name {name!r} must start with a letter and use only letters, numbers, or underscores.")
                if name in parameter_names:
                    raise ValueError(f"Input {name!r} appears more than once.")
                if not description:
                    raise ValueError(f"Add a short description for input {name!r}.")
                parameter_names.add(name)
                if required.casefold() not in {"required", "optional"}:
                    raise ValueError("Input status must be ‘required’ or ‘optional’.")
                parameters.append({
                    "name": name,
                    "type": "string",
                    "flag": "" if flag == "-" else flag,
                    "required": required.casefold() == "required",
                    "description": description,
                })
            if len(parameters) > 48:
                raise ValueError("A custom CLI tool can have at most 48 named inputs.")
            configured = list(self.mcp_config.get("custom_tools", []))
            if self.custom_tool_edit_index is not None:
                old_parameters = {
                    parameter["name"]: parameter
                    for parameter in configured[self.custom_tool_edit_index].get("parameters", [])
                }
                for index, parameter in enumerate(parameters):
                    previous_parameter = old_parameters.get(parameter["name"])
                    if previous_parameter is not None:
                        merged = dict(previous_parameter)
                        merged.update(parameter)
                        if merged["required"]:
                            merged.pop("default", None)
                        parameters[index] = merged
            tool_id = re.sub(r"[^a-z0-9]+", "-", values["name"].casefold()).strip("-")
            if not tool_id or not tool_id[0].isalpha():
                tool_id = f"tool-{tool_id}"
            tool_id = tool_id[:48].rstrip("-") or "custom-tool"
            excluded_index = self.custom_tool_edit_index
            occupied = {
                item["id"] for index, item in enumerate(configured)
                if index != excluded_index
            }
            base_id = tool_id
            suffix = 2
            while tool_id in occupied:
                ending = f"-{suffix}"
                tool_id = f"{base_id[:48 - len(ending)].rstrip('-')}{ending}"
                suffix += 1
            definition = {
                "id": tool_id,
                "name": values["name"],
                "command": command_parts[0],
                "args": fixed_args,
                "description": values["description"],
                "usage": values.get("usage", ""),
                "examples": [values["example"]] if values.get("example") else [],
                "parameters": parameters,
                "timeout_seconds": 120,
                "read_only": False,
            }
        except (KeyError, ValueError) as error:
            self.query_one("#menu-right-detail", Static).update(str(error))
            return

        previous = list(self.mcp_config.get("custom_tools", []))
        updated = list(previous)
        if excluded_index is None:
            updated.append(definition)
            action = "Added"
        else:
            updated[excluded_index] = definition
            action = "Saved"
        self.mcp_config["custom_tools"] = updated
        if not self._write_mcp_configuration():
            self.mcp_config["custom_tools"] = previous
            return
        self._show_custom_tool_list()
        self.query_one("#menu-right-detail", Static).update(
            f"{action} {definition['name']} to Mitsu’s MCP server. It will be available in new sessions."
        )

    def _set_custom_tool_form_visible(self, visible: bool) -> None:
        form = self.query_one("#menu-custom-tool-form", Vertical)
        form.display = visible
        if visible:
            self.query_one("#menu-right-list", MenuList).display = False
            self.query_one("#menu-mcp-editor", TextArea).display = False
            self.query_one("#menu-right-detail", Static).display = True
        elif self.panel_kind != "mcp_editor":
            self.query_one("#menu-right-list", MenuList).display = True

    def _write_mcp_configuration(self) -> bool:
        if self.mcp_load_error:
            self.query_one("#menu-right-detail", Static).update(
                self.mcp_load_error + " Repair the file in Custom MCP configuration before changing selections."
            )
            return False
        try:
            if not MCPConfigDialog._valid_config(self.mcp_config):
                raise ValueError("MCP settings failed validation.")
            self.mcp_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.mcp_path.parent.chmod(0o700)
            descriptor, temporary_path = tempfile.mkstemp(prefix=".mcp_servers-", dir=self.mcp_path.parent)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    json.dump(self.mcp_config, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
                os.replace(temporary_path, self.mcp_path)
            except BaseException:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                Path(temporary_path).unlink(missing_ok=True)
                raise
            self.mcp_path.chmod(0o600)
        except (OSError, ValueError) as error:
            self.query_one("#menu-right-detail", Static).update(f"Could not save MCP settings: {error}")
            return False
        return True

    def _open_mcp_editor(self) -> None:
        if self.mcp_load_error:
            try:
                editor_text = self.mcp_path.read_text(encoding="utf-8")
            except OSError as error:
                editor_text = json.dumps(self.mcp_config, ensure_ascii=False, indent=2) + "\n"
                self.mcp_load_error = f"Could not read existing MCP settings: {error}"
        else:
            editor_text = json.dumps(self.mcp_config, ensure_ascii=False, indent=2) + "\n"
        editor = self.query_one("#menu-mcp-editor", TextArea)
        editor.load_text(editor_text)
        self.panel_kind = "mcp_editor"
        self.query_one("#menu-right-title", Static).update("ADVANCED MCP CONFIGURATION")
        self.query_one("#menu-footer", Static).update(
            "Ctrl+S save    Esc server overview    Q quit"
        )
        self.query_one("#menu-right-list", MenuList).display = False
        self.query_one("#menu-model-search", Input).display = False
        self._set_custom_tool_form_visible(False)
        self.query_one("#menu-right-detail", Static).update(
            'Use "custom_tools" to teach Mitsu an installed CLI: provide a unique id, executable, purpose, '
            'usage notes/examples, and named parameters with descriptions and optional CLI flags. Mitsu exposes each '
            'entry as its own documented MCP tool (mitsu__custom_<id>) and runs that executable directly without a shell. '
            'For example, copy the tool’s documented command into "args" and map "target" to "--target" with a '
            'description explaining which authorized target value to pass. Use "servers" for programs that already '
            'speak MCP. "armory.tools" only selects catalog tools. '
            'Ctrl+S validates and saves; changes apply to new sessions.'
        )
        self._set_mcp_editor_visible(True)
        editor.focus()

    def _save_mcp_editor(self) -> None:
        editor = self.query_one("#menu-mcp-editor", TextArea)
        try:
            value = json.loads(editor.text)
        except json.JSONDecodeError as error:
            self.query_one("#menu-right-detail", Static).update(
                f"Invalid JSON: {error.msg} at line {error.lineno}. Fix it, then press Ctrl+S."
            )
            return
        if not MCPConfigDialog._valid_config(value):
            self.query_one("#menu-right-detail", Static).update(
                'Use an object with a "servers" list and optional "custom_tools" list. Custom CLI entries need an id, name, '
                'command, description, and documented parameters. Native servers need a name and command or http(s) URL.'
            )
            return
        value = dict(value)
        armory = dict(value.get("armory") or {"enabled": True})
        selection = armory.get("tools", ["*"])
        if isinstance(selection, dict):
            selected_tool_ids = {
                tool_id for tool_id, enabled in selection.items() if enabled is True
            }
        else:
            identifiers = set(selection)
            if "*" in identifiers:
                selected_tool_ids = {tool.id for tool in TOOLS}
            else:
                selected_tool_ids = identifiers & set(TOOL_BY_ID)
                for category_id in identifiers:
                    selected_tool_ids.update(
                        tool.id for tool in TOOLS_BY_CATEGORY.get(category_id, ())
                    )
        armory["tools"] = {
            tool.id: tool.id in selected_tool_ids
            for tool in TOOLS
        }
        value["armory"] = armory
        previous = self.mcp_config
        previous_error = self.mcp_load_error
        self.mcp_config = value
        # A valid editor save is also the repair path for an unreadable or malformed file.
        self.mcp_load_error = None
        if not self._write_mcp_configuration():
            self.mcp_config = previous
            self.mcp_load_error = previous_error
            return
        self.mcp_selected_tool_ids = selected_tool_ids
        self._show_mcp_categories()
        self.query_one("#menu-right-detail", Static).update(
            "MCP configuration saved. Custom CLI tools, servers, and Armory selections apply to new sessions."
        )
        self.query_one("#menu-right-list", MenuList).focus()

    def _set_mcp_editor_visible(self, visible: bool) -> None:
        editor = self.query_one("#menu-mcp-editor", TextArea)
        editor.display = visible
        if visible:
            self.query_one("#menu-custom-tool-form", Vertical).display = False
        self.query_one("#menu-right-list", MenuList).display = not visible
        self.query_one("#menu-right-detail", Static).display = True

    def _mcp_back(self) -> None:
        if self.panel_kind == "mcp_editor":
            self._set_mcp_editor_visible(False)
            self._show_mcp_categories()
            self.query_one("#menu-right-list", MenuList).focus()
        elif self.panel_kind == "mcp_custom_tool_form":
            self._show_custom_tool_list()
            self.query_one("#menu-right-list", MenuList).focus()
        elif self.panel_kind == "mcp_custom_tools":
            self._show_mcp_categories()
            self.query_one("#menu-right-list", MenuList).focus()
        elif self.panel_kind == "mcp_tools":
            self._show_mcp_armory_categories()
            self.query_one("#menu-right-list", MenuList).focus()
        elif self.panel_kind in {"mcp_armory_categories", "mcp_loading"}:
            self._show_mcp_categories()
            self.query_one("#menu-right-list", MenuList).focus()
        elif self.panel_kind == "mcp_categories":
            self.left_index = 1
            self.active_panel = "right"
            self._show_left_selection()
            self.right_index = 2
            self._render_right_list()
            self.query_one("#menu-right-list", MenuList).focus()

    def _search_engines_closed(self, saved: bool | None) -> None:
        if saved:
            self.query_one("#menu-right-detail", Static).update(
                "Search engine settings saved. Configured sources are ready for web searches."
            )

    async def _open_armory(self) -> None:
        self.armory_environment = await asyncio.to_thread(load_host_environment)
        self.armory_statuses.clear()
        self._show_armory_categories()
        self.query_one("#menu-right-list", MenuList).focus()

    def _show_armory_categories(self) -> None:
        self.panel_kind = "armory_categories"
        self.armory_category_id = None
        self.armory_tool_id = None
        self.query_one("#menu-right-title", Static).update("REDTEAM ARMORY")
        self.right_items = [
            {
                "label": f"{category.name}  ·  {len(TOOLS_BY_CATEGORY[category.id])} tools",
                "action": "armory_category",
                "category_id": category.id,
                "detail": category.description,
            }
            for category in ARMORY_CATEGORIES
        ]
        self.right_index = 0
        self._render_right_list()
        environment = self.armory_environment
        if environment is None:
            detail = "Host details are unavailable."
        else:
            manager = environment.package_manager_name
            detail = (
                f"{environment.os_name} · {manager}. Choose a category to inspect installed tools. "
                "Installs use native packages or catalogued upstream methods and run visibly in a new terminal. "
                "Mitsu only catalogs tools here; it does not execute them."
            )
            if not environment.package_manager_id:
                detail += " No supported package manager was detected."
        self.query_one("#menu-right-detail", Static).update(detail)

    async def _load_armory_tools(self, category_id: str) -> None:
        if category_id not in TOOLS_BY_CATEGORY or self.armory_environment is None:
            return
        self.armory_category_id = category_id
        self.panel_kind = "armory_loading"
        category = next(category for category in ARMORY_CATEGORIES if category.id == category_id)
        self.query_one("#menu-right-title", Static).update(category.name.upper())
        self.query_one("#menu-right-list", MenuList).update("Checking installed tools…")
        self.query_one("#menu-right-detail", Static).update(
            f"Reading package status on {self.armory_environment.os_name}."
        )
        environment = self.armory_environment
        tools = TOOLS_BY_CATEGORY[category_id]
        statuses = await asyncio.to_thread(
            lambda: {tool.id: inspect_tool(tool, environment) for tool in tools}
        )
        if self.panel_kind != "armory_loading":
            return
        self.armory_statuses.update(statuses)
        self._display_armory_tools(category_id)
        self.query_one("#menu-right-list", MenuList).focus()

    def _display_armory_tools(self, category_id: str, *, selected_tool: str | None = None) -> None:
        self.panel_kind = "armory_tools"
        self.armory_category_id = category_id
        category = next(category for category in ARMORY_CATEGORIES if category.id == category_id)
        self.query_one("#menu-right-title", Static).update(category.name.upper())
        self.right_items = []
        for tool in TOOLS_BY_CATEGORY[category_id]:
            status = self.armory_statuses.get(tool.id, ToolStatus(False, False))
            label = f"{'INSTALLED' if status.installed else 'NOT INSTALLED'}  ·  {tool.name}"
            self.right_items.append(
                {
                    "label": label,
                    "action": "armory_tool",
                    "tool_id": tool.id,
                    "status": "installed" if status.installed else "missing",
                    "detail": tool.description,
                }
            )
        self.right_index = next(
            (index for index, item in enumerate(self.right_items) if item.get("tool_id") == selected_tool),
            0,
        )
        self._render_right_list()
        self.query_one("#menu-right-detail", Static).update(
            "Enter to manage a tool · Esc / ← back to categories. Installing or removing opens a terminal."
        )

    def _show_armory_confirmation(self, tool_id: str) -> None:
        tool = TOOL_BY_ID.get(tool_id)
        if tool is None:
            return
        self.armory_tool_id = tool_id
        status = self.armory_statuses.get(tool_id, ToolStatus(False, False))
        self.panel_kind = "armory_confirm"
        if status.installed and not status.managed:
            self.query_one("#menu-right-title", Static).update("TOOL ALREADY PRESENT")
            self.right_items = [
                {
                    "label": "Back to tools",
                    "action": "armory_cancel",
                    "detail": "This executable is present, but Mitsu cannot identify a managed installation for it.",
                }
            ]
            detail = (
                f"{tool.name} is present outside Mitsu's supported install sources. "
                "Mitsu cannot safely remove a manual installation."
            )
        elif status.installed:
            self.query_one("#menu-right-title", Static).update("REMOVE TOOL?")
            detail = (
                f"{tool.name} is installed. Would you like to remove it? "
                "The selected installer will show what it plans to remove."
            )
            self.right_items = [
                {"label": "No · keep it installed", "action": "armory_cancel", "detail": "No changes will be made."},
                {"label": "Yes · uninstall", "action": "armory_uninstall", "detail": "This opens the selected installer in a new terminal."},
            ]
        else:
            self.query_one("#menu-right-title", Static).update("INSTALL TOOL?")
            detail = f"{tool.name} is not installed. Want me to install it for you? (＾▽＾)"
            self.right_items = [
                {"label": "No · go back", "action": "armory_cancel", "detail": "No changes will be made."},
                {"label": "Yes · install", "action": "armory_install", "detail": "This opens the selected installer in a new terminal."},
            ]
        self.right_index = 0
        self._render_right_list()
        self.query_one("#menu-right-detail", Static).update(detail)

    async def _start_armory_operation(self, operation: str) -> None:
        if self.armory_operation_process is not None:
            return
        tool = TOOL_BY_ID.get(self.armory_tool_id or "")
        environment = self.armory_environment
        if tool is None or environment is None:
            return
        try:
            process, method_id = await asyncio.to_thread(open_install_terminal, tool, environment, operation)
        except ArmoryError as error:
            self.query_one("#menu-right-detail", Static).update(str(error))
            return
        self.armory_operation_process = process
        self.armory_operation = operation
        self.armory_operation_method_id = method_id
        category_id = self.armory_category_id
        if category_id:
            self._display_armory_tools(category_id, selected_tool=tool.id)
        self.panel_kind = "armory_running"
        self.query_one("#menu-right-detail", Static).update(
            "A new terminal is showing the install or removal output. Status refreshes while it runs. "
            "Mitsu catalogs tools here; it does not execute them."
        )
        self.run_worker(
            self._watch_armory_operation(process, tool, operation, method_id),
            name="redteam-armory-package-operation",
            exclusive=True,
        )

    async def _watch_armory_operation(self, process, tool, operation: str, method_id: str) -> None:
        environment = self.armory_environment
        if environment is None:
            return
        previous = self.armory_statuses.get(tool.id, ToolStatus(False, False))
        while process.poll() is None:
            await asyncio.sleep(1.0)
            current = await asyncio.to_thread(inspect_tool, tool, environment)
            if current != previous:
                previous = current
                self.armory_statuses[tool.id] = current
                if self.panel_kind == "armory_running":
                    for item in self.right_items:
                        if item.get("tool_id") == tool.id:
                            item["label"] = f"{'INSTALLED' if current.installed else 'NOT INSTALLED'}  ·  {tool.name}"
                            item["status"] = "installed" if current.installed else "missing"
                    self._render_right_list()
                    self.query_one("#menu-right-detail", Static).update(
                        f"{tool.name} status updated. Close the terminal when you are done reviewing its output."
                    )
        return_code = process.poll()
        final_status = await asyncio.to_thread(inspect_tool, tool, environment)
        if operation == "install" and return_code == 0 and not method_id.startswith("system:"):
            if method_id.startswith("official-script:"):
                await asyncio.to_thread(record_managed_install, tool.id, method_id)
            final_status = await asyncio.to_thread(inspect_tool, tool, environment)
            if not final_status.installed and method_id.startswith("official-script:"):
                await asyncio.to_thread(forget_managed_install, tool.id)
                final_status = await asyncio.to_thread(inspect_tool, tool, environment)
        elif operation == "uninstall" and return_code == 0 and not final_status.installed:
            await asyncio.to_thread(forget_managed_install, tool.id)
        self.armory_statuses[tool.id] = final_status
        self.armory_operation_process = None
        self.armory_operation = None
        self.armory_operation_method_id = None
        category_id = self.armory_category_id
        if self.panel_kind != "armory_running" or category_id is None:
            return
        self._display_armory_tools(category_id, selected_tool=tool.id)
        if return_code == 0 and final_status.installed == (operation == "install"):
            message = f"{tool.name} is now {'installed' if final_status.installed else 'uninstalled'}."
        else:
            message = f"Package operation ended with status {return_code}; check the terminal output."
        self.query_one("#menu-right-detail", Static).update(message)

    def _armory_back(self) -> None:
        if self.armory_operation_process is not None and self.armory_operation_process.poll() is None:
            self.query_one("#menu-right-detail", Static).update(
                "The package manager is still running in its terminal. Close it after the operation finishes."
            )
            return
        if self.panel_kind == "armory_confirm" and self.armory_category_id:
            self._display_armory_tools(self.armory_category_id, selected_tool=self.armory_tool_id)
            self.query_one("#menu-right-list", MenuList).focus()
        elif self.panel_kind in {"armory_tools", "armory_loading"}:
            self._show_armory_categories()
            self.query_one("#menu-right-list", MenuList).focus()
        elif self.panel_kind == "armory_categories":
            self.armory_environment = None
            self.left_index = 1
            self.active_panel = "right"
            self._show_left_selection()
            self.right_index = 4
            self._render_right_list()
            self.query_one("#menu-right-list", MenuList).focus()

    def _show_left_selection(self) -> None:
        model_search = self.query_one("#menu-model-search", Input)
        model_search.display = False
        model_search.disabled = False
        model_search.value = ""
        kind = ("sessions", "configuration", "update", "quit")[self.left_index]
        self.query_one("#menu-footer", Static).update(
            "↑ / ↓ move    Enter select / open    Del remove session    ← / Esc command center    Tab switch panel    Q quit"
        )
        self.panel_kind = kind
        self.right_index = 0
        title = {
            "sessions": "SESSIONS",
            "configuration": "CONFIGURATION",
            "update": "UPDATE MITSU",
            "quit": "QUIT MITSU",
        }[kind]
        self.query_one("#menu-right-title", Static).update(title)
        if kind == "sessions":
            self.right_items = [
                {
                    "label": f"[{index}] {str(record.get('title', 'Untitled session')).splitlines()[0]}",
                    "action": "open_session",
                    "session_id": str(record["id"]),
                    "detail": self._session_detail(record),
                }
                for index, record in enumerate(self.records, start=1)
                if record.get("id")
            ]
            self.right_items.append(
                {"label": "[+] CREATE NEW SESSION", "action": "create_session", "detail": "Start a fresh session."}
            )
        elif kind == "configuration":
            self.right_items = [
                {"label": f"[{index}] {label}", "action": action, "detail": detail}
                for index, ((label, detail), action) in enumerate(
                    zip(self.CONFIG_ITEMS, (
                        "change_provider", "set_model", "mcp", "search_engines", "armory", "companions",
                    )),
                    start=1,
                )
            ]
        elif kind == "update":
            self.right_items = []
        else:
            self.right_items = []
        self._render_right_list()
        if kind == "update":
            self.query_one("#menu-right-detail", Static).update(self.update_status)
        elif kind == "quit":
            self.query_one("#menu-right-detail", Static).update("Exit Mitsu and return to your shell.")

    def _render_left_list(self) -> None:
        output = Text()
        for index, item in enumerate(self.LEFT_ITEMS):
            selected = index == self.left_index
            if selected and self.active_panel == "left":
                output.append("› ", style=Style(color=self.accent, bold=True))
                output.append(f"[*] {item}", style=Style(color=self.accent, bold=True, underline=True))
            elif selected:
                output.append("  ", style="#938a84")
                output.append(f"[*] {item}", style=Style(color=self.accent, bold=True))
            else:
                output.append("  [*] ", style="#817a75")
                output.append(item, style="#d0cbc5")
            if index + 1 < len(self.LEFT_ITEMS):
                output.append("\n")
        self.query_one("#menu-left-list", Static).update(output)

    def _render_right_list(self) -> None:
        list_widget = self.query_one("#menu-right-list", Static)
        detail_widget = self.query_one("#menu-right-detail", Static)
        output = Text()
        available_rows = max(1, min(18, list_widget.size.height or 18))
        visible_count = min(14, len(self.right_items), max(1, available_rows - 2))
        start = max(0, min(self.right_index - visible_count // 2, len(self.right_items) - visible_count))
        visible_items = self.right_items[start : start + visible_count]
        show_earlier = start > 0
        show_later = start + len(visible_items) < len(self.right_items)
        if visible_count + int(show_earlier) + int(show_later) > available_rows:
            show_earlier = show_later = False
        if show_earlier:
            output.append("  ↑ earlier items\n", style="#817a75")
        for offset, item in enumerate(visible_items):
            index = start + offset
            selected = index == self.right_index
            status = item.get("status")
            if status:
                output.append("● ", style="#79d78c" if status == "installed" else "#ef7180")
            if selected and self.active_panel == "right":
                output.append("› ", style=Style(color=self.accent, bold=True))
                output.append(item["label"], style=Style(color=self.accent, bold=True, underline=True))
            elif selected:
                output.append("  ", style="#938a84")
                output.append(item["label"], style=Style(color=self.accent, bold=True))
            else:
                output.append("  ", style="#817a75")
                output.append(item["label"], style="#d0cbc5")
            if index + 1 < start + len(visible_items):
                output.append("\n")
        if show_later:
            output.append("\n  ↓ more items", style="#817a75")
        list_widget.update(output)
        if self.right_items:
            detail_widget.update(self.right_items[self.right_index].get("detail", ""))
        else:
            detail_widget.update("")
        if self.panel_kind == "companions" and self.right_items:
            selected = self.right_items[self.right_index]
            self._set_menu_companion(selected["companion_id"])

    async def _check_for_updates(self) -> None:
        detail = self.query_one("#menu-right-detail", Static)
        self.update_status = f"Checking GitHub for a version newer than v{__version__}…"
        detail.update(self.update_status)
        try:
            latest = await asyncio.to_thread(fetch_latest_version)
        except (OSError, ValueError) as error:
            self.update_status = f"Could not check GitHub: {error}"
        else:
            if latest is None:
                self.update_status = "The upstream repository does not have a version.txt yet."
            elif compare_versions(latest, __version__) > 0:
                self.update_status = f"Mitsu v{latest} is available. Installed version: v{__version__}."
            elif compare_versions(latest, __version__) < 0:
                self.update_status = f"GitHub reports v{latest}; this checkout is v{__version__}."
            else:
                self.update_status = f"You’re up to date: v{__version__}."
        if self.panel_kind == "update":
            detail.update(self.update_status)

    def _begin_provider_selection(self) -> None:
        self.inline_flow = "provider"
        self.pending_profile = None
        self.input_stage = None
        self.api_key_prompted = False
        self.panel_kind = "provider_list"
        self.right_index = next(
            (index for index, provider in enumerate(PROVIDERS)
             if provider.id == self.profile.get("provider_id")),
            0,
        )
        self.right_items = [
            {
                "label": f"[{index}] {provider.name}",
                "action": "select_provider",
                "provider_id": provider.id,
                "detail": "Press Enter to configure this provider.",
            }
            for index, provider in enumerate(PROVIDERS, start=1)
        ]
        self.query_one("#menu-right-title", Static).update("CHOOSE PROVIDER")
        self._render_right_list()
        self.query_one("#menu-right-detail", Static).update(
            "Saved API keys are reused. Choose a provider with ↑ / ↓ and Enter."
        )

    def _begin_model_selection(self) -> None:
        profiles = self.credentials.configured_profiles()
        if not profiles:
            self.query_one("#menu-right-detail", Static).update("Configure a provider before choosing a model.")
            return
        self.inline_flow = "model"
        self.pending_profile = None
        self.panel_kind = "configured_models"
        self.run_worker(
            self._load_all_provider_models(profiles),
            name="load-configured-provider-models",
            exclusive=True,
        )

    async def _load_all_provider_models(self, profiles: list[dict] | None = None) -> None:
        profiles = profiles or self.credentials.configured_profiles()
        self.panel_kind = "configured_models"
        self.query_one("#menu-right-title", Static).update("MODELS FROM CONFIGURED PROVIDERS")
        self.query_one("#menu-right-list", Static).update("")
        self.query_one("#menu-right-detail", Static).update("Loading each configured provider’s model list…")
        self._hide_inline_inputs()
        search = self.query_one("#menu-model-search", Input)
        search.display = True
        search.disabled = True
        search.value = ""
        search.placeholder = "Loading models from configured providers…"
        self.configured_model_items = []
        self.configured_model_failures = []
        search.focus()
        results = await asyncio.gather(
            *(asyncio.to_thread(list_models, profile) for profile in profiles),
            return_exceptions=True,
        )
        if self.panel_kind != "configured_models":
            return
        failures = []
        for profile, result in zip(profiles, results):
            spec = PROVIDER_BY_ID[str(profile["provider_id"])]
            if isinstance(result, BaseException):
                failures.append(f"{spec.name}: {result}")
                continue
            for model in result:
                self.configured_model_items.append(
                    {
                        "label": f"{spec.name}  ·  {model}",
                        "action": "select_configured_model",
                        "provider_id": spec.id,
                        "model": model,
                        "detail": f"Use {model} with {spec.name}.",
                    }
                )
        self.configured_model_failures = failures
        search.disabled = False
        search.placeholder = "Filter models across configured providers"
        if self.configured_model_items:
            self.right_index = next(
                (
                    index
                    for index, item in enumerate(self.configured_model_items)
                    if item["provider_id"] == self.profile.get("provider_id")
                    and item["model"] == self.profile.get("model")
                ),
                0,
            )
            self.right_items = list(self.configured_model_items)
            self._filter_configured_models(search.value)
            search.focus()
            return
        search.display = False
        search.disabled = False
        self.right_items = [
            {"label": "[↻] RETRY MODEL LISTS", "action": "retry_models", "detail": "Try the configured providers again."}
        ]
        self.right_index = 0
        self._render_right_list()
        self.query_one("#menu-right-detail", Static).update(
            "No models were returned. " + (" · ".join(failures) if failures else "Check provider setup.")
        )

    def _filter_configured_models(self, query: str) -> None:
        normalized = query.casefold().strip()
        selected = None
        if self.right_items and 0 <= self.right_index < len(self.right_items):
            item = self.right_items[self.right_index]
            selected = (item.get("provider_id"), item.get("model"))
        matches = [
            item for item in self.configured_model_items
            if not normalized or normalized in item["label"].casefold()
        ]
        self.right_items = matches
        self.right_index = next(
            (
                index for index, item in enumerate(matches)
                if selected == (item.get("provider_id"), item.get("model"))
            ),
            0,
        )
        self._render_right_list()
        detail = (
            f"{len(matches)} matching models · ↑ / ↓ browse · Enter to choose."
            if matches
            else "No matching models. Try another model or provider name."
        )
        if self.configured_model_failures:
            detail += " Some providers could not be reached: " + " · ".join(self.configured_model_failures)
        self.query_one("#menu-right-detail", Static).update(detail)

    async def _choose_provider(self, provider_id: str) -> None:
        spec = PROVIDER_BY_ID[provider_id]
        profile = self.credentials.profile_for(provider_id)
        self.pending_profile = dict(profile) if profile else {
            "provider_id": provider_id,
            "base_url": spec.base_url,
            "model": "",
            "api_key": "",
            "protocol": spec.protocol,
        }
        self.inline_flow = "provider"
        self.panel_kind = "provider_setup"
        self.api_key_prompted = False
        self._continue_pending_profile()

    def _continue_pending_profile(self) -> None:
        profile = self.pending_profile
        if profile is None:
            return
        provider_id = str(profile.get("provider_id", ""))
        spec = PROVIDER_BY_ID[provider_id]
        if provider_id == "custom" and not profile.get("base_url"):
            self._request_inline_input(
                "base_url",
                "CUSTOM ENDPOINT",
                "Enter the base URL for your endpoint.",
                "https://your-endpoint.example/v1",
            )
            return
        if spec.requires_api_key and not profile.get("api_key"):
            prompt = f"Please input your API key for {spec.name}."
            self.api_key_prompted = True
            self._request_inline_input("api_key", f"{spec.name.upper()} API KEY", prompt, "Paste API key", secret=True)
            return
        if provider_id == "custom" and not profile.get("api_key") and not self.api_key_prompted:
            self.api_key_prompted = True
            self._request_inline_input(
                "api_key",
                "CUSTOM ENDPOINT API KEY",
                "Please set your custom endpoint API key (if applicable).",
                "Paste API key",
                secret=True,
            )
            return
        if provider_id == "cloudflare" and not self._has_cloudflare_account(str(profile.get("base_url", ""))):
            self._request_inline_input(
                "account_id",
                "CLOUDFLARE ACCOUNT",
                "Enter the account ID used by your Workers AI endpoint.",
                "Cloudflare account ID",
            )
            return
        if provider_id == "custom":
            self._request_inline_input(
                "model_name",
                "MODEL NAME",
                "Enter the model ID exactly as your endpoint expects it.",
                "Provider model ID",
            )
            return
        self.run_worker(self._load_pending_models(), name="load-provider-models", exclusive=True)

    def _request_inline_input(
        self,
        stage: str,
        title: str,
        prompt: str,
        placeholder: str,
        secret: bool = False,
    ) -> None:
        self.input_stage = stage
        self.panel_kind = "inline_input"
        self.right_items = []
        self.right_index = 0
        self.query_one("#menu-right-title", Static).update(title)
        self.query_one("#menu-right-list", Static).update("")
        note = ""
        if stage == "api_key":
            profile = self.pending_profile or {}
            if profile.get("api_key"):
                note = "\n\nAPI key already set [!]. Leave empty to keep unchanged."
            elif profile.get("provider_id") == "custom":
                note = "\n\nLeave empty if no API key is used."
            else:
                note = "\n\nAn API key is required to load this provider’s models."
        note += "\n\nEsc returns to Configuration. Enter submits."
        self.query_one("#menu-right-detail", Static).update(prompt + note)
        secret_input = self.query_one("#menu-secret-input", Input)
        text_input = self.query_one("#menu-text-input", Input)
        secret_input.display = secret
        text_input.display = not secret
        current = secret_input if secret else text_input
        current.placeholder = placeholder
        current.value = ""
        current.focus()

    async def _submit_inline_input(self, value: str) -> None:
        stage = self.input_stage
        profile = self.pending_profile
        if not stage or profile is None:
            return
        if stage == "api_key":
            provider_id = str(profile.get("provider_id", ""))
            spec = PROVIDER_BY_ID[provider_id]
            if spec.requires_api_key and not value and not profile.get("api_key"):
                self.query_one("#menu-right-detail", Static).update(
                    f"{spec.name} needs an API key to load its model list.\n\nEsc returns to Configuration."
                )
                self.query_one("#menu-secret-input", Input).focus()
                return
            if value:
                profile["api_key"] = value
        elif stage == "base_url":
            if not self._valid_endpoint(value):
                self.query_one("#menu-right-detail", Static).update(
                    "Enter a complete http:// or https:// base URL.\n\nEsc returns to Configuration."
                )
                self.query_one("#menu-text-input", Input).focus()
                return
            profile["base_url"] = value.rstrip("/")
            profile["protocol"] = str(profile.get("protocol") or "openai")
        elif stage == "account_id":
            if not re.fullmatch(r"[A-Fa-f0-9]{32}", value):
                self.query_one("#menu-right-detail", Static).update(
                    "Enter the 32-character Cloudflare account ID.\n\nEsc returns to Configuration."
                )
                self.query_one("#menu-text-input", Input).focus()
                return
            profile["base_url"] = PROVIDER_BY_ID["cloudflare"].base_url.format(account_id=value)
        elif stage == "model_name":
            if not value:
                self.query_one("#menu-right-detail", Static).update(
                    "Enter the model ID used by your endpoint.\n\nEsc returns to Configuration."
                )
                self.query_one("#menu-text-input", Input).focus()
                return
            await self._save_pending_profile(value)
            return
        self._hide_inline_inputs()
        self._continue_pending_profile()

    async def _load_pending_models(self) -> None:
        profile = self.pending_profile
        if profile is None:
            return
        provider_id = str(profile.get("provider_id", ""))
        provider = PROVIDER_BY_ID[provider_id]
        self.panel_kind = "model_list"
        self.input_stage = None
        self.query_one("#menu-right-title", Static).update("AVAILABLE MODELS")
        self.query_one("#menu-right-list", Static).update("")
        self.query_one("#menu-right-detail", Static).update(f"Loading models from {provider.name}…")
        self._hide_inline_inputs()
        try:
            models = await asyncio.to_thread(list_models, profile)
        except ProviderRequestError as error:
            self.right_items = [
                {"label": "[↻] TRY AGAIN", "action": "retry_models", "detail": str(error)}
            ]
            self.right_index = 0
            self.query_one("#menu-right-title", Static).update("MODEL LIST UNAVAILABLE")
            self._render_right_list()
            return
        if not models:
            self.right_items = [
                {"label": "[↻] TRY AGAIN", "action": "retry_models", "detail": "No models were returned."}
            ]
            self.right_index = 0
            self.query_one("#menu-right-title", Static).update("NO MODELS FOUND")
            self._render_right_list()
            return
        self.right_items = [
            {
                "label": f"[{index}] {model}",
                "action": "select_model",
                "model": model,
                "detail": "Press Enter to use this model.",
            }
            for index, model in enumerate(models, start=1)
        ]
        self.right_index = next(
            (index for index, item in enumerate(self.right_items)
             if item["model"] == profile.get("model")),
            0,
        )
        self._render_right_list()
        self.query_one("#menu-right-detail", Static).update("Choose a model with ↑ / ↓ and Enter.")

    async def _save_pending_profile(self, model: str) -> None:
        if self.pending_profile is None:
            return
        flow = self.inline_flow
        if model != str(self.pending_profile.get("model", "")):
            self.pending_profile["reasoning_enabled"] = False
            self.pending_profile["reasoning_parameter"] = ""
            self.pending_profile["reasoning_effort"] = "medium"
        self.pending_profile["model"] = model
        try:
            self.credentials.save_profile(self.pending_profile)
        except OSError as error:
            self.query_one("#menu-right-detail", Static).update(f"Could not save provider settings: {error}")
            return
        provider = PROVIDER_BY_ID[str(self.pending_profile["provider_id"])].name
        self.profile = self.credentials.active() or dict(self.pending_profile)
        self.query_one("#menu-runtime-info", Static).update(_runtime_info(provider, model))
        self.pending_profile = None
        self.inline_flow = None
        self.input_stage = None
        self.left_index = 1
        self.active_panel = "right"
        self._hide_inline_inputs()
        self._show_left_selection()
        self.right_index = 0 if flow == "provider" else 1
        self.right_index = 0 if self.right_index >= len(self.right_items) else self.right_index
        self.right_items[self.right_index]["detail"] = f"Saved {provider} · {model}."
        self._render_left_list()
        self._render_right_list()

    def _cancel_inline_flow(self) -> None:
        if not self.inline_flow:
            return
        self._hide_inline_inputs()
        self.pending_profile = None
        self.inline_flow = None
        self.input_stage = None
        self.left_index = 1
        self.active_panel = "right"
        self._show_left_selection()
        self._render_left_list()

    def _hide_inline_inputs(self) -> None:
        for widget_id in ("#menu-secret-input", "#menu-text-input", "#menu-model-search"):
            widget = self.query_one(widget_id, Input)
            widget.display = False
            widget.disabled = False
            widget.value = ""
        if self.is_mounted:
            target = "#menu-left-list" if self.active_panel == "left" else "#menu-right-list"
            self.query_one(target, MenuList).focus()

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

    def _set_menu_companion(self, companion_id: str) -> None:
        companion = companion_by_id(companion_id)
        mascot = self.query_one("#menu-companion", MitsuCompanion)
        if mascot.sprite_path != companion.path:
            mascot.set_companion(companion.path)
        mascot.set_state("running_right")

    def _provider_name(self) -> str:
        provider = str(self.profile.get("provider_id", ""))
        provider_spec = PROVIDER_BY_ID.get(provider)
        return provider_spec.name if provider_spec else "Not configured"

    @staticmethod
    def _session_detail(record: dict) -> str:
        provider = str(record.get("provider_id", "provider")).replace("_", " ").title()
        model = record.get("model", "")
        return f"{provider} · {model}\nUpdated {MainMenuScreen._format_date(record.get('updated_at', ''))}"

    @staticmethod
    def _format_date(value: str) -> str:
        try:
            return datetime.fromisoformat(value).astimezone().strftime("%b %d · %H:%M")
        except (TypeError, ValueError):
            return "Recently"
