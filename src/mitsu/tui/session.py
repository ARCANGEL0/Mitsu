from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
from datetime import date, datetime
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

from pygments.token import Token
from pygments.util import ClassNotFound
from rich.console import Group
from rich.style import Style
from rich.syntax import Syntax, SyntaxTheme
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Input, OptionList, Static, TextArea

from mitsu import __version__
from mitsu.agents import history_from_legacy, run_agent_turn
from mitsu.companions import COMPANIONS, companion_by_id
from mitsu.config import PROVIDER_BY_ID, THEMES, CredentialStore, SessionStore
from mitsu.providers import ProviderRequestError, check_reasoning_support
from mitsu.history import apply_undo_changes, capture_workspace, diff_workspace
from mitsu.tui.widgets import MitsuCompanion
from mitsu.tools import AgentToolHost
from mitsu.tui.dialogs import ConfigurationDialog, ProviderDialog, SearchEngineDialog


OPENING_GREETINGS = (
    "Hewwoo! Online and ready to investigate (✿˶ᵔ ᵕ ᵔ˶), what’s our plan?",
    "Heeey, I’m here! What are we poking at today? (｡•̀ᴗ-)✧",
    "Hewwooo, boss~ toss me the mystery and I’ll start connecting dots (≧◡≦)",
    "Psst, I’m online! Got a lab, a weird alert, or a little mystery for me? (๑˃ᴗ˂)ﻭ",
    "Yoohoo! Terminal’s open and I’m all ears (˶ᵔ ᵕ ᵔ˶) what’s going on?",
    "Mitsu’s hereee. Give me the short version and I’ll dig in (✿◠‿◠)",
    "Hiii! Point me at the puzzle, operator (｀･ω･´)ゞ",
    "Oh, a new mission? I’m listening (≧▽≦) where do we start?",
    "Hey hey, I made it! What should we check first? (•̀ᴗ•́)و",
    "Booted up and mildly curious~ what are we investigating today? (｡>ω<｡)",
    "Hewwoo! I brought tiny hacker energy and too many tabs (๑>ᴗ<๑) what’s the mission?",
    "I’m online, I’m ready, and I promise not to bite the terminal (ง'̀-'́)ง What’s our plan?",
)

MODE_COLORS = {
    "Recon": {"foreground": "#18140b", "background": "#e9c46a"},
    "Guided": {"foreground": "#071521", "background": "#4d8fe8"},
    "AutoPwn": {"foreground": "#fff5f5", "background": "#d94b5b"},
}

LEVEL_NAMES = {
    1: "Opsec Kiddy",
    2: "Curious mode",
    3: "Chill",
    4: "LulzSec Intern",
    5: "Mista Robot",
}


class PromptTextArea(TextArea):
    BINDINGS = [
        Binding("enter", "submit_prompt", "Send", priority=True),
        Binding("shift+enter", "insert_newline", "New line", priority=True),
        Binding("tab", "complete_slash_command", "Complete command", show=False, priority=True),
    ]

    COMMANDS = (
        ("/model", "choose a configured model", False),
        ("/connect", "configure a provider", False),
        ("/config", "configure one or more web search engines", False),
        ("/new", "start a fresh session", False),
        ("/target", "set or manage authorized scope", True),
        ("/mode", "switch Recon, Guided, or AutoPwn", True),
        ("/permissions", "review or clear saved approvals", True),
        ("/search", "find text in this conversation", True),
        ("/delete-session", "delete this session", False),
        ("/report", "write an assessment from session intel", False),
        ("/mcp", "configure MCP servers", False),
        ("/clear", "clear this conversation", False),
        ("/exit", "return to the command center", False),
        ("/help", "show command help", False),
        ("/level", "Change aggressiveness level for workflow", False),
        ("/export", "copy or save this session history", False),
        ("/rewind", "rewind to an earlier conversation point", False),
        ("/map", "show the attack surface map", False),
        ("/menu", "return to the command center", False),
        ("/pet", "change Mitsu’s companion", False),
        ("/nmap", "run an authorized scan", True),
        ("/reasoning", "set model reasoning effort", True),
        ("/recon", "run an authorized reconnaissance scan", True),
        ("/rename", "rename this session", True),
        ("/scan", "run an authorized scan", True),
        ("/scrape", "run an authorized web scrape", True),
        ("/setup", "open setup and preferences", False),
        ("/verbose", "toggle detailed output", True),
        ("/vulnsearch", "search local exploit references", True),
        ("/theme", "change the TUI color palette", False),
        ("/quit", "return to the command center", False),
    )

    class SlashSuggestionsChanged(Message):
        pass

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.slash_suggestions: list[tuple[str, str, bool]] = []
        self.slash_suggestion_index = 0

    class Submitted(Message):
        def __init__(self, prompt: str) -> None:
            self.prompt = prompt
            super().__init__()

    def action_submit_prompt(self) -> None:
        if self.slash_suggestions:
            command = self.text.strip().lower()
            if command not in {entry[0] for entry in self.COMMANDS}:
                self.action_complete_slash_command()
                return
        prompt = self.text
        self.clear()
        self.post_message(self.Submitted(prompt))

    def action_insert_newline(self) -> None:
        self.insert("\n")

    def action_complete_slash_command(self) -> None:
        if not self.slash_suggestions:
            self.insert("    ")
            return
        command, _description, takes_argument = self.slash_suggestions[self.slash_suggestion_index]
        completed = command + (" " if takes_argument else "")
        self.text = completed
        self.cursor_location = (0, len(completed))
        self.focus()

    def action_cursor_up(self, select: bool = False) -> None:
        if self.slash_suggestions and not select:
            self.slash_suggestion_index = (self.slash_suggestion_index - 1) % len(self.slash_suggestions)
            self.post_message(self.SlashSuggestionsChanged())
            return
        super().action_cursor_up(select)

    def action_cursor_down(self, select: bool = False) -> None:
        if self.slash_suggestions and not select:
            self.slash_suggestion_index = (self.slash_suggestion_index + 1) % len(self.slash_suggestions)
            self.post_message(self.SlashSuggestionsChanged())
            return
        super().action_cursor_down(select)

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        if event.text_area is not self:
            return
        value = self.text.strip().lower()
        if not value.startswith("/") or any(character.isspace() for character in value):
            suggestions: list[tuple[str, str, bool]] = []
        else:
            suggestions = [entry for entry in self.COMMANDS if entry[0].startswith(value)][:8]
        self.slash_suggestions = suggestions
        self.slash_suggestion_index = 0
        self.post_message(self.SlashSuggestionsChanged())


class MitsuSyntaxTheme(SyntaxTheme):
    def __init__(self, theme_id: str) -> None:
        palette = THEMES.get(theme_id, THEMES["ember"])
        code = palette["code"]
        self.styles = {
            Token: Style(color="#d8d4cd"),
            Token.Keyword: Style(color=code["keyword"], bold=True),
            Token.Name.Function: Style(color=code["function"], bold=True),
            Token.Name.Class: Style(color=code["function"], bold=True),
            Token.Name: Style(color="#d8d4cd"),
            Token.Literal.String: Style(color=code["string"]),
            Token.Literal.Number: Style(color=code["number"]),
            Token.Comment: Style(color=code["comment"], italic=True),
            Token.Operator: Style(color=code["operator"]),
            Token.Punctuation: Style(color="#c7c1bb"),
        }
        self.background = Style(bgcolor=palette["ui"]["code"])

    def get_style_for_token(self, token_type) -> Style:
        current = token_type
        while current is not None:
            if current in self.styles:
                return self.styles[current]
            current = current.parent
        return self.styles[Token]

    def get_background_style(self) -> Style:
        return self.background


class SessionTopBar(Static):
    def __init__(
        self,
        provider: dict,
        mode: str,
        target_count: int,
        finding_count: int,
        ip_count: int,
        theme_id: str,
        **kwargs,
    ) -> None:
        self.provider = provider
        self.mode = mode
        self.target_count = target_count
        self.finding_count = finding_count
        self.ip_count = ip_count
        self.theme_id = theme_id
        self.accent = THEMES.get(theme_id, THEMES["ember"])["accent"]
        super().__init__(self._content(), markup=False, **kwargs)

    def set_context(self, mode: str, target_count: int, finding_count: int, ip_count: int) -> None:
        self.mode = mode
        self.target_count = target_count
        self.finding_count = finding_count
        self.ip_count = ip_count
        self.update(self._content())

    def set_theme(self, theme_id: str) -> None:
        self.theme_id = theme_id
        self.accent = THEMES.get(theme_id, THEMES["ember"])["accent"]
        self.update(self._content())

    def _content(self) -> Text:
        provider = PROVIDER_BY_ID.get(self.provider.get("provider_id", ""))
        provider_name = provider.name if provider else "Custom provider"
        palette = THEMES.get(self.theme_id, THEMES["ember"])
        line = Text()
        line.append("Mitsu", style=f"bold {self.accent}")
        line.append(f"  v{__version__}   ", style=palette["ui"]["muted"])
        model = str(self.provider.get("model", ""))
        if len(model) > 27:
            model = f"…{model[-26:]}"
        line.append(f"{provider_name} · {model}   ", style="#e7e2dc")
        mode_colors = MODE_COLORS.get(self.mode, MODE_COLORS["Recon"])
        line.append(
            f" {self.mode} ",
            style=f"bold {mode_colors['foreground']} on {mode_colors['background']}",
        )
        line.append(
            f"   {self.target_count} targets · {self.finding_count} findings · {self.ip_count} IPs",
            style=palette["code"]["string"],
        )
        return line


class SessionRenameDialog(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel", priority=True)]

    def __init__(self, title: str) -> None:
        super().__init__()
        self.current_title = title

    def compose(self) -> ComposeResult:
        with Vertical(id="rename-dialog"):
            yield Static("RENAME SESSION", id="rename-dialog-title", markup=False)
            yield Static("Enter a name and press Enter to save.", id="rename-dialog-detail", markup=False)
            yield Input(value=self.current_title, id="rename-dialog-input")

    def on_mount(self) -> None:
        field = self.query_one("#rename-dialog-input", Input)
        field.focus()
        field.action_home()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "rename-dialog-input":
            self.dismiss(event.value.strip() or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class DeleteSessionDialog(ModalScreen[bool]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel", priority=True),
        Binding("n", "cancel", "Cancel", priority=True),
        Binding("y", "delete_session", "Delete session", priority=True),
        Binding("left", "focus_cancel", "Focus Cancel", priority=True),
        Binding("right", "focus_delete", "Focus Delete", priority=True),
    ]

    def __init__(self, in_menu: bool = False, session_title: str = "this session") -> None:
        super().__init__()
        self.in_menu = in_menu
        self.session_title = " ".join(session_title.split())[:80] or "this session"

    def compose(self) -> ComposeResult:
        with Vertical(id="delete-session-dialog"):
            yield Static("DELETE THIS SESSION?", id="delete-session-title", markup=False)
            message = (
                f"You suuure you want to remove “{self.session_title}”? Everything will be lost…\n"
                "(｡•́︿•̀｡)"
                if self.in_menu
                else f"Are you sure you want to delete “{self.session_title}”? Everything will be lost!\n"
                "(｡•́︿•̀｡)"
            )
            yield Static(message, id="delete-session-message", markup=False)
            with Horizontal(id="delete-session-actions"):
                yield Button("Cancel", id="delete-session-cancel", compact=True)
                yield Button("Delete it!", variant="error", id="delete-session-confirm", compact=True)
            yield Static("← / → choose    Enter select    Esc cancel", id="delete-session-hint", markup=False)

    def on_mount(self) -> None:
        self.query_one("#delete-session-cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "delete-session-cancel":
            self.dismiss(False)
        elif event.button.id == "delete-session-confirm":
            self.dismiss(True)

    def action_focus_cancel(self) -> None:
        self.query_one("#delete-session-cancel", Button).focus()

    def action_focus_delete(self) -> None:
        self.query_one("#delete-session-confirm", Button).focus()

    def action_cancel(self) -> None:
        self.dismiss(False)

    def action_delete_session(self) -> None:
        self.dismiss(True)


class SessionThemeDialog(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Close", priority=True)]

    def __init__(self, current_theme: str) -> None:
        super().__init__()
        self.current_theme = current_theme

    def compose(self) -> ComposeResult:
        with Vertical(id="session-theme-dialog"):
            yield Static("PICK YOUR COLORS", id="session-theme-title", markup=False)
            yield Static("Choose a palette for the whole TUI and its code blocks.", id="session-theme-copy", markup=False)
            with Horizontal(id="session-theme-layout"):
                yield OptionList(*(theme["name"] for theme in THEMES.values()), id="session-theme-list", compact=True)
                yield Static("", id="session-theme-preview", markup=False)
            yield Static("↑ / ↓ browse    Enter apply    Esc close", id="session-theme-help", markup=False)

    def on_mount(self) -> None:
        options = self.query_one("#session-theme-list", OptionList)
        options.highlighted = next(
            (index for index, theme_id in enumerate(THEMES) if theme_id == self.current_theme), 0
        )
        options.focus()
        self._update_preview(options.highlighted or 0)

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_list.id == "session-theme-list" and event.option_index is not None:
            self._update_preview(event.option_index)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "session-theme-list":
            self.dismiss(tuple(THEMES)[event.option_index])

    def _update_preview(self, index: int) -> None:
        theme_id = tuple(THEMES)[index]
        palette = THEMES[theme_id]
        code = palette["code"]
        preview = Text()
        preview.append(f"✦ {palette['name']} ✦\n", style=f"bold {palette['accent']}")
        preview.append("async ", style=f"bold {code['keyword']}")
        preview.append("def ", style=f"bold {code['keyword']}")
        preview.append("inspect_target", style=f"bold {code['function']}")
        preview.append("():\n    ")
        preview.append("return ", style=f"bold {code['keyword']}")
        preview.append('"safe and scoped"', style=code["string"])
        preview.append("  # ")
        preview.append("read-only", style=code["comment"])
        widget = self.query_one("#session-theme-preview", Static)
        widget.update(preview)

    def action_cancel(self) -> None:
        self.dismiss(None)


class CompanionDialog(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Close", priority=True)]

    def __init__(self, current_companion: str) -> None:
        super().__init__()
        self.current_companion = current_companion

    def compose(self) -> ComposeResult:
        companion = companion_by_id(self.current_companion)
        with Vertical(id="pet-dialog"):
            yield Static("PICK YOUR COMPANION", id="pet-dialog-title", markup=False)
            with Horizontal(id="pet-dialog-layout"):
                yield OptionList(*(item.name for item in COMPANIONS), id="pet-dialog-options", compact=True)
                with Vertical(id="pet-dialog-preview-panel"):
                    yield MitsuCompanion(sprite_path=companion.path, id="pet-dialog-preview")
                    yield Static(companion.description, id="pet-dialog-description", markup=False)
            yield Static("↑ / ↓ preview    Enter choose    Esc cancel", id="pet-dialog-hint", markup=False)

    def on_mount(self) -> None:
        options = self.query_one("#pet-dialog-options", OptionList)
        options.highlighted = next(
            (index for index, item in enumerate(COMPANIONS) if item.id == self.current_companion),
            0,
        )
        options.focus()
        self._show_preview(options.highlighted or 0)

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_list.id == "pet-dialog-options" and event.option_index is not None:
            self._show_preview(event.option_index)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "pet-dialog-options":
            self.dismiss(COMPANIONS[event.option_index].id)

    def _show_preview(self, index: int) -> None:
        companion = COMPANIONS[index]
        self.query_one("#pet-dialog-preview", MitsuCompanion).set_companion(companion.path)
        self.query_one("#pet-dialog-description", Static).update(companion.description)

    def action_cancel(self) -> None:
        self.dismiss(None)


class MCPConfigDialog(ModalScreen[bool]):
    BINDINGS = [
        Binding("ctrl+s", "save", "Save", priority=True),
        Binding("escape", "cancel", "Close", priority=True),
    ]

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path
        try:
            self.value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.value = {"servers": []}

    def compose(self) -> ComposeResult:
        with Vertical(id="mcp-dialog"):
            yield Static("MCP SERVER CONFIGURATION", id="mcp-dialog-title", markup=False)
            yield Static(
                "Servers connect when a session starts. Use a command with args/env or a Streamable HTTP URL.",
                id="mcp-dialog-detail",
                markup=False,
            )
            yield TextArea(
                json.dumps(self.value, ensure_ascii=False, indent=2),
                id="mcp-dialog-editor",
                language="json",
                show_line_numbers=False,
            )
            yield Static("Ctrl+S save    Esc close", id="mcp-dialog-hint", markup=False)
