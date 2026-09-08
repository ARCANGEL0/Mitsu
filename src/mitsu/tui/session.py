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

    def action_save(self) -> None:
        editor = self.query_one("#mcp-dialog-editor", TextArea)
        try:
            value = json.loads(editor.text)
        except json.JSONDecodeError as error:
            self.query_one("#mcp-dialog-detail", Static).update(f"Invalid JSON: {error.msg} at line {error.lineno}.")
            return
        if not self._valid_config(value):
            self.query_one("#mcp-dialog-detail", Static).update(
                'Use an object with a "servers" list. Each server needs a name and either a command or an http(s) URL.'
            )
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.path.parent.chmod(0o700)
            self.path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            self.path.chmod(0o600)
        except OSError as error:
            self.query_one("#mcp-dialog-detail", Static).update(f"Could not save MCP config: {error}")
            return
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)

    @staticmethod
    def _valid_config(value: object) -> bool:
        if not isinstance(value, dict) or not isinstance(value.get("servers"), list):
            return False
        for server in value["servers"]:
            if not isinstance(server, dict) or not isinstance(server.get("name"), str) or not server["name"].strip():
                return False
            command = server.get("command")
            url = server.get("url")
            if not isinstance(command, str) or not command.strip():
                if not isinstance(url, str):
                    return False
                try:
                    parsed = urlsplit(url)
                except ValueError:
                    return False
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    return False
            args = server.get("args", [])
            env = server.get("env", {})
            if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
                return False
            if not isinstance(env, dict) or any(not isinstance(key, str) or not isinstance(item, str) for key, item in env.items()):
                return False
        return True


class AskUserDialog(ModalScreen[str]):
    BINDINGS = [Binding("escape", "skip", "Skip question", priority=True)]

    def __init__(self, question: str, choices: list[str]) -> None:
        super().__init__()
        self.question = question
        self.choices = choices

    def compose(self) -> ComposeResult:
        with Vertical(id="ask-user-dialog"):
            yield Static("MITSU HAS A QUESTION", id="ask-user-title", markup=False)
            yield Static(self.question, id="ask-user-question", markup=False)
            if self.choices:
                yield OptionList(*self.choices, id="ask-user-choices", markup=False)
            yield Input(placeholder="Or type another answer…", id="ask-user-input")
            yield Static("↑ / ↓ choose    Enter answer    Esc skip", id="ask-user-hint", markup=False)

    def on_mount(self) -> None:
        if self.choices:
            self.query_one("#ask-user-choices", OptionList).focus()
        else:
            self.query_one("#ask-user-input", Input).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "ask-user-choices" and 0 <= event.option_index < len(self.choices):
            self.dismiss(self.choices[event.option_index])

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "ask-user-input" and event.value.strip():
            self.dismiss(event.value.strip())

    def action_skip(self) -> None:
        self.dismiss("[The operator skipped this question.]")


class ConversationSearchDialog(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Close search", priority=True)]

    def compose(self) -> ComposeResult:
        with Vertical(id="conversation-search-dialog"):
            yield Static("FIND IN THIS SESSION", id="conversation-search-title", markup=False)
            yield Input(placeholder="Search messages…", id="conversation-search-input")
            yield Static("Enter find    Esc close", id="conversation-search-hint", markup=False)

    def on_mount(self) -> None:
        self.query_one("#conversation-search-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "conversation-search-input":
            self.dismiss(event.value.strip() or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ToolApprovalDialog(ModalScreen[str]):
    BINDINGS = [
        Binding("escape", "deny", "Deny", priority=True),
        Binding("n", "deny", "Deny", priority=True),
        Binding("y", "allow_once", "Allow once", priority=True),
        Binding("a", "allow_always", "Always allow", priority=True),
    ]

    def __init__(self, tool_name: str, arguments: dict, mode: str = "Guided") -> None:
        super().__init__()
        self.tool_name = tool_name
        self.arguments = arguments
        self.mode = mode
        self.always_label = self._always_label()

    def compose(self) -> ComposeResult:
        with Vertical(id="tool-approval-dialog"):
            title = "RECON · ACTION REVIEW" if self.mode == "Recon" else "GUIDED · ACTION APPROVAL"
            yield Static(title, id="tool-approval-title", markup=False)
            is_shell = self.tool_name.endswith("__bash")
            action_title = (
                "Would you like to run this command?"
                if is_shell
                else f"Mitsu wants to call {self.tool_name}:"
            )
            yield Static(action_title, id="tool-approval-name", markup=False)
            if is_shell:
                command = str(self.arguments.get("command", ""))
                purpose = str(self.arguments.get("purpose", "")).strip()
                detail = "Environment: local\n\n$ " + command
                if purpose:
                    detail += "\n\nReason: " + purpose
            else:
                detail = json.dumps(self.arguments, ensure_ascii=False, indent=2, default=str)
            yield Static(detail[:4000], id="tool-approval-detail", markup=False)
            options = [
                "Yes · run once",
                self.always_label,
                "No · ask Mitsu to try a different approach",
            ]
            yield OptionList(*options, id="tool-approval-options", markup=False)
            yield Static("↑ / ↓ choose    Enter select    Y once    A always    N / Esc deny", id="tool-approval-hint", markup=False)

    def _always_label(self) -> str:
        if self.tool_name.endswith("__bash"):
            command = str(self.arguments.get("command", "")).strip()
            prefix = command[:64]
            return f"Yes · always allow commands starting with: {prefix or '(empty command)'}"
        return f"Yes · always allow this tool: {self.tool_name}"

    def on_mount(self) -> None:
        self.query_one("#tool-approval-options", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "tool-approval-options":
            choices = (
                "allow_once",
                "allow_always",
                "deny",
            )
            self.dismiss(choices[event.option_index])

    def action_allow_once(self) -> None:
        self.dismiss("allow_once")

    def action_allow_always(self) -> None:
        self.dismiss("allow_always")

    def action_deny(self) -> None:
        self.dismiss("deny")


class SessionScreen(Screen):
    BINDINGS = [
        Binding("ctrl+b", "back_to_menu", "Back to menu"),
        Binding("ctrl+f", "search_chat", "Find in chat", priority=True),
        Binding("escape", "cancel_agent", "Stop current action", priority=True),
        Binding("shift+tab", "cycle_mode", "Switch mode", priority=True),
        Binding("pageup", "scroll_chat_up", "Scroll chat up", priority=True),
        Binding("pagedown", "scroll_chat_down", "Scroll chat down", priority=True),
    ]

    def __init__(
        self,
        session: dict,
        provider: dict,
        companion_path: Path,
        sessions: SessionStore,
        theme_id: str = "ember",
    ) -> None:
        super().__init__(classes=f"theme-{theme_id}")
        self.session = session
        self.provider = provider
        self.companion_path = companion_path
        self.companion_id = next(
            (companion.id for companion in COMPANIONS if companion.path == companion_path),
            "mitsu",
        )
        self.sessions = sessions
        self.theme_id = theme_id
        self._remove_legacy_search_entries()
        self._remove_legacy_level_entries()
        self._remove_legacy_command_entries()
        mode = session.get("mode", "Recon")
        self.mode = {"Investigate": "Recon", "Autopwn": "AutoPwn", "auto-pwn": "AutoPwn"}.get(mode, mode)
        if self.mode not in {"Recon", "Guided", "AutoPwn"}:
            self.mode = "Recon"
        self.targets = session.get("targets", [])
        self.active_target = session.get("active_target")
        saved_prefixes = session.get("trusted_command_prefixes", [])
        self.trusted_command_prefixes = [
            str(value)
            for value in (saved_prefixes if isinstance(saved_prefixes, list) else [])
            if isinstance(value, str) and value
        ]
        saved_tools = session.get("trusted_tool_names", [])
        self.trusted_tool_names = [
            str(value)
            for value in (saved_tools if isinstance(saved_tools, list) else [])
            if isinstance(value, str) and value
        ]
        self.findings = self._stored_list("findings")
        stored_exploits = self._stored_list("exploits")
        self.exploits = [
            item for item in stored_exploits
            if not self._is_unverified_exploit_reference(item)
        ]
        if len(self.exploits) != len(stored_exploits):
            self.session["exploits"] = self.exploits
            self.sessions.save_session(self.session)
        self.ips = self._stored_list("ips")
        self.harvested_data = self._stored_list("harvested_data")
        self._companion_generation = 0
        self._last_activity = "Mitsu is Ready to Pwn!"
        self.level = int(session.get("level", 3)) if str(session.get("level", 3)).isdigit() else 3
        self.level = min(5, max(1, self.level))
        self.verbose = bool(session.get("verbose", False))
        self._message_widgets: list[Static] = []
        self._search_query = ""
        self._search_matches: list[int] = []
        self._search_cursor = -1
        self._search_mode = False
        self._command_panel_active = False
        self._command_panel_actions: list[str] = []
        self._command_panel_stage: str | None = None
        self._pending_export_path: Path | None = None
        self._pending_rewind_checkpoint: int | None = None
        self._active_command: str | None = None
        saved_agent_history = session.get("agent_history")
        if isinstance(saved_agent_history, list):
            self.agent_history = saved_agent_history
        else:
            self.agent_history = history_from_legacy(session.get("chat_history", []))
        self.session["agent_history"] = self.agent_history
        self._tool_host = AgentToolHost(
            Path.cwd(),
            self._ask_user,
            self._update_session_intel,
            search_settings=self.app.credentials.search_engines,
        )
        self._tool_connection_task: asyncio.Task | None = None
        self._tool_reconnect_task: asyncio.Task | None = None
        self._tool_host_ready = asyncio.Event()
        self._tool_host_shutdown = asyncio.Event()
        self._agent_running = False
        self._agent_task: asyncio.Task | None = None
        self._queued_prompts: list[str] = []
        self._queue_drain_scheduled = False
        self._command_running = False
        self._dispatching_prompt = False
        self._thinking_timer = None
        self._thinking_started: float | None = None
        self._thinking_frame = 0
        self._stream_characters = 0
        self._current_request_characters = 0
        self._current_input_estimate: int | None = None
        self._stream_text = ""
        self._stream_preview: Static | None = None
        self._exact_usage: dict[str, int] = {}
        self._retry_state: dict[str, Any] | None = None

    def compose(self) -> ComposeResult:
        yield SessionTopBar(
            self.provider,
            self.mode,
            len(self.targets),
            len(self.findings),
            len(self.ips),
            self.theme_id,
            id="session-topbar",
        )
        with Horizontal(id="session-center"):
            with VerticalScroll(id="session-left"):
                yield MitsuCompanion(sprite_path=self.companion_path, id="session-companion")
                yield Static("Mitsu is Ready to Pwn!", id="companion-status", markup=False)
                yield Static("Workspace", classes="session-label", markup=False)
                yield Static(str(Path.cwd()), id="project-path", markup=False)
                yield Static("Aggressive level:", classes="session-label", markup=False)
                yield Static("", id="aggressive-level", markup=False)
                yield Static("Search", classes="session-label", id="search-label", markup=False)
                yield Static("", id="search-status", markup=False)
            with Vertical(id="session-transcript-panel"):
                with Vertical(id="session-heading"):
                    yield Static(self._session_title_renderable(), id="session-title", markup=False)
                    yield Static("Mitsu is Ready to Pwn!", id="session-subtitle", markup=False)
                with VerticalScroll(id="conversation"):
                    if self.session.get("messages"):
                        for entry in self.session["messages"]:
                            role = entry.get("role", "assistant")
                            message_widget = Static(
                                self._message_renderable(entry.get("text", "")),
                                classes=self._message_class(role),
                                markup=False,
                            )
                            self._message_widgets.append(message_widget)
                            yield message_widget
                    else:
                        yield Static(
                            self._opening_greeting(),
                            classes="system-message",
                            markup=False,
                        )
            with VerticalScroll(id="session-right"):
                yield Static("INTEL", classes="session-section-title", markup=False)
                yield Static("Summary", classes="session-label", markup=False)
                yield Static("", id="intel-summary", markup=False)
                yield Static("Last activity", classes="session-label", markup=False)
                yield Static(self._last_activity, id="activity-summary", markup=False)
                yield Static("Authorized scope", classes="session-label", markup=False)
                yield Static("", id="target-summary", markup=False)
                yield Static("", id="target-list", markup=False)
                yield Static("Findings", classes="session-label", markup=False)
                yield Static("", id="findings-summary", markup=False)
                yield Static("Exploits", classes="session-label", markup=False)
                yield Static("", id="exploits-summary", markup=False)
                yield Static("IPs", classes="session-label", markup=False)
                yield Static("", id="ips-summary", markup=False)
                if self.harvested_data:
                    yield Static("Harvested data", classes="session-label", markup=False)
                    yield Static("", id="harvested-summary", markup=False)
        with Vertical(id="composer"):
            yield Static("", id="thinking-status", markup=False)
            yield Static("", id="queue-status", markup=False)
            yield Static("", id="slash-suggestions", markup=False)
            with Vertical(id="command-panel"):
                yield Static("", id="command-panel-title", markup=False)
                with VerticalScroll(id="command-panel-scroll"):
                    yield Static("", id="command-panel-content", markup=False)
                yield OptionList(id="command-panel-options", compact=True)
                command_input = Input(
                    placeholder="history.md or /home/me/history.md",
                    id="command-panel-input",
                )
                command_input.display = False
                yield command_input
                yield Static("", id="command-panel-hint", markup=False)
            with Horizontal(id="prompt-line"):
                yield Static("✦", id="prompt-symbol", markup=False)
                yield PromptTextArea(
                    "",
                    placeholder="Ask Mitsu…  (type / for commands)",
                    id="prompt-input",
                    show_line_numbers=False,
                )
            yield Static("Enter send    Shift+Enter new line    Shift+Tab mode    Esc stop    PgUp/PgDn history    Ctrl+B sessions", id="shortcut-hint", markup=False)

    def on_mount(self) -> None:
        self._update_context()
        self._update_search_sidebar()
        self.call_after_refresh(self._focus_prompt)
        self.query_one(MitsuCompanion).set_state("idle")
        self._tool_connection_task = asyncio.create_task(self._connect_tool_host())

    async def on_unmount(self) -> None:
        if self._thinking_timer:
            self._thinking_timer.stop()
            self._thinking_timer = None
        if self._agent_task and not self._agent_task.done():
            self._agent_task.cancel()
            await asyncio.gather(self._agent_task, return_exceptions=True)
        if self._tool_reconnect_task and not self._tool_reconnect_task.done():
            self._tool_reconnect_task.cancel()
            await asyncio.gather(self._tool_reconnect_task, return_exceptions=True)
        if self._tool_connection_task and not self._tool_connection_task.done():
            # MCP async contexts must be closed by the same task that entered them.
            self._tool_host_shutdown.set()
            if not self._tool_host_ready.is_set():
                self._tool_connection_task.cancel()
            await asyncio.gather(self._tool_connection_task, return_exceptions=True)

    async def _connect_tool_host(self) -> None:
        ready = self._tool_host_ready
        shutdown = self._tool_host_shutdown
        host = self._tool_host
        config_path = self.app.credentials.path.parent / "mcp_servers.json"
        try:
            await host.connect(config_path)
            ready.set()
            count = len(host.provider_tools(self.mode))
            status = f"Tools ready · {count} available"
            if host.connection_messages:
                status += f" · {len(host.connection_messages)} MCP connection issue(s)"
            self._set_activity(status)
            await shutdown.wait()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self._set_activity(f"Built-in tools could not start: {type(error).__name__}: {error}")
        finally:
            ready.set()
            try:
                await host.close()
            except Exception as error:
                self._set_activity(f"Tool cleanup issue: {type(error).__name__}: {error}")

    def _focus_prompt(self) -> None:
        if self.is_mounted and self.app.screen is self:
            if self._command_panel_active:
                options = self.query_one("#command-panel-options", OptionList)
                if options.display:
                    options.focus()
                return
            prompt = self.query_one("#prompt-input", PromptTextArea)
            prompt.disabled = False
            prompt.read_only = False
            prompt.focus()
            self._schedule_next_queued_prompt()

    def on_prompt_text_area_slash_suggestions_changed(
        self, event: PromptTextArea.SlashSuggestionsChanged
    ) -> None:
        self._render_slash_suggestions(self.query_one("#prompt-input", PromptTextArea))

    def _render_slash_suggestions(self, prompt: PromptTextArea) -> None:
        panel = self.query_one("#slash-suggestions", Static)
        if not prompt.slash_suggestions:
            panel.display = False
            return
        palette = THEMES.get(self.theme_id, THEMES["ember"])
        accent = palette["accent"]
        renderable = Text()
        for index, (command, description, _takes_argument) in enumerate(prompt.slash_suggestions):
            selected = index == prompt.slash_suggestion_index
            dark_bg = palette["ui"]["background"]
            marker_style = f"bold {dark_bg} on {accent}" if selected else f"bold {accent}"
            command_style = f"bold {dark_bg} on {accent}" if selected else palette["code"]["function"]
            detail_style = f"{dark_bg} on {accent}" if selected else palette["ui"]["muted"]
            renderable.append("› " if selected else "  ", style=marker_style)
            renderable.append(command, style=command_style)
            renderable.append(f"  {description}\n", style=detail_style)
        renderable.append("↑/↓ move   Tab complete   Enter run", style=palette["ui"]["muted"])
        panel.update(renderable)
        panel.display = True

    async def on_prompt_text_area_submitted(self, event: PromptTextArea.Submitted) -> None:
        prompt = event.prompt.strip()
        if not prompt:
            return
        if self._agent_running or self._command_running or self._dispatching_prompt or self._queued_prompts:
            self._queued_prompts.append(prompt)
            self._update_queue_status()
            if not self._agent_running and not self._command_running:
                self._schedule_next_queued_prompt()
            self.call_after_refresh(self._focus_prompt)
            return
        await self._dispatch_prompt(prompt)
        if self.app.screen is self and not self._agent_running:
            self.call_after_refresh(self._focus_prompt)

    async def _dispatch_prompt(self, prompt: str) -> None:
        self._dispatching_prompt = True
        try:
            if prompt.startswith("/"):
                # Slash commands are TUI actions; only ordinary prompts enter the agent loop.
                command = prompt.partition(" ")[0].casefold()
                self._command_running = True
                self._active_command = command
                try:
                    await self._handle_command(prompt)
                    if (
                        self.app.screen is self
                        and not self._command_panel_active
                        and command not in {"/search", "/clear", "/level", "/export", "/rewind"}
                    ):
                        self._show_command_panel(
                            f"/{command.removeprefix('/')}",
                            self._last_activity,
                        )
                finally:
                    self._command_running = False
                    self._active_command = None
            else:
                await self._append_message(f"›  {prompt}", "user", context_text=prompt)
                self._agent_running = True
                self._agent_task = asyncio.create_task(self._ask_provider(prompt))
                self._agent_task.add_done_callback(self._agent_task_finished)
        finally:
            self._dispatching_prompt = False
        if self._queued_prompts:
            self._schedule_next_queued_prompt()

    def _update_queue_status(self) -> None:
        if not self.is_mounted:
            return
        status = self.query_one("#queue-status", Static)
        if not self._queued_prompts:
            status.update("")
            status.display = False
            return
        palette = THEMES.get(self.theme_id, THEMES["ember"])
        accent = palette["accent"]
        renderable = Text()
        renderable.append(f"↳ In queue · {len(self._queued_prompts)}", style=f"bold {accent}")
        renderable.append(" · Esc interrupts + sends next now", style=palette["ui"]["muted"])
        preview_limit = max(8, min(72, self.size.width - 16))
        visible_prompts = self._queued_prompts[:2]
        for index, prompt in enumerate(visible_prompts, 1):
            preview = " ".join(prompt.split())
            if len(preview) > preview_limit:
                preview = preview[: preview_limit - 1].rstrip() + "…"
            renderable.append(f"\n  {index} › ", style=palette["ui"]["muted"])
            renderable.append(preview, style=accent)
        if len(self._queued_prompts) > len(visible_prompts):
            remaining = len(self._queued_prompts) - len(visible_prompts)
            renderable.append(f"\n  +{remaining} more queued", style=palette["ui"]["muted"])
        status.update(renderable)
        status.display = True

    def _show_command_panel(
        self,
        title: str,
        content: str,
        actions: list[tuple[str, str]] | None = None,
    ) -> None:
        self._command_panel_active = True
        self._command_panel_stage = None
        panel = self.query_one("#command-panel", Vertical)
        panel.display = True
        self.query_one("#command-panel-title", Static).update(title.upper())
        self.query_one("#command-panel-content", Static).update(content)
        self.query_one("#command-panel-scroll", VerticalScroll).scroll_home(animate=False)
        self.query_one("#prompt-line", Horizontal).display = False
        self.query_one("#slash-suggestions", Static).display = False
        self.query_one("#shortcut-hint", Static).display = False
        panel_input = self.query_one("#command-panel-input", Input)
        panel_input.value = ""
        panel_input.display = False

        choices = actions if actions is not None else [("Close", "close")]
        options = self.query_one("#command-panel-options", OptionList)
        options.clear_options()
        options.set_options([label for label, _action in choices])
        options.display = bool(choices)
        self._command_panel_actions = [action for _label, action in choices]
        hint = "↑ / ↓ choose    Enter select    Esc close" if choices else "Esc close"
        self.query_one("#command-panel-hint", Static).update(hint)
        self.query_one("#shortcut-hint", Static).update(hint)
        if choices:
            options.highlighted = 0
            options.focus()

    def _close_command_panel(self) -> None:
        if not self._command_panel_active:
            return
        self._command_panel_active = False
        self._command_panel_stage = None
        self._pending_export_path = None
        self._pending_rewind_checkpoint = None
        self._command_panel_actions.clear()
        self.query_one("#command-panel", Vertical).display = False
        panel_input = self.query_one("#command-panel-input", Input)
        panel_input.value = ""
        panel_input.display = False
        self.query_one("#prompt-line", Horizontal).display = True
        shortcut = self.query_one("#shortcut-hint", Static)
        shortcut.update("Enter send    Shift+Enter new line    Shift+Tab mode    Esc stop    PgUp/PgDn history    Ctrl+B sessions")
        shortcut.display = True
        self.call_after_refresh(self._focus_prompt)
        self._schedule_next_queued_prompt()

    def _show_permissions_panel(self, message: str | None = None) -> None:
        lines = ["APPROVALS SAVED FOR THIS SESSION", ""]
        lines.extend(f"• Shell command prefix: {prefix}" for prefix in self.trusted_command_prefixes)
        lines.extend(f"• MCP tool: {tool_name}" for tool_name in self.trusted_tool_names)
        if not self.trusted_command_prefixes and not self.trusted_tool_names:
            lines.append("None yet.")
        if message:
            lines.extend(["", message])
        actions = [("Close", "close")]
        if self.trusted_command_prefixes or self.trusted_tool_names:
            actions.append(("Clear all saved approvals", "clear"))
        self._show_command_panel("Session approvals", "\n".join(lines), actions)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "command-panel-options":
            return
        index = event.option_index
        if not 0 <= index < len(self._command_panel_actions):
            return
        action = self._command_panel_actions[index]
        if action == "close":
            self._close_command_panel()
        elif action == "clear":
            self.trusted_command_prefixes.clear()
            self.trusted_tool_names.clear()
            self.session["trusted_command_prefixes"] = []
            self.session["trusted_tool_names"] = []
            self.sessions.save_session(self.session)
            self._show_permissions_panel("Saved approvals cleared.")
        elif action.startswith("level:"):
            self._apply_level(int(action.partition(":")[2]))
            self._close_command_panel()
        elif action == "export:copy":
            self._copy_session_export()
        elif action == "export:save":
            self._begin_export_path()
        elif action == "export:overwrite":
            self._write_session_export(self._pending_export_path)
        elif action == "export:choose-path":
            self._begin_export_path()
        elif action.startswith("rewind-point:"):
            self._show_rewind_choices(int(action.partition(":")[2]))
        elif action in {"rewind:both", "rewind:conversation", "rewind:code"}:
            self._show_command_panel("Rewinding", "Restoring the selected conversation and workspace point…", [])
            self.run_worker(self._apply_rewind(action), name="apply-rewind")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "command-panel-input" or self._command_panel_stage != "export-path":
            return
        path_text = event.value.strip()
        if not path_text:
            self._show_export_path_error("Enter a filename or full path first.")
            return
        path = Path(path_text).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        active_session_path = self.sessions.path / f"{self.session.get('id', '')}.json"
        try:
            same_as_active_session = path.resolve(strict=False) == active_session_path.resolve(strict=False)
        except (OSError, RuntimeError):
            same_as_active_session = os.path.abspath(path) == os.path.abspath(active_session_path)
        if same_as_active_session:
            self._show_export_path_error("Choose a different path so the active session file stays intact.")
            return
        if path.exists() and path.is_dir():
            self._show_export_path_error("That path is a directory. Choose a filename instead.")
            return
        if not path.parent.is_dir():
            self._show_export_path_error(f"The destination folder does not exist: {path.parent}")
            return
        self._pending_export_path = path
        if path.exists():
            self._command_panel_stage = "export-overwrite"
            self._show_command_panel(
                "File already exists",
                f"{path}\n\nOverwrite this file?",
                [("Overwrite", "export:overwrite"), ("Choose another path", "export:choose-path"), ("Cancel", "close")],
            )
            return
        self._write_session_export(path)

    def _show_level_panel(self) -> None:
        choices = (
            ("1 · Opsec Kiddy — passive OSINT, tiny footprint", "level:1"),
            ("2 · Curious mode — follow a few low-impact clues", "level:2"),
            ("3 · Chill — balanced checks, focused validation", "level:3"),
            ("4 · LulzSec Intern — broader enumeration, more hypotheses", "level:4"),
            ("5 · Mista Robot — thorough in-scope investigation", "level:5"),
        )
        self._show_command_panel(
            "Change aggressiveness level for workflow",
            "Pick how broadly Mitsu investigates. The current mode still controls tool approvals.",
            list(choices),
        )
        options = self.query_one("#command-panel-options", OptionList)
        options.highlighted = self.level - 1

    def _session_export_text(self) -> str:
        title = str(self.session.get("title", "Mitsu session")).strip() or "Mitsu session"
        lines = [
            f"# {title}",
            "",
            f"Exported: {datetime.now().astimezone().isoformat(timespec='seconds')}",
            f"Session ID: {self.session.get('id', '')}",
            f"Mode: {self.mode}",
            f"Model: {self.provider.get('model', '')}",
            "Targets: " + (", ".join(self.targets) if self.targets else "none saved"),
            "",
        ]
        labels = {
            "user": "Operator",
            "assistant": "Mitsu",
            "tool": "Tool call",
            "tool-result": "Tool result",
            "error": "Error",
            "success": "Mitsu",
            "system": "System",
        }
        for entry in self.session.get("messages", []):
            if not isinstance(entry, dict):
                continue
            role = str(entry.get("role", "assistant"))
            body = str(entry.get("text", ""))
            if role == "user" and body.startswith("›  "):
                body = body[3:]
            lines.extend((f"## {labels.get(role, role.title())}", "", body, ""))
        return "\n".join(lines).rstrip() + "\n"

    def _copy_session_export(self) -> None:
        try:
            self.app.copy_to_clipboard(self._session_export_text())
        except (AttributeError, RuntimeError, OSError) as error:
            self._show_command_panel(
                "Clipboard unavailable",
                f"Could not copy this session: {error}",
                [("Close", "close")],
            )
            return
        self._show_command_panel(
            "Session copied",
            "The full visible session history is on your clipboard.",
            [("Close", "close")],
        )

    def _begin_export_path(self) -> None:
        self._command_panel_stage = "export-path"
        self.query_one("#command-panel-title", Static).update("SAVE SESSION HISTORY")
        self.query_one("#command-panel-content", Static).update(
            "Type a filename or full path. Relative paths are saved from the current directory."
        )
        self.query_one("#command-panel-options", OptionList).display = False
        panel_input = self.query_one("#command-panel-input", Input)
        panel_input.value = ""
        panel_input.placeholder = "history.md or /home/me/history.md"
        panel_input.display = True
        self.query_one("#command-panel-hint", Static).update("Enter save    Esc cancel")
        self.call_after_refresh(panel_input.focus)

    def _show_export_path_error(self, message: str) -> None:
        self.query_one("#command-panel-content", Static).update(message)
        self.call_after_refresh(self.query_one("#command-panel-input", Input).focus)

    def _write_session_export(self, path: Path | None) -> None:
        if path is None:
            self._show_export_path_error("Choose a destination path first.")
            return
        if path.exists() and path.is_dir():
            self._show_export_path_error("That path is a directory. Choose a filename instead.")
            return
        if not path.parent.is_dir():
            self._show_export_path_error(f"The destination folder does not exist: {path.parent}")
            return
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
            ) as stream:
                temporary = Path(stream.name)
                stream.write(self._session_export_text())
            os.replace(temporary, path)
        except OSError as error:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            self._show_export_path_error(f"Could not save the history: {error}")
            return
        self._pending_export_path = None
        self._show_command_panel(
            "History saved",
            f"Saved {len(self.session.get('messages', []))} transcript entries to:\n{path}",
            [("Close", "close")],
        )

    def _show_export_panel(self) -> None:
        self._pending_export_path = None
        self._command_panel_stage = "export"
        self._show_command_panel(
            "Export session history",
            "Copy the full transcript or save it to a file.",
            [("Copy", "export:copy"), ("Save as file", "export:save"), ("Cancel", "close")],
        )

    def _show_rewind_panel(self) -> None:
        points = self.session.get("rewind_points", [])
        available = [
            index
            for index, point in enumerate(points if isinstance(points, list) else [])
            if isinstance(point, dict) and point.get("conversation_available", True)
        ]
        if not available:
            self._show_command_panel(
                "Rewind",
                "No saved conversation points yet. Mitsu records a point after each task finishes or is interrupted.",
                [("Close", "close")],
            )
            return
        choices = []
        for index in reversed(available[-12:]):
            prompt = " ".join(str(points[index].get("prompt", "")).split())
            preview = prompt[:72] + ("…" if len(prompt) > 72 else "")
            choices.append((f"Before: {preview}", f"rewind-point:{index}"))
        choices.append(("Cancel", "close"))
        self._show_command_panel(
            "Rewind to a conversation point",
            "Choose the user request to return to. The rewind choices follow next.",
            choices,
        )

    def _show_rewind_choices(self, index: int) -> None:
        points = self.session.get("rewind_points", [])
        if not isinstance(points, list) or not 0 <= index < len(points):
            self._show_rewind_panel()
            return
        point = points[index]
        self._pending_rewind_checkpoint = index
        code_available = all(
            isinstance(item, dict)
            and (
                not item.get("file_changes_active", True)
                or item.get("files_available", False)
            )
            for item in points[index:]
        )
        actions = [("Restore conversation only", "rewind:conversation")]
        if code_available:
            actions.extend(
                [
                    ("Restore conversation + code", "rewind:both"),
                    ("Restore code only", "rewind:code"),
                ]
            )
        else:
            point["code_unavailable_reason"] = (
                "A workspace snapshot is incomplete or exceeds the rewind size limit."
            )
        actions.append(("Cancel", "close"))
        prompt = " ".join(str(point.get("prompt", "")).split())[:180]
        detail = f"Before: {prompt}\nCode restore needs complete workspace snapshots; secrets, dependencies, and large files are excluded."
        if not code_available:
            detail += "\nCode rewind is unavailable for this point."
        self._show_command_panel(
            "Choose what to rewind",
            detail,
            actions,
        )

    async def _apply_rewind(self, action: str) -> None:
        index = self._pending_rewind_checkpoint
        points = self.session.get("rewind_points", [])
        if index is None or not isinstance(points, list) or not 0 <= index < len(points):
            self._show_rewind_panel()
            return
        restore_conversation = action in {"rewind:both", "rewind:conversation"}
        restore_code = action in {"rewind:both", "rewind:code"}
        failed_paths: list[str] = []
        if restore_code:
            change_sets = [
                point.get("file_changes", {})
                for point in reversed(points[index:])
                if isinstance(point, dict)
                and point.get("file_changes_active", True)
                and isinstance(point.get("file_changes"), dict)
            ]
            failed_paths = await asyncio.to_thread(
                apply_undo_changes, Path.cwd(), change_sets
            )
            if not failed_paths:
                for point in points[index:]:
                    if isinstance(point, dict):
                        point["file_changes"] = {}
                        point["files_available"] = False
                        point["file_changes_active"] = False
        if restore_conversation:
            point = points[index]
            message_count = max(0, int(point.get("messages_before", 0)))
            chat_count = max(0, int(point.get("chat_history_before", 0)))
            history_count = point.get("agent_history_before")
            self.session["messages"] = self.session.get("messages", [])[:message_count]
            self.session["chat_history"] = self.session.get("chat_history", [])[:chat_count]
            if isinstance(history_count, int) and not isinstance(history_count, bool):
                self.agent_history[:] = self.agent_history[:max(0, history_count)]
            else:
                self.agent_history = self._history_for_new_protocol()
            self.session["agent_history"] = self.agent_history
            for newer in points[index:]:
                if isinstance(newer, dict):
                    newer["conversation_available"] = False
            await self._rebuild_conversation()
        self.session["rewind_points"] = points
        self.sessions.save_session(self.session)
        detail = "Conversation restored." if restore_conversation else "Conversation left as-is."
        if restore_code:
            detail += " Workspace code restored." if not failed_paths else f" Some files could not be restored: {', '.join(failed_paths[:8])}"
        self._pending_rewind_checkpoint = None
        self._show_command_panel("Rewind complete", detail, [("Close", "close")])

    async def _rebuild_conversation(self) -> None:
        conversation = self.query_one("#conversation", VerticalScroll)
        await conversation.remove_children()
        self._message_widgets.clear()
        messages = self.session.get("messages", [])
        if not isinstance(messages, list) or not messages:
            await conversation.mount(
                Static(self._opening_greeting(), classes="system-message", markup=False)
            )
            return
        for entry in messages:
            if not isinstance(entry, dict):
                continue
            widget = Static(
                self._message_renderable(str(entry.get("text", ""))),
                classes=self._message_class(str(entry.get("role", "assistant"))),
                markup=False,
            )
            self._message_widgets.append(widget)
            await conversation.mount(widget)
        conversation.scroll_end(animate=False)

    def _schedule_next_queued_prompt(self) -> None:
        if (
            not self._queued_prompts
            or self._agent_running
            or self._command_running
            or self._dispatching_prompt
            or self._command_panel_active
            or self._queue_drain_scheduled
            or not self.is_mounted
            or self.app.screen is not self
        ):
            return
        self._queue_drain_scheduled = True
        self.run_worker(self._run_next_queued_prompt(), name="queued-prompt")

    async def _run_next_queued_prompt(self) -> None:
        self._queue_drain_scheduled = False
        if (
            not self.is_mounted
            or self.app.screen is not self
            or self._agent_running
            or self._command_running
            or self._dispatching_prompt
            or self._command_panel_active
            or not self._queued_prompts
        ):
            return
        prompt = self._queued_prompts.pop(0)
        self._update_queue_status()
        await self._dispatch_prompt(prompt)
        if self.app.screen is self and not self._agent_running:
            self.call_after_refresh(self._focus_prompt)

    async def _ask_provider(self, prompt: str) -> None:
        self._agent_running = True
        self._agent_task = asyncio.current_task()
        history_checkpoint = copy.deepcopy(self.agent_history)
        messages = self.session.get("messages", [])
        messages_before = len(messages) if isinstance(messages, list) else 0
        if isinstance(messages, list) and messages:
            last_message = messages[-1]
            if (
                isinstance(last_message, dict)
                and last_message.get("role") == "user"
                and str(last_message.get("text", "")).removeprefix("›  ") == prompt
            ):
                messages_before -= 1
        chat_history = copy.deepcopy(self.session.get("chat_history", []))
        chat_history_before = len(chat_history) if isinstance(chat_history, list) else 0
        if isinstance(chat_history, list) and chat_history:
            last_chat_entry = chat_history[-1]
            if (
                isinstance(last_chat_entry, dict)
                and last_chat_entry.get("role") == "user"
                and last_chat_entry.get("content") == prompt
            ):
                chat_history_before -= 1
        agent_history_before = len(history_checkpoint)
        workspace_root = Path.cwd().resolve()
        workspace_before: dict[str, bytes] | None = None
        prompt_input = self.query_one("#prompt-input", PromptTextArea)
        provider_spec = PROVIDER_BY_ID.get(str(self.provider.get("provider_id", "")))
        provider_name = provider_spec.name if provider_spec else "your configured provider"
        self._set_activity(f"Preparing a request for {provider_name}…")
        self._set_companion("thinking", "Working")
        system_prompt = self._system_prompt()
        self._start_thinking(prompt, system_prompt)

        def save_history() -> None:
            self.session["agent_history"] = self.agent_history
            self.sessions.save_session(self.session)

        def restore_history(note: str) -> None:
            self.agent_history[:] = history_checkpoint
            self.agent_history.append({"role": "user", "content": prompt})
            self.agent_history.append({"role": "assistant", "content": note})
            save_history()

        was_cancelled = False
        try:
            workspace_before = await asyncio.to_thread(capture_workspace, workspace_root)
            if self._tool_connection_task:
                if self._tool_reconnect_task and not self._tool_reconnect_task.done():
                    await self._tool_reconnect_task
                await self._tool_host_ready.wait()
            self._set_activity(f"Sending your message to {provider_name}…")
            async for event in run_agent_turn(
                self.provider,
                system_prompt,
                self.agent_history,
                prompt,
                self._tool_host,
                self.mode,
                self._approve_tool,
                save_history,
            ):
                if event.kind == "assistant_turn":
                    text = str(event.data.get("text", "")).strip()
                    await self._remove_stream_preview()
                    self._current_request_characters = 0
                    if text:
                        await self._append_message(text, "assistant", context_text=text)
                    elif not event.data.get("tool_calls"):
                        response_info = event.data.get("response_info", {})
                        finish_reason = (
                            str(response_info.get("finish_reason", ""))
                            if isinstance(response_info, dict)
                            else ""
                        )
                        if isinstance(response_info, dict) and response_info.get("reasoning_only"):
                            message = (
                                "The provider sent internal reasoning but no reply or tool call. "
                                "That private reasoning was not shown. Try again or select a model "
                                "with working tool-call support."
                            )
                        elif finish_reason == "length":
                            message = "The provider stopped before returning a reply or tool call (output limit reached). Try again."
                        elif finish_reason:
                            message = f"The provider finished without a reply or tool call (finish reason: {finish_reason}). Try again or choose another model."
                        else:
                            message = (
                                "The provider returned no reply or tool call. Try again or choose "
                                "another model. Mitsu kept the conversation history valid."
                            )
                        self._set_activity("The provider returned an empty response.")
                        await self._append_message(
                            message,
                            "error",
                        )
                elif event.kind == "delta":
                    await self._show_stream_delta(str(event.data.get("text", "")))
                elif event.kind == "usage":
                    self._record_usage(event.data.get("usage", {}))
                elif event.kind == "api_retry":
                    await self._remove_stream_preview()
                    self._stream_characters = max(
                        0, self._stream_characters - self._current_request_characters
                    )
                    self._current_request_characters = 0
                    delay = max(1, int(event.data.get("delay", 3)))
                    self._retry_state = {
                        "attempt": int(event.data.get("attempt", 1)),
                        "maximum": int(event.data.get("max_attempts", 10)),
                        "deadline": time.monotonic() + delay,
                    }
                    self._animate_thinking()
                elif event.kind == "api_retrying":
                    self._retry_state = None
                    self._animate_thinking()
                elif event.kind == "tool_started":
                    name = str(event.data.get("name", "tool"))
                    arguments = event.data.get("arguments", {})
                    self._set_activity(f"Running {name}…")
                    self._set_companion("running", "Running a tool")
                    await self._append_message(self._format_tool_call(name, arguments), "tool")
                elif event.kind == "tool_finished":
                    name = str(event.data.get("name", "tool"))
                    result = str(event.data.get("result", ""))
                    if len(result) > 5000:
                        result = result[:5000] + "\n… shown output truncated"
                    self._current_input_estimate = max(
                        1,
                        len(
                            json.dumps(
                                [system_prompt, *self.agent_history],
                                ensure_ascii=False,
                                default=str,
                            )
                        )
                        // 4,
                    )
                    failed = bool(event.data.get("is_error"))
                    self._set_activity(f"{name} {'failed' if failed else 'finished'}.")
                    await self._append_message(result, "tool-result")
                    if failed:
                        self._set_companion("error", "Tool failed", reset_after=1.5)
                    elif name.endswith(("record_exploit", "remove_exploit")):
                        self._set_companion("success", "Intel updated!", reset_after=1.5)
                    else:
                        self._set_companion("thinking", "Reviewing results")
                    self._animate_thinking()
                elif event.kind == "limit":
                    message = str(event.data.get("message", "Tool loop stopped."))
                    self._set_activity(message)
                    await self._append_message(message, "system")
                elif event.kind == "done":
                    self._set_activity("Mitsu is Ready to Pwn!")
                    self._set_companion("success", "Mitsu is Ready to Pwn!", reset_after=1.8)
        except asyncio.CancelledError:
            was_cancelled = True
            await self._remove_stream_preview()
            restore_history(
                "This operator request was interrupted before completion. Keep it in context; resume only if the operator asks to continue."
            )
            self._set_activity("Stopped by operator.")
            self._set_companion("idle", "Mitsu is Ready to Pwn!")
            await self._append_message("Stopped the current action.", "system")
        except ProviderRequestError as error:
            await self._remove_stream_preview()
            restore_history(
                "The provider failed before this request finished. Keep the request in context; resume only if the operator asks to continue."
            )
            self._set_activity("The provider returned an error.")
            self._set_companion("error", "Provider error", reset_after=2.2)
            status = self.query_one("#thinking-status", Static)
            status.update(Text("⚠ API Error (｡•́︿•̀｡) · retries exhausted", style="bold #f07882"))
            await self._append_message(str(error), "error")
        except Exception as error:
            await self._remove_stream_preview()
            restore_history(
                "Mitsu stopped before this request finished. Keep the request in context; resume only if the operator asks to continue."
            )
            self._set_activity("The agent stopped after an internal error.")
            self._set_companion("error", "Agent error", reset_after=2.2)
            await self._append_message(f"Agent error: {type(error).__name__}: {error}", "error")
        finally:
            try:
                await self._record_rewind_checkpoint(
                    prompt,
                    messages_before,
                    chat_history_before,
                    agent_history_before,
                    workspace_root,
                    workspace_before,
                )
            except Exception as error:
                self._set_activity(f"Could not save a rewind point: {type(error).__name__}")
            if not was_cancelled and self._thinking_started is not None:
                visible_for = time.monotonic() - self._thinking_started
                if visible_for < 0.28:
                    await asyncio.sleep(0.28 - visible_for)
            self._agent_running = False
            self._agent_task = None
            self._stop_thinking()
            if self.is_mounted:
                prompt_input.focus()
                self._update_queue_status()
                self._schedule_next_queued_prompt()

    async def _record_rewind_checkpoint(
        self,
        prompt: str,
        messages_before: int,
        chat_history_before: int,
        agent_history_before: int,
        workspace_root: Path,
        workspace_before: dict[str, bytes] | None,
    ) -> None:
        workspace_after = await asyncio.to_thread(capture_workspace, workspace_root)
        changes = diff_workspace(workspace_before, workspace_after)
        points = self.session.get("rewind_points", [])
        if not isinstance(points, list):
            points = []
        points.append(
            {
                "prompt": prompt,
                "messages_before": messages_before,
                "chat_history_before": chat_history_before,
                "agent_history_before": agent_history_before,
                "conversation_available": True,
                "files_available": changes is not None,
                "file_changes_active": True,
                "file_changes": changes or {},
            }
        )
        points[:] = points[-20:]
        saved_delta_size = sum(
            len(value)
            for point in points
            if isinstance(point, dict) and isinstance(point.get("file_changes"), dict)
            for value in point["file_changes"].values()
            if isinstance(value, str)
        )
        for point in points:
            if saved_delta_size <= 12 * 1024 * 1024:
                break
            if isinstance(point, dict) and point.get("file_changes_active", True):
                delta = point.get("file_changes", {})
                saved_delta_size -= sum(
                    len(value) for value in delta.values() if isinstance(value, str)
                )
                point["file_changes"] = {}
                point["files_available"] = False
        self.session["rewind_points"] = points
        self.sessions.save_session(self.session)

    def _start_thinking(self, prompt: str = "", system_prompt: str = "") -> None:
        self._thinking_started = time.monotonic()
        self._thinking_frame = 0
        self._stream_characters = 0
        self._current_request_characters = 0
        self._stream_characters_at_usage = 0
        self._stream_text = ""
        self._exact_usage = {}
        self._retry_state = None
        serialized_context = json.dumps(
            [system_prompt, *self.agent_history, {"role": "user", "content": prompt}],
            ensure_ascii=False,
            default=str,
        )
        self._current_input_estimate = max(1, len(serialized_context) // 4)
        status = self.query_one("#thinking-status", Static)
        status.display = True
        self._animate_thinking()
        self._thinking_timer = self.set_interval(0.18, self._animate_thinking)

    def _stop_thinking(self) -> None:
        if self._thinking_timer:
            self._thinking_timer.stop()
            self._thinking_timer = None
        self._thinking_started = None
        if self.is_mounted:
            self.query_one("#thinking-status", Static).display = False

    def _animate_thinking(self) -> None:
        if not self.is_mounted or not self._agent_running or self._thinking_started is None:
            return
        frames = ("✧", "✦", "✧", "♡")
        phrases = (
            "hunting for clues",
            "checking the tool results",
            "connecting the dots",
            "tidying up the findings",
        )
        elapsed = max(0, int(time.monotonic() - self._thinking_started))
        minutes, seconds = divmod(elapsed, 60)
        elapsed_text = f"{minutes}:{seconds:02d}" if minutes else f"{seconds}s"
        if self._retry_state:
            remaining = max(0, int(self._retry_state["deadline"] - time.monotonic() + 0.999))
            retry_text = Text()
            symbol = ("⚠", "✖", "☄", "✧")[(self._retry_state["attempt"] - 1) % 4]
            retry_text.append(
                f"{symbol} API Error (｡•́︿•̀｡)  {self._retry_state['attempt']}/{self._retry_state['maximum']}  ·  Retrying in {remaining}s…",
                style="bold #f07882",
            )
            self.query_one("#thinking-status", Static).update(retry_text)
            return
        input_estimate = self._current_input_estimate
        output_estimate = self._stream_characters // 4
        input_text = f"~{input_estimate} est" if input_estimate is not None else "—"
        count = f"  ·  in {input_text} · out ~{output_estimate} est"
        if self._exact_usage:
            input_tokens = self._exact_usage.get("prompt_tokens")
            output_tokens = self._exact_usage.get("completion_tokens")
            if input_tokens is not None or output_tokens is not None:
                input_label = str(input_tokens) if input_tokens is not None else "—"
                output_label = str(output_tokens) if output_tokens is not None else "—"
                count = f"  ·  in {input_label} · out {output_label} tok"
        frame = self._thinking_frame
        self._thinking_frame += 1
        accent = THEMES.get(self.theme_id, THEMES["ember"])["accent"]
        renderable = Text()
        renderable.append(
            f"{frames[frame % len(frames)]}  Mitsu’s {phrases[(frame // 4) % len(phrases)]}…",
            style=f"bold {accent}",
        )
        renderable.append(
            f"  {elapsed_text}{count}",
            style=THEMES.get(self.theme_id, THEMES["ember"])["ui"]["muted"],
        )
        self.query_one("#thinking-status", Static).update(renderable)

    async def _show_stream_delta(self, text: str) -> None:
        if not text:
            return
        self._stream_text += text
        self._stream_characters += len(text)
        self._current_request_characters += len(text)
        self._set_activity("Receiving Mitsu’s response…")
        if self._stream_preview is None:
            self._stream_preview = Static(
                self._message_renderable(self._stream_text),
                classes="assistant-message streaming-message",
                markup=False,
            )
            await self.query_one("#conversation", VerticalScroll).mount(self._stream_preview)
        else:
            self._stream_preview.update(self._message_renderable(self._stream_text))
        self.query_one("#conversation", VerticalScroll).scroll_end(animate=False)
        self._animate_thinking()

    def _agent_task_finished(self, task: asyncio.Task) -> None:
        if self._agent_task is task:
            self._agent_task = None
            self._agent_running = False
            self._stop_thinking()
            if self.is_mounted:
                prompt = self.query_one("#prompt-input", PromptTextArea)
                prompt.focus()
                self._update_queue_status()
                self._schedule_next_queued_prompt()

    async def _remove_stream_preview(self) -> None:
        preview = self._stream_preview
        self._stream_preview = None
        self._stream_text = ""
        if preview is not None and preview.is_mounted:
            await preview.remove()

    def _record_usage(self, usage: object) -> None:
        if not isinstance(usage, dict):
            return
        input_tokens = usage.get("prompt_tokens", usage.get("input_tokens"))
        output_tokens = usage.get("completion_tokens", usage.get("output_tokens"))
        if isinstance(input_tokens, int) and not isinstance(input_tokens, bool):
            self._exact_usage["prompt_tokens"] = self._exact_usage.get("prompt_tokens", 0) + input_tokens
        if isinstance(output_tokens, int) and not isinstance(output_tokens, bool):
            self._exact_usage["completion_tokens"] = self._exact_usage.get("completion_tokens", 0) + output_tokens
        self._stream_characters_at_usage = self._stream_characters
        self._animate_thinking()

    async def _ask_user(self, question: str, choices: list[str]) -> str:
        answer = await self._await_modal(AskUserDialog(question, choices))
        return str(answer)

    async def _approve_tool(self, name: str, arguments: dict) -> bool:
        if name.endswith("__bash"):
            command = str(arguments.get("command", "")).strip()
            if any(command.startswith(prefix) for prefix in self.trusted_command_prefixes):
                return True
        elif name in self.trusted_tool_names:
            return True

        decision = await self._await_modal(ToolApprovalDialog(name, arguments, self.mode))
        if decision == "allow_always":
            if name.endswith("__bash"):
                prefix = str(arguments.get("command", "")).strip()[:64]
                if not prefix:
                    return False
                if prefix not in self.trusted_command_prefixes:
                    self.trusted_command_prefixes.append(prefix)
                self.session["trusted_command_prefixes"] = self.trusted_command_prefixes
            else:
                if name not in self.trusted_tool_names:
                    self.trusted_tool_names.append(name)
                self.session["trusted_tool_names"] = self.trusted_tool_names
            self.sessions.save_session(self.session)
            return True
        return decision == "allow_once"

    async def _permissions_command(self, argument: str) -> None:
        if not argument:
            self._show_permissions_panel()
            return
        if argument.casefold() in {"clear", "reset", "revoke"}:
            self.trusted_command_prefixes.clear()
            self.trusted_tool_names.clear()
            self.session["trusted_command_prefixes"] = []
            self.session["trusted_tool_names"] = []
            self.sessions.save_session(self.session)
            await self._append_message("Saved approvals cleared for this session.", "success")
            return
        await self._append_message("Use /permissions to review saved approvals.", "system")

    async def _update_session_intel(self, action: str, values: dict) -> str:
        if action == "record_exploit":
            title = str(values.get("title", "")).strip()[:180]
            target = str(values.get("target", "")).strip()[:255]
            evidence = str(values.get("evidence", "")).strip()[:1000]
            status = str(values.get("status", "candidate")).casefold()
            if not title or not target or not evidence:
                return "Exploit not recorded: title, target, and evidence are required."
            if status not in {"candidate", "confirmed"}:
                return "Exploit not recorded: status must be candidate or confirmed."
            line = f"[{status.upper()}] {title} · {target} — {evidence}"
            match_index = next(
                (
                    index
                    for index, item in enumerate(self.exploits)
                    if title.casefold() in str(item).casefold()
                    and target.casefold() in str(item).casefold()
                ),
                None,
            )
            if match_index is None:
                self.exploits.append(line)
                outcome = "Recorded"
            else:
                self.exploits[match_index] = line
                outcome = "Updated"
            self.session["exploits"] = self.exploits
            self.sessions.save_session(self.session)
            self._update_context()
            self._set_activity(f"{outcome} {status} exploit intel for {target}.")
            return f"{outcome} exploit intel: {line}"

        if action == "remove_exploit":
            title = str(values.get("title", "")).strip()
            target = str(values.get("target", "")).strip()
            reason = str(values.get("reason", "")).strip()
            if not title or not reason:
                return "Exploit was not removed: title and evidence-based reason are required."
            match = next(
                (
                    item
                    for item in self.exploits
                    if title.casefold() in str(item).casefold()
                    and (not target or target.casefold() in str(item).casefold())
                ),
                None,
            )
            if match is None:
                return f"No recorded exploit matched {title!r}; Intel was unchanged."
            self.exploits.remove(match)
            self.session["exploits"] = self.exploits
            self.sessions.save_session(self.session)
            self._update_context()
            self._set_activity(f"Removed exploit intel for {title}: {reason[:120]}")
            return f"Removed {match!s} from Exploits. Reason: {reason}"

        return f"Unknown session Intel operation: {action}."

    async def _await_modal(self, screen: ModalScreen) -> object:
        answer = asyncio.get_running_loop().create_future()

        def dismissed(value: object) -> None:
            if not answer.done():
                answer.set_result(value)

        self.app.push_screen(screen, dismissed)
        try:
            return await answer
        except asyncio.CancelledError:
            if self.app.screen is screen:
                self.app.pop_screen()
            raise

    @staticmethod
    def _format_tool_call(name: str, arguments: object) -> str:
        if name.endswith("__bash") and isinstance(arguments, dict):
            command = str(arguments.get("command", ""))
            purpose = str(arguments.get("purpose", ""))
            return f"$ {command}" + (f"\n{purpose}" if purpose else "")
        if isinstance(arguments, dict):
            tool = name.rsplit("__", 1)[-1].replace("_", " ")
            if tool == "read file":
                return f"Reading {arguments.get('path', 'file')}"
            if tool == "list files":
                return f"Listing {arguments.get('path', '.')}"
            if tool == "web search":
                return f"Searching the web · {arguments.get('query', '')}"
            if tool == "system info":
                return "Checking system information"
        try:
            serialized = json.dumps(arguments, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            serialized = str(arguments)
        if len(serialized) > 1200:
            serialized = serialized[:1200] + "…"
        return f"↳ {name} {serialized}"

    async def _handle_command(self, prompt: str) -> None:
        command, _, argument = prompt.partition(" ")
        command = command.lower()
        argument = argument.strip()
        if command in {"/menu", "/exit", "/quit"}:
            await self.app.open_menu()
            return
        if command == "/config":
            self.app.push_screen(
                ConfigurationDialog(),
                self._configuration_dialog_closed,
            )
            return
        if command == "/connect":
            self.app.push_screen(ProviderDialog(self.app.credentials, "connect"), self._provider_dialog_closed)
            return
        if command == "/model":
            self.app.push_screen(ProviderDialog(self.app.credentials, "model"), self._provider_dialog_closed)
            return
        if command == "/theme":
            if argument:
                normalized = argument.casefold().strip()
                theme_id = next(
                    (
                        candidate_id
                        for candidate_id, palette in THEMES.items()
                        if normalized in {candidate_id.casefold(), palette["name"].casefold()}
                    ),
                    None,
                )
                if theme_id is None:
                    await self._fail(
                        "Choose a theme with /theme, or use one of: " + ", ".join(THEMES),
                        "Theme not found",
                    )
                else:
                    self._apply_session_theme(theme_id)
                    self._set_activity(f"Theme changed to {THEMES[theme_id]['name']}.")
                return
            self.app.push_screen(SessionThemeDialog(self.theme_id), self._theme_dialog_closed)
            return
        if command == "/pet":
            if argument:
                normalized = " ".join(argument.casefold().split())
                selected = next(
                    (
                        companion
                        for companion in COMPANIONS
                        if normalized in {companion.id.casefold(), companion.name.casefold()}
                    ),
                    None,
                )
                if selected is None:
                    self._set_activity("Pick a pet with /pet, or use a listed companion name.")
                else:
                    self._apply_companion(selected.id)
                return
            self.app.push_screen(CompanionDialog(self.companion_id), self._companion_dialog_closed)
            return
        if command == "/new":
            await self.app.open_session()
            return
        if command == "/rename":
            if argument:
                self._rename_session(argument)
            else:
                self.app.push_screen(
                    SessionRenameDialog(str(self.session.get("title", "New session"))),
                    self._rename_dialog_closed,
                )
            return
        if command == "/clear":
            self.session["messages"] = []
            self.session["chat_history"] = []
            self.session["rewind_points"] = []
            self.agent_history.clear()
            self.session["agent_history"] = self.agent_history
            self._message_widgets.clear()
            self.sessions.save_session(self.session)
            await self.query_one("#conversation", VerticalScroll).remove_children()
            await self._append_message(
                self._opening_greeting(),
                "system",
            )
            self._set_activity("Conversation cleared.")
            self._set_companion("idle", "Mitsu is Ready to Pwn!")
            return
        if command == "/help":
            await self._append_message(
                "Commands: /connect, /model, /config, /theme, /mcp, /new, /rename [name], /target [add|select|remove|clear|list], "
                "/level, /pet, /export, /rewind, /reasoning [on|off|low|medium|high], /verbose, /permissions [clear], /search <text>, /report, /map, "
                "/vulnsearch <criteria>, /mode [recon|guided|autopwn], /delete-session, /clear, /menu. "
                "Shift+Tab cycles modes. Ask naturally to inspect files, search the web, or run a shell command. "
                "Ctrl+F opens transcript search; press it again for the next match. Esc exits search mode. "
                "Recon favors passive and low-impact checks; Guided reviews shell and external MCP tools; AutoPwn runs autonomously within scope."
            )
            return
        if command == "/mcp":
            path = self.app.credentials.path.parent / "mcp_servers.json"
            self.app.push_screen(MCPConfigDialog(path), self._mcp_dialog_closed)
            return
        if command == "/setup":
            await self.app.open_setup()
            return
        if command == "/mode":
            await self._set_mode(argument)
            return
        if command == "/permissions":
            if not argument:
                self._show_permissions_panel()
                return
            await self._permissions_command(argument)
            return
        if command in {"/target", "/targets", "/scope"}:
            await self._target_command(argument)
            return
        if command == "/level":
            await self._level_command(argument)
            return
        if command == "/export":
            self._show_export_panel()
            return
        if command == "/rewind":
            self._show_rewind_panel()
            return
        if command == "/verbose":
            await self._verbose_command(argument)
            return
        if command == "/reasoning":
            await self._reasoning_command(argument)
            return
        if command == "/search":
            if argument:
                self._search_command(argument)
            else:
                self._open_search_dialog()
            return
        if command == "/delete-session":
            self.app.push_screen(
                DeleteSessionDialog(
                    session_title=str(self.session.get("title", "this session"))
                ),
                self._delete_session_confirmation_closed,
            )
            return
        if command == "/report":
            await self._report_command()
            return
        if command == "/map":
            await self._map_command()
            return
        if command == "/vulnsearch":
            await self._vulnsearch_command(argument)
            return
        if command in {"/scan", "/recon", "/nmap", "/scrape"}:
            await self._tool_command(command.lstrip("/"), argument)
            return
        await self._fail(f"Unknown command: {command}. Use /help for the command list.", "Unknown command")

    def _delete_session_confirmation_closed(self, confirmed: bool) -> None:
        if not confirmed:
            self._set_activity("Session deletion canceled.")
            self.call_after_refresh(self._focus_prompt)
            return
        self.app.run_worker(self._delete_current_session(), name="delete-current-session")

    async def _delete_current_session(self) -> None:
        session_id = str(self.session.get("id", ""))
        try:
            deleted = self.sessions.delete_session(session_id)
        except OSError as error:
            await self._fail(f"Could not delete this session: {error}", "Delete failed")
            self.call_after_refresh(self._focus_prompt)
            return
        if not deleted:
            await self._fail("This session could not be found on disk.", "Delete failed")
            self.call_after_refresh(self._focus_prompt)
            return
        await self.app.open_menu()

    async def _target_command(self, argument: str) -> None:
        action, _, value = argument.partition(" ")
        action = action.lower()
        value = value.strip()
        if action not in {"add", "set", "select", "remove", "clear", "list"} and action:
            value = argument.strip()
            action = "set"
        if action == "set":
            if not self._valid_target(value):
                await self._fail("Enter a hostname, IP, CIDR, or http(s) URL without spaces.", "Invalid target")
                return
            if value not in self.targets:
                self.targets.append(value)
            self.active_target = value
            self._persist_scope()
            self._set_activity(f"Main target set to {value}.")
            await self._append_message(f"Main target set to {value}; it is now in this session’s authorized scope.", "success")
            return
        if action == "add":
            if not self._valid_target(value):
                await self._fail("Enter a hostname, IP, CIDR, or http(s) URL without spaces.", "Invalid target")
                return
            if value in self.targets:
                await self._append_message(f"{value} is already in the authorized scope.")
                return
            self.targets.append(value)
            self.active_target = value
            self._persist_scope()
            self._set_activity(f"Added {value} to scope.")
            self._set_companion("success", "Scope updated", reset_after=1.8)
            await self._append_message(f"Added {value} to this session’s authorized scope.", "success")
            return
        if action == "select":
            if value not in self.targets:
                await self._fail(f"Target is not in scope: {value or '(empty)'}", "Target not found")
                return
            self.active_target = value
            self._persist_scope()
            self._set_activity(f"Selected {value}.")
            self._set_companion("success", "Target selected", reset_after=1.8)
            await self._append_message(f"Selected {value} as the active target.", "success")
            return
        if action == "remove":
            if value not in self.targets:
                await self._fail(f"Target is not in scope: {value or '(empty)'}", "Target not found")
                return
            self.targets.remove(value)
            if self.active_target == value:
                self.active_target = self.targets[-1] if self.targets else None
            self._persist_scope()
            self._set_activity(f"Removed {value} from scope.")
            self._set_companion("success", "Scope updated", reset_after=1.8)
            await self._append_message(f"Removed {value} from this session’s authorized scope.", "success")
            return
        if action == "clear":
            self.targets.clear()
            self.active_target = None
            self._persist_scope()
            self._set_activity("Target scope cleared.")
            self._set_companion("success", "Scope cleared", reset_after=1.8)
            await self._append_message("Cleared the authorized target list.", "success")
            return
        if action in {"list", ""}:
            lines = "\n".join(
                f"{'›' if target == self.active_target else ' '} {target}"
                for target in self.targets
            ) or "No targets in scope."
            await self._append_message(f"Authorized targets:\n{lines}")
            return
        await self._fail("Use /target <domain-or-IP>, add, select, remove, clear, or list.", "Invalid target command")

    async def _level_command(self, argument: str) -> None:
        if not argument:
            self._show_level_panel()
            return
        try:
            level = int(argument)
        except ValueError:
            level = 0
        if level not in range(1, 6):
            self._show_level_panel()
            return
        self._apply_level(level)

    def _apply_level(self, level: int) -> None:
        self.level = level
        self.session["level"] = level
        self.sessions.save_session(self.session)
        self._update_context()
        label = LEVEL_NAMES[level]
        self._set_activity(f"Aggressive level set to {level}/5 · {label}.")

    def _companion_dialog_closed(self, companion_id: str | None) -> None:
        if companion_id:
            self._apply_companion(companion_id)
        self.call_after_refresh(self._focus_prompt)

    def _apply_companion(self, companion_id: str) -> None:
        companion = companion_by_id(companion_id)
        self.companion_id = companion.id
        self.companion_path = companion.path
        self.app.preferences.save({"companion": companion.id})
        mascot = self.query_one("#session-companion", MitsuCompanion)
        mascot.set_companion(companion.path)
        mascot.set_state("idle")
        self._set_activity(f"{companion.name} is on companion duty! ✧")

    async def _verbose_command(self, argument: str) -> None:
        choice = argument.casefold()
        if choice in {"on", "true", "1"}:
            self.verbose = True
        elif choice in {"off", "false", "0"}:
            self.verbose = False
        elif not choice or choice == "toggle":
            self.verbose = not self.verbose
        else:
            await self._fail("Use /verbose, /verbose on, or /verbose off.", "Invalid verbose setting")
            return
        self.session["verbose"] = self.verbose
        self.sessions.save_session(self.session)
        state = "on" if self.verbose else "off"
        self._set_activity(f"Expanded explanations {state}.")
        await self._append_message(f"Expanded explanations are {state}. Private internal reasoning is not displayed.", "success")

    async def _reasoning_command(self, argument: str) -> None:
        choice = argument.casefold()
        if choice not in {"", "status", "check", "on", "off", "enable", "enabled", "disable", "disabled", "low", "medium", "high"}:
            await self._fail("Use /reasoning, /reasoning on|off, or /reasoning low|medium|high.", "Invalid reasoning setting")
            return
        effort = choice if choice in {"low", "medium", "high"} else "medium"
        if choice in {"off", "disable", "disabled"}:
            self.provider["reasoning_enabled"] = False
            self.sessions.save_session(self.session)
            credentials = getattr(self.app, "credentials", None)
            if isinstance(credentials, CredentialStore):
                credentials.save_profile(self.provider)
            await self._append_message("Provider reasoning is off.", "success")
            return
        self._set_activity("Checking the model catalog for reasoning support…")
        try:
            capability = await asyncio.to_thread(check_reasoning_support, self.provider)
        except ProviderRequestError as error:
            await self._fail(str(error), "Reasoning capability check failed")
            return
        if capability == "unsupported":
            self.provider["reasoning_enabled"] = False
            detail = "The provider explicitly reports that this model does not support reasoning. It remains off."
        elif capability is None:
            self.provider["reasoning_enabled"] = False
            detail = "The provider did not expose reasoning capability metadata for this model, so support is unknown and remains off."
        elif choice in {"", "status", "check"}:
            detail = f"This model advertises {capability} support. Use /reasoning on or /reasoning low|medium|high to enable it."
        elif choice not in {"on", "enable", "enabled", "low", "medium", "high"}:
            await self._fail("Use /reasoning, /reasoning on|off, or /reasoning low|medium|high.", "Invalid reasoning setting")
            return
        else:
            self.provider["reasoning_enabled"] = True
            self.provider["reasoning_parameter"] = capability
            self.provider["reasoning_effort"] = effort
            detail = f"Provider reasoning enabled ({effort}). The model catalog advertised {capability}."
        credentials = getattr(self.app, "credentials", None)
        if isinstance(credentials, CredentialStore):
            credentials.save_profile(self.provider)
            self.provider = credentials.active() or self.provider
        self.sessions.save_session(self.session)
        self._set_activity(detail)
        await self._append_message(detail, "success" if self.provider.get("reasoning_enabled") else "assistant")
