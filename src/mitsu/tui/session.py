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
