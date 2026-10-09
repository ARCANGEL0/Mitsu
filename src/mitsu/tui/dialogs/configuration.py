"""General settings hub for session-level configuration."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import OptionList, Static

_SETTINGS = (
    ("Provider and model", "provider", "Choose the active model provider and update its connection."),
    ("Search providers", "search", "Configure, validate, enable, or pause web search engines."),
    ("MCP servers", "mcp", "Review the MCP servers Mitsu can connect to during a session."),
    ("Permissions and approvals", "planned", "Planned: approval defaults, saved command approvals, and MCP tool approvals."),
    ("Tool access", "planned", "Planned: choose which shell, file, search, and MCP tools are available."),
    ("Authorized scope", "planned", "Planned: scope reminders, target allowlists, and out-of-scope safeguards."),
    ("Autonomy and reasoning", "planned", "Planned: default workflow mode, aggressiveness level, and reasoning effort."),
    ("Privacy and session data", "planned", "Planned: history retention, export defaults, and local data controls."),
    ("Appearance and companion", "planned", "Planned: theme, motion, companion, and animation preferences."),
    ("Network and proxy", "planned", "Planned: proxy routing, request timeouts, and per-provider network settings."),
    ("Input and notifications", "planned", "Planned: keyboard shortcuts, queue behavior, and notification preferences."),
)


class ConfigurationDialog(ModalScreen[str | None]):
    """One entry point for current settings and future configuration areas."""

    BINDINGS = [Binding("escape", "cancel", "Close", priority=True)]

    def compose(self) -> ComposeResult:
        with Vertical(id="general-config-dialog"):
            yield Static("MITSU SETTINGS", id="general-config-title", markup=False)
            yield Static(
                "Choose a settings area. Items marked Planned are design placeholders for upcoming controls.",
                id="general-config-description",
                markup=False,
            )
            yield OptionList(
                *(f"{label}  ·  {'open' if action != 'planned' else 'planned'}" for label, action, _ in _SETTINGS),
                id="general-config-options",
                compact=True,
                markup=False,
            )
            yield Static("", id="general-config-detail", markup=False)
            yield Static("↑ / ↓ choose    Enter open    Esc close", id="general-config-hint", markup=False)

    def on_mount(self) -> None:
        self.query_one("#general-config-options", OptionList).focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "general-config-options" or event.option_index is None:
            return
        _, action, detail = _SETTINGS[event.option_index]
        if action in {"provider", "search", "mcp"}:
            self.dismiss(action)
            return
        self.query_one("#general-config-detail", Static).update(detail)

    def action_cancel(self) -> None:
        self.dismiss(None)
