from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class UpdateConfirmationDialog(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel", priority=True)]

    def __init__(self, source: str, current_version: str, latest_version: str | None) -> None:
        super().__init__()
        self.source = source
        self.current_version = current_version
        self.latest_version = latest_version

    def compose(self) -> ComposeResult:
        with Vertical(id="update-confirmation-dialog"):
            yield Static("UPDATE MITSU?", id="update-confirmation-title", markup=False)
            yield Static(
                f"Source: {self.source}\n"
                f"Installed: v{self.current_version}\n"
                f"Available: {f'v{self.latest_version}' if self.latest_version else 'new Git revision'}\n\n"
                "Mitsu will update from the source used for this installation, then restart.",
                id="update-confirmation-detail",
                markup=False,
            )
            with Horizontal(id="update-confirmation-actions"):
                yield Button("Update", id="confirm-update", variant="primary")
                yield Button("Cancel", id="cancel-update")
            yield Static("Enter update    Esc cancel", id="update-confirmation-hint", markup=False)

    def on_mount(self) -> None:
        self.query_one("#confirm-update", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-update")

    def action_cancel(self) -> None:
        self.dismiss(False)
