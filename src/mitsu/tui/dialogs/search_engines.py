"""Search engine configuration dialog and onboarding panel."""

from __future__ import annotations

import asyncio
import os
from queue import SimpleQueue
from typing import Callable

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Right, Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, OptionList, Static

from mitsu.config import CredentialStore
from mitsu.search import SEARCH_ENGINES, SEARCH_ENGINE_BY_ID, validate_search_engine
from mitsu.services.docker_installer import DockerInstallError, install_docker_engine
from mitsu.services.searxng import (
    DockerNotInstalledError,
    SearXNGSetupError,
    setup_local_searxng,
    stop_local_searxng,
)


class SearchEnginePanel(Vertical):
    BINDINGS = [
        Binding("escape", "cancel", "Back", priority=True),
        Binding("space", "toggle_engine", "Configure / toggle", priority=True),
    ]

    def __init__(
        self,
        credentials: CredentialStore,
        onboarding: bool = False,
        on_finish: Callable[[bool], None] | None = None,
        id: str | None = None,
    ) -> None:
        super().__init__(id=id, classes="search-engine-panel")
        self.credentials = credentials
        self.onboarding = onboarding
        self.on_finish = on_finish
        self.pending = credentials.search_engines()
        self.current_engine_id: str | None = None
        self.stage = "list"
        self.checking = False
        self.message = ""
        self.action_ids: list[str] = []

    def compose(self) -> ComposeResult:
        yield Static("SEARCH ENGINES", id="search-engine-title", markup=False)
        yield Static("", id="search-engine-detail", markup=False)
        yield OptionList(id="search-engine-list", compact=True)
        with Vertical(id="search-engine-editor"):
            yield Static("", id="search-engine-editor-title", markup=False)
            yield Static("", id="search-engine-editor-detail", markup=False)
            yield Static("Local service port", id="search-engine-port-label", classes="search-field-label", markup=False)
            yield Input(value="8888", placeholder="8888", id="search-engine-port")
            yield Static("SearXNG instance URL", id="search-engine-base-label", classes="search-field-label", markup=False)
            yield Input(placeholder="https://search.example", id="search-engine-base-url")
            yield Static("API key", id="search-engine-key-label", classes="search-field-label", markup=False)
            yield Input(placeholder="Paste API key", password=True, id="search-engine-api-key")
            with Right(id="docker-password-slot"):
                with Vertical(id="docker-password-card"):
                    yield Static(
                        "Sudo password",
                        id="search-engine-sudo-password-label",
                        classes="search-field-label",
                        markup=False,
                    )
                    yield Input(placeholder="Enter sudo password", password=True, id="search-engine-sudo-password")
            yield Static("Search Engine ID (cx)", id="search-engine-cx-label", classes="search-field-label", markup=False)
            yield Input(placeholder="Programmable Search Engine ID", id="search-engine-cx")
            yield OptionList(id="search-engine-actions", compact=True)
        yield Static("", id="search-engine-status", markup=False)
        yield Static("↑ / ↓ choose    Enter configure / select    Esc back", id="search-engine-hint", markup=False)

    def on_mount(self) -> None:
        self._show_list(focus=not self.onboarding)

    def on_key(self, event: events.Key) -> None:
        if self.stage != "docker-install":
            return
        if event.character in {"y", "Y"}:
            event.stop()
            self._begin_docker_install()
        elif event.character in {"n", "N"}:
            event.stop()
            self._show_list()

    async def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_index is None:
            return
        if event.option_list.id == "search-engine-list":
            if self.onboarding:
                self._save_and_close()
                return
            if event.option_index == len(SEARCH_ENGINES):
                self._save_and_close()
            elif event.option_index < len(SEARCH_ENGINES):
                engine_id = SEARCH_ENGINES[event.option_index].id
                if engine_id == "searxng":
                    self._show_searxng_choices()
                else:
                    self._edit(engine_id)
            return
        if event.option_list.id != "search-engine-actions" or self.checking:
            return
        action = self.action_ids[event.option_index]
        if self.stage == "searxng-choice":
            if action == "setup_local":
                self._show_searxng_setup()
            elif action == "existing":
                self._edit("searxng")
            else:
                self._show_list()
            return
        if self.stage == "searxng-setup":
            if action == "setup_local":
                await self._setup_local_searxng()
            else:
                self._show_searxng_choices()
            return
        if self.stage == "docker-install":
            if action == "install_docker":
                self._begin_docker_install()
            else:
                self._show_list()
            return
        if self.stage == "docker-password":
            if action == "install_docker":
                password = self.query_one("#search-engine-sudo-password", Input).value
                self.query_one("#search-engine-sudo-password", Input).value = ""
                await self._install_docker(password)
            else:
                self._show_docker_install_prompt()
            return
        if action == "enable_live" and self.current_engine_id:
            spec = SEARCH_ENGINE_BY_ID[self.current_engine_id]
            self.pending[self.current_engine_id] = {
                **self.pending.get(self.current_engine_id, {}),
                "enabled": True,
            }
            self.message = (
                f"{spec.name} enabled. Mitsu will try it on the next search; "
                "public pages may throttle automated requests."
            )
            self._show_list()
        elif action == "validate":
            await self._validate_and_save()
        elif action == "remove":
            if self.current_engine_id:
                existing = self.pending.get(self.current_engine_id, {})
                if self.current_engine_id == "searxng" and existing.get("managed_local"):
                    self.checking = True
                    actions = self.query_one("#search-engine-actions", OptionList)
                    actions.disabled = True
                    self.query_one("#search-engine-status", Static).update("Stopping the local SearXNG service…")
                    try:
                        await asyncio.to_thread(stop_local_searxng, existing)
                    except SearXNGSetupError as error:
                        self.checking = False
                        actions.disabled = False
                        self.query_one("#search-engine-status", Static).update(f"Could not stop SearXNG: {error}")
                        return
                    finally:
                        self.checking = False
                        actions.disabled = False
                self.pending.pop(self.current_engine_id, None)
                name = SEARCH_ENGINE_BY_ID[self.current_engine_id].name
                self.message = f"Removed {name} from configured engines."
            self._show_list()
        else:
            self._show_list()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if self.stage == "docker-password":
            password = event.value
            event.input.value = ""
            await self._install_docker(password)
            return
        if self.stage not in {"edit", "searxng-setup"}:
            return
        if self.stage == "searxng-setup":
            self.query_one("#search-engine-actions", OptionList).focus()
            return
        focus_order = [
            widget for widget in (
                self.query_one("#search-engine-base-url", Input),
                self.query_one("#search-engine-api-key", Input),
                self.query_one("#search-engine-cx", Input),
            ) if widget.display
        ]
        try:
            index = focus_order.index(event.input)
        except ValueError:
            self.query_one("#search-engine-actions", OptionList).focus()
            return
        if index + 1 < len(focus_order):
            focus_order[index + 1].focus()
        else:
            self.query_one("#search-engine-actions", OptionList).focus()

    def action_cancel(self) -> None:
        if self.checking:
            self.query_one("#search-engine-status", Static).update(
                "A check or service setup is still running; it will finish here in a moment."
            )
            return
        if self.stage == "docker-install":
            self._show_list()
        elif self.stage == "docker-password":
            self._show_docker_install_prompt()
        elif self.stage in {"edit", "searxng-choice", "searxng-setup"}:
            self._show_list()
        else:
            self._finish(False)

    async def action_toggle_engine(self) -> None:
        if self.checking:
            return
        if self.stage != "list":
            return
        option_index = self.query_one("#search-engine-list", OptionList).highlighted
        if option_index is None or option_index >= len(SEARCH_ENGINES):
            return
        engine_id = SEARCH_ENGINES[option_index].id
        if self.onboarding:
            if engine_id == "searxng":
                self._show_searxng_choices()
            else:
                self._edit(engine_id)
            return
        settings = self.pending.get(engine_id)
        if settings is None:
            self.message = "Configure and validate an engine before enabling it."
        else:
            settings["enabled"] = not bool(settings.get("enabled", True))
            state = "enabled" if settings["enabled"] else "paused"
            if engine_id == "searxng" and settings.get("managed_local") and not settings["enabled"]:
                self.checking = True
                self.query_one("#search-engine-status", Static).update("Pausing Mitsu's local SearXNG service…")
                try:
                    await asyncio.to_thread(stop_local_searxng, settings)
                    self.message = "SearXNG is paused; its local container is stopped and ready for later."
                except SearXNGSetupError as error:
                    self.message = f"SearXNG is paused, but its container could not be stopped: {error}"
                finally:
                    self.checking = False
            else:
                self.message = f"{SEARCH_ENGINE_BY_ID[engine_id].name} is {state}."
        selected = option_index
        self._show_list()
        self.query_one("#search-engine-list", OptionList).highlighted = selected

    def _show_list(self, focus: bool = True) -> None:
        self.stage = "list"
        self.current_engine_id = None
        self.query_one("#search-engine-sudo-password", Input).value = ""
        self.query_one("#search-engine-editor-title", Static).remove_class("search-engine-warning")
        self.query_one("#search-engine-editor", Vertical).display = False
        self.query_one("#search-engine-list", OptionList).display = True
        title = "CHOOSE SEARCH ENGINES" if self.onboarding else "CONFIGURE SEARCH ENGINES"
        detail = (
            "Choose one or more search engines. "
            + ("Space configures a service; Enter continues. " if self.onboarding else "Space toggles configured engines. ")
            + "API checks may use provider quota."
        )
        self.query_one("#search-engine-title", Static).update(title)
        self.query_one("#search-engine-detail", Static).update(detail)
        options = []
        for engine in SEARCH_ENGINES:
            settings = self.pending.get(engine.id)
            enabled = settings is not None and bool(settings.get("enabled", True))
            status = "✓ " if enabled else "○ " if settings else "  "
            if engine.id == "searxng":
                options.append(f"{status}SearXNG - Mitsu Default - Self-hosted/No API Key")
            else:
                configured = " (configured)" if settings and enabled else " (configured · off)" if settings else ""
                if settings and settings.get("managed_local"):
                    configured = f" (local · 127.0.0.1:{settings.get('port', '?')})" + ("" if enabled else " · off")
                options.append(f"{status}{engine.name}{configured}  ·  {engine.description}")
        if not self.onboarding:
            options.append("SAVE")
        option_list = self.query_one("#search-engine-list", OptionList)
        option_list.clear_options()
        option_list.add_options(options)
        option_list.highlighted = 0
        self.query_one("#search-engine-status", Static).update(self.message)
        self.query_one("#search-engine-status", Static).remove_class("search-engine-warning")
        self.query_one("#search-engine-hint", Static).update(
            "↑ / ↓ choose    Space configure    Enter continue    ← back"
            if self.onboarding
            else "↑ / ↓ choose    Enter configure / save    Space enable / pause    Esc cancel"
        )
        if focus:
            option_list.focus()

    def _show_searxng_choices(self) -> None:
        self.stage = "searxng-choice"
        self.current_engine_id = "searxng"
        self.message = ""
        self.query_one("#search-engine-title", Static).update("SEARXNG · LOCAL OR YOUR OWN")
        self.query_one("#search-engine-detail", Static).update("")
        self.query_one("#search-engine-list", OptionList).display = False
        self.query_one("#search-engine-editor", Vertical).display = True
        self.query_one("#search-engine-editor-title", Static).update("Mitsu's local search")
        self.query_one("#search-engine-editor-detail", Static).update(
            "Mitsu can run SearXNG on 127.0.0.1 for web search. It stops when Mitsu exits."
        )
        for selector in (
            "#search-engine-port-label", "#search-engine-port", "#search-engine-base-label",
            "#search-engine-base-url", "#search-engine-key-label", "#search-engine-api-key",
            "#docker-password-card",
            "#search-engine-cx-label", "#search-engine-cx",
        ):
            self.query_one(selector).display = False
        self.action_ids = ["setup_local", "existing", "back"]
        actions = self.query_one("#search-engine-actions", OptionList)
        actions.clear_options()
        actions.add_options([
            "Yes, set up local SearXNG",
            "Use an existing SearXNG URL",
            "Back to search engines",
        ])
        actions.highlighted = 0
        self.query_one("#search-engine-status", Static).update("")
        self.query_one("#search-engine-hint", Static).update(
            "↑ / ↓ choose    Enter select    Esc back"
        )
        actions.focus()
