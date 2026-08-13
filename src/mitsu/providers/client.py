"""HTTP clients for supported language model providers."""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from typing import Any, Callable


class ProviderRequestError(Exception):
    pass


@dataclass(frozen=True)
class ToolInvocation:
    id: str
    name: str
    arguments: Any


@dataclass(frozen=True)
class ProviderTurn:
    text: str
    assistant_message: dict[str, Any]
    tool_calls: list[ToolInvocation]
    usage: dict[str, Any] = field(default_factory=dict)
    response_info: dict[str, Any] = field(default_factory=dict)


StreamCallback = Callable[[str, dict[str, Any]], None]


class RequestCancellation:
    """Close an in-flight streamed response when the operator interrupts it."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._response: Any = None

    def cancelled(self) -> bool:
        return self._event.is_set()

    def attach(self, response: Any) -> None:
        with self._lock:
            if self._event.is_set():
                response.close()
            else:
                self._response = response

    def detach(self, response: Any) -> None:
        with self._lock:
            if self._response is response:
                self._response = None

    def cancel(self) -> None:
        self._event.set()
        with self._lock:
            response = self._response
            self._response = None
        if response is not None:
            response.close()
