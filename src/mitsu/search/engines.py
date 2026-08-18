"""Search engine definitions, validation, and result retrieval."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from html.parser import HTMLParser
import json
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote_plus, urlencode, urljoin, urlsplit
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class SearchEngineSpec:
    id: str
    name: str
    description: str
    kind: str
    fields: tuple[str, ...] = ()


SEARCH_ENGINES = (
    SearchEngineSpec(
        "searxng", "SearXNG", "Mitsu-managed metasearch · Docker required", "searxng", ("base_url",),
    ),
    SearchEngineSpec("duckduckgo", "DuckDuckGo Search", "No key · DuckDuckGo direct", "html"),
    SearchEngineSpec("google_html", "Google Search", "No key · Google direct", "html"),
    SearchEngineSpec("bing_html", "Bing Search", "No key · Bing direct", "html"),
    SearchEngineSpec("brave_html", "Brave Search", "No key · Brave direct", "html"),
    SearchEngineSpec("mojeek", "Mojeek Search", "No key · Mojeek direct", "html"),
    SearchEngineSpec("ecosia", "Ecosia Search", "No key · Ecosia direct", "html"),
    SearchEngineSpec("yahoo", "Yahoo Search", "No key · Yahoo direct", "html"),
    SearchEngineSpec("startpage", "Startpage Search", "No key · Startpage direct", "html"),
    SearchEngineSpec("exa", "Exa Web Search", "API key · semantic web search", "exa", ("api_key",)),
    SearchEngineSpec("tavily", "Tavily Search", "API key · search for AI agents", "tavily", ("api_key",)),
    SearchEngineSpec("ollama", "Ollama Web Search", "Hosted API · Ollama account key", "ollama", ("api_key",)),
    SearchEngineSpec("brave_api", "Brave Search API", "Subscription API key", "brave_api", ("api_key",)),
    SearchEngineSpec("serper", "Serper Google Search API", "API key · structured Google results", "serper", ("api_key",)),
    SearchEngineSpec("serpapi", "SerpApi Google Search", "API key · structured Google results", "serpapi", ("api_key",)),
    SearchEngineSpec("firecrawl", "Firecrawl Web Search", "API key · web/news search", "firecrawl", ("api_key",)),
    SearchEngineSpec(
        "google_cse", "Google Programmable Search", "API key + Search Engine ID", "google_cse",
        ("api_key", "search_engine_id"),
    ),
)
SEARCH_ENGINE_BY_ID = {engine.id: engine for engine in SEARCH_ENGINES}

_SERP_HOSTS = {
    "duckduckgo": ("duckduckgo.com",),
    "google_html": ("google.com", "googleusercontent.com"),
    "bing_html": ("bing.com", "bing.net"),
    "brave_html": ("search.brave.com", "brave.com"),
    "mojeek": ("mojeek.com",),
    "ecosia": ("ecosia.org",),
    "yahoo": ("search.yahoo.com", "yahoo.com"),
    "startpage": ("startpage.com",),
}
_SERP_URLS = {
    "duckduckgo": (
        "https://html.duckduckgo.com/html/?q={query}",
        "https://lite.duckduckgo.com/lite/?q={query}",
    ),
    "google_html": ("https://www.google.com/search?q={query}&num=10",),
    "bing_html": ("https://www.bing.com/search?q={query}",),
    "brave_html": ("https://search.brave.com/search?q={query}",),
    "mojeek": ("https://www.mojeek.com/search?q={query}",),
    "ecosia": ("https://www.ecosia.org/search?q={query}",),
    "yahoo": ("https://search.yahoo.com/search?p={query}",),
    "startpage": ("https://www.startpage.com/sp/search?query={query}",),
}
_USER_AGENT = "Mitsu/0.1 (terminal assistant; public search)"
class _SerpParser(HTMLParser):
    _VOID_TAGS = {
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr",
    }

    def __init__(self, engine_id: str) -> None:
        super().__init__()
        self.engine_id = engine_id
        self.items: list[dict[str, str]] = []
        self.anchor: dict[str, Any] | None = None
        self.heading_depth = 0
        self.snippet_depth = 0
        self.snippet_target: dict[str, str] | None = None

    def _is_engine_host(self, hostname: str) -> bool:
        return any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in _SERP_HOSTS[self.engine_id]
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        classes = set((attributes.get("class") or "").split())
        if self.snippet_depth and tag not in self._VOID_TAGS:
            self.snippet_depth += 1

        if tag == "a" and attributes.get("href"):
            raw_url = attributes["href"] or ""
            parsed = urlsplit(raw_url if "://" in raw_url else urljoin(self._base_url, raw_url))
            if parsed.hostname and self._is_engine_host(parsed.hostname):
                params = parse_qs(parsed.query)
                target = (params.get("uddg") or params.get("url") or params.get("q") or [raw_url])[0]
                if self.engine_id == "bing_html" and params.get("u"):
                    encoded = params["u"][0]
                    if encoded.startswith("a1"):
                        try:
                            payload = encoded[2:]
                            payload += "=" * (-len(payload) % 4)
                            target = base64.urlsafe_b64decode(payload).decode("utf-8", errors="ignore")
                        except (ValueError, UnicodeDecodeError):
                            pass
                raw_url = target
            elif "://" not in raw_url:
                raw_url = urljoin(self._base_url, raw_url)
            parsed = urlsplit(raw_url)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                self.anchor = {
                    "title": "",
                    "url": raw_url,
                    "explicit": bool(classes.intersection({
                        "result__a", "result-link", "ob", "snippet-title", "result-header",
                    })),
                    "heading": False,
                }

        if tag in {"h2", "h3"}:
            self.heading_depth += 1
            if self.anchor is not None:
                self.anchor["heading"] = True

        snippet_classes = {
            "result__snippet", "result-snippet", "VwiC3b", "b_caption",
            "snippet-description", "result-snippet-content",
        }
        if self.engine_id == "mojeek":
            snippet_classes.add("s")
        if classes.intersection(snippet_classes) and self.items and not self.snippet_depth:
            self.snippet_depth = 1
            self.snippet_target = self.items[-1]

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self.anchor is not None:
            anchor = self.anchor
            title = re.sub(r"\s+", " ", str(anchor["title"])).strip()
            parsed = urlsplit(str(anchor["url"]))
            is_engine_link = parsed.hostname and self._is_engine_host(parsed.hostname)
            # Search providers frequently change their result-link classes. Keep
            # explicit result anchors, headings, and substantial external link
            # titles as a resilient fallback for markup-only changes.
            if (
                (anchor["explicit"] or anchor["heading"] or len(title) >= 18)
                and not is_engine_link
                and len(title) > 1
            ):
                self.items.append({"title": title, "url": str(anchor["url"]), "snippet": ""})
            self.anchor = None

        if tag in {"h2", "h3"} and self.heading_depth:
            self.heading_depth -= 1
        if self.snippet_depth and tag not in self._VOID_TAGS:
            self.snippet_depth -= 1
            if not self.snippet_depth:
                self.snippet_target = None

    def handle_data(self, data: str) -> None:
        if self.anchor is not None:
            self.anchor["title"] += data
        elif self.snippet_depth and self.snippet_target is not None:
            self.snippet_target["snippet"] += data

    @property
    def _base_url(self) -> str:
        return {
            "duckduckgo": "https://duckduckgo.com",
            "google_html": "https://www.google.com",
            "bing_html": "https://www.bing.com",
            "brave_html": "https://search.brave.com",
            "mojeek": "https://www.mojeek.com",
            "ecosia": "https://www.ecosia.org",
            "yahoo": "https://search.yahoo.com",
            "startpage": "https://www.startpage.com",
        }[self.engine_id]
