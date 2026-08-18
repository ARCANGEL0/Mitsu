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


def _request_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 12,
) -> dict[str, Any]:
    request_headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=request_headers)
    with urlopen(request, timeout=timeout) as response:
        payload = response.read(2_000_000).decode("utf-8", errors="replace")
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise ValueError("The search service returned unexpected JSON.")
    return parsed


def _validate_base_url(value: str) -> str:
    url = value.strip().rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Enter a complete SearXNG http:// or https:// instance URL.")
    return url


def _api_results(engine_id: str, query: str, settings: dict[str, Any], count: int) -> list[dict[str, str]]:
    if engine_id == "searxng":
        base_url = _validate_base_url(str(settings.get("base_url", "")))
        data = _request_json(
            f"{base_url}/search?{urlencode({'q': query, 'format': 'json'})}",
        )
        raw_results = data.get("results", [])
        snippet_key = "content"
    elif engine_id == "exa":
        data = _request_json(
            "https://api.exa.ai/search",
            headers={"x-api-key": str(settings.get("api_key", ""))},
            body={
                "query": query,
                "numResults": count,
                "type": "fast",
                "contents": {"highlights": True},
            },
        )
        raw_results = data.get("results", [])
        snippet_key = "text"
    elif engine_id == "tavily":
        data = _request_json(
            "https://api.tavily.com/search",
            headers={"Authorization": f"Bearer {settings.get('api_key', '')}"},
            body={"query": query, "max_results": count, "search_depth": "basic", "topic": "general"},
        )
        raw_results = data.get("results", [])
        snippet_key = "content"
    elif engine_id == "ollama":
        data = _request_json(
            "https://ollama.com/api/web_search",
            headers={"Authorization": f"Bearer {settings.get('api_key', '')}"},
            body={"query": query, "max_results": min(count, 10)},
        )
        raw_results = data.get("results", [])
        snippet_key = "content"
    elif engine_id == "brave_api":
        params = urlencode({"q": query, "count": min(count, 20)})
        data = _request_json(
            f"https://api.search.brave.com/res/v1/web/search?{params}",
            headers={"X-Subscription-Token": str(settings.get("api_key", ""))},
        )
        web = data.get("web", {})
        raw_results = web.get("results", []) if isinstance(web, dict) else []
        snippet_key = "description"
    elif engine_id == "google_cse":
        params = urlencode({
            "key": settings.get("api_key", ""),
            "cx": settings.get("search_engine_id", ""),
            "q": query,
            "num": min(count, 10),
        })
        data = _request_json(f"https://www.googleapis.com/customsearch/v1?{params}")
        raw_results = data.get("items", [])
        snippet_key = "snippet"
    elif engine_id == "serper":
        data = _request_json(
            "https://google.serper.dev/search",
            headers={"X-API-KEY": str(settings.get("api_key", ""))},
            body={"q": query, "num": min(count, 20)},
        )
        raw_results = data.get("organic", [])
        snippet_key = "snippet"
    elif engine_id == "serpapi":
        params = urlencode({
            "engine": "google",
            "q": query,
            "num": min(count, 20),
            "api_key": settings.get("api_key", ""),
        })
        data = _request_json(f"https://serpapi.com/search.json?{params}")
        raw_results = data.get("organic_results", [])
        snippet_key = "snippet"
    elif engine_id == "firecrawl":
        data = _request_json(
            "https://api.firecrawl.dev/v2/search",
            headers={"Authorization": f"Bearer {settings.get('api_key', '')}"},
            body={"query": query, "limit": min(count, 20), "sources": ["web"]},
            timeout=45,
        )
        payload = data.get("data", {})
        raw_results = payload.get("web", []) if isinstance(payload, dict) else data.get("web", [])
        snippet_key = "description"
    else:
        raise ValueError("This search engine is not supported.")

    if not isinstance(raw_results, list):
        raise ValueError("The search service returned an unexpected results field.")
    normalized = []
    for item in raw_results:
        if not isinstance(item, dict) or not item.get("title") or not item.get("url", item.get("link")):
            continue
        snippet = item.get(snippet_key, "")
        if not snippet and isinstance(item.get("highlights"), list):
            snippet = " ".join(str(part) for part in item["highlights"])
        normalized.append({
            "title": str(item.get("title", "")).strip(),
            "url": str(item.get("url", item.get("link", ""))).strip(),
            "snippet": str(snippet).strip(),
        })
    return normalized[:count]


def _html_results(engine_id: str, query: str, count: int) -> list[dict[str, str]]:
    failures: list[str] = []
    for url_template in _SERP_URLS[engine_id]:
        url = url_template.format(query=quote_plus(query))
        request = Request(
            url,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        try:
            with urlopen(request, timeout=9) as response:
                page = response.read(1_500_000).decode("utf-8", errors="replace")
            parser = _SerpParser(engine_id)
            parser.feed(page)
        except HTTPError as error:
            failures.append(f"HTTP {error.code}")
            continue
        except (URLError, TimeoutError, OSError) as error:
            failures.append(type(error).__name__)
            continue
        if parser.items:
            return parser.items[:count]
        failures.append("no recognizable links")
    raise ValueError(", ".join(dict.fromkeys(failures)) or "no recognizable results")
