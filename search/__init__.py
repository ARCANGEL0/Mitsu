"""Web search provider catalog and query operations."""

from .engines import (
    SEARCH_ENGINES,
    SEARCH_ENGINE_BY_ID,
    SearchEngineSpec,
    fetch_web_page,
    search_web,
    validate_search_engine,
)

__all__ = [
    "SEARCH_ENGINES",
    "SEARCH_ENGINE_BY_ID",
    "SearchEngineSpec",
    "fetch_web_page",
    "search_web",
    "validate_search_engine",
]
