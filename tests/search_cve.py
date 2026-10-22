from __future__ import annotations

from mitsu.config import CredentialStore
from mitsu.search import SEARCH_ENGINE_BY_ID, search_web


QUERY = "CVE-2021-44228 Apache Log4j affected versions security advisory"


def main() -> int:
    saved = CredentialStore().search_engines()
    configured = {
        engine_id: settings
        for engine_id, settings in saved.items()
        if engine_id in SEARCH_ENGINE_BY_ID and settings.get("enabled", True)
    }
    if not configured:
        print("No web search providers are enabled. Set one up in Mitsu with /config first.")
        return 2

    print(f"Searching for: {QUERY}")
    print("Providers: " + ", ".join(SEARCH_ENGINE_BY_ID[key].name for key in configured))
    results: list[dict[str, object]] = []
    failures: list[str] = []

    def collect(found: list[dict[str, object]], unavailable: list[str]) -> None:
        results.extend(found)
        failures.extend(unavailable)

    # just use what's enabled in /config
    summary = search_web(QUERY, max_results=5, configured=configured, result_sink=collect)

    successful = {
        source
        for result in results
        for source in result.get("sources", [])
        if isinstance(source, str)
    }
    failed_names = {failure.split(":", 1)[0] for failure in failures}
    for name in (SEARCH_ENGINE_BY_ID[key].name for key in configured):
        if name in successful:
            print(f"[ok] {name}")
        elif name in failed_names:
            # empty results usually mean the provider returned nothing useful
            print(f"[unavailable] {name}")
        else:
            print(f"[no results] {name}")

    if not results:
        print("\nNo provider returned recognizable results.")
        if failures:
            print("Provider errors: " + "; ".join(failures))
        else:
            print(summary)
        return 1

    print("\nResults:")
    for result in results:
        sources = ", ".join(result.get("sources", []))
        print(f"- {result.get('title', '(untitled)')} [{sources}]")
        print(f"  {result.get('url', '')}")

    if failures:
        print("\nSome providers did not return results: " + "; ".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
