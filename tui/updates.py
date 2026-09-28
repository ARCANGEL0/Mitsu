from __future__ import annotations

import re
from urllib.error import HTTPError
from urllib.request import Request, urlopen


UPSTREAM_VERSION_URL = "https://raw.githubusercontent.com/ARCANGEL0/Mitsu/main/version.txt"


def fetch_latest_version() -> str | None:
    request = Request(UPSTREAM_VERSION_URL, headers={"User-Agent": "Mitsu version checker"})
    try:
        with urlopen(request, timeout=6) as response:
            value = response.read(128).decode("utf-8").strip()
    except HTTPError as error:
        if error.code == 404:
            return None
        raise OSError(f"GitHub returned HTTP {error.code}.") from error
    if not re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?", value):
        raise ValueError("GitHub returned an invalid version.txt value.")
    return value.removeprefix("v")


def compare_versions(left: str, right: str) -> int:
    left_parts = tuple(int(part) for part in re.findall(r"\d+", left))
    right_parts = tuple(int(part) for part in re.findall(r"\d+", right))
    width = max(len(left_parts), len(right_parts))
    left_parts = left_parts + (0,) * (width - len(left_parts))
    right_parts = right_parts + (0,) * (width - len(right_parts))
    return (left_parts > right_parts) - (left_parts < right_parts)
