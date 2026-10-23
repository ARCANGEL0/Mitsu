"""Mitsu terminal companion."""

import re
from pathlib import Path


_version_file = Path(__file__).with_name("version.txt")
_version_match = re.search(
    r"v?(\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?)",
    _version_file.read_text(encoding="utf-8"),
)
if _version_match is None:
    raise RuntimeError("Mitsu's version.txt does not contain a valid version.")

__version__ = _version_match.group(1)
