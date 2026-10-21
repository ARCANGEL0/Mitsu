from __future__ import annotations

import base64
import re

from rich.markdown import Markdown
from rich.segment import Segment
from rich.style import Style


COPY_TAG = re.compile(r"<copytag>(.*?)</copytag>|<copytag>(.*?)<copytag>", re.IGNORECASE | re.DOTALL)


def render_copy_tag(match: re.Match[str]) -> str:
    value = (match.group(1) if match.group(1) is not None else match.group(2)).strip()
    if not value:
        return ""
    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
    tick_run = max((len(run) for run in re.findall(r"`+", value)), default=0)
    delimiter = "`" * (tick_run + 1)
    return f"[{delimiter} {value} {delimiter}](mitsu-copy:{encoded})"


class CopyableMarkdown(Markdown):
    def __rich_console__(self, console, options):
        for segment in super().__rich_console__(console, options):
            style = segment.style
            link = style.link if style is not None else None
            if link and link.startswith("mitsu-copy:"):
                encoded = link.removeprefix("mitsu-copy:")
                try:
                    value = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    value = ""
                style = style.update_link(None) + Style(meta={"mitsu_copy": value}, underline=True)
                segment = Segment(segment.text, style, segment.control)
            yield segment
