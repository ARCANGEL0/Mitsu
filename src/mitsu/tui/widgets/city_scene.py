from __future__ import annotations

from math import floor

from rich.text import Text
from textual.events import Resize
from textual.widgets import Static

from mitsu.tui.widgets.mitsu import MitsuCompanion


class CityScene(Static):
    HEIGHT = 10
    PERIOD = 72
    DISTANT_BUILDINGS = (
        (0, 8, 4),
        (10, 7, 6),
        (19, 9, 5),
        (31, 8, 7),
        (42, 10, 4),
        (55, 9, 6),
    )
    BUILDINGS = (
        (0, 10, 6),
        (12, 7, 4),
        (22, 12, 7),
        (37, 9, 5),
        (49, 10, 6),
        (62, 8, 4),
    )

    def __init__(self, accent: str = "#e58b6b", **kwargs) -> None:
        self.accent = accent
        self.scroll = 0
        self.companion: MitsuCompanion | None = None
        self.companion_offset = (4, 2)
        super().__init__(markup=False, **kwargs)

    def set_companion(self, companion: MitsuCompanion, offset: tuple[int, int] = (4, 2)) -> None:
        self.companion = companion
        self.companion_offset = offset

    def on_mount(self) -> None:
        self.set_interval(0.0625, self._advance)

    def on_resize(self, _event: Resize) -> None:
        self.refresh()

    def _advance(self) -> None:
        self.scroll += 1
        self.refresh()

    def render(self) -> Text:
        width = self.size.width or 120
        cells = [[(" ", "") for _ in range(width)] for _ in range(self.HEIGHT)]

        def paint(x: int, y: int, char: str, style: str) -> None:
            if 0 <= x < width and 0 <= y < self.HEIGHT:
                cells[y][x] = (char, style)

        def skyline(pattern: tuple[tuple[int, int, int], ...], scroll: int, base: int, shade: str) -> None:
            first_cycle = floor((scroll - width) / self.PERIOD)
            last_cycle = floor((scroll + width) / self.PERIOD) + 1
            for cycle in range(first_cycle, last_cycle + 1):
                for index, (start, building_width, height) in enumerate(pattern):
                    left = cycle * self.PERIOD + start - scroll
                    right = left + building_width
                    top = base - height
                    paint(left, top, "▛", shade)
                    paint(right - 1, top, "▜", shade)
                    for x in range(left + 1, right - 1):
                        paint(x, top, "▀", shade)
                    for y in range(top + 1, base):
                        paint(left, y, "▌", shade)
                        paint(right - 1, y, "▐", shade)
                        for x in range(left + 1, right - 1):
                            if (x + y * 3 + index * 5) % 5 == 0:
                                window = "▪" if (x + y + index) % 2 else "▫"
                                paint(x, y, window, self.accent + " dim")
                            elif (x + y + index) % 3 == 0:
                                paint(x, y, "░", shade + " dim")
                    if height >= 6 and index % 2:
                        antenna = left + building_width // 2
                        paint(antenna, top - 1, "▂", shade)
                        paint(antenna, top - 2, "✦", self.accent + " dim")

        for seed in range(width // 8 + 1):
            x = (seed * 29 - self.scroll // 3) % width
            y = seed % 2
            mark = "." if seed % 3 else "+"
            paint(x, y, mark, self.accent + " dim")

        skyline(self.DISTANT_BUILDINGS, self.scroll // 2, 6, "#294853")
        skyline(self.BUILDINGS, self.scroll, 7, "#43616b")

        road_shift = self.scroll % 8
        for x in range(width):
            paint(x, 8, "·" if (x + road_shift) % 5 else "┈", "#45616a")
            paint(x, 9, "━" if (x + self.scroll) % 8 in {2, 3, 4, 5} else "─", "#56717a")

        if (
            self.companion is not None
            and not self.companion._kitty_graphics
            and not self.companion._modal_suspended
        ):
            image = self.companion.display_image()
            offset_x, offset_y = self.companion_offset
            for y in range(0, image.height, 2):
                for x in range(image.width):
                    target_x = offset_x + x
                    target_y = offset_y + y // 2
                    if not 0 <= target_x < width or not 0 <= target_y < self.HEIGHT:
                        continue
                    top_pixel = image.getpixel((x, y))
                    bottom_pixel = image.getpixel((x, min(y + 1, image.height - 1)))
                    top_visible = top_pixel[3] >= 24
                    bottom_visible = bottom_pixel[3] >= 24
                    if not top_visible and not bottom_visible:
                        continue
                    if top_visible and bottom_visible:
                        top = self.companion._terminal_color(top_pixel)
                        bottom = self.companion._terminal_color(bottom_pixel)
                        cells[target_y][target_x] = ("▀", f"{top} on {bottom}")
                    elif top_visible:
                        cells[target_y][target_x] = (
                            "▀",
                            self.companion._terminal_color(top_pixel),
                        )
                    else:
                        cells[target_y][target_x] = (
                            "▄",
                            self.companion._terminal_color(bottom_pixel),
                        )

        scene = Text(no_wrap=True, overflow="crop")
        for y, row in enumerate(cells):
            if y:
                scene.append("\n")
            for char, style in row:
                scene.append(char, style=style or None)
        return scene
