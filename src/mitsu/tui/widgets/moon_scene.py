from __future__ import annotations

import random

from rich.text import Text
from textual.widgets import Static

from mitsu.tui.branding import MITSU_CYAN, MITSU_TAGLINE, MITSU_WORDMARK

MOON_ART = (
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⠤⢀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⢀⢰⢈⣹⠓⣾⢷⡄⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣨⠀⢠⠐⣪⣭⣅⢤⣿⠞⠳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣟⣶⢃⡃⠟⠓⡁⣫⡄⡀⠐⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⡰⢫⣟⠿⠧⣿⣿⣥⠴⣴⣮⣏⡣⣄⣲⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⣰⣽⡵⢡⠤⠀⠈⢿⣷⠆⢚⡋⡁⢤⣿⡿⠁⠀⠀⠀⠀⢀⡤⠊⠉⠉⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⣠⣤⠖⠶⡟⡧⢿⠀⠀⠀⠀⠀⠛⠶⣾⣷⡶⠟⠛⠉⢣⠀⣀⣀⣀⡜⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⡜⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠁⠩⠵⠴⠲⠔⠶⠶⠶⠦⠴⠶⠶⠶⠖⠦⠤⢴⠏⠀⡴⠃⠀⠀⠀⠀⠀⠀",
)

CLOUD_SMALL = (
    "⠀⠀⠀⠀⠀⢀⣼⢶⢲⢤⡀⠀⠀⠀⠀",
    "⠀⠀⢰⣟⠉⠹⠀⠀⠂⣀⣻⣄⠀⠀⠀",
    "⢠⡟⠋⠉⠉⠽⠒⠲⠊⠉⠀⠉⠳⡄⠀",
    "⢿⡤⠀⠀⠀⣀⡀⠀⠀⠀⢀⡰⢢⣿⡄",
    "⠈⠻⣦⣠⣵⣧⣿⣶⣤⣠⣴⡽⠟⠁⠀",
)

CLOUD_MEDIUM = (
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠊⠉⠉⠙⣦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⡜⠁⠀⠀⣠⠏⠁⠀⠀⢹⡠⠤⣄⣄⠀⠀⠀⠀⠠⠀",
    "⠀⠀⠀⠀⠀⠀⠀⣠⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⣇⡀⢄⣀⠀",
    "⠀⠀⠀⠀⠀⠀⡴⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡏⡧⡀⠀",
    "⠀⠀⠀⠀⠀⠀⢻⡀⠀⠀⣀⣀⣀⢀⣀⠀⠀⠀⠀⠀⠀⣀⣀⠤⠞⠁⠀⡜⢸⡏⠀⢸",
    "⠀⠀⠀⠀⠀⠀⠀⠈⠉⠽⠕⠋⠘⠓⠒⠲⠤⠤⠤⡖⣛⠴⠶⡲⠮⠭⢶⣭⠦⠤⠎⠀",
)

CLOUD_LARGE = (
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠴⠢⠤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⡔⣝⢏⠁⠀⠀⠀⢀⣉⣀⣀⡀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⢀⠤⢉⡩⠟⣓⡿⠁⠀⠀⡖⠁⠀⠀⠀⠀⠀⠉⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⡠⣒⢯⢕⣫⡯⠗⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡗⡆⠀⠀⠀⠀⠀⠀",
    "⠉⡜⢛⣿⡇⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡄⠀⠀⠀⠀⠀",
    "⠀⠈⠉⠉⠁⠉⠛⠛⠉⠉⠉⠉⠁⠉⠁⠁⠁⠉⠉⠉⠒⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀",
)


class MoonScene(Static):
    WIDTH = 50
    HEIGHT = 11
    TICK_SECONDS = 0.12
    STAR_GLYPHS = (".", "·", "˚", "✦", "✧", "✶", "⭑", "⋆")

    def __init__(self, accent: str = "#f5d36e", show_brand: bool = False, **kwargs) -> None:
        self.accent = accent
        self.show_brand = show_brand
        self.frame = 0
        super().__init__(markup=False, **kwargs)

    def on_mount(self) -> None:
        self.set_interval(self.TICK_SECONDS, self._advance)

    def _advance(self) -> None:
        self.frame += 1
        self.refresh()

    def render(self) -> Text:
        width = self.size.width or self.WIDTH
        cells = [[(" ", "") for _ in range(width)] for _ in range(self.HEIGHT)]

        def paint(x: int, y: int, glyph: str, color: str) -> None:
            if 0 <= x < width and 0 <= y < self.HEIGHT and glyph not in {" ", "⠀"}:
                cells[y][x] = (glyph, color)

        def overlay(y: int, start: int, content: str, color: str) -> None:
            if not 0 <= y < self.HEIGHT:
                return
            for column, glyph in enumerate(content):
                x = start + column
                if 0 <= x < width:
                    cells[y][x] = (glyph, color if glyph != " " else "")

        rng = random.Random(width * 31 + self.HEIGHT)
        star_count = max(10, width // 9)
        stars: list[tuple[int, int, str]] = []
        for _ in range(star_count * 80):
            x = rng.randrange(width)
            y = rng.randrange(self.HEIGHT)
            if any(star_y == y and abs(x - star_x) < 10 for star_x, star_y, _ in stars):
                continue
            stars.append((x, y, rng.choice(self.STAR_GLYPHS)))
            if len(stars) == star_count:
                break
        for index, (x, y, glyph) in enumerate(stars):
            color = self.accent if (index + self.frame // 5) % 4 == 0 else "#91c6d0"
            paint(x, y, glyph, color)

        cloud_tracks = (
            (CLOUD_LARGE, 0.67, 1, 4, "#91b7c4"),
            (CLOUD_MEDIUM, 0.39, 2, 3, "#a4c9d2"),
            (CLOUD_SMALL, 0.10, 4, 2, "#b3d5dc"),
            (CLOUD_SMALL, 0.88, 3, 3, "#b3d5dc"),
        )
        for sprite, start_ratio, top, stride, color in cloud_tracks:
            sprite_width = max(map(len, sprite))
            start = int(max(0, width - sprite_width) * start_ratio)
            period = width + sprite_width
            travel = self.frame // stride
            left = (start + sprite_width - travel) % period - sprite_width
            for row_index, row in enumerate(sprite):
                for column, glyph in enumerate(row):
                    paint(left + column, top + row_index, glyph, color)

        moon_y = 0
        moon_x = max(0, width - 18)
        for row_index in range(7):
            if row_index >= len(MOON_ART):
                break
            row = MOON_ART[row_index]
            for column in range(14):
                source_column = 12 + column
                if source_column < len(row):
                    paint(moon_x + column, moon_y + row_index, row[source_column], self.accent)

        if self.show_brand:
            for row_index, row in enumerate(MITSU_WORDMARK.splitlines(), start=1):
                start = max(0, (width - len(row)) // 2)
                overlay(row_index, start, row, MITSU_CYAN)
            tagline_x = max(0, (width - len(MITSU_TAGLINE)) // 2)
            overlay(6, tagline_x, MITSU_TAGLINE, MITSU_CYAN)
        scene = Text(no_wrap=True, overflow="crop")
        for y, row in enumerate(cells):
            if y:
                scene.append("\n")
            for glyph, color in row:
                scene.append(glyph, style=color or None)
        return scene
