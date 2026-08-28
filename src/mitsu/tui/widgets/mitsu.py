from __future__ import annotations

import base64
import io
import os
from pathlib import Path
import secrets
import sys

from PIL import Image, ImageOps
from rich.text import Text
from textual.events import Resize
from textual.widgets import Static


class MitsuCompanion(Static):
    KITTY_CHUNK_SIZE = 4096
    KITTY_IMAGE_AREA = (13, 7)
    STATES = {
        "idle": "idle",
        "thinking": "review",
        "hacking": "running_right",
        "celebrating": "waving",
        "warning": "review",
        "success": "jumping",
        "error": "failed",
        "failed": "failed",
        "sleeping": "waiting",
        "sad": "failed",
        "glitch": "running_left",
        "running": "running",
        "running_right": "running_right",
        "running_left": "running_left",
        "waving": "waving",
        "jumping": "jumping",
        "waiting": "waiting",
        "review": "review",
    }
    # Companion sheets share the same nine-row order; the menu uses the
    # dedicated run-right row, while tool work uses the generic running row.
    ANIMATIONS = {
        "idle": (0, 6),
        "running_right": (1, 8),
        "running_left": (2, 8),
        "waving": (3, 4),
        "jumping": (4, 5),
        "failed": (5, 8),
        "waiting": (6, 6),
        "running": (7, 6),
        "review": (8, 6),
    }
    FRAME_WIDTH = 192
    FRAME_HEIGHT = 208
    DISPLAY_SIZE = (13, 14)

    def __init__(
        self,
        sprite_path: str | Path | None = None,
        animation_interval: float = 1 / 6,
        kitty_anchor: Static | None = None,
        kitty_offset: tuple[int, int] = (0, 0),
        scene_overlay: bool = False,
        flip_running_right: bool = False,
        **kwargs,
    ) -> None:
        self.state = "idle"
        self.frame_index = 0
        self.sprite_path = Path(sprite_path) if sprite_path else self._default_sprite_path()
        self.animation_interval = animation_interval
        self.kitty_anchor = kitty_anchor
        self.kitty_offset = kitty_offset
        self.scene_overlay = scene_overlay
        self.flip_running_right = flip_running_right
        self._kitty_graphics = self._supports_kitty_graphics()
        self._kitty_placement_id = secrets.randbits(31) or 1
        self._kitty_image_ids: dict[tuple[str, int], int] = {}
        self._kitty_active_key: tuple[str, int] | None = None
        self._animation_timer = None
        self._frames = self._load_frames(self.sprite_path)
        super().__init__(self._render_frame(), markup=False, **kwargs)

    @staticmethod
    def _supports_kitty_graphics() -> bool:
        override = os.environ.get("MITSU_IMAGE_PROTOCOL", "auto").lower()
        if override in {"off", "none", "text", "blocks", "false"}:
            return False
        if not sys.stdout.isatty():
            return False
        if override in {"kitty", "on", "true", "graphics"}:
            return True
        if override != "auto" or os.environ.get("TMUX"):
            return False

        term = os.environ.get("TERM", "").lower()
        program = os.environ.get("TERM_PROGRAM", "").lower()
        return (
            "kitty" in term
            or bool(os.environ.get("KITTY_WINDOW_ID"))
            or program in {
                "ghostty",
                "iterm.app",
                "kitty",
                "konsole",
                "rio",
                "vscode",
                "warpterminal",
                "wezterm",
            }
            or any(
                os.environ.get(variable)
                for variable in (
                    "GHOSTTY_RESOURCES_DIR",
                    "ITERM_SESSION_ID",
                    "KONSOLE_VERSION",
                    "WEZTERM_PANE",
                    "WARP_IS_LOCAL_SHELL_SESSION",
                )
            )
        )

    @staticmethod
    def _default_sprite_path() -> Path:
        return Path(__file__).resolve().parents[2] / "assets" / "companions" / "mitsu.webp"

    def _load_frames(self, sheet_path: Path) -> dict[str, list[Image.Image]]:
        try:
            with Image.open(sheet_path) as source:
                sheet = source.convert("RGBA")
        except OSError:
            blank = Image.new("RGBA", self.DISPLAY_SIZE)
            return {name: [blank.copy()] for name in self.ANIMATIONS}

        animations: dict[str, list[Image.Image]] = {}
        animation_rows = dict(self.ANIMATIONS)
        for name, (row_index, frame_count) in animation_rows.items():
            row_frames: list[Image.Image] = []
            for index in range(frame_count):
                left = index * self.FRAME_WIDTH
                top = row_index * self.FRAME_HEIGHT
                frame = sheet.crop(
                    (left, top, left + self.FRAME_WIDTH, top + self.FRAME_HEIGHT)
                )
                if name == "running_right" and self.flip_running_right:
                    frame = ImageOps.mirror(frame)
                row_frames.append(frame)
            animations[name] = row_frames
        return animations

    def set_state(self, state: str) -> None:
        if state not in self.STATES:
            state = "idle"
        self.state = state
        self.frame_index = 0
        self.update(self._render_frame(), layout=False)
        self._show_kitty_frame()

    def set_companion(
        self,
        sprite_path: str | Path,
        *,
        flip_running_right: bool | None = None,
    ) -> None:
        new_path = Path(sprite_path)
        new_flip = self.flip_running_right if flip_running_right is None else flip_running_right
        if new_path == self.sprite_path and new_flip == self.flip_running_right:
            return
        self._delete_active_kitty_placement()
        if self._kitty_graphics and self._kitty_image_ids:
            deletes = "".join(
                f"\x1b_Ga=d,d=I,i={image_id},q=2\x1b\\"
                for image_id in self._kitty_image_ids.values()
            )
            self._write_terminal(deletes)
        self._kitty_image_ids.clear()
        self._kitty_active_key = None
        self.sprite_path = new_path
        self.flip_running_right = new_flip
        self._frames = self._load_frames(self.sprite_path)
        self.frame_index = 0
        self.update(self._render_frame(), layout=False)
        self._show_kitty_frame(force=True)

    def on_mount(self) -> None:
        self._animation_timer = self.set_interval(self.animation_interval, self._advance)
        if self._kitty_graphics:
            self.styles.opacity = 0
            self._write_terminal("\x1b_Ga=d,q=2\x1b\\")
            self.call_after_refresh(self._show_kitty_frame)

    def on_resize(self, _event: Resize) -> None:
        if self._kitty_graphics:
            self.call_after_refresh(lambda: self._show_kitty_frame(force=True))

    def on_hide(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.pause()
        self._delete_active_kitty_placement()

    def on_show(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.resume()
        if self._kitty_graphics:
            self.call_after_refresh(self._show_kitty_frame)
