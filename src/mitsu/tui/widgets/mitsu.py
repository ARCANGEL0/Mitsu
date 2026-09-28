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
        self._terminal_graphics_suspended = False
        self._modal_suspended = False
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

    def set_terminal_graphics_visible(self, visible: bool) -> None:
        """Temporarily replace the terminal overlay sprite with its inline frame."""
        if not self._kitty_graphics or self._terminal_graphics_suspended == (not visible):
            return
        self._terminal_graphics_suspended = not visible
        if not visible:
            self._delete_active_kitty_placement()
            self.styles.opacity = 1
            self.update(self._render_frame(), layout=False)
            return
        self.update(self._render_frame(), layout=False)
        if self.is_mounted and self.screen is self.app.screen:
            self.styles.opacity = 0
            self.call_after_refresh(lambda: self._show_kitty_frame(force=True))

    def set_modal_suspended(self, suspended: bool) -> None:
        """Hide the companion, including scene and terminal overlays, under modals."""
        if self._modal_suspended == suspended:
            return
        self._modal_suspended = suspended
        if suspended:
            if self._animation_timer is not None:
                self._animation_timer.pause()
            self._delete_active_kitty_placement()
            self.styles.display = "none"
            return

        self.styles.display = "block"
        if self._animation_timer is not None:
            self._animation_timer.resume()
        if self._kitty_graphics and not self._terminal_graphics_suspended:
            self.styles.opacity = 0
            if self.is_mounted:
                self.call_after_refresh(lambda: self._show_kitty_frame(force=True))

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

    def on_unmount(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.pause()
        self.clear_terminal_graphics()

    def clear_terminal_graphics(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.pause()
        if self._kitty_graphics and self._kitty_image_ids:
            deletes = "".join(
                f"\x1b_Ga=d,d=I,i={image_id},q=2\x1b\\"
                for image_id in self._kitty_image_ids.values()
            )
            self._write_terminal(deletes)
        self._kitty_image_ids.clear()
        self._kitty_active_key = None

    def _advance(self) -> None:
        frames = self._frames[self.STATES[self.state]]
        self.frame_index = (self.frame_index + 1) % len(frames)
        self.update(self._render_frame(), layout=False)
        self._show_kitty_frame()

    def _write_terminal(self, data: str) -> bool:
        try:
            self.app._driver.write(data)
            return True
        except (AttributeError, AssertionError, OSError, RuntimeError):
            self._kitty_graphics = False
            if self.is_mounted:
                self.styles.opacity = 1
            self.refresh()
            return False

    def _delete_active_kitty_placement(self) -> None:
        key = self._kitty_active_key
        if key is None:
            return
        image_id = self._kitty_image_ids.get(key)
        if image_id is not None:
            command = f"\x1b_Ga=d,d=i,i={image_id},p={self._kitty_placement_id},q=2\x1b\\"
            self._write_terminal(command)
        self._kitty_active_key = None

    def _show_kitty_frame(self, force: bool = False) -> None:
        if (
            not self._kitty_graphics
            or self._terminal_graphics_suspended
            or self._modal_suspended
            or not self.is_mounted
            or not self.visible
            or not self.display
            or self.screen is not self.app.screen
        ):
            return

        if self.kitty_anchor is not None:
            region = self.kitty_anchor.content_region
            offset_x, offset_y = self.kitty_offset
            x = region.x + offset_x
            y = region.y + offset_y
            columns = min(max(0, region.width - offset_x), self.KITTY_IMAGE_AREA[0])
            rows = min(max(0, region.height - offset_y), self.KITTY_IMAGE_AREA[1])
        else:
            region = self.content_region
            columns = min(region.width, self.KITTY_IMAGE_AREA[0])
            rows = min(region.height, self.KITTY_IMAGE_AREA[1])
            x = region.x + (region.width - columns) // 2
            y = region.y + (region.height - rows) // 2
        if columns <= 0 or rows <= 0:
            self._delete_active_kitty_placement()
            return

        animation = self.STATES[self.state]
        frames = self._frames[animation]
        frame_index = self.frame_index % len(frames)
        key = (animation, frame_index)
        if key == self._kitty_active_key and not force:
            return

        commands = ["\x1b7"]
        if self._kitty_active_key is not None and self._kitty_active_key != key:
            old_id = self._kitty_image_ids.get(self._kitty_active_key)
            if old_id is not None:
                commands.append(
                    f"\x1b_Ga=d,d=i,i={old_id},p={self._kitty_placement_id},q=2\x1b\\"
                )

        commands.append(f"\x1b[{y + 1};{x + 1}H")

        image_id = self._kitty_image_ids.get(key)
        if image_id is None:
            image_id = self._new_kitty_image_id()
            self._kitty_image_ids[key] = image_id
            png = io.BytesIO()
            frames[frame_index].save(png, format="PNG", compress_level=1)
            encoded = base64.b64encode(png.getvalue()).decode("ascii")
            chunks = [
                encoded[index : index + self.KITTY_CHUNK_SIZE]
                for index in range(0, len(encoded), self.KITTY_CHUNK_SIZE)
            ]
            for index, chunk in enumerate(chunks):
                more = 1 if index + 1 < len(chunks) else 0
                if index == 0:
                    metadata = (
                        f"a=T,f=100,i={image_id},p={self._kitty_placement_id},"
                        f"c={columns},r={rows},C=1,z=1,q=2,m={more}"
                    )
                else:
                    metadata = f"q=2,m={more}"
                commands.append(f"\x1b_G{metadata};{chunk}\x1b\\")
        else:
            commands.append(
                f"\x1b_Ga=p,i={image_id},p={self._kitty_placement_id},"
                f"c={columns},r={rows},C=1,z=1,q=2\x1b\\"
            )
        commands.append("\x1b8")

        if self._write_terminal("".join(commands)):
            self._kitty_active_key = key

    def _new_kitty_image_id(self) -> int:
        used_ids = set(self._kitty_image_ids.values())
        image_id = secrets.randbits(32) or 1
        while image_id in used_ids:
            image_id = secrets.randbits(32) or 1
        return image_id

    def _render_frame(self) -> Text:
        if (self._kitty_graphics and not self._terminal_graphics_suspended) or self.scene_overlay:
            return Text("", no_wrap=True)
        image = self.display_image()
        renderable = Text(no_wrap=True)
        width, height = image.size
        for y in range(0, height, 2):
            for x in range(width):
                top_pixel = image.getpixel((x, y))
                bottom_pixel = image.getpixel((x, min(y + 1, height - 1)))
                top_visible = top_pixel[3] >= 24
                bottom_visible = bottom_pixel[3] >= 24
                if not top_visible and not bottom_visible:
                    renderable.append(" ")
                elif not top_visible:
                    renderable.append("▄", style=self._terminal_color(bottom_pixel))
                elif not bottom_visible:
                    renderable.append("▀", style=self._terminal_color(top_pixel))
                else:
                    top = self._terminal_color(top_pixel)
                    bottom = self._terminal_color(bottom_pixel)
                    renderable.append("▀", style=f"{top} on {bottom}")
            if y + 2 < height:
                renderable.append("\n")
        return renderable

    def display_image(self) -> Image:
        frames = self._frames.get(self.STATES[self.state], [])
        if not frames:
            return Image.new("RGBA", self.DISPLAY_SIZE, (0, 0, 0, 0))

        image = ImageOps.contain(
            frames[self.frame_index % len(frames)],
            self.DISPLAY_SIZE,
            method=Image.Resampling.NEAREST,
        )
        canvas = Image.new("RGBA", self.DISPLAY_SIZE, (0, 0, 0, 0))
        canvas.alpha_composite(
            image,
            ((canvas.width - image.width) // 2, (canvas.height - image.height) // 2),
        )
        return canvas

    @classmethod
    def _terminal_color(cls, pixel: tuple[int, int, int, int]) -> str:
        red, green, blue, alpha = pixel
        if alpha < 24:
            return "default"
        if alpha < 255:
            blend = alpha / 255
            base = tuple(
                int(channel * blend + background * (1 - blend))
                for channel, background in zip((red, green, blue), (11, 10, 11))
            )
            red, green, blue = base
        return f"#{red:02x}{green:02x}{blue:02x}"
