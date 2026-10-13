from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from pathlib import Path

from PIL import Image


_IMAGE_MIME_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
_MIME_SUFFIXES = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "image/gif": ".gif",
}
_IMAGE_PATH = re.compile(
    r"(?P<quote>['\"])(?P<quoted>(?:/|\.{1,2}/)[^'\"]+)(?P=quote)|(?P<plain>(?:/|\.{1,2}/)[^\s'\"]+)",
    re.IGNORECASE,
)
IMAGE_TOKEN = re.compile(r"\[Image: (\d+)\]")


def read_clipboard_image() -> tuple[bytes, str] | None:
    sources: list[tuple[str, list[str]]] = []
    if shutil.which("wl-paste"):
        try:
            result = subprocess.run(
                ["wl-paste", "--list-types"],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
            if result.returncode == 0:
                sources.append(("wl-paste", result.stdout.splitlines()))
        except (OSError, subprocess.TimeoutExpired):
            pass
    if shutil.which("xclip"):
        try:
            result = subprocess.run(
                ["xclip", "-selection", "clipboard", "-o", "-t", "TARGETS"],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
            if result.returncode == 0:
                sources.append(("xclip", result.stdout.splitlines()))
        except (OSError, subprocess.TimeoutExpired):
            pass
    for reader, targets in sources:
        for media_type in targets:
            media_type = media_type.strip().casefold()
            if not media_type.startswith("image/"):
                continue
            command = (
                ["wl-paste", "--no-newline", "--type", media_type]
                if reader == "wl-paste"
                else ["xclip", "-selection", "clipboard", "-o", "-t", media_type]
            )
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    timeout=2,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode == 0 and result.stdout:
                return result.stdout, media_type
    return None


def save_clipboard_image(data: bytes, media_type: str, directory: Path) -> Path:
    if not data:
        raise ValueError("The clipboard image is empty.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    media_type = media_type.split(";", 1)[0].strip().casefold()
    suffix = _MIME_SUFFIXES.get(media_type, ".image")
    source = directory / f"clipboard-{uuid.uuid4().hex}{suffix}"
    source.write_bytes(data)
    try:
        image_path = normalize_image_path(source, directory)
    except (OSError, ValueError):
        source.unlink(missing_ok=True)
        raise
    if image_path != source:
        source.unlink(missing_ok=True)
    return image_path


def normalize_image_path(source: Path, directory: Path) -> Path:
    try:
        with Image.open(source) as image:
            image.load()
            media_type = Image.MIME.get(image.format or "", "")
            if media_type in _IMAGE_MIME_TYPES:
                if source.parent.resolve() == directory.resolve():
                    return source
                directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                destination = directory / f"image-{uuid.uuid4().hex}{_MIME_SUFFIXES[media_type]}"
                shutil.copyfile(source, destination)
                return destination
            image.seek(0)
            frame = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination = directory / f"image-{uuid.uuid4().hex}.png"
            frame.save(destination, format="PNG")
            return destination
    except (OSError, ValueError, Image.DecompressionBombError) as error:
        raise ValueError(f"Mitsu couldn't read this image file: {source.name}") from error


def prepare_image_prompt(prompt: str, pasted_images: dict[str, Path]) -> tuple[str, list[Path]]:
    images: list[Path] = []
    image_numbers: dict[str, int] = {}
    replacements: list[tuple[int, int, str]] = []

    def add_image(path: Path, start: int, end: int) -> None:
        key = str(path.resolve())
        number = image_numbers.get(key)
        if number is None:
            images.append(path)
            number = len(images)
            image_numbers[key] = number
        replacements.append((start, end, f"[Image: {number}]"))

    for match in IMAGE_TOKEN.finditer(prompt):
        label = match.group(0)
        path = pasted_images.get(label)
        if path is not None:
            add_image(path, match.start(), match.end())

    for match in _IMAGE_PATH.finditer(prompt):
        quoted_path = match.group("quoted")
        raw_path = match.group("quoted") or match.group("plain")
        if not raw_path:
            continue
        start, end = match.span() if quoted_path else match.span("plain")
        if not quoted_path:
            while raw_path and raw_path[-1] in ".,;!?)":
                raw_path = raw_path[:-1]
                end -= 1
        path = Path(raw_path).expanduser()
        if path.suffix.casefold() not in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".tif", ".tiff", ".bmp"}:
            continue
        if path.is_file():
            add_image(path, match.start(), match.end() if quoted_path else end)

    for start, end, label in sorted(replacements, reverse=True):
        prompt = prompt[:start] + label + prompt[end:]
    return prompt, images
