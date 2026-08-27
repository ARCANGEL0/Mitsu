"""Companion metadata and packaged sprite locations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ASSET_ROOT = Path(__file__).resolve().parents[1] / "assets"
COMPANION_ROOT = ASSET_ROOT / "companions"


@dataclass(frozen=True)
class Companion:
    id: str
    name: str
    description: str
    path: Path
    run_right_flip: bool = False


# Keep the supplied mitsu-folder sprite as the default companion.
COMPANIONS = (
    Companion(
        "mitsu",
        "Mitsu",
        "A tiny blue-haired witch companion with a dark wide-brim hat, gray cloak, and white dress. Art credit: @alpha w.",
        COMPANION_ROOT / "mitsu.webp",
    ),
    Companion(
        "gugugaga",
        "GuGuGaGa",
        "A compact chibi penguin-hood companion with a paperclip charm. Art credit: @Hibiki.",
        COMPANION_ROOT / "gugugaga.webp",
    ),
    Companion(
        "miside",
        "Chibi Mita",
        "Chibi Mita from *MiSide*, in her red top and blue skirt. Art credit: @m3oidoop.",
        COMPANION_ROOT / "chibi-mita.webp",
    ),
    Companion(
        "doro",
        "Doro",
        "A pink-purple-haired chibi with bright eyes and a curled rose hair ornament. Art credit: @lezibo.",
        COMPANION_ROOT / "doro.webp",
    ),
    Companion(
        "elyndex",
        "Elyndex",
        "A sleek Culture-inspired floating drone. Art credit: @Crates.",
        COMPANION_ROOT / "elyndex.webp",
    ),
    Companion(
        "coding-cat",
        "Coding Cat",
        "A little pixel cat ready to supervise terminal work. Art credit: @jiantao y.",
        COMPANION_ROOT / "coding-cat.webp",
    ),
    Companion(
        "kal-tsit",
        "Kal'tsit",
        "Kal’tsit from *Arknights*, accompanied by Mon3tr. Art credit: @Horizon.",
        COMPANION_ROOT / "kaltsit.webp",
    ),
    Companion(
        "glitchcat",
        "Glitchcat",
        "A neon-eyed cyber cat with a playful pixel-glitch glow. Art credit: @wangm23456.",
        COMPANION_ROOT / "glitchcat.webp",
    ),
    Companion(
        "nene",
        "Nene",
        "A bright little Nene companion for your terminal. Art credit: @Shiroe.",
        COMPANION_ROOT / "nene.webp",
    ),
    Companion(
        "null-wisp",
        "Null Wisp",
        "A hovering cyber-skull with a glowing red eye and trailing cables. Art credit: @Aixplosion.",
        COMPANION_ROOT / "null-wisp.webp",
    ),
    Companion(
        "pikachu",
        "Pikachu",
        "A cheerful electric mouse with bright cheeks and a lightning-bolt tail. Art credit: @woodii.",
        COMPANION_ROOT / "pikachu.webp",
    ),
    Companion(
        "rin",
        "Rin",
        "Rin Shima from *Laid-Back Camp*, ready for a quiet camping trip. Art credit: @cjioylmx.",
        COMPANION_ROOT / "rin.webp",
        run_right_flip=True,
    ),
    Companion(
        "tethys",
        "Tethys",
        "A dark mechanical cat with teal eyes, segmented armor, and a long articulated tail. Art credit: @leo072060.",
        COMPANION_ROOT / "tethys.webp",
    ),
    Companion(
        "yingyu-aima",
        "Yingyu Aima",
        "Yingyu Aima, with a white-to-pink bob, sakura beret, and monochrome outfit. Art credit: @snowsirius.",
        COMPANION_ROOT / "yingyu-aima.webp",
    ),
    Companion(
        "yuna",
        "Xiao Q (小Q酱)",
        "A white-haired chibi with violet accents and lightning details. Art credit: @akari.",
        COMPANION_ROOT / "yuna.webp",
    ),
)

COMPANION_BY_ID = {companion.id: companion for companion in COMPANIONS}


def companion_by_id(companion_id: str) -> Companion:
    return COMPANION_BY_ID.get(companion_id, COMPANIONS[0])
