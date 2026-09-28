"""Companion metadata and packaged sprite locations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ASSET_ROOT = Path(__file__).resolve().parents[1] / "assets"
PET_ASSET_ROOT = ASSET_ROOT / "pets"


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
        PET_ASSET_ROOT / "mitsu.webp",
    ),
    Companion(
        "gugugaga",
        "GuGuGaGa",
        "A compact chibi penguin-hood companion with a paperclip charm. Art credit: @Hibiki.",
        PET_ASSET_ROOT / "gugugaga.webp",
    ),
    Companion(
        "miside",
        "Chibi Mita",
        "Chibi Mita from *MiSide*, in her red top and blue skirt. Art credit: @m3oidoop.",
        PET_ASSET_ROOT / "chibi-mita.webp",
    ),
    Companion(
        "doro",
        "Doro",
        "A pink-purple-haired chibi with bright eyes and a curled rose hair ornament. Art credit: @lezibo.",
        PET_ASSET_ROOT / "doro.webp",
    ),
    Companion(
        "elyndex",
        "Elyndex",
        "A sleek Culture-inspired floating drone. Art credit: @Crates.",
        PET_ASSET_ROOT / "elyndex.webp",
    ),
    Companion(
        "coding-cat",
        "Coding Cat",
        "A little pixel cat ready to supervise terminal work. Art credit: @jiantao y.",
        PET_ASSET_ROOT / "coding-cat.webp",
    ),
    Companion(
        "kal-tsit",
        "Kal'tsit",
        "Kal’tsit from *Arknights*, accompanied by Mon3tr. Art credit: @Horizon.",
        PET_ASSET_ROOT / "kaltsit.webp",
    ),
    Companion(
        "glitchcat",
        "Glitchcat",
        "A neon-eyed cyber cat with a playful pixel-glitch glow. Art credit: @wangm23456.",
        PET_ASSET_ROOT / "glitchcat.webp",
    ),
    Companion(
        "nene",
        "Nene",
        "A bright little Nene companion for your terminal. Art credit: @Shiroe.",
        PET_ASSET_ROOT / "nene.webp",
    ),
    Companion(
        "null-wisp",
        "Null Wisp",
        "A hovering cyber-skull with a glowing red eye and trailing cables. Art credit: @Aixplosion.",
        PET_ASSET_ROOT / "null-wisp.webp",
    ),
    Companion(
        "pikachu",
        "Pikachu",
        "A cheerful electric mouse with bright cheeks and a lightning-bolt tail. Art credit: @woodii.",
        PET_ASSET_ROOT / "pikachu.webp",
    ),
    Companion(
        "rin",
        "Rin",
        "Rin Shima from *Laid-Back Camp*, ready for a quiet camping trip. Art credit: @cjioylmx.",
        PET_ASSET_ROOT / "rin.webp",
        run_right_flip=True,
    ),
    Companion(
        "tethys",
        "Tethys",
        "A dark mechanical cat with teal eyes, segmented armor, and a long articulated tail. Art credit: @leo072060.",
        PET_ASSET_ROOT / "tethys.webp",
    ),
    Companion(
        "yingyu-aima",
        "Yingyu Aima",
        "Yingyu Aima, with a white-to-pink bob, sakura beret, and monochrome outfit. Art credit: @snowsirius.",
        PET_ASSET_ROOT / "yingyu-aima.webp",
    ),
    Companion(
        "yuna",
        "Xiao Q (小Q酱)",
        "A white-haired chibi with violet accents and lightning details. Art credit: @akari.",
        PET_ASSET_ROOT / "yuna.webp",
    ),
)

COMPANION_BY_ID = {companion.id: companion for companion in COMPANIONS}


def companion_by_id(companion_id: str) -> Companion:
    return COMPANION_BY_ID.get(companion_id, COMPANIONS[0])
