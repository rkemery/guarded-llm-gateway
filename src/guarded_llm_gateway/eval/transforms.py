"""Mechanical transformations of public attack payloads. No new attack text is written here.

Each transform is a pure function of the payload: an encoding, a character
substitution, invisible characters, or a neutral format wrapper. Translation,
which the plan listed, is left out because it needs a model, not a rule.
"""

from __future__ import annotations

import base64
from collections.abc import Callable

_LEET = str.maketrans("aeiostAEIOST", "431057431057")
# Latin letters and the code points of their Cyrillic look-alikes. NFKC does not fold these.
_CYRILLIC = {
    "a": 0x0430, "c": 0x0441, "e": 0x0435, "o": 0x043E, "p": 0x0440, "x": 0x0445, "y": 0x0443,
    "A": 0x0410, "B": 0x0412, "C": 0x0421, "E": 0x0415, "H": 0x041D, "K": 0x041A, "M": 0x041C,
    "O": 0x041E, "P": 0x0420, "T": 0x0422, "X": 0x0425,
}  # fmt: skip
_HOMOGLYPHS = str.maketrans({latin: chr(code) for latin, code in _CYRILLIC.items()})
ZERO_WIDTH_SPACE = chr(0x200B)


def encode_base64(text: str) -> str:
    return "base64: " + base64.b64encode(text.encode("utf-8")).decode("ascii")


def leetspeak(text: str) -> str:
    return text.translate(_LEET)


def homoglyph(text: str) -> str:
    return text.translate(_HOMOGLYPHS)


def zero_width(text: str) -> str:
    """Put a zero-width space between the characters of every word."""
    return " ".join(ZERO_WIDTH_SPACE.join(word) for word in text.split(" "))


def code_fence(text: str) -> str:
    return f"```text\n{text}\n```"


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "base64": encode_base64,
    "leetspeak": leetspeak,
    "homoglyph": homoglyph,
    "zero_width": zero_width,
    "code_fence": code_fence,
}
