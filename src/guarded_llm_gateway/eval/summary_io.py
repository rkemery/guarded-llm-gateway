"""Write summary JSON files that don't change across platforms.

Floating-point results from numpy and scipy can differ in the last digit between
machines (Apple arm64 against Linux x86, for example), which made `make demo` leave
committed summaries dirty. Rounding to 12 significant digits keeps every number the
README shows and makes the files byte-stable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SIGNIFICANT_DIGITS = 12


def _round(value: Any) -> Any:
    if isinstance(value, float):
        return float(f"{value:.{SIGNIFICANT_DIGITS}g}")
    if isinstance(value, dict):
        return {k: _round(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_round(v) for v in value]
    return value


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.write_text(json.dumps(_round(summary), indent=2) + "\n", encoding="utf-8")
