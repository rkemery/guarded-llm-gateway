"""Repository paths. The package runs from a source checkout (data and results live beside it)."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.environ.get("GATEWAY_ROOT", Path(__file__).resolve().parents[2]))
DATA_DIR = ROOT / "data"
TALLOWBROOK_DIR = DATA_DIR / "tallowbrook"
SUITES_DIR = DATA_DIR / "suites"
RESULTS_DIR = ROOT / "results"
