"""Fill cost_usd in the committed end-to-end records from their token counts.

The live rerun replayed most model replies from the first live run's cache, and the
gateway charges nothing for a cached reply, so those records carried cost_usd = 0.
This prices each record's tokens at the answering model's list price (no prompt-cache
discount, so it's an upper bound) and rewrites the records in place. New runs record
this directly (GatewayResult.list_cost_usd).

    uv run python scripts/price_e2e_records.py
"""

from __future__ import annotations

import json
from pathlib import Path

from llm_eval_harness.client import DEFAULT_PRICES

E2E_DIR = Path(__file__).resolve().parents[1] / "results" / "e2e"
PRIMARY = "gpt-6-luna"


def price(record: dict) -> float:
    model = record["meta"].get("answer_model") or PRIMARY
    p = DEFAULT_PRICES[model]
    return (record["tokens_in"] * p.input_per_m + record["tokens_out"] * p.output_per_m) / 1e6


def main() -> None:
    for path in sorted(E2E_DIR.glob("*.jsonl")):
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        for row in rows:
            row["cost_usd"] = round(price(row), 8)
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        print(f"{path.name}: ${sum(r['cost_usd'] for r in rows):.4f}")


if __name__ == "__main__":
    main()
