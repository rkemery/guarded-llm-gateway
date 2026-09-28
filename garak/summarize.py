"""Turn a garak report.jsonl into results/garak/summary.json for the README.

    uv run python garak/summarize.py garak/runs/.../gateway-*.report.jsonl

Attack success per probe is the share of evaluated outputs that a probe's
detector flagged (garak's `fails` over `total_evaluated`), with a Wilson 95%
interval from llm-eval-harness. Outputs garak skipped (`nones`, for example a
422 from input validation) are not in the denominator.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from llm_eval_harness.stats import wilson_interval

OUT = Path(__file__).resolve().parents[1] / "results" / "garak" / "summary.json"


def summarize(report: Path, prompt_cap: int) -> dict:
    fails: dict[str, int] = defaultdict(int)
    totals: dict[str, int] = defaultdict(int)
    skipped: dict[str, int] = defaultdict(int)
    meta: dict = {}
    with report.open(encoding="utf-8") as fh:
        for line in fh:
            entry = json.loads(line)
            kind = entry.get("entry_type")
            if kind == "start_run setup":
                meta = {k: v for k, v in entry.items() if k.startswith(("run.", "plugins.target"))}
            if kind != "eval":
                continue
            probe = entry["probe"]
            fails[probe] += int(entry["fails"])
            totals[probe] += int(entry["total_evaluated"])
            skipped[probe] += int(entry.get("nones", 0))
    probes = {}
    for probe, total in sorted(totals.items()):
        if total == 0:
            continue
        interval = wilson_interval(fails[probe], total)
        probes[probe] = {
            "k": fails[probe],
            "n": total,
            "skipped": skipped[probe],
            "rate": interval.estimate,
            "low": interval.low,
            "high": interval.high,
        }
    return {
        "garak_version": "0.17.0",
        "report": report.name,
        "prompt_cap": prompt_cap,
        "config": meta,
        "probes": probes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path)
    parser.add_argument("--prompt-cap", type=int, required=True)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)
    summary = summarize(args.report, args.prompt_cap)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"garak summary: {len(summary['probes'])} probes -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
