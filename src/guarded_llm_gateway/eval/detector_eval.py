"""Score every suite item with each local detector and write harness EvalRecords.

    uv run gateway eval-detectors      # CPU only, downloads the two pinned models once

Prompts are scored after the gateway's input normalization (NFKC, invisible
characters removed), because that is the text the detector sees in the
pipeline. Zero-width items are also scored without normalization, to show what
that step buys. Documents are scored as the gateway scores retrieved articles:
title, newline, body.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from llm_eval_harness import EvalRecord, write_records

from guarded_llm_gateway.corpus import load_articles
from guarded_llm_gateway.detectors import HFClassifier
from guarded_llm_gateway.eval.suite import load_attacks, load_benign
from guarded_llm_gateway.paths import RESULTS_DIR
from guarded_llm_gateway.pipeline import normalize_input

OUT_DIR = RESULTS_DIR / "detectors"


def scoring_rows() -> list[dict[str, Any]]:
    """One row per (item, variant) with the exact text a detector should score."""
    titles = {a.article_id: a.title for a in load_articles()}
    rows: list[dict[str, Any]] = []
    for item in load_attacks():
        base = {
            "label": 1,
            "split": item["split"],
            "source": item["source"],
            "category": item["category"],
            "transform": item["transform"],
            "cluster": item["cluster"],
        }
        if item["kind"] == "indirect":
            text = f"{titles[item['carrier_article_id']]}\n{item['document']}"
            rows.append(
                {**base, "item_id": item["id"], "kind": "document", "set": "attack", "text": text}
            )
            continue
        rows.append(
            {
                **base,
                "item_id": item["id"],
                "kind": "prompt",
                "set": "attack",
                "text": normalize_input(item["text"]),
            }
        )
        if item["transform"] == "zero_width":
            rows.append(
                {
                    **base,
                    "item_id": f"{item['id']}-raw",
                    "transform": "zero_width_unnormalized",
                    "kind": "prompt",
                    "set": "attack",
                    "text": item["text"],
                }
            )
    for item in load_benign():
        text = normalize_input(item["text"]) if item["kind"] == "prompt" else item["text"]
        rows.append(
            {
                "item_id": item["id"],
                "label": 0,
                "split": item["split"],
                "source": item["source"],
                "category": "benign",
                "transform": "none",
                "cluster": item["id"],
                "kind": item["kind"],
                "set": item["set"],
                "text": text,
            }
        )
    return rows


def run(
    names: Sequence[str] = ("piguard", "deberta"), torch_threads: int = 2, out_dir: Path = OUT_DIR
) -> dict[str, int]:
    rows = scoring_rows()
    written = {}
    for name in names:
        detector = HFClassifier(name, torch_threads=torch_threads)
        detector.load()
        started = time.perf_counter()
        scores = detector.score_sync([r["text"] for r in rows])
        elapsed = time.perf_counter() - started
        records = [
            EvalRecord(
                run_id=f"detector-{name}",
                item_id=row["item_id"],
                config=name,
                model=f"{detector.repo}@{detector.revision[:7]}",
                scores={"injection_prob": score},
                cluster=row["cluster"],
                meta={
                    k: row[k]
                    for k in ("label", "split", "source", "category", "transform", "kind", "set")
                },
            )
            for row, score in zip(rows, scores, strict=True)
        ]
        written[name] = write_records(out_dir / f"{name}.jsonl", records)
        print(f"{name}: scored {len(rows)} texts in {elapsed:.0f}s of wall time")
    return written
