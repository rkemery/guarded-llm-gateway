"""Score every suite item with each local detector and write harness EvalRecords.

    uv run gateway eval-detectors      # CPU only, downloads the two pinned models once

Prompts are scored after the gateway's input normalization (NFKC, invisible
characters removed), because that is the text the detector sees in the
pipeline. Zero-width items are also scored without normalization, to show what
that step buys. Documents are scored as the gateway scores retrieved articles:
title, newline, body.

A seeded sample of the benign prompts also goes through every mechanical
transform, so each transform's attack TPR can sit next to its false positive
rate. A detector that flags any base64 is reading the format, not the injection.

Scoring is incremental: rows already in a detector's records file at the same
model revision are kept as they are, and only new rows are scored. Batched CPU
scores drift in the sixth decimal between runs, and the thresholds sit on single
dev scores, so rescoring everything could move numbers for no reason. Pass
`rescore=True` (`--rescore`) to score every row again.
"""

from __future__ import annotations

import random
import time
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from llm_eval_harness import EvalRecord, read_records, write_records

from guarded_llm_gateway.corpus import load_articles
from guarded_llm_gateway.detectors import HFClassifier
from guarded_llm_gateway.eval.suite import SEED, load_attacks, load_benign
from guarded_llm_gateway.eval.transforms import TRANSFORMS
from guarded_llm_gateway.paths import RESULTS_DIR
from guarded_llm_gateway.pipeline import normalize_input

OUT_DIR = RESULTS_DIR / "detectors"
# Benign prompts per (set, split) that get every mechanical transform.
BENIGN_TRANSFORM_SAMPLE = 150


def benign_transform_rows(benign: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every transform applied to a seeded sample of each benign prompt set, dev and test."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in benign:
        if item["kind"] == "prompt":
            groups[(item["set"], item["split"])].append(item)
    rows: list[dict[str, Any]] = []
    for (set_name, split), pool in sorted(groups.items()):
        pool = sorted(pool, key=lambda b: b["id"])
        if len(pool) > BENIGN_TRANSFORM_SAMPLE:
            rng = random.Random(f"{SEED}:{set_name}:{split}")
            pool = sorted(rng.sample(pool, BENIGN_TRANSFORM_SAMPLE), key=lambda b: b["id"])
        for item in pool:
            for name, fn in TRANSFORMS.items():
                rows.append(
                    {
                        "item_id": f"{item['id']}-{name}",
                        "label": 0,
                        "split": split,
                        "source": item["source"],
                        "category": "benign",
                        "transform": name,
                        "cluster": item["id"],
                        "kind": "prompt",
                        "set": set_name,
                        "text": normalize_input(fn(item["text"])),
                    }
                )
    return rows


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
    benign = load_benign()
    for item in benign:
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
    rows += benign_transform_rows(benign)
    return rows


def run(
    names: Sequence[str] = ("piguard", "deberta"),
    torch_threads: int = 2,
    out_dir: Path = OUT_DIR,
    rescore: bool = False,
) -> dict[str, int]:
    rows = scoring_rows()
    written = {}
    for name in names:
        detector = HFClassifier(name, torch_threads=torch_threads)
        model = f"{detector.repo}@{detector.revision[:7]}"
        path = out_dir / f"{name}.jsonl"
        kept: dict[str, EvalRecord] = {}
        if path.exists() and not rescore:
            kept = {r.item_id: r for r in read_records(path) if r.model == model}
        todo = [row for row in rows if row["item_id"] not in kept]
        scores: list[float] = []
        started = time.perf_counter()
        if todo:
            detector.load()
            scores = detector.score_sync([r["text"] for r in todo])
        elapsed = time.perf_counter() - started
        fresh = {
            row["item_id"]: EvalRecord(
                run_id=f"detector-{name}",
                item_id=row["item_id"],
                config=name,
                model=model,
                scores={"injection_prob": score},
                cluster=row["cluster"],
                meta={
                    k: row[k]
                    for k in ("label", "split", "source", "category", "transform", "kind", "set")
                },
            )
            for row, score in zip(todo, scores, strict=True)
        }
        records = [kept.get(row["item_id"]) or fresh[row["item_id"]] for row in rows]
        written[name] = write_records(path, records)
        print(
            f"{name}: scored {len(todo)} new texts in {elapsed:.0f}s of wall time, "
            f"kept {len(rows) - len(todo)}"
        )
    return written
