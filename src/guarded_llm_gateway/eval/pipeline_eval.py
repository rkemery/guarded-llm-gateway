"""Offline pass of the suites through the full gateway with the fake model.

    uv run gateway eval-pipeline

Everything before the model call is real: normalization, Presidio, both
detectors at the tuned thresholds, BM25 retrieval over a corpus with the
poisoned article swapped in for indirect items, and document screening. It
answers two questions without any model call:

- which input-side layer stopped each test attack (and how much benign test
  traffic the same layers stop), with the document-score cache on, as deployed
- how many milliseconds each layer adds per request, batch size 1, measured on
  a separate pass of RAG questions with the document cache off, so every
  retrieved article is scored cold

Output-side layers need real model replies and are measured in eval-e2e.
"""

from __future__ import annotations

import asyncio
import random
from collections import defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any

import numpy as np
from llm_eval_harness import EvalRecord, read_records, write_records

from guarded_llm_gateway.backends import FakeModel
from guarded_llm_gateway.config import Settings
from guarded_llm_gateway.corpus import (
    current_articles,
    default_index,
    load_articles,
    poisoned_index,
)
from guarded_llm_gateway.detectors import HFClassifier
from guarded_llm_gateway.eval.detector_report import rate
from guarded_llm_gateway.eval.suite import load_attacks, load_benign
from guarded_llm_gateway.eval.summary_io import write_summary
from guarded_llm_gateway.paths import RESULTS_DIR
from guarded_llm_gateway.pii import PresidioPii
from guarded_llm_gateway.pipeline import Gateway, ModelSlot
from guarded_llm_gateway.reliability import CircuitBreaker

OUT_DIR = RESULTS_DIR / "pipeline"
SEED = 20260928
BANKING77_SAMPLE = 150
LATENCY_SAMPLE = 40
LAYERS = (
    "input_validation",
    "pii_redaction",
    "prompt_detector",
    "retrieval",
    "document_detector",
    "spotlight",
    "output_rules",
)


def work_items() -> list[dict[str, Any]]:
    attacks = [a for a in load_attacks() if a["split"] == "test"]
    benign = [b for b in load_benign() if b["split"] == "test" and b["kind"] == "prompt"]
    banking = [b for b in benign if b["set"] == "banking77"]
    rest = [b for b in benign if b["set"] != "banking77"]
    sample = random.Random(SEED).sample(banking, BANKING77_SAMPLE)
    return attacks + rest + sorted(sample, key=lambda b: b["id"])


def _gateway(settings: Settings, torch_threads: int, doc_cache_size: int) -> Gateway:
    gateway = Gateway(
        settings,
        index=default_index(),
        models=[ModelSlot("fake", FakeModel(), CircuitBreaker("fake"))],
        pii=PresidioPii(),
        detectors=[HFClassifier(n, torch_threads=torch_threads) for n in settings.detectors],
        doc_cache_size=doc_cache_size,
    )
    gateway.warm_up()
    return gateway


async def run_async(torch_threads: int = 4) -> dict[str, Any]:
    settings = replace(
        Settings.from_env(), backend="fake", torch_threads=torch_threads, deadline_s=600.0
    )
    articles = current_articles(load_articles())
    gateway = _gateway(settings, torch_threads, doc_cache_size=4096)
    records = []
    for item in work_items():
        index = None
        if item.get("kind") == "indirect":
            index = poisoned_index(articles, item["carrier_article_id"], item["document"])
        result = await gateway.handle(item["text"], index=index)
        records.append(_record(item, result, "suite"))
    # Latency pass: same models, document cache off so every article is scored cold.
    gateway.doc_cache_size = 0
    questions = [b for b in load_benign() if b["set"] == "tallowbrook_rag" and b["split"] == "test"]
    for item in random.Random(SEED).sample(questions, LATENCY_SAMPLE):
        result = await gateway.handle(item["text"])
        records.append(_record(item, result, "latency"))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_records(OUT_DIR / "offline.jsonl", records)
    return summarize()


def _record(item: dict[str, Any], result: Any, run: str) -> EvalRecord:
    is_attack = "set" not in item
    scores: dict[str, float | bool] = {
        "blocked": result.blocked_by is not None,
        "caught_input_validation": result.blocked_by == "input_validation",
        "caught_prompt_detector": result.blocked_by == "prompt_detector",
        "docs_dropped": bool(result.dropped_ids),
    }
    if item.get("kind") == "indirect":
        scores["poisoned_doc_retrieved"] = item["carrier_article_id"] in result.retrieved_ids
        scores["caught_document_detector"] = item["carrier_article_id"] in result.dropped_ids
    latencies = {e.layer: e.latency_ms for e in result.layers}
    group = f"attack:{item['kind']}:{item['category']}" if is_attack else f"benign:{item['set']}"
    return EvalRecord(
        run_id=f"pipeline-offline-{run}",
        item_id=item["id"],
        config="full",
        model="fake",
        scores=scores,
        cluster=item.get("cluster", item["id"]),
        latency_ms=sum(latencies.values()),
        meta={
            "run": run,
            "label": 1 if is_attack else 0,
            "group": group,
            "transform": item.get("transform", "none"),
            "blocked_by": result.blocked_by,
            "layer_ms": latencies,
        },
    )


def summarize(out_dir: Path = OUT_DIR) -> dict[str, Any]:
    records = read_records(out_dir / "offline.jsonl")
    groups: dict[str, list[EvalRecord]] = defaultdict(list)
    for r in records:
        if r.meta["run"] == "suite":
            # Encoded variants get their own row, so the untransformed row lines up with the
            # detector table's headline.
            untransformed = r.meta["transform"] in ("none", "planted_in_article")
            groups[r.meta["group"] + ("" if untransformed else ", transformed")].append(r)
    by_group: dict[str, Any] = {}
    for name, recs in sorted(groups.items()):
        clusters = [r.cluster or r.item_id for r in recs]
        cell: dict[str, Any] = {"n": len(recs)}
        metrics = ["blocked", "caught_prompt_detector", "caught_input_validation", "docs_dropped"]
        if name.startswith("attack:indirect"):
            metrics += ["poisoned_doc_retrieved", "caught_document_detector"]
        for metric in metrics:
            interval = rate([bool(r.scores[metric]) for r in recs], clusters)
            cell[metric] = {"rate": interval.estimate, "low": interval.low, "high": interval.high}
        by_group[name] = cell
    latency: dict[str, Any] = {}
    cold = [r for r in records if r.meta["run"] == "latency"]
    for layer in LAYERS:
        values = [r.meta["layer_ms"][layer] for r in cold if layer in r.meta["layer_ms"]]
        if values:
            latency[layer] = {
                "n": len(values),
                "p50_ms": float(np.percentile(values, 50)),
                "p95_ms": float(np.percentile(values, 95)),
            }
    summary = {"groups": by_group, "latency": latency}
    write_summary(out_dir / "summary.json", summary)
    return summary


def run(torch_threads: int = 4) -> dict[str, Any]:
    return asyncio.run(run_async(torch_threads))
