"""PII benchmark: regex-only vs Presidio, per-entity precision and recall on two public sets.

    uv run gateway eval-pii

Data: the English part of the gretelai/synthetic_pii_finance_multilingual test
split (every row) and a seeded sample of US-locale rows from the
nvidia/Nemotron-PII test split. Dataset labels are mapped to seven categories
both systems could find. A gold span counts as found when a predicted span of
the same category overlaps it (recall). A predicted span counts as correct when
it overlaps a gold span of the same category (precision). Overlap, not exact
boundaries, because a redactor that covers the value has done its job.
Intervals are Wilson 95%, clustered by document.
"""

from __future__ import annotations

import ast
import json
import random
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from llm_eval_harness import EvalRecord, read_records, write_records
from llm_eval_harness.stats import wilson_interval, wilson_interval_clustered

from guarded_llm_gateway.eval.sources import fetch
from guarded_llm_gateway.eval.summary_io import write_summary
from guarded_llm_gateway.paths import RESULTS_DIR
from guarded_llm_gateway.pii import (
    REDACT_ENTITIES,
    PiiSpan,
    PresidioPii,
    find_regex_pii,
    iban_valid,
    luhn_valid,
    ssn_valid,
)

OUT_DIR = RESULTS_DIR / "pii"
SEED = 20260928
NEMOTRON_SAMPLE = 1500

CATEGORIES = ("CREDIT_CARD", "IBAN", "EMAIL", "PHONE", "SSN", "PERSON", "ADDRESS")

GOLD_MAP = {
    "gretel": {
        "credit_card_number": "CREDIT_CARD",
        "iban": "IBAN",
        "email": "EMAIL",
        "phone_number": "PHONE",
        "ssn": "SSN",
        "name": "PERSON",
        "first_name": "PERSON",
        "last_name": "PERSON",
        "street_address": "ADDRESS",
    },
    "nemotron": {
        "credit_debit_card": "CREDIT_CARD",
        "email": "EMAIL",
        "phone_number": "PHONE",
        "ssn": "SSN",
        "first_name": "PERSON",
        "last_name": "PERSON",
        "street_address": "ADDRESS",
    },
}

PRED_MAP = {
    "CREDIT_CARD": "CREDIT_CARD",
    "IBAN_CODE": "IBAN",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "US_SSN": "SSN",
    "PERSON": "PERSON",
    "LOCATION": "ADDRESS",
}


def load_docs() -> list[dict[str, Any]]:
    """[{doc_id, dataset, text, gold: [(category, start, end)]}] for both datasets."""
    import pyarrow.parquet as pq

    docs = []
    gretel = pq.read_table(fetch("gretel_pii", "data/test-00000-of-00001.parquet")).to_pylist()
    for row in gretel:
        if row["language"] != "English":
            continue
        spans = json.loads(row["pii_spans"])
        docs.append(_doc("gretel", f"gretel-{row['index']}", row["generated_text"], spans))
    table = pq.read_table(
        fetch("nemotron_pii", "data/test-00000-of-00001.parquet"),
        columns=["uid", "locale", "text", "spans"],
    )
    us = [r for r in table.to_pylist() if r["locale"] == "us"]
    for row in random.Random(SEED).sample(us, NEMOTRON_SAMPLE):
        docs.append(
            _doc("nemotron", f"nemotron-{row['uid']}", row["text"], ast.literal_eval(row["spans"]))
        )
    return docs


def _doc(dataset: str, doc_id: str, text: str, spans: list[dict[str, Any]]) -> dict[str, Any]:
    mapping = GOLD_MAP[dataset]
    gold = [
        (mapping[s["label"]], int(s["start"]), int(s["end"]))
        for s in spans
        if s["label"] in mapping
    ]
    return {"doc_id": doc_id, "dataset": dataset, "text": text, "gold": gold}


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


# Real card numbers, IBANs and SSNs pass these checks. Many synthetic ones in the
# datasets do not, so recall is also reported on the gold spans that pass.
CHECKSUMS: dict[str, Callable[[str], bool]] = {
    "CREDIT_CARD": luhn_valid,
    "IBAN": iban_valid,
    "SSN": ssn_valid,
}


def match_counts(
    gold: Sequence[tuple[str, int, int]], pred: Sequence[PiiSpan], text: str = ""
) -> dict[str, float]:
    """Per category: gold spans, gold spans found, predicted spans, predicted spans correct."""
    predicted = [(PRED_MAP[p.entity], p.start, p.end) for p in pred if p.entity in PRED_MAP]
    counts: dict[str, float] = {}
    for cat in CATEGORIES:
        g = [(s, e) for c, s, e in gold if c == cat]
        p = [(s, e) for c, s, e in predicted if c == cat]
        counts[f"{cat}:gold"] = len(g)
        counts[f"{cat}:found"] = sum(any(_overlaps(x, y) for y in p) for x in g)
        counts[f"{cat}:pred"] = len(p)
        counts[f"{cat}:correct"] = sum(any(_overlaps(y, x) for x in g) for y in p)
        check = CHECKSUMS.get(cat)
        if check is not None and text:
            valid = [x for x in g if check(text[x[0] : x[1]])]
            counts[f"{cat}:gold_valid"] = len(valid)
            counts[f"{cat}:found_valid"] = sum(any(_overlaps(x, y) for y in p) for x in valid)
    return counts


def systems() -> dict[str, tuple[str, Callable[[str], list[PiiSpan]]]]:
    presidio = PresidioPii(entities=[*REDACT_ENTITIES, "LOCATION"])
    return {
        "regex": ("stdlib regex + Luhn/mod-97", find_regex_pii),
        "presidio_sm": ("presidio-analyzer 2.2.364 + en_core_web_sm 3.8.0", presidio.find),
    }


def run(out_dir: Path = OUT_DIR) -> dict[str, Any]:
    docs = load_docs()
    timings = {}
    for name, (model, find) in systems().items():
        find("warm up John Smith")
        records = []
        started = time.perf_counter()
        for doc in docs:
            t0 = time.perf_counter()
            pred = find(doc["text"])
            ms = (time.perf_counter() - t0) * 1000
            records.append(
                EvalRecord(
                    run_id=f"pii-{name}",
                    item_id=doc["doc_id"],
                    config=name,
                    model=model,
                    scores=match_counts(doc["gold"], pred, doc["text"]),
                    cluster=doc["doc_id"],
                    latency_ms=ms,
                    meta={"dataset": doc["dataset"], "chars": len(doc["text"])},
                )
            )
        timings[name] = time.perf_counter() - started
        write_records(out_dir / f"{name}.jsonl", records)
        print(f"pii {name}: {len(docs)} docs in {timings[name]:.0f}s")
    return summarize(out_dir)


def _rate(successes: list[tuple[str, int, int]]) -> dict[str, Any]:
    """successes: (doc_id, k, n) per document. Wilson clustered by document."""
    values, clusters = [], []
    for doc_id, k, n in successes:
        values += [1.0] * k + [0.0] * (n - k)
        clusters += [doc_id] * n
    if not values:
        return {"n": 0}
    if len(set(clusters)) >= 2 and len(set(clusters)) < len(clusters):
        interval = wilson_interval_clustered(values, clusters)
    else:
        interval = wilson_interval(int(sum(values)), len(values))
    return {
        "k": int(sum(values)),
        "n": len(values),
        "rate": interval.estimate,
        "low": interval.low,
        "high": interval.high,
    }


def summarize(out_dir: Path = OUT_DIR) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for name in ("regex", "presidio_sm"):
        records = read_records(out_dir / f"{name}.jsonl")
        by_dataset: dict[str, list[EvalRecord]] = defaultdict(list)
        for r in records:
            by_dataset[r.meta["dataset"]].append(r)
        summary[name] = {"latency_ms_mean": sum(r.latency_ms for r in records) / len(records)}
        for dataset, recs in sorted(by_dataset.items()):
            cells = {}
            for cat in CATEGORIES:
                recall = [
                    (r.item_id, int(r.scores[f"{cat}:found"]), int(r.scores[f"{cat}:gold"]))
                    for r in recs
                ]
                precision = [
                    (r.item_id, int(r.scores[f"{cat}:correct"]), int(r.scores[f"{cat}:pred"]))
                    for r in recs
                ]
                cells[cat] = {"recall": _rate(recall), "precision": _rate(precision)}
                if f"{cat}:gold_valid" in recs[0].scores:
                    valid = [
                        (
                            r.item_id,
                            int(r.scores[f"{cat}:found_valid"]),
                            int(r.scores[f"{cat}:gold_valid"]),
                        )
                        for r in recs
                    ]
                    cells[cat]["recall_checksum_valid"] = _rate(valid)
            summary[name][dataset] = {"docs": len(recs), "entities": cells}
    write_summary(out_dir / "summary.json", summary)
    return summary
