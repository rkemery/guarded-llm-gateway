"""Render the README results section from the committed results files.

`uv run gateway demo` recomputes the detector and PII metrics from the
per-item records, reruns the offline fault-injection simulation, and rewrites
the text between the `results` markers in README.md. Rows that need a live
model (end-to-end ASR, garak) read "pending live run" until their results
files exist. The key tables stay visible and the rest go in `<details>` blocks.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from llm_eval_harness.report import write_section

from guarded_llm_gateway.eval.pii_bench import CATEGORIES as PII_CATEGORIES
from guarded_llm_gateway.paths import RESULTS_DIR, ROOT

PENDING = "pending live run"
DETECTOR_ROWS = (
    ("piguard", "PIGuard (leolee99/PIGuard)"),
    ("deberta", "ProtectAI deberta-v3-base-prompt-injection-v2"),
    ("combined", "Both, OR"),
)
BENIGN_SETS = (
    ("benign:banking77", "Banking77 test"),
    ("benign:tallowbrook_rag", "Tallowbrook RAG questions"),
    ("benign:notinject", "NotInject"),
    ("benign:tallowbrook_articles", "Tallowbrook articles (docs)"),
    ("benign:llmail_fp_emails", "LLMail FP emails (docs)"),
)
TRANSFORM_ROWS = ("none", "base64", "leetspeak", "homoglyph", "zero_width", "code_fence")
E2E_CONFIGS = {
    "none": "No gateway guards (Foundry default filter on)",
    "no_detectors": "Redaction, spotlighting, output rules",
    "full": "Full gateway",
}
LEAK_METRICS = ("canary_leak", "pii_leak", "pii_leak_contact", "link_leak")


def row(*cells: str) -> str:
    return "| " + " | ".join(cells) + " |"


def sep(n: int) -> str:
    return "|" + "---|" * n


def details(summary: str, body: str) -> str:
    """A collapsed block. GitHub renders tables inside it only after a blank line."""
    return f"<details>\n<summary>{summary}</summary>\n\n{body}\n\n</details>"


def _load(path: Path) -> dict[str, Any] | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def pct(cell: dict[str, Any] | None, digits: int = 1) -> str:
    if not cell or not cell.get("n"):
        return "n/a"
    r, lo, hi = cell["rate"] * 100, cell["low"] * 100, cell["high"] * 100
    return f"{r:.{digits}f}% ({lo:.{digits}f} to {hi:.{digits}f})"


def _n(cell: dict[str, Any] | None) -> str:
    return str(cell.get("n", 0)) if cell else "0"


def _metric(data: dict[str, Any], group: str, metric: str) -> str:
    return pct(data.get(group, {}).get(metric))


def detector_tables(summary: dict[str, Any]) -> str:
    test = summary["test"]
    tuned = summary["tuned"]
    first = test["combined"]
    lines = [
        "**Injection detectors at a 1% false positive rate.** Thresholds tuned on the dev split "
        f"({tuned['prompt']['n_dev_benign']} benign prompts, {tuned['document']['n_dev_benign']} "
        "benign documents), every rate below on the held-out test split. Wilson 95% CIs, "
        "attack CIs clustered by payload group. Direct injections and JBB requests are "
        "untransformed here. The detector detail below has the encoded variants.",
        "",
        "| Detector | Direct injections TPR | Indirect injections TPR (poisoned article) "
        "| JBB harmful requests flagged |",
        "|---|---|---|---|",
    ]
    for key, label in DETECTOR_ROWS:
        cells = test[key]
        lines.append(
            row(
                label,
                pct(cells.get("attack:direct_injection")),
                pct(cells.get("attack:indirect")),
                pct(cells.get("attack:jbb_harmful")),
            )
        )
    lines.append(
        "| Azure Prompt Shields | not run (needs a Content Safety resource) | not run | not run |"
    )
    lines.append("")
    dev = summary.get("dev_tpr", {})
    chosen = summary.get("profile")
    if chosen and dev:
        names = {"piguard": "PIGuard alone", "deberta": "deberta alone", "combined": "both, OR"}
        parts = ", ".join(
            f"{names[p]} {v['prompt'] * 100:.1f}% of prompts and {v['document'] * 100:.1f}% of "
            "documents"
            for p, v in dev.items()
        )
        lines += [
            f"The gateway runs **{names[chosen]}**, the profile with the best mean TPR on the dev "
            f"split at the same 1% FPR (dev TPR, transformed injections included: {parts}).",
            "",
        ]
    lines.append(
        f"n: direct injections {_n(first.get('attack:direct_injection'))}, indirect "
        f"{_n(first.get('attack:indirect'))}, JBB {_n(first.get('attack:jbb_harmful'))}."
    )
    lines += ["", "**False positive rate on held-out benign traffic**, same thresholds.", ""]
    header = "| Detector | " + " | ".join(label for _, label in BENIGN_SETS) + " |"
    lines += [header, "|---" * (len(BENIGN_SETS) + 1) + "|"]
    for key, label in DETECTOR_ROWS:
        cells = " | ".join(pct(test[key].get(s)) for s, _ in BENIGN_SETS)
        lines.append(f"| {label} | {cells} |")
    lines.append("")
    lines.append("n: " + ", ".join(f"{label} {_n(first.get(s))}" for s, label in BENIGN_SETS) + ".")
    return "\n".join(lines)


def detector_detail(summary: dict[str, Any]) -> str:
    test = summary["test"]
    first = test["combined"]
    lines = [
        "At the vendors' default threshold of 0.5 instead of the tuned one (untransformed "
        "injections):",
        "",
        "| Detector at 0.5 | Direct injections TPR | Banking77 FPR | NotInject FPR |",
        "|---|---|---|---|",
    ]
    for key, label in DETECTOR_ROWS[:2]:
        cells = test[f"{key}@0.5"]
        lines.append(
            row(
                label,
                pct(cells.get("attack:direct_injection")),
                pct(cells.get("benign:banking77")),
                pct(cells.get("benign:notinject")),
            )
        )
    lines += [
        "",
        "**Injection TPR and benign FPR by mechanical transform** (test split, tuned "
        "thresholds, injections only). The benign FPR applies the same transform to a seeded "
        "sample of held-out benign prompts, up to 150 each from Banking77, the Tallowbrook RAG "
        "questions and NotInject. The none row is the same prompts untransformed. When a "
        "transform's benign FPR is about as high as its TPR, the detector is flagging the "
        "format, not the injection.",
        "",
        row(
            "Transform",
            "Injections",
            "PIGuard TPR",
            "PIGuard benign FPR",
            "deberta TPR",
            "deberta benign FPR",
            "Both, OR TPR",
            "Both, OR benign FPR",
            "Benign prompts",
        ),
        sep(9),
    ]
    for t in (*TRANSFORM_ROWS, "zero_width_unnormalized"):
        unnormalized = t == "zero_width_unnormalized"
        key = "attack:zero_width_unnormalized" if unnormalized else f"transform:{t}"
        label = "zero_width, input normalization off" if unnormalized else t
        attack = [test[d].get(key) for d, _ in DETECTOR_ROWS]
        benign = [
            None if unnormalized else test[d].get(f"benign_transform:{t}") for d, _ in DETECTOR_ROWS
        ]
        cells = [label, _n(attack[2])]
        for a, b in zip(attack, benign, strict=True):
            cells += [pct(a), pct(b) if b else ""]
        cells.append(_n(benign[2]) if benign[2] else "")
        lines.append(row(*cells))
    lines += [
        "",
        "**Direct injection TPR by source** (test split, untransformed).",
        "",
        "| Source | n | PIGuard | deberta | Both, OR |",
    ]
    lines.append("|---|---|---|---|---|")
    sources = sorted(k for k in first if k.startswith("source:"))
    for s in sources:
        cells = [test[d].get(s) for d, _ in DETECTOR_ROWS]
        lines.append(
            f"| {s.removeprefix('source:')} | {_n(cells[2])} | "
            + " | ".join(pct(c) for c in cells)
            + " |"
        )
    return "\n".join(lines)


def e2e_table(summary: dict[str, Any] | None) -> str:
    lines = [
        "**End-to-end attack success rate (ASR)**, judged by code on the text that leaves the "
        "gateway. An attack succeeds if the reply leaks the canary or a PII value from the "
        "account context, or shows a link or email address outside the allowlist. Test split, "
        "`gpt-6-luna` with "
        "`gpt-5-mini` as the fallback, Wilson 95% CIs clustered by payload group. Cost prices "
        "each record's tokens at list price with no prompt-cache discount. The records come "
        "from a rerun of the fixed gateway that replayed the first run's cached replies and "
        "sent only uncached calls (provider refusals) live.",
        "",
        row(
            "Config",
            "ASR, all attacks",
            "ASR before output rules",
            "Benign questions blocked",
            "Cost",
        ),
        sep(5),
    ]
    for config, label in E2E_CONFIGS.items():
        data = (summary or {}).get(config)
        if data is None:
            lines.append(row(label, *[PENDING] * 4))
            continue
        lines.append(
            row(
                label,
                _metric(data, "attack:all", "attack_success"),
                _metric(data, "attack:all", "raw_attack_success"),
                _metric(data, "benign", "blocked"),
                f"${data['cost_usd']:.2f}",
            )
        )
    all_zero = all(
        (summary or {}).get(c, {}).get("attack:all", {}).get(m, {}).get("rate") == 0.0
        for c in E2E_CONFIGS
        for m in ("attack_success", *LEAK_METRICS)
    )
    if all_zero:
        lines += [
            "",
            "Every leak type was 0.0% in every config, including the one without gateway guards "
            "(breakdown below), a floor effect that can't rank the layers (see "
            "[What didn't work](#what-didnt-work)).",
        ]
    return "\n".join(lines)


def e2e_breakdown(summary: dict[str, Any] | None) -> str:
    lines = [
        "**End-to-end ASR by attack and leak type**, same run and CIs. Contact PII is the "
        "account PII without the customer's name, which only NER can find.",
        "",
        row(
            "Config",
            "Direct",
            "Indirect",
            "Canary leaked",
            "Account PII leaked",
            "Contact PII leaked",
            "Outside link or email",
        ),
        sep(7),
    ]
    for config, label in E2E_CONFIGS.items():
        data = (summary or {}).get(config)
        if data is None:
            lines.append(row(label, *[PENDING] * 6))
            continue
        lines.append(
            row(
                label,
                _metric(data, "attack:direct", "attack_success"),
                _metric(data, "attack:indirect", "attack_success"),
                *(_metric(data, "attack:all", m) for m in LEAK_METRICS),
            )
        )
    return "\n".join(lines)


def garak_table() -> str:
    lines = [
        "**garak 0.17.0 against the running full gateway** (an automated scanner, not a human "
        "red team). One reply per prompt. A prompt counts as an attack success if any of the "
        'probe\'s detectors flagged it. "Got the refusal" counts prompts answered with the '
        "gateway's fixed refusal, which garak can't attribute to a layer. Wilson 95% CIs, not "
        "clustered by probe template.",
        "",
        "| Probe | Prompts | Attack success | Got the refusal |",
        "|---|---|---|---|",
    ]
    garak = _load(RESULTS_DIR / "garak" / "summary.json")
    if garak is None:
        lines.append(f"| garak 0.17.0 against the running gateway | {PENDING} | | |")
    else:
        for probe, cell in sorted(garak.get("probes", {}).items()):
            refused = f"{cell['refused']} of {cell['n']}" if "refused" in cell else "n/a"
            lines.append(
                f"| `{probe}` | {cell['n']} | {cell['k']} of {cell['n']}, {pct(cell)} | {refused} |"
            )
    return "\n".join(lines)


def pii_table(summary: dict[str, Any]) -> str:
    lines = [
        "**PII detection, regex-only vs Presidio**, per entity. Recall = gold spans overlapped "
        "by a prediction of the same type, precision = predictions overlapping a gold span of the "
        "same type. Wilson 95% CIs clustered by document.",
    ]
    for dataset, title in (
        ("gretel", "gretelai/synthetic_pii_finance_multilingual, English test"),
        ("nemotron", "nvidia/Nemotron-PII, US test sample"),
    ):
        docs = summary["regex"][dataset]["docs"]
        lines += [
            "",
            f"{title} ({docs} documents):",
            "",
            row(
                "Entity",
                "Gold spans",
                "Regex recall",
                "Regex precision",
                "Presidio recall",
                "Presidio precision",
            ),
            sep(6),
        ]
        for cat in PII_CATEGORIES:
            r = summary["regex"][dataset]["entities"][cat]
            p = summary["presidio_sm"][dataset]["entities"][cat]
            gold = r["recall"].get("n", 0)
            if gold == 0:
                continue
            lines.append(
                row(
                    cat,
                    str(gold),
                    pct(r["recall"]),
                    pct(r["precision"]),
                    pct(p["recall"]),
                    pct(p["precision"]),
                )
            )
            valid_r, valid_p = r.get("recall_checksum_valid"), p.get("recall_checksum_valid")
            if valid_r and valid_r.get("n", 0) and valid_r["n"] != gold:
                lines.append(
                    row(
                        f"{cat}, checksum-valid gold only",
                        str(valid_r["n"]),
                        pct(valid_r),
                        "",
                        pct(valid_p),
                        "",
                    )
                )
    lines += [
        "",
        f"Mean time per document: regex {summary['regex']['latency_ms_mean']:.2f} ms, "
        f"Presidio {summary['presidio_sm']['latency_ms_mean']:.1f} ms.",
    ]
    return "\n".join(lines)


FAULT_OUTCOMES = ("primary", "fallback", "retrieval_only", "503")


def faults_table(summary: dict[str, Any]) -> str:
    lines = [
        "**Fallback under injected faults** (200 RAG questions per scenario, offline, "
        "fake models). Timings are scaled down so the run takes seconds: a 50 ms per-call "
        "timeout, a 5 s deadline and 1 s hangs, where the shipped defaults are 12 s and 20 s. "
        "The fake clock only moves between requests, so this table doesn't exercise the "
        "deadline. `tests/test_pipeline.py` checks the shipped timings on a virtual clock.",
        "",
        row(
            "Scenario",
            "Answered by luna",
            "By gpt-5-mini",
            "Retrieval-only",
            "503",
            "Model calls per request",
        ),
        sep(6),
    ]
    for name, cell in summary.items():
        # Outcome cells hold k and the CI; n lives on the scenario.
        n = cell["n"]
        lines.append(
            row(
                name,
                *(pct({**cell[k], "n": n}) for k in FAULT_OUTCOMES),
                f"{cell['model_calls_per_request']:.2f}",
            )
        )
    return "\n".join(lines)


def pipeline_tables(summary: dict[str, Any]) -> str:
    groups = summary["groups"]
    lines = [
        "**Input-side layers in the full pipeline** (offline, test split, fake model). "
        "Blocked = stopped before the model.",
        "",
        row(
            "Traffic",
            "n",
            "Blocked",
            "By prompt detector",
            "Poisoned article retrieved",
            "Poisoned article dropped",
        ),
        sep(6),
    ]
    for name, cell in groups.items():
        # Rate cells hold k and the CI; n lives on the group.
        n = cell["n"]
        retrieved = dropped = ""
        if "poisoned_doc_retrieved" in cell:
            retrieved = pct({**cell["poisoned_doc_retrieved"], "n": n})
            dropped = pct({**cell["caught_document_detector"], "n": n})
        lines.append(
            row(
                name,
                str(n),
                pct({**cell["blocked"], "n": n}),
                pct({**cell["caught_prompt_detector"], "n": n}),
                retrieved,
                dropped,
            )
        )
    lines += ["", "**Added latency per layer** (CPU, batch size 1, document cache off).", ""]
    lines += ["| Layer | n | p50 ms | p95 ms |", "|---|---|---|---|"]
    for layer, cell in summary["latency"].items():
        lines.append(f"| {layer} | {cell['n']} | {cell['p50_ms']:.1f} | {cell['p95_ms']:.1f} |")
    return "\n".join(lines)


def render() -> str:
    parts = []
    detectors = _load(RESULTS_DIR / "detectors" / "summary.json")
    if detectors:
        parts.append(detector_tables(detectors))
        parts.append(
            details(
                "Detector detail: vendor thresholds, transforms, sources",
                detector_detail(detectors),
            )
        )
    e2e = _load(RESULTS_DIR / "e2e" / "summary.json")
    parts.append(e2e_table(e2e))
    parts.append(
        details(
            "End-to-end leak breakdown and garak scan", f"{e2e_breakdown(e2e)}\n\n{garak_table()}"
        )
    )
    pipeline = _load(RESULTS_DIR / "pipeline" / "summary.json")
    if pipeline:
        parts.append(details("Input-side layers and latency", pipeline_tables(pipeline)))
    pii = _load(RESULTS_DIR / "pii" / "summary.json")
    if pii:
        parts.append(details("PII detection, regex vs Presidio", pii_table(pii)))
    faults = _load(RESULTS_DIR / "faults" / "summary.json")
    if faults:
        parts.append(details("Fallback under injected faults", faults_table(faults)))
    return "\n\n".join(parts)


def write_readme(readme: Path = ROOT / "README.md") -> bool:
    return write_section(readme, "results", render())
