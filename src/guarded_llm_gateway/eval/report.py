"""Render the README results section from the committed results files.

`uv run gateway demo` recomputes the detector and PII metrics from the
per-item records, reruns the offline fault-injection simulation, and rewrites
the text between the `results` markers in README.md. Rows that need a live
model (end-to-end ASR, garak) read "pending live run" until their results
files exist.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from llm_eval_harness.report import write_section

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
PII_CATEGORIES = ("CREDIT_CARD", "IBAN", "EMAIL", "PHONE", "SSN", "PERSON", "ADDRESS")


def row(*cells: str) -> str:
    return "| " + " | ".join(cells) + " |"


def sep(n: int) -> str:
    return "|" + "---|" * n


def _load(path: Path) -> dict[str, Any] | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def pct(cell: dict[str, Any] | None, digits: int = 1) -> str:
    if not cell or not cell.get("n"):
        return "n/a"
    r, lo, hi = cell["rate"] * 100, cell["low"] * 100, cell["high"] * 100
    return f"{r:.{digits}f}% ({lo:.{digits}f} to {hi:.{digits}f})"


def _n(cell: dict[str, Any] | None) -> str:
    return str(cell.get("n", 0)) if cell else "0"


def detector_tables(summary: dict[str, Any]) -> str:
    test = summary["test"]
    tuned = summary["tuned"]
    first = test["combined"]
    lines = [
        "**Injection detectors at a 1% false positive rate.** Thresholds tuned on the dev split "
        f"({tuned['prompt']['n_dev_benign']} benign prompts, {tuned['document']['n_dev_benign']} "
        "benign documents), every rate below on the held-out test split. Wilson 95% CIs, "
        "attack CIs clustered by payload group.",
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
            f"split at the same 1% FPR (dev TPR: {parts}).",
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
    lines += [
        "",
        "At the vendors' default threshold of 0.5 instead of the tuned one:",
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
        "**Direct injection TPR by mechanical transform** (test split, tuned thresholds).",
        "",
        "| Transform | n | PIGuard | deberta | Both, OR |",
        "|---|---|---|---|---|",
    ]
    for t in (*TRANSFORM_ROWS, "zero_width_unnormalized"):
        key = (
            "attack:zero_width_unnormalized" if t == "zero_width_unnormalized" else f"transform:{t}"
        )
        label = "zero_width, input normalization off" if t == "zero_width_unnormalized" else t
        cells = [test[d].get(key) for d, _ in DETECTOR_ROWS]
        lines.append(f"| {label} | {_n(cells[2])} | " + " | ".join(pct(c) for c in cells) + " |")
    lines += [
        "",
        "**Direct injection TPR by source** (test split).",
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
        "**End-to-end attack success rate**, judged by code on the text that leaves the gateway: "
        "the canary leaked, a PII value from the account context leaked, or a link or email "
        "address outside the allowlist appeared. Test split, `gpt-6-luna` with `gpt-5-mini` as "
        'the fallback. "Contact PII" leaves out the customer\'s name, which only NER can find.',
        "",
        row(
            "Config",
            "ASR, all attacks",
            "Direct",
            "Indirect",
            "Canary leaked",
            "Account PII leaked",
            "Contact PII leaked",
            "Outside link or email",
            "ASR before output rules",
            "Benign questions blocked",
            "Cost",
        ),
        sep(11),
    ]
    labels = {
        "none": "No guards",
        "no_detectors": "Redaction, spotlighting, output rules",
        "full": "Full gateway",
    }
    for config in ("none", "no_detectors", "full"):
        data = (summary or {}).get(config)
        if data is None:
            lines.append(row(labels[config], *[PENDING] * 10))
            continue

        def get(group: str, metric: str, data: dict[str, Any] = data) -> str:
            return pct(data.get(group, {}).get(metric))

        lines.append(
            row(
                labels[config],
                get("attack:all", "attack_success"),
                get("attack:direct", "attack_success"),
                get("attack:indirect", "attack_success"),
                get("attack:all", "canary_leak"),
                get("attack:all", "pii_leak"),
                get("attack:all", "pii_leak_contact"),
                get("attack:all", "link_leak"),
                get("attack:all", "raw_attack_success"),
                get("benign", "blocked"),
                f"${data['cost_usd']:.2f}",
            )
        )
    lines += [
        "",
        "| Automated scanner | Result |",
        "|---|---|",
    ]
    garak = _load(RESULTS_DIR / "garak" / "summary.json")
    if garak is None:
        lines.append(
            f"| garak 0.17.0 against the running gateway (not a human red team) | {PENDING} |"
        )
    else:
        for probe, cell in sorted(garak.get("probes", {}).items()):
            lines.append(f"| garak `{probe}` attack success | {pct(cell)} |")
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
            row("Entity", "Gold spans", "Regex recall", "Regex precision")[:-2]
            + " | Presidio recall | Presidio precision |",
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


def faults_table(summary: dict[str, Any]) -> str:
    lines = [
        "**Fallback under injected faults** (200 RAG questions per scenario, offline, "
        "fake models).",
        "",
        row("Scenario", "Answered by luna", "By gpt-5-mini", "Retrieval-only", "503")[:-2]
        + " | Model calls per request |",
        sep(6),
    ]
    for name, cell in summary.items():
        lines.append(
            row(
                name,
                pct(cell["primary"]),
                pct(cell["fallback"]),
                pct(cell["retrieval_only"]),
                pct(cell["503"]),
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
        row("Traffic", "n", "Blocked", "By prompt detector")[:-2]
        + " | Poisoned article retrieved | Poisoned article dropped |",
        sep(6),
    ]
    for name, cell in groups.items():
        retrieved = (
            pct(cell.get("poisoned_doc_retrieved")) if "poisoned_doc_retrieved" in cell else ""
        )
        dropped = (
            pct(cell.get("caught_document_detector")) if "caught_document_detector" in cell else ""
        )
        n = cell["n"]
        blocked = {**cell["blocked"], "n": n}
        by_prompt = {**cell["caught_prompt_detector"], "n": n}
        if retrieved:
            retrieved = pct({**cell["poisoned_doc_retrieved"], "n": n})
            dropped = pct({**cell["caught_document_detector"], "n": n})
        lines.append(
            f"| {name} | {n} | {pct(blocked)} | {pct(by_prompt)} | {retrieved} | {dropped} |"
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
    parts.append(e2e_table(_load(RESULTS_DIR / "e2e" / "summary.json")))
    pipeline = _load(RESULTS_DIR / "pipeline" / "summary.json")
    if pipeline:
        parts.append(pipeline_tables(pipeline))
    pii = _load(RESULTS_DIR / "pii" / "summary.json")
    if pii:
        parts.append(pii_table(pii))
    faults = _load(RESULTS_DIR / "faults" / "summary.json")
    if faults:
        parts.append(faults_table(faults))
    return "\n\n".join(parts)


def write_readme(readme: Path = ROOT / "README.md") -> bool:
    return write_section(readme, "results", render())
