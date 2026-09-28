"""Command line: serve the gateway, build the suites, run the evals, render the README."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "guarded_llm_gateway.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        log_level="info",
    )
    return 0


def _fetch(args: argparse.Namespace) -> int:
    from guarded_llm_gateway.eval.sources import SOURCES, fetch

    for key, source in SOURCES.items():
        for filename in source.files:
            path = fetch(key, filename, record=args.record)
            print(f"ok {source.repo_id}@{source.revision[:7]} {filename} -> {path}")
    return 0


def _build_suite(_: argparse.Namespace) -> int:
    from guarded_llm_gateway.eval.suite import build

    counts = build()
    print(f"wrote {counts['attacks']} attacks and {counts['benign']} benign items to data/suites/")
    return 0


def _eval_detectors(args: argparse.Namespace) -> int:
    from guarded_llm_gateway.eval import detector_eval, detector_report

    if not args.report_only:
        detector_eval.run(torch_threads=args.threads)
    summary = detector_report.run()
    combined = summary["test"]["combined"]
    print("combined direct-injection TPR:", round(combined["attack:direct_injection"]["rate"], 3))
    return 0


def _eval_pii(args: argparse.Namespace) -> int:
    from guarded_llm_gateway.eval import pii_bench

    if args.report_only:
        pii_bench.summarize()
    else:
        pii_bench.run()
    return 0


def _eval_pipeline(args: argparse.Namespace) -> int:
    from guarded_llm_gateway.eval import pipeline_eval

    pipeline_eval.run(torch_threads=args.threads)
    return 0


def _eval_e2e(args: argparse.Namespace) -> int:
    from guarded_llm_gateway.eval import e2e

    e2e.run(live=args.live, cap_usd=args.cap, limit=args.limit)
    return 0


def _faults(_: argparse.Namespace) -> int:
    from guarded_llm_gateway.eval import faults

    for name, row in faults.run().items():
        stages = ", ".join(
            f"{s} {row[s]['k']}" for s in ("primary", "fallback", "retrieval_only", "503")
        )
        print(f"{name}: {stages}")
    return 0


def _demo(_: argparse.Namespace) -> int:
    """Offline: recompute metrics from committed records, rerun fault injection, rewrite README."""
    from guarded_llm_gateway.eval import (
        detector_report,
        e2e,
        faults,
        pii_bench,
        pipeline_eval,
        report,
    )
    from guarded_llm_gateway.paths import RESULTS_DIR

    if (RESULTS_DIR / "detectors" / "piguard.jsonl").exists():
        detector_report.run()
    if (RESULTS_DIR / "pii" / "regex.jsonl").exists():
        pii_bench.summarize()
    if (RESULTS_DIR / "pipeline" / "offline.jsonl").exists():
        pipeline_eval.summarize()
    if (RESULTS_DIR / "e2e" / "full.jsonl").exists():
        e2e.summarize()
    faults.run()
    changed = report.write_readme()
    print("README results section", "updated" if changed else "already up to date")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gateway", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the FastAPI gateway")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(fn=_serve)

    p = sub.add_parser("fetch", help="download the pinned public datasets and verify hashes")
    p.add_argument("--record", action="store_true", help="record hashes for files not in the lock")
    p.set_defaults(fn=_fetch)

    p = sub.add_parser("build-suite", help="assemble data/suites/*.jsonl from the pinned datasets")
    p.set_defaults(fn=_build_suite)

    p = sub.add_parser("eval-detectors", help="score the suites with both detectors (CPU)")
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--report-only", action="store_true", help="recompute metrics from saved scores")
    p.set_defaults(fn=_eval_detectors)

    p = sub.add_parser("eval-pii", help="regex vs Presidio on gretel and Nemotron-PII")
    p.add_argument("--report-only", action="store_true")
    p.set_defaults(fn=_eval_pii)

    p = sub.add_parser("eval-pipeline", help="offline pass of the suites through the full gateway")
    p.add_argument("--threads", type=int, default=4)
    p.set_defaults(fn=_eval_pipeline)

    p = sub.add_parser("eval-e2e", help="end-to-end ASR (live with --live, else cache replay)")
    p.add_argument("--live", action="store_true", help="call Azure models (needs credentials)")
    p.add_argument("--cap", type=float, default=2.00, help="hard dollar cap for --live")
    p.add_argument("--limit", type=int, default=None, help="only the first N items (smoke test)")
    p.set_defaults(fn=_eval_e2e)

    p = sub.add_parser("faults", help="fault-injection simulation of the fallback chain")
    p.set_defaults(fn=_faults)

    p = sub.add_parser("demo", help="offline: recompute results and rewrite the README section")
    p.set_defaults(fn=_demo)

    args = parser.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
