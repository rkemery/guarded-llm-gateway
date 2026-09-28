"""Fault injection: how often each stage of the fallback chain answers when models misbehave.

    uv run gateway faults      # offline, a few seconds

All 200 Tallowbrook RAG questions go through the gateway with fake models
wrapped in FaultyModel. Detectors and Presidio are off, since they do not
touch reliability. A fake clock advances 0.5 s per request so the circuit
breakers open and half-open on a realistic schedule. stamina runs in test mode
(retries happen, the waits between them do not), and per-call timeouts are
shortened so a hung call costs 50 ms of wall time instead of seconds.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import stamina

from guarded_llm_gateway.backends import FakeModel, FaultyModel
from guarded_llm_gateway.config import Settings
from guarded_llm_gateway.corpus import BM25Index, current_articles, load_articles, load_questions
from guarded_llm_gateway.eval.detector_report import rate
from guarded_llm_gateway.paths import RESULTS_DIR
from guarded_llm_gateway.pipeline import Gateway, ModelSlot, Unavailable
from guarded_llm_gateway.reliability import CircuitBreaker

OUT_DIR = RESULTS_DIR / "faults"
SECONDS_PER_REQUEST = 0.5


@dataclass(frozen=True)
class Scenario:
    name: str
    primary: dict[str, float]
    fallback: dict[str, float]
    empty_index: bool = False


SCENARIOS = (
    Scenario("healthy", {}, {}),
    Scenario("primary 30% errors", {"error_rate": 0.3}, {}),
    Scenario("primary 20% hangs", {"hang_rate": 0.2}, {}),
    Scenario("primary 30% malformed JSON", {"malformed_rate": 0.3}, {}),
    Scenario("primary down", {"error_rate": 1.0}, {}),
    Scenario("primary down, fallback 50% errors", {"error_rate": 1.0}, {"error_rate": 0.5}),
    Scenario("both down", {"error_rate": 1.0}, {"error_rate": 1.0}),
    Scenario("both down, retrieval finds nothing", {"error_rate": 1.0}, {"error_rate": 1.0}, True),
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


async def run_scenario(scenario: Scenario, questions: list[str], seed: int = 0) -> dict[str, Any]:
    clock = FakeClock()
    settings = replace(
        Settings(),
        detectors=(),
        deadline_s=5.0,
        model_timeout_s=0.05,
        retry_attempts=2,
        breaker_failures=5,
        breaker_reset_s=10.0,
    )
    articles = current_articles(load_articles())
    index = BM25Index(articles)
    primary = FaultyModel(FakeModel(), hang_s=1.0, seed=seed, **scenario.primary)
    fallback = FaultyModel(FakeModel(), hang_s=1.0, seed=seed + 1, **scenario.fallback)
    gateway = Gateway(
        settings,
        index=index,
        models=[
            ModelSlot("gpt-6-luna", primary, CircuitBreaker("gpt-6-luna", 5, 10.0, clock)),
            ModelSlot("gpt-5-mini", fallback, CircuitBreaker("gpt-5-mini", 5, 10.0, clock)),
        ],
        clock=clock,
    )
    stages: Counter[str] = Counter()
    calls = 0
    for question in questions:
        clock.now += SECONDS_PER_REQUEST
        text = "zzqx unmatched query" if scenario.empty_index else question
        try:
            result = await gateway.handle(text)
        except Unavailable:
            stages["503"] += 1
            continue
        stages[result.stage] += 1
        calls += result.model_calls
    n = len(questions)
    out: dict[str, Any] = {"n": n, "model_calls_per_request": calls / n, "injected": {}}
    out["injected"] = {"primary": primary.injected, "fallback": fallback.injected}
    for stage in ("primary", "fallback", "retrieval_only", "503"):
        interval = rate([s == stage for s in _expand(stages, n)])
        out[stage] = {
            "k": stages[stage],
            "rate": interval.estimate,
            "low": interval.low,
            "high": interval.high,
        }
    return out


def _expand(stages: Counter[str], n: int) -> list[str]:
    values = [stage for stage, count in stages.items() for _ in range(count)]
    if len(values) != n:
        raise AssertionError(f"stage counts sum to {len(values)}, expected {n}")
    return values


async def run_async(out_dir: Path = OUT_DIR) -> dict[str, Any]:
    questions = [str(q["question"]) for split in ("dev", "test") for q in load_questions(split)]
    summary = {}
    hooks = stamina.instrumentation.get_on_retry_hooks()
    stamina.instrumentation.set_on_retry_hooks([])  # thousands of retry log lines otherwise
    stamina.set_testing(True, attempts=2)
    try:
        for scenario in SCENARIOS:
            summary[scenario.name] = await run_scenario(scenario, questions)
    finally:
        stamina.set_testing(False)
        stamina.instrumentation.set_on_retry_hooks(hooks)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def run() -> dict[str, Any]:
    return asyncio.run(run_async())
