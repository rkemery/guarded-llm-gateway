from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import replace
from typing import Any

import pytest

from guarded_llm_gateway.backends import FakeModel
from guarded_llm_gateway.config import Settings
from guarded_llm_gateway.corpus import BM25Index, current_articles, load_articles
from guarded_llm_gateway.detectors import StaticDetector
from guarded_llm_gateway.pipeline import Gateway, ModelSlot
from guarded_llm_gateway.reliability import CircuitBreaker

CANARY = "TB-CANARY-0123456789abcdef"


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def keyword_detector(name: str = "kw", word: str = "ignore previous") -> StaticDetector:
    return StaticDetector(name, lambda text: 1.0 if word in text.lower() else 0.0)


@pytest.fixture(scope="session")
def index() -> BM25Index:
    return BM25Index(current_articles(load_articles()))


@pytest.fixture
def settings() -> Settings:
    return replace(Settings(), canary=CANARY, detectors=(), deadline_s=5.0, model_timeout_s=1.0)


@pytest.fixture
def make_gateway(settings: Settings, index: BM25Index) -> Callable[..., Gateway]:
    def factory(
        models: list[Any] | None = None,
        detectors: list[Any] | None = None,
        clock: Callable[[], float] | None = None,
        **kwargs: Any,
    ) -> Gateway:
        backends = models if models is not None else [FakeModel(), FakeModel()]
        names = ["gpt-6-luna", "gpt-5-mini"]
        breaker_clock = clock or FakeClock()
        slots = [
            ModelSlot(names[i], b, CircuitBreaker(names[i], 3, 10.0, breaker_clock))
            for i, b in enumerate(backends)
        ]
        gateway_settings = kwargs.pop("settings", settings)
        extra = {"clock": clock} if clock is not None else {}
        return Gateway(
            gateway_settings,
            index=index,
            models=slots,
            detectors=detectors or [],
            **extra,
            **kwargs,
        )

    return factory


def run(coro: Coroutine[Any, Any, Any]) -> Any:
    return asyncio.run(coro)
