from __future__ import annotations

import pytest

from guarded_llm_gateway.reliability import (
    BreakerState,
    BudgetExceeded,
    CircuitBreaker,
    TokenBudget,
    estimate_tokens,
)

from .conftest import FakeClock


def test_breaker_opens_after_consecutive_failures() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker("m", failure_threshold=3, reset_timeout_s=10, clock=clock)
    for _ in range(2):
        assert breaker.allow()
        breaker.record_failure()
    breaker.record_success()  # a success resets the count
    for _ in range(3):
        assert breaker.allow()
        breaker.record_failure()
    assert breaker.state is BreakerState.OPEN
    assert not breaker.allow()
    assert breaker.retry_after_s() == pytest.approx(10)


def test_breaker_half_open_lets_one_trial_through() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker("m", failure_threshold=1, reset_timeout_s=10, clock=clock)
    breaker.record_failure()
    clock.advance(9.9)
    assert not breaker.allow()
    clock.advance(0.2)
    assert breaker.state is BreakerState.HALF_OPEN
    assert breaker.allow()
    assert not breaker.allow()  # only one trial in flight
    breaker.record_success()
    assert breaker.state is BreakerState.CLOSED
    assert breaker.allow()


def test_breaker_failed_trial_reopens_and_restarts_timer() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker("m", failure_threshold=1, reset_timeout_s=10, clock=clock)
    breaker.record_failure()
    clock.advance(10)
    assert breaker.allow()
    breaker.record_failure()
    assert breaker.state is BreakerState.OPEN
    clock.advance(5)
    assert not breaker.allow()
    clock.advance(5)
    assert breaker.allow()


def test_breaker_rejects_bad_config() -> None:
    with pytest.raises(ValueError, match="failure_threshold"):
        CircuitBreaker("m", failure_threshold=0)


def test_token_budget_refills_and_reports_wait() -> None:
    clock = FakeClock()
    budget = TokenBudget(capacity=600, window_s=60, clock=clock)  # 10 tokens per second
    budget.reserve("k", 500)
    with pytest.raises(BudgetExceeded) as exc:
        budget.reserve("k", 300)
    assert exc.value.retry_after_s == 20  # needs 200 more tokens at 10 per second
    clock.advance(20)
    budget.reserve("k", 300)
    budget.reserve("other-key", 600)  # keys are independent


def test_token_budget_settle_refunds_unused_tokens() -> None:
    clock = FakeClock()
    budget = TokenBudget(capacity=1000, window_s=60, clock=clock)
    budget.reserve("k", 800)
    budget.settle("k", reserved=800, used=100)
    assert budget.remaining("k") == pytest.approx(900)


def test_estimate_tokens_is_positive() -> None:
    assert estimate_tokens("") == 1
    assert estimate_tokens("abcdef") == 2
