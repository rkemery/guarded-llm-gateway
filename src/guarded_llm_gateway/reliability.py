"""Circuit breaker and per-key token budget, both driven by an injectable clock.

pybreaker is sync-only (async only through Tornado) and purgatory has had no
release since 2024, so the breaker is written out here. It is small enough to
read in one sitting and is tested with a fake clock.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

Clock = Callable[[], float]


class BreakerState(IntEnum):
    CLOSED = 0
    HALF_OPEN = 1
    OPEN = 2


class CircuitBreaker:
    """Consecutive-failure breaker.

    CLOSED: calls pass. `failure_threshold` consecutive failures open it.
    OPEN: calls are refused until `reset_timeout_s` has passed, then one trial
    call is let through (HALF_OPEN). HALF_OPEN: while the trial is in flight,
    other calls are refused. Success closes the breaker, failure reopens it and
    restarts the timeout.

    Meant for one asyncio event loop: `allow` and the `record_*` methods never
    await, so they cannot interleave.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        reset_timeout_s: float = 30.0,
        clock: Clock = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if reset_timeout_s <= 0:
            raise ValueError("reset_timeout_s must be positive")
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout_s = reset_timeout_s
        self._clock = clock
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._trial_in_flight = False

    @property
    def state(self) -> BreakerState:
        if (
            self._state is BreakerState.OPEN
            and self._clock() - self._opened_at >= self.reset_timeout_s
        ):
            return BreakerState.HALF_OPEN
        return self._state

    def allow(self) -> bool:
        state = self.state
        if state is BreakerState.CLOSED:
            return True
        if state is BreakerState.HALF_OPEN and not self._trial_in_flight:
            self._state = BreakerState.HALF_OPEN
            self._trial_in_flight = True
            return True
        return False

    def record_success(self) -> None:
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._trial_in_flight = False

    def record_failure(self) -> None:
        self._trial_in_flight = False
        if self._state is BreakerState.HALF_OPEN:
            self._open()
            return
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._open()

    def retry_after_s(self) -> float:
        if self.state is not BreakerState.OPEN:
            return 0.0
        return max(0.0, self.reset_timeout_s - (self._clock() - self._opened_at))

    def _open(self) -> None:
        self._state = BreakerState.OPEN
        self._opened_at = self._clock()
        self._failures = 0


@dataclass
class _Bucket:
    tokens: float
    updated: float


class BudgetExceeded(Exception):
    """A key spent its token budget. `retry_after_s` says when enough will have refilled."""

    def __init__(self, retry_after_s: float) -> None:
        super().__init__(f"token budget exceeded, retry after {retry_after_s:.0f}s")
        self.retry_after_s = retry_after_s


class TokenBudget:
    """Per-key token bucket: `capacity` tokens, refilled at capacity / `window_s` per second.

    Before a model call the gateway reserves its worst case (estimated input
    plus max output). After the call it settles the reservation against real
    usage, refunding what was not spent. An empty bucket raises BudgetExceeded
    with the wait until the reservation would fit. In-memory and per process,
    like slowapi's default store.
    """

    def __init__(
        self, capacity: int, window_s: float = 60.0, clock: Clock = time.monotonic
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self.rate = capacity / window_s
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}

    def _bucket(self, key: str) -> _Bucket:
        now = self._clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = _Bucket(float(self.capacity), now)
        else:
            bucket.tokens = min(self.capacity, bucket.tokens + (now - bucket.updated) * self.rate)
            bucket.updated = now
        return bucket

    def reserve(self, key: str, tokens: int) -> None:
        tokens = min(tokens, self.capacity)
        bucket = self._bucket(key)
        if bucket.tokens < tokens:
            raise BudgetExceeded(math.ceil((tokens - bucket.tokens) / self.rate))
        bucket.tokens -= tokens

    def settle(self, key: str, reserved: int, used: int) -> None:
        bucket = self._bucket(key)
        bucket.tokens = min(self.capacity, bucket.tokens + min(reserved, self.capacity) - used)

    def remaining(self, key: str) -> float:
        return self._bucket(key).tokens


def estimate_tokens(text: str) -> int:
    """Rough input-token estimate for budget reservations: one token per 3 characters."""
    return max(1, math.ceil(len(text) / 3))
