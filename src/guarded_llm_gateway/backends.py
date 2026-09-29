"""Model backends: the harness clients behind an async interface, a fake model and fault injection.

Live calls go through llm-eval-harness: `FoundryClient` (OpenAI SDK against the
Foundry /openai/v1/ endpoint, SDK `max_retries=0`) inside `DollarCap`, with
`CachedClient` outermost when a cache directory is set. Those clients are
synchronous, so each call runs in a worker thread. The SDK client gets a
per-request timeout below the gateway deadline, which bounds how long a
thread can outlive a request that the deadline already answered.

Retries live in the gateway (stamina), not in the harness `RetryingClient`,
because its backoff sleeps with `time.sleep` in the worker thread, where the
request deadline cannot cancel it. stamina sleeps with `asyncio.sleep`.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
from collections.abc import Callable
from typing import Any, Protocol

from llm_eval_harness import CachedClient, DollarCap, ModelClient, ModelRequest, ModelResponse

from guarded_llm_gateway.config import Settings


class AsyncModel(Protocol):
    async def complete(self, request: ModelRequest) -> ModelResponse: ...


class TransientModelError(RuntimeError):
    """A retryable failure (used by fakes and fault injection)."""


class ContentFiltered(RuntimeError):
    """The provider's content filter refused the prompt or the completion."""


class ProviderRefused(RuntimeError):
    """The provider refused the prompt with a policy error other than Azure's content filter."""


class ThreadedClient:
    """Runs a synchronous harness `ModelClient` in a worker thread.

    With `serialize=True`, calls queue on an asyncio lock before a thread starts.
    The harness `DollarCap` is not thread-safe, so the live server serializes
    calls through it. Waiting on an asyncio lock can be cancelled by the request
    deadline, so a request that timed out never starts a model call later.
    """

    def __init__(self, client: ModelClient, *, serialize: bool = False) -> None:
        self.client = client
        self._lock = asyncio.Lock() if serialize else None

    async def complete(self, request: ModelRequest) -> ModelResponse:
        if self._lock is None:
            return await asyncio.to_thread(self.client.complete, request)
        async with self._lock:
            return await asyncio.to_thread(self.client.complete, request)


def _openai_retryable() -> tuple[type[BaseException], ...]:
    try:
        from llm_eval_harness.azure import retryable_errors
    except ImportError:
        return ()
    try:
        return retryable_errors()
    except ImportError:
        return ()


_RETRYABLE: tuple[type[BaseException], ...] = (
    TransientModelError,
    TimeoutError,
    *_openai_retryable(),
)


def is_retryable(exc: Exception) -> bool:
    return isinstance(exc, _RETRYABLE)


def is_content_filter(exc: BaseException) -> bool:
    """Azure returns HTTP 400 with error code `content_filter` when its filter blocks a prompt."""
    return isinstance(exc, ContentFiltered) or getattr(exc, "code", None) == "content_filter"


# Policy codes a provider puts on a 400 when it refuses the prompt itself. OpenAI uses
# `invalid_prompt` and `content_policy_violation`, and Azure nests
# `ResponsibleAIPolicyViolation` under `innererror`. gpt-6-luna on Foundry returned
# `cyber_policy` and `bio_policy` in the live run, so any code ending in `_policy`
# counts too. Compared lowercased.
_REFUSAL_CODES = frozenset(
    {"invalid_prompt", "content_policy_violation", "responsibleaipolicyviolation"}
)
_REFUSAL_CODE_SUFFIX = "_policy"
_REFUSAL_MESSAGES = (
    "content management policy",
    "usage policy",
    "usage policies",
    "this content was flagged",
)
_DETAIL_CHARS = 200


def _error_body(exc: BaseException) -> dict[str, Any]:
    body = getattr(exc, "body", None)
    return body if isinstance(body, dict) else {}


def _inner_error(body: dict[str, Any]) -> dict[str, Any]:
    inner = body.get("innererror") or body.get("inner_error")
    return inner if isinstance(inner, dict) else {}


def is_provider_refusal(exc: BaseException) -> bool:
    """A 400 whose code, body or message says the provider's policy refused the prompt.

    Any other 4xx (a bad parameter, an unknown deployment) is a configuration
    error and still fails over to the next model.
    """
    if isinstance(exc, ProviderRefused):
        return True
    if getattr(exc, "status_code", None) != 400:
        return False
    body = _error_body(exc)
    inner = _inner_error(body)
    if any(
        k in d for d in (body, inner) for k in ("content_filter_result", "content_filter_results")
    ):
        return True
    codes = {getattr(exc, "code", None), body.get("code"), inner.get("code")}
    lowered = {str(c).lower() for c in codes if c}
    if lowered & _REFUSAL_CODES or any(c.endswith(_REFUSAL_CODE_SUFFIX) for c in lowered):
        return True
    message = str(getattr(exc, "message", None) or exc).lower()
    return any(marker in message for marker in _REFUSAL_MESSAGES)


def error_detail(exc: BaseException) -> str:
    """The exception class plus the provider's status, code, type and a trimmed message."""
    parts = [type(exc).__name__]
    inner_code = _inner_error(_error_body(exc)).get("code")
    for label, value in (
        ("status", getattr(exc, "status_code", None)),
        ("code", getattr(exc, "code", None)),
        ("type", getattr(exc, "type", None)),
        ("inner", inner_code),
    ):
        if value is not None:
            parts.append(f"{label}={value}")
    message = " ".join(str(getattr(exc, "message", None) or exc).split())
    if message:
        parts.append(message[:_DETAIL_CHARS])
    return " ".join(parts)


# ---------------------------------------------------------------- fake model

_DOC = re.compile(r'<document id="([^"]+)">\n(.*?)\n</document>', re.DOTALL)


def fake_reply(request: ModelRequest) -> str:
    """Deterministic stand-in for the model: cite the first document and quote its title."""
    text = request.input if isinstance(request.input, str) else request.input[0]["content"]
    match = _DOC.search(text)
    if match is None:
        answer = "I could not find this in the Tallowbrook help center. Please contact support."
        return json.dumps({"answer": answer, "citations": [], "escalate": False})
    article_id = match.group(1)
    answer = f"The help-center article {article_id} covers this."
    return json.dumps({"answer": answer, "citations": [article_id], "escalate": False})


class FakeModel:
    """Async fake backend with the same reply contract as a real model. No network."""

    def __init__(
        self,
        reply: Callable[[ModelRequest], str] = fake_reply,
        *,
        latency_s: float = 0.0,
    ) -> None:
        self._reply = reply
        self._latency_s = latency_s
        self.calls: list[ModelRequest] = []

    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.calls.append(request)
        if self._latency_s:
            await asyncio.sleep(self._latency_s)
        text = self._reply(request)
        words = len(str(request.input).split()) + len((request.instructions or "").split())
        return ModelResponse(
            text=text, model=request.model, input_tokens=words, output_tokens=len(text.split())
        )


class FaultyModel:
    """Wraps a backend and injects faults with seeded probabilities.

    `error_rate`: raise TransientModelError. `hang_rate`: sleep `hang_s` (longer
    than the per-call timeout). `malformed_rate`: return text that is not JSON.
    """

    def __init__(
        self,
        inner: AsyncModel,
        *,
        error_rate: float = 0.0,
        hang_rate: float = 0.0,
        malformed_rate: float = 0.0,
        hang_s: float = 60.0,
        seed: int = 0,
    ) -> None:
        self._inner = inner
        self.error_rate = error_rate
        self.hang_rate = hang_rate
        self.malformed_rate = malformed_rate
        self.hang_s = hang_s
        self._rng = random.Random(seed)
        self.injected: dict[str, int] = {"error": 0, "hang": 0, "malformed": 0}

    async def complete(self, request: ModelRequest) -> ModelResponse:
        roll = self._rng.random()
        if roll < self.error_rate:
            self.injected["error"] += 1
            raise TransientModelError("injected 503")
        roll -= self.error_rate
        if roll < self.hang_rate:
            self.injected["hang"] += 1
            await asyncio.sleep(self.hang_s)
        roll -= self.hang_rate
        response = await self._inner.complete(request)
        if roll < self.malformed_rate:
            self.injected["malformed"] += 1
            return ModelResponse(
                text="Sure! Here is the answer, not in JSON.",
                model=response.model,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
            )
        return response


# ---------------------------------------------------------------- live stack


def live_harness_client(settings: Settings, cap_usd: float | None = None) -> Any:
    """The harness stack for one process: CachedClient(DollarCap(FoundryClient)), cache optional.

    Needs AZURE_OPENAI_BASE_URL plus AZURE_OPENAI_API_KEY or Entra ID. The SDK
    client keeps `max_retries=0` from the harness and gets a per-request timeout.
    """
    from llm_eval_harness.azure import FoundryClient, build_sdk_client

    sdk = build_sdk_client().with_options(timeout=settings.model_timeout_s, max_retries=0)
    capped = DollarCap(FoundryClient(sdk_client=sdk), cap_usd=cap_usd or settings.dollar_cap_usd)
    if settings.cache_dir:
        return CachedClient(capped, settings.cache_dir), capped
    return capped, capped
