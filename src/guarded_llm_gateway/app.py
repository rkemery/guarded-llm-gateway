"""FastAPI app: POST /v1/chat behind rate limits, GET /metrics for Prometheus, health checks."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.extension import _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

from guarded_llm_gateway import __version__
from guarded_llm_gateway.backends import FakeModel, ThreadedClient, live_harness_client
from guarded_llm_gateway.config import Settings
from guarded_llm_gateway.corpus import default_index
from guarded_llm_gateway.detectors import HFClassifier, PromptShields
from guarded_llm_gateway.metrics import GatewayMetrics
from guarded_llm_gateway.pii import PresidioPii
from guarded_llm_gateway.pipeline import Gateway, ModelSlot, Unavailable
from guarded_llm_gateway.reliability import BudgetExceeded, CircuitBreaker, TokenBudget
from guarded_llm_gateway.schemas import ChatRequest, ChatResponse


def build_gateway(settings: Settings, metrics: GatewayMetrics | None = None) -> Gateway:
    """Wire the default profile: BM25, Presidio, the configured detectors and backends."""
    metrics = metrics or GatewayMetrics()
    if settings.backend == "azure":
        client, _ = live_harness_client(settings)
        shared = ThreadedClient(client, serialize=True)
        backends: list[Any] = [shared, shared]
    else:
        backends = [FakeModel(), FakeModel()]
    slots = [
        ModelSlot(
            name, backend, CircuitBreaker(name, settings.breaker_failures, settings.breaker_reset_s)
        )
        for name, backend in zip(
            (settings.primary_model, settings.fallback_model), backends, strict=True
        )
    ]
    shields = None
    if settings.prompt_shields_enabled:
        shields = PromptShields(settings.prompt_shields_endpoint, settings.prompt_shields_key)
    return Gateway(
        settings,
        index=default_index(),
        models=slots,
        pii=PresidioPii() if settings.redact_pii else None,
        detectors=[
            HFClassifier(n, torch_threads=settings.torch_threads) for n in settings.detectors
        ],
        shields=shields,
        metrics=metrics,
        budget=TokenBudget(settings.token_budget_per_minute),
    )


def rate_key_for(api_keys: tuple[str, ...]) -> Callable[[Request], str]:
    """Key rate limits and token budgets on X-API-Key only when it is a configured key.

    Anything else, including every request in open mode (no keys configured), is
    keyed on the client IP. Otherwise a caller could send a fresh random key with
    each request and get a fresh bucket every time.
    """
    allowed = frozenset(api_keys)

    def rate_key(request: Request) -> str:
        key = request.headers.get("x-api-key")
        if key and key in allowed:
            return "key:" + hashlib.sha256(key.encode()).hexdigest()[:16]
        return "ip:" + get_remote_address(request)

    return rate_key


def _body_limit(max_bytes: int) -> Callable[..., Awaitable[Response]]:
    async def middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        length = request.headers.get("content-length")
        if length is not None and length.isdigit() and int(length) > max_bytes:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        if request.method == "POST" and length is None:
            body = await request.body()
            if len(body) > max_bytes:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    return middleware


def create_app(settings: Settings | None = None, gateway: Gateway | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    gateway = gateway or build_gateway(settings)
    metrics = gateway.metrics

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        gateway.warm_up()
        yield
        if gateway.shields is not None:
            await gateway.shields.aclose()

    rate_key = rate_key_for(settings.api_keys)
    limiter = Limiter(key_func=rate_key, headers_enabled=True)
    app = FastAPI(title="guarded-llm-gateway", version=__version__, lifespan=lifespan)
    app.state.limiter = limiter
    app.state.gateway = gateway
    app.middleware("http")(_body_limit(settings.max_body_bytes))

    def on_rate_limited(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, RateLimitExceeded)
        metrics.rate_limited.labels("requests").inc()
        return _rate_limit_exceeded_handler(request, exc)

    app.add_exception_handler(RateLimitExceeded, on_rate_limited)

    @app.post("/v1/chat", response_model=ChatResponse, response_model_exclude_none=True)
    @limiter.limit(settings.rate_limit)
    async def chat(
        request: Request,
        response: Response,
        body: ChatRequest,
        x_api_key: str | None = Header(default=None),
    ) -> Any:
        if settings.api_keys and x_api_key not in settings.api_keys:
            raise HTTPException(status_code=401, detail="missing or unknown X-API-Key")
        key = rate_key(request)
        try:
            result = await gateway.handle(body.message, api_key=key)
        except BudgetExceeded as exc:
            metrics.rate_limited.labels("tokens").inc()
            return JSONResponse(
                {"detail": "token budget exceeded"},
                status_code=429,
                headers={"Retry-After": str(int(exc.retry_after_s))},
            )
        except Unavailable as exc:
            return JSONResponse(
                {"detail": "assistant unavailable, try again shortly"},
                status_code=503,
                headers={"Retry-After": str(max(1, round(exc.retry_after_s)))},
            )
        if result.blocked_by == "input_validation":
            return JSONResponse({"detail": "message rejected by input validation"}, status_code=422)
        return ChatResponse(
            request_id=result.request_id,
            status=result.status,
            answer=result.answer,
            citations=result.citations,
            blocked_by=result.blocked_by,
            model=result.model,
            layers=result.layers if settings.debug else None,
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    async def prometheus() -> Response:
        return Response(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)

    return app
