"""Prometheus metrics. Each app instance gets its own registry, so tests stay isolated."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20)


class GatewayMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        r = self.registry
        self.requests = Counter(
            "gateway_requests_total", "Requests by final status.", ["status"], registry=r
        )
        self.blocks = Counter(
            "gateway_blocks_total", "Requests blocked, by layer.", ["layer"], registry=r
        )
        self.docs_dropped = Counter(
            "gateway_documents_dropped_total", "Retrieved documents quarantined.", registry=r
        )
        self.redactions = Counter(
            "gateway_pii_redactions_total", "PII spans redacted, by where.", ["where"], registry=r
        )
        self.layer_latency = Histogram(
            "gateway_layer_latency_seconds",
            "Time spent in each layer.",
            ["layer"],
            buckets=LATENCY_BUCKETS,
            registry=r,
        )
        self.fallbacks = Counter(
            "gateway_answer_source_total",
            "Which stage of the fallback chain answered.",
            ["stage"],
            registry=r,
        )
        self.model_errors = Counter(
            "gateway_model_errors_total", "Model call failures.", ["model", "kind"], registry=r
        )
        self.retries = Counter(
            "gateway_model_retries_total", "Retried model calls.", ["model"], registry=r
        )
        self.breaker_state = Gauge(
            "gateway_circuit_state",
            "Circuit breaker state (0 closed, 1 half-open, 2 open).",
            ["model"],
            registry=r,
        )
        self.schema_repairs = Counter(
            "gateway_schema_repairs_total", "Schema repair attempts.", ["outcome"], registry=r
        )
        self.tokens = Counter(
            "gateway_tokens_total", "Model tokens.", ["model", "kind"], registry=r
        )
        self.rate_limited = Counter(
            "gateway_rate_limited_total", "429 responses, by limiter.", ["limiter"], registry=r
        )
