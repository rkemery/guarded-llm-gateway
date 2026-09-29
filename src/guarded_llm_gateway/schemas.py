"""Pydantic models for the HTTP API and for the JSON the model must return."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Hard ceiling enforced by Pydantic before any layer runs. The configured,
# usually smaller limit is applied by the input-validation layer.
HARD_MAX_MESSAGE_CHARS = 20_000


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=HARD_MAX_MESSAGE_CHARS)
    session_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


Status = Literal["answered", "retrieval_only", "blocked"]


class LayerEvent(BaseModel):
    layer: str
    action: str
    latency_ms: float
    detail: str | None = None


class ChatResponse(BaseModel):
    request_id: str
    status: Status
    answer: str
    citations: list[str] = Field(default_factory=list)
    blocked_by: str | None = None
    model: str | None = None
    # Per-layer trace. Only filled when GATEWAY_DEBUG is on, because detector
    # verdicts are an oracle an adaptive attacker could optimize against.
    layers: list[LayerEvent] | None = None


class ModelAnswer(BaseModel):
    """What the model must return. Validated, with one repair attempt on failure."""

    model_config = ConfigDict(extra="forbid")

    answer: str = Field(min_length=1, max_length=4000)
    citations: list[str] = Field(default_factory=list, max_length=5)
    escalate: bool = False


def model_answer_json_schema() -> dict[str, object]:
    """Strict JSON schema for the Responses API `text.format` (all fields required)."""
    return {
        "type": "object",
        "properties": {
            "answer": {"type": "string"},
            "citations": {"type": "array", "items": {"type": "string"}},
            "escalate": {"type": "boolean"},
        },
        "required": ["answer", "citations", "escalate"],
        "additionalProperties": False,
    }
