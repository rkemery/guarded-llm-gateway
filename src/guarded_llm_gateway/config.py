"""Gateway settings, read from environment variables (see .env.example).

Nothing here holds a secret by default. Azure endpoints and keys are read only
when the matching feature is switched on, and are never logged.
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guarded_llm_gateway.paths import RESULTS_DIR

THRESHOLDS_FILE = RESULTS_DIR / "detectors" / "thresholds.json"

# Domains the assistant may link to or show images from. The help center and
# support mailbox of the fictional bank use the reserved .example TLD.
DEFAULT_ALLOWED_DOMAINS = ("help.tallowbrook.example", "tallowbrook.example")
# Contact details the bank publishes, so the output PII rule leaves them alone.
DEFAULT_ALLOWED_PII = ("support@tallowbrook.example", "+1 555 0142", "555 0142", "555-0142")


class ConfigError(ValueError):
    """An environment variable holds a value the gateway cannot use."""


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    if raw.lower() in {"1", "true", "yes", "on"}:
        return True
    if raw.lower() in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}")


def _number(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be positive, got {raw!r}")
    return value


def _csv(env: Mapping[str, str], name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = env.get(name)
    if raw is None:
        return default
    return tuple(part.strip() for part in raw.split(",") if part.strip())


DEFAULT_DETECTORS = ("piguard",)


def load_thresholds(
    path: Path = THRESHOLDS_FILE, detectors: tuple[str, ...] | None = None
) -> dict[str, Any]:
    """The detector profile and thresholds tuned on the dev split.

    Returns {"detectors": [...], "prompt": {name: t}, "document": {name: t}}. By
    default this is the profile chosen on dev. Passing `detectors` picks the tuned
    profile for that set instead (one detector alone, or all of them ORed). Without
    the file, detectors run at the vendors' 0.5 threshold.
    """
    chosen = list(DEFAULT_DETECTORS if detectors is None else detectors)
    if not path.exists():
        return {"detectors": chosen, "prompt": {}, "document": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if detectors is None:
        return {
            "detectors": list(data.get("detectors", DEFAULT_DETECTORS)),
            "prompt": dict(data.get("prompt", {})),
            "document": dict(data.get("document", {})),
        }
    for profile in data.get("profiles", {}).values():
        if sorted(profile["detectors"]) == sorted(detectors):
            return {
                "detectors": chosen,
                "prompt": profile["prompt"],
                "document": profile["document"],
            }
    return {"detectors": chosen, "prompt": {}, "document": {}}


@dataclass(frozen=True)
class Settings:
    backend: str = "fake"  # "fake" (offline) or "azure"
    primary_model: str = "gpt-6-luna"
    fallback_model: str = "gpt-5-mini"
    detectors: tuple[str, ...] = DEFAULT_DETECTORS
    prompt_thresholds: dict[str, float] = field(default_factory=dict)
    document_thresholds: dict[str, float] = field(default_factory=dict)
    max_input_chars: int = 4000
    max_body_bytes: int = 32_768
    top_k: int = 3
    deadline_s: float = 20.0
    model_timeout_s: float = 12.0
    retry_attempts: int = 2
    breaker_failures: int = 5
    breaker_reset_s: float = 30.0
    rate_limit: str = "30/minute"
    token_budget_per_minute: int = 20_000
    api_keys: tuple[str, ...] = ()
    canary: str = field(default_factory=lambda: f"TB-CANARY-{secrets.token_hex(8)}")
    allowed_domains: tuple[str, ...] = DEFAULT_ALLOWED_DOMAINS
    allowed_pii: tuple[str, ...] = DEFAULT_ALLOWED_PII
    max_output_tokens: int = 500
    structured_outputs: bool = True
    redact_pii: bool = True
    spotlight: bool = True
    output_rules: bool = True
    dollar_cap_usd: float = 1.0
    cache_dir: str | None = None
    prompt_shields_endpoint: str | None = None
    prompt_shields_key: str | None = None
    torch_threads: int = 2
    debug: bool = False

    @property
    def prompt_shields_enabled(self) -> bool:
        return bool(self.prompt_shields_endpoint and self.prompt_shields_key)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        requested = env.get("GATEWAY_DETECTORS")
        thresholds = load_thresholds(
            detectors=None if requested is None else _csv(env, "GATEWAY_DETECTORS", ())
        )
        backend = env.get("GATEWAY_BACKEND", "fake")
        if backend not in {"fake", "azure"}:
            raise ConfigError(f"GATEWAY_BACKEND must be 'fake' or 'azure', got {backend!r}")
        detectors = _csv(env, "GATEWAY_DETECTORS", tuple(thresholds["detectors"]))
        unknown = set(detectors) - {"piguard", "deberta"}
        if unknown:
            raise ConfigError(f"unknown detectors in GATEWAY_DETECTORS: {sorted(unknown)}")
        kwargs: dict[str, object] = {
            "backend": backend,
            "primary_model": env.get("GATEWAY_PRIMARY_MODEL", "gpt-6-luna"),
            "fallback_model": env.get("GATEWAY_FALLBACK_MODEL", "gpt-5-mini"),
            "detectors": detectors,
            "prompt_thresholds": thresholds["prompt"],
            "document_thresholds": thresholds["document"],
            "max_input_chars": int(_number(env, "GATEWAY_MAX_INPUT_CHARS", 4000)),
            "deadline_s": _number(env, "GATEWAY_DEADLINE_S", 20.0),
            "model_timeout_s": _number(env, "GATEWAY_MODEL_TIMEOUT_S", 12.0),
            "rate_limit": env.get("GATEWAY_RATE_LIMIT", "30/minute"),
            "token_budget_per_minute": int(_number(env, "GATEWAY_TOKEN_BUDGET_PER_MINUTE", 20_000)),
            "api_keys": _csv(env, "GATEWAY_API_KEYS", ()),
            "structured_outputs": _flag(env, "GATEWAY_STRUCTURED_OUTPUTS", True),
            "dollar_cap_usd": _number(env, "GATEWAY_DOLLAR_CAP_USD", 1.0),
            "cache_dir": env.get("GATEWAY_CACHE_DIR") or None,
            "prompt_shields_endpoint": env.get("AZURE_CONTENT_SAFETY_ENDPOINT") or None,
            "prompt_shields_key": env.get("AZURE_CONTENT_SAFETY_KEY") or None,
            "torch_threads": int(_number(env, "GATEWAY_TORCH_THREADS", 2)),
            "debug": _flag(env, "GATEWAY_DEBUG", False),
        }
        if env.get("GATEWAY_CANARY"):
            kwargs["canary"] = env["GATEWAY_CANARY"]
        return cls(**kwargs)  # type: ignore[arg-type]
