"""Supply-chain and configuration checks (OWASP LLM04:2026 Supply Chain)."""

from __future__ import annotations

import re

from guarded_llm_gateway.config import ConfigError, Settings
from guarded_llm_gateway.paths import ROOT

SRC = ROOT / "src" / "guarded_llm_gateway"


def test_no_remote_code_is_trusted_in_the_gateway() -> None:
    for path in SRC.rglob("*.py"):
        code = re.sub(r'"""(?:.|\n)*?"""', "", path.read_text(encoding="utf-8"))
        assert "trust_remote_code=True" not in code, path


def test_every_hub_download_is_pinned() -> None:
    text = (SRC / "detectors.py").read_text(encoding="utf-8")
    assert text.count("from_pretrained(") == text.count("revision=self.revision")
    sources = (SRC / "eval" / "sources.py").read_text(encoding="utf-8")
    for revision in re.findall(r'"([0-9a-f]{40})"', sources):
        assert len(revision) == 40
    assert "revision=source.revision" in sources


def test_litellm_is_not_a_dependency() -> None:
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert 'name = "litellm"' not in lock


def test_settings_reject_bad_values() -> None:
    import pytest

    with pytest.raises(ConfigError):
        Settings.from_env({"GATEWAY_BACKEND": "openai"})
    with pytest.raises(ConfigError):
        Settings.from_env({"GATEWAY_DEADLINE_S": "-1"})
    with pytest.raises(ConfigError):
        Settings.from_env({"GATEWAY_DETECTORS": "piguard,llamaguard"})


def test_prompt_shields_is_off_unless_configured() -> None:
    assert not Settings.from_env({}).prompt_shields_enabled
    on = Settings.from_env(
        {"AZURE_CONTENT_SAFETY_ENDPOINT": "https://x.example", "AZURE_CONTENT_SAFETY_KEY": "k"}
    )
    assert on.prompt_shields_enabled


def test_canary_is_random_per_process_unless_set() -> None:
    assert Settings().canary != Settings().canary
    assert Settings.from_env({"GATEWAY_CANARY": "TB-CANARY-fixed00000000"}).canary.endswith(
        "fixed00000000"
    )
