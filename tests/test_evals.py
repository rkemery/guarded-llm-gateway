from __future__ import annotations

import asyncio

from guarded_llm_gateway.eval.e2e import (
    E2E_CANARY,
    account_context,
    judge,
    luhn_complete,
    pii_leaked,
)
from guarded_llm_gateway.eval.faults import SCENARIOS, run_scenario
from guarded_llm_gateway.eval.pii_bench import match_counts
from guarded_llm_gateway.eval.report import pct, render
from guarded_llm_gateway.pii import PiiSpan, luhn_valid

ALLOWED = ("help.tallowbrook.example", "tallowbrook.example")


def test_match_counts_overlap_by_category() -> None:
    gold = [("PERSON", 0, 10), ("EMAIL", 20, 35), ("PHONE", 40, 52)]
    pred = [PiiSpan("PERSON", 5, 12), PiiSpan("EMAIL_ADDRESS", 60, 70), PiiSpan("US_SSN", 40, 52)]
    counts = match_counts(gold, pred)
    assert counts["PERSON:found"] == 1
    assert counts["PERSON:correct"] == 1
    assert counts["EMAIL:found"] == 0
    assert counts["EMAIL:pred"] == 1
    assert counts["EMAIL:correct"] == 0
    assert counts["PHONE:found"] == 0  # a span of the wrong type does not count
    assert counts["SSN:correct"] == 0


def test_account_context_is_deterministic_and_fake() -> None:
    context, values = account_context("atk-1")
    assert (context, values) == account_context("atk-1")
    _, email, phone, card = values
    assert email.endswith("@example.com")
    assert "555-01" in phone
    assert card.startswith("411111")
    assert luhn_valid(card)
    assert luhn_valid(luhn_complete("411111000000000"))


def test_judge_flags_each_leak_kind() -> None:
    _, values = account_context("x")
    assert judge(f"code {E2E_CANARY}", values, ALLOWED)["canary_leak"]
    card = values[3]
    spaced = " ".join(card[i : i + 4] for i in range(0, 16, 4))
    assert judge(f"your card is {spaced}", values, ALLOWED)["pii_leak"]
    assert judge("send it to contact@contact.com", values, ALLOWED)["link_leak"]
    clean = judge(
        "Plus costs $5.00 a month. See https://help.tallowbrook.example/a", values, ALLOWED
    )
    assert not any(clean.values())


def test_pii_leaked_matches_digits_across_formatting() -> None:
    assert pii_leaked("call 312.555.0142", ["(312) 555-0142"])
    assert not pii_leaked("call 555-0199", ["(312) 555-0142"])


def test_fault_scenarios_route_through_the_chain() -> None:
    questions = ["How do I freeze my card?"] * 30
    by_name = {s.name: s for s in SCENARIOS}
    healthy = asyncio.run(run_scenario(by_name["healthy"], questions))
    assert healthy["primary"]["k"] == 30
    down = asyncio.run(run_scenario(by_name["primary down"], questions))
    assert down["fallback"]["k"] == 30
    both = asyncio.run(run_scenario(by_name["both down"], questions))
    assert both["retrieval_only"]["k"] == 30
    empty = asyncio.run(run_scenario(by_name["both down, retrieval finds nothing"], questions))
    assert empty["503"]["k"] == 30


def test_report_marks_live_rows_pending() -> None:
    text = render()
    assert "pending live run" in text
    assert pct({"n": 0}) == "n/a"
    assert pct({"n": 10, "rate": 0.5, "low": 0.2, "high": 0.8}) == "50.0% (20.0 to 80.0)"
