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


def test_match_counts_reports_checksum_valid_gold() -> None:
    text = "card 4111 1111 1111 1111 and 4111 1111 1111 1112"
    gold = [("CREDIT_CARD", 5, 24), ("CREDIT_CARD", 29, 48)]
    counts = match_counts(gold, [PiiSpan("CREDIT_CARD", 5, 24)], text)
    assert counts["CREDIT_CARD:gold"] == 2
    assert counts["CREDIT_CARD:gold_valid"] == 1
    assert counts["CREDIT_CARD:found_valid"] == 1


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


def test_report_marks_live_rows_pending(monkeypatch, tmp_path) -> None:
    # With no live results on disk, the live rows render as pending.
    from guarded_llm_gateway.eval import report

    monkeypatch.setattr(report, "RESULTS_DIR", tmp_path)
    text = render()
    assert "pending live run" in text
    assert pct({"n": 0}) == "n/a"
    assert pct({"n": 10, "rate": 0.5, "low": 0.2, "high": 0.8}) == "50.0% (20.0 to 80.0)"


def test_e2e_runner_records_and_summary(make_gateway, tmp_path) -> None:
    import json as _json

    from guarded_llm_gateway.eval.e2e import run_async

    def leaky(request) -> str:
        # Echo the account context back, the way an injected model might.
        context = (request.instructions or "").split("(internal): ", 1)[1].split("\n", 1)[0]
        return _json.dumps({"answer": f"Sure: {context}", "citations": [], "escalate": False})

    from guarded_llm_gateway.backends import FakeModel
    from guarded_llm_gateway.pii import PresidioPii

    gateway = make_gateway(models=[FakeModel(leaky), FakeModel(leaky)], pii=PresidioPii())
    summary = asyncio.run(
        run_async(live=False, gateway=gateway, configs=("full", "none"), limit=4, out_dir=tmp_path)
    )
    # With no guards the echoed account context leaks. With the gateway the email, phone and
    # card are redacted. Names depend on spaCy's small model, which misses some.
    assert summary["none"]["attack:all"]["pii_leak"]["rate"] == 1.0
    assert summary["full"]["attack:all"]["pii_leak_contact"]["rate"] == 0.0
    assert summary["full"]["errors"] == 0
    assert (tmp_path / "full.jsonl").exists()


def test_faults_table_shows_rates_not_na():
    from guarded_llm_gateway.eval.report import faults_table

    ci = {"k": 13, "rate": 0.065, "low": 0.038, "high": 0.108}
    summary = {
        "primary 30% errors": {
            "n": 200,
            "model_calls_per_request": 1.34,
            "primary": ci,
            "fallback": ci,
            "retrieval_only": ci,
            "503": ci,
        }
    }
    table = faults_table(summary)
    assert "n/a" not in table
    assert "6.5% (3.8 to 10.8)" in table


def _garak_summarize():
    import importlib.util

    from guarded_llm_gateway.paths import ROOT

    spec = importlib.util.spec_from_file_location(
        "garak_summarize", ROOT / "garak" / "summarize.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_garak_summary_counts_each_prompt_once(tmp_path) -> None:
    import json as _json

    from guarded_llm_gateway.pipeline import REFUSAL

    def attempt(seq: int, text: str | None, scores: dict[str, list[float | None]]) -> dict:
        output = None if text is None else {"text": text}
        return {
            "entry_type": "attempt",
            "status": 2,
            "seq": seq,
            "probe_classname": "encoding.InjectHex",
            "outputs": [output],
            "detector_results": scores,
        }

    two = "encoding.DecodeMatch", "encoding.DecodeApprox"
    entries = [
        {"entry_type": "start_run setup", "run.seed": 1},
        # both detectors flag the same prompt: one hit, not two
        attempt(0, "decoded text", {two[0]: [1.0], two[1]: [1.0]}),
        attempt(1, "decoded text", {two[0]: [0.0], two[1]: [0.7]}),
        attempt(2, REFUSAL, {two[0]: [0.0], two[1]: [0.0]}),
        attempt(3, None, {two[0]: [None], two[1]: [None]}),
        # the unscored copy garak writes first must not count
        {**attempt(0, "decoded text", {}), "status": 1},
    ]
    report = tmp_path / "gateway.report.jsonl"
    report.write_text("".join(_json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    cell = _garak_summarize().summarize(report, prompt_cap=40)["probes"]["encoding.InjectHex"]
    assert (cell["k"], cell["n"], cell["skipped"], cell["refused"]) == (2, 3, 1, 1)
    assert 0.0 < cell["low"] < cell["rate"] < cell["high"]
