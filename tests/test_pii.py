from __future__ import annotations

import pytest

from guarded_llm_gateway.pii import (
    PiiSpan,
    PresidioPii,
    find_regex_pii,
    iban_valid,
    luhn_valid,
    merge_spans,
    redact,
    ssn_valid,
)


@pytest.mark.parametrize(
    ("number", "valid"),
    [
        ("4111 1111 1111 1111", True),
        ("4111-1111-1111-1112", False),
        ("5500 0000 0000 0004", True),
        ("3782 822463 10005", True),
        ("1234", False),
    ],
)
def test_luhn(number: str, valid: bool) -> None:
    assert luhn_valid(number) is valid


@pytest.mark.parametrize(
    ("iban", "valid"),
    [
        ("GB82 WEST 1234 5698 7654 32", True),
        ("GB82WEST12345698765433", False),
        ("DE89 3704 0044 0532 0130 00", True),
        ("DE89 3704 0044 0532 0130", False),  # wrong length for DE
        ("NOT AN IBAN", False),
    ],
)
def test_iban(iban: str, valid: bool) -> None:
    assert iban_valid(iban) is valid


def test_ssn_structure_rules() -> None:
    assert ssn_valid("123-45-6789")
    assert not ssn_valid("000-12-3456")
    assert not ssn_valid("666-12-3456")
    assert not ssn_valid("912-12-3456")
    assert not ssn_valid("123-00-4567")


def test_regex_finds_checksummed_ids_and_contacts() -> None:
    text = (
        "card 4111 1111 1111 1111, bad card 4111 1111 1111 1112, IBAN GB82 WEST 1234 5698 7654 32, "
        "mail jo@example.com, call (555) 010-1234"
    )
    found = {(s.entity, s.text(text)) for s in find_regex_pii(text)}
    assert ("CREDIT_CARD", "4111 1111 1111 1111") in found
    assert ("IBAN_CODE", "GB82 WEST 1234 5698 7654 32") in found
    assert ("EMAIL_ADDRESS", "jo@example.com") in found
    assert ("PHONE_NUMBER", "(555) 010-1234") in found
    assert not any("1112" in value for _, value in found)


def test_merge_prefers_higher_score_then_longer() -> None:
    spans = [PiiSpan("A", 0, 10, 0.5), PiiSpan("B", 5, 8, 0.9), PiiSpan("C", 12, 14, 0.1)]
    assert [s.entity for s in merge_spans(spans)] == ["B", "C"]


def test_redact_replaces_spans_with_type() -> None:
    text = "email jo@example.com now"
    assert redact(text, find_regex_pii(text)) == "email <EMAIL_ADDRESS> now"


@pytest.fixture(scope="module")
def presidio() -> PresidioPii:
    return PresidioPii()


def test_presidio_uses_our_checksum_recognizers(presidio: PresidioPii) -> None:
    names = {r.name for r in presidio.analyzer.registry.recognizers}
    assert {"LuhnCardRecognizer", "IbanChecksumRecognizer"} <= names
    assert "CreditCardRecognizer" not in names
    assert "IbanRecognizer" not in names


def test_presidio_redacts_names_but_not_brand_words(presidio: PresidioPii) -> None:
    text = "Hi, I'm John Smith. My Tallowbrook Plus card 4111 1111 1111 1111 was stolen in France."
    redacted = redact(text, presidio.find(text))
    assert "John Smith" not in redacted
    assert "4111" not in redacted
    assert "Tallowbrook Plus" in redacted
    assert "France" in redacted  # LOCATION is not redacted on purpose


def test_merge_is_independent_of_input_order() -> None:
    import itertools

    spans = [
        PiiSpan("US_SSN", 5, 14, 0.05),
        PiiSpan("US_BANK_NUMBER", 5, 14, 0.05),
        PiiSpan("PERSON", 20, 25, 0.85),
    ]
    results = {tuple(merge_spans(list(p))) for p in itertools.permutations(spans)}
    assert len(results) == 1
