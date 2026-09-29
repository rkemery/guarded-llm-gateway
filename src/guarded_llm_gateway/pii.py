"""PII detection and redaction: a regex-only detector and Presidio with my checksum recognizers.

Both detectors share the Luhn and IBAN (ISO 13616 mod-97) checks below, so the
PII benchmark isolates what Presidio's NER and context scoring add on top of
plain patterns. Presidio ships its own card and IBAN recognizers. I replace
them with mine so the two paths run one implementation that the tests cover.

Runtime NER uses spaCy `en_core_web_sm` (12 MB, CPU). Presidio's default is
`en_core_web_lg` (about 400 MB), which would triple the Docker image for a
model that only feeds PERSON. The PII benchmark reports what the small
model misses.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import cached_property
from typing import Any

# Entities the gateway redacts from user input and account context. LOCATION and
# DATE_TIME are left alone on purpose: country names and dates are what travel
# and dispute questions are about, and spaCy cannot tell a street address from a
# country.
REDACT_ENTITIES = (
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "US_BANK_NUMBER",
    "US_ITIN",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "IP_ADDRESS",
)

# Product and brand words that spaCy's small model sometimes tags as PERSON or ORG.
ALLOW_LIST = (
    "Tallowbrook",
    "BrookLink",
    "BrookPay",
    "Cushion",
    "Savings Pockets",
    "Basic",
    "Plus",
    "Premium",
)


@dataclass(frozen=True)
class PiiSpan:
    entity: str
    start: int
    end: int
    score: float = 1.0

    def text(self, source: str) -> str:
        return source[self.start : self.end]


# ---------------------------------------------------------------- checksums


def luhn_valid(number: str) -> bool:
    """Luhn mod-10 check on the digits of `number` (separators ignored), 13 to 19 digits."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# ISO 13616 lengths for the countries most likely in a US bank's support traffic.
# Others fall back to the generic 15 to 34 range.
_IBAN_LENGTHS = {
    "AT": 20, "BE": 16, "CH": 21, "DE": 22, "DK": 18, "ES": 24, "FI": 18, "FR": 27,
    "GB": 22, "IE": 22, "IT": 27, "LU": 20, "NL": 18, "NO": 15, "PL": 28, "PT": 25,
    "SE": 24,
}  # fmt: skip


def iban_valid(candidate: str) -> bool:
    """ISO 13616 IBAN check: country length where known, then mod-97 == 1."""
    iban = re.sub(r"[\s-]", "", candidate).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", iban):
        return False
    expected = _IBAN_LENGTHS.get(iban[:2])
    if expected is not None and len(iban) != expected:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def ssn_valid(candidate: str) -> bool:
    """US SSN structure rules: no 000, 666 or 9xx area, no 00 group, no 0000 serial."""
    digits = re.sub(r"\D", "", candidate)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in {"000", "666"} and area[0] != "9" and group != "00" and serial != "0000"


# ---------------------------------------------------------------- regex-only detector

CARD_PATTERN = r"\b(?:\d[ -]?){12,18}\d\b"
IBAN_PATTERN = r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}\b"
EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"
PHONE_PATTERN = (
    r"(?<![\w-])(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?![\w-])"
    r"|(?<![\w-])\+\d{1,3}(?:[ .-]?\d{2,4}){2,5}(?![\w-])"
)
SSN_PATTERN = r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"

_REGEX_RULES: tuple[tuple[str, re.Pattern[str], Any], ...] = (
    ("CREDIT_CARD", re.compile(CARD_PATTERN), luhn_valid),
    ("IBAN_CODE", re.compile(IBAN_PATTERN), iban_valid),
    ("EMAIL_ADDRESS", re.compile(EMAIL_PATTERN), None),
    ("US_SSN", re.compile(SSN_PATTERN), ssn_valid),
    ("PHONE_NUMBER", re.compile(PHONE_PATTERN), None),
)


def find_regex_pii(text: str) -> list[PiiSpan]:
    """Regex-only PII finder: cards (Luhn), IBANs (mod-97), emails, US SSNs, phone numbers."""
    spans: list[PiiSpan] = []
    for entity, pattern, validator in _REGEX_RULES:
        for match in pattern.finditer(text):
            if validator is None or validator(match.group()):
                spans.append(PiiSpan(entity, match.start(), match.end()))
    return merge_spans(spans)


def merge_spans(spans: Iterable[PiiSpan]) -> list[PiiSpan]:
    """Resolve overlaps: keep the higher-scoring span, then the longer, then the earlier.

    The entity name breaks the remaining ties. Presidio returns equal-score results
    in an order that depends on Python's hash seed, so without it the same text can
    redact differently from one process to the next.
    """
    ordered = sorted(spans, key=lambda s: (-s.score, -(s.end - s.start), s.start, s.entity))
    kept: list[PiiSpan] = []
    for span in ordered:
        if all(span.end <= k.start or span.start >= k.end for k in kept):
            kept.append(span)
    return sorted(kept, key=lambda s: s.start)


def redact(text: str, spans: Sequence[PiiSpan]) -> str:
    """Replace each span with <ENTITY>. Spans must not overlap (see merge_spans)."""
    out, cursor = [], 0
    for span in sorted(spans, key=lambda s: s.start):
        out.append(text[cursor : span.start])
        out.append(f"<{span.entity}>")
        cursor = span.end
    out.append(text[cursor:])
    return "".join(out)


# ---------------------------------------------------------------- Presidio


def _checksum_recognizers() -> list[Any]:
    from presidio_analyzer import Pattern, PatternRecognizer

    class LuhnCardRecognizer(PatternRecognizer):
        def __init__(self) -> None:
            super().__init__(
                supported_entity="CREDIT_CARD",
                name="LuhnCardRecognizer",
                patterns=[Pattern("card", CARD_PATTERN, 0.3)],
                context=["card", "credit", "debit", "visa", "mastercard", "amex"],
            )

        def validate_result(self, pattern_text: str) -> bool:
            return luhn_valid(pattern_text)

    class IbanChecksumRecognizer(PatternRecognizer):
        def __init__(self) -> None:
            super().__init__(
                supported_entity="IBAN_CODE",
                name="IbanChecksumRecognizer",
                patterns=[Pattern("iban", IBAN_PATTERN, 0.3)],
                context=["iban", "bank", "transfer", "account"],
            )

        def validate_result(self, pattern_text: str) -> bool:
            return iban_valid(pattern_text)

    return [LuhnCardRecognizer(), IbanChecksumRecognizer()]


class PresidioPii:
    """Presidio AnalyzerEngine on spaCy, with my card and IBAN recognizers swapped in."""

    def __init__(
        self,
        spacy_model: str = "en_core_web_sm",
        entities: Sequence[str] = REDACT_ENTITIES,
        allow_list: Sequence[str] = ALLOW_LIST,
    ) -> None:
        self.spacy_model = spacy_model
        self.entities = list(entities)
        self.allow_list = list(allow_list)

    @cached_property
    def analyzer(self) -> Any:
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        nlp_engine = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": self.spacy_model}],
            }
        ).create_engine()
        registry = RecognizerRegistry(supported_languages=["en"])
        registry.load_predefined_recognizers(nlp_engine=nlp_engine, languages=["en"])
        registry.remove_recognizer("CreditCardRecognizer")
        registry.remove_recognizer("IbanRecognizer")
        for recognizer in _checksum_recognizers():
            registry.add_recognizer(recognizer)
        return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry, supported_languages=["en"])

    def find(self, text: str, entities: Sequence[str] | None = None) -> list[PiiSpan]:
        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=list(entities or self.entities),
            allow_list=self.allow_list,
        )
        return merge_spans(PiiSpan(r.entity_type, r.start, r.end, r.score) for r in results)

    def warm_up(self) -> None:
        self.find("warm up call for John Smith at john@example.com")
