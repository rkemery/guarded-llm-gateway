"""Deterministic output rules, applied to every model reply before it leaves the gateway.

1. Schema: the reply must parse as `ModelAnswer` JSON (one repair try happens in
   the pipeline). Citations are kept only if they name a retrieved article.
2. Canary: the system prompt carries a random canary token. A reply that
   contains it, in plain, spaced out, reversed or base64 form, is blocked, because
   the model has been talked into dumping its hidden context.
3. Links: markdown images, links, bare URLs and email addresses are kept only
   when their domain is on the allowlist. Images are an exfiltration channel that
   renders without a click, and LLMail-Inject's goal is an email to an outside
   address. Active HTML tags are stripped.
4. PII echo: emails, phone numbers, card numbers, IBANs and SSNs left in the
   answer are redacted unless they are the bank's own published contact details,
   and so is any PII value the gateway redacted from this request's input.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from pydantic import ValidationError

from guarded_llm_gateway.pii import PiiSpan, find_regex_pii, merge_spans
from guarded_llm_gateway.schemas import ModelAnswer

_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)
_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*<?([^)\s>]*)>?(?:\s+[\"'][^\"']*[\"'])?\s*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\(\s*<?([^)\s>]*)>?(?:\s+[\"'][^\"']*[\"'])?\s*\)")
_MD_REF = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+).*$", re.MULTILINE)
_BARE_URL = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)[^\s<>\"'`)\]]+")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
_ACTIVE_HTML = re.compile(
    r"</?\s*(?:a|img|script|iframe|style|svg|object|embed|link|meta|form|input|video|audio|"
    r"source|base|frame|frameset)\b[^>]*>",
    re.IGNORECASE,
)

LINK_REMOVED = "[link removed]"
EMAIL_REMOVED = "[email removed]"


class SchemaError(ValueError):
    """The model reply is not valid ModelAnswer JSON."""


def parse_answer(raw: str) -> ModelAnswer:
    """Parse a model reply into ModelAnswer, tolerating a ```json fence around it."""
    text = _FENCE.sub("", raw.strip())
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"reply is not JSON: {exc.msg} at char {exc.pos}") from exc
    try:
        return ModelAnswer.model_validate(data)
    except ValidationError as exc:
        raise SchemaError(f"reply does not match the schema: {exc.error_count()} errors") from exc


# ---------------------------------------------------------------- canary


def _compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def contains_canary(text: str, canary: str) -> bool:
    """True if the canary (or its random part) shows up plain, spaced, reversed or base64."""
    compact = _compact(text)
    secret = _compact(canary)
    random_part = _compact(canary.rsplit("-", 1)[-1])
    candidates = {secret, random_part, secret[::-1], random_part[::-1]}
    if any(c and len(c) >= 8 and c in compact for c in candidates):
        return True
    encoded = {
        base64.b64encode(canary.encode()).decode().rstrip("="),
        base64.urlsafe_b64encode(canary.encode()).decode().rstrip("="),
    }
    squashed = re.sub(r"\s", "", text)
    return any(e in squashed for e in encoded)


# ---------------------------------------------------------------- links


def host_allowed(url: str, allowed_domains: Iterable[str]) -> bool:
    candidate = url if "://" in url else f"https://{url}"
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if parts.scheme.lower() not in {"http", "https"} or not host:
        return False
    return any(host == d or host.endswith(f".{d}") for d in allowed_domains)


def email_allowed(domain: str, allowed_domains: Iterable[str]) -> bool:
    domain = domain.lower()
    return any(domain == d or domain.endswith(f".{d}") for d in allowed_domains)


@dataclass
class LinkReport:
    text: str
    removed: int = 0


def filter_links(text: str, allowed_domains: Sequence[str]) -> LinkReport:
    removed = 0

    def image(match: re.Match[str]) -> str:
        nonlocal removed
        if host_allowed(match.group(2), allowed_domains):
            return match.group(0)
        removed += 1
        return ""

    def link(match: re.Match[str]) -> str:
        nonlocal removed
        if host_allowed(match.group(2), allowed_domains):
            return match.group(0)
        removed += 1
        return f"{match.group(1)} {LINK_REMOVED}"

    def ref(match: re.Match[str]) -> str:
        nonlocal removed
        if host_allowed(match.group(1), allowed_domains):
            return match.group(0)
        removed += 1
        return ""

    def bare(match: re.Match[str]) -> str:
        nonlocal removed
        url = match.group(0)
        stripped = url.rstrip(".,;:!?")
        if host_allowed(stripped, allowed_domains):
            return url
        removed += 1
        return LINK_REMOVED + url[len(stripped) :]

    def email(match: re.Match[str]) -> str:
        nonlocal removed
        if email_allowed(match.group(1), allowed_domains):
            return match.group(0)
        removed += 1
        return EMAIL_REMOVED

    before_html = text
    text = _ACTIVE_HTML.sub("", text)
    removed += len(_ACTIVE_HTML.findall(before_html))
    text = _MD_IMAGE.sub(image, text)
    text = _MD_LINK.sub(link, text)
    text = _MD_REF.sub(ref, text)
    text = _BARE_URL.sub(bare, text)
    text = _EMAIL.sub(email, text)
    return LinkReport(text, removed)


# ---------------------------------------------------------------- PII echo


def pii_echo_spans(
    text: str, context_values: Iterable[str], allowed_pii: Iterable[str]
) -> list[PiiSpan]:
    """Regex PII in the answer plus verbatim echoes of values redacted from this request."""
    allowed = {_compact(v) for v in allowed_pii}
    spans = [s for s in find_regex_pii(text) if _compact(s.text(text)) not in allowed]
    lowered = text.lower()
    for value in context_values:
        value = value.strip()
        if len(value) < 4:
            continue
        start = lowered.find(value.lower())
        while start != -1:
            spans.append(PiiSpan("ECHO", start, start + len(value)))
            start = lowered.find(value.lower(), start + 1)
    return merge_spans(spans)


# ---------------------------------------------------------------- all rules


@dataclass
class OutputVerdict:
    answer: str
    citations: list[str]
    escalate: bool
    blocked_by: str | None = None
    links_removed: int = 0
    pii_redacted: int = 0
    notes: list[str] = field(default_factory=list)


def apply_output_rules(
    raw_reply: str,
    answer: ModelAnswer,
    *,
    canary: str,
    retrieved_ids: Sequence[str],
    allowed_domains: Sequence[str],
    allowed_pii: Sequence[str],
    context_values: Sequence[str] = (),
) -> OutputVerdict:
    citations = [c for c in answer.citations if c in set(retrieved_ids)]
    if contains_canary(raw_reply, canary):
        return OutputVerdict("", [], False, blocked_by="output_canary")
    links = filter_links(answer.answer, allowed_domains)
    spans = pii_echo_spans(links.text, context_values, allowed_pii)
    text = links.text
    for span in sorted(spans, key=lambda s: s.start, reverse=True):
        label = "PII" if span.entity == "ECHO" else span.entity
        text = f"{text[: span.start]}<{label}>{text[span.end :]}"
    verdict = OutputVerdict(
        text.strip(),
        citations,
        answer.escalate,
        links_removed=links.removed,
        pii_redacted=len(spans),
    )
    if len(citations) != len(answer.citations):
        verdict.notes.append(f"dropped {len(answer.citations) - len(citations)} unknown citations")
    return verdict
