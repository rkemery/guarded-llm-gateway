"""The vendored Tallowbrook help center and a small Okapi BM25 retriever.

BM25 is about forty lines of standard library, so the gateway needs neither the
RAG repo's code nor a search dependency. Superseded article versions are left
out of the index, the way a maintained help center would serve only current
policy.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from guarded_llm_gateway.paths import TALLOWBROOK_DIR

_TOKEN = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "but",
        "by",
        "can",
        "do",
        "does",
        "for",
        "from",
        "how",
        "i",
        "if",
        "in",
        "is",
        "it",
        "its",
        "my",
        "of",
        "on",
        "or",
        "our",
        "so",
        "that",
        "the",
        "their",
        "there",
        "this",
        "to",
        "was",
        "we",
        "what",
        "when",
        "where",
        "which",
        "who",
        "will",
        "with",
        "you",
        "your",
    ]
)


@dataclass(frozen=True)
class Article:
    article_id: str
    title: str
    section: str
    body: str
    supersedes: str | None = None

    @property
    def url(self) -> str:
        return f"https://help.tallowbrook.example/articles/{self.article_id}"


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOPWORDS]


def load_articles(path: Path = TALLOWBROOK_DIR / "articles.jsonl") -> list[Article]:
    articles = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            articles.append(
                Article(
                    article_id=row["article_id"],
                    title=row["title"],
                    section=row["section"],
                    body=row["body"],
                    supersedes=row.get("supersedes"),
                )
            )
    return articles


def current_articles(articles: Iterable[Article]) -> list[Article]:
    """Drop every article that a newer version supersedes."""
    articles = list(articles)
    superseded = {a.supersedes for a in articles if a.supersedes}
    return [a for a in articles if a.article_id not in superseded]


def load_questions(split: str) -> list[dict[str, object]]:
    path = TALLOWBROOK_DIR / f"questions_{split}.jsonl"
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


class BM25Index:
    """Okapi BM25 (k1=1.5, b=0.75) over title plus body."""

    def __init__(self, articles: Sequence[Article], k1: float = 1.5, b: float = 0.75) -> None:
        if not articles:
            raise ValueError("cannot index an empty corpus")
        self.articles = list(articles)
        self.k1 = k1
        self.b = b
        self._tfs = [Counter(tokenize(f"{a.title} {a.body}")) for a in self.articles]
        self._lengths = [sum(tf.values()) for tf in self._tfs]
        self._avg_len = sum(self._lengths) / len(self._lengths)
        df: Counter[str] = Counter()
        for tf in self._tfs:
            df.update(tf.keys())
        n = len(self.articles)
        self._idf = {term: math.log(1 + (n - d + 0.5) / (d + 0.5)) for term, d in df.items()}

    def scores(self, query: str) -> list[float]:
        terms = tokenize(query)
        out = []
        for tf, length in zip(self._tfs, self._lengths, strict=True):
            norm = self.k1 * (1 - self.b + self.b * length / self._avg_len)
            score = 0.0
            for term in terms:
                freq = tf.get(term)
                if freq:
                    score += self._idf[term] * freq * (self.k1 + 1) / (freq + norm)
            out.append(score)
        return out

    def search(self, query: str, k: int = 3) -> list[tuple[Article, float]]:
        """Top-k articles with a positive score, best first. Ties break by article order."""
        scored = [(s, i) for i, s in enumerate(self.scores(query)) if s > 0]
        scored.sort(key=lambda pair: (-pair[0], pair[1]))
        return [(self.articles[i], s) for s, i in scored[:k]]


def default_index() -> BM25Index:
    return BM25Index(current_articles(load_articles()))
