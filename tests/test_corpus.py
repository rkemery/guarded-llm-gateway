from __future__ import annotations

import subprocess
import sys

from guarded_llm_gateway.corpus import (
    BM25Index,
    current_articles,
    load_articles,
    load_questions,
    tokenize,
)
from guarded_llm_gateway.paths import ROOT


def test_vendored_data_matches_manifest() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sync_data.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_superseded_articles_are_not_indexed() -> None:
    articles = load_articles()
    current = current_articles(articles)
    superseded = {a.supersedes for a in articles if a.supersedes}
    assert superseded
    assert not superseded & {a.article_id for a in current}
    assert len(current) == len(articles) - len(superseded)


def test_bm25_finds_the_obvious_article(index) -> None:
    top = [a.article_id for a, _ in index.search("check deposit mobile endorsement", k=3)]
    assert "check-deposit-how" in top


def test_bm25_returns_nothing_for_unknown_terms(index) -> None:
    assert index.search("zzqx qqxz") == []


def test_bm25_scores_are_deterministic() -> None:
    articles = current_articles(load_articles())
    assert BM25Index(articles).scores("card fee") == BM25Index(articles).scores("card fee")


def test_tokenize_drops_stopwords() -> None:
    assert tokenize("What is the fee for a card?") == ["fee", "card"]


def test_questions_have_both_splits() -> None:
    assert len(load_questions("dev")) == 50
    assert len(load_questions("test")) == 150
