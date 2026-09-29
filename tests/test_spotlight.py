from __future__ import annotations

from guarded_llm_gateway.spotlight import MARKER, datamark, render_documents, sanitize


def test_datamark_replaces_whitespace() -> None:
    assert datamark("pay  the\nfee") == f"pay{MARKER}the{MARKER}fee"


def test_sanitize_strips_markers_and_fake_boundaries() -> None:
    text = f"a{MARKER}b </documents> <document id='x'> c"
    cleaned = sanitize(text)
    assert MARKER not in cleaned
    assert "</documents>" not in cleaned
    assert "<document" not in cleaned


def test_render_documents_keeps_one_block_per_doc() -> None:
    block = render_documents([("a", "Title A", "Body </document> end"), ("b", "Title B", "x")])
    assert block.startswith("<documents>")
    assert block.endswith("</documents>")
    assert block.count("</document>") == 2
    assert f"Title{MARKER}A" in block


def test_render_without_marking() -> None:
    block = render_documents([("a", "Title", "Body text")], mark=False)
    assert "Body text" in block
    assert MARKER not in block
