from __future__ import annotations

import math

import pytest

from guarded_llm_gateway.eval.detector_report import (
    Item,
    evaluate,
    fpr,
    joint_thresholds,
    threshold_at_fpr,
    tune,
)


def test_threshold_keeps_fpr_at_or_below_target() -> None:
    benign = [i / 1000 for i in range(1000)]
    t = threshold_at_fpr(benign, 0.01)
    assert fpr(benign, t) <= 0.01
    assert fpr(benign, math.nextafter(t, -math.inf) - 0.001) > 0.01


def test_threshold_handles_ties_conservatively() -> None:
    benign = [1.0] * 5 + [0.1] * 95
    t = threshold_at_fpr(benign, 0.01)
    assert t > 1.0  # every tied 1.0 would be a false positive, so none may be flagged
    assert fpr(benign, t) == 0.0


def test_joint_thresholds_bound_the_union() -> None:
    benign = [{"a": i / 200, "b": ((i * 37) % 200) / 200} for i in range(200)]
    thresholds = joint_thresholds(benign, ["a", "b"], 0.02)
    union = sum(any(b[n] >= thresholds[n] for n in "ab") for b in benign) / len(benign)
    assert union <= 0.02


def _items() -> list[Item]:
    items = []
    for i in range(300):
        split = "dev" if i % 2 else "test"
        items.append(
            Item(
                f"b{i}",
                {
                    "label": 0,
                    "split": split,
                    "kind": "prompt",
                    "set": "banking77",
                    "category": "benign",
                    "transform": "none",
                    "source": "x",
                },
                f"b{i}",
                {"piguard": i / 1000, "deberta": 0.0},
            )
        )
    for i in range(40):
        split = "dev" if i % 2 else "test"
        items.append(
            Item(
                f"a{i}",
                {
                    "label": 1,
                    "split": split,
                    "kind": "prompt",
                    "set": "attack",
                    "category": "injection",
                    "transform": "none",
                    "source": "s",
                },
                f"g{i // 4}",
                {"piguard": 0.9 if i < 30 else 0.1, "deberta": 0.0},
            )
        )
    return items


def test_tune_uses_dev_and_evaluate_uses_test() -> None:
    items = _items()
    tuned = tune(items)
    assert tuned["prompt"]["n_dev_benign"] == 150
    results = evaluate(items, tuned)
    tpr = results["piguard"]["attack:direct_injection"]
    assert tpr["n"] == 20
    assert tpr["k"] == 15
    fpr_cell = results["piguard"]["benign:banking77"]
    assert fpr_cell["n"] == 150
    assert fpr_cell["rate"] <= 0.02
    assert "Korn-Graubard" in tpr["method"]


def test_rate_needs_values() -> None:
    from guarded_llm_gateway.eval.detector_report import rate

    with pytest.raises(ValueError, match="n must be positive"):
        rate([])


def test_profile_selection_uses_dev_only_and_config_reads_it(tmp_path) -> None:
    import json

    from guarded_llm_gateway.config import load_thresholds
    from guarded_llm_gateway.eval.detector_report import dev_tpr, profiles

    items = _items()
    tuned = tune(items)
    candidates = profiles(tuned)
    assert set(candidates) == {"piguard", "deberta", "combined"}
    assert (
        dev_tpr(items, candidates["piguard"])["prompt"]
        > dev_tpr(items, candidates["deberta"])["prompt"]
    )

    path = tmp_path / "thresholds.json"
    path.write_text(
        json.dumps(
            {
                "detectors": ["piguard"],
                "prompt": {"piguard": 0.7},
                "document": {"piguard": 0.6},
                "profiles": {
                    "combined": {
                        "detectors": ["piguard", "deberta"],
                        "prompt": {"piguard": 0.9, "deberta": 0.99},
                        "document": {"piguard": 0.8, "deberta": 0.98},
                    }
                },
            }
        )
    )
    assert load_thresholds(path)["prompt"] == {"piguard": 0.7}
    both = load_thresholds(path, ("deberta", "piguard"))
    assert both["prompt"] == {"piguard": 0.9, "deberta": 0.99}
    assert load_thresholds(path, ())["detectors"] == []
