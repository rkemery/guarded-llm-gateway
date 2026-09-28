"""Public datasets used by the benchmarks, pinned by Hugging Face commit.

Every file is fetched at a fixed revision and checked against the sha256 in
`data/sources.lock.json`, so a benchmark rerun reads the same bytes. Licenses
were checked on each dataset card and the HF API on 2026-09-28 (see
DATA_SOURCES.md). Nothing here needs a token: every source is public and ungated.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from guarded_llm_gateway.paths import DATA_DIR

LOCK_FILE = DATA_DIR / "sources.lock.json"


@dataclass(frozen=True)
class Source:
    key: str
    repo_id: str
    revision: str
    files: tuple[str, ...]
    license: str
    url: str


SOURCES: dict[str, Source] = {
    s.key: s
    for s in (
        Source(
            "deepset",
            "deepset/prompt-injections",
            "4f61ecb038e9c3fb77e21034b22511b523772cdd",
            (
                "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
                "data/test-00000-of-00001-701d16158af87368.parquet",
            ),
            "Apache-2.0",
            "https://huggingface.co/datasets/deepset/prompt-injections",
        ),
        Source(
            "jbb",
            "JailbreakBench/JBB-Behaviors",
            "886acc352a31533ffbcf4ef22c744658688086fc",
            ("data/harmful-behaviors.csv",),
            "MIT",
            "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors",
        ),
        Source(
            "gandalf",
            "Lakera/gandalf_ignore_instructions",
            "04737b65e90a6794ec227012e4a255a7def6344b",
            (
                "data/train-00000-of-00001-ded53be747ff55cd.parquet",
                "data/validation-00000-of-00001-94481a2a09ff2fff.parquet",
                "data/test-00000-of-00001-bc92128b9288a6d1.parquet",
            ),
            "MIT",
            "https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions",
        ),
        Source(
            "llmail",
            "microsoft/llmail-inject-challenge",
            "1063bdf01ec8762b812d5e06ee768a06faa5a6f7",
            ("data/raw_submissions_phase2.jsonl", "data/emails_for_fp_tests.json"),
            "MIT",
            "https://huggingface.co/datasets/microsoft/llmail-inject-challenge",
        ),
        Source(
            "notinject",
            "leolee99/NotInject",
            "847ae76cf8fea5ed325429e569ae8cfef022d2e0",
            (
                "data/NotInject_one-00000-of-00001.parquet",
                "data/NotInject_two-00000-of-00001.parquet",
                "data/NotInject_three-00000-of-00001.parquet",
            ),
            "MIT",
            "https://huggingface.co/datasets/leolee99/NotInject",
        ),
        Source(
            "banking77",
            "legacy-datasets/banking77",
            "f54121560de48f2852f90be299010d1d6dc612ec",
            ("data/test-00000-of-00001.parquet",),
            "CC-BY-4.0",
            "https://huggingface.co/datasets/legacy-datasets/banking77",
        ),
        Source(
            "gretel_pii",
            "gretelai/synthetic_pii_finance_multilingual",
            "7b844d16738527a04264f50214cb426a4cea0897",
            ("data/test-00000-of-00001.parquet",),
            "Apache-2.0",
            "https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual",
        ),
        Source(
            "nemotron_pii",
            "nvidia/Nemotron-PII",
            "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed",
            ("data/test-00000-of-00001.parquet",),
            "CC-BY-4.0",
            "https://huggingface.co/datasets/nvidia/Nemotron-PII",
        ),
    )
}


class SourceIntegrityError(RuntimeError):
    """A downloaded file does not match the sha256 recorded in the lock file."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_lock() -> dict[str, str]:
    if not LOCK_FILE.exists():
        return {}
    return json.loads(LOCK_FILE.read_text(encoding="utf-8"))


def fetch(key: str, filename: str, *, record: bool = False) -> Path:
    """Download one file of a pinned source (or reuse the HF cache) and verify it.

    With `record=True` a file missing from the lock file gets its hash recorded.
    Without it, a file with no recorded hash is refused.
    """
    from huggingface_hub import hf_hub_download

    source = SOURCES[key]
    if filename not in source.files:
        raise KeyError(f"{filename} is not a pinned file of {source.repo_id}")
    path = Path(
        hf_hub_download(
            source.repo_id, filename, repo_type="dataset", revision=source.revision, token=False
        )
    )
    lock = _load_lock()
    lock_key = f"{source.repo_id}@{source.revision}/{filename}"
    digest = sha256_file(path)
    expected = lock.get(lock_key)
    if expected is None:
        if not record:
            raise SourceIntegrityError(f"no sha256 recorded for {lock_key}. Run with --record.")
        lock[lock_key] = digest
        LOCK_FILE.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    elif digest != expected:
        raise SourceIntegrityError(f"sha256 mismatch for {lock_key}: {digest} != {expected}")
    return path
