"""Prompt-injection detectors: two local classifiers and Azure Prompt Shields.

Both local models are DeBERTa-v3-base classifiers (184M parameters each) pinned
to a Hugging Face commit. PIGuard ships custom modeling code and its card says
to load it with `trust_remote_code=True`. We read that code at the pinned
revision: it is a DeBERTa-v2 sequence classifier whose head is one linear layer
on the [CLS] hidden state, with no pooler. `PIGuardClassifier` below
reimplements it in a few lines, so no downloaded code ever runs. A test
(`-m download`) checks that its logits match the remote code at the pinned
revision.

Texts longer than the 512-token window are scored in overlapping windows and
the text gets the maximum window score, so a payload appended after a long
benign article is not truncated away.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any, Protocol

import httpx

PIGUARD_REPO = "leolee99/PIGuard"
PIGUARD_REVISION = "dd78b24e330193a22d2293ac66922dd4f982f563"
DEBERTA_REPO = "protectai/deberta-v3-base-prompt-injection-v2"
DEBERTA_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"

MODEL_SPECS: dict[str, tuple[str, str]] = {
    "piguard": (PIGUARD_REPO, PIGUARD_REVISION),
    "deberta": (DEBERTA_REPO, DEBERTA_REVISION),
}


class Detector(Protocol):
    name: str

    async def score(self, texts: Sequence[str]) -> list[float]:
        """Probability-like injection score in [0, 1] for each text."""
        ...


def _piguard_class() -> Any:
    import torch
    from transformers import DebertaV2ForSequenceClassification
    from transformers.modeling_outputs import SequenceClassifierOutput

    class PIGuardClassifier(DebertaV2ForSequenceClassification):
        """Local copy of modeling_piguard.PIGuard at the pinned revision."""

        def __init__(self, config: Any) -> None:
            super().__init__(config)
            self.classifier = torch.nn.Linear(config.hidden_size, config.num_labels)

        def forward(self, input_ids: Any, attention_mask: Any, **_: Any) -> Any:
            hidden = self.deberta(input_ids=input_ids, attention_mask=attention_mask)
            logits = self.classifier(hidden.last_hidden_state[:, 0, :])
            return SequenceClassifierOutput(logits=logits)

    return PIGuardClassifier


class HFClassifier:
    """A pinned Hugging Face sequence classifier with sliding-window scoring."""

    def __init__(
        self,
        name: str,
        *,
        max_tokens: int = 512,
        stride: int = 384,
        batch_size: int = 16,
        torch_threads: int | None = None,
    ) -> None:
        if name not in MODEL_SPECS:
            raise KeyError(f"unknown detector {name!r}, expected one of {sorted(MODEL_SPECS)}")
        self.name = name
        self.repo, self.revision = MODEL_SPECS[name]
        self.max_tokens = max_tokens
        self.stride = stride
        self.batch_size = batch_size
        self.torch_threads = torch_threads
        self._lock = threading.Lock()

    @cached_property
    def _loaded(self) -> tuple[Any, Any, int]:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        from transformers.utils import logging as hf_logging

        if self.torch_threads:
            torch.set_num_threads(self.torch_threads)
        # PIGuard's config names a custom model type, which makes transformers warn
        # that it is loading it into a DeBERTa-v2 class. That is exactly the intent.
        verbosity = hf_logging.get_verbosity()
        hf_logging.set_verbosity_error()
        try:
            tokenizer = AutoTokenizer.from_pretrained(
                self.repo, revision=self.revision, trust_remote_code=False
            )
            if self.name == "piguard":
                from transformers import DebertaV2Config

                config = DebertaV2Config.from_pretrained(self.repo, revision=self.revision)
                model = _piguard_class().from_pretrained(
                    self.repo, revision=self.revision, config=config
                )
            else:
                model = AutoModelForSequenceClassification.from_pretrained(
                    self.repo, revision=self.revision, trust_remote_code=False
                )
        finally:
            hf_logging.set_verbosity(verbosity)
        model.eval()
        labels = {v.lower(): int(k) for k, v in model.config.id2label.items()}
        positive = labels.get("injection")
        if positive is None:
            raise ValueError(f"{self.repo} has no 'injection' label: {model.config.id2label}")
        return tokenizer, model, positive

    def load(self) -> None:
        _ = self._loaded

    def windows(self, text: str) -> list[list[int]]:
        tokenizer, _, _ = self._loaded
        ids = tokenizer(text, add_special_tokens=False, truncation=False)["input_ids"]
        body = self.max_tokens - 2
        if len(ids) <= body:
            return [ids]
        starts = range(0, max(len(ids) - body, 0) + self.stride, self.stride)
        return [ids[s : s + body] for s in starts if s < len(ids)]

    def score_sync(self, texts: Sequence[str]) -> list[float]:
        import torch

        tokenizer, model, positive = self._loaded
        with self._lock:
            chunks: list[tuple[int, list[int]]] = []
            for i, text in enumerate(texts):
                chunks.extend((i, w) for w in self.windows(text))
            order = sorted(range(len(chunks)), key=lambda j: len(chunks[j][1]))
            chunk_scores = [0.0] * len(chunks)
            cls, sep, pad = tokenizer.cls_token_id, tokenizer.sep_token_id, tokenizer.pad_token_id
            for b in range(0, len(order), self.batch_size):
                batch = order[b : b + self.batch_size]
                seqs = [[cls, *chunks[j][1], sep] for j in batch]
                width = max(len(s) for s in seqs)
                input_ids = torch.tensor([s + [pad] * (width - len(s)) for s in seqs])
                mask = torch.tensor([[1] * len(s) + [0] * (width - len(s)) for s in seqs])
                with torch.inference_mode():
                    logits = model(input_ids=input_ids, attention_mask=mask).logits
                # float64 keeps scores distinct up to a logit margin of about 36. float32
                # rounds to exactly 1.0 past about 17, which would tie the top of the ranking.
                probs = torch.softmax(logits.double(), dim=-1)[:, positive].tolist()
                for j, p in zip(batch, probs, strict=True):
                    chunk_scores[j] = float(p)
            out = [0.0] * len(texts)
            for (i, _), p in zip(chunks, chunk_scores, strict=True):
                out[i] = max(out[i], p)
            return out

    async def score(self, texts: Sequence[str]) -> list[float]:
        return await asyncio.to_thread(self.score_sync, list(texts))


class StaticDetector:
    """Detector with a fixed scoring function, for tests and the offline fake profile."""

    def __init__(self, name: str, fn: Any) -> None:
        self.name = name
        self._fn = fn

    async def score(self, texts: Sequence[str]) -> list[float]:
        return [float(self._fn(t)) for t in texts]


# ---------------------------------------------------------------- Azure Prompt Shields

SHIELD_API_VERSION = "2024-09-01"
SHIELD_MAX_CHARS = 10_000
SHIELD_MAX_DOCS = 5


@dataclass(frozen=True)
class ShieldResult:
    prompt_attack: bool
    document_attacks: tuple[bool, ...]


class PromptShieldsError(RuntimeError):
    """Prompt Shields returned an error or an unexpected body."""


def _chunks(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)] or [""]


class PromptShields:
    """Azure AI Content Safety Prompt Shields over REST, with a result cache.

    POST {endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01 with
    {"userPrompt": str, "documents": [str]}. Inputs over the service limits
    (10K characters of prompt, 5 documents of 10K characters in total per call)
    are split across calls instead of truncated, so padding cannot push an
    attack past the limit. Results are cached by the sha256 of the request,
    in memory and optionally on disk, since the F0 tier allows 5,000 records a
    month. Written against the REST docs and tested with a mock transport only.
    """

    name = "prompt_shields"

    def __init__(
        self,
        endpoint: str,
        key: str,
        *,
        client: httpx.AsyncClient | None = None,
        cache_dir: Path | None = None,
        timeout_s: float = 5.0,
        max_cached: int = 10_000,
    ) -> None:
        self._url = f"{endpoint.rstrip('/')}/contentsafety/text:shieldPrompt"
        self._key = key
        self._client = client or httpx.AsyncClient(timeout=timeout_s)
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._max_cached = max_cached
        self._cache_dir = cache_dir
        self.calls = 0
        self.cache_hits = 0

    def _cache_path(self, key: str) -> Path | None:
        return None if self._cache_dir is None else self._cache_dir / f"{key}.json"

    async def _call(self, prompt: str, documents: list[str]) -> dict[str, Any]:
        body = {"userPrompt": prompt, "documents": documents}
        key = hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()
        if key in self._cache:
            self.cache_hits += 1
            self._cache.move_to_end(key)
            return self._cache[key]
        path = self._cache_path(key)
        if path is not None and path.exists():
            self.cache_hits += 1
            result = json.loads(path.read_text(encoding="utf-8"))
        else:
            self.calls += 1
            response = await self._client.post(
                self._url,
                params={"api-version": SHIELD_API_VERSION},
                headers={"Ocp-Apim-Subscription-Key": self._key},
                json=body,
            )
            if response.status_code != 200:
                raise PromptShieldsError(f"Prompt Shields returned HTTP {response.status_code}")
            result = response.json()
            if "userPromptAnalysis" not in result:
                raise PromptShieldsError("Prompt Shields response has no userPromptAnalysis")
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(result), encoding="utf-8")
        self._cache[key] = result
        if len(self._cache) > self._max_cached:
            self._cache.popitem(last=False)
        return result

    async def analyze(self, prompt: str, documents: Sequence[str] = ()) -> ShieldResult:
        prompt_parts = _chunks(prompt, SHIELD_MAX_CHARS)
        doc_parts = [
            (i, part) for i, d in enumerate(documents) for part in _chunks(d, SHIELD_MAX_CHARS)
        ]
        packs: list[list[tuple[int, str]]] = []
        for item in doc_parts:
            if (
                packs
                and len(packs[-1]) < SHIELD_MAX_DOCS
                and sum(len(p) for _, p in packs[-1]) + len(item[1]) <= SHIELD_MAX_CHARS
            ):
                packs[-1].append(item)
            else:
                packs.append([item])
        prompt_attack = False
        doc_attacks = [False] * len(documents)
        for n in range(max(len(prompt_parts), len(packs))):
            part = prompt_parts[n] if n < len(prompt_parts) else ""
            pack = packs[n] if n < len(packs) else []
            result = await self._call(part, [p for _, p in pack])
            if part:
                prompt_attack |= bool(result["userPromptAnalysis"].get("attackDetected"))
            analyses = result.get("documentsAnalysis") or []
            if len(analyses) != len(pack):
                raise PromptShieldsError("documentsAnalysis length does not match the request")
            for (index, _), analysis in zip(pack, analyses, strict=True):
                doc_attacks[index] |= bool(analysis.get("attackDetected"))
        return ShieldResult(prompt_attack, tuple(doc_attacks))

    async def score(self, texts: Sequence[str]) -> list[float]:
        """Score texts as user prompts (1.0 attack, 0.0 clean), for the detector benchmark."""
        results = [await self.analyze(t) for t in texts]
        return [1.0 if r.prompt_attack else 0.0 for r in results]

    async def aclose(self) -> None:
        await self._client.aclose()
