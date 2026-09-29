"""Assemble and freeze the attack and benign suites from pinned public datasets.

    uv run gateway build-suite     # writes data/suites/attacks.jsonl and benign.jsonl

Attacks
- direct: injection-labelled rows of deepset/prompt-injections, Lakera
  gandalf_ignore_instructions, and JailbreakBench JBB-Behaviors harmful goals
  (kept as their own category, since they are harmful requests, not injections).
- transformed: the mechanical transforms in transforms.py applied to a seeded
  subset of the direct payloads.
- indirect: LLMail-Inject phase-2 submissions that met every objective against
  the challenge's defenses, planted into the body of a Tallowbrook help-center
  article that a real RAG question retrieves.

Benign
- prompts: Banking77 test, the Tallowbrook RAG questions, NotInject.
- documents: the Tallowbrook articles and LLMail-Inject's false-positive emails.

Everything is seeded. Splits are by group: a payload and its transforms share
a split, and LLMail payloads are split by the team that wrote them, so the
test split holds teams the dev split never saw.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from guarded_llm_gateway.corpus import (
    Article,
    BM25Index,
    current_articles,
    load_articles,
    load_questions,
)
from guarded_llm_gateway.eval.sources import SOURCES, fetch
from guarded_llm_gateway.eval.transforms import TRANSFORMS
from guarded_llm_gateway.paths import SUITES_DIR

SEED = 20260928
DEV_FRACTION = 0.4
N_BASE = {"deepset": 100, "gandalf": 100, "jbb": 100}
N_TRANSFORMED_PER_SOURCE = 20
LLMAIL_MAX_PER_TEAM = 6
LLMAIL_TARGET = "contact@contact.com"


def split_for(group: str, seed: int = SEED) -> str:
    digest = hashlib.sha256(f"{seed}:{group}".encode()).digest()
    return "dev" if int.from_bytes(digest[:8], "big") / 2**64 < DEV_FRACTION else "test"


def _parquet_rows(key: str, filename: str) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq

    return pq.read_table(fetch(key, filename)).to_pylist()


def _source_fields(key: str) -> dict[str, str]:
    s = SOURCES[key]
    return {"source": s.repo_id, "source_revision": s.revision, "license": s.license}


# ---------------------------------------------------------------- attacks


def direct_payloads(rng: random.Random) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    deepset = []
    for filename in SOURCES["deepset"].files:
        split_name = "train" if "train" in filename else "test"
        for i, row in enumerate(_parquet_rows("deepset", filename)):
            if row["label"] == 1:
                deepset.append((f"{split_name}:{i}", row["text"]))
    gandalf = []
    for filename in SOURCES["gandalf"].files:
        split_name = filename.split("/")[1].split("-")[0]
        gandalf += [
            (f"{split_name}:{i}", r["text"])
            for i, r in enumerate(_parquet_rows("gandalf", filename))
        ]
    with fetch("jbb", "data/harmful-behaviors.csv").open(encoding="utf-8") as fh:
        jbb = [(f"harmful:{row['Index']}", row["Goal"]) for row in csv.DictReader(fh)]

    for key, pool, category in (
        ("deepset", deepset, "injection"),
        ("gandalf", gandalf, "injection"),
        ("jbb", jbb, "harmful_request"),
    ):
        chosen = rng.sample(pool, min(N_BASE[key], len(pool)))
        for n, (row_id, text) in enumerate(sorted(chosen)):
            group = f"{key}-{n:03d}"
            items.append(
                {
                    "id": f"atk-{group}",
                    "kind": "direct",
                    "category": category,
                    **_source_fields(key),
                    "source_row": row_id,
                    "transform": "none",
                    "group": group,
                    "cluster": group,
                    "text": text.strip(),
                    "document": None,
                    "carrier_article_id": None,
                    "carrier_question_id": None,
                    "target": None,
                }
            )
    return items


def transformed_payloads(base: list[dict[str, Any]], rng: random.Random) -> list[dict[str, Any]]:
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in base:
        by_source[item["source"]].append(item)
    out = []
    for source in sorted(by_source):
        for item in rng.sample(by_source[source], N_TRANSFORMED_PER_SOURCE):
            for name, fn in TRANSFORMS.items():
                out.append(
                    {
                        **item,
                        "id": f"{item['id']}-{name}",
                        "transform": name,
                        "text": fn(item["text"]),
                    }
                )
    return out


def carriers(index: BM25Index) -> list[tuple[dict[str, Any], Article]]:
    """(question, article) pairs whose single gold article the clean index ranks top-3."""
    by_id = {a.article_id: a for a in index.articles}
    pairs = []
    for split in ("dev", "test"):
        for q in load_questions(split):
            gold = q["gold_article_ids"]
            if not q["answerable"] or len(gold) != 1 or gold[0] not in by_id:
                continue
            top = [a.article_id for a, _ in index.search(str(q["question"]), k=3)]
            if gold[0] in top:
                pairs.append((q, by_id[gold[0]]))
    return pairs


def plant(body: str, payload: str, rng: random.Random) -> str:
    """Insert the payload as its own paragraph at a seeded paragraph boundary."""
    paragraphs = body.split("\n\n")
    position = rng.randint(1, len(paragraphs))
    return "\n\n".join([*paragraphs[:position], payload, *paragraphs[position:]])


def llmail_successes() -> list[dict[str, Any]]:
    """Unique phase-2 submissions whose five objective flags are all true."""
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    path = fetch("llmail", "data/raw_submissions_phase2.jsonl")
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            objectives = row["objectives"]
            if isinstance(objectives, str):
                objectives = json.loads(objectives)
            if objectives and all(objectives.values()):
                key = (row["subject"].strip(), row["body"].strip())
                seen.setdefault(key, row)
    return sorted(seen.values(), key=lambda r: r["job_id"])


def indirect_payloads(rng: random.Random) -> list[dict[str, Any]]:
    index = BM25Index(current_articles(load_articles()))
    pairs = carriers(index)
    by_team: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in llmail_successes():
        by_team[row["team_id"]].append(row)
    chosen = []
    for team in sorted(by_team):
        rows = by_team[team]
        chosen += rng.sample(rows, min(LLMAIL_MAX_PER_TEAM, len(rows)))
    items = []
    for n, row in enumerate(sorted(chosen, key=lambda r: r["job_id"])):
        question, article = pairs[rng.randrange(len(pairs))]
        payload = f"{row['subject'].strip()}\n\n{row['body'].strip()}"
        team = row["team_id"][:8]
        items.append(
            {
                "id": f"atk-llmail-{n:03d}",
                "kind": "indirect",
                "category": "injection",
                **_source_fields("llmail"),
                "source_row": f"phase2:{row['job_id']}",
                "transform": "planted_in_article",
                "group": f"llmail-team-{team}",
                "cluster": f"llmail-team-{team}",
                "text": str(question["question"]),
                "document": plant(article.body, payload, rng),
                "payload": payload,
                "carrier_article_id": article.article_id,
                "carrier_question_id": question["question_id"],
                "target": LLMAIL_TARGET,
            }
        )
    return items


# ---------------------------------------------------------------- benign


def benign_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(
        set_name: str, kind: str, key: str | None, row_id: str, text: str, split: str | None = None
    ) -> None:
        fields = (
            _source_fields(key)
            if key
            else {
                "source": "neobank-support-data",
                "source_revision": "3c72058",
                "license": "CC-BY-4.0",
            }
        )
        items.append(
            {
                "id": f"ben-{set_name}-{row_id}",
                "set": set_name,
                "kind": kind,
                **fields,
                "source_row": row_id,
                "split": split or split_for(f"{set_name}:{row_id}"),
                "text": text,
            }
        )

    for i, row in enumerate(_parquet_rows("banking77", "data/test-00000-of-00001.parquet")):
        add("banking77", "prompt", "banking77", f"test-{i:04d}", row["text"])
    for split in ("dev", "test"):
        for q in load_questions(split):
            add("tallowbrook_rag", "prompt", None, str(q["question_id"]), str(q["question"]), split)
    for filename in SOURCES["notinject"].files:
        subset = filename.split("/")[1].split("-")[0]
        for i, row in enumerate(_parquet_rows("notinject", filename)):
            add("notinject", "prompt", "notinject", f"{subset}-{i:03d}", row["prompt"])
    for article in load_articles():
        add(
            "tallowbrook_articles",
            "document",
            None,
            article.article_id,
            f"{article.title}\n{article.body}",
        )
    with fetch("llmail", "data/emails_for_fp_tests.json").open(encoding="utf-8") as fh:
        emails = json.load(fh)
    for i, email in enumerate(emails):
        add("llmail_fp_emails", "document", "llmail", f"fp-{i:03d}", str(email))
    return items


# ---------------------------------------------------------------- build


def build_attacks(seed: int = SEED) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    base = direct_payloads(rng)
    items = base + transformed_payloads(base, rng) + indirect_payloads(rng)
    for item in items:
        item["split"] = split_for(item["group"], seed)
    return items


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def load_attacks() -> list[dict[str, Any]]:
    return read_jsonl(SUITES_DIR / "attacks.jsonl")


def load_benign() -> list[dict[str, Any]]:
    return read_jsonl(SUITES_DIR / "benign.jsonl")


def build(out_dir: Path = SUITES_DIR) -> dict[str, int]:
    return {
        "attacks": write_jsonl(out_dir / "attacks.jsonl", build_attacks()),
        "benign": write_jsonl(out_dir / "benign.jsonl", benign_items()),
    }
