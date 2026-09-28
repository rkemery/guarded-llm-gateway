"""Vendor and verify the pinned Tallowbrook dataset snapshot in data/tallowbrook/.

    uv run python scripts/sync_data.py              # verify against MANIFEST.json
    uv run python scripts/sync_data.py --from DIR   # copy from a checkout, rewrite the manifest

Copy mode refuses a source checkout that is not at the pinned commit or has
uncommitted changes to the vendored files, so the manifest always names the
commit the files came from. The dataset's canonical home will be a Hugging Face
dataset. Until it is published there, the source is a git checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "data" / "tallowbrook"
PINNED_COMMIT = "3c72058e8cc7d5dd6e224ecdec7b814341a3d48f"
# source path in neobank-support-data -> vendored file name
FILES = {
    "corpus/articles.jsonl": "articles.jsonl",
    "rag/questions_dev.jsonl": "questions_dev.jsonl",
    "rag/questions_test.jsonl": "questions_test.jsonl",
}


class SyncError(RuntimeError):
    """Vendored data does not match its manifest, or the source is not the pinned commit."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(dest: Path = DEST) -> list[str]:
    """Check every vendored file against MANIFEST.json and return the verified names."""
    manifest = json.loads((dest / "MANIFEST.json").read_text(encoding="utf-8"))
    problems = []
    for entry in manifest["files"]:
        path = dest / entry["path"]
        if not path.exists():
            problems.append(f"missing {entry['path']}")
        elif sha256(path) != entry["sha256"]:
            problems.append(f"sha256 mismatch for {entry['path']}")
    if manifest.get("source_commit") != PINNED_COMMIT:
        named = manifest.get("source_commit")
        problems.append(f"manifest names commit {named}, not {PINNED_COMMIT}")
    if problems:
        raise SyncError("; ".join(problems))
    return sorted(entry["path"] for entry in manifest["files"])


def _git(source: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *args], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def copy_from(source: Path, dest: Path = DEST) -> None:
    head = _git(source, "rev-parse", "HEAD")
    if head != PINNED_COMMIT:
        raise SyncError(f"{source} is at {head}, expected the pinned commit {PINNED_COMMIT}")
    dirty = _git(source, "status", "--porcelain", "--", *FILES)
    if dirty:
        raise SyncError(f"{source} has uncommitted changes to vendored files:\n{dirty}")
    dest.mkdir(parents=True, exist_ok=True)
    entries = []
    for src_rel, name in FILES.items():
        shutil.copyfile(source / src_rel, dest / name)
        entries.append({"path": name, "source_path": src_rel, "sha256": sha256(dest / name)})
    manifest = {
        "dataset": "Tallowbrook Neobank Support (synthetic)",
        "license": "CC-BY-4.0",
        "source_repo": "neobank-support-data",
        "source_commit": PINNED_COMMIT,
        "files": entries,
    }
    (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from", dest="source", type=Path, help="neobank-support-data checkout")
    args = parser.parse_args(argv)
    try:
        if args.source is not None:
            copy_from(args.source)
        names = verify()
    except (SyncError, subprocess.CalledProcessError, OSError) as exc:
        print(f"sync_data: {exc}", file=sys.stderr)
        return 1
    print(f"sync_data: {len(names)} files match MANIFEST.json at {PINNED_COMMIT[:7]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
