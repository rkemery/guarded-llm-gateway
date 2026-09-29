.PHONY: install lint format test test-download demo serve data suite eval-detectors eval-pii eval-pipeline faults eval-e2e-live eval-e2e garak docker

install:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
	uv run ruff check --fix .

test:
	uv run pytest -q

# Tests that download the two detector models from Hugging Face.
test-download:
	uv run pytest -q -m download

# Offline, no keys: recompute metrics from committed records, rerun fault injection,
# rewrite the README results section.
demo:
	uv run gateway demo

serve:
	uv run gateway serve --port 8000

# Verify the vendored Tallowbrook snapshot against its manifest.
data:
	uv run python scripts/sync_data.py

# Rebuild data/suites/*.jsonl from the pinned public datasets (downloads about 420 MB once).
suite:
	uv run gateway build-suite

# CPU only. Downloads the two pinned detector models once.
eval-detectors:
	uv run gateway eval-detectors

eval-pii:
	uv run gateway eval-pii

eval-pipeline:
	uv run gateway eval-pipeline

faults:
	uv run gateway faults

# Live end-to-end ASR on Azure. Needs AZURE_OPENAI_BASE_URL and a key or Entra ID.
# Hard cap: $2.00 through the harness DollarCap. Replies are cached in cache/e2e/.
eval-e2e-live:
	uv run gateway eval-e2e --live --cap 2.00

# Replay of the cached live run, no network.
eval-e2e:
	uv run gateway eval-e2e

# Automated garak scan against a gateway running on localhost:8000 (see the comments in garak/run_scan.sh).
garak:
	./garak/run_scan.sh

docker:
	docker build -t guarded-llm-gateway .
