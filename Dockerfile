# syntax=docker/dockerfile:1
# CPU-only image of the gateway. torch comes from the PyTorch CPU index (see
# pyproject.toml). Both 184M-parameter detectors are baked in: the default profile
# runs PIGuard alone, and GATEWAY_DETECTORS can switch to deberta or both.
FROM python:3.11-slim AS build
# git is needed to fetch llm-eval-harness, which is pinned to the v0.1.0 tag.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.8.17 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock .python-version README.md LICENSE ./
RUN uv sync --locked --no-default-groups --no-install-project
COPY src ./src
RUN uv sync --locked --no-default-groups --no-editable

# Bake the pinned detector revisions into the image, so the container runs with
# HF_HUB_OFFLINE=1 and never downloads a model at runtime.
ENV HF_HOME=/app/hf
RUN /app/.venv/bin/python -c "from guarded_llm_gateway.detectors import HFClassifier; [HFClassifier(n).load() for n in ('piguard', 'deberta')]"

FROM python:3.11-slim
RUN useradd --create-home --uid 10001 gateway
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/hf /app/hf
COPY data/tallowbrook ./data/tallowbrook
COPY results/detectors/thresholds.json ./results/detectors/thresholds.json
ENV PATH=/app/.venv/bin:$PATH \
    GATEWAY_ROOT=/app \
    HF_HOME=/app/hf \
    HF_HUB_OFFLINE=1 \
    PYTHONUNBUFFERED=1
USER gateway
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["gateway", "serve", "--host", "0.0.0.0", "--port", "8000"]
