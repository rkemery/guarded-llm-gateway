#!/usr/bin/env bash
# Run the garak scan against a gateway that is already listening on 127.0.0.1:8000,
# then write results/garak/summary.json for the README.
#
# Live run (costs money, about 500 model calls at the soft cap below):
#   GATEWAY_BACKEND=azure GATEWAY_RATE_LIMIT=10000/minute GATEWAY_TOKEN_BUDGET_PER_MINUTE=10000000 \
#   GATEWAY_API_KEYS=garak-scan GATEWAY_DOLLAR_CAP_USD=1.00 GATEWAY_CACHE_DIR=cache/garak \
#     uv run gateway serve --port 8000 &
#   make garak
#
# Offline smoke test of the wiring (fake model, results mean nothing):
#   GATEWAY_DETECTORS= GATEWAY_API_KEYS=garak-scan uv run gateway serve --port 8000 &
#   GARAK_PROMPT_CAP=2 make garak
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
cap="${GARAK_PROMPT_CAP:-40}"
spec="${GARAK_SPEC:-probes.promptinject,probes.latentinjection.LatentInjectionReport,probes.latentinjection.LatentInjectionResume,probes.latentinjection.LatentInjectionFactSnippetEiffel,probes.latentinjection.LatentWhois,probes.web_injection.MarkdownImageExfil,probes.web_injection.StringAssemblyDataExfil,probes.web_injection.MarkdownXSS,probes.encoding.InjectBase64,probes.encoding.InjectHex}"

if ! curl -fsS http://127.0.0.1:8000/healthz > /dev/null; then
  echo "run_scan: no gateway on 127.0.0.1:8000. Start one first (see the comments in this file)." >&2
  exit 1
fi

export REST_API_KEY="${REST_API_KEY:-garak-scan}"
# garak writes reports under $XDG_DATA_HOME/garak/garak_runs.
export XDG_DATA_HOME="$here/runs"
prefix="gateway-$(date -u +%Y%m%dT%H%M%SZ)"
# mktemp -d works on both GNU and BSD (macOS), --suffix is GNU-only.
tmpdir="$(mktemp -d)"
config="$tmpdir/gateway.yaml"
trap 'rm -rf "$tmpdir"' EXIT
sed "s/soft_probe_prompt_cap: .*/soft_probe_prompt_cap: $cap/" "$here/gateway.yaml" > "$config"

uv run --project "$here" garak --config "$config" --spec "$spec" --report_prefix "$prefix"

report="$(find "$here/runs" -name "$prefix.report.jsonl" | head -1)"
if [ -z "$report" ]; then
  echo "run_scan: garak wrote no report for $prefix" >&2
  exit 1
fi
uv run --project "$root" python "$here/summarize.py" "$report" --prompt-cap "$cap"
