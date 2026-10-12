#!/bin/bash
# ExeLens report of one sample. Usage: ./experiments/run_llm_analysis.sh [md5] [exelens args]

set -euo pipefail

MD5="${1:-093fd7bfe7c1d3af0ea7eface7775ea6}"
shift || true
LLM_MODEL="${LLM_MODEL:-gemini-3.1-flash-lite}"
LLM_TOKENS_PER_MINUTE="${LLM_TOKENS_PER_MINUTE:-250000}"
LLM_REQUESTS_PER_MINUTE="${LLM_REQUESTS_PER_MINUTE:-15}"

docker run --rm --env-file .env -e LLM_MODEL="$LLM_MODEL" -e LLM_TOKENS_PER_MINUTE="$LLM_TOKENS_PER_MINUTE" \
    -e LLM_REQUESTS_PER_MINUTE="$LLM_REQUESTS_PER_MINUTE" --user "$(id -u):$(id -g)" \
    -v "$(pwd)/workdir:/usr/exelens/workdir:ro" \
    -v "$(pwd)/experiments/llm_report_analysis/results:/usr/exelens/results:rw" \
    -v "$(pwd)/dataset/APTMalware/samples:/usr/exelens/samples:ro" \
    attilamester/exelens --input "/usr/exelens/workdir/$MD5.cgcompressed.pickle" \
    -o /usr/exelens/results --samples-dir /usr/exelens/samples "$@"
