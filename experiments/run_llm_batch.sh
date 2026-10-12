#!/bin/bash
# ExeLens reports of a batch of samples. Usage: ./experiments/run_llm_batch.sh [batch.csv]

set -euo pipefail

BATCH_CSV="${1:-experiments/llm_report_analysis/batch100.csv}"
LLM_MODEL="${LLM_MODEL:-gemini-3.1-flash-lite}"
LLM_TOKENS_PER_MINUTE="${LLM_TOKENS_PER_MINUTE:-250000}"
LLM_REQUESTS_PER_MINUTE="${LLM_REQUESTS_PER_MINUTE:-10}"
BATCH_DIR="workdir/$(basename "$BATCH_CSV" .csv)"
RESULTS_DIR="experiments/llm_report_analysis/results"

exelens() {
    docker run --rm --env-file .env -e LLM_MODEL="$LLM_MODEL" -e LLM_TOKENS_PER_MINUTE="$LLM_TOKENS_PER_MINUTE" \
        -e LLM_REQUESTS_PER_MINUTE="$LLM_REQUESTS_PER_MINUTE" --user "$(id -u):$(id -g)" \
        -v "$(pwd)/$BATCH_DIR:/usr/exelens/workdir:ro" \
        -v "$(pwd)/$RESULTS_DIR:/usr/exelens/results:rw" \
        -v "$(pwd)/dataset/APTMalware/samples:/usr/exelens/samples:ro" \
        "$@"
}

echo "== 1. Staging the dumps of $BATCH_CSV into $BATCH_DIR"
mkdir -p "$BATCH_DIR" "$RESULTS_DIR"
tail -n +2 "$BATCH_CSV" | cut -d, -f1 | while read -r md5; do
    [ -f "$BATCH_DIR/$md5.cgcompressed.pickle" ] || cp "workdir/$md5.cgcompressed.pickle" "$BATCH_DIR/"
done
echo "$(ls "$BATCH_DIR" | wc -l) dumps staged"

echo "== 2. Building drawings and contexts (no LLM call)"
exelens attilamester/exelens --input /usr/exelens/workdir -o /usr/exelens/results \
    --samples-dir /usr/exelens/samples --prompt-only || echo "Some contexts failed (see above)"
exelens --entrypoint python3 attilamester/exelens -m exelens.core.cost /usr/exelens/results --model "$LLM_MODEL"

read -r -p "== 3. Call $LLM_MODEL for the samples without a report? [y/N] " answer
[ "$answer" = "y" ] || exit 0
exelens attilamester/exelens --input /usr/exelens/workdir -o /usr/exelens/results \
    --samples-dir /usr/exelens/samples || echo "Some samples failed (see above); re-run to retry them"

exelens --entrypoint python3 attilamester/exelens -m exelens.core.cost /usr/exelens/results --model "$LLM_MODEL"
exelens --entrypoint python3 attilamester/exelens -m exelens.core.grounding /usr/exelens/results
