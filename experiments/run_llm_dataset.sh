#!/bin/bash
# ExeLens reports of the whole dataset on the free tier, resuming after each daily quota reset. Usage:
#   nohup systemd-inhibit --what=sleep ./experiments/run_llm_dataset.sh > experiments/run_llm_dataset.log 2>&1 &

set -euo pipefail

export LLM_MODEL="${LLM_MODEL:-gemini-3.1-flash-lite}"
export LLM_TOKENS_PER_MINUTE="${LLM_TOKENS_PER_MINUTE:-250000}"
export LLM_REQUESTS_PER_MINUTE="${LLM_REQUESTS_PER_MINUTE:-15}"
RESULTS_DIR="experiments/llm_report_analysis/results"
RUN_LOG="$(mktemp)"
trap 'rm -f "$RUN_LOG"' EXIT

done_count() { { ls "$RESULTS_DIR"/reports/*.json 2>/dev/null || true; } | wc -l; }
TOTAL=$(ls workdir/*.cgcompressed.pickle | wc -l)
progress() { echo "== $(date '+%F %T') $1: $(done_count) of $TOTAL samples done ($LLM_MODEL)"; }

mkdir -p "$RESULTS_DIR"
while true; do
    before=$(done_count)
    progress "run start"
    docker run --rm --name exelens-dataset --env-file .env \
        -e LLM_MODEL -e LLM_TOKENS_PER_MINUTE -e LLM_REQUESTS_PER_MINUTE --user "$(id -u):$(id -g)" \
        -v "$(pwd)/workdir:/usr/exelens/workdir:ro" \
        -v "$(pwd)/$RESULTS_DIR:/usr/exelens/results:rw" \
        -v "$(pwd)/dataset/APTMalware/samples:/usr/exelens/samples:ro" \
        attilamester/exelens --input /usr/exelens/workdir -o /usr/exelens/results \
        --samples-dir /usr/exelens/samples 2>&1 | tee "$RUN_LOG" || true
    progress "run end"

    if [ "$(done_count)" -ge "$TOTAL" ]; then
        break
    elif grep -q "Daily LLM quota used up" "$RUN_LOG"; then
        resume=$(TZ=America/Los_Angeles date -d "tomorrow 00:05" +%s)
        echo "== $(date '+%F %T') daily quota used up, sleeping until $(date -d "@$resume" '+%F %T')"
        sleep $((resume - $(date +%s)))
    elif [ "$(done_count)" -eq "$before" ]; then
        echo "== $(date '+%F %T') no progress and no daily quota stop (e.g. API key, network): giving up"
        exit 1
    fi
done

progress "all done"
docker run --rm -v "$(pwd)/$RESULTS_DIR:/usr/exelens/results:ro" --entrypoint python3 attilamester/exelens \
    -m exelens.core.cost /usr/exelens/results --model "$LLM_MODEL"
