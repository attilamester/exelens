#!/bin/bash
# Call-graph dumps and SVGs of every unzipped sample (no LLM call).
# Usage: ./experiments/run_batch.sh [samples_dir] [workdir]

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLES_DIR="${1:-$REPO_ROOT/dataset/APTMalware/samples}"
WORKDIR="${2:-$REPO_ROOT/workdir}"
IMAGE="exelens:test"
LOG_FILE="$REPO_ROOT/experiments/run_batch.log"

mkdir -p "$WORKDIR"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Building $IMAGE ..."
    docker build -f "$REPO_ROOT/build/Dockerfile" -t "$IMAGE" "$REPO_ROOT"
fi

total=0
done_now=0
skipped_cached=0
failed=0

while IFS= read -r -d '' sample; do
    total=$((total + 1))
    sample_md5=$(md5sum "$sample" | cut -d' ' -f1)
    svg="$WORKDIR/drawing/$sample_md5.cg-sfdp.svg"
    pickle="$WORKDIR/$sample_md5.cgcompressed.pickle"

    if [ -f "$svg" ] && [ -f "$pickle" ]; then
        skipped_cached=$((skipped_cached + 1))
        echo "[$total] SKIP (already done)  $sample_md5  $sample" | tee -a "$LOG_FILE"
        continue
    fi

    rm -f "$WORKDIR/input.file"
    cp "$sample" "$WORKDIR/input.file"

    {
        echo "=== [$total] $sample_md5  $sample ==="
        docker run --rm -v "$WORKDIR:/usr/exelens/workdir:rw" "$IMAGE"
    } >>"$LOG_FILE" 2>&1

    if [ -f "$svg" ] && [ -f "$pickle" ]; then
        done_now=$((done_now + 1))
        echo "[$total] OK    $sample_md5  $sample"
    else
        failed=$((failed + 1))
        echo "[$total] FAIL  $sample_md5  $sample (see $LOG_FILE)"
    fi
done < <(find "$SAMPLES_DIR" -type f -regextype posix-extended -regex '.*/[0-9a-f]{64}$' -print0)

rm -f "$WORKDIR/input.file"

echo ""
echo "Done. total=$total processed=$done_now skipped(cached)=$skipped_cached failed=$failed"
echo "Outputs: $WORKDIR   Log: $LOG_FILE"
