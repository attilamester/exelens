<h1>
    <img src="./exelens.png" alt="exelens-icon" width="128" height="128" style="margin-right:20px;" align="left" />
    ExeLens
</h1>

<br><br>

## About

ExeLens is an LLM-powered binary executable analysis tool. It visually maps the execution flow of PE, ELF, DotNet, etc. files using `malflow` and `radare2`, generates control-flow graphs, extracts critical functions and entrypoints, and employs LLMs to generate comprehensive analysis reports.

## Usage

1. Stage your target executable in a `workdir` directory, named `input.file`:
```bash
mkdir -p workdir
cp /path/to/target.exe workdir/input.file
```
2. Run ExeLens via Docker:
```bash
docker run --rm \
    -v $(pwd)/workdir:/usr/exelens/workdir:rw \
    -e OPENROUTER_API_KEY="your-api-key" \
    -e LLM_MODEL="openai/gpt-4o-mini" \
    attilamester/exelens
```

Outputs go to `./workdir` (or `-o/--output-dir`):
- `drawing/<md5>.cg-sfdp.svg`: call-graph drawing
- `context/<md5>.txt`: LLM input context (system prompt: `src/exelens/prompting/main.md`), stats in `.json`
- `reports/exelens_report_<md5>.txt`: LLM report; model, tokens, cost and grounding in `.json`

Env vars (pick one credential):
- `OPENROUTER_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_API_KEY`: LLM credential
- `LLM_MODEL`: e.g. `gemini-3.1-flash-lite` or `openai/gpt-4o-mini` (default depends on the credential)
- `LLM_TOKENS_PER_MINUTE` / `LLM_REQUESTS_PER_MINUTE`: optional throttling (e.g. Gemini free tier)

By default the image reads `/usr/exelens/workdir/input.file`; arguments after the image name replace it and must
include `--input`: a PE file, a `<md5>.cgcompressed.pickle` dump (skips the radare2 scan), or a directory of
dumps (resumable). Useful options:
- `--prompt-only`: build only the drawing and context, no API key needed
- `--sample` / `--samples-dir`: original PE of a dump, to add sections, resources and overlay to the context

```bash
docker run --rm -v $(pwd)/workdir:/usr/exelens/workdir:rw attilamester/exelens \
    --input /usr/exelens/workdir/<md5>.cgcompressed.pickle --prompt-only
# estimate the cost of a run (after --prompt-only)
docker run --rm -v $(pwd)/workdir:/usr/exelens/workdir:rw --entrypoint python3 attilamester/exelens \
    -m exelens.core.cost /usr/exelens/workdir --model gemini-3.1-flash-lite
# re-check the grounding of existing reports
python3 -m exelens.core.grounding <output dir>
```

## Sample vs. report similarity analysis

Standalone modules under `experiments/` (not in the Docker image), matching samples and reports by md5:
- `sample_analysis`: EMBER cosine similarity of the samples (`features.py` vendored, AGPL-3.0)
- `llm_report_analysis`: report similarity (`jaccard` or `embedding`) and its correlation with sample similarity

```bash
pip install -r experiments/sample_analysis/requirements.txt -r experiments/llm_report_analysis/requirements.txt
export PYTHONPATH=src:experiments
python dataset/APTMalware-analysis/unzip_samples.py "dataset/APTMalware/samples/APT 1"  # 1. unzip samples
python -m sample_analysis --permutations 1000                                          # 2. EMBER similarity
./experiments/run_batch.sh                                                             # 3. call-graph dumps
nohup ./experiments/run_llm_dataset.sh > experiments/run_llm_dataset.log 2>&1 &        # 4. reports
python -m llm_report_analysis --method jaccard                                         # 5. correlation
```
