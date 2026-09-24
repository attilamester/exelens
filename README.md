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

The report (`exelens_report_<md5>.txt`) and call-graph SVG (`<md5>.cg-sfdp.svg`) are
written back into `./workdir`.

Env vars (pick one credential):
- `OPENROUTER_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_API_KEY`: LLM credential
- `LLM_MODEL`: LLM model to be used; e.g. `openai/gpt-4o-mini` or `gemini-2.5-flash`
  (defaults to a sensible model for whichever credential is set)

Note: the Docker image's entrypoint always reads `/usr/exelens/workdir/input.file` —
the `-i/--input` CLI flag only applies if you run the `exelens` Python package directly
(outside Docker), not through this image.