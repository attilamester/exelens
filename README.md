<h1>
    <img src="./exelens.png" alt="exelens-icon" width="128" height="128" style="margin-right:20px;" align="left" />
    ExeLens
</h1>

<br><br>

## About

ExeLens is an LLM-powered binary executable analysis tool. It visually maps the execution flow of PE, ELF, DotNet, etc. files using `malflow` and `radare2`, generates control-flow graphs, extracts critical functions and entrypoints, and employs LLMs to generate comprehensive analysis reports.

## Usage

1. Ensure your target executable is in your current directory.
2. Run ExeLens via Docker:
```bash
docker run -v $(pwd):/usr/exelens/workdir \
    -e OPENROUTER_API_KEY="your-api-key" \
    -e LLM_MODEL="openai/gpt-4o-mini" \
    attilamester/exelens -i target.exe
```

CLI options:
- `-i / --input`: Path to the PE file to analyze
- `-m / --model`: LLM model to be used; e.g. `openai/gpt-4o-mini` or `google/gemini-2.5-flash`