import argparse
import glob
import json
import math
import os
from typing import Optional

CHARS_PER_TOKEN = 1.7

PRICES_PER_1M = {
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-3.1-flash-lite": (0.25, 1.50),
    "gemini-3.5-flash-lite": (0.30, 2.50),
    "gemini-3.5-flash": (1.50, 9.00),
    "gemini-3.8-flash": (0.75, 3.75),
    "gemini-3.1-pro-preview": (2.00, 12.00),
}


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def billed_output_tokens(usage: dict) -> int:
    # Gemini bills thinking tokens as output, but leaves them out of completion_tokens (only total_tokens has them).
    return usage["total_tokens"] - usage["prompt_tokens"]


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> Optional[float]:
    # OpenRouter-style ids ("google/gemini-2.5-flash") are priced as the bare model id.
    prices = PRICES_PER_1M.get(model.split("/")[-1])
    if prices is None:
        return None
    return (input_tokens * prices[0] + output_tokens * prices[1]) / 1_000_000


def summarize(directory: str, model: str, output_tokens: int):
    def load(pattern):
        metas = []
        for path in sorted(glob.glob(os.path.join(directory, pattern))):
            with open(path) as f:
                metas.append(json.load(f))
        return metas

    metas = load(os.path.join("context", "*.json"))
    if not metas:
        print(f"No context/<md5>.json files in {directory}; run exelens (e.g. with --prompt-only) first.")
        return

    estimated = [m["estimated_prompt_tokens"] for m in metas]
    modes = {mode: sum(m["mode"] == mode for m in metas) for mode in sorted({m["mode"] for m in metas})}
    print(f"Samples: {len(metas)}  modes: {modes}")
    print(f"Estimated prompt tokens: total={sum(estimated):,}  mean={sum(estimated) // len(estimated):,}  max={max(estimated):,}")

    cost = estimate_cost(model, sum(estimated), output_tokens * len(metas))
    if cost is None:
        print(f"No price for '{model}'; known models: {', '.join(PRICES_PER_1M)}")
    else:
        print(f"Estimated cost with {model} (assuming {output_tokens:,} output tokens/sample): "
              f"${cost:,.2f} standard, ${cost / 2:,.2f} batch")

    runs = [m for m in load(os.path.join("reports", "exelens_report_*.json")) if m.get("usage")]
    no_report = [m for m in load(os.path.join("reports", "exelens_report_*.json")) if m.get("report_written") is False]
    if no_report:
        reasons = {r: sum(m["finish_reason"] == r for m in no_report) for r in {m["finish_reason"] for m in no_report}}
        print(f"No report (blocked or cut off): {len(no_report)} {reasons} {[m['md5'] for m in no_report]}")
    if runs:
        prompt_tokens = sum(m["usage"]["prompt_tokens"] for m in runs)
        completion_tokens = sum(billed_output_tokens(m["usage"]) for m in runs)
        prompt_chars = sum(m["prompt_chars"] for m in runs)
        print(f"Actual usage of {len(runs)} LLM runs: prompt={prompt_tokens:,}  output (incl. thinking)={completion_tokens:,}  "
              f"mean output={completion_tokens // len(runs):,}  cost=${sum(m['cost_usd'] or 0 for m in runs):,.2f}")
        print(f"Measured chars/token: {prompt_chars / prompt_tokens:.2f} (CHARS_PER_TOKEN is {CHARS_PER_TOKEN})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Summarize the estimated/actual LLM token usage and cost of ExeLens runs.")
    parser.add_argument("directory", help="Output directory of the ExeLens runs (with context/ and reports/)")
    parser.add_argument("-m", "--model", default="gemini-3.1-flash-lite", help="Model to price the estimate with")
    parser.add_argument("--output-tokens", type=int, default=8000,
                        help="Assumed output (report + thinking) tokens per sample (default: 8000)")
    args = parser.parse_args()
    summarize(args.directory, args.model, args.output_tokens)
