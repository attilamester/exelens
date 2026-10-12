import os
import sys
import time
from typing import Dict, List, Optional, Tuple

from openai import OpenAI

from exelens.core.cost import estimate_tokens

# Reports are ~1.5k tokens; the cap bounds the cost and time of a degenerate response (e.g. JSON mode repeating "}"
# until the model's 65k output limit, which took 10 minutes).
MAX_OUTPUT_TOKENS = 16384
REQUEST_TIMEOUT_SECONDS = 300

# (time, estimated input tokens) of the LLM calls of the last minute, across all clients of this process.
_recent_calls: List[Tuple[float, int]] = []


class DailyQuotaExceeded(Exception):
    """The provider's daily request quota is used up: further calls fail until it resets."""


def wait_for_rate_limit(input_tokens: int):
    """Sleeps until this call fits the per-minute limits set by LLM_TOKENS_PER_MINUTE (input tokens) and
    LLM_REQUESTS_PER_MINUTE (e.g. the free tier's), instead of failing on 429 and needing a re-run."""
    tokens_per_minute = int(os.environ.get("LLM_TOKENS_PER_MINUTE", 0))
    requests_per_minute = int(os.environ.get("LLM_REQUESTS_PER_MINUTE", 0))
    while _recent_calls:
        now = time.time()
        _recent_calls[:] = [(t, n) for t, n in _recent_calls if now - t < 60]
        tokens_ok = not tokens_per_minute or sum(n for _, n in _recent_calls) + input_tokens <= tokens_per_minute
        requests_ok = not requests_per_minute or len(_recent_calls) < requests_per_minute
        if tokens_ok and requests_ok:
            break
        time.sleep(60 - (now - _recent_calls[0][0]) + 1)
    _recent_calls.append((time.time(), input_tokens))


class LlmClient:
    def __init__(self, model_name: str = None):
        explicit_model = model_name or os.environ.get("LLM_MODEL")

        self.api_key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OPENAI_API_KEY")
        self.base_url = None
        default_model = "openai/gpt-4o-mini"

        if os.environ.get("OPENROUTER_API_KEY"):
            self.base_url = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        elif os.environ.get("OPENAI_API_KEY"):
            self.base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
            default_model = "gpt-4o-mini"

        # Fallback to Google Gemini API via original variable if others not set
        if not self.api_key and os.environ.get("GOOGLE_API_KEY"):
            self.api_key = os.environ.get("GOOGLE_API_KEY")
            self.base_url = os.environ.get("GOOGLE_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")
            # gemini-2.5-flash(-lite) is no longer available to new API users; gemini-3.8-flash often blocks malware
            # analyses with its safety filter and has a free tier of only 20 requests/day
            default_model = "gemini-3.1-flash-lite"

        self.model_name = explicit_model or default_model

        if not self.api_key:
            print("Error: No API key found. Please set OPENROUTER_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY.", file=sys.stderr)
            sys.exit(1)
            
        self.client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            # Rate-limit (429) and transient errors are retried with exponential backoff.
            max_retries=5,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

    def generate_summary(self, system_prompt: str, prompt: str) -> Tuple[Optional[str], Optional[Dict], Optional[str]]:
        """Returns (report JSON text, token usage, finish reason). The text is None if the call failed (usage is None
        too) or the LLM returned no complete report: its safety filters blocked the response, or it hit the output cap.
        Raises DailyQuotaExceeded when the provider's daily quota is used up."""
        wait_for_rate_limit(estimate_tokens(system_prompt) + estimate_tokens(prompt))
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=MAX_OUTPUT_TOKENS,
            )
        except Exception as e:
            print(f"Error calling LLM API: {e}", file=sys.stderr)
            if "PerDay" in str(e):  # Gemini: quotaId "GenerateRequestsPerDay..." of a 429
                raise DailyQuotaExceeded(str(e)) from e
            return None, None, None
        choice = response.choices[0]
        usage = response.usage.model_dump() if response.usage else None
        if choice.message is None or not choice.message.content or choice.finish_reason == "length":
            # Blocked by the provider's safety filters (Gemini: finish_reason "content_filter: ..."), or cut off at
            # MAX_OUTPUT_TOKENS (finish_reason "length"), which leaves an incomplete JSON report
            print(f"Error: LLM returned no complete report (finish_reason: {choice.finish_reason}, usage: {usage})",
                  file=sys.stderr)
            return None, usage, choice.finish_reason
        return choice.message.content, usage, choice.finish_reason
