import os
import sys
from openai import OpenAI

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
            default_model = "gemini-2.5-flash"

        self.model_name = explicit_model or default_model

        if not self.api_key:
            print("Error: No API key found. Please set OPENROUTER_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY.", file=sys.stderr)
            sys.exit(1)
            
        self.client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
        )

    def generate_summary(self, prompt: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"Error calling LLM API: {e}", file=sys.stderr)
            return f"Error: {e}"
