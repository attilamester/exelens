import os

SYSTEM_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "main.md")


def load_system_prompt() -> str:
    with open(SYSTEM_PROMPT_PATH) as f:
        return f.read()
