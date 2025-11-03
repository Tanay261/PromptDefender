import re
from typing import Tuple

SECRET_WORDS = ["api_key", "token", "password", "secret"]

REDACT = re.compile(r"(?i)(" + "|".join(map(re.escape, SECRET_WORDS)) + r")\s*[:=]\s*[\w\-]{6,}")

def sanitize(prompt: str) -> Tuple[str, int]:
    """ Redact simple secrets & strip 'ignore previous instructions' segments. """
    original = prompt
    prompt = REDACT.sub("[REDACTED]=***", prompt)
    prompt = re.sub(r"(?is)ignore\s+.*?(instructions|rules)\.?", "[REMOVED]", prompt)
    changes = 0 if prompt == original else 1
    return prompt, changes
