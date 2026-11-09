"""Security guardrails, prompt injection defenses, and output validators."""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from loglens.llm.base import LLMValidationError

T = TypeVar("T", bound=BaseModel)

# Regex to strip ANSI escape sequences
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Delimiter markers for untrusted log data
DATA_START_TAG = "<log_data>"
DATA_END_TAG = "</log_data>"

# Suspicious instruction override patterns often used in prompt injections
SUSPICIOUS_INJECTION_RE = re.compile(
    r"(?i)(?:\bignore\s+(?:all\s+)?previous\s+instructions|"
    r"\bdisregard\s+(?:all\s+)?prior|"
    r"\bsystem\s*prompt\s*:|"
    r"\byou\s+are\s+now\s+in\s+DAN\s+mode)"
)


def sanitize_log_text(text: str, max_chars: int = 15_000) -> str:
    """Sanitize raw log strings before passing to prompts.

    - Strips ANSI terminal escape codes.
    - Strips null bytes and unprintable control characters (except newline, tab, return).
    - Escapes closing `<log_data>` tags to prevent delimiter injection.
    - Truncates oversized input to prevent context window overflow or denial-of-service.
    """
    if not text:
        return ""

    # Strip ANSI escapes
    cleaned = ANSI_ESCAPE_RE.sub("", text)

    # Strip unprintable control characters (keep \t=0x09, \n=0x0A, \r=0x0D)
    cleaned = "".join(
        ch for ch in cleaned if ch in ("\t", "\n", "\r") or (ord(ch) >= 32 and ord(ch) != 127)
    )

    # Neutralize closing delimiter tag inside log content
    cleaned = cleaned.replace("</log_data>", "&lt;/log_data&gt;")
    cleaned = cleaned.replace("<log_data>", "&lt;log_data&gt;")

    # Bound string length
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + f"\n... [TRUNCATED at {max_chars} chars]"

    return cleaned


def wrap_untrusted_data(data: str) -> str:
    """Wrap untrusted log content in strict containment tags."""
    sanitized = sanitize_log_text(data)
    return f"{DATA_START_TAG}\n{sanitized}\n{DATA_END_TAG}"


def contains_injection_attempt(text: str) -> bool:
    """Detect whether text contains known prompt injection phrases."""
    return bool(SUSPICIOUS_INJECTION_RE.search(text))


def extract_and_validate_json(raw_text: str, schema: type[T]) -> T:
    """Extract JSON object from LLM response and validate against Pydantic schema.

    Handles fenced code blocks (```json ... ```) or leading/trailing commentary.

    Raises:
        LLMValidationError: If no JSON object is found or schema validation fails.
    """
    if not raw_text or not raw_text.strip():
        raise LLMValidationError("Empty response from LLM.")

    text = raw_text.strip()

    # If wrapped in markdown code fence, extract interior
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if fence_match:
        text = fence_match.group(1).strip()

    # Locate outermost JSON object boundaries { ... }
    first_brace = text.find("{")
    last_brace = text.rfind("}")

    if first_brace == -1 or last_brace == -1 or last_brace <= first_brace:
        raise LLMValidationError(f"No JSON object detected in response: {raw_text[:200]}")

    json_str = text[first_brace : last_brace + 1]

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as err:
        raise LLMValidationError(f"Invalid JSON format: {err} in: {json_str[:200]}") from err

    try:
        return schema.model_validate(data)
    except ValidationError as err:
        raise LLMValidationError(f"Output schema validation failed: {err}") from err
