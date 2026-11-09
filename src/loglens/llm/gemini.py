"""Google Gemini LLM provider implementation via direct REST API."""

from __future__ import annotations

import os

import httpx

from loglens.llm.base import (
    LLMAuthError,
    LLMConnectionError,
    LLMError,
    LLMRateLimitError,
    LLMTimeoutError,
    T,
)
from loglens.llm.guard import extract_and_validate_json


class GeminiProvider:
    """Provider for Google Gemini models via direct REST API."""

    name: str = "gemini"
    is_cloud: bool = True

    def __init__(
        self,
        model: str = "gemini-2.5-flash",
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")

    def complete_json(
        self,
        system: str,
        user: str,
        schema: type[T],
        *,
        timeout: float = 45.0,
        max_tokens: int = 2048,
    ) -> T:
        """Call Gemini generateContent endpoint with responseMimeType=application/json."""
        if not self.api_key:
            raise LLMAuthError(
                "Missing Gemini API key. Set the GEMINI_API_KEY environment variable."
            )

        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        )
        params = {"key": self.api_key}

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user}],
                }
            ],
            "systemInstruction": {
                "parts": [{"text": system}],
            },
            "generationConfig": {
                "responseMimeType": "application/json",
                "maxOutputTokens": max_tokens,
            },
        }

        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(endpoint, params=params, json=payload)
                if response.status_code in (401, 403):
                    raise LLMAuthError(f"Gemini API authentication failed: {response.text}")
                if response.status_code == 429:
                    raise LLMRateLimitError(f"Gemini rate limit exceeded: {response.text}")
                response.raise_for_status()
                data = response.json()
        except httpx.ConnectError as err:
            raise LLMConnectionError("Could not connect to Google Gemini API endpoint.") from err
        except httpx.TimeoutException as err:
            raise LLMTimeoutError(f"Gemini API request timed out after {timeout} seconds.") from err
        except Exception as err:
            if isinstance(err, (LLMAuthError, LLMRateLimitError, LLMConnectionError)):
                raise
            raise LLMError(f"Gemini request failed: {err}") from err

        candidates = data.get("candidates", [])
        if not candidates:
            raise LLMError("No candidates returned by Gemini API.")

        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            raise LLMError("No content parts returned by Gemini candidate.")

        raw_content = parts[0].get("text", "")
        return extract_and_validate_json(raw_content, schema)

    def test_connection(self) -> dict[str, str]:
        """Test Gemini API connectivity."""
        if not self.api_key:
            return {"status": "error", "error": "GEMINI_API_KEY is not set"}
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}"
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(endpoint, params={"key": self.api_key})
                if res.status_code in (401, 403):
                    return {"status": "error", "error": "Invalid API key"}
                res.raise_for_status()
                return {"status": "ok", "model": self.model}
        except Exception as e:
            return {"status": "error", "model": self.model, "error": str(e)}
