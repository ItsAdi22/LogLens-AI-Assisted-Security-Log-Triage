"""OpenAI-compatible LLM provider (OpenAI, OpenRouter, vLLM, LM Studio, etc.)."""

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


class OpenAICompatProvider:
    """Provider communicating with any OpenAI-compatible Chat Completions API."""

    name: str = "openai_compat"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        # Determine if cloud provider based on base_url host
        self.is_cloud = not any(
            local in self.base_url for local in ("localhost", "127.0.0.1", "0.0.0.0")
        )

    def complete_json(
        self,
        system: str,
        user: str,
        schema: type[T],
        *,
        timeout: float = 45.0,
        max_tokens: int = 2048,
    ) -> T:
        """Call /chat/completions with json_object response format."""
        if self.is_cloud and not self.api_key:
            raise LLMAuthError(
                f"Missing API key for OpenAI-compatible provider at {self.base_url}. "
                "Set OPENAI_API_KEY environment variable."
            )

        endpoint = f"{self.base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": max_tokens,
        }

        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(endpoint, json=payload, headers=headers)
                if response.status_code in (401, 403):
                    raise LLMAuthError(f"Authentication failed: {response.text}")
                if response.status_code == 429:
                    raise LLMRateLimitError(f"Rate limit exceeded: {response.text}")
                response.raise_for_status()
                data = response.json()
        except httpx.ConnectError as err:
            raise LLMConnectionError(
                f"Could not connect to API endpoint at {self.base_url}."
            ) from err
        except httpx.TimeoutException as err:
            raise LLMTimeoutError(
                f"Request to {self.base_url} timed out after {timeout} seconds."
            ) from err
        except Exception as err:
            if isinstance(err, (LLMAuthError, LLMRateLimitError, LLMConnectionError)):
                raise
            raise LLMError(f"OpenAI-compatible request failed: {err}") from err

        choices = data.get("choices", [])
        if not choices:
            raise LLMError("No completion choices returned by API.")

        raw_content = choices[0].get("message", {}).get("content", "")
        return extract_and_validate_json(raw_content, schema)

    def test_connection(self) -> dict[str, str]:
        """Test API connectivity by querying /models."""
        endpoint = f"{self.base_url}/models"
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(endpoint, headers=headers)
                if res.status_code in (401, 403):
                    return {
                        "status": "error",
                        "base_url": self.base_url,
                        "error": "Authentication failed (invalid API key)",
                    }
                res.raise_for_status()
                return {
                    "status": "ok",
                    "base_url": self.base_url,
                    "model": self.model,
                }
        except Exception as e:
            return {
                "status": "error",
                "base_url": self.base_url,
                "model": self.model,
                "error": str(e),
            }
