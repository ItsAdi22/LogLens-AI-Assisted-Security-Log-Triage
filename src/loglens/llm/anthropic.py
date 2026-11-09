"""Anthropic Claude LLM provider implementation via direct REST API."""

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


class AnthropicProvider:
    """Provider for Anthropic Claude models via direct REST Messages API."""

    name: str = "anthropic"
    is_cloud: bool = True

    def __init__(
        self,
        model: str = "claude-3-5-haiku-20241022",
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    def complete_json(
        self,
        system: str,
        user: str,
        schema: type[T],
        *,
        timeout: float = 45.0,
        max_tokens: int = 2048,
    ) -> T:
        """Call Anthropic /v1/messages API with instructions for JSON response."""
        if not self.api_key:
            raise LLMAuthError(
                "Missing Anthropic API key. Set the ANTHROPIC_API_KEY environment variable."
            )

        endpoint = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        # Prompt instruction emphasizing JSON output
        enhanced_system = (
            f"{system}\n\n"
            "CRITICAL: Output MUST be a strictly valid JSON object matching the required schema. "
            "No preamble, no markdown tags outside the JSON block."
        )

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": enhanced_system,
            "messages": [
                {"role": "user", "content": user},
            ],
        }

        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(endpoint, headers=headers, json=payload)
                if response.status_code in (401, 403):
                    raise LLMAuthError(f"Anthropic authentication failed: {response.text}")
                if response.status_code == 429:
                    raise LLMRateLimitError(f"Anthropic rate limit exceeded: {response.text}")
                response.raise_for_status()
                data = response.json()
        except httpx.ConnectError as err:
            raise LLMConnectionError("Could not connect to Anthropic API endpoint.") from err
        except httpx.TimeoutException as err:
            raise LLMTimeoutError(
                f"Anthropic API request timed out after {timeout} seconds."
            ) from err
        except Exception as err:
            if isinstance(err, (LLMAuthError, LLMRateLimitError, LLMConnectionError)):
                raise
            raise LLMError(f"Anthropic request failed: {err}") from err

        content_blocks = data.get("content", [])
        if not content_blocks:
            raise LLMError("No content returned in Anthropic response.")

        raw_content = content_blocks[0].get("text", "")
        return extract_and_validate_json(raw_content, schema)

    def test_connection(self) -> dict[str, str]:
        """Test Anthropic API connectivity."""
        if not self.api_key:
            return {"status": "error", "error": "ANTHROPIC_API_KEY is not set"}
        # Send minimal 1-token query to verify credentials
        endpoint = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": 5,
            "messages": [{"role": "user", "content": "ping"}],
        }
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.post(endpoint, headers=headers, json=payload)
                if res.status_code in (401, 403):
                    return {"status": "error", "error": "Invalid API key"}
                res.raise_for_status()
                return {"status": "ok", "model": self.model}
        except Exception as e:
            return {"status": "error", "model": self.model, "error": str(e)}
