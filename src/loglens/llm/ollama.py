"""Ollama local LLM provider implementation."""

from __future__ import annotations

import httpx

from loglens.llm.base import (
    LLMConnectionError,
    LLMError,
    LLMTimeoutError,
    T,
)
from loglens.llm.guard import extract_and_validate_json


class OllamaProvider:
    """Local LLM provider connecting to an Ollama server."""

    name: str = "ollama"
    is_cloud: bool = False

    def __init__(
        self,
        model: str = "llama3.2:3b",
        host: str = "http://localhost:11434",
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")

    def complete_json(
        self,
        system: str,
        user: str,
        schema: type[T],
        *,
        timeout: float = 45.0,
        max_tokens: int = 2048,
    ) -> T:
        """Call Ollama /api/chat with format=json and parse into schema."""
        endpoint = f"{self.host}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "format": "json",
            "stream": False,
            "options": {
                "num_predict": max_tokens,
            },
        }

        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(endpoint, json=payload)
                if response.status_code == 404:
                    raise LLMError(
                        f"Ollama model '{self.model}' not found or endpoint invalid. "
                        f"Run: ollama pull {self.model}"
                    )
                response.raise_for_status()
                data = response.json()
        except httpx.ConnectError as err:
            raise LLMConnectionError(
                f"Could not connect to Ollama at {self.host}. "
                "Ensure Ollama is installed and running (`ollama serve`)."
            ) from err
        except httpx.TimeoutException as err:
            raise LLMTimeoutError(f"Ollama request timed out after {timeout} seconds.") from err
        except httpx.HTTPStatusError as err:
            raise LLMError(
                f"Ollama HTTP error {err.response.status_code}: {err.response.text}"
            ) from err
        except Exception as err:
            if isinstance(err, LLMError):
                raise
            raise LLMError(f"Unexpected error communicating with Ollama: {err}") from err

        raw_content = data.get("message", {}).get("content", "")
        return extract_and_validate_json(raw_content, schema)

    def test_connection(self) -> dict[str, str]:
        """Test whether Ollama server is responsive and model is available."""
        endpoint = f"{self.host}/api/tags"
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(endpoint)
                res.raise_for_status()
                data = res.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                model_present = any(self.model in m for m in models)
                return {
                    "status": "ok" if model_present else "warning",
                    "host": self.host,
                    "model": self.model,
                    "model_available": str(model_present),
                    "available_models": ", ".join(models) if models else "none",
                }
        except Exception as e:
            return {
                "status": "error",
                "host": self.host,
                "model": self.model,
                "error": str(e),
            }
