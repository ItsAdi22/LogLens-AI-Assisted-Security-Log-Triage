"""Unit tests for Ollama, OpenAICompat, Gemini, and Anthropic providers with mocked HTTP."""

from unittest.mock import MagicMock

import httpx
import pytest

from loglens.llm.anthropic import AnthropicProvider
from loglens.llm.base import (
    LLMAuthError,
    LLMConnectionError,
    LLMError,
    LLMRateLimitError,
    LLMTimeoutError,
)
from loglens.llm.gemini import GeminiProvider
from loglens.llm.ollama import OllamaProvider
from loglens.llm.openai_compat import OpenAICompatProvider
from loglens.models import LLMAssessment


def sample_llm_json() -> str:
    return (
        '{"summary": "Test alert", "attack_type": "ssh_bruteforce", '
        '"severity": "high", "confidence": 0.95, '
        '"evidence": ["evidence 1"], "recommended_actions": ["action 1"], '
        '"false_positive_likelihood": "low"}'
    )


# =========================================================================
# OllamaProvider tests
# =========================================================================


def test_ollama_complete_json_success(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OllamaProvider(model="llama3.2:3b")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"message": {"content": sample_llm_json()}}

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    result = provider.complete_json("sys", "user", LLMAssessment)
    assert result.attack_type == "ssh_bruteforce"
    assert result.severity == "high"


def test_ollama_complete_json_404_model_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OllamaProvider(model="nonexistent")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 404

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    with pytest.raises(LLMError, match="not found"):
        provider.complete_json("sys", "user", LLMAssessment)


def test_ollama_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OllamaProvider()

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.side_effect = httpx.ConnectError("Failed to connect")

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    with pytest.raises(LLMConnectionError):
        provider.complete_json("sys", "user", LLMAssessment)


def test_ollama_timeout_error(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OllamaProvider()

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.side_effect = httpx.TimeoutException("Timed out")

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    with pytest.raises(LLMTimeoutError):
        provider.complete_json("sys", "user", LLMAssessment)


def test_ollama_test_connection_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OllamaProvider(model="llama3.2:3b")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"models": [{"name": "llama3.2:3b"}]}

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    info = provider.test_connection()
    assert info["status"] == "ok"
    assert info["model_available"] == "True"


# =========================================================================
# OpenAICompatProvider tests
# =========================================================================


def test_openai_compat_complete_json_success(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OpenAICompatProvider(api_key="sk-test-key")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"choices": [{"message": {"content": sample_llm_json()}}]}

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    result = provider.complete_json("sys", "user", LLMAssessment)
    assert result.attack_type == "ssh_bruteforce"


def test_openai_compat_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OpenAICompatProvider(api_key="sk-invalid")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    with pytest.raises(LLMAuthError):
        provider.complete_json("sys", "user", LLMAssessment)


def test_openai_compat_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OpenAICompatProvider(api_key="sk-test")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 429
    mock_resp.text = "Rate limit"

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    with pytest.raises(LLMRateLimitError):
        provider.complete_json("sys", "user", LLMAssessment)


def test_openai_compat_test_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OpenAICompatProvider(api_key="sk-test")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    info = provider.test_connection()
    assert info["status"] == "ok"


# =========================================================================
# GeminiProvider tests
# =========================================================================


def test_gemini_complete_json_success(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = GeminiProvider(api_key="test-key")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": sample_llm_json()}]}}]
    }

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    result = provider.complete_json("sys", "user", LLMAssessment)
    assert result.attack_type == "ssh_bruteforce"


def test_gemini_missing_api_key() -> None:
    provider = GeminiProvider(api_key="")
    with pytest.raises(LLMAuthError, match="Missing Gemini API key"):
        provider.complete_json("sys", "user", LLMAssessment)


def test_gemini_test_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = GeminiProvider(api_key="test-key")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    info = provider.test_connection()
    assert info["status"] == "ok"


# =========================================================================
# AnthropicProvider tests
# =========================================================================


def test_anthropic_complete_json_success(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = AnthropicProvider(api_key="test-key")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"content": [{"text": sample_llm_json()}]}

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    result = provider.complete_json("sys", "user", LLMAssessment)
    assert result.attack_type == "ssh_bruteforce"


def test_anthropic_missing_api_key() -> None:
    provider = AnthropicProvider(api_key="")
    with pytest.raises(LLMAuthError, match="Missing Anthropic API key"):
        provider.complete_json("sys", "user", LLMAssessment)


def test_anthropic_test_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = AnthropicProvider(api_key="test-key")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: mock_client)

    info = provider.test_connection()
    assert info["status"] == "ok"
