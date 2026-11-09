"""Factory for instantiating LLM providers."""

from __future__ import annotations

from loglens.llm.anthropic import AnthropicProvider
from loglens.llm.base import LLMProvider, MockLLMProvider
from loglens.llm.gemini import GeminiProvider
from loglens.llm.ollama import OllamaProvider
from loglens.llm.openai_compat import OpenAICompatProvider

DEFAULT_MODELS: dict[str, str] = {
    "ollama": "llama3.2:3b",
    "openai": "gpt-4o-mini",
    "openai_compat": "gpt-4o-mini",
    "gemini": "gemini-2.5-flash",
    "anthropic": "claude-3-5-haiku-20241022",
    "mock": "mock-triage-v1",
}


def get_provider(
    name: str = "ollama",
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> LLMProvider:
    """Create and configure an LLM provider by name.

    Args:
        name: Provider name ('ollama', 'openai', 'gemini', 'anthropic', 'mock').
        model: Model name/tag (defaults to recommended lightweight model per provider).
        base_url: Custom base URL (for Ollama or OpenAI-compatible backends).
        api_key: Optional API key (falls back to standard environment variables).

    Returns:
        Configured LLMProvider instance.
    """
    normalized_name = name.strip().lower()
    selected_model = model or DEFAULT_MODELS.get(normalized_name, "default")

    if normalized_name == "ollama":
        host = base_url or "http://localhost:11434"
        return OllamaProvider(model=selected_model, host=host)

    if normalized_name in ("openai", "openai_compat", "openrouter", "vllm", "lmstudio"):
        url = base_url or "https://api.openai.com/v1"
        return OpenAICompatProvider(model=selected_model, base_url=url, api_key=api_key)

    if normalized_name == "gemini":
        return GeminiProvider(model=selected_model, api_key=api_key)

    if normalized_name == "anthropic":
        return AnthropicProvider(model=selected_model, api_key=api_key)

    if normalized_name == "mock":
        return MockLLMProvider(name="mock")

    raise ValueError(
        f"Unknown LLM provider '{name}'. Supported providers: "
        f"ollama, openai, gemini, anthropic, mock."
    )
