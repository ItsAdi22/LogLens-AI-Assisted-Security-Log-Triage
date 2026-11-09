"""Base protocols, exceptions, and mock implementations for LLM providers."""

from __future__ import annotations

from typing import Any, Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMError(Exception):
    """Base exception for all LLM-related errors."""


class LLMConnectionError(LLMError):
    """Raised when the LLM service endpoint is unreachable."""


class LLMTimeoutError(LLMError):
    """Raised when an LLM request exceeds the allotted timeout."""


class LLMRateLimitError(LLMError):
    """Raised when the LLM provider responds with rate limit / quota exceeded."""


class LLMAuthError(LLMError):
    """Raised when authentication credentials are invalid or missing."""


class LLMValidationError(LLMError):
    """Raised when the LLM output fails schema validation."""


class LLMProvider(Protocol):
    """Protocol implemented by all LLM triage backends."""

    name: str
    is_cloud: bool

    def complete_json(
        self,
        system: str,
        user: str,
        schema: type[T],
        *,
        timeout: float = 30.0,
        max_tokens: int = 2048,
    ) -> T:
        """Execute prompt against the provider and return a validated Pydantic model instance.

        Args:
            system: System instructions and role prompt.
            user: User prompt with structured context.
            schema: Target Pydantic model type for structured output.
            timeout: Request timeout in seconds.
            max_tokens: Maximum tokens allowed for generation.

        Returns:
            Validated Pydantic model instance.

        Raises:
            LLMConnectionError: If the backend is unreachable.
            LLMTimeoutError: If request times out.
            LLMRateLimitError: If rate limited.
            LLMAuthError: If authentication fails.
            LLMValidationError: If response cannot be parsed into schema.
        """
        ...


class MockLLMProvider:
    """Deterministic mock provider for CI, offline testing, and failure simulation."""

    def __init__(
        self,
        name: str = "mock",
        is_cloud: bool = False,
        default_response: BaseModel | None = None,
        simulate_error: LLMError | None = None,
        simulate_raw_text: str | None = None,
    ) -> None:
        self.name = name
        self.is_cloud = is_cloud
        self.default_response = default_response
        self.simulate_error = simulate_error
        self.simulate_raw_text = simulate_raw_text
        self.call_history: list[dict[str, Any]] = []

    def complete_json(
        self,
        system: str,
        user: str,
        schema: type[T],
        *,
        timeout: float = 30.0,
        max_tokens: int = 2048,
    ) -> T:
        """Return pre-configured mock response or raise simulated exception."""
        self.call_history.append(
            {
                "system": system,
                "user": user,
                "schema": schema,
                "timeout": timeout,
                "max_tokens": max_tokens,
            }
        )

        if self.simulate_error:
            raise self.simulate_error

        if self.simulate_raw_text is not None:
            try:
                return schema.model_validate_json(self.simulate_raw_text)
            except Exception as e:
                raise LLMValidationError(f"Mock raw text failed validation: {e}") from e

        if self.default_response is not None:
            if isinstance(self.default_response, schema):
                return self.default_response
            # Attempt conversion if types differ
            return schema.model_validate(self.default_response.model_dump())

        # Synthesize minimal valid object if default not supplied
        # by validating an empty dictionary or fields with defaults
        try:
            return schema.model_validate({})
        except Exception as e:
            raise LLMValidationError(
                f"No mock response supplied and empty schema failed: {e}"
            ) from e
