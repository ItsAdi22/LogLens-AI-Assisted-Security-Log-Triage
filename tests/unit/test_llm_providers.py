"""Unit tests for LLM providers, factory, cache, and token budget."""

from datetime import UTC, datetime

import pytest

from loglens.llm.base import (
    LLMTimeoutError,
    LLMValidationError,
    MockLLMProvider,
)
from loglens.llm.cache import LLMCache, TokenBudget
from loglens.llm.consent import verify_cloud_consent
from loglens.llm.factory import get_provider
from loglens.llm.triage import TriageOrchestrator
from loglens.models import Cluster, Finding, LLMAssessment
from loglens.redact import Redactor


def test_mock_llm_provider_default_response() -> None:
    expected = LLMAssessment(
        summary="Test attack",
        attack_type="ssh_bruteforce",
        severity="high",
        confidence=0.9,
        evidence=["Multiple bad passwords"],
        recommended_actions=["Ban IP"],
        false_positive_likelihood="low",
    )
    provider = MockLLMProvider(default_response=expected)
    res = provider.complete_json("sys", "user", LLMAssessment)
    assert res.summary == "Test attack"
    assert len(provider.call_history) == 1


def test_mock_llm_provider_simulate_error() -> None:
    provider = MockLLMProvider(simulate_error=LLMTimeoutError("Request timed out"))
    with pytest.raises(LLMTimeoutError):
        provider.complete_json("sys", "user", LLMAssessment)


def test_provider_factory_resolution() -> None:
    prov_mock = get_provider("mock")
    assert prov_mock.name == "mock"
    assert not prov_mock.is_cloud

    prov_ollama = get_provider("ollama", model="qwen2.5:7b", base_url="http://127.0.0.1:11434")
    assert prov_ollama.name == "ollama"
    assert not prov_ollama.is_cloud

    prov_openai = get_provider("openai", api_key="sk-test-key")
    assert prov_openai.name == "openai_compat"
    assert prov_openai.is_cloud

    prov_gemini = get_provider("gemini", api_key="test-key")
    assert prov_gemini.name == "gemini"
    assert prov_gemini.is_cloud

    prov_anthropic = get_provider("anthropic", api_key="test-key")
    assert prov_anthropic.name == "anthropic"
    assert prov_anthropic.is_cloud

    with pytest.raises(ValueError, match="Unknown LLM provider"):
        get_provider("unsupported-provider")


def test_llm_cache() -> None:
    cache = LLMCache()
    key = LLMCache.compute_key("redacted_cluster", "v1", "llama3.2:3b")

    assert cache.get(key) is None
    cache.set(key, '{"summary": "cached"}', "llama3.2:3b", "v1")
    assert cache.get(key) == '{"summary": "cached"}'
    cache.close()


def test_token_budget() -> None:
    budget = TokenBudget(max_tokens_per_run=1000)
    assert budget.remaining == 1000
    assert not (budget.used_tokens >= budget.max_tokens)

    budget.consume(600)
    assert budget.remaining == 400

    budget.consume(400)
    assert budget.remaining == 0
    assert budget.used_tokens >= budget.max_tokens
    assert budget.is_exhausted

    # Over consumption rejected
    over = budget.consume(100)
    assert over is False


def test_verify_cloud_consent() -> None:
    mock_prov = MockLLMProvider(is_cloud=False)
    assert verify_cloud_consent(mock_prov) is True

    cloud_prov = MockLLMProvider(name="cloud-ai", is_cloud=True)
    # Without explicit consent
    assert verify_cloud_consent(cloud_prov, explicit_agreement=False) is False
    # With explicit consent
    assert verify_cloud_consent(cloud_prov, explicit_agreement=True) is True


def test_triage_orchestrator_flow_with_mock() -> None:
    assessment = LLMAssessment(
        summary="Brute force against root from [IP_1]",
        attack_type="ssh_bruteforce",
        severity="high",
        confidence=0.96,
        evidence=["100 failed logins from [IP_1]"],
        recommended_actions=["Block [IP_1]"],
        false_positive_likelihood="low",
    )
    provider = MockLLMProvider(default_response=assessment)
    redactor = Redactor(level="standard")
    orchestrator = TriageOrchestrator(provider=provider, redactor=redactor)

    cluster = Cluster(
        id="c-001",
        template="Failed password for root from 192.0.2.100 port 22",
        count=100,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        top_fields={"ip": [("192.0.2.100", 100)]},
        sample_messages=["Failed password for root from 192.0.2.100 port 22 ssh2"],
    )
    rule_finding = Finding(
        id="finding-ssh-bruteforce-001",
        cluster_ids=["c-001"],
        rule_ids=["ssh-bruteforce-001"],
        rule_severity="high",
    )

    findings, stats = orchestrator.triage([cluster], [rule_finding])

    assert len(findings) == 1
    f = findings[0]
    assert f.llm is not None
    # De-redaction should have replaced [IP_1] back to 192.0.2.100
    assert "192.0.2.100" in f.llm.summary
    assert "192.0.2.100" in f.llm.evidence[0]
    assert stats["llm_calls"] == 1
    assert stats["triaged_clusters"] == 1


def test_triage_orchestrator_repair_retry() -> None:
    # First attempt returns invalid json, second attempt succeeds
    valid_assessment = LLMAssessment(
        summary="Repaired summary",
        attack_type="web_scan",
        severity="medium",
        confidence=0.8,
        evidence=["Scanned path"],
        recommended_actions=["Block IP"],
        false_positive_likelihood="low",
    )

    class FlakyMockProvider:
        name = "flaky"
        is_cloud = False

        def __init__(self) -> None:
            self.calls = 0

        def complete_json(
            self, system: str, user: str, schema: type, **kwargs: object
        ) -> LLMAssessment:
            self.calls += 1
            if self.calls == 1:
                raise LLMValidationError("Invalid JSON output")
            return valid_assessment

    provider = FlakyMockProvider()
    orchestrator = TriageOrchestrator(provider=provider)  # type: ignore[arg-type]

    cluster = Cluster(
        id="c-002",
        template="GET /test HTTP/1.1",
        count=10,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )

    findings, stats = orchestrator.triage([cluster])
    assert len(findings) == 1
    assert findings[0].llm is not None
    assert findings[0].llm.summary == "Repaired summary"
    assert stats["repair_attempts"] == 1
    assert stats["llm_calls"] == 2
