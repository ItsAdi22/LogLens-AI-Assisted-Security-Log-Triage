"""Reversible token-based redaction engine for privacy preservation."""

from __future__ import annotations

import re
from typing import Literal

from loglens.models import Cluster, LLMAssessment
from loglens.redact.patterns import (
    AWS_KEY_PATTERN,
    BEARER_PATTERN,
    EMAIL_PATTERN,
    IPV4_PATTERN,
    IPV6_PATTERN,
    JWT_PATTERN,
    PRIVATE_KEY_PATTERN,
    QUERY_CREDENTIALS_PATTERN,
    STRICT_PATH_PATTERN,
    URL_CREDENTIALS_PATTERN,
)

RedactionLevel = Literal["off", "standard", "strict"]


class Redactor:
    """Reversibly replaces sensitive indicators with surrogate tokens.

    Supports three operation levels:
    - off: No redaction performed; raw input preserved.
    - standard (default): Redacts IPs, emails, JWTs, API keys, credentials, private keys.
    - strict: Standard + redacts personal user paths.
    """

    def __init__(self, level: RedactionLevel = "standard") -> None:
        self.level: RedactionLevel = level
        self._val_to_token: dict[str, str] = {}
        self._token_to_val: dict[str, str] = {}
        self._counters: dict[str, int] = {
            "IP": 0,
            "EMAIL": 0,
            "JWT": 0,
            "AWS_KEY": 0,
            "TOKEN": 0,
            "CRED": 0,
            "SECRET": 0,
            "KEY": 0,
            "PATH": 0,
        }

    def _get_or_create_token(self, category: str, value: str) -> str:
        """Retrieve existing surrogate token or assign a new numbered token."""
        if value in self._val_to_token:
            return self._val_to_token[value]

        self._counters[category] = self._counters.get(category, 0) + 1
        num = self._counters[category]
        token = f"[{category}_{num}]"

        self._val_to_token[value] = token
        self._token_to_val[token] = value
        return token

    def redact(self, text: str) -> str:
        """Redact sensitive patterns in text according to the configured level."""
        if self.level == "off" or not text:
            return text

        result = text

        # 1. Private keys (multiline)
        def replace_pkey(m: re.Match[str]) -> str:
            return self._get_or_create_token("KEY", m.group(0))

        result = PRIVATE_KEY_PATTERN.sub(replace_pkey, result)

        # 2. Bearer tokens
        def replace_bearer(m: re.Match[str]) -> str:
            token_val = m.group(1)
            surrogate = self._get_or_create_token("TOKEN", token_val)
            return f"Bearer {surrogate}"

        result = BEARER_PATTERN.sub(replace_bearer, result)

        # 3. URL credentials (scheme://user:pass@host)
        def replace_url_cred(m: re.Match[str]) -> str:
            return self._get_or_create_token("CRED", m.group(0))

        result = URL_CREDENTIALS_PATTERN.sub(replace_url_cred, result)

        # 4. Query param credentials (password=xxx)
        def replace_query_cred(m: re.Match[str]) -> str:
            val = m.group(1)
            surrogate = self._get_or_create_token("SECRET", val)
            full_match = m.group(0)
            prefix = full_match[: full_match.index("=") + 1]
            return f"{prefix}{surrogate}"

        result = QUERY_CREDENTIALS_PATTERN.sub(replace_query_cred, result)

        # 5. JWT tokens
        def replace_jwt(m: re.Match[str]) -> str:
            return self._get_or_create_token("JWT", m.group(0))

        result = JWT_PATTERN.sub(replace_jwt, result)

        # 6. AWS access keys
        def replace_aws(m: re.Match[str]) -> str:
            return self._get_or_create_token("AWS_KEY", m.group(0))

        result = AWS_KEY_PATTERN.sub(replace_aws, result)

        # 7. Email addresses
        def replace_email(m: re.Match[str]) -> str:
            return self._get_or_create_token("EMAIL", m.group(0))

        result = EMAIL_PATTERN.sub(replace_email, result)

        # 8. IPv6 addresses
        def replace_ipv6(m: re.Match[str]) -> str:
            return self._get_or_create_token("IP", m.group(0))

        result = IPV6_PATTERN.sub(replace_ipv6, result)

        # 9. IPv4 addresses
        def replace_ipv4(m: re.Match[str]) -> str:
            return self._get_or_create_token("IP", m.group(0))

        result = IPV4_PATTERN.sub(replace_ipv4, result)

        # 10. Strict path redactions
        if self.level == "strict":

            def replace_path(m: re.Match[str]) -> str:
                return self._get_or_create_token("PATH", m.group(0))

            result = STRICT_PATH_PATTERN.sub(replace_path, result)

        return result

    def restore(self, text: str) -> str:
        """Restore all surrogate tokens in text back to original sensitive values."""
        if self.level == "off" or not text or not self._token_to_val:
            return text

        # Sort tokens by length descending to avoid partial prefix replacement collisions
        tokens_sorted = sorted(self._token_to_val.keys(), key=len, reverse=True)
        escaped_tokens = [re.escape(t) for t in tokens_sorted]
        pattern = re.compile("|".join(escaped_tokens))

        def replace_token(m: re.Match[str]) -> str:
            tok = m.group(0)
            return self._token_to_val.get(tok, tok)

        return pattern.sub(replace_token, text)

    def redact_cluster(self, cluster: Cluster) -> Cluster:
        """Create a redacted copy of a Cluster instance."""
        if self.level == "off":
            return cluster

        redacted_template = self.redact(cluster.template)
        redacted_samples = [self.redact(msg) for msg in cluster.sample_messages]

        redacted_top_fields: dict[str, list[tuple[str, int]]] = {}
        for field_name, items in cluster.top_fields.items():
            redacted_items: list[tuple[str, int]] = []
            for val, count in items:
                redacted_items.append((self.redact(val), count))
            redacted_top_fields[field_name] = redacted_items

        return Cluster(
            id=cluster.id,
            template=redacted_template,
            count=cluster.count,
            first_seen=cluster.first_seen,
            last_seen=cluster.last_seen,
            top_fields=redacted_top_fields,
            sample_messages=redacted_samples,
        )

    def restore_assessment(self, assessment: LLMAssessment) -> LLMAssessment:
        """Restore surrogate tokens across all text fields of an LLMAssessment."""
        if self.level == "off" or not self._token_to_val:
            return assessment

        restored_summary = self.restore(assessment.summary)
        restored_attack = self.restore(assessment.attack_type) if assessment.attack_type else None
        restored_evidence = [self.restore(ev) for ev in assessment.evidence]
        restored_actions = [self.restore(act) for act in assessment.recommended_actions]

        return LLMAssessment(
            summary=restored_summary,
            attack_type=restored_attack,
            severity=assessment.severity,
            confidence=assessment.confidence,
            evidence=restored_evidence,
            recommended_actions=restored_actions,
            false_positive_likelihood=assessment.false_positive_likelihood,
        )
