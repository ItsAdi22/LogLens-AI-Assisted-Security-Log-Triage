"""LLM Triage Orchestrator connecting clustering, rules, redaction, and providers."""

from __future__ import annotations

import logging
from typing import Any

from loglens.llm.base import (
    LLMConnectionError,
    LLMError,
    LLMProvider,
    LLMTimeoutError,
    LLMValidationError,
)
from loglens.llm.cache import LLMCache, TokenBudget
from loglens.llm.guard import contains_injection_attempt, wrap_untrusted_data
from loglens.llm.prompts.loader import (
    format_cluster_for_llm,
    get_repair_prompt,
    get_system_prompt,
)
from loglens.models import Cluster, Finding, LLMAssessment
from loglens.redact import Redactor

logger = logging.getLogger(__name__)

SEVERITY_RANKS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


class TriageOrchestrator:
    """Coordinates automated triage of security clusters with rules and LLM assessment."""

    def __init__(
        self,
        provider: LLMProvider,
        redactor: Redactor | None = None,
        cache: LLMCache | None = None,
        token_budget: TokenBudget | None = None,
        prompt_version: str = "v1",
        max_clusters: int = 20,
    ) -> None:
        self.provider = provider
        self.redactor = redactor or Redactor(level="standard")
        self.cache = cache
        self.token_budget = token_budget or TokenBudget()
        self.prompt_version = prompt_version
        self.max_clusters = max_clusters

    def triage(
        self,
        clusters: list[Cluster],
        findings: list[Finding] | None = None,
    ) -> tuple[list[Finding], dict[str, Any]]:
        """Execute triage across clusters and return structured findings and stats.

        Gracefully degrades to rule-only findings if LLM service is unreachable or errors.
        """
        initial_findings = list(findings or [])

        # Map cluster ID to associated initial findings
        findings_by_cluster: dict[str, list[Finding]] = {}
        for f in initial_findings:
            for cid in f.cluster_ids:
                findings_by_cluster.setdefault(cid, []).append(f)

        # Rank clusters: highest rule severity first, then count
        def cluster_priority(c: Cluster) -> tuple[int, int]:
            c_findings = findings_by_cluster.get(c.id, [])
            if not c_findings:
                return (0, c.count)
            highest_sev = max(SEVERITY_RANKS.get(f.rule_severity, 1) for f in c_findings)
            return (highest_sev, c.count)

        ranked_clusters = sorted(clusters, key=cluster_priority, reverse=True)
        selected_clusters = ranked_clusters[: self.max_clusters]

        stats: dict[str, Any] = {
            "total_clusters": len(clusters),
            "triaged_clusters": 0,
            "llm_calls": 0,
            "cache_hits": 0,
            "repair_attempts": 0,
            "llm_errors": 0,
            "injection_attempts_detected": 0,
        }

        system_prompt = get_system_prompt(self.prompt_version)
        model_name = getattr(self.provider, "model", "unknown")

        enriched_findings: list[Finding] = []
        triaged_cluster_ids: set[str] = set()

        for cluster in selected_clusters:
            triaged_cluster_ids.add(cluster.id)
            c_findings = findings_by_cluster.get(cluster.id, [])
            all_rule_ids: list[str] = []

            if c_findings:
                for f in c_findings:
                    all_rule_ids.extend(f.rule_ids)

            # Check for adversarial injection phrases in cluster messages or template
            raw_text_sample = " ".join(cluster.sample_messages)
            has_injection = contains_injection_attempt(
                raw_text_sample
            ) or contains_injection_attempt(cluster.template)
            if has_injection:
                stats["injection_attempts_detected"] += 1

            # Redact sensitive data
            redacted_cluster = self.redactor.redact_cluster(cluster)
            formatted_data = format_cluster_for_llm(redacted_cluster, all_rule_ids)
            wrapped_user_prompt = wrap_untrusted_data(formatted_data)

            # Check cache
            cache_key = ""
            cached_json = None
            if self.cache is not None:
                cache_key = self.cache.compute_key(formatted_data, self.prompt_version, model_name)
                cached_json = self.cache.get(cache_key)

            assessment: LLMAssessment | None = None

            if cached_json is not None:
                try:
                    assessment = LLMAssessment.model_validate_json(cached_json)
                    stats["cache_hits"] += 1
                except Exception:
                    cached_json = None

            if assessment is None:
                if self.token_budget.is_exhausted:
                    logger.warning("Token budget exhausted; falling back to rule-only finding.")
                else:
                    try:
                        stats["llm_calls"] += 1
                        assessment = self.provider.complete_json(
                            system=system_prompt,
                            user=wrapped_user_prompt,
                            schema=LLMAssessment,
                            timeout=30.0,
                        )
                        # Consume token budget estimate
                        self.token_budget.consume(len(wrapped_user_prompt) // 4 + 300)

                    except LLMValidationError as val_err:
                        stats["repair_attempts"] += 1
                        logger.warning(
                            "LLM output validation failed for cluster %s; attempting repair: %s",
                            cluster.id,
                            val_err,
                        )
                        repair_prompt = get_repair_prompt(
                            error_msg=str(val_err),
                            cluster_data=wrapped_user_prompt,
                            version=self.prompt_version,
                        )
                        try:
                            stats["llm_calls"] += 1
                            assessment = self.provider.complete_json(
                                system=system_prompt,
                                user=repair_prompt,
                                schema=LLMAssessment,
                                timeout=30.0,
                            )
                        except Exception as repair_err:
                            logger.error(
                                "Repair attempt failed for cluster %s: %s",
                                cluster.id,
                                repair_err,
                            )
                            stats["llm_errors"] += 1
                            assessment = None

                    except (LLMConnectionError, LLMTimeoutError) as net_err:
                        logger.warning(
                            "LLM service unreachable or timed out for cluster %s: %s",
                            cluster.id,
                            net_err,
                        )
                        stats["llm_errors"] += 1
                        assessment = None

                    except LLMError as err:
                        logger.error("LLM evaluation error for cluster %s: %s", cluster.id, err)
                        stats["llm_errors"] += 1
                        assessment = None

                    # If successful, cache
                    if assessment is not None and self.cache is not None and cache_key:
                        self.cache.set(
                            cache_key=cache_key,
                            response_json=assessment.model_dump_json(),
                            model=model_name,
                            prompt_version=self.prompt_version,
                        )

            # De-redact surrogate tokens back to original indicators
            restored_assessment = (
                self.redactor.restore_assessment(assessment) if assessment else None
            )

            # Create or update findings
            if c_findings:
                for f in c_findings:
                    enriched_findings.append(
                        Finding(
                            id=f.id,
                            cluster_ids=f.cluster_ids,
                            rule_ids=f.rule_ids,
                            rule_severity=f.rule_severity,
                            llm=restored_assessment,
                        )
                    )
            else:
                # If there was no initial rule finding, only surface a finding if LLM identified a real threat
                if (
                    restored_assessment
                    and restored_assessment.attack_type
                    and restored_assessment.attack_type.lower()
                    not in ("none", "benign", "info", "normal")
                    and restored_assessment.severity in ("critical", "high", "medium")
                    and restored_assessment.false_positive_likelihood != "high"
                ):
                    enriched_findings.append(
                        Finding(
                            id=f"finding-{cluster.id}",
                            cluster_ids=[cluster.id],
                            rule_ids=[],
                            rule_severity=restored_assessment.severity,
                            llm=restored_assessment,
                        )
                    )

            stats["triaged_clusters"] += 1

        # Preserve any original findings for clusters that were not in top selected
        for f in initial_findings:
            if not any(cid in triaged_cluster_ids for cid in f.cluster_ids):
                enriched_findings.append(f)

        return enriched_findings, stats
