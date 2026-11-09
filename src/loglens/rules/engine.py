"""Deterministic rule evaluation engine."""

import re
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

import yaml

from loglens.models import Cluster, Event, Finding
from loglens.rules.schema import Rule, parse_window_to_seconds


def load_rule_from_file(file_path: Path) -> Rule:
    """Load and validate a single YAML rule file."""
    with open(file_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Rule file {file_path} does not contain a YAML mapping")
    return Rule.model_validate(data)


def load_rules_from_directory(dir_path: Path) -> list[Rule]:
    """Scan directory recursively for .yml and .yaml rule files."""
    rules: list[Rule] = []
    if not dir_path.exists():
        return rules

    for ext in ("*.yml", "*.yaml"):
        for path in sorted(dir_path.glob(ext)):
            try:
                rule = load_rule_from_file(path)
                rules.append(rule)
            except Exception as e:
                raise ValueError(f"Failed to load rule from {path}: {e}") from e

    return rules


class RuleEngine:
    """Evaluates YAML security rules against normalized events and Drain3 clusters."""

    def __init__(self, rules: Sequence[Rule] | None = None) -> None:
        """Initialize RuleEngine with given rules."""
        self.rules: list[Rule] = list(rules or [])

    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine."""
        self.rules.append(rule)

    def evaluate(
        self,
        events: Sequence[Event],
        clusters: Sequence[Cluster],
    ) -> list[Finding]:
        """Evaluate all loaded rules and return candidate security findings."""
        findings: list[Finding] = []

        # Map cluster templates for fast lookup
        cluster_by_id = {c.id: c for c in clusters}

        for rule in self.rules:
            # 1. Source filter
            target_sources: set[str] | None = None
            if rule.source:
                target_sources = {rule.source} if isinstance(rule.source, str) else set(rule.source)

            filtered_events: list[Event] = []
            for ev in events:
                if target_sources is None or ev.source in target_sources:
                    filtered_events.append(ev)

            if not filtered_events and not clusters:
                continue

            # 2. Check template matches against clusters first
            matching_cluster_ids: set[str] = set()
            if rule.match.template_regex:
                rx = re.compile(rule.match.template_regex, re.IGNORECASE)
                for cluster in clusters:
                    if rx.search(cluster.template):
                        matching_cluster_ids.add(cluster.id)

            # 3. Match individual events
            matched_events: list[Event] = []
            for ev in filtered_events:
                if self._event_matches_rule(ev, rule):
                    matched_events.append(ev)

            # If template matched clusters, correlate events belonging to those templates
            if matching_cluster_ids:
                # Find matching events whose message fits the cluster template
                for cid in matching_cluster_ids:
                    cl = cluster_by_id.get(cid)
                    if cl:
                        for sm in cl.sample_messages:
                            for ev in filtered_events:
                                if ev.message == sm and ev not in matched_events:
                                    matched_events.append(ev)

            if not matched_events and not matching_cluster_ids:
                continue

            # 4. Check conditions (group_by, count_gte, window)
            condition = rule.condition
            if condition is None:
                # Direct match, fires on any occurrence
                c_ids = list(matching_cluster_ids) or (
                    [clusters[0].id] if clusters else ["cluster-default"]
                )
                findings.append(
                    Finding(
                        id=f"finding-{rule.id}",
                        cluster_ids=c_ids,
                        rule_ids=[rule.id],
                        rule_severity=rule.severity,
                        llm=None,
                    )
                )
                continue

            # Check threshold condition
            group_field = condition.group_by
            count_threshold = condition.count_gte
            window_sec = parse_window_to_seconds(condition.window)

            if not group_field:
                # Global count check
                if len(matched_events) >= count_threshold:
                    c_ids = list(matching_cluster_ids) or [c.id for c in clusters[:3]]
                    findings.append(
                        Finding(
                            id=f"finding-{rule.id}",
                            cluster_ids=c_ids,
                            rule_ids=[rule.id],
                            rule_severity=rule.severity,
                            llm=None,
                        )
                    )
            else:
                # Group by entity field (e.g. 'ip', 'user')
                entity_groups: dict[str, list[datetime]] = defaultdict(list)
                for ev in matched_events:
                    ent = ev.fields.get(group_field)
                    if ent is not None:
                        entity_groups[str(ent)].append(ev.ts)

                # Check if any entity group exceeds threshold in window
                fired_entities: list[str] = []
                for entity_val, timestamps in entity_groups.items():
                    timestamps.sort()
                    left = 0
                    max_count = 0
                    for right in range(len(timestamps)):
                        while (timestamps[right] - timestamps[left]).total_seconds() > window_sec:
                            left += 1
                        max_count = max(max_count, right - left + 1)

                    if max_count >= count_threshold:
                        fired_entities.append(entity_val)

                if fired_entities:
                    c_ids = list(matching_cluster_ids) or [c.id for c in clusters[:3]]
                    findings.append(
                        Finding(
                            id=f"finding-{rule.id}",
                            cluster_ids=c_ids,
                            rule_ids=[rule.id],
                            rule_severity=rule.severity,
                            llm=None,
                        )
                    )

        # Sort findings by severity (critical -> high -> medium -> low -> info)
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_rank.get(f.rule_severity, 5))
        return findings

    def _event_matches_rule(self, ev: Event, rule: Rule) -> bool:
        """Check if an Event satisfies a Rule's matching criteria."""
        match = rule.match

        # 1. message_regex
        if match.message_regex and not re.search(match.message_regex, ev.message, re.IGNORECASE):
            return False

        # 2. field_matches
        for k, v in match.field_matches.items():
            if ev.fields.get(k) != v:
                return False

        # 3. field_regex
        for k, pattern in match.field_regex.items():
            val = ev.fields.get(k)
            if val is None or not re.search(pattern, str(val), re.IGNORECASE):
                return False

        return True
