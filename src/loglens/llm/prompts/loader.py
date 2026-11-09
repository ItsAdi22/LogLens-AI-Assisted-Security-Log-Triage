"""Loader and formatters for LLM triage prompt templates."""

from __future__ import annotations

from pathlib import Path

from loglens.models import Cluster

PROMPTS_DIR = Path(__file__).parent


def get_system_prompt(version: str = "v1") -> str:
    """Load the versioned triage system prompt."""
    prompt_file = PROMPTS_DIR / f"triage_{version}.md"
    if not prompt_file.exists():
        raise FileNotFoundError(f"Prompt template {prompt_file.name} not found.")
    return prompt_file.read_text(encoding="utf-8")


def get_repair_prompt(error_msg: str, cluster_data: str, version: str = "v1") -> str:
    """Load and format the versioned repair prompt."""
    prompt_file = PROMPTS_DIR / f"repair_{version}.md"
    if not prompt_file.exists():
        raise FileNotFoundError(f"Repair template {prompt_file.name} not found.")
    template = prompt_file.read_text(encoding="utf-8")
    return template.replace("{error}", error_msg).replace("{cluster_data}", cluster_data)


def format_cluster_for_llm(cluster: Cluster, triggered_rules: list[str] | None = None) -> str:
    """Format a Cluster and its metadata into clean text for prompt injection containment."""
    lines: list[str] = [
        f"Cluster ID: {cluster.id}",
        f"Template: {cluster.template}",
        f"Event Count: {cluster.count}",
        f"First Seen: {cluster.first_seen.isoformat()}",
        f"Last Seen: {cluster.last_seen.isoformat()}",
    ]

    if triggered_rules:
        lines.append(f"Triggered Rule IDs: {', '.join(triggered_rules)}")

    if cluster.top_fields:
        top_fields_str = []
        for field, counts in cluster.top_fields.items():
            counts_str = ", ".join(f"('{k}': {c})" for k, c in counts[:5])
            top_fields_str.append(f"{field}: [{counts_str}]")
        lines.append("Top Extracted Fields: " + "; ".join(top_fields_str))

    if cluster.sample_messages:
        lines.append("Sample Raw Messages:")
        for msg in cluster.sample_messages[:3]:
            lines.append(f"  - {msg}")

    return "\n".join(lines)
