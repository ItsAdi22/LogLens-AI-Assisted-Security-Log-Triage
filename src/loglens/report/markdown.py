"""Markdown report formatter for LogLens triage reports."""

from __future__ import annotations

from loglens.models import Report

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

SEVERITY_EMOJIS = {
    "critical": "🚨",
    "high": "🔴",
    "medium": "🟡",
    "low": "🔵",
    "info": "ℹ️",  # noqa: RUF001
}


def generate_markdown_report(report: Report) -> str:
    """Render a comprehensive Markdown triage report."""
    meta = report.metadata
    lines: list[str] = [
        "# LogLens Security Triage Report",
        "",
        f"> **Generated at**: `{meta.generated_at.isoformat()}` | "
        f"**Log Source**: `{meta.log_source}` | "
        f"**Schema Version**: `{meta.schema_version}`",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| **Log Source** | `{meta.log_source}` |",
        f"| **Total Lines Processed** | {meta.total_lines:,} |",
        f"| **Parsed Security Events** | {meta.parsed_events:,} |",
        f"| **Unparsed Lines** | {meta.unparsed_lines:,} |",
        f"| **Mined Template Clusters** | {meta.total_clusters:,} |",
        f"| **Actionable Findings** | **{meta.findings_count}** |",
        "",
    ]

    # Findings Breakdown
    sorted_findings = sorted(
        report.findings,
        key=lambda f: SEVERITY_ORDER.get(f.rule_severity, 1),
        reverse=True,
    )

    if sorted_findings:
        lines.extend(
            [
                "## Actionable Security Findings",
                "",
            ]
        )

        for f in sorted_findings:
            sev_upper = f.rule_severity.upper()
            emoji = SEVERITY_EMOJIS.get(f.rule_severity, "•")
            rules_str = (
                ", ".join(f"`{r}`" for r in f.rule_ids) if f.rule_ids else "*None (AI heuristic)*"
            )
            clusters_str = ", ".join(f"`{c}`" for c in f.cluster_ids)

            lines.append(f"### {emoji} [{sev_upper}] Finding `{f.id}`")
            lines.append("")
            lines.append(f"- **Detection Rules**: {rules_str}")
            lines.append(f"- **Associated Clusters**: {clusters_str}")

            if f.llm:
                lines.append(f"- **Attack Category**: `{f.llm.attack_type or 'unclassified'}`")
                lines.append(f"- **AI Confidence**: {f.llm.confidence * 100:.0f}%")
                lines.append(
                    f"- **False Positive Likelihood**: `{f.llm.false_positive_likelihood}`"
                )
                lines.append("")
                lines.append(f"**Assessment**: {f.llm.summary}")
                lines.append("")

                if f.llm.evidence:
                    lines.append("**Observable Evidence**:")
                    for ev in f.llm.evidence:
                        lines.append(f"- {ev}")
                    lines.append("")

                if f.llm.recommended_actions:
                    lines.append("**Recommended Defensive Actions**:")
                    for act in f.llm.recommended_actions:
                        lines.append(f"- [ ] {act}")
                    lines.append("")
            else:
                lines.append("")
                lines.append(f"*Deterministic rule match on clusters {clusters_str}.*")
                lines.append("")

            lines.append("---")
            lines.append("")
    else:
        lines.extend(
            [
                "## Security Findings",
                "",
                "✅ *No security threats or anomalous rule violations detected in this dataset.*",
                "",
                "---",
                "",
            ]
        )

    # Appendix: Top Clusters
    if report.clusters:
        lines.extend(
            [
                "## Appendix: Top Mined Template Clusters",
                "",
                "| Cluster ID | Events | Template Pattern |",
                "|---|---|---|",
            ]
        )
        for c in report.clusters[:10]:
            clean_tmpl = c.template.replace("|", "\\|")
            lines.append(f"| `{c.id}` | {c.count:,} | `{clean_tmpl}` |")
        lines.append("")

    # Appendix: Statistics
    if report.stats:
        lines.extend(
            [
                "## Appendix: Pipeline Statistics",
                "",
                "```json",
                str(report.stats),
                "```",
                "",
            ]
        )

    return "\n".join(lines)


class MarkdownReportFormatter:
    """Renders Report into formatted Markdown text."""

    def format(self, report: Report) -> str:
        return generate_markdown_report(report)
