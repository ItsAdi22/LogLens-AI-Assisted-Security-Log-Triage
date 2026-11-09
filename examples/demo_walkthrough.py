"""Interactive self-guided walkthrough demonstrating LogLens capabilities."""

from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from loglens.cluster import DrainClusterer
from loglens.ingest import FileReader
from loglens.llm import MockLLMProvider, TriageOrchestrator
from loglens.parsers import registry
from loglens.redact import Redactor
from loglens.report.html import generate_html_report
from loglens.rules import RuleEngine, get_builtin_rules


def main() -> None:
    console = Console()
    console.print(
        Panel.fit(
            "[bold cyan]LogLens v1.0.0[/bold cyan] — [green]Interactive Security Log Triage Walkthrough[/green]\n"
            "[dim]Autonomous local-first triage: Ingestion -> Clustering -> Rules -> Redaction -> AI Triage[/dim]",
            border_style="cyan",
        )
    )

    sample_log = Path(__file__).resolve().parent / "sample_auth.log"
    console.print(f"\n[bold]1. Reading Log Stream:[/bold] [yellow]{sample_log.name}[/yellow]")

    reader = FileReader(sample_log)
    sample_lines = []
    for _, line in reader.stream():
        sample_lines.append(line)
        if len(sample_lines) >= 50:
            break

    parser = registry.autodetect(sample_lines)
    console.print(f"   [green]✓[/green] Auto-detected format: [bold cyan]{parser.name}[/bold cyan] ({parser.description})")

    # Parse and cluster
    console.print("\n[bold]2. Mining Signature Templates with Drain3 Clustering:[/bold]")
    clusterer = DrainClusterer()
    events = []
    for line_num, raw_line in reader.stream():
        ev = parser.parse_line(raw_line, line_num)
        if ev:
            events.append(ev)
            clusterer.add_event(ev)

    clusters = clusterer.get_clusters()
    console.print(
        f"   [green]✓[/green] Parsed [bold]{len(events)}[/bold] events into [bold green]{len(clusters)}[/bold green] Drain3 clusters."
    )

    cluster_table = Table(title="Mined Log Clusters", show_header=True, header_style="bold magenta")
    cluster_table.add_column("Cluster ID", style="dim", width=12)
    cluster_table.add_column("Count", justify="right", width=8)
    cluster_table.add_column("Template Signature", style="cyan")

    for cl in clusters:
        cluster_table.add_row(cl.id[:8], str(cl.count), cl.template)
    console.print(cluster_table)

    # Evaluate rules
    console.print("\n[bold]3. Evaluating Deterministic MITRE ATT&CK Rules:[/bold]")
    engine = RuleEngine(get_builtin_rules())
    findings = engine.evaluate(events, clusters)
    console.print(f"   [green]✓[/green] Triggered [bold red]{len(findings)}[/bold red] security findings.")

    finding_table = Table(title="Detected Security Incidents", show_header=True, header_style="bold red")
    finding_table.add_column("Severity", width=10)
    finding_table.add_column("Title", style="bold")
    finding_table.add_column("MITRE Technique", style="yellow")
    finding_table.add_column("Source IP / User", style="green")

    for f in findings:
        color = "red" if f.rule_severity in ("high", "critical") else "yellow"
        rules_matched = ", ".join(f.rule_ids) if f.rule_ids else "heuristic"
        finding_table.add_row(f"[{color}]{f.rule_severity.upper()}[/{color}]", f.id[:8], rules_matched, ", ".join(f.cluster_ids))
    console.print(finding_table)

    # Reversible redaction
    console.print("\n[bold]4. Demonstrating Zero-Trust Reversible Token Redaction:[/bold]")
    redactor = Redactor()
    raw_sample = "Failed password for root from 198.51.100.42 port 54321 auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    redacted_sample = redactor.redact(raw_sample)
    console.print(f"   [dim]Raw:[/dim]      {raw_sample}")
    console.print(f"   [green]Redacted:[/green] {redacted_sample}")

    # AI Triage
    console.print("\n[bold]5. Performing AI Incident Assessment (via Deterministic Engine):[/bold]")
    from loglens.models import LLMAssessment

    default_assessment = LLMAssessment(
        summary="Automated triage assessment from AI reasoning engine.",
        attack_type="ssh_bruteforce",
        severity="high",
        confidence=0.95,
        evidence=["Multiple failed SSH logins from single IP address"],
        recommended_actions=[
            "Block IP address at firewall perimeter",
            "Disable SSH password authentication and enforce SSH keys",
            "Review sshd_config for MaxAuthTries limit",
        ],
        false_positive_likelihood="low",
    )
    provider = MockLLMProvider(default_response=default_assessment)
    orchestrator = TriageOrchestrator(provider, redactor)
    t0 = time.perf_counter()
    triaged_findings, triage_stats = orchestrator.triage(clusters, findings=findings)
    elapsed = time.perf_counter() - t0
    console.print(f"   [green]✓[/green] Completed AI assessment across findings in [bold]{elapsed:.3f}s[/bold].")

    llm_findings = [f for f in triaged_findings if f.llm is not None]
    if llm_findings and llm_findings[0].llm:
        assessment = llm_findings[0].llm
        console.print(
            Panel(
                f"[bold cyan]Executive Summary:[/bold cyan] {assessment.summary}\n"
                f"[bold yellow]Attack Classification:[/bold yellow] {assessment.attack_type}\n"
                f"[bold red]Assessed Severity:[/bold red] {assessment.severity}\n"
                f"[bold green]Recommended Containment:[/bold green]\n"
                + "\n".join(f"  • {action}" for action in assessment.recommended_actions[:3]),
                title="AI Forensic Intelligence",
                border_style="green",
            )
        )

    # Report export
    from datetime import UTC, datetime
    from loglens.models import Report, ReportMetadata

    report_out = Path("walkthrough_report.html")
    meta = ReportMetadata(
        generated_at=datetime.now(UTC),
        log_source=sample_log.name,
        total_lines=len(events),
        parsed_events=len(events),
        unparsed_lines=0,
        total_clusters=len(clusters),
        findings_count=len(triaged_findings),
    )
    report = Report(metadata=meta, findings=triaged_findings, clusters=clusters)
    html_content = generate_html_report(report)
    report_out.write_text(html_content, encoding="utf-8")
    console.print(f"\n[bold green]✓ Walkthrough complete![/bold green] Generated report at: [bold]{report_out.resolve()}[/bold]\n")


if __name__ == "__main__":
    main()
