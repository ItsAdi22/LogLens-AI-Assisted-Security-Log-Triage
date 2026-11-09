"""Command Line Interface for LogLens."""

from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from loglens import __version__
from loglens.cluster import DrainClusterer
from loglens.ingest import FileReader, LogSource, StdinReader
from loglens.llm import (
    LLMCache,
    TokenBudget,
    TriageOrchestrator,
    get_provider,
    wrap_untrusted_data,
)
from loglens.llm.consent import verify_cloud_consent
from loglens.llm.prompts.loader import format_cluster_for_llm
from loglens.models import Event, Finding
from loglens.parsers import Parser, registry
from loglens.redact import Redactor
from loglens.rules import (
    RuleEngine,
    get_builtin_rules,
    load_rule_from_file,
    load_rules_from_directory,
)

app = typer.Typer(
    name="loglens",
    help="LogLens — AI-Assisted Security Log Triage (Open Source).",
    no_args_is_help=True,
    add_completion=False,
)
rules_app = typer.Typer(
    name="rules",
    help="Manage, validate, and test LogLens detection rules.",
    no_args_is_help=True,
)
providers_app = typer.Typer(
    name="providers",
    help="Inspect and verify LLM triage provider connectivity.",
    no_args_is_help=True,
)
app.add_typer(rules_app, name="rules")
app.add_typer(providers_app, name="providers")

console = Console()


def version_callback(value: bool) -> None:
    """Print the version and exit."""
    if value:
        console.print(f"LogLens [bold cyan]v{__version__}[/bold cyan]")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """LogLens CLI entrypoint."""


@app.command(name="analyze")
def analyze_command(
    target: Annotated[
        str,
        typer.Argument(help="Path to log file (supports .gz) or '-' to read from standard input."),
    ],
    log_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Log format (auto, auth, web, syslog, json, generic).",
        ),
    ] = "auto",
    llm: Annotated[
        bool,
        typer.Option(
            "--llm/--no-llm",
            help="Enable or disable LLM-assisted triage.",
        ),
    ] = False,
    rules_dir: Annotated[
        str | None,
        typer.Option(
            "--rules",
            "-r",
            help="Optional custom rules directory.",
        ),
    ] = None,
    provider: Annotated[
        str,
        typer.Option(
            "--provider",
            help="LLM provider (ollama, openai, gemini, anthropic, mock).",
        ),
    ] = "ollama",
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            "-m",
            help="Model name or identifier for LLM provider.",
        ),
    ] = None,
    base_url: Annotated[
        str | None,
        typer.Option(
            "--base-url",
            help="Custom endpoint URL for LLM provider (Ollama or OpenAI-compatible).",
        ),
    ] = None,
    redaction: Annotated[
        str,
        typer.Option(
            "--redaction",
            help="Redaction level for sensitive indicators (strict, standard, off).",
        ),
    ] = "standard",
    dry_run_llm: Annotated[
        bool,
        typer.Option(
            "--dry-run-llm",
            help="Inspect redacted cluster payloads and prompts without making LLM API calls.",
        ),
    ] = False,
    agree_cloud_llm: Annotated[
        bool,
        typer.Option(
            "--agree-cloud-llm",
            help="Consent to sending anonymized cluster data to cloud LLM providers.",
        ),
    ] = False,
    out: Annotated[
        str | None,
        typer.Option(
            "--out",
            "-o",
            help="Path to write report.",
        ),
    ] = None,
) -> None:
    """Analyze a security log file and produce triage findings."""
    reader: LogSource
    target_display: str

    if target == "-":
        reader = StdinReader()
        target_display = "stdin"
    else:
        path = Path(target)
        if not path.exists():
            console.print(f"[bold red]Error:[/bold red] Log file not found: {target}")
            raise typer.Exit(code=1)
        reader = FileReader(path)
        target_display = str(path)

    # 1. Resolve or autodetect parser
    parser: Parser | None = None
    if log_format != "auto":
        parser = registry.get(log_format)
        if not parser:
            console.print(
                f"[bold red]Error:[/bold red] Unknown log format '{log_format}'. "
                f"Available: {[p.name for p in registry.list_all()]}"
            )
            raise typer.Exit(code=1)
    else:
        if target == "-":
            parser = registry.get("generic")
        else:
            sample_reader = FileReader(Path(target))
            sample_lines: list[str] = []
            for _, line in sample_reader.stream():
                sample_lines.append(line)
                if len(sample_lines) >= 50:
                    break
            parser = registry.autodetect(sample_lines)

    if not parser:
        parser = registry.get("generic")
        if not parser:
            console.print("[bold red]Error:[/bold red] Failed to load any log parser.")
            raise typer.Exit(code=1)

    console.print(
        f"[bold green]LogLens[/bold green] analyzing [cyan]{target_display}[/cyan] "
        f"using parser [bold magenta]{parser.name}[/bold magenta] ({parser.description})..."
    )

    # 2. Ingest, Parse, and Cluster via Drain3
    clusterer = DrainClusterer()
    all_events: list[Event] = []
    total_lines = 0
    parsed_count = 0
    unparsed_count = 0

    action_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()
    status_counts: Counter[int] = Counter()

    for line_num, raw_line in reader.stream():
        total_lines += 1
        sline = raw_line.strip()
        if not sline:
            continue

        event = parser.parse_line(raw_line, line_num)
        if event is None:
            unparsed_count += 1
            continue

        parsed_count += 1
        all_events.append(event)
        clusterer.add_event(event)

        severity_counts[event.severity_hint or "info"] += 1

        action = event.fields.get("action")
        if action and isinstance(action, str):
            action_counts[action] += 1

        status = event.fields.get("status")
        if status and isinstance(status, int):
            status_counts[status] += 1

        ip = event.fields.get("ip")
        if ip and isinstance(ip, str):
            ip_counts[ip] += 1

    # Get clusters
    clusters = clusterer.get_clusters()

    # 3. Load & Evaluate Security Rules
    loaded_rules = get_builtin_rules()
    if rules_dir:
        loaded_rules.extend(load_rules_from_directory(Path(rules_dir)))

    rule_engine = RuleEngine(loaded_rules)
    findings: list[Finding] = rule_engine.evaluate(all_events, clusters)

    # 4. Handle Dry-Run LLM
    if dry_run_llm:
        redaction_mode = "standard" if redaction not in ("off", "standard", "strict") else redaction
        redactor = Redactor(level=redaction_mode)  # type: ignore[arg-type]

        console.print(
            Panel(
                f"[bold cyan]DRY RUN: LLM Triage Payload Preview[/bold cyan]\n"
                f"Provider: {provider} | Model: {model or 'default'} | Redaction: {redaction_mode}\n"
                f"Clusters targeted for triage: {min(len(clusters), 5)} of {len(clusters)}",
                border_style="cyan",
            )
        )

        for c in clusters[:3]:
            redacted_c = redactor.redact_cluster(c)
            c_rule_ids = [f.rule_ids[0] for f in findings if c.id in f.cluster_ids and f.rule_ids]
            formatted_data = format_cluster_for_llm(redacted_c, c_rule_ids)
            wrapped_data = wrap_untrusted_data(formatted_data)

            console.print(f"[bold yellow]=== Cluster {c.id} Prompt Payload ===[/bold yellow]")
            console.print(wrapped_data)
            console.print()

        console.print(
            f"[dim]Dry-run complete. {len(clusters)} clusters prepared for LLM analysis without network dispatch.[/dim]"
        )
        raise typer.Exit(code=0)

    # 5. LLM Triage Execution (if --llm enabled)
    triage_stats = None
    if llm:
        try:
            llm_provider = get_provider(
                name=provider,
                model=model,
                base_url=base_url,
            )
        except Exception as e:
            console.print(f"[bold red]LLM Provider Error:[/bold red] {e}")
            raise typer.Exit(code=1) from e

        # Check cloud consent
        if not verify_cloud_consent(
            llm_provider, explicit_agreement=agree_cloud_llm, console=console
        ):
            console.print(
                "[bold red]Aborted:[/bold red] Cloud LLM consent not granted. "
                "Pass --agree-cloud-llm or set LOGLENS_AGREE_CLOUD_LLM=1 to proceed."
            )
            raise typer.Exit(code=1)

        redaction_mode = "standard" if redaction not in ("off", "standard", "strict") else redaction
        redactor = Redactor(level=redaction_mode)  # type: ignore[arg-type]
        cache = LLMCache()
        token_budget = TokenBudget()

        orchestrator = TriageOrchestrator(
            provider=llm_provider,
            redactor=redactor,
            cache=cache,
            token_budget=token_budget,
        )

        console.print(
            f"[bold blue]LogLens AI[/bold blue] triaging top security clusters using "
            f"[bold cyan]{llm_provider.name}[/bold cyan]..."
        )
        findings, triage_stats = orchestrator.triage(clusters, findings)

    # 6. Display Summary Tables
    rate = (parsed_count / total_lines * 100) if total_lines > 0 else 0.0

    table = Table(title="Log Parsing Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")

    table.add_row("Total Lines", str(total_lines))
    table.add_row("Parsed Events", f"[green]{parsed_count}[/green]")
    table.add_row("Unparsed Lines", f"[yellow]{unparsed_count}[/yellow]")
    table.add_row("Parse Rate", f"[bold]{rate:.1f}%[/bold]")
    table.add_row("Mined Clusters", str(len(clusters)))
    table.add_row(
        "Security Findings",
        f"[bold red]{len(findings)}[/bold red]" if findings else "[green]0[/green]",
    )

    for sev in ["critical", "error", "warning", "info"]:
        cnt = severity_counts.get(sev, 0)
        if cnt > 0:
            color = (
                "red"
                if sev in ("critical", "error")
                else ("yellow" if sev == "warning" else "blue")
            )
            table.add_row(f"Severity: {sev}", f"[{color}]{cnt}[/{color}]")

    console.print(table)

    # 7. Display Security Findings Table
    if findings:
        f_table = Table(
            title=f"Security Findings ({len(findings)})",
            show_header=True,
            header_style="bold red",
        )
        f_table.add_column("Severity", style="bold")
        f_table.add_column("Rule / Threat", style="cyan")
        f_table.add_column("Clusters", style="dim")
        f_table.add_column("Assessment Summary", style="white")

        sev_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        rule_map = {r.id: r for r in loaded_rules}

        for f in findings:
            r_id = f.rule_ids[0] if f.rule_ids else "ai-triage"
            r_obj = rule_map.get(r_id)
            title = r_obj.title if r_obj else "AI Evaluated Cluster"
            color = sev_colors.get(f.rule_severity, "white")

            summary_text = title
            if f.llm:
                summary_text = f"[bold]{f.llm.attack_type or 'anomaly'}:[/bold] {f.llm.summary}"

            f_table.add_row(
                f"[{color}]{f.rule_severity.upper()}[/{color}]",
                r_id,
                ", ".join(f.cluster_ids[:2]),
                summary_text,
            )
        console.print(f_table)

    # 8. Display LLM Detail Panels if available
    llm_findings = [f for f in findings if f.llm is not None]
    if llm_findings:
        console.print("\n[bold cyan]AI Triage Assessments & Recommendations[/bold cyan]")
        for f in llm_findings[:5]:
            assessment = f.llm
            assert assessment is not None
            details = [
                f"[bold]Attack Type:[/bold] {assessment.attack_type or 'None'}",
                f"[bold]Severity / Confidence:[/bold] {assessment.severity.upper()} ({assessment.confidence * 100:.0f}%)",
                f"[bold]False Positive Likelihood:[/bold] {assessment.false_positive_likelihood}",
                f"[bold]Summary:[/bold] {assessment.summary}",
            ]
            if assessment.evidence:
                details.append("[bold]Evidence:[/bold]")
                for ev in assessment.evidence:
                    details.append(f"  • {ev}")
            if assessment.recommended_actions:
                details.append("[bold]Recommended Defensive Actions:[/bold]")
                for act in assessment.recommended_actions:
                    details.append(f"  ➜ {act}")

            console.print(
                Panel(
                    "\n".join(details),
                    title=f"Finding {f.id} (Cluster {', '.join(f.cluster_ids)})",
                    border_style="cyan",
                )
            )

    # 9. Display Clusters
    if clusters:
        c_table = Table(
            title=f"Mined Template Clusters ({len(clusters)})",
            show_header=True,
            header_style="bold magenta",
        )
        c_table.add_column("Cluster ID", style="cyan")
        c_table.add_column("Events", justify="right")
        c_table.add_column("Template Pattern", style="white")

        for c in clusters[:5]:
            c_table.add_row(c.id, str(c.count), c.template[:70])
        console.print(c_table)

    # Top IP breakdown
    if ip_counts:
        ip_table = Table(
            title="Top Observed IP Addresses", show_header=True, header_style="bold magenta"
        )
        ip_table.add_column("IP Address", style="bold")
        ip_table.add_column("Event Count", justify="right")
        for ip, count in ip_counts.most_common(5):
            ip_table.add_row(ip, str(count))
        console.print(ip_table)

    status_message = (
        f"Analyzed {parsed_count} events into {len(clusters)} clusters.\n"
        f"Evaluated {len(loaded_rules)} rules -> Detected {len(findings)} actionable security findings."
    )
    if triage_stats:
        status_message += (
            f"\nLLM Calls: {triage_stats['llm_calls']} | Cache Hits: {triage_stats['cache_hits']} | "
            f"Repairs: {triage_stats['repair_attempts']} | Injections: {triage_stats['injection_attempts_detected']}"
        )
    console.print(Panel(status_message, title="Triage Complete", border_style="green"))


# =========================================================================
# Providers Subcommands
# =========================================================================


@providers_app.command(name="test")
def providers_test_command(
    provider: Annotated[
        str,
        typer.Option(
            "--provider",
            "-p",
            help="LLM provider name to test (ollama, openai, gemini, anthropic, mock).",
        ),
    ] = "ollama",
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            "-m",
            help="Model name to verify.",
        ),
    ] = None,
    base_url: Annotated[
        str | None,
        typer.Option(
            "--base-url",
            help="Custom endpoint URL for the provider.",
        ),
    ] = None,
) -> None:
    """Test connectivity and configuration for an LLM provider."""
    console.print(f"Testing connectivity to LLM provider [bold cyan]{provider}[/bold cyan]...")

    if provider == "mock":
        console.print("[bold green]OK:[/bold green] Mock provider is operational (local/offline).")
        return

    try:
        prov = get_provider(name=provider, model=model, base_url=base_url)
    except Exception as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(code=1) from e

    test_fn = getattr(prov, "test_connection", None)
    if callable(test_fn):
        res = test_fn()
        status = res.get("status", "unknown")
        if status == "ok":
            console.print(
                f"[bold green]Connection Successful![/bold green] Provider [bold]{provider}[/bold] is ready."
            )
            for k, v in res.items():
                if k != "status":
                    console.print(f"  • {k}: {v}")
        elif status == "warning":
            console.print(
                "[bold yellow]Warning:[/bold yellow] Provider endpoint reached, but model availability is unconfirmed."
            )
            for k, v in res.items():
                if k != "status":
                    console.print(f"  • {k}: {v}")
        else:
            console.print(
                f"[bold red]Connection Failed:[/bold red] {res.get('error', 'Unknown error')}"
            )
            raise typer.Exit(code=1)
    else:
        console.print(f"[bold green]Provider loaded:[/bold green] {prov.name} is configured.")


# =========================================================================
# Rules Subcommands
# =========================================================================


@rules_app.command(name="list")
def rules_list_command(
    custom_dir: Annotated[
        str | None,
        typer.Option(
            "--dir",
            "-d",
            help="Optional path to directory containing custom YAML rules.",
        ),
    ] = None,
) -> None:
    """List all available detection rules with severity and MITRE ATT&CK tags."""
    rules = get_builtin_rules()
    if custom_dir:
        path = Path(custom_dir)
        if not path.exists():
            console.print(f"[bold red]Error:[/bold red] Directory not found: {custom_dir}")
            raise typer.Exit(code=1)
        rules.extend(load_rules_from_directory(path))

    table = Table(
        title=f"Available Detection Rules ({len(rules)} total)",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Rule ID", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Source", style="dim")
    table.add_column("Title", style="white")
    table.add_column("Tags", style="dim")

    sev_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for r in sorted(rules, key=lambda x: (x.severity, x.id)):
        color = sev_colors.get(r.severity, "white")
        src = r.source if isinstance(r.source, str) else ", ".join(r.source or [])
        tags_str = ", ".join(r.tags[:2])
        table.add_row(
            r.id,
            f"[{color}]{r.severity.upper()}[/{color}]",
            src,
            r.title,
            tags_str,
        )

    console.print(table)


@rules_app.command(name="validate")
def rules_validate_command(
    rule_file: Annotated[
        str,
        typer.Argument(help="Path to rule YAML file to validate."),
    ],
) -> None:
    """Validate a YAML rule file against the LogLens schema."""
    path = Path(rule_file)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {rule_file}")
        raise typer.Exit(code=1)

    try:
        rule = load_rule_from_file(path)
        console.print(
            f"[bold green]Valid:[/bold green] Rule '{rule.id}' ({rule.title}) passed schema validation."
        )
    except Exception as e:
        console.print(f"[bold red]Validation Error:[/bold red] {e}")
        raise typer.Exit(code=1) from e


@rules_app.command(name="test")
def rules_test_command(
    rule_file: Annotated[
        str,
        typer.Argument(help="Path to rule YAML file to test."),
    ],
    against: Annotated[
        str,
        typer.Option(
            "--against",
            "-a",
            help="Path to log file to test the rule against.",
        ),
    ],
) -> None:
    """Test a detection rule against a sample log file."""
    rule_path = Path(rule_file)
    log_path = Path(against)

    if not rule_path.exists():
        console.print(f"[bold red]Error:[/bold red] Rule file not found: {rule_file}")
        raise typer.Exit(code=1)
    if not log_path.exists():
        console.print(f"[bold red]Error:[/bold red] Log file not found: {against}")
        raise typer.Exit(code=1)

    rule = load_rule_from_file(rule_path)
    reader = FileReader(log_path)

    # Autodetect parser
    sample_lines: list[str] = []
    for _, line in reader.stream():
        sample_lines.append(line)
        if len(sample_lines) >= 50:
            break
    parser = registry.autodetect(sample_lines)

    clusterer = DrainClusterer()
    events: list[Event] = []
    for line_num, raw_line in reader.stream():
        ev = parser.parse_line(raw_line, line_num)
        if ev:
            events.append(ev)
            clusterer.add_event(ev)

    clusters = clusterer.get_clusters()
    engine = RuleEngine([rule])
    findings = engine.evaluate(events, clusters)

    if findings:
        console.print(
            f"[bold green]RULE FIRED:[/bold green] '{rule.id}' triggered [bold]{len(findings)}[/bold] finding(s) "
            f"across {len(events)} events in {against}."
        )
    else:
        console.print(
            f"[yellow]NO MATCH:[/yellow] '{rule.id}' did not trigger on {against} ({len(events)} events analyzed)."
        )


def main() -> None:
    """Main CLI execution function."""
    app()


if __name__ == "__main__":
    main()
