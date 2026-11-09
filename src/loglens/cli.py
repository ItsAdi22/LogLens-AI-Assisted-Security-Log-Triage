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
from loglens.models import Event
from loglens.parsers import Parser, registry
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
app.add_typer(rules_app, name="rules")

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
    no_llm: Annotated[
        bool,
        typer.Option(
            "--no-llm",
            help="Run in deterministic mode without calling an LLM.",
        ),
    ] = True,
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
            help="LLM provider (ollama, openai, gemini, anthropic).",
        ),
    ] = "ollama",
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
    findings = rule_engine.evaluate(all_events, clusters)

    # 4. Display Summary Tables
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

    # 5. Display Security Findings Table
    if findings:
        f_table = Table(
            title=f"Security Findings ({len(findings)})",
            show_header=True,
            header_style="bold red",
        )
        f_table.add_column("Severity", style="bold")
        f_table.add_column("Rule ID", style="cyan")
        f_table.add_column("Clusters", style="dim")
        f_table.add_column("Description", style="white")

        sev_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        # Build rule dictionary for descriptions
        rule_map = {r.id: r for r in loaded_rules}

        for f in findings:
            r_id = f.rule_ids[0] if f.rule_ids else "custom"
            r_obj = rule_map.get(r_id)
            title = r_obj.title if r_obj else "Rule Match"
            color = sev_colors.get(f.rule_severity, "white")

            f_table.add_row(
                f"[{color}]{f.rule_severity.upper()}[/{color}]",
                r_id,
                ", ".join(f.cluster_ids[:2]),
                title,
            )
        console.print(f_table)

    # 6. Display Clusters
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
    console.print(Panel(status_message, title="Triage Complete", border_style="green"))


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
    """List all available detection rules."""
    rules = get_builtin_rules()
    if custom_dir:
        rules.extend(load_rules_from_directory(Path(custom_dir)))

    table = Table(
        title=f"Available Detection Rules ({len(rules)})",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Rule ID", style="bold cyan")
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

    for r in sorted(rules, key=lambda x: x.id):
        color = sev_colors.get(r.severity, "white")
        src = r.source if isinstance(r.source, str) else (",".join(r.source) if r.source else "*")
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
