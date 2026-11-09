"""Command Line Interface for LogLens."""

from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from loglens import __version__
from loglens.ingest import FileReader, LogSource, StdinReader
from loglens.parsers import Parser, registry

app = typer.Typer(
    name="loglens",
    help="LogLens — AI-Assisted Security Log Triage (Open Source).",
    no_args_is_help=True,
    add_completion=False,
)
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
        # Sample first lines for autodetect
        if target == "-":
            # For stdin, default to generic or read first line
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

    # 2. Stream through log lines with bounded memory
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

    # 3. Print parsed metrics
    rate = (parsed_count / total_lines * 100) if total_lines > 0 else 0.0

    table = Table(title="Log Parsing Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")

    table.add_row("Total Lines", str(total_lines))
    table.add_row("Parsed Events", f"[green]{parsed_count}[/green]")
    table.add_row("Unparsed Lines", f"[yellow]{unparsed_count}[/yellow]")
    table.add_row("Parse Rate", f"[bold]{rate:.1f}%[/bold]")

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

    # Top Actions or HTTP statuses
    if action_counts:
        act_table = Table(
            title="Top Actions / Events", show_header=True, header_style="bold yellow"
        )
        act_table.add_column("Action", style="bold")
        act_table.add_column("Occurrences", justify="right")
        for act, count in action_counts.most_common(5):
            act_table.add_row(act, str(count))
        console.print(act_table)
    elif status_counts:
        status_table = Table(
            title="HTTP Status Distribution", show_header=True, header_style="bold yellow"
        )
        status_table.add_column("HTTP Status", style="bold")
        status_table.add_column("Requests", justify="right")
        for st, count in status_counts.most_common(5):
            status_table.add_row(str(st), str(count))
        console.print(status_table)

    summary_text = (
        f"Completed deterministic triage of {parsed_count} events from {total_lines} lines.\n"
        "LLM triage is currently disabled (--no-llm mode)."
    )
    console.print(Panel(summary_text, title="Triage Status", border_style="green"))


def main() -> None:
    """Main CLI execution function."""
    app()


if __name__ == "__main__":
    main()
