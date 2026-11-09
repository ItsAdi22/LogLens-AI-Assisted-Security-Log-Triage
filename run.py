"""One-command entrypoint to launch LogLens."""

from __future__ import annotations

import argparse
import contextlib
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"

# Add src to Python module path
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def seed_sample_data(db_path: Path) -> None:
    """Pre-populate the SQLite database with sample runs if empty, for immediate dashboard usability."""
    from loglens.cluster import DrainClusterer
    from loglens.ingest import FileReader
    from loglens.parsers import AuthLogParser
    from loglens.rules import RuleEngine, get_builtin_rules
    from loglens.store import StorageManager

    storage = StorageManager(db_path)
    runs = storage.list_runs(limit=1)
    if runs:
        return  # Already seeded

    # Seed sample_auth.log
    auth_log = ROOT_DIR / "examples" / "sample_auth.log"
    if auth_log.exists():
        reader = FileReader(auth_log)
        parser = AuthLogParser()
        clusterer = DrainClusterer()
        engine = RuleEngine(get_builtin_rules())
        events = []
        for line_num, line in reader.stream():
            ev = parser.parse_line(line, line_num)
            if ev:
                events.append(ev)
                clusterer.add_event(ev)
        from datetime import UTC, datetime

        from loglens.models import Report, ReportMetadata

        clusters = clusterer.get_clusters()
        findings = engine.evaluate(events, clusters)
        meta = ReportMetadata(
            generated_at=datetime.now(UTC),
            log_source=str(auth_log),
            total_lines=len(events),
            parsed_events=len(events),
            unparsed_lines=0,
            total_clusters=len(clusters),
            findings_count=len(findings),
        )
        report = Report(metadata=meta, findings=findings, clusters=clusters)
        storage.save_run(report)


def start_web_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Launch the LogLens FastAPI web dashboard and open browser."""
    import uvicorn
    from rich.console import Console
    from rich.panel import Panel

    from loglens.store import DEFAULT_DB_PATH
    from loglens.web.app import create_app

    console = Console()
    url = f"http://{host}:{port}"

    console.print(
        Panel.fit(
            f"[bold cyan]LogLens v1.0.0[/bold cyan] — [green]Local-First Security Log Triage Console[/green]\n"
            f"Dashboard URL: [bold yellow]{url}[/bold yellow]\n"
            f"[dim]Press [bold]Ctrl+C[/bold] in this terminal to stop the server.[/dim]",
            border_style="cyan",
        )
    )

    # Seed sample data if database is new
    seed_sample_data(DEFAULT_DB_PATH)

    # Automatically open default browser after a short delay
    def open_browser() -> None:
        time.sleep(1.2)
        with contextlib.suppress(Exception):
            webbrowser.open(url)

    threading.Thread(target=open_browser, daemon=True).start()

    app = create_app(db_path=DEFAULT_DB_PATH, provider_name="mock")
    uvicorn.run(app, host=host, port=port, log_level="warning")


def run_all_tests() -> None:
    """Execute Option C: unit tests with coverage, eval scenarios, and performance benchmark."""
    from rich.console import Console

    console = Console()
    console.rule("[bold cyan]1/3 Running Unit & Integration Tests (pytest)[/bold cyan]")
    subprocess.run([sys.executable, "-m", "pytest", "--cov=src/loglens", "-v"], check=True)

    console.rule("[bold cyan]2/3 Running 12-Scenario AI Evaluation Suite[/bold cyan]")
    subprocess.run([sys.executable, "-m", "tests.eval.run", "--provider", "mock"], check=True)

    console.rule("[bold cyan]3/3 Running Large-File Performance Benchmark[/bold cyan]")
    sample_file = ROOT_DIR / "examples" / "sample_auth.log"
    subprocess.run(
        [sys.executable, "scripts/benchmark_large_file.py", str(sample_file)],
        check=True,
    )

    console.rule("[bold green]All Tests & Benchmarks Completed Successfully![/bold green]")


def run_demo() -> None:
    """Execute interactive CLI demo."""
    demo_script = ROOT_DIR / "examples" / "demo_walkthrough.py"
    subprocess.run([sys.executable, str(demo_script)], check=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LogLens — One-command launcher for Security Log Triage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py               # Starts Web Dashboard and opens http://127.0.0.1:8080
  python run.py --test        # Runs all tests, eval benchmarks, and profiler
  python run.py --demo        # Runs interactive terminal walkthrough
  python run.py --port 9000   # Starts Web Dashboard on custom port
        """,
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run full test suite, eval scenarios, and profiler",
    )
    parser.add_argument("--demo", action="store_true", help="Run interactive terminal walkthrough")
    parser.add_argument("--host", default="127.0.0.1", help="Web UI host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Web UI port (default: 8080)")
    args, _unknown = parser.parse_known_args()

    if args.test:
        run_all_tests()
    elif args.demo:
        run_demo()
    else:
        start_web_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
