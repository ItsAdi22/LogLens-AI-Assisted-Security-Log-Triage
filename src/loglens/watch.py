"""Continuous log file watching and real-time security alerting."""

from __future__ import annotations

import logging
import os
import signal
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType

from rich.console import Console

from loglens.cluster import DrainClusterer
from loglens.models import Event, Finding, Report, ReportMetadata
from loglens.notify.base import Notifier
from loglens.parsers import Parser, registry
from loglens.rules import RuleEngine, get_builtin_rules
from loglens.store import StorageManager

logger = logging.getLogger(__name__)


class WatchMonitor:
    """Watches a log file in real-time, clusters events, evaluates rules, and alerts."""

    def __init__(
        self,
        log_path: Path,
        parser: Parser | None = None,
        notifier: Notifier | None = None,
        storage: StorageManager | None = None,
        interval: float = 2.0,
        from_start: bool = False,
        console: Console | None = None,
    ) -> None:
        self.log_path = log_path
        self.parser = parser
        self.notifier = notifier
        self.storage = storage or StorageManager()
        self.interval = interval
        self.from_start = from_start
        self.console = console or Console()
        self._running = False
        self.rule_engine = RuleEngine(get_builtin_rules())
        self.clusterer = DrainClusterer()

    def stop(self) -> None:
        """Signal the watch loop to terminate."""
        self._running = False

    def _process_cycle(
        self,
        events: list[Event],
        lines_count: int,
        on_cycle_complete: Callable[[list[Finding]], None] | None = None,
    ) -> list[Finding]:
        """Evaluate rules on accumulated events and dispatch alerts."""
        clusters = self.clusterer.get_clusters()
        findings = self.rule_engine.evaluate(events, clusters)

        if findings:
            self.console.print(
                f"\n[bold red]⚡ ALERT:[/bold red] Detected [bold]{len(findings)}[/bold] finding(s) "
                f"across {len(events)} recent events:"
            )
            for f in findings:
                self.console.print(
                    f"  • [{f.rule_severity.upper()}] {', '.join(f.rule_ids)}: "
                    f"Clusters {', '.join(f.cluster_ids)}"
                )

                if self.notifier:
                    self.notifier.send_alert(f)

            meta = ReportMetadata(
                generated_at=datetime.now(UTC),
                log_source=str(self.log_path),
                total_lines=lines_count,
                parsed_events=len(events),
                unparsed_lines=lines_count - len(events),
                total_clusters=len(clusters),
                findings_count=len(findings),
            )
            report = Report(metadata=meta, findings=findings, clusters=clusters)
            self.storage.save_run(report)

        if on_cycle_complete:
            on_cycle_complete(findings)

        return findings

    def run(
        self,
        max_iterations: int | None = None,
        on_cycle_complete: Callable[[list[Finding]], None] | None = None,
    ) -> None:
        """Run the tail monitoring loop."""
        self._running = True

        def handle_signal(sig: int, frame: FrameType | None) -> None:
            self.console.print("\n[yellow]Stopping LogLens watch monitor...[/yellow]")
            self.stop()

        try:
            signal.signal(signal.SIGINT, handle_signal)
            signal.signal(signal.SIGTERM, handle_signal)
        except (ValueError, AttributeError):
            pass

        if not self.parser:
            sample_lines: list[str] = []
            if self.log_path.exists():
                with open(self.log_path, encoding="utf-8", errors="replace") as f:
                    for _ in range(50):
                        line = f.readline()
                        if not line:
                            break
                        sample_lines.append(line)
            self.parser = registry.autodetect(sample_lines)

        self.console.print(
            f"[bold green]Watching[/bold green] [cyan]{self.log_path}[/cyan] "
            f"using [bold magenta]{self.parser.name}[/bold magenta] (interval: {self.interval}s)..."
        )

        stat = self.log_path.stat()
        current_ino = getattr(stat, "st_ino", None)
        line_num = 0
        iteration = 0

        with open(self.log_path, encoding="utf-8", errors="replace") as f:
            if not self.from_start:
                f.seek(0, os.SEEK_END)

            cycle_events: list[Event] = []
            cycle_lines = 0

            while self._running:
                line = f.readline()
                if line:
                    line_num += 1
                    cycle_lines += 1
                    event = self.parser.parse_line(line.rstrip("\r\n"), line_num)
                    if event:
                        cycle_events.append(event)
                        self.clusterer.add_event(event)
                    continue

                # Reached current end of file
                if cycle_events:
                    iteration += 1
                    self._process_cycle(cycle_events, cycle_lines, on_cycle_complete)
                    cycle_events = []
                    cycle_lines = 0

                    if max_iterations is not None and iteration >= max_iterations:
                        break

                time.sleep(min(self.interval, 0.2))

                # Check for file rotation or truncation
                if not self.log_path.exists():
                    continue

                try:
                    new_stat = self.log_path.stat()
                    new_ino = getattr(new_stat, "st_ino", None)
                    if (current_ino is not None and new_ino != current_ino) or (
                        new_stat.st_size < f.tell()
                    ):
                        f.close()
                        f = open(self.log_path, encoding="utf-8", errors="replace")  # noqa: SIM115
                        current_ino = new_ino
                        line_num = 0
                except OSError:
                    pass

        self.console.print("[dim]LogLens watch monitor stopped cleanly.[/dim]")
