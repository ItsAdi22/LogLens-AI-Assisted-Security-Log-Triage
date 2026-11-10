"""Continuous log file watching and real-time security alerting."""

from __future__ import annotations

import collections
import logging
import os
import signal
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any

from rich.console import Console

from loglens.cluster import DrainClusterer
from loglens.models import Event, Finding, Report, ReportMetadata
from loglens.notify.base import SEVERITY_LEVELS, Notifier
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


class LiveWatchSession:
    """State and handles for an active or stopped live file tail monitor."""

    def __init__(
        self,
        session_id: str,
        log_path: Path,
        monitor: WatchMonitor,
        thread: threading.Thread,
    ) -> None:
        self.session_id = session_id
        self.log_path = log_path
        self.monitor = monitor
        self.thread = thread
        self.started_at = datetime.now(UTC)
        self.total_findings = 0
        self.last_activity = datetime.now(UTC)
        self.status = "ACTIVE"
        self.error: str | None = None


class LiveWatchManager:
    """Manages continuous background watch monitors for live local/server logs."""

    def __init__(self, storage: StorageManager | None = None) -> None:
        self.storage = storage or StorageManager()
        self._sessions: dict[str, LiveWatchSession] = {}
        self._lock = threading.Lock()
        self.recent_activities: collections.deque[dict[str, Any]] = collections.deque(maxlen=50)

    def start_watch(
        self,
        log_path: Path | str,
        interval: float = 2.0,
        from_start: bool = False,
        notifier: Notifier | None = None,
    ) -> str:
        """Start a new background live watch monitor for the target file."""
        path = Path(log_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Target log file does not exist: {path}")

        session_id = f"watch-{uuid.uuid4().hex[:8]}"

        def on_cycle(findings: list[Finding]) -> None:
            with self._lock:
                sess = self._sessions.get(session_id)
                if sess:
                    sess.last_activity = datetime.now(UTC)
                    sess.total_findings += len(findings)
                if findings:
                    top_sev = max(
                        (f.rule_severity.lower() for f in findings),
                        key=lambda s: SEVERITY_LEVELS.get(s, 1),
                        default="info",
                    )
                    self.record_activity(
                        source=path.name,
                        event_count=len(findings),
                        findings_count=len(findings),
                        message=f"Detected {len(findings)} security finding(s) on {path.name}",
                        severity=top_sev,
                    )

        monitor = WatchMonitor(
            log_path=path,
            notifier=notifier,
            storage=self.storage,
            interval=interval,
            from_start=from_start,
        )

        def runner() -> None:
            try:
                monitor.run(on_cycle_complete=on_cycle)
            except Exception as e:
                logger.error("Error in live watch session %s: %s", session_id, e)
                with self._lock:
                    sess = self._sessions.get(session_id)
                    if sess:
                        sess.status = "ERROR"
                        sess.error = str(e)

        thread = threading.Thread(target=runner, daemon=True, name=f"loglens-{session_id}")
        session = LiveWatchSession(session_id, path, monitor, thread)

        with self._lock:
            self._sessions[session_id] = session
            self.record_activity(
                source=path.name,
                event_count=0,
                findings_count=0,
                message=f"Live watch started on {path}",
                severity="info",
            )

        thread.start()
        return session_id

    def stop_watch(self, session_id: str) -> bool:
        """Stop an active background live watch session."""
        with self._lock:
            sess = self._sessions.get(session_id)
            if not sess:
                return False
            sess.monitor.stop()
            sess.status = "STOPPED"
            self.record_activity(
                source=sess.log_path.name,
                event_count=0,
                findings_count=0,
                message=f"Live watch stopped on {sess.log_path.name}",
                severity="info",
            )
            return True

    def list_sessions(self) -> list[dict[str, Any]]:
        """Return status information for all live watch sessions."""
        with self._lock:
            result: list[dict[str, Any]] = []
            for s in self._sessions.values():
                result.append(
                    {
                        "session_id": s.session_id,
                        "log_path": str(s.log_path),
                        "file_name": s.log_path.name,
                        "status": s.status,
                        "started_at": s.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "total_findings": s.total_findings,
                        "last_activity": s.last_activity.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "error": s.error,
                    }
                )
            return result

    def record_activity(
        self,
        source: str,
        event_count: int,
        findings_count: int,
        message: str,
        severity: str = "info",
    ) -> None:
        """Append an entry to the rolling live activity feed."""
        self.recent_activities.appendleft(
            {
                "timestamp": datetime.now(UTC).strftime("%H:%M:%S"),
                "source": source,
                "event_count": event_count,
                "findings_count": findings_count,
                "message": message,
                "severity": severity,
            }
        )

    def stop_all(self) -> None:
        """Stop all background live watch sessions cleanly."""
        with self._lock:
            for s in self._sessions.values():
                s.monitor.stop()
                s.status = "STOPPED"
