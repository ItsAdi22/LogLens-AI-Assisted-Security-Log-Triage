"""Continuous log file watching and real-time security alerting."""

from __future__ import annotations

import collections
import contextlib
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
        on_cycle_complete: Callable[..., None] | None = None,
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
            try:
                on_cycle_complete(findings, lines_count, len(events))
            except TypeError:
                on_cycle_complete(findings)

        return findings

    def run(
        self,
        max_iterations: int | None = None,
        on_cycle_complete: Callable[..., None] | None = None,
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


class LiveSSHMonitor(WatchMonitor):
    """Watches a remote VPS log stream over SSH in real time."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: str | None = None,
        key_path: str | None = None,
        remote_cmd: str = "tail -F /var/log/auth.log",
        source_label: str = "remote-ssh.log",
        parser: Parser | None = None,
        notifier: Notifier | None = None,
        storage: StorageManager | None = None,
        interval: float = 2.0,
        console: Console | None = None,
    ) -> None:
        super().__init__(
            log_path=Path(source_label),
            parser=parser,
            notifier=notifier,
            storage=storage,
            interval=interval,
            from_start=False,
            console=console,
        )
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.remote_cmd = remote_cmd
        self.source_label = source_label
        self._ssh_client: Any = None

    def stop(self) -> None:
        """Signal the watch loop to terminate and close the SSH client."""
        self._running = False
        if self._ssh_client is not None:
            with contextlib.suppress(Exception):
                self._ssh_client.close()

    def run(
        self,
        max_iterations: int | None = None,
        on_cycle_complete: Callable[..., None] | None = None,
    ) -> None:
        """Connect over SSH, stream remote command output, cluster, and evaluate rules."""
        import paramiko

        self._running = True
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh_client = client

        try:
            try:
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password or None,
                    key_filename=self.key_path or None,
                    timeout=12.0,
                    banner_timeout=12.0,
                    look_for_keys=False,
                    allow_agent=False,
                )
            except paramiko.AuthenticationException as auth_err:
                raise RuntimeError(
                    f"Authentication failed for {self.username}@{self.host}: invalid password or key"
                ) from auth_err
            except TimeoutError as to_err:
                raise RuntimeError(
                    f"Connection timed out reaching {self.host}:{self.port} (check host IP and firewall)"
                ) from to_err
            except Exception as conn_err:
                raise RuntimeError(
                    f"Failed to connect to {self.username}@{self.host}:{self.port}: {conn_err}"
                ) from conn_err

            stdin, stdout, _stderr = client.exec_command(self.remote_cmd, get_pty=True)
            stdin.close()
            channel = stdout.channel
            channel.settimeout(0.2)

            buffer: list[str] = []
            recent_output: list[str] = []
            last_flush = time.time()
            iteration = 0
            raw_buf = ""

            while self._running:
                try:
                    data = channel.recv(4096)
                    if not data:
                        # Channel closed by remote end
                        break
                    raw_text = data.decode("utf-8", errors="replace")
                    raw_buf += raw_text
                    while "\n" in raw_buf:
                        line, raw_buf = raw_buf.split("\n", 1)
                        clean_line = line.strip("\r\n")
                        if clean_line:
                            buffer.append(clean_line)
                            recent_output.append(clean_line)
                            if len(recent_output) > 25:
                                recent_output.pop(0)
                except TimeoutError:
                    pass
                except Exception:
                    break

                now = time.time()
                if (now - last_flush >= self.interval and buffer) or len(buffer) >= 50:
                    lines_to_process = list(buffer)
                    buffer.clear()
                    last_flush = now

                    if not self.parser:
                        self.parser = registry.autodetect(lines_to_process[:20]) or registry.get("generic")
                    p_active = self.parser or registry.get("generic")

                    if p_active is not None:
                        events: list[Event] = []
                        for idx, raw_line in enumerate(lines_to_process, start=1):
                            ev = p_active.parse_line(raw_line, idx)
                            if ev:
                                events.append(ev)
                                self.clusterer.add_event(ev)

                        self._process_cycle(events, len(lines_to_process), on_cycle_complete)

                    iteration += 1
                    if max_iterations is not None and iteration >= max_iterations:
                        break

            # Flush any remaining buffer on termination
            if raw_buf.strip():
                buffer.append(raw_buf.strip())
            if buffer:
                p_flush = self.parser or registry.get("generic")
                if p_flush is not None:
                    events = []
                    for idx, raw_line in enumerate(buffer, start=1):
                        ev = p_flush.parse_line(raw_line, idx)
                        if ev:
                            events.append(ev)
                            self.clusterer.add_event(ev)
                    self._process_cycle(events, len(buffer), on_cycle_complete)

            # Check if remote process exited with error
            if channel.exit_status_ready():
                exit_code = channel.recv_exit_status()
                if exit_code != 0:
                    err_msg = " ".join(recent_output[-3:]).strip() or f"Process exited with code {exit_code}"
                    raise RuntimeError(f"Remote command failed (exit code {exit_code}): {err_msg[:200]}")

        finally:
            with contextlib.suppress(Exception):
                client.close()


class LiveWatchSession:
    """State and handles for an active or stopped live file tail monitor."""

    def __init__(
        self,
        session_id: str,
        log_path: Path | str,
        monitor: WatchMonitor,
        thread: threading.Thread,
        *,
        is_ssh: bool = False,
        source_label: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.log_path = Path(log_path) if isinstance(log_path, str) else log_path
        self.source_label = source_label or str(log_path).replace("\\", "/")
        self.monitor = monitor
        self.thread = thread
        self.started_at = datetime.now(UTC)
        self.total_findings = 0
        self.total_lines = 0
        self.total_events = 0
        self.last_activity = datetime.now(UTC)
        self.status = "ACTIVE"
        self.is_ssh = is_ssh
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

        def on_cycle(findings: list[Finding], lines_count: int = 0, events_count: int = 0) -> None:
            with self._lock:
                sess = self._sessions.get(session_id)
                if sess:
                    sess.last_activity = datetime.now(UTC)
                    sess.total_findings += len(findings)
                    sess.total_lines += lines_count
                    sess.total_events += events_count
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
                    self.record_activity(
                        source=path.name,
                        event_count=0,
                        findings_count=0,
                        message=f"Watch monitor error on {path.name}: {e}",
                        severity="high",
                    )

        thread = threading.Thread(target=runner, daemon=True, name=f"loglens-{session_id}")
        session = LiveWatchSession(session_id, path, monitor, thread, is_ssh=False)

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

    def start_ssh_watch(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: str | None = None,
        key_path: str | None = None,
        remote_cmd: str = "tail -n 50 -F /var/log/auth.log",
        source_label: str = "remote-ssh.log",
        interval: float = 2.0,
        notifier: Notifier | None = None,
    ) -> str:
        """Start a new background live watch monitor over SSH for a remote VPS."""
        session_id = f"watch-ssh-{uuid.uuid4().hex[:6]}"
        last_logged_activity = 0.0

        def on_cycle(findings: list[Finding], lines_count: int = 0, events_count: int = 0) -> None:
            nonlocal last_logged_activity
            with self._lock:
                sess = self._sessions.get(session_id)
                if sess:
                    sess.last_activity = datetime.now(UTC)
                    sess.total_findings += len(findings)
                    sess.total_lines += lines_count
                    sess.total_events += events_count

                now = time.time()
                if findings:
                    top_sev = max(
                        (f.rule_severity.lower() for f in findings),
                        key=lambda s: SEVERITY_LEVELS.get(s, 1),
                        default="info",
                    )
                    self.record_activity(
                        source=source_label,
                        event_count=len(findings),
                        findings_count=len(findings),
                        message=f"Detected {len(findings)} security finding(s) on {source_label}",
                        severity=top_sev,
                    )
                    last_logged_activity = now
                elif lines_count > 0 and (
                    now - last_logged_activity >= 8.0 or (sess and sess.total_lines <= lines_count)
                ):
                    self.record_activity(
                        source=source_label,
                        event_count=events_count,
                        findings_count=0,
                        message=f"Streamed {lines_count} log line(s) from {source_label} ({events_count} parsed events, 0 threats)",
                        severity="info",
                    )
                    last_logged_activity = now

        monitor = LiveSSHMonitor(
            host=host,
            port=port,
            username=username,
            password=password,
            key_path=key_path,
            remote_cmd=remote_cmd,
            source_label=source_label,
            notifier=notifier,
            storage=self.storage,
            interval=interval,
        )

        def runner() -> None:
            try:
                monitor.run(on_cycle_complete=on_cycle)
            except Exception as e:
                logger.error("Error in live SSH watch session %s: %s", session_id, e)
                with self._lock:
                    sess = self._sessions.get(session_id)
                    if sess:
                        sess.status = "ERROR"
                        sess.error = str(e)
                    self.record_activity(
                        source=source_label,
                        event_count=0,
                        findings_count=0,
                        message=f"SSH stream failed on {source_label}: {e}",
                        severity="high",
                    )

        thread = threading.Thread(target=runner, daemon=True, name=f"loglens-{session_id}")
        session = LiveWatchSession(
            session_id=session_id,
            log_path=Path(source_label),
            monitor=monitor,
            thread=thread,
            is_ssh=True,
            source_label=source_label,
        )

        with self._lock:
            self._sessions[session_id] = session
            self.record_activity(
                source=source_label,
                event_count=0,
                findings_count=0,
                message=f"Live SSH stream initiated to {username}@{host}",
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
                source=sess.source_label,
                event_count=0,
                findings_count=0,
                message=f"Live watch stopped on {sess.source_label}",
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
                        "log_path": s.source_label,
                        "file_name": s.source_label if s.is_ssh else s.log_path.name,
                        "status": s.status,
                        "started_at": s.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "total_findings": s.total_findings,
                        "total_lines": s.total_lines,
                        "total_events": s.total_events,
                        "last_activity": s.last_activity.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "is_ssh": s.is_ssh,
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


def test_ssh_connection(
    host: str,
    port: int = 22,
    username: str = "root",
    password: str | None = None,
    key_path: str | None = None,
) -> dict[str, Any]:
    """Test SSH connectivity and detect installed panels/services (Pelican, CyberPanel, Docker)."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password or None,
            key_filename=key_path or None,
            timeout=8.0,
            banner_timeout=8.0,
            look_for_keys=False,
            allow_agent=False,
        )
        probe_cmd = (
            "echo '---OS---'; uname -a 2>/dev/null; "
            "echo '---DOCKER---'; which docker 2>/dev/null; "
            "echo '---PELICAN---'; ls -d ~/pelican-panel /root/pelican-panel /var/www/pelican 2>/dev/null; "
            "echo '---OLS---'; ls -d /usr/local/lsws 2>/dev/null; "
            "echo '---AUTH---'; ls /var/log/auth.log /var/log/secure 2>/dev/null"
        )
        _stdin, stdout, _stderr = client.exec_command(probe_cmd, timeout=8.0)
        output = stdout.read().decode("utf-8", errors="replace")
        client.close()

        has_docker = "---DOCKER---\n/" in output or "/docker" in output
        pelican_match = [
            line.strip()
            for line in output.splitlines()
            if "pelican" in line.lower() and "/" in line
        ]
        ols_match = "/usr/local/lsws" in output
        uname_parts = output.split("---OS---\n")
        uname_line = uname_parts[-1].split("\n")[0] if len(uname_parts) > 1 else "Linux"

        details: list[str] = []
        if pelican_match:
            details.append(f"Pelican directory: {pelican_match[0]}")
        if ols_match:
            details.append("CyberPanel OpenLiteSpeed installed")
        if has_docker:
            details.append("Docker installed")

        summary = " • ".join(details) if details else "Connected (Linux host)"
        return {
            "success": True,
            "os": uname_line[:80],
            "message": f"Connected to {username}@{host}. {summary}",
        }
    except Exception as exc:
        return {
            "success": False,
            "message": f"Connection failed: {exc}",
        }
