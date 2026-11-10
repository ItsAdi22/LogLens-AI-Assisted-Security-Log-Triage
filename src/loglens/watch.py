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
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import FrameType
from typing import Any

from rich.console import Console

from loglens.cluster import DrainClusterer
from loglens.models import Event, Finding, Report, ReportMetadata
from loglens.notify.base import SEVERITY_LEVELS, Notifier
from loglens.parsers import AdaptiveMultiParser, Parser, registry
from loglens.rules import RuleEngine, get_builtin_rules
from loglens.store import StorageManager

logger = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30), name="IST")


def _to_ist(dt: datetime) -> datetime:
    """Ensure datetime has timezone and convert to Indian Standard Time (IST)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(IST)


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
        run_id: str | None = None,
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
        self.run_id = run_id or f"run-live-{uuid.uuid4().hex[:8]}"
        self.all_findings: list[Finding] = []
        self.total_lines_streamed = 0
        self.total_events_streamed = 0

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
        self.total_lines_streamed += lines_count
        self.total_events_streamed += len(events)

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

            seen_ids = {af.id for af in self.all_findings}
            for f in findings:
                if f.id not in seen_ids:
                    self.all_findings.append(f)
                    seen_ids.add(f.id)

        # Persist and update the live run in SQLite storage so the dashboard reflects live activity
        if events:
            meta = ReportMetadata(
                generated_at=datetime.now(UTC),
                log_source=str(self.log_path),
                total_lines=self.total_lines_streamed,
                parsed_events=self.total_events_streamed,
                unparsed_lines=max(0, self.total_lines_streamed - self.total_events_streamed),
                total_clusters=len(clusters),
                findings_count=len(self.all_findings),
            )
            report = Report(metadata=meta, findings=self.all_findings, clusters=clusters)
            self.storage.save_run(report, run_id=self.run_id)

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


def discover_remote_sources(client: Any) -> dict[str, list[str]]:
    """Inspect remote Linux VPS to discover available log files, docker containers, and compose directories."""
    probe_script = (
        "sh -c '\n"
        'echo "===FILES==="\n'
        "for f in "
        "/var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages "
        "/usr/local/lsws/logs/access.log /usr/local/lsws/logs/error.log /usr/local/lsws/logs/stderr.log "
        "/var/log/nginx/access.log /var/log/nginx/error.log "
        "/var/log/apache2/access.log /var/log/apache2/error.log "
        "/var/log/httpd/access_log /var/log/httpd/error_log; do\n"
        '  if [ -f "$f" ]; then echo "$f"; fi\n'
        "done\n"
        "for h in /home/*/logs/*.access_log /home/*/logs/*.error_log /var/www/*/storage/logs/*.log ~/pelican-panel/storage/logs/*.log /root/pelican-panel/storage/logs/*.log; do\n"
        '  if [ -f "$h" ]; then echo "$h"; fi\n'
        "done\n"
        'echo "===DOCKER==="\n'
        "if command -v docker >/dev/null 2>&1; then\n"
        '  docker ps --format "{{.Names}}" 2>/dev/null\n'
        "fi\n"
        'echo "===COMPOSE==="\n'
        "for d in ~/pelican-panel /root/pelican-panel /var/www/pelican /var/www/pterodactyl /var/www/*; do\n"
        '  if [ -d "$d" ]; then echo "$d"; fi\n'
        "done\n"
        "'"
    )
    try:
        _stdin, stdout, _stderr = client.exec_command(probe_script, timeout=8.0)
        output = stdout.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Remote source discovery failed: %s", exc)
        return {"files": [], "docker_containers": [], "compose_dirs": []}

    files: list[str] = []
    docker_containers: list[str] = []
    compose_dirs: list[str] = []

    section = ""
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line in ("===FILES===", "---FILES---", "---AUTH---"):
            section = "files"
            continue
        if line in ("===DOCKER===", "---DOCKER---"):
            section = "docker"
            continue
        if line in ("===COMPOSE===", "---COMPOSE---", "---PELICAN---"):
            section = "compose"
            continue
        if line in ("---OLS---",):
            section = "ols"
            continue

        if section == "files":
            files.append(line)
        elif section == "docker":
            docker_containers.append(line)
        elif section == "compose":
            compose_dirs.append(line)
        elif section == "ols":
            files.append(line)

    return {
        "files": files,
        "docker_containers": docker_containers,
        "compose_dirs": compose_dirs,
    }


def summarize_discovered_sources(discovered: dict[str, list[str]]) -> str:
    """Generate a human-readable summary of discovered remote log sources."""
    parts: list[str] = []
    files = discovered.get("files", [])
    containers = discovered.get("docker_containers", [])
    compose_dirs = discovered.get("compose_dirs", [])

    if compose_dirs:
        parts.append(f"Pelican directory: {compose_dirs[0]}")
    if any("auth.log" in f or "secure" in f for f in files):
        parts.append("auth.log")
    if any("lsws" in f for f in files):
        parts.append("OpenLiteSpeed")
    if any("nginx" in f for f in files):
        parts.append("Nginx")
    if any("apache" in f or "httpd" in f for f in files):
        parts.append("Apache")
    if any("/home/" in f for f in files):
        parts.append("Site vhosts")
    if any("laravel" in f or "storage/logs" in f for f in files):
        parts.append("Panel logs")
    if any("syslog" in f or "messages" in f for f in files) and not parts:
        parts.append("syslog")
    if containers:
        c_str = ", ".join(containers[:2])
        parts.append(f"Docker ({c_str})")

    if not parts:
        return "system logs"
    return " • ".join(parts)


def build_unified_stream_command(discovered: dict[str, list[str]]) -> str:
    """Build a unified compound shell command to tail all discovered remote logs and containers."""
    files = discovered.get("files", [])
    containers = discovered.get("docker_containers", [])
    compose_dirs = discovered.get("compose_dirs", [])

    commands: list[str] = []

    if files:
        files_str = " ".join(files)
        commands.append(f"tail -q -n 30 -F {files_str} 2>/dev/null")
    else:
        commands.append(
            "tail -q -n 30 -F /var/log/auth.log /var/log/secure /var/log/syslog 2>/dev/null"
        )

    if containers:
        for c in containers[:4]:
            commands.append(f"docker logs -f --tail=20 {c} 2>/dev/null")
    elif compose_dirs:
        c_dir = compose_dirs[0]
        commands.append(f"cd {c_dir} && docker compose logs -f --tail=20 2>/dev/null")

    if len(commands) == 1:
        return commands[0]

    sub_cmds = " & \n".join(f"({cmd})" for cmd in commands)
    return f"sh -c '\ntrap \"kill 0\" EXIT TERM INT\n{sub_cmds} &\nwait\n'"


class LiveSSHMonitor(WatchMonitor):
    """Watches a remote VPS log stream over SSH in real time."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: str | None = None,
        key_path: str | None = None,
        preset: str = "smart-auto",
        remote_cmd: str = "auto",
        source_label: str = "remote-ssh.log",
        parser: Parser | None = None,
        notifier: Notifier | None = None,
        storage: StorageManager | None = None,
        interval: float = 2.0,
        console: Console | None = None,
        run_id: str | None = None,
    ) -> None:
        super().__init__(
            log_path=Path(source_label),
            parser=parser,
            notifier=notifier,
            storage=storage,
            interval=interval,
            from_start=False,
            console=console,
            run_id=run_id,
        )
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.preset = preset
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

            if self.remote_cmd in ("auto", "", None) or self.preset == "smart-auto":
                discovered = discover_remote_sources(client)
                exec_cmd = build_unified_stream_command(discovered)
                summary_str = summarize_discovered_sources(discovered)
                self.source_label = f"ssh://{self.username}@{self.host} (Unified: {summary_str})"
                self.log_path = Path(self.source_label)
                if self.parser is None or self.parser.name == "generic":
                    self.parser = registry.get("adaptive") or AdaptiveMultiParser()
            else:
                exec_cmd = self.remote_cmd
                if self.parser is None:
                    self.parser = registry.get("adaptive") or AdaptiveMultiParser()

            stdin, stdout, _stderr = client.exec_command(exec_cmd, get_pty=True)
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
                        self.parser = (
                            registry.get("adaptive")
                            or registry.autodetect(lines_to_process[:20])
                            or registry.get("generic")
                        )
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

            # Check if remote process exited with error unexpectedly while still running
            if self._running and channel.exit_status_ready():
                exit_code = channel.recv_exit_status()
                if exit_code not in (0, -1):
                    err_msg = (
                        " ".join(recent_output[-3:]).strip()
                        or f"Process exited with code {exit_code}"
                    )
                    raise RuntimeError(
                        f"Remote command failed (exit code {exit_code}): {err_msg[:200]}"
                    )

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
        self.run_id = monitor.run_id
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
        run_id = f"run-live-{uuid.uuid4().hex[:8]}"

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
            run_id=run_id,
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
        preset: str = "smart-auto",
        remote_cmd: str = "auto",
        source_label: str = "remote-ssh.log",
        interval: float = 2.0,
        notifier: Notifier | None = None,
    ) -> str:
        """Start a new background live watch monitor over SSH for a remote VPS."""
        session_id = f"watch-ssh-{uuid.uuid4().hex[:6]}"
        run_id = f"run-live-{uuid.uuid4().hex[:8]}"
        last_logged_activity = 0.0

        def on_cycle(findings: list[Finding], lines_count: int = 0, events_count: int = 0) -> None:
            nonlocal last_logged_activity
            with self._lock:
                sess = self._sessions.get(session_id)
                # Keep session label in sync if monitor updated it with discovered sources
                if sess and monitor.source_label and sess.source_label != monitor.source_label:
                    sess.source_label = monitor.source_label
                current_label = sess.source_label if sess else monitor.source_label or source_label
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
                        source=current_label,
                        event_count=len(findings),
                        findings_count=len(findings),
                        message=f"Detected {len(findings)} security finding(s) on {current_label}",
                        severity=top_sev,
                    )
                    last_logged_activity = now
                elif lines_count > 0 and (
                    now - last_logged_activity >= 8.0 or (sess and sess.total_lines <= lines_count)
                ):
                    self.record_activity(
                        source=current_label,
                        event_count=events_count,
                        findings_count=0,
                        message=f"Streamed {lines_count} log line(s) ({events_count} parsed events, 0 threats)",
                        severity="info",
                    )
                    last_logged_activity = now

        monitor = LiveSSHMonitor(
            host=host,
            port=port,
            username=username,
            password=password,
            key_path=key_path,
            preset=preset,
            remote_cmd=remote_cmd,
            source_label=source_label,
            notifier=notifier,
            storage=self.storage,
            interval=interval,
            run_id=run_id,
        )

        def runner() -> None:
            try:
                monitor.run(on_cycle_complete=on_cycle)
            except Exception as e:
                with self._lock:
                    sess = self._sessions.get(session_id)
                    # If monitor was intentionally stopped or closed by the user, ignore channel termination
                    if not monitor._running or (sess and sess.status == "STOPPED"):
                        if sess:
                            sess.status = "STOPPED"
                        return
                    logger.error("Error in live SSH watch session %s: %s", session_id, e)
                    current_label = sess.source_label if sess else source_label
                    if sess:
                        sess.status = "ERROR"
                        sess.error = str(e)
                    self.record_activity(
                        source=current_label,
                        event_count=0,
                        findings_count=0,
                        message=f"SSH stream failed on {current_label}: {e}",
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
            sess.status = "STOPPED"
            sess.monitor.stop()
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
                        "started_at": _to_ist(s.started_at).strftime("%Y-%m-%d %H:%M:%S IST"),
                        "total_findings": s.total_findings,
                        "total_lines": s.total_lines,
                        "total_events": s.total_events,
                        "last_activity": _to_ist(s.last_activity).strftime("%Y-%m-%d %H:%M:%S IST"),
                        "is_ssh": s.is_ssh,
                        "run_id": s.run_id,
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
                "timestamp": datetime.now(IST).strftime("%H:%M:%S IST"),
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
    """Test SSH connectivity and detect installed panels, log files, and containers."""
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
        discovered = discover_remote_sources(client)
        summary = summarize_discovered_sources(discovered)
        file_count = len(discovered.get("files", []))
        c_count = len(discovered.get("docker_containers", []))

        client.close()

        detail_msg = (
            f"Connected to {username}@{host}. "
            f"Detected: {summary} ({file_count} log file(s), {c_count} container(s)). "
            f"Unified auto-stream ready!"
        )
        return {
            "success": True,
            "os": "Linux host",
            "message": detail_msg,
            "discovered": discovered,
        }
    except Exception as exc:
        return {
            "success": False,
            "message": f"Connection failed: {exc}",
        }
