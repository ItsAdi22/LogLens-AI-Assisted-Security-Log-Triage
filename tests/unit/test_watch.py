"""Unit tests for the watch monitor and real-time streaming triage."""

from pathlib import Path

from loglens.models import Finding
from loglens.notify.base import MockNotifier
from loglens.parsers.auth_log import AuthLogParser
from loglens.store import StorageManager
from loglens.watch import LiveWatchManager, WatchMonitor


def test_watch_monitor_detects_appended_attacks(tmp_path: Path) -> None:
    log_file = tmp_path / "stream_auth.log"
    # Seed initially
    log_file.write_text(
        "Nov 09 12:00:00 srv sshd[100]: Accepted publickey for admin from 192.0.2.1 port 52312 ssh2\n",
        encoding="utf-8",
    )

    storage = StorageManager(db_path=":memory:")
    notifier = MockNotifier(min_severity="high", cooldown_seconds=0.0)
    parser = AuthLogParser()

    monitor = WatchMonitor(
        log_path=log_file,
        parser=parser,
        notifier=notifier,
        storage=storage,
        interval=0.5,
        from_start=True,
    )

    # Append attack lines triggering ssh-bruteforce-001
    with open(log_file, "a", encoding="utf-8") as f:
        for i in range(12):
            f.write(
                f"Nov 09 12:01:{i:02d} srv sshd[{1000 + i}]: Failed password for invalid user hacker from 198.51.100.5 port {50000 + i} ssh2\n"
            )
            f.flush()

    captured_findings: list[Finding] = []

    def on_cycle(findings: list[Finding]) -> None:
        captured_findings.extend(findings)

    # Run single cycle
    monitor.run(max_iterations=1, on_cycle_complete=on_cycle)

    assert len(captured_findings) > 0
    # Rule should have fired
    rule_ids = [r for f in captured_findings for r in f.rule_ids]
    assert any("ssh" in r for r in rule_ids)

    # Notifier should have received alert
    assert len(notifier.sent_alerts) > 0
    storage.close()


def test_live_watch_manager_lifecycle(tmp_path: Path) -> None:
    storage = StorageManager(db_path=":memory:")
    manager = LiveWatchManager(storage=storage)

    # 1. Non-existent path raises FileNotFoundError
    import pytest

    with pytest.raises(FileNotFoundError):
        manager.start_watch(tmp_path / "does_not_exist.log")

    # 2. Start watch on real file
    log_file = tmp_path / "active_watch.log"
    log_file.write_text("Nov 10 10:00:00 srv sshd[1]: Initial log\n", encoding="utf-8")

    session_id = manager.start_watch(log_file, interval=0.2, from_start=True)
    assert session_id.startswith("watch-")

    sessions = manager.list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == session_id
    assert sessions[0]["status"] == "ACTIVE"

    # 3. Check activity feed
    assert len(manager.recent_activities) >= 1
    assert "Live watch started" in manager.recent_activities[0]["message"]

    # 4. Stop session
    assert manager.stop_watch(session_id) is True
    assert manager.stop_watch("nonexistent") is False

    updated_sessions = manager.list_sessions()
    assert updated_sessions[0]["status"] == "STOPPED"

    # 5. Stop all
    manager.stop_all()
    storage.close()
