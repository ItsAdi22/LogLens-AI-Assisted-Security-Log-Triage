"""Base abstractions, protocol, and registry for log parsers."""

import contextlib
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from loglens.models import Event

# Regex patterns for PAM, cron, systemd-logind, and SSH
RE_PAM_SESSION = re.compile(
    r"pam_unix\((?P<service>[^)]+)\):\s*session\s+(?P<action>opened|closed)\s+for\s+user\s+(?P<user>[a-zA-Z0-9_\-\.]+)(?:\(uid=[0-9]+\))?(?:\s+by\s+(?P<by_user>[a-zA-Z0-9_\-\.]+)?(?:\(uid=[0-9]+\))?)?",
    re.IGNORECASE,
)
RE_PAM_FAILURE = re.compile(
    r"pam_unix\((?P<service>[^)]+)\):\s*authentication failure;\s*(?P<details>.*)",
    re.IGNORECASE,
)
RE_CRON_CMD = re.compile(
    r"(?:(?:CRON|cron)(?:\[(?P<pid>[0-9]+)\])?:\s*)?\((?P<user>[^)]+)\)\s*(?P<action>CMD|RELOAD)\s*\((?P<cmd>.*)\)",
    re.IGNORECASE,
)
RE_SYSTEMD_LOGIND_NEW = re.compile(
    r"systemd-logind(?:\[[0-9]+\])?:\s*New session\s+(?P<session>[^\s]+)\s+of\s+user\s+(?P<user>[a-zA-Z0-9_\-]+)\.?",
    re.IGNORECASE,
)
RE_SYSTEMD_LOGIND_REMOVED = re.compile(
    r"systemd-logind(?:\[[0-9]+\])?:\s*Removed session\s+(?P<session>[^\s\.]+)\.?",
    re.IGNORECASE,
)
RE_SYSTEMD_LOGIND_LOGOUT = re.compile(
    r"systemd-logind(?:\[[0-9]+\])?:\s*Session\s+(?P<session>[^\s]+)\s+logged out",
    re.IGNORECASE,
)
RE_SSHD_RESET_CLOSED = re.compile(
    r"Connection (?:closed|reset) by (?:invalid user\s+(?P<inv_user>[^\s]+)|authenticating user\s+(?P<auth_user>[^\s]+)|user\s+(?P<norm_user>[^\s]+))?\s*(?P<ip>[0-9a-fA-F\.:]+)\s+port\s+(?P<port>[0-9]+)(?:\s*\[preauth\])?",
    re.IGNORECASE,
)
RE_GENERIC_IP = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
RE_GENERIC_PORT = re.compile(r"\bport\s+([0-9]{1,5})\b", re.IGNORECASE)


def extract_common_system_fields(msg: str, fields: dict[str, Any]) -> None:
    """Extract standard entity fields (user, service, action, ip, port) from system messages."""
    # 1. PAM unix sessions
    m_pam_sess = RE_PAM_SESSION.search(msg)
    if m_pam_sess:
        raw_svc = m_pam_sess.group("service").split(":")[0]
        fields.setdefault("service", raw_svc)
        fields.setdefault("action", f"session_{m_pam_sess.group('action').lower()}")
        fields.setdefault("user", m_pam_sess.group("user"))
        if m_pam_sess.group("by_user"):
            fields.setdefault("by_user", m_pam_sess.group("by_user"))

    # 2. PAM unix failure
    m_pam_fail = RE_PAM_FAILURE.search(msg)
    if m_pam_fail:
        raw_svc = m_pam_fail.group("service").split(":")[0]
        fields.setdefault("service", raw_svc)
        fields.setdefault("action", "auth_failure")
        details = m_pam_fail.group("details")
        rhost = re.search(r"rhost=([^\s;]+)", details)
        ruser = re.search(r"ruser=([^\s;]+)", details)
        usr = re.search(r"\buser=([^\s;]+)", details)
        if rhost and rhost.group(1):
            fields.setdefault("ip", rhost.group(1))
        if ruser and ruser.group(1):
            fields.setdefault("user", ruser.group(1))
        elif usr and usr.group(1):
            fields.setdefault("user", usr.group(1))

    # 3. Cron jobs
    m_cron = RE_CRON_CMD.search(msg)
    if m_cron:
        fields.setdefault("service", "cron")
        act = "cron_cmd" if m_cron.group("action").upper() == "CMD" else "cron_reload"
        fields.setdefault("action", act)
        fields.setdefault("user", m_cron.group("user"))
        fields.setdefault("command", m_cron.group("cmd"))
        if m_cron.group("pid"):
            fields.setdefault("pid", int(m_cron.group("pid")))

    # 4. systemd-logind sessions
    m_new = RE_SYSTEMD_LOGIND_NEW.search(msg)
    if m_new:
        fields.setdefault("service", "systemd-logind")
        fields.setdefault("action", "new_session")
        fields.setdefault("user", m_new.group("user").rstrip("."))
        fields.setdefault("session_id", m_new.group("session"))

    m_rem = RE_SYSTEMD_LOGIND_REMOVED.search(msg)
    if m_rem:
        fields.setdefault("service", "systemd-logind")
        fields.setdefault("action", "removed_session")
        fields.setdefault("session_id", m_rem.group("session"))

    m_out = RE_SYSTEMD_LOGIND_LOGOUT.search(msg)
    if m_out:
        fields.setdefault("service", "systemd-logind")
        fields.setdefault("action", "session_logout")
        fields.setdefault("session_id", m_out.group("session"))

    # 5. SSH connection reset/closed & preauth
    m_ssh_reset = RE_SSHD_RESET_CLOSED.search(msg)
    if m_ssh_reset:
        fields.setdefault("service", "sshd")
        if "[preauth]" in msg:
            fields.setdefault("action", "preauth_reset")
            fields.setdefault("preauth", True)
        else:
            fields.setdefault("action", "connection_closed")
        u = m_ssh_reset.group("inv_user") or m_ssh_reset.group("auth_user") or m_ssh_reset.group("norm_user")
        if u:
            fields.setdefault("user", u)
        if m_ssh_reset.group("inv_user") or "invalid user" in msg.lower():
            fields.setdefault("invalid_user", True)
        fields.setdefault("ip", m_ssh_reset.group("ip"))
        fields.setdefault("port", int(m_ssh_reset.group("port")))

    # 6. Fallback IP and port extraction
    if "ip" not in fields:
        m_ip = RE_GENERIC_IP.search(msg)
        if m_ip:
            fields["ip"] = m_ip.group(0)

    if "port" not in fields:
        m_port = RE_GENERIC_PORT.search(msg)
        if m_port:
            with contextlib.suppress(ValueError):
                fields["port"] = int(m_port.group(1))


def resolve_syslog_timestamp(
    month_str: str,
    day_str: str,
    time_str: str,
    *,
    reference_dt: datetime | None = None,
) -> datetime:
    """Parse a legacy syslog timestamp without a year (e.g. 'Oct 11 14:32:10').

    Handles year rollover (e.g. log in December analyzed in January).
    """
    ref = reference_dt or datetime.now(UTC)
    current_year = ref.year

    # Standard 3-letter month lookup
    months = {
        "Jan": 1,
        "Feb": 2,
        "Mar": 3,
        "Apr": 4,
        "May": 5,
        "Jun": 6,
        "Jul": 7,
        "Aug": 8,
        "Sep": 9,
        "Oct": 10,
        "Nov": 11,
        "Dec": 12,
    }
    month = months.get(month_str.capitalize(), 1)
    day = int(day_str)
    hour, minute, second = (int(x) for x in time_str.split(":"))

    try:
        candidate = datetime(current_year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError:
        # Handle leap year edge cases
        candidate = datetime(current_year, month, min(day, 28), hour, minute, second, tzinfo=UTC)

    # If candidate is more than ~30 days in the future, assume it occurred late last year
    delta_days = (candidate - ref).days
    if delta_days > 30:
        candidate = candidate.replace(year=current_year - 1)

    return candidate


class Parser(Protocol):
    """Protocol for log parser implementations."""

    name: str
    description: str

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Return a confidence score between 0.0 and 1.0 for given sample lines."""
        ...

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single line into a normalized Event, or None if malformed/unparseable."""
        ...


class ParserRegistry:
    """Registry for available log parsers."""

    def __init__(self) -> None:
        self._parsers: dict[str, Parser] = {}

    def register(self, parser: Parser) -> None:
        """Register a parser instance."""
        self._parsers[parser.name] = parser

    def get(self, name: str) -> Parser | None:
        """Get parser by name."""
        return self._parsers.get(name)

    def list_all(self) -> list[Parser]:
        """List all registered parsers."""
        return list(self._parsers.values())

    def autodetect(self, sample_lines: Sequence[str], threshold: float = 0.3) -> Parser:
        """Autodetect the best parser for the sample lines.

        Returns the best matching parser or falls back to 'generic'.
        """
        cleaned_samples = [line.strip() for line in sample_lines if line.strip()][:50]
        if not cleaned_samples:
            generic = self.get("generic")
            if generic is not None:
                return generic
            raise RuntimeError("No parsers registered")

        best_parser: Parser | None = None
        best_score = -1.0

        for parser in self._parsers.values():
            if parser.name == "generic":
                continue
            try:
                score = parser.matches_sample(cleaned_samples)
                if score > best_score:
                    best_score = score
                    best_parser = parser
            except Exception:
                continue

        if best_parser is not None and best_score >= threshold:
            return best_parser

        generic_fallback = self.get("generic")
        if generic_fallback is not None:
            return generic_fallback

        return next(iter(self._parsers.values()))


# Global parser registry instance
registry = ParserRegistry()
