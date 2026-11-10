"""Parser for authentication logs (sshd, sudo, pam, su)."""

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from loglens.models import Event, compute_raw_hash
from loglens.parsers.base import extract_common_system_fields, resolve_syslog_timestamp

# Regex patterns for syslog headers
# Legacy syslog: Oct 11 14:32:10 hostname daemon[pid]: message
RE_LEGACY_HEADER = re.compile(
    r"^([A-Z][a-z]{2})\s+([0-9]{1,2})\s+([0-9]{2}:[0-9]{2}:[0-9]{2})\s+([^\s]+)\s+([a-zA-Z0-9_\-\.]+)(?:\[([0-9]+)\])?:\s*(.*)$"
)

# RFC 3339 / ISO timestamp syslog header
RE_ISO_HEADER = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)\s+([^\s]+)\s+([a-zA-Z0-9_\-\.]+)(?:\[([0-9]+)\])?:\s*(.*)$"
)

# sshd patterns
RE_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?([^\s]+) from ([0-9a-fA-F\.:]+) port ([0-9]+) ssh2?"
)
RE_ACCEPTED_AUTH = re.compile(
    r"Accepted (password|publickey|keyboard-interactive) for ([^\s]+) from ([0-9a-fA-F\.:]+) port ([0-9]+) ssh2?"
)
RE_INVALID_USER = re.compile(r"Invalid user ([^\s]+) from ([0-9a-fA-F\.:]+)(?: port ([0-9]+))?")
RE_CONNECTION_CLOSED = re.compile(
    r"Connection (?:closed|reset) by (?:authenticating user ([^\s]+) )?([0-9a-fA-F\.:]+) port ([0-9]+)"
)

# sudo patterns
RE_SUDO = re.compile(
    r"([^\s]+)\s*:\s*(?:TTY=([^\s;]+)\s*;\s*)?(?:PWD=([^\s;]+)\s*;\s*)?(?:USER=([^\s;]+)\s*;\s*)?COMMAND=(.*)"
)

# PAM patterns
RE_PAM_FAIL = re.compile(r"pam_unix\(([^)]+)\):\s*authentication failure;\s*(.*)")


class AuthLogParser:
    """Parser for /var/log/auth.log and /var/log/secure."""

    name = "auth"
    description = "Linux authentication logs (sshd, sudo, PAM, su)"

    def matches_sample(self, sample_lines: Sequence[str]) -> float:
        """Score confidence that sample is an auth log."""
        if not sample_lines:
            return 0.0

        auth_matches = 0
        for line in sample_lines:
            if (
                any(k in line for k in ("sshd[", "sudo:", "pam_unix", "sshd:", "su:", "systemd-logind"))
                or "Failed password" in line
                or "Accepted publickey" in line
                or "Accepted password" in line
                or "invalid user" in line
                or "[preauth]" in line
                or "Connection reset by" in line
                or "Connection closed by" in line
                or "authenticating user" in line
            ):
                auth_matches += 1

        return auth_matches / len(sample_lines)

    def parse_line(
        self,
        raw_line: str,
        line_number: int,
        *,
        reference_dt: datetime | None = None,
    ) -> Event | None:
        """Parse a single auth log line."""
        line = raw_line.strip()
        if not line:
            return None

        ts: datetime
        host: str | None = None
        source: str = "auth"
        msg: str = line

        # 1. Parse header
        m_iso = RE_ISO_HEADER.match(line)
        if m_iso:
            ts_str, host, source_prog, _pid, msg = m_iso.groups()
            source = source_prog
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
            except ValueError:
                ts = reference_dt or datetime.now(UTC)
        else:
            m_leg = RE_LEGACY_HEADER.match(line)
            if m_leg:
                mon, day, timestr, host, source_prog, _pid, msg = m_leg.groups()
                source = source_prog
                ts = resolve_syslog_timestamp(mon, day, timestr, reference_dt=reference_dt)
            else:
                # No standard syslog header
                ts = reference_dt or datetime.now(UTC)

        fields: dict[str, Any] = {}
        severity_hint: str = "info"

        # 2. Extract specific auth daemon patterns
        # Failed password
        m_fail = RE_FAILED_PASSWORD.search(msg)
        if m_fail:
            user, ip, port = m_fail.groups()
            fields["action"] = "failed_password"
            fields["user"] = user
            fields["ip"] = ip
            fields["port"] = int(port)
            fields["invalid_user"] = "invalid user" in msg
            severity_hint = "warning"
        else:
            # Accepted auth
            m_acc = RE_ACCEPTED_AUTH.search(msg)
            if m_acc:
                method, user, ip, port = m_acc.groups()
                fields["action"] = "accepted"
                fields["auth_method"] = method
                fields["user"] = user
                fields["ip"] = ip
                fields["port"] = int(port)
                severity_hint = "info"
            else:
                # Invalid user
                m_inv = RE_INVALID_USER.search(msg)
                if m_inv:
                    user, ip, port = m_inv.groups()
                    fields["action"] = "invalid_user"
                    fields["user"] = user
                    fields["ip"] = ip
                    if port:
                        fields["port"] = int(port)
                    severity_hint = "warning"
                else:
                    # Connection closed
                    m_close = RE_CONNECTION_CLOSED.search(msg)
                    if m_close:
                        user, ip, port = m_close.groups()
                        fields["action"] = "connection_closed"
                        fields["ip"] = ip
                        fields["port"] = int(port)
                        if user:
                            fields["user"] = user
                        severity_hint = "info"
                    else:
                        # Sudo commands
                        m_sudo = RE_SUDO.search(msg)
                        if m_sudo:
                            invoking_user, tty, pwd, target_user, cmd = m_sudo.groups()
                            fields["action"] = "sudo_command"
                            fields["user"] = invoking_user
                            fields["sudo_target_user"] = target_user or "root"
                            fields["command"] = cmd
                            if tty:
                                fields["tty"] = tty
                            if pwd:
                                fields["pwd"] = pwd
                            severity_hint = "info"
                        else:
                            # PAM failure
                            m_pam = RE_PAM_FAIL.search(msg)
                            if m_pam:
                                service, details = m_pam.groups()
                                fields["action"] = "pam_failure"
                                fields["pam_service"] = service
                                rhost_match = re.search(r"rhost=([^\s;]+)", details)
                                ruser_match = re.search(r"ruser=([^\s;]+)", details)
                                if rhost_match and rhost_match.group(1):
                                    fields["ip"] = rhost_match.group(1)
                                if ruser_match and ruser_match.group(1):
                                    fields["user"] = ruser_match.group(1)
                                severity_hint = "warning"

        # Fallback extraction for PAM sessions, cron, systemd-logind, and SSH preauth
        extract_common_system_fields(msg, fields)

        if fields.get("action") == "preauth_reset":
            severity_hint = "low"
            if source == "auth":
                source = "sshd"

        return Event(
            ts=ts,
            source=source,
            host=host,
            severity_hint=severity_hint,
            message=msg,
            fields=fields,
            raw_hash=compute_raw_hash(raw_line),
        )
