"""Suggested action export for firewall and perimeter mitigation.

SAFETY MANDATE:
All exported configurations are generated as advisory scripts only.
LogLens NEVER automatically applies firewall changes, ban rules, or network drops.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from typing import Literal

from loglens.models import Report

TargetFormat = Literal["nftables", "iptables", "cloudflare", "fail2ban"]

SAFETY_BANNER = """# ==============================================================================
# LOGLENS GENERATED ADVISORY ACTIONS - NEVER AUTOMATICALLY APPLIED
# Generated at: {generated_at}
# Total Malicious Target Candidates: {count}
#
# MANDATORY SAFETY NOTICE:
# Review and validate every IP address against internal allowlists before applying.
# Never pipe this script directly into an administrative shell without human verification.
# ==============================================================================
"""


def extract_offending_ips(report: Report, min_severity: str = "high") -> list[str]:
    """Extract distinct source IPs associated with findings meeting minimum severity threshold."""
    sev_rank = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    threshold = sev_rank.get(min_severity.lower(), 4)

    target_cluster_ids: set[str] = set()
    for finding in report.findings:
        effective_sev = finding.rule_severity.lower()
        if finding.llm and finding.llm.severity:
            effective_sev = finding.llm.severity.lower()

        if sev_rank.get(effective_sev, 1) >= threshold:
            target_cluster_ids.update(finding.cluster_ids)

    candidate_ips: set[str] = set()

    for cluster in report.clusters:
        if cluster.id in target_cluster_ids:
            for field_name in ("ip", "client_ip", "source_ip", "rhost"):
                entries = cluster.top_fields.get(field_name, [])
                for val, _ in entries:
                    raw_val = str(val).strip()
                    try:
                        ip_obj = ipaddress.ip_address(raw_val)
                        # Exclude loopback
                        if not ip_obj.is_loopback:
                            candidate_ips.add(str(ip_obj))
                    except ValueError:
                        continue

    return sorted(candidate_ips)


def export_nftables(ips: list[str], set_name: str = "loglens_blacklist") -> str:
    """Generate nftables set configuration."""
    now = datetime.now(UTC).isoformat()
    header = SAFETY_BANNER.format(generated_at=now, count=len(ips))
    if not ips:
        return f"{header}\n# No offending IPs detected meeting the severity threshold.\n"

    elements = ",\n    ".join(ips)
    body = (
        f"#!/usr/sbin/nft -f\n\n"
        f"{header}\n\n"
        f"add set inet filter {set_name} {{ type ipv4_addr; }}\n\n"
        f"add element inet filter {set_name} {{\n"
        f"    {elements}\n"
        f"}}\n"
    )
    return body


def export_iptables(ips: list[str], chain: str = "INPUT") -> str:
    """Generate standard Linux iptables drop commands."""
    now = datetime.now(UTC).isoformat()
    header = SAFETY_BANNER.format(generated_at=now, count=len(ips))
    if not ips:
        return f"{header}\n# No offending IPs detected meeting the severity threshold.\n"

    commands = [f"iptables -I {chain} -s {ip} -j DROP" for ip in ips]
    return f"#!/bin/sh\n\n{header}\nset -e\n\n" + "\n".join(commands) + "\n"


def export_fail2ban(ips: list[str], jail: str = "sshd") -> str:
    """Generate fail2ban-client manual ban execution script."""
    now = datetime.now(UTC).isoformat()
    header = SAFETY_BANNER.format(generated_at=now, count=len(ips))
    if not ips:
        return f"{header}\n# No offending IPs detected meeting the severity threshold.\n"

    commands = [f"fail2ban-client set {jail} banip {ip}" for ip in ips]
    return f"#!/bin/sh\n\n{header}\nset -e\n\n" + "\n".join(commands) + "\n"


def export_cloudflare(ips: list[str], notes: str = "LogLens auto-triage block candidate") -> str:
    """Generate Cloudflare IP Access Rules JSON configuration."""
    rules = []
    for ip in ips:
        rules.append(
            {
                "mode": "block",
                "configuration": {
                    "target": "ip",
                    "value": ip,
                },
                "notes": f"{notes} - generated on {datetime.now(UTC).strftime('%Y-%m-%d')}",
            }
        )
    return json.dumps(rules, indent=2)


def generate_action_export(
    report: Report,
    target: TargetFormat = "nftables",
    min_severity: str = "high",
) -> str:
    """Generate mitigation action configuration in the requested format."""
    ips = extract_offending_ips(report, min_severity=min_severity)

    if target == "nftables":
        return export_nftables(ips)
    if target == "iptables":
        return export_iptables(ips)
    if target == "fail2ban":
        return export_fail2ban(ips)
    if target == "cloudflare":
        return export_cloudflare(ips)

    raise ValueError(f"Unsupported action export format: '{target}'")
