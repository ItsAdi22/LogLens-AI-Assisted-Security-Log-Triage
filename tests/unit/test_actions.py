"""Unit tests for the suggested action firewall export subsystem."""

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from loglens.actions import (
    export_cloudflare,
    export_fail2ban,
    export_iptables,
    export_nftables,
    extract_offending_ips,
    generate_action_export,
)
from loglens.cli import app
from loglens.models import Cluster, Finding, LLMAssessment, Report, ReportMetadata


def create_sample_attack_report() -> Report:
    c1 = Cluster(
        id="c-attack",
        template="Failed password for invalid user admin from <*>",
        count=25,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        top_fields={"ip": [("198.51.100.22", 20), ("203.0.113.55", 5)]},
    )
    c2 = Cluster(
        id="c-clean",
        template="Accepted publickey for deploy from <*>",
        count=1,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        top_fields={"ip": [("192.0.2.1", 1)]},
    )

    f1 = Finding(
        id="f-crit-01",
        cluster_ids=["c-attack"],
        rule_ids=["ssh_bruteforce"],
        rule_severity="high",
        llm=LLMAssessment(
            summary="Brute force attack",
            attack_type="ssh_bruteforce",
            severity="critical",
            confidence=0.98,
            evidence=["High volume failures"],
            recommended_actions=["Block source IPs"],
            false_positive_likelihood="low",
        ),
    )

    return Report(
        metadata=ReportMetadata(
            generated_at=datetime.now(UTC),
            log_source="auth.log",
            total_lines=26,
            parsed_events=26,
            unparsed_lines=0,
            total_clusters=2,
            findings_count=1,
        ),
        findings=[f1],
        clusters=[c1, c2],
    )


def test_extract_offending_ips() -> None:
    rep = create_sample_attack_report()
    ips = extract_offending_ips(rep, min_severity="high")
    assert "198.51.100.22" in ips
    assert "203.0.113.55" in ips
    # Clean cluster IP should not be in offending list
    assert "192.0.2.1" not in ips


def test_export_nftables_format() -> None:
    ips = ["198.51.100.22", "203.0.113.55"]
    out = export_nftables(ips)
    assert "add element inet filter loglens_blacklist" in out
    assert "198.51.100.22" in out
    assert "NEVER AUTOMATICALLY APPLIED" in out


def test_export_iptables_format() -> None:
    ips = ["198.51.100.22"]
    out = export_iptables(ips)
    assert "iptables -I INPUT -s 198.51.100.22 -j DROP" in out
    assert "NEVER AUTOMATICALLY APPLIED" in out


def test_export_fail2ban_format() -> None:
    ips = ["198.51.100.22"]
    out = export_fail2ban(ips, jail="sshd")
    assert "fail2ban-client set sshd banip 198.51.100.22" in out
    assert "NEVER AUTOMATICALLY APPLIED" in out


def test_export_cloudflare_format() -> None:
    ips = ["198.51.100.22"]
    out = export_cloudflare(ips)
    assert '"mode": "block"' in out
    assert '"value": "198.51.100.22"' in out


def test_generate_action_export_router() -> None:
    rep = create_sample_attack_report()
    nft_script = generate_action_export(rep, target="nftables")
    assert "loglens_blacklist" in nft_script

    ip_script = generate_action_export(rep, target="iptables")
    assert "iptables" in ip_script


def test_cli_export_actions_command(cli_runner: CliRunner, tmp_path: Path) -> None:
    rep = create_sample_attack_report()
    rep_file = tmp_path / "report.json"
    rep_file.write_text(rep.model_dump_json(), encoding="utf-8")

    out_file = tmp_path / "blocklist.nft"

    result = cli_runner.invoke(
        app,
        ["export-actions", str(rep_file), "--target", "nftables", "--out", str(out_file)],
    )
    assert result.exit_code == 0
    assert "Successfully exported nftables actions" in result.output
    assert out_file.exists()
    assert "198.51.100.22" in out_file.read_text(encoding="utf-8")
