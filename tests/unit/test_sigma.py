"""Unit tests for the Sigma rule importer."""

from pathlib import Path

import pytest

from loglens.rules.sigma import (
    convert_sigma_dict_to_rule,
    import_sigma_directory,
    import_sigma_file,
)


def test_convert_sigma_dict_basic() -> None:
    data = {
        "title": "Suspicious JNDI Lookup String",
        "id": "cve-2021-44228-jndi",
        "description": "Detects Log4Shell JNDI strings",
        "level": "critical",
        "tags": [
            "attack.initial_access",
            "attack.t1190",
        ],
        "logsource": {
            "category": "webserver",
        },
        "detection": {
            "selection": {
                "message|contains": [
                    "${jndi:ldap:",
                    "${jndi:rmi:",
                ],
            },
            "condition": "selection",
        },
    }

    rule = convert_sigma_dict_to_rule(data)
    assert rule.id == "sigma-cve-2021-44228-jndi"
    assert rule.title == "Suspicious JNDI Lookup String"
    assert rule.severity == "critical"
    assert rule.source == "web"
    assert "T1190" in rule.tags
    assert "initial_access" in rule.tags
    assert rule.match.message_regex is not None
    assert "jndi" in rule.match.message_regex


def test_convert_sigma_keywords_list() -> None:
    data = {
        "title": "Directory Traversal Attack",
        "level": "high",
        "detection": {
            "keywords": [
                "/etc/passwd",
                "/etc/shadow",
                "..%2f..%2f",
            ],
            "condition": "keywords",
        },
    }

    rule = convert_sigma_dict_to_rule(data)
    assert rule.id.startswith("sigma-directory-traversal")
    assert rule.severity == "high"
    assert rule.match.message_regex is not None
    assert "passwd" in rule.match.message_regex


def test_import_sigma_file_and_directory(tmp_path: Path) -> None:
    rule_content = """title: WordPress Login Hammering
id: wp-login-hammer-01
level: medium
detection:
  selection:
    uri|contains: "/wp-login.php"
    status: 401
  condition: selection
"""
    f = tmp_path / "wp_rule.yml"
    f.write_text(rule_content, encoding="utf-8")

    # Import single file
    rule = import_sigma_file(f)
    assert rule.id == "sigma-wp-login-hammer-01"
    assert rule.severity == "medium"
    assert "uri" in rule.match.field_regex
    assert rule.match.field_matches.get("status") == 401

    # Import directory
    rules = import_sigma_directory(tmp_path)
    assert len(rules) == 1
    assert rules[0].id == "sigma-wp-login-hammer-01"


def test_import_sigma_file_errors(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        import_sigma_file(tmp_path / "nonexistent.yml")

    invalid_file = tmp_path / "invalid.yml"
    invalid_file.write_text("just a string, not a mapping", encoding="utf-8")
    with pytest.raises(ValueError):
        import_sigma_file(invalid_file)
