"""Sigma rule importer converting standard Sigma YAML rules into LogLens detection rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from loglens.rules.schema import Rule, RuleCondition, RuleMatch

SIGMA_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}

LOGSOURCE_MAP: dict[str, str] = {
    "webserver": "web",
    "web": "web",
    "nginx": "nginx",
    "apache": "apache",
    "sshd": "sshd",
    "auth": "sshd",
    "syslog": "syslog",
    "firewall": "ufw",
    "ufw": "ufw",
}


def _slugify(text: str) -> str:
    """Create a clean alphanumeric-dash slug from string."""
    slug = re.sub(r"[^a-zA-Z0-9_\-]+", "-", text.strip().lower())
    return slug.strip("-")[:48]


def convert_sigma_dict_to_rule(sigma_data: dict[str, Any]) -> Rule:
    """Convert a parsed Sigma YAML dictionary into a LogLens Rule instance."""
    raw_id = str(sigma_data.get("id", "")).strip()
    title = str(sigma_data.get("title", "Untitled Sigma Rule")).strip()
    rule_id = f"sigma-{_slugify(raw_id)}" if raw_id else f"sigma-{_slugify(title)}"
    desc = str(sigma_data.get("description", title)).strip()

    raw_level = str(sigma_data.get("level", "medium")).lower()
    severity = SIGMA_SEVERITY_MAP.get(raw_level, "medium")

    # Tags & MITRE normalization
    tags: list[str] = []
    for t in sigma_data.get("tags", []):
        t_str = str(t).strip()
        if t_str.startswith("attack.t"):
            # Normalize attack.t1190 -> T1190
            tags.append(t_str.replace("attack.", "").upper())
        elif t_str.startswith("attack."):
            tags.append(t_str.replace("attack.", ""))
        else:
            tags.append(t_str)

    references = [str(r).strip() for r in sigma_data.get("references", [])]
    false_positives = [str(fp).strip() for fp in sigma_data.get("falsepositives", [])]

    # Target log source
    logsource = sigma_data.get("logsource", {})
    source_candidate = logsource.get("service") or logsource.get("category")
    source: str | None = None
    if source_candidate:
        source = LOGSOURCE_MAP.get(str(source_candidate).lower(), str(source_candidate).lower())

    # Build RuleMatch from detection blocks
    detection = sigma_data.get("detection", {})
    selection = detection.get("selection") or detection.get("keywords") or {}

    template_regex: str | None = None
    message_regex: str | None = None
    field_matches: dict[str, str | int | float | bool] = {}
    field_regex: dict[str, str] = {}

    if isinstance(selection, list):
        # List of keywords matching message body
        escaped_terms = [re.escape(str(term)) for term in selection]
        message_regex = f"(?i)(?:{'|'.join(escaped_terms)})"
    elif isinstance(selection, dict):
        for key, val in selection.items():
            if "|" in key:
                field_name, modifier = key.split("|", 1)
                modifier = modifier.lower()
                if modifier in ("contains", "startswith", "endswith"):
                    if isinstance(val, list):
                        escaped_terms = [re.escape(str(item)) for item in val]
                        pattern = f"(?i)(?:{'|'.join(escaped_terms)})"
                    else:
                        pattern = f"(?i){re.escape(str(val))}"

                    if field_name.lower() in ("message", "msg", "commandline", "command"):
                        message_regex = pattern
                    else:
                        field_regex[field_name] = pattern
                elif modifier in ("re", "regex"):
                    if field_name.lower() in ("message", "msg"):
                        message_regex = str(val)
                    else:
                        field_regex[field_name] = str(val)
            else:
                if isinstance(val, (str, int, float, bool)):
                    field_matches[key] = val
                elif isinstance(val, list):
                    escaped_terms = [re.escape(str(item)) for item in val]
                    field_regex[key] = f"(?i)^(?:{'|'.join(escaped_terms)})$"

    if not message_regex and not field_matches and not field_regex and not template_regex:
        # Fallback keyword match on title/description
        message_regex = f"(?i){re.escape(title[:32])}"

    match = RuleMatch(
        template_regex=template_regex,
        message_regex=message_regex,
        field_matches=field_matches,
        field_regex=field_regex,
    )

    condition = RuleCondition(
        group_by="ip" if "ip" in field_matches or "client_ip" in field_matches else None,
        count_gte=1,
        window="5m",
    )

    return Rule(
        id=rule_id,
        title=title,
        description=desc,
        source=source,
        match=match,
        condition=condition,
        severity=severity,  # type: ignore[arg-type]
        tags=tags,
        references=references,
        false_positives=false_positives,
    )


def import_sigma_file(file_path: Path | str) -> Rule:
    """Read a Sigma YAML file and convert to LogLens Rule."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Sigma rule file not found: {path}")

    content = path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid Sigma YAML structure in {path}")

    return convert_sigma_dict_to_rule(data)


def import_sigma_directory(dir_path: Path | str) -> list[Rule]:
    """Import all Sigma rules (.yml, .yaml) from a directory recursively."""
    path = Path(dir_path)
    if not path.is_dir():
        raise NotADirectoryError(f"Directory not found: {path}")

    rules: list[Rule] = []
    for item in sorted(path.rglob("*.y*ml")):
        try:
            r = import_sigma_file(item)
            rules.append(r)
        except Exception:
            continue

    return rules
