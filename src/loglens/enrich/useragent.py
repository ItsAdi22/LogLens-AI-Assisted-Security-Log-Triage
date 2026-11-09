"""User-Agent categorization and threat intelligence heuristics."""

import re
from typing import Any

# Signatures of known vulnerability scanners and automated exploitation tools
KNOWN_SCANNER_REGEXES = [
    re.compile(r"\bnikto\b", re.IGNORECASE),
    re.compile(r"\bsqlmap\b", re.IGNORECASE),
    re.compile(r"\bgobuster\b", re.IGNORECASE),
    re.compile(r"\bdirbuster\b", re.IGNORECASE),
    re.compile(r"\bwpscan\b", re.IGNORECASE),
    re.compile(r"\bnmap\b", re.IGNORECASE),
    re.compile(r"\bmasscan\b", re.IGNORECASE),
    re.compile(r"\bacunetix\b", re.IGNORECASE),
    re.compile(r"\bnessus\b", re.IGNORECASE),
    re.compile(r"\bopenvas\b", re.IGNORECASE),
    re.compile(r"\bmetasploit\b", re.IGNORECASE),
    re.compile(r"\bburpcollaborator\b", re.IGNORECASE),
    re.compile(r"\bhydra\b", re.IGNORECASE),
    re.compile(r"\bzgrab\b", re.IGNORECASE),
    re.compile(r"\bshodan\b", re.IGNORECASE),
    re.compile(r"\bcensys\b", re.IGNORECASE),
]

# Generic HTTP libraries often used by automated scripts
AUTOMATED_CLIENT_REGEXES = [
    re.compile(r"\bpython-requests\b", re.IGNORECASE),
    re.compile(r"\bpython-urllib\b", re.IGNORECASE),
    re.compile(r"\bcurl/[0-9]", re.IGNORECASE),
    re.compile(r"\bwget/[0-9]", re.IGNORECASE),
    re.compile(r"\bgo-http-client\b", re.IGNORECASE),
    re.compile(r"\baiohttp\b", re.IGNORECASE),
    re.compile(r"\bhttpx/[0-9]", re.IGNORECASE),
]


def classify_user_agent(ua: str | None) -> dict[str, Any]:
    """Analyze and classify a User-Agent string."""
    if not ua or not ua.strip() or ua == "-":
        return {
            "is_empty": True,
            "is_scanner": False,
            "is_automated_client": False,
            "category": "empty",
        }

    ua_str = ua.strip()

    for pattern in KNOWN_SCANNER_REGEXES:
        if pattern.search(ua_str):
            return {
                "is_empty": False,
                "is_scanner": True,
                "is_automated_client": True,
                "category": "vulnerability_scanner",
            }

    for pattern in AUTOMATED_CLIENT_REGEXES:
        if pattern.search(ua_str):
            return {
                "is_empty": False,
                "is_scanner": False,
                "is_automated_client": True,
                "category": "http_library",
            }

    return {
        "is_empty": False,
        "is_scanner": False,
        "is_automated_client": False,
        "category": "browser_or_standard",
    }


def is_scanner_user_agent(ua: str | None) -> bool:
    """Check if the User-Agent indicates a known scanner or attack tool."""
    return bool(classify_user_agent(ua).get("is_scanner"))
