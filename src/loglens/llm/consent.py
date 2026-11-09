"""Cloud LLM privacy consent verification and notices."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from rich.console import Console

from loglens.llm.base import LLMProvider

CONSENT_FILE = Path.home() / ".config" / "loglens" / ".cloud_consent_given"


def verify_cloud_consent(
    provider: LLMProvider,
    explicit_agreement: bool = False,
    console: Console | None = None,
) -> bool:
    """Verify that user has consented to transmit redacted data to a cloud LLM provider.

    Returns True if permitted, or False if denied.
    """
    if not provider.is_cloud:
        return True

    # Check environment variable
    if explicit_agreement or os.environ.get("LOGLENS_AGREE_CLOUD_LLM", "").lower() in (
        "1",
        "true",
        "yes",
    ):
        return True

    # Check persisted consent file
    if CONSENT_FILE.exists():
        return True

    # Surface clear privacy disclosure
    c = console or Console(stderr=True)
    c.print(
        "\n[bold yellow]⚠ Cloud LLM Provider Privacy Notice[/bold yellow]\n"
        f"You have configured a cloud-hosted LLM triage provider: [bold cyan]{provider.name}[/bold cyan].\n"
        "Although LogLens applies strict bidirectional redaction (IPs, emails, API keys, credentials),\n"
        "anonymized log cluster templates and event counts will be transmitted to this external service.\n"
        "To suppress this notice, pass [bold]--agree-cloud-llm[/bold] or set [bold]LOGLENS_AGREE_CLOUD_LLM=1[/bold].\n"
    )

    # If stdin is an interactive terminal, offer immediate confirmation
    if sys.stdin.isatty():
        try:
            choice = input("Do you wish to proceed with cloud triage? (y/N): ").strip().lower()
            if choice in ("y", "yes"):
                try:
                    CONSENT_FILE.parent.mkdir(parents=True, exist_ok=True)
                    CONSENT_FILE.write_text("consented", encoding="utf-8")
                except OSError:
                    pass
                return True
        except (EOFError, KeyboardInterrupt):
            pass

    return False
