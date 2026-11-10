"""Notifier factory resolving notification channel backends."""

from __future__ import annotations

from typing import Any

from loglens.notify.base import CompositeNotifier, MockNotifier, Notifier
from loglens.notify.discord import DiscordNotifier
from loglens.notify.telegram import TelegramNotifier
from loglens.notify.webhook import WebhookNotifier


def get_notifier(name: str, **kwargs: Any) -> Notifier:
    """Resolve and configure a notification channel by name.

    Supported names: 'telegram', 'discord', 'webhook', 'mock', 'composite'.
    """
    normalized = name.strip().lower()

    if normalized == "telegram":
        return TelegramNotifier(**kwargs)
    if normalized == "discord":
        return DiscordNotifier(**kwargs)
    if normalized == "webhook":
        return WebhookNotifier(**kwargs)
    if normalized == "mock":
        return MockNotifier(**kwargs)
    if normalized == "composite":
        return CompositeNotifier(**kwargs)

    raise ValueError(
        f"Unknown notifier channel '{name}'. Supported channels: telegram, discord, webhook, mock, composite."
    )
