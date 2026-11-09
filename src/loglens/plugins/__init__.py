"""Plugin management for LogLens."""

from loglens.plugins.loader import (
    NOTIFIER_GROUP,
    PARSER_GROUP,
    RULES_GROUP,
    list_installed_plugins,
    load_plugins,
)

__all__ = [
    "NOTIFIER_GROUP",
    "PARSER_GROUP",
    "RULES_GROUP",
    "list_installed_plugins",
    "load_plugins",
]
