"""Dynamic plugin discovery and registration using Python entry points."""

from __future__ import annotations

import importlib.metadata
import logging
from typing import Any

from loglens.parsers.base import registry as parser_registry

logger = logging.getLogger(__name__)

PARSER_GROUP = "loglens.parsers"
RULES_GROUP = "loglens.rules"
NOTIFIER_GROUP = "loglens.notifiers"


def load_plugins() -> dict[str, list[str]]:
    """Discover and register all installed plugins via entry points."""
    loaded: dict[str, list[str]] = {
        PARSER_GROUP: [],
        RULES_GROUP: [],
        NOTIFIER_GROUP: [],
    }

    # Load custom parsers
    try:
        parser_eps = importlib.metadata.entry_points(group=PARSER_GROUP)
        for ep in parser_eps:
            try:
                plugin_cls_or_inst = ep.load()
                parser_inst = (
                    plugin_cls_or_inst()
                    if isinstance(plugin_cls_or_inst, type)
                    else plugin_cls_or_inst
                )
                if hasattr(parser_inst, "name") and hasattr(parser_inst, "parse_line"):
                    parser_registry.register(parser_inst)
                    loaded[PARSER_GROUP].append(ep.name)
            except Exception as e:
                logger.warning("Failed to load parser plugin '%s': %s", ep.name, e)
    except Exception as e:
        logger.debug("Entry points error loading parsers: %s", e)

    # Load custom rules
    try:
        rule_eps = importlib.metadata.entry_points(group=RULES_GROUP)
        for ep in rule_eps:
            try:
                ep.load()
                loaded[RULES_GROUP].append(ep.name)
            except Exception as e:
                logger.warning("Failed to load rules plugin '%s': %s", ep.name, e)
    except Exception as e:
        logger.debug("Entry points error loading rules: %s", e)

    # Load custom notifiers
    try:
        notifier_eps = importlib.metadata.entry_points(group=NOTIFIER_GROUP)
        for ep in notifier_eps:
            try:
                ep.load()
                loaded[NOTIFIER_GROUP].append(ep.name)
            except Exception as e:
                logger.warning("Failed to load notifier plugin '%s': %s", ep.name, e)
    except Exception as e:
        logger.debug("Entry points error loading notifiers: %s", e)

    return loaded


def list_installed_plugins() -> list[dict[str, Any]]:
    """Return an inventory of installed plugins discovered via entry points."""
    inventory: list[dict[str, Any]] = []
    groups = [PARSER_GROUP, RULES_GROUP, NOTIFIER_GROUP]

    for g in groups:
        try:
            eps = importlib.metadata.entry_points(group=g)
            for ep in eps:
                inventory.append(
                    {
                        "name": ep.name,
                        "group": g,
                        "value": ep.value,
                    }
                )
        except Exception:
            continue

    return inventory
