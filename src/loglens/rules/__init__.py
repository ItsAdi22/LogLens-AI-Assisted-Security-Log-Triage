"""Rule engine and built-in rules package."""

from pathlib import Path

from loglens.rules.engine import (
    RuleEngine,
    load_rule_from_file,
    load_rules_from_directory,
)
from loglens.rules.schema import Rule, RuleCondition, RuleMatch
from loglens.rules.sigma import (
    convert_sigma_dict_to_rule,
    import_sigma_directory,
    import_sigma_file,
)

# Path to shipped built-in rules
BUILTIN_RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules" / "builtin"


def get_builtin_rules() -> list[Rule]:
    """Load all standard built-in rules shipped with LogLens."""
    return load_rules_from_directory(BUILTIN_RULES_DIR)


__all__ = [
    "BUILTIN_RULES_DIR",
    "Rule",
    "RuleCondition",
    "RuleEngine",
    "RuleMatch",
    "convert_sigma_dict_to_rule",
    "get_builtin_rules",
    "import_sigma_directory",
    "import_sigma_file",
    "load_rule_from_file",
    "load_rules_from_directory",
]
