"""Log parsers and autodetect engine."""

from loglens.parsers.auth_log import AuthLogParser
from loglens.parsers.base import Parser, ParserRegistry, registry
from loglens.parsers.generic import GenericParser
from loglens.parsers.json_lines import JsonLinesParser
from loglens.parsers.syslog import SyslogParser
from loglens.parsers.web_access import WebAccessParser

# Register standard built-in parsers
registry.register(AuthLogParser())
registry.register(WebAccessParser())
registry.register(SyslogParser())
registry.register(JsonLinesParser())
registry.register(GenericParser())

__all__ = [
    "AuthLogParser",
    "GenericParser",
    "JsonLinesParser",
    "Parser",
    "ParserRegistry",
    "SyslogParser",
    "WebAccessParser",
    "registry",
]
