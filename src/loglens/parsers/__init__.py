"""Log parsers and autodetect engine."""

from loglens.parsers.auth_log import AuthLogParser
from loglens.parsers.base import Parser, ParserRegistry, registry
from loglens.parsers.database_auth import DatabaseAuthParser
from loglens.parsers.docker_json import DockerJsonParser
from loglens.parsers.fail2ban import Fail2banParser
from loglens.parsers.generic import GenericParser
from loglens.parsers.json_lines import JsonLinesParser
from loglens.parsers.laravel import LaravelParser
from loglens.parsers.minecraft import MinecraftParser
from loglens.parsers.pterodactyl import PterodactylParser
from loglens.parsers.syslog import SyslogParser
from loglens.parsers.ufw import UfwParser
from loglens.parsers.web_access import WebAccessParser

# Register standard built-in parsers
registry.register(AuthLogParser())
registry.register(WebAccessParser())
registry.register(SyslogParser())
registry.register(JsonLinesParser())
registry.register(Fail2banParser())
registry.register(UfwParser())
registry.register(DatabaseAuthParser())
registry.register(LaravelParser())
registry.register(MinecraftParser())
registry.register(PterodactylParser())
registry.register(DockerJsonParser())
registry.register(GenericParser())

__all__ = [
    "AuthLogParser",
    "DatabaseAuthParser",
    "DockerJsonParser",
    "Fail2banParser",
    "GenericParser",
    "JsonLinesParser",
    "LaravelParser",
    "MinecraftParser",
    "Parser",
    "ParserRegistry",
    "PterodactylParser",
    "SyslogParser",
    "UfwParser",
    "WebAccessParser",
    "registry",
]
