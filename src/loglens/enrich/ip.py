"""IP address enrichment and classification."""

import ipaddress
from typing import Any


def classify_ip(ip_str: str) -> dict[str, Any]:
    """Classify an IP string into category flags (private, loopback, reserved, version)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return {
            "is_valid": True,
            "version": ip.version,
            "is_private": ip.is_private,
            "is_loopback": ip.is_loopback,
            "is_multicast": ip.is_multicast,
            "is_reserved": ip.is_reserved,
            "is_global": ip.is_global,
        }
    except ValueError:
        return {
            "is_valid": False,
            "version": None,
            "is_private": False,
            "is_loopback": False,
            "is_multicast": False,
            "is_reserved": False,
            "is_global": False,
        }


def is_public_ip(ip_str: str) -> bool:
    """Check if an IP is a globally routable public IP."""
    info = classify_ip(ip_str)
    return bool(info.get("is_valid") and info.get("is_global"))


def lookup_geoip(
    ip_str: str,
    mmdb_path: str | None = None,
) -> dict[str, Any] | None:
    """Perform optional GeoIP enrichment using a local MaxMind GeoLite2 MMDB database.

    Gracefully returns None if geoip2 library is not installed or database is not configured.
    """
    if not mmdb_path or not is_public_ip(ip_str):
        return None

    try:
        import geoip2.database  # type: ignore[import-not-found]

        with geoip2.database.Reader(mmdb_path) as reader:
            response = reader.city(ip_str.strip())
            return {
                "country_code": response.country.iso_code,
                "country_name": response.country.name,
                "city": response.city.name,
            }
    except Exception:
        return None
