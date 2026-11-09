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
