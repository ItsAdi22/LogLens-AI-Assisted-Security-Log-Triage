"""Unit tests for IP and User-Agent enrichment modules."""

from loglens.enrich.ip import classify_ip, is_public_ip, lookup_geoip
from loglens.enrich.useragent import classify_user_agent, is_scanner_user_agent


def test_classify_ip_private() -> None:
    """Verify private IPv4 classification."""
    info = classify_ip("192.168.1.100")
    assert info["is_valid"] is True
    assert info["is_private"] is True
    assert info["is_global"] is False
    assert is_public_ip("192.168.1.100") is False


def test_classify_ip_public() -> None:
    """Verify globally routable public IPv4 classification."""
    # 8.8.8.8 is a public IP
    info = classify_ip("8.8.8.8")
    assert info["is_valid"] is True
    assert info["is_private"] is False
    assert info["is_global"] is True
    assert is_public_ip("8.8.8.8") is True


def test_classify_ip_invalid() -> None:
    """Verify invalid IP string handling."""
    info = classify_ip("not-an-ip")
    assert info["is_valid"] is False
    assert info["version"] is None
    assert is_public_ip("not-an-ip") is False


def test_classify_user_agent_scanners() -> None:
    """Verify known attack scanners are identified."""
    assert is_scanner_user_agent("Nikto/2.1.6") is True
    assert is_scanner_user_agent("sqlmap/1.7#stable") is True
    assert (
        is_scanner_user_agent(
            "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
        )
        is True
    )
    assert is_scanner_user_agent("gobuster/3.1.0") is True


def test_classify_user_agent_automated_client() -> None:
    """Verify generic HTTP client libraries are classified as automated."""
    res = classify_user_agent("python-requests/2.31.0")
    assert res["is_scanner"] is False
    assert res["is_automated_client"] is True
    assert res["category"] == "http_library"


def test_classify_user_agent_browser_and_empty() -> None:
    """Verify standard browser and empty UA handling."""
    browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    res = classify_user_agent(browser_ua)
    assert res["is_scanner"] is False
    assert res["is_automated_client"] is False
    assert res["category"] == "browser_or_standard"

    empty_res = classify_user_agent("-")
    assert empty_res["is_empty"] is True
    assert empty_res["category"] == "empty"


def test_lookup_geoip_graceful_fallback() -> None:
    """Verify lookup_geoip gracefully returns None when database is not configured."""
    assert lookup_geoip("198.51.100.22", mmdb_path=None) is None
    assert lookup_geoip("192.168.1.1", mmdb_path="fake.mmdb") is None
    assert lookup_geoip("198.51.100.22", mmdb_path="nonexistent.mmdb") is None
