"""Generate synthetic, sanitized security logs for testing and examples."""

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Synthetic IP pools in documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
ATTACKER_IPS = ["192.0.2.10", "192.0.2.11", "192.0.2.12", "198.51.100.5", "198.51.100.6"]
BENIGN_IPS = ["192.0.2.50", "192.0.2.51", "203.0.113.88"]
USERS = ["root", "admin", "ubuntu", "test", "deploy", "guest"]
HOST = "prod-srv-01"


def generate_auth_log(count: int = 200, output_path: Path | None = None) -> list[str]:
    """Generate synthetic auth.log entries with benign traffic and brute force attack."""
    lines: list[str] = []
    base_time = datetime.now(UTC) - timedelta(hours=2)

    # 1. Benign accepted logins
    for i in range(20):
        t = base_time + timedelta(minutes=i * 5)
        timestr = t.strftime("%b %d %H:%M:%S")
        ip = random.choice(BENIGN_IPS)
        user = random.choice(["ubuntu", "deploy"])
        port = random.randint(30000, 60000)
        lines.append(
            f"{timestr} {HOST} sshd[{random.randint(1000, 9999)}]: Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:synthKeyExample"
        )

    # 2. SSH Brute force burst from single attacker IP
    attacker = ATTACKER_IPS[0]
    burst_time = base_time + timedelta(hours=1)
    for i in range(80):
        t = burst_time + timedelta(seconds=i * 2)
        timestr = t.strftime("%b %d %H:%M:%S")
        user = random.choice(USERS)
        port = random.randint(30000, 60000)
        if random.random() < 0.4:
            lines.append(
                f"{timestr} {HOST} sshd[{random.randint(1000, 9999)}]: Failed password for invalid user {user} from {attacker} port {port} ssh2"
            )
        else:
            lines.append(
                f"{timestr} {HOST} sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {attacker} port {port} ssh2"
            )

    # 3. Sudo commands
    for i in range(10):
        t = base_time + timedelta(minutes=i * 10)
        timestr = t.strftime("%b %d %H:%M:%S")
        lines.append(
            f"{timestr} {HOST} sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
        )

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return lines


def generate_web_access_log(count: int = 200, output_path: Path | None = None) -> list[str]:
    """Generate synthetic Nginx/Apache combined access log with benign requests and vulnerability scanner."""
    lines: list[str] = []
    base_time = datetime.now(UTC) - timedelta(hours=3)

    # 1. Benign web requests
    benign_paths = [
        "/",
        "/about",
        "/contact",
        "/assets/app.css",
        "/assets/app.js",
        "/images/logo.png",
    ]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    ]

    for i in range(100):
        t = base_time + timedelta(seconds=i * 15)
        clf_time = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(BENIGN_IPS)
        path = random.choice(benign_paths)
        status = 200 if path != "/contact" else 304
        bytes_sent = random.randint(400, 15000)
        ua = random.choice(user_agents)
        lines.append(
            f'{ip} - - [{clf_time}] "GET {path} HTTP/1.1" {status} {bytes_sent} "https://example.com" "{ua}"'
        )

    # 2. Vulnerability scanner probes from attacker IP
    scanner_ip = ATTACKER_IPS[1]
    scanner_paths = [
        "/wp-login.php",
        "/.env",
        "/.git/config",
        "/phpmyadmin/index.php",
        "/admin.php",
        "/cgi-bin/test.cgi",
        "/actuator/env",
        "/api/v1/debug",
        "/xmlrpc.php",
        "/etc/passwd",
    ]
    scanner_ua = "Nikto/2.1.6"
    scan_time = base_time + timedelta(hours=1, minutes=30)

    for i, probe_path in enumerate(scanner_paths):
        t = scan_time + timedelta(seconds=i * 3)
        clf_time = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{scanner_ip} - - [{clf_time}] "GET {probe_path} HTTP/1.1" 404 162 "-" "{scanner_ua}"'
        )

    # 3. SQL Injection attempts
    sqli_payloads = [
        "/products?id=1%27%20OR%201=1--",
        "/login?user=admin%27%20UNION%20SELECT%20null,password%20FROM%20users--",
    ]
    for i, sqli in enumerate(sqli_payloads):
        t = scan_time + timedelta(seconds=len(scanner_paths) * 3 + i * 5)
        clf_time = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{scanner_ip} - - [{clf_time}] "GET {sqli} HTTP/1.1" 403 210 "-" "sqlmap/1.7#stable"'
        )

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return lines


def main() -> None:
    """Generate sample log files under examples/."""
    examples_dir = Path(__file__).resolve().parent.parent / "examples"
    examples_dir.mkdir(parents=True, exist_ok=True)

    auth_path = examples_dir / "sample_auth.log"
    web_path = examples_dir / "sample_access.log"

    generate_auth_log(output_path=auth_path)
    generate_web_access_log(output_path=web_path)
    print(f"Generated synthetic logs: {auth_path} and {web_path}")


if __name__ == "__main__":
    main()
