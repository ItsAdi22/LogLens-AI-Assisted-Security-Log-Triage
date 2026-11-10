"""Rule-specific fallback remediation advice and descriptions."""

from __future__ import annotations

RULE_DESCRIPTIONS: dict[str, str] = {
    "ssh-invalid-user": "Authentication attempt using a non-existent username.",
    "ssh-preauth-reset": "SSH connection was closed or reset prior to completing authentication.",
    "ssh-bruteforce": "High frequency of failed or rejected SSH authentications from a single source IP.",
    "ssh-bruteforce-001": "Repeated failed SSH password attempts from a single source IP.",
    "ssh-invalid-user-002": "Repeated username enumeration attempts against non-existent accounts.",
    "ssh-root-login-003": "Direct root SSH login detected.",
    "ssh-success-after-failure-004": "Successful SSH login immediately following multiple failed attempts.",
    "ssh-distributed-bruteforce-005": "Coordinated SSH authentication attempts across multiple source IPs.",
    "web-sqli-attempt": "SQL injection syntax detected in HTTP request payload or URI parameters.",
    "web-sqli-attempt-005": "SQL injection attack patterns detected in web query parameters.",
    "web-path-traversal-001": "Directory traversal payload (e.g. ../ or /etc/passwd) detected in HTTP path.",
    "web-xss-attempt-006": "Cross-site scripting (XSS) script tags or event handlers detected in HTTP parameters.",
    "web-env-probe-002": "Automated scan probing for exposed environment or secret files (.env).",
    "web-git-exposure-003": "Probing attempt targeting exposed .git repository configuration or index files.",
    "web-phpmyadmin-probe-004": "Automated scanner searching for publicly accessible phpMyAdmin installations.",
    "web-scanner-ua-007": "HTTP traffic originating from known automated vulnerability scanners.",
    "web-many-404s-008": "Abnormal volume of 404 Not Found responses indicating aggressive content discovery.",
    "web-server-error-spike-009": "Sudden surge in HTTP 5xx responses indicating application fault or crash.",
    "web-wp-login-hammer-010": "Brute-force credential stuffing against WordPress authentication endpoints.",
    "generic-rate-burst-002": "High-volume traffic spike exceeding normal baseline thresholds.",
    "generic-sudo-failed-001": "Failed privilege escalation attempt via sudo command.",
    "syslog-oom-killer-003": "Linux kernel Out-Of-Memory killer invoked to terminate runaway process.",
    "benign-cron-session": "Routine background task executed by cron scheduler.",
    "benign-systemd-logind": "Standard login session lifecycle event managed by systemd-logind.",
    "benign-pam-session": "Standard PAM session open or close for authenticated user.",
}

RULE_REMEDIATIONS: dict[str, str] = {
    "ssh-invalid-user": (
        "Block the source IP address in firewall, disable password authentication in "
        "/etc/ssh/sshd_config (PasswordAuthentication no), and enforce public key pairs."
    ),
    "ssh-preauth-reset": (
        "Rate limit unauthenticated SSH handshakes with iptables or nftables 'recent' module, "
        "and inspect firewall logs for external scanning behavior."
    ),
    "ssh-bruteforce": (
        "Immediately block the attacking IP using 'loglens export actions --format nftables', "
        "enable Fail2ban sshd jail with aggressive ban times, and verify PermitRootLogin is disabled."
    ),
    "ssh-bruteforce-001": (
        "Immediately block the attacking IP using 'loglens export actions --format nftables', "
        "enable Fail2ban sshd jail with aggressive ban times, and verify PermitRootLogin is disabled."
    ),
    "ssh-invalid-user-002": (
        "Block the source IP address in perimeter firewall, enforce public key authentication, "
        "and audit valid local user accounts."
    ),
    "ssh-root-login-003": (
        "Disable direct SSH root login in /etc/ssh/sshd_config (PermitRootLogin no), "
        "enforce non-privileged user access, and require sudo with multi-factor authentication."
    ),
    "ssh-success-after-failure-004": (
        "Urgent: verify whether successful login is legitimate. Rotate user credentials immediately, "
        "check for unauthorized SSH authorized_keys entries, and review active user sessions."
    ),
    "ssh-distributed-bruteforce-005": (
        "Enforce geo-IP filtering or IP reputation blocking on port 22, deploy fail2ban or crowdsec, "
        "and restrict SSH access to trusted VPN ranges."
    ),
    "web-sqli-attempt": (
        "Use parameterized prepared statements across all database queries, sanitize user input, "
        "and verify database user credentials adhere to least privilege."
    ),
    "web-sqli-attempt-005": (
        "Use parameterized prepared statements across all database queries, sanitize user input, "
        "and verify database user credentials adhere to least privilege."
    ),
    "web-path-traversal-001": (
        "Sanitize all file path inputs, resolve paths against an allowed base directory, "
        "and ensure proper chroot or container filesystem isolation."
    ),
    "web-xss-attempt-006": (
        "Sanitize and context-encode all output reflected to browsers, and configure strict Content-Security-Policy headers."
    ),
    "web-env-probe-002": (
        "Block HTTP requests targeting .env or sensitive configuration files via web server configuration, "
        "and ensure web root points only to public/ directory."
    ),
    "web-git-exposure-003": (
        "Deny web server access to .git directories and metadata files in web server configuration, "
        "and remove .git repositories from production document root."
    ),
    "web-phpmyadmin-probe-004": (
        "Remove or restrict phpMyAdmin access to trusted management IPs or internal VPN only."
    ),
    "web-scanner-ua-007": (
        "Block automated vulnerability scanner user-agents (e.g. sqlmap, nikto, nuclei) at reverse proxy or Cloudflare WAF."
    ),
    "web-many-404s-008": (
        "Inspect 404 URL patterns for automated directory busting or vulnerability scanning, and rate-limit offending IP."
    ),
    "web-server-error-spike-009": (
        "Review application error logs and exception traces to address service crashes and unhandled exceptions."
    ),
    "web-wp-login-hammer-010": (
        "Protect /wp-login.php and xmlrpc.php using rate limiting, captcha, or IP whitelisting."
    ),
    "generic-rate-burst-002": (
        "Apply rate limiting per source IP using nginx limit_req or iptables hashlimit."
    ),
    "generic-sudo-failed-001": (
        "Investigate failed sudo attempt for potential privilege escalation. Verify local user integrity and audit /var/log/auth.log."
    ),
    "syslog-oom-killer-003": (
        "Identify memory-leaking process killed by Linux kernel OOM killer, adjust service memory limits, and allocate additional swap or RAM."
    ),
    "benign-cron-session": (
        "Routine scheduled maintenance job executed by system cron daemon. No administrative remediation required."
    ),
    "benign-systemd-logind": (
        "Standard session lifecycle event managed by systemd-logind. Normal operating system behavior."
    ),
    "benign-pam-session": (
        "Standard PAM session open or close for authenticated user. Normal operating system behavior."
    ),
}

DEFAULT_DESCRIPTION = "Deterministic security rule signature matched log event pattern."
DEFAULT_REMEDIATION = (
    "Review security event context, verify authorization with system administrators, "
    "and apply appropriate perimeter firewall rules if source is unrecognized."
)


def get_rule_description(rule_ids: list[str]) -> str:
    """Return descriptive summary of the triggered rule."""
    for rid in rule_ids:
        if rid in RULE_DESCRIPTIONS:
            return RULE_DESCRIPTIONS[rid]
        for key, text in RULE_DESCRIPTIONS.items():
            if rid.startswith(key) or key.startswith(rid):
                return text
    return DEFAULT_DESCRIPTION


def get_rule_remediation(rule_ids: list[str]) -> str:
    """Return specific remediation advice for the first matched rule ID."""
    for rid in rule_ids:
        if rid in RULE_REMEDIATIONS:
            return RULE_REMEDIATIONS[rid]
        for key, text in RULE_REMEDIATIONS.items():
            if rid.startswith(key) or key.startswith(rid):
                return text
    return DEFAULT_REMEDIATION
