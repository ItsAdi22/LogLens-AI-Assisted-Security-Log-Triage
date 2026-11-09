"""Regex patterns and classification for sensitive data redaction."""

import re

# IPv4 address matching 4 octets 0-255 with word boundaries
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)

# IPv6 address matching standard and compressed forms
IPV6_PATTERN = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r")\b"
)

# Email address matching
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# JSON Web Tokens (standard three-segment header.payload.signature)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-\./+=]{10,}\b")

# AWS Access Key IDs (AKIA, ASIA, etc.)
AWS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")

# Bearer authorization tokens in headers/logs
BEARER_PATTERN = re.compile(
    r"(?i)\bbearer\s+([A-Za-z0-9_\-\.~+/]+=*)",
)

# Credentials embedded in URLs: scheme://user:pass@host
URL_CREDENTIALS_PATTERN = re.compile(r"(?<=://)[^\s/@:]+:[^\s/@:]+(?=@)")

# Sensitive query/parameter keys: password=..., token=..., secret=...
QUERY_CREDENTIALS_PATTERN = re.compile(
    r"(?i)(?:password|secret|token|api_key|apikey|access_token|auth_token)=([^&\s\"',;]+)"
)

# Private key blocks (PEM format)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+)?PRIVATE KEY-----"
)

# Strict-only path patterns (user homes, sensitive system directories)
STRICT_PATH_PATTERN = re.compile(
    r"(?:/(?:home|Users|root)/[a-zA-Z0-9._-]+|"
    r"[a-zA-Z]:\\(?:Users)\\[a-zA-Z0-9._-]+)"
)
