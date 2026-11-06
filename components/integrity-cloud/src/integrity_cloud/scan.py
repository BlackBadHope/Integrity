"""Refuse secret-like or private-network content instead of masking it.

Findings name the field path and the finding type only; the matched text is
never echoed, so a report cannot become a second copy of the secret.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

SECRET_PATTERNS = {
    "private_key_material": re.compile(
        "-" * 5 + r"BEGIN (?:[A-Z0-9][A-Z0-9 -]* )?PRIVATE KEY" + "-" * 5
    ),
    "url_embedded_credentials": re.compile(r"https?://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE),
    "github_access_token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"
    ),
    "openai_api_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "bearer_token": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    "slack_token": re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    "telegram_bot_token": re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    "password_assignment": re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[^\s\"']{6,}"
    ),
}
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?i)(?<![0-9a-z_:?])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-z_:])")
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _address_allowed(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True  # not an address (for example a version string with an octet > 255)
    if address.is_loopback or address.is_unspecified:
        return True
    return any(address in network for network in DOCUMENTATION_NETWORKS)


def walk_strings(value: object, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from walk_strings(str(key), path + ".<key>")
            yield from walk_strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_strings(item, f"{path}[{index}]")


def scan(value: object, *, network: bool = False,
         deny_literals: tuple[str, ...] = ()) -> list[dict[str, str]]:
    """Return findings for secret-like strings; with network=True also addresses."""
    findings: list[dict[str, str]] = []
    lowered = tuple(literal.lower() for literal in deny_literals if literal)
    for path, text in walk_strings(value):
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                findings.append({"path": path, "finding": label})
        if network:
            for match in IPV4.finditer(text):
                if not _address_allowed(match.group(0)):
                    findings.append({"path": path, "finding": "non_documentation_ipv4"})
                    break
            for match in IPV6.finditer(text):
                if match.group(0).count(":") >= 2 and not _address_allowed(match.group(0)):
                    findings.append({"path": path, "finding": "non_documentation_ipv6"})
                    break
        if lowered:
            folded = text.lower()
            if any(literal in folded for literal in lowered):
                findings.append({"path": path, "finding": "denied_literal"})
    return findings
