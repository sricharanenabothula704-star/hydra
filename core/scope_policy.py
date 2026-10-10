"""Fail-closed hostname checks for authorized HYDRA targets."""

from __future__ import annotations

import ipaddress
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit


DEFAULT_ALLOWLIST = Path.home() / ".config" / "opencode" / "SCOPE_ALLOWLIST.txt"


def normalize_host(target: str) -> str:
    """Extract and normalize a URL/hostname without accepting userinfo."""
    raw = target.strip()
    if not raw:
        raise ValueError("target is empty")
    parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URLs must not contain username/password")
    host = parsed.hostname
    if not host:
        raise ValueError("target must contain a hostname")
    host = host.rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("target hostname is invalid") from exc


def _normalize_rule(rule: str) -> tuple[str, str]:
    rule = rule.strip().lower().rstrip(".")
    if not rule or any(char in rule for char in "/:@?[]"):
        raise ValueError(f"invalid scope rule: {rule}")
    if "*" not in rule:
        host = rule
        kind = "domain"
    elif rule.startswith("*."):
        host = rule[2:]
        kind = "subdomains"
    else:
        labels = rule.split(".")
        if len(labels) < 2 or "*" in labels[-1]:
            raise ValueError(f"wildcards must match whole DNS labels: {rule}")
        if any("*" in label and label.count("*") != 1 for label in labels):
            raise ValueError(f"invalid wildcard in scope rule: {rule}")
        host = rule
        kind = "labels"
    try:
        if kind == "labels":
            host = ".".join(
                label if "*" in label else label.encode("idna").decode("ascii")
                for label in host.split(".")
            )
        else:
            host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid scope rule: {rule}") from exc
    if kind == "subdomains":
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("wildcards cannot be used with IP addresses")
        if "." not in host:
            raise ValueError("wildcards must target a multi-label domain")
    return kind, host


def scope_decision(
    target: str, allowlist_path: Optional[Path] = None
) -> tuple[bool, str]:
    """Return (allowed, reason). Missing or invalid allowlists fail closed."""
    try:
        host = normalize_host(target)
    except ValueError as exc:
        return False, str(exc)

    path = allowlist_path or DEFAULT_ALLOWLIST
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False, f"scope allowlist missing: {path}"

    rules = []
    invalid_rules = []
    for line in lines:
        rule = line.split("#", 1)[0].strip()
        if not rule:
            continue
        try:
            rules.append(_normalize_rule(rule))
        except ValueError as exc:
            invalid_rules.append(str(exc))

    if not rules:
        return False, "scope allowlist is empty"

    host_labels = host.split(".")
    for kind, rule_host in rules:
        if kind == "subdomains":
            # Require a DNS label boundary: notexample.com must not match
            # *.example.com.
            if host.endswith("." + rule_host) and host != rule_host:
                return True, f"{host} matches *.{rule_host}"
        elif kind == "labels":
            rule_labels = rule_host.split(".")
            if len(host_labels) == len(rule_labels) and all(
                fnmatchcase(label, pattern)
                for label, pattern in zip(host_labels, rule_labels)
            ):
                return True, f"{host} matches label pattern {rule_host}"
        elif host == rule_host or host.endswith("." + rule_host):
            return True, f"{host} is covered by {rule_host}"

    if not rules and invalid_rules:
        return False, invalid_rules[0]
    return False, f"{host} is not in the scope allowlist"


def require_scope(target: str, allowlist_path: Optional[Path] = None) -> str:
    """Return normalized host or raise PermissionError if out of scope."""
    allowed, reason = scope_decision(target, allowlist_path)
    if not allowed:
        raise PermissionError(reason)
    return normalize_host(target)
