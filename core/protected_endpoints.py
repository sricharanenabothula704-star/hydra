"""Deterministic protection for account- and session-destructive endpoints.

Scope allowlisting answers "is this host authorized?". It does not answer
"is this path safe to touch?". A host can be fully in scope while a single
request to ``/delete-account`` destroys the test account, invalidates the
session, or trips MFA and locks the operator out.

This module is the second, independent gate. It never consults the model and
never reasons about intent: every rule is a literal path pattern matched
against the normalized request URL. Rules are deny-by-default for
account- and session-destructive operations and auth-only for flows that
should not be exercised while testing.

Upstream reference: XBOW's protected-URL policy documents the same categories
(``/logout`` will end the session mid-run, ``/reset-password`` invalidates the
credentials the operator still needs). See
https://docs.xbow.com/console/reference/protected-urls
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

Action = Literal["block", "auth_only", "allow"]

# Actions are ordered most-restrictive-first by the resolver, so an explicit
# `allow` in the caller's rule set can override a built-in default but never
# the other way around.
_ACTION_RANK: dict[str, int] = {"block": 0, "auth_only": 1, "allow": 2}


@dataclass(frozen=True)
class ProtectionRule:
    """A literal path pattern and the action to take when it matches."""

    pattern: str
    action: Action
    reason: str

    def compiled(self) -> re.Pattern[str]:
        return _compile(self.pattern)


_COMPILED: dict[str, re.Pattern[str]] = {}


def _compile(pattern: str) -> re.Pattern[str]:
    cached = _COMPILED.get(pattern)
    if cached is None:
        cached = re.compile(pattern, re.IGNORECASE)
        _COMPILED[pattern] = cached
    return cached


# Each pattern is anchored to the start of the path so that a query string or
# a fragment cannot smuggle a match, and written so that a suffix such as
# ``/api/v2/logout`` is caught as well as ``/logout``.
_DEFS: tuple[tuple[str, str, str], ...] = (
    # --- account destruction ---
    (
        r"^/(?:[\w.-]+/)*(?:delete|close|remove|deactivate)-account(?:/|$)",
        "block",
        "destroys the test account",
    ),
    (
        r"^/(?:[\w.-]+/)*(?:account|settings)/delete(?:/|$)",
        "block",
        "destroys the test account",
    ),
    # --- session destruction: ends the session mid-assessment ---
    (
        r"^/(?:[\w.-]+/)*(?:logout|logoff|signout|sign-out|logoutall)(?:[/?]|$)",
        "block",
        "ends the active session mid-assessment",
    ),
    (
        r"^/(?:[\w.-]+/)*(?:invalidate|revoke|end)-sessions?(?:[/?]|$)",
        "block",
        "ends the active session mid-assessment",
    ),
    # --- credential mutation: invalidates the operator's own credentials ---
    (
        r"^/(?:[\w.-]+/)*(?:reset|change|update)-password(?:[/?]|$)",
        "block",
        "invalidates credentials the operator still needs",
    ),
    (
        r"^/(?:[\w.-]+/)*(?:forgot|request)-password(?:[/?]|$)",
        "block",
        "triggers account-recovery flows",
    ),
    (
        r"^/(?:[\w.-]+/)*(?:change|update|set-new)-email(?:[/?]|$)",
        "block",
        "changes the account identifier",
    ),
    (
        r"^/(?:[\w.-]+/)*(?:oauth/)?revoke(?:[/?]|$)",
        "block",
        "revokes the OAuth grant under test",
    ),
    # --- MFA / OTP: repeated attempts lock the account out ---
    (
        r"^/(?:[\w.-]+/)*(?:2fa|mfa|two-factor|otp)/(?:disable|reset|revoke)(?:[/?]|$)",
        "block",
        "disables or resets MFA",
    ),
    (
        r"^/(?:[\w.-]+/)*(?:reset|verify|submit)[-/]?(?:otp|code|token)(?:[/?]|$)",
        "auth_only",
        "OTP attempts can lock the account",
    ),
    # --- auth entry points: mass attempts cause lockouts and MFA storms ---
    (
        r"^/(?:[\w.-]+/)*(?:login|log-in|signin|sign-in|signon)(?:[/?]|$)",
        "auth_only",
        "auth entry point; brute-force attempts cause lockouts",
    ),
    (
        r"^/(?:[\w.-]+/)*(?:register|signup|sign-up|create-account|authenticate)(?:[/?]|$)",
        "auth_only",
        "auth entry point; mass registration is noisy",
    ),
    (
        r"^/(?:[\w.-]+/)*activate-account(?:[/?]|$)",
        "auth_only",
        "account activation flow",
    ),
    # --- destructive administrative operations ---
    (
        r"^/(?:[\w.-]+/)*(?:admin/)?(?:wipe|purge|drop|truncate)(?:[/?]|$)",
        "block",
        "destructive data operation",
    ),
)

PROTECTION_RULES: tuple[ProtectionRule, ...] = tuple(
    ProtectionRule(pattern=pattern, action=action, reason=reason)  # type: ignore[arg-type]
    for pattern, action, reason in _DEFS
)


@dataclass(frozen=True)
class ProtectionDecision:
    """Result of evaluating a target URL against the protection rules."""

    action: Action
    reason: str
    matched_pattern: str | None

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


def _normalize_path(url: str) -> str:
    raw = url.strip()
    parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    # Collapse duplicate slashes so /api//logout still matches.
    return re.sub(r"/{2,}", "/", path)


def evaluate_endpoint(
    url: str, extra_rules: tuple[ProtectionRule, ...] = ()
) -> ProtectionDecision:
    """Return the most restrictive action matching ``url``.

    ``extra_rules`` are applied alongside the built-ins and may narrow an
    action for a specific deployment. Built-in defaults can be widened to
    ``allow`` only by the operator who writes ``extra_rules``; no model or
    agent input participates in this decision.
    """
    try:
        path = _normalize_path(url)
    except ValueError:
        return ProtectionDecision("block", "unparseable target URL", None)

    best: ProtectionDecision | None = None
    for rule in (*PROTECTION_RULES, *extra_rules):
        if rule.compiled().match(path):
            candidate = ProtectionDecision(rule.action, rule.reason, rule.pattern)
            if best is None or _ACTION_RANK[rule.action] < _ACTION_RANK[best.action]:
                best = candidate
            elif rule.action == best.action and best.matched_pattern is None:
                best = candidate

    return best or ProtectionDecision("allow", "no protected pattern matched", None)


def summarize_rules() -> tuple[tuple[str, str, str], ...]:
    """Return (pattern, action, reason) for documentation and tests."""
    return tuple((r.pattern, r.action, r.reason) for r in PROTECTION_RULES)
