"""Report-contract linting against published platform rejection criteria.

Most automated reports are rejected for mechanical reasons, not because the
vulnerability was wrong: a missing proof of concept, no demonstrated impact,
no reproducible command, or inflated severity. Platforms close these as Not
Applicable or Informative. Programs have stated this explicitly, including
that pasting unverified tool output results in closure as N/A.

This module lints a draft finding against that contract before submission.
It is deterministic, takes no instruction from a model, and reports every
missing element rather than guessing.

Reference patterns drawn from public policy:
  * HackerOne closes submissions that are speculative, missing a proof of
    concept, not reproducible, video-only, or lacking demonstrated impact.
  * A repeated pattern of inflated severity is itself a policy violation.
  * Human confirmation is required before submission regardless of the tool
    that produced the draft.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

MAX_SEVERITY_RANK = 3  # low=0, medium=1, high=2, critical=3

_SEVERITY_RANK: dict[str, int] = {
    "info": -1,
    "informational": -1,
    "none": -1,
    "low": 0,
    "medium": 1,
    "moderate": 1,
    "high": 2,
    "critical": 3,
    "severe": 3,
}

_SEVERITY = re.compile(r"\b(critical|high|medium|moderate|low|informational)\b", re.I)
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_CMD = re.compile(
    r"(?:^|\n)\s*(?:\$|```|curl\s|wget\s|python[23]?\s|nmap\s|sqlmap\s|nuclei\s|burp|python -m)",
    re.I,
)
_STEP_NUMBERED = re.compile(r"(?:^|\n)\s*(?:step\s*)?\d+[.)]\s+\S", re.I)
_PLACEHOLDER = re.compile(r"\[[A-Z_]{3,}\]")
_VIDEO_ONLY = re.compile(r"\.(?:mp4|mov|avi|webm|mkv)\b", re.I)


@dataclass
class LintResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_text(self) -> str:
        if self.ok and not self.warnings:
            return "Report contract satisfied."
        lines = []
        for e in self.errors:
            lines.append(f"[BLOCKING] {e}")
        for w in self.warnings:
            lines.append(f"[WARNING]  {w}")
        return "\n".join(lines)


def _text(finding: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("title", "description", "impact", "steps_to_reproduce", "poc"):
        value = finding.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            parts.extend(str(v) for v in value)
        else:
            parts.append(str(value))
    return "\n".join(parts)


def lint_report(finding: dict[str, Any]) -> LintResult:
    """Check a draft finding against the minimum publishable report contract."""
    errors: list[str] = []
    warnings: list[str] = []

    if not finding.get("title"):
        errors.append("Missing title.")

    urls = _URL.findall(_text(finding))
    if not urls:
        errors.append(
            "No target URL found. Provide the full URL including scheme, host, "
            "path and parameters."
        )

    description = str(finding.get("description") or "")
    impact = str(finding.get("impact") or "")

    if not description.strip():
        errors.append("Missing description of the weakness.")
    if not impact.strip():
        errors.append(
            "Missing demonstrated impact. Submissions lacking demonstrated "
            "impact are closed as Not Applicable."
        )

    steps = finding.get("steps_to_reproduce") or []
    has_steps = bool(str(steps).strip()) if not isinstance(steps, list) else bool(steps)
    body = _text(finding)
    has_numbered_steps = bool(_STEP_NUMBERED.search(body))
    has_command = bool(_CMD.search(body))

    if not has_steps and not has_numbered_steps:
        errors.append(
            "No reproduction steps. Provide numbered steps or an ordered list."
        )
    if not has_command:
        errors.append(
            "No copy-paste reproduction command. Provide a command the triager "
            "can run directly."
        )

    if _VIDEO_ONLY.search(body) and not has_command:
        errors.append("Video-only evidence is not accepted; include a written proof.")

    if not _PLACEHOLDER.search(body):
        warnings.append(
            "No placeholder such as [SESSION_TOKEN] detected. Real account or "
            "customer values should be redacted in shared artifacts."
        )

    raw_severity = finding.get("severity")
    severity_match = _SEVERITY.search(body)
    severity_text = raw_severity or (
        severity_match.group(0) if severity_match else None
    )
    if severity_text is None:
        errors.append("Missing severity. Assign one explicitly at submission time.")
    else:
        rank = _SEVERITY_RANK.get(str(severity_text).strip().lower(), -1)
        if rank >= MAX_SEVERITY_RANK:
            warnings.append(
                "Critical severity asserted. Confirm the demonstrated impact "
                "justifies it; repeated inflated severity is a policy violation."
            )
        if str(severity_text).strip().lower() not in _SEVERITY_RANK:
            errors.append(f"Unrecognized severity: {severity_text!r}")

    for url in urls:
        try:
            parsed = urlsplit(url)
        except ValueError:
            warnings.append(f"Could not parse URL: {url}")
            continue
        if not parsed.scheme or not parsed.netloc:
            warnings.append(f"URL is not fully qualified: {url}")
        if parsed.username or parsed.password:
            errors.append("URL contains credentials; redact before sharing.")

    if finding.get("requires_human_review") is True:
        warnings.append(
            "Platform policy requires a human to confirm this finding before "
            "submission, even with strong automated evidence."
        )

    return LintResult(ok=not errors, errors=errors, warnings=warnings)
