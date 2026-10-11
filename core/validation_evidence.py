"""Typed, per-class validation evidence for candidate findings.

A single global "false positive rate" is a vanity metric: it hides which
classes are actually proven and which are merely argued. Leading systems
therefore classify per vulnerability class and say plainly which validator
produced the evidence.

Three evidence classes are used here:

``deterministic``
    A programmatic oracle observed the effect itself -- a headless browser
    confirmed script execution, a timing oracle measured a latency delta, a
    canary token was retrieved. Re-running the check reproduces the result.

``heuristic``
    Evidence is indirect: response differentials, header and configuration
    review, source reading. Useful for triage, not for a confirmed finding.

``unverified``
    No independent evidence was captured. The finding is a lead only and must
    not be reported as confirmed.

This mirrors the classification used by leading commercial systems, where
classes backed by a non-model validator are stated to carry no false
positives while classes validated only by an agent may. See
https://docs.xbow.com/console/reference/vulnerability-classification
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Evidence(str, Enum):
    DETERMINISTIC = "deterministic"
    HEURISTIC = "heuristic"
    UNVERIFIED = "unverified"


# Weakest first: a finding is only as strong as its weakest evidence.
_ORDER: dict[str, int] = {
    Evidence.UNVERIFIED.value: 0,
    Evidence.HEURISTIC.value: 1,
    Evidence.DETERMINISTIC.value: 2,
}

# Weakest-evidence class that may be presented as a confirmed finding.
CONFIRMABLE_THRESHOLD = Evidence.HEURISTIC.value


@dataclass
class ValidationRecord:
    """One validation observation attached to a candidate finding."""

    vuln_class: str
    evidence: str
    validator: str
    observed: str = ""
    notes: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def __post_init__(self) -> None:
        if self.evidence not in _ORDER:
            raise ValueError(f"unknown evidence class: {self.evidence}")
        if not self.vuln_class.strip():
            raise ValueError("vuln_class is required")
        if not self.validator.strip():
            raise ValueError("validator is required")


@dataclass
class ClassSummary:
    vuln_class: str
    strongest: str
    count: int
    confirmable: bool


def aggregate(records: list[ValidationRecord]) -> list[ClassSummary]:
    """Summarize the strongest evidence seen per vulnerability class."""
    grouped: dict[str, list[ValidationRecord]] = {}
    for record in records:
        grouped.setdefault(record.vuln_class, []).append(record)

    summaries = []
    for vuln_class, items in sorted(grouped.items()):
        strongest = max((r.evidence for r in items), key=lambda e: _ORDER[e])
        summaries.append(
            ClassSummary(
                vuln_class=vuln_class,
                strongest=strongest,
                count=len(items),
                confirmable=_ORDER[strongest] >= _ORDER[CONFIRMABLE_THRESHOLD],
            )
        )
    return summaries


@dataclass
class Finding:
    """A candidate finding carrying its validation records."""

    finding_id: str
    title: str
    vuln_class: str = ""
    records: list[ValidationRecord] = field(default_factory=list)

    @property
    def strongest_evidence(self) -> str:
        if not self.records:
            return Evidence.UNVERIFIED.value
        return max((r.evidence for r in self.records), key=lambda e: _ORDER[e])

    @property
    def is_confirmed(self) -> bool:
        """A finding is confirmed only with heuristic-or-better evidence."""
        return _ORDER[self.strongest_evidence] >= _ORDER[CONFIRMABLE_THRESHOLD]

    @property
    def requires_human_review(self) -> bool:
        """Deterministic evidence is reproducible but still needs a person.

        Platform policies require a human to confirm potential
        vulnerabilities before submission, regardless of automation quality.
        """
        return True

    def add(self, record: ValidationRecord) -> None:
        self.records.append(record)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "vuln_class": self.vuln_class,
            "strongest_evidence": self.strongest_evidence,
            "is_confirmed": self.is_confirmed,
            "requires_human_review": self.requires_human_review,
            "validations": [vars(r) for r in self.records],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def report(records: list[ValidationRecord]) -> str:
    """Render a per-class evidence table for humans."""
    summaries = aggregate(records)
    if not summaries:
        return "No validation records recorded."
    lines = [
        f"{'VULN CLASS':<28} {'STRONGEST EVIDENCE':<16} {'N':>3}  STATUS",
        "-" * 68,
    ]
    for s in summaries:
        status = "confirmable" if s.confirmable else "LEAD ONLY"
        lines.append(f"{s.vuln_class:<28} {s.strongest:<16} {s.count:>3}  {status}")
    lines.append("-" * 68)
    lines.append(
        "Deterministic = programmatic oracle observed the effect. "
        "Heuristic = indirect. Unverified = candidate only."
    )
    lines.append("Human confirmation is required before any finding is submitted.")
    return "\n".join(lines)
