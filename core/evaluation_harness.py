"""Offline evaluation of HYDRA's deterministic gates.

Feature claims are cheap; measured behaviour is what this market trades on.
Public benchmarks for security agents measure *recall* of known
vulnerabilities almost exclusively -- nobody publishes precision against a
real accept/reject oracle. That is the gap HYDRA can measure locally, with
no network access and no model in the loop.

What is measured:

``scope``
    Denials a naive substring matcher would miss (suffix collisions, userinfo
    tricks, lookalike hosts), and authorized targets a strict matcher would
    wrongly refuse.

``endpoint``
    Account- and session-destructive paths that must be blocked or restricted.

``evidence``
    Whether findings are correctly refused confirmation status without
    independent evidence, and correctly confirmed with it.

``report``
    Whether mechanically incomplete reports are caught before submission.

Run with::

    python core/evaluation_harness.py

The suite is deterministic: no clock, no randomness, no network. Numbers are
reproducible across machines, which is the minimum bar for publishing a claim.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .protected_endpoints import evaluate_endpoint
from .report_contract import lint_report
from .scope_policy import scope_decision
from .validation_evidence import (
    Evidence,
    Finding,
    ValidationRecord,
    aggregate,
)


@dataclass
class Case:
    name: str
    expected: bool
    subject: str


@dataclass
class Result:
    total: int
    passed: int
    failures: list[str]

    @property
    def precision_like(self) -> float:
        return round(self.passed / self.total, 4) if self.total else 0.0

    def render(self, title: str) -> str:
        pct = self.precision_like * 100
        lines = [f"{title:<10} {self.passed}/{self.total}  ({pct:.1f}%)"]
        for failure in self.failures:
            lines.append(f"   FAIL  {failure}")
        return "\n".join(lines)


def _run(cases: list[Case], subject_of: Callable[[str], bool]) -> Result:
    failures: list[str] = []
    for case in cases:
        try:
            actual = subject_of(case.subject)
        except Exception as exc:  # a raising gate is a failing gate
            failures.append(f"{case.name}: raised {type(exc).__name__}: {exc}")
            continue
        if actual != case.expected:
            failures.append(
                f"{case.name}: expected {case.expected}, got {actual} ({case.subject})"
            )
    return Result(
        total=len(cases), passed=len(cases) - len(failures), failures=failures
    )


# --- scope: the collisions a substring matcher gets wrong -------------------

_SCOPE_CASES: list[Case] = [
    Case("apex allowed", True, "example.com"),
    Case("subdomain allowed", True, "api.example.com"),
    Case("deep subdomain allowed", True, "a.b.example.com"),
    Case("suffix collision denied", False, "notexample.com"),
    Case("suffix collision on subdomain", False, "evil-example.com"),
    Case("lookalike TLD denied", False, "example.com.attacker.net"),
    Case("unrelated host denied", False, "attacker.net"),
    Case("userinfo trick denied", False, "https://example.com@attacker.net"),
    Case("trailing dot normalized", True, "example.com."),
    Case("uppercase normalized", True, "EXAMPLE.COM"),
    Case("empty target denied", False, ""),
]


def evaluate_scope(allowlist: Path | None = None) -> Result:
    """Measure scope decisions. Uses a fixed allowlist when none is given."""
    if allowlist is not None:
        return _run(_SCOPE_CASES, lambda s: scope_decision(s, allowlist)[0])

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "SCOPE_ALLOWLIST.txt"
        path.write_text("example.com\n", encoding="utf-8")
        return _run(_SCOPE_CASES, lambda s: scope_decision(s, path)[0])


# --- endpoint: destructive paths -------------------------------------------

_ENDPOINT_CASES: list[Case] = [
    # session destruction
    Case("logout blocked", False, "https://example.com/logout"),
    Case("nested logout blocked", False, "https://example.com/api/v2/logout"),
    Case("signout blocked", False, "https://example.com/signout"),
    Case(
        "invalidate sessions blocked", False, "https://example.com/invalidate-sessions"
    ),
    # account destruction
    Case("delete account blocked", False, "https://example.com/delete-account"),
    Case(
        "account settings delete blocked", False, "https://example.com/account/delete"
    ),
    # credential mutation
    Case("reset password blocked", False, "https://example.com/reset-password"),
    Case("change email blocked", False, "https://example.com/settings/change-email"),
    # MFA
    Case("mfa disable blocked", False, "https://example.com/2fa/disable"),
    Case("otp submit auth-only", False, "https://example.com/reset-otp"),
    # auth entry points
    Case("login auth-only", False, "https://example.com/login"),
    Case("register auth-only", False, "https://example.com/signup"),
    # safe paths
    Case("api endpoint allowed", True, "https://example.com/api/v1/users"),
    Case("product page allowed", True, "https://example.com/pricing"),
    Case("root allowed", True, "https://example.com/"),
    Case("query string allowed", True, "https://example.com/search?q=test"),
    # smuggling attempts
    Case("slashes collapsed", False, "https://example.com/api//logout"),
    Case("case insensitive", False, "https://example.com/LOGOUT"),
    Case("query cannot smuggle", True, "https://example.com/search?next=/logout"),
]


def evaluate_endpoints() -> Result:
    return _run(_ENDPOINT_CASES, lambda s: evaluate_endpoint(s).allowed)


# --- evidence: confirmation discipline --------------------------------------

_UNVERIFIED = Finding(finding_id="F1", title="Possible IDOR")
_UNVERIFIED.add(
    ValidationRecord(
        vuln_class="CWE-639", evidence=Evidence.UNVERIFIED.value, validator="agent-read"
    )
)

_HEURISTIC = Finding(finding_id="F2", title="Possible open redirect")
_HEURISTIC.add(
    ValidationRecord(
        vuln_class="CWE-601",
        evidence=Evidence.HEURISTIC.value,
        validator="response-diff",
    )
)

_DETERMINISTIC = Finding(finding_id="F3", title="Reflected XSS")
_DETERMINISTIC.add(
    ValidationRecord(
        vuln_class="CWE-79", evidence=Evidence.UNVERIFIED.value, validator="reflected"
    )
)
_DETERMINISTIC.add(
    ValidationRecord(
        vuln_class="CWE-79",
        evidence=Evidence.DETERMINISTIC.value,
        validator="headless-browser-confirmed-execution",
        observed="alert(document.domain) executed",
    )
)


def evaluate_evidence() -> Result:
    """Measure whether confirmation status tracks the evidence class."""
    failures: list[str] = []

    if _UNVERIFIED.is_confirmed:
        failures.append("unverified finding was marked confirmed")
    if not _HEURISTIC.is_confirmed:
        failures.append("heuristic finding was refused confirmation")

    if _DETERMINISTIC.strongest_evidence != Evidence.DETERMINISTIC.value:
        failures.append("strongest evidence did not win across mixed records")
    if not _DETERMINISTIC.is_confirmed:
        failures.append("deterministic finding was refused confirmation")

    for finding in (_UNVERIFIED, _HEURISTIC, _DETERMINISTIC):
        if not finding.requires_human_review:
            failures.append(f"{finding.finding_id} skipped human review requirement")

    summaries = aggregate(_DETERMINISTIC.records)
    if not summaries or summaries[0].confirmable is not True:
        failures.append("aggregate did not mark the deterministic class confirmable")

    total = 7
    return Result(
        total=total,
        passed=total - len(failures),
        failures=failures,
    )


# --- report: contract linting ----------------------------------------------

_COMPLETE_REPORT = {
    "title": "IDOR allows reading another user's order",
    "severity": "high",
    "description": "The orders endpoint returns another account's order without an ownership check.",
    "impact": "Any authenticated user can read another user's order contents and addresses.",
    "steps_to_reproduce": [
        "Sign in as [SESSION_TOKEN] for account A.",
        "Request https://example.com/api/orders/2 with that session.",
        "Observe a 200 response containing account B's order.",
    ],
    "poc": "curl -H 'Cookie: session=[SESSION_TOKEN]' https://example.com/api/orders/2",
}


def evaluate_reports() -> Result:
    cases: list[Case] = [
        Case("complete report passes", True, "complete"),
        Case("missing impact blocked", False, "no_impact"),
        Case("missing poc command blocked", False, "no_command"),
        Case("missing url blocked", False, "no_url"),
        Case("credentialed url blocked", False, "credentialed_url"),
        Case("missing severity blocked", False, "no_severity"),
    ]

    def subject(kind: str) -> bool:
        report = dict(_COMPLETE_REPORT)
        if kind == "no_impact":
            report.pop("impact")
        elif kind == "no_command":
            report.pop("poc")
            report["steps_to_reproduce"] = ["1. do the thing", "2. observe it"]
        elif kind == "no_url":
            report.pop("poc")
            report["steps_to_reproduce"] = ["1. curl the endpoint", "2. observe it"]
        elif kind == "credentialed_url":
            report["poc"] = "curl https://user:pass@example.com/api"
        elif kind == "no_severity":
            report.pop("severity")
        return lint_report(report).ok

    return _run(cases, subject)


def run_all(allowlist: Path | None = None) -> str:
    """Run every suite and return a printable report."""
    results = [
        ("scope", evaluate_scope(allowlist)),
        ("endpoint", evaluate_endpoints()),
        ("evidence", evaluate_evidence()),
        ("report", evaluate_reports()),
    ]

    width = 72
    out = [
        "HYDRA deterministic-gate evaluation (offline, no model, no network)",
        "=" * width,
    ]
    for title, result in results:
        out.append(result.render(title))
    out.append("=" * width)

    total = sum(r.total for _, r in results)
    passed = sum(r.passed for _, r in results)
    overall = round(passed / total, 4) if total else 0.0
    out.append(f"OVERALL     {passed}/{total}  ({overall * 100:.1f}%)")
    out.append("")
    out.append(
        "This measures the gates that do not depend on model behaviour:\n"
        "scope denial correctness, destructive-endpoint protection, evidence\n"
        "discipline, and report-contract enforcement. It does not measure\n"
        "vulnerability-discovery recall, which requires live authorized targets."
    )
    return "\n".join(out)


if __name__ == "__main__":
    print(run_all())
