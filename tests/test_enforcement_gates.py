import json
import tempfile
import unittest
from pathlib import Path

from core.audit_trail import AuditTrail
from core.evaluation_harness import (
    evaluate_endpoints,
    evaluate_evidence,
    evaluate_reports,
    evaluate_scope,
    run_all,
)
from core.protected_endpoints import evaluate_endpoint
from core.report_contract import lint_report
from core.validation_evidence import (
    Evidence,
    Finding,
    ValidationRecord,
    aggregate,
    report,
)


class ProtectedEndpointTests(unittest.TestCase):
    def test_session_and_account_destruction_is_blocked(self):
        for url in (
            "https://example.com/logout",
            "https://example.com/api/v2/logout",
            "https://example.com/signout",
            "https://example.com/delete-account",
            "https://example.com/account/delete",
            "https://example.com/reset-password",
            "https://example.com/2fa/disable",
            "https://example.com/settings/change-email",
        ):
            with self.subTest(url=url):
                self.assertFalse(evaluate_endpoint(url).allowed)

    def test_auth_entry_points_are_auth_only(self):
        for url in (
            "https://example.com/login",
            "https://example.com/signup",
            "https://example.com/reset-otp",
        ):
            with self.subTest(url=url):
                decision = evaluate_endpoint(url)
                self.assertEqual(decision.action, "auth_only")
                self.assertFalse(decision.allowed)

    def test_ordinary_endpoints_are_allowed(self):
        for url in (
            "https://example.com/",
            "https://example.com/api/v1/users",
            "https://example.com/pricing",
            "https://example.com/search?q=test",
        ):
            with self.subTest(url=url):
                self.assertTrue(evaluate_endpoint(url).allowed)

    def test_pattern_cannot_be_smuggled_by_query_or_duplicate_slashes(self):
        self.assertFalse(evaluate_endpoint("https://example.com/api//logout").allowed)
        self.assertFalse(evaluate_endpoint("https://example.com/LOGOUT").allowed)
        # A query string that merely mentions a protected path must not block.
        self.assertTrue(
            evaluate_endpoint("https://example.com/search?next=/logout").allowed
        )

    def test_decision_is_explainable_without_a_model(self):
        decision = evaluate_endpoint("https://example.com/logout")
        self.assertIsNotNone(decision.matched_pattern)
        self.assertIn("session", decision.reason.lower())


class ValidationEvidenceTests(unittest.TestCase):
    def test_unverified_evidence_cannot_confirm(self):
        finding = Finding("F1", "Possible IDOR")
        finding.add(
            ValidationRecord(
                vuln_class="CWE-639",
                evidence=Evidence.UNVERIFIED.value,
                validator="agent-read",
            )
        )
        self.assertFalse(finding.is_confirmed)
        self.assertTrue(finding.requires_human_review)

    def test_strongest_evidence_wins_across_records(self):
        finding = Finding("F2", "Reflected XSS")
        finding.add(ValidationRecord("CWE-79", Evidence.UNVERIFIED.value, "reflected"))
        finding.add(
            ValidationRecord("CWE-79", Evidence.DETERMINISTIC.value, "headless-browser")
        )
        self.assertEqual(finding.strongest_evidence, Evidence.DETERMINISTIC.value)
        self.assertTrue(finding.is_confirmed)

    def test_unknown_evidence_class_is_rejected(self):
        with self.assertRaises(ValueError):
            ValidationRecord("CWE-79", "probably-fine", "agent")

    def test_human_review_is_always_required(self):
        finding = Finding("F3", "Confirmed SQLi")
        finding.add(
            ValidationRecord("CWE-89", Evidence.DETERMINISTIC.value, "timing-oracle")
        )
        self.assertTrue(finding.requires_human_review)

    def test_aggregate_reports_per_class_confirmability(self):
        records = [
            ValidationRecord("CWE-79", Evidence.DETERMINISTIC.value, "browser"),
            ValidationRecord("CWE-89", Evidence.UNVERIFIED.value, "agent"),
        ]
        summaries = {s.vuln_class: s for s in aggregate(records)}
        self.assertTrue(summaries["CWE-79"].confirmable)
        self.assertFalse(summaries["CWE-89"].confirmable)
        self.assertIn("LEAD ONLY", report(records))

    def test_finding_serializes_to_json(self):
        finding = Finding("F4", "Open redirect")
        finding.add(
            ValidationRecord("CWE-601", Evidence.HEURISTIC.value, "response-diff")
        )
        payload = json.loads(finding.to_json())
        self.assertEqual(payload["finding_id"], "F4")
        self.assertTrue(payload["is_confirmed"])


class ReportContractTests(unittest.TestCase):
    def _report(self, **overrides):
        base = {
            "title": "IDOR allows reading another user's order",
            "severity": "high",
            "description": "Missing ownership check on the orders endpoint.",
            "impact": "Any user can read another user's order and address.",
            "steps_to_reproduce": [
                "Sign in as [SESSION_TOKEN] for account A.",
                "Request https://example.com/api/orders/2.",
                "Observe another account's order returned.",
            ],
            "poc": "curl -H 'Cookie: session=[SESSION_TOKEN]' https://example.com/api/orders/2",
        }
        base.update(overrides)
        return base

    def test_complete_report_passes(self):
        self.assertTrue(lint_report(self._report()).ok)

    def test_missing_impact_blocks(self):
        report = self._report()
        report.pop("impact")
        result = lint_report(report)
        self.assertFalse(result.ok)
        self.assertTrue(any("impact" in e.lower() for e in result.errors))

    def test_missing_reproduction_command_blocks(self):
        report = self._report()
        report.pop("poc")
        report["steps_to_reproduce"] = ["1. do the thing", "2. observe it"]
        result = lint_report(report)
        self.assertFalse(result.ok)
        self.assertTrue(any("command" in e.lower() for e in result.errors))

    def test_credentialed_url_blocks(self):
        report = self._report()
        report["poc"] = "curl https://user:pass@example.com/api"
        self.assertFalse(lint_report(report).ok)

    def test_video_only_submission_blocks(self):
        report = self._report()
        report.pop("poc")
        report["steps_to_reproduce"] = ["1. watch proof.mp4 for details"]
        result = lint_report(report)
        self.assertFalse(result.ok)

    def test_critical_severity_warns(self):
        result = lint_report(self._report(severity="critical"))
        self.assertTrue(
            any("severity" in w.lower() for w in result.warnings),
            result.warnings,
        )

    def test_human_review_is_surfaced_as_a_warning(self):
        report = self._report()
        report["requires_human_review"] = True
        self.assertTrue(any("human" in w.lower() for w in lint_report(report).warnings))


class AuditTrailTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "audit.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def test_records_are_appended_and_readable(self):
        trail = AuditTrail(self.path)
        trail.record("scope_check", "example.com", "allow", "in allowlist")
        trail.record("scope_check", "attacker.net", "deny", "not in allowlist")
        records = trail.read()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["decision"], "deny")

    def test_integrity_check_detects_tampering(self):
        trail = AuditTrail(self.path)
        trail.record("scope_check", "example.com", "allow")
        self.assertEqual(trail.verify(), (True, []))

        lines = self.path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["decision"] = "allow-everything"
        lines[0] = json.dumps(record, sort_keys=True)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        intact, bad = trail.verify()
        self.assertFalse(intact)
        self.assertEqual(bad, [1])

    def test_summary_counts_denials(self):
        trail = AuditTrail(self.path)
        trail.record("scope_check", "a.example.com", "allow")
        trail.record("endpoint_guard", "example.com/logout", "block")
        summary = trail.summary()
        self.assertEqual(summary["records"], 2)
        self.assertEqual(summary["denials"], 1)
        self.assertTrue(summary["integrity_ok"])

    def test_truncated_tail_does_not_break_reading(self):
        trail = AuditTrail(self.path)
        trail.record("scope_check", "example.com", "allow")
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write('{"event": "partial"')
        self.assertEqual(len(trail.read()), 1)


class EvaluationHarnessTests(unittest.TestCase):
    """The published numbers must not silently regress."""

    def test_all_suites_pass_fully(self):
        for suite in (
            evaluate_scope(),
            evaluate_endpoints(),
            evaluate_evidence(),
            evaluate_reports(),
        ):
            self.assertEqual(
                suite.failures, [], f"{suite.render('x')} reported failures"
            )

    def test_scope_suite_catches_naive_matcher_collisions(self):
        failures = evaluate_scope().failures
        self.assertEqual(failures, [])
        self.assertGreaterEqual(evaluate_scope().total, 10)

    def test_run_all_reports_every_suite(self):
        text = run_all()
        for suite in ("scope", "endpoint", "evidence", "report"):
            self.assertIn(suite, text)
        self.assertIn("OVERALL", text)


if __name__ == "__main__":
    unittest.main()
