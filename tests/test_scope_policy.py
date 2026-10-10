import tempfile
import unittest
from pathlib import Path

from core.scope_policy import scope_decision


class ScopePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.allowlist = Path(self.tmp.name) / "SCOPE_ALLOWLIST.txt"

    def tearDown(self):
        self.tmp.cleanup()

    def test_wildcard_accepts_a_real_subdomain(self):
        self.allowlist.write_text("*.example.com\n", encoding="utf-8")
        self.assertTrue(scope_decision("app.example.com", self.allowlist)[0])

    def test_wildcard_rejects_suffix_collision(self):
        self.allowlist.write_text("*.example.com\n", encoding="utf-8")
        self.assertFalse(scope_decision("notexample.com", self.allowlist)[0])

    def test_wildcard_rejects_apex(self):
        self.allowlist.write_text("*.example.com\n", encoding="utf-8")
        self.assertFalse(scope_decision("example.com", self.allowlist)[0])

    def test_wildcard_inside_label_matches_one_label_only(self):
        self.allowlist.write_text("onboarding-*.cloud.com\n", encoding="utf-8")
        self.assertTrue(scope_decision("onboarding-prod.cloud.com", self.allowlist)[0])
        self.assertFalse(
            scope_decision("onboarding-prod.evil.cloud.com", self.allowlist)[0]
        )
        self.assertFalse(
            scope_decision("notonboarding-prod.cloud.com.evil", self.allowlist)[0]
        )

    def test_plain_domain_covers_apex_and_subdomains(self):
        self.allowlist.write_text("example.com\n", encoding="utf-8")
        self.assertTrue(scope_decision("example.com", self.allowlist)[0])
        self.assertTrue(scope_decision("api.example.com", self.allowlist)[0])
        self.assertFalse(scope_decision("notexample.com", self.allowlist)[0])

    def test_missing_or_empty_allowlist_fails_closed(self):
        self.assertFalse(scope_decision("example.com", self.allowlist)[0])
        self.allowlist.write_text("# comments only\n", encoding="utf-8")
        self.assertFalse(scope_decision("example.com", self.allowlist)[0])

    def test_rejects_url_userinfo(self):
        self.allowlist.write_text("example.com\n", encoding="utf-8")
        self.assertFalse(
            scope_decision("https://example.com@evil.test", self.allowlist)[0]
        )


if __name__ == "__main__":
    unittest.main()
