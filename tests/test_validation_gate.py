import unittest

from core.validation_gate import GateResult, ValidationResult


class ValidationGateTests(unittest.TestCase):
    def test_unknown_scope_exploitability_and_duplicate_status_never_pass(self):
        result = ValidationResult(
            {
                "evidence": "response sample",
                "oracle_verified": True,
                "proof_capsule": "proof.json",
                "cvss_score": 9.1,
                "severity": "critical",
            }
        ).auto_validate()
        self.assertNotEqual(result["overall"], GateResult.PASS.value)
        by_number = {q["number"]: q["result"] for q in result["questions"]}
        self.assertEqual(by_number[4], GateResult.NEEDS_WORK.value)
        self.assertEqual(by_number[5], GateResult.NEEDS_WORK.value)
        self.assertEqual(by_number[2], GateResult.NEEDS_WORK.value)

    def test_explicit_evidence_scope_duplicate_check_and_cvss_can_pass(self):
        result = ValidationResult(
            {
                "evidence": "repeatable response diff",
                "oracle_verified": True,
                "proof_capsule": "proof.json",
                "exploitable": True,
                "in_scope": True,
                "scope_verified": True,
                "scope_evidence": "scope-entry-17",
                "is_duplicate": False,
                "duplicate_checked": True,
                "cvss_score": 9.1,
                "severity": "critical",
            }
        ).auto_validate()
        self.assertEqual(result["overall"], GateResult.PASS.value)
        self.assertEqual(result["score"], 100)

    def test_scope_failure_is_a_hard_failure(self):
        result = ValidationResult(
            {
                "evidence": "repeatable response diff",
                "oracle_verified": True,
                "proof_capsule": "proof.json",
                "exploitable": True,
                "in_scope": False,
                "is_duplicate": False,
                "duplicate_checked": True,
                "cvss_score": 9.1,
                "severity": "critical",
            }
        ).auto_validate()
        self.assertEqual(result["overall"], GateResult.FAIL.value)


if __name__ == "__main__":
    unittest.main()
