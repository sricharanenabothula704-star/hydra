"""7-Question Validation Gate - Kill Weak Findings Before Reporting"""

import json
import time
from enum import Enum
from pathlib import Path


class GateResult(Enum):
    PASS = "pass"
    FAIL = "fail"
    NEEDS_WORK = "needs_work"


class Question:
    def __init__(self, number, question, description):
        self.number = number
        self.question = question
        self.description = description
        self.result = GateResult.NEEDS_WORK
        self.answer = ""
        self.evidence = ""

    def to_dict(self):
        return {
            "number": self.number,
            "question": self.question,
            "description": self.description,
            "result": self.result.value,
            "answer": self.answer,
            "evidence": self.evidence,
        }


class ValidationResult:
    def __init__(self, finding):
        self.finding = finding
        self.questions = []
        self.overall_result = GateResult.NEEDS_WORK
        self.score = 0
        self.timestamp = time.time()
        self._init_questions()

    def _init_questions(self):
        self.questions = [
            Question(
                1,
                "Is this a real vulnerability?",
                "Not theoretical, hypothetical, or informational",
            ),
            Question(
                2,
                "Can an attacker exploit this RIGHT NOW?",
                "Active exploitation possible",
            ),
            Question(3, "Is there proof?", "PoC, screenshot, raw HTTP response"),
            Question(4, "Is this within scope?", "Target is authorized for testing"),
            Question(5, "Has this been reported before?", "Not a duplicate"),
            Question(6, "What's the impact?", "CVSS score + business impact"),
            Question(
                7, "Is this worth reporting?", "Severity + likelihood of acceptance"
            ),
        ]

    def answer_question(self, number, result, answer, evidence=""):
        for q in self.questions:
            if q.number == number:
                q.result = result
                q.answer = answer
                q.evidence = evidence
                break
        self._calculate_score()

    def _calculate_score(self):
        passed = sum(1 for q in self.questions if q.result == GateResult.PASS)
        total = len(self.questions)
        self.score = round(passed / total * 100) if total > 0 else 0
        failed = [q for q in self.questions if q.result == GateResult.FAIL]
        needs_work = [q for q in self.questions if q.result == GateResult.NEEDS_WORK]
        if failed:
            self.overall_result = GateResult.FAIL
        elif needs_work:
            self.overall_result = GateResult.NEEDS_WORK
        else:
            self.overall_result = GateResult.PASS

    def auto_validate(self):
        f = self.finding
        evidence = f.get("evidence")
        proof = f.get("proof_capsule") or f.get("replay_command")

        # Missing facts are unknown, not implicit approval.
        if evidence and f.get("oracle_verified") is True:
            self.answer_question(
                1, GateResult.PASS, "Evidence is marked oracle-verified"
            )
        else:
            self.answer_question(
                1,
                GateResult.NEEDS_WORK,
                "Requires evidence plus oracle_verified=true",
            )

        if f.get("exploitable") is False:
            self.answer_question(
                2, GateResult.FAIL, "Finding is marked not exploitable"
            )
        elif f.get("exploitable") is True and proof:
            self.answer_question(
                2, GateResult.PASS, "Exploitability and replay proof supplied"
            )
        else:
            self.answer_question(
                2,
                GateResult.NEEDS_WORK,
                "Requires explicit exploitable=true and a replayable proof",
            )

        if proof:
            self.answer_question(3, GateResult.PASS, "Replayable proof provided")
        else:
            self.answer_question(
                3, GateResult.NEEDS_WORK, "Requires proof_capsule or replay_command"
            )

        if f.get("in_scope") is False:
            self.answer_question(4, GateResult.FAIL, "Target is marked out of scope")
        elif f.get("in_scope") is True and (
            f.get("scope_verified") is True or f.get("scope_evidence")
        ):
            self.answer_question(
                4, GateResult.PASS, "Scope explicitly verified with supporting evidence"
            )
        else:
            self.answer_question(
                4,
                GateResult.NEEDS_WORK,
                "Requires explicit in_scope=true and scope verification evidence",
            )

        if f.get("is_duplicate") is True:
            self.answer_question(5, GateResult.FAIL, "Already reported")
        elif f.get("is_duplicate") is False and f.get("duplicate_checked") is True:
            self.answer_question(5, GateResult.PASS, "Duplicate check completed")
        else:
            self.answer_question(
                5,
                GateResult.NEEDS_WORK,
                "Requires a completed duplicate check; unknown is not a pass",
            )

        try:
            cvss = float(f.get("cvss_score"))
        except (TypeError, ValueError):
            cvss = -1
        if 7.0 <= cvss <= 10.0:
            impact_result, impact_text = GateResult.PASS, f"High impact (CVSS {cvss:g})"
        elif 4.0 <= cvss < 7.0:
            impact_result, impact_text = (
                GateResult.PASS,
                f"Medium impact (CVSS {cvss:g})",
            )
        elif 0.0 <= cvss < 4.0:
            impact_result, impact_text = (
                GateResult.NEEDS_WORK,
                f"Low impact (CVSS {cvss:g})",
            )
        else:
            impact_result, impact_text = (
                GateResult.NEEDS_WORK,
                "Requires a valid CVSS score from 0 to 10",
            )
        self.answer_question(6, impact_result, impact_text)

        severity = str(f.get("severity", "")).lower()
        expected = (
            "critical"
            if cvss >= 9
            else "high"
            if cvss >= 7
            else "medium"
            if cvss >= 4
            else "low"
            if cvss >= 0
            else "unknown"
        )
        if expected == "unknown" or not severity:
            self.answer_question(
                7, GateResult.NEEDS_WORK, "Requires severity and a valid CVSS score"
            )
        elif severity != expected:
            self.answer_question(
                7,
                GateResult.NEEDS_WORK,
                f"Severity {severity} does not match CVSS-derived {expected}",
            )
        elif severity in ("critical", "high", "medium"):
            self.answer_question(
                7, GateResult.PASS, f"{severity.title()} severity matches CVSS"
            )
        else:
            self.answer_question(
                7,
                GateResult.NEEDS_WORK,
                "Low severity: justify why a report is worthwhile",
            )
        return {
            "overall": self.overall_result.value,
            "score": self.score,
            "questions": [q.to_dict() for q in self.questions],
        }

    def render(self):
        lines = ["7-QUESTION VALIDATION GATE", "=" * 50]
        for q in self.questions:
            icon = {"pass": "PASS", "fail": "FAIL", "needs_work": "TODO"}[
                q.result.value
            ]
            lines.append(f"  Q{q.number}: [{icon}] {q.question}")
            if q.answer:
                lines.append(f"       {q.answer}")
        lines.append("=" * 50)
        lines.append(
            f"  Score: {self.score}% | Result: {self.overall_result.value.upper()}"
        )
        return "\n".join(lines)


class ValidationGate:
    def __init__(self, data_dir=None):
        self.data_dir = data_dir or Path.home() / ".hydra_data" / "validation"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.gate_file = self.data_dir / "validation_results.json"
        self.results = []
        self._load()

    def _load(self):
        if self.gate_file.exists():
            try:
                data = json.loads(self.gate_file.read_text(encoding="utf-8"))
                self.results = data.get("results", [])
            except Exception:
                pass

    def validate(self, finding):
        validator = ValidationResult(finding)
        result = validator.auto_validate()
        entry = {
            "finding_id": finding.get("id", "unknown"),
            "result": result,
            "timestamp": time.time(),
        }
        self.results.append(entry)
        self._save()
        return result

    def _save(self):
        data = {"results": self.results[-100:]}
        self.gate_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_rejection_rate(self):
        if not self.results:
            return 0.0
        rejected = sum(1 for r in self.results if r["result"]["overall"] == "fail")
        return rejected / len(self.results)

    def stats(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if r["result"]["overall"] == "pass")
        failed = sum(1 for r in self.results if r["result"]["overall"] == "fail")
        needs_work = sum(
            1 for r in self.results if r["result"]["overall"] == "needs_work"
        )
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "needs_work": needs_work,
        }


validation_gate = ValidationGate()
