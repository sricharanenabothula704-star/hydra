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
        # Q1: Real vulnerability?
        if f.get("evidence") or f.get("proof") or f.get("status") == "verified":
            self.answer_question(
                1, GateResult.PASS, "Evidence provided or oracle-verified"
            )
        else:
            self.answer_question(1, GateResult.NEEDS_WORK, "No evidence provided")
        # Q2: Exploitable now?
        if f.get("exploitable", True):
            self.answer_question(2, GateResult.PASS, "Exploitable with standard tools")
        else:
            self.answer_question(2, GateResult.FAIL, "Requires special conditions")
        # Q3: Proof?
        if f.get("proof_capsule") or f.get("replay_command"):
            self.answer_question(3, GateResult.PASS, "Replay-able proof provided")
        elif f.get("evidence"):
            self.answer_question(3, GateResult.PASS, "Evidence provided")
        else:
            self.answer_question(3, GateResult.NEEDS_WORK, "Need raw response or PoC")
        # Q4: In scope?
        if f.get("in_scope", True):
            self.answer_question(4, GateResult.PASS, "Target is in scope")
        else:
            self.answer_question(4, GateResult.FAIL, "Target is out of scope")
        # Q5: Duplicate?
        if f.get("is_duplicate", False):
            self.answer_question(5, GateResult.FAIL, "Already reported")
        else:
            self.answer_question(5, GateResult.PASS, "Not a known duplicate")
        # Q6: Impact?
        cvss = f.get("cvss_score", 0)
        if cvss >= 7.0:
            self.answer_question(6, GateResult.PASS, f"High impact (CVSS {cvss})")
        elif cvss >= 4.0:
            self.answer_question(6, GateResult.PASS, f"Medium impact (CVSS {cvss})")
        else:
            self.answer_question(6, GateResult.NEEDS_WORK, f"Low impact (CVSS {cvss})")
        # Q7: Worth reporting?
        severity = f.get("severity", "low")
        if severity in ("critical", "high"):
            self.answer_question(
                7,
                GateResult.PASS,
                f"{severity.title()} severity - definitely worth reporting",
            )
        elif severity == "medium":
            self.answer_question(
                7, GateResult.PASS, "Medium severity - worth reporting"
            )
        else:
            self.answer_question(
                7, GateResult.NEEDS_WORK, "Low severity - consider if worth reporting"
            )
        return {
            "overall": self.overall_result.value,
            "score": self.score,
            "questions": [q.to_dict() for q in self.questions],
        }

    def render(self):
        lines = ["7-QUESTION VALIDATION GATE", "=" * 50]
        for q in self.questions:
            icon = {"pass": "PASS", "fail": "FAIL", "needs_work": "????"}[
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
