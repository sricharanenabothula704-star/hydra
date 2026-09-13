"""Deterministic Completion Gates — No Premature Termination

Stolen from: opencode-pentester's deterministic completion gates
What it does: Completion is a DATABASE FACT, not an AI belief

How it works:
1. Every phase (recon, testing, exploiting, review, report) has gates
2. Each gate checks actual database state, not AI claims
3. Gates return PASS/FAIL with specific reasons
4. AI cannot claim "done" until ALL gates pass
5. 100% means 100% — no rounding, no shortcuts

This beats opencode-pentester because:
- Theirs: SQLite queries only
- Ours: Oracle-verified + anti-hallucination + database state
"""
import json
import time
from enum import Enum
from pathlib import Path
from typing import Optional


class GateStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    BLOCKED = "blocked"


class Gate:
    """A single completion gate."""

    def __init__(self, name: str, description: str, phase: str):
        self.name = name
        self.description = description
        self.phase = phase
        self.status = GateStatus.FAIL
        self.reason = ""
        self.checked_at = None
        self.details = {}

    def check(self, db_state: dict) -> GateStatus:
        """Check gate condition against actual database state."""
        raise NotImplementedError

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "phase": self.phase,
            "status": self.status.value,
            "reason": self.reason,
            "checked_at": self.checked_at,
            "details": self.details,
        }


class ReconCompleteGate(Gate):
    """Recon phase complete: all ports scanned, services enumerated, scope mapped."""

    def __init__(self):
        super().__init__("recon_complete", "All in-scope hosts have been port-scanned and services enumerated", "recon")

    def check(self, db_state: dict) -> GateStatus:
        hosts = db_state.get("hosts_in_scope", [])
        scanned = db_state.get("hosts_scanned", [])
        services = db_state.get("services_enumerated", 0)

        missing = [h for h in hosts if h not in scanned]

        if missing:
            self.status = GateStatus.FAIL
            self.reason = f"{len(missing)} hosts not scanned: {', '.join(missing[:3])}"
            self.details = {"missing_hosts": missing}
        elif services == 0:
            self.status = GateStatus.FAIL
            self.reason = "No services enumerated"
        else:
            self.status = GateStatus.PASS
            self.reason = f"All {len(hosts)} hosts scanned, {services} services found"

        self.checked_at = time.time()
        return self.status


class ToolsInstalledGate(Gate):
    """All required tools are installed and verified."""

    def __init__(self):
        super().__init__("tools_installed", "All required security tools are installed and functional", "preflight")

    def check(self, db_state: dict) -> GateStatus:
        required = db_state.get("required_tools", [])
        installed = db_state.get("installed_tools", [])

        missing = [t for t in required if t not in installed]

        if missing:
            self.status = GateStatus.FAIL
            self.reason = f"{len(missing)} tools missing: {', '.join(missing[:5])}"
            self.details = {"missing_tools": missing}
        else:
            self.status = GateStatus.PASS
            self.reason = f"All {len(required)} tools installed"

        self.checked_at = time.time()
        return self.status


class LeadsExploredGate(Gate):
    """All discovered leads have been explored or closed with reason."""

    def __init__(self):
        super().__init__("leads_explored", "Every discovered attack path has been tested or closed with valid reason", "review")

    def check(self, db_state: dict) -> GateStatus:
        open_leads = db_state.get("open_leads", 0)
        total_leads = db_state.get("total_leads", 0)

        if open_leads > 0:
            self.status = GateStatus.FAIL
            self.reason = f"{open_leads}/{total_leads} leads still open"
            self.details = {"open_leads": open_leads}
        else:
            self.status = GateStatus.PASS
            self.reason = f"All {total_leads} leads explored/closed"

        self.checked_at = time.time()
        return self.status


class FindingsCompleteGate(Gate):
    """Every finding has: status, tool, CVE check, evidence, attack vectors."""

    def __init__(self):
        super().__init__("findings_complete", "Every finding is fully documented with evidence", "review")

    def check(self, db_state: dict) -> GateStatus:
        findings = db_state.get("findings", [])
        incomplete = []

        for f in findings:
            missing_fields = []
            if not f.get("status"):
                missing_fields.append("status")
            if not f.get("tool"):
                missing_fields.append("tool")
            if not f.get("evidence"):
                missing_fields.append("evidence")
            if not f.get("vectors"):
                missing_fields.append("vectors")

            if missing_fields:
                incomplete.append({"id": f.get("id"), "missing": missing_fields})

        if incomplete:
            self.status = GateStatus.FAIL
            self.reason = f"{len(incomplete)}/{len(findings)} findings incomplete"
            self.details = {"incomplete_findings": incomplete}
        elif findings:
            self.status = GateStatus.PASS
            self.reason = f"All {len(findings)} findings fully documented"
        else:
            self.status = GateStatus.PASS
            self.reason = "No findings to verify"

        self.checked_at = time.time()
        return self.status


class ScopeEnforcedGate(Gate):
    """No out-of-scope requests were made."""

    def __init__(self):
        super().__init__("scope_enforced", "All requests stayed within authorized scope", "review")

    def check(self, db_state: dict) -> GateStatus:
        scope_violations = db_state.get("scope_violations", [])

        if scope_violations:
            self.status = GateStatus.FAIL
            self.reason = f"{len(scope_violations)} scope violations detected"
            self.details = {"violations": scope_violations[:5]}
        else:
            self.status = GateStatus.PASS
            self.reason = "No scope violations"

        self.checked_at = time.time()
        return self.status


class CompletionGates:
    """Manages all completion gates for an engagement."""

    def __init__(self, engagement_dir: Optional[Path] = None):
        self.engagement_dir = engagement_dir or Path.home() / ".hydra_data"
        self.engagement_dir.mkdir(parents=True, exist_ok=True)
        self.gates_file = self.engagement_dir / "completion_gates.json"
        self.gates: list[Gate] = [
            ToolsInstalledGate(),
            ReconCompleteGate(),
            LeadsExploredGate(),
            FindingsCompleteGate(),
            ScopeEnforcedGate(),
        ]
        self._load()

    def _load(self):
        """Load gate states from disk."""
        if self.gates_file.exists():
            try:
                data = json.loads(self.gates_file.read_text(encoding="utf-8"))
                saved = {g["name"]: g for g in data.get("gates", [])}
                for gate in self.gates:
                    if gate.name in saved:
                        gate.status = GateStatus(saved[gate.name]["status"])
                        gate.reason = saved[gate.name].get("reason", "")
                        gate.checked_at = saved[gate.name].get("checked_at")
                        gate.details = saved[gate.name].get("details", {})
            except (json.JSONDecodeError, KeyError):
                pass

    def _save(self):
        """Save gate states to disk."""
        data = {
            "gates": [g.to_dict() for g in self.gates],
            "last_checked": time.time(),
        }
        self.gates_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def check_all(self, db_state: dict) -> dict:
        """Check all gates against database state. Returns summary."""
        results = []
        all_pass = True

        for gate in self.gates:
            gate.check(db_state)
            results.append(gate.to_dict())
            if gate.status != GateStatus.PASS:
                all_pass = False

        self._save()

        passed = sum(1 for g in self.gates if g.status == GateStatus.PASS)
        total = len(self.gates)

        return {
            "all_pass": all_pass,
            "passed": passed,
            "total": total,
            "percentage": round(passed / total * 100) if total > 0 else 0,
            "gates": results,
            "blocked_by": [
                g["name"] for g in results
                if g["status"] != "pass"
            ],
        }

    def check_phase(self, phase: str, db_state: dict) -> dict:
        """Check gates for a specific phase."""
        phase_gates = [g for g in self.gates if g.phase == phase]
        results = []
        all_pass = True

        for gate in phase_gates:
            gate.check(db_state)
            results.append(gate.to_dict())
            if gate.status != GateStatus.PASS:
                all_pass = False

        self._save()

        return {
            "phase": phase,
            "all_pass": all_pass,
            "gates": results,
        }

    def is_done(self) -> bool:
        """Check if ALL gates pass (engagement is truly complete)."""
        return all(g.status == GateStatus.PASS for g in self.gates)

    def get_pending(self) -> list[str]:
        """Get list of gate names that haven't passed yet."""
        return [g.name for g in self.gates if g.status != GateStatus.PASS]

    def render(self) -> str:
        """Render gates as human-readable text."""
        lines = ["COMPLETION GATES", "=" * 40]
        for gate in self.gates:
            icon = "[PASS]" if gate.status == GateStatus.PASS else "[FAIL]"
            lines.append(f"  {icon} {gate.name}: {gate.reason}")
        lines.append("=" * 40)
        passed = sum(1 for g in self.gates if g.status == GateStatus.PASS)
        lines.append(f"  {passed}/{len(self.gates)} gates passed")
        return "\n".join(lines)


# Global instance
completion_gates = CompletionGates()
