"""HYDRA hunt state tracker.

Actual tool execution is delegated to the configured OpenCode agents. This
module records state and deliberately blocks unconfigured phases rather than
pretending scans or exploitation occurred.
"""

import json
import time
from enum import Enum
from pathlib import Path
from typing import Optional


class HuntPhase(Enum):
    INIT = "init"
    RECON = "recon"
    ENUMERATION = "enumeration"
    VULN_SCAN = "vuln_scan"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"
    COMPLETE = "complete"
    PAUSED = "paused"
    ERROR = "error"


class HuntTarget:
    def __init__(self, name, domain, scope=None, program_url=None, bounty_range=None):
        self.name = name
        self.domain = domain
        self.scope = scope or [domain]
        self.program_url = program_url
        self.bounty_range = bounty_range
        self.created_at = time.time()

    def to_dict(self):
        return {
            "name": self.name,
            "domain": self.domain,
            "scope": self.scope,
            "program_url": self.program_url,
            "bounty_range": self.bounty_range,
            "created_at": self.created_at,
        }


class HuntResult:
    def __init__(self, target, hunt_id=""):
        self.hunt_id = hunt_id
        self.target = target
        self.phase = HuntPhase.INIT
        self.paused_phase = None
        self.findings = []
        self.endpoints_discovered = []
        self.subdomains_found = []
        self.technologies = []
        self.waf_detected = None
        self.errors = []
        self.actions_log = []
        self.started_at = time.time()
        self.completed_at = None
        self.duration = None

    def log(self, action, details=""):
        self.actions_log.append(
            {
                "time": time.time(),
                "phase": self.phase.value,
                "action": action,
                "details": details,
            }
        )

    def to_dict(self):
        return {
            "hunt_id": self.hunt_id,
            "target": self.target.to_dict(),
            "phase": self.phase.value,
            "findings_count": len(self.findings),
            "endpoints_count": len(self.endpoints_discovered),
            "subdomains_count": len(self.subdomains_found),
            "technologies": self.technologies,
            "waf_detected": self.waf_detected,
            "errors": len(self.errors),
            "actions_count": len(self.actions_log),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.duration,
        }


class AutopilotEngine:
    """Hunt state tracker. Actual tool execution is delegated to OpenCode."""

    def __init__(self, data_dir=None):
        self.data_dir = data_dir or Path.home() / ".hydra_data" / "hunts"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.active_hunts = {}
        self.completed_hunts = []
        self._load_completed()

    def _load_completed(self):
        completed_file = self.data_dir / "completed.json"
        if completed_file.exists():
            try:
                self.completed_hunts = json.loads(
                    completed_file.read_text(encoding="utf-8")
                )
            except Exception:
                pass

    def _save_completed(self):
        completed_file = self.data_dir / "completed.json"
        completed_file.write_text(
            json.dumps(self.completed_hunts[-50:], indent=2), encoding="utf-8"
        )

    def start_hunt(
        self, target_name, domain, scope=None, program_url=None, bounty_range=None
    ):
        target = HuntTarget(target_name, domain, scope, program_url, bounty_range)
        hunt_id = f"hunt_{int(time.time())}_{target_name.replace(' ', '_').lower()}"
        result = HuntResult(target, hunt_id)
        result.phase = HuntPhase.INIT
        result.log("hunt_started", f"Target: {target_name} ({domain})")
        self.active_hunts[hunt_id] = result
        return hunt_id, result

    def execute_phase(self, hunt_id):
        if hunt_id not in self.active_hunts:
            return None
        result = self.active_hunts[hunt_id]
        phase = result.phase
        try:
            if phase == HuntPhase.INIT:
                return self._phase_init(result)
            elif phase == HuntPhase.RECON:
                return self._phase_recon(result)
            elif phase == HuntPhase.ENUMERATION:
                return self._phase_enumeration(result)
            elif phase == HuntPhase.VULN_SCAN:
                return self._phase_vuln_scan(result)
            elif phase == HuntPhase.EXPLOITATION:
                return self._phase_exploitation(result)
            elif phase == HuntPhase.VALIDATION:
                return self._phase_validation(result)
            elif phase == HuntPhase.REPORTING:
                return self._phase_reporting(result)
            else:
                return {"error": f"Unknown phase: {phase}"}
        except Exception as e:
            result.errors.append(str(e))
            result.log("phase_error", str(e))
            result.phase = HuntPhase.ERROR
            return {"error": str(e)}

    def _phase_init(self, result):
        result.phase = HuntPhase.RECON
        result.log("init_complete", "Target loaded, starting recon")
        return {"status": "ok", "next_phase": "recon", "target": result.target.name}

    def _phase_recon(self, result):
        return self._execution_unavailable(result, "recon")

    def _phase_enumeration(self, result):
        return self._execution_unavailable(result, "enumeration")

    def _phase_vuln_scan(self, result):
        return self._execution_unavailable(result, "vulnerability scan")

    def _phase_exploitation(self, result):
        return self._execution_unavailable(result, "exploitation")

    def _execution_unavailable(self, result, phase_name):
        """Never claim a scan/exploit completed when no adapter ran."""
        result.paused_phase = result.phase
        result.phase = HuntPhase.PAUSED
        message = (
            f"No native {phase_name} adapter is configured. Use the OpenCode-backed "
            "hydra hunt command to run real tools; no target traffic was sent."
        )
        result.log("phase_blocked", message)
        return {"status": "blocked", "phase": phase_name, "message": message}

    def _phase_validation(self, result):
        if not result.findings:
            return self._execution_unavailable(
                result, "validation (there are no findings)"
            )
        # The deterministic gate can review supplied findings, but does not
        # fabricate evidence or scope approval on their behalf.
        try:
            from .validation_gate import ValidationResult
        except ImportError:
            from core.validation_gate import ValidationResult
        outcomes = []
        for finding in result.findings:
            outcome = ValidationResult(finding).auto_validate()
            finding["validation_result"] = outcome
            finding["validated"] = outcome["overall"] == "pass"
            outcomes.append(outcome["overall"])
        validated = sum(outcome == "pass" for outcome in outcomes)
        if validated != len(result.findings):
            result.phase = HuntPhase.PAUSED
            result.paused_phase = HuntPhase.VALIDATION
            result.log(
                "validation_needs_work",
                f"{validated}/{len(result.findings)} passed; remaining findings need evidence",
            )
            return {
                "status": "needs_work",
                "validated": validated,
                "total": len(result.findings),
            }
        result.phase = HuntPhase.REPORTING
        result.log(
            "validation_complete",
            f"{validated}/{len(result.findings)} findings passed the gate",
        )
        return {"status": "ok", "next_phase": "reporting", "validated": validated}

    def _phase_reporting(self, result):
        return self._execution_unavailable(
            result, "report generation (use the OpenCode reporter agent)"
        )

    def pause_hunt(self, hunt_id):
        if hunt_id in self.active_hunts:
            result = self.active_hunts[hunt_id]
            result.paused_phase = result.phase
            result.phase = HuntPhase.PAUSED
            result.log("hunt_paused", "Manually paused")
            return True
        return False

    def resume_hunt(self, hunt_id):
        if hunt_id in self.active_hunts:
            r = self.active_hunts[hunt_id]
            if r.phase == HuntPhase.PAUSED:
                r.phase = r.paused_phase or HuntPhase.RECON
                r.paused_phase = None
                r.log("hunt_resumed", "Resumed from pause")
                return True
        return False

    def get_status(self, hunt_id):
        if hunt_id in self.active_hunts:
            return self.active_hunts[hunt_id].to_dict()
        for h in self.completed_hunts:
            if h.get("hunt_id") == hunt_id:
                return h
        return None

    def list_hunts(self):
        active = {k: v.to_dict() for k, v in self.active_hunts.items()}
        completed = self.completed_hunts[-10:]
        return {
            "active": active,
            "completed": completed,
            "total_completed": len(self.completed_hunts),
        }

    def stats(self):
        return {
            "active_hunts": len(self.active_hunts),
            "completed_hunts": len(self.completed_hunts),
            "total_findings": sum(
                h.get("findings_count", 0) for h in self.completed_hunts
            ),
        }


autopilot = AutopilotEngine()
