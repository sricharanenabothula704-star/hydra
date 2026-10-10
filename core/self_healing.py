"""Self-Healing Module — Auto-Recover from Failures

Stolen from: DRAKBEN's self-healing + strategy mutation
What it does: Auto-recover when tools fail, learn from failures

How it works:
1. On tool failure:
   - Parse error message
   - Classify: network error, permission denied, tool not found, WAF blocked
2. Select recovery strategy:
   - Network error → retry with timeout
   - Permission denied → skip, try alternative
   - Tool not found → auto-install
   - WAF blocked → try bypass technique
3. Execute recovery
4. Log what worked for future

This is what makes HYDRA better:
- PentestGPT: Crashes on tool failure
- PentestAgent: Manual retry only
- HYDRA: Auto-recover + learn from failures
"""
import json
import re
import time
from enum import Enum
from pathlib import Path
from typing import Optional


class ErrorClass(Enum):
    NETWORK = "network"
    PERMISSION = "permission"
    TOOL_NOT_FOUND = "tool_not_found"
    WAF_BLOCKED = "waf_blocked"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class RecoveryAction(Enum):
    RETRY = "retry"
    RETRY_WITH_FLAGS = "retry_with_flags"
    SKIP = "skip"
    USE_ALTERNATIVE = "use_alternative"
    INSTALL_TOOL = "install_tool"
    WAIT_AND_RETRY = "wait_and_retry"
    ABORT = "abort"


class FailureRecord:
    """Record of a tool failure and its recovery."""

    def __init__(self, tool: str, error: str, error_class: ErrorClass):
        self.tool = tool
        self.error = error
        self.error_class = error_class
        self.recovery_action = None
        self.recovery_success = False
        self.timestamp = time.time()
        self.attempts = 0

    def to_dict(self):
        return {
            "tool": self.tool,
            "error": self.error[:200],
            "error_class": self.error_class.value,
            "recovery_action": self.recovery_action.value if self.recovery_action else None,
            "recovery_success": self.recovery_success,
            "timestamp": self.timestamp,
            "attempts": self.attempts,
        }


class SelfHealer:
    """Auto-recover from tool failures."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".hydra_data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.failures_file = self.data_dir / "failures.jsonl"
        self.failure_history: list[FailureRecord] = []
        self.tool_penalties: dict[str, float] = {}  # tool → penalty (0-1)
        self.max_retries = 3
        self._load_history()

    def _load_history(self):
        """Load failure history."""
        if self.failures_file.exists():
            try:
                for line in self.failures_file.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        data = json.loads(line)
                        record = FailureRecord(
                            tool=data["tool"],
                            error=data["error"],
                            error_class=ErrorClass(data["error_class"]),
                        )
                        record.recovery_action = RecoveryAction(data["recovery_action"]) if data.get("recovery_action") else None
                        record.recovery_success = data.get("recovery_success", False)
                        record.timestamp = data.get("timestamp", time.time())
                        record.attempts = data.get("attempts", 0)
                        self.failure_history.append(record)
            except (json.JSONDecodeError, KeyError):
                pass

    def _save_failure(self, record: FailureRecord):
        """Save failure record."""
        with open(self.failures_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict()) + "\n")

    def classify_error(self, error_output: str) -> ErrorClass:
        """Classify error type from output."""
        error_lower = error_output.lower()

        # Network errors
        network_patterns = [
            "connection refused", "connection reset", "network unreachable",
            "no route to host", "name resolution", "dns", "timeout",
            "connection timed out", "ssl", "certificate",
        ]
        for pat in network_patterns:
            if pat in error_lower:
                return ErrorClass.NETWORK

        # Permission errors
        perm_patterns = [
            "permission denied", "access denied", "403 forbidden",
            "unauthorized", "not authenticated",
        ]
        for pat in perm_patterns:
            if pat in error_lower:
                return ErrorClass.PERMISSION

        # Tool not found
        tool_patterns = [
            "not found", "no such file", "command not found",
            "not recognized", "is not installed",
        ]
        for pat in tool_patterns:
            if pat in error_lower:
                return ErrorClass.TOOL_NOT_FOUND

        # WAF blocked
        waf_patterns = [
            "blocked", "waf", "firewall", "forbidden",
            "request blocked", "security", "403",
        ]
        for pat in waf_patterns:
            if pat in error_lower:
                return ErrorClass.WAF_BLOCKED

        # Rate limit
        rate_patterns = [
            "rate limit", "too many requests", "429",
            "throttl", "slowed down",
        ]
        for pat in rate_patterns:
            if pat in error_lower:
                return ErrorClass.RATE_LIMIT

        # Timeout
        timeout_patterns = ["timeout", "timed out", "deadline exceeded"]
        for pat in timeout_patterns:
            if pat in error_lower:
                return ErrorClass.TIMEOUT

        return ErrorClass.UNKNOWN

    def select_recovery(self, error_class: ErrorClass, tool: str, context: dict = None) -> RecoveryAction:
        """Select recovery strategy based on error class."""
        # Check tool penalty
        penalty = self.tool_penalties.get(tool, 0.0)
        if penalty > 0.9:
            return RecoveryAction.SKIP

        recovery_map = {
            ErrorClass.NETWORK: RecoveryAction.RETRY,
            ErrorClass.PERMISSION: RecoveryAction.USE_ALTERNATIVE,
            ErrorClass.TOOL_NOT_FOUND: RecoveryAction.INSTALL_TOOL,
            ErrorClass.WAF_BLOCKED: RecoveryAction.RETRY_WITH_FLAGS,
            ErrorClass.RATE_LIMIT: RecoveryAction.WAIT_AND_RETRY,
            ErrorClass.TIMEOUT: RecoveryAction.RETRY,
            ErrorClass.UNKNOWN: RecoveryAction.RETRY,
        }

        return recovery_map.get(error_class, RecoveryAction.RETRY)

    def handle_failure(self, tool: str, error: str, context: dict = None) -> dict:
        """
        Handle a tool failure. Returns recovery instructions.

        Args:
            tool: Tool name that failed
            error: Error output
            context: Additional context (command, target, etc.)

        Returns:
            {action, command, message, should_retry}
        """
        error_class = self.classify_error(error)
        recovery = self.select_recovery(error_class, tool, context)

        record = FailureRecord(tool, error, error_class)
        record.recovery_action = recovery
        record.attempts = context.get("attempts", 1) if context else 1

        # Generate recovery instructions
        instructions = self._generate_instructions(tool, error_class, recovery, context)

        # Update penalty
        if recovery in (RecoveryAction.ABORT, RecoveryAction.SKIP):
            self.tool_penalties[tool] = min(1.0, self.tool_penalties.get(tool, 0.0) + 0.1)
        else:
            # Successful recovery reduces penalty
            self.tool_penalties[tool] = max(0.0, self.tool_penalties.get(tool, 0.0) - 0.05)

        record.recovery_success = instructions.get("should_retry", False)
        self._save_failure(record)
        self.failure_history.append(record)

        return instructions

    def _generate_instructions(self, tool: str, error_class: ErrorClass, recovery: RecoveryAction, context: dict = None) -> dict:
        """Generate specific recovery instructions."""
        context = context or {}

        if recovery == RecoveryAction.RETRY:
            return {
                "action": "retry",
                "command": context.get("command", f"{tool} {context.get('target', '')}"),
                "message": f"Retrying {tool} (network/timeout error)",
                "should_retry": True,
                "max_attempts": self.max_retries,
            }

        elif recovery == RecoveryAction.RETRY_WITH_FLAGS:
            # Tool-specific bypass flags
            bypass_flags = {
                "nmap": "-Pn --script=http-waf-detect",
                "sqlmap": "--random-agent --tamper=space2comment",
                "nikto": "-Tuning 1234567890abc",
                "ffuf": "-H 'User-Agent: Mozilla/5.0'",
                "gobuster": "-t 1 -w /usr/share/wordlists/dirb/common.txt",
            }
            flags = bypass_flags.get(tool, "--random-agent")
            cmd = context.get("command", f"{tool} {context.get('target', '')}")
            return {
                "action": "retry_with_flags",
                "command": f"{cmd} {flags}",
                "message": f"Retrying {tool} with WAF bypass flags: {flags}",
                "should_retry": True,
                "max_attempts": self.max_retries,
            }

        elif recovery == RecoveryAction.USE_ALTERNATIVE:
            alternatives = {
                "nmap": "masscan (faster scan)",
                "nikto": "nuclei (template-based)",
                "sqlmap": "jSQL Injection, SQLi Scanner",
                "ffuf": "gobuster, feroxbuster",
                "gobuster": "ffuf, feroxbuster",
            }
            alt = alternatives.get(tool, "manual testing")
            return {
                "action": "use_alternative",
                "command": alt,
                "message": f"{tool} needs permissions. Alternative: {alt}",
                "should_retry": True,
            }

        elif recovery == RecoveryAction.INSTALL_TOOL:
            install_cmds = {
                "nmap": "apt install -y nmap || choco install nmap",
                "sqlmap": "git clone https://github.com/sqlmapproject/sqlmap.git",
                "nikto": "apt install -y nikto || git clone https://github.com/sullo/nikto.git",
                "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
                "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            }
            cmd = install_cmds.get(tool, f"echo 'Install {tool} manually'")
            return {
                "action": "install",
                "command": cmd,
                "message": f"{tool} not found. Install with: {cmd}",
                "should_retry": True,
            }

        elif recovery == RecoveryAction.WAIT_AND_RETRY:
            wait_time = context.get("wait_time", 30)
            return {
                "action": "wait",
                "command": f"sleep {wait_time}",
                "message": f"Rate limited. Waiting {wait_time}s before retry",
                "should_retry": True,
                "wait_seconds": wait_time,
            }

        elif recovery == RecoveryAction.SKIP:
            return {
                "action": "skip",
                "command": "",
                "message": f"Skipping {tool} (too many failures, penalty={self.tool_penalties.get(tool, 0):.1%})",
                "should_retry": False,
            }

        else:  # ABORT
            return {
                "action": "abort",
                "command": "",
                "message": f"Aborting {tool} (unrecoverable error)",
                "should_retry": False,
            }

    def get_tool_reliability(self, tool: str) -> dict:
        """Get reliability stats for a tool."""
        tool_failures = [f for f in self.failure_history if f.tool == tool]
        total = len(tool_failures)
        recovered = sum(1 for f in tool_failures if f.recovery_success)

        return {
            "tool": tool,
            "total_failures": total,
            "recovered": recovered,
            "recovery_rate": recovered / total if total > 0 else 1.0,
            "penalty": self.tool_penalties.get(tool, 0.0),
            "reliable": self.tool_penalties.get(tool, 0.0) < 0.7,
        }

    def get_recommended_tools(self, tool_list: list[str]) -> list[str]:
        """Sort tools by reliability, return best first."""
        scored = []
        for tool in tool_list:
            penalty = self.tool_penalties.get(tool, 0.0)
            scored.append((tool, 1.0 - penalty))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [t[0] for t in scored]

    def stats(self) -> dict:
        """Get overall healing statistics."""
        total = len(self.failure_history)
        recovered = sum(1 for f in self.failure_history if f.recovery_success)
        error_classes = {}
        for f in self.failure_history:
            error_classes[f.error_class.value] = error_classes.get(f.error_class.value, 0) + 1

        return {
            "total_failures": total,
            "recovered": recovered,
            "recovery_rate": recovered / total if total > 0 else 1.0,
            "error_classes": error_classes,
            "tool_penalties": dict(self.tool_penalties),
        }


# Global instance
self_healer = SelfHealer()
