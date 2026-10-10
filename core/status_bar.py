"""
HYDRA Status Bar — Live status for OpenCode TUI
Writes status to a file that OpenCode can display in the sidebar.
Auto-updates as the AI progresses through tasks.
"""
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

STATUS_FILE = Path.home() / ".hydra_status.json"
STATUS_HISTORY = Path.home() / ".hydra_status_history.jsonl"


class StatusBar:
    """Live status bar that auto-updates in OpenCode TUI."""

    def __init__(self):
        self.phase = "idle"
        self.task = ""
        self.detail = ""
        self.findings_count = 0
        self.verified_count = 0
        self.start_time = None
        self.tasks_done = 0
        self.tasks_total = 0
        self.errors = 0
        self._update()

    def set_phase(self, phase: str, task: str = "", detail: str = ""):
        """Set current phase: idle, recon, scan, exploit, verify, report."""
        self.phase = phase
        self.task = task
        self.detail = detail
        self._update()

    def update_task(self, task: str, detail: str = ""):
        """Update current task description."""
        self.task = task
        self.detail = detail
        self._update()

    def add_finding(self, verified: bool = False):
        """Record a new finding."""
        self.findings_count += 1
        if verified:
            self.verified_count += 1
        self._update()

    def set_progress(self, done: int, total: int):
        """Update task progress."""
        self.tasks_done = done
        self.tasks_total = total
        self._update()

    def add_error(self):
        """Record an error."""
        self.errors += 1
        self._update()

    def set_idle(self):
        """Reset to idle state."""
        self.phase = "idle"
        self.task = ""
        self.detail = ""
        self.tasks_done = 0
        self.tasks_total = 0
        self._update()

    def get_status(self) -> dict:
        """Get current status as dict."""
        elapsed = ""
        if self.start_time:
            delta = time.time() - self.start_time
            mins, secs = divmod(int(delta), 60)
            elapsed = f"{mins}m {secs}s"

        return {
            "phase": self.phase,
            "task": self.task,
            "detail": self.detail,
            "findings": self.findings_count,
            "verified": self.verified_count,
            "tasks_done": self.tasks_done,
            "tasks_total": self.tasks_total,
            "errors": self.errors,
            "elapsed": elapsed,
            "timestamp": datetime.now().isoformat(),
        }

    def render(self) -> str:
        """Render status bar as text for display."""
        s = self.get_status()
        lines = []

        # Phase indicator
        phase_icons = {
            "idle": "[ ] IDLE",
            "recon": "[>] RECON",
            "scan": "[*] SCANNING",
            "exploit": "[!] EXPLOITING",
            "verify": "[?] VERIFYING",
            "report": "[~] REPORTING",
        }
        lines.append(phase_icons.get(s["phase"], f"[?] {s['phase'].upper()}"))

        # Current task
        if s["task"]:
            lines.append(f"  {s['task']}")
        if s["detail"]:
            lines.append(f"  {s['detail']}")

        # Progress bar
        if s["tasks_total"] > 0:
            pct = int((s["tasks_done"] / s["tasks_total"]) * 100)
            bar_len = 20
            filled = int(bar_len * s["tasks_done"] / s["tasks_total"])
            bar = "=" * filled + "-" * (bar_len - filled)
            lines.append(f"  [{bar}] {pct}% ({s['tasks_done']}/{s['tasks_total']})")

        # Stats
        stats = []
        if s["findings"] > 0:
            stats.append(f"{s['findings']} found")
        if s["verified"] > 0:
            stats.append(f"{s['verified']} verified")
        if s["errors"] > 0:
            stats.append(f"{s['errors']} errors")
        if s["elapsed"]:
            stats.append(s["elapsed"])
        if stats:
            lines.append(f"  {' | '.join(stats)}")

        return "\n".join(lines)

    def _update(self):
        """Write status to file for OpenCode to display."""
        status = self.get_status()
        status["rendered"] = self.render()

        # Write current status
        with open(STATUS_FILE, "w") as f:
            json.dump(status, f, indent=2)

        # Append to history
        with open(STATUS_HISTORY, "a") as f:
            f.write(json.dumps(status) + "\n")

    @staticmethod
    def read() -> dict:
        """Read current status from file."""
        if STATUS_FILE.exists():
            with open(STATUS_FILE) as f:
                return json.load(f)
        return {"phase": "idle", "task": "", "detail": ""}

    @staticmethod
    def read_rendered() -> str:
        """Read rendered status text."""
        status = StatusBar.read()
        return status.get("rendered", "[ ] IDLE")

    @staticmethod
    def clear():
        """Clear status file."""
        if STATUS_FILE.exists():
            STATUS_FILE.unlink()


# Singleton for easy import
status = StatusBar()
