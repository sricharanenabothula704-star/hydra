"""Session Command Logger — SHA256 Hashed Outputs

Stolen from: opencode-pentester's session command logging
What it does: Every tool run recorded with timestamp, command, exit code, duration, SHA256 hash

How it works:
1. Before running any tool: log command + timestamp
2. After tool completes: log exit code + duration + output
3. Compute SHA256 of output for tamper-evident record
4. Store output excerpt (first 800 chars) inline
5. Full output saved to file
6. Session can be replayed exactly as it happened

This beats opencode-pentester because:
- Theirs: Shell script (findings.sh log)
- Ours: Python-native with anti-hallucination integration
"""
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional


class LogEntry:
    """A single tool execution log entry."""

    def __init__(
        self,
        agent: str,
        tool: str,
        command: str,
        target: str = "",
        phase: str = "",
    ):
        self.id = f"log_{int(time.time() * 1000)}"
        self.agent = agent
        self.tool = tool
        self.command = command
        self.target = target
        self.phase = phase
        self.created_at = time.time()
        self.exit_code = None
        self.duration_ms = None
        self.output_file = None
        self.output_hash = None
        self.output_excerpt = None
        self.summary = ""

    def finish(self, exit_code: int, output: str, duration_ms: float, output_dir: str = None):
        """Complete this log entry with results."""
        self.exit_code = exit_code
        self.duration_ms = duration_ms
        self.summary = output[:200].replace("\n", " ")

        # Compute SHA256
        self.output_hash = hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest()

        # Store excerpt
        self.output_excerpt = output[:800]

        # Save full output to file
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            filename = f"{self.tool}_{self.id}.txt"
            self.output_file = os.path.join(output_dir, filename)
            with open(self.output_file, "w", encoding="utf-8") as f:
                f.write(output)

    def to_dict(self):
        return {
            "id": self.id,
            "agent": self.agent,
            "tool": self.tool,
            "command": self.command,
            "target": self.target,
            "phase": self.phase,
            "created_at": self.created_at,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "output_file": self.output_file,
            "output_hash": self.output_hash,
            "output_excerpt": self.output_excerpt,
            "summary": self.summary,
        }


class SessionLogger:
    """Logs every tool execution for deterministic replay."""

    def __init__(self, engagement_dir: Optional[Path] = None):
        self.engagement_dir = engagement_dir or Path.home() / ".hydra_data"
        self.engagement_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.engagement_dir / "session_log.jsonl"
        self.output_dir = str(self.engagement_dir / "outputs")
        self.entries: list[LogEntry] = []
        self._load()

    def _load(self):
        """Load existing log entries."""
        if self.log_file.exists():
            try:
                for line in self.log_file.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        data = json.loads(line)
                        entry = LogEntry(
                            agent=data["agent"],
                            tool=data["tool"],
                            command=data["command"],
                            target=data.get("target", ""),
                            phase=data.get("phase", ""),
                        )
                        entry.id = data["id"]
                        entry.created_at = data.get("created_at", time.time())
                        entry.exit_code = data.get("exit_code")
                        entry.duration_ms = data.get("duration_ms")
                        entry.output_file = data.get("output_file")
                        entry.output_hash = data.get("output_hash")
                        entry.output_excerpt = data.get("output_excerpt")
                        entry.summary = data.get("summary", "")
                        self.entries.append(entry)
            except Exception:
                pass

    def log(self, agent: str, tool: str, command: str, target: str = "", phase: str = "") -> LogEntry:
        """Start logging a new tool execution."""
        entry = LogEntry(agent, tool, command, target, phase)
        self.entries.append(entry)
        return entry

    def finish(self, entry: LogEntry, exit_code: int, output: str, duration_ms: float):
        """Complete a log entry."""
        entry.finish(exit_code, output, duration_ms, self.output_dir)
        self._append(entry)

    def _append(self, entry: LogEntry):
        """Append entry to log file."""
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

    def get_entries(
        self,
        agent: str = None,
        phase: str = None,
        tool: str = None,
        limit: int = None,
    ) -> list[LogEntry]:
        """Filter log entries."""
        result = self.entries

        if agent:
            result = [e for e in result if e.agent == agent]
        if phase:
            result = [e for e in result if e.phase == phase]
        if tool:
            result = [e for e in result if e.tool == tool]
        if limit:
            result = result[-limit:]

        return result

    def get_session_timeline(self) -> str:
        """Render full session as text timeline."""
        lines = ["SESSION TIMELINE", "=" * 60]

        for entry in self.entries:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.created_at))
            status = "OK" if entry.exit_code == 0 else f"FAIL({entry.exit_code})"
            duration = f"{entry.duration_ms:.0f}ms" if entry.duration_ms else "?"

            lines.append(f"[{ts}] {entry.agent}/{entry.tool} {status} ({duration})")
            lines.append(f"  CMD: {entry.command[:100]}")
            if entry.output_hash:
                lines.append(f"  HASH: {entry.output_hash[:16]}...")
            lines.append("")

        lines.append("=" * 60)
        lines.append(f"Total entries: {len(self.entries)}")
        return "\n".join(lines)

    def get_tool_stats(self) -> dict:
        """Get statistics about tool usage."""
        tools = {}
        for entry in self.entries:
            if entry.tool not in tools:
                tools[entry.tool] = {"count": 0, "success": 0, "fail": 0, "total_ms": 0}
            tools[entry.tool]["count"] += 1
            if entry.exit_code == 0:
                tools[entry.tool]["success"] += 1
            else:
                tools[entry.tool]["fail"] += 1
            if entry.duration_ms:
                tools[entry.tool]["total_ms"] += entry.duration_ms

        return tools

    def verify_integrity(self, entry_id: str, original_output: str) -> bool:
        """Verify a log entry's output hash matches."""
        for entry in self.entries:
            if entry.id == entry_id and entry.output_hash:
                computed = hashlib.sha256(original_output.encode("utf-8", errors="replace")).hexdigest()
                return computed == entry.output_hash
        return False

    def stats(self) -> dict:
        """Get session statistics."""
        total = len(self.entries)
        success = sum(1 for e in self.entries if e.exit_code == 0)
        tools = set(e.tool for e in self.entries)
        agents = set(e.agent for e in self.entries)

        return {
            "total_entries": total,
            "success": success,
            "failures": total - success,
            "unique_tools": len(tools),
            "unique_agents": len(agents),
            "tools": list(tools),
            "agents": list(agents),
        }


# Global instance
session_logger = SessionLogger()
