"""
HYDRA Session Store — SQLite engagement storage
Persists engagements, findings, tasks, evidence, and notes.
Supports resume, rewind, and fork operations.
"""
import json
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_DIR = Path.home() / "hydra" / "sessions"


class SessionStore:
    """SQLite-backed engagement storage."""

    def __init__(self, engagement_id: Optional[str] = None):
        DB_DIR.mkdir(parents=True, exist_ok=True)
        if engagement_id:
            self.db_path = DB_DIR / f"{engagement_id}.db"
        else:
            self.db_path = DB_DIR / f"engagement_{int(time.time())}.db"
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS engagements (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scope TEXT,
                status TEXT DEFAULT 'active',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                notes TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                vuln_class TEXT,
                severity TEXT DEFAULT 'info',
                cvss REAL DEFAULT 0.0,
                endpoint TEXT,
                method TEXT,
                parameter TEXT,
                evidence TEXT DEFAULT '{}',
                status TEXT DEFAULT 'candidate',
                proof_capsule TEXT DEFAULT '{}',
                oracle_name TEXT,
                oracle_result TEXT,
                verified_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (engagement_id) REFERENCES engagements(id)
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER,
                engagement_id TEXT NOT NULL,
                tool_name TEXT,
                request_raw TEXT,
                response_raw TEXT,
                response_code INTEGER,
                response_size INTEGER,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(id),
                FOREIGN KEY (engagement_id) REFERENCES engagements(id)
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                parent_id INTEGER,
                task_type TEXT,
                description TEXT,
                status TEXT DEFAULT 'pending',
                tool_used TEXT,
                result TEXT,
                error TEXT,
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (engagement_id) REFERENCES engagements(id),
                FOREIGN KEY (parent_id) REFERENCES tasks(id)
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                snapshot_type TEXT DEFAULT 'auto',
                task_tree TEXT DEFAULT '{}',
                findings_summary TEXT DEFAULT '{}',
                conversation TEXT DEFAULT '[]',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (engagement_id) REFERENCES engagements(id)
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                content TEXT,
                tags TEXT DEFAULT '[]',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (engagement_id) REFERENCES engagements(id)
            );
        """)
        self.conn.commit()

    # ── Engagement ──

    def create_engagement(self, target: str, scope: str = "", notes: dict = None) -> str:
        """Create a new engagement. Returns engagement ID."""
        eid = f"eng_{int(time.time())}_{target.replace('.', '_').replace('/', '_')[:30]}"
        self.conn.execute(
            "INSERT INTO engagements (id, target, scope, notes) VALUES (?, ?, ?, ?)",
            (eid, target, scope, json.dumps(notes or {}))
        )
        self.conn.commit()
        return eid

    def get_engagement(self, eid: str) -> dict:
        """Get engagement by ID."""
        row = self.conn.execute("SELECT * FROM engagements WHERE id = ?", (eid,)).fetchone()
        if row:
            return dict(row)
        return {}

    def update_engagement(self, eid: str, **kwargs):
        """Update engagement fields."""
        for key, value in kwargs.items():
            if key in ("status", "notes", "scope"):
                if key == "notes":
                    value = json.dumps(value)
                self.conn.execute(
                    f"UPDATE engagements SET {key} = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (value, eid)
                )
        self.conn.commit()

    def list_engagements(self, status: str = None) -> list:
        """List all engagements, optionally filtered by status."""
        if status:
            rows = self.conn.execute(
                "SELECT * FROM engagements WHERE status = ? ORDER BY created_at DESC", (status,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM engagements ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Findings ──

    def add_finding(self, engagement_id: str, vuln_class: str, severity: str = "info",
                    endpoint: str = "", method: str = "GET", parameter: str = "",
                    evidence: dict = None, cvss: float = 0.0) -> int:
        """Add a finding. Returns finding ID."""
        cursor = self.conn.execute(
            """INSERT INTO findings
               (engagement_id, vuln_class, severity, cvss, endpoint, method, parameter, evidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (engagement_id, vuln_class, severity, cvss, endpoint, method, parameter,
             json.dumps(evidence or {}))
        )
        self.conn.commit()
        return cursor.lastrowid

    def update_finding(self, finding_id: int, **kwargs):
        """Update finding fields."""
        allowed = ("status", "proof_capsule", "oracle_name", "oracle_result", "verified_at", "severity", "cvss")
        for key, value in kwargs.items():
            if key in allowed:
                if key in ("proof_capsule", "evidence"):
                    value = json.dumps(value)
                self.conn.execute(
                    f"UPDATE findings SET {key} = ? WHERE id = ?", (value, finding_id)
                )
        self.conn.commit()

    def get_findings(self, engagement_id: str, status: str = None) -> list:
        """Get findings for an engagement."""
        if status:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ? AND status = ? ORDER BY created_at DESC",
                (engagement_id, status)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ? ORDER BY created_at DESC",
                (engagement_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_finding(self, finding_id: int) -> dict:
        """Get a single finding."""
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return dict(row) if row else {}

    # ── Evidence ──

    def add_evidence(self, engagement_id: str, finding_id: int = None,
                     tool_name: str = "", request_raw: str = "",
                     response_raw: str = "", response_code: int = 0) -> int:
        """Add evidence. Returns evidence ID."""
        cursor = self.conn.execute(
            """INSERT INTO evidence
               (finding_id, engagement_id, tool_name, request_raw, response_raw, response_code)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (finding_id, engagement_id, tool_name, request_raw, response_raw, response_code)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_evidence(self, engagement_id: str, finding_id: int = None) -> list:
        """Get evidence for an engagement or finding."""
        if finding_id:
            rows = self.conn.execute(
                "SELECT * FROM evidence WHERE finding_id = ? ORDER BY timestamp", (finding_id,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM evidence WHERE engagement_id = ? ORDER BY timestamp",
                (engagement_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Tasks ──

    def add_task(self, engagement_id: str, task_type: str, description: str,
                 parent_id: int = None) -> int:
        """Add a task. Returns task ID."""
        cursor = self.conn.execute(
            "INSERT INTO tasks (engagement_id, parent_id, task_type, description) VALUES (?, ?, ?, ?)",
            (engagement_id, parent_id, task_type, description)
        )
        self.conn.commit()
        return cursor.lastrowid

    def update_task(self, task_id: int, status: str = None, tool_used: str = None,
                    result: str = None, error: str = None):
        """Update task status."""
        if status:
            if status == "running":
                self.conn.execute(
                    "UPDATE tasks SET status = ?, started_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (status, task_id)
                )
            elif status in ("success", "failed"):
                self.conn.execute(
                    "UPDATE tasks SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (status, task_id)
                )
            else:
                self.conn.execute(
                    "UPDATE tasks SET status = ? WHERE id = ?", (status, task_id)
                )
        if tool_used:
            self.conn.execute("UPDATE tasks SET tool_used = ? WHERE id = ?", (tool_used, task_id))
        if result:
            self.conn.execute("UPDATE tasks SET result = ? WHERE id = ?", (result, task_id))
        if error:
            self.conn.execute("UPDATE tasks SET error = ? WHERE id = ?", (error, task_id))
        self.conn.commit()

    def get_tasks(self, engagement_id: str, status: str = None) -> list:
        """Get tasks for an engagement."""
        if status:
            rows = self.conn.execute(
                "SELECT * FROM tasks WHERE engagement_id = ? AND status = ? ORDER BY created_at",
                (engagement_id, status)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM tasks WHERE engagement_id = ? ORDER BY created_at",
                (engagement_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Snapshots (for rewind/fork) ──

    def save_snapshot(self, engagement_id: str, task_tree: dict = None,
                      findings_summary: dict = None, conversation: list = None,
                      snapshot_type: str = "auto") -> int:
        """Save a snapshot for rewind/fork. Returns snapshot ID."""
        cursor = self.conn.execute(
            """INSERT INTO snapshots
               (engagement_id, snapshot_type, task_tree, findings_summary, conversation)
               VALUES (?, ?, ?, ?, ?)""",
            (engagement_id, snapshot_type,
             json.dumps(task_tree or {}),
             json.dumps(findings_summary or {}),
             json.dumps(conversation or []))
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_snapshots(self, engagement_id: str) -> list:
        """Get all snapshots for an engagement."""
        rows = self.conn.execute(
            "SELECT * FROM snapshots WHERE engagement_id = ? ORDER BY created_at",
            (engagement_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_snapshot(self, snapshot_id: int) -> dict:
        """Get a specific snapshot."""
        row = self.conn.execute("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()
        return dict(row) if row else {}

    # ── Notes ──

    def add_note(self, engagement_id: str, content: str, category: str = "general",
                 tags: list = None) -> int:
        """Add a note. Returns note ID."""
        cursor = self.conn.execute(
            "INSERT INTO notes (engagement_id, category, content, tags) VALUES (?, ?, ?, ?)",
            (engagement_id, category, content, json.dumps(tags or []))
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_notes(self, engagement_id: str, category: str = None) -> list:
        """Get notes for an engagement."""
        if category:
            rows = self.conn.execute(
                "SELECT * FROM notes WHERE engagement_id = ? AND category = ? ORDER BY created_at DESC",
                (engagement_id, category)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM notes WHERE engagement_id = ? ORDER BY created_at DESC",
                (engagement_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Stats ──

    def get_stats(self, engagement_id: str) -> dict:
        """Get engagement statistics."""
        findings = self.get_findings(engagement_id)
        tasks = self.get_tasks(engagement_id)
        return {
            "total_findings": len(findings),
            "verified": len([f for f in findings if f["status"] == "verified"]),
            "candidates": len([f for f in findings if f["status"] == "candidate"]),
            "false_positives": len([f for f in findings if f["status"] == "false_positive"]),
            "total_tasks": len(tasks),
            "tasks_done": len([t for t in tasks if t["status"] in ("success", "failed")]),
            "critical": len([f for f in findings if f["severity"] == "critical"]),
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "low": len([f for f in findings if f["severity"] == "low"]),
        }

    def close(self):
        """Close database connection."""
        self.conn.close()


# Convenience function
def get_store(engagement_id: str = None) -> SessionStore:
    """Get a session store instance."""
    return SessionStore(engagement_id)
