"""
HYDRA Task Tree (PTT) — Hierarchical task tracking
Inspired by PentestGPT's Pentesting Task Tree.
Each node = hypothesis, finding, or task.
Tracks parent-child relationships, status, evidence.
"""
import json
import time
from datetime import datetime
from enum import Enum
from typing import Optional


class TaskType(str, Enum):
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    VERIFY = "verify"
    REPORT = "report"
    HYPOTHESIS = "hypothesis"
    FINDING = "finding"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class TaskNode:
    """A single node in the task tree."""

    def __init__(self, node_id: int, task_type: str, description: str,
                 parent_id: Optional[int] = None):
        self.id = node_id
        self.task_type = task_type
        self.description = description
        self.parent_id = parent_id
        self.status = TaskStatus.PENDING.value
        self.children = []
        self.evidence = []
        self.tool_used = ""
        self.result = ""
        self.error = ""
        self.created_at = datetime.now().isoformat()
        self.completed_at = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "task_type": self.task_type,
            "description": self.description,
            "parent_id": self.parent_id,
            "status": self.status,
            "children": [c.to_dict() if isinstance(c, TaskNode) else c for c in self.children],
            "evidence": self.evidence,
            "tool_used": self.tool_used,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TaskNode":
        node = cls(
            node_id=data["id"],
            task_type=data["task_type"],
            description=data["description"],
            parent_id=data.get("parent_id"),
        )
        node.status = data.get("status", TaskStatus.PENDING.value)
        node.evidence = data.get("evidence", [])
        node.tool_used = data.get("tool_used", "")
        node.result = data.get("result", "")
        node.error = data.get("error", "")
        node.created_at = data.get("created_at", datetime.now().isoformat())
        node.completed_at = data.get("completed_at")
        node.children = data.get("children", [])
        return node


class TaskTree:
    """Hierarchical task tree for tracking pentest progress."""

    def __init__(self):
        self.nodes = {}
        self.root_ids = []
        self._next_id = 1

    def add_node(self, task_type: str, description: str,
                 parent_id: Optional[int] = None) -> int:
        """Add a node to the tree. Returns node ID."""
        node_id = self._next_id
        self._next_id += 1
        node = TaskNode(node_id, task_type, description, parent_id)
        self.nodes[node_id] = node

        if parent_id and parent_id in self.nodes:
            self.nodes[parent_id].children.append(node_id)
        else:
            self.root_ids.append(node_id)

        return node_id

    def update_node(self, node_id: int, status: str = None, tool_used: str = None,
                    result: str = None, error: str = None, evidence: list = None):
        """Update a node's fields."""
        if node_id not in self.nodes:
            return
        node = self.nodes[node_id]
        if status:
            node.status = status
            if status in (TaskStatus.SUCCESS.value, TaskStatus.FAILED.value):
                node.completed_at = datetime.now().isoformat()
        if tool_used:
            node.tool_used = tool_used
        if result:
            node.result = result
        if error:
            node.error = error
        if evidence:
            node.evidence.extend(evidence)

    def add_finding(self, parent_id: int, description: str,
                    evidence: dict = None) -> int:
        """Add a finding node under a parent task."""
        node_id = self.add_node(TaskType.FINDING.value, description, parent_id)
        self.update_node(node_id, status=TaskStatus.SUCCESS.value,
                        evidence=[evidence] if evidence else [])
        return node_id

    def add_hypothesis(self, description: str, parent_id: Optional[int] = None) -> int:
        """Add a hypothesis node (what to test next)."""
        return self.add_node(TaskType.HYPOTHESIS.value, description, parent_id)

    def get_node(self, node_id: int) -> Optional[dict]:
        """Get a node by ID."""
        if node_id in self.nodes:
            return self.nodes[node_id].to_dict()
        return None

    def get_children(self, node_id: int) -> list:
        """Get children of a node."""
        if node_id not in self.nodes:
            return []
        children = []
        for cid in self.nodes[node_id].children:
            if cid in self.nodes:
                children.append(self.nodes[cid].to_dict())
        return children

    def get_pending(self) -> list:
        """Get all pending nodes (tasks to do next)."""
        pending = []
        for node in self.nodes.values():
            if node.status == TaskStatus.PENDING.value:
                pending.append(node.to_dict())
        return pending

    def get_findings(self) -> list:
        """Get all finding nodes."""
        findings = []
        for node in self.nodes.values():
            if node.task_type == TaskType.FINDING.value:
                findings.append(node.to_dict())
        return findings

    def get_next_task(self) -> Optional[dict]:
        """Get the next task to execute (priority: findings > hypotheses > pending)."""
        # First: unverified findings
        for node in self.nodes.values():
            if (node.task_type == TaskType.FINDING.value and
                node.status == TaskStatus.SUCCESS.value and
                not any(c.get("task_type") == TaskType.VERIFY.value
                       for c in self.get_children(node.id))):
                return {"action": "verify", "node": node.to_dict()}

        # Second: pending tasks
        for node in self.nodes.values():
            if node.status == TaskStatus.PENDING.value:
                return {"action": "execute", "node": node.to_dict()}

        return None

    def to_dict(self) -> dict:
        """Serialize entire tree."""
        return {
            "nodes": {str(k): v.to_dict() for k, v in self.nodes.items()},
            "root_ids": self.root_ids,
            "next_id": self._next_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TaskTree":
        """Deserialize tree from dict."""
        tree = cls()
        tree._next_id = data.get("next_id", 1)
        tree.root_ids = data.get("root_ids", [])
        for nid_str, node_data in data.get("nodes", {}).items():
            tree.nodes[int(nid_str)] = TaskNode.from_dict(node_data)
        return tree

    def render(self, node_id: int = None, indent: int = 0) -> str:
        """Render tree as text."""
        lines = []
        status_icons = {
            "pending": "[ ]",
            "running": "[>]",
            "success": "[+]",
            "failed": "[-]",
            "skipped": "[~]",
            "blocked": "[!]",
        }

        if node_id is None:
            # Render from roots
            for rid in self.root_ids:
                lines.append(self.render(rid, indent))
            return "\n".join(lines)

        if node_id not in self.nodes:
            return ""

        node = self.nodes[node_id]
        icon = status_icons.get(node.status, "[?]")
        prefix = "  " * indent
        lines.append(f"{prefix}{icon} {node.description}")

        for child_id in node.children:
            lines.append(self.render(child_id, indent + 1))

        return "\n".join(lines)

    def stats(self) -> dict:
        """Get tree statistics."""
        total = len(self.nodes)
        by_status = {}
        by_type = {}
        for node in self.nodes.values():
            by_status[node.status] = by_status.get(node.status, 0) + 1
            by_type[node.task_type] = by_type.get(node.task_type, 0) + 1
        return {
            "total_nodes": total,
            "by_status": by_status,
            "by_type": by_type,
            "findings": by_type.get("finding", 0),
            "pending": by_status.get("pending", 0),
        }


def create_pentest_tree(target: str, scope: str = "") -> TaskTree:
    """Create a standard pentest task tree with initial phases."""
    tree = TaskTree()

    # Phase 1: Recon
    recon_id = tree.add_node(TaskType.RECON.value, f"Reconnaissance on {target}")

    tree.add_node(TaskType.SCAN.value, "Subdomain enumeration", recon_id)
    tree.add_node(TaskType.SCAN.value, "Port scanning", recon_id)
    tree.add_node(TaskType.SCAN.value, "Technology fingerprinting", recon_id)
    tree.add_node(TaskType.SCAN.value, "WAF detection", recon_id)
    tree.add_node(TaskType.SCAN.value, "Directory enumeration", recon_id)

    # Phase 2: Scan
    scan_id = tree.add_node(TaskType.SCAN.value, "Vulnerability scanning")

    tree.add_node(TaskType.SCAN.value, "SQL injection testing", scan_id)
    tree.add_node(TaskType.SCAN.value, "XSS testing", scan_id)
    tree.add_node(TaskType.SCAN.value, "IDOR testing", scan_id)
    tree.add_node(TaskType.SCAN.value, "SSRF testing", scan_id)
    tree.add_node(TaskType.SCAN.value, "Auth bypass testing", scan_id)

    # Phase 3: Exploit
    exploit_id = tree.add_node(TaskType.EXPLOIT.value, "Exploitation")

    tree.add_node(TaskType.EXPLOIT.value, "Verify confirmed findings", exploit_id)
    tree.add_node(TaskType.EXPLOIT.value, "Chain findings for impact", exploit_id)

    # Phase 4: Report
    tree.add_node(TaskType.REPORT.value, "Generate report")

    return tree
