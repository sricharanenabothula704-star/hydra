"""Conversation Rewind — Session Snapshots

Stolen from: PentestAgent's conversation rewind/fork feature
What it does: Save snapshots at each decision point, allow rewind/fork

How it works:
1. At each AI decision, save full conversation state
2. /rewind → restore any previous snapshot
3. /fork from any message → try alternative path
4. Store last 20 conversations per engagement

This is what makes HYDRA better:
- PentestGPT: Linear conversation (can't go back)
- PentestAgent: Can rewind but not fork
- HYDRA: Full rewind + fork + conversation tree
"""
import json
import time
from pathlib import Path
from typing import Optional


class Snapshot:
    """A point-in-time snapshot of conversation state."""

    def __init__(self, snapshot_id: str, data: dict, parent_id: str = None):
        self.id = snapshot_id
        self.data = data
        self.parent_id = parent_id
        self.children = []
        self.timestamp = time.time()
        self.label = data.get("label", f"Step {snapshot_id}")

    def to_dict(self):
        return {
            "id": self.id,
            "data": self.data,
            "parent_id": self.parent_id,
            "children": self.children,
            "timestamp": self.timestamp,
            "label": self.label,
        }


class ConversationManager:
    """Manages conversation snapshots with rewind/fork capability."""

    def __init__(self, engagement_dir: Optional[Path] = None):
        self.engagement_dir = engagement_dir or Path.home() / ".hydra_data"
        self.engagement_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_file = self.engagement_dir / "conversation.json"
        self.snapshots: dict[str, Snapshot] = {}
        self.current_id: Optional[str] = None
        self.max_snapshots = 50
        self._load()

    def _load(self):
        """Load snapshots from disk."""
        if self.snapshots_file.exists():
            try:
                data = json.loads(self.snapshots_file.read_text(encoding="utf-8"))
                for s_data in data.get("snapshots", []):
                    snap = Snapshot(
                        snapshot_id=s_data["id"],
                        data=s_data["data"],
                        parent_id=s_data.get("parent_id"),
                    )
                    snap.children = s_data.get("children", [])
                    snap.timestamp = s_data.get("timestamp", time.time())
                    snap.label = s_data.get("label", "")
                    self.snapshots[snap.id] = snap
                self.current_id = data.get("current_id")
            except (json.JSONDecodeError, KeyError):
                pass

    def _save(self):
        """Save snapshots to disk."""
        data = {
            "snapshots": [s.to_dict() for s in self.snapshots.values()],
            "current_id": self.current_id,
        }
        self.snapshots_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def save_snapshot(self, state: dict, label: str = None) -> str:
        """Save current state as a snapshot. Returns snapshot ID."""
        # Enforce max snapshots
        if len(self.snapshots) >= self.max_snapshots:
            oldest = min(self.snapshots.values(), key=lambda s: s.timestamp)
            del self.snapshots[oldest.id]

        snap_id = f"snap_{int(time.time() * 1000)}"
        state["label"] = label or f"Step {len(self.snapshots) + 1}"
        snap = Snapshot(snap_id, state, parent_id=self.current_id)

        # Link parent
        if self.current_id and self.current_id in self.snapshots:
            self.snapshots[self.current_id].children.append(snap_id)

        self.snapshots[snap_id] = snap
        self.current_id = snap_id
        self._save()
        return snap_id

    def rewind(self, steps: int = 1) -> Optional[dict]:
        """Rewind N steps back. Returns the state at that point."""
        if not self.current_id:
            return None

        current = self.snapshots[self.current_id]
        path = self._get_path_to_root(self.current_id)

        if steps >= len(path):
            # Rewind to root
            target_id = path[-1]
        else:
            target_id = path[steps]

        self.current_id = target_id
        self._save()
        return self.snapshots[target_id].data

    def fork(self, snapshot_id: str) -> Optional[str]:
        """Fork from a specific snapshot. Returns new snapshot ID."""
        if snapshot_id not in self.snapshots:
            return None

        # Create a copy of the fork point's state
        fork_state = self.snapshots[snapshot_id].data.copy()
        fork_state["label"] = f"Fork from {self.snapshots[snapshot_id].label}"

        return self.save_snapshot(fork_state, label=f"fork_{snapshot_id}")

    def jump_to(self, snapshot_id: str) -> Optional[dict]:
        """Jump to a specific snapshot. Returns its state."""
        if snapshot_id not in self.snapshots:
            return None

        self.current_id = snapshot_id
        self._save()
        return self.snapshots[snapshot_id].data

    def get_current(self) -> Optional[dict]:
        """Get current snapshot state."""
        if self.current_id and self.current_id in self.snapshots:
            return self.snapshots[self.current_id].data
        return None

    def list_snapshots(self) -> list[dict]:
        """List all snapshots with their labels."""
        return [
            {
                "id": s.id,
                "label": s.label,
                "timestamp": s.timestamp,
                "is_current": s.id == self.current_id,
                "children": len(s.children),
            }
            for s in sorted(self.snapshots.values(), key=lambda x: x.timestamp)
        ]

    def _get_path_to_root(self, snap_id: str) -> list[str]:
        """Get path from snap_id to root."""
        path = []
        current = snap_id
        while current and current in self.snapshots:
            path.append(current)
            current = self.snapshots[current].parent_id
        return path

    def get_conversation_tree(self) -> str:
        """Render conversation tree as text."""
        if not self.snapshots:
            return "No snapshots yet"

        lines = []
        root = [s for s in self.snapshots.values() if not s.parent_id]
        for r in root:
            self._render_node(r.id, lines, indent=0)
        return "\n".join(lines)

    def _render_node(self, snap_id: str, lines: list, indent: int):
        """Render a node and its children."""
        snap = self.snapshots.get(snap_id)
        if not snap:
            return

        prefix = "  " * indent
        marker = " → " if snap.id == self.current_id else "   "
        lines.append(f"{prefix}{marker}{snap.label} [{snap.id[:12]}]")

        for child_id in snap.children:
            self._render_node(child_id, lines, indent + 1)

    def clear(self):
        """Clear all snapshots."""
        self.snapshots.clear()
        self.current_id = None
        self._save()


# Global instance
conversation = ConversationManager()
