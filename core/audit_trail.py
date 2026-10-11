"""Append-only local audit trail for enforcement decisions.

The first question asked of any autonomous security agent is "what did it
actually do, and when?". Every scope denial, every endpoint protection, and
every validation verdict is recorded here so the answer exists.

Design constraints:

* Append-only. Existing records are never rewritten or removed.
* One JSON object per line, so a partially written tail cannot corrupt the
  records before it.
* No target credentials are stored. URLs are normalized through the same
  path used for scope decisions and any userinfo is rejected upstream.
* Content-hashed per record so tampering is detectable after the fact.

Nothing in this module consults or is influenced by a model.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_TRAIL = Path.home() / ".local" / "share" / "opencode" / "hydra" / "audit.jsonl"

_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class AuditEvent:
    event: str
    target: str = ""
    decision: str = ""
    reason: str = ""
    actor: str = "hydra-enforcement"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "ts": _now(),
            "event": self.event,
            "actor": self.actor,
            "target": self.target,
            "decision": self.decision,
            "reason": self.reason,
            "metadata": self.metadata,
        }


class AuditTrail:
    """Append-only JSONL writer with per-record content hashing."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else DEFAULT_TRAIL
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        event: str,
        target: str = "",
        decision: str = "",
        reason: str = "",
        actor: str = "hydra-enforcement",
        **metadata: Any,
    ) -> dict[str, Any]:
        entry = AuditEvent(
            event=event,
            target=target,
            decision=decision,
            reason=reason,
            actor=actor,
            metadata=metadata,
        ).to_record()
        entry["hash"] = _digest(entry)
        line = json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
        with _LOCK:
            # Append mode plus an fsync: a crash truncates at most the last
            # line, never rewrites earlier records.
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        return entry

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError:
                # A truncated final line is expected after a crash.
                continue
        return records

    def verify(self) -> tuple[bool, list[int]]:
        """Return (intact, list_of_1_based_line_numbers_that_failed)."""
        bad: list[int] = []
        for index, record in enumerate(self.read(), start=1):
            expected = record.get("hash")
            probe = {k: v for k, v in record.items() if k != "hash"}
            if not expected or _digest(probe) != expected:
                bad.append(index)
        return (not bad, bad)

    def summary(self) -> dict[str, Any]:
        records = self.read()
        by_event: dict[str, int] = {}
        denied = 0
        for record in records:
            by_event[record.get("event", "?")] = (
                by_event.get(record.get("event", "?"), 0) + 1
            )
            if str(record.get("decision", "")).lower() in {"deny", "block", "blocked"}:
                denied += 1
        intact, bad = self.verify()
        return {
            "records": len(records),
            "by_event": by_event,
            "denials": denied,
            "integrity_ok": intact,
            "tampered_lines": bad,
            "path": str(self.path),
        }
