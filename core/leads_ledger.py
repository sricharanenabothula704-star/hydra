"""Leads Ledger — Track Unexplored Attack Paths

Stolen from: opencode-pentester's leads ledger
What it does: Every discovered-but-unexamined path is a lead
"Done" is blocked until every lead is explored or closed with reason

How it works:
1. During recon, any discovered host/service/vhost/subdomain becomes a lead
2. Leads have status: open, explored, false_positive, dead, out_of_scope, duplicate
3. AI cannot claim "recon done" while any lead is open
4. Leads are cross-referenced with findings (explored leads may produce vulns)
5. Push directive resurfaces abandoned leads

This beats opencode-pentester because:
- Theirs: Shell script (findings.sh lead)
- Ours: Python-native with strategy mutation integration
"""
import json
import time
from enum import Enum
from pathlib import Path
from typing import Optional


class LeadStatus(Enum):
    OPEN = "open"
    EXPLORED = "explored"
    FALSE_POSITIVE = "false_positive"
    DEAD = "dead"
    OUT_OF_SCOPE = "out_of_scope"
    DUPLICATE = "duplicate"


class LeadType(Enum):
    HOST = "host"
    SERVICE = "service"
    VHOST = "vhost"
    SUBDOMAIN = "subdomain"
    PORT = "port"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    CREDENTIAL = "credential"
    TECHNOLOGY = "technology"


class Lead:
    """A single discovered attack path."""

    def __init__(self, lead_id: str, lead_type: LeadType, value: str, source: str, why: str = ""):
        self.id = lead_id
        self.type = lead_type
        self.value = value
        self.source = source
        self.why = why
        self.status = LeadStatus.OPEN
        self.explored_at = None
        self.explored_by = None
        self.outcome = ""
        self.finding_id = None  # If exploration produced a finding
        self.created_at = time.time()

    def close(self, status: LeadStatus, outcome: str = ""):
        """Close this lead with a reason."""
        self.status = status
        self.outcome = outcome
        self.explored_at = time.time()

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "source": self.source,
            "why": self.why,
            "status": self.status.value,
            "explored_at": self.explored_at,
            "explored_by": self.explored_by,
            "outcome": self.outcome,
            "finding_id": self.finding_id,
            "created_at": self.created_at,
        }


class LeadsLedger:
    """Track all discovered attack paths."""

    def __init__(self, engagement_dir: Optional[Path] = None):
        self.engagement_dir = engagement_dir or Path.home() / ".hydra_data"
        self.engagement_dir.mkdir(parents=True, exist_ok=True)
        self.leads_file = self.engagement_dir / "leads.json"
        self.leads: dict[str, Lead] = {}
        self._next_id = 1
        self._load()

    def _load(self):
        """Load leads from disk."""
        if self.leads_file.exists():
            try:
                data = json.loads(self.leads_file.read_text(encoding="utf-8"))
                for l_data in data.get("leads", []):
                    lead = Lead(
                        lead_id=l_data["id"],
                        lead_type=LeadType(l_data["type"]),
                        value=l_data["value"],
                        source=l_data["source"],
                        why=l_data.get("why", ""),
                    )
                    lead.status = LeadStatus(l_data["status"])
                    lead.explored_at = l_data.get("explored_at")
                    lead.explored_by = l_data.get("explored_by")
                    lead.outcome = l_data.get("outcome", "")
                    lead.finding_id = l_data.get("finding_id")
                    lead.created_at = l_data.get("created_at", time.time())
                    self.leads[lead.id] = lead
                self._next_id = data.get("next_id", len(self.leads) + 1)
            except (json.JSONDecodeError, KeyError):
                pass

    def _save(self):
        """Save leads to disk."""
        data = {
            "leads": [l.to_dict() for l in self.leads.values()],
            "next_id": self._next_id,
            "last_updated": time.time(),
        }
        self.leads_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def add(self, lead_type: LeadType, value: str, source: str, why: str = "") -> str:
        """Add a new lead. Returns lead ID."""
        # Check for duplicates
        for lead in self.leads.values():
            if lead.type == lead_type and lead.value == value and lead.status == LeadStatus.OPEN:
                return lead.id

        lead_id = f"lead_{self._next_id}"
        self._next_id += 1

        lead = Lead(lead_id, lead_type, value, source, why)
        self.leads[lead_id] = lead
        self._save()
        return lead_id

    def explore(self, lead_id: str, outcome: str, finding_id: str = None) -> bool:
        """Mark a lead as explored."""
        if lead_id not in self.leads:
            return False

        lead = self.leads[lead_id]
        lead.close(LeadStatus.EXPLORED, outcome)
        lead.finding_id = finding_id
        self._save()
        return True

    def close(self, lead_id: str, status: LeadStatus, reason: str = "") -> bool:
        """Close a lead with a specific status."""
        if lead_id not in self.leads:
            return False

        lead = self.leads[lead_id]
        lead.close(status, reason)
        self._save()
        return True

    def get_open(self) -> list[Lead]:
        """Get all open leads."""
        return [l for l in self.leads.values() if l.status == LeadStatus.OPEN]

    def get_by_type(self, lead_type: LeadType) -> list[Lead]:
        """Get leads by type."""
        return [l for l in self.leads.values() if l.type == lead_type]

    def get_by_status(self, status: LeadStatus) -> list[Lead]:
        """Get leads by status."""
        return [l for l in self.leads.values() if l.status == status]

    def summary(self) -> dict:
        """Get summary of all leads."""
        total = len(self.leads)
        by_status = {}
        by_type = {}
        by_source = {}

        for lead in self.leads.values():
            by_status[lead.status.value] = by_status.get(lead.status.value, 0) + 1
            by_type[lead.type.value] = by_type.get(lead.type.value, 0) + 1
            by_source[lead.source] = by_source.get(lead.source, 0) + 1

        return {
            "total": total,
            "open": by_status.get("open", 0),
            "explored": by_status.get("explored", 0),
            "by_status": by_status,
            "by_type": by_type,
            "by_source": by_source,
        }

    def push_directive(self) -> str:
        """Generate push directive for abandoned leads."""
        open_leads = self.get_open()
        if not open_leads:
            return "All leads explored. Engagement complete."

        lines = ["PUSH DIRECTIVE — Abandoned leads detected:"]
        for lead in open_leads[:10]:
            lines.append(f"  [{lead.type.value}] {lead.value} (source: {lead.source})")

        if len(open_leads) > 10:
            lines.append(f"  ... and {len(open_leads) - 10} more")

        lines.append(f"\nAction: Explore {len(open_leads)} open leads before claiming completion.")
        return "\n".join(lines)

    def render(self) -> str:
        """Render leads as human-readable text."""
        summary = self.summary()
        lines = [
            "LEADS LEDGER",
            "=" * 40,
            f"Total: {summary['total']}  Open: {summary['open']}  Explored: {summary['explored']}",
            "",
        ]

        open_leads = self.get_open()
        if open_leads:
            lines.append("OPEN LEADS:")
            for lead in open_leads:
                lines.append(f"  [{lead.type.value}] {lead.value} (from {lead.source})")
        else:
            lines.append("No open leads.")

        lines.append("=" * 40)
        return "\n".join(lines)


# Global instance
leads_ledger = LeadsLedger()
